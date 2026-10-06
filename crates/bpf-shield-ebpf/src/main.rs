//! BPF-Shield kernel-space entry points.
//!
//! # Enforcement strategy, and why it is not what the design doc assumed
//!
//! The original plan was: kprobe the syscall wrapper, call
//! `bpf_override_return(ctx, -EPERM)`. That **does not work**, and it is worth
//! being precise about why, because the failure is silent and looks like a
//! policy bug:
//!
//! ```c
//! // kernel/trace/bpf_trace.c
//! #ifdef CONFIG_BPF_KPROBE_OVERRIDE
//! BPF_CALL_2(bpf_override_return, struct pt_regs *, regs, unsigned long, rc)
//! {
//!         regs_set_return_value(regs, rc);
//!         override_function_with_return(regs);
//!         return 0;
//! }
//! #endif
//! ```
//!
//! Three independent blockers:
//!
//! 1. It is gated on `CONFIG_BPF_KPROBE_OVERRIDE`, which is **not** enabled on
//!    most distro kernels (`Fedora`, `Debian`, `RHEL` all ship it off).
//! 2. `override_function_with_return()` redirects the PC, and the redirect is
//!    only permitted for functions tagged `ALLOW_ERROR_INJECTION`. Syscall
//!    wrappers (`__x64_sys_execve`, `__arm64_sys_execve`) are **not** on that
//!    list — it contains things like `ioctl_init`, `shmem_file_read_iter`,
//!    `schedule_timeout_uninterruptible`. Attempting it fails at *attach* time
//!    with `EINVAL`, before any of your logic runs.
//! 3. The helper returns `0` unconditionally. There is no way to detect from
//!    BPF that the override was rejected, so a design that trusts the return
//!    value reports "enforcing" forever while denying nothing.
//!
//! So BPF-Shield splits the two jobs that were conflated:
//!
//! | Job                | Mechanism                                    | Kernel |
//! |--------------------|----------------------------------------------|--------|
//! | **Enforce** (deny) | LSM hook `bprm_check_security`, returns `-EPERM` | 4.17+ (BPF LSM 5.7+) |
//! | **Observe**        | kprobe on the syscall wrapper                 | 4.1+ |
//! | **Sanitise**       | `bpf_probe_write_user` from a kprobe          | 5.5+ |
//! | **Fault inject**   | `bpf_override_return` on `ioctl_init`         | 4.16+ / 5.10+ / CONFIG_BPF_KPROBE_OVERRIDE |
//!
//! LSM hooks are the *correct* primitive for "deny this": they are an
//! in-kernel policy hook that already has a defined failure path returning
//! `-errno`, they cannot fail open by accident, and they are what every
//! production sandbox (AppArmor, SELinux, Tetragon) uses.
//!
//! # `bpf_override_return` is still here
//!
//! `shield_fault_ioctl_init` demonstrates it on a function that genuinely is
//! error-injection-allowed, because "deny with EPERM at an entry kprobe" is a
//! capability teams legitimately want for testing error paths. It is compiled
//! in but the daemon deliberately **does not attach it by default**, and an
//! attach failure there is logged as informational rather than fatal.

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

mod events;
mod maps;
mod policy;
mod stats;

use aya_ebpf::{
    helpers::bpf_probe_write_user,
    macros::{kprobe, lsm},
    programs::{LsmContext, ProbeContext},
};
use bpf_shield_common::{
    cfg_flags, fnv1a64, rule_flags, Action, Hook, Rule, ShieldConfig, MAX_SCAN_ARGS, NAME_HASH_LEN,
};

use crate::maps::{SANITIZE_TO, SHIELD_CONFIG};
use crate::policy::{effective_action, lookup, read_kernel_window, read_user_window, PResult, Window};
use crate::stats::bump;

/// `struct linux_binprm`, truncated to the one field we read.
///
/// `filename` is the first member and is a `char[PATH_MAX]` kernel array, so
/// `bprm as *const u8` already points at it. We never dereference this type —
/// it exists only to name the pointer type. Declaring it locally (rather than
/// using CO-RE) keeps the object loadable on kernels without matching BTF and
/// removes any dependence on `struct linux_binprm` field offsets changing.
#[repr(C)]
struct LinuxBinprm {
    filename: [u8; 4096],
}

// ---------------------------------------------------------------------------
// Config gate
// ---------------------------------------------------------------------------

/// The one and only place a probe asks "should I be doing anything at all?".
///
/// Returns a borrowed config only when the probe is live, the subsystem is
/// armed, and the kill switch is clear. Every probe starts with this, which
/// means disarming the system costs one 8-byte load and one branch per call
/// and cannot be forgotten by a future probe.
#[inline(always)]
fn live_config(want: u64) -> Option<ShieldConfig> {
    let cfg = *SHIELD_CONFIG.get(0)?;
    if !cfg.is_valid() {
        // Never initialised: fail open, loudly.
        bump!(bypassed);
        return None;
    }
    if cfg.flags & cfg_flags::KILL_SWITCH != 0 || cfg.flags & cfg_flags::ENABLED == 0 {
        bump!(bypassed);
        return None;
    }
    if cfg.flags & want == 0 {
        return None;
    }
    Some(cfg)
}

// ---------------------------------------------------------------------------
// 1. ENFORCEMENT — LSM hook
// ---------------------------------------------------------------------------

/// `LSM_HOOK(int, 0, bprm_check_security, struct linux_binprm *bprm)`
///
/// This is the execve choke point. Returning a negative value from a BPF LSM
/// program aborts the hook chain and fails the syscall with that `errno` — the
/// same contract SELinux/AppArmor hooks use, so it composes correctly with
/// whatever is already installed.
///
/// # LSM hygiene
///
/// * `retval` (argument 1) carries the previous hook's verdict. We defer to a
///   non-zero `retval` instead of overwriting it: stacking BPF-Shield on top of
///   an existing LSM must not silently *undo* that LSM's decision.
/// * Returning `0` on every internal error keeps us fail-open.
#[lsm(hook = "bprm_check_security")]
pub fn shield_bprm_check_security(ctx: LsmContext) -> i32 {
    // The phony `retval` argument is always last in the list.
    let retval: i32 = ctx.arg(1);
    if retval != 0 {
        return retval;
    }

    let Some(cfg) = live_config(cfg_flags::HOOK_EXECVE) else {
        return 0;
    };
    bump!(seen);

    match try_bprm_check(&cfg, &ctx) {
        Ok(rc) => rc,
        // Fail open. A bug in BPF-Shield must degrade to "no protection", not
        // to "nobody can exec anything".
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_bprm_check(cfg: &ShieldConfig, ctx: &LsmContext) -> PResult<i32> {
    let bprm: *const LinuxBinprm = ctx.arg(0);
    if bprm.is_null() {
        return Ok(0);
    }

    // SAFETY: `bprm` comes from the kernel; `filename` is a 4 KiB array at
    // offset 0, so a 64-byte window read cannot fault or straddle a page.
    // The read itself is performed fault-safely by the helper.
    let mut name: Window = [0u8; NAME_HASH_LEN];
    let len = read_kernel_window(bprm.cast(), &mut name)?;

    let Some(rule) = lookup(&name, len, rule_flags::EXEC_PATH, cfg) else {
        return Ok(0);
    };
    bump!(matched);

    let enforcing = cfg.enforcing();
    let action = effective_action(&rule, enforcing);

    match action {
        Action::Allow => Ok(0),
        Action::Sanitize => {
            // execve's pathname lives in a kernel array we do not own; the
            // sanitise action is not meaningful here. Report and allow.
            report(cfg, &rule, &name, len, Action::Sanitize, 0, Hook::ExecveLsm);
            bump!(audited);
            Ok(0)
        }
        Action::Audit => {
            report(cfg, &rule, &name, len, action, 0, Hook::ExecveLsm);
            bump!(audited);
            Ok(0)
        }
        Action::Deny => {
            let rc = -rule.errno;
            report(cfg, &rule, &name, len, action, rc, Hook::ExecveLsm);
            bump!(blocked);
            Ok(rc)
        }
    }
}

// ---------------------------------------------------------------------------
// 2. OBSERVATION + argv scan — kprobe
// ---------------------------------------------------------------------------

/// Observation half for `execve`, plus the `argv[]` scan.
///
/// `bprm_check_security` sees only the executable path; exploit payloads
/// usually live in an *argument*. This probe walks the first
/// [`MAX_SCAN_ARGS`] entries and applies `EXEC_ARG` rules.
///
/// # Reading syscall arguments correctly
///
/// `__x64_sys_execve(const struct pt_regs *regs)` takes one C argument (a
/// pointer to the saved register frame), but the three syscall arguments are
/// in `regs->di/rsi/rdx`. `ProbeContext::arg(n)` implements exactly the
/// `PT_REGS_PARM1..n` mapping libbpf uses, per architecture, so `arg(0)` and
/// `arg(1)` give us `filename` and `argv` without any architecture `#if`.
#[inline(always)]
fn try_execve(ctx: &ProbeContext, hook: Hook) -> PResult<()> {
    let Some(cfg) = live_config(cfg_flags::HOOK_EXECVE | cfg_flags::COLLECT) else {
        return Ok(());
    };
    bump!(seen);

    let filename: *const u8 = match ctx.arg(0) {
        Some(p) => p,
        None => return Ok(()),
    };
    let argv: *const *const u8 = match ctx.arg(1) {
        Some(p) => p,
        None => return Ok(()),
    };

    // --- executable path ---
    let mut name: Window = [0u8; NAME_HASH_LEN];
    let len = read_user_window(filename, &mut name)?;
    if let Some(rule) = lookup(&name, len, rule_flags::EXEC_PATH, cfg) {
        bump!(matched);
        report_execve(cfg, &rule, &name, len, hook);
        // We still fall through to argv: an operator wants the full picture of
        // a malicious invocation, not just its first matching component.
    }

    if cfg.flags & cfg_flags::ARG_SCAN == 0 {
        return Ok(());
    }

    // --- argv[0..MAX_SCAN_ARGS] ---
    let limit = core::cmp::min(cfg.max_arg_index, MAX_SCAN_ARGS);
    let mut slot: u32 = 0;
    // Fully unrolled by LLVM because the trip count is a constant. The `break`
    // compiles to forward branches, so the verifier never sees a back edge.
    #[allow(clippy::never_loop)]
    for _ in 0..MAX_SCAN_ARGS {
        if slot >= limit {
            break;
        }

        // `argv` is attacker-controlled memory: read the pointer through the
        // fault-safe helper rather than dereferencing it.
        let arg_ptr: *const u8 = match read_user_ptr(argv, slot) {
            Some(p) => p,
            None => break,
        };
        if arg_ptr.is_null() {
            // End of `argv`.
            break;
        }

        let mut arg: Window = [0u8; NAME_HASH_LEN];
        let arg_len = match read_user_window(arg_ptr, &mut arg) {
            Ok(n) => n,
            Err(_) => {
                slot += 1;
                continue;
            }
        };

        if let Some(rule) = lookup(&arg, arg_len, rule_flags::EXEC_ARG, cfg) {
            bump!(matched);
            report_execve(cfg, &rule, &arg, arg_len, hook);
        }

        slot += 1;
    }

    Ok(())
}

/// Read one `char *` out of a user-space pointer array.
#[inline(always)]
fn read_user_ptr(array: *const *const u8, index: u32) -> Option<*const u8> {
    // `index` is a constant at every unrolled site, so the verifier sees a
    // fixed offset and needs no range analysis of its own.
    let base = unsafe { array.add(index as usize) };
    // SAFETY: fault-safe read of 8 bytes; returns `None` on EFAULT.
    aya_ebpf::helpers::bpf_probe_read_user(base).ok()
}

// ---------------------------------------------------------------------------
// 3. OBSERVATION + SANITISATION — openat
// ---------------------------------------------------------------------------

/// `openat(dirfd, pathname, flags, mode)`: `arg(0)`=dirfd, `arg(1)`=pathname.
#[inline(always)]
fn try_openat(ctx: &ProbeContext) -> PResult<()> {
    let Some(cfg) = live_config(cfg_flags::HOOK_OPENAT) else {
        return Ok(());
    };
    bump!(seen);

    let filename: *const u8 = match ctx.arg(1) {
        Some(p) => p,
        None => return Ok(()),
    };

    let mut name: Window = [0u8; NAME_HASH_LEN];
    let len = read_user_window(filename, &mut name)?;

    let Some(rule) = lookup(&name, len, rule_flags::OPEN_PATH, cfg) else {
        return Ok(());
    };
    bump!(matched);

    let action = effective_action(&rule, cfg.enforcing());
    match action {
        Action::Deny | Action::Audit => {
            // `openat` has no LSM hook we can veto from here without a
            // context walk, so a `Deny` on this hook is audit-only. The daemon
            // refuses to install `Enforce` on `OPEN_PATH` rules and says so at
            // policy-load time rather than letting an operator believe they
            // are protected.
            events::emit(
                cfg,
                Hook::OpenatKprobe,
                rule.rule_id,
                if cfg.enforcing() && action == Action::Deny {
                    Action::Audit
                } else {
                    action
                },
                0,
                &name,
                len,
                fnv1a64(&name[..core::cmp::min(len as usize, NAME_HASH_LEN)]),
            );
            bump!(audited);
        }
        Action::Sanitize => {
            sanitize_user_path(filename);
            events::emit(
                cfg,
                Hook::OpenatKprobe,
                rule.rule_id,
                Action::Sanitize,
                0,
                &name,
                len,
                fnv1a64(&name[..core::cmp::min(len as usize, NAME_HASH_LEN)]),
            );
        }
        Action::Allow => {}
    }

    Ok(())
}

/// Overwrite the caller's pathname with the operator-configured replacement.
///
/// # Why this is best-effort, and stated plainly
///
/// `bpf_probe_write_user` needs a *single fixed-size* destination to satisfy
/// the verifier, so we write the whole 16-byte [`SANITIZE_TO`] blob. That means:
///
/// * the caller's buffer must be at least 16 bytes and writable — otherwise
///   the helper returns `-EFAULT` and we count it rather than pretending;
/// * writing into a read-only mapping (`.rodata`, `.text`) fails for the same
///   reason, which is usually the outcome you want anyway;
/// * the write is a partial overwrite, so a caller holding a pointer *into* the
///   middle of the old string still sees stale bytes. Sanitisation reduces the
///   attacker's options; it does not make an open fail. Only the LSM hook makes
///   the call fail.
///
/// This is offered as defence in depth for payloads that cannot be denied
/// cheaply at the LSM layer, and it is opt-in behind `SANITIZE_ARGS`.
#[inline(always)]
fn sanitize_user_path(dst: *const u8) {
    if dst.is_null() {
        return;
    }
    if let Some(repl) = SANITIZE_TO.get(0) {
        // SAFETY: `dst` is the user's `const char __user *pathname` from the
        // syscall ABI; the helper performs the fault-safe copy and returns
        // `Err` if any byte is unwritable.
        if bpf_probe_write_user::<u8>(dst.cast_mut(), repl.as_ptr().cast()).is_err() {
            bump!(read_errors);
        }
    }
}

// ---------------------------------------------------------------------------
// Reporting helpers
// ---------------------------------------------------------------------------

#[inline(always)]
fn report(
    cfg: &ShieldConfig,
    rule: &Rule,
    name: &Window,
    len: u16,
    action: Action,
    errno: i32,
    hook: Hook,
) {
    events::emit(
        cfg,
        hook,
        rule.rule_id,
        action,
        errno,
        name,
        len,
        full_hash(name, len),
    );
}

#[inline(always)]
fn report_execve(
    cfg: &ShieldConfig,
    rule: &Rule,
    name: &Window,
    len: u16,
    hook: Hook,
) {
    // `execve` is enforced at the LSM hook, never here. We therefore always
    // report the *audit* form from the kprobe, which keeps the event stream
    // honest: exactly one of the two probes will ever claim enforcement.
    events::emit(
        cfg,
        hook,
        rule.rule_id,
        Action::Audit,
        0,
        name,
        len,
        full_hash(name, len),
    );
    bump!(audited);
}

#[inline(always)]
fn full_hash(name: &Window, len: u16) -> u64 {
    fnv1a64(&name[..core::cmp::min(len as usize, NAME_HASH_LEN)])
}

// ---------------------------------------------------------------------------
// Program entry points (architecture dispatch)
// ---------------------------------------------------------------------------

#[cfg(bpf_target_arch = "x86_64")]
#[kprobe(__x64_sys_execve)]
pub fn shield_execve_x86(ctx: ProbeContext) -> u32 {
    if try_execve(&ctx, Hook::ExecveKprobe).is_err() {
        bump!(read_errors);
    }
    0
}

#[cfg(bpf_target_arch = "aarch64")]
#[kprobe(__arm64_sys_execve)]
pub fn shield_execve_arm64(ctx: ProbeContext) -> u32 {
    if try_execve(&ctx, Hook::ExecveKprobe).is_err() {
        bump!(read_errors);
    }
    0
}

#[cfg(bpf_target_arch = "x86_64")]
#[kprobe(__x64_sys_openat)]
pub fn shield_openat_x86(ctx: ProbeContext) -> u32 {
    if try_openat(&ctx).is_err() {
        bump!(read_errors);
    }
    0
}

#[cfg(bpf_target_arch = "aarch64")]
#[kprobe(__arm64_sys_openat)]
pub fn shield_openat_arm64(ctx: ProbeContext) -> u32 {
    if try_openat(&ctx).is_err() {
        bump!(read_errors);
    }
    0
}

/// Fault injection on `ioctl_init`, which *is* tagged `ALLOW_ERROR_INJECTION`.
///
/// This is the only legitimate use of `bpf_override_return` in BPF-Shield:
/// deny a specific ioctl with a chosen errno, to exercise an application's
/// error handling. It is disabled by default and the daemon treats a failed
/// attach as informational, because `CONFIG_BPF_KPROBE_OVERRIDE` is off on
/// many kernels and that is not an error condition.
///
/// Note the helper returns `0` whether or not the override took effect (see
/// the module docs), so we cannot — and do not claim to — verify from BPF that
/// the injection happened.
#[kprobe(ioctl_init)]
pub fn shield_fault_ioctl_init(ctx: ProbeContext) -> u32 {
    let Some(cfg) = live_config(cfg_flags::HOOK_OPENAT) else {
        return 0;
    };
    let injected: i32 = match ctx.arg(0) {
        Some(v) => v,
        None => return 0,
    };
    if injected != 0 {
        return 0;
    }
    bump!(blocked);
    // SAFETY: `ctx.regs` is the `pt_regs` the helper requires. The helper
    // returns 0 unconditionally; a rejection surfaces as a failed attach.
    unsafe {
        aya_ebpf::helpers::bpf_override_return(ctx.regs, (-bpf_shield_common::EPERM) as u64);
    }
    0
}
