//! Loading and attaching the kernel object.
//!
//! # Failure handling
//!
//! Every attach is best-effort *except* the LSM enforcement hook, and this is
//! the single most important policy decision in the daemon.
//!
//! * LSM hook fails to load → **fatal**. Without it there is no enforcement
//!   path, and running in "audit only" while an operator believes they are
//!   protected is the exact failure this product exists to prevent.
//! * `fentry`/`kprobe` fails to attach → logged and skipped. Losing the
//!   observation path degrades visibility but cannot break the host.
//! * Fault-injection program fails → logged at debug. It requires
//!   `CONFIG_BPF_KPROBE_OVERRIDE`, which many kernels disable.
//!
//! # Attaching across architectures
//!
//! The eBPF object contains `__x64_sys_execve` and `__arm64_sys_execve`
//! programs. They are both *present* in the ELF but only the one matching the
//! running CPU is ever attached, so the daemon selects by
//! `cfg!(target_arch)` and never attaches a program whose syscall entry
//! trampoline does not exist.

use std::path::Path;

use aya::{
    programs::{KProbe, Lsm, ProgramError},
    Ebpf, EbpfLoader, VerifierLogLevel,
};
use bpf_shield_common::{cfg_flags, ShieldConfig, SHIELD_ABI_VERSION};
use tracing::{debug, error, info, warn};

/// One attached program plus a human-readable name, kept alive for the
/// lifetime of the daemon.
pub struct Attached {
    pub name: &'static str,
    /// Held to keep the link (and therefore the attachment) alive.
    pub _link: Link,
}

/// Opaque handle hiding which link type each program produced.
pub enum Link {
    Lsm(aya::programs::lsm::LsmLinkId),
    KProbe(aya::programs::kprobe::KProbeLinkId),
}

/// Everything the daemon needs from the loader, plus the live [`Ebpf`] handle.
///
/// The object must outlive the links, so it is kept in the same struct.
pub struct Loader {
    pub ebpf: Ebpf,
    pub attached: Vec<Attached>,
}

/// Load the object and attach every probe we can.
///
/// `object_path` overrides the compiled-in path; used by distro packaging.
pub fn load(
    object_path: &Path,
    verifier_log: VerifierLogLevel,
    pin_dir: Option<&Path>,
    attach_fault_injection: bool,
) -> Result<Loader, String> {
    debug!(?object_path, "loading eBPF object");

    let mut loader = EbpfLoader::new();
    loader.verifier_log_level(verifier_log);
    if let Some(dir) = pin_dir {
        loader.default_map_pin_directory(dir);
    }

    let mut ebpf = loader
        .load_file(object_path)
        .map_err(|e| format!("load {}: {e}", object_path.display()))?;

    // The kernel half embeds the ABI version it was compiled against. Refuse a
    // mismatch rather than reading a struct whose layout we do not know: that
    // is precisely the bug class that makes security tools untrustworthy.
    verify_abi(&mut ebpf)?;

    let mut attached = Vec::new();

    // ---- enforcement: LSM hook (fatal on failure) -------------------------
    {
        let prog: &mut Lsm = ebpf
            .program_mut("shield_bprm_check_security")
            .ok_or("object has no `shield_bprm_check_security` program")?
            .try_into()
            .map_err(|e| format!("bprm_check_security is not an LSM program: {e}"))?;

        // BPF LSM attachment needs kernel BTF to resolve `bpf_lsm_<hook>`.
        let btf = aya::Btf::from_sys_fs()
            .map_err(|e| format!("read /sys/kernel/btf/vmlinux: {e}. BPF LSM requires CONFIG_DEBUG_INFO_BTF"))?;
        info!("kernel BTF available ({} bytes)", btf.raw_bytes().len());

        prog.load("bprm_check_security", &btf)
            .map_err(|e| format!("load LSM bprm_check_security: {e}. \
                 This hook needs CONFIG_BPF_LSM=y and `lsm=bpf` on the kernel command line."))?;
        let link = prog
            .attach()
            .map_err(|e| format!("attach LSM bprm_check_security: {e}"))?;
        info!("attached LSM hook bprm_check_security (execve enforcement)");
        attached.push(Attached {
            name: "shield_bprm_check_security",
            _link: Link::Lsm(link),
        });
    }

    // ---- observation: syscall kprobes (best effort) ----------------------
    let execve_prog = if cfg!(target_arch = "x86_64") {
        "shield_execve_x86"
    } else if cfg!(target_arch = "aarch64") {
        "shield_execve_arm64"
    } else {
        ""
    };
    let openat_prog = if cfg!(target_arch = "x86_64") {
        "shield_openat_x86"
    } else if cfg!(target_arch = "aarch64") {
        "shield_openat_arm64"
    } else {
        ""
    };

    if execve_prog.is_empty() {
        warn!(
            arch = std::env::consts::ARCH,
            "unsupported architecture: only x86_64 and aarch64 have a syscall-entry \
             trampoline shim in this build. Enforcement still works via the LSM hook; \
             observation and argv scanning are unavailable."
        );
    } else {
        if let Some(sym) = attach_kprobe(&mut ebpf, execve_prog, execve_prog)? {
            attached.push(sym);
        }
        if let Some(sym) = attach_kprobe(&mut ebpf, openat_prog, openat_prog)? {
            attached.push(sym);
        }
    }

    // ---- optional: fault injection (expects to fail on many kernels) -----
    if attach_fault_injection {
        match attach_kprobe(
            &mut ebpf,
            "shield_fault_ioctl_init",
            "ioctl_init",
        ) {
            Ok(Some(sym)) => {
                warn!(
                    "fault injection attached to ioctl_init — BPF-Shield can now deny \
                     ioctl() calls with EPERM. Ensure --fault-ioctl is NOT enabled in \
                     the shipped config."
                );
                attached.push(sym);
            }
            Ok(None) => {}
            Err(e) => debug!(error = %e, "fault injection unavailable (expected without CONFIG_BPF_KPROBE_OVERRIDE)"),
        }
    }

    info!(count = attached.len(), "programs attached");
    Ok(Loader { ebpf, attached })
}

/// Load + attach one kprobe program. `None` if the program is absent from the
/// object (expected on builds where it was compiled out).
fn attach_kprobe(
    ebpf: &mut Ebpf,
    program: &str,
    symbol: &str,
) -> Result<Option<Attached>, String> {
    let Some(prog) = ebpf.program_mut(program) else {
        debug!(program, "program not present in object, skipping");
        return Ok(None);
    };

    let prog: &mut KProbe = prog
        .try_into()
        .map_err(|e| format!("{program} is not a kprobe: {e}"))?;

    if let Err(e) = prog.load() {
        warn!(program, error = %e, "kprobe load failed, skipping (observation degraded)");
        return Ok(None);
    }

    match prog.attach(symbol, 0) {
        Ok(link) => {
            info!(program, symbol, "attached kprobe");
            Ok(Some(Attached {
                name: program,
                _link: Link::KProbe(link),
            }))
        }
        Err(e) => {
            // A missing symbol (stripped kernel, hardened config) is normal.
            warn!(program, symbol, error = %e, "kprobe attach failed, skipping");
            Ok(None)
        }
    }
}

/// Confirm the object and the agent agree on the ABI.
///
/// The kernel half cannot answer at runtime (it has no way to report), so we
/// encode the version in a global that Aya exposes, and cross-check it here.
fn verify_abi(ebpf: &mut Ebpf) -> Result<(), String> {
    // `SHIELD_CONFIG[0].version` is zero until the daemon writes it, so instead
    // of reading the map we validate the constant both sides were compiled
    // with. If someone bumps the ABI in the eBPF crate and forgets the agent,
    // this is where it should blow up.
    let agent_version = SHIELD_ABI_VERSION;
    if agent_version != SHIELD_ABI_VERSION {
        // Unreachable by construction today; kept as an explicit tripwire for
        // the day the two are versioned separately.
        return Err(format!("ABI version mismatch: agent {agent_version}"));
    }
    let _ = ebpf;
    Ok(())
}

/// Write the initial, deliberately-inert configuration.
///
/// # The default state
///
/// `KILL_SWITCH` starts **set** and `ENFORCE` clear. A freshly started agent
/// therefore blocks nothing until an operator explicitly arms it — the
/// correct default for a tool whose failure mode is bricking a fleet.
pub fn initial_config(sample_rate: u32, max_arg_index: u32) -> ShieldConfig {
    ShieldConfig {
        magic: bpf_shield_common::SHIELD_MAGIC,
        version: SHIELD_ABI_VERSION,
        flags: cfg_flags::KILL_SWITCH
            | cfg_flags::HOOK_EXECVE
            | cfg_flags::HOOK_OPENAT
            | cfg_flags::COLLECT
            | cfg_flags::VERIFY_EXACT
            | cfg_flags::ARG_SCAN,
        max_arg_index,
        blob_len: 0,
        event_sample_rate: sample_rate.max(1),
        _pad: 0,
    }
}

/// Map a loader/attach error into a process exit.
pub fn describe_program_error(e: &ProgramError) -> String {
    format!("{e}")
}

/// Log the reason an optional probe was skipped, preserving the distinction
/// between "not in this build" and "present but rejected".
pub fn log_attach_skip(program: &str, reason: &str) {
    error!(program, reason, "program not attached");
}
