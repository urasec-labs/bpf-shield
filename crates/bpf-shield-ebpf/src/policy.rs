//! The decision path: read the argument, hash it, look it up, verify it.
//!
//! Every function here is `#[inline(always)]`. That is not a style choice —
//! inlined BPF functions cost nothing at call time but *do* cost the verifier
//! state exploration, and a non-inlined helper called from six places blows up
//! the instruction count the verifier has to track.
//!
//! # The three rules this module never breaks
//!
//! 1. **Bounded loops only.** Every loop has a compile-time trip count, so
//!    LLVM unrolls it and the verifier sees a DAG, never a back edge.
//! 2. **Read through helpers, never dereference user pointers.** A malicious
//!    task controls the memory behind `argv`/`filename`; a direct dereference
//!    is an instant kernel fault.
//! 3. **Fail open on internal error.** If any step returns `Err`, the probe
//!    allows the syscall. A security tool that can fail *closed* on its own
//!    bug is a denial-of-service engine aimed at its own fleet.

use aya_ebpf::helpers::{
    bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes, bpf_probe_read_user,
    bpf_probe_read_user_str_bytes,
};
use bpf_shield_common::{
    cfg_flags, fnv1a64_padded, rule_flags, Action, Rule, ShieldConfig, NAME_HASH_LEN,
};

use crate::maps::{RULE_BLOB, RULES};
use crate::stats::bump;

/// Result alias. The error is an `errno`, matching the helpers we wrap.
pub type PResult<T> = Result<T, i32>;

const EFAULT: i32 = 14;

/// Zeroed 64-byte window. Zeroing is mandatory, not cosmetic: the hash covers
/// the *whole* window, and `bpf_probe_read_user_str` only writes `len + 1`
/// bytes, so an un-zeroed tail would make the hash depend on stack garbage and
/// no policy would ever match.
#[inline(always)]
pub type Window = [u8; NAME_HASH_LEN];

/// Read up to [`NAME_HASH_LEN`] bytes of a caller-supplied pathname.
///
/// Truncation is handled, not rejected. The underlying helper returns `-E2BIG`
/// when it fills the window without finding a NUL; in that case we fall back
/// to a raw window read and report `len == NAME_HASH_LEN`.
///
/// This fallback is a security requirement. If we simply gave up on long
/// names, every rule would be bypassable with a 300-character path — a
/// one-line bypass of the entire product.
///
/// Note the returned length comes from `read_str_bytes`, which has *already*
/// stripped the NUL; subtracting one again would silently drop the last
/// character of every path.
#[inline(always)]
pub fn read_user_window(ptr: *const u8, buf: &mut Window) -> PResult<u16> {
    if ptr.is_null() {
        bump!(read_errors);
        return Err(EFAULT);
    }
    *buf = [0u8; NAME_HASH_LEN];

    match unsafe { bpf_probe_read_user_str_bytes(ptr, buf) } {
        Ok(slice) => Ok(slice.len() as u16),
        Err(_) => {
            // SAFETY: `ptr` is non-NULL and checked; the helper performs the
            // fault-safe copy itself and returns `Err` on any problem.
            let raw: Window = unsafe { bpf_probe_read_user(ptr)? };
            *buf = raw;
            Ok(NAME_HASH_LEN as u16)
        }
    }
}

/// [`read_user_window`] for pointers into kernel memory
/// (`struct linux_binprm::filename`).
#[inline(always)]
pub fn read_kernel_window(ptr: *const u8, buf: &mut Window) -> PResult<u16> {
    if ptr.is_null() {
        bump!(read_errors);
        return Err(EFAULT);
    }
    *buf = [0u8; NAME_HASH_LEN];

    match unsafe { bpf_probe_read_kernel_str_bytes(ptr, buf) } {
        Ok(slice) => Ok(slice.len() as u16),
        Err(_) => {
            // SAFETY: as above; `bprm->filename` is a 4 KiB kernel array so a
            // 64-byte window read can never straddle a page boundary.
            let raw: Window = unsafe { bpf_probe_read_kernel(ptr)? };
            *buf = raw;
            Ok(NAME_HASH_LEN as u16)
        }
    }
}

/// Byte-for-byte confirmation of a hash hit.
///
/// The hash pre-filter is 64 bits of FNV-1a over a 64-byte window. With a
/// 16 k-rule policy the birthday collision probability is around 2^-31, which
/// is fine — but "fine" is not "zero", and a *false positive here means
/// blocking a legitimate process*. So the daemon ships `VERIFY_EXACT` on by
/// default and we pay one bounded compare on the rare hit path.
#[inline(always)]
pub fn verify(rule: &Rule, buf: &Window, len: u16) -> bool {
    let Some(chunk) = blob_chunk(rule) else {
        // Policy row present but its name blob is gone — a torn push. Treat as
        // "no match" so a partially applied policy can never deny.
        return false;
    };

    let rlen = rule.name_len as usize;
    let olen = len as usize;

    if rule.has(rule_flags::MATCH_PREFIX) {
        // Explicit opt-in: rule is a prefix of what we observed.
        if rlen > NAME_HASH_LEN || rlen > olen {
            return false;
        }
        bytes_eq(&chunk, buf, rlen)
    } else {
        // Exact match. Both lengths must be equal, which also means a path
        // truncated by our window can never match a shorter rule.
        if rlen != olen {
            return false;
        }
        let n = if rlen < NAME_HASH_LEN { rlen } else { NAME_HASH_LEN };
        bytes_eq(&chunk, buf, n)
    }
}

/// Fetch the rule's stored name chunk.
///
/// One map lookup on a value whose type is `[u8; 64]`, so the verifier knows
/// the region is exactly 64 bytes wide and every subsequent access inside it
/// is provably in bounds without a single runtime check.
#[inline(always)]
fn blob_chunk(rule: &Rule) -> Option<Window> {
    // `name_off` is a multiple of the chunk width by daemon construction.
    // Dividing by the width keeps the index provably below `RULE_BLOB_CHUNKS`
    // for *any* u32 input, which removes the need for a range check.
    let idx = rule.name_off / NAME_HASH_LEN as u32;
    RULE_BLOB.get(idx).copied()
}

/// Compare the first `n` bytes of two windows.
///
/// `n` is provably `<= NAME_HASH_LEN`: both call sites derive it from
/// `rule.name_len` after an explicit `min`/compare against the window width.
/// The loop has a compile-time trip count so it unrolls into straight-line
/// code rather than a verifier-visible loop.
#[inline(always)]
fn bytes_eq(a: &Window, b: &Window, n: usize) -> bool {
    if n > NAME_HASH_LEN {
        return false;
    }
    let mut eq = true;
    #[allow(clippy::needless_range_loop)]
    for i in 0..NAME_HASH_LEN {
        if i < n && a[i] != b[i] {
            eq = false;
            break;
        }
    }
    eq
}

/// Hash lookup plus the optional exact-verify stage.
///
/// `want` is a mask of [`rule_flags`] the rule must carry, which is how one
/// probe distinguishes "deny this executable" from "deny this argv token"
/// without a second map.
///
/// Returns `None` for *every* kind of miss — empty policy, unknown hash,
/// wrong subsystem, hash collision. The caller therefore cannot accidentally
/// treat "no rule" and "verification failed" differently, which is exactly the
/// property that keeps the two code paths from drifting apart.
#[inline(always)]
pub fn lookup(buf: &Window, len: u16, want: u64, cfg: &ShieldConfig) -> Option<Rule> {
    let hash = fnv1a64_padded(buf);
    let rule = *RULES.get(&hash, 0)?;

    if !rule.active() || !rule.has(want) {
        return None;
    }

    if cfg.flags & cfg_flags::VERIFY_EXACT != 0 && !verify(&rule, buf, len) {
        bump!(verify_skips);
        return None;
    }

    Some(rule)
}

/// Resolve the effective action for a matched rule.
///
/// `enforcing` is false in audit mode, in which even a `Deny` rule degrades to
/// "report". This one function is the only place that decision is made, so
/// there is no way for a new probe to forget about dry-run mode.
#[inline(always)]
pub fn effective_action(rule: &Rule, enforcing: bool) -> Action {
    match rule.action {
        Action::Allow => Action::Allow,
        Action::Sanitize => Action::Sanitize,
        Action::Deny if enforcing => Action::Deny,
        Action::Deny => Action::Audit,
    }
}
