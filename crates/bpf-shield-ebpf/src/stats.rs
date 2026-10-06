//! Per-CPU counters.
//!
//! # Why `PerCpuArray` and not atomics
//!
//! The obvious way to count in BPF is `__sync_fetch_and_add`, which lowers to
//! a locked read-modify-write on a shared cache line. On a 96-core host under
//! a syscall-heavy workload that single line becomes a global serialisation
//! point and the contention alone can cost more CPU than the entire decision
//! path. A `PERCPU_ARRAY` slot belongs to exactly one CPU, so the increment is
//! a plain `add` to a line that core already owns. Summation moves to
//! userspace, where it costs nothing.
//!
//! # Why the increments are `wrapping`
//!
//! A 64-bit counter incremented on a 1 GHz core wraps in ~585 years. If it
//! somehow did, wrapping to zero is strictly better than a debug-build panic
//! inside the kernel.

use crate::maps::STATS;

/// Increment one counter.
macro_rules! bump {
    ($field:ident) => {{
        if let Some(p) = STATS.get_ptr_mut(0) {
            // SAFETY: `get_ptr_mut` returns a pointer to a live map value; the
            // kernel guarantees per-CPU map values stay valid for the duration
            // of the program run and RCU-protects updates against readers.
            // Only this CPU's slot is ever written.
            unsafe {
                let slot = &mut *p;
                slot.$field = slot.$field.wrapping_add(1);
            }
        }
    }};
}

pub(crate) use bump;

/// Snapshot the current CPU's counters. Called once, at the end of a probe.
///
/// The `+` on each field (rather than plain assignment) is deliberate: two
/// probes can be nested on one CPU — e.g. `bprm_check_security` firing while
/// the task is already inside another `execve` tracepoint — and assignment
/// would silently discard the outer probe's contribution.
#[inline(always)]
#[allow(dead_code)]
pub fn snapshot() -> bpf_shield_common::StatBlock {
    let mut out = bpf_shield_common::StatBlock::default();
    if let Some(p) = STATS.get_ptr_mut(0) {
        // SAFETY: see `bump!`.
        unsafe {
            let slot = &*p;
            out.seen = out.seen.wrapping_add(slot.seen);
            out.matched = out.matched.wrapping_add(slot.matched);
            out.blocked = out.blocked.wrapping_add(slot.blocked);
            out.audited = out.audited.wrapping_add(slot.audited);
            out.emitted = out.emitted.wrapping_add(slot.emitted);
            out.ring_drops = out.ring_drops.wrapping_add(slot.ring_drops);
            out.read_errors = out.read_errors.wrapping_add(slot.read_errors);
            out.verify_skips = out.verify_skips.wrapping_add(slot.verify_skips);
            out.bypassed = out.bypassed.wrapping_add(slot.bypassed);
        }
    }
    out
}
