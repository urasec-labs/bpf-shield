//! Ring-buffer event emission.
//!
//! # Why the event is written straight into the reservation
//!
//! The obvious implementation builds an [`Event`] on the stack and calls
//! `RingBuf::output`. That costs a full 192-byte stack frame *plus* a memcpy
//! inside a syscall hot path, and the eBPF stack is capped at 512 bytes — so
//! two concurrent probes would risk `RSTACK` verifier rejections.
//!
//! Instead we reserve the slot first and write into it in place. Stack usage
//! drops to nothing and the copy disappears. The price is `addr_of_mut!`
//! discipline: we take raw pointers into possibly-uninitialised memory and
//! never form a reference to it, because `MaybeUninit` provenance rules make
//! that UB and the verifier is entitled to reject it.
//!
//! # Why a dropped event never blocks a decision
//!
//! If `bpf_ringbuf_reserve` returns NULL (buffer full, or consumer not
//! draining) we increment `ring_drops` and return. The caller has *already*
//! made its enforcement decision by this point. Losing telemetry must never
//! degrade into losing enforcement — and it must never turn into a spin loop,
//! which in a syscall context is a host-level DoS.

use core::ptr::{addr_of_mut, copy_nonoverlapping};

use aya_ebpf::helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid};
use bpf_shield_common::{Action, Event, Hook, ShieldConfig, NAME_HASH_LEN};

use crate::maps::EVENTS;
use crate::stats::bump;

/// `bpf_get_prandom_u32`, pulled in from the raw bindings.
#[inline(always)]
fn prandom() -> u32 {
    // SAFETY: takes no arguments and cannot fail; it is documented to be
    // available to every tracing program type.
    unsafe { aya_ebpf::helpers::bpf_get_prandom_u32() }
}

/// Length of a NUL-padded fixed array, bounded by the array width.
#[inline(always)]
fn nul_len<const N: usize>(buf: &[u8; N]) -> u8 {
    let mut n = 0usize;
    #[allow(clippy::needless_range_loop)]
    for i in 0..N {
        if buf[i] == 0 {
            break;
        }
        n = i + 1;
    }
    n as u8
}

/// Publish one security event.
///
/// `target` is the already-read window; `len` its true length (which may exceed
/// `NAME_HASH_LEN` when the caller fell back to a truncated raw read).
#[inline(always)]
pub fn emit(
    cfg: &ShieldConfig,
    hook: Hook,
    rule_id: u32,
    action: Action,
    errno: i32,
    target: &[u8; NAME_HASH_LEN],
    len: u16,
    full_hash: u64,
) {
    if cfg.flags & bpf_shield_common::cfg_flags::COLLECT == 0 {
        return;
    }

    // Sampling. Rate 0 disables, 1 keeps everything. Deliberately a modulo of
    // the PRNG rather than a counter so that sampling does not correlate with
    // burst traffic patterns in a way an attacker could predict and exploit.
    let rate = cfg.event_sample_rate;
    if rate > 1 && prandom() % rate != 0 {
        return;
    }

    let Some(mut slot) = EVENTS.reserve::<Event>(0) else {
        bump!(ring_drops);
        return;
    };

    // SAFETY: `reserve` guarantees `slot` points at `size_of::<Event>()` bytes
    // of ring-buffer memory owned exclusively by this CPU until `submit` (or
    // `discard`). Every write below is within that window and 8-byte aligned,
    // which is exactly what the verifier tracked at reserve time.
    unsafe {
        let p: *mut Event = slot.as_mut_ptr();

        // SAFETY: fresh reservation, so initialising fields in place is fine.
        (*p).ts_ns = aya_ebpf::helpers::bpf_ktime_get_boot_ns();
        (*p).tail_hash = full_hash;

        let captured = if (len as usize) < NAME_HASH_LEN {
            len as usize
        } else {
            NAME_HASH_LEN
        };
        copy_nonoverlapping(
            target.as_ptr(),
            addr_of_mut!((*p).target).cast::<u8>(),
            captured,
        );
        // Zero the unused tail so that two events with the same prefix are
        // byte-identical — this keeps ring-buffer deduplication in the daemon
        // trivially correct.
        let mut i = captured;
        while i < bpf_shield_common::EVENT_TARGET_MAX {
            addr_of_mut!((*p).target).cast::<u8>().add(i).write(0);
            i += 1;
        }
        (*p).target_len = captured as u16;

        let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
        (*p).comm_len = nul_len(&comm);
        copy_nonoverlapping(comm.as_ptr(), addr_of_mut!((*p).comm).as_mut_ptr(), 16);

        let pt = bpf_get_current_pid_tgid();
        (*p).tgid = (pt >> 32) as u32;
        (*p).pid = (pt & 0xffff_ffff) as u32;

        let uid_gid = bpf_get_current_uid_gid();
        (*p).uid = (uid_gid >> 32) as u32;
        (*p).gid = (uid_gid & 0xffff_ffff) as u32;

        (*p).cpu = aya_ebpf::helpers::bpf_get_smp_processor_id();
        (*p).hook = hook.as_u32();
        (*p).action = action.as_u8() as u32;
        (*p).rule_id = rule_id;
        (*p).errno = errno;
        (*p)._pad = [0u8; 9];
    }

    slot.submit(0);
    bump!(emitted);
}
