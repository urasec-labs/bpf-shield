//! Map definitions shared by every BPF-Shield probe.
//!
//! # Map-type selection is the whole performance story
//!
//! | Map          | Type                   | Why                                                     |
//! |--------------|------------------------|---------------------------------------------------------|
//! | `SHIELD_CONFIG` | `ARRAY` (1 elem)     | Always present. A lookup can *fail*; a security control that can fail open because of a lookup miss is not a control. Also: array updates are a single indivisible value copy, so readers never see a torn config. |
//! | `RULES`      | `HASH` (prealloc)      | O(1) lookup. Preallocation matters: without it the kernel allocates on update, which we would be doing on the control-plane path. |
//! | `RULE_BLOB`  | `ARRAY` of `[u8; 64]` | Fixed-width chunks, see below.                          |
//! | `STATS`      | `PERCPU_ARRAY`         | Non-atomic per-CPU increments: no atomics, no cacheline ping-pong. |
//! | `EVENTS`     | `RINGBUF`              | Single shared buffer, no per-CPU loss, no sampling skew. |
//!
//! ## Why the blob is `[u8; 64]` chunks and not `Array<u8>`
//!
//! `bpf_map_lookup_elem` on an `Array<u8>` hands the verifier a pointer with
//! `mem_size == 1`. Reading 64 bytes from it is rejected, full stop — and the
//! fix (a variable-offset read) reintroduces exactly the unbounded-offset
//! reasoning we are trying to avoid. Giving every map *element* a 64-byte
//! `[u8; 64]` type makes `mem_size == 64`, so a `Rule` name comparison is a
//! provably-bounded access with no extra checks.
//!
//! The cost is that rule names must not straddle a chunk boundary. That is
//! enforced by construction in the daemon: every name is written at
//! `index * 64`.

use aya_ebpf::{
    macros::map,
    maps::{Array, HashMap, PerCpuArray, RingBuf},
};
use bpf_shield_common::{
    Event, Rule, ShieldConfig, StatBlock, MAX_RULES, NAME_HASH_LEN, RULE_BLOB_CHUNKS_LEN,
    RINGBUF_BYTES,
};

/// Number of 64-byte chunks in [`RULE_BLOB`].
///
/// Re-exported from the ABI crate so the kernel and user halves cannot drift.
pub const RULE_BLOB_CHUNKS: u32 = RULE_BLOB_CHUNKS_LEN;

/// Global runtime configuration. One element, index 0.
///
/// Pinned so that it survives an agent restart *and* so that `bpf-shieldctl
/// kill-switch on` can write to it even while the agent is wedged — the one
/// scenario where you most need the off switch.
#[map]
pub static SHIELD_CONFIG: Array<ShieldConfig> = Array::pinned(1, 0);

/// The live policy: `fnv1a64_padded(name)` -> [`Rule`].
///
/// Pinned, so a control-plane restart does not drop protection.
#[map]
pub static RULES: HashMap<u64, Rule> = HashMap::pinned(MAX_RULES, 0);

/// Rule name storage, one name per 64-byte chunk, zero padded.
#[map]
pub static RULE_BLOB: Array<[u8; NAME_HASH_LEN]> = Array::pinned(RULE_BLOB_CHUNKS, 0);

/// Replacement pathname written by the `Sanitize` action (chunk 0).
///
/// Kept as a 16-byte NUL-terminated blob so the write is a single fixed-size
/// `bpf_probe_write_user` — see `events`/`main` for why a variable-length
/// write is not verifier-friendly.
#[map]
pub static SANITIZE_TO: Array<[u8; 16]> = Array::pinned(1, 0);

/// Per-CPU counters, index 0.
#[map]
pub static STATS: PerCpuArray<StatBlock> = PerCpuArray::pinned(1, 0);

/// Security events. 1 MiB = 256 pages, a legal ring buffer geometry.
#[map]
pub static EVENTS: RingBuf = RingBuf::with_byte_size(RINGBUF_BYTES, 0);
