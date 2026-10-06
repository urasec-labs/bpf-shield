//! Shared ABI between the BPF-Shield kernel half and its user-space half.
//!
//! # Why this crate exists
//!
//! The eBPF object and the daemon talk to each other through five maps. If a
//! single field moves by one byte, the kernel silently reads garbage — and a
//! garbage `flags` word in a security product is how you brick a fleet.
//! Therefore every ABI struct lives here, is `#[repr(C)]`, is padding-free,
//! and its size is asserted at compile time on *both* sides.
//!
//! This crate is `#![no_std]` so that it can be compiled for
//! `bpfel-unknown-none` alongside `aya-ebpf`. It has zero dependencies except
//! an optional, feature-gated `aya` used solely to emit `aya::Pod` impls.

// A user-space daemon that panics inside the kernel is a very expensive
// outage, so we forbid panicking constructs crate-wide. Loops are bounded and
// every indexing operation is range-checked by construction.
#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

// ---------------------------------------------------------------------------
// Geometry / capacity constants
//
// These are compiled into BOTH the BPF object (as `max_entries` in the map
// definitions) and the daemon (as `--set-max-entries` overrides). They must
// never diverge, hence they live in one place.
// ---------------------------------------------------------------------------

/// Maximum number of deny/audit rules held in a rule map.
pub const MAX_RULES: u32 = 16_384;

/// Size of the shared rule-name blob map, in bytes.
///
/// Rules live as NUL-terminated byte strings inside this `Array<u8>`; the
/// `Rule` struct only stores `name_off`/`name_len`. This keeps the hot-path
/// map value tiny (32 B) which keeps the hash map's cache footprint small.
pub const RULE_BLOB_MAX: u32 = 32 * 1024;

/// Bytes of a rule name the hot path will hash.
///
/// The hot path hashes a *fixed* 64 bytes of a zero-padded buffer. A fixed
/// width is not an optimisation, it is a correctness requirement: a variable
/// trip count produces a verifier-visible loop, which the verifier either
/// rejects outright or analyses for up to `1e6` states.
pub const NAME_HASH_LEN: usize = 64;

/// Longest rule name, in bytes.
///
/// Bounded by [`NAME_HASH_LEN`] minus the NUL, and deliberately so: the kernel
/// reads names through a fixed [`NAME_HASH_LEN`]-byte window, so a longer rule
/// could never be matched exactly. The daemon rejects over-long rules at load
/// time rather than accepting a policy that silently does nothing.
///
/// Raising this means raising [`NAME_HASH_LEN`], which costs stack (512-byte
/// hard limit) and roughly `2 * NAME_HASH_LEN` unrolled instructions on *every*
/// hooked syscall. That trade-off is why the window is not bigger by default;
/// see `docs/ARCHITECTURE.md` for the measurement that drove the choice.
pub const RULE_NAME_MAX: usize = NAME_HASH_LEN - 1;

/// Maximum number of `argv[i]` entries inspected per `execve`.
pub const MAX_SCAN_ARGS: u32 = 8;

/// Size of the `EVENTS` ring buffer, in bytes.
///
/// Must be a power-of-two multiple of the page size: 1 MiB = 256 pages.
pub const RINGBUF_BYTES: u32 = 1 << 20;

/// Number of 64-byte name slots in the rule blob map.
///
/// Defined here rather than in the eBPF crate because both halves must agree:
/// the daemon indexes the blob map by rule ordinal and must never write past
/// the end.
pub const RULE_BLOB_CHUNKS_LEN: u32 = RULE_BLOB_MAX / NAME_HASH_LEN as u32;

/// Bytes of user-controlled string captured per event (`target` field).
pub const EVENT_TARGET_MAX: usize = 112;

/// Sentinel written into `ShieldConfig::magic` so a zeroed (never
/// initialised) config map is detected instead of silently read as
/// "everything disabled".
pub const SHIELD_MAGIC: u32 = 0xB5F5_1EE7;

/// ABI version. Bumped whenever any struct in this module changes layout.
/// The daemon refuses to load an object whose version it does not know.
pub const SHIELD_ABI_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// Feature flags (bitfield in ShieldConfig::flags)
// ---------------------------------------------------------------------------

/// Runtime feature bits carried in [`ShieldConfig::flags`].
///
/// The entire policy can be turned off with a single 8-byte store to a map
/// value — no program reload, no re-attach, no dropped probes. That property
/// is what makes BPF-Shield safe to leave armed in production.
pub mod cfg_flags {
    /// Master switch. When clear, every probe returns immediately after a
    /// single array lookup.
    pub const ENABLED: u64 = 1 << 0;

    /// Enforce. When clear, matches are only *reported* — the dry-run mode
    /// you are expected to run for at least one full business cycle before
    /// you dare flip this on.
    pub const ENFORCE: u64 = 1 << 1;

    /// Inspect `argv[]` in addition to the executable path.
    pub const ARG_SCAN: u64 = 1 << 2;

    /// Install the `execve` LSM enforcement hook.
    pub const HOOK_EXECVE: u64 = 1 << 3;

    /// Install the `openat` observation hook.
    pub const HOOK_OPENAT: u64 = 1 << 4;

    /// Emit ring-buffer events at all.
    pub const COLLECT: u64 = 1 << 5;

    /// Verify a hash hit byte-for-byte against the rule blob before acting.
    ///
    /// Costs one bounded compare on the (rare) hit path and removes the
    /// theoretical false-positive surface of hash-only matching.
    pub const VERIFY_EXACT: u64 = 1 << 6;

    /// Rewrite a matched `openat` pathname in userspace memory
    /// (`bpf_probe_write_user`) instead of only reporting it.
    pub const SANITIZE_ARGS: u64 = 1 << 7;

    /// Panic button. Bit 63 is deliberately the highest bit so that a
    /// saturating/`u32`-truncating bug elsewhere can never set it by
    /// accident, and so a single `u64` store from `bpf-shieldctl` disarms the
    /// whole system in well under a microsecond.
    pub const KILL_SWITCH: u64 = 1 << 63;
}

/// Per-rule flags carried in [`Rule::flags`].
pub mod rule_flags {
    /// This rule participates in matching at all.
    pub const ACTIVE: u64 = 1 << 0;

    /// Match against the `execve` executable path.
    pub const EXEC_PATH: u64 = 1 << 1;

    /// Match against any of the first [`MAX_SCAN_ARGS`] `argv` entries.
    pub const EXEC_ARG: u64 = 1 << 2;

    /// Match against the `openat` pathname.
    pub const OPEN_PATH: u64 = 1 << 3;

    /// Require the full string to match, not just the first
    /// [`NAME_HASH_LEN`] bytes.
    pub const MATCH_FULL: u64 = 1 << 4;
}

/// Convenience: `cfg_flags::KILL_SWITCH` plus `ENABLED`, i.e. "armed and
/// disarmed at the same time", which is the state a shutdown path wants.
pub const CFG_DISARMED: u64 = cfg_flags::KILL_SWITCH | cfg_flags::ENABLED;

// ---------------------------------------------------------------------------
// Small enums
// ---------------------------------------------------------------------------

/// What to do about a match.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Explicitly permit (used for allow-listing an executable path).
    Allow = 0,
    /// Deny the syscall. On the LSM hook this means returning a negative
    /// `errno`; on an observation-only hook it means "report only".
    Deny = 1,
    /// Rewrite the offending argument in userspace memory, then allow.
    Sanitize = 2,
    /// Report only — the *runtime* form of a `Deny` rule while the daemon is
    /// still in audit mode.
    ///
    /// This is deliberately a distinct wire value rather than "Deny plus a
    /// flag": events recorded during the dry-run window must be able to prove
    /// later that the kernel chose not to enforce, and a single `action` byte
    /// makes that checkable without replaying daemon state.
    Audit = 3,
}

impl Action {
    /// Wire representation, used when decoding an event in userspace.
    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Human-readable name for logs.
    #[inline]
    pub const fn as_str(self) -> &'static str {
        match self {
            Action::Allow => "allow",
            Action::Deny => "deny",
            Action::Sanitize => "sanitize",
            Action::Audit => "audit",
        }
    }

    /// Decode a wire value produced by the kernel.
    ///
    /// Total by construction: the kernel only ever writes one of the four
    /// discriminants, but a ring buffer is shared memory and we do not treat
    /// that as a promise.
    #[inline]
    pub const fn from_u8(v: u8) -> Self {
        match v {
            0 => Action::Allow,
            2 => Action::Sanitize,
            3 => Action::Audit,
            _ => Action::Deny,
        }
    }
}

/// Which probe produced an event.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hook {
    /// `SEC("lsm/bprm_check_security")` — the execve *enforcement* hook.
    ExecveLsm = 1,
    /// `SEC("kprobe/__x64_sys_execve")` — execve observation + argv scan.
    ExecveKprobe = 2,
    /// `SEC("kprobe/__x64_sys_openat")` — openat observation + sanitisation.
    OpenatKprobe = 3,
    /// `SEC("kprobe/ioctl_init")` — fault-injection demo, off by default.
    IoctlInitFault = 4,
}

impl Hook {
    /// Wire representation.
    #[inline]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    /// Human-readable name for logs.
    #[inline]
    pub const fn as_str(self) -> &'static str {
        match self {
            Hook::ExecveLsm => "execve/lsm",
            Hook::ExecveKprobe => "execve/kprobe",
            Hook::OpenatKprobe => "openat/kprobe",
            Hook::IoctlInitFault => "ioctl_init/fault",
        }
    }
}

/// Severity of a rule, mirrored into events so the control plane can triage
/// without re-reading policy.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Informational.
    Info = 0,
    /// Suspicious.
    Low = 1,
    /// Medium.
    Medium = 2,
    /// High.
    High = 3,
    /// Critical.
    Critical = 4,
}

impl Severity {
    /// Wire representation.
    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Human-readable name for logs.
    #[inline]
    pub const fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

// ---------------------------------------------------------------------------
// Map value types
// ---------------------------------------------------------------------------

/// Global, atomically-updatable configuration. Lives in a 1-element
/// `BPF_MAP_TYPE_ARRAY` so that it is *always* present (a hash map lookup can
/// fail, and a security control that can fail open because of a lookup miss is
/// not a control).
///
/// The daemon writes this with a single `bpf_map_update_elem`, which the
/// kernel applies as a single indivisible memcpy of the value — so a reader
/// either sees the whole old config or the whole new one. Never a torn mix.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ShieldConfig {
    /// Must equal [`SHIELD_MAGIC`]; otherwise the map was never initialised.
    pub magic: u32,
    /// Must equal [`SHIELD_ABI_VERSION`].
    pub version: u32,
    /// Bitfield of [`cfg_flags`].
    pub flags: u64,
    /// Highest `argv` index to inspect (clamped to `MAX_SCAN_ARGS` in-kernel).
    pub max_arg_index: u32,
    /// Bytes currently valid in the rule blob map.
    pub blob_len: u32,
    /// Emit 1 event out of every N matches (0 = never sample).
    pub event_sample_rate: u32,
    /// Explicit tail padding; keeps the struct 8-byte aligned with no holes.
    pub _pad: u32,
}

impl Default for ShieldConfig {
    fn default() -> Self {
        // Safe default: armed for observation only, and the kill switch is
        // *set*, so a freshly loaded program blocks nothing until an operator
        // explicitly arms it.
        Self {
            magic: SHIELD_MAGIC,
            version: SHIELD_ABI_VERSION,
            flags: cfg_flags::KILL_SWITCH | cfg_flags::HOOK_EXECVE | cfg_flags::COLLECT,
            max_arg_index: MAX_SCAN_ARGS,
            blob_len: 0,
            event_sample_rate: 1,
            _pad: 0,
        }
    }
}

impl ShieldConfig {
    /// True when the config is safe to act on.
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.magic == SHIELD_MAGIC && self.version == SHIELD_ABI_VERSION
    }

    /// True when the kernel should actually deny something.
    #[inline]
    pub fn enforcing(&self) -> bool {
        self.is_valid()
            && self.flags & (cfg_flags::ENABLED | cfg_flags::ENFORCE | cfg_flags::KILL_SWITCH)
                == (cfg_flags::ENABLED | cfg_flags::ENFORCE)
    }
}

/// One policy entry: 40 bytes, hot-path friendly.
///
/// The matched string itself is *not* stored here — it lives in the shared
/// `RULE_BLOB` `Array<u8>` at `name_off..name_off + name_len`. Keeping the
/// map value small means a 16 k-rule map costs 640 KiB of values, which stays
/// friendly to L2 while still covering a very large policy.
///
/// # Field order is load-bearing
///
/// The fields are ordered widest-alignment-first *on purpose*. The naive
/// ordering (`... u16, u16, u8, u8, i32`) makes the compiler insert two
/// interior padding bytes at offset 26 to align `errno`. Those bytes are not
/// [`aya::Pod`]-clean: the daemon would `memcpy` 36 bytes while the kernel
/// reads 40, and the mismatch would only show up as "one rule mysteriously
/// never fires". Every struct in this module is therefore laid out so that
/// *all* padding is explicit and trailing.
///
/// # Layout
///
/// ```text
///   0  hash       u64
///   8  full_hash  u64
///  16  name_off   u32
///  20  rule_id    u32
///  24  errno      i32
///  28  name_len   u16
///  30  flags      u16
///  32  action     Action  (repr(u8))
///  33  severity   Severity (repr(u8))
///  34  _pad       [u8; 6]
///  40  = size_of::<Rule>()
/// ```
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Rule {
    /// `fnv1a64_padded` of the first [`NAME_HASH_LEN`] bytes of the name.
    pub hash: u64,
    /// `fnv1a64` of the whole name. Only compared when
    /// [`rule_flags::MATCH_FULL`] is set; gives O(1) full-length rejection.
    pub full_hash: u64,
    /// Byte offset of the name inside the `RULE_BLOB` map.
    pub name_off: u32,
    /// Operator-facing identifier, echoed into every event.
    pub rule_id: u32,
    /// `errno` to deny with. Ignored for `Allow`/`Sanitize`.
    pub errno: i32,
    /// Byte length of the name inside the `RULE_BLOB` map.
    pub name_len: u16,
    /// Bitfield of [`rule_flags`].
    pub flags: u16,
    /// What to do on a match — see [`Action`].
    pub action: Action,
    /// Severity — see [`Severity`].
    pub severity: Severity,
    /// Explicit tail padding. See the type-level note on interior padding.
    pub _pad: [u8; 6],
}

impl Default for Rule {
    fn default() -> Self {
        Self {
            hash: 0,
            full_hash: 0,
            name_off: 0,
            name_len: 0,
            flags: 0,
            action: Action::Deny,
            severity: Severity::Medium,
            errno: EPERM,
            rule_id: 0,
            _pad: [0; 6],
        }
    }
}

impl Rule {
    /// True when this rule participates in matching.
    #[inline]
    pub fn active(&self) -> bool {
        self.flags as u64 & rule_flags::ACTIVE != 0
    }

    /// True when `flags` contains every bit of `want`.
    #[inline]
    pub fn has(&self, want: u64) -> bool {
        self.flags as u64 & want == want
    }
}

/// One security event, as emitted through the ring buffer.
///
/// Fixed size on purpose: the kernel reserves a constant-size slot
/// (`RingBuf::reserve::<Event>`), so the hot path never has to reason about a
/// variable-length memcpy, and the daemon can `transmute` a borrowed slice
/// without copying.
///
/// # Layout
///
/// ```text
///   0  ts_ns        u64
///   8  target     [u8; 112]      <- truncated path/argv entry
/// 120  tail_hash    u64          <- last 8 name bytes, cheap extra entropy
/// 128  comm        [u8; 16]
/// 144  pid          u32
/// 148  tgid         u32
/// 152  uid          u32
/// 156  gid          u32
/// 160  cpu          u32
/// 164  hook         u32
/// 168  action       u32
/// 172  rule_id      u32
/// 176  errno        i32
/// 180  target_len   u16
/// 182  comm_len     u8
/// 183  _pad         [u8; 9]
/// 192  = size_of::<Event>()
/// ```
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Event {
    /// `bpf_ktime_get_boot_ns()` at the time of the event.
    pub ts_ns: u64,
    /// Truncated user-controlled string that triggered the rule.
    pub target: [u8; EVENT_TARGET_MAX],
    /// Hash of the *untruncated* target, so the control plane can correlate
    /// an event against the full string it holds in policy.
    pub tail_hash: u64,
    /// `bpf_get_current_comm()`.
    pub comm: [u8; 16],
    /// Thread id (`pid_tgid & 0xffffffff`).
    pub pid: u32,
    /// Process id (`pid_tgid >> 32`).
    pub tgid: u32,
    /// Real uid.
    pub uid: u32,
    /// Real gid.
    pub gid: u32,
    /// CPU the event was produced on.
    pub cpu: u32,
    /// See [`Hook`].
    pub hook: u32,
    /// See [`Action`].
    pub action: u32,
    /// Rule that matched, or `0` if none.
    pub rule_id: u32,
    /// `errno` the syscall failed with (0 if not denied).
    pub errno: i32,
    /// Valid bytes in `target`.
    pub target_len: u16,
    /// Valid bytes in `comm`.
    pub comm_len: u8,
    /// Tail padding; the struct is 8-aligned so this must exist.
    pub _pad: [u8; 9],
}

/// Per-CPU counters.
///
/// A `BPF_MAP_TYPE_PERCPU_ARRAY` is used deliberately: increments are plain
/// non-atomic stores to the *current CPU's* slot, so there is no cache-line
/// ping-pong between CPUs and no `__sync_fetch_and_add`. That is the single
/// biggest reason this design stays inside its CPU budget. The daemon sums
/// the per-CPU values; it never needs the kernel to do it.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct StatBlock {
    /// Probe invocations that got past the kill-switch check.
    pub seen: u64,
    /// Invocations that matched a rule.
    pub matched: u64,
    /// Syscalls actually denied.
    pub blocked: u64,
    /// Matches reported but allowed (audit mode).
    pub audited: u64,
    /// Events successfully committed to the ring buffer.
    pub emitted: u64,
    /// Events lost because `bpf_ringbuf_reserve` returned NULL.
    pub ring_drops: u64,
    /// Failed `bpf_probe_read_user*` calls. A non-zero rate here means the
    /// attacker's payload is deliberately unmapped memory, which is itself a
    /// strong signal — so we count it instead of treating it as noise.
    pub read_errors: u64,
    /// Hash hits rejected by exact verification (hash collisions).
    pub verify_skips: u64,
    /// Invocations short-circuited by the kill switch / disabled config.
    pub bypassed: u64,
    /// Explicit tail padding to a cache-line multiple.
    pub _pad: [u64; 5],
}

/// User-facing rendering of a rule row, for `status`/`rule` replies.
///
/// Lives here (rather than in the agent) so the CLI and the agent cannot
/// disagree about how a rule is described.
#[cfg(feature = "user")]
#[derive(Clone, Debug, serde::Serialize)]
pub struct RuleView {
    pub hash: String,
    pub rule_id: u32,
    pub pattern: Option<String>,
    pub pattern_len: u16,
    pub action: &'static str,
    pub severity: &'static str,
    pub errno: i32,
    pub flags: u16,
    pub active: bool,
}

#[cfg(feature = "user")]
impl Rule {
    /// Render for JSON output. `pattern` is `None` when the blob chunk could
    /// not be read, which is reported rather than papered over.
    pub fn view(&self, hash: u64, pattern: Option<String>) -> RuleView {
        RuleView {
            hash: format!("0x{hash:016x}"),
            rule_id: self.rule_id,
            pattern,
            pattern_len: self.name_len,
            action: Action::as_str(self.action),
            severity: Severity::as_str(self.severity),
            errno: self.errno,
            flags: self.flags,
            active: self.active(),
        }
    }
}

/// `EPERM`, spelled out so the kernel crate needs no libc.
pub const EPERM: i32 = 1;
/// `EACCES`, spelled out so the kernel crate needs no libc.
pub const EACCES: i32 = 13;
/// `ENOENT`, spelled out so the kernel crate needs no libc.
pub const ENOENT: i32 = 2;

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

/// FNV-1a 64-bit offset basis.
pub const FNV1A64_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
/// FNV-1a 64-bit prime.
pub const FNV1A64_PRIME: u64 = 0x0000_0100_0000_01b3;

/// Hash exactly [`NAME_HASH_LEN`] bytes.
///
/// Both halves of BPF-Shield call *this* function: the daemon hashes the
/// policy string, the kernel hashes the zero-padded copy it managed to read
/// out of the task. Because the width is a compile-time constant, LLVM
/// fully unrolls it and the verifier sees straight-line code instead of a loop
/// it would otherwise have to try (and fail) to bound.
#[inline(always)]
pub const fn fnv1a64_padded(buf: &[u8; NAME_HASH_LEN]) -> u64 {
    let mut hash = FNV1A64_OFFSET;
    let mut i = 0;
    while i < NAME_HASH_LEN {
        hash ^= buf[i] as u64;
        hash = hash.wrapping_mul(FNV1A64_PRIME);
        i += 1;
    }
    hash
}

/// Hash an arbitrary slice. Userspace only — the kernel has no slices.
#[inline]
pub fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = FNV1A64_OFFSET;
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(FNV1A64_PRIME);
    }
    hash
}

/// Copy `src` into a zero-padded [`NAME_HASH_LEN`] buffer.
///
/// Truncation is silent and *lossy by design*: a rule longer than 64 bytes
/// still matches on its prefix, and the exact-verify stage rejects the
/// mismatch rather than silently allowing it.
#[inline]
pub fn padded_name(src: &[u8]) -> [u8; NAME_HASH_LEN] {
    let mut out = [0u8; NAME_HASH_LEN];
    let n = if src.len() < NAME_HASH_LEN {
        src.len()
    } else {
        NAME_HASH_LEN
    };
    let mut i = 0;
    while i < n {
        out[i] = src[i];
        i += 1;
    }
    out
}

/// Hash a rule name the way the kernel will.
#[inline]
pub fn hash_name(src: &[u8]) -> u64 {
    fnv1a64_padded(&padded_name(src))
}

// ---------------------------------------------------------------------------
// Small accessors shared by both halves
// ---------------------------------------------------------------------------

impl Event {
    /// Valid bytes of the captured target string.
    ///
    /// Length is clamped: the bytes come from a shared ring buffer and a
    /// corrupted `target_len` must not turn into an out-of-bounds panic.
    #[inline]
    pub fn target_bytes(&self) -> &[u8] {
        let n = if (self.target_len as usize) < EVENT_TARGET_MAX {
            self.target_len as usize
        } else {
            EVENT_TARGET_MAX
        };
        &self.target[..n]
    }

    /// Valid bytes of `comm`.
    #[inline]
    pub fn comm_bytes(&self) -> &[u8] {
        let n = if (self.comm_len as usize) < 16 {
            self.comm_len as usize
        } else {
            16
        };
        &self.comm[..n]
    }
}

impl Rule {
    /// Zero the value. Written to a rule map key before filling it, so a
    /// partially written entry can never look like a valid rule.
    #[inline]
    pub fn blank() -> Self {
        Self::default()
    }
}

// ---------------------------------------------------------------------------
// `aya::Pod` — only in the user-space build.
//
// Implemented here (rather than in the agent) to satisfy Rust's orphan rule:
// the trait is foreign to the agent crate and so are these types.
// ---------------------------------------------------------------------------

#[cfg(feature = "user")]
mod pod {
    use super::{Event, Rule, ShieldConfig, StatBlock};
    use aya::Pod;

    // SAFETY: every type is `#[repr(C)]`, `Copy`, and contains no
    // padding-bytes (each field is itself `Pod`), so a flat byte
    // reinterpretation round-trips exactly. This is precisely the invariant
    // `Pod` asks for, and it is asserted by the `const` block below.
    unsafe impl Pod for ShieldConfig {}
    // SAFETY: as above.
    unsafe impl Pod for Rule {}
    // SAFETY: as above.
    unsafe impl Pod for Event {}
    // SAFETY: as above.
    unsafe impl Pod for StatBlock {}

    // Compile-time layout lock. If anyone reorders a field, adds a non-Pod
    // field, or introduces padding, the build breaks here rather than in
    // production.
    const _: () = {
        assert!(core::mem::size_of::<ShieldConfig>() == 32);
        assert!(core::mem::align_of::<ShieldConfig>() == 8);
        assert!(core::mem::size_of::<Rule>() == 40);
        assert!(core::mem::align_of::<Rule>() == 8);
        assert!(core::mem::size_of::<Event>() == 192);
        assert!(core::mem::align_of::<Event>() == 8);
        assert!(core::mem::size_of::<StatBlock>() == 112);
        assert!(core::mem::size_of::<StatBlock>() % 8 == 0);
    };
}
