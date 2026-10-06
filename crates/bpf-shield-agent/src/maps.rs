//! Map handles and the policy writer.
//!
//! # The push protocol
//!
//! Updating a live kernel policy is not a single syscall, so it has a failure
//! mode: crash halfway and leave a policy that is *half* the new one. That is
//! survivable — it is still a valid policy, just an incomplete one — but only
//! if we choose the order of operations correctly:
//!
//! 1. **Insert/overwrite every new rule first.** From this instant, the union of
//!    old and new rules is live. Over-blocking is possible but under-blocking is
//!    not, and over-blocking is what the audit-mode gate is for.
//! 2. **Only then delete rules that disappeared.** Deleting first would open a
//!    window in which a rule you *had* is briefly gone — exactly the window an
//!    attacker would time.
//!
//! Each individual `bpf_map_update_elem` is atomic, so a reader never observes
//! a half-written `Rule`. The blob chunks are written *before* the corresponding
//! `Rule` row, so a row never points at unwritten bytes; a reverse ordering
//! would produce exactly the torn-policy case this comment exists to prevent.
//!
//! Enabling enforcement is a separate, final, single-word write to
//! `SHIELD_CONFIG` — so the policy is fully materialised before it can start
//! denying anything.

use std::collections::HashMap;

use aya::{
    maps::{Array, HashMap as UserHashMap, MapData, PerCpuArray, RingBuf},
    Ebpf,
};
use bpf_shield_common::{
    cfg_flags, Action, Event, Rule, Severity, ShieldConfig, StatBlock, MAX_RULES, NAME_HASH_LEN,
    RULE_BLOB_CHUNKS_LEN, RULE_NAME_MAX,
};
use tokio::io::unix::AsyncFd;

use crate::policy::Policy;
use crate::stats::StatsSnapshot;

pub const MAP_CONFIG: &str = "SHIELD_CONFIG";
pub const MAP_RULES: &str = "RULES";
pub const MAP_BLOB: &str = "RULE_BLOB";
pub const MAP_SANITIZE: &str = "SANITIZE_TO";
pub const MAP_STATS: &str = "STATS";
pub const MAP_EVENTS: &str = "EVENTS";

/// Typed handles onto every map in the object.
pub struct Maps {
    config: Array<MapData, ShieldConfig>,
    rules: UserHashMap<MapData, u64, Rule>,
    blob: Array<MapData, [u8; NAME_HASH_LEN]>,
    sanitize: Array<MapData, [u8; 16]>,
    stats: PerCpuArray<MapData, StatBlock>,
    events: Option<RingBuf<MapData>>,
}

impl Maps {
    /// Take ownership of the maps out of a loaded object.
    ///
    /// `take_map` (rather than `map_mut`) moves the `MapData`, which lets the
    /// handles outlive the borrow on [`Ebpf`] and be moved into background
    /// tasks.
    pub fn take(bpf: &mut Ebpf) -> Result<Self, String> {
        fn take<T>(bpf: &mut Ebpf, name: &str) -> Result<T, String>
        where
            T: TryFrom<aya::maps::Map, Error = aya::maps::MapError>,
        {
            let map = bpf
                .take_map(name)
                .ok_or_else(|| format!("object has no map named {name}"))?;
            T::try_from(map).map_err(|e| format!("map {name}: {e}"))
        }

        Ok(Self {
            config: take(bpf, MAP_CONFIG)?,
            rules: take(bpf, MAP_RULES)?,
            blob: take(bpf, MAP_BLOB)?,
            sanitize: take(bpf, MAP_SANITIZE)?,
            stats: take(bpf, MAP_STATS)?,
            events: Some(take(bpf, MAP_EVENTS)?),
        })
    }

    /// Read the current config.
    pub fn config(&self) -> Result<ShieldConfig, String> {
        self.config
            .get(&0, 0)
            .map_err(|e| format!("read {MAP_CONFIG}: {e}"))
    }

    /// Overwrite the config. One atomic `bpf_map_update_elem`.
    pub fn set_config(&mut self, cfg: ShieldConfig) -> Result<(), String> {
        self.config
            .set(0, &cfg, 0)
            .map_err(|e| format!("write {MAP_CONFIG}: {e}"))
    }

    /// Read-modify-write the config flag word under the agent's own mutex.
    ///
    /// `bpf_map_update_elem` on an array map replaces the whole value, so a
    /// read-modify-write is unavoidable. The agent is the only writer during
    /// normal operation (`bpf-shieldctl` writes via the socket), which is what
    /// makes this safe; the pinned config is what makes the emergency path
    /// work when the agent is *not* healthy.
    pub fn mutate_config(
        &mut self,
        f: impl FnOnce(&mut ShieldConfig),
    ) -> Result<ShieldConfig, String> {
        let mut cfg = self.config()?;
        f(&mut cfg);
        self.set_config(cfg)?;
        Ok(cfg)
    }

    /// The kill switch. One `u64` store; safe to call from a wedged agent.
    pub fn kill_switch(&mut self, on: bool) -> Result<ShieldConfig, String> {
        self.mutate_config(|cfg| {
            if on {
                cfg.flags |= cfg_flags::KILL_SWITCH;
                cfg.flags &= !cfg_flags::ENFORCE;
            } else {
                cfg.flags &= !cfg_flags::KILL_SWITCH;
            }
        })
    }

    /// Number of rules currently installed.
    pub fn rule_count(&self) -> Result<usize, String> {
        Ok(self.rules.keys().count())
    }

    /// Replace the live policy.
    ///
    /// See the module docs for why the ordering is add-then-delete.
    pub fn apply_policy(&mut self, policy: &Policy) -> Result<usize, String> {
        if policy.rules.len() > MAX_RULES as usize {
            return Err(format!(
                "policy has {} rules, map holds at most {MAX_RULES}",
                policy.rules.len()
            ));
        }

        let mut wanted: HashMap<u64, ()> = HashMap::with_capacity(policy.rules.len());

        for (idx, spec) in policy.rules.iter().enumerate() {
            let chunk = idx as u32;
            if chunk >= RULE_BLOB_CHUNKS_LEN {
                return Err(format!(
                    "policy exceeds the {RULE_BLOB_CHUNKS_LEN} name slots in the blob map"
                ));
            }

            let mut blob = [0u8; NAME_HASH_LEN];
            let bytes = spec.pattern.as_bytes();
            if bytes.is_empty() {
                return Err(format!("rule {}: empty pattern", spec.id));
            }
            if bytes.len() > RULE_NAME_MAX {
                return Err(format!(
                    "rule {}: pattern is {} bytes, kernel window allows {RULE_NAME_MAX}. \
                     Use `prefix: true` with a shorter pattern, or shorten the rule.",
                    spec.id,
                    bytes.len()
                ));
            }
            blob[..bytes.len()].copy_from_slice(bytes);

            // Blob first. A `Rule` row must never reference unwritten bytes.
            self.blob
                .set(chunk, &blob, 0)
                .map_err(|e| format!("rule {}: write blob: {e}", spec.id))?;

            let hash = spec.hash();
            let rule = Rule {
                hash,
                full_hash: bpf_shield_common::fnv1a64(bytes),
                name_off: chunk * NAME_HASH_LEN as u32,
                name_len: bytes.len() as u16,
                flags: spec.flags(),
                action: spec.action,
                severity: spec.severity,
                errno: spec.errno_code(),
                rule_id: spec.id,
                _pad: [0; 6],
            };

            // Overwrite unconditionally: the previous rule with this hash may
            // have had different metadata (severity, errno, prefix flag).
            self.rules
                .insert(&hash, &rule, 0)
                .map_err(|e| format!("rule {}: insert: {e}", spec.id))?;

            wanted.insert(hash, ());
        }

        // Now drop the rules that are no longer wanted. Collect first: mutating
        // a hash map while iterating its keys is undefined even without unsafe.
        let stale: Vec<u64> = self
            .rules
            .keys()
            .filter_map(|k| k.ok())
            .filter(|k| !wanted.contains(k))
            .collect();
        for key in stale {
            let _ = self.rules.remove(&key);
        }

        self.chunks_in_use = policy.rules.len() as u32;
        Ok(policy.rules.len())
    }

    /// Write the replacement pathname used by the `Sanitize` action.
    pub fn set_sanitize_target(&mut self, path: &str) -> Result<(), String> {
        let mut buf = [0u8; 16];
        let bytes = path.as_bytes();
        if bytes.len() >= buf.len() {
            return Err(format!(
                "sanitize target must be <= {} bytes (incl. NUL)",
                buf.len() - 1
            ));
        }
        buf[..bytes.len()].copy_from_slice(bytes);
        self.sanitize
            .set(0, &buf, 0)
            .map_err(|e| format!("write {MAP_SANITIZE}: {e}"))
    }

    /// Sum the per-CPU counter blocks.
    pub fn read_stats(&self) -> Result<StatsSnapshot, String> {
        let values = self
            .stats
            .get(&0, 0)
            .map_err(|e| format!("read {MAP_STATS}: {e}"))?;

        let mut total = StatBlock::default();
        for cpu in values.iter() {
            total.seen = total.seen.wrapping_add(cpu.seen);
            total.matched = total.matched.wrapping_add(cpu.matched);
            total.blocked = total.blocked.wrapping_add(cpu.blocked);
            total.audited = total.audited.wrapping_add(cpu.audited);
            total.emitted = total.emitted.wrapping_add(cpu.emitted);
            total.ring_drops = total.ring_drops.wrapping_add(cpu.ring_drops);
            total.read_errors = total.read_errors.wrapping_add(cpu.read_errors);
            total.verify_skips = total.verify_skips.wrapping_add(cpu.verify_skips);
            total.bypassed = total.bypassed.wrapping_add(cpu.bypassed);
        }
        Ok(StatsSnapshot::from_stat(&total))
    }

    /// Take the ring buffer out for the event consumer task.
    ///
    /// The `RingBuf` is handed over *whole* rather than borrowed or dup'd,
    /// because a ring buffer's consumer position lives in its mmap: a second
    /// `dup` + `mmap` would silently create an independent cursor and the two
    /// readers would each see half the stream (or, worse, race on the busy
    /// bit). The consumer wraps it in an `AsyncFd`, which only needs `AsRawFd`.
    pub fn take_events(&mut self) -> Result<RingBuf<MapData>, String> {
        self.events
            .take()
            .ok_or_else(|| format!("{MAP_EVENTS} already taken"))
    }
}

/// Human-readable dump of a `Rule`, for `bpf-shieldctl rules`.
pub fn describe_rule(rule: &Rule, blob: Option<&[u8]>) -> String {
    let pattern = blob
        .map(|b| String::from_utf8_lossy(&b[..rule.name_len as usize]).into_owned())
        .unwrap_or_else(|| "<blob evicted>".to_string());
    format!(
        "id={} pattern={:?} action={} severity={} errno={} flags=0x{:x}",
        rule.rule_id,
        pattern,
        Action::as_str(rule.action),
        Severity::as_str(rule.severity),
        rule.errno,
        rule.flags
    )
}

/// Borrow helper used by the CLI when reading a pinned map without the agent.
pub fn map_fd_for(map: &aya::maps::Map) -> Option<std::os::fd::OwnedFd> {
    use std::os::fd::AsRawFd;
    let raw = map.as_raw_fd();
    if raw < 0 {
        return None;
    }
    // SAFETY: `raw` is a live fd owned by `map`; `dup` gives us an independent
    // handle so the borrow ends with `map`.
    Some(unsafe { std::os::fd::OwnedFd::from(std::os::fd::RawFd::from(libc::dup(raw))) })
}

/// Event type alias re-exported for the consumer task.
pub type RingEvent = Event;
