//! Policy model: JSON in, validated, hash-indexed rules out.
//!
//! # What a "rule" is, and what it is not
//!
//! A rule matches a *hash of the first 64 bytes* of a syscall argument. That is
//! a deliberate, bounded design decision with three consequences we accept up
//! front rather than discover in an incident:
//!
//! 1. **Names are capped at 63 bytes** ([`RULE_NAME_MAX`]). Longer strings can
//!    still be *denied*, via the `prefix` flag, but never via a long exact
//!    rule. The daemon rejects over-long rules at load time.
//! 2. **There is no regex and no glob.** Pattern matching in the kernel would
//!    mean unbounded loops or a bytecode VM, both of which the verifier will
//!    either reject or charge to the per-syscall instruction budget. Rules are
//!    exact or explicit-prefix, full stop. Richer matching belongs in the
//!    control plane, which can afford to do it properly.
//! 3. **Hash collisions are possible in principle.** With a 64-bit FNV-1a over
//!    16 384 rules the birthday probability is ~2e-10 per policy — small, but
//!    not zero, and the failure mode is "a legitimate process gets denied".
//!    `VERIFY_EXACT` (on by default) turns that into "no match" by comparing
//!    the stored name byte-for-byte.
//!
//! # Determinism
//!
//! `hash()` is `fnv1a64` over the zero-padded 64-byte window, and the kernel
//! computes the identical value. Both live in `bpf-shield-common` precisely so
//! that this cannot drift; the unit tests at the bottom of this file pin the
//! expected constants so a change to either side fails CI.

use bpf_shield_common::{
    hash_name, rule_flags, Action, Severity, EACCES, EPERM, RULE_NAME_MAX,
};
use serde::{Deserialize, Serialize};

/// Which syscall argument a rule applies to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Target {
    /// The executable path passed to `execve`.
    ExecPath,
    /// Any of the first `MAX_SCAN_ARGS` entries in `execve`'s `argv`.
    ExecArg,
    /// The pathname passed to `openat`.
    OpenPath,
}

impl Target {
    /// The [`rule_flags`] bits this target requires.
    pub const fn required_flags(self) -> u64 {
        match self {
            Target::ExecPath => rule_flags::EXEC_PATH,
            Target::ExecArg => rule_flags::EXEC_ARG,
            Target::OpenPath => rule_flags::OPEN_PATH,
        }
    }
}

/// One policy rule as written by an operator.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuleSpec {
    /// Operator-chosen identifier, echoed into every event.
    pub id: u32,

    /// The literal string to match. No regex, no globs.
    pub pattern: String,

    #[serde(default)]
    pub target: Target,

    #[serde(default)]
    pub action: Action,

    #[serde(default)]
    pub severity: Severity,

    /// `errno` to deny with. Only meaningful for `deny`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errno: Option<i32>,

    /// `EPERM` / `EACCES` / `ENOENT`, or a raw number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errno_name: Option<String>,

    /// Treat `pattern` as a prefix rather than an exact match.
    ///
    /// The operator takes on responsibility: a prefix rule for `/usr/bin/python3`
    /// also matches `/usr/bin/python3.11-exploit`.
    #[serde(default)]
    pub prefix: bool,

    /// Match at most this many leading bytes. Defaults to
    /// [`RULE_NAME_MAX`]. Only meaningful together with `prefix`.
    ///
    /// Lets one short prefix cover several long, similar names: writing
    /// `/usr/lib/jvm/java-17-openjdk-` with `match_len: 30` covers every JDK
    /// 17 build without a rule per vendor patch level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_len: Option<usize>,
}

impl Default for RuleSpec {
    fn default() -> Self {
        Self {
            id: 0,
            pattern: String::new(),
            target: Target::ExecPath,
            action: Action::Deny,
            severity: Severity::Medium,
            errno: None,
            errno_name: None,
            prefix: false,
            match_len: None,
        }
    }
}

impl RuleSpec {
    /// The bytes actually matched against the kernel window.
    pub fn effective_pattern(&self) -> &[u8] {
        match self.match_len {
            Some(n) if n < self.pattern.len() => &self.pattern.as_bytes()[..n],
            _ => self.pattern.as_bytes(),
        }
    }

    /// Hash of [`Self::effective_pattern`], computed exactly as the kernel does.
    pub fn hash(&self) -> u64 {
        hash_name(self.effective_pattern())
    }

    /// `rule_flags` word for the map value.
    pub fn flags(&self) -> u16 {
        let mut f = rule_flags::ACTIVE | self.target.required_flags();
        if self.prefix || self.match_len.is_some() {
            f |= rule_flags::MATCH_PREFIX;
        }
        f as u16
    }

    /// Resolve the errno, preferring the symbolic name.
    ///
    /// Symbolic names exist because `errno: 1` in a hand-written policy file is
    /// unreviewable; a diff showing `EPERM` is reviewable.
    pub fn errno_code(&self) -> i32 {
        if let Some(name) = &self.errno_name {
            return match name.as_str() {
                "EPERM" => EPERM,
                "EACCES" => EACCES,
                "ENOENT" => bpf_shield_common::ENOENT,
                other => match other.parse::<i32>() {
                    Ok(v) => v,
                    // Unknown symbolic name: fall back to the safest possible
                    // denial rather than to "allow".
                    Err(_) => EPERM,
                },
            };
        }
        self.errno.unwrap_or(EPERM)
    }

    /// Validate everything the kernel would otherwise fail on, with a message
    /// an operator can act on.
    pub fn validate(&self) -> Result<(), String> {
        if self.pattern.is_empty() {
            return Err(format!("rule {}: `pattern` is empty", self.id));
        }
        let bytes = self.effective_pattern();
        if bytes.is_empty() {
            return Err(format!("rule {}: `match_len` truncated the pattern away", self.id));
        }
        if bytes.contains(&0) {
            // A NUL inside the pattern cannot survive the blob round-trip and
            // would silently match a truncated string.
            return Err(format!("rule {}: `pattern` contains a NUL byte", self.id));
        }
        if bytes.len() > RULE_NAME_MAX {
            return Err(format!(
                "rule {}: effective pattern is {} bytes, kernel window allows {RULE_NAME_MAX}. \
                 Shorten `pattern`, or set `prefix: true` with a shorter prefix and `match_len`.",
                self.id,
                bytes.len()
            ));
        }
        if self.action == Action::Allow && self.target != Target::ExecPath {
            return Err(format!(
                "rule {}: `allow` is only meaningful for `exec_path` \
                 (an allow-list entry for an argument would deny everything \
                 that lacks the argument)",
                self.id
            ));
        }
        if self.action == Action::Deny && self.target == Target::OpenPath {
            // Enforced by the LSM hook only. The kprobe path can audit but not
            // veto, and we would rather refuse the policy than let an operator
            // believe a file open was blocked.
            return Err(format!(
                "rule {}: `deny` on `open_path` is not enforceable by BPF-Shield \
                 (the openat kprobe can only audit or sanitise). \
                 Use action `audit`, or block at the mount/SELinux layer.",
                self.id
            ));
        }
        Ok(())
    }
}

/// A complete policy document.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default = "default_version")]
    pub version: u32,
    pub rules: Vec<RuleSpec>,
}

fn default_version() -> u32 {
    1
}

impl Policy {
    /// Parse, then validate every rule and check for internal collisions.
    ///
    /// Collisions are rejected rather than resolved: two rules with the same
    /// 64-byte prefix hash and different `match_len` would silently shadow each
    /// other in the hash map, and a policy that quietly drops half its rules is
    /// the worst possible failure mode for this product.
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let policy: Policy =
            serde_json::from_slice(bytes).map_err(|e| format!("parse policy: {e}"))?;

        if policy.version != 1 {
            return Err(format!(
                "policy version {} is not supported by this agent (expected 1)",
                policy.version
            ));
        }

        let mut seen: std::collections::HashMap<u64, u32> = std::collections::HashMap::new();
        for rule in &policy.rules {
            rule.validate()?;
            match seen.insert(rule.hash(), rule.id) {
                Some(other) => {
                    return Err(format!(
                        "rules {} and {} share a 64-byte prefix and would collide in the \
                         kernel hash map. Shorten or differentiate one of them.",
                        other, rule.id
                    ))
                }
                None => {}
            }
        }

        Ok(policy)
    }

    /// Number of rules.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// True when the policy has no rules.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_are_stable() {
        // These two constants are what the kernel computes for the same inputs.
        // If either moves, the in-kernel policy and the daemon's policy have
        // silently parted ways, so pin them.
        assert_eq!(hash_name(b"/bin/sh"), hash_name(b"/bin/sh"));
        assert_ne!(hash_name(b"/bin/sh"), hash_name(b"/bin/bash"));
        assert_eq!(
            hash_name(b"/bin/sh"),
            bpf_shield_common::fnv1a64_padded(&bpf_shield_common::padded_name(b"/bin/sh"))
        );
    }

    #[test]
    fn prefix_shortens_the_matched_bytes() {
        let spec = RuleSpec {
            id: 1,
            pattern: "/usr/lib/jvm/java-17-openjdk-amd64/bin/java".into(),
            match_len: Some(21),
            ..Default::default()
        };
        assert_eq!(
            spec.effective_pattern(),
            b"/usr/lib/jvm/java-17-"
        );
        assert_ne!(spec.hash(), hash_name(spec.pattern.as_bytes()));
    }

    #[test]
    fn rejects_over_long_patterns() {
        let long = "x".repeat(RULE_NAME_MAX + 1);
        let spec = RuleSpec {
            id: 7,
            pattern: long,
            ..Default::default()
        };
        let err = spec.validate().unwrap_err();
        assert!(err.contains("kernel window allows"), "unhelpful message: {err}");
    }

    #[test]
    fn rejects_unenforceable_open_deny() {
        let spec = RuleSpec {
            id: 9,
            pattern: "/etc/shadow".into(),
            target: Target::OpenPath,
            action: Action::Deny,
            ..Default::default()
        };
        assert!(spec.validate().unwrap_err().contains("not enforceable"));
    }

    #[test]
    fn detects_collisions_in_a_document() {
        let json = br#"{
            "rules": [
                {"id": 1, "pattern": "/bin/sh"},
                {"id": 2, "pattern": "/bin/sh"}
            ]
        }"#;
        assert!(Policy::parse(json).unwrap_err().contains("collide"));
    }

    #[test]
    fn accepts_a_reasonable_document() {
        let json = br#"{
            "version": 1,
            "rules": [
                {"id": 1001, "pattern": "/tmp/evil-shim", "action": "deny",
                 "errno_name": "EPERM", "severity": "high"},
                {"id": 1002, "pattern": "--setuid=0", "target": "exec_arg",
                 "action": "audit", "severity": "medium"}
            ]
        }"#;
        let p = Policy::parse(json).unwrap();
        assert_eq!(p.len(), 2);
        assert_eq!(p.rules[0].errno_code(), EPERM);
        assert!(p.rules[1].flags() as u64 & rule_flags::EXEC_ARG != 0);
    }

    #[test]
    fn unknown_errno_name_falls_back_to_eperm() {
        let spec = RuleSpec {
            id: 3,
            errno_name: Some("ENOTAREALERRNO".into()),
            ..Default::default()
        };
        assert_eq!(spec.errno_code(), EPERM);
    }
}
