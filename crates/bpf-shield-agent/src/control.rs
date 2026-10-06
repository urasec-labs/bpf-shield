//! Control plane: NDJSON over a Unix socket.
//!
//! # Why a socket and not gRPC in v1
//!
//! The wire format is newline-delimited JSON, one request per line, one response
//! per line. It is trivial to implement in any language, works over `socat`,
//! `nc -U` and `curl --unix-socket`, and — critically — can be implemented by a
//! *shell script* emergency responder. When the host is degraded, the first
//! thing you need is a `kill-switch off` that does not require a working
//! Rust toolchain on the box.
//!
//! The request/response types below are the compatibility surface. A gRPC
//! service can be layered on top later without changing the kernel half,
//! because the kernel only ever sees map writes.
//!
//! # Authorisation
//!
//! v1 relies on filesystem permissions: the socket is created `0660` owned by
//! the agent's user and group, and the daemon refuses to start if the parent
//! directory is group/world-writable. Anyone who can `connect()` to the socket
//! can arm the policy, so this check is not cosmetic.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::Mutex,
};
use tracing::{error, info, warn};

use crate::maps::Maps;

/// Requests the agent accepts.
#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Liveness probe.
    Ping,
    /// Current config word and rule count.
    Status,
    /// Replace the policy. `policy` is a whole document, not a patch: partial
    /// updates need merge semantics in the kernel half, and the kernel half
    /// should stay dumb.
    Push { policy: crate::policy::Policy },
    /// Set/clear configuration flag bits by name.
    Configure {
        #[serde(default)]
        set: Vec<String>,
        #[serde(default)]
        clear: Vec<String>,
    },
    /// Emergency off switch. Works even when enforcement is wedged, because it
    /// is a single map write.
    KillSwitch { on: bool },
    /// Aggregated counters.
    Stats,
    /// Read one rule row out of the pinned rule map.
    Rule { hash: u64 },
    /// Detach everything and exit. Exists so a supervisor can request a clean
    /// reload without signalling.
    Shutdown,
}

/// Responses the agent emits.
#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Response {
    Ok {
        #[serde(skip_serializing_if = "Option::is_none")]
        detail: Option<serde_json::Value>,
    },
    Err {
        error: String,
    },
}

impl Response {
    fn ok() -> Self {
        Response::Ok { detail: None }
    }

    fn with(detail: serde_json::Value) -> Self {
        Response::Ok {
            detail: Some(detail),
        }
    }

    fn err(e: impl std::fmt::Display) -> Self {
        Response::Err {
            error: e.to_string(),
        }
    }

    /// True when this response signals success.
    pub fn is_ok(&self) -> bool {
        matches!(self, Response::Ok { .. })
    }
}

/// Handle for the control socket.
pub struct ControlServer {
    listener: UnixListener,
    path: PathBuf,
}

/// Bind the control socket, after checking the directory's permissions.
///
/// Returns the server and nothing else: once bound, the listener owns the
/// socket for the process lifetime.
pub async fn bind(path: &Path) -> Result<ControlServer, String> {
    if let Some(dir) = path.parent() {
        check_dir_permissions(dir)?;
    }
    if path.exists() {
        // A stale socket from a crashed agent. Removing it is safe because we
        // are about to take the name; the risk of two agents racing here is
        // handled by the pidfile check in main.
        std::fs::remove_file(path).map_err(|e| format!("remove stale socket: {e}"))?;
    }

    let listener = UnixListener::bind(path).map_err(|e| format!("bind {}: {e}", path.display()))?;

    // 0o660: owner and group only. The group is what an on-call engineer or a
    // config-management agent gets access through.
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))
        .map_err(|e| format!("chmod socket: {e}"))?;

    info!(path = %path.display(), "control socket listening");
    Ok(ControlServer {
        listener,
        path: path.to_path_buf(),
    })
}

/// Reject a socket directory that untrusted users can write to.
///
/// A world-writable `/run` or `/tmp/bpf-shield` would let any local user
/// replace the socket with their own and become the control plane.
fn check_dir_permissions(dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    let md = std::fs::metadata(dir).map_err(|e| format!("stat {}: {e}", dir.display()))?;
    if !md.is_dir() {
        return Err(format!("{} is not a directory", dir.display()));
    }
    let mode = md.permissions().mode() & 0o777;
    if mode & 0o022 != 0 {
        return Err(format!(
            "{} is mode {:04o}: group- or world-writable, so the control socket \
             could be hijacked. Use 0755 or 0750 and a dedicated group.",
            dir.display(),
            mode
        ));
    }
    Ok(())
}

impl ControlServer {
    /// Serve until the process exits.
    ///
    /// `maps` is behind a mutex because policy writes are read-modify-write on
    /// the config array and must not interleave with a kill-switch write.
    pub async fn serve(self, maps: std::sync::Arc<Mutex<Maps>>) {
        loop {
            let (stream, _addr) = match self.listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    error!(error = %e, "control accept failed");
                    // A transient EMFILE should not spin us at 100% CPU.
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
            };

            let maps = maps.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_conn(stream, maps).await {
                    warn!(error = %e, "control connection ended");
                }
            });
        }
    }

    /// Remove the socket on drop so a clean restart does not need `rm`.
    pub fn cleanup(self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Read newline-delimited requests until EOF, answering each.
async fn handle_conn(stream: UnixStream, maps: std::sync::Arc<Mutex<Maps>>) -> Result<(), String> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    while let Some(line) = lines
        .next_line()
        .await
        .map_err(|e| format!("read: {e}"))?
    {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let response = match serde_json::from_str::<Request>(line) {
            Ok(req) => dispatch(req, &maps).await,
            Err(e) => Response::Err {
                error: format!("bad request: {e}"),
            },
        };

        let mut payload = serde_json::to_string(&response).map_err(|e| e.to_string())?;
        payload.push('\n');
        writer
            .write_all(payload.as_bytes())
            .await
            .map_err(|e| format!("write: {e}"))?;
        writer.flush().await.map_err(|e| format!("flush: {e}"))?;
    }

    Ok(())
}

/// Execute one request.
async fn dispatch(req: Request, maps: &std::sync::Arc<Mutex<Maps>>) -> Response {
    match req {
        Request::Ping => Response::with(serde_json::json!({ "version": env!("CARGO_PKG_VERSION") })),

        Request::Status => {
            let maps = maps.lock().await;
            let cfg = match maps.config() {
                Ok(c) => c,
                Err(e) => return Response::err(e),
            };
            let count = match maps.rule_count() {
                Ok(c) => c,
                Err(e) => return Response::err(e),
            };
            Response::with(serde_json::json!({
                "abi_version": bpf_shield_common::SHIELD_ABI_VERSION,
                "flags": cfg.flags,
                "flags_hex": format!("0x{:016x}", cfg.flags),
                "enforcing": cfg.enforcing(),
                "kill_switch": cfg.flags & bpf_shield_common::cfg_flags::KILL_SWITCH != 0,
                "rules": count,
                "max_arg_index": cfg.max_arg_index,
                "sample_rate": cfg.event_sample_rate,
            }))
        }

        Request::Push { policy } => {
            let mut maps = maps.lock().await;
            if let Err(e) = validate_policy(&policy) {
                return Response::err(e);
            }
            match maps.apply_policy(&policy) {
                Ok(n) => Response::with(serde_json::json!({ "rules_installed": n })),
                Err(e) => Response::err(e),
            }
        }

        Request::Configure { set, clear } => {
            let mut maps = maps.lock().await;
            let mut set_bits = 0u64;
            let mut clear_bits = 0u64;
            for name in &set {
                match flag_by_name(name) {
                    Some(b) => set_bits |= b,
                    None => return Response::err(format!("unknown flag `{name}`")),
                }
            }
            for name in &clear {
                match flag_by_name(name) {
                    Some(b) => clear_bits |= b,
                    None => return Response::err(format!("unknown flag `{name}`")),
                }
            }

            match maps.mutate_config(|cfg| {
                cfg.flags |= set_bits;
                cfg.flags &= !clear_bits;
                // Clearing the kill switch implies wanting enforcement
                // available; refusing to silently leave it inert avoids an
                // operator thinking they armed the system when they did not.
                if clear_bits & bpf_shield_common::cfg_flags::KILL_SWITCH != 0 {
                    cfg.flags |= bpf_shield_common::cfg_flags::ENABLED;
                }
            }) {
                Ok(cfg) => Response::with(serde_json::json!({
                    "flags_hex": format!("0x{:016x}", cfg.flags),
                    "enforcing": cfg.enforcing(),
                })),
                Err(e) => Response::err(e),
            }
        }

        Request::KillSwitch { on } => {
            let mut maps = maps.lock().await;
            match maps.kill_switch(on) {
                Ok(cfg) => {
                    if on {
                        warn!("KILL SWITCH ENGAGED by control connection: enforcement disabled");
                    } else {
                        info!("kill switch released");
                    }
                    Response::with(serde_json::json!({
                        "kill_switch": on,
                        "flags_hex": format!("0x{:016x}", cfg.flags),
                    }))
                }
                Err(e) => Response::err(e),
            }
        }

        Request::Stats => {
            let maps = maps.lock().await;
            match maps.read_stats() {
                Ok(s) => Response::with(serde_json::to_value(s).unwrap_or_default()),
                Err(e) => Response::err(e),
            }
        }

        Request::Rule { hash } => {
            let maps = maps.lock().await;
            match maps.rule_by_hash(hash) {
                Ok(Some(r)) => Response::with(serde_json::to_value(r).unwrap_or_default()),
                Ok(None) => Response::err("no such rule"),
                Err(e) => Response::err(e),
            }
        }

        Request::Shutdown => {
            info!("shutdown requested over the control socket");
            // Disarm before exiting so the window between our exit and the
            // links being torn down cannot deny anything.
            if let Ok(mut maps) = maps.try_lock() {
                let _ = maps.kill_switch(true);
            }
            std::process::exit(0);
        }
    }
}

/// Re-check the rules at the socket boundary, even though `Policy::parse`
/// already validated them.
///
/// This matters because `Request::Push` carries a `Policy` deserialised
/// directly (not via `Policy::parse`), so a caller could otherwise skip
/// validation. The kernel is the backstop, but it has no way to report.
fn validate_policy(policy: &crate::policy::Policy) -> Result<(), String> {
    use std::collections::HashMap;

    if policy.version != 1 {
        return Err(format!("unsupported policy version {}", policy.version));
    }

    let mut seen: HashMap<u64, u32> = HashMap::new();
    for rule in &policy.rules {
        rule.validate()?;
        if let Some(other) = seen.insert(rule.hash(), rule.id) {
            return Err(format!(
                "rules {other} and {} collide on their matched prefix",
                rule.id
            ));
        }
    }
    Ok(())
}

/// Resolve a flag name to its bit.
fn flag_by_name(name: &str) -> Option<u64> {
    use bpf_shield_common::cfg_flags as f;
    Some(match name {
        "enabled" => f::ENABLED,
        "enforce" => f::ENFORCE,
        "arg_scan" => f::ARG_SCAN,
        "hook_execve" => f::HOOK_EXECVE,
        "hook_openat" => f::HOOK_OPENAT,
        "collect" => f::COLLECT,
        "verify_exact" => f::VERIFY_EXACT,
        "sanitize_args" => f::SANITIZE_ARGS,
        "kill_switch" => f::KILL_SWITCH,
        _ => return None,
    })
}

/// Send one request and read one response. Used by the CLI and by tests.
pub async fn roundtrip(path: &Path, req: &Request) -> Result<Response, String> {
    let stream = UnixStream::connect(path).await.map_err(|e| e.to_string())?;
    let (reader, mut writer) = stream.into_split();

    let mut line = serde_json::to_string(req).map_err(|e| e.to_string())?;
    line.push('\n');
    writer.write_all(line.as_bytes()).await.map_err(|e| e.to_string())?;
    writer.flush().await.map_err(|e| e.to_string())?;

    let mut lines = BufReader::new(reader).lines();
    let resp = lines.next_line().await.map_err(|e| e.to_string())?;
    let resp = resp.ok_or_else(|| "control socket closed without a response".to_string())?;
    serde_json::from_str(&resp).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_names_resolve() {
        use bpf_shield_common::cfg_flags as f;
        assert_eq!(flag_by_name("enforce"), Some(f::ENFORCE));
        assert_eq!(flag_by_name("kill_switch"), Some(f::KILL_SWITCH));
        assert_eq!(flag_by_name("nope"), None);
    }

    #[test]
    fn request_roundtrips_through_json() {
        let req = Request::KillSwitch { on: true };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains(r#""op":"kill_switch""#), "{json}");
        let back: Request = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, Request::KillSwitch { on: true }));
    }

    #[test]
    fn response_carries_detail() {
        let r = Response::with(serde_json::json!({"a": 1}));
        assert!(r.is_ok());
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains(r#""status":"ok""#), "{s}");
    }

    #[test]
    fn push_validates_at_the_boundary() {
        let policy: crate::policy::Policy = serde_json::from_str(
            r#"{"version":1,"rules":[{"id":1,"pattern":"/x","target":"open_path","action":"deny"}]}"#,
        )
        .unwrap();
        assert!(validate_policy(&policy).is_err());
    }
}
