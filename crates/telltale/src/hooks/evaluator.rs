//! Long-lived local evaluator (ADR 0003).
//!
//! On Unix the evaluator is a daemon behind a user-private socket (`unix`).
//! Other platforms have no evaluator yet (a Windows named-pipe transport is a
//! recorded residual risk, docs/threat-model.md): the client reports
//! `evaluator_unsupported_platform` without connecting anywhere, nothing is
//! autostarted, and the hook evaluates in-process. Correctness never depends
//! on the evaluator, so this never fails open.

use std::path::PathBuf;

use serde_json::Value;

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::{PROTOCOL_VERSION, peer_uid, request, serve, spawn_detached, trusted};
#[cfg(not(unix))]
pub use unsupported::{UNSUPPORTED_PLATFORM, request, serve, spawn_detached};

/// What a hook learned from trying the evaluator.
#[derive(Debug, PartialEq)]
pub enum ClientOutcome {
    /// The evaluator handled the event; print `output` (if any) and exit.
    Answered(Option<Value>),
    /// The evaluator did not record the event; evaluate in-process.
    NotDelivered(&'static str),
    /// The request was sent but no valid answer came back in time. The
    /// evaluator may have recorded it: see `Runtime::handle_unanswered`.
    DeliveredNoAnswer(&'static str),
}

#[derive(Debug)]
pub enum ServeError {
    Config(crate::hooks::config::ConfigError),
    Engine(crate::hooks::engine::EngineError),
    AlreadyRunning(PathBuf),
    Bind(std::io::Error),
    UnstableRules,
    /// This platform has no evaluator transport; hooks evaluate in-process.
    UnsupportedPlatform,
}

impl std::fmt::Display for ServeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(error) => write!(f, "{error}"),
            Self::Engine(error) => write!(f, "{error}"),
            Self::AlreadyRunning(path) => {
                write!(f, "an evaluator already answers on {}", path.display())
            }
            Self::Bind(error) => write!(f, "cannot bind evaluator socket: {error}"),
            Self::UnstableRules => f.write_str("rule files kept changing during startup"),
            Self::UnsupportedPlatform => f.write_str(
                "the long-lived evaluator is not supported on this platform; hooks evaluate in-process",
            ),
        }
    }
}

impl std::error::Error for ServeError {}

/// No evaluator transport on this platform: every request is "not
/// delivered", so the hook evaluates in-process and records why.
#[cfg(not(unix))]
mod unsupported {
    use std::path::Path;
    use std::time::Duration;

    use super::{ClientOutcome, ServeError};
    use crate::hooks::config::Config;
    use crate::hooks::harness::Harness;

    /// Fallback code recorded as `evaluation.evaluator_fallback`.
    pub const UNSUPPORTED_PLATFORM: &str = "evaluator_unsupported_platform";

    pub fn request(
        _socket: &Path,
        _harness: Harness,
        _fingerprint: &str,
        _payload: &[u8],
        _timeout: Duration,
    ) -> ClientOutcome {
        ClientOutcome::NotDelivered(UNSUPPORTED_PLATFORM)
    }

    /// Never starts anything; `false` means no attempt was made.
    pub fn spawn_detached(_state_dir: &Path) -> std::io::Result<bool> {
        Ok(false)
    }

    pub fn serve(_config: Config) -> Result<(), ServeError> {
        Err(ServeError::UnsupportedPlatform)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn requests_are_never_delivered_and_nothing_starts() {
            let dir = tempfile::tempdir().unwrap();
            assert_eq!(
                request(
                    &dir.path().join("evaluator.sock"),
                    Harness::ClaudeCode,
                    "fp",
                    b"{}",
                    Duration::from_secs(1)
                ),
                ClientOutcome::NotDelivered(UNSUPPORTED_PLATFORM)
            );
            let state = dir.path().join("state");
            assert!(!spawn_detached(&state).unwrap());
            assert!(!state.exists(), "nothing created");
            assert!(matches!(
                serve(Config::default()),
                Err(ServeError::UnsupportedPlatform)
            ));
        }
    }
}
