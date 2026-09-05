//! Experimental, non-production Canonical Observation v2 projection facade.
//!
//! This is deliberately a small exact-identity router over the already
//! implemented native projectors. It is not an adapter registry and does not
//! participate in source discovery or production scanning.

use std::fmt;

use telltale_schema::clients::ClientId;
use telltale_schema::observation::{CanonicalObservationV2, ObservedAt};
use telltale_schema::source::Source;

/// Caller-controlled projection inputs. No wall clock is consulted.
#[derive(Clone)]
pub struct CanonicalProjectionOptions {
    pub observed_at: ObservedAt,
}

impl CanonicalProjectionOptions {
    pub fn new(observed_at: ObservedAt) -> Self {
        Self { observed_at }
    }
}

/// Bounded, privacy-safe failure categories for canonical projection.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CanonicalProjectionError {
    UnsupportedSourceIdentity,
    SourceParse,
    CanonicalMapping,
    CanonicalValidation,
}

impl CanonicalProjectionError {
    pub fn code(self) -> &'static str {
        match self {
            Self::UnsupportedSourceIdentity => "unsupported_source_identity",
            Self::SourceParse => "source_parse",
            Self::CanonicalMapping => "canonical_mapping",
            Self::CanonicalValidation => "canonical_validation",
        }
    }
}

impl fmt::Display for CanonicalProjectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for CanonicalProjectionError {}

/// Project one supported source into Canonical Observation v2 values.
///
/// This facade is experimental and non-production. It performs no detection,
/// emits no Event, and exposes no adapter-native record types or options.
pub fn project_source_canonical_observations(
    source: &Source,
    options: CanonicalProjectionOptions,
) -> Result<Vec<CanonicalObservationV2>, CanonicalProjectionError> {
    match (source.client, source.source_id.as_str()) {
        (ClientId::Claude, "claude.projects") => {
            crate::sources::claude::canonical::project_claude_canonical_observations(
                source,
                crate::sources::claude::canonical::ClaudeCanonicalOptions::new(
                    options.observed_at,
                ),
            )
            .map_err(map_claude_error)
        }
        (ClientId::Codex, "codex.sessions")
        | (ClientId::Codex, "codex.archived_sessions")
        | (ClientId::Codex, "codex.headless_sessions")
        // This is intentionally routable for characterization only. It is not
        // part of the supported-source equivalence denominator.
        | (ClientId::Codex, "codex.project_sessions") => {
            crate::sources::codex::canonical::project_codex_canonical_observations(
                source,
                crate::sources::codex::canonical::CodexCanonicalOptions::new(options.observed_at),
            )
            .map_err(map_codex_error)
        }
        (ClientId::OpenCode, "opencode.sqlite") => {
            crate::sources::opencode::canonical::project_opencode_canonical_observations(
                source,
                crate::sources::opencode::canonical::OpenCodeCanonicalOptions::new(
                    options.observed_at,
                ),
            )
            .map_err(map_opencode_error)
        }
        (ClientId::OpenClaw, "openclaw.agents") => {
            crate::sources::openclaw::canonical::project_openclaw_canonical_observations(
                source,
                crate::sources::openclaw::canonical::OpenClawCanonicalOptions::new(
                    options.observed_at,
                ),
            )
            .map_err(map_openclaw_error)
        }
        (ClientId::Qwen, "qwen.projects") => {
            crate::sources::qwen::canonical::project_qwen_canonical_observations(
                source,
                crate::sources::qwen::canonical::QwenCanonicalOptions::new(options.observed_at),
            )
            .map_err(map_qwen_error)
        }
        _ => Err(CanonicalProjectionError::UnsupportedSourceIdentity),
    }
}

fn map_claude_error(
    error: crate::sources::claude::canonical::ClaudeCanonicalError,
) -> CanonicalProjectionError {
    match error {
        crate::sources::claude::canonical::ClaudeCanonicalError::Source(_) => {
            CanonicalProjectionError::SourceParse
        }
        crate::sources::claude::canonical::ClaudeCanonicalError::Mapping { code, .. } => {
            if code == "unsupported_source_identity" {
                CanonicalProjectionError::UnsupportedSourceIdentity
            } else {
                CanonicalProjectionError::CanonicalMapping
            }
        }
        crate::sources::claude::canonical::ClaudeCanonicalError::Observation(_) => {
            CanonicalProjectionError::CanonicalValidation
        }
    }
}

fn map_codex_error(
    error: crate::sources::codex::canonical::CodexCanonicalError,
) -> CanonicalProjectionError {
    match error {
        crate::sources::codex::canonical::CodexCanonicalError::Source(_) => {
            CanonicalProjectionError::SourceParse
        }
        crate::sources::codex::canonical::CodexCanonicalError::Mapping { code, .. } => {
            if code == "unsupported_source_identity" {
                CanonicalProjectionError::UnsupportedSourceIdentity
            } else {
                CanonicalProjectionError::CanonicalMapping
            }
        }
        crate::sources::codex::canonical::CodexCanonicalError::Observation(_) => {
            CanonicalProjectionError::CanonicalValidation
        }
    }
}

fn map_opencode_error(
    error: crate::sources::opencode::canonical::OpenCodeCanonicalError,
) -> CanonicalProjectionError {
    match error {
        crate::sources::opencode::canonical::OpenCodeCanonicalError::Source(_) => {
            CanonicalProjectionError::SourceParse
        }
        crate::sources::opencode::canonical::OpenCodeCanonicalError::Mapping { code, .. } => {
            if code == "unsupported_source_identity" {
                CanonicalProjectionError::UnsupportedSourceIdentity
            } else {
                CanonicalProjectionError::CanonicalMapping
            }
        }
        crate::sources::opencode::canonical::OpenCodeCanonicalError::Observation(_) => {
            CanonicalProjectionError::CanonicalValidation
        }
    }
}

fn map_openclaw_error(
    error: crate::sources::openclaw::canonical::OpenClawCanonicalError,
) -> CanonicalProjectionError {
    match error {
        crate::sources::openclaw::canonical::OpenClawCanonicalError::Source(_) => {
            CanonicalProjectionError::SourceParse
        }
        crate::sources::openclaw::canonical::OpenClawCanonicalError::Mapping { code, .. } => {
            if code == "unsupported_source_identity" {
                CanonicalProjectionError::UnsupportedSourceIdentity
            } else {
                CanonicalProjectionError::CanonicalMapping
            }
        }
        crate::sources::openclaw::canonical::OpenClawCanonicalError::Observation(_) => {
            CanonicalProjectionError::CanonicalValidation
        }
    }
}

fn map_qwen_error(
    error: crate::sources::qwen::canonical::QwenCanonicalError,
) -> CanonicalProjectionError {
    match error {
        crate::sources::qwen::canonical::QwenCanonicalError::Source(_) => {
            CanonicalProjectionError::SourceParse
        }
        crate::sources::qwen::canonical::QwenCanonicalError::Mapping { code, .. } => {
            if code == "unsupported_source_identity" {
                CanonicalProjectionError::UnsupportedSourceIdentity
            } else {
                CanonicalProjectionError::CanonicalMapping
            }
        }
        crate::sources::qwen::canonical::QwenCanonicalError::Observation(_) => {
            CanonicalProjectionError::CanonicalValidation
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use telltale_schema::clients::{ClientId, SourceKind};
    use telltale_schema::observation::ObservedAt;
    use telltale_schema::source::Source;
    use tempfile::tempdir;

    use super::{
        CanonicalProjectionError, CanonicalProjectionOptions, project_source_canonical_observations,
    };

    const OBSERVED_AT: &str = "2026-09-04T00:00:00Z";

    fn source(client: ClientId, source_id: &str, kind: SourceKind, fixture: &str) -> Source {
        Source {
            client,
            kind,
            source_id: source_id.to_owned(),
            path: crate::test_fixture_path(fixture),
        }
    }

    fn project(source: &Source) -> Vec<telltale_schema::observation::CanonicalObservationV2> {
        project_source_canonical_observations(
            source,
            CanonicalProjectionOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .expect("projection")
    }

    #[test]
    fn routes_each_required_identity_to_native_projector() {
        let temporary = tempdir().unwrap();
        let codex_path = temporary.path().join("synthetic-codex.jsonl");
        fs::write(
            &codex_path,
            r#"{"type":"user","session_id":"synthetic-route-session","content":"Synthetic route fixture."}"#,
        )
        .unwrap();
        let sources = [
            source(
                ClientId::Claude,
                "claude.projects",
                SourceKind::Jsonl,
                "session_stores/claude/projects/project-b/session-tool-use.jsonl",
            ),
            Source {
                client: ClientId::Codex,
                kind: SourceKind::Jsonl,
                source_id: "codex.sessions".to_owned(),
                path: codex_path.clone(),
            },
            Source {
                client: ClientId::Codex,
                kind: SourceKind::ArchivedJsonl,
                source_id: "codex.archived_sessions".to_owned(),
                path: codex_path.clone(),
            },
            Source {
                client: ClientId::Codex,
                kind: SourceKind::HeadlessJsonl,
                source_id: "codex.headless_sessions".to_owned(),
                path: codex_path,
            },
            source(
                ClientId::OpenCode,
                "opencode.sqlite",
                SourceKind::Sqlite,
                "session_stores/opencode/opencode.db",
            ),
            source(
                ClientId::OpenClaw,
                "openclaw.agents",
                SourceKind::Jsonl,
                "session_stores/openclaw/agents/project-b/uc001-openclaw-tool-result.jsonl",
            ),
            source(
                ClientId::Qwen,
                "qwen.projects",
                SourceKind::Jsonl,
                "session_stores/qwen/projects/project-b/chats/uc001-qwen-tool-result.jsonl",
            ),
        ];
        assert!(sources.iter().all(|source| !project(source).is_empty()));
    }

    #[test]
    fn candidate_project_sessions_is_routable_but_not_promoted() {
        let temporary = tempdir().unwrap();
        let path = temporary.path().join("synthetic-project-session.jsonl");
        fs::write(
            &path,
            r#"{"type":"user","session_id":"synthetic-project-session","content":"Synthetic candidate fixture."}"#,
        )
        .unwrap();
        let source = Source {
            client: ClientId::Codex,
            kind: SourceKind::Jsonl,
            source_id: "codex.project_sessions".to_owned(),
            path,
        };
        assert!(
            project_source_canonical_observations(
                &source,
                CanonicalProjectionOptions::new(ObservedAt::new(OBSERVED_AT).unwrap())
            )
            .is_ok()
        );
    }

    #[test]
    fn non_v2_identities_are_rejected_without_path_in_error() {
        let source = source(
            ClientId::OpenCode,
            "opencode.legacy_json",
            SourceKind::LegacyJson,
            "does-not-exist.json",
        );
        let error = project_source_canonical_observations(
            &source,
            CanonicalProjectionOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .unwrap_err();
        assert_eq!(error, CanonicalProjectionError::UnsupportedSourceIdentity);
        assert_eq!(error.to_string(), "unsupported_source_identity");
        assert!(!format!("{error:?}").contains("does-not-exist"));
        assert!(!format!("{error}").contains("does-not-exist"));

        for (client, source_id) in [
            (ClientId::OpenClaw, "openclaw.legacy_json"),
            (ClientId::Qwen, "qwen.legacy_json"),
        ] {
            let source = Source {
                client,
                kind: SourceKind::LegacyJson,
                source_id: source_id.to_owned(),
                path: PathBuf::from("does-not-exist.json"),
            };
            let error = project_source_canonical_observations(
                &source,
                CanonicalProjectionOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
            )
            .unwrap_err();
            assert_eq!(error, CanonicalProjectionError::UnsupportedSourceIdentity);
        }
    }

    #[test]
    fn wrong_case_and_wrong_client_use_exact_identity() {
        for (client, source_id) in [
            (ClientId::Claude, "Claude.projects"),
            (ClientId::Codex, "codex.SESSIONS"),
            (ClientId::OpenCode, "opencode.SQLite"),
            (ClientId::OpenClaw, "OpenClaw.agents"),
            (ClientId::Qwen, "Qwen.projects"),
            (ClientId::Claude, "openclaw.agents"),
            (ClientId::Codex, "qwen.projects"),
        ] {
            let source = Source {
                client,
                kind: SourceKind::Jsonl,
                source_id: source_id.to_owned(),
                path: PathBuf::from("not-read"),
            };
            assert_eq!(
                project_source_canonical_observations(
                    &source,
                    CanonicalProjectionOptions::new(ObservedAt::new(OBSERVED_AT).unwrap())
                )
                .unwrap_err(),
                CanonicalProjectionError::UnsupportedSourceIdentity
            );
        }
    }

    #[test]
    fn facade_preserves_fixed_observed_at_and_native_output_identity() {
        let codex_source = source(
            ClientId::Codex,
            "codex.sessions",
            SourceKind::Jsonl,
            "session_stores/codex/sessions/2026/04/encoded-http-exfil.jsonl",
        );
        let observations = project(&codex_source);
        assert!(
            observations
                .iter()
                .all(|observation| observation.observed_at().as_str() == OBSERVED_AT)
        );

        let direct = crate::sources::codex::canonical::project_codex_canonical_observations(
            &codex_source,
            crate::sources::codex::canonical::CodexCanonicalOptions::new(
                ObservedAt::new(OBSERVED_AT).unwrap(),
            ),
        )
        .unwrap();
        assert_eq!(
            observations
                .iter()
                .map(|observation| observation.observation_id())
                .collect::<Vec<_>>(),
            direct
                .iter()
                .map(|observation| observation.observation_id())
                .collect::<Vec<_>>()
        );

        for source in [
            source(
                ClientId::OpenClaw,
                "openclaw.agents",
                SourceKind::Jsonl,
                "session_stores/openclaw/agents/project-b/uc001-openclaw-tool-result.jsonl",
            ),
            source(
                ClientId::Qwen,
                "qwen.projects",
                SourceKind::Jsonl,
                "session_stores/qwen/projects/project-b/chats/uc001-qwen-tool-result.jsonl",
            ),
        ] {
            assert!(
                project(&source)
                    .iter()
                    .all(|observation| observation.observed_at().as_str() == OBSERVED_AT)
            );
        }
    }
}
