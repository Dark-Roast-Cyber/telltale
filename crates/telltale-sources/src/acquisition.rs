//! Authoritative Canonical Observation v2 acquisition from local sources.
//!
//! Source modules own canonical semantics. Progress is operational metadata, not
//! canonical evidence or persisted scanner state. Production runtime cutover is
//! separate from this API; acquisition performs no detection or event delivery.

use std::fmt;

use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::observation::{CanonicalObservationV2, ObservedAt};
use telltale_schema::source::Source;

use crate::parser::ParseOptions;
use crate::sources::claude::canonical::{
    ClaudeCanonicalError, ClaudeCanonicalOptions, project_claude_native_records,
};
use crate::sources::claude::native::extract_claude_native_records;
use crate::sources::codex::canonical::{
    CodexCanonicalError, CodexCanonicalOptions, project_codex_native_records,
};
use crate::sources::codex::native::extract_codex_native_records;
use crate::sources::copilot::canonical::{
    CopilotCanonicalError, CopilotCanonicalOptions, project_copilot_native_events,
};
use crate::sources::copilot::native::extract_copilot_native_events;
use crate::sources::openclaw::canonical::{
    OpenClawCanonicalError, OpenClawCanonicalOptions, project_openclaw_native_records,
};
use crate::sources::openclaw::native::extract_openclaw_native_records;
use crate::sources::opencode::canonical::{
    OpenCodeCanonicalError, project_opencode_native_records,
};
use crate::sources::opencode::native::extract_sqlite_native_source;
use crate::sources::qwen::canonical::{
    QwenCanonicalError, QwenCanonicalOptions, project_qwen_native_records,
};
use crate::sources::qwen::native::extract_qwen_native_records;

pub struct AcquisitionBatch {
    pub observations: Vec<CanonicalObservationV2>,
    pub progress: AcquisitionProgress,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AcquisitionProgress {
    None,
    OpenCodeSqlite { part_max_time_updated: Option<i64> },
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct OpenCodeSqliteReadOptions {
    pub part_min_time_updated: Option<i64>,
    pub part_limit: i64,
}

impl Default for OpenCodeSqliteReadOptions {
    fn default() -> Self {
        let options = ParseOptions::default();
        Self {
            part_min_time_updated: options.sqlite_part_min_time_updated,
            part_limit: options.sqlite_part_limit,
        }
    }
}

#[derive(Clone)]
pub struct AcquisitionOptions {
    pub observed_at: ObservedAt,
}

impl AcquisitionOptions {
    pub fn new(observed_at: ObservedAt) -> Self {
        Self { observed_at }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AcquisitionError {
    UnsupportedSourceIdentity,
    SourceKindMismatch,
    SourceRead,
    CanonicalMapping { code: &'static str },
    CanonicalValidation { code: &'static str },
}

impl AcquisitionError {
    pub fn code(self) -> &'static str {
        match self {
            Self::UnsupportedSourceIdentity => "unsupported_source_identity",
            Self::SourceKindMismatch => "source_kind_mismatch",
            Self::SourceRead => "source_read",
            Self::CanonicalMapping { code } | Self::CanonicalValidation { code } => code,
        }
    }
}

impl fmt::Display for AcquisitionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for AcquisitionError {}

/// Acquire a migrated identity with default source read controls.
pub fn acquire_source(
    source: &Source,
    options: AcquisitionOptions,
) -> Result<AcquisitionBatch, AcquisitionError> {
    let expected_kind = match (source.client, source.source_id.as_str()) {
        (ClientId::Claude, "claude.projects")
        | (ClientId::Codex, "codex.sessions")
        | (ClientId::OpenClaw, "openclaw.agents")
        | (ClientId::Qwen, "qwen.projects") => SourceKind::Jsonl,
        (ClientId::Codex, "codex.archived_sessions") => SourceKind::ArchivedJsonl,
        (ClientId::Codex, "codex.headless_sessions") => SourceKind::HeadlessJsonl,
        (ClientId::Copilot, "copilot.process_log") => SourceKind::CopilotProcessLog,
        (ClientId::OpenCode, "opencode.sqlite") => {
            return acquire_opencode_sqlite(source, options, OpenCodeSqliteReadOptions::default());
        }
        _ => return Err(AcquisitionError::UnsupportedSourceIdentity),
    };
    if source.kind != expected_kind {
        return Err(AcquisitionError::SourceKindMismatch);
    }

    let observations = match source.client {
        ClientId::Claude => {
            let records =
                extract_claude_native_records(source).map_err(|_| AcquisitionError::SourceRead)?;
            project_claude_native_records(
                &records,
                &ClaudeCanonicalOptions::new(options.observed_at),
            )
            .map_err(map_claude_error)?
        }
        ClientId::Codex => {
            let records =
                extract_codex_native_records(source).map_err(|_| AcquisitionError::SourceRead)?;
            project_codex_native_records(&records, &CodexCanonicalOptions::new(options.observed_at))
                .map_err(map_codex_error)?
        }
        ClientId::OpenClaw => {
            let records = extract_openclaw_native_records(source)
                .map_err(|_| AcquisitionError::SourceRead)?;
            project_openclaw_native_records(
                &records,
                &OpenClawCanonicalOptions::new(options.observed_at),
            )
            .map_err(map_openclaw_error)?
        }
        ClientId::Qwen => {
            let records =
                extract_qwen_native_records(source).map_err(|_| AcquisitionError::SourceRead)?;
            project_qwen_native_records(&records, &QwenCanonicalOptions::new(options.observed_at))
                .map_err(map_qwen_error)?
        }
        ClientId::Copilot => {
            let events =
                extract_copilot_native_events(source).map_err(|_| AcquisitionError::SourceRead)?;
            project_copilot_native_events(
                events,
                &CopilotCanonicalOptions::new(options.observed_at),
            )
            .map_err(map_copilot_error)?
        }
        _ => unreachable!("exact acquisition identity was validated"),
    };
    Ok(AcquisitionBatch {
        observations,
        progress: AcquisitionProgress::None,
    })
}

/// OpenCode-only bounded reads; these controls are not shared acquisition options.
pub fn acquire_opencode_sqlite(
    source: &Source,
    options: AcquisitionOptions,
    read: OpenCodeSqliteReadOptions,
) -> Result<AcquisitionBatch, AcquisitionError> {
    if source.client != ClientId::OpenCode || source.source_id != "opencode.sqlite" {
        return Err(AcquisitionError::UnsupportedSourceIdentity);
    }
    if source.kind != SourceKind::Sqlite {
        return Err(AcquisitionError::SourceKindMismatch);
    }

    let parse_options = ParseOptions {
        sqlite_part_min_time_updated: read.part_min_time_updated,
        sqlite_part_limit: read.part_limit,
    };
    let extraction = extract_sqlite_native_source(source, parse_options)
        .map_err(|_| AcquisitionError::SourceRead)?;
    let progress = AcquisitionProgress::OpenCodeSqlite {
        part_max_time_updated: extraction.sqlite_part_max_time_updated,
    };
    let observations = project_opencode_native_records(&extraction.records, &options.observed_at)
        .map_err(map_canonical_error)?;

    Ok(AcquisitionBatch {
        observations,
        progress,
    })
}

fn map_canonical_error(error: OpenCodeCanonicalError) -> AcquisitionError {
    match error {
        OpenCodeCanonicalError::Source(_) => AcquisitionError::SourceRead,
        OpenCodeCanonicalError::Mapping { code, .. } => AcquisitionError::CanonicalMapping { code },
        OpenCodeCanonicalError::Observation(error) => {
            AcquisitionError::CanonicalValidation { code: error.code() }
        }
    }
}

fn map_claude_error(error: ClaudeCanonicalError) -> AcquisitionError {
    match error {
        ClaudeCanonicalError::Source(_) => AcquisitionError::SourceRead,
        ClaudeCanonicalError::Mapping { code, .. } => AcquisitionError::CanonicalMapping { code },
        ClaudeCanonicalError::Observation(error) => {
            AcquisitionError::CanonicalValidation { code: error.code() }
        }
    }
}

fn map_codex_error(error: CodexCanonicalError) -> AcquisitionError {
    match error {
        CodexCanonicalError::Source(_) => AcquisitionError::SourceRead,
        CodexCanonicalError::Mapping { code, .. } => AcquisitionError::CanonicalMapping { code },
        CodexCanonicalError::Observation(error) => {
            AcquisitionError::CanonicalValidation { code: error.code() }
        }
    }
}

fn map_openclaw_error(error: OpenClawCanonicalError) -> AcquisitionError {
    match error {
        OpenClawCanonicalError::Source(_) => AcquisitionError::SourceRead,
        OpenClawCanonicalError::Mapping { code, .. } => AcquisitionError::CanonicalMapping { code },
        OpenClawCanonicalError::Observation(error) => {
            AcquisitionError::CanonicalValidation { code: error.code() }
        }
    }
}

fn map_qwen_error(error: QwenCanonicalError) -> AcquisitionError {
    match error {
        QwenCanonicalError::Source(_) => AcquisitionError::SourceRead,
        QwenCanonicalError::Mapping { code, .. } => AcquisitionError::CanonicalMapping { code },
        QwenCanonicalError::Observation(error) => {
            AcquisitionError::CanonicalValidation { code: error.code() }
        }
    }
}

fn map_copilot_error(error: CopilotCanonicalError) -> AcquisitionError {
    match error {
        CopilotCanonicalError::Source(_) => AcquisitionError::SourceRead,
        CopilotCanonicalError::Mapping { code, .. } => AcquisitionError::CanonicalMapping { code },
        CopilotCanonicalError::Observation(error) => {
            AcquisitionError::CanonicalValidation { code: error.code() }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use rusqlite::Connection;
    use telltale_schema::clients::{ClientId, SourceKind};
    use telltale_schema::observation::{ObservationBody, ObservedAt};
    use telltale_schema::source::Source;
    use tempfile::tempdir;

    use super::{
        AcquisitionError, AcquisitionOptions, AcquisitionProgress, OpenCodeSqliteReadOptions,
        acquire_opencode_sqlite,
    };
    use crate::parser::{ParseOptions, parse_source_records_with_options};
    use crate::sources::opencode::canonical::{
        OpenCodeCanonicalOptions, project_opencode_canonical_observations,
    };

    const OBSERVED_AT: &str = "2026-09-18T12:00:00Z";

    fn options() -> AcquisitionOptions {
        AcquisitionOptions::new(ObservedAt::new(OBSERVED_AT).unwrap())
    }

    const JSONL_IDENTITIES: &[(ClientId, &str, SourceKind)] = &[
        (ClientId::Claude, "claude.projects", SourceKind::Jsonl),
        (ClientId::OpenClaw, "openclaw.agents", SourceKind::Jsonl),
        (ClientId::Qwen, "qwen.projects", SourceKind::Jsonl),
        (ClientId::Codex, "codex.sessions", SourceKind::Jsonl),
        (
            ClientId::Codex,
            "codex.archived_sessions",
            SourceKind::ArchivedJsonl,
        ),
        (
            ClientId::Codex,
            "codex.headless_sessions",
            SourceKind::HeadlessJsonl,
        ),
    ];

    #[test]
    fn acquisition_denominator_matches_builtin_sources() {
        let expected = JSONL_IDENTITIES
            .iter()
            .copied()
            .chain([
                (ClientId::OpenCode, "opencode.sqlite", SourceKind::Sqlite),
                (
                    ClientId::Copilot,
                    "copilot.process_log",
                    SourceKind::CopilotProcessLog,
                ),
            ])
            .collect::<std::collections::BTreeSet<_>>();
        let registered = crate::clients::supported_clients()
            .iter()
            .flat_map(|client| {
                client
                    .sources
                    .iter()
                    .map(move |source| (client.id, source.id, source.kind))
            })
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(expected.len(), 8);
        assert_eq!(expected, registered);
        let directory = tempdir().unwrap();
        for (client, source_id, kind) in registered {
            // An existing directory is unreadable as any supported source format.
            let source = Source {
                client,
                source_id: source_id.to_owned(),
                kind,
                path: directory.path().to_owned(),
            };
            assert_eq!(
                acquisition_error(super::acquire_source(&source, options())),
                AcquisitionError::SourceRead
            );
        }
    }

    #[test]
    fn jsonl_acquisition_preserves_semantics_and_replay() {
        let directory = tempdir().unwrap();
        let codex_path = directory.path().join("synthetic-codex.jsonl");
        std::fs::write(&codex_path, concat!(
            "{\"type\":\"session_meta\",\"payload\":{\"session_id\":\"acquisition-session\"}}\n",
            "{\"timestamp\":\"2026-04-27T12:10:00Z\",\"type\":\"response_item\",\"payload\":{\"type\":\"function_call\",\"name\":\"exec\",\"call_id\":\"acquisition-call\",\"arguments\":{\"command\":\"printf synthetic\"}}}\n",
            "{\"type\":\"response_item\",\"payload\":{\"type\":\"function_call_output\",\"call_id\":\"acquisition-call\",\"output\":{\"text\":\"synthetic\"}}}\n"
        )).unwrap();
        let mut codex_ids = std::collections::BTreeSet::new();
        for &(client, source_id, kind) in JSONL_IDENTITIES {
            let source = Source {
                client,
                kind,
                source_id: source_id.to_owned(),
                path: match client {
                    ClientId::Claude => crate::test_fixture_path(
                        "session_stores/claude/projects/project-b/session-tool-use.jsonl",
                    ),
                    ClientId::OpenClaw => crate::test_fixture_path(
                        "session_stores/openclaw/agents/project-b/uc001-openclaw-tool-result.jsonl",
                    ),
                    ClientId::Qwen => crate::test_fixture_path(
                        "session_stores/qwen/projects/project-b/chats/uc001-qwen-tool-result.jsonl",
                    ),
                    _ => codex_path.clone(),
                },
            };
            let legacy_before = crate::parser::parse_source_records(&source).unwrap();
            let acquired = super::acquire_source(&source, options()).unwrap();
            let replay = super::acquire_source(&source, options()).unwrap();
            assert_eq!(acquired.progress, AcquisitionProgress::None);
            assert!(!acquired.observations.is_empty());
            assert_eq!(acquired.observations.len(), replay.observations.len());
            for (actual, expected) in acquired.observations.iter().zip(&replay.observations) {
                assert_eq!(actual.observation_id(), expected.observation_id());
                assert_eq!(actual.observed_at().as_str(), OBSERVED_AT);
                assert_eq!(actual.occurred_at(), expected.occurred_at());
                assert_eq!(actual.session_id(), expected.session_id());
                assert_eq!(actual.source(), expected.source());
                assert_eq!(actual.source().adapter_id(), source_id);
                assert_eq!(actual.body(), expected.body());
                assert_eq!(actual.stage(), expected.stage());
                assert_eq!(actual.correlation(), expected.correlation());
                assert_eq!(actual.fact_metadata(), expected.fact_metadata());
                assert_eq!(actual.facets(), expected.facets());
                assert_eq!(actual.capability_context(), expected.capability_context());
            }
            assert_eq!(
                acquired.observations[0].occurred_at().unwrap().as_str(),
                match client {
                    ClientId::OpenClaw => "2026-04-27T19:10:00Z",
                    ClientId::Qwen => "2026-04-27T12:40:00Z",
                    _ => "2026-04-27T12:10:00Z",
                }
            );
            if client == ClientId::Codex {
                assert!(codex_ids.insert(acquired.observations[0].observation_id().to_string()));
                assert!(acquired.observations[1].occurred_at().is_none());
                assert_eq!(
                    acquired.observations[0].stage(),
                    telltale_schema::observation::ObservationStage::ToolRequested
                );
            }
            let legacy_after = crate::parser::parse_source_records(&source).unwrap();
            assert_eq!(format!("{legacy_before:?}"), format!("{legacy_after:?}"));
        }
        assert_eq!(codex_ids.len(), 3);
    }

    #[test]
    fn dispatcher_rejects_identity_and_kind_before_io() {
        let directory = tempdir().unwrap();
        let missing = directory.path().join("private-missing-source");
        for &(client, source_id, kind) in JSONL_IDENTITIES.iter().chain(&[(
            ClientId::Copilot,
            "copilot.process_log",
            SourceKind::CopilotProcessLog,
        )]) {
            let mut source = Source {
                client,
                source_id: source_id.to_owned(),
                kind,
                path: missing.clone(),
            };
            for wrong_kind in [
                SourceKind::Jsonl,
                SourceKind::ArchivedJsonl,
                SourceKind::HeadlessJsonl,
                SourceKind::Sqlite,
            ] {
                if wrong_kind == kind {
                    continue;
                }
                source.kind = wrong_kind;
                assert_eq!(
                    acquisition_error(super::acquire_source(&source, options())),
                    AcquisitionError::SourceKindMismatch
                );
            }
            source.kind = kind;
            assert_eq!(
                acquisition_error(acquire_opencode_sqlite(
                    &source,
                    options(),
                    OpenCodeSqliteReadOptions {
                        part_min_time_updated: Some(99),
                        part_limit: 1
                    }
                )),
                AcquisitionError::UnsupportedSourceIdentity
            );
            source.client = ClientId::OpenCode;
            assert_eq!(
                acquisition_error(super::acquire_source(&source, options())),
                AcquisitionError::UnsupportedSourceIdentity
            );
        }
        for (client, source_id) in [
            (ClientId::OpenCode, "opencode.legacy_json"),
            (ClientId::OpenCode, "opencode.project_json"),
            (ClientId::Codex, "codex.project_sessions"),
            (ClientId::Claude, "Claude.projects"),
            (ClientId::Claude, "gemini.tmp"),
            (ClientId::Claude, "roocode.tasks"),
            (ClientId::Claude, "kilocode.tasks"),
            (ClientId::Qwen, "openclaw.agents"),
            (ClientId::OpenClaw, "qwen.projects"),
            (ClientId::OpenClaw, "OpenClaw.agents"),
            (ClientId::Qwen, "Qwen.projects"),
            (ClientId::Claude, "copilot.process_log"),
            (ClientId::Copilot, "Copilot.process_log"),
        ] {
            let source = Source {
                client,
                source_id: source_id.to_owned(),
                kind: SourceKind::Jsonl,
                path: missing.clone(),
            };
            assert_eq!(
                acquisition_error(super::acquire_source(&source, options())),
                AcquisitionError::UnsupportedSourceIdentity
            );
        }
        assert!(!missing.exists());
    }

    #[test]
    fn empty_opencode_progress_is_not_no_progress() {
        let (_directory, connection, source) = database();
        connection.execute("delete from part", []).unwrap();
        drop(connection);
        let batch = super::acquire_source(&source, options()).unwrap();
        assert_eq!(
            batch.progress,
            AcquisitionProgress::OpenCodeSqlite {
                part_max_time_updated: None
            }
        );
        assert_ne!(batch.progress, AcquisitionProgress::None);
    }

    #[test]
    fn openclaw_qwen_acquisition_preserves_coordinates_and_evidence_strength() {
        use telltale_schema::observation::{
            CapabilityAvailability, CapabilityId, JsonValue, ObservationStage,
        };
        let directory = tempdir().unwrap();
        let path = directory.path().join("synthetic-evidence.jsonl");
        let moved_path = directory.path().join("renamed-evidence.jsonl");
        let input = concat!(
            "{\"type\":\"user\",\"id\":\"native-message\",\"sessionId\":\"source-session\",\"content\":\"synthetic native message\"}\n",
            "{\"type\":\"user\",\"sessionId\":\"source-session\",\"content\":\"synthetic scoped message\"}\n",
            "{\"type\":\"tool_call\",\"sessionId\":\"source-session\",\"callID\":\"source-call\",\"name\":\"shell\",\"input\":{\"command\":\"printf synthetic\",\"path\":\"README.md\"}}\n",
            "{\"type\":\"tool_result\",\"sessionId\":\"source-session\",\"callID\":\"source-call\",\"tool\":\"shell\",\"output\":{\"text\":\"synthetic result\"},\"timestamp\":\"invalid-source-time\"}\n"
        );
        std::fs::write(&path, input).unwrap();
        std::fs::write(&moved_path, input).unwrap();
        for (client, source_id) in [
            (ClientId::OpenClaw, "openclaw.agents"),
            (ClientId::Qwen, "qwen.projects"),
        ] {
            let source = Source {
                client,
                source_id: source_id.to_owned(),
                kind: SourceKind::Jsonl,
                path: path.clone(),
            };
            let batch = super::acquire_source(&source, options()).unwrap();
            let relocated = super::acquire_source(
                &Source {
                    path: moved_path.clone(),
                    ..source.clone()
                },
                options(),
            )
            .unwrap();
            let reference = if client == ClientId::OpenClaw {
                super::project_openclaw_native_records(
                    &super::extract_openclaw_native_records(&source).unwrap(),
                    &super::OpenClawCanonicalOptions::new(options().observed_at),
                )
                .unwrap()
            } else {
                super::project_qwen_native_records(
                    &super::extract_qwen_native_records(&source).unwrap(),
                    &super::QwenCanonicalOptions::new(options().observed_at),
                )
                .unwrap()
            };
            assert_eq!(batch.progress, AcquisitionProgress::None);
            assert_eq!(batch.observations.len(), 4);
            assert_eq!(
                batch.observations[0].source().native_id(),
                Some("native-message")
            );
            assert!(batch.observations[1].source().native_id().is_none());
            for ((actual, moved), expected) in batch
                .observations
                .iter()
                .zip(&relocated.observations)
                .zip(&reference)
            {
                assert_eq!(actual.observation_id(), moved.observation_id());
                assert_eq!(actual.session_id(), moved.session_id());
                assert_eq!(actual.session_id().unwrap().value(), "source-session");
                assert_eq!(actual.observed_at().as_str(), OBSERVED_AT);
                assert!(actual.occurred_at().is_none());
                assert_eq!(actual.body(), expected.body());
                assert_eq!(actual.correlation(), expected.correlation());
                assert_eq!(actual.capability_context(), expected.capability_context());
                for (capability, availability) in [
                    (CapabilityId::ToolCall, CapabilityAvailability::Supported),
                    (CapabilityId::UserContext, CapabilityAvailability::Supported),
                    (CapabilityId::ToolExecution, CapabilityAvailability::Unknown),
                ] {
                    assert_eq!(
                        actual.capability_context().unwrap().resolve(capability),
                        availability
                    );
                }
                assert!(matches!(
                    actual.body(),
                    ObservationBody::Message(_) | ObservationBody::Tool(_)
                ));
                assert!(matches!(
                    actual.stage(),
                    ObservationStage::MessageObserved
                        | ObservationStage::ToolRequested
                        | ObservationStage::ToolResultReturned
                ));
            }
            for observation in &batch.observations[2..] {
                assert_eq!(
                    observation.correlation().call_id().unwrap().value(),
                    "source-call"
                );
            }
            let ObservationBody::Tool(request) = batch.observations[2].body() else {
                panic!("expected tool request")
            };
            assert_eq!(
                request.arguments(),
                Some(
                    &JsonValue::try_from_source_value(
                        &serde_json::json!({"command":"printf synthetic", "path":"README.md"})
                    )
                    .unwrap()
                )
            );
            let ObservationBody::Tool(result) = batch.observations[3].body() else {
                panic!("expected tool result")
            };
            assert_eq!(
                result.result(),
                Some(
                    &JsonValue::try_from_source_value(
                        &serde_json::json!({"text":"synthetic result"})
                    )
                    .unwrap()
                )
            );

            std::fs::write(
                &moved_path,
                format!("{{\"type\":\"session_meta\"}}\n{input}"),
            )
            .unwrap();
            let shifted = super::acquire_source(
                &Source {
                    path: moved_path.clone(),
                    ..source
                },
                options(),
            )
            .unwrap();
            assert_eq!(
                batch.observations[0].observation_id(),
                shifted.observations[0].observation_id()
            );
            assert_ne!(
                batch.observations[1].observation_id(),
                shifted.observations[1].observation_id()
            );
            std::fs::write(&moved_path, input).unwrap();
        }
    }

    #[test]
    fn jsonl_errors_are_bounded_and_do_not_restore_legacy_identity() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("private-path-marker.jsonl");
        for &(client, source_id, kind) in JSONL_IDENTITIES {
            let source = Source {
                client,
                source_id: source_id.to_owned(),
                kind,
                path: path.clone(),
            };
            for (payload, expected) in [
                ("{private-payload-marker", AcquisitionError::SourceRead),
                (
                    r#"{"type":"private-discriminator-marker","content":"private-payload-marker"}"#,
                    AcquisitionError::CanonicalMapping {
                        code: "unknown_discriminator",
                    },
                ),
                (
                    r#"{"type":"user","content":"private-payload-marker"}"#,
                    AcquisitionError::CanonicalValidation {
                        code: "replay_unverifiable",
                    },
                ),
            ] {
                std::fs::write(&path, payload).unwrap();
                let error = acquisition_error(super::acquire_source(&source, options()));
                assert_eq!(error, expected);
                let rendered = format!("{error} {error:?}");
                assert!(!rendered.contains("private-"));
                if expected != AcquisitionError::SourceRead {
                    assert!(
                        !crate::parser::parse_source_records(&source)
                            .unwrap()
                            .is_empty()
                    );
                }
            }
        }
    }

    #[test]
    fn copilot_acquisition_preserves_reference_lifecycle_and_evidence() {
        use telltale_schema::observation::{
            CapabilityAvailability, CapabilityId, ObservationStage,
        };
        let directory = tempdir().unwrap();
        let reactivated = directory.path().join("reactivated.log");
        std::fs::write(&reactivated, concat!(
            "Workspace initialized: session-a (checkpoints: 0)\n",
            "Accumulated output items (2): [{\"type\":\"reasoning\"},{\"type\":\"function_call\",\"name\":\"view\",\"call_id\":\"call-a\"}]\n",
            "Session completed.\nWorkspace initialized: session-b (checkpoints: 0)\n",
            "Accumulated output items (1): [{\"type\":\"function_call\",\"name\":\"view\"}]\n",
            "Session completed.\nWorkspace initialized: session-a (checkpoints: 0)\n",
            "Accumulated output items (1): [{\"type\":\"function_call\",\"name\":\"view\"}]\nSession completed.\n"
        )).unwrap();
        for (path, sequences) in [
            (
                crate::test_fixture_path("session_stores/copilot/process-mixed-format.log"),
                vec![1, 2, 3, 3],
            ),
            (
                crate::test_fixture_path("session_stores/copilot/process-multi-session.log"),
                vec![0, 0],
            ),
            (reactivated, vec![1, 0, 2]),
        ] {
            let source = Source {
                client: ClientId::Copilot,
                source_id: "copilot.process_log".to_owned(),
                kind: SourceKind::CopilotProcessLog,
                path,
            };
            let legacy_before = crate::parser::parse_source_records(&source).unwrap();
            let acquired = super::acquire_source(&source, options()).unwrap();
            let replay = super::acquire_source(&source, options()).unwrap();
            let reference = super::project_copilot_native_events(
                super::extract_copilot_native_events(&source).unwrap(),
                &super::CopilotCanonicalOptions::new(options().observed_at),
            )
            .unwrap();
            assert_eq!(acquired.progress, AcquisitionProgress::None);
            assert_eq!(acquired.observations.len(), reference.len());
            assert_eq!(acquired.observations.len(), replay.observations.len());
            assert_eq!(
                acquired
                    .observations
                    .iter()
                    .map(|o| o.sequence().unwrap())
                    .collect::<Vec<_>>(),
                sequences
            );
            for ((actual, expected), repeated) in acquired
                .observations
                .iter()
                .zip(&reference)
                .zip(&replay.observations)
            {
                assert_eq!(actual.observation_id(), expected.observation_id());
                assert_eq!(actual.observation_id(), repeated.observation_id());
                assert_eq!(actual.session_id(), expected.session_id());
                assert_eq!(actual.source(), expected.source());
                assert!(actual.source().native_id().is_none());
                assert_eq!(actual.observed_at().as_str(), OBSERVED_AT);
                assert_eq!(actual.occurred_at(), expected.occurred_at());
                assert_eq!(actual.body(), expected.body());
                assert_eq!(actual.correlation(), expected.correlation());
                assert_eq!(actual.facets(), expected.facets());
                assert_eq!(actual.fact_metadata(), expected.fact_metadata());
                assert_eq!(actual.capability_context(), expected.capability_context());
                for (id, availability) in [
                    (CapabilityId::ToolCall, CapabilityAvailability::Supported),
                    (CapabilityId::ToolExecution, CapabilityAvailability::Unknown),
                    (
                        CapabilityId::UserContext,
                        CapabilityAvailability::Unsupported,
                    ),
                ] {
                    assert_eq!(
                        actual.capability_context().unwrap().resolve(id),
                        availability
                    );
                }
                assert!(matches!(
                    actual.body(),
                    ObservationBody::Message(_) | ObservationBody::Tool(_)
                ));
                assert!(matches!(
                    actual.stage(),
                    ObservationStage::MessageObserved
                        | ObservationStage::ToolRequested
                        | ObservationStage::ToolResultReturned
                ));
            }
            if sequences == [1, 2, 3, 3] {
                assert!(matches!(
                    acquired.observations[0].body(),
                    ObservationBody::Message(_)
                ));
                assert_eq!(
                    acquired.observations[0].occurred_at().unwrap().as_str(),
                    "2026-04-27T16:17:17.990Z"
                );
                assert_eq!(
                    acquired.observations[1]
                        .correlation()
                        .call_id()
                        .unwrap()
                        .value(),
                    "call_mixed_001"
                );
                assert!(
                    legacy_before
                        .iter()
                        .all(|r| r.kind != telltale_schema::record::RecordKind::AssistantMessage)
                );
            }
            let legacy_after = crate::parser::parse_source_records(&source).unwrap();
            assert_eq!(format!("{legacy_before:?}"), format!("{legacy_after:?}"));
        }
    }

    #[test]
    fn copilot_acquisition_failures_preserve_strict_reference_behavior() {
        use crate::sources::copilot::canonical::{
            CopilotCanonicalOptions, project_copilot_canonical_observations,
        };
        let directory = tempdir().unwrap();
        let path = directory.path().join("private-path-marker.log");
        let source = Source {
            client: ClientId::Copilot,
            source_id: "copilot.process_log".to_owned(),
            kind: SourceKind::CopilotProcessLog,
            path: path.clone(),
        };
        let init = "Workspace initialized: private-session-marker (checkpoints: 0)\n";
        let item = "Accumulated output items (1): [{\"type\":\"function_call\",\"name\":\"private-tool-marker\",\"call_id\":\"private-call-marker\",\"arguments\":\"private-argument-marker\",\"message\":\"private-result-marker\"}]\n";
        for (input, expected, legacy_ok) in [
            (
                item.to_owned(),
                AcquisitionError::CanonicalMapping {
                    code: "replay_unverifiable",
                },
                true,
            ),
            (
                format!("{init}{item}Session completed.\n{item}"),
                AcquisitionError::CanonicalMapping {
                    code: "replay_unverifiable",
                },
                true,
            ),
            (
                format!("{init}{item}Accumulated output items (1): [{{private-malformed-marker"),
                AcquisitionError::CanonicalMapping {
                    code: "malformed_structured_output",
                },
                true,
            ),
            (
                "Accumulated output items (1): [private-malformed-marker".to_owned(),
                AcquisitionError::CanonicalMapping {
                    code: "replay_unverifiable",
                },
                false,
            ),
            (
                format!("{init}Accumulated output items (1): [42]"),
                AcquisitionError::SourceRead,
                false,
            ),
        ] {
            std::fs::write(&path, input).unwrap();
            let error = acquisition_error(super::acquire_source(&source, options()));
            assert_eq!(error, expected);
            let reference = project_copilot_canonical_observations(
                &source,
                CopilotCanonicalOptions::new(options().observed_at),
            )
            .unwrap_err();
            assert_eq!(error, super::map_copilot_error(reference));
            assert!(!format!("{error} {error:?}").contains("private-"));
            assert_eq!(
                crate::parser::parse_source_records(&source).is_ok(),
                legacy_ok
            );
        }
        // Each invocation starts fresh, even after a previous initialized stream.
        std::fs::write(&path, format!("{init}{item}")).unwrap();
        assert!(super::acquire_source(&source, options()).is_ok());
        std::fs::write(&path, item).unwrap();
        assert_eq!(
            acquisition_error(super::acquire_source(&source, options())).code(),
            "replay_unverifiable"
        );
    }

    fn acquisition_error(
        result: Result<super::AcquisitionBatch, AcquisitionError>,
    ) -> AcquisitionError {
        match result {
            Ok(_) => panic!("expected acquisition error"),
            Err(error) => error,
        }
    }

    fn source(path: PathBuf) -> Source {
        Source {
            client: ClientId::OpenCode,
            kind: SourceKind::Sqlite,
            source_id: "opencode.sqlite".to_owned(),
            path,
        }
    }

    fn database() -> (tempfile::TempDir, Connection, Source) {
        let directory = tempdir().unwrap();
        let path = directory.path().join("synthetic-opencode.db");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "create table message (
                    id text, session_id text, time_created integer,
                    time_updated integer, data text
                 );
                 create table part (
                    id text, message_id text, session_id text,
                    time_created integer, time_updated integer, data text
                 );",
            )
            .unwrap();
        connection
            .execute(
                "insert into message values (?1, ?2, ?3, ?4, ?5)",
                (
                    "message-acquisition",
                    "session-acquisition",
                    1_000_i64,
                    1_000_i64,
                    r#"{"role":"assistant","modelID":"fixture-model"}"#,
                ),
            )
            .unwrap();
        for (id, updated, text) in [
            ("part-first", 1_000_i64, "first"),
            ("part-second", 2_000_i64, "second"),
            ("part-third", 3_000_i64, "third"),
        ] {
            connection
                .execute(
                    "insert into part values (?1, ?2, ?3, ?4, ?5, ?6)",
                    (
                        id,
                        "message-acquisition",
                        "session-acquisition",
                        updated,
                        updated,
                        serde_json::json!({"type":"text","text":text}).to_string(),
                    ),
                )
                .unwrap();
        }
        let source = source(path);
        (directory, connection, source)
    }

    #[test]
    fn validates_exact_identity_and_kind_before_source_io() {
        let directory = tempdir().unwrap();
        let missing = directory.path().join("must-not-be-created.db");
        for invalid in [
            Source {
                client: ClientId::Claude,
                kind: SourceKind::Sqlite,
                source_id: "opencode.sqlite".to_owned(),
                path: missing.clone(),
            },
            Source {
                client: ClientId::OpenCode,
                kind: SourceKind::Sqlite,
                source_id: "OpenCode.sqlite".to_owned(),
                path: missing.clone(),
            },
        ] {
            assert_eq!(
                acquisition_error(acquire_opencode_sqlite(
                    &invalid,
                    options(),
                    OpenCodeSqliteReadOptions::default()
                )),
                AcquisitionError::UnsupportedSourceIdentity
            );
            assert!(!missing.exists());
        }

        let wrong_kind = Source {
            client: ClientId::OpenCode,
            kind: SourceKind::Json,
            source_id: "opencode.sqlite".to_owned(),
            path: missing.clone(),
        };
        assert_eq!(
            acquisition_error(acquire_opencode_sqlite(
                &wrong_kind,
                options(),
                OpenCodeSqliteReadOptions::default()
            )),
            AcquisitionError::SourceKindMismatch
        );
        assert!(!missing.exists());
    }

    #[test]
    fn default_acquisition_preserves_canonical_semantics_and_observed_time() {
        let (_directory, connection, source) = database();
        drop(connection);

        let acquired = super::acquire_source(&source, options()).unwrap();
        let projected = project_opencode_canonical_observations(
            &source,
            OpenCodeCanonicalOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        )
        .unwrap();

        assert_eq!(acquired.observations.len(), projected.len());
        for (acquired, projected) in acquired.observations.iter().zip(&projected) {
            assert_eq!(acquired.observation_id(), projected.observation_id());
            assert_eq!(acquired.kind(), projected.kind());
            assert_eq!(acquired.stage(), projected.stage());
            assert_eq!(acquired.body(), projected.body());
            assert_eq!(acquired.facets(), projected.facets());
            assert_eq!(acquired.fact_metadata(), projected.fact_metadata());
            assert_eq!(
                acquired.source().native_id(),
                projected.source().native_id()
            );
            assert_eq!(acquired.observed_at().as_str(), OBSERVED_AT);
        }
        assert_eq!(
            acquired.progress,
            AcquisitionProgress::OpenCodeSqlite {
                part_max_time_updated: Some(3_000)
            }
        );
    }

    #[test]
    fn bounded_read_options_return_selected_progress_and_leave_legacy_unchanged() {
        let (_directory, connection, source) = database();
        drop(connection);
        let read = OpenCodeSqliteReadOptions {
            part_min_time_updated: Some(1_001),
            part_limit: 1,
        };

        let acquired = acquire_opencode_sqlite(&source, options(), read).unwrap();
        assert_eq!(acquired.observations.len(), 1);
        let ObservationBody::Message(message) = acquired.observations[0].body() else {
            panic!("expected selected message part")
        };
        assert_eq!(
            message.content(),
            Some(&telltale_schema::observation::JsonValue::string("second"))
        );
        assert_eq!(
            acquired.progress,
            AcquisitionProgress::OpenCodeSqlite {
                part_max_time_updated: Some(2_000)
            }
        );

        let legacy = parse_source_records_with_options(
            &source,
            ParseOptions {
                sqlite_part_min_time_updated: read.part_min_time_updated,
                sqlite_part_limit: read.part_limit,
            },
        )
        .unwrap();
        assert_eq!(legacy.records.len(), 2);
        assert!(legacy.records[1].content.contains("second"));
        assert_eq!(legacy.sqlite_part_max_time_updated, Some(2_000));
    }

    #[test]
    fn repeated_equivalent_acquisition_is_identity_stable() {
        let (_directory, connection, source) = database();
        drop(connection);
        let first = super::acquire_source(&source, options()).unwrap();
        let second = super::acquire_source(&source, options()).unwrap();

        assert_eq!(first.progress, second.progress);
        assert_eq!(
            first
                .observations
                .iter()
                .map(|observation| observation.observation_id())
                .collect::<Vec<_>>(),
            second
                .observations
                .iter()
                .map(|observation| observation.observation_id())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn acquisition_errors_do_not_expose_source_details() {
        let private_directory = tempdir().unwrap();
        let private_path = private_directory
            .path()
            .join("private-source-path-marker.db");
        std::fs::create_dir(&private_path).unwrap();
        let unreadable = source(private_path.clone());
        let error = acquisition_error(super::acquire_source(&unreadable, options()));
        assert_eq!(error, AcquisitionError::SourceRead);
        assert_eq!(error.to_string(), "source_read");
        assert!(!format!("{error:?}").contains(private_path.to_string_lossy().as_ref()));

        let (directory, connection, source) = database();
        connection
            .execute(
                "insert into part values (?1, ?2, ?3, ?4, ?5, ?6)",
                (
                    "private-part-id-marker",
                    "private-message-id-marker",
                    "private-session-id-marker",
                    4_000_i64,
                    4_000_i64,
                    r#"{"type":"tool","tool":"private-tool-marker","callID":"private-call-marker","state":{"status":"private-status-marker","input":{"command":"private-argument-marker"},"output":"private-result-marker"}}"#,
                ),
            )
            .unwrap();
        drop(connection);
        let error = acquisition_error(super::acquire_source(&source, options()));
        assert_eq!(error.code(), "unknown_tool_status");
        let rendered = format!("{error:?} {error}");
        let directory_marker = directory.path().to_string_lossy().into_owned();
        for marker in [
            directory_marker.as_str(),
            "private-part-id-marker",
            "private-message-id-marker",
            "private-session-id-marker",
            "private-tool-marker",
            "private-call-marker",
            "private-status-marker",
            "private-argument-marker",
            "private-result-marker",
        ] {
            assert!(!rendered.contains(marker));
        }
    }
}
