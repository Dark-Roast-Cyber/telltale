use std::path::PathBuf;

use rusqlite::Connection;
use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::observation::{ObservationBody, ObservedAt};
use telltale_schema::source::Source;
use tempfile::tempdir;

use super::{
    AcquisitionError, AcquisitionOptions, AcquisitionProgress, BoundedReadError,
    OpenCodeSqliteReadOptions, acquire_opencode_sqlite,
};

const OBSERVED_AT: &str = "2026-09-18T12:00:00Z";

/// A call's declared operation spends no retention: the observations of a
/// source that fit its limit exactly, as acquired with their declarations,
/// still fit it and one byte less does not.
#[test]
fn declared_operations_leave_the_retention_limit_where_it_was() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("limit.jsonl");
    let content = serde_json::json!({"type":"assistant","sessionId":"limit","message":{
            "role":"assistant","content":[{"type":"tool_use","id":"call-0","name":"Write",
            "input":{"file_path":"/synthetic/w.txt","content":"synthetic"}}]}});
    std::fs::write(&path, content.to_string()).unwrap();
    let batch = super::acquire_source(
        &Source {
            client: ClientId::Claude,
            kind: SourceKind::Jsonl,
            source_id: "claude.projects".to_owned(),
            path,
        },
        options(),
    )
    .unwrap();
    let declared = batch
        .observations
        .iter()
        .filter(|observation| match observation.body() {
            ObservationBody::Tool(tool) => tool.operation().is_some(),
            _ => false,
        })
        .count();
    assert_eq!(declared, 1);
    let total: usize = batch
        .observations
        .iter()
        .map(telltale_schema::observation::CanonicalObservationV2::retained_byte_len)
        .sum();
    let mut exact = super::CanonicalCollector {
        limit: total,
        ..super::CanonicalCollector::default()
    };
    let mut short = super::CanonicalCollector {
        limit: total - 1,
        ..super::CanonicalCollector::default()
    };
    let mut fits = true;
    let mut overflows = false;
    for observation in batch.observations {
        fits &= exact.push(observation.clone()).is_ok();
        overflows |= short.push(observation).is_err();
    }
    assert!(fits && overflows);
}

fn options() -> AcquisitionOptions {
    AcquisitionOptions::new(ObservedAt::new(OBSERVED_AT).unwrap())
}

const JSONL_IDENTITIES: &[(ClientId, &str, SourceKind)] = &[
    (ClientId::Claude, "claude.projects", SourceKind::Jsonl),
    (ClientId::OpenClaw, "openclaw.agents", SourceKind::Jsonl),
    (ClientId::Qwen, "qwen.projects", SourceKind::Jsonl),
    (ClientId::Pi, "pi.sessions", SourceKind::Jsonl),
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
fn bounded_source_errors_do_not_change_production_classification() {
    for reason in [
        BoundedReadError::Missing,
        BoundedReadError::PermissionDenied,
        BoundedReadError::Unreadable,
        BoundedReadError::NonRegularSource,
        BoundedReadError::LimitExceeded,
        BoundedReadError::MalformedSource,
    ] {
        for production in [super::SourceAccess::ByName, super::SourceAccess::Resolved] {
            assert_eq!(
                super::map_source_read(super::SourceReadError::Bounded(reason), production),
                AcquisitionError::SourceRead
            );
        }
        let root = std::path::Path::new("synthetic-root");
        for bounded in [
            super::SourceAccess::Direct(super::DirectRead {
                root,
                limits: super::DirectReadLimits::default(),
            }),
            super::SourceAccess::Anchored(super::AnchoredRead {
                root: Some(root),
                max_bytes: 1,
            }),
        ] {
            assert_eq!(
                super::map_source_read(super::SourceReadError::Bounded(reason), bounded),
                AcquisitionError::BoundedSourceRead(reason)
            );
        }
    }
}

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
    assert_eq!(expected.len(), 9);
    assert_eq!(expected, registered);
    // Hook-journal identities are host-fed: no registered source is one.
    for client in ClientId::ALL {
        assert!(
            registered
                .iter()
                .all(|(_, source_id, _)| *source_id != client.hook_journal_source_id())
        );
    }
    let directory = tempdir().unwrap();
    for (client, source_id, kind) in registered {
        // An existing directory is unreadable as any supported source format.
        let source = Source {
            client,
            source_id: source_id.to_owned(),
            kind,
            path: directory.path().to_owned(),
        };
        let expected = if client == ClientId::OpenCode && !cfg!(feature = "opencode-sqlite") {
            AcquisitionError::CapabilityNotCompiled
        } else {
            AcquisitionError::SourceRead
        };
        assert_eq!(
            acquisition_error(super::acquire_source(&source, options())),
            expected
        );
    }
}

const JOURNAL_WINDOW: &str = concat!(
    r#"{"type":"user","sessionId":"synthetic-window","uuid":"u1","timestamp":"2026-11-04T00:00:00.001Z","message":{"role":"user","content":"synthetic prompt"}}"#,
    "\n",
    r#"{"type":"assistant","sessionId":"synthetic-window","uuid":"a1","timestamp":"2026-11-04T00:00:00.002Z","message":{"role":"assistant","content":[{"type":"tool_use","id":"call_1","name":"Bash","input":{"command":"ls"}}]}}"#,
    "\n",
);

fn journal_source(client: ClientId, source_id: &str, path: &std::path::Path) -> Source {
    Source {
        client,
        kind: SourceKind::Jsonl,
        source_id: source_id.to_owned(),
        path: path.to_owned(),
    }
}

/// The rule covers every client, including one with no registered source.
#[test]
fn every_clients_hook_journal_is_outside_the_registry() {
    let registered = crate::clients::supported_clients();
    for client in ClientId::ALL {
        let id = client.hook_journal_source_id();
        assert!(id.ends_with(".hooks"));
        assert!(
            registered
                .iter()
                .flat_map(|client| client.sources)
                .all(|source| source.id != id)
        );
    }
}

#[test]
#[cfg(feature = "hook-journal")]
fn hook_journal_pairs_acquire_and_carry_their_own_identity() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("window.jsonl");
    std::fs::write(&path, JOURNAL_WINDOW).unwrap();
    let session = super::acquire_source(
        &journal_source(ClientId::Claude, "claude.projects", &path),
        options(),
    )
    .unwrap();
    assert!(!session.observations.is_empty());
    for &client in ClientId::ALL {
        let source_id = client.hook_journal_source_id();
        let source = journal_source(client, source_id, &path);
        let acquired = super::acquire_source(&source, options()).unwrap();
        assert_eq!(acquired.observations.len(), session.observations.len());
        for observation in &acquired.observations {
            assert_eq!(observation.source().adapter_id(), source_id);
            assert_eq!(
                observation.source().adapter_type(),
                ClientId::HOOK_JOURNAL_ADAPTER_TYPE
            );
        }
        // Only identity differs from the session reading of the same window.
        for (hook, reference) in acquired.observations.iter().zip(&session.observations) {
            // A tool call is declared by its own client's table, not Claude's.
            match reference.body() {
                ObservationBody::Tool(tool) if tool.operation().is_some() => {
                    let mut undeclared = telltale_schema::observation::ToolObservation::new();
                    if let Some(name) = tool.name() {
                        undeclared = undeclared.with_name(name).unwrap();
                    }
                    if let Some(arguments) = tool.arguments() {
                        undeclared = undeclared.with_arguments(arguments.clone());
                    }
                    // A name's argument text holds whichever table reads it.
                    undeclared = undeclared.with_argument_text(tool.argument_text().clone());
                    let expected = crate::tool_operation::declare(
                        crate::tool_operation::table(client).unwrap_or(&[]),
                        undeclared,
                    );
                    assert_eq!(hook.body(), &ObservationBody::Tool(expected));
                }
                body => assert_eq!(hook.body(), body),
            }
            assert_eq!(hook.kind(), reference.kind());
            assert_eq!(hook.stage(), reference.stage());
            assert_eq!(hook.occurred_at(), reference.occurred_at());
            assert_eq!(hook.sequence(), reference.sequence());
            assert_eq!(hook.session_id(), reference.session_id());
            assert_eq!(hook.correlation(), reference.correlation());
            assert_eq!(hook.facets(), reference.facets());
            assert_eq!(hook.fact_metadata(), reference.fact_metadata());
            assert_eq!(hook.retained_byte_len(), reference.retained_byte_len());
        }
        // The same window under another identity is another source: no
        // observation is shared.
        for other in &session.observations {
            assert!(
                acquired
                    .observations
                    .iter()
                    .all(|o| o.observation_id() != other.observation_id())
            );
        }
    }
}

/// A hook journal converts strictly: a call over a value bound is
/// quarantined, never admitted with the value replaced, while the session
/// reading of the same window admits it.
#[test]
#[cfg(feature = "hook-journal")]
fn hook_journal_quarantines_a_call_over_a_value_bound() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("window.jsonl");
    let call = serde_json::json!({"type":"assistant","sessionId":"synthetic-window","uuid":"a1","timestamp":"2026-11-04T00:00:00.002Z","message":{"role":"assistant","content":[{"type":"tool_use","id":"call_1","name":"mcp__synthetic__run","input":{"query":"z ".repeat(2_500),"file_path":"/synthetic/project/notes.txt"}}]}});
    std::fs::write(&path, format!("{call}\n")).unwrap();
    let tool_calls = |batch: &super::AcquisitionBatch| {
        batch
            .observations
            .iter()
            .filter(|observation| matches!(observation.body(), ObservationBody::Tool(_)))
            .count()
    };
    let session = super::acquire_source(
        &journal_source(ClientId::Claude, "claude.projects", &path),
        options(),
    )
    .unwrap();
    assert_eq!((session.bounded.len(), session.quarantined.len()), (1, 0));
    assert_eq!(tool_calls(&session), 1);
    for &client in ClientId::ALL {
        let source = journal_source(client, client.hook_journal_source_id(), &path);
        let journal = super::acquire_source(&source, options()).unwrap();
        assert_eq!(
            (journal.bounded.len(), journal.quarantined.len()),
            (0, 1),
            "{client:?}"
        );
        assert_eq!(tool_calls(&journal), 0, "{client:?}");
    }
}

#[test]
fn hook_journal_pairs_refuse_other_clients_kinds_and_bounded_reads() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("window.jsonl");
    std::fs::write(&path, JOURNAL_WINDOW).unwrap();
    let compiled = cfg!(feature = "hook-journal");
    for &client in ClientId::ALL {
        let source_id = client.hook_journal_source_id();
        for &other in ClientId::ALL.iter().filter(|other| **other != client) {
            let cross = journal_source(other, source_id, &path);
            assert_eq!(
                acquisition_error(super::acquire_source(&cross, options())),
                AcquisitionError::UnsupportedSourceIdentity
            );
        }
        let mut source = journal_source(client, source_id, &path);
        let bounded = super::acquire_source_bounded(
            directory.path(),
            &source,
            options(),
            super::DirectReadLimits::default(),
        );
        assert_eq!(
            acquisition_error(bounded),
            AcquisitionError::UnsupportedSourceIdentity
        );
        if !compiled {
            // An uncompiled capability: refused before any source I/O.
            assert_eq!(
                acquisition_error(super::acquire_source(&source, options())),
                AcquisitionError::CapabilityNotCompiled
            );
            continue;
        }
        for kind in [
            SourceKind::Json,
            SourceKind::ArchivedJsonl,
            SourceKind::HeadlessJsonl,
            SourceKind::Sqlite,
            SourceKind::CopilotProcessLog,
        ] {
            source.kind = kind;
            assert_eq!(
                acquisition_error(super::acquire_source(&source, options())),
                AcquisitionError::SourceKindMismatch
            );
        }
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
                ClientId::Pi => crate::test_fixture_path(
                    "session_stores/pi/sessions/--synthetic-project-b--/2026-04-27T12-40-00-000Z_pi-uc001-tool-result.jsonl",
                ),
                _ => codex_path.clone(),
            },
        };
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
                ClientId::Pi => "2026-04-27T12:40:00.200Z",
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
    }
    assert_eq!(codex_ids.len(), 3);
}

#[test]
fn dispatcher_rejects_identity_and_kind_before_io() {
    let directory = tempdir().unwrap();
    let missing = directory.path().join("private-missing-source");
    let clients = crate::clients::supported_clients();
    for (client, definition) in clients
        .iter()
        .flat_map(|client| client.sources.iter().map(move |source| (client.id, source)))
    {
        let source_id = definition.id;
        let kind = definition.kind;
        let mut source = Source {
            client,
            source_id: source_id.to_owned(),
            kind,
            path: missing.clone(),
        };
        for wrong_kind in [
            SourceKind::Json,
            SourceKind::Jsonl,
            SourceKind::ArchivedJsonl,
            SourceKind::HeadlessJsonl,
            SourceKind::Sqlite,
            SourceKind::CopilotProcessLog,
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
        if client != ClientId::OpenCode {
            assert_eq!(
                acquisition_error(acquire_opencode_sqlite(
                    &source,
                    options(),
                    OpenCodeSqliteReadOptions::default()
                )),
                AcquisitionError::UnsupportedSourceIdentity
            );
        }
        for wrong_client in clients.iter().map(|client| client.id) {
            if wrong_client == client {
                continue;
            }
            source.client = wrong_client;
            assert_eq!(
                acquisition_error(super::acquire_source(&source, options())),
                AcquisitionError::UnsupportedSourceIdentity
            );
        }
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
fn copilot_scan_read_failures_stay_plain_source_read_failures() {
    let directory = tempdir().unwrap();
    let source = Source {
        client: ClientId::Copilot,
        source_id: "copilot.process_log".to_owned(),
        kind: SourceKind::CopilotProcessLog,
        path: directory.path().join("missing-process.log"),
    };
    assert_eq!(
        acquisition_error(super::acquire_source(&source, options())),
        AcquisitionError::SourceRead
    );
    assert_eq!(
        acquisition_error(super::acquire_resolved_source(&source, options())),
        AcquisitionError::SourceRead
    );
}

#[test]
fn bounded_acquisition_keeps_its_jsonl_only_subset() {
    let directory = tempdir().unwrap();
    let missing = directory.path().join("missing-source");
    for client in crate::clients::supported_clients() {
        for definition in client.sources {
            let source = Source {
                client: client.id,
                source_id: definition.id.to_owned(),
                kind: definition.kind,
                path: missing.clone(),
            };
            let expected = if matches!(
                definition.kind,
                SourceKind::Jsonl | SourceKind::ArchivedJsonl | SourceKind::HeadlessJsonl
            ) {
                AcquisitionError::BoundedSourceRead(BoundedReadError::Missing)
            } else {
                AcquisitionError::UnsupportedSourceIdentity
            };
            assert_eq!(
                acquisition_error(super::acquire_source_bounded(
                    directory.path(),
                    &source,
                    options(),
                    super::DirectReadLimits::default()
                )),
                expected,
                "{}",
                definition.id
            );
        }
    }
    assert!(!missing.exists());
}

#[test]
#[cfg(feature = "opencode-sqlite")]
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
                &JsonValue::try_from_source_value(&serde_json::json!({"text":"synthetic result"}))
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
fn codex_bound_diagnostic_quarantines_the_late_record() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("synthetic-bound.jsonl");
    let oversized = "x".repeat(65_537);
    let input = format!(
        "{}\n{}\n",
        serde_json::json!({"type":"user", "session_id":"synthetic", "content":"ok"}),
        serde_json::json!({"type":"user", "session_id":"synthetic", "content":oversized})
    );
    std::fs::write(&path, input).unwrap();
    for (source_id, kind) in [
        ("codex.sessions", SourceKind::Jsonl),
        ("codex.archived_sessions", SourceKind::ArchivedJsonl),
        ("codex.headless_sessions", SourceKind::HeadlessJsonl),
    ] {
        let source = Source {
            client: ClientId::Codex,
            source_id: source_id.into(),
            kind,
            path: path.clone(),
        };
        let batch = super::acquire_source(&source, options()).unwrap();
        assert_eq!(batch.observations.len(), 1);
        assert_eq!(batch.quarantined.len(), 1);
        assert_eq!(batch.quarantined[0].code, "unbounded_value");
        assert_eq!(
            batch.quarantined[0].session_id.as_deref(),
            Some("synthetic")
        );
        let diagnostic = format!("{:?}", batch.quarantined);
        assert!(
            diagnostic.contains("MessageContent"),
            "missing canonical category"
        );
        assert!(
            diagnostic.contains("StringBytes"),
            "missing bound dimension"
        );
        assert!(!diagnostic.contains(&oversized), "content leaked");
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
            let unknown_discriminator = expected
                == (AcquisitionError::CanonicalMapping {
                    code: "unknown_discriminator",
                });
            // Pi has no `user` entry type: both payloads are unknown entries.
            let pi_unknown = client == ClientId::Pi && expected != AcquisitionError::SourceRead;
            if matches!(client, ClientId::Claude | ClientId::Codex) && unknown_discriminator
                || pi_unknown
            {
                // Claude, Codex and Pi quarantine an unknown record by itself.
                let batch = super::acquire_source(&source, options()).unwrap();
                assert_eq!(batch.quarantined[0].code, "unknown_discriminator");
                assert!(!format!("{:?}", batch.quarantined).contains("private-"));
                continue;
            }
            let error = acquisition_error(super::acquire_source(&source, options()));
            assert_eq!(error, expected);
            let rendered = format!("{error} {error:?}");
            assert!(!rendered.contains("private-"));
        }
    }
}

#[test]
fn copilot_acquisition_preserves_reference_lifecycle_and_evidence() {
    use telltale_schema::observation::{CapabilityAvailability, CapabilityId, ObservationStage};
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
        let acquired = super::acquire_source(&source, options()).unwrap();
        let replay = super::acquire_source(&source, options()).unwrap();
        let reference = super::project_copilot_native_events(
            &crate::sources::copilot::native::extract_copilot_native_events(&source).unwrap(),
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
        }
    }
}

#[test]
fn copilot_acquisition_failures_preserve_strict_reference_behavior() {
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
    for (input, expected) in [
        (
            item.to_owned(),
            AcquisitionError::CanonicalMapping {
                code: "replay_unverifiable",
            },
        ),
        (
            format!("{init}{item}Session completed.\n{item}"),
            AcquisitionError::CanonicalMapping {
                code: "replay_unverifiable",
            },
        ),
        (
            format!("{init}{item}Accumulated output items (1): [{{private-malformed-marker"),
            AcquisitionError::CanonicalMapping {
                code: "malformed_structured_output",
            },
        ),
        (
            "Accumulated output items (1): [private-malformed-marker".to_owned(),
            AcquisitionError::CanonicalMapping {
                code: "replay_unverifiable",
            },
        ),
        (
            format!("{init}Accumulated output items (1): [42]"),
            AcquisitionError::SourceRead,
        ),
    ] {
        std::fs::write(&path, input).unwrap();
        let error = acquisition_error(super::acquire_source(&source, options()));
        assert_eq!(error, expected);
        assert!(!format!("{error} {error:?}").contains("private-"));
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
#[cfg(feature = "opencode-sqlite")]
fn long_message_sqlite_acquisition_keeps_full_suffix_and_rejects_atomically() {
    use telltale_schema::observation::{JsonValue, ObservationBody};
    let (_directory, connection, source) = database();
    for (bytes, accepted) in [(9_000, true), (65_537, false)] {
        let text = format!("{}suffix", "x".repeat(bytes - 6));
        connection
            .execute(
                "update part set data = ?1 where id = 'part-third'",
                [serde_json::json!({"type":"text", "text":text}).to_string()],
            )
            .unwrap();
        let result = super::acquire_source(&source, options());
        if accepted {
            let batch = result.unwrap();
            assert!(batch.observations.iter().any(|observation| matches!(observation.body(), ObservationBody::Message(message) if message.content() == Some(&JsonValue::string(&text)))));
        } else {
            assert_eq!(acquisition_error(result).code(), "unbounded_value");
        }
    }
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
fn missing_opencode_database_is_not_created_by_either_acquisition_entry() {
    let directory = tempdir().unwrap();
    let source = source(directory.path().join("missing.db"));
    for error in [
        acquisition_error(super::acquire_source(&source, options())),
        acquisition_error(acquire_opencode_sqlite(
            &source,
            options(),
            OpenCodeSqliteReadOptions::default(),
        )),
    ] {
        let expected = if cfg!(feature = "opencode-sqlite") {
            AcquisitionError::SourceRead
        } else {
            AcquisitionError::CapabilityNotCompiled
        };
        assert_eq!(error, expected);
        assert!(!source.path.exists());
    }
}

#[cfg(not(feature = "opencode-sqlite"))]
#[test]
fn disabled_opencode_acquisition_does_not_touch_present_database() {
    let (directory, connection, source) = database();
    drop(connection);
    let bytes = std::fs::read(&source.path).unwrap();
    let modified = std::fs::metadata(&source.path).unwrap().modified().unwrap();
    for result in [
        super::acquire_source(&source, options()),
        acquire_opencode_sqlite(&source, options(), OpenCodeSqliteReadOptions::default()),
    ] {
        assert_eq!(
            acquisition_error(result),
            AcquisitionError::CapabilityNotCompiled
        );
    }
    assert_eq!(std::fs::read(&source.path).unwrap(), bytes);
    assert_eq!(
        std::fs::metadata(&source.path).unwrap().modified().unwrap(),
        modified
    );
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
}

#[test]
#[cfg(feature = "opencode-sqlite")]
fn malformed_serialized_message_data_fails_atomically_but_metadata_only_succeeds() {
    let (_directory, connection, source) = database();
    connection.execute("delete from part", []).unwrap();
    connection.execute("delete from message", []).unwrap();
    connection
        .execute(
            "insert into message values ('metadata', 'session', 1, 1, '{}')",
            [],
        )
        .unwrap();
    let valid = super::acquire_source(&source, options()).unwrap();
    assert_eq!(valid.accounting.sessions[0].counts.native_units, 1);
    for invalid in ["not-json", "null", "[]", "42", "\"text\""] {
        connection
            .execute(
                "insert into message values ('malformed', 'session', 2, 2, ?1)",
                [invalid],
            )
            .unwrap();
        assert_eq!(
            acquisition_error(super::acquire_source(&source, options())),
            AcquisitionError::SourceRead,
        );
        connection
            .execute("delete from message where id = 'malformed'", [])
            .unwrap();
    }
    connection
        .execute(
            "insert into message values ('malformed', 'session', 2, 2, NULL)",
            [],
        )
        .unwrap();
    assert_eq!(
        acquisition_error(super::acquire_source(&source, options())),
        AcquisitionError::SourceRead,
    );
}

#[test]
#[cfg(feature = "opencode-sqlite")]
fn sqlite_admission_failure_is_source_read_without_partial_acquisition() {
    let (_directory, connection, source) = database();
    let before = super::acquire_source(&source, options()).unwrap();
    connection.execute_batch("alter table message add column unknown blob; alter table part add column unknown blob;").unwrap();
    let under = super::acquire_source(&source, options()).unwrap();
    assert_eq!(
        format!("{:?}", under.observations),
        format!("{:?}", before.observations)
    );
    assert_eq!(under.accounting, before.accounting);
    assert_eq!(under.progress, before.progress);
    connection.execute_batch("insert into part values('unselected','message-acquisition','session-acquisition',4,4,'{\"type\":\"metadata\"}',zeroblob(8388609));").unwrap();
    let unselected = super::acquire_source(&source, options()).unwrap();
    assert_eq!(
        format!("{:?}", unselected.observations),
        format!("{:?}", before.observations)
    );
    assert_eq!(unselected.accounting, before.accounting);
    assert_eq!(unselected.progress, before.progress);
    connection
        .execute("delete from part where id='unselected'", [])
        .unwrap();
    for table in ["message", "part"] {
        connection
            .execute_batch(&format!("update {table} set unknown=zeroblob(8388609)"))
            .unwrap();
        let error = acquisition_error(super::acquire_source(&source, options()));
        assert_eq!(error, AcquisitionError::SourceRead);
        assert!(!format!("{error:?} {error}").contains("unknown"));
        connection
            .execute_batch(&format!("update {table} set unknown=null"))
            .unwrap();
        let repaired = super::acquire_source(&source, options()).unwrap();
        assert_eq!(
            format!("{:?}", repaired.observations),
            format!("{:?}", before.observations)
        );
        assert_eq!(repaired.accounting, before.accounting);
        assert_eq!(repaired.progress, before.progress);
    }
    connection.execute_batch("insert into message values('metadata-only','another-session',4,4,'{}',zeroblob(8388609));").unwrap();
    assert_eq!(
        acquisition_error(super::acquire_source(&source, options())),
        AcquisitionError::SourceRead
    );
}

#[test]
#[cfg(feature = "opencode-sqlite")]
fn incremental_parts_must_fit_the_effective_limit_or_fail_atomically() {
    let (_directory, connection, source) = database();
    connection.execute("delete from part", []).unwrap();
    for i in 0..7 {
        connection.execute(
                "insert into part values (?1, 'message-acquisition', 'session-acquisition', 1, ?2, '{\"type\":\"text\",\"text\":\"synthetic\"}')",
                (format!("part-{i}"), if i < 5 { 100 } else { 100 + i }),
            ).unwrap();
    }
    let read = |min, limit| {
        acquire_opencode_sqlite(
            &source,
            options(),
            OpenCodeSqliteReadOptions {
                part_min_time_updated: min,
                part_limit: limit,
                resume_high_water: None,
                ..Default::default()
            },
        )
    };
    for (limit, expected) in [(8, 7), (7, 7), (6, 6)] {
        let batch = read(Some(i64::MIN), limit);
        if limit == 6 {
            assert_eq!(
                acquisition_error(batch),
                AcquisitionError::BoundedSourceRead(BoundedReadError::LimitExceeded)
            );
        } else {
            assert_eq!(batch.unwrap().observations.len(), expected);
        }
    }
    // Selecting more parts than the (at least one) limit is a typed overflow.
    for limit in [0, -1, 1, 2, 3, 4, 5] {
        assert_eq!(
            acquisition_error(read(Some(100), limit)),
            AcquisitionError::BoundedSourceRead(BoundedReadError::LimitExceeded),
        );
    }
    // An unrepresentable page limit is rejected before reading.
    assert_eq!(
        acquisition_error(read(Some(100), i64::MAX)),
        AcquisitionError::SourceRead,
    );
    for limit in [0, -1, 1] {
        let one = read(Some(106), limit).unwrap();
        assert_eq!(one.observations.len(), 1);
        assert_eq!(
            one.progress,
            AcquisitionProgress::OpenCodeSqlite {
                part_max_time_updated: Some(106)
            }
        );
    }
    assert_eq!(read(Some(105), 2).unwrap().observations.len(), 2);
    // Bootstrap still selects the newest bounded rows without overflow.
    assert_eq!(read(None, 2).unwrap().observations.len(), 2);
    let empty = read(Some(i64::MAX), 1).unwrap();
    assert!(empty.observations.is_empty());
    assert_eq!(
        empty.progress,
        AcquisitionProgress::OpenCodeSqlite {
            part_max_time_updated: None
        }
    );
    connection.execute("delete from part", []).unwrap();
    assert!(read(Some(i64::MIN), 1).unwrap().observations.is_empty());
}

#[test]
#[cfg(feature = "opencode-sqlite")]
fn dense_distinct_incremental_timestamps_fail_instead_of_truncating() {
    let (_directory, connection, source) = database();
    connection.execute("delete from part", []).unwrap();
    for i in 0..7_i64 {
        connection.execute(
                "insert into part values (?1, 'message-acquisition', 'session-acquisition', 1, ?2, '{\"type\":\"text\",\"text\":\"synthetic\"}')",
                (format!("part-{i}"), 1_000 + i),
            ).unwrap();
    }
    assert_eq!(
        acquisition_error(acquire_opencode_sqlite(
            &source,
            options(),
            OpenCodeSqliteReadOptions {
                part_min_time_updated: Some(1_000),
                part_limit: 5,
                resume_high_water: None,
                ..Default::default()
            },
        )),
        AcquisitionError::BoundedSourceRead(BoundedReadError::LimitExceeded),
    );
}

#[test]
#[cfg(feature = "opencode-sqlite")]
fn default_acquisition_preserves_canonical_semantics_and_observed_time() {
    let (_directory, connection, source) = database();
    drop(connection);

    let acquired = super::acquire_source(&source, options()).unwrap();
    assert_eq!(acquired.observations.len(), 3);
    for (observation, (id, text)) in acquired.observations.iter().zip([
        ("part-first", "first"),
        ("part-second", "second"),
        ("part-third", "third"),
    ]) {
        assert_eq!(observation.source().native_id(), Some(id));
        assert_eq!(observation.observed_at().as_str(), OBSERVED_AT);
        let ObservationBody::Message(message) = observation.body() else {
            panic!("expected text part message")
        };
        assert_eq!(
            message.content(),
            Some(&telltale_schema::observation::JsonValue::string(text))
        );
    }
    assert_eq!(
        acquired.progress,
        AcquisitionProgress::OpenCodeSqlite {
            part_max_time_updated: Some(3_000)
        }
    );
}

#[test]
#[cfg(feature = "opencode-sqlite")]
fn bounded_read_options_return_selected_progress() {
    let (_directory, connection, source) = database();
    drop(connection);
    let read = OpenCodeSqliteReadOptions {
        part_min_time_updated: Some(3_000),
        part_limit: 1,
        resume_high_water: None,
        ..Default::default()
    };

    let acquired = acquire_opencode_sqlite(&source, options(), read).unwrap();
    assert_eq!(acquired.observations.len(), 1);
    let ObservationBody::Message(message) = acquired.observations[0].body() else {
        panic!("expected selected message part")
    };
    assert_eq!(
        message.content(),
        Some(&telltale_schema::observation::JsonValue::string("third"))
    );
    assert_eq!(
        acquired.progress,
        AcquisitionProgress::OpenCodeSqlite {
            part_max_time_updated: Some(3_000)
        }
    );
}

#[test]
#[cfg(feature = "opencode-sqlite")]
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
#[cfg(feature = "opencode-sqlite")]
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
