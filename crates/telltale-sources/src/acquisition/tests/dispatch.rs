use super::*;

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
    let batch = super::super::acquire_source(
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
    let mut exact = super::super::CanonicalCollector {
        limit: total,
        ..super::super::CanonicalCollector::default()
    };
    let mut short = super::super::CanonicalCollector {
        limit: total - 1,
        ..super::super::CanonicalCollector::default()
    };
    let mut fits = true;
    let mut overflows = false;
    for observation in batch.observations {
        fits &= exact.push(observation.clone()).is_ok();
        overflows |= short.push(observation).is_err();
    }
    assert!(fits && overflows);
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
            acquisition_error(super::super::acquire_source(&source, options())),
            expected
        );
    }
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
                acquisition_error(super::super::acquire_source(&source, options())),
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
                acquisition_error(super::super::acquire_source(&source, options())),
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
            acquisition_error(super::super::acquire_source(&source, options())),
            AcquisitionError::UnsupportedSourceIdentity
        );
    }
    assert!(!missing.exists());
}
