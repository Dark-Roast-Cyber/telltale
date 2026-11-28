use super::*;

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
    let session = super::super::acquire_source(
        &journal_source(ClientId::Claude, "claude.projects", &path),
        options(),
    )
    .unwrap();
    assert!(!session.observations.is_empty());
    for &client in ClientId::ALL {
        let source_id = client.hook_journal_source_id();
        let source = journal_source(client, source_id, &path);
        let acquired = super::super::acquire_source(&source, options()).unwrap();
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
    let tool_calls = |batch: &super::super::AcquisitionBatch| {
        batch
            .observations
            .iter()
            .filter(|observation| matches!(observation.body(), ObservationBody::Tool(_)))
            .count()
    };
    let session = super::super::acquire_source(
        &journal_source(ClientId::Claude, "claude.projects", &path),
        options(),
    )
    .unwrap();
    assert_eq!((session.bounded.len(), session.quarantined.len()), (1, 0));
    assert_eq!(tool_calls(&session), 1);
    for &client in ClientId::ALL {
        let source = journal_source(client, client.hook_journal_source_id(), &path);
        let journal = super::super::acquire_source(&source, options()).unwrap();
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
                acquisition_error(super::super::acquire_source(&cross, options())),
                AcquisitionError::UnsupportedSourceIdentity
            );
        }
        let mut source = journal_source(client, source_id, &path);
        let bounded = super::super::acquire_source_bounded(
            directory.path(),
            &source,
            options(),
            super::super::DirectReadLimits::default(),
        );
        assert_eq!(
            acquisition_error(bounded),
            AcquisitionError::UnsupportedSourceIdentity
        );
        if !compiled {
            // An uncompiled capability: refused before any source I/O.
            assert_eq!(
                acquisition_error(super::super::acquire_source(&source, options())),
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
                acquisition_error(super::super::acquire_source(&source, options())),
                AcquisitionError::SourceKindMismatch
            );
        }
    }
}
