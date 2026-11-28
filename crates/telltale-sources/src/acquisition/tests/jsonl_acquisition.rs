use super::*;

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
        let acquired = super::super::acquire_source(&source, options()).unwrap();
        let replay = super::super::acquire_source(&source, options()).unwrap();
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
fn copilot_scan_read_failures_stay_plain_source_read_failures() {
    let directory = tempdir().unwrap();
    let source = Source {
        client: ClientId::Copilot,
        source_id: "copilot.process_log".to_owned(),
        kind: SourceKind::CopilotProcessLog,
        path: directory.path().join("missing-process.log"),
    };
    assert_eq!(
        acquisition_error(super::super::acquire_source(&source, options())),
        AcquisitionError::SourceRead
    );
    assert_eq!(
        acquisition_error(super::super::acquire_resolved_source(&source, options())),
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
                acquisition_error(super::super::acquire_source_bounded(
                    directory.path(),
                    &source,
                    options(),
                    super::super::DirectReadLimits::default()
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
        let batch = super::super::acquire_source(&source, options()).unwrap();
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
                let batch = super::super::acquire_source(&source, options()).unwrap();
                assert_eq!(batch.quarantined[0].code, "unknown_discriminator");
                assert!(!format!("{:?}", batch.quarantined).contains("private-"));
                continue;
            }
            let error = acquisition_error(super::super::acquire_source(&source, options()));
            assert_eq!(error, expected);
            let rendered = format!("{error} {error:?}");
            assert!(!rendered.contains("private-"));
        }
    }
}
