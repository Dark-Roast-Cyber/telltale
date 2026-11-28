use super::*;

#[test]
fn registry_acquisition_and_evaluation_domains_agree() {
    use std::collections::BTreeSet;
    use telltale_sources::acquisition::{AcquisitionOptions, acquire_source};

    // Assignment admission is reviewed independently, not inherited from a new
    // acquisition registration. This is an explicit subset of source support.
    #[cfg(feature = "protected-assignment")]
    let reviewed_assignments = BTreeSet::from([
        ("claude_code", "claude.projects"),
        ("codex", "codex.sessions"),
        ("codex", "codex.archived_sessions"),
        ("codex", "codex.headless_sessions"),
        ("copilot", "copilot.process_log"),
        ("openclaw", "openclaw.agents"),
        ("opencode", "opencode.sqlite"),
        ("qwen", "qwen.projects"),
        ("pi", "pi.sessions"),
    ]);

    let directory = tempdir().unwrap();
    let codex = directory.path().join("codex.jsonl");
    std::fs::write(&codex, concat!(
        "{\"type\":\"session_meta\",\"payload\":{\"session_id\":\"synthetic\"}}\n",
        "{\"type\":\"response_item\",\"payload\":{\"type\":\"message\",\"role\":\"user\",\"content\":\"needle\"}}\n"
    )).unwrap();
    // Keep native inputs inside the package: workspace fixtures are not shipped
    // with telltale-core, and this test also runs from normalized packages.
    for (name, content) in [
        (
            "claude.jsonl",
            r#"{"type":"user","sessionId":"synthetic","message":{"role":"user","content":"needle"}}"#,
        ),
        (
            "openclaw.jsonl",
            r#"{"type":"user","sessionId":"synthetic","content":"needle"}"#,
        ),
        (
            "qwen.jsonl",
            r#"{"type":"user","sessionId":"synthetic","content":"needle"}"#,
        ),
        (
            "pi.jsonl",
            concat!(
                "{\"type\":\"session\",\"version\":3,\"id\":\"synthetic\"}\n",
                "{\"type\":\"message\",\"id\":\"e1\",\"message\":{\"role\":\"user\",\"content\":\"needle\"}}\n"
            ),
        ),
        (
            "copilot.log",
            concat!(
                "Workspace initialized: synthetic (checkpoints: 0)\n",
                "Accumulated output items (1): [{\"type\":\"function_call\",\"name\":\"view\",\"call_id\":\"synthetic-call\",\"arguments\":\"needle\"}]\n",
                "Session completed.\n"
            ),
        ),
    ] {
        std::fs::write(directory.path().join(name), content).unwrap();
    }
    let opencode = directory.path().join("opencode.db");
    #[cfg(feature = "opencode-sqlite")]
    {
        let connection = rusqlite::Connection::open(&opencode).unwrap();
        connection.execute_batch(
            r#"CREATE TABLE session_v2 (id TEXT PRIMARY KEY, agent TEXT, model TEXT);
            CREATE TABLE session_message (id TEXT PRIMARY KEY, session_id TEXT, type TEXT, seq INTEGER,
                time_created INTEGER, time_updated INTEGER, data TEXT);
            INSERT INTO session_v2 VALUES ('synthetic', 'build', NULL);
            INSERT INTO session_message VALUES ('message', 'synthetic', 'user', 1, 0, 1,
                '{"text":"needle","time":{"created":0}}');"#,
        ).unwrap();
    }
    let registered = telltale_sources::clients::supported_clients()
        .iter()
        .flat_map(|client| {
            client
                .sources
                .iter()
                .map(move |source| (client.id, source.id, source.kind))
        })
        .collect::<BTreeSet<_>>();
    let rules = plan("user_context");
    let mut acquired = BTreeSet::new();
    let mut evaluated = BTreeSet::new();
    let mut not_compiled = BTreeSet::new();
    for &(client, source_id, kind) in &registered {
        let source = Source {
            client,
            source_id: source_id.into(),
            kind,
            path: match client {
                ClientId::Codex => codex.clone(),
                ClientId::Claude => directory.path().join("claude.jsonl"),
                ClientId::OpenClaw => directory.path().join("openclaw.jsonl"),
                ClientId::Qwen => directory.path().join("qwen.jsonl"),
                ClientId::Copilot => directory.path().join("copilot.log"),
                ClientId::Pi => directory.path().join("pi.jsonl"),
                ClientId::OpenCode => opencode.clone(),
                _ => panic!("registered client needs a native conformance fixture"),
            },
        };
        let observations = match acquire_source(&source, AcquisitionOptions::new(clock())) {
            Ok(batch) => {
                assert!(!batch.observations.is_empty(), "{source_id}");
                acquired.insert((client, source_id, kind));
                batch.observations
            }
            Err(AcquisitionError::CapabilityNotCompiled) if !cfg!(feature = "opencode-sqlite") => {
                assert_eq!(client, ClientId::OpenCode);
                assert!(!opencode.exists());
                not_compiled.insert((client, source_id, kind));
                Vec::new()
            }
            Err(error) => panic!("{source_id}: {error}"),
        };
        #[cfg(feature = "protected-assignment")]
        for observation in &observations {
            let provenance = observation.source();
            let pair = (provenance.adapter_type(), provenance.adapter_id());
            assert_eq!(
                crate::assignment::AssignmentAdapterDomain::registered(pair.0, pair.1).is_ok(),
                reviewed_assignments.contains(&pair),
                "{source_id} assignment admission"
            );
        }
        for &(candidate_client, candidate_id, _) in &registered {
            let result = evaluate_source(
                CanonicalSourceInput {
                    client: candidate_client,
                    source_id: candidate_id,
                    source_instance: None,
                    observations: &observations,
                },
                &rules,
                None,
            );
            if candidate_client == client && candidate_id == source_id {
                result.unwrap_or_else(|error| panic!("{source_id}: {error}"));
                evaluated.insert((client, source_id, kind));
            } else if !observations.is_empty() {
                assert!(
                    matches!(result, Err(ProcessingError::InvalidSource)),
                    "{source_id} as {candidate_id}"
                );
            }
        }
        for candidate_client in telltale_sources::clients::supported_clients() {
            if candidate_client.id != client {
                assert!(matches!(
                    evaluate_source(
                        CanonicalSourceInput {
                            client: candidate_client.id,
                            source_id,
                            source_instance: None,
                            observations: &[],
                        },
                        &rules,
                        None,
                    ),
                    Err(ProcessingError::InvalidSource)
                ));
            }
        }
    }
    assert_eq!(evaluated, registered);
    acquired.extend(not_compiled);
    assert_eq!(acquired, registered);
    #[cfg(feature = "protected-assignment")]
    {
        let mut admitted = BTreeSet::new();
        for &(adapter_type, _) in &reviewed_assignments {
            for &(_, source_id, _) in &registered {
                match crate::assignment::AssignmentAdapterDomain::registered(
                    adapter_type,
                    source_id,
                ) {
                    Ok(_) => {
                        admitted.insert((adapter_type, source_id));
                    }
                    Err(error) => assert_eq!(
                        error.error_code(),
                        crate::assignment::ProtectedAssignmentErrorCode::InvalidClaim
                    ),
                }
            }
        }
        assert_eq!(admitted, reviewed_assignments);
    }
}

#[test]
fn instance_scope_is_file_bound_not_content_or_session_bound() {
    let dir = tempdir().unwrap();
    let a = source(dir.path().join("a"));
    let b = source(dir.path().join("b"));
    std::fs::write(&a.path, "same").unwrap();
    std::fs::write(&b.path, "same").unwrap();
    let (_, first) = verified_source(&a).unwrap();
    assert_ne!(first, verified_source(&b).unwrap().1);
    std::fs::write(&a.path, "changed").unwrap();
    assert_eq!(first, verified_source(&a).unwrap().1);
    let alias = source(dir.path().join(".").join("a"));
    assert_eq!(first, verified_source(&alias).unwrap().1);
    let mut other_identity = a.clone();
    other_identity.client = ClientId::Qwen;
    other_identity.source_id = "qwen.projects".into();
    assert_ne!(first, verified_source(&other_identity).unwrap().1);
    assert!(verified_source(&source(dir.path().to_owned())).is_err());
}

#[test]
fn metadata_origin_must_match_not_just_visible_session_id() {
    use telltale_sources::acquisition::{AttestedValue, SessionAccounting, SessionMetadata};
    let source = source("synthetic".into());
    let instance = CorrelationId::source_reported("test-instance").unwrap();
    let result = finish_batch(
        &source,
        &instance,
        AcquisitionBatch {
            quarantined: Vec::new(),
            bounded: Vec::new(),
            message_overlap_from: None,
            source_scale: telltale_schema::observation::SourceScale::FLOOR,
            observations: vec![message("one", Some("s"))],
            progress: AcquisitionProgress::None,
            accounting: SourceAccounting {
                sessions: vec![SessionAccounting {
                    session_id: CorrelationId::new("s", CorrelationOrigin::TelltaleOriginated)
                        .unwrap(),
                    metadata: SessionMetadata {
                        agent: AttestedValue::Known("wrong-origin-agent".into()),
                        ..Default::default()
                    },
                    counts: Default::default(),
                }],
                unscoped: Default::default(),
                coverage: Default::default(),
                tool_table: Default::default(),
            },
        },
        SourceContext {
            mcp_servers: &[],
            rules: &plan("user_context"),
            pre_policy_rules: None,
            process: None,
            prior: &BaselineSnapshotStore::default(),
            baseline_deviation: BaselineDeviationConfig::default(),
        },
    );
    assert_eq!(
        result.err().expect("origin collision").stage,
        FailureStage::Activity
    );
}
