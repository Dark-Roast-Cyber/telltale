use super::*;
use telltale_detect::v2::compile_rule_v1;
use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::observation::CorrelationOrigin;
use tempfile::tempdir;

fn clock() -> ObservedAt {
    ObservedAt::new("2026-09-19T00:00:00Z").unwrap()
}

fn source(path: std::path::PathBuf) -> Source {
    Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".into(),
        path,
    }
}

fn plan(target: &str) -> RuleV1CompatibilityPlan {
    let yaml = format!(
        "version: 1\ndescription: synthetic\ndefaults:\n  case_insensitive: false\n  enabled: true\nrules:\n  - id: synthetic.target\n    category: synthetic\n    detection_class: security_detection\n    signal_type: atomic\n    analytic_intent: alert\n    severity: low\n    score: 1\n    targets: [{target}]\n    regex: needle\n    tags: [synthetic]\n    explanation: synthetic\nmodifiers: []\n"
    );
    compile_rule_v1(
        &telltale_rules::load_rule_set_from_documents(&[&yaml], None)
            .unwrap()
            .compatibility_export(),
    )
    .unwrap()
}

fn message(
    id: &str,
    session: Option<&str>,
) -> telltale_schema::observation::CanonicalObservationV2 {
    message_with_content(id, session, "needle")
}

fn message_with_content(
    id: &str,
    session: Option<&str>,
    content: &str,
) -> telltale_schema::observation::CanonicalObservationV2 {
    use telltale_schema::observation::*;
    let provenance = SourceProvenance::new(
        IngestionMode::SessionStore,
        "claude_code",
        "claude.projects",
        Fidelity::FullNative,
    )
    .unwrap()
    .with_native_id(id)
    .unwrap();
    let mut builder = CanonicalObservationV2::builder(
        ObservationBody::Message(
            MessageObservation::new(MessageRole::User).with_content(JsonValue::string(content)),
        ),
        ObservationStage::MessageObserved,
        clock(),
        provenance,
    )
    .fact_metadata("message.role", FactMetadata::reported().unwrap())
    .fact_metadata("message.content", FactMetadata::reported().unwrap())
    .capability_context(
        CapabilityContext::new()
            .with_override(CapabilityId::UserContext, CapabilityAvailability::Supported),
    );
    if let Some(session) = session {
        builder = builder.session_id(CorrelationId::source_reported(session).unwrap());
    }
    builder.build().unwrap()
}

#[test]
fn canonical_policy_accounting_counts_filtered_modifiers_and_fully_filtered_sessions() {
    use telltale_sources::acquisition::{AccountingCoverage, SessionAccounting};

    const RULES: &str = r#"version: 1
description: synthetic policy accounting
defaults:
  case_insensitive: false
  enabled: true
rules:
  - id: test.first
    category: test
    severity: medium
    score: 1
    targets: [user_context]
    regex: needle
    tags: []
    explanation: first match
  - id: test.second
    category: test
    severity: medium
    score: 1
    targets: [user_context]
    regex: second
    tags: []
    explanation: second match
modifiers:
  - id: chain.test
    score: 1
    when_all_rule_ids: [test.first]
    explanation: test modifier
"#;
    let compiled = |policy| {
        compile_rule_v1(
            &telltale_rules::load_rule_set_from_documents(&[RULES], policy)
                .unwrap()
                .compatibility_export(),
        )
        .unwrap()
    };
    let before = compiled(None);
    let effective = compiled(Some("disabled_rules: [chain.test, test.second]\n"));
    let observations = vec![
        message("first", Some("s-a")),
        message_with_content("second", Some("s-b"), "second"),
    ];
    let instance = CorrelationId::source_reported("instance").unwrap();
    let source = source("synthetic".into());
    let pre_policy = evaluate_source(
        CanonicalSourceInput {
            client: source.client,
            source_id: &source.source_id,
            source_instance: Some(&instance),
            observations: &observations,
        },
        &before,
        None,
    )
    .unwrap();
    assert_eq!(pre_policy.sessions().len(), 2);
    assert_eq!(
        pre_policy.sessions()[0].rule_ids(),
        ["chain.test", "test.first"]
    );
    assert_eq!(pre_policy.sessions()[1].rule_ids(), ["test.second"]);

    let accounting = SourceAccounting {
        coverage: AccountingCoverage::CompleteSource,
        sessions: ["s-a", "s-b"]
            .map(|id| SessionAccounting {
                session_id: CorrelationId::source_reported(id).unwrap(),
                metadata: Default::default(),
                counts: Default::default(),
            })
            .to_vec(),
        ..Default::default()
    };
    let result = finish_batch(
        &source,
        &instance,
        AcquisitionBatch {
            observations,
            progress: AcquisitionProgress::None,
            accounting,
        },
        SourceContext {
            mcp_servers: &[],
            rules: &effective,
            pre_policy_rules: Some(&before),
            process: None,
            prior: &BaselineSnapshotStore::default(),
            baseline_deviation: BaselineDeviationConfig::default(),
        },
    )
    .unwrap();
    let detections = result
        .events
        .iter()
        .filter(|event| event.event_type == "detection")
        .collect::<Vec<_>>();
    assert_eq!(detections.len(), 1);
    assert_eq!(detections[0].session_id, "s-a");
    assert_eq!(detections[0].rule_ids, ["test.first"]);
    assert_eq!(
        result.policy_accounting.unwrap().unwrap(),
        PolicyMatchAccounting {
            pre_policy_detection_candidate_count: 2,
            fully_filtered_detection_candidate_count: 1,
            filtered_rule_id_count: 2,
        }
    );
}

#[test]
fn mcp_projection_is_atomic_with_late_activity_failure() {
    use telltale_sources::acquisition::{SessionAccounting, ToolUsage};
    let directory = tempdir().unwrap();
    std::fs::write(
        directory.path().join(".mcp.json"),
        r#"{"mcpServers":{"synthetic":{"command":"synthetic","tools":["lookup"]}}}"#,
    )
    .unwrap();
    let servers = telltale_detect::mcp::discover_mcp_inventory_servers(directory.path());
    let mut accounting = SourceAccounting::default();
    let mut counts = telltale_sources::acquisition::NativeCounts::default();
    counts.record_counts.tool_call = 1;
    counts.tool_usage.insert(
        "lookup".into(),
        ToolUsage {
            count: 1,
            first_order: 1,
            first_timestamp: Some((1, "2026-09-19T00:00:00Z".into())),
        },
    );
    accounting.sessions.push(SessionAccounting {
        session_id: CorrelationId::source_reported("s").unwrap(),
        metadata: Default::default(),
        counts,
    });
    let source = source("synthetic".into());
    let projected =
        telltale_detect::mcp::project_mcp_usage(&source, &accounting, &servers).unwrap();
    assert_eq!(projected.len(), 1);
    assert!(projected[0].evidence.iter().any(|e| {
        e.redacted_value
            .contains("\"attribution_method\":\"declared_tools\"")
    }));
    accounting.sessions[0].counts.record_counts.user_message = u64::from(u32::MAX) + 1;
    let result = finish_batch(
        &source,
        &CorrelationId::new("instance", CorrelationOrigin::TelltaleOriginated).unwrap(),
        AcquisitionBatch {
            observations: vec![message("one", Some("s"))],
            progress: AcquisitionProgress::None,
            accounting,
        },
        SourceContext {
            mcp_servers: &servers,
            rules: &plan("user_context"),
            pre_policy_rules: None,
            process: None,
            prior: &BaselineSnapshotStore::default(),
            baseline_deviation: Default::default(),
        },
    );
    assert!(matches!(
        result,
        Err(SourceFailure {
            stage: FailureStage::Activity,
            ..
        })
    ));
}

#[test]
fn activity_failure_discards_successful_source_output() {
    use telltale_sources::acquisition::{AccountingCoverage, SessionAccounting};
    let source = source("synthetic".into());
    let mut accounting = SourceAccounting {
        coverage: AccountingCoverage::CompleteSource,
        ..Default::default()
    };
    for id in ["s", "bad"] {
        accounting.sessions.push(SessionAccounting {
            session_id: CorrelationId::source_reported(id).unwrap(),
            metadata: Default::default(),
            counts: Default::default(),
        });
    }
    accounting.sessions[1].counts.record_counts.user_message = u64::from(u32::MAX) + 1;
    let result = finish_batch(
        &source,
        &CorrelationId::source_reported("instance").unwrap(),
        AcquisitionBatch {
            observations: vec![message("one", Some("s"))],
            progress: AcquisitionProgress::OpenCodeSqlite {
                part_max_time_updated: Some(42),
            },
            accounting,
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
    let error = result
        .err()
        .expect("activity overflow must discard source output");
    assert_eq!(error.stage, FailureStage::Activity);
    assert_eq!(
        error.progress,
        AcquisitionProgress::OpenCodeSqlite {
            part_max_time_updated: Some(42),
        }
    );
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
fn evaluation_and_projection_failures_discard_successful_source_output() {
    let source = source("PRIVATE-path".into());
    let instance = CorrelationId::source_reported("test-instance").unwrap();
    let progress = AcquisitionProgress::OpenCodeSqlite {
        part_max_time_updated: Some(42),
    };
    let plan = plan("user_context");
    for (observations, expected) in [
        (
            vec![
                message("duplicate", Some("s")),
                message("duplicate", Some("s")),
            ],
            FailureStage::Evaluation,
        ),
        (
            vec![message("scoped", Some("s")), message("unscoped", None)],
            FailureStage::Projection,
        ),
    ] {
        let result = finish_batch(
            &source,
            &instance,
            AcquisitionBatch {
                accounting: SourceAccounting::default(),
                observations,
                progress,
            },
            SourceContext {
                mcp_servers: &[],
                rules: &plan,
                pre_policy_rules: None,
                process: None,
                prior: &BaselineSnapshotStore::default(),
                baseline_deviation: BaselineDeviationConfig::default(),
            },
        );
        let error = result.err().expect("failure must discard source output");
        assert_eq!(error.stage, expected);
        assert_eq!(error.progress, progress);
        for diagnostic in [error.to_string(), format!("{error:?}")] {
            assert!(!diagnostic.contains("PRIVATE"));
            assert!(!diagnostic.contains("needle"));
        }
    }
    let mut wrong_source = source;
    wrong_source.source_id = "codex.sessions".into();
    let result = finish_batch(
        &wrong_source,
        &instance,
        AcquisitionBatch {
            accounting: SourceAccounting::default(),
            observations: vec![message("one", Some("same-session"))],
            progress,
        },
        SourceContext {
            mcp_servers: &[],
            rules: &plan,
            pre_policy_rules: None,
            process: None,
            prior: &BaselineSnapshotStore::default(),
            baseline_deviation: BaselineDeviationConfig::default(),
        },
    );
    assert_eq!(
        result.err().expect("wrong source").stage,
        FailureStage::Evaluation
    );
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
