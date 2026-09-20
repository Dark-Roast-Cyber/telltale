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
            MessageObservation::new(MessageRole::User).with_content(JsonValue::string("needle")),
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
            rules: &plan("user_context"),
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
                rules: &plan,
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
            rules: &plan,
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
            rules: &plan("user_context"),
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
