use super::*;

#[test]
fn pre_policy_compatibility_retention_failure_remains_diagnostic_only() {
    let dir = tempdir().unwrap();
    let source = source(dir.path().join("synthetic-policy.jsonl"));
    let observations = (0..4_097)
        .map(|index| {
            message_with_content(&format!("id{index}"), Some("synthetic-session"), "needle")
        })
        .collect();
    let before = plan("user_context");
    let effective = plan("assistant_context");
    let result = finish_batch(
        &source,
        &CorrelationId::source_reported("instance").unwrap(),
        AcquisitionBatch {
            quarantined: Vec::new(),
            bounded: Vec::new(),
            message_overlap_from: None,
            source_scale: telltale_schema::observation::SourceScale::FLOOR,
            observations,
            progress: AcquisitionProgress::None,
            accounting: SourceAccounting::default(),
        },
        SourceContext {
            mcp_servers: &[],
            rules: &effective,
            pre_policy_rules: Some(&before),
            process: None,
            prior: &BaselineSnapshotStore::default(),
            baseline_deviation: Default::default(),
        },
    )
    .unwrap();
    assert!(matches!(
        result.policy_accounting,
        Some(Err(PolicyMatchAccountingError))
    ));
}

#[test]
fn pre_policy_true_shared_work_exhaustion_discards_authoritative_success() {
    let document = (0..17)
        .map(|index| format!("title: Synthetic {index}\nid: 00000000-0000-4000-8000-{index:012}\nname: synthetic.work{index}\ntaxonomy: telltale\nlogsource:\n    product: ai_agent\n    category: message\ndetection:\n    selection:\n        - message.user_text|re: needle\n    condition: selection\nlevel: low\ntelltale:\n    category: synthetic\n    score: 1\n    explanation: synthetic\n"))
        .collect::<Vec<_>>()
        .join("---\n");
    let before = compile_rule_v1(
        &telltale_rules::load_rule_set_from_documents(&[&document], None)
            .unwrap()
            .compatibility_export(),
    )
    .unwrap();
    let effective = plan("user_context");
    let observations = (0..128)
        .map(|index| {
            message_with_content(
                &format!("id{index}"),
                Some("synthetic-session"),
                &"x".repeat(60_000),
            )
        })
        .collect();
    let source = source("synthetic".into());
    let result = finish_batch(
        &source,
        &CorrelationId::source_reported("instance").unwrap(),
        AcquisitionBatch {
            quarantined: Vec::new(),
            bounded: Vec::new(),
            message_overlap_from: None,
            source_scale: telltale_schema::observation::SourceScale::FLOOR,
            observations,
            progress: AcquisitionProgress::None,
            accounting: SourceAccounting::default(),
        },
        SourceContext {
            mcp_servers: &[],
            rules: &effective,
            pre_policy_rules: Some(&before),
            process: None,
            prior: &BaselineSnapshotStore::default(),
            baseline_deviation: Default::default(),
        },
    );
    assert!(matches!(
        result,
        Err(SourceFailure {
            stage: FailureStage::Evaluation,
            ..
        })
    ));
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
    let servers = crate::inventory::discover_mcp_inventory_servers(directory.path());
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
            quarantined: Vec::new(),
            bounded: Vec::new(),
            message_overlap_from: None,
            source_scale: telltale_schema::observation::SourceScale::FLOOR,
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
            quarantined: Vec::new(),
            bounded: Vec::new(),
            message_overlap_from: None,
            source_scale: telltale_schema::observation::SourceScale::FLOOR,
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
fn evaluation_and_projection_failures_discard_successful_source_output() {
    let source = source("PRIVATE-path".into());
    let instance = CorrelationId::source_reported("test-instance").unwrap();
    let progress = AcquisitionProgress::OpenCodeSqlite {
        part_max_time_updated: Some(42),
    };
    let plan = plan("user_context");
    for (observations, expected, reason) in [
        (
            vec![
                message("duplicate", Some("s")),
                message("duplicate", Some("s")),
            ],
            FailureStage::Evaluation,
            "canonical_duplicate_observation",
        ),
        (
            vec![message("scoped", Some("s")), message("unscoped", None)],
            FailureStage::Projection,
            "event3_projection_failed",
        ),
    ] {
        let result = finish_batch(
            &source,
            &instance,
            AcquisitionBatch {
                quarantined: Vec::new(),
                bounded: Vec::new(),
                message_overlap_from: None,
                source_scale: telltale_schema::observation::SourceScale::FLOOR,
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
        assert!(error.to_string().contains(reason));
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
            quarantined: Vec::new(),
            bounded: Vec::new(),
            message_overlap_from: None,
            source_scale: telltale_schema::observation::SourceScale::FLOOR,
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
