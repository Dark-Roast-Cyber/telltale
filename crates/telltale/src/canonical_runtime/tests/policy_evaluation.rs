use super::*;

#[test]
fn codex_instruction_roles_are_isolated_in_shared_runtime_event3() {
    let directory = tempdir().unwrap();
    for (source_id, kind) in [
        ("codex.sessions", SourceKind::Jsonl),
        ("codex.archived_sessions", SourceKind::ArchivedJsonl),
        ("codex.headless_sessions", SourceKind::HeadlessJsonl),
    ] {
        let source = Source {
            client: ClientId::Codex,
            source_id: source_id.into(),
            kind,
            path: directory.path().join("synthetic.jsonl"),
        };
        for (target, control_role) in [("user_context", "user"), ("assistant_context", "assistant")]
        {
            let rules = plan(target);
            let prior = BaselineSnapshotStore::default();
            let run = || {
                process_source(
                    &source,
                    clock(),
                    None,
                    SourceContext {
                        mcp_servers: &[],
                        rules: &rules,
                        pre_policy_rules: None,
                        process: None,
                        prior: &prior,
                        baseline_deviation: Default::default(),
                    },
                )
                .unwrap()
            };
            let instructions = r#"{"type":"session_meta","payload":{"session_id":"s"}}
{"type":"response_item","payload":{"type":"message","role":"system","content":[{"type":"output_text","text":"needle"}]}}
{"type":"response_item","payload":{"type":"message","role":"developer","content":[{"type":"input_text","text":"needle"}]}}
{"type":"response_item","payload":{"type":"message","role":"system","content":"needle"}}
{"type":"response_item","payload":{"type":"message","role":"developer","content":"needle"}}"#;
            std::fs::write(&source.path, instructions).unwrap();
            let isolated = run();
            assert!(
                !isolated
                    .events
                    .iter()
                    .any(|event| event.event_type == "detection")
            );
            assert!(isolated.events.iter().all(|event| event.risk_score == 0
                && event.risk_contributions.is_empty()
                && event.rule_ids.is_empty()));
            let activity = isolated
                .events
                .iter()
                .find(|event| event.event_type == "activity")
                .expect("instruction-only activity");
            let counts = activity
                .evidence
                .iter()
                .find(|e| e.field == "record_counts")
                .unwrap();
            let counts: serde_json::Value = serde_json::from_str(&counts.redacted_value).unwrap();
            assert_eq!(counts["other"], 4);
            assert!(counts.get("user_message").is_none());
            assert!(counts.get("assistant_message").is_none());
            assert_eq!(activity.schema_version, "3.0");

            let control = format!(
                "{{\"type\":\"response_item\",\"payload\":{{\"type\":\"message\",\"role\":\"{control_role}\",\"content\":\"needle\"}}}}"
            );
            let metadata = instructions.lines().next().unwrap();
            std::fs::write(&source.path, format!("{metadata}\n{control}\n")).unwrap();
            let reference = run();
            std::fs::write(&source.path, format!("{instructions}\n{control}\n")).unwrap();
            let mixed = run();
            let detections = |result: &SourceResult| {
                result
                    .events
                    .iter()
                    .filter(|event| event.event_type == "detection")
                    .map(|event| {
                        (
                            event.risk_score,
                            event.rule_ids.clone(),
                            event.risk_contributions.clone(),
                        )
                    })
                    .collect::<Vec<_>>()
            };
            assert!(
                !detections(&reference).is_empty(),
                "positive role-specific control"
            );
            assert_eq!(detections(&mixed), detections(&reference));
            let risks = |result: &SourceResult| {
                result
                    .events
                    .iter()
                    .map(|event| {
                        (
                            event.event_type.clone(),
                            event.risk_score,
                            event.rule_ids.clone(),
                            event.risk_contributions.clone(),
                        )
                    })
                    .collect::<Vec<_>>()
            };
            assert_eq!(risks(&mixed), risks(&reference));
            assert!(
                mixed
                    .events
                    .iter()
                    .all(|event| event.schema_version == "3.0")
            );
        }
    }
}

#[test]
fn canonical_policy_accounting_counts_filtered_modifiers_and_fully_filtered_sessions() {
    use telltale_sources::acquisition::{AccountingCoverage, SessionAccounting};

    const RULES: &str = r#"title: first match
id: 3662e907-edee-4a08-89b7-16349d6c3ed3
name: test.first
taxonomy: telltale
logsource:
    product: ai_agent
    category: message
detection:
    selection:
        - message.user_text|re: 'needle'
    condition: selection
level: medium
telltale:
    category: test
    score: 1
    explanation: 'first match'
---
title: second match
id: 1b40876b-88e4-440b-8847-821afe44f9f0
name: test.second
taxonomy: telltale
logsource:
    product: ai_agent
    category: message
detection:
    selection:
        - message.user_text|re: 'second'
    condition: selection
level: medium
telltale:
    category: test
    score: 1
    explanation: 'second match'
---
title: test modifier
id: deb8e249-a994-4c77-86fc-f794e580eaeb
name: chain.test
taxonomy: telltale
correlation:
    type: telltale_chain
    rules: [test.first]
telltale:
    score: 1
    explanation: 'test modifier'
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
            quarantined: Vec::new(),
            bounded: Vec::new(),
            message_overlap_from: None,
            source_scale: telltale_schema::observation::SourceScale::FLOOR,
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
