use super::*;

#[test]
fn detection_evidence_uses_loaded_custom_and_package_severities_not_aggregate_risk() {
    let temp = tempfile::tempdir().unwrap();
    let local = temp.path().join("rules.yaml");
    fs::write(
        &local,
        r#"title: Synthetic low rule
id: b8700c7e-f8de-478e-89c1-92620cdb0ac3
name: synthetic.low
taxonomy: telltale
logsource:
    product: ai_agent
    category: tool_activity
detection:
    selection:
        - tool.command|re: 'synthetic'
    condition: selection
level: low
telltale:
    category: test
    score: 1
    explanation: 'Synthetic low rule.'
    tags: [test]
---
title: Synthetic medium rule
id: 3862bfe8-e25b-46b7-8ff0-555b155e436c
name: synthetic.medium
taxonomy: telltale
logsource:
    product: ai_agent
    category: tool_activity
detection:
    selection:
        - tool.command|re: 'synthetic'
    condition: selection
level: medium
telltale:
    category: test
    score: 1
    explanation: 'Synthetic medium rule.'
    tags: [test]
"#,
    )
    .unwrap();
    let package = temp.path().join("package.yaml");
    fs::write(
        &package,
        r#"format: telltale-rule-package/v2
id: synthetic.package
title: Synthetic packaged severity rules
version: "1.0.0"
publisher: Synthetic
license: Apache-2.0
rule_namespace: packaged
---
title: Synthetic package rule
id: 5d0f6c4e-8a1b-4c2d-9e3f-0a1b2c3d4e5f
name: packaged.high
taxonomy: telltale
logsource:
    product: ai_agent
    category: tool_activity
detection:
    selection:
        - tool.command|re: 'synthetic'
    condition: selection
level: high
telltale:
    category: test
    score: 1
    explanation: 'Synthetic package rule.'
    tags: [test]
"#,
    )
    .unwrap();
    let resolved = resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
        &RulePackPaths {
            packages: vec![package],
            ..RulePackPaths::default()
        },
        &[local],
        None,
        RuleLoadMode::CustomOnly,
        &[],
        &[],
    )
    .unwrap();
    let routine = routine_evidence_rule_ids(&resolved.rule_set);
    assert_eq!(routine, BTreeSet::from(["synthetic.low".into()]));
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".into(),
        path: temp.path().join("synthetic.jsonl"),
    };
    for rule in [
        Some("synthetic.low"),
        Some("synthetic.medium"),
        Some("packaged.high"),
        Some("native.unknown"),
        Some("network.download"),
        None,
    ] {
        let mut event = crate::event::detection_event(crate::event::DetectionEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "synthetic".into(),
            source_path_hash: "synthetic".into(),
            tool_name: Some("shell".into()),
            rule_ids: vec![rule.unwrap_or("native.unknown").into()],
            categories: vec!["test".into()],
            detection_classes: vec!["security_detection".into()],
            signal_types: vec!["atomic".into()],
            analytic_intents: vec!["alert".into()],
            atlas_tags: Vec::new(),
            tags: Vec::new(),
            evidence: vec![Evidence {
                field: "command".into(),
                redacted_value: "synthetic-one".into(),
                hash: None,
                rule_id: rule.map(str::to_string),
            }],
            risk_contributions: Vec::new(),
            event_time: None,
        })
        .unwrap();
        assert!(matches!(event.severity.as_str(), "informational" | "low"));
        let mut state = ScanState::default();
        assert!(state.should_emit(&source, &event, &routine));
        event.evidence[0].redacted_value = "synthetic-two".into();
        assert_eq!(
            state.should_emit(&source, &event, &routine),
            rule != Some("synthetic.low"),
            "{rule:?}"
        );
    }
}
