use super::*;

#[test]
fn rule_v1_export_is_effective_and_modifiers_are_not_detectors() {
    let rules = telltale_rules::load_default_rule_set().expect("bundled rules");
    let export = rules.compatibility_export();
    assert_eq!(export.rules().len(), 29);
    assert_eq!(export.modifiers().len(), 9);
    let matcher_count = export
        .rules()
        .iter()
        .map(|rule| rule.matchers.len())
        .sum::<usize>();
    assert_eq!(matcher_count, 71);
    let targets = export
        .rules()
        .iter()
        .flat_map(|rule| rule.matchers.iter().map(|matcher| matcher.target.as_str()))
        .fold(BTreeMap::<&str, usize>::new(), |mut counts, target| {
            *counts.entry(target).or_default() += 1;
            counts
        });
    assert_eq!(
        targets,
        BTreeMap::from([
            ("arguments", 21),
            ("assistant_context", 8),
            ("command", 23),
            ("file_path", 4),
            ("tool_kind", 1),
            ("tool_name", 1),
            ("tool_result", 8),
            ("url", 3),
            ("written_path", 2),
        ])
    );
    let severities =
        export
            .rules()
            .iter()
            .fold(BTreeMap::<&str, usize>::new(), |mut counts, rule| {
                *counts.entry(rule.severity.as_str()).or_default() += 1;
                counts
            });
    assert_eq!(
        severities,
        BTreeMap::from([
            ("high", 16),
            ("informational", 5),
            ("low", 4),
            ("medium", 4),
        ])
    );
    let classes = export
        .rules()
        .iter()
        .fold(BTreeMap::<&str, usize>::new(), |mut counts, rule| {
            *counts.entry(rule.detection_class.as_str()).or_default() += 1;
            counts
        });
    assert_eq!(
        classes,
        BTreeMap::from([
            ("policy_violation", 1),
            ("security_detection", 20),
            ("threat_hunting", 8),
        ])
    );
    assert_eq!(export.rules().iter().map(|rule| rule.score).min(), Some(0));
    assert_eq!(export.rules().iter().map(|rule| rule.score).max(), Some(60));
    assert!(export.rules().iter().all(|rule| {
        !rule.matchers.is_empty()
            && rule
                .matchers
                .iter()
                .all(|matcher| !matcher.target.is_empty())
    }));
    let plan = compile_rule_v1(&export).expect("v1 compatibility plan");
    assert_eq!(plan.detectors().len(), export.rules().len());
    assert!(plan.detectors().iter().all(|detector| {
        detector.detector().kind() == DetectorKind::ObservationMatch
            && detector.detector().rule_version() == Some(1)
    }));
}

#[test]
fn rule_v1_session_adapts_shared_modifier_risk_and_metadata_semantics() {
    let plan = rule_v1_session_plan();
    let observations = [
        message(
            MessageRole::Assistant,
            "alpha raw-canonical-evidence",
            "alpha-one",
        ),
        message(MessageRole::Assistant, "alpha beta", "alpha-two"),
    ];
    let observation_refs = observations.iter().collect::<Vec<_>>();
    let evaluation =
        evaluate_rule_v1_session_with_budget(&plan, &observation_refs, &mut RetentionBudget::new())
            .expect("evaluation");

    assert_eq!(
        evaluation.matched_atomic_rule_ids(),
        ["synthetic.alpha", "synthetic.beta"]
    );
    assert_eq!(
        evaluation.triggered_modifier_ids(),
        ["chain.categories", "chain.combined", "chain.rules"]
    );
    assert_eq!(
        evaluation.effective_rule_ids(),
        [
            "chain.categories",
            "chain.combined",
            "chain.rules",
            "synthetic.alpha",
            "synthetic.beta",
        ]
    );
    let alpha = evaluation
        .detectors()
        .iter()
        .find(|detector| detector.detector_id() == "synthetic.alpha")
        .expect("alpha detector");
    assert_eq!(alpha.outcome(), RuleV1DetectorOutcome::Match);
    assert_eq!(alpha.evaluated_match_count(), 2);
    assert_eq!(
        alpha.matched_selector_paths(),
        ["compat.v1.assistant_context"]
    );
    assert_eq!(
        evaluation
            .compatibility_contributions()
            .iter()
            .map(|contribution| (
                contribution.id(),
                contribution.contribution_type(),
                contribution.points(),
            ))
            .collect::<Vec<_>>(),
        [
            (
                "synthetic.alpha",
                telltale_schema::scoring::RiskContributionType::DeterministicRule,
                7,
            ),
            (
                "chain.categories",
                telltale_schema::scoring::RiskContributionType::ChainModifier,
                9,
            ),
            (
                "chain.combined",
                telltale_schema::scoring::RiskContributionType::ChainModifier,
                11,
            ),
        ]
    );
    assert_eq!(evaluation.compatibility_score(), 27);

    let metadata = evaluation.compatibility_metadata();
    assert_eq!(metadata.categories(), ["alpha", "beta"]);
    assert_eq!(
        metadata.detection_classes(),
        [
            "compliance_observation",
            "policy_violation",
            "security_detection",
            "threat_hunting",
        ]
    );
    assert_eq!(metadata.signal_types(), ["atomic", "chain"]);
    assert_eq!(metadata.analytic_intents(), ["alert", "audit", "hunt"]);
    assert_eq!(
        metadata.atlas_tags(),
        [
            "atlas:AML.T0001",
            "atlas:AML.T0002",
            "atlas:AML.T0003",
            "atlas:AML.T0004",
            "atlas:AML.T0005",
        ]
    );
    assert_eq!(metadata.tags(), ["tag:alpha", "tag:beta"]);
    assert!(!format!("{evaluation:?}").contains("raw-canonical-evidence"));
}

#[test]
fn rule_v1_session_modifier_conditions_and_empty_session_are_bounded() {
    let plan = rule_v1_session_plan();
    let alpha = message(MessageRole::Assistant, "alpha", "alpha-only");
    let alpha_only =
        evaluate_rule_v1_session_with_budget(&plan, &[&alpha], &mut RetentionBudget::new())
            .expect("alpha evaluation");
    assert_eq!(alpha_only.matched_atomic_rule_ids(), ["synthetic.alpha"]);
    assert!(alpha_only.triggered_modifier_ids().is_empty());
    assert_eq!(alpha_only.compatibility_score(), 7);

    let empty = evaluate_rule_v1_session_with_budget(&plan, &[], &mut RetentionBudget::new())
        .expect("empty evaluation");
    assert!(empty.matched_atomic_rule_ids().is_empty());
    assert!(empty.triggered_modifier_ids().is_empty());
    assert!(empty.effective_rule_ids().is_empty());
    assert!(empty.compatibility_contributions().is_empty());
    assert_eq!(empty.compatibility_score(), 0);
    assert_eq!(
        empty.compatibility_metadata(),
        &RuleV1CompatibilityMetadata::default()
    );
    assert!(
        empty
            .detectors()
            .iter()
            .all(|detector| detector.outcome() == RuleV1DetectorOutcome::NotApplicable)
    );
}

#[test]
fn rule_v1_session_compatibility_score_overflow_fails_closed() {
    let document = String::from(
        "title: synthetic\nid: 2f33e0ea-6afb-4a33-84ae-7fa76ce268cb\nname: synthetic.atomic\ntaxonomy: telltale\nlogsource:\n    product: ai_agent\n    category: message\ndetection:\n    selection:\n        - message.assistant_text|re: 'needle'\n    condition: selection\nlevel: low\ntelltale:\n    category: synthetic\n    score: 1\n    explanation: 'synthetic'\n    analytic_intent: alert\n    detection_class: security_detection\n    signal_type: atomic\n---\ntitle: synthetic\nid: 8480a708-8d36-407e-8e3e-d744914e0e1f\nname: chain.overflow\ntaxonomy: telltale\ncorrelation:\n    type: telltale_chain\n    rules: [synthetic.atomic]\ntelltale:\n    score: 0\n    explanation: 'synthetic'\n    analytic_intent: audit\n    detection_class: security_detection\n    signal_type: chain\n",
    );
    let export = telltale_rules::load_rule_set_from_documents(&[&document], None)
        .expect("overflow rules")
        .compatibility_export()
        // Rule v2 caps a score at 100; the compiled form takes any score.
        .with_modifier("chain.overflow", |modifier| modifier.score = u64::MAX);
    let plan = compile_rule_v1(&export).expect("overflow plan");
    let observation = message(MessageRole::Assistant, "needle", "overflow");
    assert!(matches!(
        evaluate_rule_v1_session_with_budget(&plan, &[&observation], &mut RetentionBudget::new()),
        Err(RuleV1SessionError::Accounting)
    ));
}

#[test]
fn effective_rule_export_preserves_defaults_and_fails_closed_on_unmappable_class() {
    let document = r#"
title: synthetic explanation
id: 316347a2-e10a-4ebb-8bfb-7a9077069766
name: synthetic.case
taxonomy: telltale
logsource:
    product: ai_agent
    category: tool_activity
detection:
    selection:
        - tool.name|re|i: 'SHELL'
    condition: selection
level: high
tags:
    - atlas.aml.t0051
telltale:
    category: synthetic
    score: 25
    explanation: 'synthetic explanation'
    detection_class: security_detection
    tags: [synthetic]
"#;
    let export = telltale_rules::load_rule_set_from_documents(&[document], None)
        .expect("custom rules")
        .compatibility_export();
    assert_eq!(export.rules().len(), 1);
    assert_eq!(export.rules()[0].matchers[0].regex, "(?i:SHELL)");
    assert_eq!(export.rules()[0].score, 25);
    let plan = compile_rule_v1(&export).expect("compatible rule");
    let result = plan.detectors()[0].evaluate(&tool("synthetic", "rule-match"));
    assert_eq!(result.evaluation_status(), EvaluationStatus::EvaluatedMatch);
    assert_eq!(result.finding_kind(), FindingKind::SecurityDetection);
    assert_eq!(result.risk_points(), Some(25));
    assert_eq!(result.techniques(), &["atlas:AML.T0051".to_owned()]);

    let policy = r#"
version: 1
name: synthetic-policy
disabled_rules: [synthetic.case]
"#;
    let export = telltale_rules::load_rule_set_from_documents(&[document], Some(policy))
        .expect("policy rules")
        .compatibility_export();
    assert_eq!(export.policy_name(), Some("synthetic-policy"));
    assert!(export.rules().is_empty());

    let override_yaml = r#"
version: 1
overrides:
  - rule_id: synthetic.case
    reason: synthetic review
    score: 31
"#;
    let override_doc: telltale_rules::RuleOverrideDocument =
        serde_yaml::from_str(override_yaml).expect("override document");
    // Apply the override to a synthetic equivalent so the effective export
    // proves that the compatibility seam sees post-override values.
    let mut rules = telltale_rules::LoadedRules::parse(document).expect("synthetic document");
    rules
        .apply_override_document(&override_doc, "synthetic-overrides.yaml", None)
        .expect("apply override");
    assert_eq!(
        rules
            .compile(None)
            .expect("overridden rules")
            .compatibility_export()
            .rules()[0]
            .score,
        31
    );

    let unmappable = document.replace(
        "detection_class: security_detection",
        "detection_class: operational_health",
    );
    let export = telltale_rules::load_rule_set_from_documents(&[&unmappable], None)
        .expect("unmappable rules still load")
        .compatibility_export();
    assert_eq!(
        compile_rule_v1(&export).unwrap_err(),
        RuleCompileError::UnmappableDetectionClass
    );
}

#[test]
fn rule_v1_target_exclusion_uses_shared_content_matcher() {
    let document = r#"
title: synthetic
id: a4f140fe-69db-4856-83e5-01f57451bec9
name: synthetic.exclusion
taxonomy: telltale
logsource:
    product: ai_agent
    category: agent_activity
detection:
    selection_arguments:
        tool.arguments|re|i: 'needle'
    selection_assistant_context:
        message.assistant_text|re|i: 'needle'
    filter_assistant_context:
        message.assistant_text|re|i: 'quoted example'
    condition: selection_arguments or (selection_assistant_context and not filter_assistant_context)
level: low
telltale:
    category: synthetic
    score: 10
    explanation: 'synthetic'
    tags: [synthetic]
"#;
    let export = telltale_rules::load_rule_set_from_documents(&[document], None)
        .expect("custom rules")
        .compatibility_export();
    let matcher = export.rules()[0]
        .matchers
        .iter()
        .find(|matcher| matcher.target == "assistant_context")
        .expect("assistant matcher");
    assert_eq!(
        matcher.exclusion_regex.as_deref(),
        Some("(?i:quoted example)")
    );

    let plan = compile_rule_v1(&export).expect("compatibility plan");
    let excluded = plan.detectors()[0].evaluate(&message(
        MessageRole::Assistant,
        "needle in a quoted example",
        "synthetic-excluded",
    ));
    assert_eq!(
        excluded.evaluation_status(),
        EvaluationStatus::EvaluatedNoMatch
    );

    let retained = plan.detectors()[0].evaluate(&message(
        MessageRole::Assistant,
        "needle retained",
        "synthetic-retained",
    ));
    assert_eq!(
        retained.evaluation_status(),
        EvaluationStatus::EvaluatedMatch
    );

    let excluded_observation = message(
        MessageRole::Assistant,
        "needle in a quoted example",
        "synthetic-excluded-first",
    );
    let retained_observation = message(
        MessageRole::Assistant,
        "needle retained",
        "synthetic-retained-later",
    );
    let compatibility = evaluate_rule_v1_session_with_budget(
        &plan,
        &[&excluded_observation, &retained_observation],
        &mut RetentionBudget::new(),
    )
    .expect("compatibility evaluation");
    assert_eq!(
        compatibility.matched_atomic_rule_ids(),
        ["synthetic.exclusion"]
    );
}
