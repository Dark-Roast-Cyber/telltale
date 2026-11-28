use super::*;

#[test]
fn evaluates_rule_purpose_metadata_and_atlas_tags() {
    let rule_set = compile(&[rule(
        "policy.agent_guardrail_modification",
        "persistence",
        HIDDEN_INSTRUCTION,
        "detection_class: policy_violation\nsignal_type: atomic\nanalytic_intent: audit",
    )
    .replace(
        "level: high\n",
        "level: high\ntags:\n    - atlas.aml.t0051\n",
    )]);

    let result = rule_set
        .evaluate(&[("assistant_context", "hidden instruction")])
        .expect("evaluate")
        .expect("match");

    assert_eq!(result.detection_classes, vec!["policy_violation"]);
    assert_eq!(result.signal_types, vec!["atomic"]);
    assert_eq!(result.analytic_intents, vec!["audit"]);
    assert_eq!(result.atlas_tags, vec!["atlas:AML.T0051"]);
}

#[test]
fn rule_purpose_metadata_agrees_with_frozen_event3_taxonomy() {
    let schema: serde_json::Value =
        serde_json::from_str(telltale_schema::event::EVENT3_SCHEMA).expect("frozen schema");
    let properties = &schema["$defs"]["detection"]["allOf"][1]["properties"];
    for class in properties["detection_classes"]["items"]["enum"]
        .as_array()
        .expect("classes")
    {
        for signal in properties["signal_types"]["items"]["enum"]
            .as_array()
            .expect("signals")
        {
            for intent in properties["analytic_intents"]["items"]["enum"]
                .as_array()
                .expect("intents")
            {
                super::super::validate_rule_metadata(
                    "rule.taxonomy",
                    class.as_str().unwrap(),
                    signal.as_str().unwrap(),
                    intent.as_str().unwrap(),
                    &[],
                )
                .expect("wire taxonomy accepted by rules");
            }
        }
    }
    for invalid in ["", "unknown", "ALERT", "atomic ", " alert", "alert\u{a0}"] {
        for (class, signal, intent, field) in [
            (invalid, "atomic", "alert", "detection_class"),
            ("security_detection", invalid, "alert", "signal_type"),
            ("security_detection", "atomic", invalid, "analytic_intent"),
        ] {
            let error =
                super::super::validate_rule_metadata("rule.taxonomy", class, signal, intent, &[])
                    .expect_err("invalid taxonomy");
            assert!(error.to_string().contains(field));
        }
    }
}

#[test]
fn rule_severity_validation_uses_detection_vocabulary() {
    let schema: serde_json::Value =
        serde_json::from_str(telltale_schema::event::EVENT3_SCHEMA).expect("frozen schema");
    assert_eq!(
        schema["$defs"]["detection"]["allOf"][1]["properties"]["severity"]["enum"],
        serde_json::json!(telltale_schema::event::VALID_DETECTION_SEVERITIES)
    );
    let document = |level: &str, telltale: &str| {
        rule("synthetic.severity", "custom", HIDDEN_INSTRUCTION, telltale)
            .replace("level: high", &format!("level: '{level}'"))
    };
    for severity in &telltale_schema::event::VALID_DETECTION_SEVERITIES {
        let compiled = compile(&[document(severity, "")]);
        assert_eq!(compiled.summaries()[0].severity, *severity);
        assert_eq!(
            compiled.compatibility_export().rules()[0].severity,
            *severity
        );
    }
    let policy = "disabled_rules: [synthetic.severity]\n";
    for invalid in [
        "warning",
        "catastrophic",
        "",
        "unknown",
        "HIGH",
        "high ",
        " high",
        "high\u{a0}",
    ] {
        let expected = format!(
            "rule synthetic.severity uses unsupported level '{invalid}'; supported values: {}",
            telltale_schema::event::VALID_DETECTION_SEVERITIES.join(", ")
        );
        // Rule v2 checks every document when it is read, so a disabled or
        // policy-filtered rule fails the same way.
        for (document, policy) in [
            (document(invalid, ""), None),
            (document(invalid, "enabled: false"), None),
            (document(invalid, ""), Some(policy)),
        ] {
            let error = load_rule_set_from_documents(&[&document], policy)
                .expect_err("invalid severity must fail")
                .to_string();
            assert!(error.ends_with(&expected), "{error}");
        }
    }
}

#[test]
fn rule_status_is_catalog_metadata_for_enabled_statuses() {
    for status in ["experimental", "test", "stable"] {
        let compiled = compile(&[
            hidden_instruction_rule("synthetic.status", "custom").replace(
                "taxonomy: telltale\n",
                &format!("taxonomy: telltale\nstatus: {status}\n"),
            ),
        ]);
        assert_eq!(compiled.rule_count(), 1);
        assert!(
            compiled
                .evaluate(&[("assistant_context", "hidden instruction")])
                .expect("evaluate")
                .is_some()
        );
    }
}

#[test]
fn rule_category_remains_open_behavior_metadata() {
    let compiled = compile(&[hidden_instruction_rule(
        "synthetic.category",
        "not_a_category",
    )]);
    assert_eq!(compiled.summaries()[0].category, "not_a_category");
    assert_eq!(
        compiled.compatibility_export().rules()[0].category,
        "not_a_category"
    );
    let result = compiled
        .evaluate(&[("assistant_context", "hidden instruction")])
        .expect("evaluate")
        .expect("match");
    assert_eq!(result.categories, ["not_a_category"]);
}

#[test]
fn rejects_invalid_rule_purpose_metadata() {
    let document = rule(
        "custom.invalid_metadata",
        "custom",
        HIDDEN_INSTRUCTION,
        "detection_class: alert",
    );
    assert!(load_rule_set_from_documents(&[&document], None).is_err());
}

#[test]
fn rejects_noncanonical_rule_ids_before_matching_for_zero_and_positive_scores() {
    for score in [0, 1] {
        let document = hidden_instruction_rule("invalid", "custom")
            .replace("score: 60", &format!("score: {score}"));
        assert!(
            load_rule_set_from_documents(&[&document], None).is_err(),
            "score {score} should reject invalid id"
        );
    }
}

#[test]
fn rejects_noncanonical_modifier_ids_and_rule_references_before_matching() {
    for score in [0, 1] {
        for (id, steps) in [
            ("invalid", "categories: [custom]"),
            ("chain.valid", "rules: [invalid]"),
        ] {
            let document = chain(id, steps, "").replace("score: 7", &format!("score: {score}"));
            assert!(
                load_rule_set_from_documents(&[&document], None).is_err(),
                "invalid modifier metadata should reject at score {score}"
            );
        }
    }
}
