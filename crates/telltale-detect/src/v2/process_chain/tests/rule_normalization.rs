use super::*;

#[test]
fn authoritative_rule_dedup_winner_and_merged_techniques_are_normalized() {
    let rules = load_process_chain_rules(
            r#"
version: 1
description: synthetic dedupe
defaults: { enabled: true, risk_entity: host, suppression_window_seconds: 3600 }
categories:
  synthetic:
    detection_class: security_detection
    analytic_intent: alert
    investigation_fields: []
    falsepositives: []
rules:
  - { id: procchain.synthetic.weak, title: weak, category: synthetic, severity: low, score: 20, confidence: low, parent: cmd, child: whoami, mitre: [T1219], reason: weak }
  - { id: procchain.synthetic.strong, title: strong, category: synthetic, severity: high, score: 50, confidence: high, parent: cmd, child: whoami, mitre: [T1003.001], reason: strong }
standalone: []
correlations: []
"#,
        )
        .unwrap();
    let observation = requested_command("cmd.exe /c whoami", "dedupe");
    let results =
        evaluate_tool_process_chains(&rules, &observation, &ProcessChainContext::default())
            .unwrap();

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].detector().id(), "procchain.synthetic.strong");
    assert_eq!(
        results[0].techniques(),
        ["attack:T1003.001", "attack:T1219"]
    );
}

#[test]
fn attack_normalization_is_strict_and_malformed_pack_values_fail_closed() {
    assert_eq!(normalize_attack_technique("T1219").unwrap(), "attack:T1219");
    assert_eq!(
        normalize_attack_technique("T1003.001").unwrap(),
        "attack:T1003.001"
    );
    for malformed in ["T121", "t1219", "T1003.01", "T1003.001x", "not-attack"] {
        assert_eq!(
            normalize_attack_technique(malformed).unwrap_err(),
            DetectionError::InvalidMetadata
        );
    }

    let rules = load_process_chain_rules(
            r#"
version: 1
description: malformed technique
defaults: { enabled: true, risk_entity: host, suppression_window_seconds: 3600 }
categories:
  synthetic: { detection_class: security_detection, analytic_intent: alert, investigation_fields: [], falsepositives: [] }
rules:
  - { id: procchain.synthetic.invalid_attack, title: invalid, category: synthetic, severity: low, score: 20, confidence: low, parent: cmd, child: whoami, mitre: [invalid], reason: invalid }
standalone: []
correlations: []
"#,
        )
        .unwrap();
    assert_eq!(
        evaluate_tool_process_chains(
            &rules,
            &requested_command("cmd.exe /c whoami", "invalid-attack"),
            &ProcessChainContext::default(),
        )
        .unwrap_err(),
        DetectionError::InvalidMetadata
    );
}

#[test]
fn unsafe_process_dedupe_text_keeps_bounded_stable_distinct_findings() {
    let rules = load_process_chain_rules(r#"
version: 1
description: synthetic executable names
defaults: { enabled: true, risk_entity: host, suppression_window_seconds: 3600 }
categories:
  discovery: { detection_class: security_detection, analytic_intent: alert, investigation_fields: [], falsepositives: [] }
rules: []
standalone:
  - { id: procchain.synthetic.helper, title: helper, category: discovery, severity: informational, score: 0, confidence: low, match: process_name, patterns: ["helper"], mitre: [T1082], reason: synthetic }
correlations: []
"#).unwrap();
    let key = |name: &str| {
        let command = format!("\"{name}.exe\" --version");
        let result = evaluate_tool_process_chains(
            &rules,
            &requested_command(&command, "synthetic-name"),
            &ProcessChainContext::default(),
        )
        .unwrap();
        assert_eq!(result.len(), 1);
        result[0].dedupe_key().unwrap().to_owned()
    };
    let first = key("helper utility");
    assert!(first.starts_with("process:sha256:"));
    assert_eq!(first, key("helper utility"));
    assert_ne!(first, key("helper other"));
    assert_eq!(
        key("helper"),
        "standalone:procchain.synthetic.helper:helper"
    );
    for raw in ["", "a/b", "a\\b", "a..b", "a\nb", &"x".repeat(100)] {
        let normalized = atomic_dedupe_key(raw);
        assert!(
            super::super::super::types::bounded_opaque(
                &normalized,
                super::super::super::types::MAX_ID_BYTES
            )
            .is_ok()
        );
        assert_eq!(normalized, atomic_dedupe_key(raw));
    }
}

#[test]
fn unsupported_detection_class_fails_closed() {
    let rules = load_process_chain_rules(
            r#"
version: 1
description: unsupported class
defaults: { enabled: true, risk_entity: host, suppression_window_seconds: 3600 }
categories:
  synthetic: { detection_class: operational_health, analytic_intent: alert, investigation_fields: [], falsepositives: [] }
rules:
  - { id: procchain.synthetic.unsupported_class, title: invalid, category: synthetic, severity: low, score: 20, confidence: low, parent: cmd, child: whoami, mitre: [T1219], reason: invalid }
standalone: []
correlations: []
"#,
        )
        .unwrap();
    assert_eq!(
        evaluate_tool_process_chains(
            &rules,
            &requested_command("cmd.exe /c whoami", "unsupported-class"),
            &ProcessChainContext::default(),
        )
        .unwrap_err(),
        DetectionError::UnmappableRuleClass
    );
}
