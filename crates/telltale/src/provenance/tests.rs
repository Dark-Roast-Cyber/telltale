use super::*;
use telltale_rules::{load_default_rule_set, load_rule_set_from_documents};
use telltale_schema::provenance::ProducerSuppressionState;

#[test]
fn assembles_safe_manifest_from_effective_rules() {
    let rules = load_default_rule_set().expect("default rules");
    let manifest =
        assemble_producer_provenance_manifest(&rules, &ProducerProvenanceOptions::default())
            .expect("manifest");
    assert_eq!(manifest.rules.rule_count, rules.rule_count() as u64);
    assert_eq!(
        manifest.rules.canonicalization,
        telltale_schema::provenance::RULE_V1_CANONICALIZATION
    );
    assert_eq!(manifest.suppression.state, ProducerSuppressionState::None);
    assert!(manifest.to_json_bytes().is_ok());
}

#[test]
fn effective_exclusion_changes_rules_and_manifest_identity() {
    let document = |exclusion: &str| {
        format!(
            "title: synthetic explanation\nid: ae1f897e-d152-448a-8f35-1cfb169b06cf\nname: rule.synthetic\ntaxonomy: telltale\nlogsource:\n    product: ai_agent\n    category: tool_activity\ndetection:\n    selection_command:\n        tool.command|re: 'synthetic-command'\n    filter_command:\n        tool.command|re: '{exclusion}'\n    condition: selection_command and not filter_command\nlevel: low\ntelltale:\n    category: execution\n    score: 20\n    explanation: 'synthetic explanation'\n    tags: [synthetic]\n"
        )
    };
    let first = load_rule_set_from_documents(&[&document("benign-a")], None).expect("first");
    let second = load_rule_set_from_documents(&[&document("benign-b")], None).expect("second");
    let options = ProducerProvenanceOptions::default();
    let first = assemble_producer_provenance_manifest(&first, &options).expect("first manifest");
    let second = assemble_producer_provenance_manifest(&second, &options).expect("second manifest");

    assert_ne!(first.rules.fingerprint, second.rules.fingerprint);
    assert_ne!(first.producer_manifest_id, second.producer_manifest_id);
}

#[test]
fn malformed_allowlist_fails_without_returning_source_text() {
    let rules = load_default_rule_set().expect("default rules");
    let marker = "TT_PRIVACY_CORE_ALLOWLIST_39";
    let error = assemble_producer_provenance_manifest(
        &rules,
        &ProducerProvenanceOptions::default()
            .with_allowlist_document(format!("suppressions: [\"{marker}\"]")),
    )
    .expect_err("invalid allowlist");
    assert!(!error.to_string().contains(marker));
}

#[test]
fn non_rule_inputs_change_only_the_full_manifest_identity() {
    let rules = load_default_rule_set().expect("default rules");
    let base_options = ProducerProvenanceOptions::default();
    let base = assemble_producer_provenance_manifest(&rules, &base_options).expect("manifest");

    let mut threshold_options = base_options.clone();
    threshold_options.risk_thresholds.low += 1;
    let threshold = assemble_producer_provenance_manifest(&rules, &threshold_options)
        .expect("threshold manifest");
    assert_eq!(base.rules.fingerprint, threshold.rules.fingerprint);
    assert_ne!(base.producer_manifest_id, threshold.producer_manifest_id);

    let mut operational_options = base_options.clone();
    operational_options
        .operational_alert_thresholds
        .max_scanner_errors += 1;
    let operational = assemble_producer_provenance_manifest(&rules, &operational_options)
        .expect("operational manifest");
    assert_eq!(base.rules.fingerprint, operational.rules.fingerprint);
    assert_ne!(base.producer_manifest_id, operational.producer_manifest_id);

    let mut feature_options = base_options;
    feature_options.features.emit_activity = true;
    let feature =
        assemble_producer_provenance_manifest(&rules, &feature_options).expect("feature manifest");
    assert_eq!(base.rules.fingerprint, feature.rules.fingerprint);
    assert_ne!(base.producer_manifest_id, feature.producer_manifest_id);
}

#[test]
fn defaults_are_the_compiled_producer_defaults() {
    let options = ProducerProvenanceOptions::default();
    assert_eq!(options.risk_thresholds, RiskThresholds::default());
    assert_eq!(
        options.operational_alert_thresholds,
        OperationalAlertConfig::default()
    );
    assert!(options.features.process_chain_detections);
    assert!(options.features.install_inventory);
    assert_eq!(
        options.features.install_inventory_interval_seconds,
        Some(DEFAULT_INSTALL_INVENTORY_INTERVAL_SECONDS)
    );
}

#[test]
fn policy_name_changes_full_identity_but_not_ruleset_identity() {
    let rules_document = "title: synthetic explanation\nid: ae1f897e-d152-448a-8f35-1cfb169b06cf\nname: rule.synthetic\ntaxonomy: telltale\nlogsource:\n    product: ai_agent\n    category: tool_activity\ndetection:\n    selection:\n        - tool.command|re: 'synthetic-command'\n    condition: selection\nlevel: low\ntelltale:\n    category: execution\n    score: 20\n    explanation: 'synthetic explanation'\n    tags: [synthetic]\n";
    let policy_a = "version: 1\nname: policy.a\n";
    let policy_b = "version: 1\nname: policy.b\n";
    let rules_a =
        load_rule_set_from_documents(&[rules_document], Some(policy_a)).expect("policy a rules");
    let rules_b =
        load_rule_set_from_documents(&[rules_document], Some(policy_b)).expect("policy b rules");
    let options = ProducerProvenanceOptions::default();
    let manifest_a =
        assemble_producer_provenance_manifest(&rules_a, &options).expect("policy a manifest");
    let manifest_b =
        assemble_producer_provenance_manifest(&rules_b, &options).expect("policy b manifest");

    assert_eq!(manifest_a.rules.fingerprint, manifest_b.rules.fingerprint);
    assert_eq!(
        manifest_a.rules.active_policy_name.as_deref(),
        Some(opaque_identifier("policy", "policy.a").as_str())
    );
    assert_eq!(
        manifest_b.rules.active_policy_name.as_deref(),
        Some(opaque_identifier("policy", "policy.b").as_str())
    );
    assert_ne!(
        manifest_a.producer_manifest_id,
        manifest_b.producer_manifest_id
    );
}
