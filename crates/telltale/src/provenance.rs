//! Assembly of the public producer provenance manifest from effective values.

use telltale_detect::allowlist::Allowlist;
use telltale_rules::CompiledRuleSet;
use telltale_schema::event::{OperationalAlertConfig, opaque_identifier};
use telltale_schema::provenance::{
    ProducerFeatureSwitches, ProducerOperationalAlertThresholds, ProducerProvenanceError,
    ProducerProvenanceManifestV1, ProducerRiskThresholds, ProducerRuleProvenance,
};
use telltale_schema::scoring::RiskThresholds;

pub const DEFAULT_INSTALL_INVENTORY_INTERVAL_SECONDS: u64 = 24 * 60 * 60;

/// Already resolved producer choices that are not part of Rule v1 semantics.
/// The allowlist is supplied as the selected document content; this type does
/// not resolve configuration paths or policy files.
#[derive(Debug, Clone)]
pub struct ProducerProvenanceOptions {
    pub allowlist_document: Option<String>,
    pub risk_thresholds: RiskThresholds,
    pub operational_alert_thresholds: OperationalAlertConfig,
    pub features: ProducerFeatureSwitches,
}

/// Compiled producer defaults. Telltale libraries do not read the process
/// environment; a host resolves operator settings and overrides fields.
impl Default for ProducerProvenanceOptions {
    fn default() -> Self {
        Self {
            allowlist_document: None,
            risk_thresholds: RiskThresholds::default(),
            operational_alert_thresholds: OperationalAlertConfig::default(),
            features: ProducerFeatureSwitches {
                emit_activity: false,
                emit_session_risk_summary: false,
                baseline_deviation_scoring: false,
                process_chain_detections: true,
                install_inventory: true,
                install_inventory_interval_seconds: Some(
                    DEFAULT_INSTALL_INVENTORY_INTERVAL_SECONDS,
                ),
            },
        }
    }
}

impl ProducerProvenanceOptions {
    pub fn with_allowlist_document(mut self, document: impl Into<String>) -> Self {
        self.allowlist_document = Some(document.into());
        self
    }
}

/// Assemble a manifest from an already effective compiled rule set and resolved
/// producer values. Path, tier, policy-file, and allowlist-path resolution is
/// owned by the caller, such as the CLI scan configuration path.
pub fn assemble_producer_provenance_manifest(
    rule_set: &CompiledRuleSet,
    options: &ProducerProvenanceOptions,
) -> Result<ProducerProvenanceManifestV1, ProducerProvenanceError> {
    let allowlist = match options.allowlist_document.as_deref() {
        Some(document) => {
            Allowlist::from_yaml(document).map_err(|_| ProducerProvenanceError::InvalidFormat)?
        }
        None => Allowlist::default(),
    };
    let export = rule_set.compatibility_export();
    let active_policy_name = export
        .policy_name()
        .map(|name| opaque_identifier("policy", name));
    ProducerProvenanceManifestV1::new(
        env!("CARGO_PKG_VERSION"),
        ProducerRuleProvenance {
            canonicalization: telltale_schema::provenance::RULE_V1_CANONICALIZATION.to_string(),
            fingerprint: export.fingerprint(),
            rule_count: rule_set.rule_count() as u64,
            active_policy_name,
        },
        producer_risk_thresholds(options.risk_thresholds),
        ProducerOperationalAlertThresholds {
            max_scanner_errors: options.operational_alert_thresholds.max_scanner_errors,
            max_scan_duration_ms: options.operational_alert_thresholds.max_scan_duration_ms,
        },
        allowlist.suppression_provenance(),
        options.features.clone(),
    )
}

fn producer_risk_thresholds(thresholds: RiskThresholds) -> ProducerRiskThresholds {
    ProducerRiskThresholds {
        low: thresholds.low,
        medium: thresholds.medium,
        high: thresholds.high,
        critical: thresholds.critical,
    }
}

#[cfg(test)]
mod tests {
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
                "version: 1\ndescription: synthetic\ndefaults: {{case_insensitive: false, enabled: true}}\nrules:\n  - id: rule.synthetic\n    category: execution\n    severity: low\n    score: 20\n    detection:\n      selection:\n        command: synthetic-command\n      exclude:\n        command: {exclusion}\n      condition: selection\n    tags: [synthetic]\n    explanation: synthetic explanation\nmodifiers: []\n"
            )
        };
        let first = load_rule_set_from_documents(&[&document("benign-a")], None).expect("first");
        let second = load_rule_set_from_documents(&[&document("benign-b")], None).expect("second");
        let options = ProducerProvenanceOptions::default();
        let first =
            assemble_producer_provenance_manifest(&first, &options).expect("first manifest");
        let second =
            assemble_producer_provenance_manifest(&second, &options).expect("second manifest");

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
        let feature = assemble_producer_provenance_manifest(&rules, &feature_options)
            .expect("feature manifest");
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
        let rules_document = "version: 1\ndescription: synthetic\ndefaults:\n  case_insensitive: false\n  enabled: true\nrules:\n  - id: rule.synthetic\n    category: execution\n    severity: low\n    score: 20\n    targets: [command]\n    regex: synthetic-command\n    tags: [synthetic]\n    explanation: synthetic explanation\nmodifiers: []\n";
        let policy_a = "version: 1\nname: policy.a\n";
        let policy_b = "version: 1\nname: policy.b\n";
        let rules_a = load_rule_set_from_documents(&[rules_document], Some(policy_a))
            .expect("policy a rules");
        let rules_b = load_rule_set_from_documents(&[rules_document], Some(policy_b))
            .expect("policy b rules");
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
}
