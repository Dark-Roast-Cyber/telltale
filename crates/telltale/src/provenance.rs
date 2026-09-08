//! Assembly of the public producer provenance manifest from effective values.

use telltale_detect::allowlist::Allowlist;
use telltale_rules::CompiledRuleSet;
use telltale_schema::event::{OperationalAlertConfig, opaque_identifier};
use telltale_schema::provenance::{
    ProducerFeatureSwitches, ProducerOperationalAlertThresholds, ProducerProvenanceError,
    ProducerProvenanceManifestV1, ProducerRiskThresholds, ProducerRuleProvenance,
};
use telltale_schema::scoring::{RiskThresholds, load_thresholds};

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

impl Default for ProducerProvenanceOptions {
    fn default() -> Self {
        Self::from_environment()
    }
}

impl ProducerProvenanceOptions {
    /// Resolve the same environment-controlled semantic defaults used by scan.
    pub fn from_environment() -> Self {
        let install_inventory_interval_seconds =
            resolve_install_inventory_interval_seconds(None, false);
        Self {
            allowlist_document: None,
            risk_thresholds: load_thresholds(),
            operational_alert_thresholds: telltale_schema::event::load_operational_alert_config(),
            features: ProducerFeatureSwitches {
                emit_activity: false,
                emit_session_risk_summary: false,
                baseline_deviation_scoring: false,
                process_chain_detections: process_chain_enabled(),
                install_inventory: install_inventory_interval_seconds.is_some(),
                install_inventory_interval_seconds,
            },
        }
    }

    pub fn with_allowlist_document(mut self, document: impl Into<String>) -> Self {
        self.allowlist_document = Some(document.into());
        self
    }
}

/// Resolve the inventory cadence used by both scan and provenance materialization.
pub fn resolve_install_inventory_interval_seconds(
    interval_seconds: Option<u64>,
    disabled: bool,
) -> Option<u64> {
    if disabled {
        return None;
    }
    Some(interval_seconds.unwrap_or_else(|| {
        std::env::var("TELLTALE_INSTALL_INVENTORY_INTERVAL_SECONDS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(DEFAULT_INSTALL_INVENTORY_INTERVAL_SECONDS)
    }))
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

fn process_chain_enabled() -> bool {
    std::env::var("TELLTALE_PROCESS_CHAIN_DETECTIONS")
        .map(|value| !matches!(value.trim(), "0" | "false" | "off" | "no"))
        .unwrap_or(true)
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
        assert_eq!(manifest.suppression.state, ProducerSuppressionState::None);
        assert!(manifest.to_json_bytes().is_ok());
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
    fn environment_defaults_use_the_shared_inventory_interval_resolver() {
        let previous = std::env::var_os("TELLTALE_INSTALL_INVENTORY_INTERVAL_SECONDS");
        unsafe {
            std::env::set_var("TELLTALE_INSTALL_INVENTORY_INTERVAL_SECONDS", "37");
        }
        let options = ProducerProvenanceOptions::from_environment();
        match previous {
            Some(value) => unsafe {
                std::env::set_var("TELLTALE_INSTALL_INVENTORY_INTERVAL_SECONDS", value)
            },
            None => unsafe { std::env::remove_var("TELLTALE_INSTALL_INVENTORY_INTERVAL_SECONDS") },
        }

        assert_eq!(
            options.features.install_inventory_interval_seconds,
            Some(37)
        );
        assert!(options.features.install_inventory);
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
