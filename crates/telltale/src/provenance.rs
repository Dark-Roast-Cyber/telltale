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
mod tests;
