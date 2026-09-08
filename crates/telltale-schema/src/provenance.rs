//! Public producer configuration provenance, separate from Event 3.0 telemetry.
//!
//! This contract identifies the effective content and selected producer options
//! represented by a build. It is not an attestation, authentication mechanism,
//! per-event link, or scan identity.

use serde::ser::{Error as SerdeError, SerializeStruct};
use serde::{Deserialize, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::event::{
    EVENT3_SCHEMA_SHA256, NATIVE_SCHEMA_VERSION, is_canonical_opaque_identifier_for_kind,
};

pub const PRODUCER_PROVENANCE_SCHEMA: &str = "producer_provenance_manifest";
pub const PRODUCER_PROVENANCE_VERSION: u32 = 1;
pub const RULE_V1_CANONICALIZATION: &str = "rule-v1-compiled-compatibility-v1";
pub const SUPPRESSION_V1_CANONICALIZATION: &str = "suppression-v1-effective-v1";

const MANIFEST_ID_DOMAIN: &[u8] = b"telltale:producer-provenance-manifest-v1-id:v1\0";

/// The exact Event 3.0 contract represented by a producer manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event3ContractIdentity {
    pub schema_version: String,
    pub schema_sha256: String,
}

impl Default for Event3ContractIdentity {
    fn default() -> Self {
        Self {
            schema_version: NATIVE_SCHEMA_VERSION.to_string(),
            schema_sha256: EVENT3_SCHEMA_SHA256.to_string(),
        }
    }
}

/// Effective compiled Rule v1 identity and the public policy label.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProducerRuleProvenance {
    pub canonicalization: String,
    pub fingerprint: String,
    pub rule_count: u64,
    pub active_policy_name: Option<String>,
}

/// Risk-score severity thresholds used by Event 3 producers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProducerRiskThresholds {
    pub low: u32,
    pub medium: u32,
    pub high: u32,
    pub critical: u32,
}

/// Operational health thresholds that can cause an Event 3 operational alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProducerOperationalAlertThresholds {
    pub max_scanner_errors: u32,
    pub max_scan_duration_ms: u64,
}

/// Whether allowlist suppression semantics are represented.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProducerSuppressionState {
    None,
    Configured,
}

/// Effective suppression identity. Names and criteria are intentionally not
/// public fields; names remain in the private fingerprint preimage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProducerSuppressionProvenance {
    pub canonicalization: String,
    pub state: ProducerSuppressionState,
    pub fingerprint: Option<String>,
    pub count: u64,
}

impl ProducerSuppressionProvenance {
    pub fn none() -> Self {
        Self {
            canonicalization: SUPPRESSION_V1_CANONICALIZATION.to_string(),
            state: ProducerSuppressionState::None,
            fingerprint: None,
            count: 0,
        }
    }
}

/// Closed set of producer options that can alter Event 3 output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProducerFeatureSwitches {
    pub emit_activity: bool,
    pub emit_session_risk_summary: bool,
    pub baseline_deviation_scoring: bool,
    pub process_chain_detections: bool,
    pub install_inventory: bool,
    pub install_inventory_interval_seconds: Option<u64>,
}

/// A deterministic, versioned identity for effective producer configuration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProducerProvenanceManifestV1 {
    pub schema: String,
    pub version: u32,
    pub producer_manifest_id: String,
    pub telltale_version: String,
    pub event3: Event3ContractIdentity,
    pub rules: ProducerRuleProvenance,
    pub risk_thresholds: ProducerRiskThresholds,
    pub operational_alert_thresholds: ProducerOperationalAlertThresholds,
    pub suppression: ProducerSuppressionProvenance,
    pub features: ProducerFeatureSwitches,
}

impl Serialize for ProducerProvenanceManifestV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.validate()
            .map_err(|_| S::Error::custom("producer provenance manifest serialization rejected"))?;
        let mut state = serializer.serialize_struct("ProducerProvenanceManifestV1", 10)?;
        state.serialize_field("schema", &self.schema)?;
        state.serialize_field("version", &self.version)?;
        state.serialize_field("producer_manifest_id", &self.producer_manifest_id)?;
        state.serialize_field("telltale_version", &self.telltale_version)?;
        state.serialize_field("event3", &self.event3)?;
        state.serialize_field("rules", &self.rules)?;
        state.serialize_field("risk_thresholds", &self.risk_thresholds)?;
        state.serialize_field(
            "operational_alert_thresholds",
            &self.operational_alert_thresholds,
        )?;
        state.serialize_field("suppression", &self.suppression)?;
        state.serialize_field("features", &self.features)?;
        state.end()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProducerProvenanceError {
    InvalidFormat,
    InvalidSchema,
    InvalidVersion,
    InvalidHash,
    InvalidEvent3Identity,
    InvalidSuppressionState,
    InvalidFeatureSwitches,
    InvalidPublicLabel,
    IdentityMismatch,
    Serialization,
}

impl std::fmt::Display for ProducerProvenanceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFormat => "producer provenance manifest has invalid format",
            Self::InvalidSchema => "producer provenance manifest has unsupported schema",
            Self::InvalidVersion => "producer provenance manifest has unsupported version",
            Self::InvalidHash => "producer provenance manifest has invalid fingerprint",
            Self::InvalidEvent3Identity => {
                "producer provenance manifest has invalid Event 3 identity"
            }
            Self::InvalidSuppressionState => {
                "producer provenance manifest has invalid suppression state"
            }
            Self::InvalidFeatureSwitches => {
                "producer provenance manifest has invalid feature switches"
            }
            Self::InvalidPublicLabel => "producer provenance manifest has invalid public label",
            Self::IdentityMismatch => "producer provenance manifest identity mismatch",
            Self::Serialization => "producer provenance manifest serialization failed",
        })
    }
}

impl std::error::Error for ProducerProvenanceError {}

impl ProducerProvenanceManifestV1 {
    pub fn new(
        telltale_version: impl Into<String>,
        rules: ProducerRuleProvenance,
        risk_thresholds: ProducerRiskThresholds,
        operational_alert_thresholds: ProducerOperationalAlertThresholds,
        suppression: ProducerSuppressionProvenance,
        features: ProducerFeatureSwitches,
    ) -> Result<Self, ProducerProvenanceError> {
        let mut manifest = Self {
            schema: PRODUCER_PROVENANCE_SCHEMA.to_string(),
            version: PRODUCER_PROVENANCE_VERSION,
            producer_manifest_id: String::new(),
            telltale_version: telltale_version.into(),
            event3: Event3ContractIdentity::default(),
            rules,
            risk_thresholds,
            operational_alert_thresholds,
            suppression,
            features,
        };
        manifest.producer_manifest_id = manifest.expected_identity()?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<(), ProducerProvenanceError> {
        if self.schema != PRODUCER_PROVENANCE_SCHEMA {
            return Err(ProducerProvenanceError::InvalidSchema);
        }
        if self.version != PRODUCER_PROVENANCE_VERSION || !valid_semver(&self.telltale_version) {
            return Err(ProducerProvenanceError::InvalidVersion);
        }
        validate_hash(&self.producer_manifest_id)?;
        if self.event3.schema_version != NATIVE_SCHEMA_VERSION
            || self.event3.schema_sha256 != EVENT3_SCHEMA_SHA256
        {
            return Err(ProducerProvenanceError::InvalidEvent3Identity);
        }
        if self.rules.canonicalization != RULE_V1_CANONICALIZATION
            || !valid_hash(&self.rules.fingerprint)
        {
            return Err(ProducerProvenanceError::InvalidHash);
        }
        if let Some(name) = &self.rules.active_policy_name
            && !is_canonical_opaque_identifier_for_kind("policy", name)
        {
            return Err(ProducerProvenanceError::InvalidPublicLabel);
        }
        if self.suppression.canonicalization != SUPPRESSION_V1_CANONICALIZATION {
            return Err(ProducerProvenanceError::InvalidSuppressionState);
        }
        match self.suppression.state {
            ProducerSuppressionState::None => {
                if self.suppression.fingerprint.is_some() || self.suppression.count != 0 {
                    return Err(ProducerProvenanceError::InvalidSuppressionState);
                }
            }
            ProducerSuppressionState::Configured => {
                if self
                    .suppression
                    .fingerprint
                    .as_deref()
                    .is_none_or(|value| !valid_hash(value))
                {
                    return Err(ProducerProvenanceError::InvalidSuppressionState);
                }
            }
        }
        if self.features.install_inventory
            != self.features.install_inventory_interval_seconds.is_some()
        {
            return Err(ProducerProvenanceError::InvalidFeatureSwitches);
        }
        if self.expected_identity()? != self.producer_manifest_id {
            return Err(ProducerProvenanceError::IdentityMismatch);
        }
        Ok(())
    }

    pub fn to_json_bytes(&self) -> Result<Vec<u8>, ProducerProvenanceError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| ProducerProvenanceError::Serialization)
    }

    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, ProducerProvenanceError> {
        let manifest = serde_json::from_slice::<Self>(bytes)
            .map_err(|_| ProducerProvenanceError::InvalidFormat)?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn expected_identity(&self) -> Result<String, ProducerProvenanceError> {
        let payload = ManifestIdentityPayload::from(self);
        let canonical =
            serde_json::to_vec(&payload).map_err(|_| ProducerProvenanceError::Serialization)?;
        Ok(domain_hash(MANIFEST_ID_DOMAIN, &canonical))
    }
}

#[derive(Serialize)]
struct ManifestIdentityPayload<'a> {
    schema: &'a str,
    version: u32,
    telltale_version: &'a str,
    event3: &'a Event3ContractIdentity,
    rules: &'a ProducerRuleProvenance,
    risk_thresholds: ProducerRiskThresholds,
    operational_alert_thresholds: ProducerOperationalAlertThresholds,
    suppression: &'a ProducerSuppressionProvenance,
    features: &'a ProducerFeatureSwitches,
}

impl<'a> From<&'a ProducerProvenanceManifestV1> for ManifestIdentityPayload<'a> {
    fn from(manifest: &'a ProducerProvenanceManifestV1) -> Self {
        Self {
            schema: &manifest.schema,
            version: manifest.version,
            telltale_version: &manifest.telltale_version,
            event3: &manifest.event3,
            rules: &manifest.rules,
            risk_thresholds: manifest.risk_thresholds,
            operational_alert_thresholds: manifest.operational_alert_thresholds,
            suppression: &manifest.suppression,
            features: &manifest.features,
        }
    }
}

pub(crate) fn domain_hash(domain: &[u8], canonical: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(canonical);
    format!("sha256:{:x}", hasher.finalize())
}

fn validate_hash(value: &str) -> Result<(), ProducerProvenanceError> {
    if valid_hash(value) {
        Ok(())
    } else {
        Err(ProducerProvenanceError::InvalidHash)
    }
}

fn valid_hash(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_semver(value: &str) -> bool {
    let (without_build, build) = match value.split_once('+') {
        Some((core, build)) => (core, Some(build)),
        None => (value, None),
    };
    if build.is_some_and(|build| !valid_semver_identifiers(build, false)) {
        return false;
    }

    let (core, prerelease) = match without_build.split_once('-') {
        Some((core, prerelease)) => (core, Some(prerelease)),
        None => (without_build, None),
    };
    let parts = core.split('.').collect::<Vec<_>>();
    if parts.len() != 3 || parts.iter().any(|part| !valid_numeric_identifier(part)) {
        return false;
    }
    prerelease.is_none_or(|prerelease| valid_semver_identifiers(prerelease, true))
}

fn valid_numeric_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'))
}

fn valid_semver_identifiers(value: &str, numeric_leading_zeroes_forbidden: bool) -> bool {
    !value.is_empty()
        && value.split('.').all(|identifier| {
            !identifier.is_empty()
                && identifier
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && (!numeric_leading_zeroes_forbidden
                    || !identifier.bytes().all(|byte| byte.is_ascii_digit())
                    || valid_numeric_identifier(identifier))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> ProducerProvenanceManifestV1 {
        ProducerProvenanceManifestV1::new(
            "0.5.0",
            ProducerRuleProvenance {
                canonicalization: RULE_V1_CANONICALIZATION.to_string(),
                fingerprint: format!("sha256:{}", "1".repeat(64)),
                rule_count: 2,
                active_policy_name: Some(crate::event::opaque_identifier("policy", "policy-a")),
            },
            ProducerRiskThresholds {
                low: 20,
                medium: 50,
                high: 70,
                critical: 90,
            },
            ProducerOperationalAlertThresholds {
                max_scanner_errors: 3,
                max_scan_duration_ms: 300_000,
            },
            ProducerSuppressionProvenance::none(),
            ProducerFeatureSwitches {
                emit_activity: false,
                emit_session_risk_summary: false,
                baseline_deviation_scoring: false,
                process_chain_detections: true,
                install_inventory: true,
                install_inventory_interval_seconds: Some(86_400),
            },
        )
        .expect("manifest")
    }

    #[test]
    fn canonical_json_is_stable_and_round_trips() {
        let manifest = manifest();
        let first = manifest.to_json_bytes().expect("json");
        let second = manifest.to_json_bytes().expect("json");
        assert_eq!(first, second);
        assert_eq!(
            ProducerProvenanceManifestV1::from_json_bytes(&first),
            Ok(manifest)
        );
    }

    #[test]
    fn rejects_identity_event_and_unknown_field_failures_without_payloads() {
        let base_manifest = manifest();
        let mut value: serde_json::Value =
            serde_json::from_slice(&base_manifest.to_json_bytes().unwrap()).unwrap();
        value["unexpected"] = serde_json::json!("synthetic-secret");
        let error =
            ProducerProvenanceManifestV1::from_json_bytes(&serde_json::to_vec(&value).unwrap())
                .expect_err("unknown field");
        assert_eq!(error, ProducerProvenanceError::InvalidFormat);
        assert!(!error.to_string().contains("synthetic-secret"));

        let mut changed = base_manifest.clone();
        changed.producer_manifest_id = format!("sha256:{}", "2".repeat(64));
        assert_eq!(
            changed.validate(),
            Err(ProducerProvenanceError::IdentityMismatch)
        );

        let mut malformed_version = base_manifest.clone();
        malformed_version.telltale_version = "01.2.3".to_string();
        assert_eq!(
            malformed_version.validate(),
            Err(ProducerProvenanceError::InvalidVersion)
        );

        let mut invalid_serialization = base_manifest;
        invalid_serialization.producer_manifest_id = format!("sha256:{}", "3".repeat(64));
        let error = serde_json::to_vec(&invalid_serialization).expect_err("invalid manifest");
        assert!(
            !error
                .to_string()
                .contains(&invalid_serialization.producer_manifest_id)
        );
    }

    #[test]
    fn explicit_suppression_state_requires_digest() {
        let mut configured_without_digest = manifest();
        configured_without_digest.suppression.state = ProducerSuppressionState::Configured;
        assert_eq!(
            configured_without_digest.validate(),
            Err(ProducerProvenanceError::InvalidSuppressionState)
        );

        let mut invalid_canonicalization = manifest();
        invalid_canonicalization.suppression.canonicalization = "suppression-v0".to_string();
        assert_ne!(
            manifest().expected_identity().unwrap(),
            invalid_canonicalization.expected_identity().unwrap()
        );
        assert_eq!(
            invalid_canonicalization.validate(),
            Err(ProducerProvenanceError::InvalidSuppressionState)
        );

        let mut raw_policy_name = manifest();
        raw_policy_name.rules.active_policy_name = Some("user@example.invalid".to_string());
        assert_eq!(
            raw_policy_name.validate(),
            Err(ProducerProvenanceError::InvalidPublicLabel)
        );

        let mut enabled_without_interval = manifest();
        enabled_without_interval
            .features
            .install_inventory_interval_seconds = None;
        assert_eq!(
            enabled_without_interval.validate(),
            Err(ProducerProvenanceError::InvalidFeatureSwitches)
        );

        let mut disabled_with_interval = manifest();
        disabled_with_interval.features.install_inventory = false;
        assert_eq!(
            disabled_with_interval.validate(),
            Err(ProducerProvenanceError::InvalidFeatureSwitches)
        );
    }
}
