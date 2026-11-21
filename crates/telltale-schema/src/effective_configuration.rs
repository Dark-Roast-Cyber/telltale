//! Effective configuration v1: what one built pipeline runs.
//!
//! An embedding host shows an operator which rule content an endpoint runs:
//! each rule package and supplied document by identity and content hash, and
//! per rule and chain modifier whether it is enabled, what it scores, which
//! tier supplied it and which overrides changed it. The document holds no rule
//! matchers, no paths and no document text; the only operator-written text is
//! an override's bounded `reason`.
//!
//! It is separate from the rule catalog, which carries display metadata.
//! Every list is in a stable order, so equal configurations serialize to
//! equal bytes. A change to a field is a new version and a new type.

use std::sync::LazyLock;

use jsonschema::{Validator, validator_for};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Value of the `schema` field of every v1 document.
pub const EFFECTIVE_CONFIGURATION_V1_ID: &str = "telltale.effective_configuration.v1";

/// JSON Schema (Draft 2020-12) for effective configuration v1.
pub const EFFECTIVE_CONFIGURATION_V1_SCHEMA: &str =
    include_str!("../data/effective-configuration-v1.schema.json");

/// Largest serialized document [`EffectiveConfigurationV1::from_json`]
/// accepts and [`EffectiveConfigurationV1::to_json`] produces: 8 MiB, the
/// rule catalog's bound, which holds the most definitions a pipeline reports
/// with room for override reasons.
pub const EFFECTIVE_CONFIGURATION_MAX_INPUT_BYTES: usize = 8 * 1024 * 1024;

static VALIDATOR: LazyLock<Result<Validator, ()>> = LazyLock::new(|| {
    let schema: Value = serde_json::from_str(EFFECTIVE_CONFIGURATION_V1_SCHEMA).map_err(|_| ())?;
    validator_for(&schema).map_err(|_| ())
});

/// The effective configuration of one pipeline. `semantic_identity` is the
/// pipeline's identity for the evaluation options the document was made
/// with, as in the rule catalog and action records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectiveConfigurationV1 {
    /// Always [`EFFECTIVE_CONFIGURATION_V1_ID`].
    pub schema: String,
    pub telltale_version: String,
    pub semantic_identity: String,
    /// Rule packages compiled into the pipeline, by `id`.
    pub packages: Vec<EffectivePackageV1>,
    /// Documents the host supplied as text, by `kind` in the order
    /// organization, explicit, override, policy, then in the order supplied.
    pub documents: Vec<EffectiveDocumentV1>,
    /// Every rule and chain modifier loaded, enabled or not, and the
    /// process-chain rules when the options enable them; by `id`.
    pub definitions: Vec<EffectiveDefinitionV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectivePackageV1 {
    pub id: String,
    pub version: String,
    /// Lowercase hex SHA-256 of the package text.
    pub content_sha256: String,
    pub origin: PackageOriginV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageOriginV1 {
    /// The community snapshot built into Telltale.
    Embedded,
    /// A package the host supplied.
    Supplied,
}

/// A document the host supplied as text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectiveDocumentV1 {
    pub kind: DocumentKindV1,
    /// The host's label, or the document's 1-based position among its kind.
    pub label: String,
    /// Lowercase hex SHA-256 of the document text.
    pub content_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocumentKindV1 {
    /// A rule document at the organization tier.
    Organization,
    /// An additive rule document.
    Explicit,
    /// An override document.
    Override,
    /// The rule policy.
    Policy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectiveDefinitionV1 {
    /// The compiled id: a Rule v2 `name` or a process-chain rule `id`.
    pub id: String,
    pub kind: DefinitionKindV1,
    /// Whether it takes part in detection, policy and overrides included.
    pub enabled: bool,
    /// What turned it off; `None` exactly when it is enabled.
    pub disabled_by: Option<DisabledByV1>,
    /// The session score after overrides.
    pub session_score: u64,
    /// The individual action score; `None` when the definition does not
    /// take part in action detection.
    pub action_score: Option<u64>,
    /// The tier whose definition is in effect.
    pub tier: RuleTierV1,
    /// The tier of the definition this one replaced by ID; `None` when it
    /// replaced nothing.
    pub replaced_tier: Option<RuleTierV1>,
    /// The package that ships the definition; `None` for other content.
    pub package_id: Option<String>,
    /// The `label` of the supplied document of kind `tier` that defines it;
    /// `None` for bundled and packaged content and content not supplied as
    /// text.
    pub document: Option<String>,
    /// Overrides that changed it, in the order applied; the last one wins.
    pub overrides: Vec<AppliedOverrideV1>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefinitionKindV1 {
    Rule,
    /// A chain modifier (a Rule v2 chain).
    Modifier,
    /// A rule of the bundled process-chain pack.
    ProcessChain,
}

/// What turned a definition off, checked in this order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisabledByV1 {
    /// Its own definition: `enabled: false`, or a status that loads it
    /// disabled, and no override sets `enabled`.
    Definition,
    /// The last override entry that sets `enabled` sets `false`.
    Override,
    /// It is enabled before policy, and the rule policy leaves it out.
    Policy,
}

/// Rule content tiers, lowest first; a higher tier replaces a definition in
/// place.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleTierV1 {
    Builtin,
    Package,
    Organization,
    Deployment,
    Local,
    Explicit,
}

/// One override entry applied to a definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppliedOverrideV1 {
    /// The `label` of the override document; `None` for overrides not
    /// supplied as text.
    pub document: Option<String>,
    /// The operator's reason: one to 256 characters, without control or
    /// invisible formatting characters other than tab and newline.
    pub reason: String,
    pub enabled: Option<bool>,
    pub score: Option<u64>,
}

/// Privacy-safe consumer error: a code-owned constant only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectiveConfigurationError(&'static str);

impl EffectiveConfigurationError {
    pub const fn code(self) -> &'static str {
        self.0
    }
}

impl std::fmt::Display for EffectiveConfigurationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "effective configuration error: {}", self.0)
    }
}

impl std::error::Error for EffectiveConfigurationError {}

impl EffectiveConfigurationV1 {
    /// Parse and validate a document; rejects other versions, unknown fields
    /// and input over [`EFFECTIVE_CONFIGURATION_MAX_INPUT_BYTES`].
    pub fn from_json(bytes: &[u8]) -> Result<Self, EffectiveConfigurationError> {
        if bytes.len() > EFFECTIVE_CONFIGURATION_MAX_INPUT_BYTES {
            return Err(EffectiveConfigurationError("input_too_large"));
        }
        let value: Value = serde_json::from_slice(bytes)
            .map_err(|_| EffectiveConfigurationError("malformed_json"))?;
        check(&value)?;
        serde_json::from_value(value).map_err(|_| EffectiveConfigurationError("schema_mismatch"))
    }

    /// Serialize the document, failing if it would not pass [`Self::from_json`].
    pub fn to_json(&self) -> Result<Vec<u8>, EffectiveConfigurationError> {
        let value = serde_json::to_value(self)
            .map_err(|_| EffectiveConfigurationError("schema_mismatch"))?;
        check(&value)?;
        let bytes = serde_json::to_vec(&value)
            .map_err(|_| EffectiveConfigurationError("schema_mismatch"))?;
        if bytes.len() > EFFECTIVE_CONFIGURATION_MAX_INPUT_BYTES {
            return Err(EffectiveConfigurationError("input_too_large"));
        }
        Ok(bytes)
    }
}

fn check(value: &Value) -> Result<(), EffectiveConfigurationError> {
    if value.get("schema").and_then(Value::as_str) != Some(EFFECTIVE_CONFIGURATION_V1_ID) {
        return Err(EffectiveConfigurationError("unsupported_version"));
    }
    let validator = VALIDATOR
        .as_ref()
        .map_err(|_| EffectiveConfigurationError("schema_unavailable"))?;
    if validator.is_valid(value) {
        Ok(())
    } else {
        Err(EffectiveConfigurationError("schema_mismatch"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn document() -> EffectiveConfigurationV1 {
        EffectiveConfigurationV1 {
            schema: EFFECTIVE_CONFIGURATION_V1_ID.into(),
            telltale_version: "0.8.0-rc.1".into(),
            semantic_identity: format!("semantic:v1:sha256:{}", "b".repeat(64)),
            packages: vec![EffectivePackageV1 {
                id: "syn.pack".into(),
                version: "1.0.0".into(),
                content_sha256: "c".repeat(64),
                origin: PackageOriginV1::Supplied,
            }],
            documents: vec![EffectiveDocumentV1 {
                kind: DocumentKindV1::Override,
                label: "fleet-tuning".into(),
                content_sha256: "d".repeat(64),
            }],
            definitions: vec![EffectiveDefinitionV1 {
                id: "syn.base".into(),
                kind: DefinitionKindV1::Rule,
                enabled: true,
                disabled_by: None,
                session_score: 55,
                action_score: Some(55),
                tier: RuleTierV1::Package,
                replaced_tier: None,
                package_id: Some("syn.pack".into()),
                document: None,
                overrides: vec![AppliedOverrideV1 {
                    document: Some("fleet-tuning".into()),
                    reason: "Noisy in CI.".into(),
                    enabled: None,
                    score: Some(55),
                }],
            }],
        }
    }

    fn code(value: &Value) -> &'static str {
        EffectiveConfigurationV1::from_json(&serde_json::to_vec(value).unwrap())
            .unwrap_err()
            .code()
    }

    #[test]
    fn document_round_trips() {
        let document = document();
        let bytes = document.to_json().unwrap();
        assert_eq!(
            EffectiveConfigurationV1::from_json(&bytes).unwrap(),
            document
        );
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let mut top = serde_json::to_value(document()).unwrap();
        top["extra"] = json!(true);
        assert_eq!(code(&top), "schema_mismatch");
        let mut nested = serde_json::to_value(document()).unwrap();
        nested["definitions"][0]["overrides"][0]["path"] = json!("synthetic");
        assert_eq!(code(&nested), "schema_mismatch");
    }

    #[test]
    fn other_versions_are_rejected() {
        let mut value = serde_json::to_value(document()).unwrap();
        value["schema"] = json!("telltale.effective_configuration.v2");
        assert_eq!(code(&value), "unsupported_version");
    }

    #[test]
    fn input_over_eight_mebibytes_is_rejected_before_parsing() {
        let oversized = vec![b' '; 8 * 1024 * 1024 + 1];
        assert_eq!(
            EffectiveConfigurationV1::from_json(&oversized)
                .unwrap_err()
                .code(),
            "input_too_large"
        );
    }

    #[test]
    fn reasons_are_bounded_text_without_control_characters() {
        for (reason, expected) in [
            ("a".repeat(256), None),
            ("a".repeat(257), Some("schema_mismatch")),
            ("tab\tand\nnewline".into(), None),
            ("escape\u{1b}[2J".into(), Some("schema_mismatch")),
            ("bidi\u{202e}override".into(), Some("schema_mismatch")),
            (String::new(), Some("schema_mismatch")),
        ] {
            let mut value = serde_json::to_value(document()).unwrap();
            value["definitions"][0]["overrides"][0]["reason"] = json!(reason);
            let result = EffectiveConfigurationV1::from_json(&serde_json::to_vec(&value).unwrap());
            assert_eq!(
                result.err().map(|error| error.code()),
                expected,
                "{reason:?}"
            );
        }
    }

    #[test]
    fn a_disabled_cause_is_present_exactly_when_a_definition_is_disabled() {
        for (enabled, disabled_by, expected) in [
            (true, json!(null), None),
            (false, json!("policy"), None),
            (false, json!(null), Some("schema_mismatch")),
            (true, json!("override"), Some("schema_mismatch")),
            (false, json!("status"), Some("schema_mismatch")),
        ] {
            let mut value = serde_json::to_value(document()).unwrap();
            value["definitions"][0]["enabled"] = json!(enabled);
            value["definitions"][0]["disabled_by"] = disabled_by.clone();
            let result = EffectiveConfigurationV1::from_json(&serde_json::to_vec(&value).unwrap());
            assert_eq!(
                result.err().map(|error| error.code()),
                expected,
                "{enabled} {disabled_by}"
            );
        }
    }

    #[test]
    fn to_json_refuses_a_document_the_consumer_would_reject() {
        let mut document = document();
        document.definitions[0].overrides[0].reason = "a".repeat(257);
        assert_eq!(document.to_json().unwrap_err().code(), "schema_mismatch");
    }

    #[test]
    fn published_schema_matches_the_embedded_copy() {
        // The repository mirror is absent from the published crate.
        let published = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../schemas/effective-configuration-v1.schema.json");
        if published.is_file() {
            assert_eq!(
                std::fs::read_to_string(published).unwrap(),
                EFFECTIVE_CONFIGURATION_V1_SCHEMA
            );
        }
    }
}
