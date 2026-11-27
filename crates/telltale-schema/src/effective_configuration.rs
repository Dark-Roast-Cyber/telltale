//! Effective configuration v1: what one built pipeline runs.
//!
//! An embedding host shows an operator which rule content an endpoint runs:
//! each rule package and supplied document by identity and content hash, and
//! per rule and chain modifier whether it is enabled and what turned it off,
//! what it scores, which tier supplied it and what it replaced, and which
//! overrides were applied to it. The document holds no rule matchers, no paths
//! and no document text; the only operator-written text is an override's
//! bounded `reason` and the bounded labels the host gave its inputs.
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
    /// Overrides applied to it, in the order applied, including any that set
    /// a value it already had. For `enabled` and for `score`, the last entry
    /// that sets that field decides it.
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
mod tests;
