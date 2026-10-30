//! Rule catalog v1: versioned presentation metadata for bundled rules.
//!
//! A host publishes this document to services that render detections (rule
//! titles, explanations, false-positive guidance) instead of projecting the
//! facade's catalog accessors into its own format. It is display metadata,
//! not executable content.

use std::sync::LazyLock;

use jsonschema::{Validator, validator_for};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Value of the `schema` field of every v1 catalog.
pub const RULE_CATALOG_V1_ID: &str = "telltale.rule_catalog.v1";

/// JSON Schema (Draft 2020-12) for rule catalog v1.
pub const RULE_CATALOG_V1_SCHEMA: &str = include_str!("../data/rule-catalog-v1.schema.json");

/// Maximum input accepted by [`RuleCatalogV1::from_json`].
pub const RULE_CATALOG_MAX_INPUT_BYTES: usize = 8 * 1024 * 1024;

static VALIDATOR: LazyLock<Result<Validator, ()>> = LazyLock::new(|| {
    let schema: Value = serde_json::from_str(RULE_CATALOG_V1_SCHEMA).map_err(|_| ())?;
    validator_for(&schema).map_err(|_| ())
});

/// Catalog document. `semantic_identity` identifies the default pipeline the
/// `enabled` flags and action scores describe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleCatalogV1 {
    /// Always [`RULE_CATALOG_V1_ID`].
    pub schema: String,
    pub telltale_version: String,
    pub semantic_identity: String,
    pub entries: Vec<RuleCatalogEntryV1>,
}

/// One rule or modifier. Session scores are frozen Event 3.0 contributions;
/// action scores are individual native contributions, not promotion totals.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleCatalogEntryV1 {
    pub id: String,
    /// `rule`, `modifier`, or `process_chain` for a rule of the bundled
    /// process-chain pack.
    pub kind: String,
    pub title: Option<String>,
    pub explanation: String,
    pub falsepositives: Vec<String>,
    pub category: Option<String>,
    pub severity: Option<String>,
    pub session_score: u64,
    pub action_score: Option<u64>,
    pub action_ordered: bool,
    pub action_within_seconds: Option<u64>,
    pub action_link: Option<String>,
    pub atlas_tags: Vec<String>,
    /// MITRE ATT&CK technique IDs; process-chain rules carry them, Rule v1
    /// rules and modifiers only `atlas_tags`.
    pub attack_techniques: Vec<String>,
    pub signal_type: String,
    pub tags: Vec<String>,
    pub enabled: bool,
    pub when_all_categories: Vec<String>,
    pub when_all_rule_ids: Vec<String>,
    /// `None` for core rules; the package ID for packaged rules.
    pub package_id: Option<String>,
}

/// Privacy-safe catalog consumer error: a code-owned constant only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleCatalogError(&'static str);

impl RuleCatalogError {
    pub const fn code(self) -> &'static str {
        self.0
    }
}

impl std::fmt::Display for RuleCatalogError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "rule catalog error: {}", self.0)
    }
}

impl std::error::Error for RuleCatalogError {}

impl RuleCatalogV1 {
    /// Parse and validate a catalog document; rejects other versions and
    /// unknown fields.
    pub fn from_json(bytes: &[u8]) -> Result<Self, RuleCatalogError> {
        if bytes.len() > RULE_CATALOG_MAX_INPUT_BYTES {
            return Err(RuleCatalogError("input_too_large"));
        }
        let value: Value =
            serde_json::from_slice(bytes).map_err(|_| RuleCatalogError("malformed_json"))?;
        if value.get("schema").and_then(Value::as_str) != Some(RULE_CATALOG_V1_ID) {
            return Err(RuleCatalogError("unsupported_catalog_version"));
        }
        let validator = VALIDATOR
            .as_ref()
            .map_err(|_| RuleCatalogError("schema_unavailable"))?;
        if !validator.is_valid(&value) {
            return Err(RuleCatalogError("schema_mismatch"));
        }
        serde_json::from_value(value).map_err(|_| RuleCatalogError("schema_mismatch"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn catalog() -> RuleCatalogV1 {
        RuleCatalogV1 {
            schema: RULE_CATALOG_V1_ID.into(),
            telltale_version: "0.7.0-rc.3".into(),
            semantic_identity: format!("semantic:v1:sha256:{}", "b".repeat(64)),
            entries: vec![RuleCatalogEntryV1 {
                id: "network.download".into(),
                kind: "rule".into(),
                title: Some("Network download".into()),
                explanation: "A tool call downloads content.".into(),
                falsepositives: vec!["Package installs".into()],
                category: Some("network".into()),
                severity: Some("medium".into()),
                session_score: 15,
                action_score: Some(15),
                action_ordered: false,
                action_within_seconds: None,
                action_link: None,
                atlas_tags: Vec::new(),
                attack_techniques: Vec::new(),
                signal_type: "atomic".into(),
                tags: Vec::new(),
                enabled: true,
                when_all_categories: Vec::new(),
                when_all_rule_ids: Vec::new(),
                package_id: None,
            }],
        }
    }

    #[test]
    fn catalog_round_trips_and_rejects_unknown_shapes() {
        let catalog = catalog();
        let text = serde_json::to_vec(&catalog).unwrap();
        assert_eq!(RuleCatalogV1::from_json(&text).unwrap(), catalog);

        let mut value = serde_json::to_value(&catalog).unwrap();
        value["entries"][0]["extra"] = true.into();
        assert_eq!(
            RuleCatalogV1::from_json(&serde_json::to_vec(&value).unwrap())
                .unwrap_err()
                .code(),
            "schema_mismatch"
        );
        value = serde_json::to_value(&catalog).unwrap();
        value["schema"] = "telltale.rule_catalog.v2".into();
        assert_eq!(
            RuleCatalogV1::from_json(&serde_json::to_vec(&value).unwrap())
                .unwrap_err()
                .code(),
            "unsupported_catalog_version"
        );
    }

    #[test]
    fn process_chain_entries_carry_attack_technique_ids_only() {
        let mut catalog = catalog();
        let entry = &mut catalog.entries[0];
        entry.kind = "process_chain".into();
        entry.attack_techniques = vec!["T1105".into(), "T1003.001".into()];
        let text = serde_json::to_vec(&catalog).unwrap();
        assert_eq!(RuleCatalogV1::from_json(&text).unwrap(), catalog);
        for invalid in ["attack:T1105", "T105", "T1003.1", "AML.T0051"] {
            let mut value = serde_json::to_value(&catalog).unwrap();
            value["entries"][0]["attack_techniques"] = serde_json::json!([invalid]);
            assert_eq!(
                RuleCatalogV1::from_json(&serde_json::to_vec(&value).unwrap())
                    .unwrap_err()
                    .code(),
                "schema_mismatch",
                "{invalid}"
            );
        }
        let mut value = serde_json::to_value(&catalog).unwrap();
        value["entries"][0]["kind"] = "detector".into();
        assert!(RuleCatalogV1::from_json(&serde_json::to_vec(&value).unwrap()).is_err());
    }

    #[test]
    fn published_schema_matches_the_embedded_copy() {
        // The repository mirror is absent from the published crate.
        let published = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../schemas/rule-catalog-v1.schema.json");
        if published.is_file() {
            assert_eq!(
                std::fs::read_to_string(published).unwrap(),
                RULE_CATALOG_V1_SCHEMA
            );
        }
    }

    #[test]
    fn v1_schema_is_frozen() {
        // A catalog version is frozen from the first release tag that carries
        // it: after that, a schema change is a new version and a new type,
        // never an edit of v1.
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(RULE_CATALOG_V1_SCHEMA.as_bytes());
        let hex = digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(
            hex,
            "347479fb462aa8169184d5d706384374dcd1080d8b47e8f68e6a772b1a5ad584"
        );
    }
}
