//! Rule catalog v2: versioned presentation metadata for rules.
//!
//! A host publishes this document to services that render detections (rule
//! titles, explanations, false-positive guidance), and an external rule
//! repository's lint reads it for the content a Telltale build resolves,
//! instead of each parsing rule files. It is display metadata, not executable
//! content. Catalog v1 (`telltale.rule_catalog.v1`, Telltale 0.7) is kept
//! only as `schemas/historical/rule-catalog-v1.schema.json`.

use std::sync::LazyLock;

use jsonschema::{Validator, validator_for};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Value of the `schema` field of every v2 catalog.
pub const RULE_CATALOG_V2_ID: &str = "telltale.rule_catalog.v2";

/// JSON Schema (Draft 2020-12) for rule catalog v2.
pub const RULE_CATALOG_V2_SCHEMA: &str = include_str!("../data/rule-catalog-v2.schema.json");

/// Maximum input accepted by [`RuleCatalogV2::from_json`].
pub const RULE_CATALOG_MAX_INPUT_BYTES: usize = 8 * 1024 * 1024;

static VALIDATOR: LazyLock<Result<Validator, ()>> = LazyLock::new(|| {
    let schema: Value = serde_json::from_str(RULE_CATALOG_V2_SCHEMA).map_err(|_| ())?;
    validator_for(&schema).map_err(|_| ())
});

/// Catalog document. `semantic_identity` identifies the pipeline the
/// `enabled` flags and action scores describe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleCatalogV2 {
    /// Always [`RULE_CATALOG_V2_ID`].
    pub schema: String,
    pub telltale_version: String,
    pub semantic_identity: String,
    pub entries: Vec<RuleCatalogEntryV2>,
}

/// One rule, modifier (a Rule v2 chain) or process-chain rule. Session scores
/// are frozen Event 3.0 contributions; action scores are individual native
/// contributions, not promotion totals. Every key is always present.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleCatalogEntryV2 {
    /// The compiled id: a Rule v2 `name`, a Rule v1 `id`.
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
    /// MITRE ATT&CK technique IDs: from a Rule v2 document's `attack.*` tags,
    /// or a process-chain rule's techniques.
    pub attack_techniques: Vec<String>,
    pub signal_type: String,
    pub tags: Vec<String>,
    pub enabled: bool,
    pub when_all_categories: Vec<String>,
    pub when_all_rule_ids: Vec<String>,
    /// `None` for core rules; the package ID for packaged rules.
    pub package_id: Option<String>,
    /// The Rule v2 `id`; `None` for Rule v1 and process-chain rules.
    pub uuid: Option<String>,
    /// Sigma status: `experimental`, `test`, `stable`, `deprecated` or
    /// `unsupported`.
    pub status: Option<String>,
    pub description: Option<String>,
    pub references: Vec<String>,
    pub author: Option<String>,
    pub license: Option<String>,
    /// `YYYY-MM-DD`.
    pub date: Option<String>,
    /// `YYYY-MM-DD`.
    pub modified: Option<String>,
    pub related: Vec<RuleCatalogRelatedV2>,
    pub logsource: Option<RuleCatalogLogSourceV2>,
    /// `sha256:<hex>` of the rule's one-rule compiled export (its behaviour
    /// revision); `None` for process-chain rules and content that does not
    /// compile.
    pub behavior_fingerprint: Option<String>,
    /// `sha256:<hex>` of the descriptive metadata the behaviour fingerprint
    /// leaves out; `None` for process-chain rules.
    pub metadata_revision: Option<String>,
}

/// A Sigma `related` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleCatalogRelatedV2 {
    pub id: String,
    /// `derived`, `obsolete`, `merged`, `renamed` or `similar`.
    #[serde(rename = "type")]
    pub kind: String,
}

/// A Rule v2 rule's `logsource`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleCatalogLogSourceV2 {
    pub product: String,
    pub category: String,
    pub service: Option<String>,
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

impl RuleCatalogV2 {
    /// Parse and validate a catalog document; rejects other versions and
    /// unknown fields.
    pub fn from_json(bytes: &[u8]) -> Result<Self, RuleCatalogError> {
        if bytes.len() > RULE_CATALOG_MAX_INPUT_BYTES {
            return Err(RuleCatalogError("input_too_large"));
        }
        let value: Value =
            serde_json::from_slice(bytes).map_err(|_| RuleCatalogError("malformed_json"))?;
        if value.get("schema").and_then(Value::as_str) != Some(RULE_CATALOG_V2_ID) {
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

    fn catalog() -> RuleCatalogV2 {
        RuleCatalogV2 {
            schema: RULE_CATALOG_V2_ID.into(),
            telltale_version: "0.8.0-rc.1".into(),
            semantic_identity: format!("semantic:v1:sha256:{}", "b".repeat(64)),
            entries: vec![RuleCatalogEntryV2 {
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
                attack_techniques: vec!["T1105".into()],
                signal_type: "atomic".into(),
                tags: Vec::new(),
                enabled: true,
                when_all_categories: Vec::new(),
                when_all_rule_ids: Vec::new(),
                package_id: None,
                uuid: Some("3f2504e0-4f89-41d3-9a0c-0305e82c3301".into()),
                status: Some("stable".into()),
                description: Some("Synthetic description.".into()),
                references: vec!["https://example.invalid/note".into()],
                author: Some("Synthetic author".into()),
                license: Some("Apache-2.0".into()),
                date: Some("2026-11-18".into()),
                modified: None,
                related: vec![RuleCatalogRelatedV2 {
                    id: "9b2d6c8e-1f4a-4c3b-8d2e-5a6f7b8c9d0e".into(),
                    kind: "derived".into(),
                }],
                logsource: Some(RuleCatalogLogSourceV2 {
                    product: "ai_agent".into(),
                    category: "tool_activity".into(),
                    service: None,
                }),
                behavior_fingerprint: Some(format!("sha256:{}", "c".repeat(64))),
                metadata_revision: Some(format!("sha256:{}", "d".repeat(64))),
            }],
        }
    }

    fn code(value: &Value) -> &'static str {
        RuleCatalogV2::from_json(&serde_json::to_vec(value).unwrap())
            .unwrap_err()
            .code()
    }

    #[test]
    fn catalog_round_trips_and_rejects_unknown_shapes() {
        let catalog = catalog();
        let text = serde_json::to_vec(&catalog).unwrap();
        assert_eq!(RuleCatalogV2::from_json(&text).unwrap(), catalog);

        let mut value = serde_json::to_value(&catalog).unwrap();
        value["entries"][0]["extra"] = true.into();
        assert_eq!(code(&value), "schema_mismatch");
        value = serde_json::to_value(&catalog).unwrap();
        value["schema"] = "telltale.rule_catalog.v1".into();
        assert_eq!(code(&value), "unsupported_catalog_version");
    }

    #[test]
    fn every_key_is_required_and_absent_values_are_null() {
        let catalog = catalog();
        let mut nulls = serde_json::to_value(&catalog).unwrap();
        for key in [
            "uuid",
            "status",
            "description",
            "author",
            "license",
            "date",
            "modified",
            "logsource",
            "behavior_fingerprint",
            "metadata_revision",
        ] {
            nulls["entries"][0][key] = Value::Null;
        }
        assert!(RuleCatalogV2::from_json(&serde_json::to_vec(&nulls).unwrap()).is_ok());
        for key in ["uuid", "related", "logsource", "metadata_revision"] {
            let mut value = serde_json::to_value(&catalog).unwrap();
            value["entries"][0].as_object_mut().unwrap().remove(key);
            assert_eq!(code(&value), "schema_mismatch", "{key}");
        }
    }

    #[test]
    fn metadata_values_are_checked() {
        let catalog = catalog();
        for (pointer, invalid) in [
            ("/entries/0/uuid", serde_json::json!("not-a-uuid")),
            ("/entries/0/status", serde_json::json!("draft")),
            ("/entries/0/date", serde_json::json!("18.11.2026")),
            ("/entries/0/related/0/type", serde_json::json!("parent")),
            ("/entries/0/logsource/service", serde_json::json!("")),
            (
                "/entries/0/behavior_fingerprint",
                serde_json::json!("md5:00"),
            ),
            (
                "/entries/0/attack_techniques/0",
                serde_json::json!("AML.T0051"),
            ),
            ("/entries/0/kind", serde_json::json!("detector")),
        ] {
            let mut value = serde_json::to_value(&catalog).unwrap();
            *value.pointer_mut(pointer).unwrap() = invalid;
            assert_eq!(code(&value), "schema_mismatch", "{pointer}");
        }
    }

    #[test]
    fn published_schema_matches_the_embedded_copy() {
        // The repository mirror is absent from the published crate.
        let published = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../schemas/rule-catalog-v2.schema.json");
        if published.is_file() {
            assert_eq!(
                std::fs::read_to_string(published).unwrap(),
                RULE_CATALOG_V2_SCHEMA
            );
        }
    }

    #[test]
    fn historical_v1_schema_is_unchanged() {
        // Catalog v1 shipped in 0.7 and is frozen; only its historical copy
        // remains. A catalog version is frozen from the first release tag that
        // carries it: v2 joins this test then.
        use sha2::{Digest, Sha256};
        let historical = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../schemas/historical/rule-catalog-v1.schema.json");
        if historical.is_file() {
            let digest = Sha256::digest(std::fs::read(historical).unwrap());
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
}
