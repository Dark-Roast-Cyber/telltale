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
