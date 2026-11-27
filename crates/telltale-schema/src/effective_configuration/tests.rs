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
