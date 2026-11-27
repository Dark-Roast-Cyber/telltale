use super::*;
use crate::action_record::ACTION_RECORD_V1_SCHEMA;
use serde_json::json;

const GOLDEN: &[u8] = include_bytes!("fixtures/action-record-v2.json");

fn golden() -> Value {
    serde_json::from_slice(GOLDEN).unwrap()
}

fn wire(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

fn assert_rejected(
    bytes: &[u8],
    category: ActionRecordErrorCategory,
    code: &str,
) -> ActionRecordError {
    let error = ActionRecordV2::from_json(bytes).unwrap_err();
    assert_eq!(error.category(), category);
    assert_eq!(error.code(), code);
    error
}

fn v1_wire(mut value: Value) -> Value {
    value["schema"] = json!(ACTION_RECORD_V1_ID);
    let fields = value.as_object_mut().unwrap();
    fields.remove("destinations");
    value
}

#[test]
fn golden_record_round_trips_through_the_strict_consumer() {
    let record = ActionRecordV2::from_json(GOLDEN).unwrap();
    record.validate().unwrap();
    assert_eq!(serde_json::to_value(&record).unwrap(), golden());
    assert_eq!(
        ActionRecordV2::from_json(&serde_json::to_vec(&record).unwrap()).unwrap(),
        record
    );
}

#[test]
fn consumer_rejects_oversized_and_malformed_input() {
    use ActionRecordErrorCategory::{Malformed, Structure};
    let oversized = vec![b' '; ACTION_RECORD_MAX_INPUT_BYTES + 1];
    assert_rejected(&oversized, Structure, "input_too_large");
    assert_rejected(b"{not json", Malformed, "malformed_json");
}

#[test]
fn consumer_rejects_other_record_versions() {
    use ActionRecordErrorCategory::Version;
    let v1 = v1_wire(golden());
    ActionRecordV1::from_json(&wire(&v1)).unwrap();
    assert_rejected(&wire(&v1), Version, "unsupported_record_version");

    let mut future = golden();
    future["schema"] = json!("telltale.action.v3");
    assert_rejected(&wire(&future), Version, "unsupported_record_version");
}

#[test]
fn consumer_requires_exact_fields_even_when_nullable() {
    use ActionRecordErrorCategory::Structure;
    let mut extra = golden();
    extra["host_field"] = json!(true);
    assert_rejected(&wire(&extra), Structure, "schema_mismatch");
    let mut nested = golden();
    nested["destinations"]["raw"] = json!("synthetic-input");
    assert_rejected(&wire(&nested), Structure, "schema_mismatch");
    for key in ["occurred_at", "destinations"] {
        let mut missing = golden();
        missing.as_object_mut().unwrap().remove(key);
        assert_rejected(&wire(&missing), Structure, "schema_mismatch");
    }
}

#[test]
fn consumer_distinguishes_unknown_clients_from_bad_client_syntax() {
    use ActionRecordErrorCategory::{Identity, Structure};
    let mut value = golden();
    value["client"] = json!("synthetic_client");
    let error = assert_rejected(&wire(&value), Identity, "unknown_client");
    assert_eq!(error.to_string(), "action record error: unknown_client");
    assert!(!format!("{error:?}").contains("synthetic_client"));

    value["client"] = json!("Pi");
    assert_rejected(&wire(&value), Structure, "schema_mismatch");
}

#[test]
fn pi_is_accepted_in_v2_and_rejected_in_v1() {
    let mut value = golden();
    value["client"] = json!("pi");
    value["source_id"] = json!("pi.sessions");
    let record = ActionRecordV2::from_json(&wire(&value)).unwrap();
    record.validate().unwrap();
    assert_eq!(record.client, "pi");
    assert_eq!(
        ActionRecordV1::from_json(&wire(&v1_wire(value)))
            .unwrap_err()
            .code(),
        "schema_mismatch"
    );
}

#[test]
fn local_only_requires_complete_facts_with_no_destinations() {
    use ActionRecordErrorCategory::Structure;
    let mut value = golden();
    value["destinations"]["local_only"] = json!(true);
    assert_rejected(&wire(&value), Structure, "schema_mismatch");

    value["destinations"]["destinations"] = json!([]);
    assert!(
        ActionRecordV2::from_json(&wire(&value))
            .unwrap()
            .destinations
            .unwrap()
            .local_only
    );

    value["destinations"]["complete"] = json!(false);
    assert_rejected(&wire(&value), Structure, "schema_mismatch");
}

#[test]
fn consumer_rejects_destination_facts_that_break_their_invariants() {
    use ActionRecordErrorCategory::Semantic;
    let mut value = golden();
    // Valid shape, but entries must be in ascending byte order.
    value["destinations"]["destinations"] = json!([
        "uploads.example.invalid/artifacts",
        "artifacts.example.invalid/org/repo"
    ]);
    assert_rejected(&wire(&value), Semantic, "invalid_destinations");
    let error = serde_json::from_value::<ActionRecordV2>(value)
        .unwrap()
        .validate()
        .unwrap_err();
    assert_eq!(error.code(), "invalid_destinations");

    let mut unsafe_entry = golden();
    unsafe_entry["destinations"]["destinations"][0] = json!("example.invalid/akiaiosfodnn7example");
    let error = assert_rejected(&wire(&unsafe_entry), Semantic, "invalid_destinations");
    assert!(!format!("{error} {error:?}").contains("akiaiosfodnn7example"));
}

#[test]
fn consumer_allows_destination_facts_only_on_the_upload_rule() {
    use ActionRecordErrorCategory::Semantic;
    let mut value = golden();
    value["rule_ids"] = json!(["network.download"]);
    value["canonical_findings"][0]["detector_id"] = json!("network.download");
    value["evidence"][0]["rule_id"] = json!("network.download");
    value["contributions"][0]["id"] = json!("network.download");
    assert_rejected(&wire(&value), Semantic, "invalid_destinations");

    value["destinations"] = Value::Null;
    assert!(
        ActionRecordV2::from_json(&wire(&value))
            .unwrap()
            .destinations
            .is_none()
    );
}

#[test]
fn consumer_rejects_a_call_identifier_field() {
    // v2 defines no call pairing; a record that carries one is not v2.
    use ActionRecordErrorCategory::Structure;
    for call_id in [
        Value::Null,
        json!(format!("call:v1:hmac-sha256:{}", "a".repeat(64))),
    ] {
        let mut value = golden();
        value["call_id"] = call_id;
        assert_rejected(&wire(&value), Structure, "schema_mismatch");
    }
}

#[test]
fn consumer_keeps_the_shared_action_semantic_checks() {
    use ActionRecordErrorCategory::{Identity, Semantic};
    let cases = [
        (
            "/session_id",
            json!("synthetic session with spaces"),
            Identity,
            "invalid_session_id",
        ),
        (
            "/stage",
            json!("message_observed"),
            Semantic,
            "incompatible_stage",
        ),
        (
            "/tool_name",
            json!("Not A Tool"),
            Semantic,
            "invalid_time_or_tool",
        ),
        (
            "/occurred_at",
            json!("yesterday"),
            Semantic,
            "invalid_time_or_tool",
        ),
        (
            "/rule_ids/0",
            json!("not a rule id"),
            Semantic,
            "invalid_rule_id",
        ),
        (
            "/promotion_score",
            json!(26),
            Semantic,
            "promotion_score_mismatch",
        ),
        (
            "/severity",
            json!("critical"),
            Semantic,
            "inconsistent_findings",
        ),
        (
            "/evidence/0/redacted_value",
            json!("\u{2603}".repeat(200)),
            Semantic,
            "evidence_too_large",
        ),
        (
            "/evidence/0/highlight",
            json!({"start": 0, "end": 100}),
            Semantic,
            "invalid_highlight",
        ),
        (
            "/context/0/redacted_text",
            json!("\u{2603}".repeat(200)),
            Semantic,
            "context_too_large",
        ),
    ];
    for (pointer, edited, category, code) in cases {
        let mut value = golden();
        *value.pointer_mut(pointer).unwrap() = edited;
        assert_rejected(&wire(&value), category, code);
    }
}

#[test]
fn consumer_rejects_text_redaction_would_change_without_echoing_it() {
    let marker = "AKIAPRIVATEMARKER234";
    for pointer in [
        "/context/0/redacted_text",
        "/evidence/0/redacted_value",
        "/contributions/0/rationale",
    ] {
        let mut value = golden();
        *value.pointer_mut(pointer).unwrap() = json!(format!("key {marker}"));
        let error = assert_rejected(
            &wire(&value),
            ActionRecordErrorCategory::Semantic,
            "unredacted_text",
        );
        assert!(!format!("{error} {error:?}").contains(marker));
    }
}

#[test]
fn delivery_keys_and_aliases_match_v1_with_or_without_replay_identity() {
    let v1 = ActionRecordV1::from_json(&wire(&v1_wire(golden()))).unwrap();
    let v2 = ActionRecordV2::from_json(GOLDEN).unwrap();
    let projected = ActionRecordV2::from_v1(v1.clone(), v2.destinations.clone());
    assert_eq!(projected, v2);
    assert_eq!(v2.delivery_key(), v1.delivery_key());
    assert_eq!(v2.delivery_aliases(), v1.delivery_aliases());
    assert_eq!(v2.delivery_aliases().len(), 2);

    let v1 = ActionRecordV1 {
        replay_identity: None,
        ..v1
    };
    let v2 = ActionRecordV2 {
        replay_identity: None,
        ..v2
    };
    assert_eq!(v2.delivery_key(), v1.delivery_key());
    assert_eq!(v2.delivery_aliases(), v1.delivery_aliases());
    assert_eq!(v2.delivery_aliases(), [v2.delivery_key()]);
}

#[test]
fn schema_vocabularies_match_the_rust_types() {
    let mut v2: Value = serde_json::from_str(ACTION_RECORD_V2_SCHEMA).unwrap();
    let client_schema = validator_for(&v2["properties"]["client"]).unwrap();
    for client in ClientId::ALL {
        assert!(
            client_schema.is_valid(&json!(client.as_str())),
            "{client:?}"
        );
    }

    // v1 checks the shared vocabularies (family, stage and contribution type)
    // against the Rust types; v2 keeps all those definitions and field uses.
    let v1: Value = serde_json::from_str(ACTION_RECORD_V1_SCHEMA).unwrap();
    v2["$defs"]
        .as_object_mut()
        .unwrap()
        .remove("destinationFacts");
    let properties = v2["properties"].as_object_mut().unwrap();
    properties.remove("destinations");
    properties.insert("client".into(), v1["properties"]["client"].clone());
    properties.insert("schema".into(), v1["properties"]["schema"].clone());
    assert_eq!(v2["$defs"], v1["$defs"]);
    assert_eq!(v2["properties"], v1["properties"]);
    let required = v2["required"].as_array_mut().unwrap();
    required.retain(|field| field != "destinations");
    assert_eq!(v2["required"], v1["required"]);
}

#[test]
fn published_schema_matches_the_embedded_copy() {
    // The repository mirror is absent from the published crate.
    let published = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../schemas/action-record-v2.schema.json");
    if published.is_file() {
        assert_eq!(
            std::fs::read_to_string(published).unwrap(),
            ACTION_RECORD_V2_SCHEMA
        );
    }
}
