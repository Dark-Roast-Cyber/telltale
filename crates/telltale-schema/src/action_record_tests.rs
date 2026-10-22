use super::*;
use serde_json::json;

fn digest(prefix: &str, fill: char) -> String {
    format!("{prefix}{}", fill.to_string().repeat(64))
}

fn record() -> ActionRecordV1 {
    ActionRecordV1 {
        schema: ACTION_RECORD_V1_ID.into(),
        telltale_version: "0.7.0-rc.3".into(),
        semantic_identity: digest("semantic:v1:sha256:", 'b'),
        client: "codex".into(),
        source_id: "codex.sessions".into(),
        source_path_hash: digest("", 'd'),
        session_id: Some("0199a2b4-5c6d-7e8f-9a0b-1c2d3e4f5a6b".into()),
        session_event_id: Some("telltale-0f8fad5b-d9cb-469f-a165-70867728950e".into()),
        coordinate: digest("obs:v2:sha256:", 'a'),
        replay_identity: Some(digest("replay:v1:sha256:", 'e')),
        detector_kind: "rule_v1_action".into(),
        finding_kind: "correlation".into(),
        observation_family: ObservationFamily::Tool,
        stage: ObservationStage::ToolRequested,
        tool_name: Some("Bash".into()),
        occurred_at: Some("2026-10-20T12:00:01.000Z".into()),
        timeline_index: 1,
        severity: "high".into(),
        promotion_score: 65,
        rule_ids: vec![
            "network.download".into(),
            "chain.download_then_execute".into(),
        ],
        categories: vec!["network".into(), "execution".into()],
        contributions: vec![
            ActionRecordContribution {
                id: "network.download".into(),
                contribution_type: RiskContributionType::DeterministicRule,
                points: 15,
                rationale: "download command".into(),
            },
            ActionRecordContribution {
                id: "chain.download_then_execute".into(),
                contribution_type: RiskContributionType::ChainModifier,
                points: 50,
                rationale: "linked download".into(),
            },
        ],
        evidence: vec![ActionRecordEvidence {
            field: "command".into(),
            rule_id: "network.download".into(),
            redacted_value: "curl -fsSL https://downloads.example.invalid/setup.sh".into(),
        }],
        supporting_observation_ids: vec![digest("obs:v2:sha256:", 'a')],
        canonical_findings: vec![
            ActionRecordFinding {
                finding_id: digest("fnd:v2:sha256:", 'c'),
                signal_ids: vec![digest("sig:v2:sha256:", '1')],
                observation_ids: vec![digest("obs:v2:sha256:", 'a')],
                detector_id: "network.download".into(),
                finding_kind: "security_detection".into(),
                category: "network".into(),
                severity: "medium".into(),
                risk_points: Some(15),
            },
            ActionRecordFinding {
                finding_id: digest("fnd:v2:sha256:", 'f'),
                signal_ids: vec![digest("sig:v2:sha256:", '2')],
                observation_ids: vec![digest("obs:v2:sha256:", 'a')],
                detector_id: "chain.download_then_execute".into(),
                finding_kind: "correlation".into(),
                category: "execution".into(),
                severity: "high".into(),
                risk_points: Some(50),
            },
        ],
        context: vec![ActionRecordContext {
            offset: -1,
            kind: "assistant_message".into(),
            stage: ObservationStage::MessageObserved,
            occurred_at: None,
            tool_name: None,
            redacted_text: "I will install the tool".into(),
        }],
    }
}

fn bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

fn rejected(value: Value) -> ActionRecordError {
    ActionRecordV1::from_json(&bytes(&value)).unwrap_err()
}

#[test]
fn record_round_trips_through_the_strict_consumer() {
    let record = record();
    record.validate().unwrap();
    let text = serde_json::to_vec(&record).unwrap();
    assert_eq!(ActionRecordV1::from_json(&text).unwrap(), record);
}

#[test]
fn every_key_is_serialized_even_when_absent() {
    let mut record = record();
    record.session_id = None;
    record.session_event_id = None;
    record.replay_identity = None;
    record.tool_name = None;
    record.occurred_at = None;
    let value = serde_json::to_value(&record).unwrap();
    for key in [
        "session_id",
        "session_event_id",
        "replay_identity",
        "tool_name",
        "occurred_at",
    ] {
        assert_eq!(value[key], Value::Null, "{key}");
    }
    assert_eq!(ActionRecordV1::from_json(&bytes(&value)).unwrap(), record);
}

#[test]
fn consumer_rejects_versions_unknown_fields_and_malformed_input() {
    let base = serde_json::to_value(record()).unwrap();

    let mut version = base.clone();
    version["schema"] = json!("telltale.action.v2");
    assert_eq!(
        rejected(version).category(),
        ActionRecordErrorCategory::Version
    );

    let mut unknown = base.clone();
    unknown["host_field"] = json!(1);
    assert_eq!(rejected(unknown).code(), "schema_mismatch");

    let mut nested = base.clone();
    nested["evidence"][0]["raw"] = json!("value");
    assert_eq!(rejected(nested).code(), "schema_mismatch");

    let mut missing = base.clone();
    missing.as_object_mut().unwrap().remove("occurred_at");
    assert_eq!(rejected(missing).code(), "schema_mismatch");

    let error = ActionRecordV1::from_json(b"{not json").unwrap_err();
    assert_eq!(error.category(), ActionRecordErrorCategory::Malformed);

    let oversized = vec![b' '; ACTION_RECORD_MAX_INPUT_BYTES + 1];
    assert_eq!(
        ActionRecordV1::from_json(&oversized).unwrap_err().code(),
        "input_too_large"
    );
}

#[test]
fn consumer_rejects_values_the_producer_cannot_emit() {
    let base = serde_json::to_value(record()).unwrap();
    let cases: [(&str, Value, &str); 7] = [
        ("coordinate", json!("obs:v2:sha256:ABC"), "schema_mismatch"),
        (
            "replay_identity",
            json!("replay:v2:sha256:00"),
            "schema_mismatch",
        ),
        ("stage", json!("tool_ran"), "schema_mismatch"),
        ("promotion_score", json!(66), "promotion_score_mismatch"),
        ("stage", json!("message_observed"), "incompatible_stage"),
        ("tool_name", json!("Not A Tool"), "invalid_time_or_tool"),
        ("occurred_at", json!("yesterday"), "invalid_time_or_tool"),
    ];
    for (key, value, code) in cases {
        let mut changed = base.clone();
        changed[key] = value;
        assert_eq!(rejected(changed).code(), code, "{key}");
    }

    let mut context = base.clone();
    context["context"][0]["redacted_text"] = json!("x".repeat(MAX_REDACTED_TEXT_BYTES + 1));
    assert_eq!(rejected(context).code(), "schema_mismatch");

    let mut multibyte = base.clone();
    // 200 characters, 600 bytes: within the schema's character bound only.
    multibyte["context"][0]["redacted_text"] = json!("\u{2603}".repeat(200));
    assert_eq!(rejected(multibyte).code(), "context_too_large");
}

#[test]
fn consumer_rejects_summaries_its_findings_do_not_support() {
    let base = serde_json::to_value(record()).unwrap();
    let cases: [(&str, Value); 9] = [
        ("/severity", json!("critical")),
        ("/finding_kind", json!("atomic")),
        ("/rule_ids", json!(["network.download"])),
        ("/categories", json!(["network"])),
        (
            "/supporting_observation_ids",
            json!([digest("obs:v2:sha256:", 'a'), digest("obs:v2:sha256:", '9')]),
        ),
        ("/occurred_at", Value::Null),
        ("/contributions/1/points", json!(49)),
        ("/evidence/0/rule_id", json!("execution.shell")),
        (
            "/canonical_findings/1/finding_id",
            json!(digest("fnd:v2:sha256:", 'c')),
        ),
    ];
    for (pointer, value) in cases {
        let mut changed = base.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        if pointer == "/contributions/1/points" {
            changed["promotion_score"] = json!(64);
        }
        let error = rejected(changed);
        assert_eq!(error.code(), "inconsistent_findings", "{pointer}");
        assert_eq!(error.category(), ActionRecordErrorCategory::Semantic);
    }
}

#[test]
fn errors_carry_no_input_text() {
    let mut value = serde_json::to_value(record()).unwrap();
    value["tool_name"] = json!("PRIVATE-MARKER tool");
    let error = rejected(value);
    let rendered = format!("{error} {error:?}");
    assert!(!rendered.contains("PRIVATE-MARKER"), "{rendered}");
}

#[test]
fn published_schema_matches_the_embedded_copy() {
    // The repository mirror is absent from the published crate.
    let published = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../schemas/action-record-v1.schema.json");
    if published.is_file() {
        assert_eq!(
            std::fs::read_to_string(published).unwrap(),
            ACTION_RECORD_V1_SCHEMA
        );
    }
}

#[test]
fn v1_schema_is_frozen() {
    // A record version is frozen: a schema change is a new version and a new
    // type, never an edit of v1.
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(ACTION_RECORD_V1_SCHEMA.as_bytes());
    let hex = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(
        hex,
        "4124821e09bab03b17dc11404b6694bc36b496dcc54bb98af1116ed4afa0289b"
    );
}

#[test]
fn schema_vocabularies_match_the_rust_types() {
    let schema: Value = serde_json::from_str(ACTION_RECORD_V1_SCHEMA).unwrap();
    let names = |values: Vec<Value>| -> Vec<String> {
        values
            .into_iter()
            .map(|value| value.as_str().unwrap().to_owned())
            .collect()
    };
    let enumerated =
        |pointer: &str| names(schema.pointer(pointer).unwrap().as_array().unwrap().clone());

    let families = ObservationFamily::ALL
        .iter()
        .map(|family| serde_json::to_value(family).unwrap())
        .collect();
    assert_eq!(enumerated("/$defs/family/enum"), names(families));

    let stages = all_stages()
        .iter()
        .map(|stage| serde_json::to_value(stage).unwrap())
        .collect();
    assert_eq!(enumerated("/$defs/stage/enum"), names(stages));

    let contribution_types = [
        RiskContributionType::DeterministicRule,
        RiskContributionType::ChainModifier,
        RiskContributionType::BaselineDeviation,
    ]
    .iter()
    .map(|kind| serde_json::to_value(kind).unwrap())
    .collect();
    assert_eq!(
        enumerated("/$defs/contribution/properties/type/enum"),
        names(contribution_types)
    );
}

/// Every stage, in declaration order. The match fails to compile when a
/// stage is added, so the schema enum cannot silently drift.
fn all_stages() -> Vec<ObservationStage> {
    use ObservationStage::*;
    let all = vec![
        MessageObserved,
        InferenceRequested,
        InferenceStarted,
        InferenceCompleted,
        InferenceFailed,
        ToolProposed,
        ToolRequested,
        ToolExecutionStarted,
        ToolExecutionCompleted,
        ToolResultReturned,
        DefinitionChanged,
        McpInventoryChanged,
        ProcessObserved,
        FileObserved,
        NetworkObserved,
        BrowserObserved,
        RuntimeObserved,
        RuntimeChanged,
        SessionOpened,
        SessionUpdated,
        SessionClosed,
        OtherObserved,
    ];
    for stage in &all {
        match stage {
            MessageObserved
            | InferenceRequested
            | InferenceStarted
            | InferenceCompleted
            | InferenceFailed
            | ToolProposed
            | ToolRequested
            | ToolExecutionStarted
            | ToolExecutionCompleted
            | ToolResultReturned
            | DefinitionChanged
            | McpInventoryChanged
            | ProcessObserved
            | FileObserved
            | NetworkObserved
            | BrowserObserved
            | RuntimeObserved
            | RuntimeChanged
            | SessionOpened
            | SessionUpdated
            | SessionClosed
            | OtherObserved => {}
        }
    }
    all
}
