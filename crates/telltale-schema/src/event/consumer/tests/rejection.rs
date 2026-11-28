use super::*;

#[test]
fn errors_are_classified_and_do_not_echo_input() {
    let canary = "TT_EVENT3_CONSUMER_SECRET_CANARY";
    let malformed =
        Event3Record::from_json(format!("{{{canary}").as_bytes()).expect_err("malformed");
    assert_eq!(malformed.category(), Event3ErrorCategory::Malformed);
    assert!(!malformed.to_string().contains(canary));
    assert!(!format!("{malformed:?}").contains(canary));

    let mut missing = serde_json::from_slice::<Value>(&health_bytes()).expect("health JSON");
    missing
        .as_object_mut()
        .expect("object")
        .remove("session_id");
    let error = Event3Record::from_json(&serde_json::to_vec(&missing).expect("JSON"))
        .expect_err("missing common field");
    assert_eq!(error.category(), Event3ErrorCategory::Structure);

    let mut invalid_id = serde_json::from_slice::<Value>(&health_bytes()).expect("health JSON");
    invalid_id["event_id"] = Value::String(canary.to_string());
    let error = Event3Record::from_json(&serde_json::to_vec(&invalid_id).expect("JSON"))
        .expect_err("invalid identity");
    assert_eq!(error.category(), Event3ErrorCategory::Identity);
    assert!(!error.to_string().contains(canary));
}

#[test]
fn event_id_must_be_a_lowercase_prefixed_uuid_v4() {
    for event_id in [
        "00000000-0000-4000-8000-000000000000",
        "event-00000000-0000-4000-8000-000000000000",
        "telltale-0000000A-0000-4000-8000-000000000000",
        "telltale-00000000-0000-1000-8000-000000000000",
        "telltale-00000000-0000-4000-c000-000000000000",
        "telltale-00000000-0000-4000-8000-00000000000",
        "telltale-00000000000040008000000000000000",
    ] {
        let mut value = serde_json::from_slice::<Value>(&health_bytes()).expect("health JSON");
        value["event_id"] = Value::String(event_id.to_string());
        let error = Event3Record::from_json(&serde_json::to_vec(&value).expect("JSON"))
            .expect_err(event_id);
        assert_eq!(
            (error.category(), error.code()),
            (Event3ErrorCategory::Identity, "invalid_identity_or_time"),
            "{event_id}"
        );
    }
}

#[test]
fn oversized_input_is_rejected_before_json_parsing() {
    let canary = "TT_EVENT3_OVERSIZED_INPUT_CANARY";
    let mut oversized = vec![b' '; EVENT3_MAX_INPUT_BYTES + 1];
    oversized.extend_from_slice(canary.as_bytes());
    let error = Event3Record::from_json(&oversized).expect_err("oversized input");
    assert_eq!(error.category(), Event3ErrorCategory::Structure);
    assert_eq!(error.code(), "input_too_large");
    assert!(!error.to_string().contains(canary));
    assert!(!format!("{error:?}").contains(canary));
}

#[test]
fn unknown_property_is_rejected_before_projection() {
    let mut value = serde_json::from_slice::<Value>(&health_bytes()).expect("health JSON");
    value["unexpected"] = Value::String("synthetic".to_string());
    let error = Event3Record::from_json(&serde_json::to_vec(&value).expect("JSON"))
        .expect_err("unknown property");
    assert_eq!(error.category(), Event3ErrorCategory::Structure);

    let mut nested = serde_json::from_slice::<Value>(&health_bytes()).expect("health JSON");
    nested["evidence"][0]["unexpected"] = Value::String("synthetic".to_string());
    let error = Event3Record::from_json(&serde_json::to_vec(&nested).expect("JSON"))
        .expect_err("nested unknown property");
    assert_eq!(error.category(), Event3ErrorCategory::Structure);
}

#[test]
fn adversarial_version_taxonomy_family_anchor_and_semantic_failures_are_classified() {
    let non_object = Event3Record::from_json(b"[]").expect_err("non-object");
    assert_eq!(non_object.category(), Event3ErrorCategory::Structure);

    let mut version = serde_json::from_slice::<Value>(&health_bytes()).expect("health JSON");
    version["schema_version"] = Value::String("4.0".to_string());
    let error = Event3Record::from_json(&serde_json::to_vec(&version).expect("JSON"))
        .expect_err("version failure");
    assert_eq!(error.category(), Event3ErrorCategory::Version);

    let mut taxonomy = serde_json::from_slice::<Value>(&health_bytes()).expect("health JSON");
    taxonomy["time_source"] = Value::String("synthetic-taxonomy".to_string());
    let error = Event3Record::from_json(&serde_json::to_vec(&taxonomy).expect("JSON"))
        .expect_err("taxonomy failure");
    assert_eq!(error.category(), Event3ErrorCategory::Semantic);

    let mut family = serde_json::from_slice::<Value>(&health_bytes()).expect("health JSON");
    family["event_type"] = Value::String("detection".to_string());
    let error = Event3Record::from_json(&serde_json::to_vec(&family).expect("JSON"))
        .expect_err("family failure");
    assert_eq!(error.category(), Event3ErrorCategory::Family);

    let mut missing_family_field =
        serde_json::from_slice::<Value>(&health_bytes()).expect("health JSON");
    missing_family_field
        .as_object_mut()
        .expect("object")
        .remove("component");
    let error = Event3Record::from_json(&serde_json::to_vec(&missing_family_field).expect("JSON"))
        .expect_err("missing family field");
    assert_eq!(error.category(), Event3ErrorCategory::Family);

    let mut detection = serde_json::to_value(
        &positive_constructor_corpus()
            .into_iter()
            .find(|(name, _)| *name == "detection")
            .expect("detection corpus")
            .1,
    )
    .expect("detection JSON");
    detection["risk_score"] = Value::Number(99.into());
    let error = Event3Record::from_json(&serde_json::to_vec(&detection).expect("JSON"))
        .expect_err("semantic risk failure");
    assert_eq!(error.category(), Event3ErrorCategory::Semantic);

    let mut process = serde_json::to_value(
        &positive_constructor_corpus()
            .into_iter()
            .find(|(name, _)| *name == "process_chain")
            .expect("process-chain corpus")
            .1,
    )
    .expect("process-chain JSON");
    process["risk_contributions"][0]["type"] = Value::String("baseline_deviation".to_string());
    let error = Event3Record::from_json(&serde_json::to_vec(&process).expect("JSON"))
        .expect_err("process-chain risk scope failure");
    assert_eq!(error.category(), Event3ErrorCategory::Semantic);

    let anchors = detection["timeline_anchors"]
        .as_array_mut()
        .expect("anchors");
    anchors.push(serde_json::json!({
        "entry_index": 0,
        "rule_ids": ["rule.consumer.chain"],
        "categories": ["network"],
        "evidence_fields": ["command"]
    }));
    detection["risk_score"] = Value::Number(5.into());
    let error = Event3Record::from_json(&serde_json::to_vec(&detection).expect("JSON"))
        .expect_err("anchor failure");
    assert_eq!(error.category(), Event3ErrorCategory::Semantic);
}

#[test]
fn rejects_inconsistent_timing_relationships() {
    let mut source_without_event_time =
        serde_json::from_slice::<Value>(&health_bytes()).expect("health JSON");
    source_without_event_time["time_source"] = Value::String("source".to_string());
    let error =
        Event3Record::from_json(&serde_json::to_vec(&source_without_event_time).expect("JSON"))
            .expect_err("source timing must retain event time");
    assert_eq!(error.category(), Event3ErrorCategory::Semantic);
    assert_eq!(error.code(), "invalid_time_relationship");

    let mut unrelated_observed_timestamp =
        serde_json::from_slice::<Value>(&health_bytes()).expect("health JSON");
    unrelated_observed_timestamp["timestamp"] =
        Value::String("2026-05-01T00:00:00.000Z".to_string());
    let error =
        Event3Record::from_json(&serde_json::to_vec(&unrelated_observed_timestamp).expect("JSON"))
            .expect_err("observed timing must use observation time");
    assert_eq!(error.category(), Event3ErrorCategory::Semantic);
    assert_eq!(error.code(), "invalid_time_relationship");
}
