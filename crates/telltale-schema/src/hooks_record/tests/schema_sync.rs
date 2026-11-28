use super::*;

#[test]
fn published_schema_matches_the_embedded_copy() {
    let published = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../schemas/telltale-hooks-record-v1.schema.json");
    if published.is_file() {
        assert_eq!(
            std::fs::read_to_string(published).unwrap(),
            HOOKS_RECORD_V1_SCHEMA
        );
    }
}

#[test]
fn schema_vocabularies_match_the_rust_types() {
    let schema: Value = serde_json::from_str(HOOKS_RECORD_V1_SCHEMA).unwrap();
    fn check<T: Serialize>(schema: &Value, pointer: &str, variants: &[T]) {
        let wire = serde_json::to_value(variants).unwrap();
        let declared: Vec<_> = schema
            .pointer(pointer)
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .filter(|value| !value.is_null())
            .cloned()
            .collect();
        assert_eq!(wire, json!(declared), "{pointer}");
    }
    let enums = [
        ("/properties/kind/enum", json!(HooksRecordKind::ALL)),
        (
            "/properties/evaluation/properties/status/enum",
            json!(HooksEvaluationStatus::ALL),
        ),
        (
            "/properties/evaluation/properties/coverage/enum",
            json!(HooksCoverage::ALL),
        ),
        (
            "/properties/evaluation/properties/evaluator/enum",
            json!(HooksEvaluator::ALL),
        ),
        (
            "/properties/evaluation/properties/scans/properties/whole/enum",
            json!(HooksScanResult::ALL),
        ),
        (
            "/properties/evaluation/properties/scans/properties/together/enum",
            json!(HooksScanResult::ALL),
        ),
        (
            "/properties/evaluation/properties/scans/properties/history/enum",
            json!(HooksHistoryScanResult::ALL),
        ),
        (
            "/properties/decision/properties/mode/enum",
            json!(HooksMode::ALL),
        ),
        (
            "/properties/decision/properties/verdict/enum",
            json!(HooksVerdict::ALL),
        ),
        (
            "/properties/decision/properties/returned_verdict/enum",
            json!(HooksReturnedVerdict::ALL),
        ),
        (
            "/properties/decision/properties/basis/enum",
            json!(HooksDecisionBasis::ALL),
        ),
        (
            "/properties/decision/properties/grant/properties/scope/enum",
            json!(HooksGrantScope::ALL),
        ),
        (
            "/properties/outcome/properties/result/enum",
            json!(HooksOutcomeResult::ALL),
        ),
        (
            "/properties/outcome/properties/prior_verdict/enum",
            json!(HooksVerdict::ALL),
        ),
        (
            "/properties/outcome/properties/prior_returned_verdict/enum",
            json!(HooksReturnedVerdict::ALL),
        ),
        (
            "/properties/outcome/properties/enforcement/enum",
            json!(HooksEnforcement::ALL),
        ),
        (
            "/properties/lifecycle/oneOf/6/properties/cause/enum",
            json!(HooksGrantRefusal::ALL),
        ),
    ];
    for (pointer, variants) in enums {
        check(&schema, pointer, variants.as_array().unwrap());
    }

    let mut lifecycle_events = BTreeSet::new();
    for branch in schema["properties"]["lifecycle"]["oneOf"]
        .as_array()
        .unwrap()
    {
        let event = &branch["properties"]["event"];
        lifecycle_events.extend(event["const"].as_str());
        lifecycle_events.extend(
            event["enum"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str),
        );
    }
    let examples = [
        json!({"event": "session_start", "source": null}),
        json!({"event": "session_end", "reason": null, "cumulative_score": 0, "scored_actions": 0,
            "denied_attempts": 0, "asked_attempts": 0, "subagents": 0, "unsettled_calls": 0}),
        json!({"event": "subagent_start", "agent_id": "synthetic-agent", "agent_type": null}),
        json!({"event": "subagent_stop", "agent_id": "synthetic-agent", "agent_type": null}),
        json!({"event": "permission_prompt"}),
        json!({"event": "user_prompt", "prompt_sha256": "a".repeat(64), "prompt_bytes": 0}),
        json!({"event": "grant", "scope": "session", "tool": "Bash", "rule_ids": ["synthetic.rule"],
            "offer_record_id": format!("tth:{}", "a".repeat(32))}),
        json!({"event": "grant_refused", "cause": "no_offer"}),
        json!({"event": "grant_revoked", "grant_id": "g-000000000001"}),
        json!({"event": "other"}),
    ];
    let rust_events = examples
        .iter()
        .map(|shape| {
            let kind: HooksLifecycle = serde_json::from_value(shape.clone()).unwrap();
            assert_eq!(*shape, serde_json::to_value(kind).unwrap());
            shape["event"].as_str().unwrap()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(rust_events, lifecycle_events);
}
