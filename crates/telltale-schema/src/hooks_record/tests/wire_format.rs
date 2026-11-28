use super::*;

#[test]
fn old_missing_fields_and_current_nulls_round_trip_as_written() {
    let current = record();
    let mut older = current.clone();
    older["evaluation"]
        .as_object_mut()
        .unwrap()
        .remove("lock_wait_ms");
    older["evaluation"]["scans"]
        .as_object_mut()
        .unwrap()
        .remove("history");
    for wire in [current, older] {
        let parsed = HooksRecordV1::from_json(&bytes(&wire)).unwrap();
        parsed.validate().unwrap();
        assert_eq!(serde_json::to_value(parsed).unwrap(), wire);
    }
}

#[test]
fn older_claude_format_hook_windows_remain_readable() {
    let mut older = record();
    older["producer"]["version"] = json!("0.7.2");
    older["telltale"][0]["record"]["telltale_version"] = json!("0.7.2");
    older["telltale"][0]["record"]["source_id"] = json!("claude.projects");
    older["telltale"][0]
        .as_object_mut()
        .unwrap()
        .remove("destinations");
    let parsed = HooksRecordV1::from_json(&bytes(&older)).unwrap();
    assert_eq!(serde_json::to_value(parsed).unwrap(), older);
}

#[test]
fn wire_errors_carry_only_closed_codes() {
    let valid = record();
    let mut wire = bytes(&valid);
    wire.extend_from_slice(MARKER.as_bytes());
    check_rejection(&wire, "malformed_json", Malformed);
    wire.resize(HOOKS_RECORD_MAX_INPUT_BYTES + 1, b' ');
    check_rejection(&wire, "input_too_large", Structure);

    let mut wrong_version = valid.clone();
    wrong_version["schema"] = json!(MARKER);
    check_rejection(
        &bytes(&wrong_version),
        "unsupported_record_version",
        Version,
    );

    let mut unknown = valid.clone();
    unknown["action"]["extra"] = json!(MARKER);
    let mut missing = valid.clone();
    missing["evaluation"]
        .as_object_mut()
        .unwrap()
        .remove("scan_ms");
    let mut wrong_type = valid.clone();
    wrong_type["decision"]["returned"] = json!(MARKER);
    let mut bad_enum = valid.clone();
    bad_enum["decision"]["verdict"] = json!(MARKER);
    let mut bad_time = valid.clone();
    bad_time["recorded_at"] = json!(MARKER);
    for case in [unknown, missing, wrong_type, bad_enum, bad_time] {
        check_rejection(&bytes(&case), "schema_mismatch", Structure);
    }
    let duplicate = format!(r#"{{"kind":"{MARKER}",{}"#, &valid.to_string()[1..]);
    check_rejection(duplicate.as_bytes(), "schema_mismatch", Structure);
}

#[test]
fn jsonl_budget_includes_the_line_feed_and_precedes_parsing() {
    let mut wire = bytes(&record());
    wire.resize(16 * 1024 * 1024 - 1, b' ');
    wire.push(b'\n');
    assert_eq!(HOOKS_RECORD_MAX_INPUT_BYTES, wire.len());
    assert!(HooksRecordV1::from_json(&wire).is_ok());

    *wire.last_mut().unwrap() = b' ';
    check_rejection(&wire, "input_too_large", Structure);
    wire.push(b'!');
    check_rejection(&wire, "input_too_large", Structure);
}

#[test]
fn size_error_can_preserve_an_outcomes_action_without_an_input_digest() {
    let mut error = with_kind(
        &record(),
        "error",
        "error_code",
        json!("telemetry_record_too_large"),
    );
    error["action"] = json!({
        "tool_use_id": "synthetic-call", "tool_name": "Bash", "input_sha256": null
    });
    let parsed = HooksRecordV1::from_json(&bytes(&error)).unwrap();
    assert_eq!(serde_json::to_value(parsed).unwrap(), error);
}

#[test]
fn maximal_bounded_labels_destinations_and_scan_trace_round_trip() {
    let mut decision = record();
    let label = "\"".repeat(256);
    assert_eq!(serde_json::to_vec(&label).unwrap().len(), 514);
    for pointer in [
        "/harness/hook_event",
        "/harness/permission_mode",
        "/session/session_id",
        "/session/agent_id",
        "/session/agent_type",
        "/session/prompt_id",
        "/action/tool_name",
        "/action/tool_use_id",
    ] {
        *decision.pointer_mut(pointer).unwrap() = json!(label);
    }
    // Exercise the full vocabulary, including limits from different paths.
    decision["evaluation"]["visibility_limits"] = json!([
        "unverified_source_instance",
        "missing_session_identity",
        "detector_not_evaluated",
        "process_capability_unavailable",
        "history_lost",
        "pending_pieces_unscanned",
        "pending_input_projected",
        "pending_input_truncated",
        "pending_input_separated",
        "input_keys_rewritten",
        "tool_name_malformed",
        "state_dir_unresolved",
        "result_history_truncated"
    ]);
    decision["evaluation"]["scans"] = json!({
        "variants": 128, "whole": "skipped_pieces_only", "together": "skipped_pieces_only",
        "history": "passed", "pieces_scanned": 128, "pieces_total": 128, "pieces_refused": 128,
        "first_refusal": "synthetic_refusal", "whole_ms": u64::MAX, "together_ms": u64::MAX,
        "pieces_ms": u64::MAX, "history_ms": u64::MAX
    });
    let destinations = (0..16)
        .map(|index| {
            let prefix = format!("s3://synthetic-{index:02}.invalid/");
            format!("{prefix}{}", "-".repeat(256 - prefix.len()))
        })
        .collect::<Vec<_>>();
    decision["telltale"][0]["destinations"]["destinations"] = json!(destinations);
    let parsed = HooksRecordV1::from_json(&bytes(&decision)).unwrap();
    assert_eq!(serde_json::to_value(parsed).unwrap(), decision);

    // Outcome's copy of the hook event is the ninth label. The wire contract
    // does not allow an outcome to carry destinations or a scan trace.
    let mut outcome = with_kind(
        &decision,
        "outcome",
        "outcome",
        json!({
            "result": "completed", "established_by": label, "decision_record_id": null,
            "prior_verdict": null, "prior_returned": null, "enforcement": "no_decision",
            "duration_ms": u64::MAX, "supersedes": null
        }),
    );
    outcome["action"] = decision["action"].clone();
    outcome["action"]["input_sha256"] = Value::Null;
    let parsed = HooksRecordV1::from_json(&bytes(&outcome)).unwrap();
    assert_eq!(serde_json::to_value(parsed).unwrap(), outcome);
}
