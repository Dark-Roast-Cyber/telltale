use super::*;

#[test]
fn every_open_text_field_is_checked_for_redaction() {
    let mut decision = record();
    decision["evaluation"]["scans"]["pieces_scanned"] = json!(1);
    decision["evaluation"]["scans"]["pieces_refused"] = json!(1);
    decision["evaluation"]["scans"]["pieces_total"] = json!(1);
    decision["evaluation"]["visibility_limits"] = json!(["synthetic_limit"]);
    for field in [
        "/producer/version",
        "/harness/name",
        "/harness/hook_event",
        "/harness/permission_mode",
        "/session/session_id",
        "/session/agent_id",
        "/session/agent_type",
        "/session/prompt_id",
        "/action/tool_use_id",
        "/action/tool_name",
        "/evaluation/visibility_limits/0",
        "/evaluation/failure_code",
        "/evaluation/evaluator_fallback",
        "/evaluation/scans/first_refusal",
    ] {
        assert_unredacted(&decision, &[field]);
    }
    let error = with_kind(&decision, "error", "error_code", json!("synthetic_error"));
    assert_unredacted(&error, &["/error_code"]);

    let mut outcome = with_kind(
        &decision,
        "outcome",
        "outcome",
        json!({
            "result": "completed", "established_by": "PreToolUse", "decision_record_id": null,
            "prior_verdict": null, "prior_returned": null, "enforcement": "no_decision",
            "duration_ms": null, "supersedes": null
        }),
    );
    outcome["action"] = decision["action"].clone();
    outcome["action"]["input_sha256"] = Value::Null;
    assert_unredacted(
        &outcome,
        &["/outcome/established_by", "/harness/hook_event"],
    );

    for (details, field) in [
        (
            json!({"event": "session_start", "source": "startup"}),
            "/lifecycle/source",
        ),
        (
            json!({"event": "session_start", "source": null, "pinned_over": ["HOME"]}),
            "/lifecycle/pinned_over/0",
        ),
        (
            json!({"event": "session_end", "reason": "exit", "cumulative_score": 0, "scored_actions": 0,
            "denied_attempts": 0, "asked_attempts": 0, "subagents": 0, "unsettled_calls": 0}),
            "/lifecycle/reason",
        ),
        (
            json!({"event": "subagent_start", "agent_id": "synthetic-agent", "agent_type": "general-purpose"}),
            "/lifecycle/agent_id",
        ),
        (
            json!({"event": "subagent_stop", "agent_id": "synthetic-agent", "agent_type": "general-purpose"}),
            "/lifecycle/agent_type",
        ),
        (
            json!({"event": "grant", "scope": "session", "tool": "Bash", "rule_ids": ["exfil.outbound_upload"],
            "offer_record_id": format!("tth:{}", "b".repeat(32))}),
            "/lifecycle/tool",
        ),
    ] {
        assert_unredacted(
            &with_kind(&decision, "lifecycle", "lifecycle", details),
            &[field],
        );
    }

    let mut rationale = decision;
    rationale["telltale"][0]["record"]["contributions"][0]["rationale"] =
        json!("AKIAPRIVATEMARKER234");
    check_rejection(&bytes(&rationale), "invalid_action_record", Semantic);
}

#[test]
fn native_labels_require_readability_in_bytes_or_an_exact_stand_in() {
    let base = record();
    for invalid in [
        " Bash".to_owned(),
        "synthetic\u{0007}tool".to_owned(),
        "é".repeat(129),
        format!("tth-esc-{}", "1".repeat(33)),
    ] {
        let mut changed = base.clone();
        changed["action"]["tool_name"] = json!(invalid);
        check_rejection(&bytes(&changed), "unredacted_text", Semantic);
    }
    let mut changed = base;
    changed["action"]["tool_name"] = json!(format!("tth-esc-{}", "1".repeat(32)));
    assert!(HooksRecordV1::from_json(&bytes(&changed)).is_ok());
}
