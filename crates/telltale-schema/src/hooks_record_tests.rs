use super::*;
use serde_json::json;

const MARKER: &str = "synthetic-private-marker";

fn record() -> Value {
    record_for("exfil.outbound_upload")
}

/// The decision of [`record`], covered by a session grant.
fn granted(rule: &str) -> Value {
    let mut value = record_for(rule);
    let decision = value["decision"].as_object_mut().unwrap();
    decision.remove("returned_verdict");
    decision.insert("returned".into(), json!(false));
    decision.insert("session_score_after".into(), json!(3));
    decision.insert(
        "grant".into(),
        json!({"scope": "session", "granted_by": format!("tth:{}", "3".repeat(32))}),
    );
    value
}

fn record_for(rule: &str) -> Value {
    let upload = rule == "exfil.outbound_upload";
    let observation = format!("obs:v2:sha256:{}", "a".repeat(64));
    let semantic = format!("semantic:v1:sha256:{}", "b".repeat(64));
    let action = json!({
        "schema": "telltale.action.v1",
        "telltale_version": "0.8.0",
        "semantic_identity": semantic,
        "client": "claude",
        "source_id": "claude.hooks",
        "source_path_hash": "d".repeat(64),
        "session_id": "synthetic-session",
        "session_event_id": null,
        "coordinate": observation,
        "replay_identity": null,
        "detector_kind": "rule_v1_action",
        "finding_kind": "atomic",
        "observation_family": "tool",
        "stage": "tool_requested",
        "tool_name": "Bash",
        "occurred_at": "2026-11-26T12:00:00Z",
        "timeline_index": 1,
        "severity": "medium",
        "promotion_score": 10,
        "rule_ids": [rule],
        "categories": ["exfiltration"],
        "contributions": [
            {"id": rule, "type": "deterministic_rule", "points": 10,
             "rationale": "synthetic upload"}
        ],
        "evidence": [],
        "supporting_observation_ids": [observation],
        "canonical_findings": [{
            "finding_id": format!("fnd:v2:sha256:{}", "c".repeat(64)),
            "signal_ids": [format!("sig:v2:sha256:{}", "e".repeat(64))],
            "observation_ids": [observation],
            "detector_id": rule,
            "finding_kind": "security_detection",
            "category": "exfiltration",
            "severity": "medium",
            "risk_points": 10
        }],
        "context": []
    });
    let key = ActionRecordV1::from_json(&bytes(&action))
        .unwrap()
        .delivery_key();
    let mut entry = json!({"delivery_key": key, "record": action});
    if upload {
        entry["destinations"] =
            json!({"destinations": ["example.invalid"], "complete": true, "local_only": false});
    }
    json!({
        "schema": HOOKS_RECORD_V1_ID,
        "record_id": format!("tth:{}", "1".repeat(32)),
        "recorded_at": "2026-11-26T12:00:01Z",
        "kind": "decision",
        "producer": {"name": "telltale-hooks", "version": "0.8.0",
            "telltale_rev": "2".repeat(40), "semantic_identity": semantic},
        "harness": {"name": "claude-code", "hook_event": "PreToolUse", "permission_mode": "default"},
        "session": {"session_id": "synthetic-session", "agent_id": "synthetic-agent",
            "agent_type": "general-purpose", "prompt_id": "synthetic-prompt", "cwd_sha256": "f".repeat(64)},
        "action": {"tool_use_id": "synthetic-call", "tool_name": "Bash", "input_sha256": "d".repeat(64)},
        "evaluation": {"status": "complete", "coverage": "whole_source",
            "visibility_limits": [], "failure_code": null, "window_records": 1, "window_truncated": false,
            "build_ms": 2, "scan_ms": 1, "lock_wait_ms": null, "evaluator": "in_process",
            "evaluator_fallback": null,
            "scans": { "variants": 0, "whole": "passed", "together": null, "history": null,
                "pieces_scanned": 0, "pieces_total": 0, "pieces_refused": 0, "first_refusal": null,
                "whole_ms": 1, "together_ms": 0, "pieces_ms": 0, "history_ms": 0 }
        },
        "decision": {"mode": "enforce", "verdict": "ask", "returned": true, "returned_verdict": "deny",
            "basis": "action_score", "action_score": 10, "session_score_before": 3,
            "session_score_after": 13, "denied_attempts_before": 0,
            "rule_ids": [rule], "categories": ["exfiltration"]},
        "telltale": [entry]
    })
}

fn bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

fn check_rejection(bytes: &[u8], code: &str, category: HooksRecordErrorCategory) {
    let Err(error) = HooksRecordV1::from_json(bytes) else {
        panic!("expected consumer rejection");
    };
    assert_eq!(error.code(), code);
    assert_eq!(error.category(), category);
    assert_eq!(error.to_string(), format!("hooks record error: {code}"));
    assert_eq!(
        format!("{error:?}"),
        format!("HooksRecordError {{ category: {category:?}, code: {code:?} }}")
    );
    assert!(std::error::Error::source(&error).is_none());
}

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

#[test]
fn rejects_inconsistent_envelope_and_invalid_actions() {
    let base = record();
    for (field, value, code, category) in [
        ("/kind", json!("lifecycle"), "inconsistent_kind", Semantic),
        (
            "/telltale/0/record/promotion_score",
            json!(11),
            "invalid_action_record",
            Semantic,
        ),
        (
            "/telltale/0/delivery_key",
            json!(MARKER),
            "delivery_key_mismatch",
            Identity,
        ),
        (
            "/telltale/0/record/source_id",
            json!("claude.projects"),
            "action_source_mismatch",
            Identity,
        ),
        (
            "/telltale/0/destinations/local_only",
            json!(true),
            "invalid_destinations",
            Semantic,
        ),
        (
            "/telltale/0/destinations/destinations/0",
            json!("example.invalid/akiaiosfodnn7example"),
            "invalid_destinations",
            Semantic,
        ),
        (
            "/evaluation/scans/pieces_scanned",
            json!(1),
            "inconsistent_evaluation",
            Semantic,
        ),
        (
            "/decision/session_score_after",
            json!(14),
            "score_mismatch",
            Semantic,
        ),
        (
            "/decision/session_score_after",
            json!(3),
            "score_mismatch",
            Semantic,
        ),
        (
            "/decision/returned",
            json!(false),
            "inconsistent_verdict",
            Semantic,
        ),
        (
            "/decision/rule_ids",
            json!(["synthetic.other"]),
            "finding_summary_mismatch",
            Semantic,
        ),
    ] {
        let mut changed = base.clone();
        *changed.pointer_mut(field).unwrap() = value;
        check_rejection(&bytes(&changed), code, category);
    }

    let mut grant = base.clone();
    grant["decision"]["returned"] = json!(false);
    grant["decision"]
        .as_object_mut()
        .unwrap()
        .remove("returned_verdict");
    grant["decision"]["session_score_after"] = json!(3);
    grant["decision"]["grant"] = json!({"scope": "session", "granted_by": MARKER});
    check_rejection(&bytes(&grant), "inconsistent_grant", Semantic);

    let mut typed = HooksRecordV1::from_json(&bytes(&base)).unwrap();
    typed.decision.as_mut().unwrap().session_score_after = 14;
    assert_eq!(typed.validate().unwrap_err().code(), "score_mismatch");
}

#[test]
fn a_grant_never_covers_a_host_self_protection_rule() {
    HooksRecordV1::from_json(&bytes(&granted("exfil.outbound_upload"))).unwrap();
    // The same record is consistent in every other respect, so the rule ID
    // alone decides.
    let mut ungranted = granted("tth.tamper.synthetic");
    let decision = ungranted["decision"].as_object_mut().unwrap();
    decision.remove("grant");
    decision.insert("returned".into(), json!(true));
    decision.insert("returned_verdict".into(), json!("deny"));
    decision.insert("session_score_after".into(), json!(13));
    HooksRecordV1::from_json(&bytes(&ungranted)).unwrap();
    check_rejection(
        &bytes(&granted("tth.tamper.synthetic")),
        "inconsistent_grant",
        Semantic,
    );
}

fn with_kind(value: &Value, kind: &str, block: &str, data: Value) -> Value {
    let mut changed = value.clone();
    let fields = changed.as_object_mut().unwrap();
    fields.remove("action");
    fields.remove("evaluation");
    fields.remove("decision");
    changed["kind"] = json!(kind);
    changed["telltale"] = json!([]);
    changed[block] = data;
    changed
}

#[test]
fn outcome_accounting_uses_the_returned_verdict() {
    let base = record();
    let mut outcome = with_kind(
        &base,
        "outcome",
        "outcome",
        json!({
            "result": "not_executed", "established_by": "PreToolUse", "decision_record_id": base["record_id"],
            "prior_verdict": "ask", "prior_returned": true, "prior_returned_verdict": "deny",
            "enforcement": "honored", "duration_ms": null, "supersedes": null
        }),
    );
    outcome["action"] = base["action"].clone();
    outcome["action"]["input_sha256"] = Value::Null;
    HooksRecordV1::from_json(&bytes(&outcome)).unwrap();
    outcome["outcome"]["enforcement"] = json!("declined");
    check_rejection(&bytes(&outcome), "inconsistent_outcome", Semantic);
}

#[test]
fn non_upload_action_cannot_carry_destinations() {
    let mut changed = record();
    let action = &mut changed["telltale"][0]["record"];
    action["rule_ids"][0] = json!("synthetic.other");
    action["contributions"][0]["id"] = json!("synthetic.other");
    action["canonical_findings"][0]["detector_id"] = json!("synthetic.other");
    changed["decision"]["rule_ids"][0] = json!("synthetic.other");
    check_rejection(&bytes(&changed), "invalid_destinations", Semantic);
}

#[test]
fn local_only_requires_complete_and_no_listed_destination() {
    let mut local = record();
    local["telltale"][0]["destinations"] = json!({
        "destinations": [], "complete": true, "local_only": true
    });
    HooksRecordV1::from_json(&bytes(&local)).unwrap();

    let mut incomplete = local.clone();
    incomplete["telltale"][0]["destinations"]["complete"] = json!(false);
    check_rejection(&bytes(&incomplete), "invalid_destinations", Semantic);
    local["telltale"][0]["destinations"]["destinations"] = json!(["example.invalid"]);
    check_rejection(&bytes(&local), "invalid_destinations", Semantic);
    // The same code applies even when the wire validator also rejects the entry.
    local["telltale"][0]["destinations"]["unexpected"] = json!(true);
    check_rejection(&bytes(&local), "invalid_destinations", Semantic);
}

#[test]
fn lifecycle_rejects_unknown_content_and_enforces_grant_scope() {
    let mut lifecycle = with_kind(
        &record(),
        "lifecycle",
        "lifecycle",
        json!({
            "event": "grant", "scope": "session", "tool": "Bash", "rule_ids": ["exfil.outbound_upload"],
            "offer_record_id": format!("tth:{}", "a".repeat(32))
        }),
    );
    HooksRecordV1::from_json(&bytes(&lifecycle)).unwrap();
    lifecycle["lifecycle"]["scope"] = json!("project");
    check_rejection(&bytes(&lifecycle), "inconsistent_lifecycle", Semantic);
    lifecycle["lifecycle"]["raw_payload"] = json!(MARKER);
    check_rejection(&bytes(&lifecycle), "schema_mismatch", Structure);
}

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

fn assert_unredacted(base: &Value, fields: &[&str]) {
    HooksRecordV1::from_json(&bytes(base)).unwrap();
    for text in ["AKIAPRIVATEMARKER234", "/home/synthetic/private.txt"] {
        let mut changed = base.clone();
        for field in fields {
            *changed.pointer_mut(field).unwrap() = json!(text);
        }
        let wire = bytes(&changed);
        assert_eq!(
            HooksRecordV1::from_json(&wire)
                .err()
                .map(HooksRecordError::code),
            Some("unredacted_text"),
            "{fields:?}"
        );
        check_rejection(&wire, "unredacted_text", Semantic);
    }
}

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
