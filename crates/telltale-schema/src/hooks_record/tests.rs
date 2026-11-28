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

/// Every array of the envelope and where its bound sits in the schema.
const BOUNDED_ARRAYS: &[&str] = &[
    "/properties/evaluation/properties/visibility_limits",
    "/properties/decision/properties/rule_ids",
    "/properties/decision/properties/categories",
    "/properties/lifecycle/oneOf/0/properties/pinned_over",
    "/properties/lifecycle/oneOf/5/properties/rule_ids",
    "/properties/telltale",
];

/// A record with the array at `pointer` holding `items`, valid apart from
/// that array's own consistency.
fn with_array(pointer: &str, items: Vec<Value>) -> Value {
    let base = record();
    let mut value = match pointer {
        "/lifecycle/pinned_over" => with_kind(
            &base,
            "lifecycle",
            "lifecycle",
            json!({"event": "session_start", "source": null}),
        ),
        "/lifecycle/rule_ids" => with_kind(
            &base,
            "lifecycle",
            "lifecycle",
            json!({"event": "grant", "scope": "session", "tool": "Bash", "rule_ids": [],
                "offer_record_id": format!("tth:{}", "a".repeat(32))}),
        ),
        _ => base,
    };
    let (parent, name) = pointer.rsplit_once('/').unwrap();
    value.pointer_mut(parent).unwrap()[name] = Value::Array(items);
    value
}

mod array_bounds;
mod envelope_consistency;
mod redaction;
mod schema_sync;
mod wire_format;
