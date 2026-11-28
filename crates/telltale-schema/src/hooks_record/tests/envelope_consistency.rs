use super::*;

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
