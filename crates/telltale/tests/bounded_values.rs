//! A tool call with an over-bound value, through the public pipeline: the
//! value is replaced, the call's other facts are still evaluated, and the scan
//! reports the unit by coordinates only.
use telltale_core::{
    ClientId, DetailedEvaluationOptions, Pipeline, Source, SourceCoverage, SourceKind,
};

fn line(value: serde_json::Value) -> String {
    value.to_string() + "\n"
}

#[test]
fn a_call_with_a_replaced_value_is_evaluated_and_reported_by_coordinates() {
    let directory = tempfile::tempdir().unwrap();
    let pipeline = Pipeline::builder().build().unwrap();
    // A non-authored argument over the string bound next to a command the
    // bundled rules detect.
    let call = line(serde_json::json!({
        "sessionId": "synthetic-bounded",
        "type": "assistant",
        "uuid": "call-bounded",
        "timestamp": "2026-09-17T00:00:00Z",
        "message": {"role": "assistant", "content": [{
            "type": "tool_use", "id": "toolu_bounded", "name": "Bash",
            "input": {"command": "rm -rf /", "synthetic_note": "z".repeat(5_000)}
        }]}
    }));
    // A record type this adapter does not know is quarantined by itself.
    let unknown = line(serde_json::json!({
        "sessionId": "synthetic-bounded",
        "type": "synthetic-future-record",
        "uuid": "future-record",
    }));
    for (case, text, quarantined) in [
        ("bounded", call.clone(), 0),
        ("bounded-and-quarantined", call + &unknown, 1),
    ] {
        let path = directory.path().join(format!("{case}.jsonl"));
        std::fs::write(&path, text).unwrap();
        let source = Source {
            client: ClientId::Claude,
            kind: SourceKind::Jsonl,
            source_id: "claude.projects".into(),
            path,
        };
        let scans = pipeline
            .scan_sources_detailed(&[source], &DetailedEvaluationOptions::default())
            .unwrap();
        let scan = &scans[0];
        assert!(scan.failure().is_none(), "{case}");
        assert_eq!(scan.coverage(), Some(SourceCoverage::Partial), "{case}");
        assert_eq!(scan.quarantined().len(), quarantined, "{case}");
        let [unit] = scan.bounded_units() else {
            panic!("{case}: expected one bounded unit")
        };
        assert_eq!(unit.native_id, "call-bounded");
        assert_eq!(unit.session_id.as_deref(), Some("synthetic-bounded"));
        assert_eq!(unit.source_sequence, 0);
        assert_eq!(unit.target.as_str(), "arguments");
        assert_eq!(unit.dimension.as_str(), "string_bytes");
        assert!(!format!("{unit:?}").contains("zzzz"));
        // The command beside the replaced value is still evaluated.
        assert!(!scan.action_findings.is_empty(), "{case}");
    }
}
