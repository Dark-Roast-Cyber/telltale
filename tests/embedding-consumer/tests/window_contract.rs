#![cfg(feature = "opencode-sqlite")]

use serde_json::Value;
use telltale_core::*;

fn projection(event: &Event) -> Value {
    let mut wire = serde_json::to_value(event).unwrap();
    Event3Record::from_json(&serde_json::to_vec(&wire).unwrap()).unwrap();
    for field in ["event_id", "observed_at", "ingested_at"] {
        wire.as_object_mut().unwrap().remove(field);
    }
    if event.event_time.is_none() {
        wire.as_object_mut().unwrap().remove("timestamp");
    }
    wire
}

#[test]
fn stateless_opencode_repeats_keep_events_and_action_replay_semantics() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("synthetic.db");
    // The checked-in synthetic fixture exercises the native message fallback.
    // No embedding cursor or lower-bound option is used or implied here.
    let bytes = include_bytes!("../../fixtures/session_stores/opencode/opencode.db");
    std::fs::write(&path, bytes).unwrap();
    let source = Source {
        client: ClientId::OpenCode,
        kind: SourceKind::Sqlite,
        source_id: "opencode.sqlite".into(),
        path,
    };
    let pipeline = Pipeline::builder()
        .without_bundled_defaults()
        .rules_document(
            r#"
version: 1
description: Synthetic fallback repeat coverage.
defaults: { case_insensitive: false, enabled: true }
modifiers: []
rules:
  - id: synthetic.window.result
    title: Synthetic result
    tags: [synthetic]
    category: synthetic
    severity: high
    score: 70
    detection:
      selection:
        tool_result: 'Hidden instruction'
      condition: selection
    explanation: Synthetic test.
"#,
        )
        .build()
        .unwrap();
    let scan = || {
        pipeline
            .scan_sources_detailed(
                std::slice::from_ref(&source),
                &DetailedEvaluationOptions::default(),
            )
            .unwrap()
            .remove(0)
    };
    let first = scan();
    let second = scan();
    assert_eq!(first.source, source);
    assert_eq!(second.source, source);
    assert!(!first.events.is_empty());
    assert!(
        first
            .events
            .iter()
            .any(|event| event.event_type == "detection")
    );
    assert_eq!(
        first.events.iter().map(projection).collect::<Vec<_>>(),
        second.events.iter().map(projection).collect::<Vec<_>>()
    );
    assert!(
        first
            .events
            .iter()
            .zip(&second.events)
            .all(|(a, b)| a.event_id != b.event_id)
    );
    assert_eq!(first.action_findings.len(), 1);
    assert_eq!(first.action_findings, second.action_findings);
    let action = &first.action_findings[0];
    assert!(!action.coordinate().as_str().is_empty());
    assert!(action.occurred_at().is_some());
    assert!(action.replay_identity().is_some());
    assert_eq!(std::fs::read(&source.path).unwrap(), bytes);
    assert_eq!(
        std::fs::read_dir(root.path()).unwrap().count(),
        1,
        "stateless embedding must not create cursor, state, or output files"
    );
}
