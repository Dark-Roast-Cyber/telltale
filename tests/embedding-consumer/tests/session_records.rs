//! External embedding-consumer tests for `Pipeline::read_session_records`.

use std::fs;

use telltale_core::{
    ClientId, Pipeline, SessionRecordContent, SessionRecordKind, SessionRecordOptions, Source,
    SourceKind,
};

#[test]
fn external_consumer_reads_redacted_records_with_cursor_resume() {
    let dir = tempfile::tempdir().unwrap();
    let projects = dir.path().join(".claude/projects/synthetic");
    fs::create_dir_all(&projects).unwrap();
    let path = projects.join("session.jsonl");
    fs::write(
        &path,
        concat!(
            r#"{"type":"user","sessionId":"embed-sess","uuid":"u1","timestamp":"2026-11-20T10:00:00Z","message":{"role":"user","content":"Check token ghp_Zq3Wt9LmP2kR7vX4nB8cY1dF6hJ0sA5uE3iO"}}"#,
            "\n",
            r#"{"type":"user","sessionId":"embed-sess","uuid":"u2","timestamp":"2026-11-20T10:00:01Z","message":{"role":"user","content":"<bash-stdout>HIDDEN_BY_DEFAULT</bash-stdout>"}}"#,
            "\n",
            r#"{"type":"assistant","sessionId":"embed-sess","uuid":"a1","timestamp":"2026-11-20T10:00:02Z","message":{"role":"assistant","content":[{"type":"text","text":"All set."}]}}"#,
            "\n",
        ),
    )
    .unwrap();
    let source = Source {
        client: ClientId::Claude,
        source_id: "claude.projects".to_owned(),
        kind: SourceKind::Jsonl,
        path,
    };

    let pipeline = Pipeline::builder().build().unwrap();
    let page1 = pipeline
        .read_session_records(&source, &{
            let mut value = SessionRecordOptions::default();
            value.max_records = 1;
            value.content = SessionRecordContent::transcript_without_results();
            value.root = Some(dir.path().to_path_buf());
            value
        })
        .unwrap();
    assert_eq!(page1.records().len(), 1);
    assert!(page1.has_more());
    assert_eq!(page1.records()[0].kind(), SessionRecordKind::UserMessage);
    assert_eq!(page1.records()[0].text(), "Check token [redacted-secret]");

    let page2 = pipeline
        .read_session_records(&source, &{
            let mut value = SessionRecordOptions::default();
            value.after_ordinal = page1.next_after_ordinal();
            value.after_record_key = page1.next_after_record_key().map(str::to_owned);
            value.content = SessionRecordContent::transcript_without_results();
            value.root = Some(dir.path().to_path_buf());
            value
        })
        .unwrap();
    assert_eq!(page2.records().len(), 1);
    assert_eq!(
        page2.records()[0].kind(),
        SessionRecordKind::AssistantMessage
    );
    assert!(!page2.records()[0].text().contains("HIDDEN_BY_DEFAULT"));
    assert!(!page2.has_more());
}
