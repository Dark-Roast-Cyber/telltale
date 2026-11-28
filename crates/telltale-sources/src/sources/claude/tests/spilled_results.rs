use super::*;

#[test]
fn spilled_tool_results_resolve_from_the_session_directory() {
    let project = tempfile::tempdir().unwrap();
    let full = format!("{SPILL_MARKER}\n{}", "x".repeat(3000));
    write_spill(project.path(), "b9synthetic.txt", full.as_bytes());
    // The notice names the writer's absolute path; only the file name is used,
    // so a store copied elsewhere (here, a different directory) still resolves.
    let notice = spill_notice(r"C:\Elsewhere\project\other-session\tool-results\b9synthetic.txt");
    let source = spill_source(
        project.path().join(format!("{SPILL_SESSION}.jsonl")),
        json!(notice),
    );
    assert_eq!(spilled_result(&source), json!(full));

    // Every production read mode resolves it, and the observation carries it.
    let batch = acquire_source(&source, options()).unwrap();
    assert!(batch.quarantined.is_empty());
    assert_eq!(
        observed_result(&batch.observations),
        Some(JsonValue::string(&full))
    );
    let bounded = acquire_source_bounded(
        project.path(),
        &source,
        options(),
        DirectReadLimits::default(),
    )
    .unwrap();
    assert_eq!(
        observed_result(&bounded.observations),
        Some(JsonValue::string(&full))
    );

    // A single-text-block array notice resolves the same way.
    let source = spill_source(
        project.path().join(format!("{SPILL_SESSION}.jsonl")),
        json!([{"type":"text","text":notice}]),
    );
    assert_eq!(spilled_result(&source), json!(full));
}

#[test]
fn spilled_subagent_results_resolve_from_the_parent_session_directory() {
    let project = tempfile::tempdir().unwrap();
    write_spill(
        project.path(),
        "toolu_synthetic.txt",
        SPILL_MARKER.as_bytes(),
    );
    let source = spill_source(
        project
            .path()
            .join(SPILL_SESSION)
            .join("subagents")
            .join("agent-synthetic.jsonl"),
        json!(spill_notice("/home/u/p/s/tool-results/toolu_synthetic.txt")),
    );
    assert_eq!(spilled_result(&source), json!(SPILL_MARKER));
}

#[test]
fn unresolvable_spills_keep_the_notice() {
    let project = tempfile::tempdir().unwrap();
    write_spill(project.path(), "present.txt", SPILL_MARKER.as_bytes());
    write_spill(project.path(), "invalid.txt", &[0xff, 0xfe, 0x00]);
    write_spill(
        project.path(),
        "oversized.txt",
        &vec![b'x'; telltale_schema::observation::TOOL_RESULT_MAX_TEXT_BYTES + 1],
    );
    write_spill(
        project.path(),
        "atlimit.txt",
        &vec![b'y'; telltale_schema::observation::TOOL_RESULT_MAX_TEXT_BYTES],
    );
    let present = spill_notice("/p/s/tool-results/present.txt");
    let cases = [
        // Not exactly one notice: quoted inside other output, or unterminated.
        json!(format!("transcript excerpt: {present}")),
        json!(present.trim_end_matches("</persisted-output>")),
        json!([{"type":"text","text":present},{"type":"text","text":"more"}]),
        // The named file is not a plain name in a tool-results directory.
        json!(spill_notice("/p/s/other/present.txt")),
        json!(spill_notice("/p/s/tool-results/../present.txt")),
        json!(spill_notice("/p/s/tool-results/pre sent.txt")),
        json!(spill_notice("/p/s/tool-results/present.exe")),
        // Missing, not UTF-8, or over the direct tool-result budget.
        json!(spill_notice("/p/s/tool-results/missing.txt")),
        json!(spill_notice("/p/s/tool-results/invalid.txt")),
        json!(spill_notice("/p/s/tool-results/oversized.txt")),
    ];
    let transcript = project.path().join(format!("{SPILL_SESSION}.jsonl"));
    for case in cases {
        let source = spill_source(transcript.clone(), case.clone());
        assert_eq!(spilled_result(&source), case);
    }
    let source = spill_source(
        transcript,
        json!(spill_notice("/p/s/tool-results/atlimit.txt")),
    );
    assert_eq!(
        spilled_result(&source).as_str().map(str::len),
        Some(telltale_schema::observation::TOOL_RESULT_MAX_TEXT_BYTES)
    );
}

#[test]
fn spills_outside_a_plain_session_directory_are_not_read() {
    let project = tempfile::tempdir().unwrap();
    write_spill(project.path(), "present.txt", SPILL_MARKER.as_bytes());
    let notice = json!(spill_notice("/p/s/tool-results/present.txt"));
    // A subagent directory under a different session, and a session id that
    // is not a single plain path component, resolve nothing.
    let source = spill_source(
        project
            .path()
            .join("other-session")
            .join("subagents")
            .join("agent-synthetic.jsonl"),
        notice.clone(),
    );
    assert_eq!(spilled_result(&source), notice);
    let transcript = project.path().join("traversal.jsonl");
    let call = json!({"type":"user","sessionId":"../synthetic-spill-session","message":{"role":"user",
        "content":[{"type":"tool_result","tool_use_id":"synthetic-call","content":notice}]}});
    std::fs::write(&transcript, format!("{call}\n")).unwrap();
    let source = Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".into(),
        path: transcript,
    };
    assert_eq!(spilled_result(&source), notice);
}
