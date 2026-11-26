//! Contract tests for `Pipeline::read_session_records`. Every store is
//! synthetic and owned by the test. Failures name a case and a field only,
//! never record text.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use telltale_core::{
    ClientId, Pipeline, PipelineError, SESSION_RECORD_CURSOR_CHANGED, SessionRecordContent,
    SessionRecordKind, SessionRecordOptions, SessionRecordPage, Source, SourceKind,
    read_session_records,
};

/// A generated token-shaped secret; the tail is the oracle.
const SECRET_TAIL: &str = "Zq3Wt9LmP2kR7vX4nB8cY1dF6hJ0sA5uE3iO";
const RESULT_MARKER: &str = "synthetic-result-body";

fn secret() -> String {
    format!("ghp_{SECRET_TAIL}")
}

fn jsonl(lines: &[Value]) -> String {
    lines.iter().map(|line| format!("{line}\n")).collect()
}

fn write(root: &Path, relative: &str, body: &str) -> PathBuf {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, body).unwrap();
    path
}

fn source(client: ClientId, source_id: &str, kind: SourceKind, path: PathBuf) -> Source {
    Source {
        client,
        source_id: source_id.to_owned(),
        kind,
        path,
    }
}

fn code(error: &PipelineError) -> &'static str {
    match error {
        PipelineError::SessionRecords(error) => error.code(),
        PipelineError::InvalidOptions => "invalid_options",
        _ => "other_pipeline_error",
    }
}

fn read(
    source: &Source,
    options: &SessionRecordOptions,
) -> Result<SessionRecordPage, &'static str> {
    read_session_records(source, options).map_err(|error| code(&error))
}

fn transcript(root: Option<&Path>) -> SessionRecordOptions {
    let mut value = SessionRecordOptions::default();
    value.content = SessionRecordContent::transcript_without_results();
    value.root = root.map(Path::to_path_buf);
    value
}

fn with_results(root: Option<&Path>) -> SessionRecordOptions {
    let mut value = transcript(root);
    value.content = SessionRecordContent::all();
    value
}

fn kinds(page: &SessionRecordPage) -> Vec<SessionRecordKind> {
    page.records().iter().map(|record| record.kind()).collect()
}

/// One registered transcript identity with a planted secret in the user
/// prompt, a tool call, and a tool result holding [`RESULT_MARKER`].
struct Case {
    id: &'static str,
    client: ClientId,
    source_id: &'static str,
    kind: SourceKind,
    relative: &'static str,
    body: String,
    session: &'static str,
    /// Kinds in order without tool results.
    expected: Vec<SessionRecordKind>,
}

fn codex_body(session: &str) -> String {
    jsonl(&[
        json!({"type":"session_meta","timestamp":"2026-11-20T10:00:00Z","payload":{"id":session,"session_id":session}}),
        json!({"type":"response_item","timestamp":"2026-11-20T10:00:01Z","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":format!("deploy with token {}", secret())}]}}),
        json!({"type":"response_item","timestamp":"2026-11-20T10:00:02Z","payload":{"type":"function_call","name":"shell_command","arguments":"{\"command\":\"echo synthetic\"}","call_id":"call-1"}}),
        json!({"type":"response_item","timestamp":"2026-11-20T10:00:03Z","payload":{"type":"function_call_output","call_id":"call-1","output":RESULT_MARKER}}),
        json!({"type":"response_item","timestamp":"2026-11-20T10:00:04Z","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"synthetic answer"}]}}),
    ])
}

fn flat_body(agent: &str, session: &str, call: &str) -> String {
    let base = |kind: &str, second: u32| json!({"type":kind,"sessionId":session,"timestamp":format!("2026-11-20T10:00:0{second}Z"),"agent":agent,"provider":agent,"model":"synthetic-model"});
    let mut user = base("user", 1);
    user["content"] = json!(format!("deploy with token {}", secret()));
    let mut tool_call = base("tool_call", 2);
    tool_call["name"] = json!(call);
    tool_call["input"] = json!({"command": "echo synthetic"});
    let mut tool_result = base("tool_result", 3);
    tool_result["tool"] = json!(call);
    tool_result["content"] = json!(RESULT_MARKER);
    let mut assistant = base("assistant", 4);
    assistant["content"] = json!("synthetic answer");
    jsonl(&[user, tool_call, tool_result, assistant])
}

fn cases() -> Vec<Case> {
    use SessionRecordKind::{AssistantMessage, ToolCall, UserMessage};
    let claude = jsonl(&[
        json!({"type":"user","sessionId":"synthetic-claude","uuid":"u1","timestamp":"2026-11-20T10:00:01Z","message":{"role":"user","content":format!("deploy with token {}", secret())}}),
        json!({"type":"assistant","sessionId":"synthetic-claude","uuid":"a1","timestamp":"2026-11-20T10:00:02Z","message":{"role":"assistant","content":[{"type":"text","text":"synthetic answer"},{"type":"tool_use","id":"toolu_1","name":"Bash","input":{"command":"echo synthetic"}}]}}),
        json!({"type":"user","sessionId":"synthetic-claude","uuid":"r1","timestamp":"2026-11-20T10:00:03Z","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":RESULT_MARKER}]}}),
        json!({"type":"user","sessionId":"synthetic-claude","uuid":"u2","timestamp":"2026-11-20T10:00:04Z","message":{"role":"user","content":format!("<bash-stdout>{RESULT_MARKER}</bash-stdout>")}}),
    ]);
    let pi = jsonl(&[
        json!({"type":"session","version":3,"id":"synthetic-pi","timestamp":"2026-11-20T10:00:00.000Z","cwd":"/synthetic/project"}),
        json!({"type":"message","id":"p1","parentId":null,"timestamp":"2026-11-20T10:00:01.000Z","message":{"role":"user","content":[{"type":"text","text":format!("deploy with token {}", secret())}]}}),
        json!({"type":"message","id":"p2","parentId":"p1","timestamp":"2026-11-20T10:00:02.000Z","message":{"role":"assistant","content":[{"type":"toolCall","id":"call-1","name":"bash","arguments":{"command":"echo synthetic"}}]}}),
        json!({"type":"message","id":"p3","parentId":"p2","timestamp":"2026-11-20T10:00:03.000Z","message":{"role":"toolResult","toolCallId":"call-1","toolName":"bash","content":[{"type":"text","text":RESULT_MARKER}],"isError":false}}),
        json!({"type":"message","id":"p4","parentId":"p3","timestamp":"2026-11-20T10:00:04.000Z","message":{"role":"assistant","content":[{"type":"text","text":"synthetic answer"}]}}),
    ]);
    let copilot = format!(
        "2026-11-20T10:00:00.000Z [INFO] Workspace initialized: synthetic-copilot (checkpoints: 0)\n\
         2026-11-20T10:00:01.000Z [INFO] Accumulated output items (1): [{{\"arguments\":\"{{\\\"command\\\":\\\"deploy {}\\\"}}\",\"call_id\":\"call-1\",\"id\":\"c1\",\"name\":\"bash\",\"status\":\"completed\",\"type\":\"function_call\"}}]\n",
        secret()
    );
    vec![
        Case {
            id: "claude.projects",
            client: ClientId::Claude,
            source_id: "claude.projects",
            kind: SourceKind::Jsonl,
            relative: ".claude/projects/synthetic/session.jsonl",
            body: claude,
            session: "synthetic-claude",
            expected: vec![UserMessage, AssistantMessage, ToolCall],
        },
        Case {
            id: "codex.sessions",
            client: ClientId::Codex,
            source_id: "codex.sessions",
            kind: SourceKind::Jsonl,
            relative: ".codex/sessions/2026/11/20/rollout-synthetic.jsonl",
            body: codex_body("synthetic-codex"),
            session: "synthetic-codex",
            expected: vec![UserMessage, ToolCall, AssistantMessage],
        },
        Case {
            id: "codex.archived_sessions",
            client: ClientId::Codex,
            source_id: "codex.archived_sessions",
            kind: SourceKind::ArchivedJsonl,
            relative: ".codex/archived_sessions/rollout-synthetic.jsonl",
            body: codex_body("synthetic-codex-archived"),
            session: "synthetic-codex-archived",
            expected: vec![UserMessage, ToolCall, AssistantMessage],
        },
        Case {
            id: "codex.headless_sessions",
            client: ClientId::Codex,
            source_id: "codex.headless_sessions",
            kind: SourceKind::HeadlessJsonl,
            relative: ".codex/headless/synthetic.jsonl",
            body: codex_body("synthetic-codex-headless"),
            session: "synthetic-codex-headless",
            expected: vec![UserMessage, ToolCall, AssistantMessage],
        },
        Case {
            id: "openclaw.agents",
            client: ClientId::OpenClaw,
            source_id: "openclaw.agents",
            kind: SourceKind::Jsonl,
            relative: ".openclaw/agents/synthetic/session.jsonl",
            body: flat_body("openclaw", "synthetic-openclaw", "bash"),
            session: "synthetic-openclaw",
            expected: vec![UserMessage, ToolCall, AssistantMessage],
        },
        Case {
            id: "qwen.projects",
            client: ClientId::Qwen,
            source_id: "qwen.projects",
            kind: SourceKind::Jsonl,
            relative: ".qwen/projects/synthetic/chats/session.jsonl",
            body: flat_body("qwen", "synthetic-qwen", "run_shell_command"),
            session: "synthetic-qwen",
            expected: vec![UserMessage, ToolCall, AssistantMessage],
        },
        Case {
            id: "pi.sessions",
            client: ClientId::Pi,
            source_id: "pi.sessions",
            kind: SourceKind::Jsonl,
            relative: ".pi/agent/sessions/--synthetic--/2026-11-20T10-00-00-000Z_synthetic-pi.jsonl",
            body: pi,
            session: "synthetic-pi",
            expected: vec![UserMessage, ToolCall, AssistantMessage],
        },
        Case {
            id: "copilot.process_log",
            client: ClientId::Copilot,
            source_id: "copilot.process_log",
            kind: SourceKind::CopilotProcessLog,
            relative: ".copilot/logs/process-synthetic.log",
            body: copilot,
            session: "synthetic-copilot",
            expected: vec![ToolCall],
        },
    ]
}

fn check_case(case: &Case, page: &SessionRecordPage, mode: &str) {
    let label = format!("{} [{mode}]", case.id);
    assert_eq!(kinds(page), case.expected, "{label}: kinds");
    assert!(!page.has_more(), "{label}: has_more");
    let ordinals: Vec<u64> = page.records().iter().map(|r| r.ordinal()).collect();
    assert!(
        ordinals.windows(2).all(|pair| pair[0] < pair[1]),
        "{label}: order"
    );
    for record in page.records() {
        assert_eq!(
            record.session_id(),
            Some(case.session),
            "{label}: session_id"
        );
        assert!(!record.text().contains(SECRET_TAIL), "{label}: secret");
        assert!(
            !record.text().contains(RESULT_MARKER),
            "{label}: result body"
        );
        assert!(
            record.record_key().starts_with("rec:v1:sha256:"),
            "{label}: key"
        );
    }
    assert!(
        page.records()
            .iter()
            .any(|r| r.text().contains("[redacted")),
        "{label}: redaction marker"
    );
}

#[test]
fn every_registered_transcript_identity_reads_in_both_modes() {
    for case in cases() {
        let root = tempfile::tempdir().unwrap();
        let path = write(root.path(), case.relative, &case.body);
        let source = source(case.client, case.source_id, case.kind, path);
        for (mode, root) in [("root", Some(root.path())), ("no_root", None)] {
            let page = read(&source, &transcript(root))
                .unwrap_or_else(|code| panic!("{} [{mode}]: read failed: {code}", case.id));
            check_case(&case, &page, mode);
            let session = {
                let mut value = transcript(root);
                value.session_id = Some(case.session.to_owned());
                value
            };
            let page = read(&source, &session)
                .unwrap_or_else(|code| panic!("{} [{mode}]: session read failed: {code}", case.id));
            check_case(&case, &page, mode);
            let all = read(&source, &with_results(root))
                .unwrap_or_else(|code| panic!("{} [{mode}]: result read failed: {code}", case.id));
            for record in all.records() {
                if record.text().contains(RESULT_MARKER) {
                    assert_eq!(
                        record.kind(),
                        SessionRecordKind::ToolResult,
                        "{} [{mode}]: result kind",
                        case.id
                    );
                }
            }
            if case.id != "copilot.process_log" {
                assert!(
                    all.records()
                        .iter()
                        .any(|r| r.text().contains(RESULT_MARKER)),
                    "{} [{mode}]: result present when enabled",
                    case.id
                );
            }
        }
    }
}

/// A Codex rollout that holds a turn imported from another session.
fn codex_imported_rollout() -> String {
    jsonl(&[
        json!({"type":"session_meta","timestamp":"2026-11-20T10:00:00Z","payload":{"id":"synthetic-codex","session_id":"synthetic-codex"}}),
        json!({"type":"event_msg","timestamp":"2026-11-20T10:00:01Z","payload":{"type":"task_started","turn_id":"external-import-turn-synthetic"}}),
        json!({"type":"response_item","timestamp":"2026-11-20T10:00:02Z","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"synthetic imported prompt"}]}}),
        json!({"type":"event_msg","timestamp":"2026-11-20T10:00:03Z","payload":{"type":"task_started","turn_id":"turn-synthetic"}}),
        json!({"type":"response_item","timestamp":"2026-11-20T10:00:04Z","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"synthetic native prompt"}]}}),
    ])
}

#[test]
fn imported_turns_are_read_in_order() {
    let root = tempfile::tempdir().unwrap();
    let path = write(
        root.path(),
        "codex/rollout.jsonl",
        &codex_imported_rollout(),
    );
    let source = source(ClientId::Codex, "codex.sessions", SourceKind::Jsonl, path);
    let page = read(&source, &transcript(None)).unwrap();
    let texts: Vec<&str> = page.records().iter().map(|r| r.text()).collect();
    assert_eq!(
        texts,
        ["synthetic imported prompt", "synthetic native prompt"]
    );
    let imported: Vec<bool> = page.records().iter().map(|r| r.imported()).collect();
    assert_eq!(imported, [true, false]);
    assert_ne!(
        page.records()[0].record_key(),
        page.records()[1].record_key()
    );
}

/// Codex stores a command the user ran from the prompt, with its output, as
/// a user message; that record is a tool result. A prompt that only names
/// the tag stays a user message.
#[test]
fn codex_user_shell_records_are_tool_results() {
    let shell = format!(
        "<user_shell_command>\n<command>\necho synthetic\n</command>\n<result>\nExit code: 0\nOutput:\n{RESULT_MARKER}\n</result>\n</user_shell_command>"
    );
    let message = |text: &str| json!({"type":"response_item","timestamp":"2026-11-20T10:00:01Z","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":text}]}});
    let root = tempfile::tempdir().unwrap();
    let path = write(
        root.path(),
        "codex/rollout.jsonl",
        &jsonl(&[
            json!({"type":"session_meta","timestamp":"2026-11-20T10:00:00Z","payload":{"id":"synthetic-codex","session_id":"synthetic-codex"}}),
            message("what does <user_shell_command> hold"),
            message(&shell),
        ]),
    );
    for (source_id, kind) in [
        ("codex.sessions", SourceKind::Jsonl),
        ("codex.archived_sessions", SourceKind::ArchivedJsonl),
        ("codex.headless_sessions", SourceKind::HeadlessJsonl),
    ] {
        let source = source(ClientId::Codex, source_id, kind, path.clone());
        let page = read(&source, &transcript(None)).unwrap();
        assert_eq!(
            kinds(&page),
            vec![SessionRecordKind::UserMessage],
            "{source_id}"
        );
        assert!(
            !page.records()[0].text().contains(RESULT_MARKER),
            "{source_id}: output in prompt"
        );
        let all = read(&source, &with_results(None)).unwrap();
        assert_eq!(
            kinds(&all),
            vec![
                SessionRecordKind::UserMessage,
                SessionRecordKind::ToolResult
            ],
            "{source_id}"
        );
    }
}

#[test]
fn hook_journals_are_not_transcripts() {
    let root = tempfile::tempdir().unwrap();
    let path = write(root.path(), "journal.jsonl", "{}\n");
    let journal = source(ClientId::Claude, "claude.hooks", SourceKind::Jsonl, path);
    for root in [Some(root.path()), None] {
        assert_eq!(
            read(&journal, &transcript(root)).err(),
            Some("unsupported_source_identity")
        );
    }
}

#[test]
fn default_options_return_no_content_class() {
    let case = &cases()[0];
    let root = tempfile::tempdir().unwrap();
    let path = write(root.path(), case.relative, &case.body);
    let source = source(case.client, case.source_id, case.kind, path);
    let page = read(&source, &SessionRecordOptions::default()).unwrap();
    assert!(page.records().is_empty());
    assert!(!page.has_more());
}

/// A record that mixes text with a tool result keeps the text as a message
/// and the result body only as a tool result.
#[test]
fn mixed_text_and_tool_result_records_never_put_the_result_in_message_text() {
    let mixed_flat = |agent: &str, session: &str, id_field: &str| {
        jsonl(&[
            json!({"type":"user","sessionId":session,"timestamp":"2026-11-20T10:00:01Z","agent":agent,"provider":agent,"model":"synthetic-model","content":[
                {"type":"text","text":"synthetic prompt text"},
                {"type":"tool_result", id_field:"call-1","content":RESULT_MARKER}
            ]}),
        ])
    };
    let codex = jsonl(&[
        json!({"type":"session_meta","timestamp":"2026-11-20T10:00:00Z","payload":{"id":"synthetic-codex","session_id":"synthetic-codex"}}),
        json!({"type":"response_item","timestamp":"2026-11-20T10:00:01Z","payload":{"type":"message","role":"user","content":[
            {"type":"input_text","text":"synthetic prompt text"},
            {"type":"tool_result","tool_use_id":"call-1","content":RESULT_MARKER}
        ]}}),
    ]);
    let stores = [
        (
            "qwen",
            ClientId::Qwen,
            "qwen.projects",
            mixed_flat("qwen", "synthetic-qwen", "tool_call_id"),
        ),
        (
            "openclaw",
            ClientId::OpenClaw,
            "openclaw.agents",
            mixed_flat("openclaw", "synthetic-openclaw", "tool_use_id"),
        ),
        ("codex", ClientId::Codex, "codex.sessions", codex),
    ];
    for (id, client, source_id, body) in stores {
        let root = tempfile::tempdir().unwrap();
        let path = write(root.path(), "store/session.jsonl", &body);
        let source = source(client, source_id, SourceKind::Jsonl, path);
        let page = read(&source, &transcript(None))
            .unwrap_or_else(|code| panic!("{id}: read failed: {code}"));
        assert!(
            page.records()
                .iter()
                .any(|r| r.kind() == SessionRecordKind::UserMessage
                    && r.text().contains("synthetic prompt text")),
            "{id}: prompt text"
        );
        let all = read(&source, &with_results(None))
            .unwrap_or_else(|code| panic!("{id}: result read failed: {code}"));
        for page in [&page, &all] {
            for record in page.records() {
                if record.kind() != SessionRecordKind::ToolResult {
                    assert!(
                        !record.text().contains(RESULT_MARKER),
                        "{id}: result in message"
                    );
                }
            }
        }
    }
}

/// Command output a Claude harness stores as a user record is a tool result;
/// a prompt that only quotes a tag mid-text stays a user message.
#[test]
fn claude_command_output_records_are_tool_results() {
    let tags = [
        "bash-stdout",
        "bash-stderr",
        "local-command-stdout",
        "local-command-stderr",
        "task-notification",
    ];
    let mut lines = vec![
        json!({"type":"user","sessionId":"synthetic-claude","uuid":"q","timestamp":"2026-11-20T10:00:00Z","message":{"role":"user","content":"explain what <bash-stdout> means"}}),
        // A tag split across text parts, and an unclosed tag that opens a
        // line after a preamble, are output too.
        json!({"type":"user","sessionId":"synthetic-claude","uuid":"s","timestamp":"2026-11-20T10:00:00Z","message":{"role":"user","content":[{"type":"text","text":"<bash-"},{"type":"text","text":format!("stdout>{RESULT_MARKER}</bash-stdout>")}]}}),
        json!({"type":"user","sessionId":"synthetic-claude","uuid":"u","timestamp":"2026-11-20T10:00:00Z","message":{"role":"user","content":format!("<system-reminder>note</system-reminder>\n<bash-stdout>{RESULT_MARKER}")}}),
        json!({"type":"user","sessionId":"synthetic-claude","uuid":"v","timestamp":"2026-11-20T10:00:00Z","message":{"role":"user","content":[{"type":"text","text":"synthetic preamble"},{"type":"text","text":format!("  <task-notification>{RESULT_MARKER}")}]}}),
        // A self-closed opening tag before the closing tag, and an unclosed
        // tag behind a mark, quote or bullet at the start of its line.
        json!({"type":"user","sessionId":"synthetic-claude","uuid":"w","timestamp":"2026-11-20T10:00:00Z","message":{"role":"user","content":format!("<bash-stdout/>{RESULT_MARKER}</bash-stdout>")}}),
        json!({"type":"user","sessionId":"synthetic-claude","uuid":"x","timestamp":"2026-11-20T10:00:00Z","message":{"role":"user","content":format!("\u{feff}<bash-stdout>{RESULT_MARKER}")}}),
        json!({"type":"user","sessionId":"synthetic-claude","uuid":"y","timestamp":"2026-11-20T10:00:00Z","message":{"role":"user","content":format!("- \"<local-command-stdout>{RESULT_MARKER}")}}),
    ];
    for (index, tag) in tags.iter().enumerate() {
        lines.push(json!({"type":"user","sessionId":"synthetic-claude","uuid":format!("t{index}"),"timestamp":"2026-11-20T10:00:01Z","message":{"role":"user","content":format!("  <{tag}>{RESULT_MARKER}</{tag}>")}}));
        lines.push(json!({"type":"user","sessionId":"synthetic-claude","uuid":format!("p{index}"),"timestamp":"2026-11-20T10:00:02Z","message":{"role":"user","content":[{"type":"text","text":format!("<{tag} id=\"1\">{RESULT_MARKER}</{tag}>")}]}}));
        // A complete output element after other text is output too.
        lines.push(json!({"type":"user","sessionId":"synthetic-claude","uuid":format!("m{index}"),"timestamp":"2026-11-20T10:00:03Z","message":{"role":"user","content":format!("synthetic prefix\n<{}>{RESULT_MARKER}</{tag}>", tag.to_uppercase())}}));
    }
    let root = tempfile::tempdir().unwrap();
    let path = write(
        root.path(),
        ".claude/projects/synthetic/session.jsonl",
        &jsonl(&lines),
    );
    let source = source(ClientId::Claude, "claude.projects", SourceKind::Jsonl, path);
    let page = read(&source, &transcript(Some(root.path()))).unwrap();
    assert_eq!(kinds(&page), vec![SessionRecordKind::UserMessage]);
    let all = read(&source, &with_results(Some(root.path()))).unwrap();
    assert_eq!(
        all.records()
            .iter()
            .filter(|r| r.kind() == SessionRecordKind::ToolResult)
            .count(),
        tags.len() * 3 + 6
    );
    for record in page.records() {
        assert!(
            !record.text().contains(RESULT_MARKER),
            "claude: output in prompt"
        );
    }

    // The same text from another client is not reclassified.
    let qwen = flat_body("qwen", "synthetic-qwen", "bash")
        .replace("deploy with token", "<bash-stdout>synthetic</bash-stdout>");
    let path = write(root.path(), "qwen/session.jsonl", &qwen);
    let qwen = crate::source(ClientId::Qwen, "qwen.projects", SourceKind::Jsonl, path);
    let page = read(&qwen, &transcript(None)).unwrap();
    assert_eq!(page.records()[0].kind(), SessionRecordKind::UserMessage);
}

#[cfg(unix)]
#[test]
fn links_under_a_root_are_refused_with_a_closed_code() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let case = &cases()[0];
    let target = write(outside.path(), "synthetic-outside.jsonl", &case.body);
    let link = root.path().join(".claude/projects/synthetic/linked.jsonl");
    fs::create_dir_all(link.parent().unwrap()).unwrap();
    symlink(&target, &link).unwrap();
    let source = source(case.client, case.source_id, case.kind, link);
    let error = read_session_records(&source, &transcript(Some(root.path()))).unwrap_err();
    assert_eq!(code(&error), "non_regular_source");
    let rendered = format!("{error} {error:?}");
    assert!(
        !rendered.contains("synthetic-outside"),
        "rendered error: path"
    );
}

#[test]
fn missing_sources_fail_with_a_closed_code_and_no_path() {
    let missing = source(
        ClientId::Claude,
        "claude.projects",
        SourceKind::Jsonl,
        PathBuf::from("/nonexistent/synthetic-private-dir/session.jsonl"),
    );
    for root in [None, Some(Path::new("/nonexistent"))] {
        let error = read_session_records(&missing, &transcript(root)).unwrap_err();
        assert_eq!(code(&error), "source_missing");
        let rendered = format!("{error} {error:?}");
        assert!(
            !rendered.contains("synthetic-private-dir"),
            "rendered error: path"
        );
    }
}

#[test]
fn source_byte_limit_is_a_closed_error_and_large_sessions_read_by_default() {
    let root = tempfile::tempdir().unwrap();
    let prompt = "synthetic filler line\n".repeat(400);
    let lines: Vec<Value> = (0..1_000)
        .map(|index| json!({"type":"user","sessionId":"synthetic-large","uuid":format!("u{index}"),"timestamp":"2026-11-20T10:00:00Z","message":{"role":"user","content":prompt}}))
        .collect();
    let path = write(
        root.path(),
        ".claude/projects/synthetic/large.jsonl",
        &jsonl(&lines),
    );
    assert!(fs::metadata(&path).unwrap().len() > 8 * 1024 * 1024);
    let source = source(ClientId::Claude, "claude.projects", SourceKind::Jsonl, path);
    let page = read(&source, &transcript(Some(root.path()))).unwrap();
    assert!(page.has_more(), "large: has_more");
    assert!(!page.records().is_empty(), "large: records");
    let limited = {
        let mut value = transcript(Some(root.path()));
        value.max_source_bytes = 1024 * 1024;
        value
    };
    assert_eq!(read(&source, &limited).err(), Some("source_limit_exceeded"));
    let invalid = {
        let mut value = transcript(None);
        value.max_source_bytes = 0;
        value
    };
    assert_eq!(read(&source, &invalid).err(), Some("invalid_options"));
}

#[test]
fn paging_resumes_after_the_cursor_and_detects_a_changed_cursor_record() {
    let root = tempfile::tempdir().unwrap();
    let line = |index: usize, text: &str| json!({"type":"user","sessionId":"synthetic-resume","uuid":format!("u{index}"),"timestamp":format!("2026-11-20T10:00:0{index}Z"),"message":{"role":"user","content":text}});
    let mut lines = vec![line(0, "first"), line(1, "second"), line(2, "third")];
    let path = write(
        root.path(),
        ".claude/projects/synthetic/resume.jsonl",
        &jsonl(&lines),
    );
    let source = source(
        ClientId::Claude,
        "claude.projects",
        SourceKind::Jsonl,
        path.clone(),
    );
    let paged = {
        let mut value = transcript(Some(root.path()));
        value.max_records = 2;
        value
    };
    let first = read(&source, &paged).unwrap();
    assert!(first.has_more());
    assert_eq!(first.records().len(), 2);
    let cursor = {
        let mut value = paged.clone();
        value.after_ordinal = first.next_after_ordinal();
        value.after_record_key = first.next_after_record_key().map(str::to_owned);
        value
    };
    let second = read(&source, &cursor).unwrap();
    assert!(!second.has_more());
    assert_eq!(second.records().len(), 1);
    assert_eq!(second.records()[0].text(), "third");

    // Appending keeps ordinals and keys; the cursor still resumes.
    lines.push(line(3, "fourth"));
    fs::write(&path, jsonl(&lines)).unwrap();
    let appended = read(&source, &cursor).unwrap();
    assert_eq!(appended.records()[0], second.records()[0]);
    assert_eq!(appended.records().len(), 2);

    // Rewriting the cursor record, or removing it, fails closed.
    lines[1] = line(1, "rewritten");
    fs::write(&path, jsonl(&lines)).unwrap();
    assert_eq!(
        read(&source, &cursor).err(),
        Some(SESSION_RECORD_CURSOR_CHANGED)
    );
    fs::write(&path, jsonl(&lines[..1])).unwrap();
    assert_eq!(
        read(&source, &cursor).err(),
        Some(SESSION_RECORD_CURSOR_CHANGED)
    );

    // A key without an ordinal is invalid.
    let keyless = {
        let mut value = cursor;
        value.after_ordinal = None;
        value
    };
    assert_eq!(read(&source, &keyless).err(), Some("invalid_options"));
}

#[test]
fn record_keys_hash_redacted_text_and_budgets_bound_the_page() {
    let root = tempfile::tempdir().unwrap();
    let one = |token: &str| {
        jsonl(&[
            json!({"type":"user","sessionId":"synthetic-key","uuid":"u1","timestamp":"2026-11-20T10:00:00Z","message":{"role":"user","content":format!("token {token}")}}),
        ])
    };
    let first = write(root.path(), "a/session.jsonl", &one(&secret()));
    let second = write(
        root.path(),
        "b/session.jsonl",
        &one("ghp_Ab9Cd8Ef7Gh6Ij5Kl4Mn3Op2Qr1St0Uv9Wx8"),
    );
    let key = |path: PathBuf| {
        let page = read(
            &source(ClientId::Claude, "claude.projects", SourceKind::Jsonl, path),
            &transcript(None),
        )
        .unwrap();
        page.records()[0].record_key().to_owned()
    };
    assert_eq!(key(first), key(second));

    let long = jsonl(
        &(0..4)
            .map(|index| json!({"type":"user","sessionId":"synthetic-budget","uuid":format!("u{index}"),"timestamp":"2026-11-20T10:00:00Z","message":{"role":"user","content":"synthetic words ".repeat(64)}}))
            .collect::<Vec<_>>(),
    );
    let path = write(root.path(), "c/session.jsonl", &long);
    let source = source(ClientId::Claude, "claude.projects", SourceKind::Jsonl, path);
    let full = read(&source, &transcript(None)).unwrap();
    let small = {
        let mut value = transcript(None);
        value.max_record_bytes = 64;
        value.max_total_bytes = 100;
        value
    };
    let page = read(&source, &small).unwrap();
    assert!(page.has_more());
    assert_eq!(page.records().len(), 1);
    assert!(page.records()[0].truncated());
    assert!(page.records()[0].text().len() <= 64);
    assert!(page.total_bytes() <= 100);
    assert_eq!(
        page.records()[0].record_key(),
        full.records()[0].record_key()
    );
}

#[test]
fn time_range_keeps_records_in_the_window() {
    let root = tempfile::tempdir().unwrap();
    let line = |time: &str, text: &str| json!({"type":"user","sessionId":"synthetic-time","uuid":text,"timestamp":time,"message":{"role":"user","content":text}});
    let path = write(
        root.path(),
        "time/session.jsonl",
        &jsonl(&[
            line("2026-11-20T10:00:00Z", "early"),
            line("2026-11-20T12:00:00Z", "middle"),
            line("2026-11-20T14:00:00Z", "late"),
        ]),
    );
    let source = source(ClientId::Claude, "claude.projects", SourceKind::Jsonl, path);
    let page = read(&source, &{
        let mut value = transcript(None);
        value.since = Some("2026-11-20T11:00:00Z".to_owned());
        value.until = Some("2026-11-20T14:00:00Z".to_owned());
        value
    })
    .unwrap();
    assert_eq!(page.records().len(), 1);
    assert_eq!(page.records()[0].text(), "middle");
}

#[test]
fn pipeline_method_matches_the_free_function() {
    let case = &cases()[1];
    let root = tempfile::tempdir().unwrap();
    let path = write(root.path(), case.relative, &case.body);
    let source = source(case.client, case.source_id, case.kind, path);
    let pipeline = Pipeline::builder().build().unwrap();
    assert_eq!(
        pipeline
            .read_session_records(&source, &transcript(None))
            .unwrap(),
        read_session_records(&source, &transcript(None)).unwrap()
    );
}

#[cfg(feature = "opencode-sqlite")]
mod opencode {
    use super::*;
    use rusqlite::Connection;

    const SCHEMA: &str = "
        create table session_v2 (id text primary key, project_id text not null, slug text not null,
          directory text not null, version text not null, agent text, model text, metadata text,
          permission text, time_created integer not null, time_updated integer not null);
        create table session_message (id text primary key, session_id text not null, type text not null,
          seq integer not null, time_created integer not null, time_updated integer not null,
          data text not null);";
    const T0: i64 = 1_775_000_000_000;

    struct Store {
        _directory: tempfile::TempDir,
        connection: Connection,
        source: Source,
    }

    impl Store {
        fn new(schema: &str) -> Self {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("opencode.db");
            let connection = Connection::open(&path).unwrap();
            connection.execute_batch(schema).unwrap();
            if schema.contains("session_v2") {
                connection
                    .execute(
                        "insert into session_v2 (id, project_id, slug, directory, version, agent, model, metadata, permission, time_created, time_updated)
                         values ('ses_synthetic', 'prj_synthetic', 'synthetic', '/synthetic', '2.0.27', 'build',
                         '{\"id\":\"synthetic-model\",\"providerID\":\"synthetic-provider\"}', '{}', '[]', ?1, ?1)",
                        [T0],
                    )
                    .unwrap();
            }
            Self {
                source: super::source(
                    ClientId::OpenCode,
                    "opencode.sqlite",
                    SourceKind::Sqlite,
                    path,
                ),
                _directory: directory,
                connection,
            }
        }

        fn message(&self, seq: i64, mut data: Value) {
            let kind = data.as_object_mut().unwrap().remove("type").unwrap();
            self.connection
                .execute(
                    "insert into session_message (id, session_id, type, seq, time_created, time_updated, data)
                     values (?1, 'ses_synthetic', ?2, ?3, ?4, ?4, ?5)",
                    rusqlite::params![format!("msg_{seq:06}"), kind.as_str().unwrap(), seq, T0 + seq, data.to_string()],
                )
                .unwrap();
        }

        fn user(&self, seq: i64, text: &str) {
            self.message(
                seq,
                json!({"type":"user","text":text,"time":{"created":T0 + seq}}),
            );
        }

        fn tool(&self, seq: i64) {
            self.message(
                seq,
                json!({"type":"assistant","agent":"build","model":{"id":"synthetic-model","providerID":"synthetic-provider"},
                    "content":[{"type":"text","text":"synthetic answer"},
                        {"type":"tool","id":format!("call_{seq}"),"name":"bash","executed":false,
                         "state":{"status":"completed","input":{"command":"echo synthetic"},"content":[{"type":"text","text":RESULT_MARKER}]},
                         "time":{"created":T0 + seq,"ran":T0 + seq + 1,"completed":T0 + seq + 2}}],
                    "time":{"created":T0 + seq}}),
            );
        }
    }

    fn options() -> SessionRecordOptions {
        let mut value = transcript(None);
        value.session_id = Some("ses_synthetic".to_owned());
        value
    }

    #[test]
    fn opencode_reads_oldest_first_across_windows_with_stable_cursors() {
        let store = Store::new(SCHEMA);
        store.user(1, &format!("deploy with token {}", secret()));
        store.tool(2);
        for seq in 3..=600 {
            store.user(seq, &format!("synthetic prompt {seq}"));
        }
        let page = read(&store.source, &options()).unwrap();
        assert!(page.has_more());
        assert_eq!(page.records()[0].kind(), SessionRecordKind::UserMessage);
        assert!(!page.records()[0].text().contains(SECRET_TAIL));
        assert_eq!(
            &kinds(&page)[1..3],
            [
                SessionRecordKind::AssistantMessage,
                SessionRecordKind::ToolCall
            ]
        );
        assert!(
            page.records()
                .iter()
                .all(|r| !r.text().contains(RESULT_MARKER))
        );
        assert!(
            page.records()
                .iter()
                .all(|r| r.session_id() == Some("ses_synthetic"))
        );

        // Page through every record: oldest first, past one store window.
        let mut texts = Vec::new();
        let mut ordinals = Vec::new();
        let mut cursor = options();
        cursor.max_records = 100;
        loop {
            let page = read(&store.source, &cursor).unwrap();
            for record in page.records() {
                ordinals.push(record.ordinal());
                texts.push(record.text().to_owned());
            }
            if !page.has_more() {
                break;
            }
            cursor.after_ordinal = page.next_after_ordinal();
            cursor.after_record_key = page.next_after_record_key().map(str::to_owned);
        }
        assert!(ordinals.windows(2).all(|pair| pair[0] < pair[1]), "order");
        assert_eq!(
            texts.last().map(String::as_str),
            Some("synthetic prompt 600")
        );
        assert_eq!(texts.len(), 3 + 598);

        // Appending keeps every ordinal and key; the old cursor resumes.
        let before = read(&store.source, &options()).unwrap();
        store.user(601, "synthetic appended");
        let after = read(&store.source, &options()).unwrap();
        assert_eq!(before.records(), after.records());
        let tail = read(&store.source, &cursor).unwrap();
        assert_eq!(
            tail.records().last().map(|r| r.text()),
            Some("synthetic appended")
        );

        // Tool results are opt-in.
        let all = {
            let mut value = options();
            value.content = SessionRecordContent::all();
            value.max_records = 4;
            value
        };
        let page = read(&store.source, &all).unwrap();
        assert!(
            page.records()
                .iter()
                .any(|r| r.kind() == SessionRecordKind::ToolResult
                    && r.text().contains(RESULT_MARKER))
        );
    }

    #[test]
    fn opencode_without_a_stable_order_fails_closed() {
        let store = Store::new(SCHEMA);
        store.user(1, "synthetic prompt");
        let no_session = transcript(None);
        assert_eq!(
            read(&store.source, &no_session).err(),
            Some("transcript_session_required")
        );
        store
            .connection
            .execute("update session_message set seq = 'x'", [])
            .unwrap();
        assert_eq!(
            read(&store.source, &options()).err(),
            Some("transcript_order_unavailable")
        );

        let legacy = Store::new(
            "create table message (id text, session_id text, time_created integer, time_updated integer, data text);
             create table part (id text, message_id text, session_id text, time_created integer, time_updated integer, data text);",
        );
        assert_eq!(
            read(&legacy.source, &options()).err(),
            Some("transcript_order_unavailable")
        );
    }

    #[test]
    fn opencode_filtered_prefix_is_resumed_through_the_continuation() {
        let store = Store::new(SCHEMA);
        for seq in 1..=300 {
            store.user(seq, &format!("synthetic prompt {seq}"));
        }
        // Rows 1..=279 are before the range; the source budget covers far
        // fewer rows than that per read.
        let mut cursor = {
            let mut value = options();
            value.since = Some("2026-03-31T23:33:20.280Z".to_owned());
            value.max_source_bytes = 4_096;
            value.max_records = 1;
            value
        };
        let mut empty_pages = 0;
        let found = loop {
            let page = read(&store.source, &cursor).unwrap();
            if let Some(record) = page.records().first() {
                break record.text().to_owned();
            }
            assert!(page.has_more(), "empty page: has_more");
            assert!(page.next_after_record_key().is_none(), "empty page: key");
            let next = page.next_after_ordinal().expect("empty page: continuation");
            assert!(
                cursor.after_ordinal.is_none_or(|previous| next > previous),
                "progress"
            );
            cursor.after_ordinal = Some(next);
            cursor.after_record_key = None;
            empty_pages += 1;
            assert!(empty_pages < 200, "pages bounded");
        };
        assert!(empty_pages > 1, "prefix spans several reads");
        assert_eq!(found, "synthetic prompt 280");

        // One row larger than the whole source budget cannot be read.
        let tight = {
            let mut value = options();
            value.max_source_bytes = 16;
            value
        };
        assert_eq!(
            read(&store.source, &tight).err(),
            Some("source_limit_exceeded")
        );
    }

    /// Two rows that each fit the source budget but not together: every read
    /// must move on, and none may spend its budget on the row the cursor is
    /// already past.
    #[test]
    fn opencode_rows_that_fit_the_budget_only_alone_are_each_read() {
        let store = Store::new(SCHEMA);
        for seq in 1..=3 {
            store.user(
                seq,
                &format!("synthetic prompt {seq} {}", "word ".repeat(120)),
            );
        }
        let mut cursor = {
            let mut value = options();
            value.max_source_bytes = 1_000;
            value
        };
        let mut seen = Vec::new();
        for _ in 0..8 {
            let page = read(&store.source, &cursor).unwrap();
            seen.extend(page.records().iter().map(|record| record.ordinal()));
            if !page.has_more() {
                break;
            }
            let next = page.next_after_ordinal().expect("continuation");
            assert!(
                cursor.after_ordinal.is_none_or(|previous| next > previous),
                "progress"
            );
            cursor.after_ordinal = Some(next);
            cursor.after_record_key = None;
        }
        assert_eq!(seen.len(), 3, "each row read once");
        assert!(seen.windows(2).all(|pair| pair[0] < pair[1]), "in order");
    }

    #[test]
    fn opencode_session_lookup_is_bounded_and_fails_closed() {
        let store = Store::new(SCHEMA);
        store.user(1, "synthetic prompt");
        let oversized = format!("ses_{}", "x".repeat(8 * 1024));
        store
            .connection
            .execute(
                "insert into session_v2 (id, project_id, slug, directory, version, time_created, time_updated)
                 values (?1, 'prj_synthetic', 'synthetic', '/synthetic', '2.0.27', 0, 0)",
                [&oversized],
            )
            .unwrap();
        store
            .connection
            .execute(
                "insert into session_message (id, session_id, type, seq, time_created, time_updated, data)
                 values ('msg_oversized', ?1, 'user', 1, 0, 0, '{\"text\":\"synthetic\"}')",
                [&oversized],
            )
            .unwrap();
        // An exact stored id needs no scan.
        assert!(read(&store.source, &options()).is_ok(), "exact id");
        // Any other id is looked up by scanning stored ids, which stops at an
        // oversized one.
        let other = {
            let mut value = transcript(None);
            value.session_id = Some("synthetic-absent".to_owned());
            value
        };
        assert_eq!(
            read(&store.source, &other).err(),
            Some("source_limit_exceeded")
        );
    }

    #[cfg(unix)]
    #[test]
    fn opencode_store_links_under_a_root_are_refused() {
        use std::os::unix::fs::symlink;
        let store = Store::new(SCHEMA);
        store.user(1, "synthetic prompt");
        let root = tempfile::tempdir().unwrap();
        let link = root.path().join(".local/share/opencode/opencode.db");
        fs::create_dir_all(link.parent().unwrap()).unwrap();
        symlink(&store.source.path, &link).unwrap();
        let linked = Source {
            path: link.clone(),
            ..store.source.clone()
        };
        let under_root = {
            let mut value = options();
            value.root = Some(root.path().to_path_buf());
            value
        };
        assert_eq!(read(&linked, &under_root).err(), Some("non_regular_source"));

        // A linked sidecar is refused too.
        fs::remove_file(&link).unwrap();
        fs::copy(&store.source.path, &link).unwrap();
        let outside = tempfile::tempdir().unwrap();
        let wal = outside.path().join("synthetic-wal");
        fs::write(&wal, b"").unwrap();
        symlink(&wal, link.with_extension("db-wal")).unwrap();
        assert_eq!(read(&linked, &under_root).err(), Some("non_regular_source"));
    }
}
