//! `telltale investigate transcript` through the real binary. Stores are
//! synthetic; failures name a field, never record text.

use super::*;

const SECRET_TAIL: &str = "Zq3Wt9LmP2kR7vX4nB8cY1dF6hJ0sA5uE3iO";
const RESULT_MARKER: &str = "synthetic-result-body";

fn claude_store(root: &Path) -> std::path::PathBuf {
    let lines = [
        serde_json::json!({"type":"user","sessionId":"synthetic-cli","uuid":"u1","timestamp":"2026-11-20T10:00:01Z","message":{"role":"user","content":format!("deploy with token ghp_{SECRET_TAIL}")}}),
        serde_json::json!({"type":"assistant","sessionId":"synthetic-cli","uuid":"a1","timestamp":"2026-11-20T10:00:02Z","message":{"role":"assistant","content":[{"type":"text","text":"synthetic answer"},{"type":"tool_use","id":"toolu_1","name":"Bash","input":{"command":"echo synthetic"}}]}}),
        serde_json::json!({"type":"user","sessionId":"synthetic-cli","uuid":"r1","timestamp":"2026-11-20T10:00:03Z","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":RESULT_MARKER}]}}),
        serde_json::json!({"type":"user","sessionId":"synthetic-cli","uuid":"u2","timestamp":"2026-11-20T10:00:04Z","message":{"role":"user","content":"synthetic follow-up"}}),
    ];
    let path = root.join(".claude/projects/synthetic/session.jsonl");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(
        &path,
        lines
            .iter()
            .map(|line| format!("{line}\n"))
            .collect::<String>(),
    )
    .unwrap();
    path
}

fn transcript(source: &Path, extra: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["investigate", "transcript", "--source"])
        .arg(source)
        .args(["--client", "claude", "--source-id", "claude.projects"])
        .args(extra)
        .output()
        .unwrap()
}

fn lines(output: &std::process::Output) -> Vec<Value> {
    String::from_utf8(output.stdout.clone())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

#[test]
fn transcript_exports_a_complete_redacted_page() {
    let temp = tempdir().unwrap();
    let store = claude_store(temp.path());
    let output = transcript(&store, &[]);
    assert!(output.status.success(), "status");
    let records = lines(&output);
    let kinds: Vec<&str> = records
        .iter()
        .map(|record| record["kind"].as_str().unwrap())
        .collect();
    assert_eq!(
        kinds,
        [
            "user_message",
            "assistant_message",
            "tool_call",
            "user_message"
        ]
    );
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    assert!(!stdout.contains(SECRET_TAIL), "stdout: secret");
    assert!(!stdout.contains(RESULT_MARKER), "stdout: result body");
    assert!(
        records
            .iter()
            .all(|record| record["session_id"] == "synthetic-cli"),
        "session_id"
    );
    assert!(
        records.iter().all(|record| record["imported"] == false),
        "imported flag"
    );
    assert!(
        stderr(&output).contains("complete: 4 records"),
        "stderr: status"
    );

    // Tool results are opt-in.
    let output = transcript(&store, &["--include-tool-results"]);
    assert!(output.status.success(), "status with results");
    let records = lines(&output);
    assert!(
        records.iter().any(|record| record["kind"] == "tool_result"
            && record["text"].as_str().unwrap().contains(RESULT_MARKER)),
        "result present when enabled"
    );
}

#[test]
fn transcript_pages_name_their_continuation() {
    let temp = tempdir().unwrap();
    let store = claude_store(temp.path());
    let mut extra = vec!["--max-records".to_owned(), "3".to_owned()];
    let first = transcript(
        &store,
        &extra.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    assert!(first.status.success(), "first status");
    assert_eq!(lines(&first).len(), 3);
    let status = stderr(&first);
    let continuation = status
        .split("continue with ")
        .nth(1)
        .expect("continuation named")
        .split_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    assert_eq!(continuation[0], "--after-ordinal");
    assert_eq!(continuation[2], "--after-key");
    extra.extend(continuation);
    let second = transcript(
        &store,
        &extra.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    assert!(second.status.success(), "second status");
    let records = lines(&second);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["text"], "synthetic follow-up");
    assert!(
        stderr(&second).contains("complete: 1 records"),
        "second status line"
    );

    // The JSON page document carries the same cursor.
    let json = transcript(&store, &["--max-records", "3", "--json"]);
    assert!(json.status.success(), "json status");
    let document: Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(document["has_more"], true);
    assert_eq!(document["records"].as_array().unwrap().len(), 3);
    assert_eq!(
        document["next_after_ordinal"],
        document["records"][2]["ordinal"]
    );
    assert_eq!(
        document["next_after_record_key"],
        document["records"][2]["record_key"]
    );

    // A changed cursor record fails with its closed code.
    let changed = transcript(
        &store,
        &[
            "--after-ordinal",
            "0",
            "--after-key",
            "rec:v1:sha256:0000000000000000000000000000000000000000000000000000000000000000",
        ],
    );
    assert_eq!(changed.status.code(), Some(1));
    assert!(
        stderr(&changed).contains("session_record_cursor_changed"),
        "cursor code"
    );
}

#[cfg(unix)]
#[test]
fn transcript_refuses_a_link_under_the_root_with_its_code() {
    let temp = tempdir().unwrap();
    let root = temp.path().join("root");
    let outside = temp.path().join("synthetic-outside");
    let target = claude_store(&outside);
    let link = root.join(".claude/projects/synthetic/linked.jsonl");
    fs::create_dir_all(link.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["investigate", "transcript", "--root"])
        .arg(&root)
        .arg("--source")
        .arg(&link)
        .args(["--client", "claude", "--source-id", "claude.projects"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty(), "stdout");
    let message = stderr(&output);
    assert!(message.contains("non_regular_source"), "code");
    assert!(!message.contains("synthetic-outside"), "stderr: path");

    // A missing source fails with its code too.
    let output = transcript(&root.join("synthetic-missing.jsonl"), &[]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("source_missing"), "missing code");
}

#[test]
fn transcript_finds_the_session_under_a_root() {
    let temp = tempdir().unwrap();
    claude_store(temp.path());
    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["investigate", "transcript", "--root"])
        .arg(temp.path())
        .args(["--session", "synthetic-cli", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "status");
    let document: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["source_id"], "claude.projects");
    assert_eq!(document["has_more"], false);
    assert_eq!(document["records"].as_array().unwrap().len(), 4);

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["investigate", "transcript", "--root"])
        .arg(temp.path())
        .args(["--session", "synthetic-absent"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
}
