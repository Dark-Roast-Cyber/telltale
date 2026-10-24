//! Synthetic shell calls through the native adapters, without executing commands.
use rusqlite::{Connection, params};
use serde_json::json;
use std::fs;
use telltale_core::Pipeline;
use telltale_schema::{
    clients::{ClientId, SourceKind},
    source::Source,
};

#[test]
fn shell_execution_credit_matches_codex_recording_shapes() {
    let temp = tempfile::tempdir().unwrap();
    let pipeline = Pipeline::builder()
        .without_community_rules()
        .build()
        .unwrap();
    let command = "systemctl --user enable synthetic-preview.service";
    for (name, arguments) in [
        ("shell", json!({"command":["bash", "-lc", command]})),
        ("exec_command", json!({"cmd":command})),
    ] {
        let path = temp.path().join(format!("{name}.jsonl"));
        fs::write(&path, [
            json!({"type":"session_meta","payload":{"id":"synthetic-shell"}}),
            json!({"type":"response_item","payload":{"type":"function_call","name":name,"call_id":"call-1","arguments":arguments.to_string()}}),
            json!({"type":"response_item","payload":{"type":"function_call_output","call_id":"call-1","output":"exec command rejected by user"}}),
        ].iter().map(ToString::to_string).collect::<Vec<_>>().join("\n")).unwrap();
        assert_credit(
            &pipeline,
            Source {
                client: ClientId::Codex,
                source_id: "codex.sessions".into(),
                kind: SourceKind::Jsonl,
                path,
            },
        );
    }
}

#[test]
fn shell_execution_credit_matches_opencode_v2_recording_shapes() {
    let temp = tempfile::tempdir().unwrap();
    let pipeline = Pipeline::builder()
        .without_community_rules()
        .build()
        .unwrap();
    let command = "systemctl --user enable synthetic-preview.service";
    // Minimal columns read by the v2 adapter; content follows the pinned v2 case.
    for name in ["bash", "shell"] {
        let path = temp.path().join(format!("{name}.db"));
        let db = Connection::open(&path).unwrap();
        db.execute_batch("CREATE TABLE session_v2 (id TEXT PRIMARY KEY, agent TEXT, model TEXT);
            INSERT INTO session_v2 VALUES ('synthetic-shell', 'build', NULL);
            CREATE TABLE session_message (id TEXT PRIMARY KEY, session_id TEXT, type TEXT, seq INTEGER, time_created INTEGER, time_updated INTEGER, data TEXT);").unwrap();
        db.execute("INSERT INTO session_message VALUES ('message-1', 'synthetic-shell', 'assistant', 1, 1775000000000, 1775000000001, ?1)", params![json!({
            "agent":"build", "time":{"created":1775000000000_i64},
            "content":[{"type":"tool","id":"call-1","name":name,"executed":false,
                "state":{"status":"error","input":{"command":command},"error":{"type":"Denied","message":"exec command rejected by user"}},
                "time":{"created":1775000000000_i64,"completed":1775000000001_i64}}]
        }).to_string()]).unwrap();
        drop(db);
        assert_credit(
            &pipeline,
            Source {
                client: ClientId::OpenCode,
                source_id: "opencode.sqlite".into(),
                kind: SourceKind::Sqlite,
                path,
            },
        );
    }
}

#[test]
fn long_native_shell_histories_keep_late_detections() {
    let temp = tempfile::tempdir().unwrap();
    let pipeline = Pipeline::builder()
        .without_community_rules()
        .build()
        .unwrap();
    let command = |index| {
        if index == 4000 {
            "systemctl --user enable synthetic-preview.service"
        } else {
            "echo ordinary"
        }
    };
    for name in ["shell", "exec_command", "Bash"] {
        let path = temp.path().join(format!("long-{name}.jsonl"));
        let mut records = vec![json!({"type":"session_meta","payload":{"id":"synthetic-shell"}})];
        for index in 0..4001 {
            let arguments = if name == "shell" {
                json!({"command":["bash","-lc",command(index)]})
            } else {
                json!({"cmd":command(index)})
            };
            records.push(if name == "Bash" {
                json!({"type":"assistant","sessionId":"synthetic-shell","message":{"role":"assistant","content":[{"type":"tool_use","id":format!("call-{index}"),"name":"Bash","input":{"command":command(index)}}]}})
            } else {
                json!({"type":"response_item","payload":{"type":"function_call","name":name,"call_id":format!("call-{index}"),"arguments":arguments.to_string()}})
            });
        }
        // Claude uses its own envelope, not Codex session metadata.
        if name == "Bash" {
            records.remove(0);
        }
        fs::write(
            &path,
            records
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n"),
        )
        .unwrap();
        assert_credit(
            &pipeline,
            Source {
                client: if name == "Bash" {
                    ClientId::Claude
                } else {
                    ClientId::Codex
                },
                source_id: if name == "Bash" {
                    "claude.projects"
                } else {
                    "codex.sessions"
                }
                .into(),
                kind: SourceKind::Jsonl,
                path,
            },
        );
    }
    let path = temp.path().join("long-opencode.db");
    let mut db = Connection::open(&path).unwrap();
    db.execute_batch("CREATE TABLE session_v2 (id TEXT PRIMARY KEY, agent TEXT, model TEXT);
        INSERT INTO session_v2 VALUES ('synthetic-shell', 'build', NULL);
        CREATE TABLE session_message (id TEXT PRIMARY KEY, session_id TEXT, type TEXT, seq INTEGER, time_created INTEGER, time_updated INTEGER, data TEXT);").unwrap();
    let transaction = db.transaction().unwrap();
    for index in 0..4001 {
        transaction.execute("INSERT INTO session_message VALUES (?1, 'synthetic-shell', 'assistant', ?2, 1775000000000, 1775000000001, ?3)", params![format!("message-{index}"), index, json!({
            "agent":"build", "time":{"created":1775000000000_i64},
            "content":[{"type":"tool","id":format!("call-{index}"),"name":"shell",
                "state":{"status":"running","input":{"command":command(index)}},
                "time":{"created":1775000000000_i64}}]
        }).to_string()]).unwrap();
    }
    transaction.commit().unwrap();
    drop(db);
    assert_credit(
        &pipeline,
        Source {
            client: ClientId::OpenCode,
            source_id: "opencode.sqlite".into(),
            kind: SourceKind::Sqlite,
            path,
        },
    );
}

fn assert_credit(pipeline: &Pipeline, source: Source) {
    let batch = telltale_sources::acquisition::acquire_source(
        &source,
        telltale_sources::acquisition::AcquisitionOptions::new(
            telltale_schema::observation::ObservedAt::new("2026-10-13T12:00:00Z").unwrap(),
        ),
    )
    .unwrap();
    assert!(batch.quarantined.is_empty());
    assert!(!batch.observations.is_empty());
    let scan = pipeline
        .scan_sources_with_occurrences(std::slice::from_ref(&source))
        .unwrap()
        .remove(0);
    let detection = scan
        .events
        .iter()
        .find(|e| e.event_type == "detection")
        .unwrap();
    assert_eq!(
        detection.rule_ids,
        ["execution.shell", "persistence.shell_profile"],
        "{}",
        source.path.display()
    );
    assert_eq!(detection.risk_score, 60);
    assert_eq!(detection.severity, "medium");
    assert_eq!(
        detection
            .risk_contributions
            .iter()
            .filter(|c| c.id() == "execution.shell")
            .count(),
        1
    );
}
