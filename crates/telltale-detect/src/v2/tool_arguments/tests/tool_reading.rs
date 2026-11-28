//! Pins what detection reads from a tool call by its name and its top-level
//! argument keys, over every key and tool name it knows and one it does not.
//!
//! The pinned digest is of the reading as it was before the argument reading
//! moved into one module (`tool_arguments`). A new digest is a change in what
//! detection reads from a call. To review one, write the reading before and
//! after and compare the two files:
//! `TELLTALE_TOOL_READING_REPORT=<path> cargo test -p telltale-detect --lib
//! tool_reading`. The new reading must keep every fact the old one has.

use super::super::super::tests::written_path::file_tool;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use telltale_schema::observation::ObservationBody;

/// SHA-256 of the reading, and its number of calls.
const PINNED: (&str, usize) = (
    "768bbec76f886b332785072a25db8024f33b9179d00e3c3efc5f66c137cecdbb",
    784,
);

/// Every argument key a vocabulary names, and `note`, which none does.
const KEYS: &[&str] = &[
    "command",
    "cmd",
    "commandLine",
    "command_line",
    "content",
    "contents",
    "new_string",
    "newString",
    "new_str",
    "newText",
    "file_text",
    "new_source",
    "edits",
    "code_edit",
    "old_string",
    "prompt",
    "description",
    "todos",
    "plan",
    "questions",
    "summary",
    "title",
    "message",
    "reason",
    "tldr",
    "caption",
    "activeForm",
    "subject",
    "url",
    "uri",
    "href",
    "endpoint",
    "file_path",
    "filePath",
    "path",
    "paths",
    "notebook_path",
    "absolute_path",
    "target_file",
    "file",
    "filename",
    "glob",
    "pattern",
    "note",
];

/// Every tool name a vocabulary names, in more than one case, and two it does
/// not.
const NAMES: &[&str] = &[
    "write",
    "Write",
    "WRITE",
    "write_file",
    "writefile",
    "WriteFile",
    "create",
    "create_file",
    "edit",
    "Edit",
    "edit_file",
    "multiedit",
    "MultiEdit",
    "multi_edit",
    "notebookedit",
    "NotebookEdit",
    "replace",
    "read",
    "Read",
    "read_file",
    "readfile",
    "view_file",
    "glob",
    "Glob",
    "list",
    "grep",
    "Grep",
    "exec",
    "Exec",
    "multi_tool_use.parallel",
    "Bash",
    "probe",
];

/// The value shapes a key can carry.
fn shapes(key: &str) -> Vec<Value> {
    vec![
        json!(format!("s-{key}")),
        json!([format!("a-{key}"), "b c"]),
        json!([{"new_string": format!("n-{key}")}, {"old_string": "o"}]),
        json!({"new_string": format!("m-{key}")}),
        json!(7),
    ]
}

/// The argument sets whose reading depends on the tool's name or on which
/// other keys the call carries.
fn calls() -> Vec<Value> {
    vec![
        json!({"file_path": "/p/a"}),
        json!({"path": "/p/a", "content": "c"}),
        json!({"absolute_path": "/p/a", "newText": "c"}),
        json!({"filename": "/p/a", "url": "https://example.test/x"}),
        json!({"command": "cat /p/a > /p/b"}),
        json!({"cmd": ["cat", "/p/a"]}),
        json!({"pattern": "*.rs", "path": "/p"}),
        json!({"file_path": "/p/a", "old_string": "o", "new_string": "n"}),
    ]
}

fn line(name: &str, arguments: Value) -> String {
    let observation = file_tool("matrix", name, arguments.clone());
    let ObservationBody::Tool(tool) = observation.body() else {
        unreachable!("a tool observation");
    };
    let urls = super::super::super::tool_arguments::tool_argument_urls(tool, true);
    let written = super::super::super::tool_arguments::tool_written_paths(tool, true);
    format!(
        "{name} {arguments} => {} | urls={urls:?} written={written:?}\n",
        super::super::super::actions::view_facts(&observation)
    )
}

/// A value nested `depth` arrays deep, as raw JSON text.
fn nested(depth: usize) -> String {
    format!("{}1{}", "[".repeat(depth), "]".repeat(depth))
}

fn reading() -> String {
    let mut out = String::new();
    for key in KEYS {
        for shape in shapes(key) {
            let object = json!({ *key: shape });
            // The same members as an object and as the encoded string some
            // native envelopes carry.
            out.push_str(&line("probe", Value::String(object.to_string())));
            out.push_str(&line("probe", object));
        }
        // Members the per-value bounds or the parser's depth limit skip.
        for depth in [40, 200] {
            let encoded = format!(r#"{{"{key}":{},"note":"kept"}}"#, nested(depth));
            out.push_str(&line("probe", Value::String(encoded)));
        }
    }
    for name in NAMES {
        for arguments in calls() {
            out.push_str(&line(name, arguments));
        }
    }
    out
}

#[test]
fn the_reading_of_tool_names_and_argument_keys_is_pinned() {
    let reading = reading();
    if let Some(path) = std::env::var_os("TELLTALE_TOOL_READING_REPORT") {
        std::fs::write(path, &reading).expect("write the report");
    }
    assert_eq!(
        (
            hex::encode(Sha256::digest(reading.as_bytes())).as_str(),
            reading.lines().count()
        ),
        PINNED,
        "the reading of tool calls changed: compare reports"
    );
}
