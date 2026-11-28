//! A tool call's declared operation is read together with the structural
//! reading of its arguments and only adds to it: no fact is lost or repeated,
//! the text already read keeps its bytes, and the replay identity is the one
//! the call has without the declaration.

use super::super::actions::{
    assert_one_reading_matches_two, replay_identity, view_reading, view_readings, view_work,
};
use super::super::selector::{SelectorId, SelectorRegistry};
use super::super::session::RetentionBudget;
use super::super::tool_arguments::{is_file_read_tool, is_file_write_tool};
use super::super::written_path_tests::{declared_tool, file_tool};
use serde_json::{Value, json};
use telltale_schema::observation::{CanonicalObservationV2, JsonValue, ToolKind, ToolOperation};

const NAMES: &[&str] = &[
    "Write",
    "write_file",
    "create",
    "Edit",
    "MultiEdit",
    "NotebookEdit",
    "replace",
    "Read",
    "read_file",
    "view_file",
    "glob",
    "list",
    "Grep",
    "Bash",
    "exec",
    "probe",
];

const FILE_KEYS: &[&str] = &[
    "file_path",
    "filePath",
    "path",
    "notebook_path",
    "absolute_path",
    "target_file",
    "file",
    "filename",
];
const URL_KEYS: &[&str] = &["url", "uri", "href", "endpoint"];

/// Arguments no key of the structural reading names, long enough to hold the
/// operands a test declares.
fn padded() -> Value {
    json!({"target": "x", "pad": "p".repeat(200)})
}

fn deep() -> String {
    format!("{}1{}", "[".repeat(200), "]".repeat(200))
}

/// The call's own text as the arguments carry it, as a table would read it:
/// before the observation's normal form, and without reading an over-deep
/// member.
fn derived(kind: ToolKind, arguments: &Value) -> ToolOperation {
    let decoded = match arguments {
        Value::String(text) => serde_json::from_str::<Value>(text).ok(),
        other => Some(other.clone()),
    };
    let mut operation = ToolOperation::new(kind);
    let Some(Value::Object(members)) = decoded else {
        return operation;
    };
    for (key, value) in &members {
        let strings: Vec<&str> = match value {
            Value::String(text) => vec![text],
            Value::Array(items) => items.iter().filter_map(Value::as_str).collect(),
            _ => Vec::new(),
        };
        if matches!(key.as_str(), "command" | "cmd") {
            if let Some(text) = value.as_str() {
                operation = operation.with_command(text);
            } else if !strings.is_empty() {
                operation = operation.with_command(strings.join(" "));
            }
        } else if FILE_KEYS.contains(&key.as_str()) {
            for path in strings {
                operation = match kind {
                    ToolKind::FileWrite => operation.with_written_path(path),
                    ToolKind::FileRead => operation.with_read_path(path),
                    _ => operation,
                };
            }
        } else if URL_KEYS.contains(&key.as_str()) {
            for url in strings {
                operation = operation.with_url(url);
            }
        }
    }
    operation
}

fn written(observation: &CanonicalObservationV2) -> Vec<String> {
    selected(observation, SelectorId::CompatWrittenPath)
}

fn urls(observation: &CanonicalObservationV2) -> Vec<String> {
    selected(observation, SelectorId::CompatUrl)
}

fn selected(observation: &CanonicalObservationV2, selector: SelectorId) -> Vec<String> {
    let resolution = SelectorRegistry::new()
        .resolve(selector, observation)
        .unwrap();
    match resolution.value() {
        Some(JsonValue::String(text)) if resolution.is_present() => {
            text.lines().map(str::to_owned).collect()
        }
        _ => Vec::new(),
    }
}

/// The declared reading holds the bare reading and nothing twice: every field
/// starts with the bytes it had, what it adds repeats no line it had, the
/// selectors keep their facts, the read flag stays set, and the replay
/// identity is unchanged.
fn assert_only_adds(label: &str, bare: &CanonicalObservationV2, declared: &CanonicalObservationV2) {
    let (bare_fields, bare_reads) = view_reading(bare);
    let (fields, reads) = view_reading(declared);
    for (field, text) in &bare_fields {
        let kept = fields
            .get(field)
            .unwrap_or_else(|| panic!("{label}: lost field {field}"));
        if *field == "command" || *field == "written_path" {
            assert!(
                kept.starts_with(text.as_str()),
                "{label}: {field} changed its bytes: {text:?} vs {kept:?}"
            );
        }
        // Every line the field had is still there, in its order, and what the
        // declaration adds repeats none of them.
        let had: Vec<&str> = text.lines().collect();
        let now: Vec<&str> = kept.lines().collect();
        let mut at = 0;
        for line in &had {
            let found = now[at..]
                .iter()
                .position(|candidate| candidate == line)
                .unwrap_or_else(|| panic!("{label}: {field} lost or reordered {line:?}"));
            at += found + 1;
        }
        let mut remaining = had.clone();
        for line in &now {
            match remaining.iter().position(|candidate| candidate == line) {
                Some(position) => {
                    remaining.remove(position);
                }
                None => assert!(
                    !had.contains(line) || line.trim().is_empty(),
                    "{label}: {field} repeats {line:?}"
                ),
            }
        }
    }
    assert!(reads || !bare_reads, "{label}: lost reads");
    for (before, after) in [
        (written(bare), written(declared)),
        (urls(bare), urls(declared)),
    ] {
        assert!(
            before.iter().all(|fact| after.contains(fact)),
            "{label}: lost a selector fact"
        );
        let mut seen = std::collections::BTreeSet::new();
        assert!(
            after.iter().all(|fact| seen.insert(fact)),
            "{label}: repeats a selector fact"
        );
    }
    assert_eq!(
        replay_identity(bare),
        replay_identity(declared),
        "{label}: replay identity changed"
    );
}

fn calls() -> Vec<Value> {
    let nested = format!(
        r#"{{"command":"cat /p/a","note":"prose","deep":{}}}"#,
        deep()
    );
    vec![
        json!({"file_path": "/p/a"}),
        json!({"path": "/p/a", "content": "c"}),
        json!({"absolute_path": "/p/a", "newText": "c"}),
        json!({"filename": "/p/a", "url": "https://example.test/x"}),
        json!({"command": "cat /p/a > /p/b"}),
        json!({"cmd": ["cat", "/p/a"]}),
        json!({"cmd": ["cat", "/p/a"], "command": "ls /p"}),
        json!({"command": "echo one\necho two"}),
        json!({"pattern": "*.rs", "path": "/p"}),
        json!({"file_path": "/p/e\u{301}", "content": "c"}),
        json!({"note": "n"}),
        json!({"note": "n".repeat(200), "file_path": "/p/a"}),
        json!({"note": "n".repeat(200), "command": "echo hi"}),
        Value::String(json!({"command": "cat /p/a", "file_path": "/p/a"}).to_string()),
        Value::String(nested),
        Value::String(format!(
            r#"{{"command":"echo one\necho two","note":"prose","deep":{}}}"#,
            deep()
        )),
        Value::String("ls /bare".to_owned()),
    ]
}

const ALL_KINDS: [ToolKind; 6] = [
    ToolKind::Shell,
    ToolKind::FileRead,
    ToolKind::FileWrite,
    ToolKind::Web,
    ToolKind::Delegate,
    ToolKind::Other,
];

/// Every call of the matrix as a bare observation and as declared, for each
/// kind the declaration can have and operands read from the arguments and
/// operands that are not in them at all: `(label, bare, declared)`.
fn matrix(
    kinds_for: impl Fn(&str) -> Vec<ToolKind>,
) -> Vec<(String, CanonicalObservationV2, CanonicalObservationV2)> {
    let mut cases = Vec::new();
    for name in NAMES {
        for arguments in calls() {
            let bare = file_tool("bare", name, arguments.clone());
            for kind in kinds_for(name) {
                for operation in [
                    derived(kind, &arguments),
                    derived(kind, &arguments)
                        .with_command("echo declared")
                        .with_written_path("/d/w")
                        .with_read_path("/d/r")
                        .with_url("https://declared.test/x"),
                ] {
                    cases.push((
                        format!("{name} {arguments} {kind:?}"),
                        bare.clone(),
                        declared_tool("bare", name, arguments.clone(), operation),
                    ));
                }
            }
        }
    }
    cases
}

#[test]
fn a_declaration_that_agrees_with_the_name_only_adds_facts() {
    let agreeing = |name: &str| {
        if is_file_write_tool(name) {
            vec![ToolKind::FileWrite]
        } else if is_file_read_tool(name) {
            vec![ToolKind::FileRead]
        } else {
            ALL_KINDS.to_vec()
        }
    };
    for (label, bare, declared) in matrix(agreeing) {
        assert_only_adds(&label, &bare, &declared);
    }
}

/// A call whose declaration cannot add to its reading is read once; the view
/// is what reading it twice gives, for every call, whatever kind it declares.
#[test]
fn reading_a_call_once_when_its_declaration_adds_nothing_gives_the_two_reading_view() {
    for (label, bare, declared) in matrix(|_| ALL_KINDS.to_vec()) {
        assert_one_reading_matches_two(&bare, &label);
        assert_one_reading_matches_two(&declared, &label);
    }
}

#[test]
fn a_declared_call_whose_operands_are_in_its_arguments_is_read_once() {
    let patch = "*** Begin Patch\n*** Add File: /p/new\n+x\n*** End Patch";
    let once = |name: &str, arguments: Value, operation: ToolOperation| {
        let call = declared_tool("bare", name, arguments, operation);
        view_readings(&call)
    };
    assert_eq!(
        view_readings(&file_tool("bare", "Bash", json!({"command": "ls"}))),
        1
    );
    for (name, arguments, operation) in [
        (
            "Bash",
            json!({"command": "cargo test --workspace"}),
            ToolOperation::new(ToolKind::Shell).with_command("cargo test --workspace"),
        ),
        (
            "shell",
            json!({"command": ["cat", "/p/a"]}),
            ToolOperation::new(ToolKind::Shell).with_command("cat /p/a"),
        ),
        (
            "Read",
            json!({"file_path": "/p/a"}),
            ToolOperation::new(ToolKind::FileRead).with_read_path("/p/a"),
        ),
        (
            "Write",
            json!({"file_path": "/p/a", "content": "c"}),
            ToolOperation::new(ToolKind::FileWrite).with_written_path("/p/a"),
        ),
        (
            "WebFetch",
            json!({"url": "https://example.test/x"}),
            ToolOperation::new(ToolKind::Web).with_url("https://example.test/x"),
        ),
        (
            "Task",
            json!({"prompt": "p"}),
            ToolOperation::new(ToolKind::Delegate),
        ),
    ] {
        assert_eq!(
            once(name, arguments.clone(), operation),
            1,
            "{name} {arguments}"
        );
    }
    // What the declaration can add, or a kind the name does not give, is read
    // a second time.
    for (name, arguments, operation) in [
        (
            "Bash",
            json!({"command": "ls"}),
            ToolOperation::new(ToolKind::Shell).with_command("echo declared"),
        ),
        (
            "Read",
            json!({"file_path": "/p/a"}),
            ToolOperation::new(ToolKind::FileRead).with_read_path("/p/other"),
        ),
        (
            "Write",
            json!({"file_path": "/p/a", "content": "c"}),
            ToolOperation::new(ToolKind::FileWrite).with_written_path("/p/other"),
        ),
        (
            "WebFetch",
            json!({"url": "https://example.test/x"}),
            ToolOperation::new(ToolKind::Web).with_url("https://example.test/other"),
        ),
        (
            "apply_patch",
            Value::String(patch.to_owned()),
            ToolOperation::new(ToolKind::FileWrite).with_written_path("/p/new"),
        ),
        (
            "novel_tool",
            json!({"file_path": "/p/a"}),
            ToolOperation::new(ToolKind::FileRead),
        ),
        (
            "novel_tool",
            json!({"file_path": "/p/a", "content": "c"}),
            ToolOperation::new(ToolKind::FileWrite),
        ),
    ] {
        assert_eq!(
            once(name, arguments.clone(), operation),
            2,
            "{name} {arguments}"
        );
    }
}

#[test]
fn a_declaration_adds_operands_the_arguments_do_not_name_by_key() {
    let bare = file_tool("bare", "novel_tool", padded());
    let (fields, reads) = view_reading(&bare);
    assert!(!reads && !fields.contains_key("written_path"));

    let operation = ToolOperation::new(ToolKind::FileWrite)
        .with_written_path("/d/w")
        .with_url("https://declared.test/x")
        .with_command("echo declared");
    let declared = declared_tool("bare", "novel_tool", padded(), operation);
    let (fields, _) = view_reading(&declared);
    assert_eq!(fields["written_path"], "/d/w");
    assert!(fields["file_path"].lines().any(|path| path == "/d/w"));
    assert!(
        fields["url"]
            .lines()
            .any(|url| url == "https://declared.test/x")
    );
    assert!(
        fields["command"]
            .lines()
            .any(|line| line == "echo declared")
    );
    assert_eq!(written(&declared), ["/d/w"]);
    assert_eq!(urls(&declared), ["https://declared.test/x"]);
    assert_only_adds("novel", &bare, &declared);

    // A declared read tool reads the files it is given, whatever its name.
    let reader = ToolOperation::new(ToolKind::FileRead).with_read_path("/d/r");
    let declared = declared_tool("bare", "novel_reader", padded(), reader);
    let (fields, reads) = view_reading(&declared);
    assert!(reads);
    assert!(fields["file_path"].lines().any(|path| path == "/d/r"));

    // A declared tool of any other kind does not read what it names.
    let other = ToolOperation::new(ToolKind::Other).with_read_path("/d/r");
    let declared = declared_tool("bare", "novel_search", padded(), other);
    assert!(!view_reading(&declared).1);
}

#[test]
fn a_path_in_two_unicode_forms_is_one_fact() {
    let nfd = "/p/e\u{301}";
    let bare = file_tool("bare", "Write", json!({"file_path": nfd, "content": "c"}));
    let declared = declared_tool(
        "bare",
        "Write",
        json!({"file_path": nfd, "content": "c"}),
        ToolOperation::new(ToolKind::FileWrite).with_written_path(nfd),
    );
    assert_eq!(view_reading(&bare).0, view_reading(&declared).0);
    assert_eq!(written(&declared), ["/p/\u{e9}"]);
}

#[test]
fn a_command_the_text_already_holds_is_not_read_twice() {
    for (arguments, command) in [
        (
            json!({"cmd": ["cat", "/p/a"], "command": "ls /p"}),
            "cat /p/a",
        ),
        (json!({"cmd": ["cat", "/p/a"], "command": "ls /p"}), "ls /p"),
        (
            json!({"command": "echo one\necho two"}),
            "echo one\necho two",
        ),
        (
            Value::String(format!(
                r#"{{"command":"echo one\necho two","deep":{}}}"#,
                deep()
            )),
            "echo one\necho two",
        ),
    ] {
        let bare = file_tool("bare", "novel_shell", arguments.clone());
        let declared = declared_tool(
            "bare",
            "novel_shell",
            arguments.clone(),
            ToolOperation::new(ToolKind::Shell).with_command(command),
        );
        assert_eq!(
            view_reading(&bare).0,
            view_reading(&declared).0,
            "{arguments} {command:?}"
        );
    }
}

/// The replay identity of a call that a source declares is the identity it has
/// without the declaration, for the calls whose declaration adds the most.
#[test]
fn declared_calls_keep_the_replay_identity_of_their_bare_form() {
    let patch = "*** Begin Patch\n*** Add File: /p/new\n+x\n*** End Patch";
    for (name, arguments, operation) in [
        (
            "apply_patch",
            Value::String(patch.to_owned()),
            ToolOperation::new(ToolKind::FileWrite).with_written_path("/p/new"),
        ),
        (
            "read_file",
            json!({"absolute_path": "/p/a"}),
            ToolOperation::new(ToolKind::FileRead).with_read_path("/p/a"),
        ),
        (
            "patch",
            json!({"patchText": patch}),
            ToolOperation::new(ToolKind::FileWrite).with_written_path("/p/new"),
        ),
    ] {
        let bare = file_tool("bare", name, arguments.clone());
        let declared = declared_tool("bare", name, arguments, operation);
        assert!(view_reading(&declared).0 != view_reading(&bare).0 || name == "patch");
        assert!(replay_identity(&bare).is_some());
        assert_eq!(replay_identity(&bare), replay_identity(&declared), "{name}");
    }
}

/// The work a declaration adds is not charged to the source's budget: a source
/// whose calls just fit without declarations still fits with them, and the
/// reading keeps what the declaration added.
#[test]
fn a_declaration_spends_none_of_the_budget_a_bare_call_would_have_had() {
    let arguments = json!({"target": "x", "pad": "p".repeat(200)});
    let bare = file_tool("bare", "novel_shell", arguments.clone());
    let declared = declared_tool(
        "bare",
        "novel_shell",
        arguments,
        ToolOperation::new(ToolKind::Shell).with_command("echo declared"),
    );
    let bound = RetentionBudget::new().bounds.work;
    let (spent, bare_fields) = view_work(&bare, 0).expect("a bare call fits");
    let (used, fields) = view_work(&declared, bound - spent).expect("a declared call still fits");
    assert_eq!(used, bound, "the declaration charged the budget");
    assert!(!bare_fields.contains_key("command"));
    assert!(fields["command"].contains("echo declared"));
    // One byte short for the bare call fails it, declared or not.
    assert!(view_work(&declared, bound - spent + 1).is_none());
}
