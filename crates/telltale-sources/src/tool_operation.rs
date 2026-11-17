//! Declared tool operations: what a source's own tool table says a call does.
//!
//! Each source module keeps one table of the built-in tools of its harness: a
//! tool name, its kind in the shared vocabulary (decision O7) and where the
//! operands sit in the arguments. Tool names and argument keys therefore live
//! with the source that knows them. This module holds only the neutral reading
//! those tables share: top-level argument members, argv arrays and the
//! `*** Begin Patch` patch format.
//!
//! A declaration only adds to what detection reads from the arguments by
//! shape; it never replaces that reading. A tool missing from a table is left
//! undeclared, and so is a call whose arguments hold no operand.

use std::collections::BTreeMap;

use telltale_schema::observation::{JsonValue, ToolKind, ToolObservation, ToolOperation};

/// One built-in tool of one harness.
pub(crate) struct ToolSpec {
    name: &'static str,
    kind: ToolKind,
    /// Argument keys holding the command: a string, or an argv array.
    commands: &'static [&'static str],
    /// Argument keys naming one file the call writes.
    written: &'static [&'static str],
    /// Argument keys naming files or directories the call reads or searches.
    read: &'static [&'static str],
    /// Argument keys holding destination URLs.
    urls: &'static [&'static str],
    /// A patch tool: the argument keys that hold its patch text. The whole
    /// argument string is a patch as well when the call carries no object.
    patch: Option<&'static [&'static str]>,
}

impl ToolSpec {
    pub(crate) const fn new(name: &'static str, kind: ToolKind) -> Self {
        Self {
            name,
            kind,
            commands: &[],
            written: &[],
            read: &[],
            urls: &[],
            patch: None,
        }
    }

    pub(crate) const fn commands(mut self, keys: &'static [&'static str]) -> Self {
        self.commands = keys;
        self
    }

    pub(crate) const fn written(mut self, keys: &'static [&'static str]) -> Self {
        self.written = keys;
        self
    }

    pub(crate) const fn read(mut self, keys: &'static [&'static str]) -> Self {
        self.read = keys;
        self
    }

    pub(crate) const fn urls(mut self, keys: &'static [&'static str]) -> Self {
        self.urls = keys;
        self
    }

    pub(crate) const fn patch(mut self, keys: &'static [&'static str]) -> Self {
        self.patch = Some(keys);
        self
    }

    pub(crate) fn name(&self) -> &'static str {
        self.name
    }

    pub(crate) fn kind(&self) -> ToolKind {
        self.kind
    }

    fn operation(&self, arguments: Option<&JsonValue>) -> ToolOperation {
        let members = Members::of(arguments);
        let mut operation = ToolOperation::new(self.kind);
        for key in self.commands {
            if let Some(command) = members.command(key) {
                operation = operation.with_command(command);
            }
        }
        for key in self.written {
            for path in members.strings(key) {
                operation = operation.with_written_path(path);
            }
        }
        for key in self.read {
            for path in members.strings(key) {
                operation = operation.with_read_path(path);
            }
        }
        for key in self.urls {
            for url in members.strings(key) {
                operation = operation.with_url(url);
            }
        }
        if let Some(keys) = self.patch {
            let texts = keys
                .iter()
                .filter_map(|key| members.text(key))
                .chain(members.raw().map(str::to_owned));
            for text in texts {
                for path in patch_targets(&text) {
                    operation = operation.with_written_path(path);
                }
            }
        }
        operation
    }
}

/// Declare the operation a source's table gives a tool call: the tool's row,
/// read against the arguments already on the body. A tool with no row stays
/// undeclared.
pub(crate) fn declare(table: &[ToolSpec], body: ToolObservation) -> ToolObservation {
    let operation = body
        .name()
        .and_then(|name| table.iter().find(|spec| spec.name == name))
        .map(|spec| spec.operation(body.arguments()));
    match operation {
        Some(operation) => body.with_operation(operation),
        None => body,
    }
}

/// The top-level members of a call's arguments: an object, the JSON-encoded
/// object some native envelopes carry as a string, or plain text.
enum Members<'a> {
    None,
    Object(&'a BTreeMap<String, JsonValue>),
    /// An encoded object. Each member stays raw JSON until a table asks for it,
    /// so a member nested past the parser's depth limit hides no other member
    /// and its text is never read as an operand.
    Decoded(BTreeMap<String, Box<serde_json::value::RawValue>>),
    /// Text that is not a JSON object at all.
    Raw(&'a str),
}

impl<'a> Members<'a> {
    fn of(arguments: Option<&'a JsonValue>) -> Self {
        match arguments {
            Some(JsonValue::Object(members)) => Self::Object(members),
            Some(JsonValue::String(text)) => {
                let decoded = text
                    .trim_start()
                    .starts_with('{')
                    .then(|| serde_json::from_str(text).ok())
                    .flatten();
                decoded.map_or(Self::Raw(text), Self::Decoded)
            }
            _ => Self::None,
        }
    }

    /// The decoded value of an encoded member; one nested too deep has none.
    fn decoded(&self, key: &str) -> Option<serde_json::Value> {
        match self {
            Self::Decoded(members) => serde_json::from_str(members.get(key)?.get()).ok(),
            _ => None,
        }
    }

    /// The text of an argument that is one string.
    fn text(&self, key: &str) -> Option<String> {
        match self {
            Self::Object(members) => match members.get(key) {
                Some(JsonValue::String(text)) => Some(text.clone()),
                _ => None,
            },
            Self::Decoded(_) => match self.decoded(key) {
                Some(serde_json::Value::String(text)) => Some(text),
                _ => None,
            },
            Self::None | Self::Raw(_) => None,
        }
    }

    /// The whole argument text of a call that carries no object.
    fn raw(&self) -> Option<&str> {
        match self {
            Self::Raw(text) => Some(text),
            _ => None,
        }
    }

    /// The strings of an argument that is a string or an array of them.
    fn strings(&self, key: &str) -> Vec<String> {
        match self {
            Self::Object(members) => match members.get(key) {
                Some(JsonValue::String(text)) => vec![text.clone()],
                Some(JsonValue::Array(items)) => items
                    .iter()
                    .filter_map(|item| match item {
                        JsonValue::String(text) => Some(text.clone()),
                        _ => None,
                    })
                    .collect(),
                _ => Vec::new(),
            },
            Self::Decoded(_) => match self.decoded(key) {
                Some(serde_json::Value::String(text)) => vec![text],
                Some(serde_json::Value::Array(items)) => items
                    .into_iter()
                    .filter_map(|item| match item {
                        serde_json::Value::String(text) => Some(text),
                        _ => None,
                    })
                    .collect(),
                _ => Vec::new(),
            },
            Self::None | Self::Raw(_) => Vec::new(),
        }
    }

    /// A command: one string, an argv array joined by spaces, or the whole
    /// argument text of a call that carries no object.
    fn command(&self, key: &str) -> Option<String> {
        match self {
            Self::Raw(text) => Some((*text).to_owned()),
            _ => self.text(key).or_else(|| {
                let argv = self.strings(key);
                (!argv.is_empty()).then(|| argv.join(" "))
            }),
        }
    }
}

/// File-operation headers of the `*** Begin Patch` format. `Move to` names the
/// new path of an updated file.
const PATCH_HEADERS: &[&str] = &[
    "*** Add File: ",
    "*** Update File: ",
    "*** Delete File: ",
    "*** Move to: ",
];

/// The files a patch in the `*** Begin Patch` format names. Only a header at
/// the start of a line counts, so content lines, which start with a space, `+`
/// or `-`, never do. Text without the `*** Begin Patch` line names nothing.
fn patch_targets(text: &str) -> Vec<String> {
    if !text.lines().any(|line| line.trim() == "*** Begin Patch") {
        return Vec::new();
    }
    text.lines()
        .filter_map(|line| {
            let line = line.trim_end_matches('\r');
            PATCH_HEADERS
                .iter()
                .find_map(|header| line.strip_prefix(header))
        })
        .map(|path| path.trim().to_owned())
        .filter(|path| !path.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sources::{claude, codex, copilot, openclaw, opencode, qwen};

    fn tool(name: &str, arguments: serde_json::Value) -> ToolObservation {
        ToolObservation::new()
            .with_name(name)
            .unwrap()
            .with_arguments(JsonValue::try_from_source_value(&arguments).unwrap())
    }

    fn declared(table: &[ToolSpec], body: ToolObservation) -> ToolOperation {
        declare(table, body).operation().cloned().expect("declared")
    }

    #[test]
    fn a_tool_with_no_row_stays_undeclared() {
        let body = declare(
            claude::tools::TOOLS,
            tool("NoSuchTool", serde_json::json!({"file_path": "/p/a"})),
        );
        assert!(body.operation().is_none());
        let body = declare(claude::tools::TOOLS, ToolObservation::new());
        assert!(body.operation().is_none());
    }

    #[test]
    fn operands_come_from_objects_encoded_objects_argv_and_plain_text() {
        let table = &[
            ToolSpec::new("run", ToolKind::Shell).commands(&["cmd", "command"]),
            ToolSpec::new("save", ToolKind::FileWrite).written(&["path"]),
            ToolSpec::new("look", ToolKind::FileRead).read(&["paths"]),
            ToolSpec::new("fetch", ToolKind::Web).urls(&["url"]),
        ];
        let operation = declared(table, tool("run", serde_json::json!({"cmd": "ls /p"})));
        assert_eq!(operation.kind(), ToolKind::Shell);
        assert_eq!(operation.commands(), ["ls /p"]);
        let operation = declared(
            table,
            tool("run", serde_json::json!({"command": ["cat", "/p/a"]})),
        );
        assert_eq!(operation.commands(), ["cat /p/a"]);
        let encoded = serde_json::json!({"command": "ls"}).to_string();
        let operation = declared(table, tool("run", serde_json::Value::String(encoded)));
        assert_eq!(operation.commands(), ["ls"]);
        let operation = declared(table, tool("run", serde_json::json!("ls /bare")));
        assert_eq!(operation.commands(), ["ls /bare"]);
        let operation = declared(table, tool("save", serde_json::json!({"path": "/p/a"})));
        assert_eq!(operation.written_paths(), ["/p/a"]);
        let operation = declared(
            table,
            tool("look", serde_json::json!({"paths": ["/p/a", "/p/b"]})),
        );
        assert_eq!(operation.read_paths(), ["/p/a", "/p/b"]);
        let operation = declared(
            table,
            tool(
                "fetch",
                serde_json::json!({"url": "https://example.test/x"}),
            ),
        );
        assert_eq!(operation.urls(), ["https://example.test/x"]);
        // The kind is declared even when the call holds no operand.
        let operation = declared(table, tool("save", serde_json::json!({"other": 1})));
        assert_eq!(operation.kind(), ToolKind::FileWrite);
        assert!(operation.written_paths().is_empty());
    }

    #[test]
    fn patch_tools_name_their_files_from_headers_only() {
        let table = &[ToolSpec::new("patch", ToolKind::FileWrite).patch(&["patchText"])];
        let text = "*** Begin Patch\n*** Add File: /p/new\n+*** Update File: /p/not-a-header\n*** Update File: /p/old\n*** Move to: /p/moved\n*** Delete File: /p/gone\n*** End Patch";
        let expected = ["/p/new", "/p/old", "/p/moved", "/p/gone"];
        for arguments in [
            serde_json::json!({"patchText": text}),
            serde_json::json!(text),
            serde_json::Value::String(serde_json::json!({"patchText": text}).to_string()),
        ] {
            let operation = declared(table, tool("patch", arguments));
            assert_eq!(operation.written_paths(), expected);
        }
        let operation = declared(
            table,
            tool(
                "patch",
                serde_json::json!({"patchText": "*** Add File: /p/x"}),
            ),
        );
        assert!(operation.written_paths().is_empty());
    }

    #[test]
    fn an_over_deep_member_hides_no_other_member_and_adds_no_command() {
        let table = &[ToolSpec::new("run", ToolKind::Shell).commands(&["command"])];
        let deep = format!("{}1{}", "[".repeat(200), "]".repeat(200));
        let encoded = format!(r#"{{"command":"ls /p","prose":"not a command","deep":{deep}}}"#);
        let operation = declared(table, tool("run", serde_json::Value::String(encoded)));
        assert_eq!(operation.commands(), ["ls /p"]);
        // An over-deep member under a key the table reads has no operand.
        let encoded = format!(r#"{{"command":{deep},"prose":"not a command"}}"#);
        let operation = declared(table, tool("run", serde_json::Value::String(encoded)));
        assert!(operation.commands().is_empty());
        // Only text that is no JSON object at all is a bare command.
        let operation = declared(table, tool("run", serde_json::json!("{not json")));
        assert_eq!(operation.commands(), ["{not json"]);
    }

    #[test]
    fn no_table_lists_a_tool_twice() {
        let tables: &[(&str, &[ToolSpec])] = &[
            ("claude", claude::tools::TOOLS),
            ("codex", codex::tools::TOOLS),
            ("copilot", copilot::tools::TOOLS),
            ("openclaw", openclaw::tools::TOOLS),
            ("opencode", opencode::tools::TOOLS),
            ("qwen", qwen::tools::TOOLS),
        ];
        for &(source, table) in tables {
            let mut names = std::collections::BTreeSet::new();
            for spec in table {
                assert!(
                    names.insert(spec.name()),
                    "{source} lists {} twice",
                    spec.name()
                );
            }
        }
    }
}
