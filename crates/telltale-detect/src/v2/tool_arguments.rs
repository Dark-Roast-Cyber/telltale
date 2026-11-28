//! The structural reading of a tool call: what its arguments say by their
//! keys and shape, whatever harness sent the call.
//!
//! The session selectors and the action view both read a call through this
//! module, so they agree on its facts. Nothing here knows a harness except the
//! three tool-name lists ([`is_file_write_tool`], [`is_file_read_tool`],
//! [`is_shell_tool`]).
//!
//! A source declares the operation of each built-in tool it knows: a kind,
//! operands and, for a few arguments, a role (`ToolObservation::operation`).
//! That declaration is read together with the structural reading. Operands only
//! add to it. A role replaces the reading of one named argument: its text is
//! authored content, or replaced text that is no action fact, instead of what
//! its key says. A patch is authored content, so its lines are no command text.
//! Only the keys the declaration names change, and no other call or key
//! reads differently. The name lists remain as the fallback for a call with no
//! declaration: a tool the source's table does not name, and observations a
//! host supplies or imports. A hooks journal window is read with the tool table
//! of the client whose hooks wrote it. A declared call takes its kind from the
//! declaration and not from its name.
//!
//! A call with roles reads as its Claude Code `Write` or `Edit` equivalent in
//! both consumers. The action view reads the members by role
//! ([`ArgumentReading::declared`]). The session selectors have no argument text
//! to read for such a call ([`reads_by_role`]: `compat.v1.arguments`,
//! `tool.arguments.text` and the process-chain command lines), and no command
//! facet where the member it came from has a role ([`command_member_has_role`]).
//! For the Claude Code call, whose arguments are an object, those selectors have
//! no text either. The typed `tool.arguments` and `tool.searchable_arguments`
//! selectors, which return the arguments as reported, and the action view's
//! authored content are unchanged and still see the text.
//!
//! `tests::tool_reading` pins the reading of every key and name below for calls
//! with no declaration.

use std::borrow::Cow;
use std::collections::BTreeMap;

use telltale_schema::observation::{JsonValue, ToolKind, ToolObservation, ToolOperation};

/// Top-level tool argument keys whose string values are destination URLs.
pub(crate) fn is_url_argument_key(key: &str) -> bool {
    matches!(key, "url" | "uri" | "href" | "endpoint")
}

/// URL-keyed top-level non-empty string arguments, in key order, from an object
/// or a JSON-encoded object string, then the URLs the call's declaration adds.
/// Nothing else in the arguments is a URL fact. Callers charge the argument
/// bytes before resolution.
pub(crate) fn tool_argument_urls(tool: &ToolObservation, declared: bool) -> Vec<String> {
    let mut urls = argument_object(tool.arguments()).map_or_else(Vec::new, |object| {
        string_arguments(&object, is_url_argument_key)
    });
    if let Some(operation) = tool.operation().filter(|_| declared) {
        add_missing(&mut urls, operation.urls());
    }
    urls
}

/// Append the operands not already present, in order.
fn add_missing(into: &mut Vec<String>, operands: &[String]) {
    for operand in operands {
        if !into.contains(operand) {
            into.push(operand.clone());
        }
    }
}

/// Native file tools that write the file their path argument names.
pub(super) fn is_file_write_tool(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "write"
            | "write_file"
            | "writefile"
            | "create"
            | "create_file"
            | "edit"
            | "edit_file"
            | "multiedit"
            | "multi_edit"
            | "notebookedit"
            | "replace"
    )
}

/// Native file tools that read, search or list the paths their arguments name.
pub(super) fn is_file_read_tool(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "read" | "read_file" | "readfile" | "view_file" | "glob" | "list" | "grep"
    )
}

/// Native shell tools by name: the tool runs the command its arguments carry.
/// A name matches in any letter case, as the shell-execution rule's own name
/// pattern did, which folds the long s (U+017F) to `s`.
pub(super) fn is_shell_tool(name: &str) -> bool {
    let folded: String = name
        .chars()
        .map(|c| {
            if c == '\u{17f}' {
                's'
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect();
    matches!(
        folded.as_str(),
        "shell"
            | "exec_command"
            | "shell_command"
            | "bash"
            | "sh"
            | "zsh"
            | "fish"
            | "pwsh"
            | "powershell"
            | "cmd.exe"
    )
}

/// What a call does: the kind its declaration gives, and for a call with none, or read without it, the kind its
/// name gives in the lists above. A call of no declared kind and no listed name
/// has no kind; it is not `other`.
pub(crate) fn tool_kind(tool: &ToolObservation, declared: bool) -> Option<ToolKind> {
    match tool.operation().filter(|_| declared) {
        Some(operation) => Some(operation.kind()),
        None => tool.name().and_then(|name| {
            if is_file_write_tool(name) {
                Some(ToolKind::FileWrite)
            } else if is_file_read_tool(name) {
                Some(ToolKind::FileRead)
            } else if is_shell_tool(name) {
                Some(ToolKind::Shell)
            } else {
                None
            }
        }),
    }
}

/// The `tool_kind` target: the kind of the tool a record names. A record that
/// names no tool has none, whatever its declaration says. Both consumers read it
/// here.
pub(crate) fn named_tool_kind(tool: &ToolObservation) -> Option<ToolKind> {
    tool.name()?;
    tool_kind(tool, true)
}

/// Top-level tool argument keys whose string value names one file.
fn is_file_argument_key(key: &str) -> bool {
    matches!(
        key,
        "file_path"
            | "filePath"
            | "path"
            | "notebook_path"
            | "absolute_path"
            | "target_file"
            | "file"
            | "filename"
    )
}

/// Top-level tool argument keys that carry the content a call writes.
fn is_written_content_argument_key(key: &str) -> bool {
    matches!(
        key,
        "content"
            | "contents"
            | "new_string"
            | "newString"
            | "new_str"
            | "newText"
            | "file_text"
            | "new_source"
            | "edits"
            | "code_edit"
    )
}

/// Whether a call reads the files it is given by name: a declared file-read
/// tool, or for a call with no declaration a native file-read tool by name.
pub(crate) fn reads_paths(tool: &ToolObservation, declared: bool) -> bool {
    tool_kind(tool, declared) == Some(ToolKind::FileRead)
}

/// Whether a call is a file-write tool: by its declaration, and for a call
/// with none, or read without it, by its name.
pub(crate) fn writes_by_kind(tool: &ToolObservation, declared: bool) -> bool {
    tool_kind(tool, declared) == Some(ToolKind::FileWrite)
}

/// File-keyed top-level non-empty string arguments of a call that writes them:
/// a declared file-write tool (for a call with no declaration, a native
/// file-write tool by name), or any call whose arguments also carry the content
/// written. Then the paths the declaration adds. Read, search and listing calls
/// name a path without content and yield nothing. Callers charge the argument
/// bytes before resolution. With `declared` false the call is read as if it
/// carried no declaration.
pub(crate) fn tool_written_paths(tool: &ToolObservation, declared: bool) -> Vec<String> {
    let operation = tool.operation().filter(|_| declared);
    let writes_by_kind = writes_by_kind(tool, declared);
    let mut paths = argument_object(tool.arguments()).map_or_else(Vec::new, |object| {
        if writes_by_kind
            || object
                .keys()
                .any(|key| is_written_content_argument_key(key))
        {
            string_arguments(&object, is_file_argument_key)
        } else {
            Vec::new()
        }
    });
    if let Some(operation) = operation {
        add_missing(&mut paths, operation.written_paths());
    }
    paths
}

/// The top-level argument object, from an object or a JSON-encoded object string.
fn argument_object(arguments: Option<&JsonValue>) -> Option<Cow<'_, BTreeMap<String, JsonValue>>> {
    match arguments {
        Some(JsonValue::Object(object)) => Some(Cow::Borrowed(object)),
        Some(JsonValue::String(text)) => {
            decoded_argument_object(text).map(|(object, _)| Cow::Owned(object))
        }
        _ => None,
    }
}

/// Selected non-empty top-level string arguments, in key order.
fn string_arguments(
    object: &BTreeMap<String, JsonValue>,
    selected: fn(&str) -> bool,
) -> Vec<String> {
    object
        .iter()
        .filter(|(key, _)| selected(key))
        .filter_map(|(_, value)| match value {
            JsonValue::String(value) if !value.is_empty() => Some(value.clone()),
            _ => None,
        })
        .collect()
}

/// Admitted members, and skipped members as `(key, raw JSON text)`.
pub(crate) type DecodedArguments = (BTreeMap<String, JsonValue>, Vec<(String, String)>);

/// Decode tool arguments that a native envelope carries as an encoded JSON
/// object. Each top-level member is admitted under the ordinary per-value bounds
/// on its own; a member that exceeds them, including nesting beyond the JSON
/// parser's recursion limit, is skipped rather than hiding the other members.
/// Skipped members are returned as `(key, raw JSON text)`. Shared by the session
/// selectors and the action view so both read the same facts.
pub(crate) fn decoded_argument_object(text: &str) -> Option<DecodedArguments> {
    // Raw member values are scanned without recursion, so an over-deep member
    // cannot fail the parse of the whole object. Later duplicate keys win, as in
    // ordinary JSON object decoding.
    let members: BTreeMap<String, Box<serde_json::value::RawValue>> =
        serde_json::from_str(text).ok()?;
    let mut admitted = BTreeMap::new();
    let mut skipped = Vec::new();
    for (key, raw) in members {
        // Wrapping keeps the member at its real depth and checks its key.
        let member = serde_json::from_str::<serde_json::Value>(raw.get())
            .ok()
            .map(|value| serde_json::Value::Object([(key.clone(), value)].into_iter().collect()))
            .and_then(|wrapped| JsonValue::try_from_source_value(&wrapped).ok());
        match member {
            Some(JsonValue::Object(member)) => {
                for (admitted_key, value) in member {
                    // Keys equal only after normalization keep the first value;
                    // the colliding member stays searchable as skipped text.
                    match admitted.entry(admitted_key) {
                        std::collections::btree_map::Entry::Vacant(entry) => {
                            entry.insert(value);
                        }
                        std::collections::btree_map::Entry::Occupied(_) => {
                            skipped.push((key.clone(), raw.get().to_owned()));
                        }
                    }
                }
            }
            _ => skipped.push((key, raw.get().to_owned())),
        }
    }
    Some((admitted, skipped))
}

/// Whether a call's declaration gives any argument a role. The call's argument
/// text is then no command text. For a call whose arguments are an object this is
/// the reading every object gets: its members are read by key and the text selectors
/// (`compat.v1.arguments`, `tool.arguments.text`) have no one text to read, so an
/// encoded object or a patch held as the whole argument text is no such text either.
pub(crate) fn reads_by_role(tool: &ToolObservation) -> bool {
    tool.operation().is_some_and(ToolOperation::has_roles)
}

/// Whether the declaration gives a role to the member that holds a command, so
/// that a command facet copied from it is authored or replaced text and no command.
pub(crate) fn command_member_has_role(tool: &ToolObservation) -> bool {
    tool.operation().is_some_and(|operation| {
        operation
            .authored_keys()
            .iter()
            .chain(operation.replaced_keys())
            .any(|key| is_command_argument_key(key))
    })
}

/// Top-level tool argument keys whose value is the command a call runs.
fn is_command_argument_key(key: &str) -> bool {
    matches!(key, "command" | "cmd" | "commandLine" | "command_line")
}

/// Top-level tool argument keys whose string value is content a call authors.
fn is_authored_argument_key(key: &str) -> bool {
    matches!(key, "content" | "new_string" | "new_source")
}

/// Top-level tool argument keys whose values name paths or path patterns.
fn is_path_argument_key(key: &str) -> bool {
    matches!(
        key,
        "file_path"
            | "filePath"
            | "path"
            | "paths"
            | "notebook_path"
            | "file"
            | "filename"
            | "target_file"
            | "glob"
            | "pattern"
    )
}

/// Argument keys whose values are prose or replaced text, never action facts.
fn is_ignored_argument_key(key: &str) -> bool {
    matches!(
        key,
        "old_string"
            | "prompt"
            | "description"
            | "todos"
            | "plan"
            | "questions"
            | "summary"
            | "title"
            | "message"
            | "reason"
            | "tldr"
            | "caption"
            | "activeForm"
            | "subject"
    )
}

/// What the keys of a call's arguments say, in the order read.
#[derive(Default)]
pub(crate) struct ArgumentReading {
    /// The text the call runs as a command, and any text with no known role in
    /// a call whose arguments are not an object.
    pub(crate) command: String,
    /// Whether command text was joined from an argv array.
    pub(crate) argv: bool,
    /// `(field, text)` facts in the order read: `authored_content`, `url`,
    /// `file_path` and `arguments`.
    pub(crate) facts: Vec<(&'static str, String)>,
    /// Keys a declaration reads as authored content, and as replaced text, and
    /// whether the text of a call with no argument object is authored content.
    authored: Vec<String>,
    replaced: Vec<String>,
}

impl ArgumentReading {
    /// A reading that follows the argument roles of a call's declaration.
    pub(crate) fn declared(operation: Option<&ToolOperation>) -> Self {
        operation.map_or_else(Self::default, |operation| Self {
            authored: operation.authored_keys().to_vec(),
            replaced: operation.replaced_keys().to_vec(),
            ..Self::default()
        })
    }

    fn put(&mut self, field: &'static str, text: String) {
        self.facts.push((field, text));
    }

    /// Read the top-level members of an argument object, each by its key.
    pub(crate) fn read(&mut self, input: &BTreeMap<String, JsonValue>) {
        for (key, value) in input {
            match key.as_str() {
                // A declared role comes before what the key says.
                key if self.authored.iter().any(|known| known == key) => {
                    if let Some(v) = string(value) {
                        self.put("authored_content", v.to_owned());
                    }
                }
                key if self.replaced.iter().any(|known| known == key) => {}
                key if is_command_argument_key(key) => {
                    if let Some(v) = string(value) {
                        self.command.push_str(v);
                        self.command.push('\n');
                    }
                    if let JsonValue::Array(items) = value {
                        self.argv = true;
                        for v in items.iter().filter_map(string) {
                            self.command.push_str(v);
                            self.command.push(' ');
                        }
                    }
                }
                key if is_authored_argument_key(key) => {
                    if let Some(v) = string(value) {
                        self.put("authored_content", v.to_owned());
                    }
                }
                "edits" => {
                    if let JsonValue::Array(edits) = value {
                        for edit in edits {
                            if let JsonValue::Object(edit) = edit {
                                for key in std::iter::once("new_string")
                                    .chain(self.authored.iter().map(String::as_str))
                                {
                                    if let Some(v) = edit.get(key).and_then(string) {
                                        self.facts.push(("authored_content", v.to_owned()));
                                    }
                                }
                            }
                        }
                    }
                }
                key if is_ignored_argument_key(key) => {}
                key if is_url_argument_key(key) => {
                    if let Some(v) = string(value) {
                        self.put("url", v.to_owned());
                    }
                }
                key if is_path_argument_key(key) => {
                    if let Some(v) = string(value) {
                        self.put("file_path", v.to_owned());
                    }
                    if let JsonValue::Array(items) = value {
                        for v in items.iter().filter_map(string) {
                            self.put("file_path", v.to_owned());
                        }
                    }
                }
                _ => {
                    if let Some(v) = string(value) {
                        self.put("arguments", v.to_owned());
                    }
                }
            }
        }
    }

    /// Add what a call's declaration names and its arguments did not yield:
    /// commands not already a line of the command text, and paths and URLs
    /// not already facts. Facts are only ever added. Whether anything was.
    pub(crate) fn declare(&mut self, operation: &ToolOperation) -> bool {
        let mut added = false;
        if operation.replaces_command() {
            self.command = operation.commands().join("\n");
            added = true;
        } else {
            for command in operation.commands() {
                let command = command.trim();
                // Text already read stays as it is; a command it holds adds nothing.
                if command.is_empty() || self.command.contains(command) {
                    continue;
                }
                // An argv array leaves its text with no line end.
                if !self.command.is_empty() && !self.command.ends_with('\n') {
                    self.command.push('\n');
                }
                self.command.push_str(command);
                self.command.push('\n');
                added = true;
            }
        }
        let paths = operation
            .written_paths()
            .iter()
            .chain(operation.read_paths())
            .map(|path| ("file_path", path));
        let urls = operation.urls().iter().map(|url| ("url", url));
        let authored = operation
            .authored_contents()
            .iter()
            .map(|text| ("authored_content", text));
        for (field, text) in paths.chain(urls).chain(authored) {
            if !self
                .facts
                .iter()
                .any(|(known, fact)| *known == field && fact == text)
            {
                self.put(field, text.clone());
                added = true;
            }
        }
        added
    }

    /// Encoded-argument members skipped by value-bound admission. Members with a
    /// known role are routed exactly as admitted members are, from a transient value
    /// used only for this reading (its bytes were charged before decoding), so replaced
    /// `old_string` text never becomes command text. Other members, and members too
    /// deep to parse, stay searchable as command text unless their key is ignored.
    pub(crate) fn read_skipped(&mut self, skipped: &[(String, String)]) {
        for (key, raw) in skipped {
            if self.replaced.contains(key) || is_ignored_argument_key(key) {
                continue;
            }
            let routed = self.authored.contains(key)
                || is_command_argument_key(key)
                || is_authored_argument_key(key)
                || is_path_argument_key(key)
                || key == "edits"
                || is_url_argument_key(key);
            match serde_json::from_str::<serde_json::Value>(raw) {
                Ok(value) if routed => {
                    let member = BTreeMap::from([(key.clone(), transient_value(&value))]);
                    self.read(&member);
                }
                _ => {
                    self.command.push_str(raw);
                    self.command.push('\n');
                }
            }
        }
    }
}

/// Unbounded copy for routing only; never retained or emitted as observation
/// data. Depth is limited by the JSON parser that produced `value`.
fn transient_value(value: &serde_json::Value) -> JsonValue {
    match value {
        serde_json::Value::Null => JsonValue::Null,
        serde_json::Value::Bool(value) => JsonValue::Bool(*value),
        serde_json::Value::Number(number) => number
            .as_i64()
            .map(JsonValue::Integer)
            .or_else(|| number.as_u64().map(JsonValue::Unsigned))
            .unwrap_or_else(|| JsonValue::Number(number.as_f64().unwrap_or_default())),
        serde_json::Value::String(text) => JsonValue::String(text.clone()),
        serde_json::Value::Array(items) => {
            JsonValue::Array(items.iter().map(transient_value).collect())
        }
        serde_json::Value::Object(members) => JsonValue::Object(
            members
                .iter()
                .map(|(key, value)| (key.clone(), transient_value(value)))
                .collect(),
        ),
    }
}

fn string(value: &JsonValue) -> Option<&str> {
    if let JsonValue::String(v) = value {
        Some(v)
    } else {
        None
    }
}

#[cfg(test)]
mod tests;
