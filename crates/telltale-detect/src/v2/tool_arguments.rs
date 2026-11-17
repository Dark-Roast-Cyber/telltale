//! The structural reading of a tool call: what its arguments say by their
//! keys and shape, whatever harness sent the call.
//!
//! The session selectors and the action view both read a call through this
//! module, so they agree on its facts. Nothing here knows a harness. The two
//! tool-name lists ([`is_file_write_tool`], [`is_file_read_tool`]) are the
//! exception that remains: hand-kept names from several harnesses, to be
//! replaced by the operations each source declares for its own tools. A
//! declaration will only add to this reading, never replace it, so a call a
//! source does not declare keeps every fact it has here.
//!
//! `tool_reading_tests` pins the reading of every key and name below.

use std::borrow::Cow;
use std::collections::BTreeMap;

use telltale_schema::observation::JsonValue;

/// Top-level tool argument keys whose string values are destination URLs.
pub(crate) fn is_url_argument_key(key: &str) -> bool {
    matches!(key, "url" | "uri" | "href" | "endpoint")
}

/// URL-keyed top-level non-empty string arguments, in key order, from an object
/// or a JSON-encoded object string. Nothing else in the arguments is a URL fact.
/// Callers charge the argument bytes before resolution.
pub(crate) fn tool_argument_urls(arguments: Option<&JsonValue>) -> Vec<String> {
    argument_object(arguments).map_or_else(Vec::new, |object| {
        string_arguments(&object, is_url_argument_key)
    })
}

/// Native file tools that write the file their path argument names.
fn is_file_write_tool(name: &str) -> bool {
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
pub(crate) fn is_file_read_tool(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "read" | "read_file" | "readfile" | "view_file" | "glob" | "list" | "grep"
    )
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

/// File-keyed top-level non-empty string arguments of a call that writes them:
/// a native file-write tool, or any call whose arguments also carry the content
/// written. Read, search and listing calls name a path without content and
/// yield nothing. Callers charge the argument bytes before resolution.
pub(crate) fn tool_written_paths(name: Option<&str>, arguments: Option<&JsonValue>) -> Vec<String> {
    argument_object(arguments).map_or_else(Vec::new, |object| {
        if name.is_some_and(is_file_write_tool)
            || object
                .keys()
                .any(|key| is_written_content_argument_key(key))
        {
            string_arguments(&object, is_file_argument_key)
        } else {
            Vec::new()
        }
    })
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
}

impl ArgumentReading {
    fn put(&mut self, field: &'static str, text: String) {
        self.facts.push((field, text));
    }

    /// Read the top-level members of an argument object, each by its key.
    pub(crate) fn read(&mut self, input: &BTreeMap<String, JsonValue>) {
        for (key, value) in input {
            match key.as_str() {
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
                            if let JsonValue::Object(edit) = edit
                                && let Some(v) = edit.get("new_string").and_then(string)
                            {
                                self.put("authored_content", v.to_owned());
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

    /// Encoded-argument members skipped by value-bound admission. Members with a
    /// known role are routed exactly as admitted members are, from a transient value
    /// used only for this reading (its bytes were charged before decoding), so replaced
    /// `old_string` text never becomes command text. Other members, and members too
    /// deep to parse, stay searchable as command text unless their key is ignored.
    pub(crate) fn read_skipped(&mut self, skipped: &[(String, String)]) {
        for (key, raw) in skipped {
            if is_ignored_argument_key(key) {
                continue;
            }
            let routed = is_command_argument_key(key)
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
