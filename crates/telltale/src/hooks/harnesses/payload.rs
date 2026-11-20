//! Payload reading that several adapters share, for harnesses whose hook
//! protocol follows the same conventions.

use serde::{Deserialize, Deserializer};
use serde_json::Value;

/// A field read as `Some` whenever its key is present, `null` included. With
/// `#[serde(default, deserialize_with = "payload::present")]`, only an absent
/// key is `None`, which plain `Option` cannot tell from `null`.
pub fn present<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<Value>, D::Error> {
    Value::deserialize(deserializer).map(Some)
}

/// Whether the bounded prefix of an unparseable payload holds `"key":
/// "event"`: the test for a pre-execution event on a harness that writes its
/// event key before the tool input.
pub fn names_event_as(bytes: &[u8], key: &str, event: &str) -> bool {
    let head = &bytes[..bytes.len().min(64 * 1024)];
    let text = String::from_utf8_lossy(head);
    let key = format!("\"{key}\"");
    let event = format!("\"{event}\"");
    text.match_indices(key.as_str()).any(|(at, _)| {
        let rest = text[at + key.len()..].trim_start();
        rest.strip_prefix(':')
            .map(str::trim_start)
            .is_some_and(|value| value.starts_with(event.as_str()))
    })
}

/// Text a tool result contributed, in the shape Telltale's `tool_result`
/// target reads. Bash results join stdout and stderr; Read results use the
/// file content; anything else is compact JSON.
pub fn tool_response_text(response: &Value) -> String {
    match response {
        Value::String(text) => text.clone(),
        Value::Object(map) => {
            if map.contains_key("stdout") || map.contains_key("stderr") {
                let stdout = map.get("stdout").and_then(Value::as_str).unwrap_or("");
                let stderr = map.get("stderr").and_then(Value::as_str).unwrap_or("");
                return match (stdout.is_empty(), stderr.is_empty()) {
                    (_, true) => stdout.to_owned(),
                    (true, false) => stderr.to_owned(),
                    (false, false) => format!("{stdout}\n{stderr}"),
                };
            }
            if let Some(content) = map
                .get("file")
                .and_then(|file| file.get("content"))
                .and_then(Value::as_str)
            {
                return content.to_owned();
            }
            if let Some(Value::Array(parts)) = map.get("content") {
                let text: Vec<&str> = parts
                    .iter()
                    .filter_map(|part| part.get("text").and_then(Value::as_str))
                    .collect();
                if !text.is_empty() {
                    return text.join("\n");
                }
            }
            response.to_string()
        }
        other => other.to_string(),
    }
}
