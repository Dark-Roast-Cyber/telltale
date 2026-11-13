//! Per-session journal of what the harness reported through hooks, written in
//! Claude Code's native session JSONL shape so Telltale's own `claude.projects`
//! adapter evaluates it (docs/adr/0002-pending-action-evaluation.md).
//!
//! Why not read the harness transcript: at `PreToolUse` time Claude Code
//! 2.1.318 has not yet written the pending `tool_use` to `transcript_path`
//! (verified by capture, see tests/fixtures/claude-code/2.1.318), subagent
//! calls live in separate transcripts, and transcripts carry far more content
//! than detection needs. The journal holds only hook-reported facts.

use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::hooks::state::open_regular;

/// Longest identity value kept readable in a journal line. Telltale bounds a
/// string at 4,096 bytes (`LOCAL_MAX_STRING_BYTES`); real harness values are
/// far shorter.
const MAX_ID_BYTES: usize = 256;
/// A journal `uuid` is a prefix plus an ID plus a suffix.
const MAX_UUID_BYTES: usize = 512;
const ESCAPED_PREFIX: &str = "tth-esc-";

/// `tth-esc-<32 hex of SHA-256 over the raw value>`: a stable, safe stand-in.
fn escaped(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    format!("{ESCAPED_PREFIX}{}", hex::encode(&digest[..16]))
}

fn readable(value: &str, max: usize) -> bool {
    !value.trim().is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

/// An identifier as it appears in a journal line: a call key (`tool_use_id`),
/// the session ID, or a line `uuid` (with a longer bound). These come from the
/// harness or the model, and Telltale fails the whole source read, not just
/// the line, for a value it cannot accept (at the pinned rev:
/// `CorrelationId::new` -> `opaque_text`/`non_empty`, telltale-schema
/// `observation/value.rs`, refuse `/`, `\`, `..`, an empty value, `\n` and
/// `\r`; probes also fail a blank, control-character or over-long value).
/// A value with none of those and at most 256 bytes stays as it is; any
/// other becomes `tth-esc-<32 hex of SHA-256 over the raw value>`. The
/// encoding is a pure function, so it is stable across a session and
/// idempotent (an encoded value is already readable). A raw value that
/// literally looks like `tth-esc-...` stays as it is, which is harmless: the
/// `~<ms>` suffix on call keys and the per-session directories keep identities
/// apart. A call key of about 243 bytes or more does not stay readable once `journal_id`
/// adds `~<ms>`: the `tool_use_id` is then past 256 bytes and is hashed
/// (the link and the line stay consistent). Telemetry, correlation and the session
/// state path keep the raw value.
pub fn safe_id(value: &str) -> std::borrow::Cow<'_, str> {
    safe_id_within(value, MAX_ID_BYTES)
}

fn safe_id_within(value: &str, max: usize) -> std::borrow::Cow<'_, str> {
    if readable(value, max) && !value.contains("..") && !value.contains(['/', '\\']) {
        value.into()
    } else {
        escaped(value).into()
    }
}

/// A tool name as it appears in a journal line. Telltale refuses an empty or
/// blank name and one with a control character (line breaks, tab, NUL), and
/// an overlong one fails the call; it is then not evaluated. The stand-in
/// name keeps the source readable but loses name-based rule matches: Telltale
/// routes some tools (`Read`, `Grep`, a path-only `Write`) by name, so the
/// runtime floors a call whose name was encoded at `on_unevaluable`
/// ([`tool_name_is_malformed`]). Tools routed by argument key (`Bash` commands)
/// keep their rule verdicts. Ordinary names (`Bash`, `mcp__server__tool`,
/// `server-tool`) are unchanged.
pub fn safe_tool_name(value: &str) -> std::borrow::Cow<'_, str> {
    if tool_name_is_encoded(value) {
        escaped(value).into()
    } else {
        value.into()
    }
}

/// Whether [`safe_tool_name`] replaces this name.
fn tool_name_is_encoded(value: &str) -> bool {
    !readable(value, MAX_ID_BYTES)
}

/// A name no harness legitimately sends: one that needs encoding, or padded
/// with whitespace (`Read `, ` Read`, NBSP-padded), which name-routed rules
/// would not match either. The runtime floors such a call at `on_unevaluable`.
/// A padded name is journaled as reported unless it also needed encoding.
/// Zero-width and other invisible characters are not covered.
pub fn tool_name_is_malformed(value: &str) -> bool {
    tool_name_is_encoded(value) || value != value.trim()
}

/// One native Claude Code JSONL line.
#[derive(Debug, Clone, PartialEq)]
pub struct Line(pub Value);

impl Line {
    pub fn user_prompt(session_id: &str, uuid: &str, timestamp: &str, prompt: &str) -> Self {
        Self(json!({
            "type": "user",
            "sessionId": safe_id(session_id),
            "uuid": safe_id_within(uuid, MAX_UUID_BYTES),
            "timestamp": timestamp,
            "message": {"role": "user", "content": prompt},
        }))
    }

    pub fn tool_use(
        session_id: &str,
        uuid: &str,
        timestamp: &str,
        tool_use_id: &str,
        tool_name: &str,
        input: &Value,
    ) -> Self {
        Self(json!({
            "type": "assistant",
            "sessionId": safe_id(session_id),
            "uuid": safe_id_within(uuid, MAX_UUID_BYTES),
            "timestamp": timestamp,
            "message": {
                "role": "assistant",
                "content": [{"type": "tool_use", "id": safe_id(tool_use_id), "name": safe_tool_name(tool_name), "input": input}],
            },
        }))
    }

    pub fn tool_result(
        session_id: &str,
        uuid: &str,
        timestamp: &str,
        tool_use_id: &str,
        content: &str,
        is_error: bool,
    ) -> Self {
        Self(json!({
            "type": "user",
            "sessionId": safe_id(session_id),
            "uuid": safe_id_within(uuid, MAX_UUID_BYTES),
            "timestamp": timestamp,
            "message": {
                "role": "user",
                "content": [{"type": "tool_result", "tool_use_id": safe_id(tool_use_id), "content": content, "is_error": is_error}],
            },
        }))
    }

    pub fn to_jsonl(&self) -> String {
        let mut text = self.0.to_string();
        text.push('\n');
        text
    }
}

/// Recursively cut long strings so one journaled record stays small. Used for
/// history context only; the pending action is always evaluated unmodified.
pub fn bound_value(value: &Value, max_string_bytes: usize) -> Value {
    match value {
        Value::String(text) => Value::String(cut_utf8(text, max_string_bytes).to_owned()),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| bound_value(item, max_string_bytes))
                .collect(),
        ),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, item)| (key.clone(), bound_value(item, max_string_bytes)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Longest prefix of `text` within `max` bytes that ends on a char boundary.
pub fn cut_utf8(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

pub struct Journal {
    path: PathBuf,
}

impl Journal {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn append(&self, line: &Line) -> std::io::Result<()> {
        let mut file = open_regular(OpenOptions::new().create(true).append(true), &self.path)?;
        file.write_all(line.to_jsonl().as_bytes())
    }

    /// The most recent complete lines, bounded by count and by bytes read
    /// from the end of the file. Unparseable lines are skipped and counted.
    pub fn tail(&self, max_records: usize, max_bytes: u64) -> std::io::Result<Tail> {
        let mut file = match open_regular(OpenOptions::new().read(true), &self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Tail::default());
            }
            Err(error) => return Err(error),
        };
        let len = file.metadata()?.len();
        let start = len.saturating_sub(max_bytes);
        file.seek(SeekFrom::Start(start))?;
        let mut bytes = Vec::with_capacity((len - start) as usize);
        file.read_to_end(&mut bytes)?;
        let text = String::from_utf8_lossy(&bytes);
        let mut lines: Vec<&str> = text.split('\n').collect();
        // A cut start lands mid-line; the trailing element is empty or partial.
        if start > 0 && !lines.is_empty() {
            lines.remove(0);
        }
        let truncated_by_bytes = start > 0;
        let mut tail = Tail {
            truncated: truncated_by_bytes,
            ..Tail::default()
        };
        for line in lines.into_iter().filter(|line| !line.trim().is_empty()) {
            match serde_json::from_str::<Value>(line) {
                Ok(value) => tail.lines.push(Line(value)),
                Err(_) => tail.skipped += 1,
            }
        }
        if tail.lines.len() > max_records {
            let excess = tail.lines.len() - max_records;
            tail.lines.drain(..excess);
            tail.truncated = true;
        }
        Ok(tail)
    }
}

#[derive(Debug, Default)]
pub struct Tail {
    pub lines: Vec<Line>,
    /// Older journal history exists outside this window.
    pub truncated: bool,
    /// Lines that did not parse (for example, a torn write).
    pub skipped: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_values_are_kept_or_encoded_idempotently() {
        for ok in ["toolu_01:a%b.c", "5f0e3b1c-0d3a", "caf\u{e9}", "a b"] {
            assert_eq!(safe_id(ok), ok);
        }
        for bad in [
            "", " ", "\u{a0}", "a/b", "a\\b", "a..b", "a\nb", "a\tb", "a\0b",
        ] {
            let id = safe_id(bad).into_owned();
            assert!(id.starts_with("tth-esc-") && id.len() == 8 + 32, "{bad:?}");
            assert_eq!(safe_id(&id), id);
        }
        assert_ne!(safe_id("a/b"), safe_id("a\\b"));
        assert!(safe_id(&"k".repeat(257)).starts_with("tth-esc-"));
        for name in [
            "Bash",
            "mcp__server__tool",
            "server-tool",
            "server_tool",
            "a/b",
        ] {
            assert_eq!(safe_tool_name(name), name);
        }
        for bad in ["", " ", "\u{a0}", "Bash\n", "Bash\r", "Bash\t", "Bash\0"] {
            assert!(safe_tool_name(bad).starts_with("tth-esc-"), "{bad:?}");
        }
    }

    #[test]
    fn tail_is_bounded_by_records_and_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let journal = Journal::new(dir.path().join("j.jsonl"));
        for i in 0..10 {
            journal
                .append(&Line::user_prompt(
                    "s",
                    &format!("u{i}"),
                    "2026-01-01T00:00:00.000Z",
                    "hi",
                ))
                .unwrap();
        }
        let tail = journal.tail(3, 1 << 20).unwrap();
        assert_eq!(tail.lines.len(), 3);
        assert!(tail.truncated);
        assert_eq!(tail.lines[2].0["uuid"], "u9");

        let one_line = Line::user_prompt("s", "u0", "2026-01-01T00:00:00.000Z", "hi")
            .to_jsonl()
            .len() as u64;
        let tail = journal.tail(100, one_line * 2 + 5).unwrap();
        assert_eq!(tail.lines.len(), 2, "partial first line is dropped");
        assert_eq!(tail.skipped, 0);
    }

    #[test]
    fn missing_journal_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let tail = Journal::new(dir.path().join("none.jsonl"))
            .tail(10, 10)
            .unwrap();
        assert!(tail.lines.is_empty() && !tail.truncated);
    }

    #[test]
    fn bound_value_cuts_on_char_boundaries() {
        let value = json!({"a": "ééé", "b": [ "abcdef" ], "n": 5});
        let bounded = bound_value(&value, 3);
        assert_eq!(bounded, json!({"a": "é", "b": ["abc"], "n": 5}));
    }
}
