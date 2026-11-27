//! Per-session journal of what the harness reported through hooks, written in
//! Claude Code's native session JSONL shape so Telltale's Claude Code reader
//! evaluates it, under the hook-journal identity of the harness the calls
//! belong to (docs/hooks/adr/0002-pending-action-evaluation.md).
//!
//! Why not read the harness transcript: at `PreToolUse` time Claude Code
//! 2.1.318 has not yet written the pending `tool_use` to `transcript_path`
//! (verified by capture, see tests/fixtures/claude-code/2.1.318), subagent
//! calls live in separate transcripts, and transcripts carry far more content
//! than detection needs. The journal holds only hook-reported facts.

use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use telltale_schema::hooks_record::{
    HOOK_LABEL_ESCAPE_PREFIX, HOOK_LABEL_MAX_BYTES as MAX_ID_BYTES, readable_hook_text as readable,
};
use unicode_normalization::UnicodeNormalization;

use crate::hooks::projection::is_command_key;
use crate::hooks::state::open_regular;

/// A journal `uuid` is a prefix plus an ID plus a suffix.
const MAX_UUID_BYTES: usize = 512;

/// `tth-esc-<32 hex of SHA-256 over the raw value>`: a stable, safe stand-in.
pub(super) fn escaped(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    format!("{HOOK_LABEL_ESCAPE_PREFIX}{}", hex::encode(&digest[..16]))
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
/// (the link and the line stay consistent). Correlation and the session state
/// path use the raw value; telemetry has its own output check.
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

/// A tool input as it appears in a journal line. Telltale normalizes object
/// keys to NFC and fails the whole source when two collide (`é` composed and
/// decomposed), so a key that collides is renamed `<nfc form>~<n>`. The spelling
/// already in NFC keeps its name, so selectors keep reading the key a harness
/// would read, and every value stays evaluated. Input without a collision is
/// returned unchanged. A pure function; telemetry and correlation keep the
/// input as reported. Unlike the backstop in `Engine::evaluate`, this keeps the
/// line in history.
pub fn safe_input_keys(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(safe_input_keys).collect()),
        Value::Object(map) => {
            let forms: Vec<String> = map.keys().map(|key| key.nfc().collect()).collect();
            let mut taken: BTreeSet<String> = map
                .keys()
                .zip(&forms)
                .filter(|(key, form)| key == form)
                .map(|(_, form)| form.clone())
                .collect();
            let mut safe = Map::new();
            for ((key, item), form) in map.iter().zip(forms) {
                let name = if *key == form || taken.insert(form.clone()) {
                    key.clone()
                } else {
                    (1u64..)
                        .map(|n| format!("{form}~{n}"))
                        .find(|name| taken.insert(name.clone()))
                        .expect("an unused suffix exists")
                };
                safe.insert(name, safe_input_keys(item));
            }
            Value::Object(safe)
        }
        other => other.clone(),
    }
}

/// Whether [`safe_input_keys`] renames a key of this input.
pub fn input_keys_collide(value: &Value) -> bool {
    safe_input_keys(value) != *value
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
                "content": [{"type": "tool_use", "id": safe_id(tool_use_id), "name": safe_tool_name(tool_name), "input": safe_input_keys(input)}],
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

/// A tool input as history, so one journaled record stays small: every
/// string cut to `max_string_bytes`, and the whole within `max_bytes` as the
/// journal line encodes it, so no call costs the window more than one
/// Telltale evaluates whole. Cutting strings alone leaves an excluded input
/// (too many members, leaves or variants) able to outgrow the window. Used
/// for history only; the pending action is always evaluated unmodified.
///
/// The members Telltale reads as the call's command go in first, then short
/// top-level scalars, shortest first: a call's path or URL, which Telltale
/// also reads by member name. Then the rest in order,
/// a string cut and a member left out where the budget ends. Only an input
/// Telltale did not evaluate whole loses more than its long strings' ends,
/// and its record already says so (`pending_input_projected` or an
/// `unevaluable_input` basis). Sizes are counted as the value is built; no
/// second encoding.
pub fn bound_history(value: &Value, max_string_bytes: usize, max_bytes: usize) -> Value {
    let mut budget = max_bytes;
    let Value::Object(map) = value else {
        return within(value, max_string_bytes, &mut budget).unwrap_or(Value::Null);
    };
    let short = |item: &Value| match item {
        Value::String(text) => Some(escaped_len(cut_utf8(text, max_string_bytes))),
        Value::Object(_) | Value::Array(_) => None,
        other => Some(other.to_string().len()),
    };
    let mut order: Vec<(bool, Option<usize>, usize)> = map
        .iter()
        .enumerate()
        .map(|(n, (key, item))| {
            let len = short(item).filter(|len| *len <= SHORT_HISTORY_BYTES);
            (!is_command_key(key), len, n)
        })
        .collect();
    // Commands, then short scalars (`Some` sorts after `None`, hence the key).
    order.sort_by_key(|(other, len, n)| (*other, len.is_none(), *len, *n));
    let members: Vec<(&String, &Value)> = map.iter().collect();
    budget = budget.saturating_sub(2);
    let mut kept = Map::new();
    for (_, _, n) in order {
        let (key, item) = members[n];
        if let Some(item) =
            member_within(key, item, !kept.is_empty(), max_string_bytes, &mut budget)
        {
            kept.insert(key.clone(), item);
        }
    }
    Value::Object(kept)
}

/// A top-level scalar up to this many encoded bytes goes into history first.
const SHORT_HISTORY_BYTES: usize = 1024;

/// `"key":value`, with a comma ahead of it unless it is the first member,
/// within `budget`; `None` leaves `budget` untouched.
fn member_within(
    key: &str,
    item: &Value,
    comma: bool,
    max_string_bytes: usize,
    budget: &mut usize,
) -> Option<Value> {
    let mut room = budget.checked_sub(usize::from(comma) + escaped_len(key) + 3)?;
    let item = within(item, max_string_bytes, &mut room)?;
    *budget = room;
    Some(item)
}

/// `value` with strings cut to `max_string_bytes`, cut to fit `budget`
/// encoded bytes and charged to it; `None` (and `budget` untouched) when not
/// even an empty form fits.
fn within(value: &Value, max_string_bytes: usize, budget: &mut usize) -> Option<Value> {
    match value {
        Value::String(text) => {
            let room = budget.checked_sub(2)?;
            let text = cut_escaped(cut_utf8(text, max_string_bytes), room);
            *budget = room - escaped_len(text);
            Some(Value::String(text.to_owned()))
        }
        Value::Array(items) => {
            let mut room = budget.checked_sub(2)?;
            let mut kept = Vec::new();
            for item in items {
                let Some(mut left) = room.checked_sub(usize::from(!kept.is_empty())) else {
                    break;
                };
                if let Some(item) = within(item, max_string_bytes, &mut left) {
                    kept.push(item);
                    room = left;
                }
            }
            *budget = room;
            Some(Value::Array(kept))
        }
        Value::Object(map) => {
            let mut room = budget.checked_sub(2)?;
            let mut kept = Map::new();
            for (key, item) in map {
                if let Some(item) =
                    member_within(key, item, !kept.is_empty(), max_string_bytes, &mut room)
                {
                    kept.insert(key.clone(), item);
                }
            }
            *budget = room;
            Some(Value::Object(kept))
        }
        other => {
            *budget = budget.checked_sub(other.to_string().len())?;
            Some(other.clone())
        }
    }
}

/// Bytes `c` takes inside a JSON string as `serde_json` writes it.
fn escaped_char_len(c: char) -> usize {
    match c {
        '"' | '\\' | '\n' | '\r' | '\t' | '\u{8}' | '\u{c}' => 2,
        c if c < ' ' => 6,
        c => c.len_utf8(),
    }
}

/// Bytes `text` takes inside a JSON string, quotes not counted.
fn escaped_len(text: &str) -> usize {
    text.chars().map(escaped_char_len).sum()
}

/// Longest prefix of `text` that takes at most `max` bytes escaped, and so
/// at most `max` bytes raw.
pub fn cut_escaped(text: &str, max: usize) -> &str {
    let mut used = 0;
    for (at, c) in text.char_indices() {
        used += escaped_char_len(c);
        if used > max {
            return &text[..at];
        }
    }
    text
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

    /// The most recent complete lines, bounded by count and by their bytes.
    /// Unparseable lines are skipped and counted. A line longer than
    /// `max_bytes` on its own (written by an older version, which did not
    /// bound every call) is skipped and counted too, and older lines fill the
    /// budget in its place: one line cannot empty the window. Stepping over
    /// such lines reads at most [`OVERSIZED_SCAN_FACTOR`] times `max_bytes`
    /// more; past that the window ends there.
    pub fn tail(&self, max_records: usize, max_bytes: u64) -> std::io::Result<Tail> {
        let mut file = match open_regular(OpenOptions::new().read(true), &self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Tail::default());
            }
            Err(error) => return Err(error),
        };
        let mut tail = Tail::default();
        let mut end = file.metadata()?.len();
        let mut budget = max_bytes;
        let mut scan_left = max_bytes.saturating_mul(OVERSIZED_SCAN_FACTOR);
        // Spans of whole lines, newest first.
        let mut spans: Vec<Vec<u8>> = Vec::new();
        loop {
            let start = end.saturating_sub(budget);
            file.seek(SeekFrom::Start(start))?;
            let mut bytes = Vec::with_capacity((end - start) as usize);
            (&mut file).take(end - start).read_to_end(&mut bytes)?;
            if start == 0 {
                spans.push(bytes);
                break;
            }
            // A cut start lands mid-line: leave that line's part out.
            tail.truncated = true;
            let cut = bytes
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(bytes.len(), |at| at + 1);
            let line_end = start + cut as u64;
            budget -= end - line_end;
            spans.push(bytes.split_off(cut));
            match line_start(&mut file, start, &mut scan_left)? {
                Some(line_begin) if line_end - line_begin > max_bytes => {
                    tail.skipped += 1;
                    end = line_begin;
                    if end == 0 || budget == 0 {
                        break;
                    }
                }
                _ => break,
            }
        }
        let bytes: Vec<u8> = spans.into_iter().rev().flatten().collect();
        let text = String::from_utf8_lossy(&bytes);
        for line in text.split('\n').filter(|line| !line.trim().is_empty()) {
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

/// How far past its byte budget [`Journal::tail`] reads to step over lines
/// longer than the budget, as a multiple of the budget.
pub const OVERSIZED_SCAN_FACTOR: u64 = 4;
const SCAN_CHUNK: u64 = 64 * 1024;

/// Where the line holding the byte before `pos` starts: just past the last
/// line break before `pos`, or the start of the file. `None` when that is
/// more than `scan_left` bytes back, which is charged for what is read.
fn line_start(file: &mut File, mut pos: u64, scan_left: &mut u64) -> std::io::Result<Option<u64>> {
    let mut chunk = vec![0; SCAN_CHUNK.min(pos) as usize];
    while pos > 0 {
        let n = SCAN_CHUNK.min(pos).min(*scan_left);
        if n == 0 {
            return Ok(None);
        }
        pos -= n;
        let chunk = &mut chunk[..n as usize];
        file.seek(SeekFrom::Start(pos))?;
        file.read_exact(chunk)?;
        if let Some(at) = chunk.iter().rposition(|byte| *byte == b'\n') {
            // Charged for the line's own bytes only.
            *scan_left -= n - at as u64 - 1;
            return Ok(Some(pos + at as u64 + 1));
        }
        *scan_left -= n;
    }
    Ok(Some(0))
}

#[derive(Debug, Default)]
pub struct Tail {
    pub lines: Vec<Line>,
    /// Older journal history exists outside this window.
    pub truncated: bool,
    /// Lines left out: one that did not parse (for example, a torn write) or
    /// one longer than the whole byte budget.
    pub skipped: usize,
}

#[cfg(test)]
mod tests;
