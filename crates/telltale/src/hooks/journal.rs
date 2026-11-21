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
use unicode_normalization::UnicodeNormalization;

use crate::hooks::projection::is_command_key;
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
    fn colliding_keys_are_renamed_and_nothing_else_changes() {
        // No collision: either spelling alone, ASCII, nested, arrays.
        for clean in [
            json!({"command": "ls", "\u{e9}": 1}),
            json!({"command": "ls", "e\u{301}": 1}),
            json!({"a": [{"b": "\u{e9}"}], "n": 5, "s": "e\u{301}"}),
            json!("e\u{301}"),
        ] {
            assert_eq!(safe_input_keys(&clean), clean);
            assert!(!input_keys_collide(&clean));
        }
        // The spelling already in NFC keeps its name; values all survive.
        let top = json!({"\u{e9}": "composed", "e\u{301}": "decomposed", "command": "ls"});
        let safe = json!({"\u{e9}": "composed", "\u{e9}~1": "decomposed", "command": "ls"});
        assert_eq!(safe_input_keys(&top), safe);
        assert!(input_keys_collide(&top));
        // Idempotent, and nested objects inside arrays are covered.
        assert_eq!(safe_input_keys(&safe), safe);
        let nested = json!({"a": [{"\u{e9}": 1, "e\u{301}": 2}]});
        assert_eq!(
            safe_input_keys(&nested),
            json!({"a": [{"\u{e9}": 1, "\u{e9}~1": 2}]})
        );
        // Non-ASCII spellings of ASCII keys: the ASCII key keeps its name.
        let kelvin = json!({"Key": "plain", "\u{212a}ey": "kelvin"});
        assert_eq!(
            safe_input_keys(&kelvin),
            json!({"Key": "plain", "Key~1": "kelvin"})
        );
        // A chosen suffix never lands on a key that is already there, in
        // either spelling, and no two results share an NFC form.
        let taken = json!({"\u{e9}": 1, "e\u{301}": 2, "\u{e9}~1": 3, "e\u{301}~1": 4});
        let safe = safe_input_keys(&taken);
        let map = safe.as_object().unwrap();
        assert_eq!(map.len(), 4);
        let forms: BTreeSet<String> = map.keys().map(|key| key.nfc().collect()).collect();
        assert_eq!(forms.len(), 4, "{safe}");
        assert_eq!(map["\u{e9}"], 1);
        assert_eq!(map["\u{e9}~1"], 3);
        // No spelling in NFC: one keeps its spelling, Telltale folds it alone.
        let neither = json!({"\u{212b}": 1, "A\u{30a}": 2});
        let safe = safe_input_keys(&neither);
        let forms: BTreeSet<String> = safe
            .as_object()
            .unwrap()
            .keys()
            .map(|key| key.nfc().collect())
            .collect();
        assert_eq!(forms.len(), 2, "{safe}");
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
    fn bound_history_cuts_on_char_boundaries() {
        let value = json!({"a": "ééé", "b": [ "abcdef" ], "n": 5});
        let bounded = bound_history(&value, 3, 1 << 20);
        assert_eq!(bounded, json!({"a": "é", "b": ["abc"], "n": 5}));
    }

    /// An input within the budget is only string-cut; any other is cut to the
    /// budget exactly as the line encodes it, short top-level values first.
    #[test]
    fn bound_history_fits_the_budget_and_keeps_short_top_level_values() {
        let ordinary = json!({"command": "ls -la", "description": "x".repeat(5000)});
        assert_eq!(
            bound_history(&ordinary, 4000, 16 * 1024),
            json!({"command": "ls -la", "description": "x".repeat(4000)})
        );
        let members = |n: usize, text: &str| {
            let mut map: Map<String, Value> =
                (0..n).map(|i| (format!("a{i:04}"), json!(text))).collect();
            map.insert("url".to_owned(), json!("https://example.invalid/x"));
            map.insert("command".to_owned(), json!("sh /tmp/x.sh"));
            Value::Object(map)
        };
        let deep = (0..100).fold(json!("q\"\u{1}é".repeat(2000)), |v, _| json!({"d": [v, 1]}));
        let cases = [
            members(1100, &"m".repeat(4000)),
            members(2000, "m"),
            members(3, &"\u{1}\"\\é".repeat(4000)),
            json!({"command": "ls", "nested": deep}),
            json!([deep, "x".repeat(4000), "y".repeat(4000)]),
            json!("z".repeat(100_000)),
        ];
        for budget in [16 * 1024, 300, 40, 2] {
            for (n, value) in cases.iter().enumerate() {
                let bounded = bound_history(value, 4000, budget);
                let written = bounded.to_string().len();
                assert!(written <= budget, "{written} > {budget}");
                // Long padding members do not crowd out the short values.
                if budget >= 300
                    && (n == 0 || n == 2)
                    && let Some(map) = value.as_object()
                {
                    assert_eq!(bounded["command"], map["command"]);
                    assert_eq!(bounded["url"], map["url"]);
                }
            }
        }
        // Filled close to the budget, not left far short of it.
        let bounded = bound_history(&cases[0], 4000, 16 * 1024);
        assert!(bounded.to_string().len() > 16 * 1024 - 4100);
    }

    /// A command member goes into history ahead of members shorter than it.
    #[test]
    fn bound_history_keeps_the_command_ahead_of_shorter_members() {
        let mut map: Map<String, Value> =
            (0..3000).map(|i| (format!("a{i:04}"), json!(1))).collect();
        map.insert("command".to_owned(), json!("sh /tmp/x.sh"));
        let bounded = bound_history(&Value::Object(map), 4000, 16 * 1024);
        assert_eq!(bounded["command"], "sh /tmp/x.sh");
    }

    /// A line longer than the whole budget is skipped, not left to empty the
    /// window: the lines before it fill the budget in its place.
    #[test]
    fn tail_steps_over_a_line_longer_than_the_budget() {
        let dir = tempfile::tempdir().unwrap();
        let journal = Journal::new(dir.path().join("j.jsonl"));
        let prompt =
            |uuid: &str, text: &str| Line::user_prompt("s", uuid, "2026-01-01T00:00:00.000Z", text);
        let one_line = prompt("u0", "hi").to_jsonl().len() as u64;
        for i in 0..5 {
            journal.append(&prompt(&format!("u{i}"), "hi")).unwrap();
        }
        let budget = one_line * 3 + 5;
        // Longer than the budget, within the bytes read to step over it.
        let big = "b".repeat(budget as usize * 2);
        journal.append(&prompt("big", &big)).unwrap();
        journal.append(&prompt("u5", "hi")).unwrap();
        let tail = journal.tail(100, budget).unwrap();
        let uuids: Vec<&Value> = tail.lines.iter().map(|line| &line.0["uuid"]).collect();
        assert_eq!(uuids, [&json!("u3"), &json!("u4"), &json!("u5")]);
        assert!(tail.truncated);
        assert_eq!(tail.skipped, 1);

        // The oversized line last, and alone.
        journal.append(&prompt("big2", &big)).unwrap();
        let tail = journal.tail(100, budget).unwrap();
        let uuids: Vec<&Value> = tail.lines.iter().map(|line| &line.0["uuid"]).collect();
        assert_eq!(uuids, [&json!("u3"), &json!("u4"), &json!("u5")]);
        assert_eq!(tail.skipped, 2);

        // Stepping over is bounded: past the bytes it may read, the window
        // ends there.
        journal
            .append(&prompt("huge", &"h".repeat(budget as usize * 10)))
            .unwrap();
        let tail = journal.tail(100, budget).unwrap();
        assert!(tail.lines.is_empty() && tail.truncated);
    }
}
