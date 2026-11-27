//! Shell command segments for Rule v1 `detection.scope: segment`.
//!
//! A segment is the text between unquoted [`statement_separator`]s (`;`, `|`,
//! `||`, `|&`, `&&`, a background `&` and newlines), trimmed of surrounding
//! ASCII whitespace; empty segments are skipped. The `&` of a redirection
//! (`2>&1`, `&>`) separates nothing. Single quotes are literal. A backslash
//! escapes the next character outside single quotes, so `\;` and a `\"` inside
//! double quotes end nothing, and `$'...'` takes backslash escapes, so its `\'`
//! ends nothing either. An unclosed quote runs to the end of the text, which
//! yields one larger segment rather than an error.
//!
//! This is a lexical split, not a shell parser: subshells, command
//! substitution, heredocs and comments are not interpreted. It makes one pass
//! over the bytes and allocates nothing. Every separator, quote and escape is
//! ASCII, so every range starts and ends on a character boundary.
//!
//! The helpers below serve `detection.scope: exclusion_segment`. Sources may
//! store a shell call's arguments as raw JSON, whose quoting makes the whole call
//! one segment. [`json_shell_call`] reads only an exact, known shape, because any
//! other member could carry the real request: a decoy in a free-text member must
//! not speak for the call. Anything else stays raw text, which fails toward a
//! match. A repeated key keeps its last value, as the parsers that run the call
//! do.

use std::ops::Range;

/// Byte ranges of the non-empty segments of `text`, in order.
pub(crate) fn segments(text: &str) -> Segments<'_> {
    Segments {
        bytes: text.as_bytes(),
        position: 0,
    }
}

pub(crate) struct Segments<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl Iterator for Segments<'_> {
    type Item = Range<usize>;

    fn next(&mut self) -> Option<Range<usize>> {
        while self.position < self.bytes.len() {
            let (end, next) = segment_end(self.bytes, self.position);
            let range = trim(self.bytes, self.position..end);
            self.position = next;
            if !range.is_empty() {
                return Some(range);
            }
        }
        None
    }
}

/// `segment` without the line continuation left before a separator that follows
/// it, as in `a \\` + newline + `&& b`.
pub(crate) fn without_continuation(segment: &str) -> &str {
    segment.strip_suffix('\\').map_or(segment, str::trim_end)
}

/// Whether `text` opens like a JSON object or array, before paying to parse it.
pub(crate) fn may_be_json(text: &str) -> bool {
    text.trim_start().starts_with(['{', '['])
}

/// Members beside the command that describe how a shell call runs, never what
/// it sends. An unknown member leaves the call to the raw text.
const SHELL_CALL_METADATA: &[&str] = &[
    "cwd",
    "description",
    "initial_wait",
    "justification",
    "max_output_tokens",
    "mode",
    "timeout",
    "timeout_ms",
    "workdir",
    "yield_time_ms",
];

/// The parts of a raw JSON shell call that bear on a rule.
pub(crate) struct JsonShellCall {
    pub(crate) command: String,
    /// String metadata, such as a description, which may still quote a command.
    pub(crate) other_strings: Vec<String>,
}

/// `text` as one JSON object with exactly one command member, a `cmd` or
/// `command` string or a `command` argv naming a shell and its script, and
/// otherwise only scalar [`SHELL_CALL_METADATA`] members. `None` for anything else.
pub(crate) fn json_shell_call(text: &str) -> Option<JsonShellCall> {
    use serde_json::Value;

    let Value::Object(members) = serde_json::from_str::<Value>(text).ok()? else {
        return None;
    };
    let mut command = None;
    let mut other_strings = Vec::new();
    for (key, value) in members {
        match (key.as_str(), value) {
            ("cmd" | "command", _) if command.is_some() => return None,
            ("cmd" | "command", Value::String(text)) => command = Some(text),
            ("command", Value::Array(argv)) => command = Some(shell_script(argv)?),
            (key, Value::String(text)) if SHELL_CALL_METADATA.contains(&key) => {
                other_strings.push(text);
            }
            (key, Value::Number(_) | Value::Bool(_) | Value::Null)
                if SHELL_CALL_METADATA.contains(&key) => {}
            _ => return None,
        }
    }
    Some(JsonShellCall {
        command: command?,
        other_strings,
    })
}

/// `raw` JSON with the spelling of each byte range of `text`, and of each line
/// break in `text`, blanked to spaces in every string literal that decodes to
/// `text`. JSON can spell any character as an escape, so raw and decoded
/// readings can differ; the result keeps the raw reading for everything outside
/// the ranges, with lines joined as in the one-line remainder.
/// `None` when no literal decodes to `text` or a literal cannot be decoded.
pub(crate) fn blank_json_spelling(
    raw: &str,
    text: &str,
    ranges: &[Range<usize>],
) -> Option<String> {
    let mut blanked = raw.as_bytes().to_vec();
    let mut found = false;
    let mut position = 0;
    // Outside its string literals, valid JSON holds no double quote.
    while let Some(open) = raw[position..].find('"') {
        let (decoded, starts, close) = decode_json_string(raw, position + open + 1)?;
        if decoded == text {
            found = true;
            let breaks = text.match_indices('\n').map(|(at, _)| at..at + 1);
            for range in ranges.iter().cloned().chain(breaks) {
                blanked[starts[range.start]..starts[range.end]].fill(b' ');
            }
        }
        position = close + 1;
    }
    // Each range covers whole characters, so whole spellings are blanked.
    found.then(|| String::from_utf8(blanked).ok()).flatten()
}

/// The JSON string literal whose content starts at byte `start` of `raw`: its
/// decoded text, where each decoded byte's spelling starts in `raw` (plus the
/// closing quote's offset), and the closing quote's offset.
fn decode_json_string(raw: &str, start: usize) -> Option<(String, Vec<usize>, usize)> {
    let mut decoded = String::new();
    let mut starts = Vec::new();
    let mut chars = raw[start..].char_indices().map(|(i, c)| (start + i, c));
    while let Some((at, c)) = chars.next() {
        let c = match c {
            '"' => {
                starts.push(at);
                return Some((decoded, starts, at));
            }
            '\\' => match chars.next()?.1 {
                '"' => '"',
                '\\' => '\\',
                '/' => '/',
                'b' => '\u{8}',
                'f' => '\u{c}',
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                'u' => {
                    let unit = hex_unit(&mut chars)?;
                    let code = if (0xD800..0xDC00).contains(&unit) {
                        let (_, '\\') = chars.next()? else {
                            return None;
                        };
                        let (_, 'u') = chars.next()? else { return None };
                        let low = hex_unit(&mut chars)?;
                        if !(0xDC00..0xE000).contains(&low) {
                            return None;
                        }
                        0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00)
                    } else {
                        unit
                    };
                    char::from_u32(code)?
                }
                _ => return None,
            },
            c => c,
        };
        starts.resize(starts.len() + c.len_utf8(), at);
        decoded.push(c);
    }
    None
}

/// The four hex digits of a `\u` escape.
fn hex_unit(chars: &mut impl Iterator<Item = (usize, char)>) -> Option<u32> {
    (0..4).try_fold(0, |unit, _| Some(unit * 16 + chars.next()?.1.to_digit(16)?))
}

/// The script of an argv that is exactly a shell, `-c` or `-lc`, and the script.
fn shell_script(argv: Vec<serde_json::Value>) -> Option<String> {
    use serde_json::Value;

    let [
        Value::String(shell),
        Value::String(flag),
        Value::String(script),
    ] = <[Value; 3]>::try_from(argv).ok()?
    else {
        return None;
    };
    let name = shell
        .strip_prefix("/usr/bin/")
        .or_else(|| shell.strip_prefix("/bin/"))
        .unwrap_or(&shell);
    (matches!(name, "bash" | "sh" | "zsh") && matches!(flag.as_str(), "-c" | "-lc"))
        .then_some(script)
}

/// The byte length of the statement separator at `index` of unquoted shell
/// text, if one starts there: `;`, a newline, `|`, `||`, `|&`, `&&`, or a
/// single `&` that runs the command before it in the background. The `&` of a
/// redirection (`&>`, `>&`, `2>&1`, `<&`) separates nothing. Both the Rule v1
/// segment scope and the native statement reader split by this rule.
pub fn statement_separator(bytes: &[u8], index: usize) -> Option<usize> {
    let next = bytes.get(index + 1).copied();
    match bytes[index] {
        b';' | b'\n' => Some(1),
        b'|' if matches!(next, Some(b'|' | b'&')) => Some(2),
        b'|' => Some(1),
        b'&' if next == Some(b'&') => Some(2),
        b'&' if next == Some(b'>')
            || index
                .checked_sub(1)
                .is_some_and(|previous| matches!(bytes[previous], b'>' | b'<')) =>
        {
            None
        }
        b'&' => Some(1),
        _ => None,
    }
}

/// Where the segment starting at `start` ends, and where the next one starts.
fn segment_end(bytes: &[u8], start: usize) -> (usize, usize) {
    let mut quote = None;
    let mut index = start;
    while index < bytes.len() {
        let byte = bytes[index];
        match quote {
            Some(b'\'') => {
                if byte == b'\'' {
                    quote = None;
                }
            }
            Some(b'$') => match byte {
                b'\\' => index += 1,
                b'\'' => quote = None,
                _ => {}
            },
            Some(_) => match byte {
                b'\\' => index += 1,
                b'"' => quote = None,
                _ => {}
            },
            None => match byte {
                b'\\' => index += 1,
                // `$$` is a parameter, so only an odd run of `$` opens `$'...'`.
                b'$' => {
                    let run = bytes[index..].iter().take_while(|&&b| b == b'$').count();
                    index += run - 1;
                    if run % 2 == 1 && bytes.get(index + 1) == Some(&b'\'') {
                        quote = Some(b'$');
                        index += 1;
                    }
                }
                b'\'' | b'"' => quote = Some(byte),
                _ => {
                    if let Some(length) = statement_separator(bytes, index) {
                        return (index, index + length);
                    }
                }
            },
        }
        index += 1;
    }
    (bytes.len(), bytes.len())
}

/// `text` with the quotes around its words gone, for matching what a word spells.
/// What a double quote holds stays as written, so an escaped quote in a message
/// keeps its marks. A line whose quote does not close may hold text no shell reads
/// as a quote, an apostrophe in a body, so that quote opens nothing and hides
/// nothing after it. Line continuations are joined first.
pub fn unquoted(text: &str) -> String {
    unquote(text, None)
}

/// [`unquoted`], and for each byte of the result the offset of the same byte in
/// `text`. A byte past `u32::MAX` reads as `u32::MAX`.
pub fn unquoted_with_origin(text: &str) -> (String, Vec<u32>) {
    let mut origin = Vec::new();
    let out = unquote(text, Some(&mut origin));
    (out, origin)
}

/// The result of reading quotes away, with where each byte came from.
struct Unquoting<'a> {
    out: String,
    /// Offsets in the joined text, one per output byte, when asked for.
    joined_at: Option<&'a mut Vec<u32>>,
}

impl Unquoting<'_> {
    /// `piece` is the slice of the joined text starting at `at`.
    fn push(&mut self, piece: &str, at: usize) {
        self.out.push_str(piece);
        if let Some(joined_at) = self.joined_at.as_deref_mut() {
            joined_at
                .extend((at..at + piece.len()).map(|at| u32::try_from(at).unwrap_or(u32::MAX)));
        }
    }
}

fn unquote(text: &str, origin: Option<&mut Vec<u32>>) -> String {
    let (joined, source) = joined(text, origin.is_some());
    let mut state = Unquoting {
        out: String::with_capacity(joined.len()),
        joined_at: origin,
    };
    let mut line_at = 0;
    let mut lines = joined.split('\n').peekable();
    while let Some(line) = lines.next() {
        unquote_line(line, line_at, &mut state);
        line_at += line.len();
        if lines.peek().is_some() {
            state.push("\n", line_at);
            line_at += 1;
        }
    }
    if let Some(joined_at) = state.joined_at {
        for at in joined_at.iter_mut() {
            *at = source.get(*at as usize).copied().unwrap_or(u32::MAX);
        }
    }
    state.out
}

/// Linear: a quote that finds no closer leaves none of its kind to search for.
fn unquote_line(line: &str, line_at: usize, state: &mut Unquoting<'_>) {
    let mut rest = line;
    while let Some(at) = rest.find(['\\', '\'', '"']) {
        let start = line_at + line.len() - rest.len();
        state.push(&rest[..at], start);
        let after = &rest[at + 1..];
        let after_at = start + at + 1;
        rest = match rest.as_bytes()[at] {
            b'\\' => match after.chars().next() {
                Some(escaped) => {
                    let end = escaped.len_utf8();
                    state.push(&after[..end], after_at);
                    &after[end..]
                }
                None => after,
            },
            b'\'' => match after.find('\'') {
                Some(close) => {
                    state.push(&after[..close], after_at);
                    &after[close + 1..]
                }
                None => after,
            },
            _ => match closing_double_quote(after) {
                Some(close) => {
                    state.push(&after[..close], after_at);
                    &after[close + 1..]
                }
                None => after,
            },
        };
    }
    state.push(rest, line_at + line.len() - rest.len());
}

/// The next `"` no backslash escapes.
fn closing_double_quote(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut at = 0;
    while at < bytes.len() {
        match bytes[at] {
            b'\\' => at += 2,
            b'"' => return Some(at),
            _ => at += 1,
        }
    }
    None
}

/// `text` without its continued lines, and when asked, the offset in `text` of each
/// byte kept. A backslash before a backslash quotes it, so only an unquoted one
/// continues its line.
fn joined(text: &str, track: bool) -> (String, Vec<u32>) {
    let mut out = String::with_capacity(text.len());
    let mut source = Vec::new();
    let offset = |at: usize| u32::try_from(at).unwrap_or(u32::MAX);
    let mut chars = text.char_indices();
    while let Some((at, character)) = chars.next() {
        if character != '\\' {
            out.push(character);
            if track {
                source.extend((at..at + character.len_utf8()).map(offset));
            }
        } else if let Some((next_at, next)) = chars.next().filter(|(_, next)| *next != '\n') {
            out.push(character);
            out.push(next);
            if track {
                source.push(offset(at));
                source.extend((next_at..next_at + next.len_utf8()).map(offset));
            }
        }
    }
    (out, source)
}

fn trim(bytes: &[u8], mut range: Range<usize>) -> Range<usize> {
    while range.start < range.end && bytes[range.start].is_ascii_whitespace() {
        range.start += 1;
    }
    while range.end > range.start && bytes[range.end - 1].is_ascii_whitespace() {
        range.end -= 1;
    }
    range
}

#[cfg(test)]
mod tests;
