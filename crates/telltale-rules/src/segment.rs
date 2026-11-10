//! Shell command segments for Rule v1 `detection.scope: segment`.
//!
//! A segment is the text between unquoted `;`, `|`, `||`, `&&` and newline
//! separators, trimmed of surrounding ASCII whitespace; empty segments are
//! skipped. Single quotes are literal. A backslash escapes the next character
//! outside single quotes, so `\;` and a `\"` inside double quotes end nothing,
//! and `$'...'` takes backslash escapes, so its `\'` ends nothing either.
//! An unclosed quote runs to the end of the text, which yields one larger
//! segment rather than an error. A single `&` is not a separator, so `2>&1`,
//! `&>` and unquoted query strings stay in their segment.
//! This also leaves background commands (`a & b`) in one segment: an upload
//! after a single `&` can still exclude a download before it.
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
                b';' | b'\n' => return (index, index + 1),
                b'|' if bytes.get(index + 1) == Some(&b'|') => return (index, index + 2),
                b'|' => return (index, index + 1),
                b'&' if bytes.get(index + 1) == Some(&b'&') => return (index, index + 2),
                _ => {}
            },
        }
        index += 1;
    }
    (bytes.len(), bytes.len())
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
mod tests {
    use super::{json_shell_call, may_be_json, segments, without_continuation};

    fn split(text: &str) -> Vec<&str> {
        segments(text).map(|range| &text[range]).collect()
    }

    #[test]
    fn splits_on_unquoted_command_separators() {
        assert_eq!(
            split("a; b && c || d | e\nf"),
            ["a", "b", "c", "d", "e", "f"]
        );
        assert_eq!(split("a\r\nb"), ["a", "b"]);
        assert_eq!(split("a |& b"), ["a", "& b"]);
    }

    #[test]
    fn quotes_and_escapes_keep_separators_inside_a_segment() {
        assert_eq!(split("a 'x; y | z' b; c"), ["a 'x; y | z' b", "c"]);
        assert_eq!(
            split("a \"x && y || z\" b; c"),
            ["a \"x && y || z\" b", "c"]
        );
        assert_eq!(split("a \"x\\\"; y\" b; c"), ["a \"x\\\"; y\" b", "c"]);
        assert_eq!(split("a \"x\\\\\"; c"), ["a \"x\\\\\"", "c"]);
        assert_eq!(split("a 'x\\'; c"), ["a 'x\\'", "c"]);
        assert_eq!(
            split("find . -exec rm {} \\; ; c"),
            ["find . -exec rm {} \\;", "c"]
        );
        assert_eq!(split("grep a\\|b f | c"), ["grep a\\|b f", "c"]);
        assert_eq!(split("a 'x\ny'; c"), ["a 'x\ny'", "c"]);
        assert_eq!(split("a $'x\\'; y' b; c"), ["a $'x\\'; y' b", "c"]);
        assert_eq!(split("a $'x\\\\'; c"), ["a $'x\\\\'", "c"]);
        assert_eq!(split("a \"$'x\"; c"), ["a \"$'x\"", "c"]);
        // `$$` is a parameter, so the quote after it is a plain one.
        assert_eq!(split("a $$'x\\'; c"), ["a $$'x\\'", "c"]);
        assert_eq!(split("a $$$'x\\'; y' b; c"), ["a $$$'x\\'; y' b", "c"]);
    }

    #[test]
    fn a_json_shell_call_has_one_command_and_only_known_metadata() {
        for (text, command, others) in [
            (r#"{"cmd":"a; b"}"#, "a; b", &[][..]),
            (
                r#"{"command":"a","description":"d","timeout":5,"mode":null}"#,
                "a",
                &["d"][..],
            ),
            (
                r#"{"cmd":"a","workdir":"/w","yield_time_ms":1,"justification":"j"}"#,
                "a",
                &["j", "/w"][..],
            ),
            (
                r#"{"command":["bash","-lc","a; b"],"workdir":"/w"}"#,
                "a; b",
                &["/w"][..],
            ),
            (r#"{"command":["/bin/sh","-c","a"]}"#, "a", &[][..]),
            (r#"{"command":["/usr/bin/zsh","-c","a"]}"#, "a", &[][..]),
            (r#"{"cmd":"first","cmd":"last"}"#, "last", &[][..]),
            (r#"{"cmd":"\u0063"}"#, "c", &[][..]),
        ] {
            // Members come back in the JSON map's key order.
            let call = json_shell_call(text).expect(text);
            assert_eq!(call.command, command, "{text}");
            assert_eq!(call.other_strings, others, "{text}");
        }
    }

    #[test]
    fn any_other_shape_is_not_a_json_shell_call() {
        for text in [
            // No command member, or one that is not a shell call.
            "[]",
            r#"["bash","-c","a"]"#,
            r#"{"description":"a"}"#,
            r#"{"cmd":1}"#,
            r#"{"cmd":["bash","-c","a"]}"#,
            r#"{"command":["curl","-d","@f","x"]}"#,
            r#"{"command":["python","-c","a"]}"#,
            r#"{"command":["bash","-x","a"]}"#,
            r#"{"command":["bash","-c","a","arg0"]}"#,
            r#"{"command":["bash","-c",1]}"#,
            // Members that could carry the real request.
            r#"{"cmd":"a","command":"b"}"#,
            r#"{"cmd":"a","args":"-d @f"}"#,
            r#"{"cmd":"a","args":["-d","@f"]}"#,
            r#"{"cmd":"a","description":["d"]}"#,
            r#"{"cmd":"a","workdir":{"path":"/w"}}"#,
            // Not one whole JSON value.
            "{ curl https://example.invalid; }",
            r#"{"cmd":"a""#,
            r#"{"cmd":"a"} trailing"#,
        ] {
            assert!(json_shell_call(text).is_none(), "{text}");
        }
        let deep = format!("{}{}", "[".repeat(4096), "]".repeat(4096));
        assert!(json_shell_call(&deep).is_none());
    }

    #[test]
    fn only_text_that_opens_like_json_is_parsed() {
        for text in [
            "curl https://example.invalid",
            "\"curl https://example.invalid\"",
        ] {
            assert!(!may_be_json(text), "{text}");
        }
        for text in ["{ a; }", " {}", "[ -f a ] && b"] {
            assert!(may_be_json(text), "{text}");
        }
    }

    #[test]
    fn only_one_trailing_continuation_is_removed() {
        assert_eq!(without_continuation("a \\"), "a");
        assert_eq!(without_continuation("a"), "a");
        assert_eq!(without_continuation("a \\\\"), "a \\");
    }

    #[test]
    fn single_ampersands_do_not_split() {
        assert_eq!(
            split("curl https://example.invalid/?a=1&b=2 2>&1 &> log; c"),
            ["curl https://example.invalid/?a=1&b=2 2>&1 &> log", "c"]
        );
        assert_eq!(split("a & b"), ["a & b"]);
    }

    #[test]
    fn empty_and_whitespace_segments_are_skipped() {
        assert!(split("").is_empty());
        assert!(split(" ;;\n || \t&& | ").is_empty());
        assert_eq!(split(";;a;;"), ["a"]);
        assert_eq!(split("  a  "), ["a"]);
    }

    #[test]
    fn unclosed_quotes_and_trailing_escapes_run_to_the_end() {
        assert_eq!(split("a 'x; b | c"), ["a 'x; b | c"]);
        assert_eq!(split("a \"x; b\\"), ["a \"x; b\\"]);
        assert_eq!(split("a; b\\"), ["a", "b\\"]);
        assert_eq!(split("don't; curl x"), ["don't; curl x"]);
    }

    #[test]
    fn ranges_are_field_relative_and_respect_unicode() {
        let text = "é; ünï 'ß;ü' | 日本\n∅";
        let ranges = segments(text).collect::<Vec<_>>();
        assert_eq!(split(text), ["é", "ünï 'ß;ü'", "日本", "∅"]);
        for range in ranges {
            assert!(text.is_char_boundary(range.start));
            assert!(text.is_char_boundary(range.end));
        }
        // A backslash before a multi-byte character escapes only its lead byte;
        // continuation bytes are never separators.
        assert_eq!(split("a\\é; b"), ["a\\é", "b"]);
    }

    #[test]
    fn malformed_input_is_bounded_and_never_panics() {
        let alphabet = [
            "'", "\"", "\\", ";", "|", "&", "\n", " ", "é", "x", "\r", "\t",
        ];
        let mut state = 0x9e37_79b9_u32;
        for length in 0..64 {
            for _ in 0..64 {
                let mut text = String::new();
                for _ in 0..length {
                    state ^= state << 13;
                    state ^= state >> 17;
                    state ^= state << 5;
                    text.push_str(alphabet[state as usize % alphabet.len()]);
                }
                let mut previous_end = 0;
                let mut count = 0;
                for range in segments(&text) {
                    assert!(range.start >= previous_end && range.start < range.end);
                    assert!(range.end <= text.len());
                    assert!(text.is_char_boundary(range.start));
                    assert!(text.is_char_boundary(range.end));
                    previous_end = range.end;
                    count += 1;
                }
                assert!(count <= text.len() / 2 + 1);
            }
        }
        let separators = ";".repeat(1 << 16);
        assert_eq!(segments(&separators).count(), 0);
    }
}
