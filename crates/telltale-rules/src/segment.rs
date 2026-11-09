//! Shell command segments for Rule v1 `detection.scope: segment`.
//!
//! A segment is the text between unquoted `;`, `|`, `||`, `&&` and newline
//! separators, trimmed of surrounding ASCII whitespace; empty segments are
//! skipped. Single quotes are literal. A backslash escapes the next character
//! outside single quotes, so `\;` and a `\"` inside double quotes end nothing,
//! and `$'...'` takes backslash escapes, so its `\'` ends nothing either. A `#`
//! after an unescaped space or tab, or at a segment's start, and outside quotes
//! starts a comment, which runs to the end of its line and is in no segment, so
//! its quotes open nothing. Once a backtick, `(` or `${` appears in a segment, a
//! `#` in it is text, since a substitution or an expansion may hold it.
//! An unclosed quote runs to the end of the text, which yields one larger
//! segment rather than an error. A single `&` is not a separator, so `2>&1`,
//! `&>` and unquoted query strings stay in their segment.
//! This also leaves background commands (`a & b`) in one segment: an upload
//! after a single `&` can still exclude a download before it.
//!
//! This is a lexical split, not a shell parser: subshells, command
//! substitution and heredocs are not interpreted. It makes one pass
//! over the bytes and allocates nothing. Every separator, quote and escape is
//! ASCII, so every range starts and ends on a character boundary.

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

/// Where the segment starting at `start` ends, and where the next one starts.
fn segment_end(bytes: &[u8], start: usize) -> (usize, usize) {
    let mut quote = None;
    // Whether the last byte read outside quotes was in a word, and whether a
    // substitution or an expansion has opened, in which a `#` may be text.
    let (mut word, mut nested) = (false, false);
    let mut index = start;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'`' || byte == b'(' || (byte == b'{' && index > 0 && bytes[index - 1] == b'$') {
            nested = true;
        }
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
            None => {
                match byte {
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
                    // A comment runs to the end of its line and is in no segment.
                    b'#' if !word && !nested => {
                        return match bytes[index..].iter().position(|&b| b == b'\n') {
                            Some(offset) => (index, index + offset + 1),
                            None => (index, bytes.len()),
                        };
                    }
                    b';' | b'\n' => return (index, index + 1),
                    b'|' if bytes.get(index + 1) == Some(&b'|') => return (index, index + 2),
                    b'|' => return (index, index + 1),
                    b'&' if bytes.get(index + 1) == Some(&b'&') => return (index, index + 2),
                    _ => {}
                }
                // Only a shell's blanks end a word; an escaped one is in it.
                word = !matches!(byte, b' ' | b'\t');
            }
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
    use super::segments;

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
    fn a_comment_is_in_no_segment_and_its_quotes_open_nothing() {
        assert_eq!(split("a # b; c\nd"), ["a", "d"]);
        assert_eq!(split("a # don't\nb"), ["a", "b"]);
        assert_eq!(split("a # $'\\'\nb"), ["a", "b"]);
        assert_eq!(split("# x\nb"), ["b"]);
        assert_eq!(split("a;# x\nb"), ["a", "b"]);
        assert_eq!(split("a # x"), ["a"]);
        // Inside a word, a quote or a parameter, `#` is text.
        assert_eq!(split("a#b; c"), ["a#b", "c"]);
        assert_eq!(
            split("echo $# ${#x} '# y'; c"),
            ["echo $# ${#x} '# y'", "c"]
        );
        assert_eq!(
            split("curl https://example.invalid/#f; c"),
            ["curl https://example.invalid/#f", "c"]
        );
    }

    #[test]
    fn a_hash_that_may_be_text_starts_no_comment() {
        // An escaped blank or a carriage return is part of the word.
        assert_eq!(split("a\\ #b; c"), ["a\\ #b", "c"]);
        assert_eq!(split("a\r#b; c"), ["a\r#b", "c"]);
        // After a substitution or an expansion opens, a `#` stays text.
        assert_eq!(split("a `b #c`; d"), ["a `b #c`", "d"]);
        assert_eq!(split("a \"`b \" #c\" `\"; d"), ["a \"`b \" #c\" `\"", "d"]);
        assert_eq!(split("a $(b #c)\nd"), ["a $(b #c)", "d"]);
        assert_eq!(split("a \"$(b \" #c\")\"; d"), ["a \"$(b \" #c\")\"", "d"]);
        assert_eq!(split("a ${x:- #}; c"), ["a ${x:- #}", "c"]);
        assert_eq!(split("a=(b #c); d"), ["a=(b #c)", "d"]);
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
