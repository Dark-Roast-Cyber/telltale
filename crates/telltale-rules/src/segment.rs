//! Shell command segments for Rule v1 `detection.scope: segment`.
//!
//! A segment is the text between unquoted `;`, `|`, `||`, `&&` and newline
//! separators, trimmed of surrounding ASCII whitespace; empty segments are
//! skipped. Single quotes are literal. A backslash escapes the next character
//! outside single quotes, so `\;` and a `\"` inside double quotes end nothing.
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
            Some(_) => match byte {
                b'\\' => index += 1,
                b'"' => quote = None,
                _ => {}
            },
            None => match byte {
                b'\\' => index += 1,
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
    use super::{segments, without_continuation};

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
