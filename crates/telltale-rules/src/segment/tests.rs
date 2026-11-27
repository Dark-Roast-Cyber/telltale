use super::{
    json_shell_call, may_be_json, segments, unquoted, unquoted_with_origin, without_continuation,
};

#[test]
fn quotes_are_read_away_and_a_quoted_string_keeps_what_it_holds() {
    assert_eq!(
        unquoted("rm -f ~/\".cl\"\"aude\"/s.json"),
        "rm -f ~/.claude/s.json"
    );
    assert_eq!(unquoted("git commit -m \"a; b\""), "git commit -m a; b");
    assert_eq!(
        unquoted("git commit -m 'a; \"b\"'"),
        "git commit -m a; \"b\""
    );
    assert_eq!(unquoted("a \"b \\\"c\\\" d\""), "a b \\\"c\\\" d");
    assert_eq!(unquoted("a\\;b"), "a;b");
    assert_eq!(unquoted("a \\\nb"), "a b");
    // A quote with no closer opens nothing, and the quote itself goes.
    assert_eq!(unquoted("it's\nrm x"), "its\nrm x");
}

/// Every byte of the reading is a byte of the text, at the offset it reports,
/// so a match in the reading can be placed in the text.
#[test]
fn every_byte_of_the_reading_names_its_place_in_the_text() {
    let alphabet = ["a", " ", "'", "\"", "\\", ";", "\n", "\u{e9}"];
    let mut texts = vec![String::new()];
    for _ in 0..6 {
        let longer: Vec<String> = texts
            .iter()
            .flat_map(|text| alphabet.iter().map(move |piece| format!("{text}{piece}")))
            .collect();
        for text in &longer {
            let (reading, origin) = unquoted_with_origin(text);
            assert_eq!(reading, unquoted(text), "{text:?}");
            assert_eq!(origin.len(), reading.len(), "{text:?}");
            for (at, &from) in origin.iter().enumerate() {
                assert_eq!(
                    text.as_bytes()[from as usize],
                    reading.as_bytes()[at],
                    "{text:?} byte {at}"
                );
            }
            assert!(origin.windows(2).all(|pair| pair[0] < pair[1]), "{text:?}");
        }
        texts = longer;
    }
}

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
fn a_background_ampersand_splits_and_a_redirection_ampersand_does_not() {
    assert_eq!(split("a & b &"), ["a", "b"]);
    assert_eq!(
        split("curl https://example.invalid/?a=1&b=2 2>&1 &> log >&2 0<&3; c"),
        [
            "curl https://example.invalid/?a=1",
            "b=2 2>&1 &> log >&2 0<&3",
            "c"
        ]
    );
    assert_eq!(split("a |& b"), ["a", "b"]);
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
