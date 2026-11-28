use super::*;

#[test]
fn multiline_redaction_keeps_line_breaks_and_collapses_other_whitespace() {
    use super::super::redact_multiline_bounded;

    let (out, truncated) = redact_multiline_bounded("line   one\t\there\r\nline   two\n", 4096);
    assert_eq!(out, "line one here\nline two\n");
    assert!(!truncated);
    let (again, _) = redact_multiline_bounded(&out, 4096);
    assert!(again == out, "output is a fixed point");
}

#[test]
fn multiline_redaction_hides_a_token_across_an_internal_chunk_boundary() {
    use super::super::{MAX_INPUT_BYTES, redact_multiline_bounded};

    // Indented filler collapses, so a token that straddles the first
    // chunk's input bound lands well inside the output cap.
    let filler = format!("x{}\n", " ".repeat(60)).repeat(65);
    let token = synthetic_token("ghp_", 40, 7);
    let padding = " ".repeat(MAX_INPUT_BYTES - 16 - filler.len() - "alpha".len());
    let input = format!("{filler}alpha{padding}{token} omega\n");
    let token_start = filler.len() + "alpha".len() + padding.len();
    assert!(token_start < MAX_INPUT_BYTES && token_start + token.len() > MAX_INPUT_BYTES);

    let (out, truncated) = redact_multiline_bounded(&input, 4096);
    assert!(!truncated, "the whole record fits the output cap");
    assert!(out.ends_with("alpha [redacted-secret] omega\n"));
    assert!(!shows_marker_window(&out, &token), "token window visible");
}

#[test]
fn multiline_redaction_fails_closed_on_an_unbroken_secret_line() {
    use super::super::redact_multiline_bounded;

    let secret = synthetic_letters(5000, 11);
    let (out, truncated) = redact_multiline_bounded(&format!("api_key={secret}"), 4096);
    assert!(truncated);
    assert!(!shows_marker_window(&out, &secret), "secret window visible");
    assert!(out.len() <= 4096);
}

#[test]
fn multiline_chunk_cuts_never_show_what_one_call_hides() {
    use super::super::{MAX_INPUT_BYTES, MAX_MULTILINE_INPUT_BYTES, redact_multiline_with_limits};

    const CHUNKS: [usize; 4] = [24, 41, 64, 97];
    for (case_index, case) in SPAN_CASES.iter().enumerate() {
        for lead in 0..CHUNKS[CHUNKS.len() - 1] {
            let (input, markers) = span_case_input(case, case_index, lead);
            assert!(input.len() <= MAX_INPUT_BYTES);
            let (single, _) = redact_multiline_with_limits(
                &input,
                MAX_INPUT_BYTES,
                MAX_INPUT_BYTES,
                MAX_MULTILINE_INPUT_BYTES,
            );
            for chunk in CHUNKS.into_iter().filter(|chunk| lead < *chunk) {
                let (chunked, _) = redact_multiline_with_limits(
                    &input,
                    MAX_INPUT_BYTES,
                    chunk,
                    MAX_MULTILINE_INPUT_BYTES,
                );
                for (field, marker) in MARKER_FIELDS.iter().zip(&markers) {
                    if !case.template.contains(field) {
                        continue;
                    }
                    let hidden = !shows_marker_window(&single, marker);
                    assert!(
                        hidden || !case.hidden,
                        "case {case_index} field {field}: one call does not hide it"
                    );
                    assert!(
                        !hidden || !shows_marker_window(&chunked, marker),
                        "case {case_index}/{chunk}/{lead} field {field}: chunked output shows it"
                    );
                }
            }
        }
    }
}

#[test]
fn multiline_input_cut_never_shows_what_one_call_hides() {
    use super::super::{MAX_INPUT_BYTES, MAX_MULTILINE_INPUT_BYTES, redact_multiline_with_limits};

    for (case_index, case) in SPAN_CASES.iter().enumerate() {
        let (input, markers) = span_case_input(case, case_index, 3);
        let (single, _) = redact_multiline_with_limits(
            &input,
            MAX_INPUT_BYTES,
            MAX_INPUT_BYTES,
            MAX_MULTILINE_INPUT_BYTES,
        );
        for input_limit in 1..input.len() {
            let (cut, truncated) =
                redact_multiline_with_limits(&input, MAX_INPUT_BYTES, 41, input_limit);
            assert!(
                truncated,
                "case {case_index}/{input_limit}: cut not reported"
            );
            for (field, marker) in MARKER_FIELDS.iter().zip(&markers) {
                if case.template.contains(field) && !shows_marker_window(&single, marker) {
                    assert!(
                        !shows_marker_window(&cut, marker),
                        "case {case_index}/{input_limit} field {field}: input cut shows it"
                    );
                }
            }
        }
    }
}

#[test]
fn multiline_output_is_a_fixed_point_and_within_the_cap() {
    use super::super::{
        MAX_MULTILINE_INPUT_BYTES, redact_multiline_bounded, redact_multiline_with_limits,
    };

    for (case_index, case) in SPAN_CASES.iter().enumerate() {
        let (input, _) = span_case_input(case, case_index, 5);
        for maximum in [64, 100, 4096] {
            let (out, truncated) =
                redact_multiline_with_limits(&input, maximum, 41, MAX_MULTILINE_INPUT_BYTES);
            assert!(
                out.len() <= maximum,
                "case {case_index}/{maximum}: over the cap"
            );
            let (again, _) = redact_multiline_bounded(&out, maximum);
            // Compared without printing either side: both can hold markers.
            assert!(
                again == out,
                "case {case_index}/{maximum}: not a fixed point"
            );
            if truncated {
                assert!(
                    out.ends_with("[truncated]"),
                    "case {case_index}/{maximum}: unmarked cut"
                );
            }
        }
    }
}

#[test]
fn multiline_guards_fold_case_as_their_passes_do() {
    use super::super::redact_multiline_bounded;

    // The passes match with `(?i)`, so the Kelvin sign is `k` and the
    // long s is `s`: a guard must refuse the cut for those spellings too.
    let cases = [
        (
            "armor",
            padded_to_a_chunk(
                "https%3A%2F%2Fexample.invalid%2Ffoo%20-----BEGIN%20\u{212A}",
                "PRIVATE KEY-----\nAbCdEfGh",
            ),
            4096,
        ),
        (
            "package manager",
            padded_to_a_chunk("npm in\u{17f}tall", "AbCdEfGh"),
            4096,
        ),
        (
            "basic",
            padded_to_a_chunk("Ba\u{17f}ic", "AbCdEfGh\nordinary filler"),
            26,
        ),
    ];
    for (case, input, limit) in cases {
        let (out, _) = redact_multiline_bounded(&input, limit);
        assert!(
            !out.contains(&PLANTED[..7]),
            "case {case} field text: planted credential shown"
        );
    }
}

#[test]
fn multiline_hard_cut_drops_a_drive_prefix() {
    use super::super::redact_multiline_bounded;

    let input = format!("{}C:\\Toy Name.txt", " ".repeat(4089));
    let (out, truncated) = redact_multiline_bounded(&input, 4096);
    assert!(out == "[truncated]" && truncated, "drive field text: shown");
    let input = format!("{}see D:\\Synthetic Dir\\x", "w ".repeat(2040));
    let (out, truncated) = redact_multiline_bounded(&input, 4096);
    assert!(
        truncated && out.ends_with("see [truncated]"),
        "drive in a line field text: shown"
    );
}

#[test]
fn multiline_newline_normalization_stops_at_the_input_cap() {
    use super::super::normalize_newlines_bounded;

    assert_eq!(
        normalize_newlines_bounded("a\r\nb\rc\n", 64),
        ("a\nb\nc\n".to_owned(), false)
    );
    // A CRLF at the cap is read whole.
    let (out, over) = normalize_newlines_bounded("xxxx\r\nyyyy", 5);
    assert!(over);
    assert!(out.starts_with("xxxx\ny") && !out.contains('\r'));
    // The work is bounded by the cap, not the input.
    let long = "a\r\n".repeat(1 << 20);
    let (out, over) = normalize_newlines_bounded(&long, 1024);
    assert!(over);
    assert!(out.len() <= 1024 + 4, "copied {} bytes", out.len());
}

#[test]
fn multiline_short_limits_have_exact_outputs() {
    use super::super::redact_multiline_bounded;

    let input = "password=x and some ordinary words";
    let expected = [
        (1, ""),
        (10, ""),
        (11, "[truncated]"),
        (12, "[truncated]"),
        (13, "p [truncated]"),
        (20, "password [truncated]"),
        (25, "password [truncated]"),
        (40, "password=[redacted-secret] a [truncated]"),
        (50, "password=[redacted-secret] and some ordinary words"),
    ];
    for (limit, text) in expected {
        let (out, truncated) = redact_multiline_bounded(input, limit);
        assert_eq!(out, text, "limit {limit}");
        assert_eq!(truncated, limit < 50, "limit {limit}: truncated flag");
    }
    // `password=x` redacts to 26 bytes; at 21 the cut before the value
    // would read as a new assignment, so it backs off to the key.
    assert_eq!(
        redact_multiline_bounded("password=x", 21),
        ("password [truncated]".to_owned(), true)
    );
    assert_eq!(
        redact_multiline_bounded("password=x", 26),
        ("password=[redacted-secret]".to_owned(), false)
    );
}

#[test]
fn multiline_fit_comes_after_the_whole_text_is_redacted() {
    use super::super::redact_then_fit;

    // Joined text that is not yet a fixed point, as a missed cut guard
    // would leave it: the cut to fit must not keep a prefix of the
    // credential that only the whole text shows to be one.
    let cases = [
        (
            "basic across a join",
            "Ba\u{17f}ic\nAbCdEfGh\nordinary filler",
            26,
        ),
        ("basic in a line", "Basic AbCdEfGhIjKl", 22),
    ];
    for (case, body, limit) in cases {
        let (out, _) = redact_then_fit(body.to_owned(), false, limit);
        assert!(out.len() <= limit, "case {case}: over the cap");
        assert!(
            !out.contains(&PLANTED[..4]),
            "case {case} field text: planted credential prefix shown"
        );
    }
}

#[test]
fn multiline_fit_follows_the_complete_redaction() {
    use super::super::redact_multiline_bounded;

    // Redacted to a fixed point before the cut: every kept prefix is a
    // prefix of the full output.
    for (case_index, case) in SPAN_CASES.iter().enumerate() {
        let (input, _) = span_case_input(case, case_index, 3);
        let (full, _) = redact_multiline_bounded(&input, 4096);
        for limit in [16, 24, 32, 48, 64, 100] {
            let (out, truncated) = redact_multiline_bounded(&input, limit);
            assert!(
                out.len() <= limit,
                "case {case_index}/{limit}: over the cap"
            );
            let kept = out.strip_suffix("[truncated]").unwrap_or(&out).trim_end();
            assert!(
                full.starts_with(kept) && (truncated || out == full),
                "case {case_index}/{limit} field text: not a prefix of the full output"
            );
        }
    }
}

#[test]
fn multiline_never_shows_what_one_sanitizer_call_hides() {
    use super::super::{MAX_INPUT_BYTES, redact_multiline_bounded, redact_sensitive_text};

    for (case_index, case) in SPAN_CASES.iter().enumerate() {
        let (input, markers) = span_case_input(case, case_index, 3);
        let single = redact_sensitive_text(&input);
        let lead = "filler;\n".repeat((MAX_INPUT_BYTES - input.len() / 2) / 8);
        let forms = [
            ("fits", input.clone()),
            ("first chunk", format!("{input}{}", "filler;\n".repeat(600))),
            ("across a chunk", format!("{lead}{input}")),
        ];
        for (form, text) in forms {
            let (out, _) = redact_multiline_bounded(&text, MAX_INPUT_BYTES);
            for (field, marker) in MARKER_FIELDS.iter().zip(&markers) {
                if case.template.contains(field) && !shows_marker_window(&single, marker) {
                    assert!(
                        !shows_marker_window(&out, marker),
                        "case {case_index} {form} field {field}: shown"
                    );
                }
            }
        }
    }
}

#[test]
fn multiline_cut_guards_refuse_what_their_passes_read_across() {
    use super::super::{MultilineSource, url_pass_line};

    // (case, line before the cut, line after it, safe to cut)
    let cases = [
        ("plain", "ordinary words", "AbCdEfGh", true),
        ("basic", "Basic", "AbCdEfGh", false),
        ("basic folded", "Ba\u{17f}ic", "AbCdEfGh", false),
        ("bearer", "Bearer", "AbCdEfGh", false),
        ("phrase", "RSA", "PRIVATE KEY", false),
        ("phrase folded", "R\u{17f}A", "PRIVATE KEY", false),
        ("label", "api", "key AbCdEfGh", false),
        ("decoder folded", "ba\u{17f}e64", "--decode", false),
        ("manager word", "pnpm", "add AbCdEfGh", false),
        ("subcommand", "npm install", "AbCdEfGh", false),
        ("subcommand folded", "npm in\u{17f}tall", "AbCdEfGh", false),
        (
            "subcommand wide space",
            "npm\u{3000}install",
            "AbCdEfGh",
            false,
        ),
        ("secret key", "password =", "AbCdEfGh", false),
        ("secret key folded", "api_\u{212A}ey:", "AbCdEfGh", false),
        ("quote", "\"client_secret\"", ": \"AbCdEfGh\"", false),
        ("escape", "pass\\x77ord", "AbCdEfGh", false),
        (
            "escape before wide space",
            "pass\\x77\u{3000}ord",
            "AbCdEfGh",
            false,
        ),
        ("block scalar", "secret: |", "  AbCdEfGh", false),
        (
            "block scalar wide space",
            "secret: |",
            "\u{3000}AbCdEfGh",
            false,
        ),
        ("armor", "-----BEGIN RSA", "PRIVATE KEY-----", false),
        (
            "armor folded",
            "-----BEGIN \u{212A}",
            "PRIVATE KEY-----",
            false,
        ),
        ("path", "C:\\Users\\Synthetic", "Dir\\file.txt", false),
        ("path stop", "/srv/Synthetic;", "Dir/file.txt", true),
        (
            "escape in a path",
            "C:\\Users\\Synthetic;",
            "Dir\\file.txt",
            false,
        ),
        (
            "path wide space",
            "/srv/Synthetic",
            "Dir\u{3000}x/file.txt",
            false,
        ),
    ];
    for (case, left, next, safe) in cases {
        let text = format!("{left}\n{next}");
        let mut source = MultilineSource::new(&text, 4096);
        assert_eq!(
            source.cut_is_safe(&url_pass_line(left), 1),
            safe,
            "case {case}"
        );
    }
}
