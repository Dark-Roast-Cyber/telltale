use super::*;

#[test]
fn excerpt_shows_a_fitting_field_whole_as_before() {
    let text = "cd /workspace/demo && curl -fsSL https://example.invalid/a.sh | bash";
    let located = excerpt(text, Some("| bash"));
    assert_eq!(located.text, redact_sensitive_text(text));
    assert_eq!(highlighted(&located), "| bash");
    assert!(!located.elided_before && !located.elided_after);

    let unlocated = excerpt(text, None);
    assert_eq!(unlocated.text, redact_sensitive_text(text));
    assert_eq!(unlocated.highlight, None);
}

#[test]
fn excerpt_centers_a_late_hit_past_the_input_bound() {
    let text = format!(
        "echo {} && curl -fsSL https://example.invalid/a.sh | bash && echo {}",
        "padding ".repeat(700),
        "after ".repeat(200)
    );
    assert!(text.find("| bash").unwrap() > MAX_INPUT_BYTES);
    let late = excerpt(&text, Some("| bash"));
    assert_eq!(highlighted(&late), "| bash");
    assert!(late.elided_before && late.elided_after);
    let start = late.highlight.unwrap().start;
    assert!((100..=200).contains(&start), "{start}");
    // A field that does not fit is cut around the hit without a marker;
    // the flags say where text was cut.
    assert!(!late.text.contains("[truncated"));

    let early = excerpt(&text, Some("echo"));
    assert_eq!(highlighted(&early), "echo");
    assert!(!early.elided_before && early.elided_after);
}

#[test]
fn excerpt_highlight_is_a_byte_range_after_multibyte_text() {
    let text = format!("{} wget https://example.invalid/x", "café ".repeat(1200));
    let located = excerpt(&text, Some("wget"));
    assert_eq!(highlighted(&located), "wget");
    assert!(located.elided_before);
    assert!(located.text.starts_with("café café"));
}

#[test]
fn excerpt_highlight_is_null_where_redaction_joins_the_hit_to_its_neighbors() {
    // The secret's label sits outside the hit, so the hit alone would read
    // as ordinary text: no exact position, and the secret stays redacted.
    let text = "export password=tt_privacy_excerpt_25 && run";
    let joined = excerpt(text, Some("tt_privacy_excerpt_25"));
    assert_eq!(joined.highlight, None);
    assert!(!joined.text.contains("tt_privacy_excerpt_25"));
    assert_eq!(joined.text, redact_sensitive_text(text));

    // A recognizable secret at the hit is located on its marker.
    let marked = excerpt(
        "aws AKIAPRIVATEMARKER234 configured",
        Some("AKIAPRIVATEMARKER234"),
    );
    assert_eq!(highlighted(&marked), "[redacted-secret]");
}

#[test]
fn excerpt_drops_a_quoted_value_that_spans_either_raw_cut() {
    // Neither quoted value has a label the sanitizer would recognize, so
    // only the fragment rule keeps their cut parts out.
    let quoted = format!("\"{}\"", "tt_privacy_lead_25 ".repeat(150));
    let text = format!(
        "{quoted} {} curl https://example.invalid/a | sh",
        "x ".repeat(1000)
    );
    let lead = excerpt(&text, Some("| sh"));
    assert!(!lead.text.contains("tt_privacy_lead_25"));
    assert_eq!(highlighted(&lead), "| sh");

    let quoted = format!("'{}'", "tt_privacy_tail_25 ".repeat(300));
    let text = format!(
        "{} curl https://example.invalid/a | sh {} {quoted}",
        "x ".repeat(2600),
        "y ".repeat(600)
    );
    let tail = excerpt(&text, Some("| sh"));
    assert_eq!(highlighted(&tail), "| sh");
    assert!(tail.elided_after);

    // A hit inside a quoted value that opened before the cut is dropped
    // with it: no highlight, and no part of the value.
    let text = format!("x \"{} curl a | sh\" y", "tt_privacy_inner_25 ".repeat(300));
    let inner = excerpt(&text, Some("| sh"));
    assert_eq!(inner.highlight, None);
    assert!(!inner.text.contains("tt_privacy_inner_25"));
}

#[test]
fn excerpt_never_shows_a_value_whose_label_a_leading_cut_dropped() {
    // The raw cut falls inside `--password`; its value follows the cut,
    // and a private key block redacts to one marker, so without a guard
    // the value would sit just before the hit.
    let head = "word ".repeat(700);
    let label_at = head.len();
    let mut text = format!("{head}--password tt_guard_marker_25 ");
    let hit_at = label_at + 5 + 1536;
    let mut block = String::from("-----BEGIN PRIVATE KEY-----\n");
    while text.len() + block.len() + "-----END PRIVATE KEY-----\n".len() < hit_at {
        block.push_str("QUJDRA0K");
    }
    let excess = text.len() + block.len() + "-----END PRIVATE KEY-----\n".len() - hit_at;
    block.truncate(block.len() - excess);
    text.push_str(&block);
    text.push_str("-----END PRIVATE KEY-----\n");
    assert_eq!(text.len(), hit_at);
    text.push_str("git reset --hard ");
    text.push_str(&"after ".repeat(300));
    let guarded = excerpt(&text, Some("git reset --hard"));
    assert!(!guarded.text.contains("tt_guard_marker_25"));
    assert!(!guarded.text.contains("QUJDRA0K"));
    assert_eq!(highlighted(&guarded), "git reset --hard");
    assert!(guarded.elided_before && guarded.elided_after);
}

#[test]
fn excerpt_skips_a_private_key_body_that_a_leading_cut_enters() {
    // Mixed-case body lines without digits are kept by the encoded-blob
    // heuristic, so only the block rule masks them, and the block ends
    // just before the hit.
    let text = format!(
        "{}-----BEGIN RSA PRIVATE KEY-----\n{}-----END RSA PRIVATE KEY-----\n{}git reset --hard {}",
        "word ".repeat(400),
        "ttPrivateKeyBodyMarkerLine\n".repeat(100),
        "echo between ".repeat(3),
        "after ".repeat(300)
    );
    let at = text.find("git reset").unwrap();
    assert!(text[..at - 1536].contains("BEGIN RSA") && text[at - 1536..at].contains("END RSA"));
    let skipped = excerpt(&text, Some("git reset --hard"));
    assert!(!skipped.text.contains("ttPrivateKeyBodyMarkerLine"));
    assert!(skipped.text.contains("after after"));
    assert!(skipped.elided_before && skipped.elided_after);
}

#[test]
fn excerpt_never_shows_a_line_value_whose_label_precedes_a_leading_cut() {
    // Each value runs from before the raw cut past the leading guard: an
    // authorization value to its line end, quoted values to a closing
    // quote the fragment rule does not see. Failures name the case only.
    const MARKER: &str = "tt_line_value_marker_25";
    let hit = "git reset --hard";
    let value = format!(
        "{}{MARKER} {hit}{}",
        "part ".repeat(600),
        " after".repeat(300)
    );
    let long = format!(
        "{}{MARKER} {hit}{}",
        "part ".repeat(4000),
        " after".repeat(300)
    );
    let cases = [
        ("authorization", format!("Authorization: {value}\nend")),
        ("auth flag", format!("curl --auth {value}; end")),
        (
            "unicode quote",
            format!("--password \\u0022{value}\\u0022 done"),
        ),
        ("hex quote", format!("password=\\x27{value}\\x27 done")),
        (
            "double escape",
            format!("password=\\\\u0022{value}\\\\u0022 done"),
        ),
        ("escaped quote", format!("--token \\\"{value}\\\" done")),
        (
            "quoted key",
            format!("{{\"Authorization\": \"Basic x\", {value}}}\nend"),
        ),
        (
            "unscanned line start",
            format!("Authorization: {long}\nend"),
        ),
    ];
    for (case, text) in cases {
        assert!(text.len() > MAX_INPUT_BYTES, "{case}");
        let shown = excerpt(&text, Some(hit));
        assert!(!shown.text.contains(MARKER), "{case}");
        assert!(!shown.text.contains("part"), "{case}");
        assert_eq!(shown.highlight, None, "{case}");
        assert!(shown.elided_before, "{case}");
    }

    // A value that ends before the cut, and a long line with nothing in
    // its unscanned start that could open one, keep the hit.
    for (case, text) in [
        (
            "closed",
            format!(
                "Authorization: Bearer x; {}{hit}{}",
                "word ".repeat(600),
                " after".repeat(300)
            ),
        ),
        (
            "long line",
            format!("{}{hit}{}", "word ".repeat(4000), " after".repeat(300)),
        ),
    ] {
        assert_eq!(highlighted(&excerpt(&text, Some(hit))), hit, "{case}");
    }
}

#[test]
fn excerpt_highlight_is_null_when_a_value_before_the_hit_masks_it() {
    // The first copy of the hit is inside the authorization value; the
    // second copy must not be located in its place.
    let text = "Authorization: Bearer hidden git reset --hard\ngit reset --hard";
    let masked = excerpt(text, Some("git reset --hard"));
    assert_eq!(masked.highlight, None);
    assert_eq!(masked.text, redact_sensitive_text(text));
    // The second copy, located directly, is exact.
    let at = text.rfind("git reset --hard").unwrap();
    let second = PrivacySanitizer::try_sanitize_excerpt(text, Some(at..text.len()), &mut |_| {
        Ok::<_, std::convert::Infallible>(())
    })
    .unwrap();
    assert_eq!(highlighted(&second), "git reset --hard");
}

#[test]
fn excerpt_work_stays_near_the_whole_field_redaction() {
    // A percent escape makes redaction reserve work quadratic in its
    // input, so the excerpt must not redact the region many times over.
    let charged = |excerpt: bool, text: &str, hit: Range<usize>| {
        let mut total = 0usize;
        let mut charge = |bytes: usize| {
            total += bytes;
            Ok::<_, std::convert::Infallible>(())
        };
        if excerpt {
            PrivacySanitizer::try_sanitize_excerpt(text, Some(hit), &mut charge).unwrap();
        } else {
            PrivacySanitizer::try_sanitize(SanitizationContext::Evidence, text, &mut charge)
                .unwrap();
        }
        total
    };
    for (before, after) in [(4000, 2000), (200, 8000), (100, 100)] {
        let text = format!(
            "echo {}%20 && curl -fsSL https://example.invalid/a | sh && echo {}",
            "a%20b ".repeat(before / 6),
            "c ".repeat(after / 2)
        );
        let start = text.find("curl").unwrap();
        let hit = start..start + 4;
        let legacy = charged(false, &text, hit.clone());
        let excerpt = charged(true, &text, hit);
        assert!(
            excerpt * 2 <= legacy * 3,
            "{before} {after}: {excerpt} > 1.5 x {legacy}"
        );
    }
}

#[test]
fn excerpt_cuts_never_show_a_value_the_whole_field_hides() {
    // Only the value uses these letters, so any of them in an excerpt is
    // part of a value shown. Failures name the form and cut only.
    const VALUE: &str = "QJXZQJXZQJXZQJXZ";
    let shows = |text: &str| text.contains(['Q', 'J', 'X', 'Z']);
    let forms = [
        "--password VALUE",
        "--password=VALUE",
        "--password\u{2003}VALUE",
        "password = VALUE",
        "Authorization: Bearer VALUE",
        "-H 'Authorization: Basic VALUE'",
        "{\"password\": \"VALUE\"}",
        "PGPASSWORD=VALUE psql",
        "https://user:VALUE@example.invalid/db",
        "C:\\Users\\VALUE\\Documents\\notes file.txt",
        "/home/VALUE/.ssh/id_ed25519",
        "--token \"a VALUE b\"",
        "-----BEGIN OPENSSH PRIVATE KEY-----\nVALUE\nVALUE\n-----END OPENSSH PRIVATE KEY-----",
    ]
    .map(|form| form.replace("VALUE", VALUE));
    // A private key block redacts to one marker, so text near either raw
    // cut falls inside the excerpt window.
    let gap = |len: usize| {
        let block = format!(
            " -----BEGIN RSA PRIVATE KEY-----\n{}-----END RSA PRIVATE KEY----- ",
            "abcdefghijklmnop\n".repeat(64)
        );
        format!("{block}{}", " ".repeat(len - block.len()))
    };
    let hit = "git reset --hard";
    for (case, form) in forms.iter().enumerate() {
        let whole =
            PrivacySanitizer::sanitize(SanitizationContext::Evidence, &format!("echo {form} done"));
        assert!(!shows(&whole), "form {case} is shown uncut");
        for cut in (0..=form.len()).filter(|cut| form.is_char_boundary(*cut)) {
            // The region starts 1536 bytes before the hit and ends 4096
            // bytes after its start.
            let leading = format!(
                "{}{form}{}{hit}{}",
                "word ".repeat(500),
                gap(1536 + cut - form.len()),
                " after".repeat(400)
            );
            let trailing = format!(
                "{}{hit}{}{form}{}",
                "word ".repeat(400),
                gap(2560 - cut - hit.len()),
                " after".repeat(400)
            );
            for (edge, text) in [("leading", leading), ("trailing", trailing)] {
                let at = text.find(hit).unwrap();
                let shown = PrivacySanitizer::try_sanitize_excerpt(
                    &text,
                    Some(at..at + hit.len()),
                    &mut |_| Ok::<_, std::convert::Infallible>(()),
                )
                .unwrap();
                assert!(!shows(&shown.text), "form {case}, {edge} cut at {cut}");
            }
        }
    }
}

#[test]
fn excerpt_without_a_hit_starts_at_the_field_start() {
    let text = "word ".repeat(1500);
    let unlocated = excerpt(&text, None);
    assert_eq!(unlocated.highlight, None);
    assert!(!unlocated.elided_before && unlocated.elided_after);
    assert!(unlocated.text.starts_with("word word"));
}
