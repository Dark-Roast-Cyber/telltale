use super::*;

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
fn privacy_corpus_bounds_pathological_assignment_input() {
    let marker = "TT_PRIVACY_BOUNDED_25";
    let redacted = PrivacySanitizer::sanitize(
        SanitizationContext::Evidence,
        &format!("TOKEN={marker}{}", "x".repeat(100_000)),
    );

    assert!(!redacted.contains(marker));
    assert!(redacted.len() <= 512);
}
