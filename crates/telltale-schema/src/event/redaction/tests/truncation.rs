use super::*;

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
