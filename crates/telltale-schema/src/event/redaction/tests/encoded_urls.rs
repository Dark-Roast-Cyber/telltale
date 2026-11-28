use super::*;

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
