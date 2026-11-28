use super::*;

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
