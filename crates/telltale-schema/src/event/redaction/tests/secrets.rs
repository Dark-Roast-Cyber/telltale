use super::*;

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
fn ordinary_bare_text_is_not_classified_as_a_secret() {
    let value = "ordinary-marker";
    assert_eq!(
        PrivacySanitizer::sanitize(SanitizationContext::Summary, value),
        value
    );
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
