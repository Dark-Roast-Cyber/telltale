use super::*;

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
