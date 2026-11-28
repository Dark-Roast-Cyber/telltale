use super::*;

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
