use super::*;

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
