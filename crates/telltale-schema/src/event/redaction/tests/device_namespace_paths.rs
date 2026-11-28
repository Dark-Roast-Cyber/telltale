use super::*;

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
