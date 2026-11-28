use super::*;

/// Text that starts with `//name/` is ambiguous: a build label, a document
/// query and a depot path are spelled like a network path with forward
/// slashes. It is read as a scheme-relative URL, never redacted whole as
/// a Windows path.
#[test]
fn double_slash_names_are_read_as_urls_not_as_windows_paths() {
    for kept in [
        "bazel build //app/server:binary",
        "xpath //div/span/text()",
        "p4 sync //depot/main/src/...",
        "open //server/share/example/notes.txt now",
        "copy //192.0.2.10/share/a.txt .",
        "dir //FILESRV01/share",
    ] {
        assert_eq!(redact_sensitive_text(kept), kept);
        assert_eq!(
            PrivacySanitizer::sanitize(SanitizationContext::Diagnostic, kept),
            kept
        );
    }
}

#[test]
fn mixed_width_and_escaped_unc_paths_redact_server_names_whole() {
    let cases = [
        (r"dir \\fileserver\\share\notes.txt", "dir [sensitive-path]"),
        (
            r"dir \\fileserver\\share\\notes.txt",
            "dir [sensitive-path]",
        ),
        (
            r"dir \\fileserver\\\share\notes.txt",
            "dir [sensitive-path]",
        ),
        (
            r"dir \\fileserver\\\\share\\notes.txt",
            "dir [sensitive-path]",
        ),
        (
            r"dir \\\\fileserver\share\notes.txt",
            "dir [sensitive-path]",
        ),
        (
            r"dir \\\\fileserver\\\\share\\notes.txt",
            "dir [sensitive-path]",
        ),
        (r"dir \\\fileserver\share\notes.txt", "dir [sensitive-path]"),
        (
            r"dir \\fileserver\\Shared Docs\\SyntheticUser\\notes.txt",
            "dir [sensitive-path]",
        ),
        (
            r#"{"path":"\\fileserver\\share\\notes.txt"}"#,
            r#"{"path":"[sensitive-path]"}"#,
        ),
        (
            r#"{"path":"\\\\fileserver\\\\share\\notes.txt"}"#,
            r#"{"path":"[sensitive-path]"}"#,
        ),
        (
            r"dir \\10.0.0.5\\c$\\Users\\SyntheticUser\\notes.txt",
            "dir [sensitive-path]",
        ),
        (
            r"exit\r\n\\fileserver\\share\notes.txt",
            r"exit\r\n[sensitive-path]",
        ),
        (
            r"dir \\?\\C:\Users\SyntheticUser\notes.txt",
            "dir [sensitive-path]",
        ),
        (
            r"dir \\\\?\C:\Users\SyntheticUser\notes.txt",
            "dir [sensitive-path]",
        ),
        (
            r"dir \\?\\UNC\\fileserver\\share\notes.txt",
            "dir [sensitive-path]",
        ),
        (
            r"dir \\?\\Volume{12345678-1234-1234-1234-1234567890ab}\Users\SyntheticUser\notes.txt",
            "dir [sensitive-path]",
        ),
        (r"dir \\.\\pipe\\SyntheticPipe", "dir [sensitive-path]"),
        (r"dir \\\\.\pipe\SyntheticPipe", "dir [sensitive-path]"),
    ];

    for (case, (input, expected)) in cases.into_iter().enumerate() {
        let redacted = redact_sensitive_text(input);
        assert!(redacted == expected, "UNC path case {case}");
        assert!(!redacted.contains("fileserver"), "UNC server case {case}");
        assert!(!redacted.contains("Synthetic"), "UNC privacy case {case}");
        assert!(
            redact_sensitive_text(&redacted) == redacted,
            "UNC idempotence case {case}"
        );
    }
}

/// The URL reading still redacts what a URL may not show.
#[test]
fn double_slash_names_keep_url_redaction_of_home_directories() {
    let redacted = redact_sensitive_text("open //server/Users/example/notes.txt now");
    assert!(!redacted.contains("example"), "{redacted}");
}

/// Scheme-relative URLs, URLs with doubled slashes and ordinary `//` text
/// keep their current treatment.
#[test]
fn urls_and_ordinary_double_slash_text_are_not_read_as_unc_paths() {
    for kept in [
        r#"<script src="//cdn.example.com/lib/app.js"></script>"#,
        "fetch //api.example.com:8443/v1/items",
        "//localhost:8080/health",
        "https://example.invalid/a//b/c",
        "http://host//double/slash",
        "a // b",
        "x = n//2/3",
        "call(); //eslint-disable-line",
        "//server",
    ] {
        assert_eq!(redact_sensitive_text(kept), kept);
    }
}

#[test]
fn unicode_unc_server_names_are_redacted_without_losing_boundaries() {
    let redacted = redact_sensitive_text(r"dir \\büro\team\notes.txt now");
    assert!(redacted == "dir [sensitive-path] now", "Unicode UNC path");
    assert!(
        redact_sensitive_text(&redacted) == redacted,
        "Unicode UNC idempotence"
    );
    assert!(
        redact_sensitive_text("dir \\\\bu\u{0308}ro\\team\\notes.txt now")
            == "dir [sensitive-path] now",
        "decomposed Unicode UNC path"
    );
    assert!(
        redact_sensitive_text(r"dir \\文件\共享\notes.txt now") == "dir [sensitive-path] now",
        "CJK UNC path"
    );
    assert!(
        redact_sensitive_text(r"dir \\_synthetic-host\team\notes.txt now")
            == "dir [sensitive-path] now",
        "underscore UNC path"
    );
}

#[test]
fn webdav_unc_server_components_are_redacted_whole() {
    let redacted = redact_sensitive_text(r"dir \\portal.example@SSL\DavWWWRoot\team\notes.txt now");
    assert!(redacted == "dir [sensitive-path] now", "WebDAV UNC path");
    assert!(
        redact_sensitive_text(&redacted) == redacted,
        "WebDAV UNC idempotence"
    );
}

#[test]
fn regex_like_unc_servers_are_not_exempt_with_an_ordinary_share() {
    assert!(
        redact_sensitive_text(r"dir \\d+\\share\notes.txt now") == "dir [sensitive-path] now",
        "quantified UNC server with ordinary share"
    );
    assert!(
        redact_sensitive_text(r#"grep -E "\\d+\\s+\\w+""#) == r#"grep -E "\\d+\\s+\\w+""#,
        "quantified regex escapes"
    );
}
