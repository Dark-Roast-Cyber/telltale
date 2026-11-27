use super::*;

#[test]
fn terminal_identifiers_reject_lowercase_known_credentials() {
    for credential in ["sk-abcdefghijklmnop", "ghp_abcdefghijklmnopqrstuvwxyz12"] {
        assert!(terminal_identifier("tool", credential).starts_with("[tool:"));
    }
    assert_eq!(
        terminal_identifier("rule", "secret.env.read"),
        "secret.env.read"
    );
}

#[test]
fn every_client_name_stays_readable() {
    let names = ClientId::ALL
        .iter()
        .map(|client| client.as_str())
        .chain(RETIRED_CLIENT_NAMES.iter().copied());
    for name in names {
        assert_eq!(terminal_client_id(name), name);
        assert_eq!(terminal_product_metadata("agent", name), name);
    }
    assert_eq!(terminal_client_id("codex,claude"), "codex,claude");
    for value in ["claude-code", "Claude", "notaclient"] {
        assert_ne!(terminal_client_id(value), value, "{value}");
        assert_ne!(terminal_product_metadata("agent", value), value, "{value}");
    }
}

#[test]
fn tool_labels_keep_only_known_harness_names_verbatim() {
    assert_eq!(terminal_tool_label("Bash"), "Bash");
    assert_eq!(terminal_tool_label("WebFetch"), "WebFetch");
    assert_eq!(terminal_tool_label("apply_patch"), "apply_patch");
    // Unknown mixed-case or host-defined names stay opaque, as in Event 3.
    for value in [
        "AKIAABCDEFGHIJKLMNOP",
        "mcp__Private__Tool",
        "bash ",
        "BASH",
    ] {
        assert!(terminal_tool_label(value).starts_with("[tool:"), "{value}");
        assert_eq!(
            terminal_tool_label(value),
            terminal_identifier("tool", value)
        );
    }
    assert!(terminal_identifier("tool", "Bash").starts_with("[tool:"));
}

#[test]
fn historical_tool_labels_preserve_every_produced_label() {
    // A host validating a stored or received action tool label must accept
    // exactly what `terminal_tool_label` produced, without re-hashing it.
    for value in [
        "Bash",
        "WebFetch",
        "apply_patch",
        "shell",
        "BASH",
        "mcp__Private__Tool",
        "AKIAABCDEFGHIJKLMNOP",
        "/home/synthetic/private/tool",
    ] {
        let label = terminal_tool_label(value);
        assert_eq!(terminal_historical_tool_label(&label), label, "{value}");
    }
    // The generic historical identifier is not a tool-label validator: it
    // re-hashes readable built-in names, so it would reject a valid label.
    assert_ne!(terminal_historical_identifier("tool", "Bash"), "Bash");
    // Values that are not produced labels are normalized, never preserved.
    for value in ["BASH", "mcp__Private__Tool", "[tool:not-a-hash]"] {
        assert_ne!(terminal_historical_tool_label(value), value, "{value}");
        assert_eq!(
            terminal_historical_tool_label(value),
            terminal_tool_label(value)
        );
    }
}

#[test]
fn terminal_identifiers_reject_lowercase_path_and_url_shapes() {
    for value in [
        "https://source.example.invalid/private",
        "relative/source/path",
    ] {
        assert!(
            terminal_identifier("tool", value).starts_with("[tool:"),
            "path-shaped source identifier remained terminal text"
        );
        assert!(
            terminal_identifier("process", value).starts_with("[process:"),
            "path-shaped source process identifier remained terminal text"
        );
    }
}

#[test]
fn canonical_opaque_identifier_recognizer_requires_registered_exact_markers() {
    let digest = "a".repeat(64);
    let marker = format!("[session:{digest}]");
    let parsed = parse_canonical_opaque_identifier(&marker).expect("exact marker");
    assert_eq!(parsed.kind(), "session");
    assert_eq!(parsed.digest(), digest);
    assert!(is_canonical_opaque_identifier_for_kind("session", &marker));
    assert!(!is_canonical_opaque_identifier_for_kind("model", &marker));

    for malformed in [
        format!("[session:{}]", "a".repeat(63)),
        format!("[session:{}]", "a".repeat(65)),
        format!("[session:{}]", "g".repeat(64)),
        format!("[session:{}]", "A".repeat(64)),
        format!("prefix{marker}"),
        format!("{marker}suffix"),
        format!("[unknown:{digest}]"),
    ] {
        assert!(
            parse_canonical_opaque_identifier(&malformed).is_none(),
            "malformed marker received canonical recognition"
        );
        assert_ne!(
            terminal_historical_session_id(&malformed),
            malformed,
            "malformed marker received historical preservation"
        );
    }
}
