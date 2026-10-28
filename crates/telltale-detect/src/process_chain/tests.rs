use super::{observations_from_command_line, split_statements, statement_spans};

#[test]
fn explicit_nested_shells_preserve_statement_order_without_wrapper_observations() {
    let observations = observations_from_command_line("cmd.exe /c \"whoami && hostname\"");
    assert_eq!(observations.len(), 2);
    assert_eq!(observations[0].child.normalized_name(), "whoami");
    assert_eq!(observations[1].child.normalized_name(), "hostname");
    assert!(
        observations
            .iter()
            .all(|o| o.parent.normalized_name() == "cmd" && !o.parent_inferred)
    );
    let nested = observations_from_command_line("bash -c 'cmd /c whoami'");
    assert_eq!(nested.len(), 1);
    assert_eq!(nested[0].parent.normalized_name(), "cmd");
    assert!(!nested[0].parent_inferred);
}

#[test]
fn unrecoverable_interpreter_payload_is_retained_and_depth_is_bounded() {
    let encoded = observations_from_command_line("powershell.exe -enc SQBFAFgAKAA=");
    assert_eq!(encoded.len(), 1);
    assert_eq!(encoded[0].child.normalized_name(), "powershell");
    assert!(encoded[0].parent.normalized_name().is_empty());
    assert_eq!(
        observations_from_command_line("cmd /c cmd /c cmd /c whoami").len(),
        1
    );
    assert!(observations_from_command_line("cmd /c cmd /c cmd /c cmd /c whoami").is_empty());
}

#[test]
fn windows_inference_does_not_invent_a_posix_parent() {
    for text in ["whoami", r"C:\tools\custom.exe", "%TEMP%\\custom"] {
        let observations = observations_from_command_line(text);
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].parent.normalized_name(), "cmd");
        assert!(observations[0].parent_inferred);
    }
    let observations = observations_from_command_line("git status && ls -la");
    assert_eq!(observations.len(), 2);
    assert!(
        observations
            .iter()
            .all(|o| o.parent.normalized_name().is_empty())
    );
}

#[test]
fn transparent_wrappers_quotes_separators_and_normalization() {
    let observations = observations_from_command_line(
        r#"env MODE=test sudo nohup "C:\Program Files\WHOAMI.EXE" "a;b|c&d"; hostname | ipconfig || netstat
git status"#,
    );
    assert_eq!(
        observations
            .iter()
            .map(|o| o.child.normalized_name())
            .collect::<Vec<_>>(),
        ["whoami", "hostname", "ipconfig", "netstat", "git"]
    );
    assert_eq!(
        observations[0].child.path.as_deref(),
        Some(r"C:\Program Files\WHOAMI.EXE")
    );
    assert!(
        observations[0]
            .child
            .command_line_text()
            .contains("a;b|c&d")
    );
}

#[test]
fn statement_spans_locate_each_statement_in_the_command() {
    let command = "cd /w && curl -o a 'x|y' | sh; echo \"a;b\" || true &\nlast";
    let statements: Vec<&str> = statement_spans(command)
        .into_iter()
        .map(|span| &command[span])
        .collect();
    assert_eq!(
        statements,
        [
            "cd /w ",
            " curl -o a 'x|y' ",
            " sh",
            " echo \"a;b\" ",
            " true ",
            "last"
        ]
    );
    assert_eq!(split_statements(command), statements);
    assert!(statement_spans("  ;; && ").is_empty());
    let multibyte = "echo café | wc";
    let spans = statement_spans(multibyte);
    assert_eq!(&multibyte[spans[1].clone()], " wc");
}
