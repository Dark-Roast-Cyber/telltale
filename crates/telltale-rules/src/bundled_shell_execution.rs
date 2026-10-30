//! Tests pinning the bundled shell-execution rules.

use super::load_default_rule_set;

#[test]
fn shell_execution_credit_is_independent_of_wrapper_text() {
    let rules = load_default_rule_set().unwrap();
    for name in [
        "shell",
        "exec_command",
        "shell_command",
        "bash",
        "Bash",
        "sh",
        "zsh",
        "fish",
        "pwsh",
        "powershell",
        "cmd.exe",
    ] {
        for command in ["printf synthetic", "bash -lc 'printf synthetic'"] {
            let result = rules
                .evaluate(&[("tool_name", name), ("command", command)])
                .unwrap()
                .unwrap();
            assert_eq!(result.rule_ids, ["execution.shell"], "{name}: {command}");
            assert_eq!(
                result.score, 15,
                "credit is counted once even with a wrapper"
            );
        }
    }
    for name in [
        "read_file",
        "shell_help",
        "exec_command_status",
        "mcp__shell",
        "bashful",
    ] {
        assert!(
            rules
                .evaluate(&[("tool_name", name), ("command", "printf synthetic")])
                .unwrap()
                .is_none(),
            "{name}"
        );
    }
    for command in [
        "bash -lc 'printf synthetic'",
        "python -c 'print(1)'",
        "node -e '1'",
        "perl -e '1'",
        "ruby -e '1'",
    ] {
        assert_eq!(
            rules
                .evaluate(&[("command", command)])
                .unwrap()
                .unwrap()
                .score,
            15
        );
    }
    assert!(
        rules
            .evaluate(&[
                ("assistant_context", "exec_command bash shell"),
                ("tool_result", "exec_command bash shell")
            ])
            .unwrap()
            .is_none()
    );
}
