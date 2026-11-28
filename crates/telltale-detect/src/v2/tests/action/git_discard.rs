use super::*;

#[test]
fn git_discard_file_restore_contributes_existing_risk_in_both_views() {
    let output = actions(&[parsed_shell_call("restore", "git restore src/app.rs")]);
    let session = &output.sessions()[0];
    assert!(
        session
            .rule_ids()
            .iter()
            .any(|id| id == "destructive.git_discard")
    );
    assert_eq!(session.rule_score(), 70);
    let action = &session.action_findings()[0];
    assert_eq!(action.promotion_score(), 55);
    let finding = action
        .canonical_findings()
        .iter()
        .find(|finding| finding.detector_id() == "destructive.git_discard")
        .unwrap();
    assert_eq!(finding.severity(), Severity::High);
    assert_eq!(finding.risk_points(), Some(55));
}

#[test]
fn git_discard_dry_run_keeps_session_shell_credit_without_a_destructive_action() {
    let output = actions(&[parsed_shell_call("preview", "git clean -n -fdx")]);
    let session = &output.sessions()[0];
    assert_eq!(session.rule_ids(), ["execution.shell"]);
    assert_eq!(session.rule_score(), 15);
    assert!(session.action_findings().is_empty());
}

#[test]
fn git_discard_nested_preview_cannot_hide_a_file_restore() {
    let output = actions(&[parsed_shell_call(
        "nested",
        "bash -c 'git clean -n -fd; git restore src/app.rs'",
    )]);
    let session = &output.sessions()[0];
    assert!(
        session
            .rule_ids()
            .iter()
            .any(|id| id == "destructive.git_discard")
    );
    assert!(
        session.action_findings()[0]
            .rule_ids()
            .iter()
            .any(|id| id == "destructive.git_discard")
    );
}

#[test]
fn git_discard_help_in_another_command_cannot_hide_a_reset() {
    let output = actions(&[parsed_shell_call(
        "help-and-reset",
        "git reset --hard; git reset --hard --help",
    )]);
    let session = &output.sessions()[0];
    assert!(
        session
            .rule_ids()
            .iter()
            .any(|id| id == "destructive.git_discard")
    );
    assert!(
        session.action_findings()[0]
            .rule_ids()
            .iter()
            .any(|id| id == "destructive.git_discard")
    );
}
