use super::*;

#[test]
fn session_suppresses_repeats_and_retains_private_count() {
    let rules = load_default_process_chain_rules().unwrap();
    let first = timed_command(
        "cmd.exe /c hostname",
        "repeat-first",
        Some("session:repeat"),
        Some("2026-09-17T10:00:00Z"),
    );
    let second = timed_command(
        "cmd.exe /c hostname",
        "repeat-second",
        Some("session:repeat"),
        Some("2026-09-17T10:30:00Z"),
    );
    let evaluation = evaluate_tool_process_chain_session(
        &rules,
        &[&first, &second],
        &ProcessChainContext::default(),
        &ProcessChainSessionConfig::default(),
    )
    .unwrap();
    assert_eq!(evaluation.results().len(), 1);
    assert_eq!(evaluation.suppressed_count(), 1);
    let retained = evaluation
        .results()
        .iter()
        .find(|result| {
            result.detector().id() == "procchain.discovery.cmd_hostname"
                && result.observation_ids() == [first.observation_id()]
        })
        .expect("retained first occurrence");
    assert_eq!(
        evaluation
            .projection
            .get(&super::super::super::event3::process_result_key(retained))
            .expect("retained occurrence projection")
            .repeat_count,
        Some(2)
    );
}

#[test]
fn suppressed_atomic_occurrence_cannot_satisfy_correlation() {
    let rules = load_default_process_chain_rules().unwrap();
    let anchor = timed_command(
        "cmd.exe /c hostname",
        "suppression-anchor",
        Some("session:suppression-lifecycle"),
        Some("2026-09-17T10:00:00Z"),
    );
    let repeated = timed_command(
        "cmd.exe /c hostname",
        "suppressed-repeat",
        Some("session:suppression-lifecycle"),
        Some("2026-09-17T10:50:00Z"),
    );
    let account = timed_command(
        "cmd.exe /c whoami",
        "correlation-step",
        Some("session:suppression-lifecycle"),
        Some("2026-09-17T10:55:00Z"),
    );

    let evaluation = evaluate_tool_process_chain_session(
        &rules,
        &[&anchor, &repeated, &account],
        &ProcessChainContext::default(),
        &ProcessChainSessionConfig::default(),
    )
    .unwrap();

    assert_eq!(evaluation.suppressed_count(), 1);
    let retained = evaluation
        .results()
        .iter()
        .find(|result| {
            result.detector().id() == "procchain.discovery.cmd_hostname"
                && result.observation_ids() == [anchor.observation_id()]
        })
        .expect("retained anchor occurrence");
    assert_eq!(
        evaluation
            .projection
            .get(&super::super::super::event3::process_result_key(retained))
            .expect("retained occurrence projection")
            .repeat_count,
        Some(2)
    );
    assert!(!evaluation.results().iter().any(|result| {
        result.detector().id() == "procchain.correlation.host_then_account_discovery"
    }));
}

#[test]
fn repeats_outside_window_and_different_sessions_survive() {
    let rules = load_default_process_chain_rules().unwrap();
    let first = timed_command(
        "cmd.exe /c hostname",
        "outside-first",
        Some("session:outside"),
        Some("2026-09-17T10:00:00Z"),
    );
    let outside = timed_command(
        "cmd.exe /c hostname",
        "outside-second",
        Some("session:outside"),
        Some("2026-09-17T12:01:00Z"),
    );
    let other_session = timed_command(
        "cmd.exe /c hostname",
        "other-session",
        Some("session:other"),
        Some("2026-09-17T10:30:00Z"),
    );
    let evaluation = evaluate_tool_process_chain_session(
        &rules,
        &[&first, &outside, &other_session],
        &ProcessChainContext::default(),
        &ProcessChainSessionConfig::default(),
    )
    .unwrap();
    assert_eq!(evaluation.results().len(), 3);
    assert_eq!(evaluation.suppressed_count(), 0);
}

#[test]
fn repeat_outside_suppression_window_can_start_correlation() {
    let rules = load_default_process_chain_rules().unwrap();
    let original = timed_command(
        "cmd.exe /c hostname",
        "outside-correlation-original",
        Some("session:outside-correlation"),
        Some("2026-09-17T10:00:00Z"),
    );
    let later = timed_command(
        "cmd.exe /c hostname",
        "outside-correlation-later",
        Some("session:outside-correlation"),
        Some("2026-09-17T11:01:00Z"),
    );
    let account = timed_command(
        "cmd.exe /c whoami",
        "outside-correlation-account",
        Some("session:outside-correlation"),
        Some("2026-09-17T11:05:00Z"),
    );

    let evaluation = evaluate_tool_process_chain_session(
        &rules,
        &[&original, &later, &account],
        &ProcessChainContext::default(),
        &ProcessChainSessionConfig::default(),
    )
    .unwrap();

    assert_eq!(evaluation.suppressed_count(), 0);
    let correlation = result(
        evaluation.results(),
        "procchain.correlation.host_then_account_discovery",
    );
    assert_eq!(
        correlation
            .observation_ids()
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        [later.observation_id(), account.observation_id()]
            .into_iter()
            .collect::<BTreeSet<_>>()
    );
}

#[test]
fn missing_session_id_keeps_atomic_matches_unjoined() {
    let rules = load_default_process_chain_rules().unwrap();
    let first = timed_command(
        "cmd.exe /c hostname",
        "no-session-first",
        None,
        Some("2026-09-17T10:00:00Z"),
    );
    let second = timed_command(
        "cmd.exe /c hostname",
        "no-session-second",
        None,
        Some("2026-09-17T10:01:00Z"),
    );
    let evaluation = evaluate_tool_process_chain_session(
        &rules,
        &[&first, &second],
        &ProcessChainContext::default(),
        &ProcessChainSessionConfig::default(),
    )
    .unwrap();
    assert_eq!(evaluation.results().len(), 2);
    assert_eq!(evaluation.suppressed_count(), 0);
}

#[test]
fn missing_occurred_at_keeps_atomic_match_but_cannot_suppress_or_correlate() {
    let rules = load_default_process_chain_rules().unwrap();
    let untimed = timed_command(
        "cmd.exe /c hostname",
        "untimed-hostname",
        Some("session:untimed"),
        None,
    );
    let account = timed_command(
        "cmd.exe /c whoami",
        "untimed-account",
        Some("session:untimed"),
        Some("2026-09-17T10:01:00Z"),
    );
    let evaluation = evaluate_tool_process_chain_session(
        &rules,
        &[&untimed, &account],
        &ProcessChainContext::default(),
        &ProcessChainSessionConfig::default(),
    )
    .unwrap();
    assert!(
        evaluation
            .results()
            .iter()
            .any(|result| result.detector().id() == "procchain.discovery.cmd_hostname")
    );
    assert!(
        evaluation
            .results()
            .iter()
            .all(|result| !result.detector().id().starts_with("procchain.correlation."))
    );
    assert_eq!(evaluation.suppressed_count(), 0);
}
