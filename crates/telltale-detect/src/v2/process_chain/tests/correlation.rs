use super::*;

#[test]
fn correlation_dedupe_identity_includes_rule_and_session_scope() {
    let rules = load_process_chain_rules(
            r#"
version: 1
description: synthetic correlation identity
defaults: { enabled: true, risk_entity: host, suppression_window_seconds: 3600 }
categories:
  discovery: { detection_class: security_detection, analytic_intent: alert, investigation_fields: [], falsepositives: [] }
rules: []
standalone:
  - { id: procchain.synthetic.hostname, title: hostname, category: discovery, severity: informational, score: 0, confidence: low, match: command_line, patterns: ["\\bhostname\\b"], mitre: [T1082], reason: hostname }
  - { id: procchain.synthetic.whoami, title: whoami, category: discovery, severity: informational, score: 0, confidence: low, match: command_line, patterns: ["\\bwhoami\\b"], mitre: [T1087], reason: whoami }
correlations:
  - id: procchain.correlation.synthetic_one
    title: first
    category: discovery
    severity: medium
    score: 45
    confidence: medium
    mitre: [T1082]
    reason: first
    window_seconds: 60
    entity: host
    sequence:
      - { any_rule_id: [procchain.synthetic.hostname], any_child: [hostname] }
      - { any_rule_id: [procchain.synthetic.whoami], any_child: [whoami] }
  - id: procchain.correlation.synthetic_two
    title: second
    category: discovery
    severity: medium
    score: 45
    confidence: medium
    mitre: [T1082]
    reason: second
    window_seconds: 60
    entity: host
    sequence:
      - { any_rule_id: [procchain.synthetic.hostname], any_child: [hostname] }
      - { any_rule_id: [procchain.synthetic.whoami], any_child: [whoami] }
"#,
        )
        .unwrap();
    let observations = [
        timed_command(
            "cmd.exe /c hostname",
            "identity-host",
            Some("opaque-session"),
            Some("2026-09-17T10:00:00Z"),
        ),
        timed_command(
            "cmd.exe /c whoami",
            "identity-account",
            Some("opaque-session"),
            Some("2026-09-17T10:01:00Z"),
        ),
    ];
    let evaluate = || {
        evaluate_tool_process_chain_session(
            &rules,
            &[&observations[0], &observations[1]],
            &ProcessChainContext::default(),
            &ProcessChainSessionConfig::default(),
        )
        .unwrap()
        .results()
        .iter()
        .filter(|result| result.detector().id().starts_with("procchain.correlation."))
        .map(|result| {
            (
                result.detector().id().to_owned(),
                result.dedupe_key().unwrap().to_owned(),
            )
        })
        .collect::<BTreeMap<_, _>>()
    };
    let first = evaluate();
    let second = evaluate();
    assert_eq!(first, second);
    assert_eq!(first.len(), 2);
    let keys = first.values().collect::<BTreeSet<_>>();
    assert_eq!(keys.len(), 2);
    assert!(
        keys.iter().all(|key| {
            key.starts_with("correlation:sha256:") && !key.contains("opaque-session")
        })
    );
}

#[test]
fn occurred_at_orders_candidates_without_observed_at_fallback() {
    let rules = load_default_process_chain_rules().unwrap();
    // Both observations have the same observed_at in the synthetic helper,
    // while source occurrence time intentionally puts the account step first.
    let hostname = timed_command(
        "cmd.exe /c hostname",
        "occurred-later",
        Some("session:ordering"),
        Some("2026-09-17T10:10:00Z"),
    );
    let account = timed_command(
        "cmd.exe /c whoami",
        "occurred-earlier",
        Some("session:ordering"),
        Some("2026-09-17T10:00:00Z"),
    );
    let evaluation = evaluate_tool_process_chain_session(
        &rules,
        &[&hostname, &account],
        &ProcessChainContext::default(),
        &ProcessChainSessionConfig::default(),
    )
    .unwrap();
    assert!(
        evaluation
            .results()
            .iter()
            .all(|result| !result.detector().id().starts_with("procchain.correlation."))
    );
}

#[test]
fn shipped_any_child_correlation_uses_private_child_context() {
    let rules = load_default_process_chain_rules().unwrap();
    let hostname = timed_command(
        "cmd.exe /c hostname",
        "any-child-hostname",
        Some("session:any-child"),
        Some("2026-09-17T10:00:00Z"),
    );
    let account = timed_command(
        "cmd.exe /c whoami",
        "any-child-account",
        Some("session:any-child"),
        Some("2026-09-17T10:01:00Z"),
    );
    let evaluation = evaluate_tool_process_chain_session(
        &rules,
        &[&hostname, &account],
        &ProcessChainContext::default(),
        &ProcessChainSessionConfig::default(),
    )
    .unwrap();
    let correlation = result(
        evaluation.results(),
        "procchain.correlation.host_then_account_discovery",
    );
    assert_eq!(correlation.finding_kind(), FindingKind::Correlation);
    assert_eq!(correlation.correlation_scope(), CorrelationScope::Sequence);
    assert_eq!(correlation.observation_ids().len(), 2);
    assert_eq!(
        correlation
            .observation_ids()
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        [hostname.observation_id(), account.observation_id()]
            .into_iter()
            .collect::<BTreeSet<_>>()
    );
    let signal = correlation.signal().unwrap().unwrap();
    let finding = signal.finding().unwrap();
    assert_eq!(signal.observation_ids(), correlation.observation_ids());
    assert_eq!(finding.observation_ids(), correlation.observation_ids());
}

#[test]
fn one_tool_observation_preserves_command_order_for_correlation() {
    let rules = load_default_process_chain_rules().unwrap();
    let reversed = timed_command(
        "cmd.exe /c whoami && cmd.exe /c hostname",
        "same-observation-reversed",
        Some("s:reversed"),
        Some("2026-09-17T10:00:00Z"),
    );
    let reversed = evaluate_tool_process_chain_session(
        &rules,
        &[&reversed],
        &ProcessChainContext::default(),
        &ProcessChainSessionConfig::default(),
    )
    .unwrap();
    assert!(!reversed.results().iter().any(|result| {
        result.detector().id() == "procchain.correlation.host_then_account_discovery"
    }));

    let forward = timed_command(
        "cmd.exe /c hostname && cmd.exe /c whoami",
        "same-observation-forward",
        Some("s:forward"),
        Some("2026-09-17T10:00:00Z"),
    );
    let forward = evaluate_tool_process_chain_session(
        &rules,
        &[&forward],
        &ProcessChainContext::default(),
        &ProcessChainSessionConfig::default(),
    )
    .unwrap();
    assert!(forward.results().iter().any(|result| {
        result.detector().id() == "procchain.correlation.host_then_account_discovery"
    }));
}

#[test]
fn correlation_keeps_child_context_when_atomic_signal_identity_collapses() {
    let rules = load_process_chain_rules(
            r#"
version: 1
description: private child context
defaults: { enabled: true, risk_entity: host, suppression_window_seconds: 3600 }
categories:
  discovery: { detection_class: security_detection, analytic_intent: alert, investigation_fields: [], falsepositives: [] }
rules: []
standalone:
  - { id: procchain.synthetic.command, title: command, category: discovery, severity: informational, score: 0, confidence: low, match: command_line, patterns: ["\\b(hostname|whoami)\\b"], mitre: [T1082], reason: command }
correlations:
  - id: procchain.correlation.synthetic_children
    title: child sequence
    category: discovery
    severity: medium
    score: 45
    confidence: medium
    mitre: [T1082]
    reason: child sequence
    window_seconds: 60
    entity: host
    sequence:
      - { any_rule_id: [procchain.synthetic.command], any_child: [hostname] }
      - { any_rule_id: [procchain.synthetic.command], any_child: [whoami] }
"#,
        )
        .unwrap();
    let observation = timed_command(
        "cmd.exe /c hostname && cmd.exe /c whoami",
        "same-identity-children",
        Some("session:private-children"),
        Some("2026-09-17T10:00:00Z"),
    );
    let evaluation = evaluate_tool_process_chain_session(
        &rules,
        &[&observation],
        &ProcessChainContext::default(),
        &ProcessChainSessionConfig::default(),
    )
    .unwrap();

    assert_eq!(
        evaluation
            .results()
            .iter()
            .filter(|result| result.detector().id() == "procchain.synthetic.command")
            .count(),
        1,
        "outward atomic Signal identity remains unique"
    );
    assert_eq!(evaluation.suppressed_count(), 0);
    let correlation = result(
        evaluation.results(),
        "procchain.correlation.synthetic_children",
    );
    assert_eq!(
        correlation.observation_ids(),
        [observation.observation_id()]
    );
}

#[test]
fn correlation_omits_non_aggregate_capability_context() {
    let rules = load_default_process_chain_rules().unwrap();
    let hostname = tool_with_session_time_and_capability(
        ObservationStage::ToolRequested,
        Some("cmd.exe /c hostname"),
        None,
        None,
        "shell",
        "capability-hostname",
        Some("session:capability-context"),
        Some("2026-09-17T10:00:00Z"),
        CapabilityAvailability::Supported,
    );
    let account = tool_with_session_time_and_capability(
        ObservationStage::ToolRequested,
        Some("cmd.exe /c whoami"),
        None,
        None,
        "shell",
        "capability-account",
        Some("session:capability-context"),
        Some("2026-09-17T10:01:00Z"),
        CapabilityAvailability::Unknown,
    );
    let evaluation = evaluate_tool_process_chain_session(
        &rules,
        &[&hostname, &account],
        &ProcessChainContext::default(),
        &ProcessChainSessionConfig::default(),
    )
    .unwrap();
    let correlation = result(
        evaluation.results(),
        "procchain.correlation.host_then_account_discovery",
    );

    assert!(correlation.capability_context().is_none());
}

#[test]
fn category_and_rule_id_correlation_predicates_remain_compiled_authority() {
    let rules = load_process_chain_rules(
            r#"
version: 1
description: predicate coverage
defaults: { enabled: true, risk_entity: host, suppression_window_seconds: 3600 }
categories:
  discovery: { detection_class: security_detection, analytic_intent: alert, investigation_fields: [], falsepositives: [] }
  lateral_movement: { detection_class: security_detection, analytic_intent: alert, investigation_fields: [], falsepositives: [] }
rules:
  - { id: procchain.synthetic.first, title: first, category: discovery, severity: informational, score: 0, confidence: low, parent: cmd, child: hostname, mitre: [T1082], reason: first, dedup_key: synthetic:first }
  - { id: procchain.synthetic.second, title: second, category: lateral_movement, severity: high, score: 55, confidence: high, parent: cmd, child: psexec, mitre: [T1570], reason: second, dedup_key: synthetic:second }
standalone: []
correlations:
  - id: procchain.correlation.synthetic_predicates
    title: predicates
    category: lateral_movement
    severity: high
    score: 55
    confidence: high
    mitre: [T1570]
    reason: predicates
    window_seconds: 60
    entity: host
    sequence:
      - any_category: [discovery]
        any_rule_id: [procchain.synthetic.first]
      - any_category: [lateral_movement]
"#,
        )
        .unwrap();
    let first = timed_command(
        "cmd.exe /c hostname",
        "predicate-first",
        Some("session:predicate"),
        Some("2026-09-17T10:00:00Z"),
    );
    let second = timed_command(
        "cmd.exe /c psexec",
        "predicate-second",
        Some("session:predicate"),
        Some("2026-09-17T10:00:01Z"),
    );
    let evaluation = evaluate_tool_process_chain_session(
        &rules,
        &[&first, &second],
        &ProcessChainContext::default(),
        &ProcessChainSessionConfig::default(),
    )
    .unwrap();
    let correlation = result(
        evaluation.results(),
        "procchain.correlation.synthetic_predicates",
    );
    assert_eq!(correlation.risk_points(), Some(55));
    assert_eq!(correlation.techniques(), ["attack:T1570"]);
    assert!(
        evaluation
            .results()
            .iter()
            .any(|result| result.detector().id() == "procchain.synthetic.first")
    );
}

#[test]
fn correlation_window_and_throttle_are_session_scoped() {
    let rules = load_default_process_chain_rules().unwrap();
    let hostname = timed_command(
        "cmd.exe /c hostname",
        "window-hostname",
        Some("session:window"),
        Some("2026-09-17T10:00:00Z"),
    );
    let account = timed_command(
        "cmd.exe /c whoami",
        "window-account",
        Some("session:window"),
        Some("2026-09-17T10:16:00Z"),
    );
    let outside = evaluate_tool_process_chain_session(
        &rules,
        &[&hostname, &account],
        &ProcessChainContext::default(),
        &ProcessChainSessionConfig::default(),
    )
    .unwrap();
    assert!(!outside.results().iter().any(
        |result| result.detector().id() == "procchain.correlation.host_then_account_discovery"
    ));

    let first = timed_command(
        "cmd.exe /c hostname",
        "throttle-hostname-1",
        Some("session:throttle"),
        Some("2026-09-17T10:00:00Z"),
    );
    let first_account = timed_command(
        "cmd.exe /c whoami",
        "throttle-account-1",
        Some("session:throttle"),
        Some("2026-09-17T10:01:00Z"),
    );
    let second = timed_command(
        "cmd.exe /c systeminfo",
        "throttle-hostname-2",
        Some("session:throttle"),
        Some("2026-09-17T10:02:00Z"),
    );
    let second_account = timed_command(
        "cmd.exe /c net user",
        "throttle-account-2",
        Some("session:throttle"),
        Some("2026-09-17T10:03:00Z"),
    );
    let evaluation = evaluate_tool_process_chain_session(
        &rules,
        &[&first, &first_account, &second, &second_account],
        &ProcessChainContext::default(),
        &ProcessChainSessionConfig::default(),
    )
    .unwrap();
    assert_eq!(
        evaluation
            .results()
            .iter()
            .filter(|result| result.detector().id()
                == "procchain.correlation.host_then_account_discovery")
            .count(),
        1
    );
    let expanded = evaluate_tool_process_chain_session(
        &rules,
        &[&first, &first_account, &second, &second_account],
        &ProcessChainContext::default(),
        &ProcessChainSessionConfig {
            max_correlations_per_rule_entity: 2,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(
        expanded
            .results()
            .iter()
            .filter(|result| result.detector().id()
                == "procchain.correlation.host_then_account_discovery")
            .count(),
        2
    );
}

#[test]
fn risk_capped_correlation_remains_an_informational_process_chain_result() {
    let rules = load_process_chain_rules(
            r#"
version: 1
description: cap coverage
defaults: { enabled: true, risk_entity: host, suppression_window_seconds: 3600 }
categories:
  discovery: { detection_class: security_detection, analytic_intent: alert, investigation_fields: [], falsepositives: [] }
  lateral_movement: { detection_class: security_detection, analytic_intent: alert, investigation_fields: [], falsepositives: [] }
rules:
  - { id: procchain.synthetic.first, title: first, category: discovery, severity: medium, score: 45, confidence: high, parent: cmd, child: hostname, mitre: [T1082], reason: first, dedup_key: synthetic:first }
  - { id: procchain.synthetic.second, title: second, category: lateral_movement, severity: high, score: 55, confidence: high, parent: cmd, child: psexec, mitre: [T1570], reason: second, dedup_key: synthetic:second }
standalone: []
correlations:
  - { id: procchain.correlation.synthetic_first, title: first, category: discovery, severity: medium, score: 45, confidence: high, mitre: [T1082], reason: first, window_seconds: 60, entity: host, sequence: [{ any_category: [discovery] }, { any_category: [lateral_movement] }] }
  - { id: procchain.correlation.synthetic_second, title: second, category: lateral_movement, severity: high, score: 55, confidence: high, mitre: [T1570], reason: second, window_seconds: 60, entity: host, sequence: [{ any_category: [discovery] }, { any_category: [lateral_movement] }] }
"#,
        )
        .unwrap();
    let first = timed_command(
        "cmd.exe /c hostname",
        "cap-first",
        Some("session:cap"),
        Some("2026-09-17T10:00:00Z"),
    );
    let second = timed_command(
        "cmd.exe /c psexec",
        "cap-second",
        Some("session:cap"),
        Some("2026-09-17T10:01:00Z"),
    );
    let evaluation = evaluate_tool_process_chain_session(
        &rules,
        &[&first, &second],
        &ProcessChainContext::default(),
        &ProcessChainSessionConfig {
            max_correlation_risk_per_entity: 50,
            ..Default::default()
        },
    )
    .unwrap();
    let uncapped = result(
        evaluation.results(),
        "procchain.correlation.synthetic_first",
    );
    let capped = result(
        evaluation.results(),
        "procchain.correlation.synthetic_second",
    );
    assert_eq!(uncapped.risk_points(), Some(45));
    assert_eq!(capped.evaluation_status(), EvaluationStatus::EvaluatedMatch);
    assert_eq!(capped.risk_points(), Some(0));
    assert_eq!(capped.severity(), Severity::Informational);
    assert_eq!(capped.finding_kind(), FindingKind::Correlation);
    assert!(capped.tags().contains(&"risk_capped".to_owned()));
    assert_eq!(capped.confidence(), Some(Confidence::High));
    assert_eq!(capped.techniques(), ["attack:T1570"]);
    assert_eq!(capped.observation_ids().len(), 2);
}
