use super::*;
use telltale_rules::process_chain::load_process_chain_rules;

fn candidate(
    occurrence_id: usize,
    rule_id: &str,
    category: &str,
    child: &str,
    dedupe_key: &str,
    entity: Option<&str>,
    occurred_at: Option<&str>,
) -> ProcessChainSessionCandidate {
    ProcessChainSessionCandidate {
        occurrence_id: ProcessChainOccurrenceId::new(occurrence_id),
        rule_id: rule_id.to_owned(),
        category: category.to_owned(),
        child: child.to_owned(),
        dedupe_key: dedupe_key.to_owned(),
        entity: entity.map(str::to_owned),
        occurred_at: occurred_at.map(|value| {
            OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339).unwrap()
        }),
    }
}

#[test]
fn all_shipped_correlation_contracts_use_the_session_kernel() {
    let rules = telltale_rules::process_chain::load_default_process_chain_rules().unwrap();
    // Fixed semantic facts, including stronger parent evidence unavailable
    // from Tool commands. These are kernel contracts, not runtime telemetry.
    let cases = [
        (
            "procchain.correlation.host_then_account_discovery",
            45,
            ("procchain.discovery.cmd_hostname", "discovery", "hostname"),
            ("procchain.discovery.cmd_whoami", "discovery", "whoami"),
        ),
        (
            "procchain.correlation.discovery_then_remote_exec",
            55,
            ("procchain.discovery.cmd_whoami", "discovery", "whoami"),
            (
                "procchain.lateral.psexec_remote_exec",
                "lateral_movement",
                "psexec",
            ),
        ),
        (
            "procchain.correlation.archive_then_cloud_transfer",
            65,
            ("procchain.collection.cmd_7za", "collection", "7za"),
            ("procchain.exfil.cmd_rclone", "exfiltration", "rclone"),
        ),
        (
            "procchain.correlation.office_script_then_download",
            70,
            (
                "procchain.execution.winword_powershell",
                "execution",
                "powershell",
            ),
            (
                "procchain.c2.certutil_download_cradle",
                "command_and_control",
                "certutil",
            ),
        ),
        (
            "procchain.correlation.webshell_then_discovery",
            80,
            ("procchain.execution.w3wp_cmd", "execution", "cmd"),
            ("procchain.discovery.cmd_whoami", "discovery", "whoami"),
        ),
        (
            "procchain.correlation.rmm_then_credential_or_evasion",
            60,
            (
                "procchain.c2.anydesk_powershell",
                "command_and_control",
                "powershell",
            ),
            (
                "procchain.credaccess.credential_dump_command",
                "credential_access",
                "procdump",
            ),
        ),
    ];
    assert_eq!(rules.correlations().len(), cases.len());
    for (id, score, first, second) in cases {
        let candidates = [
            candidate(
                0,
                first.0,
                first.1,
                first.2,
                "first",
                Some("synthetic-session"),
                Some("2026-01-01T00:00:00Z"),
            ),
            candidate(
                1,
                second.0,
                second.1,
                second.2,
                "second",
                Some("synthetic-session"),
                Some("2026-01-01T00:00:00Z"),
            ),
        ];
        let config = ProcessChainSessionConfig::default();
        let result = evaluate_process_chain_session(&candidates, &rules, &config);
        let decision = result
            .correlations
            .iter()
            .find(|d| rules.correlations()[d.rule_index].id == id)
            .expect(id);
        assert_eq!(decision.effective_score, score, "{id}");
        assert_eq!(decision.candidate_indexes, [0, 1], "{id}");
        assert!(!decision.risk_capped, "{id}");
        let reversed = [candidates[1].clone(), candidates[0].clone()];
        assert!(
            evaluate_process_chain_session(&reversed, &rules, &config)
                .correlations
                .iter()
                .all(|d| rules.correlations()[d.rule_index].id != id),
            "{id}"
        );
    }
}

#[test]
fn zero_window_matches_ordered_equal_timestamps_only() {
    let yaml = r#"
version: 1
description: synthetic zero window
defaults: { enabled: true, risk_entity: host, suppression_window_seconds: 3600 }
categories:
  discovery: { detection_class: security_detection, analytic_intent: alert }
correlations:
  - { id: procchain.correlation.zero, title: zero, category: discovery, severity: medium, score: 45, confidence: high, reason: synthetic, window_seconds: 0, entity: host, sequence: [{ any_rule_id: [rule.first] }, { any_rule_id: [rule.second] }] }
"#;
    let rules = load_process_chain_rules(yaml).unwrap();
    let first = candidate(
        0,
        "rule.first",
        "discovery",
        "first",
        "first",
        Some("session"),
        Some("2026-01-01T00:00:00Z"),
    );
    let second = candidate(
        1,
        "rule.second",
        "discovery",
        "second",
        "second",
        Some("session"),
        Some("2026-01-01T00:00:00Z"),
    );
    let config = ProcessChainSessionConfig::default();
    let result = evaluate_process_chain_session(&[first.clone(), second.clone()], &rules, &config);
    assert_eq!(result.correlations.len(), 1);
    assert_eq!(result.correlations[0].candidate_indexes, [0, 1]);
    assert!(
        evaluate_process_chain_session(&[second.clone(), first.clone()], &rules, &config)
            .correlations
            .is_empty()
    );
    let later = candidate(
        1,
        "rule.second",
        "discovery",
        "second",
        "second",
        Some("session"),
        Some("2026-01-01T00:00:01Z"),
    );
    assert!(
        evaluate_process_chain_session(&[first, later], &rules, &config)
            .correlations
            .is_empty()
    );
}

#[test]
fn suppression_groups_by_rule_entity_and_matcher_key() {
    let candidates = vec![
        candidate(
            0,
            "rule.a",
            "discovery",
            "hostname",
            "chain:cmd>hostname",
            Some("session:a"),
            Some("2026-01-01T00:00:00Z"),
        ),
        candidate(
            1,
            "rule.a",
            "discovery",
            "hostname",
            "chain:cmd>hostname",
            Some("session:a"),
            Some("2026-01-01T00:30:00Z"),
        ),
        candidate(
            2,
            "rule.a",
            "discovery",
            "hostname",
            "chain:cmd>hostname",
            Some("session:b"),
            Some("2026-01-01T00:30:00Z"),
        ),
        candidate(
            3,
            "rule.b",
            "discovery",
            "hostname",
            "chain:cmd>hostname",
            Some("session:a"),
            Some("2026-01-01T00:30:00Z"),
        ),
    ];
    let result = suppress_repeats(&candidates, Duration::hours(1), &mut |_| {
        Ok::<_, std::convert::Infallible>(())
    })
    .unwrap();
    assert_eq!(result.retained, [0, 2, 3]);
    assert_eq!(result.repeat_counts[&0], 2);
    assert_eq!(result.suppressed_count, 1);
}

#[test]
fn missing_time_or_entity_remains_atomic_only() {
    let candidates = vec![
        candidate(
            0,
            "rule.a",
            "discovery",
            "hostname",
            "same",
            Some("session:a"),
            None,
        ),
        candidate(
            1,
            "rule.a",
            "discovery",
            "hostname",
            "same",
            None,
            Some("2026-01-01T00:00:00Z"),
        ),
    ];
    let result = suppress_repeats(&candidates, Duration::hours(1), &mut |_| {
        Ok::<_, std::convert::Infallible>(())
    })
    .unwrap();
    assert_eq!(result.retained, [0, 1]);
    assert!(result.repeat_counts.is_empty());
}

#[test]
fn correlation_uses_authored_rule_order_for_risk_cap() {
    let rules = load_process_chain_rules(
            r#"
version: 1
description: order
defaults: { enabled: true, risk_entity: host, suppression_window_seconds: 3600 }
categories:
  discovery: { detection_class: security_detection, analytic_intent: alert, investigation_fields: [], falsepositives: [] }
  lateral_movement: { detection_class: security_detection, analytic_intent: alert, investigation_fields: [], falsepositives: [] }
rules: []
standalone: []
correlations:
  - { id: procchain.correlation.first, title: first, category: discovery, severity: medium, score: 45, confidence: high, reason: first, window_seconds: 60, entity: host, sequence: [{ any_category: [discovery] }, { any_category: [lateral_movement] }] }
  - { id: procchain.correlation.second, title: second, category: discovery, severity: high, score: 55, confidence: high, reason: second, window_seconds: 60, entity: host, sequence: [{ any_category: [discovery] }, { any_category: [lateral_movement] }] }
"#,
        )
        .unwrap();
    let candidates = vec![
        candidate(
            0,
            "rule.discovery",
            "discovery",
            "hostname",
            "a",
            Some("session:a"),
            Some("2026-01-01T00:00:00Z"),
        ),
        candidate(
            1,
            "rule.remote",
            "lateral_movement",
            "psexec",
            "b",
            Some("session:a"),
            Some("2026-01-01T00:01:00Z"),
        ),
    ];
    let result = evaluate_process_chain_session(
        &candidates,
        &rules,
        &ProcessChainSessionConfig {
            max_correlation_risk_per_entity: 50,
            ..Default::default()
        },
    );
    assert_eq!(result.correlations.len(), 2);
    assert_eq!(result.correlations[0].rule_index, 0);
    assert_eq!(result.correlations[0].effective_score, 45);
    assert_eq!(result.correlations[1].rule_index, 1);
    assert!(result.correlations[1].risk_capped);
    assert_eq!(result.correlations[1].effective_score, 0);
}

#[test]
fn risk_cap_isolated_by_entity() {
    let rules = load_process_chain_rules(
            r#"
version: 1
description: entity isolation
defaults: { enabled: true, risk_entity: host, suppression_window_seconds: 3600 }
categories:
  discovery: { detection_class: security_detection, analytic_intent: alert, investigation_fields: [], falsepositives: [] }
  lateral_movement: { detection_class: security_detection, analytic_intent: alert, investigation_fields: [], falsepositives: [] }
rules: []
standalone: []
correlations:
  - { id: procchain.correlation.one, title: one, category: discovery, severity: high, score: 55, confidence: high, reason: one, window_seconds: 60, entity: host, sequence: [{ any_category: [discovery] }, { any_category: [lateral_movement] }] }
"#,
        )
        .unwrap();
    let candidates = vec![
        candidate(
            0,
            "rule.discovery",
            "discovery",
            "hostname",
            "a1",
            Some("session:a"),
            Some("2026-01-01T00:00:00Z"),
        ),
        candidate(
            1,
            "rule.remote",
            "lateral_movement",
            "psexec",
            "a2",
            Some("session:a"),
            Some("2026-01-01T00:01:00Z"),
        ),
        candidate(
            2,
            "rule.discovery",
            "discovery",
            "hostname",
            "b1",
            Some("session:b"),
            Some("2026-01-01T00:00:00Z"),
        ),
        candidate(
            3,
            "rule.remote",
            "lateral_movement",
            "psexec",
            "b2",
            Some("session:b"),
            Some("2026-01-01T00:01:00Z"),
        ),
    ];
    let result = evaluate_process_chain_session(
        &candidates,
        &rules,
        &ProcessChainSessionConfig {
            max_correlation_risk_per_entity: 55,
            ..Default::default()
        },
    );
    assert_eq!(result.correlations.len(), 2);
    assert!(
        result
            .correlations
            .iter()
            .all(|decision| !decision.risk_capped && decision.effective_score == 55)
    );
}
