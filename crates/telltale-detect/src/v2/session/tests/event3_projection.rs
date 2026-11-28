use super::*;

#[test]
fn event3_uses_checked_contributions_and_actual_canonical_anchors() {
    use super::super::super::event3::project_event3;
    let observations = [
        message(
            "match",
            Some("synthetic-session"),
            "needle api_key=tt_SYNTHETIC_SECRET_123456789",
            CapabilityAvailability::Supported,
        ),
        message(
            "no-match",
            Some("synthetic-session"),
            "ordinary text",
            CapabilityAvailability::Supported,
        ),
    ];
    let evaluation = evaluate(&observations, &plan(7)).unwrap();
    assert_eq!(evaluation.completion(), EvaluationCompletion::Complete);
    let projected = project_event3(&evaluation, &context()).unwrap();
    assert_eq!(projected.events.len(), 1);
    let event = &projected.events[0];
    assert_eq!(event.rule_ids, ["chain.synthetic", "synthetic.atomic"]);
    assert_eq!(event.risk_score, 8);
    assert_eq!(event.risk_contributions.len(), 2);
    assert!(event.tags.contains(&"chain".to_owned()));
    assert_eq!(event.categories, ["synthetic"]);
    assert_eq!(
        event.event_time.as_deref(),
        Some("2026-09-17T00:00:00.000Z")
    );
    assert_eq!(event.agent, None);
    assert_eq!(event.model, None);
    assert_eq!(event.provider, None);
    assert_eq!(event.timeline_anchors.len(), 1);
    assert!(
        event
            .evidence
            .iter()
            .any(|e| e.field == "canonical_observation_id"
                && e.hash.as_deref()
                    == Some(
                        telltale_schema::event::evidence_hash(observations[0].observation_id())
                            .as_str()
                    ))
    );
    let serialized = serde_json::to_string(event).unwrap();
    assert!(!serialized.contains("tt_SYNTHETIC_SECRET_123456789"));
    assert!(serialized.contains("3.0"));
    assert_eq!(
        evaluation.sessions()[0].activity().observation_counts["message.observed"],
        2
    );
}

#[test]
fn capability_limited_completion_is_not_no_match_or_operational_failure() {
    for (availability, reason) in [
        (
            CapabilityAvailability::Unsupported,
            "required_capability_unsupported",
        ),
        (
            CapabilityAvailability::Unknown,
            "required_capability_unknown",
        ),
    ] {
        let observations = [message("limited", Some("session"), "needle", availability)];
        let evaluation = evaluate(&observations, &plan(0)).unwrap();
        assert_eq!(
            evaluation.completion(),
            EvaluationCompletion::VisibilityLimited
        );
        let detector = &evaluation.sessions()[0].detectors()[0];
        assert_eq!(
            detector.outcome(),
            super::super::super::RuleV1DetectorOutcome::Indeterminate
        );
        assert_eq!(detector.non_evaluation_reason_counts()[reason], 1);
        let projected =
            super::super::super::event3::project_event3(&evaluation, &context()).unwrap();
        assert!(projected.events.is_empty());
        assert_eq!(
            projected.completion,
            EvaluationCompletion::VisibilityLimited
        );
    }
    let observations = [message(
        "ordinary",
        Some("session"),
        "ordinary",
        CapabilityAvailability::Supported,
    )];
    let evaluation = evaluate(&observations, &plan(0)).unwrap();
    assert_eq!(evaluation.completion(), EvaluationCompletion::Complete);
    assert_eq!(
        evaluation.sessions()[0].detectors()[0].outcome(),
        super::super::super::RuleV1DetectorOutcome::NoMatch
    );
}

#[test]
fn event3_aggregates_one_deterministic_anchor_per_occurrence() {
    let document = "title: synthetic\nid: 7a02cd2b-4f01-4a02-8ba6-5de7618c40b2\nname: synthetic.alpha\ntaxonomy: telltale\nlogsource:\n    product: ai_agent\n    category: tool_activity\ndetection:\n    selection:\n        - tool.arguments|re: &pattern 'shell'\n        - tool.name|re: *pattern\n    condition: selection\nlevel: low\ntelltale:\n    category: synthetic\n    score: 1\n    explanation: 'synthetic'\n    analytic_intent: alert\n    detection_class: security_detection\n    signal_type: atomic\n    tags: [synthetic]\n---\ntitle: synthetic\nid: 07accc6a-2c10-4c59-82a0-1ae67c726ef6\nname: synthetic.beta\ntaxonomy: telltale\nlogsource:\n    product: ai_agent\n    category: tool_activity\ndetection:\n    selection:\n        - tool.arguments|re: 'needle'\n    condition: selection\nlevel: low\ntelltale:\n    category: synthetic\n    score: 2\n    explanation: 'synthetic'\n    analytic_intent: alert\n    detection_class: security_detection\n    signal_type: atomic\n    tags: [synthetic]\n---\ntitle: synthetic\nid: 87dc6578-a998-43b8-832a-62596015a375\nname: chain.synthetic_both\ntaxonomy: telltale\ncorrelation:\n    type: telltale_chain\n    rules: [synthetic.alpha, synthetic.beta]\ntelltale:\n    score: 3\n    explanation: 'synthetic'\n    analytic_intent: audit\n    detection_class: security_detection\n    signal_type: chain\n";
    let anchor_plan = compile_rule_v1(
        &telltale_rules::load_rule_set_from_documents(&[document], None)
            .unwrap()
            .compatibility_export(),
    )
    .unwrap();
    let observations = [command(
        "anchor",
        "shell needle",
        Some("2026-09-17T00:00:00Z"),
        0,
    )];
    let evaluation = evaluate(&observations, &anchor_plan).unwrap();
    let projected = super::super::super::event3::project_event3(&evaluation, &context()).unwrap();
    let first = &projected.events;
    let first_anchor = &first[0].timeline_anchors[0];
    assert_eq!(first[0].timeline_anchors.len(), 1);
    assert_eq!(first_anchor.entry_index, 0);
    assert_eq!(
        first_anchor.rule_ids,
        ["chain.synthetic_both", "synthetic.alpha", "synthetic.beta"]
    );
    assert_eq!(first_anchor.evidence_fields, ["arguments", "tool_name"]);
    assert_eq!(projected.occurrences.len(), 1);
    let occurrence = &projected.occurrences[0];
    assert_eq!(occurrence.finding_index, 0);
    assert_eq!(occurrence.timeline_index, Some(first_anchor.entry_index));
    assert_eq!(occurrence.rule_ids, first_anchor.rule_ids);
    assert_eq!(occurrence.categories, first_anchor.categories);
    assert_eq!(occurrence.evidence_fields, first_anchor.evidence_fields);
    assert_eq!(occurrence.session_id, first[0].session_id);
    for retained in evaluation.sessions()[0].rules.projection() {
        assert_eq!(occurrence.observation_id, retained.observation_id);
        assert_eq!(occurrence.occurred_at, retained.occurred_at);
    }
    assert_eq!(occurrence.observation_id, observations[0].observation_id());
    assert_eq!(
        occurrence.occurred_at.as_deref(),
        Some("2026-09-17T00:00:00Z")
    );
}

#[test]
fn projected_occurrences_preserve_process_repeats_correlations_and_derived_context() {
    let observations = [
        command(
            "hostname",
            "cmd.exe /c hostname",
            Some("2026-09-17T00:00:00Z"),
            0,
        ),
        command(
            "repeat",
            "cmd.exe /c hostname",
            Some("2026-09-17T00:00:01Z"),
            1,
        ),
        command(
            "whoami",
            "cmd.exe /c whoami",
            Some("2026-09-17T00:01:00Z"),
            2,
        ),
    ];
    assert!(observations[0].observation_id() > observations[2].observation_id());
    let instance = CorrelationId::source_reported("instance").unwrap();
    let process_rules = telltale_rules::process_chain::load_default_process_chain_rules().unwrap();
    let config = crate::process_chain::ProcessChainConfig::default();
    let evaluation = evaluate_source(
        CanonicalSourceInput {
            client: ClientId::Claude,
            source_id: "claude.projects",
            source_instance: Some(&instance),
            observations: &observations,
        },
        &plan(0),
        Some((&process_rules, &config)),
    )
    .unwrap();
    let projected = super::super::super::event3::project_event3(&evaluation, &context()).unwrap();
    let events = &projected.events;
    for (finding_index, event) in events.iter().enumerate() {
        let occurrences = projected
            .occurrences
            .iter()
            .filter(|occurrence| occurrence.finding_index == finding_index)
            .collect::<Vec<_>>();
        let result = evaluation.sessions()[0]
            .processes
            .as_ref()
            .unwrap()
            .results()
            .iter()
            .find(|result| result.detector().id() == event.rule_ids[0])
            .unwrap();
        assert_eq!(
            occurrences.len(),
            result
                .observation_ids()
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
        );
        for occurrence in occurrences {
            let index = observations
                .iter()
                .position(|observation| observation.observation_id() == occurrence.observation_id)
                .unwrap();
            assert_eq!(occurrence.timeline_index, Some(index));
            assert_eq!(occurrence.rule_ids, event.rule_ids);
            assert_eq!(occurrence.categories, event.categories);
            assert_eq!(occurrence.session_id, event.session_id);
            assert!(occurrence.evidence_fields.is_empty());
            if result.observation_ids().len() == 1 {
                let observation = observations
                    .iter()
                    .find(|observation| observation.observation_id() == occurrence.observation_id)
                    .unwrap();
                assert_eq!(
                    occurrence.occurred_at.as_deref(),
                    observation.occurred_at().map(|time| time.as_str())
                );
            } else {
                assert_eq!(occurrence.occurred_at, None);
            }
        }
    }
    assert!(
        observations
            .iter()
            .all(|o| o.kind() == ObservationFamily::Tool)
    );
    assert!(events.iter().any(|e| {
        e.evidence
            .iter()
            .any(|item| item.field == "repeat_count" && item.redacted_value == "2")
    }));
    let correlation = events
        .iter()
        .find(|e| e.rule_ids[0] == "procchain.correlation.host_then_account_discovery")
        .unwrap();
    let hostname_index = events
        .iter()
        .position(|event| event.rule_ids[0] == "procchain.discovery.cmd_hostname")
        .unwrap();
    let whoami_index = events
        .iter()
        .position(|event| event.rule_ids[0] == "procchain.discovery.cmd_whoami")
        .unwrap();
    let correlation_index = events
        .iter()
        .position(|event| event.rule_ids[0] == "procchain.correlation.host_then_account_discovery")
        .unwrap();
    assert!(hostname_index < whoami_index && whoami_index < correlation_index);
    assert_eq!(correlation.risk_score, 45);
    assert_eq!(
        correlation.process.as_ref().unwrap().dedup_key,
        "correlation:sha256:41b8eb6755cfda95d8059e32619a191386e1177f0939f6e3af208bfe64caa72c"
    );
    assert_eq!(correlation.risk_entity_type.as_deref(), Some("session"));
    assert!(correlation.timeline_anchors.is_empty());
    assert!(
        correlation
            .evidence
            .iter()
            .any(|e| e.field == "canonical_occurrences" && e.redacted_value == "0,2")
    );
    let supporting = correlation
        .evidence
        .iter()
        .find(|e| e.field == "correlated_event_ids")
        .unwrap();
    for id in supporting.redacted_value.split(',') {
        assert!(events.iter().any(|e| e.event_id == id));
    }
    let atomic = events
        .iter()
        .find(|e| e.rule_ids[0] == "procchain.discovery.cmd_whoami")
        .unwrap();
    let process = atomic.process.as_ref().unwrap();
    assert_eq!(process.source_process_name, "cmd");
    assert_eq!(process.target_process_name, "whoami");
    assert!(process.source_process_id.is_none());
    assert_eq!(
        process.source_event_id.as_deref(),
        Some(observations[2].observation_id())
    );
    assert!(!process.rule_name.is_empty());
    for event in events {
        serde_json::to_string(event).unwrap();
    }
}

#[test]
fn collapsed_process_variants_keep_truthful_correlation_step_evidence() {
    let rules = telltale_rules::process_chain::load_process_chain_rules(r#"
version: 1
description: synthetic variant projection
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
"#).unwrap();
    let observations = [command(
        "variants",
        "cmd.exe /c hostname && cmd.exe /c whoami",
        Some("2026-09-17T00:00:00Z"),
        0,
    )];
    let instance = CorrelationId::source_reported("instance").unwrap();
    let config = crate::process_chain::ProcessChainConfig::default();
    let output = evaluate_source(
        CanonicalSourceInput {
            client: ClientId::Claude,
            source_id: "claude.projects",
            source_instance: Some(&instance),
            observations: &observations,
        },
        &plan(0),
        Some((&rules, &config)),
    )
    .unwrap();
    let events = super::super::super::event3::project_event3(&output, &context())
        .unwrap()
        .events;
    let atomic = events
        .iter()
        .find(|e| e.rule_ids[0] == "procchain.synthetic.command")
        .unwrap();
    assert!(
        atomic
            .evidence
            .iter()
            .any(|e| e.field == "process_context_variant")
    );
    let correlation = events
        .iter()
        .find(|e| e.rule_ids[0] == "procchain.correlation.synthetic_children")
        .unwrap();
    let steps = correlation
        .evidence
        .iter()
        .filter(|e| e.field == "correlation_process_step")
        .collect::<Vec<_>>();
    assert_eq!(steps.len(), 2);
    assert!(steps[0].redacted_value.contains("hostname"));
    assert!(steps[1].redacted_value.contains("whoami"));
}

#[test]
fn retained_process_context_markers_do_not_survive_terminal_event3() {
    let markers = [
        "api_key=tt_SYNTHETIC_COMMAND_SECRET_123456789",
        "api_key=tt_SYNTHETIC_TITLE_SECRET_123456789",
        "api_key=tt_SYNTHETIC_REASON_SECRET_123456789",
        "api_key=tt_SYNTHETIC_INVESTIGATION_SECRET_123456789",
        "api_key=tt_SYNTHETIC_FALSEPOSITIVE_SECRET_123456789",
    ];
    let document = format!(
        r#"
version: 1
description: synthetic privacy
defaults: {{ enabled: true, risk_entity: host, suppression_window_seconds: 3600 }}
categories:
  discovery:
    detection_class: security_detection
    analytic_intent: alert
    investigation_fields: ["{}"]
    falsepositives: ["{}"]
rules:
  - id: procchain.synthetic.privacy
    title: "{}"
    category: discovery
    severity: low
    score: 20
    confidence: low
    parent: cmd
    child: whoami
    mitre: [T1087]
    reason: "{}"
standalone: []
correlations: []
"#,
        markers[3], markers[4], markers[1], markers[2]
    );
    let rules = telltale_rules::process_chain::load_process_chain_rules(&document).unwrap();
    let command_text = format!(r#"cmd.exe /c whoami C:\private\token.txt {}"#, markers[0]);
    let observations = [command(
        "privacy-context",
        &command_text,
        Some("2026-09-17T00:00:00Z"),
        0,
    )];
    let instance = CorrelationId::source_reported("privacy-instance").unwrap();
    let evaluation = evaluate_source(
        CanonicalSourceInput {
            client: ClientId::Claude,
            source_id: "claude.projects",
            source_instance: Some(&instance),
            observations: &observations,
        },
        &plan(0),
        Some((&rules, &crate::process_chain::ProcessChainConfig::default())),
    )
    .unwrap();
    let serialized = serde_json::to_string(
        &super::super::super::event3::project_event3(&evaluation, &context())
            .unwrap()
            .events,
    )
    .unwrap();
    for marker in markers {
        assert!(!serialized.contains(marker));
    }
    assert!(!serialized.contains(r#"C:\private\token.txt"#));
}

#[test]
fn oversized_detection_event_keeps_anchors_and_marks_omitted_evidence() {
    use telltale_schema::event::{EVENT3_MAX_INPUT_BYTES, Event3Record, evidence_hash};
    let observations = dense_needles(3_000, &format!("needle {}", "ordinary ".repeat(60)));
    let (evaluation, _) = evaluate_scaled(&observations, 64 << 20);
    let projected =
        super::super::super::event3::project_event3(&evaluation.unwrap(), &context()).unwrap();
    let [event] = projected.events.as_slice() else {
        panic!("one detection event");
    };
    let bytes = serde_json::to_vec(event).unwrap();
    assert!(bytes.len() <= EVENT3_MAX_INPUT_BYTES);
    Event3Record::from_json(&bytes).expect("the strict consumer accepts the fitted event");
    assert_eq!(event.timeline_anchors.len(), observations.len());
    assert_eq!(projected.occurrences.len(), observations.len());
    let markers = omitted_markers(event);
    assert_eq!(markers.len(), 1);
    assert_eq!(markers[0].rule_id.as_deref(), Some("synthetic.atomic"));
    assert_eq!(markers[0].hash, None);
    let omitted = markers[0].redacted_value.parse::<usize>().unwrap();
    let kept = &event.evidence[..event.evidence.len() - 1];
    assert!(omitted > 0 && !kept.is_empty());
    assert_eq!(kept.len() + omitted, observations.len() * 2);
    // The earliest occurrences keep their evidence pairs, in order.
    let kept_ids = kept
        .iter()
        .filter(|item| item.field == "canonical_observation_id")
        .map(|item| item.hash.clone().unwrap())
        .collect::<Vec<_>>();
    let earliest = observations[..kept.len() / 2]
        .iter()
        .map(|observation| evidence_hash(observation.observation_id()))
        .collect::<Vec<_>>();
    assert_eq!(kept_ids, earliest);
    // Rules and score are those of the same rule in an event that fits.
    let (small, _) = evaluate_scaled(&observations[..1], 64 << 20);
    let small = super::super::super::event3::project_event3(&small.unwrap(), &context()).unwrap();
    assert_eq!(event.rule_ids, small.events[0].rule_ids);
    assert_eq!(event.risk_score, small.events[0].risk_score);
    assert!(omitted_markers(&small.events[0]).is_empty());
}

#[test]
fn detection_event_within_the_limit_is_not_changed_by_fitting() {
    let observations = dense_needles(200, &format!("needle {}", "ordinary ".repeat(60)));
    let (evaluation, _) = evaluate_scaled(&observations, 64 << 20);
    let projected =
        super::super::super::event3::project_event3(&evaluation.unwrap(), &context()).unwrap();
    let event = &projected.events[0];
    let before = serde_json::to_vec(event).unwrap();
    assert!(before.len() <= telltale_schema::event::EVENT3_MAX_INPUT_BYTES);
    assert_eq!(event.evidence.len(), observations.len() * 2);
    assert!(omitted_markers(event).is_empty());
    let mut fitted = event.clone();
    let occurrences = (0..observations.len()).collect::<Vec<_>>();
    super::super::super::event3::fit_detection_evidence(
        &mut fitted,
        &occurrences,
        &mut RetentionBudget::new(),
    )
    .unwrap();
    assert_eq!(serde_json::to_vec(&fitted).unwrap(), before);
}

#[test]
fn detection_event_whose_anchors_alone_exceed_the_limit_fails_projection() {
    let observations = dense_needles(10_000, "needle");
    let (evaluation, _) = evaluate_scaled(&observations, 64 << 20);
    assert!(matches!(
        super::super::super::event3::project_event3(&evaluation.unwrap(), &context()),
        Err(ProcessingError::Projection)
    ));
}
