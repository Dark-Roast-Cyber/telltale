//! Current Claude Code (2.1.x) transcripts through the scan binary. The
//! records are synthetic but keep the shapes Claude Code and the Claude
//! desktop app write today: bookkeeping records between turns, thinking
//! blocks, nested tool inputs, large authored file bodies, and text-array tool
//! results. Commands and outputs are inert data, never executed.

use super::*;

const SESSION: &str = "11111111-2222-4333-8444-555555555555";
const SECRET: &str = "SYNTHETIC-CLAUDE-OUTPUT-SECRET";
const RULES: &str = r#"
version: 1
description: Synthetic Claude Code coverage.
defaults: { case_insensitive: false, enabled: true }
modifiers: []
rules:
  - id: synthetic.claude.command
    title: Synthetic Claude command marker
    tags: [synthetic]
    category: synthetic
    severity: high
    score: 70
    detection:
      selection:
        command: 'synthetic-claude-command-marker'
      condition: selection
    explanation: Synthetic test.
  - id: synthetic.claude.result
    title: Synthetic Claude result marker
    tags: [synthetic]
    category: synthetic
    severity: high
    score: 60
    detection:
      selection:
        tool_result: 'synthetic-claude-result-marker'
      condition: selection
    explanation: Synthetic test.
  - id: synthetic.claude.path
    title: Synthetic Claude write path marker
    tags: [synthetic]
    category: synthetic
    severity: high
    score: 50
    detection:
      selection:
        file_path: 'synthetic-claude-path-marker'
      condition: selection
    explanation: Synthetic test.
"#;

fn record(kind: &str, uuid: &str, body: Value) -> String {
    let mut value = serde_json::json!({
        "type": kind,
        "uuid": uuid,
        "sessionId": SESSION,
        "timestamp": "2026-10-14T19:50:00.000Z",
        "cwd": "C:\\Users\\synthetic\\repo",
        "version": "2.1.295",
        "entrypoint": "claude-desktop",
        "userType": "external",
    });
    value
        .as_object_mut()
        .unwrap()
        .extend(body.as_object().unwrap().clone());
    value.to_string()
}

fn assistant(uuid: &str, content: Value) -> String {
    record(
        "assistant",
        uuid,
        serde_json::json!({"message": {"role": "assistant", "model": "claude-synthetic", "content": content}}),
    )
}

fn user(uuid: &str, content: Value) -> String {
    record(
        "user",
        uuid,
        serde_json::json!({"message": {"role": "user", "content": content}}),
    )
}

fn transcript() -> Vec<String> {
    let body = format!("{}\nsynthetic file body\n", "line ".repeat(2_000));
    vec![
        record(
            "queue-operation",
            "q1",
            serde_json::json!({"operation": "enqueue"}),
        ),
        user("u1", serde_json::json!("Please audit the synthetic repo.")),
        record(
            "attachment",
            "a1",
            serde_json::json!({"attachment": {"type": "hook_additional_context", "content": ["synthetic"]}}),
        ),
        assistant(
            "m1",
            serde_json::json!([
                {"type": "thinking", "thinking": "Synthetic private reasoning.", "signature": "sig"},
                {"type": "text", "text": "Planning the audit."},
                {"type": "tool_use", "id": "toolu_plan", "name": "mcp__ccd_turn__update_plan",
                 "input": {"items": [{"content": "Look around", "status": "in_progress"}], "scope": "first_task"}}
            ]),
        ),
        user(
            "u2",
            serde_json::json!([{"type": "tool_result", "tool_use_id": "toolu_plan", "content": "Plan shown."}]),
        ),
        assistant(
            "m2",
            serde_json::json!([
                {"type": "tool_use", "id": "toolu_ps", "name": "PowerShell",
                 "input": {"command": "Write-Output synthetic-claude-command-marker", "description": "Synthetic"}}
            ]),
        ),
        user(
            "u3",
            serde_json::json!([{"type": "tool_result", "tool_use_id": "toolu_ps",
                "content": [{"type": "text", "text": format!("token={SECRET}")},
                            {"type": "text", "text": "synthetic-claude-result-marker"}]}]),
        ),
        assistant(
            "m3",
            serde_json::json!([
                {"type": "tool_use", "id": "toolu_write", "name": "Write",
                 "input": {"file_path": "C:\\Users\\synthetic\\repo\\synthetic-claude-path-marker.txt", "content": body}}
            ]),
        ),
        // A search pattern is not authored text: over 4 KB it is quarantined
        // by itself, and the records after it still map.
        assistant(
            "m4",
            serde_json::json!([
                {"type": "tool_use", "id": "toolu_grep", "name": "Grep",
                 "input": {"pattern": format!("{SECRET}{}", "p".repeat(5_000))}}
            ]),
        ),
        record(
            "last-prompt",
            "l1",
            serde_json::json!({"lastPrompt": "synthetic"}),
        ),
        record(
            "custom-title",
            "t1",
            serde_json::json!({"customTitle": "synthetic"}),
        ),
        record(
            "agent-name",
            "n1",
            serde_json::json!({"agentName": "synthetic"}),
        ),
        record("atis-latch", "x1", serde_json::json!({"latched": true})),
        record(
            "file-history-snapshot",
            "f1",
            serde_json::json!({"snapshot": {"trackedFileBackups": {}}}),
        ),
        assistant(
            "m5",
            serde_json::json!([{"type": "text", "text": "Synthetic audit complete."}]),
        ),
    ]
}

#[test]
fn current_claude_code_transcript_is_parsed_and_detected() {
    let temp = tempdir().unwrap();
    let root = temp.path().join("home");
    let project = root.join(".claude/projects/C--Users-synthetic-repo");
    fs::create_dir_all(&project).unwrap();
    fs::write(
        project.join(format!("{SESSION}.jsonl")),
        transcript().join("\n") + "\n",
    )
    .unwrap();
    let rules = temp.path().join("rules.yaml");
    fs::write(&rules, RULES).unwrap();
    let log = temp.path().join("events.jsonl");

    let result = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .env_clear()
        .current_dir(temp.path())
        .args([
            "scan",
            "--once",
            "--client",
            "claude",
            "--no-local-config",
            "--emit-activity",
            "--install-inventory-disabled",
            "--no-default-rules",
            "--root",
        ])
        .arg(&root)
        .arg("--rules")
        .arg(&rules)
        .arg("--log-path")
        .arg(&log)
        .arg("--state-path")
        .arg(temp.path().join("state.json"))
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let summary: Value = serde_json::from_slice(&result.stdout).unwrap();
    let processing = &summary["source_processing"];
    assert_eq!(processing["parse_success_source_count"], 1, "{summary}");
    assert_eq!(processing["parse_error_source_count"], 0, "{summary}");
    assert_eq!(processing["selected_source_coverage"], "partial");
    assert_eq!(
        processing["quarantined_units"],
        serde_json::json!([{
            "source": "claude.projects",
            "session_id": SESSION,
            "native_id": "m4",
            "source_sequence": 8,
            "code": "unbounded_value",
            "bound_category": "ToolArguments",
            "bound_dimension": "StringBytes",
        }])
    );

    let events = fs::read_to_string(&log)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    for event in &events {
        assert!(event_schema_validator().is_valid(event), "{event}");
    }
    let detected = |rule: &str| {
        events
            .iter()
            .filter(|event| {
                event["event_type"] == "detection"
                    && event["evidence"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|evidence| evidence["rule_id"] == rule)
            })
            .count()
    };
    assert_eq!(detected("synthetic.claude.command"), 1);
    assert_eq!(detected("synthetic.claude.result"), 1);
    assert_eq!(detected("synthetic.claude.path"), 1);
    assert!(
        events
            .iter()
            .any(|event| event["event_type"] == "activity" && event["session_id"] == SESSION),
        "the session reports activity"
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| event["event_type"] == "scanner_error")
            .count(),
        1,
        "one content-free quarantine marker"
    );
    for bytes in [
        fs::read(&log).unwrap(),
        serde_json::to_vec(&summary).unwrap(),
    ] {
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains(SECRET));
        assert!(!text.contains("Synthetic private reasoning"));
    }
}

#[test]
fn persisted_claude_baseline_survives_quarantine_and_malformed_then_replaces_on_repair() {
    const EXCLUDED: &str = "SYNTHETIC-CLAUDE-LIFECYCLE-EXCLUDED";
    let temp = tempdir().unwrap();
    let directory = temp.path().canonicalize().unwrap();
    let root = directory.join("home");
    let project = root.join(".claude/projects/synthetic-lifecycle");
    fs::create_dir_all(&project).unwrap();
    let source = project.join(format!("{SESSION}.jsonl"));
    let rules = directory.join("rules.yaml");
    fs::write(&rules, RULES).unwrap();
    let log = directory.join("events.jsonl");
    let state_path = directory.join("state.json");

    let request = |id: &str, name: &str, input: Value| {
        record(
            "assistant",
            id,
            serde_json::json!({
                // Keep incidental version/time/cwd strings out of path contributions.
                "version":"synthetic", "timestamp":"2026-10-17T00:00:00Z", "cwd":"synthetic",
                "message":{"role":"assistant","model":"claude-synthetic","content":[
                    {"type":"tool_use","id":id,"name":name,"input":input}
                ]}
            }),
        )
    };
    let initial = vec![
        user(
            "initial-user",
            serde_json::json!("Initial complete source."),
        ),
        request(
            "initial-call",
            "PowerShell",
            serde_json::json!({"command":"Write-Output synthetic-claude-command-marker initial"}),
        ),
        user(
            "initial-result",
            serde_json::json!([{"type":"tool_result","tool_use_id":"initial-call","content":[
                {"type":"text","text":format!("synthetic-claude-result-marker initial token={SECRET}")}
            ]}]),
        ),
    ];
    let partial = vec![
        user(
            "partial-user",
            serde_json::json!("Different successful partial prefix."),
        ),
        request(
            "partial-call",
            "Write",
            serde_json::json!({"file_path":"synthetic-claude-path-marker.partial-only.txt","content":"partial body"}),
        ),
        user(
            "partial-result",
            serde_json::json!([{"type":"tool_result","tool_use_id":"partial-call","content":"synthetic-claude-result-marker partial-only"}]),
        ),
        record(
            "Future",
            "excluded-record",
            serde_json::json!({"opaque":format!("token={EXCLUDED}")}),
        ),
    ];
    let malformed = vec![
        user(
            "malformed-user",
            serde_json::json!("Distinct malformed-source prefix."),
        ),
        request(
            "malformed-call",
            "Bash",
            serde_json::json!({"command":"printf synthetic-claude-command-marker malformed-prefix-only"}),
        ),
        user(
            "malformed-result",
            serde_json::json!([{"type":"tool_result","tool_use_id":"malformed-call","content":"synthetic-claude-result-marker malformed-prefix-only"}]),
        ),
        user(
            "malformed-tail",
            serde_json::json!([{"type":null,"text":format!("token={EXCLUDED}")}]),
        ),
    ];
    let repaired = vec![
        user(
            "repaired-user-a",
            serde_json::json!("Repaired complete source, first user message."),
        ),
        user(
            "repaired-user-b",
            serde_json::json!("Repaired complete source, second user message."),
        ),
        request(
            "repaired-bash",
            "Bash",
            serde_json::json!({"command":"printf synthetic-claude-command-marker repaired-only"}),
        ),
        request("repaired-read", "Read", serde_json::json!({"limit":1})),
        user(
            "repaired-result",
            serde_json::json!([{"type":"tool_result","tool_use_id":"repaired-bash","content":"synthetic-claude-result-marker repaired-only"}]),
        ),
    ];

    let run = |phase: &str| {
        let previous = if log.exists() {
            fs::read(&log).unwrap()
        } else {
            Vec::new()
        };
        let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
            .env_clear()
            .current_dir(&directory)
            .args([
                "scan",
                "--once",
                "--client",
                "claude",
                "--no-local-config",
                "--emit-activity",
                "--install-inventory-disabled",
                "--no-default-rules",
                "--root",
            ])
            .arg(&root)
            .arg("--rules")
            .arg(&rules)
            .arg("--log-path")
            .arg(&log)
            .arg("--state-path")
            .arg(&state_path)
            .output()
            .unwrap();
        // Source failure is a summary/Event3 outcome, not a nonzero CLI status.
        assert!(output.status.success(), "{phase}: scan process failed");
        let log_bytes = fs::read(&log).unwrap();
        let state_bytes = fs::read(&state_path).unwrap();
        for (surface, bytes) in [
            ("stdout", &output.stdout),
            ("stderr", &output.stderr),
            ("JSONL", &log_bytes),
            ("state", &state_bytes),
        ] {
            let text = String::from_utf8_lossy(bytes);
            for marker in [SECRET, EXCLUDED] {
                assert!(
                    !text.contains(marker),
                    "{phase}: private marker leaked in {surface}"
                );
            }
        }
        assert!(
            log_bytes.starts_with(&previous),
            "{phase}: event log must append, not rewrite"
        );
        let events = std::str::from_utf8(&log_bytes[previous.len()..])
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert!(!events.is_empty(), "{phase}: missing appended events");
        for event in &events {
            assert!(
                event_schema_validator().is_valid(event),
                "{phase}: appended Event3 failed schema validation"
            );
        }
        (
            serde_json::from_slice::<Value>(&output.stdout).unwrap(),
            serde_json::from_slice::<Value>(&state_bytes).unwrap(),
            events,
        )
    };
    let baseline = |state: &Value, expected: &Value| {
        let contributions = state["baseline_source_contributions"].as_object().unwrap();
        assert_eq!(contributions.len(), 1, "exactly one source contribution");
        let contribution = contributions.values().next().unwrap();
        assert_eq!(contribution["client"], "claude");
        assert_eq!(contribution["source_id"], "claude.projects");
        for field in ["source_instance_id", "source_fingerprint"] {
            let hash = contribution[field].as_str().expect("persisted source hash");
            assert_eq!(hash.len(), 64);
            assert!(
                hash.bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            );
        }
        let source_snapshots = contribution["snapshots"].as_object().unwrap();
        let snapshots = state["baseline_snapshots"]["snapshots"]
            .as_object()
            .unwrap();
        assert_eq!(state["baseline_snapshots"]["schema_version"], 3);
        assert_eq!(source_snapshots.len(), 1);
        assert_eq!(snapshots.len(), 1);
        assert!(
            source_snapshots.values().next().unwrap() == expected,
            "persisted source counts differ from independent expectation"
        );
        assert!(
            snapshots.values().next().unwrap() == expected,
            "persisted aggregate counts differ from independent expectation"
        );
        assert!(source_snapshots.keys().eq(snapshots.keys()));
    };
    let initial_expected = serde_json::json!({
        "key":{"client":"claude","agent":null,"model":"claude-synthetic","provider":null},
        "observations":{"records":3,"user_messages":1,"assistant_messages":0,"tool_calls":1,"tool_results":1,"session_meta":0,"other":0},
        "tool_call_counts":{"powershell":1},"path_class_counts":{},"network_host_counts":{}
    });
    let repaired_expected = serde_json::json!({
        "key":{"client":"claude","agent":null,"model":"claude-synthetic","provider":null},
        "observations":{"records":5,"user_messages":2,"assistant_messages":0,"tool_calls":2,"tool_results":1,"session_meta":0,"other":0},
        "tool_call_counts":{"bash":1,"read":1},"path_class_counts":{},"network_host_counts":{}
    });
    let mut retained_baseline = None::<Value>;
    let mut source_event_hash = None::<Value>;
    for (phase, records, parsed_count, kinds, expected_rules, error_code) in [
        (
            "complete",
            initial,
            3,
            serde_json::json!({"user_message":1,"assistant_message":0,"tool_call":1,"tool_result":1,"session_meta":0,"other":0}),
            vec!["synthetic.claude.command", "synthetic.claude.result"],
            None,
        ),
        (
            "quarantine",
            partial,
            4,
            serde_json::json!({"user_message":1,"assistant_message":0,"tool_call":1,"tool_result":1,"session_meta":0,"other":1}),
            vec!["synthetic.claude.path", "synthetic.claude.result"],
            Some("canonical_units_quarantined"),
        ),
        (
            "malformed",
            malformed,
            0,
            serde_json::json!({"user_message":0,"assistant_message":0,"tool_call":0,"tool_result":0,"session_meta":0,"other":0}),
            vec![],
            Some("canonical_acquisition_failed"),
        ),
        (
            "repaired",
            repaired,
            5,
            serde_json::json!({"user_message":2,"assistant_message":0,"tool_call":2,"tool_result":1,"session_meta":0,"other":0}),
            vec!["synthetic.claude.command", "synthetic.claude.result"],
            None,
        ),
    ] {
        let is_quarantined = phase == "quarantine";
        let is_malformed = phase == "malformed";
        let is_repaired = phase == "repaired";
        let is_complete = phase == "complete" || is_repaired;
        fs::write(&source, records.join("\n") + "\n").unwrap();
        let (summary, state, events) = run(phase);
        let processing = &summary["source_processing"];
        assert_eq!(processing["selected_source_count"], 1, "{phase}");
        assert_eq!(
            processing["parse_success_source_count"],
            usize::from(!is_malformed),
            "{phase}"
        );
        assert_eq!(
            processing["parse_error_source_count"],
            usize::from(is_malformed),
            "{phase}"
        );
        assert_eq!(processing["parsed_record_count"], parsed_count, "{phase}");
        assert_eq!(processing["record_kind_counts"], kinds, "{phase}");
        assert_eq!(
            processing["accounting_complete_source_count"],
            usize::from(is_complete),
            "{phase}"
        );
        assert_eq!(
            processing["accounting_partial_source_count"],
            usize::from(is_quarantined),
            "{phase}"
        );
        assert_eq!(
            processing["selected_source_coverage"],
            if is_complete { "complete" } else { "partial" },
            "{phase}"
        );
        assert_eq!(processing["incomplete_window_source_count"], 0);
        assert_eq!(state["sqlite_ingestion_cursors"], serde_json::json!({}));
        if is_quarantined {
            assert_eq!(processing["quarantined_unit_count"], 1);
            assert_eq!(
                processing["quarantined_units"],
                serde_json::json!([{
                    "source":"claude.projects","session_id":SESSION,"native_id":"excluded-record",
                    "source_sequence":3,"code":"unknown_discriminator","bound_category":null,"bound_dimension":null
                }])
            );
        } else {
            assert_eq!(processing["quarantined_unit_count"], 0);
            assert_eq!(processing["quarantined_units"], serde_json::json!([]));
        }
        assert_eq!(
            processing["failures"],
            if is_malformed {
                serde_json::json!([{
                    "stage":"Acquisition","acquisition_code":"source_read","bound_category":null,"bound_dimension":null,"source_count":1
                }])
            } else {
                serde_json::json!([])
            },
            "{phase}"
        );

        let activity = events
            .iter()
            .filter(|event| event["event_type"] == "activity")
            .collect::<Vec<_>>();
        assert_eq!(
            activity.len(),
            usize::from(!is_malformed),
            "{phase}: successful prefix activity"
        );
        let detections = events
            .iter()
            .filter(|event| event["event_type"] == "detection")
            .collect::<Vec<_>>();
        if is_malformed {
            assert!(
                detections.is_empty(),
                "malformed source must not emit successful prefix detections"
            );
        }
        let mut detected_rules = detections
            .iter()
            .flat_map(|event| {
                event["rule_ids"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|id| id.as_str().unwrap())
            })
            .collect::<Vec<_>>();
        detected_rules.sort_unstable();
        assert_eq!(
            detected_rules, expected_rules,
            "{phase}: exact prefix rule findings"
        );
        let errors = events
            .iter()
            .filter(|event| event["event_type"] == "scanner_error")
            .collect::<Vec<_>>();
        assert_eq!(errors.len(), usize::from(error_code.is_some()), "{phase}");
        if let Some(code) = error_code {
            let evidence = errors[0]["evidence"].as_array().unwrap();
            assert!(
                evidence
                    .iter()
                    .any(|value| value["field"] == "error" && value["redacted_value"] == code),
                "{phase}: scanner-error category"
            );
            assert!(
                evidence.iter().any(|value| value["field"] == "source_path"
                    && value["redacted_value"] == "canonical source"),
                "{phase}: content-free source diagnostic"
            );
        }
        for event in activity
            .iter()
            .chain(detections.iter())
            .chain(errors.iter())
        {
            assert_eq!(event["client"], "claude");
            let hash = &event["source_path_hash"];
            assert_eq!(hash.as_str().unwrap().len(), 64);
            if let Some(first) = &source_event_hash {
                assert_eq!(hash, first, "{phase}: stable event source identity");
            } else {
                source_event_hash = Some(hash.clone());
            }
        }

        if let Some(first) = &retained_baseline {
            let contributions = state["baseline_source_contributions"].as_object().unwrap();
            let prior = first["baseline_source_contributions"].as_object().unwrap();
            assert_eq!(contributions.len(), 1);
            assert!(
                contributions.keys().eq(prior.keys()),
                "{phase}: stable persisted source key"
            );
            assert_eq!(
                contributions.values().next().unwrap()["source_instance_id"],
                prior.values().next().unwrap()["source_instance_id"]
            );
            if is_repaired {
                baseline(&state, &repaired_expected);
                assert!(
                    state["baseline_snapshots"]["snapshots"]
                        .as_object()
                        .unwrap()
                        .keys()
                        .eq(first["baseline_snapshots"]["snapshots"]
                            .as_object()
                            .unwrap()
                            .keys()),
                    "repair must replace the same baseline bucket"
                );
                assert_ne!(
                    contributions.values().next().unwrap()["source_fingerprint"],
                    prior.values().next().unwrap()["source_fingerprint"]
                );
            } else {
                for family in ["baseline_source_contributions", "baseline_snapshots"] {
                    assert!(
                        state[family] == first[family],
                        "{phase}: must preserve prior complete {family}"
                    );
                }
            }
        } else {
            baseline(&state, &initial_expected);
            retained_baseline = Some(serde_json::json!({
                "baseline_source_contributions":state["baseline_source_contributions"],
                "baseline_snapshots":state["baseline_snapshots"],
            }));
        }
    }
}
