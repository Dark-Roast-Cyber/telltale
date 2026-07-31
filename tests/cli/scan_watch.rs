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

fn start_mock_llm_server() -> (String, mpsc::Receiver<String>, thread::JoinHandle<()>) {
    start_mock_llm_server_with_content(
        "{\"verdict\":\"malicious\",\"severity\":\"critical\",\"confidence\":0.97,\"reason\":\"mock triage confirmed MCP injection\"}",
    )
}

fn start_mock_llm_server_with_content(
    content: &'static str,
) -> (String, mpsc::Receiver<String>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock llm server");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let addr = listener.local_addr().expect("listener addr");
    let (tx, rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let response_body = serde_json::json!({
            "id": "mock",
            "choices": [{
                "message": {
                    "content": content
                }
            }]
        })
        .to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            response_body.len(),
            response_body
        );
        let mut handled = 0_usize;
        while handled < 2 && Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_nonblocking(false).expect("blocking stream");
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .expect("read timeout");
                    let mut request = Vec::new();
                    let mut buf = [0_u8; 1024];
                    while let Ok(read) = stream.read(&mut buf) {
                        if read == 0 {
                            break;
                        }
                        request.extend_from_slice(&buf[..read]);
                        // Header matching is case-insensitive: the ureq
                        // transport sends lowercase header names.
                        let text = String::from_utf8_lossy(&request).to_lowercase();
                        if let Some((headers, body)) = text.split_once("\r\n\r\n") {
                            let content_length = headers
                                .lines()
                                .find_map(|line| line.strip_prefix("content-length: "))
                                .and_then(|value| value.trim().parse::<usize>().ok())
                                .unwrap_or(0);
                            if body.len() >= content_length {
                                break;
                            }
                        }
                    }
                    let _ = tx.send(String::from_utf8_lossy(&request).to_string());
                    stream
                        .write_all(response.as_bytes())
                        .expect("write mock response");
                    handled += 1;
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(_) => break,
            }
        }
    });
    (format!("http://{}", addr), rx, handle)
}

#[test]
fn scan_once_writes_schema_shaped_health_jsonl() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
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
        .expect("run adr");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    assert_eq!(summary["event_type"], "health");
    assert_eq!(summary["detection_count"], 36);
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
    assert_eq!(event["schema_version"], "2.0");
    assert_eq!(event["event_type"], "health");
    assert_eq!(event["severity"], "informational");
    assert_eq!(event["risk_score"], 0);
    assert_eq!(event["session_id"], "scanner");
    assert_eq!(event["component"], "scanner");
    assert_eq!(event["check_name"], "source_discovery");
    assert_eq!(event["status"], "ok");
    assert_eq!(
        event["adr_version"],
        format!("{} ({})", env!("CARGO_PKG_VERSION"), env!("ADR_GIT_HASH"))
    );
    assert!(event["scan_duration_ms"].as_u64().is_some());
    assert_eq!(event["rule_count"], 18);
    assert_eq!(event["emitted_count"], 37);
    assert_eq!(event["suppressed_count"], 0);
    assert_eq!(event["scanner_error_count"], 0);
    assert_eq!(event["threshold_config"]["low"], 20);
    assert_eq!(event["threshold_config"]["medium"], 50);
    assert_eq!(event["threshold_config"]["triage"], 70);
    assert_eq!(event["threshold_config"]["alert"], 90);
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
fn scan_once_client_filter_limits_discovered_sources() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
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
        .expect("run adr");

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
    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
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
        .output()
        .expect("run adr");

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
    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
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
        .expect("run adr");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unsupported client 'unknown-agent'"));
    assert!(stderr.contains("codex"));
    assert!(stderr.contains("gemini"));
}

#[test]
fn scan_once_max_sources_limits_discovered_sources() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
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
        .expect("run adr");

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
    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");

    for _ in 0..2 {
        let output = Command::new(env!("CARGO_BIN_EXE_adr"))
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
            .expect("run adr");

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
    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
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
        .expect("run adr");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--max-sources must be greater than 0"));
}

#[test]
fn scan_once_max_sources_is_deterministic() {
    let run_scan = || {
        Command::new(env!("CARGO_BIN_EXE_adr"))
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
            ])
            .output()
            .expect("run adr")
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
    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");

    let first = Command::new(env!("CARGO_BIN_EXE_adr"))
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
        .expect("run adr");
    assert!(
        first.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    let first_summary: Value = serde_json::from_slice(&first.stdout).expect("summary json");
    assert_eq!(first_summary["detection_count"], 36);
    assert_eq!(first_summary["emitted_count"], 37);

    let second = Command::new(env!("CARGO_BIN_EXE_adr"))
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
        .expect("run adr");
    assert!(
        second.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    let second_summary: Value = serde_json::from_slice(&second.stdout).expect("summary json");
    assert_eq!(second_summary["detection_count"], 36);
    assert_eq!(second_summary["emitted_count"], 0);

    let lines = fs::read_to_string(log_path).expect("log file");
    assert_eq!(lines.lines().count(), 38);
}

#[test]
fn cross_alias_scans_share_state_and_deduplicate_in_both_directions() {
    for (first_name, first_path, second_name, second_path) in [
        (
            "telltale",
            env!("CARGO_BIN_EXE_telltale"),
            "adr",
            env!("CARGO_BIN_EXE_adr"),
        ),
        (
            "adr",
            env!("CARGO_BIN_EXE_adr"),
            "telltale",
            env!("CARGO_BIN_EXE_telltale"),
        ),
    ] {
        let temp = tempdir().expect("tempdir");
        let log_path = temp.path().join("adr-events.jsonl");
        let state_path = temp.path().join("adr-state.json");
        let run_scan = |path: &str| {
            Command::new(path)
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
                .unwrap_or_else(|error| panic!("run {path}: {error}"))
        };

        let first = run_scan(first_path);
        assert!(
            first.status.success(),
            "{first_name} stderr: {}",
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

        let status = Command::new(second_path)
            .args(["status", "--log-path"])
            .arg(&log_path)
            .args(["--state-path"])
            .arg(&state_path)
            .output()
            .unwrap_or_else(|error| panic!("run {second_name} status: {error}"));
        assert!(
            status.status.success(),
            "{second_name} status stderr: {}",
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

        let second = run_scan(second_path);
        assert!(
            second.status.success(),
            "{second_name} stderr: {}",
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
            "{second_name} must not duplicate first-scan telemetry"
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
                "{second_name} must preserve shared dedup state field {field}"
            );
        }
    }
}

#[test]
fn scan_once_persists_incremental_baseline_snapshots() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");

    let run_scan = || {
        let output = Command::new(env!("CARGO_BIN_EXE_adr"))
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
            .expect("run adr");
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
    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");

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
        let output = Command::new(env!("CARGO_BIN_EXE_adr"))
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
            .expect("run adr");
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
    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");

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

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
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
        .expect("run adr");
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
    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");

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
        let mut command = Command::new(env!("CARGO_BIN_EXE_adr"));
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
        command.output().expect("run adr")
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
    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
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
        .expect("run adr");

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

    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");
    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
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
        .expect("run adr");

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
    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");
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

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
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
        .expect("run adr");

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
    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
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
        .expect("run adr");

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
    let log_path = temp.path().join("adr-events.jsonl");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
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
        .output()
        .expect("run adr");

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
    assert!(filebeat.contains("/var/log/telltale/adr-events.jsonl"));
    assert!(filebeat.contains("filestream"));
    assert!(filebeat.contains("ndjson"));

    let logrotate = include_str!("../../config/examples/telltale-logrotate");
    assert!(logrotate.contains("/var/log/telltale/adr-events.jsonl"));
    assert!(logrotate.contains("daily"));
    assert!(logrotate.contains("rotate 14"));
    assert!(logrotate.contains("extension .jsonl"));
    assert!(logrotate.contains("create 0640 telltale adrlogs"));
    assert!(logrotate.contains("su telltale adrlogs"));
    assert!(
        !logrotate.contains("copytruncate"),
        "JSONL rotation should avoid copytruncate by default"
    );

    // The Splunk UF helper ships as a tracked, portable example. Its defaults
    // must target the Linux `system` path profile used by managed/Splunk-forwarded
    // deployments, not stale repo-local or host-absolute paths. The matching
    // `config/examples/splunk-*.conf` and `splunk-*.xml` examples are host-only and
    // intentionally not tracked, so they are verified on disk instead of via
    // include_str!.
    let splunk_uf_setup = include_str!("../../scripts/slunk_uf_set_up");
    assert!(
        splunk_uf_setup.contains("ADR_LOG_PATH:-/var/log/telltale/adr-events.jsonl"),
        "splunk UF helper must default ADR_LOG_PATH to the system-profile JSONL path"
    );
    assert!(
        splunk_uf_setup.contains("COPILOT_LOG_DIR:-/var/log/telltale/copilot"),
        "splunk UF helper must default COPILOT_LOG_DIR to the system-profile copilot path"
    );
    assert!(
        !splunk_uf_setup.contains("/home/christian/github/adr/logs"),
        "splunk UF helper must not default to stale repo-local log paths"
    );
}

#[test]
fn elastic_template_preserves_schema_two_u64_risk_fields() {
    const DEFAULT_ELASTIC_INDEX: &str = "adr-events";

    let template: Value = serde_json::from_str(include_str!(
        "../../config/examples/elastic-telltale-index-template.json"
    ))
    .expect("elastic template json");
    let patterns = template["index_patterns"]
        .as_array()
        .expect("elastic index patterns");
    assert!(
        patterns
            .iter()
            .any(|pattern| { pattern.as_str() == Some(DEFAULT_ELASTIC_INDEX) })
    );
    let rollover_pattern = format!("{DEFAULT_ELASTIC_INDEX}-*");
    assert!(
        patterns
            .iter()
            .any(|pattern| pattern.as_str() == Some(rollover_pattern.as_str()))
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
        script.contains("~/.local/bin"),
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

    // Curl|bash ready.
    assert!(script.contains("agentarchaeology.ai/telltale_install.sh"));
}

#[test]
fn scan_rotates_jsonl_when_max_size_exceeded() {
    let temp = tempdir().expect("tempdir");
    let fixture_root = std::env::current_dir()
        .expect("current dir")
        .join("tests/fixtures/session_stores");
    let log_path = temp.path().join("logs/adr-events.jsonl");

    // First scan creates the file (no rotation since file doesn't exist yet).
    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
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
        ])
        .output()
        .expect("run adr");

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
    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
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
        ])
        .output()
        .expect("run adr");

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
            name.starts_with("adr-events-") && name.ends_with(".jsonl")
        })
        .collect();
    assert!(
        !rotated.is_empty(),
        "expected at least one rotated file after exceeding max size"
    );

    // Rotated file should have a date in the name.
    let rotated_name = rotated[0].file_name().to_string_lossy().to_string();
    assert!(
        rotated_name.contains("adr-events-2"),
        "rotated file should be date-stamped: {rotated_name}"
    );
}

#[test]
fn scan_with_log_rotate_disabled_does_not_rotate() {
    let temp = tempdir().expect("tempdir");
    let fixture_root = std::env::current_dir()
        .expect("current dir")
        .join("tests/fixtures/session_stores");
    let log_path = temp.path().join("logs/adr-events.jsonl");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
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
        .expect("run adr");

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
            name.starts_with("adr-events-") && name.ends_with(".jsonl")
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

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
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
        .expect("run adr");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    assert_eq!(summary["log_path"], "logs/adr-events.jsonl");
    assert!(temp.path().join("logs/adr-events.jsonl").is_file());
    assert!(temp.path().join("state/adr-state.json").is_file());
    assert!(!temp.path().join("logs/adr-state.json").exists());
}

#[test]
fn scan_uses_env_log_and_state_defaults() {
    let temp = tempdir().expect("tempdir");
    let fixture_root = std::env::current_dir()
        .expect("current dir")
        .join("tests/fixtures/session_stores");
    let log_path = temp.path().join("env-logs/adr-events.jsonl");
    let state_path = temp.path().join("env-state/adr-state.json");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .current_dir(temp.path())
        .env("ADR_LOG_PATH", &log_path)
        .env("ADR_STATE_PATH", &state_path)
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
        .expect("run adr");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    assert_eq!(summary["log_path"], log_path.display().to_string());
    assert!(log_path.is_file());
    assert!(state_path.is_file());
    assert!(!temp.path().join("logs/adr-events.jsonl").exists());
    assert!(!temp.path().join("state/adr-state.json").exists());
}

#[test]
fn systemd_examples_run_periodic_scan_with_env_defaults() {
    let service = include_str!("../../config/examples/adr-scan.service");
    assert!(service.contains("User=telltale"));
    assert!(service.contains("Group=telltale"));
    assert!(service.contains("WorkingDirectory=/var/lib/telltale"));
    assert!(service.contains("Environment=ADR_LOG_PATH=/var/log/telltale/adr-events.jsonl"));
    assert!(service.contains("Environment=ADR_STATE_PATH=/var/lib/telltale/adr-state.json"));
    assert!(service.contains("Environment=ADR_SCAN_ROOT=/home/telltale"));
    assert!(service.contains("EnvironmentFile=-/etc/telltale/adr.env"));
    assert!(
        service
            .find("Environment=ADR_SCAN_ROOT=/home/telltale")
            .expect("scan root default")
            < service
                .find("EnvironmentFile=-/etc/telltale/adr.env")
                .expect("env file")
    );
    assert!(service.contains("/usr/local/bin/telltale scan --once"));
    assert!(!service.contains("ExecStart=/usr/local/bin/adr "));
    assert!(service.contains("--emit-activity"));
    assert!(service.contains("--path-profile system"));
    assert!(
        service.contains("--log-rotate-disabled"),
        "system profile service must disable built-in rotation when OS-native logrotate is used"
    );
    assert!(service.contains("ReadWritePaths=/var/log/telltale /var/lib/telltale"));

    let timer = include_str!("../../config/examples/adr-scan.timer");
    assert!(timer.contains("OnUnitActiveSec=5min"));
    assert!(timer.contains("Unit=adr-scan.service"));
    assert!(timer.contains("WantedBy=timers.target"));

    let timer_template = include_str!("../../config/examples/adr-scan.timer.in");
    assert!(timer_template.contains("OnUnitActiveSec=5min"));
    assert!(timer_template.contains("Unit=adr-scan.service"));
    assert!(timer_template.contains("WantedBy=timers.target"));

    let task = include_str!("../../config/examples/adr-scan-task.xml");
    assert!(task.contains(r#"<URI>\TelltaleScan</URI>"#));
    assert!(task.contains(r#"<Command>%LOCALAPPDATA%\Telltale\telltale.exe</Command>"#));
    assert!(!task.contains("\\adr.exe"));
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

    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");
    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
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
        .expect("run adr");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    assert_eq!(summary["detection_count"], 2);
    assert_eq!(summary["emitted_count"], 2);
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
    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
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
        .expect("run adr");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("refusing to write fixture/demo data"));
    assert!(!log_path.exists());
}

#[test]
fn scan_once_allows_fixture_root_with_dry_run() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
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
        .expect("run adr");

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
    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["watch", "--help"])
        .output()
        .expect("run adr watch help");

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

#[test]
fn watch_scans_changed_source_and_exits_after_iterations() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("stores");
    copy_dir_recursive(
        Path::new("tests/fixtures/session_stores/codex"),
        &root.join("codex"),
    );
    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");
    let session_path = root.join("codex/sessions/2026/04/session-a.jsonl");

    let mut child = Command::new(env!("CARGO_BIN_EXE_adr"))
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
        .expect("spawn adr watch");

    // Rewrite a watched fixture until the watcher notices; the watcher may
    // still be initializing on the first writes.
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if child.try_wait().expect("poll adr watch").is_some() {
            break;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("adr watch did not exit within timeout");
        }
        let contents = fs::read(&session_path).expect("read watched fixture");
        fs::write(&session_path, contents).expect("rewrite watched fixture");
        thread::sleep(Duration::from_millis(200));
    }

    let output = child.wait_with_output().expect("collect adr watch output");
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
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("stores");
    copy_dir_recursive(
        Path::new("tests/fixtures/session_stores/codex"),
        &root.join("codex"),
    );
    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");
    let session_path = root.join("codex/sessions/2026/04/session-a.jsonl");

    let mut child = Command::new(env!("CARGO_BIN_EXE_adr"))
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
        .expect("spawn adr watch");

    // Trigger the first scan by rewriting the watched file. The watcher
    // blocks until a filesystem event arrives, so we must poke the file
    // to start the first iteration. Retry until the state file appears,
    // which signals the first scan completed and persisted state.
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if child.try_wait().expect("poll adr watch").is_some() {
            panic!("adr watch exited before first scan completed");
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("adr watch did not persist state within timeout");
        }
        let contents = fs::read(&session_path).expect("read watched fixture");
        fs::write(&session_path, contents).expect("rewrite watched fixture");
        if state_path.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(200));
    }

    // Give the first scan a moment to finish writing state and re-block on
    // the next event before we snapshot mtime and trigger the second scan.
    thread::sleep(Duration::from_millis(300));

    let mtime_after_first_scan = fs::metadata(&state_path)
        .expect("state metadata")
        .modified()
        .expect("state mtime");

    // Trigger the second scan with identical content. No new records means
    // no emitted events and no durable state changes, so the state-save
    // should be skipped.
    let contents = fs::read(&session_path).expect("read watched fixture");
    fs::write(&session_path, contents).expect("rewrite watched fixture");

    // Wait for the second iteration to finish and the process to exit.
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if child.try_wait().expect("poll adr watch").is_some() {
            break;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("adr watch did not exit after second scan within timeout");
        }
        thread::sleep(Duration::from_millis(100));
    }

    let output = child.wait_with_output().expect("collect adr watch output");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let mtime_after_second_scan = fs::metadata(&state_path)
        .expect("state metadata")
        .modified()
        .expect("state mtime");
    assert_eq!(
        mtime_after_first_scan, mtime_after_second_scan,
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

    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");
    let mut child = WatchChildGuard::new(
        Command::new(env!("CARGO_BIN_EXE_adr"))
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
            .expect("spawn adr watch soak"),
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
            if let Some(status) = child.try_wait().expect("poll adr watch") {
                panic!("adr watch exited before scan completed: {status:?}")
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("adr watch did not complete the single triggered scan within timeout")
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
                .expect("poll adr watch quiet period")
                .is_some()
                && !allow_exit_during_quiet
            {
                panic!("adr watch exited unexpectedly during quiet period")
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
                        name == "adr-events.jsonl"
                            || (name.starts_with("adr-events-") && name.ends_with(".jsonl"))
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
        if let Some(status) = child.child_mut().try_wait().expect("poll final adr watch") {
            break status;
        }
        if Instant::now() >= exit_deadline {
            let _ = child.child_mut().kill();
            let _ = child.child_mut().wait();
            panic!("adr watch did not exit after finite soak iterations")
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
        .expect("collect adr watch output");
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
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("stores");
    copy_dir_recursive(
        Path::new("tests/fixtures/session_stores/codex"),
        &root.join("codex"),
    );

    let mut child = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["watch", "--dry-run", "--no-local-config", "--root"])
        .arg(&root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn adr watch");

    // Give the process time to install the signal handler and watcher.
    thread::sleep(Duration::from_secs(2));
    let kill = Command::new("kill")
        .arg(child.id().to_string())
        .status()
        .expect("send SIGTERM");
    assert!(kill.success());

    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status) = child.try_wait().expect("poll adr watch") {
            assert!(
                status.success(),
                "watch should exit cleanly on SIGTERM, got {status:?}"
            );
            break;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("adr watch did not exit after SIGTERM");
        }
        thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn watch_rejects_unknown_client_filter() {
    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args([
            "watch",
            "--dry-run",
            "--root",
            "tests/fixtures/session_stores",
            "--client",
            "unknown-agent",
        ])
        .output()
        .expect("run adr watch");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unsupported client 'unknown-agent'"));
    assert!(stderr.contains("codex"));
    assert!(stderr.contains("gemini"));
}

#[test]
fn scan_once_attaches_mock_llm_triage_to_detection_event() {
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
    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");
    let (api_base, requests, handle) = start_mock_llm_server();
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

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
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
        .env("ADR_RISK_THRESHOLD_TRIAGE", "1")
        .current_dir(temp.path())
        .output()
        .expect("run adr scan");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    handle.join().expect("mock server thread");
    let captured_requests = requests.try_iter().collect::<Vec<_>>();
    assert_eq!(captured_requests.len(), 2);
    assert!(captured_requests[0].contains("\"model\":\"guard-model\""));
    assert!(captured_requests[1].contains("\"model\":\"triage-model\""));

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
    assert_eq!(detection["triage"]["required"], true);
    assert_eq!(detection["triage"]["verdict"], "malicious");
    assert_eq!(detection["triage"]["confidence"], 0.97);
    assert_eq!(
        detection["triage"]["reason"],
        "mock triage confirmed MCP injection"
    );
}

#[test]
fn scan_once_preserves_schema_valid_benign_triage_verdict() {
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
    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");
    let (api_base, _requests, handle) = start_mock_llm_server_with_content(
        "{\"verdict\":\"benign\",\"severity\":\"low\",\"confidence\":0.88,\"reason\":\"mock triage treated fixture as explained developer workflow\"}",
    );
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

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
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
        .env("ADR_RISK_THRESHOLD_TRIAGE", "1")
        .current_dir(temp.path())
        .output()
        .expect("run adr scan");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    handle.join().expect("mock server thread");

    let lines = fs::read_to_string(log_path).expect("log file");
    let detection = lines
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event json"))
        .find(|event| event["event_type"] == "detection")
        .expect("detection event");
    assert_eq!(detection["triage"]["required"], true);
    assert_eq!(detection["triage"]["verdict"], "benign");
    assert_eq!(detection["triage"]["confidence"], 0.88);

    let schema: Value =
        serde_json::from_str(include_str!("../../schemas/event.schema.json")).expect("schema json");
    let validator = validator_for(&schema).expect("schema validator");
    assert!(
        validator.is_valid(&detection),
        "benign triage event failed schema validation"
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

    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");
    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
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
        .env("ADR_OP_ALERT_MAX_SCANNER_ERRORS", "0")
        .output()
        .expect("run adr");

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
    assert!(alert["adr_version"].is_string());

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

    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");
    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
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
        .env("ADR_OP_ALERT_MAX_SCANNER_ERRORS", "5")
        .output()
        .expect("run adr");

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

    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");

    let run_scan = || {
        let output = Command::new(env!("CARGO_BIN_EXE_adr"))
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
            .env("ADR_OP_ALERT_MAX_SCANNER_ERRORS", "5")
            .output()
            .expect("run adr");

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
