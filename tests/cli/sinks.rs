use super::*;

fn assert_http_header(request: &str, expected_name: &str, expected_value: &str) {
    let actual = request
        .lines()
        .take_while(|line| !line.trim().is_empty())
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case(expected_name)
                .then_some(value.trim())
        });
    assert_eq!(
        actual,
        Some(expected_value),
        "expected HTTP header {expected_name}: {expected_value}; captured request:\n{request}"
    );
}

fn start_mock_hec_server() -> (
    String,
    mpsc::Receiver<String>,
    mpsc::Sender<()>,
    thread::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock hec server");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let addr = listener.local_addr().expect("listener addr");
    let (tx, rx) = mpsc::channel();
    let (shutdown_tx, shutdown_rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        loop {
            match shutdown_rx.try_recv() {
                Ok(()) | Err(mpsc::TryRecvError::Disconnected) => break,
                Err(mpsc::TryRecvError::Empty) => {}
            }
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
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 17\r\nConnection: close\r\n\r\n{\"text\":\"ok\"}\n",
                        )
                        .expect("write mock hec response");
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(_) => break,
            }
        }
    });
    (
        format!("http://{addr}/services/collector"),
        rx,
        shutdown_tx,
        handle,
    )
}

#[test]
fn scan_once_can_emit_to_splunk_hec_without_disabling_jsonl() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("empty-root");
    fs::create_dir_all(&root).expect("empty root");
    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");
    let (hec_endpoint, requests, shutdown, handle) = start_mock_hec_server();

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["scan", "--once", "--no-local-config", "--root"])
        .arg(&root)
        .args(["--log-path"])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .args(["--splunk-hec-endpoint", &hec_endpoint])
        .args(["--splunk-hec-token", "test-token"])
        .arg("--install-inventory-disabled")
        .output()
        .expect("run adr");

    shutdown.send(()).expect("stop mock hec server");
    handle.join().expect("mock hec thread");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let lines = fs::read_to_string(&log_path).expect("jsonl log");
    assert_eq!(lines.lines().count(), 1);
    let request = requests
        .recv_timeout(Duration::from_secs(2))
        .expect("hec request");
    assert!(request.starts_with("POST /services/collector HTTP/1.1"));
    assert_http_header(&request, "Authorization", "Splunk test-token");
    let body = request.split_once("\r\n\r\n").expect("body split").1;
    let envelope: Value = serde_json::from_str(body.trim()).expect("hec envelope");
    assert_eq!(envelope["index"], "adr");
    assert_eq!(envelope["sourcetype"], "adr:json");
    assert_eq!(envelope["event"]["event_type"], "health");
    assert_eq!(
        envelope["event"]["source_counts"]
            .as_object()
            .unwrap()
            .len(),
        0
    );
    assert!(envelope["event"].get("index").is_none());
}

#[test]
fn scan_once_emits_identical_events_to_jsonl_and_splunk_hec() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");
    let (hec_endpoint, requests, shutdown, handle) = start_mock_hec_server();

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
        .args(["--splunk-hec-endpoint", &hec_endpoint])
        .args(["--splunk-hec-token", "test-token"])
        .arg("--install-inventory-disabled")
        .output()
        .expect("run adr");

    shutdown.send(()).expect("stop mock hec server");
    handle.join().expect("mock hec thread");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let jsonl_events = fs::read_to_string(&log_path)
        .expect("jsonl log")
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("jsonl event"))
        .collect::<Vec<_>>();
    let hec_events = requests
        .iter()
        .flat_map(|request| {
            assert!(request.starts_with("POST /services/collector HTTP/1.1"));
            assert_http_header(&request, "Authorization", "Splunk test-token");
            // Envelopes are batched: one request body holds one envelope
            // per line.
            let body = request.split_once("\r\n\r\n").expect("body split").1;
            body.lines()
                .filter(|line| !line.trim().is_empty())
                .map(|line| {
                    let envelope: Value = serde_json::from_str(line).expect("hec envelope");
                    assert_eq!(envelope["index"], "adr");
                    assert_eq!(envelope["sourcetype"], "adr:json");
                    envelope["event"].clone()
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    assert_eq!(hec_events.len(), jsonl_events.len());
    assert_eq!(hec_events, jsonl_events);

    let detections = jsonl_events
        .iter()
        .filter(|event| event["event_type"] == "detection")
        .collect::<Vec<_>>();
    assert!(detections.len() >= 36, "expected fixture detections");
    assert!(detections.iter().any(|event| {
        event["session_id"] == "tool-injection-shape-session"
            && event["rule_ids"].as_array().is_some_and(|rule_ids| {
                rule_ids
                    .iter()
                    .any(|rule_id| rule_id == "tool.injection.shape")
            })
    }));
}

#[test]
fn scan_once_requires_splunk_hec_endpoint_and_token_together() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("empty-root");
    fs::create_dir_all(&root).expect("empty root");
    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["scan", "--once", "--no-local-config", "--root"])
        .arg(&root)
        .args(["--log-path"])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .args([
            "--splunk-hec-endpoint",
            "http://127.0.0.1:8088/services/collector",
        ])
        .output()
        .expect("run adr");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--splunk-hec-endpoint and --splunk-hec-token must be set together"));
    assert!(!log_path.exists());
    assert!(!state_path.exists());
}

#[test]
fn scan_once_continues_and_alerts_when_splunk_hec_is_unreachable() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("empty-root");
    fs::create_dir_all(&root).expect("empty root");
    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");
    // Bind and immediately drop a listener so the port is closed: connection refused.
    let unreachable_endpoint = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("probe listener");
        let addr = listener.local_addr().expect("probe addr");
        drop(listener);
        format!("http://{addr}/services/collector")
    };

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["scan", "--once", "--no-local-config", "--root"])
        .arg(&root)
        .args(["--log-path"])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .args(["--splunk-hec-endpoint", &unreachable_endpoint])
        .args(["--splunk-hec-token", "test-token"])
        .arg("--install-inventory-disabled")
        .output()
        .expect("run adr");

    assert!(
        output.status.success(),
        "remote sink failure must not abort the scan; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // The local JSONL log has the health event plus the delivery-failure alert.
    let jsonl_events = fs::read_to_string(&log_path)
        .expect("jsonl log")
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("jsonl event"))
        .collect::<Vec<_>>();
    let alert = jsonl_events
        .iter()
        .find(|event| event["event_type"] == "operational_alert")
        .expect("sink delivery failure alert in local jsonl");
    assert_eq!(alert["check_name"], "sink_delivery");
    let evidence = alert["evidence"].as_array().expect("alert evidence");
    assert!(evidence.iter().any(|item| {
        item["field"] == "threshold"
            && item["redacted_value"]
                .as_str()
                .is_some_and(|value| value.starts_with("attempts_made="))
    }));
    assert!(evidence.iter().any(|item| {
        item["field"] == "alert_type" && item["redacted_value"] == "sink_delivery_failure"
    }));
    assert!(evidence.iter().any(|item| {
        item["field"] == "actual_value"
            && item["redacted_value"].as_str().is_some_and(|value| {
                value.contains("sink=cli-splunk-hec") && value.contains("type=splunk_hec")
            })
    }));

    // The stdout summary reports the failed sink.
    let stdout = String::from_utf8_lossy(&output.stdout);
    let summary: Value =
        serde_json::from_str(stdout.lines().last().expect("summary line")).expect("summary json");
    let sink_failures = summary["sink_failures"].as_array().expect("sink_failures");
    assert_eq!(sink_failures.len(), 1);
    assert_eq!(sink_failures[0]["name"], "cli-splunk-hec");
    assert_eq!(sink_failures[0]["type"], "splunk_hec");
    assert_eq!(summary["delivery"]["posture"], "durable_first_write");
    assert_eq!(summary["delivery"]["status"], "failed");
    assert_eq!(summary["delivery"]["durable_first_write"], true);
    assert_eq!(summary["delivery"]["built_in_persistent_replay"], false);
    assert!(String::from_utf8_lossy(&output.stderr).contains("local JSONL retains"));
}

#[test]
fn scan_once_uses_outputs_config_sinks() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("empty-root");
    fs::create_dir_all(&root).expect("empty root");
    let cli_log_path = temp.path().join("cli-events.jsonl");
    let config_log_path = temp.path().join("policy-events.jsonl");
    let state_path = temp.path().join("adr-state.json");
    let (hec_endpoint, requests, shutdown, handle) = start_mock_hec_server();

    let config_dir = temp.path().join("conf");
    let outputs_dir = config_dir.join("outputs.d");
    fs::create_dir_all(&outputs_dir).expect("outputs.d");
    fs::write(
        outputs_dir.join("outputs.yaml"),
        format!(
            r#"
version: 1
sinks:
  - name: local
    type: jsonl
    path: {}
  - name: corp-splunk
    type: splunk_hec
    endpoint: {}
    token: {{ env: ADR_TEST_OUTPUTS_HEC_TOKEN }}
    source: telltale:outputs-test
"#,
            config_log_path.display(),
            hec_endpoint
        ),
    )
    .expect("write outputs yaml");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["scan", "--once", "--root"])
        .arg(&root)
        .args(["--config-dir"])
        .arg(&config_dir)
        .args(["--log-path"])
        .arg(&cli_log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .arg("--install-inventory-disabled")
        .env("ADR_TEST_OUTPUTS_HEC_TOKEN", "env-secret-token")
        .output()
        .expect("run adr");

    shutdown.send(()).expect("stop mock hec server");
    handle.join().expect("mock hec thread");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // The config-defined jsonl path wins over --log-path.
    let lines = fs::read_to_string(&config_log_path).expect("policy jsonl log");
    assert_eq!(lines.lines().count(), 1);
    assert!(!cli_log_path.exists(), "config path replaces --log-path");

    // The HEC sink resolved its token from the environment and applied
    // the config's source override.
    let request = requests
        .recv_timeout(Duration::from_secs(2))
        .expect("hec request");
    assert_http_header(&request, "Authorization", "Splunk env-secret-token");
    let body = request.split_once("\r\n\r\n").expect("body split").1;
    let envelope: Value = serde_json::from_str(body.trim()).expect("hec envelope");
    assert_eq!(envelope["source"], "telltale:outputs-test");
    assert_eq!(envelope["event"]["event_type"], "health");
}

#[test]
fn scan_once_remote_only_delivers_without_creating_local_log() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("empty-root");
    fs::create_dir_all(&root).expect("empty root");
    let log_path = temp.path().join("should-not-exist.jsonl");
    let state_path = temp.path().join("adr-state.json");
    let (hec_endpoint, requests, shutdown, handle) = start_mock_hec_server();

    let config_dir = temp.path().join("conf");
    let outputs_dir = config_dir.join("outputs.d");
    fs::create_dir_all(&outputs_dir).expect("outputs.d");
    fs::write(
        outputs_dir.join("outputs.yaml"),
        format!(
            r#"
version: 1
sinks:
  - name: remote-only
    type: splunk_hec
    endpoint: {hec_endpoint}
    token: test-token
    retry: {{ max_attempts: 1, base_delay_ms: 0 }}
"#
        ),
    )
    .expect("write outputs yaml");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["scan", "--once", "--root"])
        .arg(&root)
        .args(["--config-dir"])
        .arg(&config_dir)
        .args(["--log-path"])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .arg("--install-inventory-disabled")
        .output()
        .expect("run adr");

    let request = requests
        .recv_timeout(Duration::from_secs(2))
        .expect("hec request");
    shutdown.send(()).expect("stop mock hec server");
    handle.join().expect("mock hec thread");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !log_path.exists(),
        "remote-only delivery must not create JSONL"
    );

    let body = request.split_once("\r\n\r\n").expect("body split").1;
    let envelope: Value = serde_json::from_str(body.trim()).expect("hec envelope");
    assert_eq!(envelope["event"]["event_type"], "health");
    assert_eq!(envelope["event"]["schema_version"], "1.0");
    assert!(envelope["event"]["event_id"].is_string());
    assert!(envelope["event"].get("index").is_none());

    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    assert_eq!(summary["delivery"]["posture"], "best_effort_no_replay");
    assert_eq!(summary["delivery"]["status"], "delivered");
    assert_eq!(summary["delivery"]["built_in_persistent_replay"], false);
    assert_eq!(summary["sink_failures"].as_array().unwrap().len(), 0);
}

#[test]
fn scan_once_explicit_empty_outputs_has_no_legacy_local_sink() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("empty-root");
    fs::create_dir_all(&root).expect("empty root");
    let log_path = temp.path().join("should-not-exist.jsonl");
    let state_path = temp.path().join("adr-state.json");
    let config_dir = temp.path().join("conf");
    let outputs_dir = config_dir.join("outputs.d");
    fs::create_dir_all(&outputs_dir).expect("outputs.d");
    fs::write(outputs_dir.join("outputs.yaml"), "version: 1\nsinks: []\n")
        .expect("write empty outputs yaml");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["scan", "--once", "--root"])
        .arg(&root)
        .args(["--config-dir"])
        .arg(&config_dir)
        .args(["--log-path"])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .arg("--install-inventory-disabled")
        .output()
        .expect("run adr");

    assert!(output.status.success(), "stderr: {:?}", output.stderr);
    assert!(
        !log_path.exists(),
        "explicit empty outputs must not use legacy JSONL"
    );
    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    assert_eq!(summary["delivery"]["posture"], "no_enabled_sinks");
    assert_eq!(summary["delivery"]["status"], "not_delivered");
}

#[test]
fn scan_once_all_disabled_outputs_have_no_local_sink() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("empty-root");
    fs::create_dir_all(&root).expect("empty root");
    let log_path = temp.path().join("should-not-exist.jsonl");
    let state_path = temp.path().join("adr-state.json");
    let config_dir = temp.path().join("conf");
    let outputs_dir = config_dir.join("outputs.d");
    fs::create_dir_all(&outputs_dir).expect("outputs.d");
    fs::write(
        outputs_dir.join("outputs.yaml"),
        "version: 1\nsinks:\n  - name: disabled-local\n    type: jsonl\n    enabled: false\n",
    )
    .expect("write disabled outputs yaml");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["scan", "--once", "--root"])
        .arg(&root)
        .args(["--config-dir"])
        .arg(&config_dir)
        .args(["--log-path"])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .arg("--install-inventory-disabled")
        .output()
        .expect("run adr");

    assert!(output.status.success(), "stderr: {:?}", output.stderr);
    assert!(
        !log_path.exists(),
        "all-disabled outputs must not write JSONL"
    );
    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    assert_eq!(summary["delivery"]["posture"], "no_enabled_sinks");
    assert_eq!(summary["delivery"]["status"], "not_delivered");
}

#[test]
fn scan_once_explicit_empty_outputs_keeps_cli_hec_overlay_only() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("empty-root");
    fs::create_dir_all(&root).expect("empty root");
    let log_path = temp.path().join("should-not-exist.jsonl");
    let state_path = temp.path().join("adr-state.json");
    let (hec_endpoint, requests, shutdown, handle) = start_mock_hec_server();
    let config_dir = temp.path().join("conf");
    let outputs_dir = config_dir.join("outputs.d");
    fs::create_dir_all(&outputs_dir).expect("outputs.d");
    fs::write(outputs_dir.join("outputs.yaml"), "version: 1\nsinks: []\n")
        .expect("write empty outputs yaml");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["scan", "--once", "--root"])
        .arg(&root)
        .args(["--config-dir"])
        .arg(&config_dir)
        .args(["--log-path"])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .args(["--splunk-hec-endpoint", &hec_endpoint])
        .args(["--splunk-hec-token", "test-token"])
        .arg("--install-inventory-disabled")
        .output()
        .expect("run adr");

    let request = requests
        .recv_timeout(Duration::from_secs(2))
        .expect("hec request");
    shutdown.send(()).expect("stop mock hec server");
    handle.join().expect("mock hec thread");
    assert!(output.status.success(), "stderr: {:?}", output.stderr);
    assert!(
        !log_path.exists(),
        "explicit empty outputs must not add JSONL"
    );
    let body = request.split_once("\r\n\r\n").expect("body split").1;
    let envelope: Value = serde_json::from_str(body.trim()).expect("hec envelope");
    assert_eq!(envelope["event"]["event_type"], "health");
    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    assert_eq!(summary["delivery"]["posture"], "best_effort_no_replay");
    assert_eq!(summary["delivery"]["status"], "delivered");
}

#[test]
fn scan_once_exhausted_remote_only_delivery_is_failed_without_replay_claim() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("empty-root");
    fs::create_dir_all(&root).expect("empty root");
    let log_path = temp.path().join("should-not-exist.jsonl");
    let state_path = temp.path().join("adr-state.json");
    let unreachable_endpoint = {
        let listener = TcpListener::bind("127.0.0.1:0").expect("probe listener");
        let addr = listener.local_addr().expect("probe addr");
        drop(listener);
        format!("http://{addr}/services/collector")
    };

    let config_dir = temp.path().join("conf");
    let outputs_dir = config_dir.join("outputs.d");
    fs::create_dir_all(&outputs_dir).expect("outputs.d");
    fs::write(
        outputs_dir.join("outputs.yaml"),
        format!(
            r#"
version: 1
sinks:
  - name: remote-only
    type: splunk_hec
    endpoint: {unreachable_endpoint}
    token: test-token
    retry: {{ max_attempts: 1, base_delay_ms: 0 }}
"#
        ),
    )
    .expect("write outputs yaml");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["scan", "--once", "--root"])
        .arg(&root)
        .args(["--config-dir"])
        .arg(&config_dir)
        .args(["--log-path"])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .arg("--install-inventory-disabled")
        .output()
        .expect("run adr");

    assert!(
        output.status.success(),
        "remote failure should remain non-fatal: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !log_path.exists(),
        "remote-only delivery must not create JSONL"
    );

    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    assert_eq!(summary["delivery"]["posture"], "best_effort_no_replay");
    assert_eq!(summary["delivery"]["status"], "failed");
    let failures = summary["sink_failures"].as_array().expect("sink failures");
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0]["attempts"], 1);
    assert!(!String::from_utf8_lossy(&output.stdout).contains("recoverable"));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("no persistent replay"), "stderr: {stderr}");
    assert!(
        stderr.contains("retries exhausted or not applicable"),
        "stderr: {stderr}"
    );
    assert!(
        stderr.contains("not persisted") && stderr.contains("not recoverable for replay"),
        "stderr: {stderr}"
    );
    assert!(
        !stderr.contains("test-token"),
        "secret leaked in stderr: {stderr}"
    );
}

/// Mock Elasticsearch: accepts requests until shutdown, captures each raw
/// request, and answers every one with a successful bulk response.
fn start_mock_elastic_server() -> (
    String,
    mpsc::Receiver<String>,
    mpsc::Sender<()>,
    thread::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock elastic server");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let addr = listener.local_addr().expect("listener addr");
    let (tx, rx) = mpsc::channel();
    let (shutdown_tx, shutdown_rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        loop {
            match shutdown_rx.try_recv() {
                Ok(()) | Err(mpsc::TryRecvError::Disconnected) => break,
                Err(mpsc::TryRecvError::Empty) => {}
            }
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_nonblocking(false).expect("blocking stream");
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .expect("read timeout");
                    let mut request = Vec::new();
                    let mut buf = [0_u8; 4096];
                    while let Ok(read) = stream.read(&mut buf) {
                        if read == 0 {
                            break;
                        }
                        request.extend_from_slice(&buf[..read]);
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
                    let body = r#"{"took":1,"errors":false,"items":[]}"#;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    stream
                        .write_all(response.as_bytes())
                        .expect("write mock elastic response");
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(_) => break,
            }
        }
    });
    (format!("http://{addr}"), rx, shutdown_tx, handle)
}

#[test]
fn scan_once_ships_events_to_elastic_bulk_sink() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("empty-root");
    fs::create_dir_all(&root).expect("empty root");
    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");
    let (elastic_endpoint, requests, shutdown, handle) = start_mock_elastic_server();

    let config_dir = temp.path().join("conf");
    let outputs_dir = config_dir.join("outputs.d");
    fs::create_dir_all(&outputs_dir).expect("outputs.d");
    fs::write(
        outputs_dir.join("outputs.yaml"),
        format!(
            r#"
version: 1
sinks:
  - name: local
    type: jsonl
  - name: corp-elastic
    type: elastic_bulk
    endpoint: {}
    index: adr-events
    api_key: {{ env: ADR_TEST_ELASTIC_API_KEY }}
"#,
            elastic_endpoint
        ),
    )
    .expect("write outputs yaml");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["scan", "--once", "--root"])
        .arg(&root)
        .args(["--config-dir"])
        .arg(&config_dir)
        .args(["--log-path"])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .arg("--install-inventory-disabled")
        .env("ADR_TEST_ELASTIC_API_KEY", "test-api-key")
        .output()
        .expect("run adr");

    shutdown.send(()).expect("stop mock elastic server");
    handle.join().expect("mock elastic thread");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Local JSONL still receives the events.
    let jsonl_events = fs::read_to_string(&log_path)
        .expect("jsonl log")
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("jsonl event"))
        .collect::<Vec<_>>();
    assert_eq!(jsonl_events.len(), 1);

    // The bulk request pairs an action line with the identical canonical event.
    let request = requests
        .recv_timeout(Duration::from_secs(2))
        .expect("bulk request");
    assert!(request.starts_with("POST /_bulk HTTP/1.1"));
    let lowercase = request.to_lowercase();
    assert!(lowercase.contains("authorization: apikey test-api-key"));
    assert!(lowercase.contains("content-type: application/x-ndjson"));
    let body = request.split_once("\r\n\r\n").expect("body split").1;
    let lines: Vec<&str> = body
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    assert_eq!(lines.len(), 2, "one action/source pair");
    let action: Value = serde_json::from_str(lines[0]).expect("action line");
    let source: Value = serde_json::from_str(lines[1]).expect("source line");
    assert_eq!(action["index"]["_index"], "adr-events");
    assert_eq!(action["index"]["_id"], jsonl_events[0]["event_id"]);
    assert_eq!(source, jsonl_events[0]);
}

#[test]
fn scan_once_fails_fast_on_invalid_outputs_config() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("empty-root");
    fs::create_dir_all(&root).expect("empty root");
    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");

    let config_dir = temp.path().join("conf");
    let outputs_dir = config_dir.join("outputs.d");
    fs::create_dir_all(&outputs_dir).expect("outputs.d");
    fs::write(
        outputs_dir.join("outputs.yaml"),
        "version: 1\nsinks:\n  - name: local\n    type: jsonl\n    pth: /tmp/typo.jsonl\n",
    )
    .expect("write outputs yaml");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["scan", "--once", "--root"])
        .arg(&root)
        .args(["--config-dir"])
        .arg(&config_dir)
        .args(["--log-path"])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .arg("--install-inventory-disabled")
        .output()
        .expect("run adr");

    assert!(!output.status.success(), "typo config must fail fast");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("sink 'local'"), "stderr: {stderr}");
    assert!(!log_path.exists(), "no events written on config error");
}

#[test]
fn config_validate_reports_outputs_block() {
    let temp = tempdir().expect("tempdir");
    let config_dir = temp.path().join("conf");
    let outputs_dir = config_dir.join("outputs.d");
    fs::create_dir_all(&outputs_dir).expect("outputs.d");
    fs::write(
        outputs_dir.join("outputs.yaml"),
        r#"
version: 1
sinks:
  - name: local
    type: jsonl
  - name: corp-splunk
    type: splunk_hec
    enabled: false
    endpoint: http://splunk.example.com:8088
    token: inline-lab-token
"#,
    )
    .expect("write outputs yaml");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["config", "validate", "--config-dir"])
        .arg(&config_dir)
        .output()
        .expect("run adr");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value =
        serde_json::from_slice(&output.stdout).expect("config validate json output");
    assert_eq!(report["local_config"]["discovered_output_count"], 1);
    let sinks = report["outputs"]["sinks"].as_array().expect("sinks");
    assert_eq!(sinks.len(), 2);
    assert_eq!(sinks[0]["name"], "local");
    assert_eq!(sinks[0]["type"], "jsonl");
    assert_eq!(sinks[1]["name"], "corp-splunk");
    assert_eq!(sinks[1]["enabled"], false);
    assert_eq!(
        report["outputs"]["delivery"]["posture"],
        "durable_first_write"
    );
    assert_eq!(report["outputs"]["delivery"]["enabled_sink_count"], 1);
    assert_eq!(report["outputs"]["delivery"]["remote_sink_count"], 0);
    let warnings = report["outputs"]["warnings"].as_array().expect("warnings");
    assert_eq!(warnings.len(), 1);
    assert!(
        warnings[0]
            .as_str()
            .expect("warning text")
            .contains("inline secret")
    );
}

#[test]
fn config_validate_reports_remote_only_delivery_without_rejecting_it() {
    let temp = tempdir().expect("tempdir");
    let config_dir = temp.path().join("conf");
    let outputs_dir = config_dir.join("outputs.d");
    fs::create_dir_all(&outputs_dir).expect("outputs.d");
    fs::write(
        outputs_dir.join("outputs.yaml"),
        r#"
version: 1
sinks:
  - name: remote-only
    type: splunk_hec
    endpoint: https://splunk.example.com:8088/services/collector
    token: inline-lab-token
"#,
    )
    .expect("write outputs yaml");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["config", "validate", "--config-dir"])
        .arg(&config_dir)
        .output()
        .expect("run adr");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "unexpected validation warning: {:?}",
        output.stderr
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("config validate json");
    assert_eq!(
        report["outputs"]["delivery"]["posture"],
        "best_effort_no_replay"
    );
    assert_eq!(report["outputs"]["delivery"]["enabled_sink_count"], 1);
    assert_eq!(report["outputs"]["delivery"]["durable_sink_count"], 0);
    assert_eq!(report["outputs"]["delivery"]["remote_sink_count"], 1);
    assert_eq!(
        report["outputs"]["delivery"]["built_in_persistent_replay"],
        false
    );
    let warnings = report["outputs"]["warnings"].as_array().expect("warnings");
    assert!(warnings.iter().any(|warning| {
        warning
            .as_str()
            .is_some_and(|warning| warning.contains("no persistent replay"))
    }));
}

#[test]
fn config_validate_rejects_missing_enabled_sink_secret() {
    let temp = tempdir().expect("tempdir");
    let config_dir = temp.path().join("conf");
    let outputs_dir = config_dir.join("outputs.d");
    fs::create_dir_all(&outputs_dir).expect("outputs.d");
    fs::write(
        outputs_dir.join("outputs.yaml"),
        r#"
version: 1
sinks:
  - name: remote-only
    type: splunk_hec
    endpoint: https://splunk.example.com:8088/services/collector
    token: { env: ADR_TEST_MISSING_VALIDATE_TOKEN }
"#,
    )
    .expect("write outputs yaml");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["config", "validate", "--config-dir"])
        .arg(&config_dir)
        .env_remove("ADR_TEST_MISSING_VALIDATE_TOKEN")
        .output()
        .expect("run adr");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("ADR_TEST_MISSING_VALIDATE_TOKEN"),
        "stderr: {stderr}"
    );
    assert!(!stderr.contains("test-token"), "secret leaked: {stderr}");
}
