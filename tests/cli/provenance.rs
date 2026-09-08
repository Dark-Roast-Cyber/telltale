use super::*;

#[test]
fn config_provenance_is_deterministic_and_validates_as_public_manifest() {
    let first = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["config", "provenance", "--no-local-config"])
        .output()
        .expect("run provenance command");
    let second = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["config", "provenance", "--no-local-config"])
        .output()
        .expect("run provenance command");

    assert!(first.status.success(), "stderr: {:?}", first.stderr);
    assert!(second.status.success(), "stderr: {:?}", second.stderr);
    assert_eq!(first.stdout, second.stdout);
    let manifest =
        telltale_schema::provenance::ProducerProvenanceManifestV1::from_json_bytes(&first.stdout)
            .expect("public manifest");
    assert_eq!(manifest.rules.rule_count, 18);
    assert_eq!(
        manifest.suppression.state,
        telltale_schema::provenance::ProducerSuppressionState::None
    );
    assert!(first.stderr.is_empty());
}

#[test]
fn config_provenance_uses_effective_rule_policy_and_allowlist_inputs() {
    let temp = tempdir().expect("tempdir");
    let rules = temp.path().join("rules.yaml");
    let policy = temp.path().join("policy.yaml");
    let allowlist = temp.path().join("allowlist.yaml");
    let criterion_marker = "TT_PRIVACY_CLI_SUPPRESSION_CRITERION_39";
    fs::write(
        &rules,
        "version: 1\ndescription: synthetic\ndefaults:\n  case_insensitive: false\n  enabled: true\nrules:\n  - id: rule.synthetic\n    category: execution\n    severity: low\n    score: 20\n    targets: [command]\n    regex: synthetic-command\n    tags: [synthetic]\n    explanation: synthetic explanation\nmodifiers: []\n",
    )
    .expect("rules");
    fs::write(
        &policy,
        "version: 1\nname: policy.synthetic\nenabled_rules: [rule.synthetic]\n",
    )
    .expect("policy");
    fs::write(
        &allowlist,
        format!(
            "version: 1\nsuppressions:\n  - name: synthetic-suppression\n    categories: [{criterion_marker}]\n"
        ),
    )
    .expect("allowlist");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args([
            "config",
            "provenance",
            "--no-local-config",
            "--no-default-rules",
            "--emit-activity",
            "--emit-session-risk-summary",
            "--baseline-deviation-scoring",
            "--install-inventory-disabled",
            "--rules",
        ])
        .arg(&rules)
        .args(["--policy"])
        .arg(&policy)
        .args(["--allowlist"])
        .arg(&allowlist)
        .output()
        .expect("run provenance command");

    assert!(output.status.success(), "stderr: {:?}", output.stderr);
    let text = String::from_utf8(output.stdout.clone()).expect("UTF-8 manifest");
    assert!(!text.contains(criterion_marker));
    let value: Value = serde_json::from_slice(&output.stdout).expect("manifest JSON");
    assert_eq!(value["rules"]["rule_count"], 1);
    assert_eq!(
        value["rules"]["active_policy_name"],
        opaque_identifier("policy", "policy.synthetic")
    );
    assert_eq!(
        value["suppression"]["canonicalization"],
        "suppression-v1-effective-v1"
    );
    assert_eq!(value["suppression"]["state"], "configured");
    assert!(value["suppression"].get("names").is_none());
    assert_eq!(value["features"]["emit_activity"], true);
    assert_eq!(value["features"]["emit_session_risk_summary"], true);
    assert_eq!(value["features"]["baseline_deviation_scoring"], true);
    assert_eq!(value["features"]["install_inventory"], false);
    assert!(value["features"]["install_inventory_interval_seconds"].is_null());
    let manifest =
        telltale_schema::provenance::ProducerProvenanceManifestV1::from_json_bytes(&output.stdout)
            .expect("valid manifest");
    assert_eq!(manifest.suppression.count, 1);
}

#[test]
fn config_provenance_errors_are_private_and_do_not_write_files() {
    let temp = tempdir().expect("tempdir");
    let allowlist = temp.path().join("allowlist.yaml");
    let marker = "TT_PRIVACY_CLI_ERROR_39";
    fs::write(&allowlist, format!("suppressions: [\"{marker}")).expect("malformed allowlist");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args(["config", "provenance", "--no-local-config", "--allowlist"])
        .arg(&allowlist)
        .output()
        .expect("run provenance command");

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains(marker));
    assert!(!temp.path().join("telltale-events.jsonl").exists());
}

#[test]
fn config_provenance_rejects_invalid_inventory_interval_privately() {
    let marker = "-tt_privacy_invalid_interval_username.example.invalid/session-39";
    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args([
            "config",
            "provenance",
            "--no-local-config",
            "--install-inventory-interval-seconds",
            marker,
        ])
        .output()
        .expect("run provenance command");

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains(marker));
}

#[test]
fn config_provenance_opaque_labels_hide_lowercase_identity_like_values() {
    let temp = tempdir().expect("tempdir");
    let rules = temp.path().join("rules.yaml");
    let policy = temp.path().join("policy.yaml");
    let allowlist = temp.path().join("allowlist.yaml");
    let username = "tt_privacy_username_39";
    let domain = "tt-privacy-domain-39.example.invalid";
    let session = "tt-privacy-session-39";
    fs::write(
        &rules,
        "version: 1\ndescription: synthetic\ndefaults:\n  case_insensitive: false\n  enabled: true\nrules:\n  - id: rule.synthetic\n    category: execution\n    severity: low\n    score: 20\n    targets: [command]\n    regex: synthetic-command\n    tags: [synthetic]\n    explanation: synthetic explanation\nmodifiers: []\n",
    )
    .expect("rules");
    fs::write(
        &policy,
        format!("version: 1\nname: '{username}@{domain}/{session}'\n"),
    )
    .expect("policy");
    fs::write(
        &allowlist,
        format!("version: 1\nsuppressions:\n  - name: '{session}'\n    categories: [synthetic]\n"),
    )
    .expect("allowlist");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args([
            "config",
            "provenance",
            "--no-local-config",
            "--no-default-rules",
            "--rules",
        ])
        .arg(&rules)
        .args(["--policy"])
        .arg(&policy)
        .args(["--allowlist"])
        .arg(&allowlist)
        .output()
        .expect("run provenance command");

    assert!(output.status.success(), "stderr: {:?}", output.stderr);
    let rendered = String::from_utf8_lossy(&output.stdout);
    for marker in [username, domain, session] {
        assert!(!rendered.contains(marker));
    }
    assert!(!String::from_utf8_lossy(&output.stderr).contains(username));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(domain));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(session));
}

#[test]
fn config_provenance_matches_the_public_core_assembly() {
    let temp = tempdir().expect("tempdir");
    let rules = temp.path().join("rules.yaml");
    let policy = temp.path().join("policy.yaml");
    let allowlist = temp.path().join("allowlist.yaml");
    let rules_document = "version: 1\ndescription: synthetic\ndefaults:\n  case_insensitive: false\n  enabled: true\nrules:\n  - id: rule.synthetic\n    category: execution\n    severity: low\n    score: 20\n    targets: [command]\n    regex: synthetic-command\n    tags: [synthetic]\n    explanation: synthetic explanation\nmodifiers: []\n";
    let policy_document = "version: 1\nname: policy.synthetic\nenabled_rules: [rule.synthetic]\n";
    let allowlist_document =
        "version: 1\nsuppressions:\n  - name: synthetic-suppression\n    categories: [synthetic]\n";
    fs::write(&rules, rules_document).expect("rules");
    fs::write(&policy, policy_document).expect("policy");
    fs::write(&allowlist, allowlist_document).expect("allowlist");

    let pipeline = telltale_core::Pipeline::builder()
        .without_bundled_defaults()
        .rules_document(rules_document)
        .policy_document(policy_document)
        .build()
        .expect("pipeline");
    let options = telltale_core::ProducerProvenanceOptions {
        allowlist_document: Some(allowlist_document.to_string()),
        ..Default::default()
    };
    let api = pipeline
        .producer_provenance_manifest(&options)
        .expect("API manifest")
        .to_json_bytes()
        .expect("API JSON");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args([
            "config",
            "provenance",
            "--no-local-config",
            "--no-default-rules",
            "--rules",
        ])
        .arg(&rules)
        .args(["--policy"])
        .arg(&policy)
        .args(["--allowlist"])
        .arg(&allowlist)
        .output()
        .expect("run provenance command");
    assert!(output.status.success(), "stderr: {:?}", output.stderr);
    assert_eq!(output.stdout.strip_suffix(b"\n").unwrap(), api.as_slice());
}

#[test]
fn config_provenance_invalid_rule_errors_are_private() {
    let temp = tempdir().expect("tempdir");
    let rules = temp.path().join("rules.yaml");
    let marker = "TT_PRIVACY_CLI_RULE_ERROR_39";
    fs::write(&rules, format!("description: '{marker}\n")).expect("malformed rules");

    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args([
            "config",
            "provenance",
            "--no-local-config",
            "--no-default-rules",
            "--rules",
        ])
        .arg(&rules)
        .output()
        .expect("run provenance command");
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains(marker));
}
