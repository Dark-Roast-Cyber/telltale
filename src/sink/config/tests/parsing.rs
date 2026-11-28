use super::*;

#[test]
fn parses_full_outputs_document() {
    let temp = tempdir().expect("tempdir");
    let path = write_outputs(
        temp.path(),
        "outputs.yaml",
        r#"
version: 1
sinks:
  - name: local
    type: jsonl
    path: /var/log/telltale/telltale-events.jsonl
    rotation:
      max_size_bytes: 1048576
      keep: 3
  - name: corp-splunk
    type: splunk_hec
    endpoint: http://splunk.example.com:8088/services/collector
    token: { env: SPLUNK_HEC_TOKEN }
    index: telltale
    sourcetype: telltale:json
    timeout_ms: 5000
  - name: disabled-splunk
    type: splunk_hec
    enabled: false
    endpoint: http://other.example.com:8088
    token: inline-lab-token
"#,
    );

    let specs = load_outputs_config(&[path]).expect("load outputs");

    assert_eq!(specs.len(), 3);
    assert_eq!(specs[0].name, "local");
    assert!(specs[0].enabled);
    assert!(matches!(specs[0].kind, SinkKind::Jsonl(_)));
    assert_eq!(specs[1].name, "corp-splunk");
    let SinkKind::SplunkHec(hec) = &specs[1].kind else {
        panic!("expected splunk_hec kind");
    };
    assert!(matches!(&hec.token, SecretValue::Env { env } if env == "SPLUNK_HEC_TOKEN"));
    assert_eq!(hec.timeout_ms, Some(5000));
    assert!(!specs[2].enabled);
    assert!(specs[2].has_inline_secret());
    assert!(!specs[1].has_inline_secret());
}

#[test]
fn merge_is_last_wins_per_sink_name() {
    let temp = tempdir().expect("tempdir");
    let system = write_outputs(
        temp.path(),
        "50-system.yaml",
        r#"
version: 1
sinks:
  - name: corp-splunk
    type: splunk_hec
    endpoint: http://splunk.example.com:8088
    token: system-token
  - name: local
    type: jsonl
"#,
    );
    let user = write_outputs(
        temp.path(),
        "60-user.yaml",
        r#"
version: 1
sinks:
  - name: corp-splunk
    type: splunk_hec
    enabled: false
    endpoint: http://splunk.example.com:8088
    token: user-token
  - name: extra-jsonl
    type: jsonl
    path: /tmp/extra.jsonl
"#,
    );

    let specs = load_outputs_config(&[system, user]).expect("load outputs");

    // First-seen order, later definition replaces the earlier one.
    assert_eq!(
        specs.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(),
        vec!["corp-splunk", "local", "extra-jsonl"]
    );
    assert!(!specs[0].enabled, "user file disabled corp-splunk");
}

#[test]
fn duplicate_sink_name_in_one_file_is_an_error() {
    let temp = tempdir().expect("tempdir");
    let path = write_outputs(
        temp.path(),
        "outputs.yaml",
        r#"
version: 1
sinks:
  - name: local
    type: jsonl
  - name: local
    type: jsonl
"#,
    );

    let err = load_outputs_config(&[path]).expect_err("duplicate names");
    assert!(err.to_string().contains("duplicate sink name 'local'"));
}

#[test]
fn unknown_sink_type_is_an_error() {
    let temp = tempdir().expect("tempdir");
    let path = write_outputs(
        temp.path(),
        "outputs.yaml",
        "version: 1\nsinks:\n  - name: sys\n    type: syslog\n    endpoint: udp://x\n",
    );

    let err = load_outputs_config(&[path]).expect_err("unknown type");
    assert!(err.to_string().contains("unknown sink type 'syslog'"));
}

#[test]
fn elastic_bulk_spec_parses_and_flags_inline_secrets() {
    let temp = tempdir().expect("tempdir");
    let path = write_outputs(
        temp.path(),
        "outputs.yaml",
        r#"
version: 1
sinks:
  - name: corp-elastic
    type: elastic_bulk
    endpoint: https://elastic.example.com:9243
    index: telltale-events
    api_key: inline-key
    max_batch_bytes: 1048576
    retry: { max_attempts: 5, base_delay_ms: 250 }
    tls: { insecure_skip_verify: true }
"#,
    );

    let specs = load_outputs_config(&[path]).expect("load outputs");
    assert_eq!(specs.len(), 1);
    assert_eq!(specs[0].kind.type_name(), "elastic_bulk");
    assert!(specs[0].has_inline_secret());
    assert!(specs[0].has_insecure_tls());
}

#[test]
fn elastic_bulk_rejects_conflicting_auth() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("telltale-events.jsonl");
    let path = write_outputs(
        temp.path(),
        "outputs.yaml",
        r#"
version: 1
sinks:
  - name: corp-elastic
    type: elastic_bulk
    endpoint: https://elastic.example.com:9200
    api_key: key
    username: user
    password: pass
"#,
    );
    let specs = load_outputs_config(&[path]).expect("load");

    let err = match build_sink_set(&specs, &cli_defaults(&log_path)) {
        Ok(_) => panic!("conflicting auth must error"),
        Err(err) => err,
    };
    assert!(
        err.to_string()
            .contains("either api_key or username/password")
    );
}

#[test]
fn unknown_field_is_an_error() {
    let temp = tempdir().expect("tempdir");
    let path = write_outputs(
        temp.path(),
        "outputs.yaml",
        "version: 1\nsinks:\n  - name: local\n    type: jsonl\n    pth: /tmp/x.jsonl\n",
    );

    let err = load_outputs_config(&[path]).expect_err("unknown field");
    let message = err.to_string();
    assert!(message.contains("sink 'local'"), "message: {message}");
    assert!(message.contains("pth"), "message: {message}");
}

#[test]
fn unsupported_version_is_an_error() {
    let temp = tempdir().expect("tempdir");
    let path = write_outputs(temp.path(), "outputs.yaml", "version: 2\nsinks: []\n");

    let err = load_outputs_config(&[path]).expect_err("bad version");
    assert!(err.to_string().contains("version 2 is not supported"));
}
