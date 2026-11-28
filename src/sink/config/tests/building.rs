use super::*;

#[test]
fn debug_redacts_inline_secrets_directly_and_when_nested() {
    let secret = "sentinel-inline-secret";
    let direct = format!("{:?}", SecretValue::Inline(secret.to_string()));
    assert!(!direct.contains(secret));

    let dir = tempdir().expect("tempdir");
    let path = write_outputs(
        dir.path(),
        "outputs.yaml",
        &format!(
            "version: 1\nsinks:\n  - name: splunk\n    type: splunk_hec\n    endpoint: http://127.0.0.1:8088\n    token: {secret}\n  - name: elastic\n    type: elastic_bulk\n    endpoint: http://127.0.0.1:9200\n    api_key: {secret}\n"
        ),
    );
    let specs = load_outputs_config(&[path]).expect("outputs");
    let nested = format!("{specs:?}");
    assert!(!nested.contains(secret));
}

#[test]
fn secret_resolution_covers_inline_env_and_file() {
    let inline = SecretValue::Inline("inline-token".to_string());
    assert_eq!(inline.resolve("test").expect("inline"), "inline-token");

    // SAFETY: test-only env mutation; key is unique to this test.
    unsafe { std::env::set_var("TELLTALE_TEST_SINK_SECRET", "env-token") };
    let env = SecretValue::Env {
        env: "TELLTALE_TEST_SINK_SECRET".to_string(),
    };
    assert_eq!(env.resolve("test").expect("env"), "env-token");
    unsafe { std::env::remove_var("TELLTALE_TEST_SINK_SECRET") };
    assert!(env.resolve("test").is_err(), "unset env must error");

    let temp = tempdir().expect("tempdir");
    let secret_path = temp.path().join("hec-token");
    std::fs::write(&secret_path, "file-token\n").expect("write secret");
    let file = SecretValue::File {
        file: secret_path.clone(),
    };
    // Trailing newline is trimmed.
    assert_eq!(file.resolve("test").expect("file"), "file-token");

    let missing = SecretValue::File {
        file: temp.path().join("missing"),
    };
    assert!(missing.resolve("test").is_err(), "missing file must error");
}

#[test]
fn empty_specs_reproduce_legacy_default_sinks() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("telltale-events.jsonl");

    let sinks = build_sink_set(&[], &cli_defaults(&log_path)).expect("build");
    assert!(sinks.has_canonical_first_write());

    let mut cli = cli_defaults(&log_path);
    cli.splunk_hec_endpoint = Some("http://127.0.0.1:8088");
    let err = match build_sink_set(&[], &cli) {
        Ok(_) => panic!("endpoint without token must error"),
        Err(err) => err,
    };
    assert!(
        err.to_string()
            .contains("--splunk-hec-endpoint and --splunk-hec-token must be set together")
    );
}

#[test]
fn build_resolves_env_secret_and_honors_disabled_sinks() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("telltale-events.jsonl");
    let path = write_outputs(
        temp.path(),
        "outputs.yaml",
        r#"
version: 1
sinks:
  - name: local
    type: jsonl
  - name: corp-splunk
    type: splunk_hec
    enabled: false
    endpoint: https://splunk.example.com:8088
    token: { env: TELLTALE_TEST_UNSET_TOKEN_VAR }
"#,
    );
    let specs = load_outputs_config(&[path]).expect("load");

    // The disabled sink's secret must not be resolved: no error.
    let sinks = build_sink_set(&specs, &cli_defaults(&log_path)).expect("build");
    assert!(sinks.has_canonical_first_write());
}

#[test]
fn build_fails_fast_on_missing_env_secret_for_enabled_sink() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("telltale-events.jsonl");
    let path = write_outputs(
        temp.path(),
        "outputs.yaml",
        r#"
version: 1
sinks:
  - name: corp-splunk
    type: splunk_hec
    endpoint: https://splunk.example.com:8088
    token: { env: TELLTALE_TEST_UNSET_TOKEN_VAR }
"#,
    );
    let specs = load_outputs_config(&[path]).expect("load");

    let err = match build_sink_set(&specs, &cli_defaults(&log_path)) {
        Ok(_) => panic!("missing env secret must error"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("TELLTALE_TEST_UNSET_TOKEN_VAR"));
}
