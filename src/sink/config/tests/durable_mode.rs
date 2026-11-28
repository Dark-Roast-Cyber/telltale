use super::*;

#[test]
fn simulated_windows_durable_config_is_rejected_before_outbox_initialization() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("events.jsonl");
    let outbox_path = temp.path().join("private").join("outbox.sqlite");
    let path = write_outputs(
        temp.path(),
        "durable-windows.yaml",
        &format!(
            "version: 1\ndelivery:\n  policy: durable\n  outbox_path: {}\nsinks:\n  - name: canonical\n    type: jsonl\n",
            outbox_path.display()
        ),
    );
    let loaded = load_outputs_config_with_delivery(&[path]).expect("load durable config");

    let error = match build_sink_set_with_presence_and_delivery_for_platform(
        &loaded.sinks,
        true,
        &CliSinkOverrides {
            log_path: &log_path,
            rotation: RotationConfig::disabled(),
            splunk_hec_endpoint: None,
            splunk_hec_token: None,
        },
        &loaded.delivery,
        false,
        true,
    ) {
        Ok(_) => panic!("Windows durable config must be rejected"),
        Err(error) => error,
    };
    let delivery = error
        .downcast_ref::<DeliveryError>()
        .expect("platform rejection must be structured");
    assert_eq!(delivery.class, DeliveryErrorClass::DurableStorage);
    assert!(
        error
            .to_string()
            .contains(crate::sink::outbox::WINDOWS_DURABLE_STORAGE_UNSUPPORTED)
    );
    assert!(!outbox_path.parent().expect("outbox parent").exists());
    assert!(!outbox_path.exists());
    assert!(!log_path.exists());
}

#[test]
fn simulated_windows_best_effort_configuration_remains_valid() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("best-effort.jsonl");
    let sinks = build_sink_set_with_presence_and_delivery_for_platform(
        &[],
        false,
        &cli_defaults(&log_path),
        &DeliveryConfig::default(),
        false,
        true,
    )
    .expect("Windows best-effort configuration");
    assert!(sinks.has_canonical_first_write());
    assert!(!sinks.has_persistent_replay());
}

#[cfg(not(windows))]
#[test]
fn durable_mode_requires_canonical_jsonl_and_private_outbox() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("events.jsonl");
    let outbox_path = temp.path().join("private").join("outbox.sqlite");
    let path = write_outputs(
        temp.path(),
        "durable.yaml",
        &format!(
            "version: 1\ndelivery:\n  policy: durable\n  outbox_path: {}\nsinks:\n  - name: canonical\n    type: jsonl\n  - name: remote-a\n    type: splunk_hec\n    endpoint: https://collector.example.invalid/collector\n    token: {{ env: TELLTALE_TEST_DURABLE_TOKEN }}\n",
            outbox_path.display()
        ),
    );
    let loaded = load_outputs_config_with_delivery(&[path]).expect("load durable config");
    // SAFETY: test-only env mutation; key is unique to this test.
    unsafe { std::env::set_var("TELLTALE_TEST_DURABLE_TOKEN", "synthetic-token") };
    let sinks = super::super::build_sink_set_with_presence_and_delivery(
        &loaded.sinks,
        true,
        &CliSinkOverrides {
            log_path: &log_path,
            rotation: RotationConfig::disabled(),
            splunk_hec_endpoint: None,
            splunk_hec_token: None,
        },
        &loaded.delivery,
        false,
    )
    .expect("durable config");
    unsafe { std::env::remove_var("TELLTALE_TEST_DURABLE_TOKEN") };

    assert!(sinks.has_persistent_replay());
    assert!(sinks.durable_sink_ids.contains(&"remote-a".to_string()));
    assert!(outbox_path.is_file());
    assert_eq!(
        sinks.delivery_posture(),
        crate::sink::DeliveryPosture::DurableFirstWrite
    );
}

#[cfg(not(windows))]
#[test]
fn durable_mode_without_jsonl_is_rejected_without_forcing_a_local_sink() {
    let temp = tempdir().expect("tempdir");
    let outbox_path = temp.path().join("private").join("outbox.sqlite");
    let path = write_outputs(
        temp.path(),
        "durable-remote-only.yaml",
        &format!(
            "version: 1\ndelivery:\n  policy: durable\n  outbox_path: {}\nsinks:\n  - name: remote-a\n    type: splunk_hec\n    endpoint: https://collector.example.invalid/collector\n    token: synthetic-token\n",
            outbox_path.display()
        ),
    );
    let loaded = load_outputs_config_with_delivery(&[path]).expect("load durable config");
    let result = super::super::build_sink_set_with_presence_and_delivery(
        &loaded.sinks,
        true,
        &CliSinkOverrides {
            log_path: temp.path().join("events.jsonl").as_path(),
            rotation: RotationConfig::disabled(),
            splunk_hec_endpoint: None,
            splunk_hec_token: None,
        },
        &loaded.delivery,
        false,
    );
    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("durable remote-only config must fail"),
    };
    assert!(error.to_string().contains("requires canonical JSONL"));
}

#[cfg(not(windows))]
#[test]
fn durable_mode_retains_existing_tls_validation() {
    let temp = tempdir().expect("tempdir");
    let outbox_path = temp.path().join("private").join("outbox.sqlite");
    let path = write_outputs(
        temp.path(),
        "durable-invalid-tls.yaml",
        &format!(
            "version: 1\ndelivery:\n  policy: durable\n  outbox_path: {}\nsinks:\n  - name: canonical\n    type: jsonl\n  - name: remote-a\n    type: splunk_hec\n    endpoint: https://collector.example.invalid/collector\n    token: synthetic-token\n    tls:\n      ca_file: {}/missing-ca.pem\n",
            outbox_path.display(),
            temp.path().display()
        ),
    );
    let loaded = load_outputs_config_with_delivery(&[path]).expect("load durable config");
    let log_path = temp.path().join("events.jsonl");
    let result = super::super::build_sink_set_with_presence_and_delivery(
        &loaded.sinks,
        true,
        &CliSinkOverrides {
            log_path: &log_path,
            rotation: RotationConfig::disabled(),
            splunk_hec_endpoint: None,
            splunk_hec_token: None,
        },
        &loaded.delivery,
        false,
    );
    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("missing TLS CA must fail in durable mode"),
    };
    assert!(error.to_string().contains("ca_file"));
}

#[cfg(not(windows))]
#[test]
fn durable_capacity_defaults_and_yaml_overrides_are_loaded() {
    let temp = tempdir().expect("tempdir");
    let default_path = write_outputs(
        temp.path(),
        "default.yaml",
        &format!(
            "version: 1\ndelivery:\n  policy: durable\n  outbox_path: {}/outbox.sqlite\nsinks: []\n",
            temp.path().display()
        ),
    );
    let defaults = load_outputs_config_with_delivery(&[default_path])
        .expect("default durable config")
        .delivery;
    assert_eq!(defaults.policy, ConfigDeliveryPolicy::Durable);
    assert_eq!(
        defaults.capacity_limits,
        CapacityLimits {
            max_pending_events: DEFAULT_MAX_PENDING_EVENTS,
            max_pending_bytes: DEFAULT_MAX_PENDING_BYTES,
        }
    );

    let override_path = write_outputs(
        temp.path(),
        "override.yaml",
        &format!(
            "version: 1\ndelivery:\n  policy: durable\n  outbox_path: {}/outbox.sqlite\n  max_pending_events: 7\n  max_pending_bytes: 4096\nsinks: []\n",
            temp.path().display()
        ),
    );
    let overrides = load_outputs_config_with_delivery(&[override_path])
        .expect("overridden durable config")
        .delivery;
    assert_eq!(
        overrides.capacity_limits,
        CapacityLimits {
            max_pending_events: 7,
            max_pending_bytes: 4096,
        }
    );
}

#[test]
fn zero_capacity_and_best_effort_capacity_fields_are_rejected() {
    let temp = tempdir().expect("tempdir");
    for field in ["max_pending_events", "max_pending_bytes"] {
        let path = write_outputs(
            temp.path(),
            &format!("zero-{field}.yaml"),
            &format!(
                "version: 1\ndelivery:\n  policy: durable\n  outbox_path: {}/outbox.sqlite\n  {field}: 0\nsinks: []\n",
                temp.path().display()
            ),
        );
        let error = match load_outputs_config_with_delivery(&[path]) {
            Ok(_) => panic!("zero durable capacity must be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("must be greater than zero"));
    }

    let path = write_outputs(
        temp.path(),
        "best-effort-capacity.yaml",
        "version: 1\ndelivery:\n  policy: best_effort\n  max_pending_events: 1\nsinks: []\n",
    );
    let error = match load_outputs_config_with_delivery(&[path]) {
        Ok(_) => panic!("best-effort capacity fields must be rejected"),
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("best-effort delivery cannot configure durable capacity limits")
    );
}
