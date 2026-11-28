use super::*;

#[test]
fn defaults_are_valid_and_detect_only() {
    let config = Config::default();
    config.validate().unwrap();
    assert_eq!(config.mode, Mode::Observe);
    assert_eq!(config.on_error, OnError::Allow);
    assert_eq!(config.thresholds.action_deny, 90);
    assert!(config.rules.self_protection);
    assert!(!config.rules.tamper_prevention);
    assert!(!config.rules.test_signatures);
    // Pipelines that do not carry the self-protection rules or the test
    // signatures leave out override entries for them by these prefixes.
    assert_eq!(
        crate::rule_resolution::HOOKS_RULE_PREFIXES,
        [HOST_RULE_ID_PREFIX, TEST_RULE_ID_PREFIX]
    );
    assert!(config.rules.process_chain);
}

/// Grants need the self-protection rules: they keep a tool call from
/// writing the session state or raising a prompt of its own.
#[test]
fn grants_without_the_self_protection_rules_are_invalid() {
    let mut config = Config::default();
    config.grants.enabled = true;
    config.validate().unwrap();
    config.rules.self_protection = false;
    let error = config.validate().unwrap_err().to_string();
    assert!(
        error.contains("hooks.grants.enabled needs hooks.self_protection_rules"),
        "{error}"
    );
    config.grants.enabled = false;
    config.validate().unwrap();
}

#[test]
fn rejects_inverted_thresholds() {
    let mut config = Config::default();
    config.thresholds.action_ask = 95;
    assert!(config.validate().is_err());
    let mut config = Config::default();
    config.thresholds.session_ask = config.thresholds.session_deny + 1;
    assert!(config.validate().is_err());
    let mut config = Config::default();
    config.window.max_records = 0;
    assert!(config.validate().is_err());
}

#[test]
fn fingerprint_tracks_configuration_and_rule_content() {
    let dir = tempfile::tempdir().unwrap();
    let rules = dir.path().join("r.yaml");
    std::fs::write(&rules, "a").unwrap();
    let mut config = Config {
        state_dir: Some(dir.path().to_owned()),
        ..Config::default()
    };
    config.rules.packs.deployment = vec![rules.clone()];
    let first = config.fingerprint();
    assert_eq!(first, config.fingerprint());
    std::fs::write(&rules, "b").unwrap();
    let second = config.fingerprint();
    assert_ne!(first, second, "rule content change");
    config.thresholds.action_deny = 95;
    assert_ne!(second, config.fingerprint(), "policy change");
    let third = config.fingerprint();
    config.grants.enabled = true;
    assert_ne!(third, config.fingerprint(), "grants change");
    let fourth = config.fingerprint();
    config.grants.covers = GrantCover::Ask;
    assert_ne!(fourth, config.fingerprint(), "grant cover change");
    let fifth = config.fingerprint();
    config
        .grants
        .always
        .push(crate::hooks::grants::AlwaysGrant {
            id: "g-000000000001".into(),
            version: 1,
            scope: crate::hooks::grants::AlwaysScope::User,
            project: None,
            harness: "claude-code".into(),
            tool: "Bash".into(),
            rule_ids: vec!["r".into()],
            created_at: "2026-11-22T00:00:00Z".into(),
            from_record: "tth:1".into(),
        });
    assert_ne!(fifth, config.fingerprint(), "an always grant added");
    config.grants.always.clear();
    assert_eq!(fifth, config.fingerprint(), "the always grant removed");
}

#[test]
fn long_state_dirs_get_a_short_socket_path() {
    let mut config = Config {
        state_dir: Some(PathBuf::from("/s")),
        ..Config::default()
    };
    assert_eq!(
        config.resolved_socket_path().unwrap(),
        PathBuf::from("/s/evaluator.sock")
    );
    config.state_dir = Some(PathBuf::from(format!("/{}", "d".repeat(120))));
    let socket = config.resolved_socket_path().unwrap();
    let length = socket.as_os_str().len();
    assert!(
        length <= MAX_SOCKET_PATH_BYTES,
        "socket path of {length} bytes"
    );
    assert!(
        socket
            .to_string_lossy()
            .contains(&format!("telltale-hooks-{}", current_uid()))
    );
}

#[test]
fn relative_paths_become_absolute() {
    let mut config = Config {
        state_dir: Some(PathBuf::from("rel/state")),
        ..Config::default()
    };
    config.rules.packs.deployment = vec![PathBuf::from("r.yaml")];
    config.sources = vec![PathBuf::from("settings.d")];
    config.make_paths_absolute();
    assert!(config.state_dir.as_ref().unwrap().is_absolute());
    assert!(config.rules.packs.deployment[0].is_absolute());
    assert!(config.sources[0].is_absolute());
}

#[test]
fn fingerprint_names_the_build_and_its_paths() {
    let a = Config {
        state_dir: Some(PathBuf::from("/a")),
        ..Config::default()
    };
    let b = Config {
        state_dir: Some(PathBuf::from("/a")),
        evaluator: EvaluatorSettings {
            socket: Some(PathBuf::from("/elsewhere.sock")),
            ..EvaluatorSettings::default()
        },
        ..Config::default()
    };
    assert_ne!(a.fingerprint(), b.fingerprint());
    let c = Config {
        state_dir: Some(PathBuf::from("/a")),
        sources: vec![PathBuf::from("/etc/telltale")],
        ..Config::default()
    };
    assert_ne!(a.fingerprint(), c.fingerprint(), "config folders");
}

#[test]
fn configuration_sources_and_rule_files_are_protected() {
    let mut config = Config {
        state_dir: Some(PathBuf::from("/state")),
        sources: vec![PathBuf::from("/etc/telltale")],
        ..Config::default()
    };
    config.rules.policy = Some(PathBuf::from("/etc/telltale/policies.d/p.yaml"));
    let protected = config.protected_paths();
    assert!(protected.contains(&PathBuf::from("/state")));
    assert!(protected.contains(&PathBuf::from("/etc/telltale")));
    assert!(protected.contains(&PathBuf::from("/etc/telltale/policies.d/p.yaml")));
}

/// The names a pin replaced describe one invocation's launch, not the
/// configuration: they do not key the evaluator.
#[test]
fn fingerprint_ignores_the_sources_a_pin_replaced() {
    let plain = Config::default();
    let pinned = Config {
        pinned_over: vec!["TELLTALE_HOOKS_STATE_DIR".into()],
        ..Config::default()
    };
    assert_eq!(plain.fingerprint(), pinned.fingerprint());
}

#[test]
fn modes_parse_with_two_detect_only_spellings() {
    for spelling in ["observe", "detect"] {
        let mode: Mode = serde_json::from_value(serde_json::json!(spelling)).unwrap();
        assert_eq!(mode, Mode::Observe, "{spelling}");
    }
    let mode: Mode = serde_json::from_value(serde_json::json!("enforce")).unwrap();
    assert_eq!(mode, Mode::Enforce);
    assert!(serde_json::from_value::<Mode>(serde_json::json!("block")).is_err());
}
