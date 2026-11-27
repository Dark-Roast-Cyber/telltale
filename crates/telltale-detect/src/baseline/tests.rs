use super::*;
use telltale_schema::activity_facts::classify_path_token;

fn summary() -> BaselineSummary {
    BaselineSummary {
        key: BaselineKey {
            client: "codex".into(),
            agent: Some("agent".into()),
            model: Some("model".into()),
            provider: Some("provider".into()),
        },
        ..BaselineSummary::default()
    }
}

#[test]
fn only_exact_lowercase_host_hashes_bypass_normalization() {
    let canonical = format!("sha256:{}", "a".repeat(64));
    assert_eq!(baseline_host_identity(&canonical), canonical);
    assert_ne!(baseline_host_identity("sha256:ABC"), "sha256:ABC");
    assert_ne!(
        baseline_host_identity(&format!("sha256:{}", "A".repeat(64))),
        format!("sha256:{}", "A".repeat(64))
    );
}

#[test]
fn baseline_deviation_scoring_is_bounded_and_opt_in() {
    let mut previous = summary();
    previous.observations.tool_calls = 6;
    previous.tool_call_counts.insert("read_file".into(), 6);
    previous.path_class_counts.insert(PathClass::Source, 6);
    let mut current = summary();
    current.observations.tool_calls = 1;
    current.tool_call_counts.insert("shell".into(), 1);
    current.path_class_counts.insert(PathClass::Temp, 1);
    current
        .network_host_counts
        .insert("new.example.test".into(), 1);

    assert_eq!(
        assess_baseline_deviation(
            Some(&previous),
            &current,
            BaselineDeviationConfig::default()
        )
        .unwrap(),
        None
    );
    let deviation = assess_baseline_deviation(
        Some(&previous),
        &current,
        BaselineDeviationConfig {
            enabled: true,
            min_previous_tool_calls: 5,
        },
    )
    .unwrap()
    .unwrap();
    assert_eq!(deviation.risk_modifier, 15);
    assert_eq!(deviation.new_tool_names, 1);
    assert_eq!(deviation.new_path_classes, 1);
    assert_eq!(deviation.new_network_hosts, 1);
}

#[test]
fn baseline_deviation_compares_hashed_persisted_hosts() {
    let host = "known.example.test";
    let mut previous = summary();
    previous.observations.tool_calls = 6;
    previous
        .network_host_counts
        .insert(baseline_host_identity(host), 6);
    let mut current = summary();
    current.network_host_counts.insert(host.into(), 1);
    assert_eq!(
        assess_baseline_deviation(
            Some(&previous),
            &current,
            BaselineDeviationConfig {
                enabled: true,
                min_previous_tool_calls: 5
            },
        )
        .unwrap(),
        None
    );
}

#[test]
fn baseline_deviation_requires_model_and_provider() {
    let mut previous = summary();
    previous.observations.tool_calls = 6;
    let mut current = summary();
    current.key.model = None;
    current.tool_call_counts.insert("shell".into(), 1);
    assert_eq!(
        assess_baseline_deviation(
            Some(&previous),
            &current,
            BaselineDeviationConfig {
                enabled: true,
                min_previous_tool_calls: 0
            },
        )
        .unwrap(),
        None
    );
}

#[test]
fn baseline_merge_hashes_and_snapshot_ids_preserve_state_semantics() {
    let mut first = summary();
    first.observations.records = 2;
    first.observations.tool_calls = 2;
    first.network_host_counts.insert("Example.test".into(), 1);
    let mut second = summary();
    second.observations.records = 3;
    second.observations.tool_calls = 3;
    second.network_host_counts.insert("example.test".into(), 2);
    first.checked_merge_from(second).unwrap();
    assert_eq!(first.observations.records, 5);
    assert_eq!(first.observations.tool_calls, 5);
    assert_eq!(first.network_host_counts.get("Example.test"), Some(&1));
    assert_eq!(first.network_host_counts.get("example.test"), Some(&2));
    first.hash_network_hosts_for_state().unwrap();
    assert_eq!(first.network_host_counts.len(), 1);
    assert_eq!(first.network_host_counts.values().copied().sum::<u64>(), 3);
    assert_eq!(
        baseline_snapshot_id(&first.key),
        "codex\u{1f}agent\u{1f}model\u{1f}provider"
    );
    assert_eq!(
        BaselineSnapshotStore::default().schema_version,
        BASELINE_STATE_VERSION
    );
}

#[test]
fn classifies_macos_and_windows_home_and_temp_paths() {
    assert_eq!(
        classify_path_token("/Users/tester/project/src/main.rs"),
        Some(PathClass::Home)
    );
    assert_eq!(
        classify_path_token("C:/Users/tester/AppData/Local/Temp/build.log"),
        Some(PathClass::Temp)
    );
    assert_eq!(
        classify_path_token("C:/Users/tester/Documents/notes.txt"),
        Some(PathClass::Home)
    );
}
