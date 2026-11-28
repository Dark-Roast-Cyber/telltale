use super::*;

#[test]
fn aggregate_overflow_does_not_replace_snapshot() {
    let mut state = ScanState::default();
    let mut summary = BaselineSummary::default();
    summary.observations.records = u64::MAX;
    let source = Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".into(),
        path: "one.jsonl".into(),
    };
    state
        .record_baseline_source_contribution(&source, "one".into(), vec![summary.clone()])
        .unwrap();
    state
        .rebuild_baseline_snapshots_from_source_contributions()
        .unwrap();
    let before = state.baseline_snapshots.clone();
    summary.observations.records = 1;
    let other = Source {
        path: "two.jsonl".into(),
        ..source
    };
    state
        .record_baseline_source_contribution(&other, "two".into(), vec![summary])
        .unwrap();
    assert!(
        state
            .rebuild_baseline_snapshots_from_source_contributions()
            .is_err()
    );
    assert_eq!(state.baseline_snapshots, before);
}

#[test]
fn persists_and_reloads_versioned_baseline_snapshots() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("state-with-baselines.json");
    let key = BaselineKey {
        client: "codex".to_string(),
        agent: Some("codex-agent".to_string()),
        model: Some("o3".to_string()),
        provider: Some("openai".to_string()),
    };
    let mut summary = BaselineSummary {
        key: key.clone(),
        observations: BaselineObservationTotals {
            records: 3,
            user_messages: 1,
            assistant_messages: 0,
            tool_calls: 2,
            tool_results: 0,
            session_meta: 0,
            other: 0,
        },
        ..BaselineSummary::default()
    };
    summary.tool_call_counts.insert("shell".to_string(), 2);
    summary.path_class_counts.insert(PathClass::Source, 1);
    summary
        .network_host_counts
        .insert("docs.example.test".to_string(), 1);

    let mut state = ScanState::default();
    state.replace_baseline_snapshots(vec![summary]);
    state.save(&path).expect("save");

    let reloaded = ScanState::load(&path).expect("reload");
    let persisted = reloaded.baseline_snapshot(&key).expect("baseline snapshot");

    assert_eq!(
        reloaded.baseline_snapshots.schema_version,
        BASELINE_STATE_VERSION
    );
    assert!(
        reloaded
            .baseline_snapshots
            .snapshots
            .contains_key(&baseline_snapshot_id(&key))
    );
    assert_eq!(persisted.observations.records, 3);
    assert_eq!(persisted.tool_call_counts.get("shell"), Some(&2));
    assert_eq!(
        persisted
            .network_host_counts
            .get(&baseline_host_identity("docs.example.test")),
        Some(&1)
    );
    assert!(
        persisted
            .network_host_counts
            .keys()
            .all(|host| host.starts_with(BASELINE_HOST_HASH_PREFIX))
    );
    assert!(
        !persisted
            .network_host_counts
            .contains_key("docs.example.test")
    );
}

#[test]
fn replaces_baseline_source_contribution_for_same_source() {
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "sessions/source-a.jsonl".to_string(),
        path: Path::new("tests/fixtures/session_stores/codex/sessions/source-a.jsonl")
            .to_path_buf(),
    };
    let key = BaselineKey {
        client: "codex".to_string(),
        agent: Some("codex-agent".to_string()),
        model: Some("o3".to_string()),
        provider: Some("openai".to_string()),
    };
    let first = BaselineSummary {
        key: key.clone(),
        observations: BaselineObservationTotals {
            records: 1,
            user_messages: 0,
            assistant_messages: 0,
            tool_calls: 1,
            tool_results: 0,
            session_meta: 0,
            other: 0,
        },
        ..BaselineSummary::default()
    };
    let second = BaselineSummary {
        key: key.clone(),
        observations: BaselineObservationTotals {
            records: 2,
            user_messages: 0,
            assistant_messages: 0,
            tool_calls: 2,
            tool_results: 0,
            session_meta: 0,
            other: 0,
        },
        ..BaselineSummary::default()
    };

    let mut state = ScanState::default();
    state
        .record_baseline_source_contribution(&source, "fingerprint-before".to_string(), vec![first])
        .unwrap();
    state
        .record_baseline_source_contribution(&source, "fingerprint-after".to_string(), vec![second])
        .unwrap();
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("state-with-source-contribution.json");
    state.save(&path).expect("save state");

    let reloaded = ScanState::load(&path).expect("reload state");
    assert_eq!(reloaded.baseline_source_contributions.len(), 1);
    let contribution = reloaded
        .baseline_source_contributions
        .values()
        .next()
        .expect("source contribution");
    assert_eq!(contribution.client, "codex");
    assert_eq!(contribution.source_id, "sessions/source-a.jsonl");
    assert!(!contribution.source_instance_id.is_empty());
    assert_eq!(contribution.source_fingerprint, "fingerprint-after");
    assert_eq!(
        contribution.snapshots[&baseline_snapshot_id(&key)]
            .observations
            .records,
        2
    );
}

#[test]
fn keeps_distinct_contributions_for_sources_in_same_bucket() {
    let mut state = ScanState::default();
    let source_a = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".to_string(),
        path: Path::new("tests/fixtures/session_stores/codex/sessions/source-a.jsonl")
            .to_path_buf(),
    };
    let source_b = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".to_string(),
        path: Path::new("tests/fixtures/session_stores/codex/sessions/source-b.jsonl")
            .to_path_buf(),
    };
    state.observe_sources(&[source_a.clone(), source_b.clone()], 1_000);
    assert_eq!(state.source_observations.len(), 2);

    let key = BaselineKey {
        client: "codex".to_string(),
        agent: Some("codex-agent".to_string()),
        model: Some("o3".to_string()),
        provider: Some("openai".to_string()),
    };
    let summary = BaselineSummary {
        key,
        observations: BaselineObservationTotals {
            records: 1,
            user_messages: 0,
            assistant_messages: 0,
            tool_calls: 1,
            tool_results: 0,
            session_meta: 0,
            other: 0,
        },
        ..BaselineSummary::default()
    };
    state
        .record_baseline_source_contribution(
            &source_a,
            "fingerprint-a".to_string(),
            vec![summary.clone()],
        )
        .unwrap();
    state
        .record_baseline_source_contribution(&source_b, "fingerprint-b".to_string(), vec![summary])
        .unwrap();
    assert_eq!(state.baseline_source_contributions.len(), 2);
}

#[test]
fn summarizes_source_inventory_changes_without_paths() {
    let mut state = ScanState::default();
    let source_a = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".to_string(),
        path: Path::new("tests/fixtures/session_stores/codex/sessions/source-a.jsonl")
            .to_path_buf(),
    };
    let source_b = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".to_string(),
        path: Path::new("tests/fixtures/session_stores/codex/sessions/source-b.jsonl")
            .to_path_buf(),
    };

    let first = state.source_inventory_change_summary(&[source_a.clone(), source_b.clone()]);
    assert!(first.baseline);
    assert_eq!(first.added, 2);
    assert_eq!(first.removed, 0);
    assert_eq!(first.unchanged, 0);
    assert_eq!(first.hash.len(), 64);

    state.observe_sources(&[source_a.clone(), source_b], 1_000);
    let second = state.source_inventory_change_summary(std::slice::from_ref(&source_a));
    assert!(!second.baseline);
    assert_eq!(second.added, 0);
    assert_eq!(second.removed, 1);
    assert_eq!(second.unchanged, 1);
    assert_eq!(second.hash.len(), 64);

    state.replace_source_observations(std::slice::from_ref(&source_a), 2_000);
    let third = state.source_inventory_change_summary(std::slice::from_ref(&source_a));
    assert!(!third.baseline);
    assert_eq!(third.added, 0);
    assert_eq!(third.removed, 0);
    assert_eq!(third.unchanged, 1);
}
