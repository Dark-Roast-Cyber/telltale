use super::*;
use crate::baseline::{BaselineKey, BaselineSummary};
use crate::sink::{EventSink, LocalJsonlSink};
use std::fs;

struct Fixture {
    dir: tempfile::TempDir,
    sources: Vec<Source>,
    state: PathBuf,
    log: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".codex/sessions/synthetic.jsonl");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "{\"type\":\"user\",\"session_id\":\"synthetic\",\"model\":\"model\",\"provider\":\"provider\",\"content\":\"hello\"}\n").unwrap();
        let opencode = telltale_sources::clients::supported_clients()
            .iter()
            .find(|client| client.id == ClientId::OpenCode)
            .unwrap();
        let sqlite = opencode
            .sources
            .iter()
            .find(|source| source.id == "opencode.sqlite")
            .unwrap();
        let db = telltale_sources::discovery::source_search_root(dir.path(), *sqlite);
        fs::create_dir_all(db.parent().unwrap()).unwrap();
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute_batch(r#"CREATE TABLE message (id TEXT, session_id TEXT, data TEXT);
            CREATE TABLE part (id TEXT, message_id TEXT, session_id TEXT, time_updated INTEGER, data TEXT);
            INSERT INTO message VALUES ('m','s','{"role":"assistant"}');
            INSERT INTO part VALUES ('p','m','s',10,'{"type":"tool","tool":"shell","callID":"c","state":{"status":"running","input":{"command":"echo synthetic"}}}');"#).unwrap();
        drop(conn);
        let state = dir.path().join("state.json");
        let log = dir.path().join("events.jsonl");
        let sources = vec![
            Source {
                client: ClientId::Codex,
                kind: SourceKind::Jsonl,
                source_id: "codex.sessions".into(),
                path,
            },
            Source {
                client: ClientId::OpenCode,
                kind: SourceKind::Sqlite,
                source_id: "opencode.sqlite".into(),
                path: db,
            },
        ];
        ScanState::default().save(&state).unwrap();
        Self {
            dir,
            sources,
            state,
            log,
        }
    }

    fn sinks(&self) -> SinkSet {
        let mut sinks = SinkSet::new();
        sinks.add_canonical_first_write(
            "jsonl",
            Box::new(LocalJsonlSink::with_rotation(
                &self.log,
                crate::sink::RotationConfig::disabled(),
            )),
        );
        sinks
    }

    fn scan(
        &self,
        sinks: &SinkSet,
        targeted: bool,
        dry_run: bool,
        backfill: bool,
    ) -> Result<ScanRunResult, Box<dyn std::error::Error>> {
        let packs = RulePackPaths::default();
        let value = serde_json::json!({});
        let config = ScanConfig {
            execution: ScanExecutionConfig {
                root: self.dir.path(),
                log_path: &self.log,
                sinks,
                state_path: &self.state,
                dry_run,
                emit_activity: true,
                emit_session_risk_summary: false,
                allow_fixtures: true,
                rule_pack_paths: &packs,
                rule_paths: &[],
                override_paths: &[],
                rule_load_mode: RuleLoadMode::IncludeDefault,
                policy_path: None,
                allowlist_path: None,
                baseline_deviation_scoring: false,
                clients: &[ClientId::Codex, ClientId::OpenCode],
                project_config_paths: &[],
                install_inventory_interval_seconds: None,
                runtime: &value,
                effective_configuration: &value,
            },
            backfill,
            rebuild_baselines: false,
            max_sources: None,
        };
        if targeted {
            // Exactly the production watch dispatch: same targets and save policy.
            run_scan(
                config,
                ScanTargets::Targeted {
                    sources: self.sources.clone(),
                    discovery: SourceDiscoveryAccounting {
                        checked_status: "complete",
                        first_error_category: None,
                        best_effort_fallback_used: false,
                        returned_source_count: self.sources.len(),
                        operational_source_count: self.sources.len(),
                        project_configuration: discovery::ProjectConfigurationAccounting::none(),
                    },
                },
                StateSavePolicy::OnChange,
            )
        } else {
            run_scan(config, ScanTargets::Full, StateSavePolicy::Always)
        }
    }

    fn load(&self) -> ScanState {
        ScanState::load(&self.state).unwrap()
    }

    fn events(&self) -> Vec<serde_json::Value> {
        fs::read_to_string(&self.log)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}

struct RequiredFailure;
impl EventSink for RequiredFailure {
    fn name(&self) -> &str {
        "synthetic-required-failure"
    }
    fn emit(&self, _: &[Event]) -> Result<(), Box<dyn std::error::Error>> {
        Err("synthetic output failure".into())
    }
}

#[test]
fn required_output_failure_preserves_entire_state_then_success_installs_baseline_and_cursor() {
    let fixture = Fixture::new();
    let before = fs::read(&fixture.state).unwrap();
    let mut failed = SinkSet::new();
    failed.add_canonical_first_write("jsonl", Box::new(RequiredFailure));
    assert!(fixture.scan(&failed, false, false, false).is_err());
    assert_eq!(fs::read(&fixture.state).unwrap(), before);
    fixture.scan(&fixture.sinks(), false, false, false).unwrap();
    let state = fixture.load();
    assert_eq!(
        state.sqlite_ingestion_cursor_time_updated(&fixture.sources[1], "part"),
        Some(10)
    );
    assert_eq!(state.baseline_source_contributions.len(), 1);
    assert_eq!(
        state
            .baseline_snapshots
            .snapshots
            .values()
            .next()
            .unwrap()
            .observations
            .records,
        1
    );
    let events = fixture.events();
    assert!(events.iter().any(|event| event["event_type"] == "activity"));
    assert!(
        !events
            .iter()
            .any(|event| event["event_type"] == "scanner_error")
    );
}

#[test]
fn watch_shared_path_replaces_empty_but_partial_source_retains_its_contribution() {
    let fixture = Fixture::new();
    fixture.scan(&fixture.sinks(), true, false, false).unwrap();
    let mut state = fixture.load();
    let partial_summary = BaselineSummary {
        key: BaselineKey {
            client: "opencode".into(),
            ..BaselineKey::default()
        },
        ..BaselineSummary::default()
    };
    state
        .record_baseline_source_contribution(
            &fixture.sources[1],
            "retained".into(),
            vec![partial_summary],
        )
        .unwrap();
    state
        .rebuild_baseline_snapshots_from_source_contributions()
        .unwrap();
    state.save(&fixture.state).unwrap();
    let retained = state
        .baseline_source_contributions
        .values()
        .find(|value| value.client == "opencode")
        .unwrap()
        .clone();
    // Complete source with no eligible population requests Replace(empty).
    fs::write(
        &fixture.sources[0].path,
        "{\"type\":\"session_meta\",\"payload\":{}}\n",
    )
    .unwrap();
    fixture.scan(&fixture.sinks(), true, false, false).unwrap();
    let state = fixture.load();
    assert_eq!(
        state
            .baseline_source_contributions
            .values()
            .find(|value| value.client == "opencode"),
        Some(&retained)
    );
    assert!(
        state
            .baseline_source_contributions
            .values()
            .find(|value| value.client == "codex")
            .unwrap()
            .snapshots
            .is_empty()
    );
    assert_eq!(state.baseline_snapshots.snapshots.len(), 1);
}

#[test]
fn aggregate_overflow_blocks_all_persistence_and_progress() {
    let fixture = Fixture::new();
    fixture.scan(&fixture.sinks(), true, false, false).unwrap();
    let mut state = fixture.load();
    let mut summary = state
        .baseline_snapshots
        .snapshots
        .values()
        .next()
        .unwrap()
        .clone();
    summary.observations.records = u64::MAX;
    let other = Source {
        path: fixture.dir.path().join("unscanned.jsonl"),
        ..fixture.sources[0].clone()
    };
    state
        .record_baseline_source_contribution(&other, "retained".into(), vec![summary])
        .unwrap();
    state.save(&fixture.state).unwrap();
    let before = fs::read(&fixture.state).unwrap();
    let output_before = fs::read(&fixture.log).unwrap();
    let error = fixture
        .scan(&fixture.sinks(), true, false, false)
        .err()
        .unwrap();
    assert!(error.downcast_ref::<RiskAccountingError>().is_some());
    assert_eq!(fs::read(&fixture.state).unwrap(), before);
    assert_eq!(fs::read(&fixture.log).unwrap(), output_before);
}

#[test]
fn dry_run_and_backfill_never_install_baseline_or_cursor() {
    for (dry_run, backfill) in [(true, false), (false, true)] {
        let fixture = Fixture::new();
        fixture
            .scan(&fixture.sinks(), false, dry_run, backfill)
            .unwrap();
        let state = fixture.load();
        assert!(state.baseline_source_contributions.is_empty());
        assert!(state.baseline_snapshots.snapshots.is_empty());
        assert!(state.sqlite_ingestion_cursors.is_empty());
    }
}

#[test]
fn late_canonical_failure_has_no_success_output_or_progress_for_that_source() {
    let fixture = Fixture::new();
    // A valid first part cannot escape a later conflicting ownership failure.
    let conn = rusqlite::Connection::open(&fixture.sources[1].path).unwrap();
    conn.execute_batch(r#"INSERT INTO part VALUES ('late','m','s',20,'{"type":"tool","sessionID":"different","tool":"shell","callID":"late","state":{"status":"running","input":{"command":"echo synthetic"}}}');"#).unwrap();
    drop(conn);
    fixture.scan(&fixture.sinks(), true, false, false).unwrap();
    let state = fixture.load();
    assert!(state.sqlite_ingestion_cursors.is_empty());
    assert!(
        state
            .baseline_source_contributions
            .values()
            .all(|value| value.client != "opencode")
    );
    let events = fixture
        .events()
        .into_iter()
        .filter(|event| event["client"] == "opencode")
        .collect::<Vec<_>>();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["event_type"], "scanner_error");
}
