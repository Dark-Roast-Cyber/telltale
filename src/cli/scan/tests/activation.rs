use super::super::*;
use crate::baseline::{BaselineKey, BaselineSummary};
use crate::sink::{EventSink, LocalJsonlSink};
use std::fs;

fn blocked_failure(sink: &str, status: u16) -> SinkFailure {
    SinkFailure {
        name: sink.into(),
        kind: "splunk_hec".into(),
        class: DeliveryErrorClass::AuthenticationBlocked { status },
        attempts: 1,
        error: "synthetic authentication failure".into(),
        prior_attempts: 0,
        prior_error_class: None,
    }
}

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
            history: false,
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
                health_heartbeat_interval_seconds: None,
                process_chain: true,
                operational_alerts: Default::default(),
                runtime: &value,
                effective_configuration: &value,
            },
            backfill,
            rebuild_baselines: false,
            max_sources: None,
            diagnostics: None,
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

struct AlertWriteFailure(LocalJsonlSink);

impl EventSink for AlertWriteFailure {
    fn name(&self) -> &str {
        "synthetic-canonical"
    }
    fn emit(&self, events: &[Event]) -> Result<(), Box<dyn std::error::Error>> {
        if events
            .iter()
            .any(|event| event.check_name.as_deref() == Some("sink_delivery"))
        {
            return Err("synthetic canonical alert write failure".into());
        }
        self.0.emit(events)
    }
}

struct AuthenticationFailure;

impl EventSink for AuthenticationFailure {
    fn name(&self) -> &str {
        "synthetic-remote"
    }
    fn emit(&self, _: &[Event]) -> Result<(), Box<dyn std::error::Error>> {
        Err(crate::sink::DeliveryError::new(
            DeliveryErrorClass::AuthenticationBlocked { status: 401 },
            1,
            "synthetic authentication failure",
        )
        .into())
    }
}

struct ThresholdHarness {
    dir: tempfile::TempDir,
    log: PathBuf,
    state: PathBuf,
    packs: RulePackPaths,
    runtime: serde_json::Value,
    clients: Vec<ClientId>,
    sources: Vec<Source>,
}

impl ThresholdHarness {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let malformed = dir.path().join(".codex/sessions/malformed-source.jsonl");
        fs::create_dir_all(malformed.parent().expect("sessions parent")).expect("sessions dir");
        fs::write(
            &malformed,
            include_str!("../../../../tests/fixtures/rule_samples/malformed-source.jsonl"),
        )
        .expect("malformed fixture");
        let clients = vec![ClientId::Codex];
        let (sources, _) = discover_operational_sources(
            dir.path(),
            &clients,
            None,
            &[],
            &discovery::ProjectConfigurationAccounting::none(),
        );
        assert_eq!(
            sources.len(),
            1,
            "synthetic malformed fixture should be the only source"
        );
        assert_eq!(sources[0].path, malformed);
        Self {
            log: dir.path().join("events.jsonl"),
            state: dir.path().join("state.json"),
            packs: RulePackPaths::default(),
            runtime: serde_json::json!({}),
            clients,
            sources,
            dir,
        }
    }

    fn scan(&self, max_scanner_errors: u32, targeted: bool, backfill: bool) {
        let mut sinks = SinkSet::new();
        sinks.add_canonical_first_write(
            "jsonl",
            Box::new(LocalJsonlSink::with_rotation(
                &self.log,
                crate::sink::RotationConfig::disabled(),
            )),
        );
        let config = ScanConfig {
            history: false,
            execution: ScanExecutionConfig {
                root: self.dir.path(),
                log_path: &self.log,
                sinks: &sinks,
                state_path: &self.state,
                dry_run: false,
                emit_activity: false,
                emit_session_risk_summary: false,
                allow_fixtures: true,
                rule_pack_paths: &self.packs,
                rule_paths: &[],
                override_paths: &[],
                rule_load_mode: RuleLoadMode::IncludeDefault,
                policy_path: None,
                allowlist_path: None,
                baseline_deviation_scoring: false,
                clients: &self.clients,
                project_config_paths: &[],
                install_inventory_interval_seconds: None,
                health_heartbeat_interval_seconds: None,
                process_chain: false,
                operational_alerts: OperationalAlertConfig {
                    max_scanner_errors,
                    max_scan_duration_ms: u64::MAX,
                },
                runtime: &self.runtime,
                effective_configuration: &self.runtime,
            },
            backfill,
            rebuild_baselines: false,
            max_sources: None,
            diagnostics: None,
        };
        let result = if targeted {
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
        };
        result.unwrap_or_else(|error| panic!("scan failed: {error}"));
    }

    fn take_events(&self) -> Vec<serde_json::Value> {
        let events = fs::read_to_string(&self.log)
            .unwrap_or_default()
            .lines()
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_str(line).expect("event json"))
            .collect();
        if self.log.exists() {
            fs::write(&self.log, "").expect("truncate log");
        }
        events
    }

    fn latched(&self) -> bool {
        ScanState::load(&self.state)
            .expect("load state")
            .scanner_error_threshold_latched()
    }
}

fn threshold_alerts(events: &[serde_json::Value]) -> usize {
    events
        .iter()
        .filter(|event| event["check_name"] == "scanner_error_threshold")
        .count()
}

fn health_events(events: &[serde_json::Value]) -> usize {
    events
        .iter()
        .filter(|event| event["event_type"] == "health")
        .count()
}

mod error_threshold;
mod evidence_severity;
mod progress_commit;
mod sink_failure_episodes;
