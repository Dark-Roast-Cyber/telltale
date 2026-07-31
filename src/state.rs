use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[cfg(test)]
use crate::baseline::BaselineKey;
use crate::baseline::{
    BASELINE_STATE_VERSION, BaselineSnapshotStore, BaselineSummary, baseline_snapshot_id,
};
use crate::event::Event;
use crate::install_inventory::InstallInventorySnapshot;
use telltale_schema::clients::SourceKind;
use telltale_schema::source::Source;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ScanState {
    pub seen_source_fingerprints: BTreeSet<String>,
    pub seen_detection_fingerprints: BTreeSet<String>,
    #[serde(default)]
    pub baseline_snapshots: BaselineSnapshotStore,
    #[serde(default)]
    pub baseline_source_contributions: BTreeMap<String, BaselineSourceContribution>,
    #[serde(default)]
    pub source_observations: BTreeMap<String, SourceObservation>,
    #[serde(default)]
    pub sqlite_ingestion_cursors: BTreeMap<String, SqliteIngestionCursor>,
    #[serde(default)]
    pub install_inventory: Option<InstallInventorySnapshot>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SourceObservation {
    pub client: String,
    pub source_id: String,
    #[serde(default)]
    pub source_instance_id: String,
    pub last_seen_unix_ms: u64,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SqliteIngestionCursor {
    pub client: String,
    pub source_id: String,
    #[serde(default)]
    pub source_instance_id: String,
    pub table: String,
    pub last_time_updated: i64,
    pub observed_at_unix_ms: u64,
}

pub use telltale_schema::source::SourceInventoryChangeSummary;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct BaselineSourceContribution {
    pub client: String,
    pub source_id: String,
    #[serde(default)]
    pub source_instance_id: String,
    pub source_fingerprint: String,
    pub snapshots: BTreeMap<String, BaselineSummary>,
}

impl ScanState {
    pub fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        match fs::read_to_string(path) {
            Ok(contents) => {
                if contents.trim().is_empty() {
                    Ok(Self::default())
                } else {
                    let mut state: Self = serde_json::from_str(&contents)?;
                    state.hash_baseline_network_hosts_for_state();
                    Ok(state)
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(err) => Err(err.into()),
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }

    pub fn should_emit(&mut self, source: &Source, event: &Event) -> bool {
        let source_fingerprint = source_fingerprint(source);
        let detection_fingerprint = detection_fingerprint(event, &source_fingerprint);
        if self
            .seen_detection_fingerprints
            .contains(&detection_fingerprint)
        {
            return false;
        }
        self.seen_source_fingerprints.insert(source_fingerprint);
        self.seen_detection_fingerprints
            .insert(detection_fingerprint);
        true
    }

    #[cfg(test)]
    fn replace_baseline_snapshots(&mut self, snapshots: Vec<BaselineSummary>) {
        self.baseline_snapshots = BaselineSnapshotStore {
            schema_version: BASELINE_STATE_VERSION,
            snapshots: snapshots
                .into_iter()
                .map(|mut snapshot| {
                    snapshot.hash_network_hosts_for_state();
                    (baseline_snapshot_id(&snapshot.key), snapshot)
                })
                .collect(),
        };
    }

    pub fn merge_baseline_snapshots(&mut self, snapshots: Vec<BaselineSummary>) {
        self.baseline_snapshots.schema_version = BASELINE_STATE_VERSION;
        for mut snapshot in snapshots {
            snapshot.hash_network_hosts_for_state();
            let id = baseline_snapshot_id(&snapshot.key);
            if let Some(existing) = self.baseline_snapshots.snapshots.get_mut(&id) {
                if existing.key == snapshot.key {
                    existing.merge_from(snapshot);
                } else {
                    self.baseline_snapshots.snapshots.insert(id, snapshot);
                }
            } else {
                self.baseline_snapshots.snapshots.insert(id, snapshot);
            }
        }
    }

    pub fn record_baseline_source_contribution(
        &mut self,
        source: &Source,
        source_fingerprint: String,
        snapshots: Vec<BaselineSummary>,
    ) {
        self.baseline_source_contributions.insert(
            source_observation_key(source),
            BaselineSourceContribution {
                client: source.client.as_str().to_string(),
                source_id: source.source_id.clone(),
                source_instance_id: source_instance_id(source),
                source_fingerprint,
                snapshots: snapshots
                    .into_iter()
                    .map(|mut snapshot| {
                        snapshot.hash_network_hosts_for_state();
                        (baseline_snapshot_id(&snapshot.key), snapshot)
                    })
                    .collect(),
            },
        );
    }

    pub fn rebuild_baseline_snapshots_from_source_contributions(&mut self) {
        self.baseline_snapshots = BaselineSnapshotStore::default();
        let snapshots = self
            .baseline_source_contributions
            .values()
            .flat_map(|contribution| contribution.snapshots.values().cloned())
            .collect::<Vec<_>>();
        self.merge_baseline_snapshots(snapshots);
    }

    #[cfg(test)]
    fn baseline_snapshot(&self, key: &BaselineKey) -> Option<&BaselineSummary> {
        self.baseline_snapshots
            .snapshots
            .get(&baseline_snapshot_id(key))
            .filter(|snapshot| &snapshot.key == key)
    }

    pub fn source_inventory_change_summary(
        &self,
        current_sources: &[Source],
    ) -> SourceInventoryChangeSummary {
        let previous_keys = self
            .source_observations
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        let current_keys = current_sources
            .iter()
            .map(source_observation_key)
            .collect::<BTreeSet<_>>();
        let added = current_keys
            .difference(&previous_keys)
            .cloned()
            .collect::<Vec<_>>();
        let removed = previous_keys
            .difference(&current_keys)
            .cloned()
            .collect::<Vec<_>>();
        let unchanged = current_keys.intersection(&previous_keys).count();
        let mut hasher = Sha256::new();
        for key in &added {
            hasher.update(b"added:");
            hasher.update(key.as_bytes());
            hasher.update(b"\n");
        }
        for key in &removed {
            hasher.update(b"removed:");
            hasher.update(key.as_bytes());
            hasher.update(b"\n");
        }

        SourceInventoryChangeSummary {
            baseline: previous_keys.is_empty(),
            added: added.len() as u32,
            removed: removed.len() as u32,
            unchanged: unchanged as u32,
            hash: format!("{:x}", hasher.finalize()),
        }
    }

    pub fn observe_sources(&mut self, sources: &[Source], observed_at_unix_ms: u64) {
        for source in sources {
            self.source_observations.insert(
                source_observation_key(source),
                SourceObservation {
                    client: source.client.as_str().to_string(),
                    source_id: source.source_id.clone(),
                    source_instance_id: source_instance_id(source),
                    last_seen_unix_ms: observed_at_unix_ms,
                },
            );
        }
    }

    pub fn replace_source_observations(&mut self, sources: &[Source], observed_at_unix_ms: u64) {
        self.source_observations.clear();
        self.observe_sources(sources, observed_at_unix_ms);
    }

    pub fn sqlite_ingestion_cursor_time_updated(
        &self,
        source: &Source,
        table: &str,
    ) -> Option<i64> {
        self.sqlite_ingestion_cursors
            .get(&sqlite_ingestion_cursor_key(source, table))
            .map(|cursor| cursor.last_time_updated)
    }

    pub fn observe_sqlite_ingestion_cursor(
        &mut self,
        source: &Source,
        table: &str,
        last_time_updated: i64,
        observed_at_unix_ms: u64,
    ) {
        self.sqlite_ingestion_cursors.insert(
            sqlite_ingestion_cursor_key(source, table),
            SqliteIngestionCursor {
                client: source.client.as_str().to_string(),
                source_id: source.source_id.clone(),
                source_instance_id: source_instance_id(source),
                table: table.to_string(),
                last_time_updated,
                observed_at_unix_ms,
            },
        );
    }

    pub fn has_legacy_source_identity_state(&self) -> bool {
        self.baseline_source_contributions
            .values()
            .any(|contribution| contribution.source_instance_id.is_empty())
            || self
                .source_observations
                .values()
                .any(|observation| observation.source_instance_id.is_empty())
    }

    pub fn drop_legacy_source_identity_state(&mut self) {
        self.baseline_source_contributions
            .retain(|_, contribution| !contribution.source_instance_id.is_empty());
        self.source_observations
            .retain(|_, observation| !observation.source_instance_id.is_empty());
    }

    fn hash_baseline_network_hosts_for_state(&mut self) {
        self.baseline_snapshots.schema_version = BASELINE_STATE_VERSION;
        for snapshot in self.baseline_snapshots.snapshots.values_mut() {
            snapshot.hash_network_hosts_for_state();
        }
        for contribution in self.baseline_source_contributions.values_mut() {
            for snapshot in contribution.snapshots.values_mut() {
                snapshot.hash_network_hosts_for_state();
            }
        }
    }
}

fn source_observation_key(source: &Source) -> String {
    format!(
        "{}\u{1f}{}\u{1f}{}",
        source.client.as_str(),
        source.source_id,
        source_instance_id(source)
    )
}

fn sqlite_ingestion_cursor_key(source: &Source, table: &str) -> String {
    format!(
        "{}\u{1f}{}\u{1f}{}\u{1f}{}",
        source.client.as_str(),
        source.source_id,
        source_instance_id(source),
        table
    )
}

fn source_instance_id(source: &Source) -> String {
    let mut hasher = Sha256::new();
    hasher.update(source.path.to_string_lossy().as_bytes());
    format!("{:x}", hasher.finalize())
}

pub fn source_fingerprint(source: &Source) -> String {
    let mut hasher = Sha256::new();
    hasher.update(source.path.to_string_lossy().as_bytes());
    if source.kind == SourceKind::Sqlite {
        if let Ok(metadata) = fs::metadata(&source.path) {
            hasher.update(metadata.len().to_le_bytes());
            if let Ok(modified) = metadata.modified()
                && let Ok(duration) = modified.duration_since(std::time::UNIX_EPOCH)
            {
                hasher.update(duration.as_secs().to_le_bytes());
                hasher.update(duration.subsec_nanos().to_le_bytes());
            }
        }
        return format!("{:x}", hasher.finalize());
    }
    if let Ok(bytes) = fs::read(&source.path) {
        hasher.update(&bytes);
    }
    format!("{:x}", hasher.finalize())
}

pub fn detection_fingerprint(event: &Event, source_fingerprint: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(event.client.as_bytes());
    if let Some(source_path_hash) = &event.source_path_hash {
        hasher.update(source_path_hash.as_bytes());
    } else {
        hasher.update(source_fingerprint.as_bytes());
    }
    hasher.update(event.session_id.as_bytes());
    hasher.update(event.event_type.as_bytes());
    hasher.update(event.severity.as_bytes());
    if let Ok(score) = u32::try_from(event.risk_score) {
        hasher.update(score.to_le_bytes());
    } else {
        hasher.update(b"risk_score:u64:");
        hasher.update(event.risk_score.to_le_bytes());
    }
    if let Some(agent) = &event.agent {
        hasher.update(agent.as_bytes());
    }
    if let Some(model) = &event.model {
        hasher.update(model.as_bytes());
    }
    if let Some(provider) = &event.provider {
        hasher.update(provider.as_bytes());
    }
    if let Some(tool_name) = &event.tool_name {
        hasher.update(tool_name.as_bytes());
    }
    for rule_id in &event.rule_ids {
        hasher.update(rule_id.as_bytes());
    }
    for category in &event.categories {
        hasher.update(category.as_bytes());
    }
    for tag in &event.tags {
        hasher.update(tag.as_bytes());
    }
    for evidence in &event.evidence {
        hasher.update(evidence.field.as_bytes());
        hasher.update(evidence.redacted_value.as_bytes());
        if let Some(hash) = &evidence.hash {
            hasher.update(hash.as_bytes());
        }
    }
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::baseline::{
        BASELINE_HOST_HASH_PREFIX, BaselineKey, BaselineObservationTotals, BaselineSummary,
        PathClass, baseline_host_identity,
    };
    use crate::event::{DetectionEventInput, Evidence, detection_event};
    use telltale_schema::clients::{ClientId, SourceKind};
    use telltale_schema::source::Source;

    use super::{
        BASELINE_STATE_VERSION, ScanState, baseline_snapshot_id, detection_fingerprint,
        source_fingerprint,
    };

    #[test]
    fn suppresses_duplicate_detections_for_same_source_content() {
        let source = Source {
            client: ClientId::Codex,
            kind: SourceKind::Jsonl,
            source_id: "source".to_string(),
            path: Path::new(
                "tests/fixtures/session_stores/codex/sessions/2026/04/uc001-positive.jsonl",
            )
            .to_path_buf(),
        };
        let event = detection_event(DetectionEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "session".to_string(),
            source_path_hash: "hash".to_string(),
            tool_name: Some("repo_status".to_string()),
            rule_ids: vec!["rule.test".to_string()],
            categories: vec!["category".to_string()],
            detection_classes: Vec::new(),
            signal_types: Vec::new(),
            analytic_intents: Vec::new(),
            atlas_tags: Vec::new(),
            tags: vec!["tag".to_string()],
            evidence: vec![Evidence {
                field: "field".to_string(),
                redacted_value: "value".to_string(),
                hash: Some("abc".to_string()),
                rule_id: None,
            }],
            risk_contributions: Vec::new(),
            event_time: Some("2026-05-01T00:00:00.000Z".to_string()),
        })
        .expect("build detection event");

        let mut state = ScanState::default();
        assert!(state.should_emit(&source, &event));
        assert!(!state.should_emit(&source, &event));
        assert_eq!(state.seen_source_fingerprints.len(), 1);
        assert_eq!(state.seen_detection_fingerprints.len(), 1);
        assert_eq!(
            detection_fingerprint(&event, &source_fingerprint(&source)),
            detection_fingerprint(&event, &source_fingerprint(&source))
        );
        let mut wide_score = event.clone();
        wide_score.risk_score = u64::from(u32::MAX) + 1;
        assert_ne!(
            detection_fingerprint(&event, &source_fingerprint(&source)),
            detection_fingerprint(&wide_score, &source_fingerprint(&source))
        );
    }

    #[test]
    fn stable_event_source_hash_dedup_ignores_container_fingerprint_churn() {
        let event = detection_event(DetectionEventInput {
            client: ClientId::OpenCode,
            agent: Some("build".to_string()),
            model: Some("gpt-5.4".to_string()),
            provider: Some("github-copilot".to_string()),
            session_id: "ses_stable".to_string(),
            source_path_hash: "stable-source-hash".to_string(),
            tool_name: None,
            rule_ids: vec!["rule.test".to_string()],
            categories: vec!["category".to_string()],
            detection_classes: Vec::new(),
            signal_types: Vec::new(),
            analytic_intents: Vec::new(),
            atlas_tags: Vec::new(),
            tags: vec!["activity".to_string(), "session".to_string()],
            evidence: vec![Evidence {
                field: "record_counts".to_string(),
                redacted_value: r#"{"assistant_message":2,"user_message":1}"#.to_string(),
                hash: Some("abc".to_string()),
                rule_id: None,
            }],
            risk_contributions: Vec::new(),
            event_time: Some("2026-05-01T00:00:00.000Z".to_string()),
        })
        .expect("build detection event");

        assert_eq!(
            detection_fingerprint(&event, "container-fingerprint-a"),
            detection_fingerprint(&event, "container-fingerprint-b")
        );
    }

    #[test]
    fn loads_empty_state_file_as_default() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("empty-state.json");
        std::fs::write(&path, "").expect("write empty");

        let state = ScanState::load(&path).expect("load");
        assert!(state.seen_source_fingerprints.is_empty());
        assert!(state.seen_detection_fingerprints.is_empty());
        assert_eq!(
            state.baseline_snapshots.schema_version,
            BASELINE_STATE_VERSION
        );
        assert!(state.baseline_snapshots.snapshots.is_empty());
        assert!(state.baseline_source_contributions.is_empty());
    }

    #[test]
    fn loads_legacy_state_without_baseline_snapshots() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("legacy-state.json");
        std::fs::write(
            &path,
            r#"{
  "seen_source_fingerprints": ["source-a"],
  "seen_detection_fingerprints": ["detection-a"]
}"#,
        )
        .expect("write legacy state");

        let state = ScanState::load(&path).expect("load");

        assert!(state.seen_source_fingerprints.contains("source-a"));
        assert!(state.seen_detection_fingerprints.contains("detection-a"));
        assert_eq!(
            state.baseline_snapshots.schema_version,
            BASELINE_STATE_VERSION
        );
        assert!(state.baseline_snapshots.snapshots.is_empty());
        assert!(state.baseline_source_contributions.is_empty());
    }

    #[test]
    fn persists_sqlite_ingestion_cursors_by_source_and_table() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("sqlite-cursor-state.json");
        let source = Source {
            client: ClientId::OpenCode,
            kind: SourceKind::Sqlite,
            source_id: "opencode.sqlite".to_string(),
            path: Path::new("/home/user/.local/share/opencode/opencode.db").to_path_buf(),
        };

        let mut state = ScanState::default();
        state.observe_sqlite_ingestion_cursor(&source, "part", 1_775_000_001_000, 1234);
        state.save(&path).expect("save");

        let reloaded = ScanState::load(&path).expect("reload");
        assert_eq!(
            reloaded.sqlite_ingestion_cursor_time_updated(&source, "part"),
            Some(1_775_000_001_000)
        );
        assert_eq!(
            reloaded.sqlite_ingestion_cursor_time_updated(&source, "message"),
            None
        );
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
    fn loads_legacy_raw_baseline_hosts_as_hashed_state() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("legacy-raw-host-baseline.json");
        std::fs::write(
            &path,
            r#"{
  "seen_source_fingerprints": [],
  "seen_detection_fingerprints": [],
  "baseline_snapshots": {
    "schema_version": 1,
    "snapshots": {
      "codex\u001f\u001fo3\u001fopenai": {
        "key": {
          "client": "codex",
          "agent": null,
          "model": "o3",
          "provider": "openai"
        },
        "observations": {
          "records": 1,
          "user_messages": 0,
          "assistant_messages": 0,
          "tool_calls": 1,
          "tool_results": 0,
          "session_meta": 0,
          "other": 0
        },
        "tool_call_counts": {"shell": 1},
        "path_class_counts": {},
        "network_host_counts": {"internal.example.test": 1}
      }
    }
  },
  "baseline_source_contributions": {},
  "source_observations": {}
}"#,
        )
        .expect("write legacy state");

        let key = BaselineKey {
            client: "codex".to_string(),
            agent: None,
            model: Some("o3".to_string()),
            provider: Some("openai".to_string()),
        };

        let state = ScanState::load(&path).expect("load state");
        let snapshot = state.baseline_snapshot(&key).expect("baseline snapshot");

        assert_eq!(
            snapshot
                .network_host_counts
                .get(&baseline_host_identity("internal.example.test")),
            Some(&1)
        );
        assert!(
            snapshot
                .network_host_counts
                .keys()
                .all(|host| host.starts_with(BASELINE_HOST_HASH_PREFIX))
        );
        assert!(
            !serde_json::to_string(&state)
                .expect("serialize state")
                .contains("internal.example.test")
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
        state.record_baseline_source_contribution(
            &source,
            "fingerprint-before".to_string(),
            vec![first],
        );
        state.record_baseline_source_contribution(
            &source,
            "fingerprint-after".to_string(),
            vec![second],
        );
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
        state.record_baseline_source_contribution(
            &source_a,
            "fingerprint-a".to_string(),
            vec![summary.clone()],
        );
        state.record_baseline_source_contribution(
            &source_b,
            "fingerprint-b".to_string(),
            vec![summary],
        );
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
}
