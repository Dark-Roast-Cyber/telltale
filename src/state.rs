//! Scanner state: per-source observations for change detection, OpenCode
//! ingestion cursors, baseline contributions, and the versioned on-disk format
//! with its validation and atomic save.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[cfg(test)]
use crate::baseline::BaselineKey;
use crate::baseline::{
    BASELINE_STATE_VERSION, BaselineSnapshotStore, BaselineSummary, baseline_snapshot_id,
};
use crate::event::{Event, Evidence, is_canonical_sha256_hex};
use crate::file_lock::{
    FileInfo, SidecarLock, TempFile, atomic_replace, read_snapshot, safe_path_info, validate_target,
};
use crate::install_inventory::InstallInventorySnapshot;
use telltale_schema::clients::SourceKind;
use telltale_schema::source::Source;

pub(crate) const STATE_SCHEMA_VERSION: &str = "1.0";
const INVALID_STATE: &str = "scanner state is invalid and was not changed";
const OLDER_STATE: &str = "scanner state may use an older format or be invalid and was not changed; published v0.7.0 and v0.7.1 migrate supported older state only, not invalid data; migration eligibility has not been validated";

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
    /// An unfinished OpenCode v2 window. Older writers stored only the
    /// monotone checkpoint, so an absent raw cut requires overlap replay.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub draining: bool,
    /// Raw cut, independent of the monotone `last_time_updated` checkpoint.
    /// Older readers reject this unknown field rather than skip unfinished rows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continue_after_time_updated: Option<i64>,
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
    #[cfg(test)]
    pub fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let _lock = StateLock::acquire(path)?;
        Self::load_snapshot(path)
    }

    #[cfg(test)]
    pub fn save(&self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let _lock = StateLock::acquire(path)?;
        self.save_unlocked(path)
    }

    pub(crate) fn load_snapshot(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        if is_missing(path)? {
            Ok(Self::default())
        } else {
            parse_native_state(&read_snapshot(path)?)
        }
    }

    #[cfg(test)]
    pub(crate) fn save_unlocked(&self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let prepared = self.prepare_atomic_save(path)?;
        prepared.install_replace(path)
    }

    pub(crate) fn prepare_atomic_save(
        &self,
        path: &Path,
    ) -> Result<PreparedAtomicState, Box<dyn std::error::Error>> {
        let bytes = native_state_bytes(self)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let expected = safe_path_info(path)?;
        validate_target(path)?;
        Ok(PreparedAtomicState {
            temp: Some(TempFile::write_and_sync(path, &bytes, 0o600)?),
            expected,
        })
    }

    #[cfg(test)]
    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        native_state_bytes(self)
    }

    #[cfg(test)]
    pub(crate) fn validate_native_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        parse_native_state(bytes)
    }

    pub fn should_emit(
        &mut self,
        source: &Source,
        event: &Event,
        routine_evidence_rules: &BTreeSet<String>,
    ) -> bool {
        // Summaries must not re-emit when only evidence or event time changed.
        // Activities and other non-detection events still hash every evidence
        // item through `detection_fingerprint`, except that canonical process
        // correlations omit their regenerated supporting Event3 links.
        // Detections use a posture fingerprint plus evidence not known to be
        // routine low-severity activity.
        if event.event_type == "session_risk_summary" {
            return self.should_emit_session_risk_summary(source, event);
        }
        let source_fingerprint = source_fingerprint(source);
        if event.event_type == "detection" {
            let posture =
                detection_emission_fingerprint(event, &source_fingerprint, routine_evidence_rules);
            return self.should_emit_posture(
                source_fingerprint,
                event,
                "detection_emission",
                &posture,
            );
        }
        if let Some(posture) = process_correlation_emission_fingerprint(event, &source_fingerprint)
        {
            return self.should_emit_posture(
                source_fingerprint,
                event,
                "process_correlation_emission",
                &posture,
            );
        }
        let fingerprint = detection_fingerprint(event, &source_fingerprint);
        if self.seen_detection_fingerprints.contains(&fingerprint) {
            return false;
        }
        self.seen_source_fingerprints.insert(source_fingerprint);
        self.seen_detection_fingerprints.insert(fingerprint);
        true
    }

    /// Records a `session_risk_summary` fingerprint that ignores evidence and
    /// event time. Backfill callers must skip this, as they do for
    /// [`Self::should_emit`].
    pub fn should_emit_session_risk_summary(&mut self, source: &Source, event: &Event) -> bool {
        debug_assert_eq!(event.event_type, "session_risk_summary");
        let source_fingerprint = source_fingerprint(source);
        let posture = session_risk_summary_fingerprint(event, &source_fingerprint);
        self.should_emit_posture(source_fingerprint, event, "session_risk_summary", &posture)
    }

    fn should_emit_posture(
        &mut self,
        source_fingerprint: String,
        event: &Event,
        kind: &str,
        posture: &str,
    ) -> bool {
        // Legacy keys omitted classification. Learn exact historical events
        // only while all learned classifications for this posture agree. Once
        // classification changes, legacy evidence can never hide that change.
        let mut hasher = Sha256::new();
        hash_event_posture(&mut hasher, event, &source_fingerprint);
        let prefix = format!("telltale:{kind}:{}:", hex::encode(hasher.finalize()));
        let classified = format!("{prefix}{}:", classification_fingerprint(event));
        let fingerprint = format!("{classified}{posture}");
        if self.seen_detection_fingerprints.contains(&fingerprint) {
            return false;
        }
        let classification_changed = self
            .seen_detection_fingerprints
            .range(prefix.clone()..)
            .take_while(|key| key.starts_with(&prefix))
            .any(|key| !key.starts_with(&classified));
        let legacy_seen = !classification_changed
            && self
                .seen_detection_fingerprints
                .contains(&detection_fingerprint(event, &source_fingerprint));
        self.seen_source_fingerprints.insert(source_fingerprint);
        self.seen_detection_fingerprints.insert(fingerprint);
        !legacy_seen
    }

    /// Records that a full scan saw `client` lose every source. True when the
    /// outage is new: it stays recorded, and quiet, until a full scan sees the
    /// client process a source successfully, so a recurrence after recovery
    /// alerts again.
    pub fn enter_source_outage(&mut self, client: &str) -> bool {
        self.seen_detection_fingerprints
            .insert(source_outage_fingerprint(client))
    }

    pub fn clear_source_outage(&mut self, client: &str) {
        self.seen_detection_fingerprints
            .remove(&source_outage_fingerprint(client));
    }

    /// Records that a durable full scan saw the pre-dedup `scanner_error` count
    /// above the threshold. True when that crossing is new: it stays recorded,
    /// and quiet, until a durable full scan is at or below the threshold, so a
    /// later rise while still above does not alert again.
    pub fn enter_scanner_error_threshold(&mut self) -> bool {
        self.seen_detection_fingerprints
            .insert(scanner_error_threshold_fingerprint())
    }

    pub fn clear_scanner_error_threshold(&mut self) {
        self.seen_detection_fingerprints
            .remove(&scanner_error_threshold_fingerprint());
    }

    #[cfg(test)]
    pub(crate) fn scanner_error_threshold_latched(&self) -> bool {
        self.seen_detection_fingerprints
            .contains(&scanner_error_threshold_fingerprint())
    }

    /// When a scan with the liveness heartbeat enabled last emitted a health
    /// event, in Unix milliseconds. A marker that does not parse reads as none,
    /// so a damaged value makes the heartbeat due rather than silent.
    pub(crate) fn last_health_heartbeat_unix_ms(&self) -> Option<u64> {
        self.seen_detection_fingerprints
            .range(HEALTH_HEARTBEAT_PREFIX.to_string()..)
            .take_while(|key| key.starts_with(HEALTH_HEARTBEAT_PREFIX))
            .filter_map(|key| key.strip_prefix(HEALTH_HEARTBEAT_PREFIX)?.parse().ok())
            .max()
    }

    /// Replaces the heartbeat marker with `unix_ms`.
    pub(crate) fn record_health_heartbeat(&mut self, unix_ms: u64) {
        self.seen_detection_fingerprints
            .retain(|key| !key.starts_with(HEALTH_HEARTBEAT_PREFIX));
        self.seen_detection_fingerprints
            .insert(format!("{HEALTH_HEARTBEAT_PREFIX}{unix_ms}"));
    }

    #[cfg(test)]
    fn replace_baseline_snapshots(&mut self, snapshots: Vec<BaselineSummary>) {
        self.baseline_snapshots = BaselineSnapshotStore {
            schema_version: BASELINE_STATE_VERSION,
            snapshots: snapshots
                .into_iter()
                .map(|mut snapshot| {
                    snapshot
                        .hash_network_hosts_for_state()
                        .expect("test baseline");
                    (baseline_snapshot_id(&snapshot.key), snapshot)
                })
                .collect(),
        };
    }

    pub fn record_baseline_source_contribution(
        &mut self,
        source: &Source,
        source_fingerprint: String,
        snapshots: Vec<BaselineSummary>,
    ) -> Result<(), crate::scoring::RiskAccountingError> {
        let snapshots = snapshots
            .into_iter()
            .map(|mut snapshot| {
                snapshot.hash_network_hosts_for_state()?;
                Ok((baseline_snapshot_id(&snapshot.key), snapshot))
            })
            .collect::<Result<BTreeMap<_, _>, crate::scoring::RiskAccountingError>>()?;
        self.baseline_source_contributions.insert(
            source_observation_key(source),
            BaselineSourceContribution {
                client: source.client.as_str().to_string(),
                source_id: source.source_id.clone(),
                source_instance_id: source_instance_id(source),
                source_fingerprint,
                snapshots,
            },
        );
        Ok(())
    }

    pub fn rebuild_baseline_snapshots_from_source_contributions(
        &mut self,
    ) -> Result<(), crate::scoring::RiskAccountingError> {
        let mut staged = BaselineSnapshotStore::default();
        let snapshots = self
            .baseline_source_contributions
            .values()
            .flat_map(|contribution| contribution.snapshots.values().cloned());
        for snapshot in snapshots {
            let id = baseline_snapshot_id(&snapshot.key);
            if let Some(existing) = staged.snapshots.get_mut(&id) {
                existing.checked_merge_from(snapshot)?;
            } else {
                staged.snapshots.insert(id, snapshot);
            }
        }
        self.baseline_snapshots = staged;
        Ok(())
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
            hash: hex::encode(hasher.finalize()),
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

    pub fn sqlite_ingestion_continue_after(&self, source: &Source, table: &str) -> Option<i64> {
        self.sqlite_ingestion_cursors
            .get(&sqlite_ingestion_cursor_key(source, table))
            .and_then(|cursor| cursor.continue_after_time_updated)
    }

    pub fn observe_sqlite_ingestion_cursor(
        &mut self,
        source: &Source,
        table: &str,
        last_time_updated: i64,
        observed_at_unix_ms: u64,
    ) {
        let key = sqlite_ingestion_cursor_key(source, table);
        let last_time_updated = self
            .sqlite_ingestion_cursors
            .get(&key)
            .map_or(last_time_updated, |prior| {
                last_time_updated.max(prior.last_time_updated)
            });
        self.insert_sqlite_ingestion_cursor(
            source,
            table,
            last_time_updated,
            observed_at_unix_ms,
            None,
        );
    }

    /// Record both the raw cut for strict continuation and a monotone checkpoint.
    pub fn observe_sqlite_ingestion_drain(
        &mut self,
        source: &Source,
        table: &str,
        last_time_updated: i64,
        observed_at_unix_ms: u64,
    ) {
        let cut = last_time_updated;
        let last_time_updated = self
            .sqlite_ingestion_cursors
            .get(&sqlite_ingestion_cursor_key(source, table))
            .map_or(last_time_updated, |prior| {
                last_time_updated.max(prior.last_time_updated)
            });
        self.insert_sqlite_ingestion_cursor(
            source,
            table,
            last_time_updated,
            observed_at_unix_ms,
            Some(cut),
        );
    }

    fn insert_sqlite_ingestion_cursor(
        &mut self,
        source: &Source,
        table: &str,
        last_time_updated: i64,
        observed_at_unix_ms: u64,
        continue_after_time_updated: Option<i64>,
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
                draining: continue_after_time_updated.is_some(),
                continue_after_time_updated,
            },
        );
    }
}

pub(crate) struct PreparedAtomicState {
    temp: Option<TempFile>,
    expected: Option<FileInfo>,
}

impl PreparedAtomicState {
    pub(crate) fn install_replace(
        mut self,
        destination: &Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        atomic_replace(
            self.temp.take().ok_or("state temporary already consumed")?,
            destination,
            self.expected,
        )
    }
}

pub(crate) struct StateLock {
    _lock: SidecarLock,
}

impl StateLock {
    pub(crate) fn acquire(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            _lock: SidecarLock::acquire(path)?,
        })
    }

    pub(crate) fn verify(&self) -> Result<(), Box<dyn std::error::Error>> {
        self._lock.verify()
    }

    pub(crate) fn verify_lock(&self) -> Result<(), Box<dyn std::error::Error>> {
        self._lock.verify_lock()
    }
}

#[derive(Serialize)]
struct NativeState<'a> {
    state_schema_version: &'static str,
    #[serde(flatten)]
    state: &'a ScanState,
}

fn native_state_bytes(state: &ScanState) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes = serde_json::to_vec_pretty(&NativeState {
        state_schema_version: STATE_SCHEMA_VERSION,
        state,
    })?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn is_missing(path: &Path) -> Result<bool, Box<dyn std::error::Error>> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error.into()),
    }
}

fn parse_native_state(bytes: &[u8]) -> Result<ScanState, Box<dyn std::error::Error>> {
    let value = parse_json(bytes)?;
    let object = value.as_object().ok_or(INVALID_STATE)?;
    let mut native_fields = vec!["state_schema_version"];
    native_fields.extend_from_slice(state_field_names());
    validate_fields(object, &native_fields)?;
    if object.get("state_schema_version").is_none() {
        if state_field_names()
            .iter()
            .any(|field| object.contains_key(*field))
        {
            return Err(OLDER_STATE.into());
        }
        return Err(INVALID_STATE.into());
    }
    if object.get("state_schema_version") != Some(&Value::String(STATE_SCHEMA_VERSION.into())) {
        return Err(INVALID_STATE.into());
    }
    for field in state_field_names() {
        if !object.contains_key(*field) {
            return Err(INVALID_STATE.into());
        }
    }
    if matches!(
        value["baseline_snapshots"]["schema_version"].as_u64(),
        Some(1 | 2)
    ) {
        return Err(OLDER_STATE.into());
    }
    validate_state_families(&value)?;
    let mut state_object = object.clone();
    state_object.remove("state_schema_version");
    let state: ScanState =
        serde_json::from_value(Value::Object(state_object)).map_err(|_| INVALID_STATE)?;
    if has_raw_network_hosts(&state)
        || state.baseline_snapshots.schema_version != BASELINE_STATE_VERSION
    {
        return Err(INVALID_STATE.into());
    }
    Ok(state)
}

fn state_field_names() -> &'static [&'static str] {
    &[
        "seen_source_fingerprints",
        "seen_detection_fingerprints",
        "baseline_snapshots",
        "baseline_source_contributions",
        "source_observations",
        "sqlite_ingestion_cursors",
        "install_inventory",
    ]
}

fn validate_state_families(value: &Value) -> Result<(), Box<dyn std::error::Error>> {
    let object = value.as_object().ok_or(INVALID_STATE)?;
    if let Some(value) = object.get("baseline_snapshots") {
        validate_object(value, &["schema_version", "snapshots"])?;
        require_fields(value, &["schema_version", "snapshots"])?;
        let baseline = value.as_object().ok_or(INVALID_STATE)?;
        if let Some(version) = baseline.get("schema_version")
            && !matches!(
                version,
                Value::Number(number) if number.as_u64() == Some(u64::from(BASELINE_STATE_VERSION))
            )
        {
            return Err(INVALID_STATE.into());
        }
        if let Some(snapshots) = baseline.get("snapshots") {
            validate_map_values(snapshots, validate_baseline_summary)?;
        }
    }
    if let Some(value) = object.get("baseline_source_contributions") {
        validate_map_values(value, validate_baseline_contribution)?;
    }
    if let Some(value) = object.get("source_observations") {
        validate_map_values(value, |value| {
            validate_object(
                value,
                &[
                    "client",
                    "source_id",
                    "source_instance_id",
                    "last_seen_unix_ms",
                ],
            )?;
            require_fields(
                value,
                &[
                    "client",
                    "source_id",
                    "source_instance_id",
                    "last_seen_unix_ms",
                ],
            )?;
            Ok(())
        })?;
    }
    if let Some(value) = object.get("sqlite_ingestion_cursors") {
        validate_map_values(value, |value| {
            validate_object(
                value,
                &[
                    "client",
                    "source_id",
                    "source_instance_id",
                    "table",
                    "last_time_updated",
                    "observed_at_unix_ms",
                    "draining",
                    "continue_after_time_updated",
                ],
            )?;
            if let Some(cut) = value.get("continue_after_time_updated") {
                let valid = cut
                    .as_i64()
                    .zip(value["last_time_updated"].as_i64())
                    .is_some_and(|(cut, checkpoint)| cut <= checkpoint);
                if !valid
                    || value["draining"] != true
                    || value["client"] != "opencode"
                    || value["source_id"] != "opencode.sqlite"
                    || value["table"] != "session_message"
                {
                    return Err(INVALID_STATE.into());
                }
            }
            require_fields(
                value,
                &[
                    "client",
                    "source_id",
                    "source_instance_id",
                    "table",
                    "last_time_updated",
                    "observed_at_unix_ms",
                ],
            )?;
            Ok(())
        })?;
    }
    if let Some(value) = object.get("install_inventory")
        && !value.is_null()
    {
        validate_object(value, &["observed_at_unix_ms", "hash", "agents"])?;
        require_fields(value, &["observed_at_unix_ms", "hash", "agents"])?;
        let inventory = value.as_object().ok_or(INVALID_STATE)?;
        if let Some(agents) = inventory.get("agents") {
            let agents = agents.as_array().ok_or(INVALID_STATE)?;
            for agent in agents {
                validate_object(agent, &["agent", "installed", "confidence", "signals"])?;
                require_fields(agent, &["agent", "installed", "confidence", "signals"])?;
                let agent = agent.as_object().ok_or(INVALID_STATE)?;
                let signals = agent.get("signals").ok_or(INVALID_STATE)?;
                let signals = signals.as_array().ok_or(INVALID_STATE)?;
                for signal in signals {
                    validate_object(signal, &["kind", "name", "present", "path_hash"])?;
                    require_fields(signal, &["kind", "name", "present", "path_hash"])?;
                }
            }
        }
    }
    Ok(())
}

fn validate_baseline_contribution(value: &Value) -> Result<(), Box<dyn std::error::Error>> {
    validate_object(
        value,
        &[
            "client",
            "source_id",
            "source_instance_id",
            "source_fingerprint",
            "snapshots",
        ],
    )?;
    require_fields(
        value,
        &[
            "client",
            "source_id",
            "source_instance_id",
            "source_fingerprint",
            "snapshots",
        ],
    )?;
    let object = value.as_object().ok_or(INVALID_STATE)?;
    if let Some(snapshots) = object.get("snapshots") {
        validate_map_values(snapshots, validate_baseline_summary)?;
    }
    Ok(())
}

fn validate_baseline_summary(value: &Value) -> Result<(), Box<dyn std::error::Error>> {
    validate_object(
        value,
        &[
            "key",
            "observations",
            "tool_call_counts",
            "path_class_counts",
            "network_host_counts",
        ],
    )?;
    require_fields(
        value,
        &[
            "key",
            "observations",
            "tool_call_counts",
            "path_class_counts",
            "network_host_counts",
        ],
    )?;
    let object = value.as_object().ok_or(INVALID_STATE)?;
    validate_object(
        object.get("key").ok_or(INVALID_STATE)?,
        &["client", "agent", "model", "provider"],
    )?;
    require_fields(
        object.get("key").ok_or(INVALID_STATE)?,
        &["client", "agent", "model", "provider"],
    )?;
    validate_object(
        object.get("observations").ok_or(INVALID_STATE)?,
        &[
            "records",
            "user_messages",
            "assistant_messages",
            "tool_calls",
            "tool_results",
            "session_meta",
            "other",
        ],
    )?;
    require_fields(
        object.get("observations").ok_or(INVALID_STATE)?,
        &[
            "records",
            "user_messages",
            "assistant_messages",
            "tool_calls",
            "tool_results",
            "session_meta",
            "other",
        ],
    )?;
    for field in [
        "tool_call_counts",
        "path_class_counts",
        "network_host_counts",
    ] {
        if !object.get(field).is_some_and(Value::is_object) {
            return Err(INVALID_STATE.into());
        }
    }
    let hosts = object
        .get("network_host_counts")
        .and_then(Value::as_object)
        .ok_or(INVALID_STATE)?;
    if hosts.keys().any(|host| !valid_host_hash(host)) {
        return Err(INVALID_STATE.into());
    }
    Ok(())
}

fn validate_map_values(
    value: &Value,
    validate: impl Fn(&Value) -> Result<(), Box<dyn std::error::Error>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let map = value.as_object().ok_or(INVALID_STATE)?;
    for value in map.values() {
        validate(value)?;
    }
    Ok(())
}

fn validate_object(value: &Value, fields: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let object = value.as_object().ok_or(INVALID_STATE)?;
    validate_fields(object, fields)
}

fn require_fields(value: &Value, fields: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let object = value.as_object().ok_or(INVALID_STATE)?;
    if fields.iter().all(|field| object.contains_key(*field)) {
        Ok(())
    } else {
        Err(INVALID_STATE.into())
    }
}

fn valid_host_hash(value: &str) -> bool {
    value
        .strip_prefix(crate::baseline::BASELINE_HOST_HASH_PREFIX)
        .is_some_and(is_canonical_sha256_hex)
}

fn validate_fields(
    object: &serde_json::Map<String, Value>,
    fields: &[&str],
) -> Result<(), Box<dyn std::error::Error>> {
    if object.keys().all(|key| fields.contains(&key.as_str())) {
        Ok(())
    } else {
        Err(INVALID_STATE.into())
    }
}

fn has_raw_network_hosts(state: &ScanState) -> bool {
    state
        .baseline_snapshots
        .snapshots
        .values()
        .chain(
            state
                .baseline_source_contributions
                .values()
                .flat_map(|contribution| contribution.snapshots.values()),
        )
        .any(|snapshot| {
            snapshot
                .network_host_counts
                .keys()
                .any(|host| !valid_host_hash(host))
        })
}

fn parse_json(bytes: &[u8]) -> Result<Value, Box<dyn std::error::Error>> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = serde::de::DeserializeSeed::deserialize(ValueSeed, &mut deserializer)
        .map_err(|_| INVALID_STATE)?;
    deserializer.end().map_err(|_| INVALID_STATE)?;
    Ok(value)
}

struct ValueSeed;

impl<'de> serde::de::DeserializeSeed<'de> for ValueSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(ValueVisitor)
    }
}

struct ValueVisitor;

impl<'de> serde::de::Visitor<'de> for ValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("invalid JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Value::String(value.to_string()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A>(self, mut access: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = access.next_element_seed(ValueSeed)? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        let mut object = serde_json::Map::new();
        while let Some(key) = access.next_key::<String>()? {
            if object.contains_key(&key) {
                return Err(serde::de::Error::custom("duplicate JSON object key"));
            }
            object.insert(key, access.next_value_seed(ValueSeed)?);
        }
        Ok(Value::Object(object))
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
    sqlite_ingestion_cursor_key_for_instance(
        source.client.as_str(),
        &source.source_id,
        &source_instance_id(source),
        table,
    )
}

pub(crate) fn sqlite_ingestion_cursor_key_for_instance(
    client: &str,
    source_id: &str,
    source_instance_id: &str,
    table: &str,
) -> String {
    format!(
        "{}\u{1f}{}\u{1f}{}\u{1f}{}",
        client, source_id, source_instance_id, table
    )
}

fn source_instance_id(source: &Source) -> String {
    let mut hasher = Sha256::new();
    hasher.update(source.path.to_string_lossy().as_bytes());
    hex::encode(hasher.finalize())
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
        return hex::encode(hasher.finalize());
    }
    // Acquisition owns validity and progress. Fingerprinting must not reread a
    // rejected source into an unbounded allocation (including scanner errors).
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    if let Ok(mut file) = options.open(&source.path)
        && let Ok(metadata) = file.metadata()
        && metadata.is_file()
        && metadata.len() <= 128 * 1024 * 1024
    {
        use std::io::Read;
        let mut candidate = hasher.clone();
        let mut buffer = [0; 8192];
        let mut total = 0usize;
        loop {
            match file.read(&mut buffer) {
                Ok(0) => {
                    hasher = candidate;
                    break;
                }
                Ok(count) => {
                    total += count;
                    if total > 128 * 1024 * 1024 {
                        break;
                    }
                    candidate.update(&buffer[..count]);
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
    }
    hex::encode(hasher.finalize())
}

/// Kept among the detection fingerprints, so outage tracking needs no state
/// schema change; the prefix keeps it apart from any event fingerprint.
fn source_outage_fingerprint(client: &str) -> String {
    hex::encode(Sha256::digest(
        format!("telltale:source_parse_outage:{client}").as_bytes(),
    ))
}

/// Kept among the detection fingerprints, like the alert latches, so the
/// heartbeat needs no state schema change and older readers accept it. Event
/// fingerprints are hex digests and `telltale:<kind>:` keys, never this prefix.
const HEALTH_HEARTBEAT_PREFIX: &str = "telltale:health_heartbeat_v1@";

/// Kept among the detection fingerprints, so threshold suppression needs no
/// state schema change; the prefix keeps it apart from event fingerprints and
/// from `source_parse_outage`.
fn scanner_error_threshold_fingerprint() -> String {
    hex::encode(Sha256::digest(b"telltale:scanner_error_threshold_exceeded"))
}

pub fn detection_fingerprint(event: &Event, source_fingerprint: &str) -> String {
    let mut hasher = Sha256::new();
    hash_event_posture(&mut hasher, event, source_fingerprint);
    for evidence in &event.evidence {
        hash_evidence_item(&mut hasher, evidence);
    }
    hex::encode(hasher.finalize())
}

/// Dedup identity for canonical process-chain correlations. Their supporting
/// Event3 IDs (`correlated_event_ids`) are regenerated on every projection, so
/// they are not new evidence. Only links attributed to one of the event's rules
/// that also carries that rule's `canonical_observation_id` and
/// `correlation_process_step` evidence are omitted; every other item is
/// hashed. `None` keeps full-evidence [`detection_fingerprint`] dedup.
fn process_correlation_emission_fingerprint(
    event: &Event,
    source_fingerprint: &str,
) -> Option<String> {
    if event.event_type != "process_chain"
        || !event.signal_types.iter().any(|kind| kind == "correlation")
    {
        return None;
    }
    let generated_link = |item: &Evidence| {
        item.field == "correlated_event_ids"
            && item.rule_id.as_ref().is_some_and(|rule_id| {
                event.rule_ids.contains(rule_id)
                    && ["canonical_observation_id", "correlation_process_step"]
                        .iter()
                        .all(|field| {
                            event.evidence.iter().any(|support| {
                                support.field == *field && support.rule_id.as_ref() == Some(rule_id)
                            })
                        })
            })
    };
    if !event.evidence.iter().any(generated_link) {
        return None;
    }
    let mut hasher = Sha256::new();
    hash_event_posture(&mut hasher, event, source_fingerprint);
    for item in &event.evidence {
        if !generated_link(item) {
            hash_evidence_item(&mut hasher, item);
        }
    }
    Some(hex::encode(hasher.finalize()))
}

/// Dedup identity for `detection` emission only. Posture is always included:
/// identity, tool name, severity, score, rule ids, categories, and tags.
/// Only evidence explicitly classified as routine low-severity activity is
/// omitted. Unknown rules and unattributed evidence stay visible rather than
/// inheriting an aggregate event severity. Activities keep [`detection_fingerprint`].
fn detection_emission_fingerprint(
    event: &Event,
    source_fingerprint: &str,
    routine_evidence_rules: &BTreeSet<String>,
) -> String {
    let mut hasher = Sha256::new();
    hash_event_posture(&mut hasher, event, source_fingerprint);
    for evidence in &event.evidence {
        if detection_evidence_reemits(evidence, routine_evidence_rules) {
            hash_evidence_item(&mut hasher, evidence);
        }
    }
    hex::encode(hasher.finalize())
}

fn hash_event_posture(hasher: &mut Sha256, event: &Event, source_fingerprint: &str) {
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
}

fn hash_evidence_item(hasher: &mut Sha256, evidence: &Evidence) {
    hasher.update(evidence.field.as_bytes());
    hasher.update(evidence.redacted_value.as_bytes());
    if let Some(hash) = &evidence.hash {
        hasher.update(hash.as_bytes());
    }
}

fn detection_evidence_reemits(
    evidence: &Evidence,
    routine_evidence_rules: &BTreeSet<String>,
) -> bool {
    evidence.rule_id.as_deref().is_none_or(|rule_id| {
        rule_id == "network.download" || !routine_evidence_rules.contains(rule_id)
    })
}

fn classification_fingerprint(event: &Event) -> String {
    let mut hasher = Sha256::new();
    for values in [
        &event.detection_classes,
        &event.signal_types,
        &event.analytic_intents,
        &event.atlas_tags,
    ] {
        hasher.update((values.len() as u64).to_le_bytes());
        for value in values {
            hasher.update((value.len() as u64).to_le_bytes());
            hasher.update(value.as_bytes());
        }
    }
    hex::encode(hasher.finalize())
}

/// Dedup identity for `session_risk_summary` only. Evidence, including event
/// and tool-call counts, and event time are omitted so a growing session does
/// not re-emit while severity, score, and rule ids stay the same. Kept among
/// the detection fingerprints; the prefix keeps it apart from
/// [`detection_fingerprint`] and from latch markers.
fn session_risk_summary_fingerprint(event: &Event, source_fingerprint: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"telltale:session_risk_summary\0");
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
    for rule_id in &event.rule_ids {
        hasher.update(rule_id.as_bytes());
    }
    for category in &event.categories {
        hasher.update(category.as_bytes());
    }
    for tag in &event.tags {
        hasher.update(tag.as_bytes());
    }
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests;
