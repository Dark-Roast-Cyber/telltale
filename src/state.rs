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
use crate::event::Event;
use crate::file_lock::{
    FileInfo, SidecarLock, TempFile, atomic_no_replace, atomic_replace, read_snapshot,
    safe_path_info, validate_target,
};
use crate::install_inventory::InstallInventorySnapshot;
use telltale_schema::clients::SourceKind;
use telltale_schema::source::Source;

pub(crate) const STATE_SCHEMA_VERSION: &str = "1.0";
const MIGRATION_GUIDANCE: &str =
    "state requires explicit migration; run telltale migrate state --from <OLD> --to <NEW>";

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
    #[allow(dead_code)]
    pub fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let _lock = StateLock::acquire(path)?;
        Self::load_unlocked(path)
    }

    #[allow(dead_code)]
    pub fn save(&self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let _lock = StateLock::acquire(path)?;
        self.save_unlocked(path)
    }

    pub(crate) fn load_unlocked(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        if is_missing(path)? {
            Ok(Self::default())
        } else {
            parse_native_state(&read_snapshot(path)?)
        }
    }

    pub(crate) fn load_snapshot(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        if is_missing(path)? {
            Ok(Self::default())
        } else {
            parse_native_state(&read_snapshot(path)?)
        }
    }

    #[allow(dead_code)]
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

    pub(crate) fn prepare_save(
        &self,
        path: &Path,
    ) -> Result<PreparedState, Box<dyn std::error::Error>> {
        let bytes = native_state_bytes(self)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        validate_target(path)?;
        Ok(PreparedState {
            temp: Some(TempFile::write_and_sync(path, &bytes, 0o600)?),
        })
    }

    pub(crate) fn normalize_legacy_for_migration(&mut self) -> usize {
        let count = raw_network_host_count(self);
        self.hash_baseline_network_hosts_for_state();
        count
    }

    pub(crate) fn family_counts(&self) -> BTreeMap<&'static str, usize> {
        BTreeMap::from([
            (
                "seen_source_fingerprints",
                self.seen_source_fingerprints.len(),
            ),
            (
                "seen_detection_fingerprints",
                self.seen_detection_fingerprints.len(),
            ),
            (
                "baseline_snapshots",
                self.baseline_snapshots.snapshots.len(),
            ),
            (
                "baseline_source_contributions",
                self.baseline_source_contributions.len(),
            ),
            ("source_observations", self.source_observations.len()),
            (
                "sqlite_ingestion_cursors",
                self.sqlite_ingestion_cursors.len(),
            ),
            (
                "install_inventory_agents",
                self.install_inventory
                    .as_ref()
                    .map(|inventory| inventory.agents.len())
                    .unwrap_or_default(),
            ),
        ])
    }

    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        native_state_bytes(self)
    }

    #[allow(dead_code)]
    pub(crate) fn validate_native_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        parse_native_state(bytes)
    }

    pub(crate) fn validate_legacy_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        parse_legacy_state(bytes)
    }

    #[allow(dead_code)]
    pub(crate) fn validate_native_migration_bytes(
        bytes: &[u8],
    ) -> Result<Self, Box<dyn std::error::Error>> {
        parse_native_state_mode(bytes, true)
    }

    pub(crate) fn validate_native_migration_bytes_with_count(
        bytes: &[u8],
    ) -> Result<(Self, usize), Box<dyn std::error::Error>> {
        parse_native_state_mode_with_count(bytes, true)
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

pub(crate) struct PreparedState {
    temp: Option<TempFile>,
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

impl PreparedState {
    pub(crate) fn install_no_replace(
        mut self,
        destination: &Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        atomic_no_replace(
            self.temp.take().ok_or("state temporary already consumed")?,
            destination,
        )
    }
}

impl Drop for PreparedState {
    fn drop(&mut self) {
        let _ = self.temp.take();
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
    parse_native_state_mode(bytes, false)
}

fn parse_native_state_mode(
    bytes: &[u8],
    allow_legacy_baseline_version: bool,
) -> Result<ScanState, Box<dyn std::error::Error>> {
    parse_native_state_mode_with_count(bytes, allow_legacy_baseline_version).map(|(state, _)| state)
}

fn parse_native_state_mode_with_count(
    bytes: &[u8],
    allow_legacy_baseline_version: bool,
) -> Result<(ScanState, usize), Box<dyn std::error::Error>> {
    let value = parse_json(bytes)?;
    let object = value.as_object().ok_or(MIGRATION_GUIDANCE)?;
    let mut native_fields = vec!["state_schema_version"];
    native_fields.extend_from_slice(state_field_names());
    validate_fields(object, &native_fields)?;
    if object.get("state_schema_version") != Some(&Value::String(STATE_SCHEMA_VERSION.into())) {
        return Err(MIGRATION_GUIDANCE.into());
    }
    for field in state_field_names() {
        if !object.contains_key(*field) {
            return Err(MIGRATION_GUIDANCE.into());
        }
    }
    let strict_hosts = !allow_legacy_baseline_version;
    validate_state_families(&value, true, allow_legacy_baseline_version, strict_hosts)?;
    let mut state_object = object.clone();
    state_object.remove("state_schema_version");
    let mut state: ScanState =
        serde_json::from_value(Value::Object(state_object)).map_err(|_| MIGRATION_GUIDANCE)?;
    if strict_hosts && has_raw_network_hosts(&state)
        || (!allow_legacy_baseline_version
            && state.baseline_snapshots.schema_version != BASELINE_STATE_VERSION)
        || (allow_legacy_baseline_version
            && !matches!(
                state.baseline_snapshots.schema_version,
                1 | BASELINE_STATE_VERSION
            ))
    {
        return Err(MIGRATION_GUIDANCE.into());
    }
    let normalization_count = if allow_legacy_baseline_version {
        raw_network_host_count(&state)
    } else {
        0
    };
    state.hash_baseline_network_hosts_for_state();
    Ok((state, normalization_count))
}

fn parse_legacy_state(bytes: &[u8]) -> Result<ScanState, Box<dyn std::error::Error>> {
    let value = parse_json(bytes)?;
    let object = value.as_object().ok_or(MIGRATION_GUIDANCE)?;
    if object.contains_key("state_schema_version") {
        return Err(MIGRATION_GUIDANCE.into());
    }
    validate_fields(object, state_field_names())?;
    validate_state_families(&value, false, true, false)?;
    serde_json::from_value(value).map_err(|_| MIGRATION_GUIDANCE.into())
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

fn validate_state_families(
    value: &Value,
    native: bool,
    allow_legacy_baseline_version: bool,
    strict_hosts: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let object = value.as_object().ok_or(MIGRATION_GUIDANCE)?;
    if let Some(value) = object.get("baseline_snapshots") {
        validate_object(value, &["schema_version", "snapshots"])?;
        if native {
            require_fields(value, &["schema_version", "snapshots"])?;
        }
        let baseline = value.as_object().ok_or(MIGRATION_GUIDANCE)?;
        if let Some(version) = baseline.get("schema_version")
            && !matches!(version, Value::Number(number) if number.as_u64() == Some(BASELINE_STATE_VERSION as u64) || allow_legacy_baseline_version && number.as_u64() == Some(1))
        {
            return Err(MIGRATION_GUIDANCE.into());
        }
        if let Some(snapshots) = baseline.get("snapshots") {
            validate_map_values(snapshots, |value| {
                validate_baseline_summary(value, native, strict_hosts)
            })?;
        }
    }
    if let Some(value) = object.get("baseline_source_contributions") {
        validate_map_values(value, |value| {
            validate_baseline_contribution(value, native, strict_hosts)
        })?;
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
            if native {
                require_fields(
                    value,
                    &[
                        "client",
                        "source_id",
                        "source_instance_id",
                        "last_seen_unix_ms",
                    ],
                )?;
            }
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
                ],
            )?;
            if native {
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
            }
            Ok(())
        })?;
    }
    if let Some(value) = object.get("install_inventory")
        && !value.is_null()
    {
        validate_object(value, &["observed_at_unix_ms", "hash", "agents"])?;
        if native {
            require_fields(value, &["observed_at_unix_ms", "hash", "agents"])?;
        }
        let inventory = value.as_object().ok_or(MIGRATION_GUIDANCE)?;
        if let Some(agents) = inventory.get("agents") {
            let agents = agents.as_array().ok_or(MIGRATION_GUIDANCE)?;
            for agent in agents {
                validate_object(agent, &["agent", "installed", "confidence", "signals"])?;
                if native {
                    require_fields(agent, &["agent", "installed", "confidence", "signals"])?;
                }
                let agent = agent.as_object().ok_or(MIGRATION_GUIDANCE)?;
                let signals = agent.get("signals").ok_or(MIGRATION_GUIDANCE)?;
                let signals = signals.as_array().ok_or(MIGRATION_GUIDANCE)?;
                for signal in signals {
                    validate_object(signal, &["kind", "name", "present", "path_hash"])?;
                    if native {
                        require_fields(signal, &["kind", "name", "present", "path_hash"])?;
                    }
                }
            }
        }
    }
    Ok(())
}

fn validate_baseline_contribution(
    value: &Value,
    native: bool,
    strict_hosts: bool,
) -> Result<(), Box<dyn std::error::Error>> {
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
    if native {
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
    }
    let object = value.as_object().ok_or(MIGRATION_GUIDANCE)?;
    if let Some(snapshots) = object.get("snapshots") {
        validate_map_values(snapshots, |value| {
            validate_baseline_summary(value, native, strict_hosts)
        })?;
    }
    Ok(())
}

fn validate_baseline_summary(
    value: &Value,
    native: bool,
    strict_hosts: bool,
) -> Result<(), Box<dyn std::error::Error>> {
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
    if native {
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
    }
    let object = value.as_object().ok_or(MIGRATION_GUIDANCE)?;
    validate_object(
        object.get("key").ok_or(MIGRATION_GUIDANCE)?,
        &["client", "agent", "model", "provider"],
    )?;
    if native {
        require_fields(
            object.get("key").ok_or(MIGRATION_GUIDANCE)?,
            &["client", "agent", "model", "provider"],
        )?;
    }
    validate_object(
        object.get("observations").ok_or(MIGRATION_GUIDANCE)?,
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
    if native {
        require_fields(
            object.get("observations").ok_or(MIGRATION_GUIDANCE)?,
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
    }
    for field in [
        "tool_call_counts",
        "path_class_counts",
        "network_host_counts",
    ] {
        if !object.get(field).is_some_and(Value::is_object) {
            return Err(MIGRATION_GUIDANCE.into());
        }
    }
    if native && strict_hosts {
        let hosts = object
            .get("network_host_counts")
            .and_then(Value::as_object)
            .ok_or(MIGRATION_GUIDANCE)?;
        if hosts.keys().any(|host| !valid_host_hash(host)) {
            return Err(MIGRATION_GUIDANCE.into());
        }
    }
    Ok(())
}

fn validate_map_values(
    value: &Value,
    validate: impl Fn(&Value) -> Result<(), Box<dyn std::error::Error>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let map = value.as_object().ok_or(MIGRATION_GUIDANCE)?;
    for value in map.values() {
        validate(value)?;
    }
    Ok(())
}

fn validate_object(value: &Value, fields: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let object = value.as_object().ok_or(MIGRATION_GUIDANCE)?;
    validate_fields(object, fields)
}

fn require_fields(value: &Value, fields: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let object = value.as_object().ok_or(MIGRATION_GUIDANCE)?;
    if fields.iter().all(|field| object.contains_key(*field)) {
        Ok(())
    } else {
        Err(MIGRATION_GUIDANCE.into())
    }
}

fn valid_host_hash(value: &str) -> bool {
    let Some(hex) = value.strip_prefix(crate::baseline::BASELINE_HOST_HASH_PREFIX) else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_fields(
    object: &serde_json::Map<String, Value>,
    fields: &[&str],
) -> Result<(), Box<dyn std::error::Error>> {
    if object.keys().all(|key| fields.contains(&key.as_str())) {
        Ok(())
    } else {
        Err(MIGRATION_GUIDANCE.into())
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

fn raw_network_host_count(state: &ScanState) -> usize {
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
        .map(|snapshot| {
            snapshot
                .network_host_counts
                .keys()
                .filter(|host| !valid_host_hash(host))
                .count()
        })
        .sum()
}

fn parse_json(bytes: &[u8]) -> Result<Value, Box<dyn std::error::Error>> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = serde::de::DeserializeSeed::deserialize(ValueSeed, &mut deserializer)
        .map_err(|_| MIGRATION_GUIDANCE)?;
    deserializer.end().map_err(|_| MIGRATION_GUIDANCE)?;
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

    use serde_json::Value;

    use crate::baseline::{
        BASELINE_HOST_HASH_PREFIX, BaselineKey, BaselineObservationTotals, BaselineSummary,
        PathClass, baseline_host_identity,
    };
    use crate::event::{DetectionEventInput, Evidence, detection_event};
    use telltale_schema::clients::{ClientId, SourceKind};
    use telltale_schema::source::Source;

    use super::{
        BASELINE_STATE_VERSION, STATE_SCHEMA_VERSION, ScanState, baseline_snapshot_id,
        detection_fingerprint, source_fingerprint,
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
    fn rejects_empty_state_file_with_migration_guidance() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("empty-state.json");
        std::fs::write(&path, "").expect("write empty");

        let error = ScanState::load(&path).expect_err("empty state must fail");
        assert!(error.to_string().contains("migrate state"));
    }

    #[test]
    fn accepts_legacy_state_only_through_explicit_validation() {
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

        let state = ScanState::validate_legacy_bytes(&std::fs::read(&path).expect("read"))
            .expect("validate legacy");

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
    fn legacy_scan_state_golden_covers_all_serialized_families_semantically() {
        let fixture: Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/state/legacy-scan-state.json"
        )))
        .expect("legacy state fixture");
        for field in [
            "seen_source_fingerprints",
            "seen_detection_fingerprints",
            "baseline_snapshots",
            "baseline_source_contributions",
            "source_observations",
            "sqlite_ingestion_cursors",
            "install_inventory",
        ] {
            assert!(fixture.get(field).is_some(), "missing state family {field}");
        }

        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("legacy-scan-state.json");
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&fixture).expect("fixture JSON"),
        )
        .expect("write state fixture");

        let mut state = ScanState::validate_legacy_bytes(&std::fs::read(&path).expect("read"))
            .expect("validate legacy");
        state.normalize_legacy_for_migration();
        let normalized = serde_json::to_value(&state).expect("state value");
        assert_ne!(
            normalized, fixture,
            "raw baseline host is normalized on load"
        );
        assert_eq!(
            normalized["baseline_source_contributions"]
                .as_object()
                .expect("source contributions")
                .values()
                .next()
                .expect("source contribution")["snapshots"]
                .as_object()
                .expect("contribution snapshots")
                .values()
                .next()
                .expect("contribution snapshot")["network_host_counts"]
                [baseline_host_identity("internal.example.test")],
            1
        );
        assert!(
            !serde_json::to_string(&normalized)
                .expect("normalized state JSON")
                .contains("internal.example.test")
        );

        state.save(&path).expect("save state fixture");
        let saved: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("saved state"))
                .expect("saved state JSON");
        assert_eq!(saved["state_schema_version"], STATE_SCHEMA_VERSION);
        assert_eq!(
            saved["seen_source_fingerprints"],
            normalized["seen_source_fingerprints"]
        );
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

        let mut state = ScanState::validate_legacy_bytes(&std::fs::read(&path).expect("read"))
            .expect("validate legacy");
        state.normalize_legacy_for_migration();
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

    #[test]
    fn native_state_requires_version_and_rejects_recursive_unknown_fields() {
        let state = ScanState::default();
        let native = state.canonical_bytes().expect("native bytes");
        assert!(ScanState::validate_native_bytes(&native).is_ok());

        let mut observed = ScanState::default();
        observed.source_observations.insert(
            "source".to_string(),
            super::SourceObservation {
                client: "codex".to_string(),
                source_id: "source".to_string(),
                source_instance_id: "instance".to_string(),
                last_seen_unix_ms: 1,
            },
        );
        let mut missing_nested = serde_json::to_value(&observed).expect("state value");
        missing_nested["source_observations"]["source"]
            .as_object_mut()
            .expect("observation")
            .remove("source_instance_id");
        missing_nested["state_schema_version"] = Value::String(STATE_SCHEMA_VERSION.to_string());
        assert!(
            ScanState::validate_native_bytes(
                &serde_json::to_vec(&missing_nested).expect("missing nested bytes")
            )
            .is_err()
        );

        let mut unversioned = serde_json::to_value(&state).expect("state value");
        assert!(
            ScanState::validate_native_bytes(
                &serde_json::to_vec(&unversioned).expect("unversioned bytes")
            )
            .is_err()
        );

        unversioned["baseline_snapshots"]["unexpected"] = Value::Bool(true);
        assert!(
            ScanState::validate_legacy_bytes(
                &serde_json::to_vec(&unversioned).expect("unknown bytes")
            )
            .is_err()
        );

        let duplicate = br#"{"seen_source_fingerprints":[],"seen_source_fingerprints":[]}"#;
        assert!(ScanState::validate_legacy_bytes(duplicate).is_err());
    }

    #[test]
    fn native_state_rejects_raw_network_hosts() {
        let raw = br#"{
          "state_schema_version":"1.0",
          "seen_source_fingerprints":[],
          "seen_detection_fingerprints":[],
          "baseline_snapshots":{"schema_version":2,"snapshots":{"id":{"key":{"client":"codex","agent":null,"model":null,"provider":null},"observations":{"records":1,"user_messages":0,"assistant_messages":0,"tool_calls":1,"tool_results":0,"session_meta":0,"other":0},"tool_call_counts":{},"path_class_counts":{},"network_host_counts":{"internal.example":1}}}},
          "baseline_source_contributions":{},"source_observations":{},"sqlite_ingestion_cursors":{},"install_inventory":null
        }"#;
        assert!(ScanState::validate_native_bytes(raw).is_err());
        let malformed_hash = String::from_utf8(raw.to_vec())
            .expect("utf8")
            .replace("internal.example", "sha256:ABC")
            .into_bytes();
        assert!(ScanState::validate_native_bytes(&malformed_hash).is_err());
    }

    #[test]
    fn migration_hashes_malformed_prefixed_hosts_before_strict_reparse() {
        let mut value: Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/state/legacy-scan-state.json"
        )))
        .expect("legacy fixture");
        value["state_schema_version"] = Value::String(STATE_SCHEMA_VERSION.to_string());
        let bytes = serde_json::to_vec(&value).expect("native migration input");
        let bytes = String::from_utf8(bytes)
            .expect("fixture utf8")
            .replace("internal.example.test", "sha256:ABC")
            .into_bytes();
        let state = ScanState::validate_native_migration_bytes(&bytes).expect("migration input");
        let canonical = state.canonical_bytes().expect("canonical bytes");
        assert!(ScanState::validate_native_bytes(&canonical).is_ok());
        assert!(!String::from_utf8_lossy(&canonical).contains("sha256:ABC"));
    }
}
