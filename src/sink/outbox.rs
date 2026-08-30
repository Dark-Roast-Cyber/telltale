use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::jsonl::JsonlGeneration;
use super::{DeliveryError, DeliveryErrorClass};
use crate::event::{
    Event, NATIVE_SCHEMA_VERSION, PrivacySanitizer, SanitizationContext,
    check_serialized_event_markers, serialize_event_for_emission,
};
use crate::file_lock::{
    PinnedFile, SidecarLock, open_pinned_read, paths_identity_equivalent, remove_verified_file,
    stable_file_identity, sync_parent,
};

const OUTBOX_SCHEMA_VERSION: i64 = 6;
const OUTBOX_DIRECTORY_MODE: u32 = 0o700;
const OUTBOX_DATABASE_MODE: u32 = 0o600;
const CURSOR_INTEGRITY_WINDOW: usize = 4 * 1024;
const MAX_CURSOR_TEXT: usize = 128;
const MAX_RETRY_DELAY_MILLIS: u64 = 24 * 60 * 60 * 1_000;
const MAX_CAPACITY_SCAN_BYTES: u64 = 64 * 1024 * 1024;
const CAPACITY_READ_CHUNK_BYTES: usize = 64 * 1024;

pub(crate) const WINDOWS_DURABLE_STORAGE_UNSUPPORTED: &str =
    "persistent durable-delivery private storage is not supported on Windows yet";

#[cfg(windows)]
const CURRENT_PLATFORM_IS_WINDOWS: bool = true;
#[cfg(not(windows))]
const CURRENT_PLATFORM_IS_WINDOWS: bool = false;

pub(crate) fn current_platform_is_windows() -> bool {
    CURRENT_PLATFORM_IS_WINDOWS
}

/// Persistent durable delivery has no supported private-storage profile on
/// Windows yet. Keep this policy separate from the filesystem checks so the
/// decision is deterministic and testable on a non-Windows host.
pub(crate) fn ensure_durable_storage_supported() -> Result<(), Box<dyn std::error::Error>> {
    ensure_durable_storage_supported_for_platform(CURRENT_PLATFORM_IS_WINDOWS)
}

pub(crate) fn ensure_durable_storage_supported_for_platform(
    is_windows: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if is_windows {
        return Err(Box::new(DeliveryError::new(
            DeliveryErrorClass::DurableStorage,
            0,
            WINDOWS_DURABLE_STORAGE_UNSUPPORTED,
        )));
    }
    Ok(())
}

pub(crate) const DEFAULT_MAX_PENDING_EVENTS: u64 = 100_000;
pub(crate) const DEFAULT_MAX_PENDING_BYTES: u64 = 512 * 1024 * 1024;

/// Acquire the per-outbox admission owner. Durable writers hold this sidecar
/// lock from recovery and capacity inspection through the canonical append and
/// follow-up reconciliation. It coordinates local Telltale writers without
/// making the outbox a distributed lock service.
pub(crate) fn acquire_admission_lock(
    path: &Path,
) -> Result<SidecarLock, Box<dyn std::error::Error>> {
    acquire_admission_lock_for_platform(path, CURRENT_PLATFORM_IS_WINDOWS)
}

fn acquire_admission_lock_for_platform(
    path: &Path,
    is_windows: bool,
) -> Result<SidecarLock, Box<dyn std::error::Error>> {
    ensure_durable_storage_supported_for_platform(is_windows)?;
    ensure_private_parent(path_parent(path))?;
    SidecarLock::acquire_lock_only(path)
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct CapacityLimits {
    pub(crate) max_pending_events: u64,
    pub(crate) max_pending_bytes: u64,
}

impl Default for CapacityLimits {
    fn default() -> Self {
        Self {
            max_pending_events: DEFAULT_MAX_PENDING_EVENTS,
            max_pending_bytes: DEFAULT_MAX_PENDING_BYTES,
        }
    }
}

/// Explicit SQLite settings used by every outbox connection.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct OutboxOpenProfile {
    pub(crate) busy_timeout: Duration,
    pub(crate) journal_mode: &'static str,
    pub(crate) synchronous: &'static str,
}

pub(crate) const OUTBOX_OPEN_PROFILE: OutboxOpenProfile = OutboxOpenProfile {
    busy_timeout: Duration::from_millis(5_000),
    journal_mode: "delete",
    synchronous: "full",
};

/// Reject a durable outbox path that can resolve to the canonical JSONL
/// journal. This runs before the outbox parent, database, or admission sidecar
/// is created. The rollback-journal name is checked as well because the
/// selected DELETE journal mode can create it during SQLite transactions.
pub(crate) fn validate_outbox_jsonl_paths(
    outbox_path: &Path,
    jsonl_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let jsonl_lock_path = path_with_suffix(jsonl_path, ".lock");
    let jsonl_candidates = [
        (jsonl_path, "canonical JSONL path"),
        (&jsonl_lock_path, "canonical JSONL coordination sidecar"),
    ];
    let mut sqlite_candidates = vec![(outbox_path, "durable outbox path")];
    let journal_path = OUTBOX_OPEN_PROFILE
        .journal_mode
        .eq_ignore_ascii_case("delete")
        .then(|| path_with_suffix(outbox_path, "-journal"));
    if let Some(journal_path) = journal_path.as_ref() {
        sqlite_candidates.push((journal_path, "durable outbox rollback journal path"));
    }

    for (sqlite_path, sqlite_name) in &sqlite_candidates {
        for (jsonl_path, jsonl_name) in &jsonl_candidates {
            if paths_identity_equivalent(sqlite_path, jsonl_path)? {
                return Err(storage_message(format!(
                    "{sqlite_name} collides with {jsonl_name}"
                )));
            }
        }
    }
    Ok(())
}

/// Validate the private outbox path without creating a missing parent or
/// opening the database. Missing path components remain valid prospective
/// storage; existing components and an existing database retain the same
/// private ownership/mode checks used during activation.
pub(crate) fn validate_outbox_path_without_activation(
    outbox_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let parent = path_parent(outbox_path);
    match fs::symlink_metadata(parent) {
        Ok(_) => validate_private_directory(parent)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    match fs::symlink_metadata(outbox_path) {
        Ok(_) => validate_private_database(outbox_path)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn path_with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct CanonicalPayload {
    pub(crate) event_id: String,
    pub(crate) bytes: Vec<u8>,
    pub(crate) hash: [u8; 32],
    pub(crate) generation_id: Option<String>,
    pub(crate) generation_offset: Option<u64>,
}

/// The one terminal serialization produced for a prospective durable batch.
/// The payloads are used for capacity accounting; the newline-terminated bytes
/// are handed to the canonical JSONL sink so the event is not serialized again
/// between the capacity check and the durable first write.
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct CanonicalReplayBatch {
    pub(crate) payloads: Vec<CanonicalPayload>,
    pub(crate) jsonl_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct OutboxEvent {
    pub(crate) event_id: String,
    pub(crate) payload: Vec<u8>,
    pub(crate) payload_hash: [u8; 32],
    pub(crate) created_at: i64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum DeliveryState {
    Pending,
    Acked,
    Blocked,
    Dead,
}

/// Durable lifecycle of a JSONL generation. The database keeps this metadata
/// after the corresponding file is removed so a historical generation cannot
/// be silently accepted again.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum GenerationLifecycle {
    Present,
    PrunePending,
    Pruned,
}

impl GenerationLifecycle {
    fn from_str(value: &str) -> Option<Self> {
        match value {
            "present" => Some(Self::Present),
            "prune_pending" => Some(Self::PrunePending),
            "pruned" => Some(Self::Pruned),
            _ => None,
        }
    }
}

impl DeliveryState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Acked => "acked",
            Self::Blocked => "blocked",
            Self::Dead => "dead",
        }
    }

    fn from_str(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "acked" => Some(Self::Acked),
            "blocked" => Some(Self::Blocked),
            "dead" => Some(Self::Dead),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct DeliveryRow {
    pub(crate) event_id: String,
    pub(crate) sink_id: String,
    pub(crate) state: DeliveryState,
    pub(crate) attempts: u32,
    pub(crate) next_attempt_at: Option<i64>,
    pub(crate) last_error_class: Option<DeliveryErrorClass>,
    pub(crate) updated_at: i64,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct DurableSinkHealth {
    pub(crate) sink_id: String,
    /// Pending includes retry-delayed and blocked deliveries. Acked and dead
    /// deliveries are terminal and are excluded.
    pub(crate) pending_depth: u64,
    pub(crate) pending_bytes: u64,
    pub(crate) oldest_pending_age_seconds: Option<u64>,
    pub(crate) dead_count: u64,
    pub(crate) last_success_at: Option<i64>,
    pub(crate) last_error_at: Option<i64>,
    pub(crate) last_error_class: Option<DeliveryErrorClass>,
    pub(crate) last_error_status: Option<u16>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct DurableHealth {
    pub(crate) sinks: Vec<DurableSinkHealth>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct DeliveryUpdate {
    pub(crate) state: DeliveryState,
    pub(crate) attempts: u32,
    pub(crate) next_attempt_at: Option<i64>,
    pub(crate) last_error_class: Option<DeliveryErrorClass>,
    pub(crate) updated_at: i64,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct ReadyDelivery {
    pub(crate) row: DeliveryRow,
    pub(crate) payload: Vec<u8>,
}

/// Clock used by the durable scheduler. Values are Unix milliseconds so a
/// configured sub-second backoff cannot collapse into an immediate retry.
pub(crate) trait DeliveryClock {
    fn now_millis(&self) -> i64;
}

pub(crate) struct SystemDeliveryClock;

impl DeliveryClock for SystemDeliveryClock {
    fn now_millis(&self) -> i64 {
        unix_millis()
    }
}

/// Durable position in the canonical JSONL journal. The hashes cover bounded
/// bytes immediately before the position and at the beginning of the
/// generation; the file identity covers coordinated rename versus replacement.
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct IngestCursor {
    pub(crate) journal_namespace: String,
    pub(crate) journal_path_hash: String,
    pub(crate) generation_id: String,
    pub(crate) byte_offset: u64,
    pub(crate) observed_length: u64,
    pub(crate) window_start: u64,
    pub(crate) prefix_hash: [u8; 32],
    pub(crate) window_hash: [u8; 32],
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct ReconcileResult {
    pub(crate) ingested_events: usize,
    pub(crate) ingested_bytes: usize,
}

#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub(crate) struct PruneReport {
    pub(crate) pruned: usize,
    pub(crate) finalized_pending: usize,
    pub(crate) protected: usize,
    pub(crate) warnings: Vec<String>,
}

pub(crate) type MaintenanceResult = PruneReport;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
struct CapacityUsage {
    events: u64,
    bytes: u64,
}

#[derive(Debug, Default)]
struct CapacityInspection {
    base: CapacityUsage,
    payloads: BTreeMap<String, Vec<u8>>,
}

#[derive(Debug)]
pub(crate) struct Outbox {
    connection: Connection,
    #[cfg(test)]
    fail_next_prune_deletion: bool,
    #[cfg(test)]
    capacity_scan_limit: u64,
}

impl Outbox {
    pub(crate) fn open(path: impl AsRef<Path>) -> Result<Self, Box<dyn std::error::Error>> {
        Self::open_for_platform(path, CURRENT_PLATFORM_IS_WINDOWS)
    }

    fn open_for_platform(
        path: impl AsRef<Path>,
        is_windows: bool,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        ensure_durable_storage_supported_for_platform(is_windows)?;
        let path = path.as_ref();
        let parent = path_parent(path);
        ensure_private_parent(parent).map_err(|error| storage_error("private path", error))?;

        let exists = match fs::symlink_metadata(path) {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(storage_error("inspect database", error)),
        };
        if !exists {
            create_private_database(path)
                .map_err(|error| storage_error("create database", error))?;
        }
        validate_private_database(path)
            .map_err(|error| storage_error("validate database", error))?;

        let mut connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)
            .map_err(|error| storage_error("open database", error))?;
        configure_connection(&connection)?;
        migrate_schema(&mut connection)?;
        Ok(Self {
            connection,
            #[cfg(test)]
            fail_next_prune_deletion: false,
            #[cfg(test)]
            capacity_scan_limit: MAX_CAPACITY_SCAN_BYTES,
        })
    }

    /// Open an existing outbox without migration or any write-capable SQLite
    /// operation. Health reporting uses this path so a locked or damaged
    /// database is reported rather than repaired or changed as a side effect.
    pub(crate) fn open_read_only(
        path: impl AsRef<Path>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::open_read_only_for_platform(path, CURRENT_PLATFORM_IS_WINDOWS)
    }

    fn open_read_only_for_platform(
        path: impl AsRef<Path>,
        is_windows: bool,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        ensure_durable_storage_supported_for_platform(is_windows)?;
        let path = path.as_ref();
        validate_private_database(path)
            .map_err(|error| storage_error("validate database for health", error))?;
        let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|error| storage_error("open database for health", error))?;
        configure_read_only_connection(&connection)?;
        Ok(Self {
            connection,
            #[cfg(test)]
            fail_next_prune_deletion: false,
            #[cfg(test)]
            capacity_scan_limit: MAX_CAPACITY_SCAN_BYTES,
        })
    }

    /// Return bounded metadata-only health for the configured sinks. Pending
    /// means Pending or Blocked, including retry-delayed rows; Acked and Dead
    /// are terminal and excluded. Payload bytes are used only through SQLite's
    /// length metadata and are never loaded or inspected.
    pub(crate) fn health(
        &self,
        sink_ids: &[&str],
        now_seconds: i64,
    ) -> Result<DurableHealth, Box<dyn std::error::Error>> {
        ensure_durable_storage_supported()?;
        let sink_ids = if sink_ids.is_empty() {
            let mut statement = self
                .connection
                .prepare("SELECT sink_id FROM sink_health ORDER BY sink_id")
                .map_err(|error| storage_error("list durable health sinks", error))?;
            let rows = statement
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(|error| storage_error("list durable health sinks", error))?;
            let mut discovered = Vec::new();
            for row in rows {
                discovered
                    .push(row.map_err(|error| storage_error("list durable health sinks", error))?);
            }
            discovered
        } else {
            validate_sink_ids(sink_ids, false)?
        };
        let mut sinks = Vec::with_capacity(sink_ids.len());
        for sink_id in sink_ids {
            let (pending_depth, pending_bytes, oldest_created_at, dead_count) = self
                .connection
                .query_row(
                    "SELECT
                         COUNT(CASE WHEN state IN ('pending', 'blocked') THEN 1 END),
                         COALESCE(SUM(CASE WHEN state IN ('pending', 'blocked')
                                           THEN length(events.payload) ELSE 0 END), 0),
                         MIN(CASE WHEN state IN ('pending', 'blocked')
                                  THEN events.created_at END),
                         COUNT(CASE WHEN state = 'dead' THEN 1 END)
                     FROM deliveries
                     JOIN events ON events.event_id = deliveries.event_id
                     WHERE deliveries.sink_id = ?1",
                    params![&sink_id],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, Option<i64>>(2)?,
                            row.get::<_, i64>(3)?,
                        ))
                    },
                )
                .map_err(|error| storage_error("query durable health", error))?;
            let pending_depth = u64::try_from(pending_depth)
                .map_err(|_| storage_message("durable pending depth is invalid"))?;
            let pending_bytes = u64::try_from(pending_bytes)
                .map_err(|_| storage_message("durable pending bytes are invalid"))?;
            let dead_count = u64::try_from(dead_count)
                .map_err(|_| storage_message("durable dead count is invalid"))?;
            let oldest_pending_age_seconds = oldest_created_at.map(|created_at| {
                u64::try_from(now_seconds.saturating_sub(created_at).max(0)).unwrap_or(u64::MAX)
            });
            let (last_success_at, last_error_at, error_class, error_status) = self
                .connection
                .query_row(
                    "SELECT last_success_at, last_error_at, last_error_class,
                            last_error_status
                     FROM sink_health WHERE sink_id = ?1",
                    params![&sink_id],
                    |row| {
                        Ok((
                            row.get::<_, Option<i64>>(0)?,
                            row.get::<_, Option<i64>>(1)?,
                            row.get::<_, Option<String>>(2)?,
                            row.get::<_, Option<i64>>(3)?,
                        ))
                    },
                )
                .optional()
                .map_err(|error| storage_error("query sink health history", error))?
                .unwrap_or((None, None, None, None));
            let last_error_class = decode_error_class(error_class.as_deref(), error_status)?;
            let last_error_status = error_status
                .map(u16::try_from)
                .transpose()
                .map_err(|_| storage_message("stored sink health error status is invalid"))?;
            sinks.push(DurableSinkHealth {
                sink_id,
                pending_depth,
                pending_bytes,
                oldest_pending_age_seconds,
                dead_count,
                last_success_at,
                last_error_at,
                last_error_class,
                last_error_status,
            });
        }
        Ok(DurableHealth { sinks })
    }

    pub(crate) fn check_capacity_for_payloads(
        &self,
        log_path: &Path,
        prospective: &[CanonicalPayload],
        limits: CapacityLimits,
    ) -> Result<(), Box<dyn std::error::Error>> {
        validate_capacity_limits(limits)?;
        let _log_lock = SidecarLock::acquire_lock_only(log_path)
            .map_err(|error| storage_error("lock canonical JSONL for capacity", error))?;
        self.check_capacity_payloads_locked(log_path, prospective, limits)
    }

    fn capacity_scan_limit(&self) -> u64 {
        #[cfg(test)]
        {
            self.capacity_scan_limit
        }
        #[cfg(not(test))]
        {
            MAX_CAPACITY_SCAN_BYTES
        }
    }

    fn check_capacity_payloads_locked(
        &self,
        log_path: &Path,
        prospective: &[CanonicalPayload],
        limits: CapacityLimits,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let inspection = self.inspect_capacity_inputs(log_path)?;
        let mut seen_payloads = inspection.payloads;
        let mut prospective_usage = CapacityUsage::default();

        for payload in prospective {
            validate_capacity_payload(payload)?;
            if event_is_already_stored(&self.connection, payload)? {
                continue;
            }
            if let Some(previous) = seen_payloads.get(&payload.event_id) {
                if previous != &payload.bytes {
                    return Err(payload_collision_error());
                }
                continue;
            }
            seen_payloads.insert(payload.event_id.clone(), payload.bytes.clone());
            prospective_usage.events = prospective_usage
                .events
                .checked_add(1)
                .ok_or_else(|| storage_message("durable capacity event count overflow"))?;
            prospective_usage.bytes = prospective_usage
                .bytes
                .checked_add(
                    u64::try_from(payload.bytes.len())
                        .map_err(|_| storage_message("durable capacity byte count is too large"))?,
                )
                .ok_or_else(|| storage_message("durable capacity byte count overflow"))?;
        }

        self.check_capacity_totals(inspection.base, prospective_usage, limits)
    }

    fn inspect_capacity_inputs(
        &self,
        log_path: &Path,
    ) -> Result<CapacityInspection, Box<dyn std::error::Error>> {
        let namespace = journal_namespace(&self.connection)?;
        let path_hash = journal_path_hash(log_path);
        let journal_bound = verify_journal_path_for_capacity(&self.connection, &path_hash)?;
        let generations = super::jsonl::discover_jsonl_generations(log_path)
            .map_err(|error| storage_error("discover JSONL generations for capacity", error))?;
        validate_generation_metadata_readonly(
            &self.connection,
            &path_hash,
            &generations,
            !journal_bound,
        )?;
        let cursor = read_ingest_cursor(&self.connection)?;
        let pending = query_pending_capacity(&self.connection)?;
        let unread = inspect_unread_jsonl_capacity(
            &self.connection,
            &generations,
            cursor.as_ref(),
            &namespace,
            &path_hash,
            self.capacity_scan_limit(),
        )?;
        let base = CapacityUsage {
            events: pending
                .events
                .checked_add(unread.base.events)
                .ok_or_else(|| storage_message("durable capacity event count overflow"))?,
            bytes: pending
                .bytes
                .checked_add(unread.base.bytes)
                .ok_or_else(|| storage_message("durable capacity byte count overflow"))?,
        };
        Ok(CapacityInspection {
            base,
            payloads: unread.payloads,
        })
    }

    fn check_capacity_totals(
        &self,
        base: CapacityUsage,
        projected: CapacityUsage,
        limits: CapacityLimits,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // A pre-existing queue may be over a newly lowered limit. It is still
        // safe to reconcile already accepted JSONL in that state; only a
        // prospective batch that adds unique queue usage is rejected.
        if projected.events == 0 && projected.bytes == 0 {
            return Ok(());
        }
        let total_events = base
            .events
            .checked_add(projected.events)
            .ok_or_else(|| storage_message("durable capacity event count overflow"))?;
        let total_bytes = base
            .bytes
            .checked_add(projected.bytes)
            .ok_or_else(|| storage_message("durable capacity byte count overflow"))?;
        if total_events > limits.max_pending_events {
            return Err(capacity_exceeded_error(
                "pending_events",
                base.events,
                total_events,
                limits.max_pending_events,
            ));
        }
        if total_bytes > limits.max_pending_bytes {
            return Err(capacity_exceeded_error(
                "pending_bytes",
                base.bytes,
                total_bytes,
                limits.max_pending_bytes,
            ));
        }
        Ok(())
    }

    #[cfg(all(test, not(windows)))]
    pub(crate) fn insert_event(
        &mut self,
        event: &Event,
        sink_ids: &[&str],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let payload = canonical_payload(event)?;
        let sink_ids = validate_sink_ids(sink_ids, true)?;

        let transaction = self
            .connection
            .transaction()
            .map_err(|error| storage_error("begin event insert", error))?;
        insert_payload_transaction(&transaction, &payload, &sink_ids)?;

        transaction
            .commit()
            .map_err(|error| storage_error("commit event insert", error))?;
        Ok(())
    }

    /// Reconcile complete canonical JSONL records from the persisted cursor.
    /// Event rows, per-sink rows, and cursor advancement share one SQLite
    /// transaction; a malformed record or storage failure therefore leaves the
    /// cursor at its previous committed position.
    pub(crate) fn reconcile_jsonl(
        &mut self,
        log_path: &Path,
        sink_ids: &[&str],
    ) -> Result<ReconcileResult, Box<dyn std::error::Error>> {
        let sink_ids = validate_sink_ids(sink_ids, false)?;
        let path_hash = journal_path_hash(log_path);
        let _log_lock = SidecarLock::acquire_lock_only(log_path)
            .map_err(|error| storage_error("lock canonical JSONL", error))?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| storage_error("begin JSONL ingest", error))?;
        let current_cursor = read_ingest_cursor(&transaction)?;
        let generations = super::jsonl::discover_jsonl_generations(log_path)
            .map_err(|error| storage_error("discover JSONL generations", error))?;

        let namespace = journal_namespace(&transaction)?;
        ensure_journal_path(&transaction, &path_hash)?;
        ensure_sink_identities(&transaction, &sink_ids)?;
        ensure_generation_metadata(&transaction, &path_hash, &generations, &sink_ids)?;

        if generations.is_empty() {
            if current_cursor.is_some() {
                return Err(storage_message(
                    "durable ingest cursor generation is missing",
                ));
            }
            transaction
                .commit()
                .map_err(|error| storage_error("commit empty JSONL ingest", error))?;
            return Ok(ReconcileResult {
                ingested_events: 0,
                ingested_bytes: 0,
            });
        }

        let snapshots = generations
            .iter()
            .map(|generation| {
                let mut file = open_pinned_read(&generation.path)
                    .map_err(|error| storage_error("open JSONL generation", error))?;
                let bytes = file
                    .snapshot()
                    .map_err(|error| storage_error("read JSONL generation", error))?;
                Ok(JournalSnapshot {
                    identity: stable_file_identity(&generation.path)
                        .map_err(|error| storage_error("identify JSONL generation", error))?,
                    bytes,
                })
            })
            .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;

        let plan =
            build_reconciliation_plan(&snapshots, current_cursor.as_ref(), &namespace, &path_hash)?;
        if plan.advance {
            for payload in &plan.payloads {
                insert_payload_transaction(&transaction, payload, &sink_ids)?;
            }
            if let Some(cursor) = plan.cursor.as_ref() {
                write_ingest_cursor(&transaction, cursor)?;
            }
        }

        _log_lock
            .verify_lock()
            .map_err(|error| storage_error("verify canonical JSONL lock", error))?;
        transaction
            .commit()
            .map_err(|error| storage_error("commit JSONL ingest", error))?;
        Ok(ReconcileResult {
            ingested_events: plan.payloads.len(),
            ingested_bytes: plan.ingested_bytes,
        })
    }

    /// Reconcile durable generation state with the files on disk and remove
    /// only rotated generations that are outside the configured keep window
    /// and have been completely ingested into durable SQLite state. The sidecar lock is acquired
    /// before the SQLite write transaction; the final transaction remains open
    /// across the verified unlink so a crash leaves a recoverable
    /// `prune_pending` row rather than claiming deletion early.
    pub(crate) fn prune_eligible_rotations(
        &mut self,
        log_path: &Path,
        keep: usize,
    ) -> MaintenanceResult {
        let mut report = PruneReport::default();
        let _log_lock = match SidecarLock::acquire_lock_only(log_path) {
            Ok(lock) => lock,
            Err(error) => {
                report.warning("acquire JSONL rotation lock", error);
                return report;
            }
        };
        let path_hash = journal_path_hash(log_path);
        let generations = match super::jsonl::discover_jsonl_generations(log_path) {
            Ok(generations) => generations,
            Err(error) => {
                report.warning("discover JSONL generations for pruning", error);
                return report;
            }
        };
        if !generations.iter().any(|generation| generation.is_active) {
            report.warning(
                "validate active JSONL generation for pruning",
                "active JSONL generation is missing",
            );
            return report;
        }
        if let Err(error) =
            validate_generation_metadata_readonly(&self.connection, &path_hash, &generations, false)
        {
            report.warning("validate JSONL generation metadata for pruning", error);
            return report;
        }
        let metadata = match read_generation_metadata(&self.connection) {
            Ok(metadata) => metadata,
            Err(error) => {
                report.warning("read JSONL generation metadata for pruning", error);
                return report;
            }
        };

        // Recovery is independent of the current keep window. In particular,
        // an absent pending file can be finalized even if later rotations have
        // moved the generation outside the originally selected candidate set.
        for record in metadata
            .iter()
            .filter(|record| record.lifecycle == GenerationLifecycle::PrunePending)
        {
            match self.recover_prune_pending(
                log_path,
                keep,
                record.generation_id.as_str(),
                &_log_lock,
            ) {
                Ok(PruneOutcome::Pruned) => {
                    report.pruned += 1;
                    report.finalized_pending += 1;
                }
                Ok(PruneOutcome::FinalizedAbsent) => {
                    report.finalized_pending += 1;
                }
                Ok(PruneOutcome::Protected) => {
                    report.protected += 1;
                    report.finalized_pending += 1;
                }
                Err(error) => report.warning("recover pending JSONL prune", error),
            }
        }

        // Walk the discovered order so the oldest eligible generation is
        // attempted first. Newest `keep` rotated files are never candidates;
        // older protected files remain in the database and on disk.
        for generation in generations.iter().filter(|generation| {
            !generation.is_active
                && !is_newest_kept_generation(&generations, &generation.identity, keep)
        }) {
            let Some(record) = metadata.iter().find(|record| {
                record.generation_id == generation.identity
                    && record.lifecycle == GenerationLifecycle::Present
            }) else {
                continue;
            };
            match generation_is_eligible(&self.connection, log_path, &generations, generation) {
                Ok(true) => {}
                Ok(false) => {
                    report.protected += 1;
                    continue;
                }
                Err(error) => {
                    report.warning("validate JSONL generation eligibility", error);
                    continue;
                }
            }
            match mark_generation_prune_pending(&mut self.connection, &record.generation_id) {
                Ok(true) => {}
                Ok(false) => {
                    report.warning(
                        "claim JSONL generation for pruning",
                        "generation lifecycle changed before pruning",
                    );
                    continue;
                }
                Err(error) => {
                    report.warning("mark JSONL generation prune pending", error);
                    continue;
                }
            }

            match self.recover_prune_pending(log_path, keep, &record.generation_id, &_log_lock) {
                Ok(PruneOutcome::Pruned) => report.pruned += 1,
                Ok(PruneOutcome::FinalizedAbsent) => report.finalized_pending += 1,
                Ok(PruneOutcome::Protected) => report.protected += 1,
                Err(error) => report.warning("complete JSONL generation prune", error),
            }
        }
        report
    }

    fn recover_prune_pending(
        &mut self,
        log_path: &Path,
        keep: usize,
        generation_id: &str,
        log_lock: &SidecarLock,
    ) -> Result<PruneOutcome, Box<dyn std::error::Error>> {
        let path_hash = journal_path_hash(log_path);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| storage_error("begin JSONL prune recovery", error))?;
        let generations = super::jsonl::discover_jsonl_generations(log_path)
            .map_err(|error| storage_error("rediscover JSONL generations for pruning", error))?;
        validate_generation_metadata_readonly(&transaction, &path_hash, &generations, false)?;

        let Some(generation) = generations
            .iter()
            .find(|generation| generation.identity == generation_id)
        else {
            log_lock.verify_lock().map_err(|error| {
                storage_error("verify JSONL lock before finalizing prune", error)
            })?;
            finalize_prune_pending_transaction(&transaction, generation_id)?;
            transaction
                .commit()
                .map_err(|error| storage_error("commit absent JSONL prune recovery", error))?;
            return Ok(PruneOutcome::FinalizedAbsent);
        };

        if generation.is_active || is_newest_kept_generation(&generations, generation_id, keep) {
            restore_present_transaction(&transaction, generation_id)?;
            log_lock.verify_lock().map_err(|error| {
                storage_error("verify JSONL lock while restoring generation", error)
            })?;
            transaction
                .commit()
                .map_err(|error| storage_error("commit restored JSONL generation", error))?;
            return Ok(PruneOutcome::Protected);
        }

        if !generation_is_eligible(&transaction, log_path, &generations, generation)? {
            restore_present_transaction(&transaction, generation_id)?;
            log_lock.verify_lock().map_err(|error| {
                storage_error("verify JSONL lock while protecting generation", error)
            })?;
            transaction
                .commit()
                .map_err(|error| storage_error("commit protected JSONL generation", error))?;
            return Ok(PruneOutcome::Protected);
        }

        log_lock.verify_lock().map_err(|error| {
            storage_error("verify JSONL lock before deleting generation", error)
        })?;
        #[cfg(test)]
        if self.fail_next_prune_deletion {
            self.fail_next_prune_deletion = false;
            return Err(storage_message(
                "synthetic JSONL generation deletion failure",
            ));
        }
        remove_verified_file(&generation.path, generation_id)
            .map_err(|error| storage_error("delete verified JSONL generation", error))?;
        sync_parent(log_path)
            .map_err(|error| storage_error("sync JSONL parent after pruning", error))?;
        log_lock
            .verify_lock()
            .map_err(|error| storage_error("verify JSONL lock after deleting generation", error))?;
        finalize_prune_pending_transaction(&transaction, generation_id)?;
        transaction
            .commit()
            .map_err(|error| storage_error("commit JSONL generation prune", error))?;
        Ok(PruneOutcome::Pruned)
    }

    pub(crate) fn get_event(
        &self,
        event_id: &str,
    ) -> Result<Option<OutboxEvent>, Box<dyn std::error::Error>> {
        let row = self
            .connection
            .query_row(
                "SELECT event_id, payload, payload_hash, created_at
                 FROM events WHERE event_id = ?1",
                params![event_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| storage_error("get event", error))?;
        let Some((stored_event_id, payload, stored_hash, created_at)) = row else {
            return Ok(None);
        };
        let payload_hash: [u8; 32] = stored_hash
            .as_slice()
            .try_into()
            .map_err(|_| storage_message("stored payload hash has an invalid length"))?;
        let actual_hash: [u8; 32] = Sha256::digest(&payload).into();
        if payload_hash != actual_hash {
            return Err(storage_message(
                "stored payload hash does not match its bytes",
            ));
        }
        validate_canonical_event_bytes(&payload, Some(&stored_event_id))
            .map_err(|error| storage_error("validate stored event", error))?;
        Ok(Some(OutboxEvent {
            event_id: stored_event_id,
            payload,
            payload_hash,
            created_at,
        }))
    }

    #[cfg(all(test, not(windows)))]
    pub(crate) fn get_delivery(
        &self,
        event_id: &str,
        sink_id: &str,
    ) -> Result<Option<DeliveryRow>, Box<dyn std::error::Error>> {
        let row = self
            .connection
            .query_row(
                "SELECT event_id, sink_id, state, attempt_count, next_attempt_at,
                        last_error_class, last_error_status, updated_at
                 FROM deliveries WHERE event_id = ?1 AND sink_id = ?2",
                params![event_id, sink_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, Option<i64>>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, Option<i64>>(6)?,
                        row.get::<_, i64>(7)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| storage_error("get delivery state", error))?;
        let Some((
            event_id,
            sink_id,
            state,
            attempts,
            next_attempt_at,
            error_class,
            error_status,
            updated_at,
        )) = row
        else {
            return Ok(None);
        };
        let state = DeliveryState::from_str(&state)
            .ok_or_else(|| storage_message("stored delivery state is unknown"))?;
        let attempts = u32::try_from(attempts)
            .map_err(|_| storage_message("stored delivery attempt count is invalid"))?;
        let last_error_class = decode_error_class(error_class.as_deref(), error_status)?;
        Ok(Some(DeliveryRow {
            event_id,
            sink_id,
            state,
            attempts,
            next_attempt_at,
            last_error_class,
            updated_at,
        }))
    }

    pub(crate) fn next_ready_delivery(
        &self,
        sink_id: &str,
        now_millis: i64,
    ) -> Result<Option<ReadyDelivery>, Box<dyn std::error::Error>> {
        validate_sink_ids(&[sink_id], false)?;
        let row = self
            .connection
            .query_row(
                "SELECT event_id, sink_id, state, attempt_count, next_attempt_at,
                        last_error_class, last_error_status, updated_at
                 FROM deliveries
                 WHERE sink_id = ?1
                   AND state = 'pending'
                   AND (next_attempt_at IS NULL OR next_attempt_at <= ?2)
                 ORDER BY COALESCE(next_attempt_at, 0), updated_at, event_id
                 LIMIT 1",
                params![sink_id, now_millis],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, Option<i64>>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, Option<i64>>(6)?,
                        row.get::<_, i64>(7)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| storage_error("get ready delivery", error))?;
        let Some((
            event_id,
            stored_sink_id,
            state,
            attempts,
            next_attempt_at,
            error_class,
            error_status,
            updated_at,
        )) = row
        else {
            return Ok(None);
        };
        let state = DeliveryState::from_str(&state)
            .ok_or_else(|| storage_message("stored delivery state is unknown"))?;
        let attempts = u32::try_from(attempts)
            .map_err(|_| storage_message("stored delivery attempt count is invalid"))?;
        let last_error_class = decode_error_class(error_class.as_deref(), error_status)?;
        let row = DeliveryRow {
            event_id: event_id.clone(),
            sink_id: stored_sink_id,
            state,
            attempts,
            next_attempt_at,
            last_error_class,
            updated_at,
        };
        let event = self
            .get_event(&event_id)?
            .ok_or_else(|| storage_message("delivery state references a missing event"))?;
        Ok(Some(ReadyDelivery {
            row,
            payload: event.payload,
        }))
    }

    #[cfg(all(test, not(windows)))]
    pub(crate) fn ingest_cursor(&self) -> Result<Option<IngestCursor>, Box<dyn std::error::Error>> {
        read_ingest_cursor(&self.connection)
    }

    #[cfg(all(test, not(windows)))]
    pub(crate) fn fail_next_prune_deletion(&mut self) {
        self.fail_next_prune_deletion = true;
    }

    #[cfg(test)]
    pub(crate) fn set_capacity_scan_limit(&mut self, limit: u64) {
        assert!(limit > 0, "capacity inspection limit must be nonzero");
        self.capacity_scan_limit = limit;
    }

    pub(crate) fn record_delivery_at(
        &mut self,
        event_id: &str,
        sink_id: &str,
        update: DeliveryUpdate,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if event_id.trim().is_empty() || sink_id.trim().is_empty() {
            return Err(canonical_error("outbox delivery identity is empty"));
        }
        if !matches!(update.state, DeliveryState::Pending) && update.next_attempt_at.is_some() {
            return Err(canonical_error(
                "terminal delivery state cannot have a next attempt time",
            ));
        }
        if update.next_attempt_at.is_some_and(|value| value < 0) {
            return Err(canonical_error("outbox next attempt time is invalid"));
        }
        let (error_class, error_status) = encode_error_class(update.last_error_class);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| storage_error("begin delivery state update", error))?;
        let changed = transaction
            .execute(
                "UPDATE deliveries
                 SET state = ?1, attempt_count = ?2, next_attempt_at = ?3,
                     last_error_class = ?4, last_error_status = ?5, updated_at = ?6
                 WHERE event_id = ?7 AND sink_id = ?8",
                params![
                    update.state.as_str(),
                    i64::from(update.attempts),
                    update.next_attempt_at,
                    error_class,
                    error_status,
                    update.updated_at,
                    event_id,
                    sink_id,
                ],
            )
            .map_err(|error| storage_error("record delivery state", error))?;
        if changed != 1 {
            return Err(storage_message("delivery state row does not exist"));
        }
        transaction
            .execute(
                "INSERT OR IGNORE INTO sink_health
                 (sink_id, last_success_at, last_error_at, last_error_class, last_error_status)
                 VALUES (?1, NULL, NULL, NULL, NULL)",
                params![sink_id],
            )
            .map_err(|error| storage_error("initialize sink health", error))?;
        if matches!(update.state, DeliveryState::Acked) {
            transaction
                .execute(
                    "UPDATE sink_health SET last_success_at = ?1 WHERE sink_id = ?2",
                    params![update.updated_at, sink_id],
                )
                .map_err(|error| storage_error("record sink success", error))?;
        }
        if update.last_error_class.is_some() {
            transaction
                .execute(
                    "UPDATE sink_health
                     SET last_error_at = ?1, last_error_class = ?2, last_error_status = ?3
                     WHERE sink_id = ?4",
                    params![update.updated_at, error_class, error_status, sink_id],
                )
                .map_err(|error| storage_error("record sink error", error))?;
        }
        transaction
            .commit()
            .map_err(|error| storage_error("commit delivery state update", error))?;
        Ok(())
    }

    /// Make every blocked delivery for a sink eligible for an immediate retry.
    /// Attempts and the last structured error remain history for operator
    /// inspection; only the state, retry time, and transition timestamp move.
    pub(crate) fn release_blocked_for_sink(
        &mut self,
        sink_id: &str,
        now: i64,
    ) -> Result<u64, DeliveryError> {
        let sink_id = validate_sink_ids(&[sink_id], false)
            .map_err(delivery_error_from_box)
            .and_then(|sink_ids| {
                sink_ids.into_iter().next().ok_or_else(|| {
                    DeliveryError::new(
                        DeliveryErrorClass::UnknownInternal,
                        0,
                        "validated sink identity is missing",
                    )
                })
            })?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| storage_delivery_error("begin blocked delivery release", error))?;
        let changed = transaction
            .execute(
                "UPDATE deliveries
                 SET state = 'pending', next_attempt_at = ?1, updated_at = ?1
                 WHERE sink_id = ?2 AND state = 'blocked'",
                params![now, sink_id],
            )
            .map_err(|error| storage_delivery_error("release blocked deliveries", error))?;
        transaction
            .commit()
            .map_err(|error| storage_delivery_error("commit blocked delivery release", error))?;
        u64::try_from(changed).map_err(|_| {
            storage_delivery_error("count released blocked deliveries", "row count overflow")
        })
    }

    /// Operator action for a blocked sink/event. No automatic path calls this;
    /// a credential or endpoint repair must be explicit before the row is made
    /// eligible again.
    #[cfg(all(test, not(windows)))]
    pub(crate) fn release_blocked_delivery(
        &mut self,
        event_id: &str,
        sink_id: &str,
        now_millis: i64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let changed = self
            .connection
            .execute(
                "UPDATE deliveries
                 SET state = 'pending', attempt_count = 0, next_attempt_at = NULL,
                     last_error_class = NULL, last_error_status = NULL, updated_at = ?1
                 WHERE event_id = ?2 AND sink_id = ?3 AND state = 'blocked'",
                params![now_millis, event_id, sink_id],
            )
            .map_err(|error| storage_error("release blocked delivery", error))?;
        if changed != 1 {
            return Err(storage_message("blocked delivery state row does not exist"));
        }
        Ok(())
    }

    #[cfg(all(test, not(windows)))]
    fn meta_value(&self, key: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
        self.connection
            .query_row(
                "SELECT value FROM meta WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| storage_error("read metadata", error))
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum PruneOutcome {
    Pruned,
    FinalizedAbsent,
    Protected,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct GenerationMetadata {
    generation_id: String,
    journal_path_hash: String,
    observed_at: i64,
    lifecycle: GenerationLifecycle,
    pruned_at: Option<i64>,
}

impl PruneReport {
    fn warning(&mut self, context: &str, error: impl fmt::Display) {
        let rendered = format!(
            "{context}: {}",
            PrivacySanitizer::sanitize(SanitizationContext::Diagnostic, &error.to_string())
        );
        self.warnings
            .push(rendered.chars().take(200).collect::<String>());
    }
}

fn read_generation_metadata(
    connection: &Connection,
) -> Result<Vec<GenerationMetadata>, Box<dyn std::error::Error>> {
    let mut statement = connection
        .prepare(
            "SELECT generation_id, journal_path_hash, observed_at, lifecycle, pruned_at
             FROM journal_generations",
        )
        .map_err(|error| storage_error("read generation metadata", error))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<i64>>(4)?,
            ))
        })
        .map_err(|error| storage_error("read generation metadata", error))?;
    let mut metadata = Vec::new();
    for row in rows {
        let (generation_id, journal_path_hash, observed_at, lifecycle, pruned_at) =
            row.map_err(|error| storage_error("read generation metadata", error))?;
        let generation_id = bounded_cursor_text(&generation_id, "generation identity")?;
        let journal_path_hash = validate_journal_path_hash(&journal_path_hash)?;
        if observed_at < 0 {
            return Err(storage_message(
                "generation observation timestamp is invalid",
            ));
        }
        let lifecycle = GenerationLifecycle::from_str(&lifecycle)
            .ok_or_else(|| storage_message("stored generation lifecycle is unknown"))?;
        match lifecycle {
            GenerationLifecycle::Pruned if pruned_at.is_none() => {
                return Err(storage_message(
                    "pruned generation metadata has no prune timestamp",
                ));
            }
            GenerationLifecycle::Present | GenerationLifecycle::PrunePending
                if pruned_at.is_some() =>
            {
                return Err(storage_message(
                    "unpruned generation metadata has a prune timestamp",
                ));
            }
            _ => {}
        }
        if pruned_at.is_some_and(|value| value < 0) {
            return Err(storage_message("generation prune timestamp is invalid"));
        }
        metadata.push(GenerationMetadata {
            generation_id,
            journal_path_hash,
            observed_at,
            lifecycle,
            pruned_at,
        });
    }
    Ok(metadata)
}

fn mark_generation_prune_pending(
    connection: &mut Connection,
    generation_id: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| storage_error("begin generation prune claim", error))?;
    let changed = transaction.execute(
        "UPDATE journal_generations
             SET lifecycle = 'prune_pending', pruned_at = NULL
             WHERE generation_id = ?1 AND lifecycle = 'present'",
        params![generation_id],
    )?;
    transaction
        .commit()
        .map_err(|error| storage_error("commit generation prune claim", error))?;
    Ok(changed == 1)
}

fn restore_present_transaction(
    transaction: &Transaction<'_>,
    generation_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let changed = transaction.execute(
        "UPDATE journal_generations
         SET lifecycle = 'present', pruned_at = NULL
         WHERE generation_id = ?1 AND lifecycle = 'prune_pending'",
        params![generation_id],
    )?;
    if changed != 1 {
        return Err(storage_message(
            "generation is not pending prune during recovery",
        ));
    }
    Ok(())
}

fn finalize_prune_pending_transaction(
    transaction: &Transaction<'_>,
    generation_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let changed = transaction.execute(
        "UPDATE journal_generations
         SET lifecycle = 'pruned', pruned_at = ?1
         WHERE generation_id = ?2 AND lifecycle = 'prune_pending'",
        params![unix_seconds(), generation_id],
    )?;
    if changed != 1 {
        return Err(storage_message(
            "generation is not pending prune during finalization",
        ));
    }
    Ok(())
}

fn is_newest_kept_generation(
    generations: &[JsonlGeneration],
    generation_id: &str,
    keep: usize,
) -> bool {
    generations
        .iter()
        .filter(|generation| !generation.is_active)
        .rev()
        .take(keep)
        .any(|generation| generation.identity == generation_id)
}

fn generation_is_eligible(
    connection: &Connection,
    log_path: &Path,
    generations: &[JsonlGeneration],
    candidate: &JsonlGeneration,
) -> Result<bool, Box<dyn std::error::Error>> {
    if candidate.is_active {
        return Ok(false);
    }
    let path_hash = journal_path_hash(log_path);
    let cursor = read_ingest_cursor(connection)?;
    let Some(cursor) = cursor else {
        return Ok(false);
    };
    if cursor.journal_path_hash != path_hash {
        return Err(storage_message(
            "durable ingest cursor belongs to a different JSONL journal",
        ));
    }
    let candidate_index = generations
        .iter()
        .position(|generation| generation.identity == candidate.identity)
        .ok_or_else(|| storage_message("JSONL prune candidate is not currently observed"))?;
    let cursor_index = generations
        .iter()
        .position(|generation| generation.identity == cursor.generation_id)
        .ok_or_else(|| storage_message("durable ingest cursor generation is missing"))?;

    let mut candidate_file = open_pinned_read(&candidate.path)
        .map_err(|error| storage_error("open JSONL prune candidate", error))?;
    let candidate_identity = stable_file_identity(&candidate.path)
        .map_err(|error| storage_error("identify JSONL prune candidate", error))?;
    if candidate_identity != candidate.identity {
        return Err(storage_message(
            "JSONL prune candidate identity changed during inspection",
        ));
    }
    let candidate_bytes = candidate_file
        .snapshot()
        .map_err(|error| storage_error("read JSONL prune candidate", error))?;
    let candidate_identity_after = stable_file_identity(&candidate.path)
        .map_err(|error| storage_error("reidentify JSONL prune candidate", error))?;
    if candidate_identity_after != candidate.identity {
        return Err(storage_message(
            "JSONL prune candidate changed during inspection",
        ));
    }
    let snapshot = JournalSnapshot {
        identity: candidate.identity.clone(),
        bytes: candidate_bytes,
    };
    let progress = parse_generation(&snapshot, 0)?;
    if !progress.complete {
        return Ok(false);
    }

    if cursor_index != candidate_index {
        let cursor_generation = &generations[cursor_index];
        let mut cursor_file = open_pinned_read(&cursor_generation.path)
            .map_err(|error| storage_error("open JSONL cursor generation", error))?;
        let cursor_identity = stable_file_identity(&cursor_generation.path)
            .map_err(|error| storage_error("identify JSONL cursor generation", error))?;
        if cursor_identity != cursor_generation.identity {
            return Err(storage_message(
                "JSONL cursor generation identity changed during inspection",
            ));
        }
        let bytes = cursor_file
            .snapshot()
            .map_err(|error| storage_error("read JSONL cursor generation", error))?;
        if stable_file_identity(&cursor_generation.path)
            .map_err(|error| storage_error("reidentify JSONL cursor generation", error))?
            != cursor_generation.identity
        {
            return Err(storage_message(
                "JSONL cursor generation changed during inspection",
            ));
        }
        // Keep the owned snapshot alive while cursor integrity is checked.
        return generation_is_eligible_with_cursor_snapshot(
            connection,
            &cursor,
            generations,
            candidate,
            GenerationEligibilitySnapshots {
                candidate_index,
                cursor_index,
                cursor_snapshot: &JournalSnapshot {
                    identity: cursor_generation.identity.clone(),
                    bytes,
                },
                progress,
            },
        );
    }
    generation_is_eligible_with_cursor_snapshot(
        connection,
        &cursor,
        generations,
        candidate,
        GenerationEligibilitySnapshots {
            candidate_index,
            cursor_index,
            cursor_snapshot: &snapshot,
            progress,
        },
    )
}

struct GenerationEligibilitySnapshots<'a> {
    candidate_index: usize,
    cursor_index: usize,
    cursor_snapshot: &'a JournalSnapshot,
    progress: GenerationProgress,
}

fn generation_is_eligible_with_cursor_snapshot(
    connection: &Connection,
    cursor: &IngestCursor,
    generations: &[JsonlGeneration],
    candidate: &JsonlGeneration,
    snapshots: GenerationEligibilitySnapshots<'_>,
) -> Result<bool, Box<dyn std::error::Error>> {
    let GenerationEligibilitySnapshots {
        candidate_index,
        cursor_index,
        cursor_snapshot,
        progress,
    } = snapshots;
    let candidate_generation = generations
        .get(candidate_index)
        .ok_or_else(|| storage_message("JSONL prune candidate index is invalid"))?;
    if candidate_generation.identity != candidate.identity {
        return Err(storage_message(
            "JSONL prune candidate changed during eligibility validation",
        ));
    }
    let cursor_generation = generations
        .get(cursor_index)
        .ok_or_else(|| storage_message("JSONL cursor generation index is invalid"))?;
    if cursor_generation.identity != cursor_snapshot.identity {
        return Err(storage_message(
            "JSONL cursor generation changed during eligibility validation",
        ));
    }
    verify_cursor_against_snapshot(cursor, cursor_snapshot)?;
    if candidate_index == cursor_index {
        return Ok(false);
    }
    let cursor_read = candidate_index < cursor_index;
    if !cursor_read {
        return Ok(false);
    }

    // Once the cursor has advanced beyond a complete rotated generation,
    // every event origin in that generation must have an authoritative SQLite
    // event row created by the same ingest transaction. This check also
    // protects against an in-place mutation that preserves the filesystem
    // identity: an identity alone proves coordinated rename, not unchanged
    // contents. Downstream acknowledgement is deliberately not part of
    // source-file pruning: pending, retrying, or blocked rows remain
    // replayable in SQLite.
    generation_origins_match(connection, &candidate.identity, &progress.payloads)
}

fn generation_origins_match(
    connection: &Connection,
    generation_id: &str,
    payloads: &[CanonicalPayload],
) -> Result<bool, Box<dyn std::error::Error>> {
    let origin_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM event_origins WHERE generation_id = ?1",
            params![generation_id],
            |row| row.get(0),
        )
        .map_err(|error| storage_error("count JSONL generation origins", error))?;
    if origin_count < 0 || u64::try_from(origin_count).ok() != Some(payloads.len() as u64) {
        return Ok(false);
    }

    for payload in payloads {
        let Some(offset) = payload.generation_offset else {
            return Ok(false);
        };
        let origin_event_id = connection
            .query_row(
                "SELECT event_id FROM event_origins
                 WHERE generation_id = ?1 AND byte_offset = ?2",
                params![
                    generation_id,
                    i64::try_from(offset).map_err(|_| {
                        storage_message("durable event origin offset is too large")
                    })?
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| storage_error("read JSONL generation origin", error))?;
        if origin_event_id.as_deref() != Some(payload.event_id.as_str())
            || !event_is_already_stored(connection, payload)?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

#[derive(Debug)]
struct JournalSnapshot {
    identity: String,
    bytes: Vec<u8>,
}

#[derive(Debug)]
struct ReconciliationPlan {
    payloads: Vec<CanonicalPayload>,
    cursor: Option<IngestCursor>,
    advance: bool,
    ingested_bytes: usize,
}

#[derive(Debug)]
struct GenerationProgress {
    next_offset: usize,
    complete: bool,
    payloads: Vec<CanonicalPayload>,
}

fn validate_sink_ids(
    sink_ids: &[&str],
    require_one: bool,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut values = std::collections::BTreeSet::new();
    for sink_id in sink_ids {
        let sink_id = sink_id.trim();
        if sink_id.is_empty() {
            return Err(canonical_error("outbox sink identity is empty"));
        }
        if sink_id.len() > MAX_CURSOR_TEXT {
            return Err(canonical_error("outbox sink identity is too long"));
        }
        if sink_id.chars().any(char::is_control) {
            return Err(canonical_error(
                "outbox sink identity contains control characters",
            ));
        }
        values.insert(sink_id.to_string());
    }
    if require_one && values.is_empty() {
        return Err(canonical_error(
            "durable ingest requires a configured sink identity",
        ));
    }
    Ok(values.into_iter().collect())
}

fn verify_journal_path_for_capacity(
    connection: &Connection,
    path_hash: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let path_hash = validate_journal_path_hash(path_hash)?;
    let persisted = connection
        .query_row(
            "SELECT value FROM meta WHERE key = 'journal_path_hash'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|error| storage_error("read journal path identity", error))?;
    let Some(persisted) = persisted else {
        let has_state = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM events)
                   OR EXISTS(SELECT 1 FROM ingest_cursor)
                   OR EXISTS(SELECT 1 FROM journal_generations)",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|error| storage_error("inspect unbound journal state", error))?;
        return match has_state {
            0 => Ok(false),
            1 => Err(storage_message(
                "durable canonical JSONL journal identity is missing",
            )),
            _ => Err(storage_message(
                "durable canonical JSONL journal identity state is invalid",
            )),
        };
    };
    let persisted = validate_journal_path_hash(&persisted)?;
    if persisted != path_hash {
        return Err(storage_message(
            "durable outbox is bound to a different canonical JSONL journal",
        ));
    }
    Ok(true)
}

fn validate_journal_path_hash(value: &str) -> Result<String, Box<dyn std::error::Error>> {
    let value = bounded_cursor_text(value, "journal path hash")?;
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(storage_message("durable journal path identity is invalid"));
    }
    Ok(value)
}

fn validate_observed_generations(
    generations: &[JsonlGeneration],
) -> Result<BTreeSet<String>, Box<dyn std::error::Error>> {
    let mut identities = BTreeSet::new();
    for generation in generations {
        let identity = bounded_cursor_text(&generation.identity, "generation identity")?;
        if !identities.insert(identity.clone()) {
            return Err(storage_message(
                "durable JSONL generation identity is ambiguous",
            ));
        }
        let actual_identity = stable_file_identity(&generation.path)
            .map_err(|error| storage_error("identify JSONL generation", error))?;
        if actual_identity != identity {
            return Err(storage_message(
                "durable JSONL generation identity changed during inspection",
            ));
        }
    }
    Ok(identities)
}

fn validate_generation_metadata_readonly(
    connection: &Connection,
    path_hash: &str,
    generations: &[JsonlGeneration],
    allow_uninitialized: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let path_hash = validate_journal_path_hash(path_hash)?;
    let observed = validate_observed_generations(generations)?;
    let metadata = read_generation_metadata(connection)?;
    if allow_uninitialized && metadata.is_empty() {
        return Ok(());
    }
    let mut persisted = BTreeMap::new();
    for record in metadata {
        if record.journal_path_hash != path_hash {
            return Err(storage_message(
                "durable generation metadata belongs to a different JSONL journal",
            ));
        }
        if persisted
            .insert(record.generation_id.clone(), record.lifecycle)
            .is_some()
        {
            return Err(storage_message(
                "durable JSONL generation metadata is ambiguous",
            ));
        }
        match record.lifecycle {
            GenerationLifecycle::Present if !observed.contains(&record.generation_id) => {
                return Err(storage_message(
                    "durable JSONL generation metadata is missing a present generation",
                ));
            }
            GenerationLifecycle::Pruned if observed.contains(&record.generation_id) => {
                return Err(storage_message(
                    "pruned durable JSONL generation reappeared",
                ));
            }
            GenerationLifecycle::PrunePending => {}
            GenerationLifecycle::Present | GenerationLifecycle::Pruned => {}
        }
    }
    for generation_id in observed {
        match persisted.get(&generation_id) {
            Some(GenerationLifecycle::Present | GenerationLifecycle::PrunePending) => {}
            Some(GenerationLifecycle::Pruned) => {
                return Err(storage_message(
                    "pruned durable JSONL generation reappeared",
                ));
            }
            None => {
                return Err(storage_message(
                    "durable JSONL generation metadata is missing an observed generation",
                ));
            }
        }
    }
    Ok(())
}

fn ensure_generation_metadata(
    transaction: &Transaction<'_>,
    path_hash: &str,
    generations: &[JsonlGeneration],
    _sink_ids: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let path_hash = validate_journal_path_hash(path_hash)?;
    let observed = validate_observed_generations(generations)?;
    let metadata = read_generation_metadata(transaction)?;
    let mut persisted = BTreeMap::new();
    for record in metadata {
        if record.journal_path_hash != path_hash {
            return Err(storage_message(
                "durable generation metadata belongs to a different JSONL journal",
            ));
        }
        if persisted
            .insert(record.generation_id.clone(), record.lifecycle)
            .is_some()
        {
            return Err(storage_message(
                "durable JSONL generation metadata is invalid or ambiguous",
            ));
        }
        match record.lifecycle {
            GenerationLifecycle::Present if !observed.contains(&record.generation_id) => {
                return Err(storage_message(
                    "durable JSONL generation metadata contains a missing present generation",
                ));
            }
            GenerationLifecycle::Pruned if observed.contains(&record.generation_id) => {
                return Err(storage_message(
                    "pruned durable JSONL generation reappeared",
                ));
            }
            GenerationLifecycle::PrunePending => {}
            GenerationLifecycle::Present | GenerationLifecycle::Pruned => {}
        }
    }

    for generation in generations {
        let generation_id = bounded_cursor_text(&generation.identity, "generation identity")?;
        match persisted.get(&generation_id) {
            Some(GenerationLifecycle::Present | GenerationLifecycle::PrunePending) => continue,
            Some(GenerationLifecycle::Pruned) => {
                return Err(storage_message(
                    "pruned durable JSONL generation reappeared",
                ));
            }
            None => {}
        }
        transaction
            .execute(
                "INSERT INTO journal_generations
                 (generation_id, journal_path_hash, observed_at, lifecycle, pruned_at)
                 VALUES (?1, ?2, ?3, 'present', NULL)",
                params![generation_id, &path_hash, unix_seconds()],
            )
            .map_err(|error| storage_error("insert generation metadata", error))?;
    }
    Ok(())
}

fn query_pending_capacity(
    connection: &Connection,
) -> Result<CapacityUsage, Box<dyn std::error::Error>> {
    let (events, bytes) = connection
        .query_row(
            "SELECT COUNT(*), COALESCE(SUM(length(events.payload)), 0)
             FROM events
             WHERE EXISTS (
                 SELECT 1 FROM deliveries
                 WHERE deliveries.event_id = events.event_id
                   AND deliveries.state IN ('pending', 'blocked')
             )",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .map_err(|error| storage_error("calculate pending capacity", error))?;
    let events = u64::try_from(events)
        .map_err(|_| storage_message("durable pending event count is invalid"))?;
    let bytes = u64::try_from(bytes)
        .map_err(|_| storage_message("durable pending byte count is invalid"))?;
    Ok(CapacityUsage { events, bytes })
}

fn capacity_exceeded_error(
    limit_kind: &str,
    current: u64,
    projected: u64,
    limit: u64,
) -> Box<dyn std::error::Error> {
    Box::new(DeliveryError::new(
        DeliveryErrorClass::DurableStorage,
        0,
        format!(
            "durable capacity exceeded: limit_kind={limit_kind} current={current} projected={projected} limit={limit}"
        ),
    ))
}

fn inspect_unread_jsonl_capacity(
    connection: &Connection,
    generations: &[JsonlGeneration],
    cursor: Option<&IngestCursor>,
    namespace: &str,
    path_hash: &str,
    max_scan_bytes: u64,
) -> Result<CapacityInspection, Box<dyn std::error::Error>> {
    let namespace = bounded_cursor_text(namespace, "journal namespace")?;
    let path_hash = validate_journal_path_hash(path_hash)?;
    let observed = validate_observed_generations(generations)?;
    if observed.len() != generations.len() {
        return Err(storage_message(
            "durable JSONL generation identity is ambiguous",
        ));
    }

    let (start_index, start_offset) = match cursor {
        None => (0, 0),
        Some(cursor) => {
            if cursor.journal_namespace != namespace {
                return Err(storage_message(
                    "durable ingest cursor journal namespace is invalid",
                ));
            }
            if cursor.journal_path_hash != path_hash {
                return Err(storage_message(
                    "durable ingest cursor belongs to a different JSONL journal",
                ));
            }
            let matches = generations
                .iter()
                .enumerate()
                .filter(|(_, generation)| generation.identity == cursor.generation_id)
                .map(|(index, _)| index)
                .collect::<Vec<_>>();
            let Some(&index) = matches.first() else {
                return Err(storage_message(
                    "durable ingest cursor generation cannot be identified safely",
                ));
            };
            if matches.len() != 1 {
                return Err(storage_message(
                    "durable ingest cursor generation identity is ambiguous",
                ));
            }
            (index, cursor.byte_offset)
        }
    };

    if start_index >= generations.len() {
        if cursor.is_some() {
            return Err(storage_message(
                "durable ingest cursor generation is invalid",
            ));
        }
        return Ok(CapacityInspection::default());
    }

    let mut inspection = CapacityInspection::default();
    let mut seen_payloads = BTreeMap::new();
    let mut scanned_bytes = 0_u64;
    for (index, generation) in generations.iter().enumerate().skip(start_index) {
        let expected_identity = bounded_cursor_text(&generation.identity, "generation identity")?;
        let identity_before = stable_file_identity(&generation.path)
            .map_err(|error| storage_error("identify JSONL generation", error))?;
        if identity_before != expected_identity {
            return Err(storage_message(
                "durable JSONL generation identity changed during inspection",
            ));
        }
        let mut file = open_pinned_read(&generation.path)
            .map_err(|error| storage_error("open JSONL generation", error))?;
        let identity_opened = stable_file_identity(&generation.path)
            .map_err(|error| storage_error("identify JSONL generation", error))?;
        if identity_opened != expected_identity {
            return Err(storage_message(
                "durable JSONL generation identity changed during inspection",
            ));
        }

        let offset = if index == start_index {
            start_offset
        } else {
            0
        };
        if let Some(cursor) = cursor.filter(|_| index == start_index) {
            verify_cursor_against_file(cursor, &mut file)?;
        }
        let is_last = index + 1 == generations.len();
        scan_jsonl_generation_capacity(CapacityScanContext {
            connection,
            file: &mut file,
            start_offset: offset,
            is_last_generation: is_last,
            seen_payloads: &mut seen_payloads,
            scanned_bytes: &mut scanned_bytes,
            inspection: &mut inspection,
            max_scan_bytes,
        })?;

        let identity_after = stable_file_identity(&generation.path)
            .map_err(|error| storage_error("identify JSONL generation", error))?;
        if identity_after != expected_identity {
            return Err(storage_message(
                "durable JSONL generation changed during inspection",
            ));
        }
    }
    inspection.payloads = seen_payloads;
    Ok(inspection)
}

fn verify_cursor_against_file(
    cursor: &IngestCursor,
    file: &mut PinnedFile,
) -> Result<(), Box<dyn std::error::Error>> {
    let length = file.length();
    let offset = cursor.byte_offset;
    if offset > length || cursor.observed_length < offset || length < cursor.observed_length {
        return Err(storage_message("durable JSONL generation was truncated"));
    }
    if offset > 0 {
        let previous = file
            .read_range(offset - 1, 1)
            .map_err(|error| storage_error("verify JSONL cursor boundary", error))?;
        if previous.as_slice() != b"\n" {
            return Err(storage_message(
                "durable ingest cursor is not at a complete line boundary",
            ));
        }
    }

    let integrity_window = u64::try_from(CURSOR_INTEGRITY_WINDOW)
        .map_err(|_| storage_message("durable ingest cursor integrity window is too large"))?;
    let expected_window_start = offset.saturating_sub(integrity_window);
    if cursor.window_start != expected_window_start || cursor.window_start > offset {
        return Err(storage_message(
            "durable ingest cursor integrity window is invalid",
        ));
    }
    let prefix_end = offset.min(integrity_window);
    let prefix_hash = hash_file_range(file, 0, prefix_end)?;
    let window_hash = hash_file_range(file, cursor.window_start, offset)?;
    if prefix_hash != cursor.prefix_hash || window_hash != cursor.window_hash {
        return Err(storage_message(
            "durable JSONL generation integrity check failed",
        ));
    }
    Ok(())
}

fn hash_file_range(
    file: &mut PinnedFile,
    start: u64,
    end: u64,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let integrity_window = u64::try_from(CURSOR_INTEGRITY_WINDOW)
        .map_err(|_| storage_message("durable ingest cursor integrity window is too large"))?;
    if end < start || end - start > integrity_window {
        return Err(storage_message(
            "durable ingest cursor integrity range is invalid",
        ));
    }
    let length = usize::try_from(end - start)
        .map_err(|_| storage_message("durable ingest cursor integrity range is too large"))?;
    let bytes = if length == 0 {
        Vec::new()
    } else {
        file.read_range(start, length)
            .map_err(|error| storage_error("read JSONL cursor integrity range", error))?
    };
    Ok(Sha256::digest(&bytes).into())
}

struct CapacityScanContext<'a> {
    connection: &'a Connection,
    file: &'a mut PinnedFile,
    start_offset: u64,
    is_last_generation: bool,
    seen_payloads: &'a mut BTreeMap<String, Vec<u8>>,
    scanned_bytes: &'a mut u64,
    inspection: &'a mut CapacityInspection,
    max_scan_bytes: u64,
}

fn scan_jsonl_generation_capacity(
    context: CapacityScanContext<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let CapacityScanContext {
        connection,
        file,
        start_offset,
        is_last_generation,
        seen_payloads,
        scanned_bytes,
        inspection,
        max_scan_bytes,
    } = context;
    let length = file.length();
    if start_offset > length {
        return Err(storage_message(
            "durable ingest cursor points past the JSONL generation",
        ));
    }
    let read_chunk_size = u64::try_from(CAPACITY_READ_CHUNK_BYTES)
        .map_err(|_| storage_message("bounded JSONL capacity read is too large"))?;
    let max_scan_bytes_u64 = max_scan_bytes;
    let max_scan_bytes = usize::try_from(max_scan_bytes_u64)
        .map_err(|_| storage_message("durable JSONL capacity scan bound is too large"))?;
    let mut offset = start_offset;
    let mut line = Vec::with_capacity(CAPACITY_READ_CHUNK_BYTES);
    while offset < length {
        let remaining = length - offset;
        let read_length = usize::try_from(remaining.min(read_chunk_size))
            .map_err(|_| storage_message("bounded JSONL capacity read is too large"))?;
        let chunk = file
            .read_range(offset, read_length)
            .map_err(|error| storage_error("read JSONL capacity range", error))?;
        *scanned_bytes =
            scanned_bytes
                .checked_add(u64::try_from(read_length).map_err(|_| {
                    storage_message("durable JSONL capacity read length is too large")
                })?)
                .ok_or_else(|| storage_message("durable JSONL capacity scan overflow"))?;
        if *scanned_bytes > max_scan_bytes_u64 {
            return Err(storage_message(
                "durable JSONL capacity scan exceeds the bounded inspection range",
            ));
        }

        for byte in chunk {
            if byte == b'\n' {
                if line.last() == Some(&b'\r') {
                    return Err(storage_message(
                        "canonical JSONL uses an invalid line ending",
                    ));
                }
                account_unread_payload(connection, &line, seen_payloads, &mut inspection.base)?;
                line.clear();
            } else {
                let next_length = line
                    .len()
                    .checked_add(1)
                    .ok_or_else(|| storage_message("durable JSONL line length overflow"))?;
                if next_length > max_scan_bytes {
                    return Err(storage_message(
                        "durable JSONL record exceeds the bounded inspection range",
                    ));
                }
                line.push(byte);
            }
        }
        offset =
            offset
                .checked_add(u64::try_from(read_length).map_err(|_| {
                    storage_message("durable JSONL capacity read offset is too large")
                })?)
                .ok_or_else(|| storage_message("durable JSONL capacity offset overflow"))?;
    }

    if !line.is_empty() && !is_last_generation {
        return Err(storage_message("malformed non-tail canonical JSONL record"));
    }
    Ok(())
}

fn account_unread_payload(
    connection: &Connection,
    bytes: &[u8],
    seen_payloads: &mut BTreeMap<String, Vec<u8>>,
    usage: &mut CapacityUsage,
) -> Result<(), Box<dyn std::error::Error>> {
    let payload = canonical_payload_from_bytes(bytes)
        .map_err(|error| storage_error("malformed non-tail canonical JSONL record", error))?;
    if event_is_already_stored(connection, &payload)? {
        return Ok(());
    }
    if let Some(previous) = seen_payloads.get(&payload.event_id) {
        if previous != &payload.bytes {
            return Err(payload_collision_error());
        }
        return Ok(());
    }
    seen_payloads.insert(payload.event_id.clone(), payload.bytes.clone());

    usage.events = usage
        .events
        .checked_add(1)
        .ok_or_else(|| storage_message("durable capacity event count overflow"))?;
    usage.bytes = usage
        .bytes
        .checked_add(
            u64::try_from(payload.bytes.len())
                .map_err(|_| storage_message("durable capacity byte count is too large"))?,
        )
        .ok_or_else(|| storage_message("durable capacity byte count overflow"))?;
    Ok(())
}

fn event_is_already_stored(
    connection: &Connection,
    payload: &CanonicalPayload,
) -> Result<bool, Box<dyn std::error::Error>> {
    let row = connection
        .query_row(
            "SELECT payload_hash, length(payload), payload = ?2
             FROM events WHERE event_id = ?1",
            params![&payload.event_id, &payload.bytes],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()
        .map_err(|error| storage_error("check existing JSONL event", error))?;
    let Some((stored_hash, stored_length, same_bytes)) = row else {
        return Ok(false);
    };
    let payload_length = u64::try_from(payload.bytes.len())
        .map_err(|_| storage_message("durable payload length is too large"))?;
    let stored_hash: [u8; 32] = stored_hash
        .as_slice()
        .try_into()
        .map_err(|_| storage_message("stored payload hash has an invalid length"))?;
    if stored_length < 0
        || u64::try_from(stored_length).ok() != Some(payload_length)
        || stored_hash != payload.hash
    {
        return Err(payload_collision_error());
    }
    match same_bytes {
        0 => Err(payload_collision_error()),
        1 => Ok(true),
        _ => Err(storage_message(
            "stored event payload comparison is invalid",
        )),
    }
}

fn insert_payload_transaction(
    transaction: &Transaction<'_>,
    payload: &CanonicalPayload,
    sink_ids: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    match (&payload.generation_id, payload.generation_offset) {
        (Some(generation_id), Some(_)) => {
            bounded_cursor_text(generation_id, "generation identity")?;
        }
        (None, None) => {}
        _ => {
            return Err(storage_message("durable event provenance is incomplete"));
        }
    }
    let existing = transaction
        .query_row(
            "SELECT payload, payload_hash FROM events WHERE event_id = ?1",
            params![&payload.event_id],
            |row| {
                let bytes = row.get::<_, Vec<u8>>(0)?;
                let hash = row.get::<_, Vec<u8>>(1)?;
                Ok((bytes, hash))
            },
        )
        .optional()
        .map_err(|error| storage_error("read existing event", error))?;

    match existing {
        Some((stored_bytes, stored_hash)) => {
            if stored_bytes != payload.bytes {
                return Err(payload_collision_error());
            }
            let stored_hash: [u8; 32] = stored_hash
                .as_slice()
                .try_into()
                .map_err(|_| storage_message("stored payload hash has an invalid length"))?;
            if stored_hash != payload.hash {
                return Err(storage_message(
                    "stored payload hash does not match its bytes",
                ));
            }
        }
        None => {
            transaction
                .execute(
                    "INSERT INTO events (event_id, payload, payload_hash, created_at)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![
                        &payload.event_id,
                        &payload.bytes,
                        payload.hash.as_slice(),
                        unix_seconds(),
                    ],
                )
                .map_err(|error| storage_error("insert event", error))?;
        }
    }

    let now = unix_seconds();
    if let (Some(generation_id), Some(generation_offset)) =
        (&payload.generation_id, payload.generation_offset)
    {
        transaction
            .execute(
                "INSERT OR IGNORE INTO event_origins
                 (event_id, generation_id, byte_offset)
                 VALUES (?1, ?2, ?3)",
                params![
                    &payload.event_id,
                    generation_id,
                    i64::try_from(generation_offset)
                        .map_err(|_| storage_message("durable event offset is too large"))?,
                ],
            )
            .map_err(|error| storage_error("insert event provenance", error))?;
    }
    // A delivery-failure alert is an operational signal, not durable delivery
    // work for the sink whose failure it describes. Keeping it out of the
    // per-sink queue prevents an unavailable sink from generating an
    // alert-of-alert on every subsequent dispatch cycle. The canonical event
    // and its JSONL origin remain durable and capacity-admitted; healthy sinks
    // receive the one-time follow-up through SinkSet::deliver_alerts.
    if is_delivery_failure_alert_payload(&payload.bytes) {
        return Ok(());
    }
    for sink_id in sink_ids {
        transaction
            .execute(
                "INSERT OR IGNORE INTO deliveries
                 (event_id, sink_id, state, attempt_count, next_attempt_at,
                  last_error_class, last_error_status, updated_at)
                 VALUES (?1, ?2, 'pending', 0, NULL, NULL, NULL, ?3)",
                params![&payload.event_id, sink_id, now],
            )
            .map_err(|error| storage_error("insert delivery state", error))?;
        transaction
            .execute(
                "INSERT OR IGNORE INTO sink_health
                 (sink_id, last_success_at, last_error_at, last_error_class, last_error_status)
                 VALUES (?1, NULL, NULL, NULL, NULL)",
                params![sink_id],
            )
            .map_err(|error| storage_error("insert sink health", error))?;
    }
    Ok(())
}

fn build_reconciliation_plan(
    snapshots: &[JournalSnapshot],
    current_cursor: Option<&IngestCursor>,
    namespace: &str,
    path_hash: &str,
) -> Result<ReconciliationPlan, Box<dyn std::error::Error>> {
    let (start_index, start_offset) = match current_cursor {
        None => (0, 0),
        Some(cursor) => {
            if cursor.journal_namespace != namespace {
                return Err(storage_message(
                    "durable ingest cursor journal namespace is invalid",
                ));
            }
            if cursor.journal_path_hash != path_hash {
                return Err(storage_message(
                    "durable ingest cursor belongs to a different JSONL journal",
                ));
            }
            let matches = snapshots
                .iter()
                .enumerate()
                .filter(|(_, snapshot)| snapshot.identity == cursor.generation_id)
                .map(|(index, _)| index)
                .collect::<Vec<_>>();
            let Some(&index) = matches.first() else {
                return Err(storage_message(
                    "durable ingest cursor generation cannot be identified safely",
                ));
            };
            if matches.len() != 1 {
                return Err(storage_message(
                    "durable ingest cursor generation identity is ambiguous",
                ));
            }
            verify_cursor_against_snapshot(cursor, &snapshots[index])?;
            (
                index,
                usize::try_from(cursor.byte_offset)
                    .map_err(|_| storage_message("durable ingest cursor offset is invalid"))?,
            )
        }
    };

    if start_index >= snapshots.len() {
        return Err(storage_message(
            "durable ingest cursor generation is invalid",
        ));
    }

    let mut payloads = Vec::new();
    let mut ingested_bytes = 0_usize;
    let mut final_index = start_index;
    let mut final_offset = start_offset;
    let mut advance = current_cursor.is_none();

    for (index, snapshot) in snapshots.iter().enumerate().skip(start_index) {
        let offset = if index == start_index {
            start_offset
        } else {
            0
        };
        let progress = parse_generation(snapshot, offset)?;
        ingested_bytes = ingested_bytes
            .checked_add(
                progress
                    .payloads
                    .iter()
                    .map(|payload| payload.bytes.len())
                    .sum(),
            )
            .ok_or_else(|| storage_message("durable ingest byte count overflow"))?;
        advance |=
            !progress.payloads.is_empty() || progress.next_offset != offset || index != start_index;
        payloads.extend(progress.payloads);
        final_index = index;
        final_offset = progress.next_offset;
        if !progress.complete {
            break;
        }
    }

    let cursor = if advance {
        Some(make_cursor(
            namespace,
            path_hash,
            &snapshots[final_index],
            final_offset,
        )?)
    } else {
        None
    };
    Ok(ReconciliationPlan {
        payloads,
        cursor,
        advance,
        ingested_bytes,
    })
}

fn parse_generation(
    snapshot: &JournalSnapshot,
    offset: usize,
) -> Result<GenerationProgress, Box<dyn std::error::Error>> {
    if offset > snapshot.bytes.len() {
        return Err(storage_message(
            "durable ingest cursor points past the JSONL generation",
        ));
    }
    if offset > 0 && snapshot.bytes.get(offset - 1) != Some(&b'\n') {
        return Err(storage_message(
            "durable ingest cursor is not at a complete line boundary",
        ));
    }

    let mut cursor = offset;
    let mut payloads = Vec::new();
    while cursor < snapshot.bytes.len() {
        let Some(relative_end) = snapshot.bytes[cursor..]
            .iter()
            .position(|byte| *byte == b'\n')
        else {
            // A non-newline-terminated final record is intentionally left for
            // a later reconciliation after the writer completes it.
            return Ok(GenerationProgress {
                next_offset: cursor,
                complete: false,
                payloads,
            });
        };
        let end = cursor
            .checked_add(relative_end)
            .ok_or_else(|| storage_message("JSONL line offset overflow"))?;
        let line = &snapshot.bytes[cursor..end];
        if line.last() == Some(&b'\r') {
            return Err(storage_message(
                "canonical JSONL uses an invalid line ending",
            ));
        }
        let mut payload = canonical_payload_from_bytes(line)
            .map_err(|error| storage_error("malformed non-tail canonical JSONL record", error))?;
        payload.generation_id = Some(snapshot.identity.clone());
        payload.generation_offset = Some(
            u64::try_from(cursor)
                .map_err(|_| storage_message("durable event offset is too large"))?,
        );
        payloads.push(payload);
        cursor = end
            .checked_add(1)
            .ok_or_else(|| storage_message("JSONL line offset overflow"))?;
    }
    Ok(GenerationProgress {
        next_offset: cursor,
        complete: true,
        payloads,
    })
}

fn make_cursor(
    namespace: &str,
    path_hash: &str,
    snapshot: &JournalSnapshot,
    offset: usize,
) -> Result<IngestCursor, Box<dyn std::error::Error>> {
    let byte_offset = u64::try_from(offset)
        .map_err(|_| storage_message("durable ingest cursor offset is too large"))?;
    let observed_length = u64::try_from(snapshot.bytes.len())
        .map_err(|_| storage_message("durable JSONL generation is too large"))?;
    let window_start = offset.saturating_sub(CURSOR_INTEGRITY_WINDOW);
    let prefix_end = offset.min(CURSOR_INTEGRITY_WINDOW);
    let prefix_hash: [u8; 32] = Sha256::digest(&snapshot.bytes[..prefix_end]).into();
    let window_hash: [u8; 32] = Sha256::digest(&snapshot.bytes[window_start..offset]).into();
    Ok(IngestCursor {
        journal_namespace: bounded_cursor_text(namespace, "journal namespace")?,
        journal_path_hash: bounded_cursor_text(path_hash, "journal path hash")?,
        generation_id: bounded_cursor_text(&snapshot.identity, "generation identity")?,
        byte_offset,
        observed_length,
        window_start: u64::try_from(window_start)
            .map_err(|_| storage_message("durable ingest window offset is too large"))?,
        prefix_hash,
        window_hash,
    })
}

fn verify_cursor_against_snapshot(
    cursor: &IngestCursor,
    snapshot: &JournalSnapshot,
) -> Result<(), Box<dyn std::error::Error>> {
    let offset = usize::try_from(cursor.byte_offset)
        .map_err(|_| storage_message("durable ingest cursor offset is invalid"))?;
    let observed_length = usize::try_from(cursor.observed_length)
        .map_err(|_| storage_message("durable ingest cursor length is invalid"))?;
    let window_start = usize::try_from(cursor.window_start)
        .map_err(|_| storage_message("durable ingest cursor integrity window is invalid"))?;
    if offset > snapshot.bytes.len() || observed_length < offset {
        return Err(storage_message("durable JSONL generation was truncated"));
    }
    if snapshot.bytes.len() < observed_length {
        return Err(storage_message("durable JSONL generation was truncated"));
    }
    if offset > 0 && snapshot.bytes.get(offset - 1) != Some(&b'\n') {
        return Err(storage_message(
            "durable ingest cursor is not at a complete line boundary",
        ));
    }
    let expected_window_start = offset.saturating_sub(CURSOR_INTEGRITY_WINDOW);
    if window_start != expected_window_start || window_start > offset {
        return Err(storage_message(
            "durable ingest cursor integrity window is invalid",
        ));
    }
    let prefix_end = offset.min(CURSOR_INTEGRITY_WINDOW);
    let prefix_hash: [u8; 32] = Sha256::digest(&snapshot.bytes[..prefix_end]).into();
    let window_hash: [u8; 32] = Sha256::digest(&snapshot.bytes[window_start..offset]).into();
    if prefix_hash != cursor.prefix_hash || window_hash != cursor.window_hash {
        return Err(storage_message(
            "durable JSONL generation integrity check failed",
        ));
    }
    Ok(())
}

fn canonical_payload_from_bytes(
    bytes: &[u8],
) -> Result<CanonicalPayload, Box<dyn std::error::Error>> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|error| canonical_error(format!("canonical JSONL record is invalid: {error}")))?;
    let event_id = value
        .get("event_id")
        .and_then(Value::as_str)
        .ok_or_else(|| canonical_error("canonical JSONL record has no event ID"))?
        .to_string();
    validate_canonical_event_bytes(bytes, Some(&event_id))?;
    let hash: [u8; 32] = Sha256::digest(bytes).into();
    Ok(CanonicalPayload {
        event_id,
        bytes: bytes.to_vec(),
        hash,
        generation_id: None,
        generation_offset: None,
    })
}

pub(crate) fn is_delivery_failure_alert_payload(bytes: &[u8]) -> bool {
    let Ok(value) = serde_json::from_slice::<Value>(bytes) else {
        return false;
    };
    value.get("event_type").and_then(Value::as_str) == Some("operational_alert")
        && value.get("check_name").and_then(Value::as_str) == Some("sink_delivery")
}

fn bounded_cursor_text(value: &str, what: &str) -> Result<String, Box<dyn std::error::Error>> {
    if value.is_empty() || value.len() > MAX_CURSOR_TEXT || value.chars().any(char::is_control) {
        return Err(storage_message(format!("durable ingest {what} is invalid")));
    }
    Ok(value.to_string())
}

fn journal_path_hash(path: &Path) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"telltale-jsonl-journal-v1\0");
    match resolve_journal_path(path) {
        Ok(path) => hasher.update(path.to_string_lossy().as_bytes()),
        Err(absolute) => {
            hasher.update(b"\0journal-path-resolution-failed-v1\0");
            hasher.update(absolute.to_string_lossy().as_bytes());
        }
    }
    format!("{:x}", hasher.finalize())
}

fn resolve_journal_path(path: &Path) -> Result<PathBuf, PathBuf> {
    let absolute = match std::path::absolute(path) {
        Ok(path) => path,
        Err(_) => return Err(path.to_path_buf()),
    };

    for prefix in absolute.ancestors() {
        let mut resolved = match fs::canonicalize(prefix) {
            Ok(resolved) => resolved,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                ) =>
            {
                continue;
            }
            Err(_) => return Err(absolute.clone()),
        };
        let Ok(suffix) = absolute.strip_prefix(prefix) else {
            return Err(absolute.clone());
        };
        for component in suffix.components() {
            match component {
                Component::Normal(name) => resolved.push(name),
                Component::CurDir => {}
                Component::ParentDir => {
                    let can_pop = resolved
                        .parent()
                        .is_some_and(|parent| parent != resolved.as_path());
                    if can_pop {
                        let _ = resolved.pop();
                    }
                }
                Component::Prefix(_) | Component::RootDir => return Err(absolute.clone()),
            }
        }
        return Ok(resolved);
    }
    Err(absolute)
}

fn canonical_payload(event: &Event) -> Result<CanonicalPayload, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    let mut serializer = serde_json::Serializer::new(&mut bytes);
    serialize_event_for_emission(event, &mut serializer)
        .map_err(|error| canonical_error(format!("serialize Event 3.0 payload: {error}")))?;
    validate_canonical_event_bytes(&bytes, Some(&event.event_id))?;
    let hash: [u8; 32] = Sha256::digest(&bytes).into();
    Ok(CanonicalPayload {
        event_id: event.event_id.clone(),
        bytes,
        hash,
        generation_id: None,
        generation_offset: None,
    })
}

pub(crate) fn canonical_replay_batch(
    events: &[Event],
) -> Result<CanonicalReplayBatch, Box<dyn std::error::Error>> {
    let mut payloads = Vec::with_capacity(events.len());
    let mut jsonl_bytes = Vec::new();
    for event in events {
        let payload = canonical_payload(event)?;
        jsonl_bytes.extend_from_slice(&payload.bytes);
        jsonl_bytes.push(b'\n');
        payloads.push(payload);
    }
    Ok(CanonicalReplayBatch {
        payloads,
        jsonl_bytes,
    })
}

fn validate_capacity_limits(limits: CapacityLimits) -> Result<(), Box<dyn std::error::Error>> {
    if limits.max_pending_events == 0 {
        return Err(storage_message(
            "durable max pending event capacity must be greater than zero",
        ));
    }
    if limits.max_pending_bytes == 0 {
        return Err(storage_message(
            "durable max pending byte capacity must be greater than zero",
        ));
    }
    usize::try_from(limits.max_pending_events)
        .map_err(|_| storage_message("durable max pending event capacity is too large"))?;
    usize::try_from(limits.max_pending_bytes)
        .map_err(|_| storage_message("durable max pending byte capacity is too large"))?;
    Ok(())
}

fn validate_capacity_payload(payload: &CanonicalPayload) -> Result<(), Box<dyn std::error::Error>> {
    validate_canonical_event_bytes(&payload.bytes, Some(&payload.event_id))?;
    let hash: [u8; 32] = Sha256::digest(&payload.bytes).into();
    if hash != payload.hash {
        return Err(storage_message(
            "prospective durable payload hash does not match its bytes",
        ));
    }
    Ok(())
}

fn validate_canonical_event_bytes(
    bytes: &[u8],
    expected_event_id: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    check_serialized_event_markers(bytes, "outbox-payload", &[])
        .map_err(|error| canonical_error(format!("serialized Event 3.0 check failed: {error}")))?;
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|error| canonical_error(format!("serialized Event 3.0 is invalid: {error}")))?;
    let object = value
        .as_object()
        .ok_or_else(|| canonical_error("serialized Event 3.0 is not an object"))?;

    for field in [
        "schema_version",
        "event_id",
        "telltale_version",
        "timestamp",
        "observed_at",
        "ingested_at",
        "time_source",
        "time_confidence",
        "event_type",
        "severity",
        "client",
        "session_id",
    ] {
        let valid = object
            .get(field)
            .and_then(Value::as_str)
            .is_some_and(|value| !value.trim().is_empty());
        if !valid {
            return Err(canonical_error(format!(
                "serialized Event 3.0 is missing required field {field}"
            )));
        }
    }
    if object.get("schema_version").and_then(Value::as_str) != Some(NATIVE_SCHEMA_VERSION) {
        return Err(canonical_error(
            "serialized event has an unsupported schema version",
        ));
    }
    let serialized_event_id = object
        .get("event_id")
        .and_then(Value::as_str)
        .expect("event_id was checked above");
    if !is_native_event_id(serialized_event_id) {
        return Err(canonical_error("serialized event has an invalid event ID"));
    }
    if expected_event_id.is_some_and(|event_id| event_id != serialized_event_id) {
        return Err(canonical_error(
            "serialized event ID does not match its record identity",
        ));
    }
    for field in ["risk_contributions", "tags", "evidence"] {
        if !object.get(field).is_some_and(Value::is_array) {
            return Err(canonical_error(format!(
                "serialized Event 3.0 field {field} is not an array"
            )));
        }
    }
    Ok(())
}

fn is_native_event_id(value: &str) -> bool {
    let Some(uuid) = value.strip_prefix("telltale-") else {
        return false;
    };
    let bytes = uuid.as_bytes();
    if bytes.len() != 36
        || bytes[8] != b'-'
        || bytes[13] != b'-'
        || bytes[18] != b'-'
        || bytes[23] != b'-'
    {
        return false;
    }
    if bytes[14] != b'4' || !matches!(bytes[19], b'8' | b'9' | b'a' | b'b') {
        return false;
    }
    bytes.iter().enumerate().all(|(index, byte)| {
        matches!(index, 8 | 13 | 18 | 23)
            || (*byte >= b'0' && *byte <= b'9')
            || (*byte >= b'a' && *byte <= b'f')
    })
}

fn configure_connection(connection: &Connection) -> Result<(), Box<dyn std::error::Error>> {
    connection
        .busy_timeout(OUTBOX_OPEN_PROFILE.busy_timeout)
        .map_err(|error| storage_error("configure busy timeout", error))?;
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .map_err(|error| storage_error("enable foreign keys", error))?;
    connection
        .pragma_update(None, "journal_mode", OUTBOX_OPEN_PROFILE.journal_mode)
        .map_err(|error| storage_error("configure journal mode", error))?;
    let journal_mode: String = connection
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .map_err(|error| storage_error("verify journal mode", error))?;
    if !journal_mode.eq_ignore_ascii_case(OUTBOX_OPEN_PROFILE.journal_mode) {
        return Err(storage_message(
            "SQLite did not select the required journal mode",
        ));
    }
    connection
        .pragma_update(None, "synchronous", OUTBOX_OPEN_PROFILE.synchronous)
        .map_err(|error| storage_error("configure synchronous mode", error))?;
    Ok(())
}

fn configure_read_only_connection(
    connection: &Connection,
) -> Result<(), Box<dyn std::error::Error>> {
    connection
        .busy_timeout(OUTBOX_OPEN_PROFILE.busy_timeout)
        .map_err(|error| storage_error("configure health busy timeout", error))?;
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .map_err(|error| storage_error("enable health foreign keys", error))?;
    Ok(())
}

fn migrate_schema(connection: &mut Connection) -> Result<(), Box<dyn std::error::Error>> {
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS meta (
                 key TEXT PRIMARY KEY NOT NULL,
                 value TEXT NOT NULL
             )",
        )
        .map_err(|error| storage_error("create metadata table", error))?;

    let transaction = connection
        .transaction()
        .map_err(|error| storage_error("begin schema migration", error))?;
    let version = transaction
        .query_row(
            "SELECT value FROM meta WHERE key = 'schema_version'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|error| storage_error("read schema version", error))?;
    let version = match version {
        None => 0,
        Some(value) => value
            .parse::<i64>()
            .map_err(|_| storage_message("outbox schema version is invalid"))?,
    };
    if !(0..=OUTBOX_SCHEMA_VERSION).contains(&version) {
        if version > OUTBOX_SCHEMA_VERSION {
            return Err(storage_message("outbox schema is newer than this build"));
        }
        return Err(storage_message("outbox schema version is invalid"));
    }

    let mut migrated_version = version;
    if migrated_version < 1 {
        transaction
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS events (
                     event_id TEXT PRIMARY KEY NOT NULL,
                     payload BLOB NOT NULL,
                     payload_hash BLOB NOT NULL,
                     created_at INTEGER NOT NULL,
                     CHECK(length(event_id) > 0),
                     CHECK(length(payload) > 0),
                     CHECK(length(payload_hash) = 32)
                 );
                 CREATE TABLE IF NOT EXISTS deliveries (
                     event_id TEXT NOT NULL,
                     sink_id TEXT NOT NULL,
                     state TEXT NOT NULL CHECK(state IN ('pending', 'acked', 'blocked', 'dead')),
                     attempt_count INTEGER NOT NULL CHECK(attempt_count >= 0),
                     next_attempt_at INTEGER,
                     last_error_class TEXT,
                     last_error_status INTEGER,
                     updated_at INTEGER NOT NULL,
                     PRIMARY KEY(event_id, sink_id),
                     FOREIGN KEY(event_id) REFERENCES events(event_id) ON DELETE CASCADE
                 );
                 CREATE INDEX IF NOT EXISTS deliveries_ready_idx
                     ON deliveries(sink_id, state, next_attempt_at);
                ",
            )
            .map_err(|error| storage_error("migrate schema", error))?;
        transaction
            .execute(
                "INSERT INTO meta (key, value) VALUES ('schema_version', '1')
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                [],
            )
            .map_err(|error| storage_error("write schema version", error))?;
        transaction
            .execute(
                "INSERT INTO meta (key, value) VALUES (?1, ?2)
                 ON CONFLICT(key) DO NOTHING",
                params!["journal_namespace", Uuid::new_v4().to_string()],
            )
            .map_err(|error| storage_error("write journal namespace", error))?;
        migrated_version = 1;
    }
    if migrated_version < 2 {
        transaction
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS ingest_cursor (
                     id INTEGER PRIMARY KEY CHECK(id = 1),
                     journal_namespace TEXT NOT NULL,
                     journal_path_hash TEXT NOT NULL,
                     generation_id TEXT NOT NULL,
                     byte_offset INTEGER NOT NULL CHECK(byte_offset >= 0),
                     observed_length INTEGER NOT NULL CHECK(observed_length >= 0),
                     window_start INTEGER NOT NULL CHECK(window_start >= 0),
                     prefix_hash BLOB NOT NULL CHECK(length(prefix_hash) = 32),
                     window_hash BLOB NOT NULL CHECK(length(window_hash) = 32),
                     updated_at INTEGER NOT NULL
                 )",
            )
            .map_err(|error| storage_error("migrate ingest cursor", error))?;
        migrated_version = 2;
    }
    if migrated_version < 3 {
        transaction
            .execute_batch(
                "DROP INDEX IF EXISTS deliveries_ready_idx;
                 ALTER TABLE deliveries RENAME TO deliveries_v2;
                 CREATE TABLE deliveries (
                     event_id TEXT NOT NULL,
                     sink_id TEXT NOT NULL,
                     state TEXT NOT NULL CHECK(state IN ('pending', 'acked', 'blocked', 'dead')),
                     attempt_count INTEGER NOT NULL CHECK(attempt_count >= 0),
                     next_attempt_at INTEGER,
                     last_error_class TEXT,
                     last_error_status INTEGER,
                     updated_at INTEGER NOT NULL,
                     PRIMARY KEY(event_id, sink_id),
                     FOREIGN KEY(event_id) REFERENCES events(event_id) ON DELETE CASCADE
                 );
                 INSERT INTO deliveries
                     (event_id, sink_id, state, attempt_count, next_attempt_at,
                      last_error_class, last_error_status, updated_at)
                 SELECT event_id, sink_id, state, attempt_count, next_attempt_at,
                        last_error_class, last_error_status, updated_at
                 FROM deliveries_v2;
                 DROP TABLE deliveries_v2;
                 CREATE INDEX deliveries_ready_idx
                     ON deliveries(sink_id, state, next_attempt_at);",
            )
            .map_err(|error| storage_error("migrate delivery states", error))?;
        migrated_version = 3;
    }
    if migrated_version < 4 {
        transaction
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS event_origins (
                     event_id TEXT NOT NULL,
                     generation_id TEXT NOT NULL,
                     byte_offset INTEGER NOT NULL CHECK(byte_offset >= 0),
                     PRIMARY KEY(event_id, generation_id, byte_offset),
                     FOREIGN KEY(event_id) REFERENCES events(event_id) ON DELETE CASCADE
                 );
                 CREATE INDEX IF NOT EXISTS event_origins_generation_idx
                     ON event_origins(generation_id, event_id);
                 CREATE TABLE IF NOT EXISTS journal_generations (
                     generation_id TEXT PRIMARY KEY NOT NULL,
                     journal_path_hash TEXT NOT NULL,
                     observed_at INTEGER NOT NULL
                 );
                 CREATE INDEX IF NOT EXISTS journal_generations_path_idx
                     ON journal_generations(journal_path_hash);",
            )
            .map_err(|error| storage_error("migrate generation metadata", error))?;
        migrated_version = 4;
    }
    if migrated_version < 5 {
        transaction
            .execute_batch(
                "DROP INDEX IF EXISTS journal_generations_path_idx;
                 ALTER TABLE journal_generations RENAME TO journal_generations_v4;
                 CREATE TABLE journal_generations (
                     generation_id TEXT PRIMARY KEY NOT NULL,
                     journal_path_hash TEXT NOT NULL,
                     observed_at INTEGER NOT NULL,
                     lifecycle TEXT NOT NULL DEFAULT 'present'
                         CHECK(lifecycle IN ('present', 'prune_pending', 'pruned')),
                     pruned_at INTEGER,
                     CHECK(
                         (lifecycle = 'pruned' AND pruned_at IS NOT NULL)
                         OR
                         (lifecycle IN ('present', 'prune_pending') AND pruned_at IS NULL)
                     ),
                     CHECK(pruned_at IS NULL OR pruned_at >= 0)
                 );
                 INSERT INTO journal_generations
                     (generation_id, journal_path_hash, observed_at, lifecycle, pruned_at)
                 SELECT generation_id, journal_path_hash, observed_at, 'present', NULL
                 FROM journal_generations_v4;
                 DROP TABLE journal_generations_v4;
                 CREATE INDEX journal_generations_path_idx
                     ON journal_generations(journal_path_hash);",
            )
            .map_err(|error| storage_error("migrate generation lifecycle", error))?;
        migrated_version = 5;
    }
    if migrated_version < 6 {
        transaction
            .execute_batch(
                "CREATE TABLE sink_health (
                     sink_id TEXT PRIMARY KEY NOT NULL,
                     last_success_at INTEGER,
                     last_error_at INTEGER,
                     last_error_class TEXT,
                     last_error_status INTEGER,
                     CHECK(last_success_at IS NULL OR last_success_at >= 0),
                     CHECK(last_error_at IS NULL OR last_error_at >= 0)
                 );
                 INSERT INTO sink_health (sink_id)
                 SELECT DISTINCT sink_id FROM deliveries;
                 UPDATE sink_health
                 SET last_success_at = (
                     SELECT MAX(updated_at) FROM deliveries
                     WHERE deliveries.sink_id = sink_health.sink_id
                       AND deliveries.state = 'acked'
                 );
                 UPDATE sink_health
                 SET last_error_at = (
                         SELECT updated_at FROM deliveries
                         WHERE deliveries.sink_id = sink_health.sink_id
                           AND last_error_class IS NOT NULL
                         ORDER BY updated_at DESC, event_id DESC LIMIT 1
                     ),
                     last_error_class = (
                         SELECT last_error_class FROM deliveries
                         WHERE deliveries.sink_id = sink_health.sink_id
                           AND last_error_class IS NOT NULL
                         ORDER BY updated_at DESC, event_id DESC LIMIT 1
                     ),
                     last_error_status = (
                         SELECT last_error_status FROM deliveries
                         WHERE deliveries.sink_id = sink_health.sink_id
                           AND last_error_class IS NOT NULL
                         ORDER BY updated_at DESC, event_id DESC LIMIT 1
                     );",
            )
            .map_err(|error| storage_error("migrate sink health", error))?;
        migrated_version = 6;
    }
    if migrated_version != version {
        transaction
            .execute(
                "UPDATE meta SET value = ?1 WHERE key = 'schema_version'",
                params![migrated_version.to_string()],
            )
            .map_err(|error| storage_error("update schema version", error))?;
    }

    transaction
        .commit()
        .map_err(|error| storage_error("commit schema migration", error))?;
    Ok(())
}

fn journal_namespace(connection: &Connection) -> Result<String, Box<dyn std::error::Error>> {
    let value = connection
        .query_row(
            "SELECT value FROM meta WHERE key = 'journal_namespace'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|error| storage_error("read journal namespace", error))?
        .ok_or_else(|| storage_message("outbox journal namespace is missing"))?;
    bounded_cursor_text(&value, "journal namespace")
}

fn ensure_journal_path(
    transaction: &Transaction<'_>,
    path_hash: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let existing = transaction
        .query_row(
            "SELECT value FROM meta WHERE key = 'journal_path_hash'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|error| storage_error("read journal path identity", error))?;
    match existing {
        Some(existing) if existing != path_hash => Err(storage_message(
            "outbox is bound to a different canonical JSONL journal",
        )),
        Some(_) => Ok(()),
        None => transaction
            .execute(
                "INSERT INTO meta (key, value) VALUES ('journal_path_hash', ?1)",
                params![path_hash],
            )
            .map(|_| ())
            .map_err(|error| storage_error("bind canonical JSONL journal", error)),
    }
}

fn ensure_sink_identities(
    transaction: &Transaction<'_>,
    sink_ids: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let expected = serde_json::to_string(sink_ids)
        .map_err(|error| storage_error("encode durable sink identities", error))?;
    let existing = transaction
        .query_row(
            "SELECT value FROM meta WHERE key = 'durable_sink_ids'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|error| storage_error("read durable sink identities", error))?;
    match existing {
        Some(existing) => {
            let parsed: Vec<String> = serde_json::from_str(&existing)
                .map_err(|_| storage_message("stored durable sink identities are invalid"))?;
            if parsed != sink_ids {
                return Err(storage_message(
                    "configured durable sink identities changed",
                ));
            }
            Ok(())
        }
        None => transaction
            .execute(
                "INSERT INTO meta (key, value) VALUES ('durable_sink_ids', ?1)",
                params![expected],
            )
            .map(|_| ())
            .map_err(|error| storage_error("bind durable sink identities", error)),
    }
}

fn read_ingest_cursor(
    connection: &Connection,
) -> Result<Option<IngestCursor>, Box<dyn std::error::Error>> {
    let row = connection
        .query_row(
            "SELECT journal_namespace, journal_path_hash, generation_id, byte_offset,
                    observed_length, window_start, prefix_hash, window_hash
             FROM ingest_cursor WHERE id = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                ))
            },
        )
        .optional()
        .map_err(|error| storage_error("read ingest cursor", error))?;
    let Some((
        journal_namespace,
        journal_path_hash,
        generation_id,
        byte_offset,
        observed_length,
        window_start,
        prefix_hash,
        window_hash,
    )) = row
    else {
        return Ok(None);
    };
    let prefix_hash: [u8; 32] = prefix_hash
        .as_slice()
        .try_into()
        .map_err(|_| storage_message("stored ingest cursor prefix hash is invalid"))?;
    let window_hash: [u8; 32] = window_hash
        .as_slice()
        .try_into()
        .map_err(|_| storage_message("stored ingest cursor window hash is invalid"))?;
    Ok(Some(IngestCursor {
        journal_namespace: bounded_cursor_text(&journal_namespace, "journal namespace")?,
        journal_path_hash: bounded_cursor_text(&journal_path_hash, "journal path hash")?,
        generation_id: bounded_cursor_text(&generation_id, "generation identity")?,
        byte_offset: u64::try_from(byte_offset)
            .map_err(|_| storage_message("stored ingest cursor offset is invalid"))?,
        observed_length: u64::try_from(observed_length)
            .map_err(|_| storage_message("stored ingest cursor length is invalid"))?,
        window_start: u64::try_from(window_start)
            .map_err(|_| storage_message("stored ingest cursor window is invalid"))?,
        prefix_hash,
        window_hash,
    }))
}

fn write_ingest_cursor(
    transaction: &Transaction<'_>,
    cursor: &IngestCursor,
) -> Result<(), Box<dyn std::error::Error>> {
    transaction
        .execute(
            "INSERT INTO ingest_cursor
             (id, journal_namespace, journal_path_hash, generation_id, byte_offset,
              observed_length, window_start, prefix_hash, window_hash, updated_at)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(id) DO UPDATE SET
                 journal_namespace = excluded.journal_namespace,
                 journal_path_hash = excluded.journal_path_hash,
                 generation_id = excluded.generation_id,
                 byte_offset = excluded.byte_offset,
                 observed_length = excluded.observed_length,
                 window_start = excluded.window_start,
                 prefix_hash = excluded.prefix_hash,
                 window_hash = excluded.window_hash,
                 updated_at = excluded.updated_at",
            params![
                &cursor.journal_namespace,
                &cursor.journal_path_hash,
                &cursor.generation_id,
                i64::try_from(cursor.byte_offset)
                    .map_err(|_| storage_message("ingest cursor offset is too large"))?,
                i64::try_from(cursor.observed_length)
                    .map_err(|_| storage_message("ingest cursor length is too large"))?,
                i64::try_from(cursor.window_start)
                    .map_err(|_| storage_message("ingest cursor window is too large"))?,
                cursor.prefix_hash.as_slice(),
                cursor.window_hash.as_slice(),
                unix_seconds(),
            ],
        )
        .map(|_| ())
        .map_err(|error| storage_error("write ingest cursor", error))
}

fn decode_error_class(
    class: Option<&str>,
    status: Option<i64>,
) -> Result<Option<DeliveryErrorClass>, Box<dyn std::error::Error>> {
    let Some(class) = class else {
        if status.is_some() {
            return Err(storage_message("stored error status has no error class"));
        }
        return Ok(None);
    };
    let status = status
        .map(u16::try_from)
        .transpose()
        .map_err(|_| storage_message("stored error status is invalid"))?;
    let value = match class {
        "transport_no_response" if status.is_none() => DeliveryErrorClass::TransportNoResponse,
        "timeout" if status.is_none() => DeliveryErrorClass::Timeout,
        "http_status" => DeliveryErrorClass::HttpStatus {
            status: status.ok_or_else(|| storage_message("HTTP error status is missing"))?,
        },
        "sink_application_rejected" if status.is_none() => {
            DeliveryErrorClass::SinkApplicationRejected
        }
        "authentication_blocked" => DeliveryErrorClass::AuthenticationBlocked {
            status: status.ok_or_else(|| storage_message("authentication status is missing"))?,
        },
        "payload_collision" if status.is_none() => DeliveryErrorClass::PayloadCollision,
        "durable_storage" if status.is_none() => DeliveryErrorClass::DurableStorage,
        "unknown_internal" if status.is_none() => DeliveryErrorClass::UnknownInternal,
        _ => return Err(storage_message("stored delivery error class is invalid")),
    };
    Ok(Some(value))
}

fn encode_error_class(class: Option<DeliveryErrorClass>) -> (Option<&'static str>, Option<u16>) {
    match class {
        None => (None, None),
        Some(DeliveryErrorClass::HttpStatus { status }) => (Some("http_status"), Some(status)),
        Some(DeliveryErrorClass::AuthenticationBlocked { status }) => {
            (Some("authentication_blocked"), Some(status))
        }
        Some(class) => (Some(class.as_str()), None),
    }
}

fn path_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn ensure_private_parent(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let existed = match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err("outbox parent is not a private directory".into());
            }
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    if !existed {
        fs::create_dir_all(path)?;
        set_directory_mode(path, OUTBOX_DIRECTORY_MODE)?;
    }
    validate_private_directory(path)
}

fn validate_private_directory(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("outbox parent is not a private directory".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err("outbox parent is not owned by the effective user".into());
        }
        let mode = metadata.permissions().mode() & 0o7777;
        if mode & 0o077 != 0 || mode & 0o700 != 0o700 {
            return Err("outbox parent permissions are too broad or not writable".into());
        }
    }
    Ok(())
}

fn create_private_database(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = OpenOptions::new();
    options.create_new(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(OUTBOX_DATABASE_MODE);
    }
    match options.open(path) {
        Ok(file) => {
            set_file_mode(&file, OUTBOX_DATABASE_MODE)?;
            file.sync_all()?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn validate_private_database(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("outbox database is not a regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err("outbox database is not owned by the effective user".into());
        }
        if metadata.nlink() > 1 {
            return Err("outbox database hard links are not allowed".into());
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("outbox database permissions are too broad".into());
        }
    }
    Ok(())
}

fn set_directory_mode(path: &Path, mode: u32) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
    Ok(())
}

fn set_file_mode(file: &std::fs::File, mode: u32) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (file, mode);
    }
    Ok(())
}

pub(crate) fn unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().min(i64::MAX as u64) as i64)
        .unwrap_or(0)
}

pub(crate) fn unix_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
        .unwrap_or(0)
}

pub(crate) fn next_retry_at(now_millis: i64, base_delay_millis: u64, attempt: u32) -> i64 {
    let exponent = attempt.saturating_sub(1).min(31);
    let multiplier = 1_u64 << exponent;
    let delay = base_delay_millis
        .max(1)
        .saturating_mul(multiplier)
        .min(MAX_RETRY_DELAY_MILLIS);
    now_millis.saturating_add(i64::try_from(delay).unwrap_or(i64::MAX))
}

fn payload_collision_error() -> Box<dyn std::error::Error> {
    Box::new(DeliveryError::new(
        DeliveryErrorClass::PayloadCollision,
        0,
        "outbox event identity maps to different canonical payload bytes",
    ))
}

fn storage_error(context: &str, error: impl fmt::Display) -> Box<dyn std::error::Error> {
    storage_message(format!("outbox {context}: {error}"))
}

fn storage_delivery_error(context: &str, error: impl fmt::Display) -> DeliveryError {
    DeliveryError::new(
        DeliveryErrorClass::DurableStorage,
        0,
        format!("outbox {context}: {error}"),
    )
}

fn delivery_error_from_box(error: Box<dyn std::error::Error>) -> DeliveryError {
    match error.downcast::<DeliveryError>() {
        Ok(error) => *error,
        Err(error) => DeliveryError::new(DeliveryErrorClass::UnknownInternal, 0, error.to_string()),
    }
}

fn storage_message(message: impl Into<String>) -> Box<dyn std::error::Error> {
    Box::new(DeliveryError::new(
        DeliveryErrorClass::DurableStorage,
        0,
        PrivacySanitizer::sanitize(SanitizationContext::Diagnostic, &message.into()),
    ))
}

fn canonical_error(message: impl Into<String>) -> Box<dyn std::error::Error> {
    Box::new(DeliveryError::new(
        DeliveryErrorClass::UnknownInternal,
        0,
        PrivacySanitizer::sanitize(SanitizationContext::Diagnostic, &message.into()),
    ))
}

#[cfg(all(test, not(windows)))]
mod tests {
    use std::fs;

    use rusqlite::{Connection, TransactionBehavior, params};
    use sha2::{Digest, Sha256};
    use tempfile::tempdir;

    use super::{
        CapacityLimits, DeliveryState, DeliveryUpdate, GenerationLifecycle, JournalSnapshot,
        OUTBOX_OPEN_PROFILE, Outbox, canonical_replay_batch, ensure_generation_metadata,
        ensure_journal_path, journal_namespace, journal_path_hash, make_cursor,
        mark_generation_prune_pending, read_generation_metadata, write_ingest_cursor,
    };
    use crate::event::{
        ActivityEventInput, ControlledMarker, Event, Evidence, append_jsonl_events,
        check_serialized_event_markers, serialize_event_for_emission,
    };
    use crate::sink::jsonl::{JsonlGeneration, discover_jsonl_generations};
    use crate::sink::{DeliveryError, DeliveryErrorClass, EventSink, LocalJsonlSink};
    use telltale_schema::clients::ClientId;

    fn record_delivery_for_test(
        outbox: &mut Outbox,
        event_id: &str,
        sink_id: &str,
        state: DeliveryState,
        attempts: u32,
        next_attempt_at: Option<i64>,
        last_error_class: Option<DeliveryErrorClass>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        outbox.record_delivery_at(
            event_id,
            sink_id,
            DeliveryUpdate {
                state,
                attempts,
                next_attempt_at,
                last_error_class,
                updated_at: super::unix_millis(),
            },
        )
    }

    fn marked_event(marker: &str) -> crate::event::Event {
        crate::event::activity_event(ActivityEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "synthetic-outbox-session".to_string(),
            source_path_hash: "synthetic-outbox-source".to_string(),
            tool_name: Some("shell".to_string()),
            tags: vec![format!("synthetic:{marker}")],
            evidence: vec![Evidence {
                field: "tool_result".to_string(),
                redacted_value: format!("token={marker}"),
                hash: None,
                rule_id: None,
            }],
            risk_contributions: Vec::new(),
            event_time: None,
        })
        .expect("synthetic activity event")
    }

    fn canonical_bytes(event: &crate::event::Event) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut serializer = serde_json::Serializer::new(&mut bytes);
        serialize_event_for_emission(event, &mut serializer).expect("canonical event bytes");
        bytes
    }

    fn assert_payload_is_safe(bytes: &[u8], marker: &str, case_id: &str) {
        assert!(
            check_serialized_event_markers(
                bytes,
                case_id,
                &[ControlledMarker {
                    id: "outbox-marker",
                    value: marker,
                }],
            )
            .is_ok(),
            "outbox payload retained a synthetic marker"
        );
        let value: serde_json::Value = serde_json::from_slice(bytes).expect("Event 3.0 JSON");
        assert_eq!(value["schema_version"], "3.0");
        assert!(value["event_id"].is_string());
        assert!(value["event_type"].is_string());
    }

    fn private_outbox_path(temp: &tempfile::TempDir) -> std::path::PathBuf {
        let path = temp.path().join("private-outbox").join("outbox.sqlite");
        create_private_parent(path.parent().expect("outbox parent"));
        path
    }

    #[cfg(test)]
    fn create_private_parent(path: &std::path::Path) {
        fs::create_dir_all(path).expect("private parent");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .expect("private parent mode");
        }
    }

    fn capacity_limits(max_pending_events: u64, max_pending_bytes: u64) -> CapacityLimits {
        CapacityLimits {
            max_pending_events,
            max_pending_bytes,
        }
    }

    fn named_private_outbox_path(temp: &tempfile::TempDir, name: &str) -> std::path::PathBuf {
        let path = temp.path().join(name).join("outbox.sqlite");
        create_private_parent(path.parent().expect("outbox parent"));
        path
    }

    fn generation_lifecycle(outbox: &Outbox, generation_id: &str) -> GenerationLifecycle {
        read_generation_metadata(&outbox.connection)
            .expect("generation metadata")
            .into_iter()
            .find(|record| record.generation_id == generation_id)
            .map(|record| record.lifecycle)
            .expect("generation metadata row")
    }

    fn install_generation_state(
        outbox: &mut Outbox,
        log_path: &std::path::Path,
        generations: &[JsonlGeneration],
        cursor: Option<(&JsonlGeneration, usize)>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let namespace = journal_namespace(&outbox.connection)?;
        let path_hash = journal_path_hash(log_path);
        let transaction = outbox
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_journal_path(&transaction, &path_hash)?;
        ensure_generation_metadata(&transaction, &path_hash, generations, &[])?;
        if let Some((generation, offset)) = cursor {
            let snapshot = JournalSnapshot {
                identity: generation.identity.clone(),
                bytes: fs::read(&generation.path)?,
            };
            let cursor = make_cursor(&namespace, &path_hash, &snapshot, offset)?;
            write_ingest_cursor(&transaction, &cursor)?;
        }
        transaction.commit()?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn journal_path_hash_is_stable_across_missing_to_created_symlinked_ancestor() {
        use std::os::unix::fs::symlink;

        let temp = tempdir().expect("tempdir");
        let real_parent = temp.path().join("real");
        let alias_parent = temp.path().join("alias");
        fs::create_dir(&real_parent).expect("real parent");
        symlink(&real_parent, &alias_parent).expect("symlink parent");

        let journal_path = alias_parent.join("events.jsonl");
        let before = journal_path_hash(&journal_path);
        fs::write(&journal_path, b"synthetic journal\n").expect("journal leaf");
        let after = journal_path_hash(&journal_path);

        assert_eq!(before, after);
    }

    #[cfg(unix)]
    #[test]
    fn journal_path_hash_distinguishes_symlink_then_parent_alias() {
        use std::os::unix::fs::symlink;

        let temp = tempdir().expect("tempdir");
        let root = temp.path().join("root");
        let target_nested = temp.path().join("target").join("nested");
        fs::create_dir_all(&root).expect("root");
        fs::create_dir_all(&target_nested).expect("target nested");
        symlink(&target_nested, root.join("alias")).expect("alias symlink");

        let root_journal = root.join("events.jsonl");
        let aliased_parent_journal = root.join("alias").join("..").join("events.jsonl");
        fs::write(&root_journal, b"synthetic-root-journal\n").expect("root journal");
        fs::write(&aliased_parent_journal, b"synthetic-target-journal\n")
            .expect("aliased parent journal");

        assert_eq!(
            fs::read(&root_journal).expect("read root journal"),
            b"synthetic-root-journal\n"
        );
        assert_eq!(
            fs::read(&aliased_parent_journal).expect("read aliased parent journal"),
            b"synthetic-target-journal\n"
        );
        assert_ne!(
            journal_path_hash(&root_journal),
            journal_path_hash(&aliased_parent_journal)
        );
    }

    fn create_legacy_base(connection: &Connection, version: i64) {
        connection
            .execute_batch(
                "CREATE TABLE meta (
                     key TEXT PRIMARY KEY NOT NULL,
                     value TEXT NOT NULL
                 );
                 CREATE TABLE events (
                     event_id TEXT PRIMARY KEY NOT NULL,
                     payload BLOB NOT NULL,
                     payload_hash BLOB NOT NULL,
                     created_at INTEGER NOT NULL
                 );
                 CREATE TABLE deliveries (
                     event_id TEXT NOT NULL,
                     sink_id TEXT NOT NULL,
                     state TEXT NOT NULL,
                     attempt_count INTEGER NOT NULL,
                     next_attempt_at INTEGER,
                     last_error_class TEXT,
                     last_error_status INTEGER,
                     updated_at INTEGER NOT NULL,
                     PRIMARY KEY(event_id, sink_id)
                 );
                 CREATE TABLE ingest_cursor (
                     id INTEGER PRIMARY KEY CHECK(id = 1),
                     journal_namespace TEXT NOT NULL,
                     journal_path_hash TEXT NOT NULL,
                     generation_id TEXT NOT NULL,
                     byte_offset INTEGER NOT NULL,
                     observed_length INTEGER NOT NULL,
                     window_start INTEGER NOT NULL,
                     prefix_hash BLOB NOT NULL,
                     window_hash BLOB NOT NULL,
                     updated_at INTEGER NOT NULL
                 );",
            )
            .expect("create legacy outbox tables");
        connection
            .execute(
                "INSERT INTO meta (key, value) VALUES
                 ('schema_version', ?1),
                 ('journal_namespace', 'legacy-test-namespace'),
                 ('journal_path_hash', ?2),
                 ('durable_sink_ids', '[\"sink-a\",\"sink-b\"]')",
                params![version.to_string(), "a".repeat(64)],
            )
            .expect("insert legacy metadata");
    }

    fn insert_legacy_event(connection: &Connection, event: &Event, created_at: i64) {
        let payload = canonical_bytes(event);
        let payload_hash: [u8; 32] = Sha256::digest(&payload).into();
        connection
            .execute(
                "INSERT INTO events (event_id, payload, payload_hash, created_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![event.event_id, payload, payload_hash.as_slice(), created_at],
            )
            .expect("insert legacy event");
    }

    fn insert_legacy_cursor(connection: &Connection, generation_id: &str, offset: i64) {
        connection
            .execute(
                "INSERT INTO ingest_cursor
                 (id, journal_namespace, journal_path_hash, generation_id, byte_offset,
                  observed_length, window_start, prefix_hash, window_hash, updated_at)
                 VALUES (1, 'legacy-test-namespace', ?1, ?2, ?3, ?4, 0, ?5, ?6, 900)",
                params![
                    "a".repeat(64),
                    generation_id,
                    offset,
                    offset,
                    vec![0x11_u8; 32],
                    vec![0x22_u8; 32],
                ],
            )
            .expect("insert legacy cursor");
    }

    fn table_exists(connection: &Connection, table: &str) -> bool {
        connection
            .query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1
                 )",
                params![table],
                |row| row.get::<_, i64>(0),
            )
            .expect("query table existence")
            == 1
    }

    #[test]
    fn stores_canonical_terminal_event_bytes_and_reuses_them_for_retry_and_dead_state() {
        let marker = "TT_PRIVACY_OUTBOX_26";
        let temp = tempdir().expect("temporary directory");
        let path = private_outbox_path(&temp);
        let event = marked_event(marker);
        let expected = canonical_bytes(&event);
        let expected_hash: [u8; 32] = Sha256::digest(&expected).into();

        let mut outbox = Outbox::open(&path).expect("open outbox");
        outbox
            .insert_event(&event, &["sink-a"])
            .expect("insert event");

        let stored = outbox
            .get_event(&event.event_id)
            .expect("get event")
            .expect("stored event");
        assert_eq!(stored.event_id, event.event_id);
        assert_eq!(stored.payload, expected);
        assert_eq!(stored.payload_hash, expected_hash);
        assert_payload_is_safe(&stored.payload, marker, "outbox-event-payload");

        record_delivery_for_test(
            &mut outbox,
            &event.event_id,
            "sink-a",
            DeliveryState::Pending,
            1,
            Some(1_700_000_000),
            Some(DeliveryErrorClass::HttpStatus { status: 503 }),
        )
        .expect("record retry state");
        let retry_payload = outbox
            .get_event(&event.event_id)
            .expect("get retry payload")
            .expect("retry event")
            .payload;
        assert_eq!(retry_payload, expected);
        assert_payload_is_safe(&retry_payload, marker, "outbox-retry-payload");

        record_delivery_for_test(
            &mut outbox,
            &event.event_id,
            "sink-a",
            DeliveryState::Dead,
            2,
            None,
            Some(DeliveryErrorClass::SinkApplicationRejected),
        )
        .expect("record dead state");
        let dead_payload = outbox
            .get_event(&event.event_id)
            .expect("get dead payload")
            .expect("dead event")
            .payload;
        assert_eq!(dead_payload, expected);
        assert_payload_is_safe(&dead_payload, marker, "outbox-dead-payload");
    }

    #[test]
    fn release_blocked_for_sink_releases_matching_rows_without_resetting_history() {
        let temp = tempdir().expect("temporary directory");
        let path = private_outbox_path(&temp);
        let events = [
            marked_event("TT_RELEASE_BLOCKED_FIRST"),
            marked_event("TT_RELEASE_BLOCKED_SECOND"),
            marked_event("TT_RELEASE_PENDING"),
            marked_event("TT_RELEASE_ACKED"),
            marked_event("TT_RELEASE_DEAD"),
        ];
        let mut outbox = Outbox::open(&path).expect("open outbox");
        for event in &events {
            outbox
                .insert_event(event, &["sink-a", "sink-b"])
                .expect("insert event");
        }

        record_delivery_for_test(
            &mut outbox,
            &events[0].event_id,
            "sink-a",
            DeliveryState::Blocked,
            3,
            None,
            Some(DeliveryErrorClass::AuthenticationBlocked { status: 403 }),
        )
        .expect("record first blocked row");
        record_delivery_for_test(
            &mut outbox,
            &events[1].event_id,
            "sink-a",
            DeliveryState::Blocked,
            5,
            None,
            Some(DeliveryErrorClass::AuthenticationBlocked { status: 401 }),
        )
        .expect("record second blocked row");
        record_delivery_for_test(
            &mut outbox,
            &events[2].event_id,
            "sink-a",
            DeliveryState::Pending,
            2,
            Some(100),
            Some(DeliveryErrorClass::HttpStatus { status: 429 }),
        )
        .expect("record pending row");
        record_delivery_for_test(
            &mut outbox,
            &events[3].event_id,
            "sink-a",
            DeliveryState::Acked,
            4,
            None,
            None,
        )
        .expect("record acked row");
        record_delivery_for_test(
            &mut outbox,
            &events[4].event_id,
            "sink-a",
            DeliveryState::Dead,
            6,
            None,
            Some(DeliveryErrorClass::SinkApplicationRejected),
        )
        .expect("record dead row");
        record_delivery_for_test(
            &mut outbox,
            &events[0].event_id,
            "sink-b",
            DeliveryState::Blocked,
            7,
            None,
            Some(DeliveryErrorClass::AuthenticationBlocked { status: 403 }),
        )
        .expect("record other sink blocked row");

        let now = 1_700_000_123_456;
        assert_eq!(
            outbox
                .release_blocked_for_sink("sink-a", now)
                .expect("release blocked rows"),
            2
        );
        for (event, attempts, error_class) in [
            (
                &events[0],
                3,
                Some(DeliveryErrorClass::AuthenticationBlocked { status: 403 }),
            ),
            (
                &events[1],
                5,
                Some(DeliveryErrorClass::AuthenticationBlocked { status: 401 }),
            ),
        ] {
            let row = outbox
                .get_delivery(&event.event_id, "sink-a")
                .expect("released delivery lookup")
                .expect("released delivery row");
            assert_eq!(row.state, DeliveryState::Pending);
            assert_eq!(row.attempts, attempts);
            assert_eq!(row.next_attempt_at, Some(now));
            assert_eq!(row.last_error_class, error_class);
            assert_eq!(row.updated_at, now);
        }

        let pending = outbox
            .get_delivery(&events[2].event_id, "sink-a")
            .expect("pending delivery lookup")
            .expect("pending delivery row");
        assert_eq!(pending.state, DeliveryState::Pending);
        assert_eq!(pending.attempts, 2);
        assert_eq!(pending.next_attempt_at, Some(100));
        assert_eq!(
            pending.last_error_class,
            Some(DeliveryErrorClass::HttpStatus { status: 429 })
        );
        assert_eq!(
            outbox
                .get_delivery(&events[3].event_id, "sink-a")
                .expect("acked delivery lookup")
                .expect("acked delivery row")
                .state,
            DeliveryState::Acked
        );
        assert_eq!(
            outbox
                .get_delivery(&events[4].event_id, "sink-a")
                .expect("dead delivery lookup")
                .expect("dead delivery row")
                .state,
            DeliveryState::Dead
        );
        assert_eq!(
            outbox
                .get_delivery(&events[0].event_id, "sink-b")
                .expect("other sink delivery lookup")
                .expect("other sink delivery row")
                .state,
            DeliveryState::Blocked
        );
        assert_eq!(
            outbox
                .release_blocked_for_sink("sink-a", now)
                .expect("repeat release"),
            0
        );
        drop(outbox);

        let reopened = Outbox::open(&path).expect("reopen outbox");
        let row = reopened
            .get_delivery(&events[0].event_id, "sink-a")
            .expect("reopened delivery lookup")
            .expect("reopened delivery row");
        assert_eq!(row.state, DeliveryState::Pending);
        assert_eq!(row.attempts, 3);
        assert_eq!(row.next_attempt_at, Some(now));
        assert_eq!(
            row.last_error_class,
            Some(DeliveryErrorClass::AuthenticationBlocked { status: 403 })
        );
    }

    #[test]
    fn duplicate_event_is_harmless_and_missing_sink_rows_are_added_without_resetting_state() {
        let temp = tempdir().expect("temporary directory");
        let path = private_outbox_path(&temp);
        let event = marked_event("TT_OUTBOX_DUPLICATE_26");
        let mut outbox = Outbox::open(&path).expect("open outbox");

        outbox
            .insert_event(&event, &["sink-a", "sink-b"])
            .expect("first insert");
        record_delivery_for_test(
            &mut outbox,
            &event.event_id,
            "sink-a",
            DeliveryState::Acked,
            1,
            None,
            None,
        )
        .expect("ack first sink");

        outbox
            .insert_event(&event, &["sink-a", "sink-b", "sink-c"])
            .expect("duplicate insert");

        assert_eq!(
            outbox
                .get_delivery(&event.event_id, "sink-a")
                .expect("get sink a")
                .expect("sink a row")
                .state,
            DeliveryState::Acked
        );
        assert_eq!(
            outbox
                .get_delivery(&event.event_id, "sink-b")
                .expect("get sink b")
                .expect("sink b row")
                .state,
            DeliveryState::Pending
        );
        assert_eq!(
            outbox
                .get_delivery(&event.event_id, "sink-c")
                .expect("get sink c")
                .expect("sink c row")
                .state,
            DeliveryState::Pending
        );
    }

    #[test]
    fn same_event_id_with_different_canonical_bytes_fails_closed_as_payload_collision() {
        let temp = tempdir().expect("temporary directory");
        let path = private_outbox_path(&temp);
        let event = marked_event("TT_OUTBOX_COLLISION_A_26");
        let mut different = event.clone();
        different.evidence[0].redacted_value = "synthetic second payload".to_string();

        let mut outbox = Outbox::open(&path).expect("open outbox");
        outbox
            .insert_event(&event, &["sink-a"])
            .expect("first insert");
        let error = outbox
            .insert_event(&different, &["sink-b"])
            .expect_err("different bytes for one event ID must fail");
        let delivery = error
            .downcast_ref::<DeliveryError>()
            .expect("structured delivery error");
        assert_eq!(delivery.class, DeliveryErrorClass::PayloadCollision);
        assert!(
            outbox
                .get_delivery(&event.event_id, "sink-b")
                .expect("collision lookup")
                .is_none(),
            "collision must not create a delivery row"
        );
    }

    #[test]
    fn sqlite_open_profile_is_explicit_and_schema_migrates_forward_only() {
        let temp = tempdir().expect("temporary directory");
        let path = private_outbox_path(&temp);
        let outbox = Outbox::open(&path).expect("open outbox");

        let foreign_keys: i64 = outbox
            .connection
            .pragma_query_value(None, "foreign_keys", |row| row.get(0))
            .expect("foreign_keys pragma");
        let busy_timeout: i64 = outbox
            .connection
            .pragma_query_value(None, "busy_timeout", |row| row.get(0))
            .expect("busy_timeout pragma");
        let journal_mode: String = outbox
            .connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .expect("journal_mode pragma");
        let synchronous: i64 = outbox
            .connection
            .pragma_query_value(None, "synchronous", |row| row.get(0))
            .expect("synchronous pragma");
        assert_eq!(foreign_keys, 1);
        assert_eq!(
            busy_timeout,
            OUTBOX_OPEN_PROFILE.busy_timeout.as_millis() as i64
        );
        assert_eq!(
            journal_mode.to_ascii_lowercase(),
            OUTBOX_OPEN_PROFILE.journal_mode
        );
        assert_eq!(synchronous, 2, "SQLite FULL synchronous mode is 2");

        let namespace = outbox
            .meta_value("journal_namespace")
            .expect("journal namespace")
            .expect("namespace value");
        assert!(!namespace.is_empty());
        drop(outbox);

        let reopened = Outbox::open(&path).expect("reopen outbox");
        assert_eq!(
            reopened
                .meta_value("journal_namespace")
                .expect("namespace after reopen"),
            Some(namespace)
        );
        drop(reopened);

        let connection = Connection::open(&path).expect("raw connection");
        connection
            .execute(
                "UPDATE meta SET value = '999' WHERE key = 'schema_version'",
                [],
            )
            .expect("make newer schema");
        drop(connection);
        let error = Outbox::open(&path).expect_err("newer schema must not be downgraded");
        let delivery = error
            .downcast_ref::<DeliveryError>()
            .expect("structured schema error");
        assert_eq!(delivery.class, DeliveryErrorClass::DurableStorage);
        assert!(delivery.message.contains("newer"));
    }

    #[test]
    fn migrates_v4_to_current_without_losing_replay_or_generation_state() {
        let temp = tempdir().expect("temporary directory");
        let path = temp.path().join("migration-v4").join("outbox.sqlite");
        create_private_parent(path.parent().expect("outbox parent"));
        let connection = Connection::open(&path).expect("legacy v4 database");
        create_legacy_base(&connection, 4);
        connection
            .execute_batch(
                "CREATE TABLE event_origins (
                     event_id TEXT NOT NULL,
                     generation_id TEXT NOT NULL,
                     byte_offset INTEGER NOT NULL,
                     PRIMARY KEY(event_id, generation_id, byte_offset)
                 );
                 CREATE TABLE journal_generations (
                     generation_id TEXT PRIMARY KEY NOT NULL,
                     journal_path_hash TEXT NOT NULL,
                     observed_at INTEGER NOT NULL
                 );",
            )
            .expect("create v4 generation tables");

        let pending = marked_event("TT_MIGRATE_V4_PENDING");
        let blocked = marked_event("TT_MIGRATE_V4_BLOCKED");
        let acked = marked_event("TT_MIGRATE_V4_ACKED");
        let dead = marked_event("TT_MIGRATE_V4_DEAD");
        for (event, created_at) in [
            (&pending, 101_i64),
            (&blocked, 102),
            (&acked, 103),
            (&dead, 104),
        ] {
            insert_legacy_event(&connection, event, created_at);
        }
        connection
            .execute(
                "INSERT INTO deliveries
                 (event_id, sink_id, state, attempt_count, next_attempt_at,
                  last_error_class, last_error_status, updated_at)
                 VALUES (?1, 'sink-a', 'pending', 2, 1_234,
                         'transport_no_response', NULL, 201),
                        (?2, 'sink-a', 'blocked', 3, NULL,
                         'authentication_blocked', 403, 202),
                        (?3, 'sink-a', 'acked', 4, NULL, NULL, NULL, 203),
                        (?4, 'sink-a', 'dead', 5, NULL,
                         'sink_application_rejected', NULL, 204)",
                params![
                    pending.event_id,
                    blocked.event_id,
                    acked.event_id,
                    dead.event_id
                ],
            )
            .expect("insert v4 delivery states");
        connection
            .execute(
                "INSERT INTO event_origins (event_id, generation_id, byte_offset)
                 VALUES (?1, 'legacy-generation-1', 0),
                        (?2, 'legacy-generation-2', 27)",
                params![pending.event_id, blocked.event_id],
            )
            .expect("insert v4 event origins");
        connection
            .execute(
                "INSERT INTO journal_generations
                 (generation_id, journal_path_hash, observed_at)
                 VALUES ('legacy-generation-1', ?1, 301),
                        ('legacy-generation-2', ?1, 302)",
                params!["a".repeat(64)],
            )
            .expect("insert v4 generation metadata");
        insert_legacy_cursor(&connection, "legacy-generation-2", 27);
        drop(connection);
        make_database_private(&path);

        let outbox = Outbox::open(&path).expect("migrate v4 outbox");
        assert_eq!(
            outbox.meta_value("schema_version").expect("schema version"),
            Some("6".to_string())
        );
        for (event, expected_state, expected_attempts, expected_next, expected_error) in [
            (
                &pending,
                DeliveryState::Pending,
                2,
                Some(1_234),
                Some(DeliveryErrorClass::TransportNoResponse),
            ),
            (
                &blocked,
                DeliveryState::Blocked,
                3,
                None,
                Some(DeliveryErrorClass::AuthenticationBlocked { status: 403 }),
            ),
            (&acked, DeliveryState::Acked, 4, None, None),
            (
                &dead,
                DeliveryState::Dead,
                5,
                None,
                Some(DeliveryErrorClass::SinkApplicationRejected),
            ),
        ] {
            let stored = outbox
                .get_event(&event.event_id)
                .expect("migrated event")
                .expect("event row");
            assert_eq!(stored.payload, canonical_bytes(event));
            let delivery = outbox
                .get_delivery(&event.event_id, "sink-a")
                .expect("migrated delivery")
                .expect("delivery row");
            assert_eq!(delivery.state, expected_state);
            assert_eq!(delivery.attempts, expected_attempts);
            assert_eq!(delivery.next_attempt_at, expected_next);
            assert_eq!(delivery.last_error_class, expected_error);
        }

        let cursor = outbox
            .ingest_cursor()
            .expect("migrated cursor")
            .expect("cursor row");
        assert_eq!(cursor.journal_namespace, "legacy-test-namespace");
        assert_eq!(cursor.journal_path_hash, "a".repeat(64));
        assert_eq!(cursor.generation_id, "legacy-generation-2");
        assert_eq!(cursor.byte_offset, 27);
        assert_eq!(cursor.observed_length, 27);
        assert_eq!(cursor.prefix_hash, [0x11_u8; 32]);
        assert_eq!(cursor.window_hash, [0x22_u8; 32]);

        let origins: Vec<(String, String, i64)> = outbox
            .connection
            .prepare(
                "SELECT event_id, generation_id, byte_offset
                 FROM event_origins ORDER BY generation_id, byte_offset",
            )
            .expect("origins query")
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .expect("origins rows")
            .collect::<Result<_, _>>()
            .expect("origins values");
        assert_eq!(origins.len(), 2);
        assert!(origins.iter().any(|(event_id, generation, offset)| {
            event_id == &pending.event_id && generation == "legacy-generation-1" && *offset == 0
        }));
        assert!(origins.iter().any(|(event_id, generation, offset)| {
            event_id == &blocked.event_id && generation == "legacy-generation-2" && *offset == 27
        }));

        let generations = read_generation_metadata(&outbox.connection).expect("generations");
        assert_eq!(generations.len(), 2);
        assert!(generations.iter().all(|generation| {
            generation.lifecycle == GenerationLifecycle::Present
                && generation.pruned_at.is_none()
                && generation.journal_path_hash == "a".repeat(64)
        }));
        assert!(table_exists(&outbox.connection, "sink_health"));
    }

    #[test]
    fn migrates_v3_to_current_without_fabricating_origins() {
        let temp = tempdir().expect("temporary directory");
        let path = temp.path().join("migration-v3").join("outbox.sqlite");
        create_private_parent(path.parent().expect("outbox parent"));
        let connection = Connection::open(&path).expect("legacy v3 database");
        create_legacy_base(&connection, 3);
        let event = marked_event("TT_MIGRATE_V3_EVENT");
        insert_legacy_event(&connection, &event, 401);
        connection
            .execute(
                "INSERT INTO deliveries
                 (event_id, sink_id, state, attempt_count, next_attempt_at,
                  last_error_class, last_error_status, updated_at)
                 VALUES (?1, 'sink-a', 'pending', 7, 4_321,
                         'http_status', 429, 402)",
                params![event.event_id],
            )
            .expect("insert v3 delivery");
        insert_legacy_cursor(&connection, "legacy-generation-v3", 19);
        drop(connection);
        make_database_private(&path);

        let outbox = Outbox::open(&path).expect("migrate v3 outbox");
        assert_eq!(
            outbox.meta_value("schema_version").expect("schema version"),
            Some("6".to_string())
        );
        assert_eq!(
            outbox
                .get_event(&event.event_id)
                .expect("event lookup")
                .expect("event row")
                .payload,
            canonical_bytes(&event)
        );
        let delivery = outbox
            .get_delivery(&event.event_id, "sink-a")
            .expect("delivery lookup")
            .expect("delivery row");
        assert_eq!(delivery.state, DeliveryState::Pending);
        assert_eq!(delivery.attempts, 7);
        assert_eq!(delivery.next_attempt_at, Some(4_321));
        assert_eq!(
            delivery.last_error_class,
            Some(DeliveryErrorClass::HttpStatus { status: 429 })
        );
        let cursor = outbox
            .ingest_cursor()
            .expect("cursor lookup")
            .expect("cursor row");
        assert_eq!(cursor.generation_id, "legacy-generation-v3");
        assert_eq!(cursor.byte_offset, 19);
        assert!(table_exists(&outbox.connection, "event_origins"));
        assert!(table_exists(&outbox.connection, "journal_generations"));
        assert!(table_exists(&outbox.connection, "sink_health"));
        assert!(
            read_generation_metadata(&outbox.connection)
                .expect("generation metadata")
                .is_empty()
        );
        let origin_count: i64 = outbox
            .connection
            .query_row("SELECT COUNT(*) FROM event_origins", [], |row| row.get(0))
            .expect("origin count");
        assert_eq!(
            origin_count, 0,
            "v3 migration must not invent event origins"
        );
    }

    #[cfg(unix)]
    #[test]
    fn outbox_parent_and_database_are_private() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let temp = tempdir().expect("temporary directory");
        let path = private_outbox_path(&temp);
        let _outbox = Outbox::open(&path).expect("open outbox");
        let parent_mode = fs::metadata(path.parent().expect("outbox parent"))
            .expect("parent metadata")
            .permissions()
            .mode()
            & 0o777;
        let database = fs::metadata(&path).expect("database metadata");
        assert_eq!(parent_mode, 0o700);
        assert_eq!(database.permissions().mode() & 0o777, 0o600);
        assert_eq!(database.nlink(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn broad_outbox_parent_permissions_are_rejected() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempdir().expect("temporary directory");
        let parent = temp.path().join("broad-outbox");
        fs::create_dir(&parent).expect("parent");
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o755)).expect("permissions");
        let error =
            Outbox::open(parent.join("outbox.sqlite")).expect_err("broad parent must be rejected");
        let delivery = error
            .downcast_ref::<DeliveryError>()
            .expect("structured permissions error");
        assert_eq!(delivery.class, DeliveryErrorClass::DurableStorage);
        assert!(!delivery.message.contains("TT_PRIVACY"));
    }

    #[test]
    fn corrupt_outbox_is_a_bounded_durable_storage_error() {
        let temp = tempdir().expect("temporary directory");
        let path = private_outbox_path(&temp);
        fs::write(&path, b"synthetic-not-a-sqlite-database").expect("corrupt database");
        make_database_private(&path);

        let error = Outbox::open(&path).expect_err("corrupt database must fail closed");
        let delivery = error
            .downcast_ref::<DeliveryError>()
            .expect("structured corrupt database error");
        assert_eq!(delivery.class, DeliveryErrorClass::DurableStorage);
        assert!(delivery.message.len() <= 200);
        assert!(!delivery.message.contains("TT_PRIVACY"));
    }

    #[test]
    fn locked_outbox_fails_closed_without_losing_an_accepted_event() {
        use std::time::{Duration, Instant};

        let temp = tempdir().expect("temporary directory");
        let path = private_outbox_path(&temp);
        let accepted = marked_event("TT_OUTBOX_LOCK_ACCEPTED_26");
        let blocked = marked_event("TT_OUTBOX_LOCK_BLOCKED_26");
        let mut holder = Outbox::open(&path).expect("open holding outbox");
        holder
            .insert_event(&accepted, &["sink-a"])
            .expect("accepted event");
        let mut contender = Outbox::open(&path).expect("open second outbox");
        contender
            .connection
            .busy_timeout(Duration::from_millis(25))
            .expect("bounded contender busy timeout");

        holder
            .connection
            .execute_batch("BEGIN EXCLUSIVE")
            .expect("hold an exclusive lock");
        let started = Instant::now();
        let error = contender
            .insert_event(&blocked, &["sink-a"])
            .expect_err("locked outbox must reject the new event");
        let elapsed = started.elapsed();
        holder
            .connection
            .execute_batch("ROLLBACK")
            .expect("release exclusive lock");

        let delivery = error
            .downcast_ref::<DeliveryError>()
            .expect("structured lock error");
        assert_eq!(delivery.class, DeliveryErrorClass::DurableStorage);
        assert!(
            elapsed < Duration::from_secs(1),
            "lock failure was not bounded"
        );
        assert!(delivery.message.len() <= 200);
        assert!(!delivery.message.contains("TT_OUTBOX_LOCK"));
        assert!(
            holder
                .get_event(&accepted.event_id)
                .expect("accepted event lookup")
                .is_some()
        );
        assert!(
            contender
                .get_event(&blocked.event_id)
                .expect("blocked event lookup")
                .is_none()
        );
    }

    #[test]
    fn full_outbox_fails_closed_without_deleting_accepted_rows() {
        let temp = tempdir().expect("temporary directory");
        let path = private_outbox_path(&temp);
        let accepted = marked_event("TT_OUTBOX_FULL_ACCEPTED_26");
        let mut blocked = marked_event("TT_OUTBOX_FULL_BLOCKED_26");
        blocked.evidence = (0..1_200)
            .map(|index| Evidence {
                field: "tool_result".to_string(),
                redacted_value: format!(
                    "synthetic-full-storage-payload-{index:04}-{}",
                    "x".repeat(480)
                ),
                hash: None,
                rule_id: None,
            })
            .collect();

        let mut outbox = Outbox::open(&path).expect("open outbox");
        outbox
            .insert_event(&accepted, &["sink-a"])
            .expect("accepted event");
        let page_count: i64 = outbox
            .connection
            .pragma_query_value(None, "page_count", |row| row.get(0))
            .expect("page count");
        let configured_max: i64 = outbox
            .connection
            .pragma_query_value(None, "max_page_count", |row| row.get(0))
            .expect("maximum page count");
        assert!(configured_max > page_count);
        outbox
            .connection
            .pragma_update(None, "max_page_count", page_count)
            .expect("set deterministic storage limit");

        let error = outbox
            .insert_event(&blocked, &["sink-a"])
            .expect_err("storage limit must reject the new event");
        let delivery = error
            .downcast_ref::<DeliveryError>()
            .expect("structured full-storage error");
        assert_eq!(delivery.class, DeliveryErrorClass::DurableStorage);
        assert!(
            delivery.message.contains("full"),
            "storage limit must report SQLite full, not a renamed error: {}",
            delivery.message
        );
        assert!(delivery.message.len() <= 200);
        assert!(!delivery.message.contains("TT_OUTBOX_FULL"));
        assert!(
            outbox
                .get_event(&accepted.event_id)
                .expect("accepted event lookup")
                .is_some()
        );
        assert_eq!(
            outbox
                .get_delivery(&accepted.event_id, "sink-a")
                .expect("accepted delivery lookup")
                .expect("accepted delivery row")
                .state,
            DeliveryState::Pending
        );
        assert!(
            outbox
                .get_event(&blocked.event_id)
                .expect("blocked event lookup")
                .is_none()
        );
    }

    #[test]
    fn capacity_accepts_exact_event_limit_but_rejects_the_next_event() {
        let temp = tempdir().expect("temporary directory");
        let log_path = temp.path().join("events.jsonl");
        let outbox_path = private_outbox_path(&temp);
        let first = marked_event("TT_CAPACITY_EVENT_FIRST_26");
        let second = marked_event("TT_CAPACITY_EVENT_SECOND_26");
        let first_batch =
            canonical_replay_batch(std::slice::from_ref(&first)).expect("first canonical batch");
        let both_batch = canonical_replay_batch(&[first, second]).expect("two canonical events");
        let outbox = Outbox::open(&outbox_path).expect("open outbox");

        outbox
            .check_capacity_for_payloads(
                &log_path,
                &first_batch.payloads,
                capacity_limits(1, first_batch.payloads[0].bytes.len() as u64),
            )
            .expect("exact event capacity is accepted");
        let error = outbox
            .check_capacity_for_payloads(
                &log_path,
                &both_batch.payloads,
                capacity_limits(1, u64::MAX),
            )
            .expect_err("the next unique event exceeds event capacity");
        assert!(error.to_string().contains("limit_kind=pending_events"));
    }

    #[test]
    fn capacity_accepts_exact_canonical_byte_boundary_but_rejects_the_next_byte() {
        let temp = tempdir().expect("temporary directory");
        let log_path = temp.path().join("events.jsonl");
        let outbox_path = private_outbox_path(&temp);
        let first = marked_event("TT_CAPACITY_BYTES_FIRST_26");
        let second = marked_event("TT_CAPACITY_BYTES_SECOND_26");
        let batch = canonical_replay_batch(&[first, second]).expect("canonical batch");
        let bytes = batch
            .payloads
            .iter()
            .map(|payload| payload.bytes.len() as u64)
            .sum::<u64>();
        let outbox = Outbox::open(&outbox_path).expect("open outbox");

        outbox
            .check_capacity_for_payloads(&log_path, &batch.payloads, capacity_limits(2, bytes))
            .expect("exact canonical byte boundary is accepted");
        let error = outbox
            .check_capacity_for_payloads(&log_path, &batch.payloads, capacity_limits(2, bytes - 1))
            .expect_err("one byte below the canonical boundary is rejected");
        assert!(error.to_string().contains("limit_kind=pending_bytes"));
    }

    #[test]
    fn pending_and_blocked_count_but_acked_and_dead_release_capacity() {
        let temp = tempdir().expect("temporary directory");
        let log_path = temp.path().join("events.jsonl");
        let outbox_path = private_outbox_path(&temp);
        let first = marked_event("TT_CAPACITY_PENDING_26");
        let second = marked_event("TT_CAPACITY_BLOCKED_26");
        let third = marked_event("TT_CAPACITY_ACKED_26");
        let fourth = marked_event("TT_CAPACITY_DEAD_26");
        let fifth = marked_event("TT_CAPACITY_RELEASED_26");
        append_jsonl_events(
            &log_path,
            &[first.clone(), second.clone(), third.clone(), fourth.clone()],
        )
        .expect("canonical JSONL");
        let mut outbox = Outbox::open(&outbox_path).expect("open outbox");
        outbox
            .reconcile_jsonl(&log_path, &["sink-a"])
            .expect("ingest events");
        record_delivery_for_test(
            &mut outbox,
            &second.event_id,
            "sink-a",
            DeliveryState::Blocked,
            1,
            None,
            None,
        )
        .expect("blocked state");
        record_delivery_for_test(
            &mut outbox,
            &third.event_id,
            "sink-a",
            DeliveryState::Acked,
            1,
            None,
            None,
        )
        .expect("acked state");
        record_delivery_for_test(
            &mut outbox,
            &fourth.event_id,
            "sink-a",
            DeliveryState::Dead,
            1,
            None,
            None,
        )
        .expect("dead state");
        let batch =
            canonical_replay_batch(std::slice::from_ref(&fifth)).expect("prospective event");
        outbox
            .check_capacity_for_payloads(&log_path, &batch.payloads, capacity_limits(3, u64::MAX))
            .expect("pending and blocked plus one prospective event fit");
    }

    #[test]
    fn multi_sink_event_counts_once_for_capacity() {
        let temp = tempdir().expect("temporary directory");
        let log_path = temp.path().join("events.jsonl");
        let outbox_path = private_outbox_path(&temp);
        let existing = marked_event("TT_CAPACITY_MULTI_EXISTING_26");
        let prospective = marked_event("TT_CAPACITY_MULTI_PROSPECTIVE_26");
        append_jsonl_events(&log_path, std::slice::from_ref(&existing)).expect("canonical JSONL");
        let mut outbox = Outbox::open(&outbox_path).expect("open outbox");
        outbox
            .reconcile_jsonl(&log_path, &["sink-a", "sink-b"])
            .expect("ingest multi-sink event");
        let batch =
            canonical_replay_batch(std::slice::from_ref(&prospective)).expect("prospective event");
        outbox
            .check_capacity_for_payloads(&log_path, &batch.payloads, capacity_limits(2, u64::MAX))
            .expect("one event per sink is counted once");
    }

    #[test]
    fn unread_jsonl_counts_with_empty_sqlite_and_after_reopen() {
        let temp = tempdir().expect("temporary directory");
        let log_path = temp.path().join("events.jsonl");
        let outbox_path = private_outbox_path(&temp);
        let first = marked_event("TT_CAPACITY_UNREAD_FIRST_26");
        let second = marked_event("TT_CAPACITY_UNREAD_SECOND_26");
        append_jsonl_events(&log_path, &[first, second]).expect("committed JSONL");
        let batch = canonical_replay_batch(&[marked_event("TT_CAPACITY_UNREAD_NEXT_26")])
            .expect("prospective event");
        let bytes = fs::read_to_string(&log_path)
            .expect("JSONL")
            .lines()
            .map(|line| line.len() as u64)
            .sum::<u64>();

        let outbox = Outbox::open(&outbox_path).expect("open empty outbox");
        let error = outbox
            .check_capacity_for_payloads(
                &log_path,
                &batch.payloads,
                capacity_limits(2, bytes + 1_000),
            )
            .expect_err("unread events plus prospective event exceed count");
        assert!(error.to_string().contains("limit_kind=pending_events"));
        drop(outbox);

        let reopened = Outbox::open(&outbox_path).expect("reopen empty outbox");
        reopened
            .check_capacity_for_payloads(
                &log_path,
                &batch.payloads,
                capacity_limits(3, bytes + batch.payloads[0].bytes.len() as u64),
            )
            .expect("unread capacity is counted after reopen");
    }

    #[test]
    fn already_represented_unread_event_is_not_counted_twice() {
        let temp = tempdir().expect("temporary directory");
        let log_path = temp.path().join("events.jsonl");
        let outbox_path = private_outbox_path(&temp);
        let existing = marked_event("TT_CAPACITY_REPRESENTED_26");
        let next = marked_event("TT_CAPACITY_REPRESENTED_NEXT_26");
        append_jsonl_events(&log_path, std::slice::from_ref(&existing)).expect("first JSONL");
        let mut outbox = Outbox::open(&outbox_path).expect("open outbox");
        outbox
            .reconcile_jsonl(&log_path, &["sink-a"])
            .expect("represent first event");
        append_jsonl_events(&log_path, std::slice::from_ref(&existing)).expect("duplicate JSONL");
        let duplicate =
            canonical_replay_batch(std::slice::from_ref(&existing)).expect("duplicate payload");
        outbox
            .check_capacity_for_payloads(
                &log_path,
                &duplicate.payloads,
                capacity_limits(1, duplicate.payloads[0].bytes.len() as u64),
            )
            .expect("represented duplicate does not consume capacity");
        let next_batch = canonical_replay_batch(std::slice::from_ref(&next)).expect("next payload");
        let error = outbox
            .check_capacity_for_payloads(
                &log_path,
                &next_batch.payloads,
                capacity_limits(1, u64::MAX),
            )
            .expect_err("the next unique event exceeds the one-event limit");
        assert!(error.to_string().contains("limit_kind=pending_events"));
    }

    #[test]
    fn unread_same_id_with_different_bytes_fails_closed() {
        let temp = tempdir().expect("temporary directory");
        let log_path = temp.path().join("events.jsonl");
        let outbox_path = private_outbox_path(&temp);
        let first = marked_event("TT_CAPACITY_COLLISION_FIRST_26");
        let mut different = first.clone();
        different.evidence[0].redacted_value = "safe-different-canonical-payload".to_string();
        append_jsonl_events(&log_path, &[first, different]).expect("collision JSONL");
        let outbox = Outbox::open(&outbox_path).expect("open outbox");
        let error = outbox
            .check_capacity_for_payloads(&log_path, &[], capacity_limits(10, u64::MAX))
            .expect_err("same ID with different bytes must fail closed");
        let delivery = error
            .downcast_ref::<DeliveryError>()
            .expect("structured collision error");
        assert_eq!(delivery.class, DeliveryErrorClass::PayloadCollision);
        assert!(!delivery.message.contains("TT_CAPACITY_COLLISION"));
    }

    #[test]
    fn recovery_reconcile_is_not_gated_by_current_capacity_limits() {
        let temp = tempdir().expect("temporary directory");
        let log_path = temp.path().join("events.jsonl");
        let outbox_path = private_outbox_path(&temp);
        let first = marked_event("TT_CAPACITY_RECOVERY_FIRST_26");
        let second = marked_event("TT_CAPACITY_RECOVERY_SECOND_26");
        append_jsonl_events(&log_path, &[first, second]).expect("committed JSONL");
        let mut outbox = Outbox::open(&outbox_path).expect("open outbox");
        let prospective = marked_event("TT_CAPACITY_RECOVERY_PROSPECTIVE_26");
        let batch = canonical_replay_batch(std::slice::from_ref(&prospective))
            .expect("prospective recovery event");
        let error = outbox
            .check_capacity_for_payloads(&log_path, &batch.payloads, capacity_limits(1, u64::MAX))
            .expect_err("existing unread queue is above the current limit");
        assert!(error.to_string().contains("pending_events"));
        outbox
            .reconcile_jsonl(&log_path, &["sink-a"])
            .expect("recovery reconciliation remains available");
    }

    #[test]
    fn restart_reconciles_jsonl_after_the_fsync_before_ingest_gap() {
        let temp = tempdir().expect("temporary directory");
        let log_path = temp.path().join("events.jsonl");
        let outbox_path = private_outbox_path(&temp);
        let event = marked_event("TT_OUTBOX_CRASH_GAP_FSYNC_26");

        LocalJsonlSink::with_rotation(&log_path, crate::sink::RotationConfig::disabled())
            .emit(std::slice::from_ref(&event))
            .expect("canonical JSONL fsync");
        let outbox = Outbox::open(&outbox_path).expect("open before crash");
        assert!(
            outbox
                .get_event(&event.event_id)
                .expect("before crash")
                .is_none()
        );
        drop(outbox);

        let mut restarted = Outbox::open(&outbox_path).expect("restart outbox");
        restarted
            .reconcile_jsonl(&log_path, &["sink-a"])
            .expect("reconcile after restart");

        let stored = restarted
            .get_event(&event.event_id)
            .expect("stored event")
            .expect("event recovered from JSONL");
        assert_payload_is_safe(
            &stored.payload,
            "TT_OUTBOX_CRASH_GAP_FSYNC_26",
            "outbox-restart-recovery",
        );
        assert_eq!(
            restarted
                .get_delivery(&event.event_id, "sink-a")
                .expect("delivery row")
                .expect("pending delivery")
                .state,
            DeliveryState::Pending
        );
    }

    #[test]
    fn restart_replays_ingested_pending_rows_before_any_send_attempt() {
        let temp = tempdir().expect("temporary directory");
        let log_path = temp.path().join("events.jsonl");
        let outbox_path = private_outbox_path(&temp);
        let event = marked_event("TT_OUTBOX_CRASH_GAP_INGEST_26");
        append_jsonl_events(&log_path, std::slice::from_ref(&event)).expect("canonical JSONL");

        let mut outbox = Outbox::open(&outbox_path).expect("open outbox");
        outbox
            .reconcile_jsonl(&log_path, &["sink-a"])
            .expect("ingest transaction");
        drop(outbox);

        let restarted = Outbox::open(&outbox_path).expect("restart outbox");
        let delivery = restarted
            .get_delivery(&event.event_id, "sink-a")
            .expect("delivery lookup")
            .expect("pending delivery survives restart");
        assert_eq!(delivery.state, DeliveryState::Pending);
        assert_eq!(delivery.attempts, 0);
        assert_eq!(delivery.next_attempt_at, None);
    }

    #[test]
    fn reconcile_leaves_partial_trailing_record_until_the_line_is_complete() {
        let temp = tempdir().expect("temporary directory");
        let log_path = temp.path().join("events.jsonl");
        let outbox_path = private_outbox_path(&temp);
        let first = marked_event("TT_OUTBOX_PARTIAL_FIRST_26");
        let second = marked_event("TT_OUTBOX_PARTIAL_SECOND_26");
        append_jsonl_events(&log_path, std::slice::from_ref(&first)).expect("first JSONL event");

        let mut outbox = Outbox::open(&outbox_path).expect("open outbox");
        outbox
            .reconcile_jsonl(&log_path, &["sink-a"])
            .expect("initial ingest");
        let cursor_before = outbox.ingest_cursor().expect("cursor").expect("cursor row");

        let second_bytes = canonical_bytes(&second);
        let split = second_bytes.len() / 2;
        let mut log = fs::OpenOptions::new()
            .append(true)
            .open(&log_path)
            .expect("open JSONL for partial append");
        std::io::Write::write_all(&mut log, &second_bytes[..split]).expect("append partial line");
        drop(log);

        let partial = outbox
            .reconcile_jsonl(&log_path, &["sink-a"])
            .expect("partial tail is deferred");
        assert_eq!(partial.ingested_events, 0);
        assert_eq!(
            outbox.ingest_cursor().expect("cursor after partial"),
            Some(cursor_before)
        );
        assert!(
            outbox
                .get_event(&second.event_id)
                .expect("partial event lookup")
                .is_none()
        );

        let mut log = fs::OpenOptions::new()
            .append(true)
            .open(&log_path)
            .expect("reopen JSONL");
        std::io::Write::write_all(&mut log, &second_bytes[split..]).expect("complete partial line");
        std::io::Write::write_all(&mut log, b"\n").expect("terminate JSONL line");
        drop(log);

        let completed = outbox
            .reconcile_jsonl(&log_path, &["sink-a"])
            .expect("completed tail ingest");
        assert_eq!(completed.ingested_events, 1);
        assert!(
            outbox
                .get_event(&second.event_id)
                .expect("completed event lookup")
                .is_some()
        );
        assert_eq!(
            outbox
                .get_delivery(&second.event_id, "sink-a")
                .expect("completed delivery lookup")
                .expect("completed pending delivery")
                .state,
            DeliveryState::Pending
        );
    }

    #[test]
    fn malformed_non_tail_jsonl_does_not_commit_prior_events_or_cursor() {
        let temp = tempdir().expect("temporary directory");
        let log_path = temp.path().join("events.jsonl");
        let outbox_path = private_outbox_path(&temp);
        let event = marked_event("TT_OUTBOX_MALFORMED_NON_TAIL_26");
        let mut bytes = canonical_bytes(&event);
        bytes.extend_from_slice(b"\n{\"not_an_event\":true}\n");
        fs::write(&log_path, bytes).expect("malformed JSONL fixture");

        let mut outbox = Outbox::open(&outbox_path).expect("open outbox");
        let error = outbox
            .reconcile_jsonl(&log_path, &["sink-a"])
            .expect_err("malformed non-tail record must fail closed");
        let delivery = error
            .downcast_ref::<DeliveryError>()
            .expect("structured ingest error");
        assert_eq!(delivery.class, DeliveryErrorClass::DurableStorage);
        assert!(
            outbox
                .get_event(&event.event_id)
                .expect("event lookup")
                .is_none()
        );
        assert!(outbox.ingest_cursor().expect("cursor lookup").is_none());
    }

    #[test]
    fn cursor_rejects_replacement_truncation_and_unsafe_advancement() {
        let temp = tempdir().expect("temporary directory");
        let log_path = temp.path().join("events.jsonl");
        let outbox_path = private_outbox_path(&temp);
        let event = marked_event("TT_OUTBOX_CURSOR_INTEGRITY_26");
        append_jsonl_events(&log_path, std::slice::from_ref(&event)).expect("canonical JSONL");

        let mut outbox = Outbox::open(&outbox_path).expect("open outbox");
        outbox
            .reconcile_jsonl(&log_path, &["sink-a"])
            .expect("initial ingest");
        let cursor = outbox.ingest_cursor().expect("cursor").expect("cursor row");
        assert_eq!(
            cursor.byte_offset as usize,
            fs::read(&log_path).expect("log").len()
        );

        let replacement = temp.path().join("replacement.jsonl");
        fs::write(&replacement, fs::read(&log_path).expect("original log")).expect("replacement");
        fs::remove_file(&log_path).expect("remove active log");
        fs::rename(&replacement, &log_path).expect("replace active log");
        let error = outbox
            .reconcile_jsonl(&log_path, &["sink-a"])
            .expect_err("replacement must fail closed");
        assert!(error.to_string().contains("generation"));

        // Restore the original bytes through a new outbox so the truncation
        // and cursor-boundary checks each exercise the persisted cursor.
        let second_path = named_private_outbox_path(&temp, "second-outbox");
        let original = canonical_bytes(&event);
        fs::write(
            &log_path,
            format!("{}\n", String::from_utf8(original).expect("UTF-8")),
        )
        .expect("restore log");
        let mut second = Outbox::open(&second_path).expect("second outbox");
        second
            .reconcile_jsonl(&log_path, &["sink-a"])
            .expect("second initial ingest");
        let mut truncated = fs::read(&log_path).expect("read restored log");
        truncated.truncate(truncated.len().saturating_sub(1));
        fs::write(&log_path, truncated).expect("truncate log");
        let error = second
            .reconcile_jsonl(&log_path, &["sink-a"])
            .expect_err("truncation must fail closed");
        assert!(error.to_string().contains("truncat"));

        let unsafe_path = named_private_outbox_path(&temp, "unsafe-cursor");
        let log_path = temp.path().join("unsafe-events.jsonl");
        append_jsonl_events(&log_path, std::slice::from_ref(&event)).expect("unsafe log");
        let mut unsafe_outbox = Outbox::open(&unsafe_path).expect("unsafe outbox");
        unsafe_outbox
            .reconcile_jsonl(&log_path, &["sink-a"])
            .expect("unsafe cursor initial ingest");
        let cursor = unsafe_outbox
            .ingest_cursor()
            .expect("unsafe cursor lookup")
            .expect("unsafe cursor row");
        assert!(cursor.byte_offset > 1);
        unsafe_outbox
            .connection
            .execute("UPDATE ingest_cursor SET byte_offset = 1 WHERE id = 1", [])
            .expect("unsafe cursor fixture");
        let error = unsafe_outbox
            .reconcile_jsonl(&log_path, &["sink-a"])
            .expect_err("cursor in the middle of a line must fail closed");
        assert!(error.to_string().contains("line boundary"));
    }

    fn prepare_rotated_journal() -> (
        tempfile::TempDir,
        std::path::PathBuf,
        std::path::PathBuf,
        crate::event::Event,
        crate::event::Event,
        std::path::PathBuf,
    ) {
        let temp = tempdir().expect("tempdir");
        let log_path = temp.path().join("events.jsonl");
        let outbox_path = private_outbox_path(&temp);
        let first = marked_event("TT_ROTATION_FIRST_26");
        let second = marked_event("TT_ROTATION_SECOND_26");
        let rotation = crate::sink::RotationConfig {
            max_size_bytes: 1,
            keep: 0,
        };
        let sink = LocalJsonlSink::with_rotation(&log_path, rotation).with_durable_rotation();
        sink.emit(std::slice::from_ref(&first))
            .expect("first durable JSONL event");
        let mut outbox = Outbox::open(&outbox_path).expect("open outbox");
        outbox
            .reconcile_jsonl(&log_path, &["sink-a"])
            .expect("ingest first event");
        sink.emit(std::slice::from_ref(&second))
            .expect("rotate and append second event");
        let rotated = discover_jsonl_generations(&log_path)
            .expect("discover rotated generation")
            .into_iter()
            .find(|generation| !generation.is_active)
            .expect("rotated generation")
            .path;
        (temp, log_path, outbox_path, first, second, rotated)
    }

    #[test]
    fn unread_rotated_generation_is_retained_before_reconciliation() {
        let (_temp, log_path, outbox_path, _first, _second, rotated) = prepare_rotated_journal();
        let mut outbox = Outbox::open(&outbox_path).expect("reopen outbox");
        let report = outbox.prune_eligible_rotations(&log_path, 0);
        assert!(rotated.exists(), "unread rotated bytes must be retained");
        assert!(report.pruned == 0);
        assert!(
            !report.warnings.is_empty(),
            "unregistered identity is fail-safe"
        );
    }

    #[test]
    fn current_cursor_generation_is_protected_even_when_fully_consumed() {
        // The first event is reconciled while it is still active. The second
        // write then renames that file to A and creates active B without
        // reconciling B. The persisted cursor must follow A by filesystem
        // identity, not by the discovery filename.
        let (_temp, log_path, outbox_path, first, _second, rotated) = prepare_rotated_journal();
        let mut outbox = Outbox::open(&outbox_path).expect("reopen outbox");
        let generations = discover_jsonl_generations(&log_path).expect("discover generations");
        let rotated_generation = generations
            .iter()
            .find(|generation| generation.path == rotated)
            .expect("rotated generation");
        let active = generations
            .iter()
            .find(|generation| generation.is_active)
            .expect("active generation");
        let cursor = outbox
            .ingest_cursor()
            .expect("cursor after rotation")
            .expect("cursor established while A was active");
        let rotated_length = fs::metadata(&rotated).expect("rotated metadata").len();
        assert_eq!(cursor.generation_id, rotated_generation.identity);
        assert_eq!(cursor.byte_offset, rotated_length);
        assert_eq!(cursor.observed_length, rotated_length);
        assert_eq!(cursor.byte_offset, canonical_bytes(&first).len() as u64 + 1);

        // Register the newly discovered active generation without reconciling
        // its bytes. This is the metadata state a rotation restart must be
        // able to validate before deciding whether A is still protected.
        install_generation_state(&mut outbox, &log_path, &generations, None)
            .expect("register rotated and active generations");
        let report = outbox.prune_eligible_rotations(&log_path, 0);
        assert_eq!(report.pruned, 0);
        assert!(rotated.exists(), "the cursor generation remains protected");
        assert_eq!(
            generation_lifecycle(&outbox, &rotated_generation.identity),
            GenerationLifecycle::Present
        );
        assert!(active.path.exists(), "active generation remains present");
    }

    #[test]
    fn older_unread_generation_is_protected_when_cursor_points_to_a_newer_generation() {
        let temp = tempdir().expect("tempdir");
        let log_path = temp.path().join("events.jsonl");
        let outbox_path = private_outbox_path(&temp);
        let older = marked_event("TT_ROTATION_OLDER_UNREAD");
        let active = marked_event("TT_ROTATION_NEWER_ACTIVE");
        let older_path = temp.path().join("events-2020-01-01.jsonl");
        fs::write(
            &older_path,
            [canonical_bytes(&older).as_slice(), b"\n{\"partial\""].concat(),
        )
        .expect("write partial older generation");
        let active_bytes = [canonical_bytes(&active).as_slice(), b"\n"].concat();
        fs::write(&log_path, &active_bytes).expect("write active generation");

        let generations = discover_jsonl_generations(&log_path).expect("discover generations");
        let active_generation = generations
            .iter()
            .find(|generation| generation.is_active)
            .expect("active generation");
        let mut outbox = Outbox::open(&outbox_path).expect("open outbox");
        install_generation_state(
            &mut outbox,
            &log_path,
            &generations,
            Some((active_generation, active_bytes.len())),
        )
        .expect("install generation metadata and newer cursor");

        let report = outbox.prune_eligible_rotations(&log_path, 0);
        assert_eq!(report.pruned, 0);
        assert_eq!(report.protected, 1);
        assert!(older_path.exists(), "unread older bytes must remain");
        assert_eq!(
            generation_lifecycle(
                &outbox,
                &generations
                    .iter()
                    .find(|generation| !generation.is_active)
                    .expect("older generation")
                    .identity,
            ),
            GenerationLifecycle::Present
        );
    }

    #[test]
    fn newest_rotated_keep_window_is_retained_after_older_consumed_generation_is_pruned() {
        let temp = tempdir().expect("tempdir");
        let log_path = temp.path().join("events.jsonl");
        let outbox_path = private_outbox_path(&temp);
        let first = marked_event("TT_ROTATION_KEEP_OLDEST");
        let second = marked_event("TT_ROTATION_KEEP_NEWEST");
        let third = marked_event("TT_ROTATION_KEEP_ACTIVE");
        let first_path = temp.path().join("events-2020-01-01.jsonl");
        let second_path = temp.path().join("events-2020-01-02.jsonl");
        fs::write(
            &first_path,
            [canonical_bytes(&first).as_slice(), b"\n"].concat(),
        )
        .expect("oldest generation");
        fs::write(
            &second_path,
            [canonical_bytes(&second).as_slice(), b"\n"].concat(),
        )
        .expect("newest rotated generation");
        let active_bytes = [canonical_bytes(&third).as_slice(), b"\n"].concat();
        fs::write(&log_path, &active_bytes).expect("active generation");

        let generations = discover_jsonl_generations(&log_path).expect("discover generations");
        let mut outbox = Outbox::open(&outbox_path).expect("open outbox");
        outbox
            .reconcile_jsonl(&log_path, &["sink-a"])
            .expect("consume every generation");
        let report = outbox.prune_eligible_rotations(&log_path, 1);
        assert_eq!(report.pruned, 1);
        assert!(!first_path.exists(), "oldest consumed generation is pruned");
        assert!(
            second_path.exists(),
            "newest rotated keep window is retained"
        );
        assert!(log_path.exists(), "active generation is retained");
        assert_eq!(
            generation_lifecycle(
                &outbox,
                &generations
                    .iter()
                    .find(|generation| generation.path == first_path)
                    .expect("oldest generation")
                    .identity,
            ),
            GenerationLifecycle::Pruned
        );
    }

    #[test]
    fn fully_ingested_generation_prunes_without_downstream_ack_and_keeps_active() {
        let (_temp, log_path, outbox_path, first, second, rotated) = prepare_rotated_journal();
        let mut outbox = Outbox::open(&outbox_path).expect("reopen outbox");
        outbox
            .reconcile_jsonl(&log_path, &["sink-a"])
            .expect("ingest rotated and active generations");
        record_delivery_for_test(
            &mut outbox,
            &first.event_id,
            "sink-a",
            DeliveryState::Blocked,
            1,
            None,
            Some(DeliveryErrorClass::AuthenticationBlocked { status: 403 }),
        )
        .expect("block first delivery");
        let report = outbox.prune_eligible_rotations(&log_path, 0);
        assert_eq!(report.pruned, 1);
        assert!(
            !rotated.exists(),
            "fully ingested generation should be pruned"
        );
        assert!(log_path.exists(), "active generation must be retained");
        assert_eq!(
            outbox
                .get_delivery(&first.event_id, "sink-a")
                .expect("first delivery")
                .expect("first row")
                .state,
            DeliveryState::Blocked
        );
        assert_eq!(
            outbox
                .get_delivery(&first.event_id, "sink-a")
                .expect("first delivery")
                .expect("first row")
                .last_error_class,
            Some(DeliveryErrorClass::AuthenticationBlocked { status: 403 })
        );
        assert_eq!(
            outbox
                .get_event(&first.event_id)
                .expect("first event after prune")
                .expect("first event remains replayable")
                .payload,
            canonical_bytes(&first)
        );
        assert_eq!(
            outbox
                .get_delivery(&second.event_id, "sink-a")
                .expect("second delivery")
                .expect("second row")
                .state,
            DeliveryState::Pending
        );
    }

    #[test]
    fn pending_consumed_generation_prunes_and_remains_replayable() {
        let (_temp, log_path, outbox_path, first, _second, rotated) = prepare_rotated_journal();
        let mut outbox = Outbox::open(&outbox_path).expect("reopen outbox");
        outbox
            .reconcile_jsonl(&log_path, &["sink-a"])
            .expect("ingest rotated and active generations");
        record_delivery_for_test(
            &mut outbox,
            &first.event_id,
            "sink-a",
            DeliveryState::Pending,
            2,
            Some(1_700_000_100_000),
            Some(DeliveryErrorClass::TransportNoResponse),
        )
        .expect("retain pending delivery");
        record_delivery_for_test(
            &mut outbox,
            &_second.event_id,
            "sink-a",
            DeliveryState::Acked,
            1,
            None,
            None,
        )
        .expect("complete active delivery");

        let report = outbox.prune_eligible_rotations(&log_path, 0);
        assert_eq!(report.pruned, 1);
        assert!(!rotated.exists(), "consumed source generation is pruned");

        let delivery = outbox
            .get_delivery(&first.event_id, "sink-a")
            .expect("pending delivery")
            .expect("pending row remains after source prune");
        assert_eq!(delivery.state, DeliveryState::Pending);
        assert_eq!(delivery.attempts, 2);
        assert_eq!(
            delivery.last_error_class,
            Some(DeliveryErrorClass::TransportNoResponse)
        );
        let event = outbox
            .get_event(&first.event_id)
            .expect("replay event")
            .expect("event remains after source prune");
        assert_eq!(event.payload, canonical_bytes(&first));
        let ready = outbox
            .next_ready_delivery("sink-a", 1_700_000_100_001)
            .expect("ready pending delivery")
            .expect("pending delivery remains replayable");
        assert_eq!(ready.row.state, DeliveryState::Pending);
        assert_eq!(ready.payload, event.payload);
    }

    #[test]
    fn prune_pending_generation_is_recovered_after_restart() {
        let (_temp, log_path, outbox_path, _first, _second, rotated) = prepare_rotated_journal();
        let mut outbox = Outbox::open(&outbox_path).expect("reopen outbox");
        outbox
            .reconcile_jsonl(&log_path, &["sink-a"])
            .expect("ingest rotated generation");
        let generation = discover_jsonl_generations(&log_path)
            .expect("discover generations")
            .into_iter()
            .find(|generation| generation.path == rotated)
            .expect("rotated generation");
        assert!(
            mark_generation_prune_pending(&mut outbox.connection, &generation.identity)
                .expect("mark prune pending")
        );
        drop(outbox);

        let mut restarted = Outbox::open(&outbox_path).expect("restart outbox");
        let report = restarted.prune_eligible_rotations(&log_path, 0);
        assert_eq!(report.pruned, 1);
        assert_eq!(report.finalized_pending, 1);
        assert!(
            !rotated.exists(),
            "pending deletion should complete after restart"
        );
    }

    #[test]
    fn missing_prune_pending_file_is_finalized_and_cleanup_is_idempotent() {
        let (_temp, log_path, outbox_path, _first, _second, rotated) = prepare_rotated_journal();
        let mut outbox = Outbox::open(&outbox_path).expect("reopen outbox");
        outbox
            .reconcile_jsonl(&log_path, &["sink-a"])
            .expect("ingest rotated generation");
        let generation = discover_jsonl_generations(&log_path)
            .expect("discover generations")
            .into_iter()
            .find(|generation| generation.path == rotated)
            .expect("rotated generation");
        assert!(
            mark_generation_prune_pending(&mut outbox.connection, &generation.identity)
                .expect("mark prune pending")
        );
        std::fs::remove_file(&rotated).expect("simulate missing rotated file");

        let first = outbox.prune_eligible_rotations(&log_path, 0);
        assert_eq!(first.finalized_pending, 1);
        assert!(first.warnings.is_empty());
        let second = outbox.prune_eligible_rotations(&log_path, 0);
        assert_eq!(second, super::PruneReport::default());
    }

    #[test]
    fn invalid_generation_lifecycle_fails_safe_without_pruning_source_bytes() {
        let (_temp, log_path, outbox_path, _first, _second, rotated) = prepare_rotated_journal();
        let mut outbox = Outbox::open(&outbox_path).expect("reopen outbox");
        outbox
            .reconcile_jsonl(&log_path, &["sink-a"])
            .expect("ingest rotated generation");
        let rotated_identity = discover_jsonl_generations(&log_path)
            .expect("discover generations")
            .into_iter()
            .find(|generation| generation.path == rotated)
            .expect("rotated generation")
            .identity;
        drop(outbox);

        let connection = Connection::open(&outbox_path).expect("raw lifecycle fixture");
        if connection
            .pragma_update(None, "ignore_check_constraints", "ON")
            .is_err()
        {
            drop(connection);
            fs::write(&outbox_path, b"synthetic-corrupt-lifecycle-database")
                .expect("corrupt database fallback");
            let error = Outbox::open(&outbox_path).expect_err("corrupt fallback must fail closed");
            let delivery = error
                .downcast_ref::<DeliveryError>()
                .expect("structured corrupt lifecycle fallback error");
            assert_eq!(delivery.class, DeliveryErrorClass::DurableStorage);
            assert!(outbox_path.exists());
            assert!(rotated.exists(), "corrupt storage must retain JSONL bytes");
            return;
        }
        connection
            .execute(
                "UPDATE journal_generations
                 SET lifecycle = 'synthetic-invalid-lifecycle'
                 WHERE generation_id = ?1",
                [&rotated_identity],
            )
            .expect("insert invalid lifecycle fixture");
        drop(connection);

        let mut reopened = Outbox::open(&outbox_path).expect("reopen normal outbox");
        let report = reopened.prune_eligible_rotations(&log_path, 0);
        assert_eq!(report.pruned, 0);
        assert!(!report.warnings.is_empty());
        assert!(
            rotated.exists(),
            "invalid lifecycle must retain JSONL bytes"
        );
    }

    #[test]
    fn unknown_or_mismatched_cursor_state_never_authorizes_pruning() {
        let (_temp, log_path, outbox_path, _first, _second, rotated) = prepare_rotated_journal();
        let mut outbox = Outbox::open(&outbox_path).expect("reopen outbox");
        outbox
            .reconcile_jsonl(&log_path, &["sink-a"])
            .expect("ingest rotated generation");
        outbox
            .connection
            .execute(
                "UPDATE ingest_cursor SET generation_id = 'unknown-generation' WHERE id = 1",
                [],
            )
            .expect("corrupt cursor identity");
        let report = outbox.prune_eligible_rotations(&log_path, 0);
        assert!(rotated.exists(), "unknown cursor must retain bytes");
        assert_eq!(report.pruned, 0);
        assert!(!report.warnings.is_empty());

        outbox
            .connection
            .execute(
                "UPDATE ingest_cursor SET generation_id = (SELECT generation_id FROM journal_generations WHERE lifecycle = 'present' ORDER BY observed_at LIMIT 1), journal_path_hash = ?1 WHERE id = 1",
                ["f".repeat(64)],
            )
            .expect("corrupt cursor journal binding");
        let report = outbox.prune_eligible_rotations(&log_path, 0);
        assert!(rotated.exists(), "mismatched cursor must retain bytes");
        assert_eq!(report.pruned, 0);
    }

    #[test]
    fn rename_restart_keeps_unregistered_generation_until_reconciliation() {
        let (_temp, log_path, outbox_path, _first, _second, rotated) = prepare_rotated_journal();
        let mut restarted = Outbox::open(&outbox_path).expect("restart outbox");
        let cursor_before = restarted
            .ingest_cursor()
            .expect("cursor before restart")
            .expect("cursor row");
        let rotated_identity = discover_jsonl_generations(&log_path)
            .expect("discover generations")
            .into_iter()
            .find(|generation| generation.path == rotated)
            .expect("rotated generation")
            .identity;
        assert_eq!(cursor_before.generation_id, rotated_identity);

        // The rename and new active-file write happened before the process
        // stopped. The old cursor and generation metadata are still the only
        // committed state, so cleanup must wait for restart reconciliation.
        let before_reconcile = restarted.prune_eligible_rotations(&log_path, 0);
        assert_eq!(before_reconcile.pruned, 0);
        assert!(!before_reconcile.warnings.is_empty());
        assert!(rotated.exists());

        restarted
            .reconcile_jsonl(&log_path, &["sink-a"])
            .expect("reconcile renamed generation after restart");
        let after_reconcile = restarted.prune_eligible_rotations(&log_path, 0);
        assert_eq!(after_reconcile.pruned, 1);
        assert!(!rotated.exists());
    }

    #[test]
    fn rotation_pruning_is_serialized_by_the_jsonl_sidecar_lock() {
        let (_temp, log_path, outbox_path, _first, _second, rotated) = prepare_rotated_journal();
        let mut outbox = Outbox::open(&outbox_path).expect("reopen outbox");
        outbox
            .reconcile_jsonl(&log_path, &["sink-a"])
            .expect("ingest rotated generation");

        let lock = crate::file_lock::SidecarLock::acquire_lock_only(&log_path)
            .expect("hold rotation lock");
        let blocked = outbox.prune_eligible_rotations(&log_path, 0);
        assert_eq!(blocked.pruned, 0);
        assert!(!blocked.warnings.is_empty());
        assert!(rotated.exists(), "a locked lifecycle cannot prune bytes");
        drop(lock);

        let after_release = outbox.prune_eligible_rotations(&log_path, 0);
        assert_eq!(after_release.pruned, 1);
        assert!(!rotated.exists());
    }

    #[test]
    fn corrupt_generation_metadata_disables_pruning() {
        let (_temp, log_path, outbox_path, _first, _second, rotated) = prepare_rotated_journal();
        let mut outbox = Outbox::open(&outbox_path).expect("reopen outbox");
        outbox
            .reconcile_jsonl(&log_path, &["sink-a"])
            .expect("ingest rotated generation");
        let rotated_identity = discover_jsonl_generations(&log_path)
            .expect("discover generations")
            .into_iter()
            .find(|generation| generation.path == rotated)
            .expect("rotated generation")
            .identity;
        outbox
            .connection
            .execute(
                "UPDATE journal_generations SET journal_path_hash = 'corrupt' WHERE generation_id = ?1",
                [&rotated_identity],
            )
            .expect("corrupt generation metadata fixture");

        let report = outbox.prune_eligible_rotations(&log_path, 0);
        assert_eq!(report.pruned, 0);
        assert!(!report.warnings.is_empty());
        assert!(rotated.exists(), "corrupt metadata must retain JSONL");
    }

    #[test]
    fn deletion_failure_leaves_prune_pending_until_restart_recovery() {
        let (_temp, log_path, outbox_path, _first, _second, rotated) = prepare_rotated_journal();
        let mut outbox = Outbox::open(&outbox_path).expect("reopen outbox");
        outbox
            .reconcile_jsonl(&log_path, &["sink-a"])
            .expect("ingest rotated generation");
        let rotated_identity = discover_jsonl_generations(&log_path)
            .expect("discover generations")
            .into_iter()
            .find(|generation| generation.path == rotated)
            .expect("rotated generation")
            .identity;
        outbox.fail_next_prune_deletion();

        let failed = outbox.prune_eligible_rotations(&log_path, 0);
        assert_eq!(failed.pruned, 0);
        assert!(!failed.warnings.is_empty());
        assert!(rotated.exists(), "failed deletion must retain JSONL");
        let lifecycle: String = outbox
            .connection
            .query_row(
                "SELECT lifecycle FROM journal_generations WHERE generation_id = ?1",
                [&rotated_identity],
                |row| row.get(0),
            )
            .expect("pending lifecycle");
        assert_eq!(lifecycle, "prune_pending");
        drop(outbox);

        let mut restarted = Outbox::open(&outbox_path).expect("restart after deletion failure");
        let recovered = restarted.prune_eligible_rotations(&log_path, 0);
        assert_eq!(recovered.pruned, 1);
        assert_eq!(recovered.finalized_pending, 1);
        assert!(!rotated.exists());
    }

    #[test]
    fn replaced_rotated_generation_is_retained_by_identity_mismatch() {
        let (temp, log_path, outbox_path, _first, _second, rotated) = prepare_rotated_journal();
        let mut outbox = Outbox::open(&outbox_path).expect("reopen outbox");
        outbox
            .reconcile_jsonl(&log_path, &["sink-a"])
            .expect("ingest rotated generation");
        let replacement = temp.path().join("replacement.jsonl");
        fs::copy(&rotated, &replacement).expect("copy replacement");
        fs::remove_file(&rotated).expect("remove original generation");
        fs::rename(&replacement, &rotated).expect("replace generation");

        let report = outbox.prune_eligible_rotations(&log_path, 0);
        assert_eq!(report.pruned, 0);
        assert!(!report.warnings.is_empty());
        assert!(rotated.exists(), "identity replacement must be retained");
    }

    #[test]
    fn changed_bytes_with_the_same_generation_identity_are_retained() {
        use std::io::Write;

        let (_temp, log_path, outbox_path, _first, _second, rotated) = prepare_rotated_journal();
        let mut outbox = Outbox::open(&outbox_path).expect("reopen outbox");
        outbox
            .reconcile_jsonl(&log_path, &["sink-a"])
            .expect("ingest rotated generation");
        let extra = marked_event("TT_ROTATION_APPENDED_AFTER_CURSOR_26");
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(&rotated)
            .expect("open rotated generation");
        file.write_all(&canonical_bytes(&extra))
            .expect("append changed bytes");
        file.write_all(b"\n").expect("terminate changed bytes");
        file.sync_all().expect("sync changed bytes");

        let report = outbox.prune_eligible_rotations(&log_path, 0);
        assert_eq!(report.pruned, 0);
        assert!(rotated.exists(), "unproven appended bytes must be retained");
    }

    #[test]
    fn missing_active_generation_disables_pruning() {
        let (_temp, log_path, outbox_path, _first, _second, rotated) = prepare_rotated_journal();
        let mut outbox = Outbox::open(&outbox_path).expect("reopen outbox");
        outbox
            .reconcile_jsonl(&log_path, &["sink-a"])
            .expect("ingest rotated generation");
        fs::remove_file(&log_path).expect("remove active generation");

        let report = outbox.prune_eligible_rotations(&log_path, 0);
        assert_eq!(report.pruned, 0);
        assert!(!report.warnings.is_empty());
        assert!(rotated.exists(), "missing active state must retain bytes");
    }

    #[test]
    fn health_is_metadata_only_and_separates_sink_states() {
        let temp = tempdir().expect("temporary directory");
        let path = private_outbox_path(&temp);
        let first = marked_event("TT_HEALTH_FIRST");
        let second = marked_event("TT_HEALTH_SECOND");
        let third = marked_event("TT_HEALTH_THIRD");
        let first_bytes = canonical_bytes(&first);
        let second_bytes = canonical_bytes(&second);
        let mut outbox = Outbox::open(&path).expect("open outbox");
        for event in [&first, &second, &third] {
            outbox
                .insert_event(event, &["sink-a", "sink-b"])
                .expect("insert event");
        }
        outbox
            .connection
            .execute(
                "UPDATE events SET created_at = CASE event_id
                     WHEN ?1 THEN 100 WHEN ?2 THEN 200 WHEN ?3 THEN 300 END",
                params![first.event_id, second.event_id, third.event_id],
            )
            .expect("set deterministic event times");
        outbox
            .record_delivery_at(
                &first.event_id,
                "sink-a",
                super::DeliveryUpdate {
                    state: DeliveryState::Pending,
                    attempts: 1,
                    next_attempt_at: Some(9_999),
                    last_error_class: Some(DeliveryErrorClass::HttpStatus { status: 429 }),
                    updated_at: 1_000,
                },
            )
            .expect("record retry-delayed row");
        outbox
            .record_delivery_at(
                &second.event_id,
                "sink-a",
                super::DeliveryUpdate {
                    state: DeliveryState::Blocked,
                    attempts: 1,
                    next_attempt_at: None,
                    last_error_class: Some(DeliveryErrorClass::AuthenticationBlocked {
                        status: 403,
                    }),
                    updated_at: 1_100,
                },
            )
            .expect("record blocked row");
        outbox
            .record_delivery_at(
                &third.event_id,
                "sink-a",
                super::DeliveryUpdate {
                    state: DeliveryState::Dead,
                    attempts: 1,
                    next_attempt_at: None,
                    last_error_class: Some(DeliveryErrorClass::SinkApplicationRejected),
                    updated_at: 1_200,
                },
            )
            .expect("record dead row");
        outbox
            .record_delivery_at(
                &first.event_id,
                "sink-b",
                super::DeliveryUpdate {
                    state: DeliveryState::Acked,
                    attempts: 1,
                    next_attempt_at: None,
                    last_error_class: None,
                    updated_at: 1_300,
                },
            )
            .expect("record acknowledged row");

        let health = outbox.health(&["sink-a", "sink-b"], 1_000).expect("health");
        assert_eq!(health.sinks.len(), 2);
        let sink_a = &health.sinks[0];
        assert_eq!(sink_a.sink_id, "sink-a");
        assert_eq!(sink_a.pending_depth, 2);
        assert_eq!(
            sink_a.pending_bytes,
            (first_bytes.len() + second_bytes.len()) as u64
        );
        assert_eq!(sink_a.oldest_pending_age_seconds, Some(900));
        assert_eq!(sink_a.dead_count, 1);
        assert_eq!(sink_a.last_error_at, Some(1_200));
        assert_eq!(
            sink_a.last_error_class,
            Some(DeliveryErrorClass::SinkApplicationRejected)
        );
        let sink_b = &health.sinks[1];
        assert_eq!(sink_b.pending_depth, 2);
        assert_eq!(sink_b.dead_count, 0);
        assert_eq!(sink_b.last_success_at, Some(1_300));
        assert!(sink_b.last_error_at.is_none());

        let rendered = crate::sink::durable_health_json_from_path(&path, &["sink-a", "sink-b"]);
        let rendered = serde_json::to_string(&rendered).expect("health JSON");
        assert!(!rendered.contains("TT_HEALTH_FIRST"));
        assert!(!rendered.contains("TT_HEALTH_SECOND"));
        assert!(!rendered.contains("TT_HEALTH_THIRD"));
    }

    #[test]
    fn health_history_survives_restart_and_read_only_lookup_is_bounded() {
        let temp = tempdir().expect("temporary directory");
        let path = private_outbox_path(&temp);
        let event = marked_event("TT_HEALTH_RESTART");
        let mut outbox = Outbox::open(&path).expect("open outbox");
        outbox
            .insert_event(&event, &["sink"])
            .expect("insert event");
        outbox
            .record_delivery_at(
                &event.event_id,
                "sink",
                super::DeliveryUpdate {
                    state: DeliveryState::Acked,
                    attempts: 1,
                    next_attempt_at: None,
                    last_error_class: None,
                    updated_at: 2_000,
                },
            )
            .expect("record success");
        let failed = marked_event("TT_HEALTH_FAILURE");
        outbox
            .insert_event(&failed, &["sink"])
            .expect("insert failed event");
        outbox
            .record_delivery_at(
                &failed.event_id,
                "sink",
                super::DeliveryUpdate {
                    state: DeliveryState::Dead,
                    attempts: 1,
                    next_attempt_at: None,
                    last_error_class: Some(DeliveryErrorClass::HttpStatus { status: 500 }),
                    updated_at: 3_000,
                },
            )
            .expect("record failure");
        drop(outbox);

        let restarted = Outbox::open_read_only(&path).expect("read-only restart lookup");
        let health = restarted.health(&[], 4_000).expect("restart health");
        assert_eq!(health.sinks[0].last_success_at, Some(2_000));
        assert_eq!(health.sinks[0].last_error_at, Some(3_000));
        assert_eq!(
            health.sinks[0].last_error_class,
            Some(DeliveryErrorClass::HttpStatus { status: 500 })
        );

        let corrupt = temp.path().join("corrupt.sqlite");
        fs::write(&corrupt, b"TT_HEALTH_CORRUPT_SECRET").expect("write corrupt outbox");
        let rendered = crate::sink::durable_health_json_from_path(&corrupt, &[]);
        let rendered = serde_json::to_string(&rendered).expect("unavailable health JSON");
        assert!(rendered.len() < 512);
        assert!(!rendered.contains("TT_HEALTH_CORRUPT_SECRET"));
        assert!(rendered.contains("unavailable"));
    }

    #[cfg(unix)]
    fn make_database_private(path: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(
            path.parent().expect("database parent"),
            fs::Permissions::from_mode(0o700),
        )
        .expect("database parent mode");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("database mode");
    }

    #[cfg(not(unix))]
    fn make_database_private(_path: &std::path::Path) {}
}

#[cfg(test)]
mod platform_tests {
    #[cfg(windows)]
    use std::fs;

    use tempfile::tempdir;

    use super::{
        Outbox, WINDOWS_DURABLE_STORAGE_UNSUPPORTED, acquire_admission_lock_for_platform,
        ensure_durable_storage_supported, ensure_durable_storage_supported_for_platform,
    };
    use crate::sink::{DeliveryError, DeliveryErrorClass};

    fn assert_windows_storage_error(error: Box<dyn std::error::Error>) {
        let delivery = error
            .downcast_ref::<DeliveryError>()
            .expect("Windows durable policy must return a structured delivery error");
        assert_eq!(delivery.class, DeliveryErrorClass::DurableStorage);
        assert_eq!(delivery.attempts, 0);
        assert!(
            error
                .to_string()
                .contains(WINDOWS_DURABLE_STORAGE_UNSUPPORTED)
        );
    }

    #[test]
    fn durable_storage_policy_rejects_windows_before_filesystem_side_effects() {
        let temp = tempdir().expect("temporary directory");
        let outbox_path = temp.path().join("private").join("outbox.sqlite");

        let error = ensure_durable_storage_supported_for_platform(true)
            .expect_err("Windows durable storage must be rejected");
        assert_windows_storage_error(error);
        assert!(!outbox_path.parent().expect("outbox parent").exists());
        assert!(!outbox_path.exists());
    }

    #[test]
    fn durable_storage_policy_allows_non_windows_platforms() {
        ensure_durable_storage_supported_for_platform(false)
            .expect("non-Windows durable storage policy");
    }

    #[test]
    fn current_platform_uses_cfg_selected_durable_storage_policy() {
        if cfg!(windows) {
            let error = ensure_durable_storage_supported()
                .expect_err("Windows durable storage must be rejected");
            assert_windows_storage_error(error);
        } else {
            ensure_durable_storage_supported().expect("non-Windows durable storage policy");
        }
    }

    #[test]
    fn simulated_windows_outbox_open_and_admission_reject_before_parent_creation() {
        let temp = tempdir().expect("temporary directory");
        let outbox_path = temp.path().join("private").join("outbox.sqlite");

        let error = Outbox::open_for_platform(&outbox_path, true)
            .expect_err("Windows durable outbox open must be rejected");
        assert_windows_storage_error(error);
        assert!(!outbox_path.parent().expect("outbox parent").exists());
        assert!(!outbox_path.exists());

        let error = match acquire_admission_lock_for_platform(&outbox_path, true) {
            Ok(_) => panic!("Windows durable admission must be rejected"),
            Err(error) => error,
        };
        assert_windows_storage_error(error);
        assert!(!outbox_path.parent().expect("outbox parent").exists());
        assert!(!outbox_path.exists());
    }

    #[test]
    fn simulated_windows_read_only_health_open_rejects_before_inspection() {
        let temp = tempdir().expect("temporary directory");
        let outbox_path = temp.path().join("private").join("outbox.sqlite");

        let error = Outbox::open_read_only_for_platform(&outbox_path, true)
            .expect_err("Windows durable health open must be rejected");
        assert_windows_storage_error(error);
        assert!(!outbox_path.parent().expect("outbox parent").exists());
        assert!(!outbox_path.exists());
    }

    #[cfg(windows)]
    #[test]
    fn native_windows_outbox_open_rejects_without_creating_artifacts() {
        let temp = tempdir().expect("temporary directory");
        let outbox_path = temp.path().join("private").join("outbox.sqlite");

        let error =
            Outbox::open(&outbox_path).expect_err("Windows durable storage must fail closed");
        assert_windows_storage_error(error);
        assert!(!outbox_path.parent().expect("outbox parent").exists());
        assert!(!outbox_path.exists());
    }

    #[cfg(windows)]
    #[test]
    fn native_windows_best_effort_does_not_use_the_durable_storage_guard() {
        let temp = tempdir().expect("temporary directory");
        let path = temp.path().join("best-effort.jsonl");
        fs::write(&path, b"synthetic-best-effort\n").expect("best-effort fixture");
        assert!(path.is_file());
    }
}
