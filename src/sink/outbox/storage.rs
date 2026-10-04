use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[cfg(test)]
use super::MAX_CAPACITY_SCAN_BYTES;
use super::{OUTBOX_OPEN_PROFILE, Outbox};
use crate::event::{PrivacySanitizer, SanitizationContext};
use crate::file_lock::{SidecarLock, paths_identity_equivalent};
use crate::sink::{DeliveryError, DeliveryErrorClass};

const OUTBOX_SCHEMA_VERSION: i64 = 6;
const OUTBOX_DIRECTORY_MODE: u32 = 0o700;
const OUTBOX_DATABASE_MODE: u32 = 0o600;

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

/// Acquire the per-outbox admission and dispatch owner. Durable writers hold
/// this sidecar from recovery and capacity inspection through canonical append and
/// follow-up reconciliation. Standalone dispatch holds it from before opening
/// the outbox through all selections, transport attempts, and result commits.
/// It coordinates local Telltale writers without making the outbox a distributed
/// lock service.
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

pub(super) fn storage_error(context: &str, error: impl fmt::Display) -> Box<dyn std::error::Error> {
    storage_message(format!("outbox {context}: {error}"))
}

pub(super) fn storage_delivery_error(context: &str, error: impl fmt::Display) -> DeliveryError {
    DeliveryError::new(
        DeliveryErrorClass::DurableStorage,
        0,
        format!("outbox {context}: {error}"),
    )
}

pub(super) fn storage_message(message: impl Into<String>) -> Box<dyn std::error::Error> {
    Box::new(DeliveryError::new(
        DeliveryErrorClass::DurableStorage,
        0,
        PrivacySanitizer::sanitize(SanitizationContext::Diagnostic, &message.into()),
    ))
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
