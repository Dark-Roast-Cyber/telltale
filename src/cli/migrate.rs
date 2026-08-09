use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use flate2::read::MultiGzDecoder;
use serde::Serialize;
use serde::de::{DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::file_lock::{
    FILE_STREAM_BUFFER_SIZE, PinnedFile, SidecarLock, TempFile, atomic_no_replace, manifest_path,
    open_pinned_read, read_snapshot, safe_path_info, validate_existing_mode,
    validate_migration_paths, validate_migration_targets, validate_target,
};
use crate::state::{ScanState, StateLock};

#[derive(Serialize)]
struct MigrationManifest {
    source_format: &'static str,
    destination_format: &'static str,
    source_sha256: String,
    destination_sha256: String,
    source_bytes: usize,
    destination_bytes: usize,
    family_counts: BTreeMap<&'static str, usize>,
    normalization_count: usize,
    completion: &'static str,
}

pub(crate) fn run_state_migration(
    source: &Path,
    destination: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    reject_alias(source, destination)?;
    validate_migration_paths(source, destination)?;
    validate_target(source)?;
    if safe_path_info(source)?.is_none() {
        return Err("migration source must be an existing regular file".into());
    }

    let companion = manifest_path(destination);
    let mut lock_order = vec![
        (SidecarLock::lock_order_key(source)?, 0u8, source),
        (SidecarLock::lock_order_key(destination)?, 1u8, destination),
        (
            SidecarLock::lock_order_key(&companion)?,
            2u8,
            companion.as_path(),
        ),
    ];
    lock_order.sort_by(|left, right| left.0.cmp(&right.0));
    let mut locks: Vec<StateLock> = Vec::with_capacity(3);
    for (_, _, path) in lock_order {
        locks.push(StateLock::acquire(path)?);
    }
    validate_existing_mode(destination, 0o600)?;
    validate_existing_mode(&companion, 0o600)?;

    let (mut pinned_source, source_bytes) = stable_read(source)?;
    let (source_format, mut state, native_normalization_count) =
        if contains_schema_version(&source_bytes) {
            let (state, normalization_count) =
                ScanState::validate_native_migration_bytes_with_count(&source_bytes)?;
            ("native_state_1.0", state, normalization_count)
        } else {
            (
                "legacy_state_unversioned",
                ScanState::validate_legacy_bytes(&source_bytes)?,
                0,
            )
        };
    let baseline_promotion_count = usize::from(needs_baseline_promotion(&source_bytes));
    let normalization_count = if source_format == "legacy_state_unversioned" {
        state
            .normalize_legacy_for_migration()
            .saturating_add(baseline_promotion_count)
    } else {
        native_normalization_count.saturating_add(baseline_promotion_count)
    };
    pinned_source.verify_unchanged()?;
    let destination_bytes = state.canonical_bytes()?;
    ScanState::validate_native_bytes(&destination_bytes)?;
    let destination_hash = sha256(&destination_bytes);
    let manifest = MigrationManifest {
        source_format,
        destination_format: "native_state_1.0",
        source_sha256: sha256(&source_bytes),
        destination_sha256: destination_hash.clone(),
        source_bytes: source_bytes.len(),
        destination_bytes: destination_bytes.len(),
        family_counts: state.family_counts(),
        normalization_count,
        completion: "complete",
    };
    let manifest_bytes = manifest_bytes(&manifest)?;
    let manifest_path = companion;
    let existing_destination = existing_bytes(destination)?;
    let existing_manifest = existing_bytes(&manifest_path)?;
    let existing_manifest_present = existing_manifest.is_some();
    let destination_installed = match existing_destination {
        Some(existing) if existing == destination_bytes => false,
        Some(_) => return Err("migration destination conflict: existing bytes differ".into()),
        None if existing_manifest.is_some() => {
            return Err("migration manifest exists without its destination".into());
        }
        None => {
            let prepared = state.prepare_save(destination)?;
            locks.iter().try_for_each(StateLock::verify)?;
            pinned_source.verify_unchanged()?;
            prepared.install_no_replace(destination)?;
            true
        }
    };

    locks.iter().try_for_each(if destination_installed {
        StateLock::verify_lock
    } else {
        StateLock::verify
    })?;
    validate_installed_target(destination, 0o600, !destination_installed)?;
    pinned_source.verify_unchanged()?;
    match &existing_manifest {
        Some(existing) if existing == &manifest_bytes => {}
        Some(_) => return Err("migration manifest conflict: existing bytes differ".into()),
        None => {
            let temporary = TempFile::write_and_sync(&manifest_path, &manifest_bytes, 0o600)?;
            atomic_no_replace(temporary, &manifest_path)?;
        }
    }
    validate_installed_target(&manifest_path, 0o600, existing_manifest_present)?;
    locks.iter().try_for_each(StateLock::verify_lock)?;
    pinned_source.verify_unchanged()?;
    print!("{}", String::from_utf8(manifest_bytes)?);
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct MigrationFailure(&'static str);

impl fmt::Display for MigrationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for MigrationFailure {}

fn migration_failure(code: &'static str) -> Box<dyn std::error::Error> {
    Box::new(MigrationFailure(code))
}

fn checked_length(length: usize, error: &'static str) -> Result<u64, Box<dyn std::error::Error>> {
    u64::try_from(length).map_err(|_| migration_failure(error))
}

fn checked_add_u64(
    counter: &mut u64,
    amount: u64,
    limit: u64,
    error: &'static str,
) -> Result<(), Box<dyn std::error::Error>> {
    let next = counter
        .checked_add(amount)
        .ok_or_else(|| migration_failure(error))?;
    if next > limit {
        return Err(migration_failure(error));
    }
    *counter = next;
    Ok(())
}

fn checked_add_usize(
    counter: &mut usize,
    amount: usize,
    error: &'static str,
) -> Result<(), Box<dyn std::error::Error>> {
    *counter = counter
        .checked_add(amount)
        .ok_or_else(|| migration_failure(error))?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EventCompression {
    None,
    Gzip,
}

impl EventCompression {
    fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Gzip => "gzip",
        }
    }
}

const MAX_EVENT_FRAME_BYTES: usize = 16 * 1024 * 1024;
const MAX_EVENT_TOTAL_RAW_BYTES: u64 = 512 * 1024 * 1024;
const MAX_EVENT_TOTAL_DECOMPRESSED_BYTES: u64 = 512 * 1024 * 1024;
const MAX_EVENT_TOTAL_OUTPUT_SPOOL_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_EVENT_RECORD_COUNT: usize = 1_000_000;
// Collision bodies are disk-backed; only event ID metadata is retained here.
const MAX_EVENT_UNIQUE_COLLISION_IDS: usize = 100_000;
const MAX_EVENT_TOTAL_FRAMES: usize = 1_000_000;
const MAX_EVENT_BLANK_FRAMES: usize = 100_000;
const MAX_EVENT_GZIP_EXPANSION_BYTES: u64 = 256 * 1024 * 1024;
const MAX_EVENT_PAIR_COUNT: usize = 64;
const MAX_EVENT_DESTINATION_COUNT: usize = 32;

#[derive(Default)]
struct EventBudget {
    raw_bytes: u64,
    decompressed_bytes: u64,
    output_spool_bytes: u64,
    gzip_expansion_bytes: u64,
    record_count: usize,
    unique_collision_ids: usize,
    frame_count: usize,
    blank_frame_count: usize,
}

impl EventBudget {
    fn charge_raw(&mut self, amount: u64) -> Result<(), Box<dyn std::error::Error>> {
        checked_add_u64(
            &mut self.raw_bytes,
            amount,
            MAX_EVENT_TOTAL_RAW_BYTES,
            "event migration raw byte budget exceeded",
        )
    }

    fn charge_decompressed(
        &mut self,
        amount: u64,
        gzip: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        checked_add_u64(
            &mut self.decompressed_bytes,
            amount,
            MAX_EVENT_TOTAL_DECOMPRESSED_BYTES,
            "event migration decompressed byte budget exceeded",
        )?;
        if gzip {
            checked_add_u64(
                &mut self.gzip_expansion_bytes,
                amount,
                MAX_EVENT_GZIP_EXPANSION_BYTES,
                "event migration gzip expansion budget exceeded",
            )?;
        }
        Ok(())
    }

    fn charge_output_spool(&mut self, amount: u64) -> Result<(), Box<dyn std::error::Error>> {
        checked_add_u64(
            &mut self.output_spool_bytes,
            amount,
            MAX_EVENT_TOTAL_OUTPUT_SPOOL_BYTES,
            "event migration output and spool byte budget exceeded",
        )
    }

    fn charge_frame(&mut self, blank: bool) -> Result<(), Box<dyn std::error::Error>> {
        checked_add_usize(
            &mut self.frame_count,
            1,
            "event migration frame count budget exceeded",
        )?;
        if self.frame_count > MAX_EVENT_TOTAL_FRAMES {
            return Err(migration_failure(
                "event migration frame count budget exceeded",
            ));
        }
        if blank {
            checked_add_usize(
                &mut self.blank_frame_count,
                1,
                "event migration blank frame budget exceeded",
            )?;
            if self.blank_frame_count > MAX_EVENT_BLANK_FRAMES {
                return Err(migration_failure(
                    "event migration blank frame budget exceeded",
                ));
            }
        }
        Ok(())
    }

    fn charge_record(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        checked_add_usize(
            &mut self.record_count,
            1,
            "event migration record count budget exceeded",
        )?;
        if self.record_count > MAX_EVENT_RECORD_COUNT {
            return Err(migration_failure(
                "event migration record count budget exceeded",
            ));
        }
        Ok(())
    }

    fn charge_unique_collision_id(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        checked_add_usize(
            &mut self.unique_collision_ids,
            1,
            "event migration unique collision ID budget exceeded",
        )?;
        if self.unique_collision_ids > MAX_EVENT_UNIQUE_COLLISION_IDS {
            return Err(migration_failure(
                "event migration unique collision ID budget exceeded",
            ));
        }
        Ok(())
    }
}

struct EventSetStats {
    record_count: usize,
    blank_frame_count: usize,
    schema_versions: BTreeMap<&'static str, usize>,
}

impl Default for EventSetStats {
    fn default() -> Self {
        Self {
            record_count: 0,
            blank_frame_count: 0,
            schema_versions: BTreeMap::from([("1.0", 0), ("2.0", 0), ("3.0", 0)]),
        }
    }
}

impl EventSetStats {
    fn add(&mut self, other: Self) -> Result<(), Box<dyn std::error::Error>> {
        checked_add_usize(
            &mut self.record_count,
            other.record_count,
            "event migration record counter overflow",
        )?;
        checked_add_usize(
            &mut self.blank_frame_count,
            other.blank_frame_count,
            "event migration blank frame counter overflow",
        )?;
        for (version, count) in other.schema_versions {
            let mut total = self
                .schema_versions
                .get(version)
                .copied()
                .unwrap_or_default();
            checked_add_usize(&mut total, count, "event migration schema counter overflow")?;
            self.schema_versions.insert(version, total);
        }
        Ok(())
    }
}

struct EventDestination {
    path: PathBuf,
    compression: EventCompression,
    temporary: Option<TempFile>,
    hasher: Sha256,
    byte_count: u64,
    composition: DestinationComposition,
}

#[derive(Default)]
struct DestinationComposition {
    has_nonempty_contribution: bool,
    last_nonempty_ended_with_lf: bool,
}

struct EventContribution {
    stats: EventSetStats,
    byte_count: u64,
    last_byte: Option<u8>,
}

#[derive(Serialize)]
struct EventDestinationManifest {
    ordinal: usize,
    compression: &'static str,
    source_bytes: u64,
    source_sha256: String,
    destination_bytes: u64,
    destination_sha256: String,
}

#[derive(Serialize)]
struct EventMigrationManifest {
    manifest_version: &'static str,
    source_format: &'static str,
    destination_format: &'static str,
    source_sha256: String,
    destination_sha256: String,
    source_bytes: u64,
    destination_bytes: u64,
    pair_count: usize,
    destination_count: usize,
    record_count: usize,
    blank_frame_count: usize,
    schema_versions: BTreeMap<&'static str, usize>,
    compression: String,
    destinations: Vec<EventDestinationManifest>,
    status: &'static str,
}

pub(crate) fn run_event_migration(
    pairs: &[(PathBuf, PathBuf)],
) -> Result<(), Box<dyn std::error::Error>> {
    run_event_migration_inner(pairs, EventInstallBehavior::Normal)
}

#[cfg(test)]
fn run_event_migration_with_failpoint(
    pairs: &[(PathBuf, PathBuf)],
    fail_after_destination_install: Option<usize>,
) -> Result<(), Box<dyn std::error::Error>> {
    run_event_migration_inner(
        pairs,
        EventInstallBehavior::FailAfter(fail_after_destination_install),
    )
}

#[derive(Clone, Copy)]
enum EventInstallBehavior {
    Normal,
    #[cfg(test)]
    FailAfter(Option<usize>),
}

fn run_event_migration_inner(
    pairs: &[(PathBuf, PathBuf)],
    _install_behavior: EventInstallBehavior,
) -> Result<(), Box<dyn std::error::Error>> {
    if pairs.is_empty() {
        return Err(migration_failure(
            "event migration requires at least one pair",
        ));
    }
    if pairs.len() > MAX_EVENT_PAIR_COUNT {
        return Err(migration_failure(
            "event migration pair count budget exceeded",
        ));
    }

    let canonical_destination = pairs[0].1.clone();
    let canonical_manifest = manifest_path(&canonical_destination);
    let mut destinations = Vec::new();
    let mut destination_indexes = BTreeMap::new();
    let mut migration_targets = Vec::with_capacity(pairs.len() * 2 + 1);

    for (source, destination) in pairs {
        migration_targets.push(source.clone());
        if !destination_indexes.contains_key(destination) {
            if destinations.len() >= MAX_EVENT_DESTINATION_COUNT {
                return Err(migration_failure(
                    "event migration destination count budget exceeded",
                ));
            }
            let index = destinations.len();
            destination_indexes.insert(destination.clone(), index);
            destinations.push(EventDestination {
                path: destination.clone(),
                compression: event_compression(destination),
                temporary: None,
                hasher: Sha256::new(),
                byte_count: 0,
                composition: DestinationComposition::default(),
            });
        }
    }
    migration_targets.extend(
        destinations
            .iter()
            .map(|destination| destination.path.clone()),
    );
    migration_targets.push(canonical_manifest.clone());
    validate_migration_targets(&migration_targets)?;

    for (source, _) in pairs {
        if safe_path_info(source)?.is_none() {
            return Err(migration_failure("event migration source is unavailable"));
        }
    }

    let mut lock_targets = pairs
        .iter()
        .map(|(source, _)| source.clone())
        .collect::<Vec<_>>();
    lock_targets.extend(
        destinations
            .iter()
            .map(|destination| destination.path.clone()),
    );
    lock_targets.push(canonical_manifest.clone());
    let locks = acquire_migration_locks(&lock_targets)?;

    for destination in &destinations {
        validate_existing_mode(&destination.path, 0o640)?;
    }
    validate_existing_mode(&canonical_manifest, 0o600)?;

    for destination in &mut destinations {
        destination.temporary = Some(TempFile::create(&destination.path, 0o640)?);
    }

    let mut collision_index = EventCollisionIndex::new(&canonical_destination)?;

    let mut source_files = Vec::with_capacity(pairs.len());
    let mut source_hasher = Sha256::new();
    let mut budget = EventBudget::default();
    let mut stats = EventSetStats::default();

    for (source, destination) in pairs {
        let mut pinned = open_pinned_read(source)
            .map_err(|_| migration_failure("event migration source could not be pinned"))?;
        let compression = event_compression(source);
        let destination_compression = event_compression(destination);
        if compression != destination_compression {
            return Err(migration_failure("event migration compression mismatch"));
        }
        let destination_index = destination_indexes
            .get(destination)
            .copied()
            .ok_or_else(|| migration_failure("event migration destination mapping failed"))?;
        let destination = &mut destinations[destination_index];
        let source_start = destination
            .temporary
            .as_mut()
            .ok_or_else(|| migration_failure("event migration destination spool unavailable"))?
            .position()?;
        pinned.stream_to(|chunk| {
            let chunk_length =
                checked_length(chunk.len(), "event migration raw byte counter overflow")?;
            budget.charge_raw(chunk_length)?;
            budget.charge_output_spool(chunk_length)?;
            source_hasher.update(chunk);
            destination.hasher.update(chunk);
            destination
                .temporary
                .as_mut()
                .ok_or_else(|| migration_failure("event migration destination spool unavailable"))?
                .write_all(chunk)?;
            destination.byte_count = destination
                .byte_count
                .checked_add(chunk_length)
                .ok_or_else(|| migration_failure("event migration output byte counter overflow"))?;
            Ok(())
        })?;
        let source_length = destination
            .byte_count
            .checked_sub(source_start)
            .ok_or_else(|| migration_failure("event migration source byte counter overflow"))?;

        let mut reader = destination
            .temporary
            .as_ref()
            .ok_or_else(|| migration_failure("event migration destination spool unavailable"))?
            .open_reader()?;
        reader.seek(SeekFrom::Start(source_start))?;
        let contribution_reader = reader.take(source_length);
        let contribution = match compression {
            EventCompression::None => validate_event_jsonl(
                contribution_reader,
                &mut collision_index,
                &mut budget,
                false,
            )?,
            EventCompression::Gzip => {
                let mut decoder = MultiGzDecoder::new(contribution_reader);
                let contribution =
                    validate_event_jsonl(&mut decoder, &mut collision_index, &mut budget, true)?;
                let mut discard = [0_u8; FILE_STREAM_BUFFER_SIZE];
                loop {
                    match decoder.read(&mut discard) {
                        Ok(0) => break,
                        Ok(_) => {}
                        Err(_) => return Err(migration_failure("event migration invalid gzip")),
                    }
                }
                contribution
            }
        };
        if let Some(previous) = destination
            .composition
            .has_nonempty_contribution
            .then_some(destination.composition.last_nonempty_ended_with_lf)
            && contribution.byte_count > 0
            && !previous
        {
            return Err(migration_failure(
                "event migration destination contributions lack an LF boundary",
            ));
        }
        if contribution.byte_count > 0 {
            destination.composition.has_nonempty_contribution = true;
            destination.composition.last_nonempty_ended_with_lf =
                contribution.last_byte == Some(b'\n');
        }
        stats.add(contribution.stats)?;
        source_files.push(pinned);
    }

    let mut compression_names = BTreeSet::new();
    let mut destination_manifest_entries = Vec::with_capacity(destinations.len());
    let mut destination_hasher = Sha256::new();
    let mut destination_bytes = 0_u64;
    for (ordinal, destination) in destinations.iter_mut().enumerate() {
        destination
            .temporary
            .as_mut()
            .ok_or_else(|| migration_failure("event migration destination spool unavailable"))?
            .sync()?;
        let destination_hash = destination.hasher.clone().finalize();
        let destination_hash = format!("{:x}", destination_hash);
        let mut reader = destination
            .temporary
            .as_ref()
            .ok_or_else(|| migration_failure("event migration destination spool unavailable"))?
            .open_reader()?;
        let mut buffer = [0_u8; FILE_STREAM_BUFFER_SIZE];
        loop {
            let read = reader.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            destination_hasher.update(&buffer[..read]);
        }
        destination_bytes = destination_bytes
            .checked_add(destination.byte_count)
            .ok_or_else(|| {
                migration_failure("event migration destination byte counter overflow")
            })?;
        compression_names.insert(destination.compression.as_str());
        destination_manifest_entries.push(EventDestinationManifest {
            ordinal,
            compression: destination.compression.as_str(),
            source_bytes: destination.byte_count,
            source_sha256: destination_hash.clone(),
            destination_bytes: destination.byte_count,
            destination_sha256: destination_hash,
        });
    }
    let compression = if compression_names.len() == 1 {
        compression_names
            .into_iter()
            .next()
            .unwrap_or("none")
            .to_string()
    } else {
        "mixed".to_string()
    };
    let manifest = EventMigrationManifest {
        manifest_version: "1.0",
        source_format: "event_jsonl_set",
        destination_format: "event_jsonl_set",
        source_sha256: format!("{:x}", source_hasher.finalize()),
        destination_sha256: format!("{:x}", destination_hasher.finalize()),
        source_bytes: budget.raw_bytes,
        destination_bytes,
        pair_count: pairs.len(),
        destination_count: destinations.len(),
        record_count: stats.record_count,
        blank_frame_count: stats.blank_frame_count,
        schema_versions: stats.schema_versions,
        compression,
        destinations: destination_manifest_entries,
        status: "complete",
    };
    let manifest_bytes = serialized_manifest(&manifest)?;

    let mut destination_exists = Vec::with_capacity(destinations.len());
    let mut destination_to_install = Vec::new();
    for (index, destination) in destinations.iter().enumerate() {
        let temporary = destination
            .temporary
            .as_ref()
            .ok_or_else(|| migration_failure("event migration destination spool unavailable"))?;
        match existing_matches_file(&destination.path, &temporary.path, 0o640)? {
            Some(true) => {
                destination_exists.push(true);
            }
            Some(false) => {
                return Err(migration_failure(
                    "event migration destination conflict: existing bytes differ",
                ));
            }
            None => {
                destination_exists.push(false);
                destination_to_install.push(index);
            }
        }
    }

    let existing_manifest = existing_matches_bytes(&canonical_manifest, &manifest_bytes, 0o600)?;
    match &existing_manifest {
        Some(false) => {
            return Err(migration_failure(
                "event migration manifest conflict: existing bytes differ",
            ));
        }
        Some(true) if !destination_exists[0] => {
            return Err(migration_failure(
                "event migration manifest exists without its destination",
            ));
        }
        _ => {}
    }

    verify_migration_locks(&locks)?;
    verify_migration_sources(&mut source_files)?;
    let mut prepared_destinations = Vec::new();
    for index in destination_to_install {
        let temporary = destinations[index]
            .temporary
            .take()
            .ok_or_else(|| migration_failure("event migration destination spool unavailable"))?;
        prepared_destinations.push((index, temporary));
    }
    let prepared_manifest = if existing_manifest.is_none() {
        Some(TempFile::write_and_sync(
            &canonical_manifest,
            &manifest_bytes,
            0o600,
        )?)
    } else {
        None
    };

    verify_migration_locks(&locks)?;
    verify_migration_sources(&mut source_files)?;
    let mut installed_destinations = 0_usize;
    for (index, temporary) in prepared_destinations {
        verify_migration_locks(&locks)?;
        verify_migration_sources(&mut source_files)?;
        atomic_no_replace(temporary, &destinations[index].path)?;
        checked_add_usize(
            &mut installed_destinations,
            1,
            "event migration install counter overflow",
        )?;
        #[cfg(test)]
        if let EventInstallBehavior::FailAfter(limit) = _install_behavior
            && limit == Some(installed_destinations)
        {
            return Err(migration_failure(
                "event migration test failpoint after destination install",
            ));
        }
    }
    verify_existing_destinations(&destinations, &destination_exists)?;
    if let Some(temporary) = prepared_manifest {
        verify_migration_locks(&locks)?;
        verify_migration_sources(&mut source_files)?;
        atomic_no_replace(temporary, &canonical_manifest)?;
    }
    validate_installed_target(&canonical_manifest, 0o600, existing_manifest.is_some())?;
    if matches_bytes(&canonical_manifest, &manifest_bytes)? != Some(true) {
        return Err(migration_failure("event migration manifest changed"));
    }
    verify_migration_locks(&locks)?;
    verify_migration_sources(&mut source_files)?;
    print_bytes(&manifest_bytes)
}

#[derive(Serialize)]
struct EnvMigrationManifest {
    manifest_version: &'static str,
    source_format: &'static str,
    destination_format: &'static str,
    source_sha256: String,
    destination_sha256: String,
    source_bytes: u64,
    destination_bytes: u64,
    line_count: usize,
    assignment_count: usize,
    mapped_count: usize,
    status: &'static str,
}

pub(crate) fn run_env_migration(
    source: &Path,
    destination: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    run_env_migration_with_hook(source, destination, || Ok(()))
}

fn run_env_migration_with_hook(
    source: &Path,
    destination: &Path,
    mut before_install: impl FnMut() -> Result<(), Box<dyn std::error::Error>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let companion = manifest_path(destination);
    validate_migration_targets(&[
        source.to_path_buf(),
        destination.to_path_buf(),
        companion.clone(),
    ])?;
    if safe_path_info(source)?.is_none() {
        return Err(migration_failure(
            "environment migration source is unavailable",
        ));
    }

    let locks = acquire_migration_locks(&[
        source.to_path_buf(),
        destination.to_path_buf(),
        companion.clone(),
    ])?;
    validate_existing_mode(destination, 0o600)?;
    validate_existing_mode(&companion, 0o600)?;

    let mut pinned = open_pinned_read(source)
        .map_err(|_| migration_failure("environment migration source could not be pinned"))?;
    let mut temporary = TempFile::create(destination, 0o600)?;
    let (
        source_digest,
        source_bytes,
        destination_bytes,
        destination_digest,
        line_count,
        assignment_count,
        mapped_count,
    ) = {
        let mut environment = EnvironmentStream::new(&mut temporary);
        let source_digest = pinned.stream_to(|chunk| environment.push(chunk))?;
        environment.finish()?;
        let destination_digest: [u8; 32] = environment.destination_hasher.clone().finalize().into();
        (
            source_digest,
            environment.source_bytes,
            environment.destination_bytes,
            destination_digest,
            environment.line_count,
            environment.assignment_count,
            environment.mapped_count,
        )
    };
    temporary.sync()?;
    let manifest = EnvMigrationManifest {
        manifest_version: "1.0",
        source_format: "environment_file",
        destination_format: "environment_file",
        source_sha256: digest_hex(&source_digest),
        destination_sha256: digest_hex(&destination_digest),
        source_bytes,
        destination_bytes,
        line_count,
        assignment_count,
        mapped_count,
        status: "complete",
    };
    let manifest_bytes = serialized_manifest(&manifest)?;
    let existing_destination = existing_matches_file(destination, &temporary.path, 0o600)?;
    if let Some(false) = existing_destination {
        return Err(migration_failure(
            "environment migration destination conflict: existing bytes differ",
        ));
    }
    let existing_manifest = existing_matches_bytes(&companion, &manifest_bytes, 0o600)?;
    match existing_manifest {
        Some(false) => {
            return Err(migration_failure(
                "environment migration manifest conflict: existing bytes differ",
            ));
        }
        Some(true) if existing_destination != Some(true) => {
            return Err(migration_failure(
                "environment migration manifest exists without its destination",
            ));
        }
        _ => {}
    }

    verify_migration_locks(&locks)?;
    pinned
        .verify_unchanged()
        .map_err(|_| migration_failure("environment migration source changed during validation"))?;
    if existing_destination == Some(true)
        && existing_matches_file(destination, &temporary.path, 0o600)? != Some(true)
    {
        return Err(migration_failure(
            "environment migration destination changed",
        ));
    }
    let prepared_destination = if existing_destination.is_none() {
        Some(temporary)
    } else {
        temporary.disarm();
        None
    };
    let prepared_manifest = if existing_manifest.is_none() {
        Some(TempFile::write_and_sync(
            &companion,
            &manifest_bytes,
            0o600,
        )?)
    } else {
        None
    };
    verify_migration_locks(&locks)?;
    pinned
        .verify_unchanged()
        .map_err(|_| migration_failure("environment migration source changed during validation"))?;
    if let Some(temporary) = prepared_destination {
        verify_migration_locks(&locks)?;
        before_install()?;
        pinned.verify_unchanged().map_err(|_| {
            migration_failure("environment migration source changed before destination install")
        })?;
        atomic_no_replace(temporary, destination)?;
    }
    validate_installed_target(destination, 0o600, existing_destination.is_some())?;
    if verify_file_digest(destination, destination_bytes, &destination_digest)? != Some(true) {
        return Err(migration_failure(
            "environment migration destination changed",
        ));
    }
    if let Some(temporary) = prepared_manifest {
        verify_migration_locks(&locks)?;
        before_install()?;
        pinned.verify_unchanged().map_err(|_| {
            migration_failure("environment migration source changed before manifest install")
        })?;
        atomic_no_replace(temporary, &companion)?;
    }
    validate_installed_target(&companion, 0o600, existing_manifest.is_some())?;
    if matches_bytes(&companion, &manifest_bytes)? != Some(true) {
        return Err(migration_failure("environment migration manifest changed"));
    }
    verify_migration_locks(&locks)?;
    pinned
        .verify_unchanged()
        .map_err(|_| migration_failure("environment migration source changed during commit"))?;
    print_bytes(&manifest_bytes)
}

fn acquire_migration_locks(
    targets: &[PathBuf],
) -> Result<Vec<SidecarLock>, Box<dyn std::error::Error>> {
    let mut ordered = targets
        .iter()
        .map(|target| Ok((SidecarLock::lock_order_key(target)?, target.clone())))
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    ordered.sort_by(|left, right| left.0.cmp(&right.0));
    ordered.dedup_by(|left, right| left.0 == right.0);
    ordered
        .into_iter()
        .map(|(_, target)| SidecarLock::acquire(&target))
        .collect()
}

fn verify_migration_locks(locks: &[SidecarLock]) -> Result<(), Box<dyn std::error::Error>> {
    locks.iter().try_for_each(SidecarLock::verify_lock)
}

fn verify_migration_sources(sources: &mut [PinnedFile]) -> Result<(), Box<dyn std::error::Error>> {
    for source in sources {
        source
            .verify_unchanged()
            .map_err(|_| migration_failure("migration source changed during operation"))?;
    }
    Ok(())
}

fn verify_existing_destinations(
    destinations: &[EventDestination],
    existing: &[bool],
) -> Result<(), Box<dyn std::error::Error>> {
    for (destination, existed) in destinations.iter().zip(existing) {
        validate_installed_target(&destination.path, 0o640, *existed)?;
        let expected: [u8; 32] = destination.hasher.clone().finalize().into();
        if verify_file_digest(&destination.path, destination.byte_count, &expected)? != Some(true) {
            return Err(migration_failure("event migration destination changed"));
        }
    }
    Ok(())
}

fn validate_installed_target(
    path: &Path,
    allowed_mode: u32,
    existed_before_install: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if existed_before_install {
        return validate_existing_mode(path, allowed_mode);
    }
    #[cfg(unix)]
    {
        validate_existing_mode(path, allowed_mode)
    }
    #[cfg(not(unix))]
    {
        let _ = (path, allowed_mode);
        Ok(())
    }
}

fn existing_matches_file(
    path: &Path,
    expected: &Path,
    allowed_mode: u32,
) -> Result<Option<bool>, Box<dyn std::error::Error>> {
    validate_existing_mode(path, allowed_mode)?;
    if safe_path_info(path)?.is_none() {
        return Ok(None);
    }
    Ok(Some(compare_files(path, expected)?))
}

fn existing_matches_bytes(
    path: &Path,
    expected: &[u8],
    allowed_mode: u32,
) -> Result<Option<bool>, Box<dyn std::error::Error>> {
    validate_existing_mode(path, allowed_mode)?;
    matches_bytes(path, expected)
}

fn matches_bytes(path: &Path, expected: &[u8]) -> Result<Option<bool>, Box<dyn std::error::Error>> {
    let Some(initial) = safe_path_info(path)? else {
        return Ok(None);
    };
    let mut file = fs::File::open(path)?;
    let mut buffer = [0_u8; FILE_STREAM_BUFFER_SIZE];
    let mut offset: usize = 0;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let end = offset
            .checked_add(read)
            .ok_or_else(|| migration_failure("migration comparison byte counter overflow"))?;
        if expected.get(offset..end) != Some(&buffer[..read]) {
            return Ok(Some(false));
        }
        offset = end;
        if offset >= expected.len() {
            let mut extra = [0_u8; 1];
            let result = file.read(&mut extra)? == 0 && offset == expected.len();
            if safe_path_info(path)? != Some(initial) {
                return Err(migration_failure(
                    "migration target changed during comparison",
                ));
            }
            return Ok(Some(result));
        }
    }
    if safe_path_info(path)? != Some(initial) {
        return Err(migration_failure(
            "migration target changed during comparison",
        ));
    }
    Ok(Some(offset == expected.len()))
}

fn compare_files(left: &Path, right: &Path) -> Result<bool, Box<dyn std::error::Error>> {
    let left_info = safe_path_info(left)?.ok_or("comparison file is unavailable")?;
    let mut left_file = fs::File::open(left)?;
    let mut right_file = fs::File::open(right)?;
    let mut left_buffer = [0_u8; FILE_STREAM_BUFFER_SIZE];
    let mut right_buffer = [0_u8; FILE_STREAM_BUFFER_SIZE];
    loop {
        let left_read = left_file.read(&mut left_buffer)?;
        let right_read = right_file.read(&mut right_buffer)?;
        if left_read != right_read {
            return Ok(false);
        }
        if left_read == 0 {
            break;
        }
        if left_buffer[..left_read] != right_buffer[..right_read] {
            return Ok(false);
        }
    }
    if safe_path_info(left)? != Some(left_info) {
        return Err("migration destination changed during comparison".into());
    }
    Ok(true)
}

fn verify_file_digest(
    path: &Path,
    expected_length: u64,
    expected_digest: &[u8; 32],
) -> Result<Option<bool>, Box<dyn std::error::Error>> {
    if safe_path_info(path)?.is_none() {
        return Ok(None);
    }
    let mut pinned = open_pinned_read(path)?;
    let digest = pinned.stream_to(|_| Ok(()))?;
    Ok(Some(
        digest == *expected_digest
            && safe_path_info(path)?.is_some_and(|info| info.length == expected_length),
    ))
}

fn digest_hex(digest: &[u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn serialized_manifest<T: Serialize>(manifest: &T) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes = serde_json::to_vec_pretty(manifest)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn print_bytes(bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    print!("{}", std::str::from_utf8(bytes)?);
    Ok(())
}

fn event_compression(path: &Path) -> EventCompression {
    if path.extension().and_then(|extension| extension.to_str()) == Some("gz") {
        EventCompression::Gzip
    } else {
        EventCompression::None
    }
}

struct FixedByteReader<R> {
    reader: R,
    buffer: [u8; FILE_STREAM_BUFFER_SIZE],
    offset: usize,
    length: usize,
}

impl<R: Read> FixedByteReader<R> {
    fn new(reader: R) -> Self {
        Self {
            reader,
            buffer: [0; FILE_STREAM_BUFFER_SIZE],
            offset: 0,
            length: 0,
        }
    }

    fn next_byte(&mut self) -> io::Result<Option<u8>> {
        if self.offset == self.length {
            self.length = self.reader.read(&mut self.buffer)?;
            self.offset = 0;
            if self.length == 0 {
                return Ok(None);
            }
        }
        let byte = self.buffer[self.offset];
        self.offset += 1;
        Ok(Some(byte))
    }
}

struct BoundedLineReader<R> {
    reader: FixedByteReader<R>,
}

impl<R: Read> BoundedLineReader<R> {
    fn new(reader: R) -> Self {
        Self {
            reader: FixedByteReader::new(reader),
        }
    }

    fn next_frame(&mut self) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
        let mut frame = Vec::new();
        loop {
            let Some(byte) = self.reader.next_byte()? else {
                return Ok((!frame.is_empty()).then_some(frame));
            };
            frame.push(byte);
            if frame.len() > MAX_EVENT_FRAME_BYTES {
                return Err(migration_failure(
                    "event migration record exceeds bounded frame limit",
                ));
            }
            if byte == b'\n' {
                return Ok(Some(frame));
            }
        }
    }
}

struct CollisionEntry {
    offset: u64,
    length: u64,
    digest: [u8; 32],
}

struct EventCollisionIndex {
    entries: BTreeMap<String, CollisionEntry>,
    spool: TempFile,
}

impl EventCollisionIndex {
    fn new(anchor: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            entries: BTreeMap::new(),
            spool: TempFile::create(anchor, 0o600)?,
        })
    }

    fn check(
        &mut self,
        event_id: &str,
        object_bytes: &[u8],
        budget: &mut EventBudget,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let digest: [u8; 32] = Sha256::digest(object_bytes).into();
        if let Some(previous) = self.entries.get(event_id) {
            let same = previous.length
                == checked_length(
                    object_bytes.len(),
                    "event migration collision body byte counter overflow",
                )?
                && previous.digest == digest
                && self.spool_matches(previous, object_bytes)?;
            if !same {
                return Err(migration_failure("event migration event_id collision"));
            }
            return Ok(());
        }
        if self.entries.len() >= MAX_EVENT_UNIQUE_COLLISION_IDS {
            return Err(migration_failure(
                "event migration unique collision ID budget exceeded",
            ));
        }
        budget.charge_unique_collision_id()?;
        let object_length = checked_length(
            object_bytes.len(),
            "event migration collision body byte counter overflow",
        )?;
        budget.charge_output_spool(object_length)?;
        let offset = self.spool.position()?;
        self.spool.write_all(object_bytes)?;
        self.entries.insert(
            event_id.to_string(),
            CollisionEntry {
                offset,
                length: object_length,
                digest,
            },
        );
        Ok(())
    }

    fn spool_matches(
        &self,
        previous: &CollisionEntry,
        current: &[u8],
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let mut file = self.spool.open_reader()?;
        file.seek(SeekFrom::Start(previous.offset))?;
        let mut remaining = previous.length;
        let mut offset = 0_usize;
        let mut buffer = [0_u8; FILE_STREAM_BUFFER_SIZE];
        while remaining > 0 {
            let requested = remaining.min(buffer.len() as u64) as usize;
            let read = file.read(&mut buffer[..requested])?;
            let end = offset.checked_add(read).ok_or_else(|| {
                migration_failure("event migration collision body offset overflow")
            })?;
            if read == 0 || current.get(offset..end) != Some(&buffer[..read]) {
                return Ok(false);
            }
            remaining = remaining
                .checked_sub(checked_length(
                    read,
                    "event migration collision body byte counter overflow",
                )?)
                .ok_or_else(|| migration_failure("event migration collision body underflow"))?;
            offset = end;
        }
        Ok(offset == current.len())
    }
}

fn validate_event_jsonl<R: Read>(
    reader: R,
    collision_index: &mut EventCollisionIndex,
    budget: &mut EventBudget,
    gzip: bool,
) -> Result<EventContribution, Box<dyn std::error::Error>> {
    let mut stats = EventSetStats::default();
    let mut frames = BoundedLineReader::new(reader);
    let mut byte_count = 0_u64;
    let mut last_byte = None;
    while let Some(raw) = frames
        .next_frame()
        .map_err(|error| map_event_read_error(error, gzip))?
    {
        let raw_length = checked_length(
            raw.len(),
            "event migration decompressed byte counter overflow",
        )?;
        budget.charge_decompressed(raw_length, gzip)?;
        byte_count = byte_count.checked_add(raw_length).ok_or_else(|| {
            migration_failure("event migration contribution byte counter overflow")
        })?;
        last_byte = raw.last().copied();
        let object_end = if raw.ends_with(b"\r\n") {
            raw.len() - 2
        } else if raw.ends_with(b"\n") {
            raw.len() - 1
        } else {
            raw.len()
        };
        let object_bytes = &raw[..object_end];
        if object_bytes.iter().all(u8::is_ascii_whitespace) {
            budget.charge_frame(true)?;
            checked_add_usize(
                &mut stats.blank_frame_count,
                1,
                "event migration blank frame counter overflow",
            )?;
        } else {
            budget.charge_frame(false)?;
            let value = parse_json_value(object_bytes)?;
            let (value, _) = crate::cli::historical::validate_event_record(value)
                .map_err(event_validation_failure)?;
            let object = value
                .as_object()
                .ok_or_else(|| migration_failure("event migration schema violation"))?;
            let version = object
                .get("schema_version")
                .and_then(Value::as_str)
                .ok_or_else(|| migration_failure("event migration schema violation"))?;
            let version = match version {
                "1.0" => "1.0",
                "2.0" => "2.0",
                "3.0" => "3.0",
                _ => return Err(migration_failure("event migration unknown schema version")),
            };
            let event_id = object
                .get("event_id")
                .and_then(Value::as_str)
                .ok_or_else(|| migration_failure("event migration schema violation"))?;
            budget.charge_record()?;
            collision_index.check(event_id, object_bytes, budget)?;
            checked_add_usize(
                stats.schema_versions.entry(version).or_default(),
                1,
                "event migration schema counter overflow",
            )?;
            checked_add_usize(
                &mut stats.record_count,
                1,
                "event migration record counter overflow",
            )?;
        }
    }
    Ok(EventContribution {
        stats,
        byte_count,
        last_byte,
    })
}

fn map_event_read_error(
    error: Box<dyn std::error::Error>,
    gzip: bool,
) -> Box<dyn std::error::Error> {
    if error.downcast_ref::<MigrationFailure>().is_some() {
        error
    } else if gzip {
        migration_failure("event migration invalid gzip")
    } else {
        migration_failure("event migration input read failed")
    }
}

fn event_validation_failure(
    error: crate::cli::historical::HistoricalEventValidationError,
) -> Box<dyn std::error::Error> {
    let code = match error {
        crate::cli::historical::HistoricalEventValidationError::MissingSchemaVersion => {
            "event migration missing schema version"
        }
        crate::cli::historical::HistoricalEventValidationError::InvalidSchemaVersionType => {
            "event migration schema version type invalid"
        }
        crate::cli::historical::HistoricalEventValidationError::UnknownRequestedSchemaVersion
        | crate::cli::historical::HistoricalEventValidationError::UnknownActualSchemaVersion => {
            "event migration unknown schema version"
        }
        crate::cli::historical::HistoricalEventValidationError::SchemaVersionMismatch => {
            "event migration schema version mismatch"
        }
        crate::cli::historical::HistoricalEventValidationError::SchemaUnavailable => {
            "event migration schema unavailable"
        }
        crate::cli::historical::HistoricalEventValidationError::SchemaViolation => {
            "event migration schema violation"
        }
    };
    migration_failure(code)
}

enum JsonValueError {
    DuplicateKey,
    Invalid,
}

fn parse_json_value(bytes: &[u8]) -> Result<Value, Box<dyn std::error::Error>> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = NoDuplicateValueSeed
        .deserialize(&mut deserializer)
        .map_err(|error| {
            if error.to_string().starts_with("duplicate JSON key") {
                JsonValueError::DuplicateKey
            } else {
                JsonValueError::Invalid
            }
        });
    let value = match value {
        Ok(value) => value,
        Err(JsonValueError::DuplicateKey) => {
            return Err(migration_failure("event migration duplicate JSON key"));
        }
        Err(JsonValueError::Invalid) => {
            return Err(migration_failure("event migration invalid JSON"));
        }
    };
    deserializer
        .end()
        .map_err(|_| migration_failure("event migration invalid JSON"))?;
    Ok(value)
}

struct NoDuplicateValueSeed;

impl<'de> DeserializeSeed<'de> for NoDuplicateValueSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(NoDuplicateValueVisitor)
    }
}

struct NoDuplicateValueVisitor;

impl<'de> Visitor<'de> for NoDuplicateValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Value::String(value.to_string()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Value::String(value))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Value::Null)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(NoDuplicateValueSeed)? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        let mut keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(serde::de::Error::custom("duplicate JSON key"));
            }
            let value = map.next_value_seed(NoDuplicateValueSeed)?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

#[derive(Clone, Copy)]
struct EnvironmentMapping {
    old: &'static str,
    new: &'static str,
}

const ENVIRONMENT_MAPPINGS: &[EnvironmentMapping] = &[
    EnvironmentMapping {
        old: "ADR_LOG_PATH",
        new: "TELLTALE_LOG_PATH",
    },
    EnvironmentMapping {
        old: "ADR_STATE_PATH",
        new: "TELLTALE_STATE_PATH",
    },
    EnvironmentMapping {
        old: "ADR_SCAN_ROOT",
        new: "TELLTALE_SCAN_ROOT",
    },
    EnvironmentMapping {
        old: "ADR_PROJECT_CONFIG",
        new: "TELLTALE_PROJECT_CONFIG",
    },
    EnvironmentMapping {
        old: "ADR_LOG_ROTATE_MAX_SIZE",
        new: "TELLTALE_LOG_ROTATE_MAX_SIZE",
    },
    EnvironmentMapping {
        old: "ADR_LOG_ROTATE_KEEP",
        new: "TELLTALE_LOG_ROTATE_KEEP",
    },
    EnvironmentMapping {
        old: "ADR_INSTALL_INVENTORY_INTERVAL_SECONDS",
        new: "TELLTALE_INSTALL_INVENTORY_INTERVAL_SECONDS",
    },
    EnvironmentMapping {
        old: "ADR_PROCESS_CHAIN_DETECTIONS",
        new: "TELLTALE_PROCESS_CHAIN_DETECTIONS",
    },
    EnvironmentMapping {
        old: "ADR_OP_ALERT_MAX_SCANNER_ERRORS",
        new: "TELLTALE_OP_ALERT_MAX_SCANNER_ERRORS",
    },
    EnvironmentMapping {
        old: "ADR_OP_ALERT_MAX_SCAN_DURATION_MS",
        new: "TELLTALE_OP_ALERT_MAX_SCAN_DURATION_MS",
    },
    EnvironmentMapping {
        old: "ADR_RISK_THRESHOLD_LOW",
        new: "TELLTALE_RISK_THRESHOLD_LOW",
    },
    EnvironmentMapping {
        old: "ADR_RISK_THRESHOLD_MEDIUM",
        new: "TELLTALE_RISK_THRESHOLD_MEDIUM",
    },
    EnvironmentMapping {
        old: "ADR_RISK_THRESHOLD_TRIAGE",
        new: "TELLTALE_RISK_THRESHOLD_HIGH",
    },
    EnvironmentMapping {
        old: "ADR_RISK_THRESHOLD_ALERT",
        new: "TELLTALE_RISK_THRESHOLD_CRITICAL",
    },
    EnvironmentMapping {
        old: "ADR_INDEX",
        new: "TELLTALE_INDEX",
    },
    EnvironmentMapping {
        old: "ADR_SOURCETYPE",
        new: "TELLTALE_SOURCETYPE",
    },
    EnvironmentMapping {
        old: "ADR_ATLAS_PATH",
        new: "TELLTALE_ATLAS_PATH",
    },
    EnvironmentMapping {
        old: "ADR_GIT_HASH",
        new: "TELLTALE_GIT_HASH",
    },
    EnvironmentMapping {
        old: "ADR_LIVETEST_ES_CONTAINER",
        new: "TELLTALE_LIVETEST_ES_CONTAINER",
    },
    EnvironmentMapping {
        old: "ADR_LIVETEST_SPLUNK_CONTAINER",
        new: "TELLTALE_LIVETEST_SPLUNK_CONTAINER",
    },
    EnvironmentMapping {
        old: "ADR_LIVETEST_ES_INDEX",
        new: "TELLTALE_LIVETEST_ES_INDEX",
    },
    EnvironmentMapping {
        old: "ADR_LIVETEST_ES_PASSWORD",
        new: "TELLTALE_LIVETEST_ES_PASSWORD",
    },
    EnvironmentMapping {
        old: "ADR_LIVETEST_HEC_TOKEN",
        new: "TELLTALE_LIVETEST_HEC_TOKEN",
    },
];

const ENVIRONMENT_UNMAPPED_PRODUCT_KEYS: &[&str] =
    &["ADR_TRIAGE_TIMEOUT_MS", "ADR_TRIAGE_MAX_RETRIES"];

const MAX_ENVIRONMENT_SOURCE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_ENVIRONMENT_OUTPUT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_ENVIRONMENT_ASSIGNMENTS: usize = 100_000;
const MAX_ENVIRONMENT_LINE_COUNT: usize = 1_000_000;
const MAX_ENVIRONMENT_LINE_BYTES: usize = 1024 * 1024;

struct EnvironmentStream<'a> {
    destination: &'a mut TempFile,
    current_line: Vec<u8>,
    seen_names: BTreeSet<String>,
    mapped_names: BTreeSet<&'static str>,
    source_bytes: u64,
    destination_bytes: u64,
    line_count: usize,
    assignment_count: usize,
    mapped_count: usize,
    destination_hasher: Sha256,
}

impl<'a> EnvironmentStream<'a> {
    fn new(destination: &'a mut TempFile) -> Self {
        Self {
            destination,
            current_line: Vec::new(),
            seen_names: BTreeSet::new(),
            mapped_names: BTreeSet::new(),
            source_bytes: 0,
            destination_bytes: 0,
            line_count: 0,
            assignment_count: 0,
            mapped_count: 0,
            destination_hasher: Sha256::new(),
        }
    }

    fn push(&mut self, chunk: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        checked_add_u64(
            &mut self.source_bytes,
            checked_length(
                chunk.len(),
                "environment migration source byte counter overflow",
            )?,
            MAX_ENVIRONMENT_SOURCE_BYTES,
            "environment migration source byte budget exceeded",
        )?;
        for byte in chunk {
            if *byte == 0 {
                return Err(migration_failure("environment migration NUL byte rejected"));
            }
            self.current_line.push(*byte);
            if self.current_line.len() > MAX_ENVIRONMENT_LINE_BYTES {
                return Err(migration_failure(
                    "environment migration line exceeds bounded limit",
                ));
            }
            if *byte == b'\n' {
                self.process_line()?;
            }
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.current_line.is_empty() {
            self.process_line()?;
        }
        Ok(())
    }

    fn process_line(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let raw = std::mem::take(&mut self.current_line);
        checked_add_usize(
            &mut self.line_count,
            1,
            "environment migration line counter overflow",
        )?;
        if self.line_count > MAX_ENVIRONMENT_LINE_COUNT {
            return Err(migration_failure(
                "environment migration line count budget exceeded",
            ));
        }
        let content_end = if raw.ends_with(b"\n") {
            let without_lf = raw.len() - 1;
            if without_lf > 0 && raw[without_lf - 1] == b'\r' {
                without_lf - 1
            } else {
                without_lf
            }
        } else {
            raw.len()
        };
        let content = &raw[..content_end];
        if content.iter().all(u8::is_ascii_whitespace)
            || content
                .iter()
                .find(|byte| !byte.is_ascii_whitespace())
                .is_some_and(|byte| *byte == b'#')
        {
            self.write(&raw)?;
            return Ok(());
        }
        let Some(equal) = content.iter().position(|byte| *byte == b'=') else {
            return Err(migration_failure(
                "environment migration malformed assignment",
            ));
        };
        let name_bytes = &content[..equal];
        if !valid_environment_name(name_bytes) || has_environment_continuation(content) {
            return Err(migration_failure(
                "environment migration malformed assignment",
            ));
        }
        let name = std::str::from_utf8(name_bytes)
            .map_err(|_| migration_failure("environment migration malformed assignment"))?
            .to_string();
        if !self.seen_names.insert(name.clone()) {
            return Err(migration_failure("environment migration duplicate key"));
        }
        checked_add_usize(
            &mut self.assignment_count,
            1,
            "environment migration assignment counter overflow",
        )?;
        if self.assignment_count > MAX_ENVIRONMENT_ASSIGNMENTS {
            return Err(migration_failure(
                "environment migration assignment count budget exceeded",
            ));
        }
        let replacement = environment_mapping(&name).map(|mapping| mapping.new);
        if replacement.is_none() && ENVIRONMENT_UNMAPPED_PRODUCT_KEYS.contains(&name.as_str()) {
            return Err(migration_failure(
                "environment migration unmapped product key",
            ));
        }
        if self.mapped_names.contains(name.as_str()) {
            return Err(migration_failure(
                "environment migration old and new keys coexist",
            ));
        }
        if let Some(replacement) = replacement {
            if self.seen_names.contains(replacement) {
                return Err(migration_failure(
                    "environment migration old and new keys coexist",
                ));
            }
            self.mapped_names.insert(replacement);
            self.write(replacement.as_bytes())?;
            self.write(&raw[equal..])?;
            checked_add_usize(
                &mut self.mapped_count,
                1,
                "environment migration mapped counter overflow",
            )?;
        } else {
            self.write(&raw)?;
        }
        Ok(())
    }

    fn write(&mut self, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        checked_add_u64(
            &mut self.destination_bytes,
            checked_length(
                bytes.len(),
                "environment migration output byte counter overflow",
            )?,
            MAX_ENVIRONMENT_OUTPUT_BYTES,
            "environment migration output byte budget exceeded",
        )?;
        self.destination.write_all(bytes)?;
        self.destination_hasher.update(bytes);
        Ok(())
    }
}

fn valid_environment_name(name: &[u8]) -> bool {
    let Some((&first, rest)) = name.split_first() else {
        return false;
    };
    (first == b'_' || first.is_ascii_alphabetic())
        && rest
            .iter()
            .all(|byte| *byte == b'_' || byte.is_ascii_alphanumeric())
}

fn has_environment_continuation(content: &[u8]) -> bool {
    content
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .is_some_and(|index| content[index] == b'\\')
}

fn environment_mapping(name: &str) -> Option<EnvironmentMapping> {
    ENVIRONMENT_MAPPINGS
        .iter()
        .copied()
        .find(|mapping| mapping.old == name)
}

fn contains_schema_version(bytes: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(bytes)
        .ok()
        .and_then(|value| value.get("state_schema_version").cloned())
        .is_some()
}

fn needs_baseline_promotion(bytes: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(bytes)
        .ok()
        .and_then(|value| {
            value
                .get("baseline_snapshots")?
                .get("schema_version")
                .cloned()
        })
        .and_then(|value| value.as_u64())
        == Some(1)
}

fn stable_read(
    path: &Path,
) -> Result<(crate::file_lock::PinnedFile, Vec<u8>), Box<dyn std::error::Error>> {
    let mut pinned = open_pinned_read(path)?;
    let bytes = pinned.snapshot()?;
    if bytes.is_empty() || bytes.iter().all(u8::is_ascii_whitespace) {
        return Err("state requires explicit migration; empty input is not a state file".into());
    }
    Ok((pinned, bytes))
}

fn manifest_bytes(manifest: &MigrationManifest) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes = serde_json::to_vec_pretty(manifest)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn existing_bytes(path: &Path) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    validate_existing_mode(path, 0o600)?;
    if safe_path_info(path)?.is_some() {
        Ok(Some(read_snapshot(path)?))
    } else {
        Ok(None)
    }
}

fn reject_alias(source: &Path, destination: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let source_identity = fs::canonicalize(source)?;
    let destination_identity = canonical_destination(destination)?;
    if source_identity == destination_identity {
        return Err("migration source and destination must not alias".into());
    }
    Ok(())
}

fn canonical_destination(path: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if path.exists() {
        return Ok(fs::canonicalize(path)?);
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let parent = fs::canonicalize(parent).or_else(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            std::path::absolute(parent)
        } else {
            Err(error)
        }
    })?;
    Ok(parent.join(path.file_name().ok_or("invalid destination")?))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Cursor;
    use std::path::PathBuf;

    use serde_json::Value;
    use tempfile::tempdir;

    use super::{
        BoundedLineReader, ENVIRONMENT_MAPPINGS, ENVIRONMENT_UNMAPPED_PRODUCT_KEYS,
        EnvironmentStream, EventBudget, MAX_ENVIRONMENT_ASSIGNMENTS, MAX_ENVIRONMENT_OUTPUT_BYTES,
        MAX_ENVIRONMENT_SOURCE_BYTES, MAX_EVENT_DESTINATION_COUNT, MAX_EVENT_FRAME_BYTES,
        MAX_EVENT_GZIP_EXPANSION_BYTES, MAX_EVENT_PAIR_COUNT, MAX_EVENT_TOTAL_DECOMPRESSED_BYTES,
        MAX_EVENT_TOTAL_OUTPUT_SPOOL_BYTES, MAX_EVENT_TOTAL_RAW_BYTES, environment_mapping,
        manifest_path, run_env_migration_with_hook, run_event_migration,
        run_event_migration_with_failpoint, run_state_migration,
    };
    use crate::state::ScanState;

    #[test]
    fn migration_preserves_source_and_is_idempotent() {
        let temp = tempdir().expect("tempdir");
        let source = temp.path().join("legacy.json");
        let destination = temp.path().join("native.json");
        let source_bytes = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/state/legacy-scan-state.json"
        ));
        fs::write(&source, source_bytes).expect("source");

        run_state_migration(&source, &destination).expect("migrate");
        assert_eq!(fs::read(&source).expect("source bytes"), source_bytes);
        let first = fs::read(&destination).expect("destination bytes");
        let mut expected = ScanState::validate_legacy_bytes(source_bytes).expect("legacy parse");
        expected.normalize_legacy_for_migration();
        assert_eq!(first, expected.canonical_bytes().expect("canonical bytes"));
        let manifest = fs::read(manifest_path(&destination)).expect("manifest");
        let manifest_value: Value = serde_json::from_slice(&manifest).expect("manifest JSON");
        assert_eq!(manifest_value["normalization_count"], 1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            assert_eq!(
                fs::metadata(&destination)
                    .expect("destination metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(manifest_path(&destination))
                    .expect("manifest metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        run_state_migration(&source, &destination).expect("repeat migration");
        assert_eq!(fs::read(&destination).expect("destination bytes"), first);
        assert_eq!(
            fs::read(manifest_path(&destination)).expect("manifest"),
            manifest
        );
        fs::remove_file(manifest_path(&destination)).expect("remove manifest");
        run_state_migration(&source, &destination).expect("repair migration");
        assert_eq!(
            fs::read(manifest_path(&destination)).expect("manifest"),
            manifest
        );
        fs::write(manifest_path(&destination), b"conflict\n").expect("conflict manifest");
        assert!(run_state_migration(&source, &destination).is_err());

        let manifest_as_destination = manifest_path(&destination);
        let other_source = temp.path().join("other-legacy.json");
        fs::write(&other_source, source_bytes).expect("other source");
        assert!(run_state_migration(&other_source, &manifest_as_destination).is_err());
    }

    #[test]
    fn migration_refuses_conflicting_destination_and_alias() {
        let temp = tempdir().expect("tempdir");
        let source = temp.path().join("legacy.json");
        let destination = temp.path().join("native.json");
        fs::write(
            &source,
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/state/legacy-scan-state.json"
            )),
        )
        .expect("source");
        fs::write(&destination, b"conflict").expect("destination");
        assert!(run_state_migration(&source, &destination).is_err());
        assert!(run_state_migration(&source, &source).is_err());
    }

    #[test]
    fn environment_inventory_is_exact_and_bijective() {
        for mapping in ENVIRONMENT_MAPPINGS {
            assert_eq!(
                environment_mapping(mapping.old).map(|value| value.new),
                Some(mapping.new)
            );
            assert!(!ENVIRONMENT_UNMAPPED_PRODUCT_KEYS.contains(&mapping.old));
        }
        assert!(environment_mapping("ADR_TRIAGE_TIMEOUT_MS").is_none());
        assert!(environment_mapping("ADR_TRIAGE_MAX_RETRIES").is_none());
        assert!(environment_mapping("ADR_TEST_UNRELATED").is_none());
        assert!(environment_mapping("ADR_LOGISTICS_PATH").is_none());
        assert!(environment_mapping("ADR_VENDOR_MODE").is_none());
    }

    #[test]
    fn event_frame_reader_rejects_oversize_records_with_static_error() {
        let bytes = vec![b'x'; MAX_EVENT_FRAME_BYTES + 1];
        let error = BoundedLineReader::new(Cursor::new(bytes))
            .next_frame()
            .expect_err("oversize frame");
        assert_eq!(
            error.to_string(),
            "event migration record exceeds bounded frame limit"
        );
    }

    #[test]
    fn migration_budgets_reject_limits_with_static_errors() {
        let mut budget = EventBudget::default();
        budget
            .charge_raw(MAX_EVENT_TOTAL_RAW_BYTES)
            .expect("raw limit");
        assert_eq!(
            budget.charge_raw(1).expect_err("raw overflow").to_string(),
            "event migration raw byte budget exceeded"
        );

        let mut budget = EventBudget::default();
        budget
            .charge_decompressed(MAX_EVENT_TOTAL_DECOMPRESSED_BYTES, false)
            .expect("decompressed limit");
        assert_eq!(
            budget
                .charge_decompressed(1, false)
                .expect_err("decompressed overflow")
                .to_string(),
            "event migration decompressed byte budget exceeded"
        );

        let mut budget = EventBudget::default();
        budget
            .charge_decompressed(MAX_EVENT_GZIP_EXPANSION_BYTES, true)
            .expect("gzip limit");
        assert_eq!(
            budget
                .charge_decompressed(1, true)
                .expect_err("gzip overflow")
                .to_string(),
            "event migration gzip expansion budget exceeded"
        );

        let mut budget = EventBudget::default();
        budget
            .charge_output_spool(MAX_EVENT_TOTAL_OUTPUT_SPOOL_BYTES)
            .expect("spool limit");
        assert_eq!(
            budget
                .charge_output_spool(1)
                .expect_err("spool overflow")
                .to_string(),
            "event migration output and spool byte budget exceeded"
        );
    }

    #[test]
    fn event_pair_and_destination_caps_reject_before_filesystem_activity() {
        let temp = tempdir().expect("tempdir");
        let source = temp.path().join("empty-source.jsonl");
        fs::write(&source, []).expect("empty source");

        let pair_overflow = (0..=MAX_EVENT_PAIR_COUNT)
            .map(|index| {
                (
                    source.clone(),
                    temp.path().join(format!("pair-destination-{index}.jsonl")),
                )
            })
            .collect::<Vec<(PathBuf, PathBuf)>>();
        assert_eq!(
            run_event_migration(&pair_overflow)
                .expect_err("pair cap")
                .to_string(),
            "event migration pair count budget exceeded"
        );
        assert_eq!(
            fs::read_dir(temp.path())
                .expect("migration directory")
                .count(),
            1
        );

        let destination_overflow = (0..=MAX_EVENT_DESTINATION_COUNT)
            .map(|index| {
                (
                    source.clone(),
                    temp.path().join(format!("destination-{index}.jsonl")),
                )
            })
            .collect::<Vec<(PathBuf, PathBuf)>>();
        assert_eq!(
            run_event_migration(&destination_overflow)
                .expect_err("destination cap")
                .to_string(),
            "event migration destination count budget exceeded"
        );
        assert_eq!(
            fs::read_dir(temp.path())
                .expect("migration directory")
                .count(),
            1
        );
        for destination in destination_overflow.iter().map(|(_, path)| path) {
            assert!(!destination.exists());
            assert!(!manifest_path(destination).exists());
            assert!(!PathBuf::from(format!("{}.lock", destination.display())).exists());
        }
    }

    #[test]
    fn event_migration_accepts_representative_pair_and_destination_cardinality() {
        let temp = tempdir().expect("tempdir");
        let source_one = temp.path().join("accepted-source-one.jsonl");
        let source_two = temp.path().join("accepted-source-two.jsonl");
        let source_three = temp.path().join("accepted-source-three.jsonl");
        let source_four = temp.path().join("accepted-source-four.jsonl");
        let destination_one = temp.path().join("accepted-destination-one.jsonl");
        let destination_two = temp.path().join("accepted-destination-two.jsonl");
        let destination_three = temp.path().join("accepted-destination-three.jsonl");
        let first = serde_json::to_vec(
            &serde_json::from_slice::<Value>(include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/historical_events/event-1.0.json"
            )))
            .expect("first fixture"),
        )
        .expect("compact first fixture");
        let second = serde_json::to_vec(
            &serde_json::from_slice::<Value>(include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/historical_events/event-2.0.json"
            )))
            .expect("second fixture"),
        )
        .expect("compact second fixture");
        let mut first_with_lf = first.clone();
        first_with_lf.push(b'\n');
        fs::write(&source_one, &first_with_lf).expect("source one");
        fs::write(&source_two, &second).expect("source two");
        fs::write(&source_three, &first).expect("source three");
        fs::write(&source_four, &second).expect("source four");

        run_event_migration(&[
            (source_one, destination_one.clone()),
            (source_two, destination_one.clone()),
            (source_three, destination_two.clone()),
            (source_four, destination_three.clone()),
        ])
        .expect("representative migration");

        let mut joined = first_with_lf;
        joined.extend_from_slice(&second);
        assert_eq!(
            fs::read(&destination_one).expect("joined destination"),
            joined
        );
        assert_eq!(
            fs::read(&destination_two).expect("second destination"),
            first
        );
        assert_eq!(
            fs::read(&destination_three).expect("third destination"),
            second
        );
        let manifest: Value =
            serde_json::from_slice(&fs::read(manifest_path(&destination_one)).expect("manifest"))
                .expect("manifest JSON");
        assert_eq!(manifest["pair_count"], 4);
        assert_eq!(manifest["destination_count"], 3);
    }

    #[test]
    fn event_destination_install_failure_is_recoverable_without_clobbering() {
        let temp = tempdir().expect("tempdir");
        let source_one = temp.path().join("recover-one.jsonl");
        let source_two = temp.path().join("recover-two.jsonl");
        let destination_one = temp.path().join("recover-new-one.jsonl");
        let destination_two = temp.path().join("recover-new-two.jsonl");
        let first = serde_json::to_vec(
            &serde_json::from_slice::<Value>(include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/historical_events/event-1.0.json"
            )))
            .expect("first fixture"),
        )
        .expect("compact first fixture");
        let second = serde_json::to_vec(
            &serde_json::from_slice::<Value>(include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/historical_events/event-2.0.json"
            )))
            .expect("second fixture"),
        )
        .expect("compact second fixture");
        fs::write(&source_one, &first).expect("source one");
        fs::write(&source_two, &second).expect("source two");

        let error = run_event_migration_with_failpoint(
            &[
                (source_one.clone(), destination_one.clone()),
                (source_two.clone(), destination_two.clone()),
            ],
            Some(1),
        )
        .expect_err("destination install failpoint");
        assert_eq!(
            error.to_string(),
            "event migration test failpoint after destination install"
        );
        assert_eq!(
            fs::read(&destination_one).expect("first destination"),
            first
        );
        assert!(!destination_two.exists());
        assert!(!manifest_path(&destination_one).exists());
        assert_eq!(fs::read(&source_one).expect("source one bytes"), first);
        assert_eq!(fs::read(&source_two).expect("source two bytes"), second);

        run_event_migration(&[
            (source_one, destination_one.clone()),
            (source_two, destination_two.clone()),
        ])
        .expect("recover migration");
        assert_eq!(
            fs::read(&destination_one).expect("first destination"),
            first
        );
        assert_eq!(
            fs::read(&destination_two).expect("second destination"),
            second
        );
        assert!(manifest_path(&destination_one).exists());
    }

    #[test]
    fn environment_byte_budgets_are_checked_before_output() {
        let temp = tempdir().expect("tempdir");
        let destination = temp.path().join("environment-output");
        let mut temporary =
            crate::file_lock::TempFile::create(&destination, 0o600).expect("temporary destination");
        let mut environment = EnvironmentStream::new(&mut temporary);
        environment.source_bytes = MAX_ENVIRONMENT_SOURCE_BYTES;
        assert_eq!(
            environment
                .push(b"x")
                .expect_err("source budget")
                .to_string(),
            "environment migration source byte budget exceeded"
        );
        drop(environment);
        temporary.disarm();

        let destination = temp.path().join("environment-output-limit");
        let mut temporary =
            crate::file_lock::TempFile::create(&destination, 0o600).expect("temporary destination");
        let mut environment = EnvironmentStream::new(&mut temporary);
        environment.destination_bytes = MAX_ENVIRONMENT_OUTPUT_BYTES;
        assert_eq!(
            environment
                .write(b"x")
                .expect_err("output budget")
                .to_string(),
            "environment migration output byte budget exceeded"
        );
    }

    #[test]
    fn environment_digest_recheck_rejects_same_length_source_mutation_before_install() {
        let temp = tempdir().expect("tempdir");
        let source = temp.path().join("source.env");
        let destination = temp.path().join("destination.env");
        fs::write(&source, b"ADR_LOG_PATH=/old\n").expect("source");

        let result = run_env_migration_with_hook(&source, &destination, || {
            fs::write(&source, b"ADR_LOG_PATH=/new\n").expect("same-length mutation");
            Ok(())
        });
        assert_eq!(
            result.expect_err("source mutation must fail").to_string(),
            "environment migration source changed before destination install"
        );
        assert_eq!(
            fs::read(&source).expect("mutated source"),
            b"ADR_LOG_PATH=/new\n"
        );
        assert!(!destination.exists());
        assert!(!manifest_path(&destination).exists());
    }

    #[test]
    fn environment_manifest_install_failure_leaves_destination_without_manifest() {
        let temp = tempdir().expect("tempdir");
        let source = temp.path().join("source.env");
        let destination = temp.path().join("destination.env");
        fs::write(&source, b"ADR_LOG_PATH=/old\n").expect("source");
        let mut install_boundaries = 0;

        let result = run_env_migration_with_hook(&source, &destination, || {
            install_boundaries += 1;
            if install_boundaries == 2 {
                fs::write(&source, b"ADR_LOG_PATH=/new\n").expect("same-length mutation");
            }
            Ok(())
        });
        assert_eq!(
            result
                .expect_err("manifest-boundary source mutation")
                .to_string(),
            "environment migration source changed before manifest install"
        );
        assert_eq!(install_boundaries, 2);
        assert_eq!(
            fs::read(&destination).expect("installed destination"),
            b"TELLTALE_LOG_PATH=/old\n"
        );
        assert!(!manifest_path(&destination).exists());
    }

    #[test]
    fn environment_assignment_budget_is_bounded() {
        let temp = tempdir().expect("tempdir");
        let source = temp.path().join("assignments.env");
        let destination = temp.path().join("destination.env");
        let mut input = String::new();
        for index in 0..=MAX_ENVIRONMENT_ASSIGNMENTS {
            input.push_str(&format!("KEY_{index}=value\n"));
        }
        fs::write(&source, input).expect("source");

        let error = run_env_migration_with_hook(&source, &destination, || Ok(()))
            .expect_err("assignment budget");
        assert_eq!(
            error.to_string(),
            "environment migration assignment count budget exceeded"
        );
        assert!(!destination.exists());
    }

    #[cfg(unix)]
    #[test]
    fn migration_refuses_symlink_and_hardlink_sources() {
        use std::fs::hard_link;
        use std::os::unix::fs::symlink;

        let temp = tempdir().expect("tempdir");
        let source = temp.path().join("legacy.json");
        let destination = temp.path().join("native.json");
        fs::write(
            &source,
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/state/legacy-scan-state.json"
            )),
        )
        .expect("source");

        let symlink_source = temp.path().join("symlink.json");
        symlink(&source, &symlink_source).expect("symlink");
        assert!(run_state_migration(&symlink_source, &destination).is_err());

        let hardlink_source = temp.path().join("hardlink.json");
        hard_link(&source, &hardlink_source).expect("hardlink");
        assert!(run_state_migration(&hardlink_source, &destination).is_err());

        let symlink_target = temp.path().join("symlink-target.json");
        fs::write(&symlink_target, b"target").expect("symlink target");
        let symlink_destination = temp.path().join("symlink-destination.json");
        symlink(&symlink_target, &symlink_destination).expect("destination symlink");
        assert!(run_state_migration(&source, &symlink_destination).is_err());

        let hardlink_target = temp.path().join("hardlink-target.json");
        fs::write(&hardlink_target, b"target").expect("hardlink target");
        let hardlink_destination = temp.path().join("hardlink-destination.json");
        hard_link(&hardlink_target, &hardlink_destination).expect("destination hardlink");
        assert!(run_state_migration(&source, &hardlink_destination).is_err());

        let directory_destination = temp.path().join("directory-destination");
        fs::create_dir(&directory_destination).expect("directory destination");
        assert!(run_state_migration(&source, &directory_destination).is_err());
    }
}
