use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::file_lock::{
    SidecarLock, TempFile, atomic_no_replace, manifest_path, open_pinned_read, read_snapshot,
    safe_path_info, validate_migration_paths, validate_target,
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
    pinned_source.verify_unchanged()?;
    match existing_manifest {
        Some(existing) if existing == manifest_bytes => {}
        Some(_) => return Err("migration manifest conflict: existing bytes differ".into()),
        None => {
            let temporary = TempFile::write_and_sync(&manifest_path, &manifest_bytes, 0o600)?;
            atomic_no_replace(temporary, &manifest_path)?;
        }
    }
    locks.iter().try_for_each(StateLock::verify_lock)?;
    pinned_source.verify_unchanged()?;
    print!("{}", String::from_utf8(manifest_bytes)?);
    Ok(())
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

    use serde_json::Value;
    use tempfile::tempdir;

    use super::{manifest_path, run_state_migration};
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
