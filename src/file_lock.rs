use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use fs4::fs_std::FileExt;
use sha2::{Digest, Sha256};
use uuid::Uuid;

const LOCK_BUSY: &str = "resource busy; retry later";
pub(crate) const FILE_STREAM_BUFFER_SIZE: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FileIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(windows)]
    value: u128,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FileTime {
    seconds: i64,
    nanos: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FileInfo {
    pub(crate) identity: FileIdentity,
    pub(crate) links: u64,
    pub(crate) length: u64,
    modified: FileTime,
    changed: FileTime,
}

type TargetBaseline = (Option<FileInfo>, Option<[u8; 32]>);

/// The private filename namespace reserved by one enabled JSONL rotator.
/// Rotation cleanup uses the same parent and stem/extension, so protected
/// persistence paths in that namespace must be rejected before scanning.
#[derive(Clone, Debug)]
pub(crate) struct RotationNamespace {
    parent: PathBuf,
    prefix: String,
    suffix: String,
}

impl RotationNamespace {
    pub(crate) fn from_active_path(active: &Path, stem: &str, extension: &str) -> Self {
        Self {
            parent: path_parent_or_current(active).to_path_buf(),
            prefix: format!("{stem}-"),
            suffix: format!(".{extension}"),
        }
    }

    fn matches(&self, candidate: &Path) -> Result<bool, Box<dyn std::error::Error>> {
        if !normalized_paths_equal(&self.parent, path_parent_or_current(candidate))? {
            return Ok(false);
        }
        let Some(name) = candidate.file_name() else {
            return Ok(false);
        };
        rotation_name_matches(name, &self.prefix, &self.suffix)
    }
}

pub(crate) struct SidecarLock {
    file: File,
    target: PathBuf,
    target_info: Option<FileInfo>,
    target_digest: Option<[u8; 32]>,
    lock_info: FileInfo,
    verification: TargetVerification,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TargetVerification {
    Strict,
    LockOnly,
}

impl SidecarLock {
    pub(crate) fn acquire(target: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        Self::acquire_with_verification(target, TargetVerification::Strict)
    }

    pub(crate) fn acquire_lock_only(target: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        Self::acquire_with_verification(target, TargetVerification::LockOnly)
    }

    fn acquire_with_verification(
        target: &Path,
        verification: TargetVerification,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let lock_path = sidecar_path(target);
        if let Some(parent) = lock_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = open_lock(&lock_path)?;
        match file.try_lock_exclusive() {
            Ok(true) => {
                set_file_mode(&file, 0o600)?;
                let lock_info = safe_file_info(&file, true)?;
                let (target_info, target_digest) = match verification {
                    TargetVerification::Strict => strict_target_baseline(target)?,
                    TargetVerification::LockOnly => (safe_path_info(target)?, None),
                };
                let lock = Self {
                    file,
                    target: target.to_path_buf(),
                    target_info,
                    target_digest,
                    lock_info,
                    verification,
                };
                lock.verify_lock()?;
                lock.verify_target_metadata()?;
                Ok(lock)
            }
            Ok(false) => Err(LOCK_BUSY.into()),
            Err(error) if is_busy(&error) => Err(LOCK_BUSY.into()),
            Err(error) => Err(error.into()),
        }
    }

    pub(crate) fn lock_order_key(target: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
        normalized_path(&sidecar_path(target))
    }

    pub(crate) fn verify(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.verify_lock()?;
        if self.verification != TargetVerification::Strict {
            return Err("strict target verification is unavailable for a lock-only lock".into());
        }
        let current_info = self.verify_target_metadata()?;
        let actual_digest = strict_target_digest(&self.target, current_info)?;
        verify_target_observation(
            self.target_info,
            current_info,
            self.target_digest,
            actual_digest,
        )
    }

    pub(crate) fn verify_lock(&self) -> Result<(), Box<dyn std::error::Error>> {
        if safe_path_info(&sidecar_path(&self.target))? != Some(self.lock_info) {
            return Err("persistence lock target changed during operation".into());
        }
        Ok(())
    }

    fn verify_target_metadata(&self) -> Result<Option<FileInfo>, Box<dyn std::error::Error>> {
        let current = safe_path_info(&self.target)?;
        if current != self.target_info {
            return Err("persistence target changed during operation".into());
        }
        Ok(current)
    }
}

fn sidecar_path(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(".lock");
    PathBuf::from(value)
}

impl Drop for SidecarLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

pub(crate) struct PinnedFile {
    file: File,
    path: PathBuf,
    info: FileInfo,
    digest: Option<[u8; 32]>,
}

impl PinnedFile {
    pub(crate) fn length(&self) -> u64 {
        self.info.length
    }

    pub(crate) fn read_range(
        &mut self,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let before = safe_file_info(&self.file, false)?;
        if before != self.info || safe_path_info(&self.path)? != Some(self.info) {
            return Err("source changed during bounded read; retry".into());
        }
        let end = offset
            .checked_add(u64::try_from(length).map_err(|_| "bounded read is too large")?)
            .ok_or("bounded read offset overflow")?;
        if end > before.length {
            return Err("bounded read exceeds source length".into());
        }
        self.file.seek(SeekFrom::Start(offset))?;
        let mut bytes = vec![0_u8; length];
        self.file.read_exact(&mut bytes)?;
        let after = safe_file_info(&self.file, false)?;
        validate_pinned_observation(
            self.info,
            before,
            after,
            safe_path_info(&self.path)?,
            "source changed during bounded read; retry",
        )?;
        Ok(bytes)
    }

    pub(crate) fn snapshot(&mut self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let before = safe_file_info(&self.file, false)?;
        if before != self.info {
            return Err("source changed during validation; retry".into());
        }
        self.file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        self.file.read_to_end(&mut bytes)?;
        let after = safe_file_info(&self.file, false)?;
        if after != before || after.length != bytes.len() as u64 {
            return Err("source changed during validation; retry".into());
        }
        if safe_path_info(&self.path)? != Some(before) {
            return Err("source path changed during validation; retry".into());
        }
        self.digest = Some(Sha256::digest(&bytes).into());
        Ok(bytes)
    }

    pub(crate) fn verify_unchanged(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let expected = self
            .digest
            .ok_or("source was not streamed before stability verification")?;
        let actual = self.stream_impl(|_| Ok(()), false)?;
        if actual != expected {
            return Err("source changed during migration; retry".into());
        }
        Ok(())
    }

    pub(crate) fn stream_to(
        &mut self,
        consumer: impl FnMut(&[u8]) -> Result<(), Box<dyn std::error::Error>>,
    ) -> Result<[u8; 32], Box<dyn std::error::Error>> {
        self.stream_impl(consumer, true)
    }

    fn stream_impl(
        &mut self,
        mut consumer: impl FnMut(&[u8]) -> Result<(), Box<dyn std::error::Error>>,
        remember_digest: bool,
    ) -> Result<[u8; 32], Box<dyn std::error::Error>> {
        let before = safe_file_info(&self.file, false)?;
        if before != self.info || safe_path_info(&self.path)? != Some(self.info) {
            return Err("source changed during migration; retry".into());
        }
        self.file.seek(SeekFrom::Start(0))?;
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; FILE_STREAM_BUFFER_SIZE];
        loop {
            let read = self.file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
            consumer(&buffer[..read])?;
        }
        let after = safe_file_info(&self.file, false)?;
        validate_pinned_observation(
            self.info,
            before,
            after,
            safe_path_info(&self.path)?,
            "source changed during migration; retry",
        )?;
        let digest: [u8; 32] = hasher.finalize().into();
        if remember_digest {
            self.digest = Some(digest);
        }
        Ok(digest)
    }
}

pub(crate) fn open_pinned_read(path: &Path) -> Result<PinnedFile, Box<dyn std::error::Error>> {
    let file = open_read(path)?;
    pinned_file(path, file)
}

fn pinned_file(path: &Path, file: File) -> Result<PinnedFile, Box<dyn std::error::Error>> {
    let info = safe_file_info(&file, true)?;
    Ok(PinnedFile {
        file,
        path: path.to_path_buf(),
        info,
        digest: None,
    })
}

#[cfg(windows)]
fn open_pinned_read_if_exists(
    path: &Path,
) -> Result<Option<PinnedFile>, Box<dyn std::error::Error>> {
    if !windows_preflight_regular_file(path)? {
        return Ok(None);
    }
    let mut options = OpenOptions::new();
    options.read(true);
    configure_no_follow(&mut options);
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err("persistence target disappeared during acquisition".into());
        }
        Err(error) => return Err(error.into()),
    };
    Ok(Some(pinned_file(path, file)?))
}

#[cfg(windows)]
fn windows_preflight_regular_file(path: &Path) -> Result<bool, Box<dyn std::error::Error>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    let file_type = metadata.file_type();
    if !file_type.is_file() || file_type.is_symlink() {
        return Err("unsafe persistence target: expected a regular file".into());
    }

    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_DEVICE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        GetFileAttributesW, INVALID_FILE_ATTRIBUTES,
    };

    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    wide.push(0);
    let attributes = unsafe { GetFileAttributesW(wide.as_ptr()) };
    if attributes == INVALID_FILE_ATTRIBUTES {
        return Err(io::Error::last_os_error().into());
    }
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err("unsafe persistence target: reparse points are refused".into());
    }
    if attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_DEVICE) != 0 {
        return Err("unsafe persistence target: expected a regular file".into());
    }
    Ok(true)
}

fn strict_target_baseline(path: &Path) -> Result<TargetBaseline, Box<dyn std::error::Error>> {
    #[cfg(windows)]
    {
        let Some(mut pinned) = open_pinned_read_if_exists(path)? else {
            return Ok((None, None));
        };
        let info = pinned.info;
        let digest = pinned.stream_to(|_| Ok(()))?;
        Ok((Some(info), Some(digest)))
    }
    #[cfg(not(windows))]
    {
        Ok((safe_path_info(path)?, None))
    }
}

fn strict_target_digest(
    path: &Path,
    target_info: Option<FileInfo>,
) -> Result<Option<[u8; 32]>, Box<dyn std::error::Error>> {
    #[cfg(windows)]
    {
        let Some(target_info) = target_info else {
            return Ok(None);
        };
        let mut pinned = open_pinned_read(path)?;
        if pinned.info != target_info {
            return Err("persistence target changed during operation".into());
        }
        return Ok(Some(pinned.stream_to(|_| Ok(()))?));
    }
    #[cfg(not(windows))]
    {
        let _ = (path, target_info);
        Ok(None)
    }
}

fn verify_target_observation(
    expected_info: Option<FileInfo>,
    current_info: Option<FileInfo>,
    expected_digest: Option<[u8; 32]>,
    current_digest: Option<[u8; 32]>,
) -> Result<(), Box<dyn std::error::Error>> {
    if current_info != expected_info {
        return Err("persistence target changed during operation".into());
    }
    if expected_digest.is_some() && current_digest != expected_digest {
        return Err("persistence target changed during operation".into());
    }
    Ok(())
}

fn validate_pinned_observation(
    expected_info: FileInfo,
    before: FileInfo,
    after: FileInfo,
    path_info: Option<FileInfo>,
    error: &'static str,
) -> Result<(), Box<dyn std::error::Error>> {
    if before != expected_info || after != before || path_info != Some(expected_info) {
        return Err(error.into());
    }
    Ok(())
}

pub(crate) fn read_snapshot(path: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut file = open_pinned_read(path)?;
    file.snapshot()
}

pub(crate) fn safe_path_info(path: &Path) -> Result<Option<FileInfo>, Box<dyn std::error::Error>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() {
                return Err("unsafe persistence target: expected a regular file".into());
            }
            let file = open_read(path)?;
            Ok(Some(safe_file_info(&file, true)?))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Return a stable, opaque identity for a regular file. The identity is based
/// on the filesystem file identity rather than its name, so a coordinated
/// rename preserves a JSONL generation while replacement or recreation does
/// not. The raw platform identity never leaves this module.
pub(crate) fn stable_file_identity(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let info = safe_path_info(path)?.ok_or("file identity target does not exist")?;
    file_identity_token(info)
}

fn file_identity_token(info: FileInfo) -> Result<String, Box<dyn std::error::Error>> {
    let mut hasher = Sha256::new();
    hasher.update(b"telltale-file-identity-v1\0");
    #[cfg(unix)]
    {
        hasher.update(info.identity.device.to_le_bytes());
        hasher.update(info.identity.inode.to_le_bytes());
    }
    #[cfg(windows)]
    {
        hasher.update(info.identity.value.to_le_bytes());
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = info;
        return Err("file identity is unsupported on this platform".into());
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Remove one previously discovered regular file only after reopening and
/// validating the exact path against its opaque stable identity. The caller
/// must hold the corresponding sidecar lock while this check and unlink run.
pub(crate) fn remove_verified_file(
    path: &Path,
    expected_identity: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let pinned = open_pinned_read(path)?;
    let expected_info = pinned.info;
    if file_identity_token(expected_info)? != expected_identity
        || safe_path_info(path)? != Some(expected_info)
    {
        return Err("persistence target changed during verified deletion".into());
    }

    #[cfg(windows)]
    {
        // Windows generally cannot unlink while this handle is open. Close it
        // and repeat the metadata check immediately before removal; the
        // sidecar lock held by the caller closes the remaining coordination
        // window, but cannot prevent an unrelated external actor from racing.
        drop(pinned);
        if safe_path_info(path)? != Some(expected_info) {
            return Err("persistence target changed before verified deletion".into());
        }
    }
    #[cfg(not(windows))]
    let _pinned = pinned;

    fs::remove_file(path)?;
    sync_parent(path)
}

pub(crate) fn validate_target(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(info) = safe_path_info(path)?
        && info.links > 1
    {
        return Err("unsafe persistence target: hardlinked files are refused".into());
    }
    Ok(())
}

pub(crate) fn validate_existing_mode(
    path: &Path,
    allowed_mode: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    if safe_path_info(path)?.is_none() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;

        let file = open_read(path)?;
        let metadata = file.metadata()?;
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err("existing migration target is not owned by the effective user".into());
        }
        let mode = metadata.permissions().mode() & 0o7777;
        if mode & !allowed_mode != 0 {
            return Err("existing migration target permissions are too broad".into());
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        let _ = (path, allowed_mode);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "existing migration target ownership is unsupported on Windows",
        )
        .into())
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, allowed_mode);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "existing migration target ownership is unsupported on this platform",
        )
        .into())
    }
}

pub(crate) fn validate_runtime_paths(
    state: &Path,
    local_logs: &[PathBuf],
    rotation_namespaces: &[RotationNamespace],
) -> Result<(), Box<dyn std::error::Error>> {
    let manifest = manifest_path(state);
    let mut paths = vec![
        state.to_path_buf(),
        sidecar_path(state),
        manifest.clone(),
        sidecar_path(&manifest),
    ];
    for log in local_logs {
        paths.push(log.clone());
        paths.push(sidecar_path(log));
    }
    validate_path_set(&paths, rotation_namespaces)
}

pub(crate) fn validate_migration_paths(
    source: &Path,
    destination: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let manifest = manifest_path(destination);
    validate_migration_targets(&[source.to_path_buf(), destination.to_path_buf(), manifest])
}

pub(crate) fn validate_migration_targets(
    targets: &[PathBuf],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut paths = targets.to_vec();
    paths.extend(targets.iter().map(|target| sidecar_path(target)));
    validate_path_set(&paths, &[])
}

fn validate_path_set(
    paths: &[PathBuf],
    rotation_namespaces: &[RotationNamespace],
) -> Result<(), Box<dyn std::error::Error>> {
    for path in paths {
        validate_target(path)?;
    }
    for (index, left) in paths.iter().enumerate() {
        for right in paths.iter().skip(index + 1) {
            let left_identity = existing_identity(left)?;
            let right_identity = existing_identity(right)?;
            if normalized_paths_equal(left, right)?
                || left_identity.is_some() && left_identity == right_identity
            {
                return Err("state, log, and sidecar paths must not overlap".into());
            }
        }
    }
    for namespace in rotation_namespaces {
        for path in paths {
            if namespace.matches(path)? {
                return Err(
                    "persistence path collides with an enabled JSONL rotation namespace".into(),
                );
            }
        }
    }
    Ok(())
}

pub(crate) fn manifest_path(destination: &Path) -> PathBuf {
    let mut value = destination.as_os_str().to_os_string();
    value.push(".migration.json");
    PathBuf::from(value)
}

pub(crate) fn sync_parent(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    sync_directory(parent)
}

pub(crate) struct TempFile {
    pub(crate) path: PathBuf,
    file: Option<File>,
}

impl TempFile {
    pub(crate) fn create(target: &Path, mode: u32) -> Result<Self, Box<dyn std::error::Error>> {
        let parent = target.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;
        let name = target
            .file_name()
            .unwrap_or_else(|| OsStr::new("state"))
            .to_os_string();
        for _ in 0..100 {
            let mut candidate = OsString::from(".");
            candidate.push(&name);
            candidate.push(".telltale-tmp-");
            candidate.push(Uuid::new_v4().simple().to_string());
            let path = parent.join(candidate);
            match open_temp(&path, mode) {
                Ok(file) => {
                    return Ok(Self {
                        path,
                        file: Some(file),
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err("could not allocate a unique temporary file".into())
    }

    pub(crate) fn write_and_sync(
        target: &Path,
        bytes: &[u8],
        mode: u32,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut temporary = Self::create(target, mode)?;
        temporary.write_all(bytes)?;
        temporary.sync()?;
        Ok(temporary)
    }

    pub(crate) fn write_all(&mut self, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        self.file
            .as_mut()
            .ok_or("temporary file is closed")?
            .write_all(bytes)?;
        Ok(())
    }

    pub(crate) fn sync(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let file = self.file.as_mut().ok_or("temporary file is closed")?;
        file.flush()?;
        file.sync_all()?;
        Ok(())
    }

    pub(crate) fn position(&mut self) -> Result<u64, Box<dyn std::error::Error>> {
        Ok(self
            .file
            .as_mut()
            .ok_or("temporary file is closed")?
            .stream_position()?)
    }

    pub(crate) fn open_reader(&self) -> Result<File, Box<dyn std::error::Error>> {
        open_read(&self.path)
    }

    fn close(&mut self) {
        let _ = self.file.take();
    }

    pub(crate) fn disarm(mut self) {
        self.close();
        self.path = PathBuf::new();
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        self.file.take();
        if !self.path.as_os_str().is_empty() {
            let _ = fs::remove_file(&self.path);
        }
    }
}

pub(crate) fn atomic_replace(
    mut temp: TempFile,
    destination: &Path,
    expected: Option<FileInfo>,
) -> Result<(), Box<dyn std::error::Error>> {
    validate_destination_identity(destination, expected)?;
    temp.close();
    atomic_replace_native(&temp.path, destination)?;
    sync_parent(destination)?;
    temp.disarm();
    Ok(())
}

pub(crate) fn atomic_no_replace(
    mut temp: TempFile,
    destination: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    if safe_path_info(destination)?.is_some() {
        return Err("destination already exists".into());
    }
    temp.close();
    atomic_no_replace_native(&temp.path, destination)?;
    sync_parent(destination)?;
    temp.disarm();
    Ok(())
}

pub(crate) fn atomic_rename_no_replace(
    source: &Path,
    destination: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    if safe_path_info(source)?.is_none() {
        return Err("rename source does not exist".into());
    }
    if safe_path_info(destination)?.is_some() {
        return Err("rename destination already exists".into());
    }
    atomic_no_replace_native(source, destination)?;
    sync_parent(destination)?;
    Ok(())
}

pub(crate) fn open_append(
    path: &Path,
) -> Result<(File, bool, FileInfo), Box<dyn std::error::Error>> {
    let expected = safe_path_info(path)?;
    let existed = expected.is_some();
    let mut options = OpenOptions::new();
    options.create(true).append(true).read(true).write(true);
    configure_no_follow(&mut options);
    configure_mode(&mut options, 0o640);
    let file = options.open(path)?;
    let info = safe_file_info(&file, true)?;
    if info.links > 1 {
        return Err("unsafe log target: hardlinked files are refused".into());
    }
    if existed && expected != Some(info) {
        return Err("log target changed during append preparation".into());
    }
    Ok((file, !existed, info))
}

fn open_lock(path: &Path) -> Result<File, Box<dyn std::error::Error>> {
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    configure_no_follow(&mut options);
    configure_mode(&mut options, 0o600);
    Ok(options.open(path)?)
}

fn open_read(path: &Path) -> Result<File, Box<dyn std::error::Error>> {
    let mut options = OpenOptions::new();
    options.read(true);
    configure_no_follow(&mut options);
    let file = options.open(path)?;
    let _ = safe_file_info(&file, true)?;
    Ok(file)
}

fn open_temp(path: &Path, mode: u32) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true).read(true);
    configure_no_follow(&mut options);
    configure_mode(&mut options, mode);
    options.open(path)
}

fn safe_file_info(file: &File, reject_links: bool) -> Result<FileInfo, Box<dyn std::error::Error>> {
    let info = platform_file_info(file)?;
    if reject_links && info.links > 1 {
        return Err("unsafe persistence target: hardlinked files are refused".into());
    }
    Ok(info)
}

fn existing_identity(path: &Path) -> Result<Option<FileIdentity>, Box<dyn std::error::Error>> {
    Ok(safe_path_info(path)?.map(|info| info.identity))
}

fn normalized_path(path: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let absolute = std::path::absolute(path)?;
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            _ => normalized.push(component.as_os_str()),
        }
    }
    let mut ancestor = normalized.clone();
    let mut suffix = Vec::new();
    loop {
        match fs::symlink_metadata(&ancestor) {
            Ok(_) => break,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let name = ancestor
                    .file_name()
                    .ok_or("could not resolve persistence path ancestor")?
                    .to_os_string();
                suffix.push(name);
                ancestor = ancestor
                    .parent()
                    .ok_or("could not resolve persistence path ancestor")?
                    .to_path_buf();
            }
            Err(error) => return Err(error.into()),
        }
    }
    let mut result = fs::canonicalize(ancestor)?;
    for component in suffix.iter().rev() {
        result.push(component);
    }
    Ok(result)
}

fn normalized_paths_equal(left: &Path, right: &Path) -> Result<bool, Box<dyn std::error::Error>> {
    let left = normalized_path(left)?;
    let right = normalized_path(right)?;
    if left == right {
        return Ok(true);
    }
    #[cfg(windows)]
    {
        // Windows compares missing path components case-insensitively. Use
        // the native ordinal comparison instead of lossy string conversion.
        windows_ordinal_equal(left.as_os_str(), right.as_os_str())
    }
    #[cfg(target_os = "macos")]
    {
        // The volume's case sensitivity cannot be queried portably. ASCII
        // case-only aliases are therefore treated as equal, while differing
        // non-ASCII spellings fail closed instead of guessing filesystem
        // normalization rules.
        macos_case_insensitive_path_equal(&left, &right)
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        // Other Unix filesystems are case-sensitive for this contract.
        Ok(false)
    }
}

/// Compare two paths for the identities that can be resolved without opening
/// either file for mutation. Lexical/symlink aliases are resolved through the
/// nearest existing ancestor; Unix device/inode identity additionally catches
/// hard links whose names remain different.
pub(crate) fn paths_identity_equivalent(
    left: &Path,
    right: &Path,
) -> Result<bool, Box<dyn std::error::Error>> {
    if normalized_paths_equal(left, right)? {
        return Ok(true);
    }

    #[cfg(unix)]
    {
        let left = path_device_inode(left)?;
        let right = path_device_inode(right)?;
        if let (Some(left), Some(right)) = (left, right) {
            return Ok(left == right);
        }
    }

    Ok(false)
}

#[cfg(unix)]
fn path_device_inode(path: &Path) -> Result<Option<(u64, u64)>, Box<dyn std::error::Error>> {
    use std::os::unix::fs::MetadataExt;

    match fs::metadata(path) {
        Ok(metadata) => Ok(Some((metadata.dev(), metadata.ino()))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

#[cfg(windows)]
fn windows_ordinal_equal(left: &OsStr, right: &OsStr) -> Result<bool, Box<dyn std::error::Error>> {
    let left = windows_wide(left)?;
    let right = windows_wide(right)?;
    windows_ordinal_equal_units(&left, &right)
}

#[cfg(windows)]
fn windows_wide(value: &OsStr) -> Result<Vec<u16>, Box<dyn std::error::Error>> {
    use std::os::windows::ffi::OsStrExt;

    let units: Vec<u16> = value.encode_wide().collect();
    let mut index = 0;
    while index < units.len() {
        match units[index] {
            0 => return Err("invalid Windows path name: embedded NUL".into()),
            0xD800..=0xDBFF => {
                if !matches!(
                    units.get(index + 1),
                    Some(unit) if (0xDC00..=0xDFFF).contains(unit)
                ) {
                    return Err("invalid Windows path name: unpaired UTF-16 surrogate".into());
                }
                index += 2;
            }
            0xDC00..=0xDFFF => {
                return Err("invalid Windows path name: unpaired UTF-16 surrogate".into());
            }
            _ => index += 1,
        }
    }
    Ok(units)
}

#[cfg(windows)]
fn windows_ordinal_equal_units(
    left: &[u16],
    right: &[u16],
) -> Result<bool, Box<dyn std::error::Error>> {
    if left.is_empty() || right.is_empty() {
        return Ok(left.is_empty() && right.is_empty());
    }
    let left_len = i32::try_from(left.len())?;
    let right_len = i32::try_from(right.len())?;
    let result = unsafe {
        windows_sys::Win32::Globalization::CompareStringOrdinal(
            left.as_ptr(),
            left_len,
            right.as_ptr(),
            right_len,
            1,
        )
    };
    match result {
        0 => Err(io::Error::last_os_error().into()),
        2 => Ok(true),
        _ => Ok(false),
    }
}

#[cfg(target_os = "macos")]
fn macos_case_insensitive_path_equal(
    left: &Path,
    right: &Path,
) -> Result<bool, Box<dyn std::error::Error>> {
    let left = left
        .components()
        .map(|component| component.as_os_str())
        .collect::<Vec<_>>();
    let right = right
        .components()
        .map(|component| component.as_os_str())
        .collect::<Vec<_>>();
    if left.len() != right.len() {
        return Ok(false);
    }
    for (left, right) in left.iter().zip(right.iter()) {
        if left == right {
            continue;
        }
        let left = left
            .to_str()
            .ok_or("ambiguous macOS path alias: invalid filename encoding")?;
        let right = right
            .to_str()
            .ok_or("ambiguous macOS path alias: invalid filename encoding")?;
        if !left.is_ascii() || !right.is_ascii() {
            return Err("ambiguous macOS path alias: non-ASCII spelling differs".into());
        }
        if !left.eq_ignore_ascii_case(right) {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(windows)]
fn rotation_name_matches(
    name: &OsStr,
    prefix: &str,
    suffix: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let name = windows_wide(name)?;
    let prefix = windows_wide(OsStr::new(prefix))?;
    let suffix = windows_wide(OsStr::new(suffix))?;
    let minimum = prefix
        .len()
        .checked_add(suffix.len())
        .ok_or("rotation name is too long")?;
    if name.len() <= minimum {
        return Ok(false);
    }
    Ok(windows_ordinal_equal_units(&name[..prefix.len()], &prefix)?
        && windows_ordinal_equal_units(&name[name.len() - suffix.len()..], &suffix)?)
}

#[cfg(target_os = "macos")]
fn rotation_name_matches(
    name: &OsStr,
    prefix: &str,
    suffix: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let name = name
        .to_str()
        .ok_or("ambiguous macOS rotation alias: invalid filename encoding")?;
    let minimum = prefix
        .len()
        .checked_add(suffix.len())
        .ok_or("rotation name is too long")?;
    if name.len() <= minimum {
        return Ok(false);
    }
    if name.starts_with(prefix) && name.ends_with(suffix) {
        return Ok(true);
    }
    if !prefix.is_ascii() || !suffix.is_ascii() {
        return Err("ambiguous macOS rotation alias: non-ASCII spelling differs".into());
    }
    let name_bytes = name.as_bytes();
    let name_prefix = name_bytes.get(..prefix.len()).unwrap_or_default();
    let name_suffix = name_bytes
        .get(name_bytes.len().saturating_sub(suffix.len())..)
        .unwrap_or_default();
    Ok(ascii_case_insensitive_equal(name_prefix, prefix.as_bytes())
        && ascii_case_insensitive_equal(name_suffix, suffix.as_bytes()))
}

#[cfg(not(any(windows, target_os = "macos")))]
fn rotation_name_matches(
    name: &OsStr,
    prefix: &str,
    suffix: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let Some(name) = name.to_str() else {
        return Ok(false);
    };
    Ok(name.starts_with(prefix)
        && name.ends_with(suffix)
        && name.len() > prefix.len() + suffix.len())
}

#[cfg(target_os = "macos")]
fn ascii_case_insensitive_equal(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
}

fn path_parent_or_current(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

fn validate_destination_identity(
    destination: &Path,
    expected: Option<FileInfo>,
) -> Result<(), Box<dyn std::error::Error>> {
    validate_target(destination)?;
    if safe_path_info(destination)? != expected {
        return Err("persistence destination changed during commit".into());
    }
    Ok(())
}

fn is_busy(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::AlreadyExists
    )
}

#[cfg(unix)]
fn platform_file_info(file: &File) -> Result<FileInfo, Box<dyn std::error::Error>> {
    use std::os::unix::fs::MetadataExt;

    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err("unsafe persistence target: expected a regular file".into());
    }
    Ok(FileInfo {
        identity: FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        },
        links: metadata.nlink(),
        length: metadata.len(),
        modified: FileTime {
            seconds: metadata.mtime(),
            nanos: metadata.mtime_nsec() as u32,
        },
        changed: FileTime {
            seconds: metadata.ctime(),
            nanos: metadata.ctime_nsec() as u32,
        },
    })
}

#[cfg(windows)]
fn platform_file_info(file: &File) -> Result<FileInfo, Box<dyn std::error::Error>> {
    use std::mem::zeroed;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DEVICE, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_REPARSE_POINT, GetFileInformationByHandle,
    };

    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(io::Error::last_os_error().into());
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err("unsafe persistence target: reparse points are refused".into());
    }
    if info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_DEVICE) != 0 {
        return Err("unsafe persistence target: expected a regular file".into());
    }
    Ok(FileInfo {
        identity: FileIdentity {
            value: ((info.dwVolumeSerialNumber as u128) << 64)
                | ((info.nFileIndexHigh as u128) << 32)
                | info.nFileIndexLow as u128,
        },
        links: info.nNumberOfLinks as u64,
        length: ((info.nFileSizeHigh as u64) << 32) | info.nFileSizeLow as u64,
        modified: windows_file_time(info.ftLastWriteTime),
        changed: windows_file_time(info.ftLastWriteTime),
    })
}

#[cfg(windows)]
fn windows_file_time(time: windows_sys::Win32::Foundation::FILETIME) -> FileTime {
    let value = ((time.dwHighDateTime as u64) << 32) | time.dwLowDateTime as u64;
    FileTime {
        seconds: (value / 10_000_000) as i64,
        nanos: ((value % 10_000_000) * 100) as u32,
    }
}

#[cfg(not(any(unix, windows)))]
fn platform_file_info(_file: &File) -> Result<FileInfo, Box<dyn std::error::Error>> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "file identity is unsupported").into())
}

#[cfg(unix)]
fn configure_no_follow(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;

    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
}

#[cfg(windows)]
fn configure_no_follow(options: &mut OpenOptions) {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;

    options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
}

#[cfg(not(any(unix, windows)))]
fn configure_no_follow(_options: &mut OpenOptions) {}

#[cfg(unix)]
fn configure_mode(options: &mut OpenOptions, mode: u32) {
    use std::os::unix::fs::OpenOptionsExt;

    options.mode(mode);
}

#[cfg(unix)]
fn set_file_mode(file: &File, mode: u32) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = file.metadata()?.permissions();
    permissions.set_mode(mode);
    file.set_permissions(permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_file_mode(_file: &File, _mode: u32) -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

#[cfg(not(unix))]
fn configure_mode(_options: &mut OpenOptions, _mode: u32) {}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(windows)]
fn sync_directory(_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    // Windows has no supported directory-handle flush equivalent here. File
    // contents are flushed through writable handles and renames use
    // MOVEFILE_WRITE_THROUGH; parent-directory durability is not asserted.
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn sync_directory(_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "directory sync is unsupported").into())
}

#[cfg(unix)]
fn atomic_replace_native(
    temp: &Path,
    destination: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = c_path(temp)?;
    let destination = c_path(destination)?;
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::rename(temp.as_ptr(), destination.as_ptr()) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        if unsafe { libc::rename(temp.as_ptr(), destination.as_ptr()) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(())
    }
}

#[cfg(unix)]
fn atomic_no_replace_native(
    temp: &Path,
    destination: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = c_path(temp)?;
    let destination = c_path(destination)?;
    #[cfg(target_os = "linux")]
    {
        let result = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                libc::AT_FDCWD,
                temp.as_ptr(),
                libc::AT_FDCWD,
                destination.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        if unsafe {
            libc::renameatx_np(
                libc::AT_FDCWD,
                temp.as_ptr(),
                libc::AT_FDCWD,
                destination.as_ptr(),
                libc::RENAME_EXCL,
            )
        } != 0
        {
            return Err(io::Error::last_os_error().into());
        }
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (temp, destination);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "atomic no-replace is unsupported",
        )
        .into())
    }
}

#[cfg(windows)]
fn atomic_replace_native(
    temp: &Path,
    destination: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    move_file_native(temp, destination, true)
}

#[cfg(windows)]
fn atomic_no_replace_native(
    temp: &Path,
    destination: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    move_file_native(temp, destination, false)
}

#[cfg(windows)]
fn move_file_native(
    temp: &Path,
    destination: &Path,
    replace: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    let mut old: Vec<u16> = temp.as_os_str().encode_wide().collect();
    let mut new: Vec<u16> = destination.as_os_str().encode_wide().collect();
    old.push(0);
    new.push(0);
    let flags = MOVEFILE_WRITE_THROUGH
        | if replace {
            MOVEFILE_REPLACE_EXISTING
        } else {
            0
        };
    if unsafe { MoveFileExW(old.as_ptr(), new.as_ptr(), flags) } == 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(unix)]
fn c_path(path: &Path) -> Result<std::ffi::CString, Box<dyn std::error::Error>> {
    use std::os::unix::ffi::OsStrExt;

    Ok(std::ffi::CString::new(path.as_os_str().as_bytes())?)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    #[cfg(windows)]
    use super::{sync_directory, windows_file_time};

    use super::{
        RotationNamespace, SidecarLock, TempFile, atomic_no_replace, atomic_rename_no_replace,
        safe_path_info, sidecar_path, stable_file_identity, validate_pinned_observation,
        validate_runtime_paths, verify_target_observation,
    };

    #[test]
    fn sidecar_lock_is_permanent_and_fail_fast() {
        let temp = tempdir().expect("tempdir");
        let target = temp.path().join("state.json");
        let first = SidecarLock::acquire(&target).expect("first lock");
        assert!(target.with_file_name("state.json.lock").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            assert_eq!(
                fs::metadata(target.with_file_name("state.json.lock"))
                    .expect("sidecar metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        let error = match SidecarLock::acquire(&target) {
            Ok(_) => panic!("second lock must be busy"),
            Err(error) => error,
        };
        assert_eq!(error.to_string(), "resource busy; retry later");
        drop(first);
        let _second = SidecarLock::acquire(&target).expect("released lock");
    }

    #[test]
    fn stable_identity_survives_atomic_rotation_rename_and_restart_lookup() {
        let temp = tempdir().expect("tempdir");
        let source = temp.path().join("events.jsonl");
        let rotated = temp.path().join("events-2026-06-21.jsonl");
        fs::write(&source, b"one\n").expect("source");
        let identity = stable_file_identity(&source).expect("source identity");
        let lock = SidecarLock::acquire_lock_only(&source).expect("rotation lock");

        atomic_rename_no_replace(&source, &rotated).expect("atomic rotation rename");
        lock.verify_lock().expect("sidecar remains stable");
        drop(lock);

        assert!(!source.exists());
        assert_eq!(
            stable_file_identity(&rotated).expect("rotated identity after restart"),
            identity
        );
    }

    #[test]
    fn no_replace_is_atomic_and_temp_is_cleaned() {
        let temp = tempdir().expect("tempdir");
        let destination = temp.path().join("state.json");
        let temporary = TempFile::write_and_sync(&destination, b"one", 0o600).expect("temp");
        atomic_no_replace(temporary, &destination).expect("install");
        assert_eq!(fs::read(&destination).expect("destination"), b"one");
        let temporary = TempFile::write_and_sync(&destination, b"two", 0o600).expect("temp");
        assert!(atomic_no_replace(temporary, &destination).is_err());
        assert_eq!(fs::read(&destination).expect("destination"), b"one");
        assert!(safe_path_info(&destination).expect("info").is_some());
        assert!(
            !fs::read_dir(temp.path())
                .expect("temporary directory")
                .filter_map(Result::ok)
                .any(|entry| entry
                    .file_name()
                    .to_string_lossy()
                    .contains(".telltale-tmp-"))
        );
    }

    #[test]
    fn lock_verification_detects_same_length_target_changes() {
        let temp = tempdir().expect("tempdir");
        let target = temp.path().join("state.json");
        fs::write(&target, b"one").expect("target");
        let lock = SidecarLock::acquire(&target).expect("lock");
        fs::write(&target, b"two").expect("same-length mutation");
        assert!(lock.verify().is_err());
    }

    #[test]
    fn unchanged_strict_target_verifies_successfully() {
        let temp = tempdir().expect("tempdir");
        let target = temp.path().join("state.json");
        fs::write(&target, b"one").expect("target");
        let lock = SidecarLock::acquire(&target).expect("lock");
        lock.verify().expect("unchanged target");
    }

    #[test]
    fn strict_verification_detects_different_length_target_changes() {
        let temp = tempdir().expect("tempdir");
        let target = temp.path().join("state.json");
        fs::write(&target, b"one").expect("target");
        let lock = SidecarLock::acquire(&target).expect("lock");
        fs::write(&target, b"ones").expect("different-length mutation");
        assert!(lock.verify().is_err());
    }

    #[test]
    fn strict_verification_detects_replacement_identity_change() {
        let temp = tempdir().expect("tempdir");
        let target = temp.path().join("state.json");
        let replacement = temp.path().join("replacement.json");
        fs::write(&target, b"one").expect("target");
        fs::write(&replacement, b"one").expect("replacement");
        let lock = SidecarLock::acquire(&target).expect("lock");
        fs::remove_file(&target).expect("remove target");
        fs::rename(&replacement, &target).expect("replace target");
        assert!(lock.verify().is_err());
    }

    #[test]
    fn strict_verification_detects_deletion_and_recreation() {
        let temp = tempdir().expect("tempdir");
        let target = temp.path().join("state.json");
        fs::write(&target, b"one").expect("target");
        let lock = SidecarLock::acquire(&target).expect("lock");
        fs::remove_file(&target).expect("delete target");
        fs::write(&target, b"one").expect("recreate target");
        assert!(lock.verify().is_err());
    }

    #[test]
    fn strict_verification_rejects_absent_to_created_transition() {
        let temp = tempdir().expect("tempdir");
        let target = temp.path().join("state.json");
        let lock = SidecarLock::acquire(&target).expect("lock");
        fs::write(&target, b"created").expect("created target");
        assert!(lock.verify().is_err());
    }

    #[test]
    fn sidecar_replacement_is_detected_by_verify_lock() {
        let temp = tempdir().expect("tempdir");
        let target = temp.path().join("state.json");
        let replacement = temp.path().join("replacement.lock");
        let sidecar = sidecar_path(&target);
        let lock = SidecarLock::acquire(&target).expect("lock");
        fs::write(&replacement, b"replacement").expect("replacement sidecar");
        fs::remove_file(&sidecar).expect("remove sidecar");
        fs::rename(&replacement, &sidecar).expect("replace sidecar");
        assert!(lock.verify_lock().is_err());
    }

    #[test]
    fn lock_only_allows_protected_target_mutation() {
        let temp = tempdir().expect("tempdir");
        let target = temp.path().join("events.jsonl");
        fs::write(&target, b"one\n").expect("target");
        let lock = SidecarLock::acquire_lock_only(&target).expect("lock");
        fs::write(&target, b"two\n").expect("mutable target");
        lock.verify_lock().expect("sidecar unchanged");
        assert!(lock.verify().is_err());
    }

    #[test]
    fn equal_metadata_with_different_digest_fails_closed() {
        let temp = tempdir().expect("tempdir");
        let target = temp.path().join("state.json");
        fs::write(&target, b"one").expect("target");
        let info = safe_path_info(&target)
            .expect("target info")
            .expect("existing target");
        assert!(
            verify_target_observation(Some(info), Some(info), Some([0; 32]), Some([1; 32]),)
                .is_err()
        );
        verify_target_observation(Some(info), Some(info), Some([0; 32]), Some([0; 32]))
            .expect("equal metadata and digest");
    }

    #[cfg(windows)]
    #[test]
    fn windows_strict_verification_rejects_same_length_mutation_with_restored_timestamp() {
        let temp = tempdir().expect("tempdir");
        let target = temp.path().join("state.json");
        fs::write(&target, b"one").expect("target");
        let lock = SidecarLock::acquire(&target).expect("lock");
        let captured_time = lock.target_info.expect("target info").modified;

        fs::write(&target, b"two").expect("same-length mutation");
        restore_windows_last_write_time(&target, captured_time);

        assert_eq!(
            safe_path_info(&target).expect("target info"),
            lock.target_info
        );
        assert!(lock.verify().is_err());
    }

    #[test]
    fn pinned_read_rejects_acquisition_instability() {
        let temp = tempdir().expect("tempdir");
        let target = temp.path().join("state.json");
        fs::write(&target, b"one").expect("target");
        let info = safe_path_info(&target)
            .expect("target info")
            .expect("existing target");
        let mut after = info;
        after.length += 1;
        assert!(
            validate_pinned_observation(info, info, after, Some(info), "unstable pinned read",)
                .is_err()
        );
    }

    #[test]
    fn pinned_read_rejects_verification_instability() {
        let temp = tempdir().expect("tempdir");
        let target = temp.path().join("state.json");
        fs::write(&target, b"one").expect("target");
        let info = safe_path_info(&target)
            .expect("target info")
            .expect("existing target");
        assert!(
            validate_pinned_observation(info, info, info, None, "unstable pinned read",).is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn namespace_validation_resolves_symlinked_missing_ancestors() {
        use std::os::unix::fs::symlink;

        let temp = tempdir().expect("tempdir");
        let real = temp.path().join("real");
        fs::create_dir(&real).expect("real directory");
        let alias = temp.path().join("alias");
        symlink(&real, &alias).expect("alias");
        let state = alias.join("nested/state.json");
        let log = real.join("nested/state.json");
        assert!(validate_runtime_paths(&state, std::slice::from_ref(&log), &[]).is_err());
    }

    #[test]
    fn rotation_namespace_rejects_each_protected_category_without_path_overlap() {
        let temp = tempdir().expect("tempdir");
        let cases = vec![
            (
                "state path",
                validate_runtime_paths(
                    &temp.path().join("events-2026-06-21.jsonl"),
                    &[temp.path().join("events.jsonl")],
                    &[RotationNamespace::from_active_path(
                        &temp.path().join("events.jsonl"),
                        "events",
                        "jsonl",
                    )],
                ),
            ),
            (
                "migration companion",
                validate_runtime_paths(
                    &temp.path().join("events-2026"),
                    &[temp.path().join("events.json")],
                    &[RotationNamespace::from_active_path(
                        &temp.path().join("events.json"),
                        "events",
                        "json",
                    )],
                ),
            ),
            (
                "state sidecar",
                validate_runtime_paths(
                    &temp.path().join("events-x.2026"),
                    &[temp.path().join("events.lock")],
                    &[RotationNamespace::from_active_path(
                        &temp.path().join("events.lock"),
                        "events",
                        "2026.lock",
                    )],
                ),
            ),
            (
                "manifest sidecar",
                validate_runtime_paths(
                    &temp.path().join("events-2026"),
                    &[temp.path().join("events.json")],
                    &[RotationNamespace::from_active_path(
                        &temp.path().join("events.json"),
                        "events",
                        "json.lock",
                    )],
                ),
            ),
            (
                "another active local JSONL sink",
                validate_runtime_paths(
                    &temp.path().join("state.json"),
                    &[
                        temp.path().join("events.jsonl"),
                        temp.path().join("events-2026-06-21.jsonl"),
                    ],
                    &[RotationNamespace::from_active_path(
                        &temp.path().join("events.jsonl"),
                        "events",
                        "jsonl",
                    )],
                ),
            ),
            (
                "overlapping local sinks",
                validate_runtime_paths(
                    &temp.path().join("state.json"),
                    &[
                        temp.path().join("events.jsonl"),
                        temp.path().join("events-2026.jsonl"),
                    ],
                    &[
                        RotationNamespace::from_active_path(
                            &temp.path().join("events.jsonl"),
                            "events",
                            "jsonl",
                        ),
                        RotationNamespace::from_active_path(
                            &temp.path().join("events-2026.jsonl"),
                            "events-2026",
                            "jsonl",
                        ),
                    ],
                ),
            ),
        ];
        let failures = cases
            .into_iter()
            .filter_map(|(name, result)| match result {
                Err(error) if error.to_string().contains("rotation namespace") => None,
                Ok(()) => Some(format!("{name}: collision was accepted")),
                Err(error) => Some(format!("{name}: unexpected error: {error}")),
            })
            .collect::<Vec<_>>();
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[cfg(any(windows, target_os = "macos"))]
    #[test]
    fn case_only_aliases_are_rejected_for_state_manifest_sidecar_and_rotation() {
        let temp = tempdir().expect("tempdir");
        let cases = vec![
            (
                "state path",
                validate_runtime_paths(
                    &temp.path().join("State.json"),
                    &[temp.path().join("state.JSON")],
                    &[],
                ),
            ),
            (
                "migration manifest",
                super::validate_migration_paths(
                    &temp.path().join("native.migration.JSON"),
                    &temp.path().join("native"),
                ),
            ),
            (
                "sidecar",
                validate_runtime_paths(
                    &temp.path().join("sidecar-state.json"),
                    &[temp.path().join("SIDECAR-STATE.JSON.LOCK")],
                    &[],
                ),
            ),
            (
                "rotation path",
                validate_runtime_paths(
                    &temp.path().join("ROTATION-2026-06-21.JSONL"),
                    &[],
                    &[RotationNamespace::from_active_path(
                        &temp.path().join("rotation.jsonl"),
                        "rotation",
                        "jsonl",
                    )],
                ),
            ),
        ];
        let failures = cases
            .into_iter()
            .filter_map(|(name, result)| match result {
                Err(_) => None,
                Ok(()) => Some(format!("{name}: case-only alias was accepted")),
            })
            .collect::<Vec<_>>();
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_filesystem_bindings_compile() {
        use std::path::Path;
        use windows_sys::Win32::Foundation::FILETIME;

        let time = windows_file_time(FILETIME {
            dwHighDateTime: 0,
            dwLowDateTime: 0,
        });
        assert_eq!(time.seconds, 0);
        assert_eq!(time.nanos, 0);
        sync_directory(Path::new("."))
            .expect("Windows parent durability is intentionally not asserted");
    }

    #[cfg(windows)]
    fn restore_windows_last_write_time(path: &std::path::Path, time: super::FileTime) {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::FILETIME;
        use windows_sys::Win32::Storage::FileSystem::SetFileTime;

        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .expect("open target for timestamp restoration");
        let value = time.seconds as u64 * 10_000_000 + u64::from(time.nanos) / 100;
        let write_time = FILETIME {
            dwHighDateTime: (value >> 32) as u32,
            dwLowDateTime: value as u32,
        };
        assert_ne!(
            unsafe {
                SetFileTime(
                    file.as_raw_handle(),
                    std::ptr::null(),
                    std::ptr::null(),
                    &write_time,
                )
            },
            0
        );
    }
}
