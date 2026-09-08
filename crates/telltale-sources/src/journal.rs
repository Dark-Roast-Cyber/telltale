//! Read-only primitives for the canonical local Event 3.0 JSONL journal.
//!
//! This module deliberately contains no writer, lock, cursor, or delivery
//! behavior. It owns the narrow filename, identity, and safe-open contract
//! shared by the CLI's generation discovery and lower-level consumers.

use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

const IDENTITY_DOMAIN: &[u8] = b"telltale-file-identity-v1\0";

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct JournalGeneration {
    pub path: PathBuf,
    pub identity: String,
    pub is_active: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct JournalDiscovery {
    pub generations: Vec<JournalGeneration>,
    pub directory_bound_reached: bool,
}

#[derive(Debug)]
pub struct JournalFile {
    file: File,
    identity: String,
    length: u64,
}

impl JournalFile {
    pub fn open(path: &Path) -> io::Result<Self> {
        let expected = path_metadata(path)?;
        let mut options = OpenOptions::new();
        options.read(true);
        configure_no_follow(&mut options);
        let file = options.open(path)?;
        let actual = file_metadata(&file)?;
        validate_regular(&actual)?;
        if expected.identity != actual.identity {
            return Err(other("journal file changed while opening"));
        }
        Ok(Self {
            file,
            identity: identity_token(actual.identity)?,
            length: actual.length,
        })
    }

    pub fn identity(&self) -> &str {
        &self.identity
    }

    pub fn len(&self) -> u64 {
        self.length
    }

    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Read at most `length` bytes from one stable point in the open file.
    /// Appends after the initial metadata check are left for the next poll.
    pub fn read_at(&mut self, offset: u64, length: usize) -> io::Result<Vec<u8>> {
        let before = file_metadata(&self.file)?;
        validate_regular(&before)?;
        if identity_token(before.identity)? != self.identity {
            return Err(other("journal identity changed during read"));
        }
        if offset > before.length {
            return Err(other("journal offset exceeds file length"));
        }
        let available = before.length.saturating_sub(offset);
        let amount = available.min(length as u64) as usize;
        self.file.seek(SeekFrom::Start(offset))?;
        let mut bytes = vec![0_u8; amount];
        self.file.read_exact(&mut bytes)?;
        let after = file_metadata(&self.file)?;
        validate_regular(&after)?;
        if identity_token(after.identity)? != self.identity {
            return Err(other("journal identity changed during read"));
        }
        self.length = after.length;
        Ok(bytes)
    }

    pub fn refresh_len(&mut self) -> io::Result<u64> {
        let info = file_metadata(&self.file)?;
        validate_regular(&info)?;
        if identity_token(info.identity)? != self.identity {
            return Err(other("journal identity changed"));
        }
        self.length = info.length;
        Ok(self.length)
    }
}

pub fn stable_file_identity(path: &Path) -> io::Result<String> {
    Ok(JournalFile::open(path)?.identity().to_owned())
}

/// Discover the active file and exact built-in rotated generations in physical
/// oldest-to-newest order. `max_entries` bounds directory work and is reported
/// rather than silently presented as complete history.
pub fn discover_generations(path: &Path, max_entries: usize) -> io::Result<JournalDiscovery> {
    if max_entries == 0 {
        return Err(other("journal discovery bound must be positive"));
    }
    let mut active = None;
    match path_metadata(path) {
        Ok(info) => {
            validate_regular(&info)?;
            active = Some(JournalGeneration {
                path: path.to_path_buf(),
                identity: identity_token(info.identity)?,
                is_active: true,
            });
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let (stem, extension) = match rotation_components(path) {
        Ok(components) => components,
        Err(_) => {
            return Ok(JournalDiscovery {
                generations: active.into_iter().collect(),
                directory_bound_reached: false,
            });
        }
    };

    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let entries = match fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound && active.is_none() => {
            return Ok(JournalDiscovery {
                generations: Vec::new(),
                directory_bound_reached: false,
            });
        }
        Err(error) => return Err(error),
    };

    let mut rotated = Vec::new();
    let mut bound = false;
    for (examined, entry) in entries.enumerate() {
        if examined >= max_entries {
            bound = true;
            break;
        }
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some((date, counter)) = parse_rotated_name(name, &stem, &extension) else {
            continue;
        };
        let file_type = entry.file_type()?;
        if !file_type.is_file() || file_type.is_symlink() {
            return Err(other("unsafe journal generation"));
        }
        rotated.push(RotatedEntry {
            date: date.to_owned(),
            counter,
            path: entry.path(),
        });
    }
    rotated.sort();

    let mut generations = Vec::with_capacity(rotated.len() + usize::from(active.is_some()));
    for entry in rotated {
        let info = path_metadata(&entry.path)?;
        validate_regular(&info)?;
        generations.push(JournalGeneration {
            path: entry.path,
            identity: identity_token(info.identity)?,
            is_active: false,
        });
    }
    if let Some(active) = active {
        generations.push(active);
    }

    let mut identities = std::collections::BTreeSet::new();
    for generation in &generations {
        if !identities.insert(generation.identity.clone()) {
            return Err(other("ambiguous journal generation identity"));
        }
    }
    Ok(JournalDiscovery {
        generations,
        directory_bound_reached: bound,
    })
}

pub fn rotation_components(active: &Path) -> io::Result<(String, String)> {
    let stem = active
        .file_stem()
        .and_then(OsStr::to_str)
        .ok_or_else(|| other("built-in rotation requires a UTF-8 filename"))?;
    let extension = active
        .extension()
        .and_then(OsStr::to_str)
        .ok_or_else(|| other("built-in rotation requires a UTF-8 filename"))?;
    Ok((stem.to_owned(), extension.to_owned()))
}

pub fn parse_rotated_name(name: &str, stem: &str, extension: &str) -> Option<(String, usize)> {
    let suffix = format!(".{extension}");
    let prefix = format!("{stem}-");
    let value = name.strip_prefix(&prefix)?.strip_suffix(&suffix)?;
    if let Some((date, counter)) = value.rsplit_once('.') {
        if valid_date(date) {
            return Some((date.to_owned(), counter.parse().ok()?));
        }
        return None;
    }
    valid_date(value).then(|| (value.to_owned(), 0))
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
struct RotatedEntry {
    date: String,
    counter: usize,
    path: PathBuf,
}

fn valid_date(value: &str) -> bool {
    if value.len() != 10
        || value.as_bytes().get(4) != Some(&b'-')
        || value.as_bytes().get(7) != Some(&b'-')
    {
        return false;
    }
    if !value
        .chars()
        .enumerate()
        .all(|(index, character)| index == 4 || index == 7 || character.is_ascii_digit())
    {
        return false;
    }
    let month = value[5..7].parse::<u32>().unwrap_or(0);
    let day = value[8..10].parse::<u32>().unwrap_or(0);
    (1..=12).contains(&month) && (1..=31).contains(&day)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PhysicalIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(windows)]
    value: u128,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileMetadata {
    identity: PhysicalIdentity,
    links: u64,
    length: u64,
}

fn identity_token(identity: PhysicalIdentity) -> io::Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(IDENTITY_DOMAIN);
    #[cfg(unix)]
    {
        hasher.update(identity.device.to_le_bytes());
        hasher.update(identity.inode.to_le_bytes());
    }
    #[cfg(windows)]
    hasher.update(identity.value.to_le_bytes());
    #[cfg(not(any(unix, windows)))]
    {
        let _ = identity;
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "file identity is unsupported",
        ));
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn path_metadata(path: &Path) -> io::Result<FileMetadata> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(other("unsafe journal file"));
    }
    let file = JournalFile::open_metadata(path)?;
    file_metadata(&file)
}

impl JournalFile {
    fn open_metadata(path: &Path) -> io::Result<File> {
        let mut options = OpenOptions::new();
        options.read(true);
        configure_no_follow(&mut options);
        options.open(path)
    }
}

fn file_metadata(file: &File) -> io::Result<FileMetadata> {
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(other("unsafe journal file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        return Ok(FileMetadata {
            identity: PhysicalIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            },
            links: metadata.nlink(),
            length: metadata.len(),
        });
    }
    #[cfg(windows)]
    {
        use std::mem::zeroed;
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DEVICE, FILE_ATTRIBUTE_DIRECTORY,
            FILE_ATTRIBUTE_REPARSE_POINT, GetFileInformationByHandle,
        };
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if info.dwFileAttributes
            & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_DEVICE)
            != 0
        {
            return Err(other("unsafe journal file"));
        }
        return Ok(FileMetadata {
            identity: PhysicalIdentity {
                value: ((info.dwVolumeSerialNumber as u128) << 64)
                    | ((info.nFileIndexHigh as u128) << 32)
                    | info.nFileIndexLow as u128,
            },
            links: info.nNumberOfLinks as u64,
            length: ((info.nFileSizeHigh as u64) << 32) | info.nFileSizeLow as u64,
        });
    }
    #[allow(unreachable_code)]
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "file identity is unsupported",
    ))
}

fn validate_regular(info: &FileMetadata) -> io::Result<()> {
    if info.links > 1 {
        return Err(other("unsafe journal hard link"));
    }
    Ok(())
}

fn other(message: &'static str) -> io::Error {
    io::Error::other(message)
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

#[cfg(test)]
mod tests {
    use super::{JournalFile, discover_generations, parse_rotated_name};
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn exact_rotation_names_are_orderable_and_external_names_are_ignored() {
        assert_eq!(
            parse_rotated_name("events-2026-01-02.3.jsonl", "events", "jsonl"),
            Some(("2026-01-02".to_string(), 3))
        );
        assert!(parse_rotated_name("events-20260102.jsonl", "events", "jsonl").is_none());
    }

    #[test]
    fn discovery_and_open_are_read_only_and_identity_survives_rename() {
        let directory = tempdir().expect("tempdir");
        let active = directory.path().join("events.jsonl");
        fs::write(&active, b"one\n").expect("active");
        let mut file = JournalFile::open(&active).expect("open");
        let identity = file.identity().to_owned();
        assert_eq!(file.read_at(0, 4).expect("read"), b"one\n");
        let rotated = directory.path().join("events-2026-01-02.jsonl");
        fs::rename(&active, &rotated).expect("rename");
        assert_eq!(file.read_at(0, 4).expect("renamed handle"), b"one\n");
        assert_eq!(file.identity(), identity);
        let discovery =
            discover_generations(&directory.path().join("events.jsonl"), 8).expect("discover");
        assert_eq!(discovery.generations.len(), 1);
        assert!(!discovery.generations[0].is_active);
    }

    #[test]
    fn bounded_directory_discovery_reports_when_the_entry_cap_is_reached() {
        let directory = tempdir().expect("tempdir");
        let active = directory.path().join("events.jsonl");
        fs::write(&active, b"active\n").expect("active");
        for index in 0..4 {
            fs::write(
                directory.path().join(format!("unrelated-{index}")),
                b"fixture",
            )
            .expect("unrelated entry");
        }

        let discovery = discover_generations(&active, 2).expect("bounded discovery");

        assert!(discovery.directory_bound_reached);
    }

    #[test]
    fn extensionless_active_file_is_discovered_without_rotations() {
        let directory = tempdir().expect("tempdir");
        let active = directory.path().join("events");
        fs::write(&active, b"active\n").expect("active");

        let discovery = discover_generations(&active, 8).expect("discover");

        assert_eq!(discovery.generations.len(), 1);
        assert_eq!(discovery.generations[0].path, active);
        assert!(discovery.generations[0].is_active);
        assert!(!discovery.directory_bound_reached);
    }

    #[test]
    fn discover_open_and_read_at_do_not_create_files() {
        let directory = tempdir().expect("tempdir");
        let missing = directory.path().join("missing/events.jsonl");
        let before_missing = fs::read_dir(directory.path())
            .expect("fixture directory")
            .count();
        let discovery = discover_generations(&missing, 8).expect("missing discovery");
        assert!(discovery.generations.is_empty());
        assert!(JournalFile::open(&missing).is_err());
        assert_eq!(
            fs::read_dir(directory.path())
                .expect("fixture directory")
                .count(),
            before_missing
        );
        assert!(!missing.exists());
        assert!(!missing.parent().expect("missing parent").exists());

        let active = directory.path().join("events.jsonl");
        fs::write(&active, b"one\n").expect("active fixture");
        let mut before_read = fs::read_dir(directory.path())
            .expect("fixture directory")
            .map(|entry| entry.expect("entry").file_name())
            .collect::<Vec<_>>();
        before_read.sort();
        let mut file = JournalFile::open(&active).expect("open active");
        assert_eq!(file.read_at(0, 4).expect("read active"), b"one\n");
        let mut after_read = fs::read_dir(directory.path())
            .expect("fixture directory")
            .map(|entry| entry.expect("entry").file_name())
            .collect::<Vec<_>>();
        after_read.sort();
        assert_eq!(after_read, before_read);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_and_hardlink_journals_are_rejected_by_open_and_discovery() {
        use std::os::unix::fs::symlink;

        let directory = tempdir().expect("tempdir");
        let real = directory.path().join("real.jsonl");
        fs::write(&real, b"one\n").expect("real journal");

        let symlink_path = directory.path().join("symlink.jsonl");
        symlink(&real, &symlink_path).expect("symlink journal");
        assert!(JournalFile::open(&symlink_path).is_err());
        assert!(discover_generations(&symlink_path, 8).is_err());

        let hardlink_path = directory.path().join("hardlink.jsonl");
        fs::hard_link(&real, &hardlink_path).expect("hardlink journal");
        assert!(JournalFile::open(&hardlink_path).is_err());
        assert!(discover_generations(&hardlink_path, 8).is_err());
    }
}
