//! Bounded, exact-candidate metadata inventory with explicit caller-owned roots.
//!
//! No environment lookup, traversal, source-file reads, execution, or network.
//! Each metadata/access operation is charged before it runs, including every
//! checked root and ancestor. Static candidate lists have at most two entries
//! per product. Unix probes are descriptor-relative, refusing symlinks at every
//! step even when ancestors are replaced during collection. Other execution
//! platforms return `UnsupportedExecutionPlatform` without filesystem access.

use crate::catalog::{
    ArtifactKind, CandidatePlatform, CandidateType, CatalogEntry, CatalogRoot, TOKSCALE_REVISION,
    catalog,
};
pub use crate::record::Platform;
use crate::record::{
    CandidateId, CandidateOutcome, CandidateRecord, INVENTORY_SCHEMA, InstallationAssessment,
    InventoryRecord, InventorySnapshot, LocatorQualification, NotImplemented, ProbeImplementation,
};
use serde::Serialize;
use std::fmt;
#[cfg(unix)]
use std::io;
use std::path::{Component, Path, PathBuf};

const MAX_ROOT_COMPONENTS: usize = 64;
const MAX_CHECKS: u32 = 65_536;

/// Absolute, caller-approved directory roots. Optional roots override only that
/// root class; none are resolved from ambient process state. Explicit roots
/// must exist and allow opening a directory handle, even in an empty inventory.
/// Derived defaults need not exist and are probed beneath the approved home.
#[derive(Clone)]
pub struct InventoryContext {
    pub home: PathBuf,
    pub platform: Platform,
    pub data_dir: Option<PathBuf>,
    /// Generic config base, not the Tokscale subdirectory.
    pub config_dir: Option<PathBuf>,
    pub app_data_dir: Option<PathBuf>,
}

impl InventoryContext {
    pub fn from_home(home: PathBuf, platform: Platform) -> Self {
        Self {
            home,
            platform,
            data_dir: None,
            config_dir: None,
            app_data_dir: None,
        }
    }
}

/// Aggregate filesystem-operation limit, including root validation. Zero and
/// values above the hard ceiling of 65,536 are rejected rather than unlimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InventoryLimits {
    pub max_checks: u32,
}

impl Default for InventoryLimits {
    fn default() -> Self {
        Self { max_checks: 4_096 }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RootKind {
    Home,
    Data,
    Config,
    AppData,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InventoryErrorKind {
    UnsupportedExecutionPlatform,
    InvalidLimits,
    MalformedRoot,
    RootMissing,
    SymlinkRefused,
    WrongType,
    PermissionDenied,
    MetadataUnavailable,
    CheckLimitReached,
}

/// Intentionally contains no paths, OS messages, or other uncontrolled text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct InventoryError {
    pub root: Option<RootKind>,
    pub kind: InventoryErrorKind,
}

impl fmt::Display for InventoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self.kind {
            InventoryErrorKind::UnsupportedExecutionPlatform => {
                "inventory execution platform unsupported"
            }
            InventoryErrorKind::InvalidLimits => "invalid inventory limits",
            InventoryErrorKind::MalformedRoot => "malformed inventory root",
            InventoryErrorKind::RootMissing => "inventory root missing",
            InventoryErrorKind::SymlinkRefused => "inventory root symlink refused",
            InventoryErrorKind::WrongType => "inventory root is not a directory",
            InventoryErrorKind::PermissionDenied => "inventory root access denied",
            InventoryErrorKind::MetadataUnavailable => "inventory root metadata unavailable",
            InventoryErrorKind::CheckLimitReached => "inventory check limit reached",
        };
        f.write_str(message)
    }
}

impl std::error::Error for InventoryError {}

struct Budget {
    #[cfg(unix)]
    max: u32,
    used: u32,
    exhausted: bool,
}

#[cfg(unix)]
impl Budget {
    fn charge(&mut self) -> Result<(), CandidateOutcome> {
        if self.used == self.max {
            self.exhausted = true;
            return Err(CandidateOutcome::CheckLimitReached);
        }
        self.used += 1;
        Ok(())
    }
}

#[cfg(unix)]
fn io_outcome(error: io::Error) -> CandidateOutcome {
    match error.kind() {
        io::ErrorKind::NotFound => CandidateOutcome::NotFoundInCheckedCandidate,
        io::ErrorKind::PermissionDenied => CandidateOutcome::PermissionDenied,
        _ => CandidateOutcome::MetadataUnavailable,
    }
}

fn root_error(root: RootKind, outcome: CandidateOutcome) -> InventoryError {
    let kind = match outcome {
        CandidateOutcome::NotFoundInCheckedCandidate => InventoryErrorKind::RootMissing,
        CandidateOutcome::SymlinkRefused => InventoryErrorKind::SymlinkRefused,
        CandidateOutcome::WrongType => InventoryErrorKind::WrongType,
        CandidateOutcome::PermissionDenied => InventoryErrorKind::PermissionDenied,
        CandidateOutcome::CheckLimitReached => InventoryErrorKind::CheckLimitReached,
        _ => InventoryErrorKind::MetadataUnavailable,
    };
    InventoryError {
        root: Some(root),
        kind,
    }
}

fn valid_root(path: &Path) -> bool {
    path.is_absolute()
        && !path.as_os_str().as_encoded_bytes().contains(&0)
        && path.components().count() <= MAX_ROOT_COMPONENTS
        && !path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
}

fn validate_root(
    path: &Path,
    root: RootKind,
    budget: &mut Budget,
) -> Result<backend::Directory, InventoryError> {
    if !valid_root(path) {
        return Err(InventoryError {
            root: Some(root),
            kind: InventoryErrorKind::MalformedRoot,
        });
    }
    backend::open_root(path, budget).map_err(|outcome| root_error(root, outcome))
}

fn platform_matches(scope: CandidatePlatform, platform: Platform) -> bool {
    match scope {
        CandidatePlatform::Any => platform != Platform::Unknown,
        CandidatePlatform::Linux => platform == Platform::Linux,
        CandidatePlatform::MacOs => platform == Platform::MacOs,
        CandidatePlatform::Unix => matches!(platform, Platform::Linux | Platform::MacOs),
    }
}

fn append_relative(path: &mut PathBuf, relative: &str) {
    // All relative values are compiled literals; split for native separators.
    for component in relative.split('/').filter(|part| !part.is_empty()) {
        path.push(component);
    }
}

/// Resolves only compiled hints and explicit roots, never upstream env rules.
/// The returned relative prefix remains beneath its already validated root.
fn base_and_prefix(context: &InventoryContext, root: CatalogRoot) -> (RootKind, PathBuf) {
    let home = RootKind::Home;
    match root {
        CatalogRoot::Home => (home, PathBuf::new()),
        CatalogRoot::Data => context.data_dir.as_deref().map_or_else(
            || (home, native_relative(".local/share")),
            |_| (RootKind::Data, PathBuf::new()),
        ),
        CatalogRoot::TokscaleConfig => {
            if context.config_dir.is_some() {
                (RootKind::Config, native_relative("tokscale"))
            } else if context.platform == Platform::Windows {
                let (base, mut prefix) = base_and_prefix(context, CatalogRoot::AppData);
                prefix.push("tokscale");
                (base, prefix)
            } else {
                (home, native_relative(".config/tokscale"))
            }
        }
        CatalogRoot::AppData => context.app_data_dir.as_deref().map_or_else(
            || {
                let relative = match context.platform {
                    Platform::Windows => "AppData/Roaming",
                    Platform::MacOs => "Library/Application Support",
                    _ => ".config",
                };
                (home, native_relative(relative))
            },
            |_| (RootKind::AppData, PathBuf::new()),
        ),
        CatalogRoot::ReasonixHome => {
            if context.platform == Platform::Windows {
                let (base, mut prefix) = base_and_prefix(context, CatalogRoot::AppData);
                prefix.push("reasonix");
                (base, prefix)
            } else {
                (home, native_relative(".reasonix"))
            }
        }
        CatalogRoot::EnvironmentFallback { home_relative, .. } => {
            (home, native_relative(home_relative))
        }
    }
}

fn native_relative(relative: &str) -> PathBuf {
    let mut path = PathBuf::new();
    append_relative(&mut path, relative);
    path
}

fn discover_entry(
    context: &InventoryContext,
    roots: &[(RootKind, backend::Directory)],
    entry: &CatalogEntry,
    budget: &mut Budget,
) -> InventoryRecord {
    let enabled = platform_matches(entry.platform, context.platform);
    let (base, mut relative) = base_and_prefix(context, entry.upstream_root);
    append_relative(&mut relative, entry.upstream_relative_path);
    let mut candidates = vec![CandidateRecord {
        candidate: CandidateId::UpstreamPrimary,
        artifact_kind: entry.artifact_kind,
        outcome: if enabled {
            backend::probe(
                find_root(roots, base),
                &relative,
                entry.candidate_type,
                budget,
            )
        } else {
            CandidateOutcome::PlatformUnverified
        },
    }];
    let extra = match entry.id {
        "opencode" => Some((
            CandidateId::OpenCodeDefaultDatabase,
            CatalogRoot::Data,
            "opencode/opencode.db",
        )),
        "copilot" => Some((
            CandidateId::CopilotSessionStoreDatabase,
            CatalogRoot::Home,
            ".copilot/session-store.db",
        )),
        _ => None,
    };
    if let Some((candidate, root, path)) = extra {
        // Pinned scanner supplements the registry with these current database
        // filenames. No DB bytes are read. Variants and relocations are unprobed.
        let (base, mut relative) = base_and_prefix(context, root);
        append_relative(&mut relative, path);
        candidates.push(CandidateRecord {
            candidate,
            artifact_kind: ArtifactKind::NativeData,
            outcome: if enabled {
                backend::probe(
                    find_root(roots, base),
                    &relative,
                    CandidateType::File,
                    budget,
                )
            } else {
                CandidateOutcome::PlatformUnverified
            },
        });
    }
    InventoryRecord {
        id: entry.id,
        display_name: entry.display_name,
        probe_implementation: if enabled {
            ProbeImplementation::ExactMetadataCandidates
        } else {
            ProbeImplementation::PlatformUnverified
        },
        locator_qualification: LocatorQualification::UpstreamCandidateOnly,
        installation: InstallationAssessment::NotAssessed,
        usage: NotImplemented::NotImplemented,
        additional_locations: NotImplemented::NotImplemented,
        environment_relocations: NotImplemented::NotImplemented,
        scanner_patterns: NotImplemented::NotImplemented,
        candidates,
    }
}

/// Inventory all catalog entries in pinned order. This is neither a session
/// discovery API nor a complete installation survey. Timestamp comes from the
/// caller. Missing explicit roots are errors; a valid empty home is success.
/// Budget exhaustion after root validation appears on remaining candidates,
/// never as absence. No raw paths or OS error strings enter returned records.
pub fn discover(
    context: &InventoryContext,
    observed_at_unix_ms: u64,
    limits: InventoryLimits,
) -> Result<InventorySnapshot, InventoryError> {
    if !cfg!(unix) {
        return Err(InventoryError {
            root: None,
            kind: InventoryErrorKind::UnsupportedExecutionPlatform,
        });
    }
    if limits.max_checks == 0 || limits.max_checks > MAX_CHECKS {
        return Err(InventoryError {
            root: None,
            kind: InventoryErrorKind::InvalidLimits,
        });
    }
    let mut budget = Budget {
        #[cfg(unix)]
        max: limits.max_checks,
        used: 0,
        exhausted: false,
    };
    let mut roots = vec![(
        RootKind::Home,
        validate_root(&context.home, RootKind::Home, &mut budget)?,
    )];
    for (kind, path) in [
        (RootKind::Data, context.data_dir.as_deref()),
        (RootKind::Config, context.config_dir.as_deref()),
        (RootKind::AppData, context.app_data_dir.as_deref()),
    ] {
        if let Some(path) = path {
            roots.push((kind, validate_root(path, kind, &mut budget)?));
        }
    }
    let entries = catalog()
        .iter()
        .map(|entry| discover_entry(context, &roots, entry, &mut budget))
        .collect();
    Ok(InventorySnapshot {
        schema: INVENTORY_SCHEMA,
        catalog_revision: TOKSCALE_REVISION,
        observed_at_unix_ms,
        platform: context.platform,
        checks_performed: budget.used,
        check_limit_reached: budget.exhausted,
        entries,
    })
}

fn find_root(roots: &[(RootKind, backend::Directory)], kind: RootKind) -> &backend::Directory {
    &roots
        .iter()
        .find(|(root, _)| *root == kind)
        .expect("resolved root was validated")
        .1
}

#[cfg(unix)]
mod backend {
    use super::*;
    use std::ffi::{CString, OsStr};
    use std::fs::File;
    use std::mem::MaybeUninit;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;

    pub(super) struct Directory(File);

    fn name(value: &OsStr) -> Result<CString, CandidateOutcome> {
        CString::new(value.as_bytes()).map_err(|_| CandidateOutcome::MetadataUnavailable)
    }

    fn os_outcome() -> CandidateOutcome {
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::ELOOP) => CandidateOutcome::SymlinkRefused,
            Some(libc::ENOTDIR) => CandidateOutcome::WrongType,
            _ => io_outcome(error),
        }
    }

    fn open_at(
        parent: Option<&Directory>,
        child: &OsStr,
        budget: &mut Budget,
    ) -> Result<Directory, CandidateOutcome> {
        let name = name(child)?;
        budget.charge()?;
        // SAFETY: CString is terminated; the optional parent descriptor stays
        // live throughout the call. O_DIRECTORY | O_NOFOLLOW cannot follow a
        // replacement symlink. Only the initial literal `/` uses AT_FDCWD.
        let fd = unsafe {
            libc::openat(
                parent.map_or(libc::AT_FDCWD, |dir| dir.0.as_raw_fd()),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(os_outcome());
        }
        // SAFETY: openat returned a new owned descriptor, consumed exactly once.
        Ok(Directory(unsafe { File::from_raw_fd(fd) }))
    }

    fn inspect(
        parent: &Directory,
        child: &OsStr,
        budget: &mut Budget,
    ) -> Result<CandidateType, CandidateOutcome> {
        let name = name(child)?;
        let mut metadata = MaybeUninit::<libc::stat>::uninit();
        budget.charge()?;
        // SAFETY: the output buffer is valid for stat; the parent handle is
        // live and name terminated. No path contains unchecked separators.
        let result = unsafe {
            libc::fstatat(
                parent.0.as_raw_fd(),
                name.as_ptr(),
                metadata.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result != 0 {
            return Err(os_outcome());
        }
        // SAFETY: successful fstatat initialized the stat buffer.
        let mode = unsafe { metadata.assume_init() }.st_mode & libc::S_IFMT;
        match mode {
            libc::S_IFLNK => Err(CandidateOutcome::SymlinkRefused),
            libc::S_IFDIR => Ok(CandidateType::Directory),
            libc::S_IFREG => Ok(CandidateType::File),
            _ => Err(CandidateOutcome::WrongType),
        }
    }

    fn descend(
        parent: &Directory,
        child: &OsStr,
        budget: &mut Budget,
    ) -> Result<Directory, CandidateOutcome> {
        if inspect(parent, child, budget)? != CandidateType::Directory {
            return Err(CandidateOutcome::WrongType);
        }
        open_at(Some(parent), child, budget)
    }

    pub(super) fn open_root(
        path: &Path,
        budget: &mut Budget,
    ) -> Result<Directory, CandidateOutcome> {
        let mut directory = open_at(None, OsStr::new("/"), budget)?;
        for component in path.components() {
            if let Component::Normal(name) = component {
                directory = descend(&directory, name, budget)?;
            }
        }
        Ok(directory)
    }

    pub(super) fn probe(
        base: &Directory,
        relative: &Path,
        expected: CandidateType,
        budget: &mut Budget,
    ) -> CandidateOutcome {
        let mut current = None;
        let mut components = relative.components().peekable();
        while let Some(component) = components.next() {
            let parent = current.as_ref().unwrap_or(base);
            if components.peek().is_some() {
                match descend(parent, component.as_os_str(), budget) {
                    Ok(directory) => current = Some(directory),
                    Err(outcome) => return outcome,
                }
            } else {
                return match inspect(parent, component.as_os_str(), budget) {
                    Ok(kind) if kind == expected => CandidateOutcome::IndicatorPresent,
                    Ok(_) => CandidateOutcome::WrongType,
                    Err(outcome) => outcome,
                };
            }
        }
        CandidateOutcome::WrongType
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::fs::symlink;

        #[test]
        fn anchored_handle_survives_ancestor_replacement_without_escape() {
            let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
            let root = temp.path().join("root");
            let outside = temp.path().join("outside");
            std::fs::create_dir(&root).unwrap();
            std::fs::create_dir_all(outside.join(".pi/agent/sessions")).unwrap();
            let mut budget = Budget {
                max: 100,
                used: 0,
                exhausted: false,
            };
            let handle = open_root(&root, &mut budget).unwrap();
            std::fs::rename(&root, temp.path().join("retained")).unwrap();
            symlink(&outside, &root).unwrap();
            assert_eq!(
                probe(
                    &handle,
                    Path::new(".pi/agent/sessions"),
                    CandidateType::Directory,
                    &mut budget
                ),
                CandidateOutcome::NotFoundInCheckedCandidate
            );
        }

        #[test]
        fn symlink_swapped_between_inspect_and_open_is_refused() {
            let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
            std::fs::create_dir(temp.path().join("child")).unwrap();
            std::fs::create_dir(temp.path().join("outside")).unwrap();
            let mut budget = Budget {
                max: 100,
                used: 0,
                exhausted: false,
            };
            let handle = open_root(temp.path(), &mut budget).unwrap();
            assert_eq!(
                inspect(&handle, OsStr::new("child"), &mut budget),
                Ok(CandidateType::Directory)
            );
            std::fs::rename(temp.path().join("child"), temp.path().join("retained")).unwrap();
            symlink(temp.path().join("outside"), temp.path().join("child")).unwrap();
            assert!(matches!(
                open_at(Some(&handle), OsStr::new("child"), &mut budget),
                Err(CandidateOutcome::SymlinkRefused | CandidateOutcome::WrongType)
            ));
        }
    }
}

#[cfg(not(unix))]
mod backend {
    use super::*;
    pub(super) struct Directory;

    pub(super) fn open_root(_: &Path, _: &mut Budget) -> Result<Directory, CandidateOutcome> {
        Err(CandidateOutcome::PlatformUnverified)
    }

    pub(super) fn probe(
        _: &Directory,
        _: &Path,
        _: CandidateType,
        _: &mut Budget,
    ) -> CandidateOutcome {
        CandidateOutcome::PlatformUnverified
    }
}
