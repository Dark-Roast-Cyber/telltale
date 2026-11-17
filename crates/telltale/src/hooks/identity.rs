//! Identity of the running build, for telemetry and evaluator compatibility.
//!
//! A long-lived evaluator may serve a hook only when both come from the same
//! build, or an upgraded binary would answer with the old rules and code. The
//! hooks live inside the Telltale executable, so their identity is the
//! executable's:
//!
//! - the package version of this crate;
//! - the build metadata the host executable registers with
//!   [`set_host_build`] (the CLI registers its Git hash; `unknown` otherwise);
//! - [`executable_identity`], the file identity of the running executable,
//!   read at run time. It changes whenever the binary is rebuilt or replaced,
//!   whether or not the version or commit changed. When the file cannot be
//!   read, the identity is unique to the process, so it matches nothing.
//!
//! [`crate::hooks::config::Config::fingerprint`] folds all three in. The
//! telemetry `producer.telltale_rev` field is [`revision`], a 40-hex digest of
//! the first two only. It names the Telltale release and commit that produced a
//! record and is stable across reinstalls of the same build. It is not a Git
//! object name: recompute it from the version and commit to compare.

use std::sync::OnceLock;

use sha2::{Digest, Sha256};

static HOST_BUILD: OnceLock<String> = OnceLock::new();
static REVISION: OnceLock<String> = OnceLock::new();

/// Metadata reported when the host executable registered none.
pub const UNKNOWN_HOST_BUILD: &str = "unknown";

/// Register the host executable's build metadata (for example its Git hash).
/// Call once, before the first [`revision`]; returns `false` when metadata was
/// already registered or the revision was already computed, so a late call
/// cannot make a process report two identities.
pub fn set_host_build(metadata: &str) -> bool {
    if REVISION.get().is_some() {
        return false;
    }
    HOST_BUILD.set(metadata.to_owned()).is_ok()
}

/// The registered host build metadata, or [`UNKNOWN_HOST_BUILD`].
pub fn host_build() -> &'static str {
    HOST_BUILD.get().map_or(UNKNOWN_HOST_BUILD, String::as_str)
}

/// Package version of the Telltale libraries this runtime was built from.
pub const PACKAGE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// 40 lowercase hex digits naming this build in telemetry
/// (`producer.telltale_rev`): SHA-256 over [`PACKAGE_VERSION`] and
/// [`host_build`], truncated to 160 bits.
pub fn revision() -> &'static str {
    REVISION.get_or_init(|| {
        let mut hasher = Sha256::new();
        for part in [
            "telltale-hooks build revision v1",
            PACKAGE_VERSION,
            host_build(),
        ] {
            hasher.update((part.len() as u64).to_be_bytes());
            hasher.update(part.as_bytes());
        }
        hex::encode(hasher.finalize())[..40].to_owned()
    })
}

/// An identity no other process has: this process's id and the time it was
/// first needed. It stays fixed for the life of the process, because the
/// evaluator compares its fingerprint before and after building its rules.
/// An executable whose file cannot be read therefore never shares an
/// evaluator with another process; its hooks evaluate in-process instead.
fn unknown_identity() -> String {
    static UNKNOWN: OnceLock<String> = OnceLock::new();
    UNKNOWN
        .get_or_init(|| {
            let at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |since| since.as_nanos());
            format!("unknown:{}:{at}", std::process::id())
        })
        .clone()
}

/// Device, inode, size and modification time of the running executable. On
/// Linux this reads `/proc/self/exe`, the image the process runs even after
/// its path was replaced; elsewhere, the file at [`std::env::current_exe`].
/// When neither can be read, [`unknown_identity`].
#[cfg(unix)]
pub fn executable_identity() -> String {
    use std::os::unix::fs::MetadataExt;
    #[cfg(target_os = "linux")]
    let running = std::fs::metadata("/proc/self/exe");
    #[cfg(not(target_os = "linux"))]
    let running: std::io::Result<std::fs::Metadata> = Err(std::io::ErrorKind::Unsupported.into());
    running
        .or_else(|_| std::env::current_exe().and_then(std::fs::metadata))
        .map(|m| {
            format!(
                "{}:{}:{}:{}.{}",
                m.dev(),
                m.ino(),
                m.size(),
                m.mtime(),
                m.mtime_nsec()
            )
        })
        .unwrap_or_else(|_| unknown_identity())
}

/// Path, size and modification time of the running executable (there is no
/// portable file identity outside Unix), or [`unknown_identity`].
#[cfg(not(unix))]
pub fn executable_identity() -> String {
    let Ok(exe) = std::env::current_exe() else {
        return unknown_identity();
    };
    std::fs::metadata(&exe)
        .map(|m| {
            let modified = m
                .modified()
                .ok()
                .and_then(|at| at.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|at| format!("{}.{}", at.as_secs(), at.subsec_nanos()))
                .unwrap_or_default();
            format!("{}:{}:{modified}", exe.display(), m.len())
        })
        .unwrap_or_else(|_| unknown_identity())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revision_is_forty_lowercase_hex_digits_and_stable() {
        let rev = revision();
        assert_eq!(rev.len(), 40);
        assert!(
            rev.bytes()
                .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
        );
        assert_eq!(rev, revision());
    }

    #[test]
    fn host_build_cannot_change_after_the_revision_is_fixed() {
        let _ = revision();
        assert!(!set_host_build("late-registration"));
        assert_ne!(host_build(), "late-registration");
    }

    #[test]
    fn the_executable_has_a_file_identity() {
        let identity = executable_identity();
        assert!(!identity.starts_with("unknown"), "{identity}");
        assert_eq!(identity, executable_identity());
    }

    #[test]
    fn an_unreadable_executable_gets_an_identity_only_this_process_has() {
        let identity = unknown_identity();
        assert_eq!(identity, unknown_identity());
        let pid = std::process::id().to_string();
        assert_eq!(identity.split(':').nth(1), Some(pid.as_str()));
        assert_ne!(identity, "unknown");
    }
}
