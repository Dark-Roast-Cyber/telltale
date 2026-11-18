//! The Windows system config root and the check that only administrators can
//! change what is read from it.
//!
//! Unix keeps the system root in `/etc`, which only root can write. On Windows
//! the root is `%ProgramData%\telltale`, resolved through the known folder, and
//! any user can create a folder in `%ProgramData%` and own it, or inherit its
//! `Users` create-files grant. So every object read from the system root must
//! be owned by, and writable only by, Administrators, SYSTEM or
//! TrustedInstaller, and must not be a link.

use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::mem::MaybeUninit;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::ptr::null_mut;
use windows_sys::Win32::Foundation::{ERROR_SUCCESS, HLOCAL, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSidToSidW, GetSecurityInfo, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, GetAce, GetLengthSid,
    INHERIT_ONLY_ACE, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, READ_CONTROL,
};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::UI::Shell::{FOLDERID_ProgramData, KF_FLAG_DEFAULT, SHGetKnownFolderPath};

/// Principals that may own or change the system root. `OWNER RIGHTS` applies
/// to the owner, which must itself be one of the first three; `CREATOR OWNER`
/// on an ACE that applies to the object matches no one.
const TRUSTED: &[&str] = &[
    "S-1-5-32-544",                                                   // Administrators
    "S-1-5-18",                                                       // SYSTEM
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", // TrustedInstaller
    "S-1-3-4",                                                        // OWNER RIGHTS
    "S-1-3-0",                                                        // CREATOR OWNER
];
const TRUSTED_OWNERS: usize = 3;

/// Rights that change an object's content, name, existence, owner or ACL, or
/// a directory's entries. Attribute writes count because they can set a
/// reparse point; extended-attribute writes are not read and do not.
const WRITE_RIGHTS: u32 = 0x0000_0002 // FILE_WRITE_DATA, FILE_ADD_FILE
    | 0x0000_0004 // FILE_APPEND_DATA, FILE_ADD_SUBDIRECTORY
    | 0x0000_0040 // FILE_DELETE_CHILD
    | 0x0000_0100 // FILE_WRITE_ATTRIBUTES
    | 0x0001_0000 // DELETE
    | 0x0004_0000 // WRITE_DAC
    | 0x0008_0000 // WRITE_OWNER
    | 0x1000_0000 // GENERIC_ALL
    | 0x4000_0000; // GENERIC_WRITE

const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const ACCESS_DENIED_ACE_TYPE: u8 = 1;
const ACCESS_DENIED_OBJECT_ACE_TYPE: u8 = 6;
const ACCESS_ALLOWED_CALLBACK_ACE_TYPE: u8 = 9;
const ACCESS_DENIED_CALLBACK_ACE_TYPE: u8 = 10;
const ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE: u8 = 12;

/// `%ProgramData%`, from the known folder rather than the environment or a
/// literal drive, so a system drive other than `C:` and a relocated folder
/// both resolve.
pub(super) fn program_data() -> Option<PathBuf> {
    let mut path = null_mut();
    // SAFETY: a valid known-folder ID and output pointer; no token (current user).
    let result = unsafe {
        SHGetKnownFolderPath(
            &FOLDERID_ProgramData,
            KF_FLAG_DEFAULT as u32,
            null_mut(),
            &mut path,
        )
    };
    let resolved = (result >= 0 && !path.is_null()).then(|| {
        // SAFETY: success returns a NUL-terminated wide string.
        let length = (0..).take_while(|&i| unsafe { *path.add(i) } != 0).count();
        // SAFETY: `length` units precede the terminator.
        PathBuf::from(OsString::from_wide(unsafe {
            std::slice::from_raw_parts(path, length)
        }))
    });
    // SAFETY: the shell allocates the string with CoTaskMemAlloc, even on failure.
    unsafe { CoTaskMemFree(path.cast()) };
    resolved
}

/// Why an object in the system root is not trusted. Payload-free apart from
/// the principal, which is a SID, never a name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Untrusted {
    Link,
    Owner,
    NullDacl,
    Writable(String),
    UnknownAce(u8),
}

impl std::fmt::Display for Untrusted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Link => f.write_str("is a link"),
            Self::Owner => {
                f.write_str("is not owned by Administrators, SYSTEM or TrustedInstaller")
            }
            Self::NullDacl => f.write_str("has no access control list"),
            Self::Writable(sid) => write!(f, "can be changed by {sid}"),
            Self::UnknownAce(kind) => write!(f, "has an access entry of unsupported type {kind}"),
        }
    }
}

/// `Ok(Err(_))` when `path` exists but may be changed by someone other than
/// Administrators, SYSTEM or TrustedInstaller.
pub(super) fn administrator_only(path: &Path) -> io::Result<Result<(), Untrusted>> {
    check(path, &trusted_sids(TRUSTED)?, TRUSTED_OWNERS)
}

fn trusted_sids(strings: &[&str]) -> io::Result<Vec<Vec<u8>>> {
    strings.iter().map(|sid| sid_bytes(sid)).collect()
}

fn sid_bytes(string: &str) -> io::Result<Vec<u8>> {
    let wide: Vec<u16> = std::ffi::OsStr::new(string)
        .encode_wide()
        .chain([0])
        .collect();
    let mut sid: PSID = null_mut();
    // SAFETY: NUL-terminated input and a writable output pointer.
    if unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut sid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a valid SID from the call above, freed exactly once.
    let bytes = unsafe { sid_slice(sid) }.to_vec();
    unsafe { LocalFree(sid as HLOCAL) };
    Ok(bytes)
}

/// # Safety
/// `sid` points to a valid SID that outlives the returned slice.
unsafe fn sid_slice<'a>(sid: PSID) -> &'a [u8] {
    // SAFETY: per the contract, `GetLengthSid` bytes are readable.
    unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), GetLengthSid(sid) as usize) }
}

fn sid_string(sid: &[u8]) -> String {
    // S-<revision>-<authority>-<sub authorities>, as ConvertSidToStringSid.
    let authority = sid[2..8]
        .iter()
        .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte));
    let subs = sid[8..]
        .as_chunks::<4>()
        .0
        .iter()
        .take(usize::from(sid[1]))
        .map(|chunk| u32::from_le_bytes(*chunk).to_string());
    std::iter::once(format!("S-{}-{authority}", sid[0]))
        .chain(subs)
        .collect::<Vec<_>>()
        .join("-")
}

/// `trusted[..owners]` may own the object; any of `trusted` may hold write
/// rights. Deny entries are ignored, so the check never trusts more than the
/// allow entries grant.
fn check(path: &Path, trusted: &[Vec<u8>], owners: usize) -> io::Result<Result<(), Untrusted>> {
    // The object itself, never a link's target.
    let file = File::options()
        .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    if file.metadata()?.file_type().is_symlink() {
        return Ok(Err(Untrusted::Link));
    }
    let descriptor = Descriptor::of(&file)?;
    if descriptor.owner.is_null() {
        return Ok(Err(Untrusted::Owner));
    }
    // SAFETY: owner and DACL point into the descriptor, which `descriptor` keeps alive.
    let owner = unsafe { sid_slice(descriptor.owner) };
    if !trusted[..owners].iter().any(|sid| sid == owner) {
        return Ok(Err(Untrusted::Owner));
    }
    if descriptor.dacl.is_null() {
        return Ok(Err(Untrusted::NullDacl));
    }
    // SAFETY: a non-null DACL from GetSecurityInfo.
    let count = unsafe { (*descriptor.dacl).AceCount };
    for index in 0..u32::from(count) {
        let mut ace = MaybeUninit::uninit();
        // SAFETY: index is below the ACL's own count.
        if unsafe { GetAce(descriptor.dacl, index, ace.as_mut_ptr()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: GetAce succeeded and wrote the ACE's address.
        let ace = unsafe { ace.assume_init() };
        // SAFETY: every ACE starts with a header.
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        if u32::from(header.AceFlags) & INHERIT_ONLY_ACE != 0 {
            continue;
        }
        match header.AceType {
            ACCESS_DENIED_ACE_TYPE
            | ACCESS_DENIED_OBJECT_ACE_TYPE
            | ACCESS_DENIED_CALLBACK_ACE_TYPE
            | ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE => continue,
            // A callback ACE has the allowed layout, with its condition after the SID.
            ACCESS_ALLOWED_ACE_TYPE | ACCESS_ALLOWED_CALLBACK_ACE_TYPE => {}
            other => return Ok(Err(Untrusted::UnknownAce(other))),
        }
        // SAFETY: both allowed types share ACCESS_ALLOWED_ACE's layout.
        let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        if allowed.Mask & WRITE_RIGHTS == 0 {
            continue;
        }
        // SAFETY: SidStart begins the ACE's SID, inside the descriptor.
        let sid = unsafe { sid_slice((&raw const allowed.SidStart).cast_mut().cast()) };
        if !trusted.iter().any(|trusted| trusted == sid) {
            return Ok(Err(Untrusted::Writable(sid_string(sid))));
        }
    }
    Ok(Ok(()))
}

struct Descriptor {
    owner: PSID,
    dacl: *mut ACL,
    descriptor: PSECURITY_DESCRIPTOR,
}

impl Descriptor {
    fn of(file: &File) -> io::Result<Self> {
        let mut owner = MaybeUninit::uninit();
        let mut dacl = MaybeUninit::uninit();
        let mut descriptor = MaybeUninit::uninit();
        // SAFETY: a live handle with READ_CONTROL and writable outputs; the
        // descriptor is freed in Drop.
        let result = unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                owner.as_mut_ptr(),
                null_mut(),
                dacl.as_mut_ptr(),
                null_mut(),
                descriptor.as_mut_ptr(),
            )
        };
        if result != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(result as i32));
        }
        // SAFETY: on success GetSecurityInfo wrote all three outputs; the
        // owner and DACL may still be null, which `check` tests.
        Ok(unsafe {
            Self {
                owner: owner.assume_init(),
                dacl: dacl.assume_init(),
                descriptor: descriptor.assume_init(),
            }
        })
    }
}

impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: allocated by GetSecurityInfo with LocalAlloc, freed once.
        unsafe { LocalFree(self.descriptor as HLOCAL) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn current_user() -> String {
        let output = Command::new("whoami")
            .args(["/user", "/fo", "csv", "/nh"])
            .output()
            .unwrap();
        let text = String::from_utf8(output.stdout).unwrap();
        text.trim()
            .rsplit(',')
            .next()
            .unwrap()
            .trim_matches('"')
            .to_owned()
    }

    fn icacls(path: &Path, args: &[&str]) {
        let output = Command::new("icacls")
            .arg(path)
            .args(args)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
    }

    /// The ACL as icacls prints it, for assertion messages.
    fn acl(path: &Path) -> String {
        let output = Command::new("icacls").arg(path).output().unwrap();
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    #[test]
    fn program_data_is_the_known_folder() {
        let path = program_data().unwrap();
        assert!(path.is_absolute());
        assert!(path.is_dir());
        assert!(path.ends_with("ProgramData"));
    }

    #[test]
    fn sid_strings_round_trip() {
        for sid in TRUSTED {
            assert_eq!(sid_string(&sid_bytes(sid).unwrap()), *sid);
        }
    }

    /// Real system folders pass with the production principals; a folder the
    /// test creates is owned by its user and refused.
    #[test]
    fn administrator_only_reads_real_acls() {
        let windows = PathBuf::from(std::env::var_os("SystemRoot").unwrap());
        for path in [
            windows.join("System32"),
            windows.join("System32\\kernel32.dll"),
        ] {
            assert_eq!(administrator_only(&path).unwrap(), Ok(()), "{path:?}");
        }
        let temp = tempfile::tempdir().unwrap();
        // Run elevated, the creator may be Administrators: owner or write.
        assert!(matches!(
            administrator_only(temp.path()).unwrap(),
            Err(Untrusted::Owner | Untrusted::Writable(_))
        ));
        assert_eq!(
            administrator_only(&temp.path().join("missing"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
    }

    /// The root that docs/install.md tells operators to create passes, with a
    /// file an administrator adds. Setting the owner to Administrators needs
    /// elevation, which Windows CI runners have.
    #[test]
    fn documented_root_passes_when_elevated() {
        let groups = Command::new("whoami").arg("/groups").output().unwrap();
        if !String::from_utf8_lossy(&groups.stdout).contains("S-1-16-12288") {
            eprintln!("not elevated: documented root not checked");
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("telltale");
        std::fs::create_dir(&root).unwrap();
        icacls(&root, &["/setowner", "*S-1-5-32-544"]);
        icacls(&root, &["/reset"]);
        icacls(
            &root,
            &[
                "/inheritance:r",
                "/grant:r",
                "*S-1-5-32-544:(OI)(CI)F",
                "*S-1-5-18:(OI)(CI)F",
                "*S-1-5-32-545:(OI)(CI)RX",
            ],
        );
        let file = root.join("settings.yaml");
        std::fs::write(&file, b"version: 1\n").unwrap();
        icacls(&file, &["/setowner", "*S-1-5-32-544"]);
        assert_eq!(administrator_only(&root).unwrap(), Ok(()), "{}", acl(&root));
        assert_eq!(administrator_only(&file).unwrap(), Ok(()), "{}", acl(&file));
        // A user-writable file in it is still refused.
        icacls(&file, &["/grant", "*S-1-5-32-545:(M)"]);
        assert_eq!(
            administrator_only(&file).unwrap(),
            Err(Untrusted::Writable("S-1-5-32-545".into()))
        );
    }

    /// The same check with the test's own user standing in for the trusted
    /// principals, so pass and fail cases run without elevation.
    #[test]
    fn write_grants_owner_and_links_decide() {
        let user = current_user();
        let trusted = trusted_sids(&[&user, "S-1-5-18"]).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        std::fs::create_dir(&root).unwrap();
        let file = root.join("settings.yaml");
        std::fs::write(&file, b"version: 1\n").unwrap();
        // Elevated, new objects are owned by Administrators instead.
        let owner = format!("*{user}");
        let grant = format!("*{user}:(OI)(CI)F");
        icacls(&root, &["/setowner", &owner]);
        icacls(&root, &["/reset"]);
        icacls(
            &root,
            &[
                "/inheritance:r",
                "/grant:r",
                &grant,
                "/grant:r",
                "*S-1-5-32-545:(OI)(CI)RX",
            ],
        );
        icacls(&file, &["/setowner", &owner]);
        icacls(&file, &["/reset"]);
        let check = |path: &Path| check(path, &trusted, 1).unwrap();
        assert_eq!(check(&root), Ok(()), "{}", acl(&root));
        assert_eq!(check(&file), Ok(()), "{}", acl(&file));

        // Users may add files: the folder's content can change.
        icacls(&root, &["/grant", "*S-1-5-32-545:(AD,WD)"]);
        assert_eq!(
            check(&root),
            Err(Untrusted::Writable("S-1-5-32-545".into()))
        );
        // An inherit-only grant does not apply to the folder itself.
        icacls(
            &root,
            &[
                "/remove:g",
                "*S-1-5-32-545",
                "/grant",
                "*S-1-5-32-545:(OI)(CI)(IO)RX",
            ],
        );
        icacls(&root, &["/grant", "*S-1-1-0:(OI)(IO)M"]);
        assert_eq!(check(&root), Ok(()));
        // ...but it does apply to a file that inherits it.
        icacls(&file, &["/reset"]);
        assert_eq!(check(&file), Err(Untrusted::Writable("S-1-1-0".into())));
        // Deny entries never make an object trusted.
        icacls(&file, &["/deny", "*S-1-1-0:(WD,AD)"]);
        assert_eq!(check(&file), Err(Untrusted::Writable("S-1-1-0".into())));
        // Extended-attribute writes do not change what is read...
        icacls(&file, &["/reset"]);
        icacls(&root, &["/remove:g", "*S-1-1-0"]);
        icacls(&file, &["/reset"]);
        icacls(&file, &["/grant", "*S-1-5-32-545:(WEA)"]);
        assert_eq!(check(&file), Ok(()));
        // ...but attribute writes can turn the file into a link.
        icacls(&file, &["/grant", "*S-1-5-32-545:(WA)"]);
        assert_eq!(
            check(&file),
            Err(Untrusted::Writable("S-1-5-32-545".into()))
        );
        icacls(&file, &["/reset"]);
        // The owner must be trusted: SYSTEM alone is not an owner here.
        assert_eq!(
            super::check(&file, &trusted[1..], 1).unwrap(),
            Err(Untrusted::Owner)
        );

        // A junction is refused as a link, whatever its ACL.
        let junction = root.join("linked");
        let made = Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&junction)
            .arg(temp.path())
            .output()
            .unwrap();
        assert!(made.status.success());
        assert_eq!(check(&junction), Err(Untrusted::Link));
    }
}
