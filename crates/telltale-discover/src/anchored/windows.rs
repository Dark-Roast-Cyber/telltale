//! NT parent-handle-relative opens, refusing name-surrogate reparse points.
//!
//! Only directory handles request listing access. During discovery regular
//! files are opened for attributes only and immediately closed; no session or
//! database bytes are read. `open_file` opens one for a reader instead.
//!
//! A name surrogate (symbolic link, junction, mount point) names another
//! object and is a link. Any other reparse point (a cloud placeholder, a
//! deduplicated file) is the object itself, but its content and listing belong
//! to the filter that owns its tag, which the reparse-point open bypasses. Such
//! an object is reopened through that filter, relative to the same parent and
//! with `OBJ_DONT_REPARSE`, before it is read or traversed. A tag that no
//! filter owns is refused by that reopen, as Windows refuses every program.

use super::{Error, Kind, Node, OsStr, OsString, Path, io_error};
use std::fs::File;
use std::io;
use std::mem::{offset_of, size_of, size_of_val};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::ptr::{null, null_mut};
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_DIRECTORY_INFORMATION, FILE_OPEN, FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
    FileDirectoryInformation, NtCreateFile, NtQueryDirectoryFile,
};
use windows_sys::Win32::Foundation::{
    HANDLE, OBJ_CASE_INSENSITIVE, OBJ_DONT_REPARSE, RtlNtStatusToDosError, STATUS_NO_MORE_FILES,
    STATUS_REPARSE_POINT_ENCOUNTERED, UNICODE_STRING,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_ATTRIBUTE_TAG_INFO, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_READ_DATA,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FileAttributeTagInfo,
    GetFileInformationByHandle, GetFileInformationByHandleEx, SYNCHRONIZE,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

pub(super) struct Directory(File);

/// `IsReparseTagNameSurrogate`: the tag names another object.
const NAME_SURROGATE: u32 = 0x2000_0000;

fn nt_error(status: i32) -> io::Error {
    // SAFETY: pure NT status translation, no pointer arguments.
    io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(status) } as i32)
}

fn status_error(status: i32) -> Error {
    io_error(nt_error(status))
}

fn open_at(parent: Option<&Directory>, name: &OsStr, listing: bool) -> io::Result<Node> {
    let access = if listing { FILE_LIST_DIRECTORY } else { 0 };
    let (kind, file) = open_handle(parent, name, access)?;
    Ok(Node {
        kind,
        directory: (kind == Kind::Directory).then_some(Directory(file)),
    })
}

fn open_handle(parent: Option<&Directory>, name: &OsStr, access: u32) -> io::Result<(Kind, File)> {
    // OPEN_REPARSE_POINT opens the redirect itself, never its target.
    let file = nt_open(
        parent,
        name,
        access,
        FILE_OPEN_REPARSE_POINT,
        OBJ_CASE_INSENSITIVE,
    )
    .map_err(nt_error)?;
    let information = file_information(&file)?;
    let kind = kind_of(&information);
    if information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0 {
        return Ok((kind, file));
    }
    if reparse_tag(&file)? & NAME_SURROGATE != 0 {
        return Ok((Kind::Link, file));
    }
    // Attribute-only file handles need no filter. Roots are volume roots.
    let Some(parent) = parent.filter(|_| kind == Kind::Directory || access & FILE_READ_DATA != 0)
    else {
        return Ok((kind, file));
    };
    // Without OPEN_REPARSE_POINT the tag's filter interprets the object;
    // DONT_REPARSE refuses a name surrogate swapped in since the first open.
    let filtered = match nt_open(
        Some(parent),
        name,
        access,
        0,
        OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
    ) {
        Ok(filtered) => filtered,
        Err(STATUS_REPARSE_POINT_ENCOUNTERED) => return Ok((Kind::Link, file)),
        Err(status) => return Err(nt_error(status)),
    };
    let again = file_information(&filtered)?;
    if identity(&again) != identity(&information) || kind_of(&again) != kind {
        return Err(io::Error::other(
            "reparse point replaced while it was reopened",
        ));
    }
    Ok((kind, filtered))
}

fn nt_open(
    parent: Option<&Directory>,
    name: &OsStr,
    access: u32,
    options: u32,
    object: u32,
) -> Result<File, i32> {
    const STATUS_INVALID_PARAMETER: i32 = 0xC000_000D_u32 as i32;
    let mut wide: Vec<u16> = name.encode_wide().collect();
    let Some(bytes) = wide
        .len()
        .checked_mul(2)
        .filter(|n| *n <= u16::MAX as usize && !wide.contains(&0))
    else {
        return Err(STATUS_INVALID_PARAMETER);
    };
    let mut unicode = UNICODE_STRING {
        Length: bytes as u16,
        MaximumLength: bytes as u16,
        Buffer: wide.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.map_or(null_mut(), |dir| dir.0.as_raw_handle() as HANDLE),
        ObjectName: &mut unicode,
        Attributes: object,
        SecurityDescriptor: null_mut(),
        SecurityQualityOfService: null_mut(),
    };
    let mut status = IO_STATUS_BLOCK::default();
    let mut handle = null_mut();
    // SAFETY: all input buffers and optional parent handle live through this
    // synchronous call. Child names contain no separators; root uses an NT path.
    let result = unsafe {
        NtCreateFile(
            &mut handle,
            FILE_READ_ATTRIBUTES | SYNCHRONIZE | access,
            &attributes,
            &mut status,
            null(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            options | FILE_SYNCHRONOUS_IO_NONALERT,
            null(),
            0,
        )
    };
    if result < 0 {
        return Err(result);
    }
    // SAFETY: a successful NtCreateFile transfers a new owned handle.
    Ok(unsafe { File::from_raw_handle(handle) })
}

fn file_information(file: &File) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: live owned handle and valid writable output structure.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(information)
}

fn reparse_tag(file: &File) -> io::Result<u32> {
    let mut tag = FILE_ATTRIBUTE_TAG_INFO::default();
    // SAFETY: live owned handle and a writable output of the stated size.
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileAttributeTagInfo,
            (&raw mut tag).cast(),
            size_of_val(&tag) as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(tag.ReparseTag)
}

fn kind_of(information: &BY_HANDLE_FILE_INFORMATION) -> Kind {
    if information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
        Kind::Directory
    } else {
        Kind::File
    }
}

fn identity(information: &BY_HANDLE_FILE_INFORMATION) -> (u32, u32, u32) {
    (
        information.dwVolumeSerialNumber,
        information.nFileIndexHigh,
        information.nFileIndexLow,
    )
}

pub(super) fn root(path: &Path) -> Result<Node, Error> {
    let wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    let mut nt: Vec<u16> = r"\??\".encode_utf16().collect();
    if wide.starts_with(&[92, 92, 63, 92]) {
        nt.extend_from_slice(&wide[4..]);
    } else if wide.starts_with(&[92, 92]) {
        nt.extend("UNC\\".encode_utf16());
        nt.extend_from_slice(&wide[2..]);
    } else {
        nt.extend_from_slice(&wide);
    }
    let node = open_at(None, &OsString::from_wide(&nt), false).map_err(io_error)?;
    if node.kind != Kind::Directory {
        return Err(Error::SymlinkRoot);
    }
    Ok(node)
}

pub(super) fn child(parent: &Directory, name: &OsStr, _: bool) -> Result<Option<Node>, Error> {
    match open_at(Some(parent), name, false) {
        Ok(node) => Ok(Some(node)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(io_error(error)),
    }
}

/// Reads the opened object, never a name surrogate's target; the caller checks
/// that it is a regular file.
pub(super) fn open_file(parent: &Directory, name: &OsStr) -> Result<Option<File>, Error> {
    match open_handle(Some(parent), name, FILE_READ_DATA) {
        Ok((Kind::Link, _)) => Err(Error::SymlinkRoot),
        Ok((_, file)) => Ok(Some(file)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(io_error(error)),
    }
}

pub(super) fn entries(
    parent: &Directory,
) -> Result<impl Iterator<Item = Result<OsString, Error>>, Error> {
    // An empty name relative to a handle reopens that same directory object,
    // now with listing access; no pathname is resolved again.
    let node = open_at(Some(parent), OsStr::new(""), true).map_err(io_error)?;
    Ok(Entries {
        directory: node.directory.ok_or(Error::Traversal)?,
        done: false,
    })
}

struct Entries {
    directory: Directory,
    done: bool,
}

impl Iterator for Entries {
    type Item = Result<OsString, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.done {
                return None;
            }
            // Aligned storage large enough for one maximum-size NT filename.
            let mut buffer = [0_u64; 8192];
            let mut status = IO_STATUS_BLOCK::default();
            // SAFETY: directory has listing access, synchronous mode, and the
            // aligned writable buffer remains live. Exactly one entry is read.
            let result = unsafe {
                NtQueryDirectoryFile(
                    self.directory.0.as_raw_handle(),
                    null_mut(),
                    None,
                    null(),
                    &mut status,
                    buffer.as_mut_ptr().cast(),
                    size_of_val(&buffer) as u32,
                    FileDirectoryInformation,
                    true,
                    null(),
                    false,
                )
            };
            if result == STATUS_NO_MORE_FILES {
                self.done = true;
                return None;
            }
            if result < 0 {
                self.done = true;
                return Some(Err(status_error(result)));
            }
            let start = offset_of!(FILE_DIRECTORY_INFORMATION, FileName);
            // SAFETY: success initialized the fixed header within aligned storage.
            let header = unsafe { &*buffer.as_ptr().cast::<FILE_DIRECTORY_INFORMATION>() };
            let length = header.FileNameLength as usize;
            if !length.is_multiple_of(2)
                || start + length > status.Information
                || status.Information > size_of_val(&buffer)
            {
                self.done = true;
                return Some(Err(Error::Traversal));
            }
            // SAFETY: validated initialized UTF-16 byte range within the buffer.
            let units = unsafe {
                std::slice::from_raw_parts(
                    buffer.as_ptr().cast::<u8>().add(start).cast::<u16>(),
                    length / 2,
                )
            };
            let name = OsString::from_wide(units);
            if name != "." && name != ".." {
                return Some(Ok(name));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Node, open_file};
    use super::*;
    use std::fs;
    use std::io::Read;
    use std::os::windows::fs::OpenOptionsExt;
    use std::path::PathBuf;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    };
    use windows_sys::Win32::System::IO::DeviceIoControl;

    /// Third-party tags no filter owns; only bit 29 (name surrogate) differs.
    const OPAQUE: u32 = 0x0000_7A11;
    const SURROGATE: u32 = OPAQUE | NAME_SURROGATE;

    /// `FSCTL_SET_REPARSE_POINT` with a third-party (GUID) buffer, which needs
    /// no privilege, unlike a symbolic link.
    fn set_reparse_point(path: &Path, tag: u32) {
        const FSCTL_SET_REPARSE_POINT: u32 = 0x0009_00A4;
        const GENERIC_WRITE: u32 = 0x4000_0000;
        let file = fs::OpenOptions::new()
            .access_mode(GENERIC_WRITE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)
            .unwrap();
        let mut buffer = Vec::new();
        buffer.extend(tag.to_le_bytes());
        buffer.extend(4_u16.to_le_bytes());
        buffer.extend([0; 2]);
        buffer.extend(*b"telltale-fixture");
        buffer.extend([1, 2, 3, 4]);
        let mut returned = 0;
        // SAFETY: live handle; the input buffer outlives the synchronous call.
        let ok = unsafe {
            DeviceIoControl(
                file.as_raw_handle(),
                FSCTL_SET_REPARSE_POINT,
                buffer.as_ptr().cast(),
                buffer.len() as u32,
                null_mut(),
                0,
                &mut returned,
                null_mut(),
            )
        };
        assert_ne!(ok, 0, "{}", io::Error::last_os_error());
    }

    fn read(path: &Path) -> Result<Option<Vec<u8>>, Error> {
        open_file(path, &[]).map(|file| {
            file.map(|mut file| {
                let mut bytes = Vec::new();
                file.read_to_end(&mut bytes).unwrap();
                bytes
            })
        })
    }

    fn kind(path: &Path) -> Result<Option<Kind>, Error> {
        Node::open(path, &[]).map(|node| node.map(|node| node.kind))
    }

    #[test]
    fn only_name_surrogate_reparse_points_are_links() {
        let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let root = temp.path().to_path_buf();
        let plain = root.join("plain.jsonl");
        let opaque = root.join("opaque.jsonl");
        let surrogate = root.join("surrogate.jsonl");
        let opaque_dir = root.join("opaque-dir");
        for path in [&plain, &opaque, &surrogate] {
            fs::write(path, b"synthetic").unwrap();
        }
        // A directory reparse point must be empty when it is set.
        fs::create_dir(&opaque_dir).unwrap();
        set_reparse_point(&opaque, OPAQUE);
        set_reparse_point(&surrogate, SURROGATE);
        set_reparse_point(&opaque_dir, OPAQUE);

        assert_eq!(kind(&plain), Ok(Some(Kind::File)));
        assert_eq!(read(&plain), Ok(Some(b"synthetic".to_vec())));
        // Discovery sees a non-surrogate reparse point as the file it is.
        assert_eq!(kind(&opaque), Ok(Some(Kind::File)));
        // Reading it goes through its tag's filter. No filter owns this tag,
        // so Windows refuses the open, as it does for every program; the raw
        // stream behind the reparse point is never returned as content.
        assert_eq!(read(&opaque), Err(Error::Traversal));
        // A directory is traversed only through its filter, too.
        assert_eq!(
            kind(&opaque_dir.join("inside.jsonl")),
            Err(Error::Traversal)
        );
        // Any name surrogate stays a link, whatever its owner.
        let parent = Node::open(&root, &[]).unwrap().unwrap();
        let child = |name: &str| parent.child(OsStr::new(name)).map(|n| n.map(|n| n.kind));
        assert_eq!(child("surrogate.jsonl"), Ok(Some(Kind::Link)));
        assert_eq!(child("opaque.jsonl"), Ok(Some(Kind::File)));
        assert_eq!(kind(&surrogate), Err(Error::SymlinkRoot));
        assert_eq!(read(&surrogate), Err(Error::SymlinkRoot));
    }

    #[test]
    fn filtered_reopen_refuses_a_name_surrogate() {
        let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let target = temp.path().join("target");
        let junction = temp.path().join("junction");
        fs::create_dir(&target).unwrap();
        assert!(
            std::process::Command::new("cmd")
                .args(["/C", "mklink", "/J"])
                .arg(&junction)
                .arg(&target)
                .output()
                .unwrap()
                .status
                .success()
        );
        let parent = root(&PathBuf::from(temp.path())).unwrap();
        let parent = parent.directory.as_ref().unwrap();
        // The reopen a non-surrogate reparse point gets: were the name swapped
        // for a junction since the first open, the junction is not followed.
        let result = nt_open(
            Some(parent),
            OsStr::new("junction"),
            0,
            0,
            OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
        );
        assert_eq!(result.err(), Some(STATUS_REPARSE_POINT_ENCOUNTERED));
        assert!(
            nt_open(
                Some(parent),
                OsStr::new("target"),
                0,
                0,
                OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
            )
            .is_ok()
        );
    }
}
