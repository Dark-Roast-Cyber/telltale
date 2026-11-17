//! NT parent-handle-relative opens, refusing all reparse points.
//!
//! Only directory handles request listing access. During discovery regular
//! files are opened for attributes only and immediately closed; no session or
//! database bytes are read. `open_file` opens one for a reader instead.

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
    HANDLE, OBJ_CASE_INSENSITIVE, RtlNtStatusToDosError, STATUS_NO_MORE_FILES, UNICODE_STRING,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, GetFileInformationByHandle, SYNCHRONIZE,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

pub(super) struct Directory(File);

fn status_error(status: i32) -> Error {
    // SAFETY: pure NT status translation, no pointer arguments.
    io_error(std::io::Error::from_raw_os_error(
        unsafe { RtlNtStatusToDosError(status) } as i32,
    ))
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
    let mut wide: Vec<u16> = name.encode_wide().collect();
    let bytes = wide
        .len()
        .checked_mul(2)
        .filter(|n| *n <= u16::MAX as usize)
        .ok_or(io::ErrorKind::InvalidInput)?;
    if wide.contains(&0) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut unicode = UNICODE_STRING {
        Length: bytes as u16,
        MaximumLength: bytes as u16,
        Buffer: wide.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.map_or(null_mut(), |dir| dir.0.as_raw_handle() as HANDLE),
        ObjectName: &mut unicode,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: null_mut(),
        SecurityQualityOfService: null_mut(),
    };
    let mut status = IO_STATUS_BLOCK::default();
    let mut handle = null_mut();
    // SAFETY: all input buffers and optional parent handle live through this
    // synchronous call. Child names contain no separators; root uses an NT path.
    // OPEN_REPARSE_POINT opens the redirect itself, never its target.
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
            FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            null(),
            0,
        )
    };
    if result < 0 {
        // SAFETY: pure NT status translation, no pointer arguments.
        return Err(io::Error::from_raw_os_error(
            unsafe { RtlNtStatusToDosError(result) } as i32,
        ));
    }
    // SAFETY: a successful NtCreateFile transfers a new owned handle.
    let file = unsafe { File::from_raw_handle(handle) };
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: live owned handle and valid writable output structure.
    if unsafe { GetFileInformationByHandle(handle, &mut information) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let kind = if information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        Kind::Link
    } else if information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
        Kind::Directory
    } else {
        Kind::File
    };
    Ok((kind, file))
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

/// Reads the opened object, never a reparse point's target; the caller checks
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
