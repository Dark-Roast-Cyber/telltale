//! Unix directory descriptors. Discovery inspects leaf files without opening
//! them; `open_file` opens one for a reader relative to its parent descriptor.

use super::{Error, Kind, Node, OsStr, OsString, Path, io_error};
use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, open, openat, statat};
use rustix::io::Errno;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;

pub(super) struct Directory(OwnedFd);

fn map_error(error: Errno) -> Error {
    if error == Errno::LOOP {
        Error::SymlinkRoot
    } else {
        io_error(error.into())
    }
}

fn search_flags() -> OFlags {
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "freebsd"))]
    let access = OFlags::PATH;
    #[cfg(target_os = "macos")]
    let access = OFlags::from_bits_retain(libc::O_SEARCH as _);
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "macos"
    )))]
    let access = OFlags::RDONLY;
    access | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

pub(super) fn root(path: &Path) -> Result<Node, Error> {
    let fd = open(path, search_flags(), Mode::empty()).map_err(map_error)?;
    Ok(Node {
        kind: Kind::Directory,
        directory: Some(Directory(fd)),
    })
}

pub(super) fn child(
    parent: &Directory,
    name: &OsStr,
    descend: bool,
) -> Result<Option<Node>, Error> {
    let stat = match statat(&parent.0, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(Errno::NOENT) => return Ok(None),
        Err(error) => return Err(map_error(error)),
    };
    let kind = match FileType::from_raw_mode(stat.st_mode) {
        FileType::Directory => Kind::Directory,
        FileType::RegularFile => Kind::File,
        FileType::Symlink => Kind::Link,
        _ => Kind::Other,
    };
    let directory = if kind == Kind::Directory && descend {
        Some(Directory(
            openat(&parent.0, name, search_flags(), Mode::empty()).map_err(map_error)?,
        ))
    } else {
        None
    };
    Ok(Some(Node { kind, directory }))
}

pub(super) fn entries(
    parent: &Directory,
) -> Result<impl Iterator<Item = Result<OsString, Error>>, Error> {
    let readable = openat(
        &parent.0,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(map_error)?;
    let directory = Dir::new(readable).map_err(map_error)?;
    Ok(directory.filter_map(|entry| match entry {
        Ok(entry)
            if entry.file_name().to_bytes() == b"." || entry.file_name().to_bytes() == b".." =>
        {
            None
        }
        Ok(entry) => Some(Ok(
            OsStr::from_bytes(entry.file_name().to_bytes()).to_owned()
        )),
        Err(error) => Some(Err(map_error(error))),
    }))
}

/// Never blocks on a FIFO and never follows a link in the last component.
pub(super) fn open_file(parent: &Directory, name: &OsStr) -> Result<Option<std::fs::File>, Error> {
    let flags =
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC;
    match openat(&parent.0, name, flags, Mode::empty()) {
        Ok(fd) => Ok(Some(fd.into())),
        Err(Errno::NOENT) => Ok(None),
        Err(error) => Err(map_error(error)),
    }
}
