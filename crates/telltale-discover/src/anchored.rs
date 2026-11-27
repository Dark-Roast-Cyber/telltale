//! Handle-relative metadata traversal for bounded source discovery.
//!
//! Nothing below a caller-approved anchor is followed; the anchor itself is
//! resolved once (see `Node::open`). Discovery owns which anchors are approved.
//!
//! Root establishment has a separate finite component bound. Entry accounting
//! belongs to the caller; inventory's syscall budget is deliberately unrelated.
//! Paths returned by discovery remain coordinates, not acquisition capabilities:
//! a reader reopens one with `open_file` under the same anchors, or, for a path
//! it already canonicalized, with no anchors (strict from the filesystem root).

use super::discovery::BoundedDiscoveryError as Error;
use std::ffi::{OsStr, OsString};
use std::path::{Component, Path, PathBuf};

#[cfg(unix)]
#[path = "anchored/unix.rs"]
mod platform;
#[cfg(not(any(unix, windows)))]
mod platform {
    use super::*;
    pub(super) struct Directory;
    pub(super) fn root(_: &Path) -> Result<Node, Error> {
        Err(Error::Traversal)
    }
    pub(super) fn child(_: &Directory, _: &OsStr, _: bool) -> Result<Option<Node>, Error> {
        Err(Error::Traversal)
    }
    pub(super) fn entries(
        _: &Directory,
    ) -> Result<std::iter::Empty<Result<OsString, Error>>, Error> {
        Err(Error::Traversal)
    }
    pub(super) fn open_file(_: &Directory, _: &OsStr) -> Result<Option<std::fs::File>, Error> {
        Err(Error::Traversal)
    }
}
#[cfg(windows)]
#[path = "anchored/windows.rs"]
mod platform;

/// What the metadata inventory walks with on Windows: an open directory, the
/// open of a volume root, and one counted open of a child. `charge` runs
/// before every system open and its refusal, the outer error, stops there.
#[cfg(windows)]
pub(crate) mod windows {
    use super::{Kind, OsStr, Path, platform, single_name};
    use std::io;

    pub(crate) use super::platform::Directory;

    pub(crate) type Opened = io::Result<(Kind, Option<Directory>)>;

    /// The volume root `prefix` names (`C:\`, a verbatim or UNC root).
    pub(crate) fn open_root<E>(
        prefix: &Path,
        charge: &mut impl FnMut() -> Result<(), E>,
    ) -> Result<Opened, E> {
        platform::open_metadata_budgeted(None, &platform::nt_root_path(prefix), charge)
    }

    /// The child `name` of `parent`. A name that is not one plain component
    /// is refused before any open: the system would resolve a longer name
    /// itself, links included.
    pub(crate) fn open_child<E>(
        parent: &Directory,
        name: &OsStr,
        charge: &mut impl FnMut() -> Result<(), E>,
    ) -> Result<Opened, E> {
        if !single_name(name) {
            return Ok(Err(io::ErrorKind::InvalidInput.into()));
        }
        platform::open_metadata_budgeted(Some(parent), name, charge)
    }
}

/// Whether `name` is one plain component: no separator, `.`, `..` or prefix.
fn single_name(name: &OsStr) -> bool {
    let mut components = Path::new(name).components();
    matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    File,
    Directory,
    Link,
    #[cfg(unix)]
    Other,
}

pub(crate) struct Node {
    pub(crate) kind: Kind,
    directory: Option<platform::Directory>,
}

/// Absolute spelling without lexical `..` collapse: a parent component must be
/// inspected before the walk returns to its parent.
fn absolute(path: &Path) -> Result<PathBuf, Error> {
    if path.is_absolute() {
        return Ok(path.to_owned());
    }
    if matches!(path.components().next(), Some(Component::Prefix(_))) {
        return Err(Error::Traversal);
    }
    Ok(std::env::current_dir().map_err(io_error)?.join(path))
}

/// The part of `path` below `anchor` when it lexically never leaves `anchor`.
fn remainder_within<'a>(anchor: &Path, path: &'a Path) -> Option<&'a Path> {
    let rest = path.strip_prefix(anchor).ok()?;
    let mut depth = 0_usize;
    for component in rest.components() {
        match component {
            Component::Normal(_) => depth += 1,
            Component::ParentDir => depth = depth.checked_sub(1)?,
            Component::CurDir => {}
            Component::Prefix(_) | Component::RootDir => return None,
        }
    }
    Some(rest)
}

impl Node {
    /// Open `path` without following any link. A caller-approved anchor that
    /// lexically contains the whole path is resolved to its real location once
    /// (accepting administrator aliases such as a linked `/home`); everything
    /// below it is walked strictly. Paths under no anchor are walked strictly
    /// from the filesystem root.
    pub(crate) fn open(path: &Path, anchors: &[PathBuf]) -> Result<Option<Self>, Error> {
        // Do not apply OpenCode's explicit lexical override semantics to
        // generic paths: inspect `component/..` before returning to its parent.
        if path.as_os_str().len() > 65_536 || path.components().count() > 256 {
            return Err(Error::LimitExceeded);
        }
        let absolute_path = absolute(path)?;
        let mut selected: Option<(PathBuf, &Path)> = None;
        for anchor in anchors {
            let anchor = absolute(anchor)?;
            if let Some(rest) = remainder_within(&anchor, &absolute_path)
                && selected
                    .as_ref()
                    .is_none_or(|(best, _)| anchor.components().count() > best.components().count())
            {
                selected = Some((anchor, rest));
            }
        }
        let Some((anchor, rest)) = selected else {
            return Self::open_strict(&absolute_path);
        };
        let canonical = match std::fs::canonicalize(&anchor) {
            Ok(canonical) => canonical,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io_error(error)),
        };
        let Some(base) = Self::open_strict(&canonical)? else {
            return Ok(None);
        };
        Self::walk(vec![base], rest.components())
    }

    fn open_strict(absolute: &Path) -> Result<Option<Self>, Error> {
        if absolute.components().count() > 256 {
            return Err(Error::LimitExceeded);
        }
        let mut prefix = PathBuf::new();
        let mut names = Vec::new();
        for component in absolute.components() {
            match component {
                Component::Prefix(_) | Component::RootDir => prefix.push(component.as_os_str()),
                component => names.push(component),
            }
        }
        Self::walk(vec![platform::root(&prefix)?], names.into_iter())
    }

    /// `..` never climbs below the first stack entry: the filesystem root, or
    /// an anchor whose remainder was checked to stay inside it.
    fn walk<'a>(
        mut stack: Vec<Self>,
        components: impl Iterator<Item = Component<'a>>,
    ) -> Result<Option<Self>, Error> {
        for component in components {
            if component == Component::CurDir {
                continue;
            }
            let parent = stack.last().ok_or(Error::Traversal)?;
            if parent.kind != Kind::Directory {
                return Err(Error::Traversal);
            }
            if component == Component::ParentDir {
                if stack.len() > 1 {
                    stack.pop();
                }
            } else {
                let Some(next) = parent.child(component.as_os_str())? else {
                    return Ok(None);
                };
                if next.kind == Kind::Link {
                    return Err(Error::SymlinkRoot);
                }
                stack.push(next);
            }
        }
        Ok(stack.pop())
    }

    pub(crate) fn child(&self, name: &OsStr) -> Result<Option<Self>, Error> {
        self.child_for_walk(name, true)
    }

    pub(crate) fn child_for_walk(
        &self,
        name: &OsStr,
        descend: bool,
    ) -> Result<Option<Self>, Error> {
        if !single_name(name) {
            return Err(Error::Traversal);
        }
        platform::child(
            self.directory.as_ref().ok_or(Error::Traversal)?,
            name,
            descend,
        )
    }

    pub(crate) fn entries(&self) -> Result<impl Iterator<Item = Result<OsString, Error>>, Error> {
        platform::entries(self.directory.as_ref().ok_or(Error::Traversal)?)
    }
}

/// Open the file at `path` for reading. Its parent is reached exactly as by
/// `Node::open`; the last component is then opened relative to that parent
/// handle without following a link, so no link below the selected anchor (or
/// anywhere, with no anchor) is followed, even if a pathname is replaced concurrently. The caller checks
/// the opened object's type (a directory or FIFO opens, nonblocking). `None`
/// when a component is absent.
pub(crate) fn open_file(path: &Path, anchors: &[PathBuf]) -> Result<Option<std::fs::File>, Error> {
    let mut components = path.components();
    let Some(Component::Normal(name)) = components.next_back() else {
        return Err(Error::Traversal);
    };
    let parent = match components.as_path() {
        parent if parent.as_os_str().is_empty() => Path::new("."),
        parent => parent,
    };
    let Some(parent) = Node::open(parent, anchors)? else {
        return Ok(None);
    };
    platform::open_file(parent.directory.as_ref().ok_or(Error::Traversal)?, name)
}

fn io_error(error: std::io::Error) -> Error {
    Error::from_io(error)
}

#[cfg(all(test, any(unix, windows)))]
mod tests;
