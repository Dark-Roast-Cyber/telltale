//! Handle-relative metadata traversal for bounded source discovery.
//!
//! Root establishment has a separate finite component bound. Entry accounting
//! belongs to the caller; inventory's syscall budget is deliberately unrelated.
//! Paths returned by discovery remain coordinates, not acquisition capabilities.

use super::discovery::BoundedDiscoveryError as Error;
use std::ffi::{OsStr, OsString};
use std::path::{Component, Path};

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
}
#[cfg(windows)]
#[path = "anchored/windows.rs"]
mod platform;

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

impl Node {
    pub(crate) fn open(path: &Path) -> Result<Option<Self>, Error> {
        // Do not apply OpenCode's explicit lexical override semantics to
        // generic paths: inspect `component/..` before returning to its parent.
        if path.as_os_str().len() > 65_536 || path.components().count() > 256 {
            return Err(Error::LimitExceeded);
        }
        let absolute = if path.is_absolute() {
            path.to_owned()
        } else {
            if matches!(path.components().next(), Some(Component::Prefix(_))) {
                return Err(Error::Traversal);
            }
            std::env::current_dir().map_err(io_error)?.join(path)
        };
        if absolute.components().count() > 256 {
            return Err(Error::LimitExceeded);
        }
        let mut prefix = std::path::PathBuf::new();
        let mut names = Vec::new();
        for component in absolute.components() {
            match component {
                Component::Prefix(_) | Component::RootDir => prefix.push(component.as_os_str()),
                Component::Normal(_) | Component::ParentDir => names.push(component),
                Component::CurDir => {}
            }
        }
        let mut stack = vec![platform::root(&prefix)?];
        for component in names {
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
        if Path::new(name).components().count() != 1
            || !matches!(
                Path::new(name).components().next(),
                Some(Component::Normal(_))
            )
        {
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

fn io_error(error: std::io::Error) -> Error {
    Error::from_io(error)
}

#[cfg(all(test, any(unix, windows)))]
mod tests {
    use super::*;
    use std::fs;

    fn link(target: &Path, path: &Path) {
        #[cfg(unix)]
        std::os::unix::fs::symlink(target, path).unwrap();
        #[cfg(windows)]
        assert!(
            std::process::Command::new("cmd")
                .args(["/C", "mklink", "/J"])
                .arg(path)
                .arg(target)
                .output()
                .unwrap()
                .status
                .success()
        );
    }

    #[test]
    fn enumeration_remains_on_the_handle_after_root_replacement() {
        let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let root = temp.path().join("root");
        let outside = temp.path().join("outside");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(root.join("inside"), b"synthetic").unwrap();
        fs::write(outside.join("outside"), b"synthetic").unwrap();
        let handle = Node::open(&root).unwrap().unwrap();
        fs::rename(&root, temp.path().join("retained")).unwrap();
        link(&outside, &root);
        let names = handle
            .entries()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(names, vec![OsString::from("inside")]);
        assert!(handle.child(OsStr::new("outside")).unwrap().is_none());
    }

    #[test]
    fn child_replacement_is_refused_or_stays_on_the_opened_handle() {
        let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let root = temp.path().join("root");
        let outside = temp.path().join("outside");
        fs::create_dir_all(root.join("child")).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("outside"), b"synthetic").unwrap();
        let parent = Node::open(&root).unwrap().unwrap();
        let child = parent.child(OsStr::new("child")).unwrap().unwrap();
        fs::rename(root.join("child"), root.join("retained")).unwrap();
        link(&outside, &root.join("child"));
        assert_eq!(
            parent.child(OsStr::new("child")).unwrap().unwrap().kind,
            Kind::Link
        );
        assert!(
            child
                .entries()
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
                .is_empty()
        );
    }
}
