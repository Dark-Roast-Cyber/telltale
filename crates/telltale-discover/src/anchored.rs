//! Handle-relative metadata traversal for bounded source discovery.
//!
//! Nothing below a caller-approved anchor is followed; the anchor itself is
//! resolved once (see `Node::open`). Discovery owns which anchors are approved.
//!
//! Root establishment has a separate finite component bound. Entry accounting
//! belongs to the caller; inventory's syscall budget is deliberately unrelated.
//! Paths returned by discovery remain coordinates, not acquisition capabilities.

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
    fn anchors_resolve_once_and_everything_below_stays_strict() {
        let temp = tempfile::tempdir().unwrap();
        let real = temp.path().join("real");
        let alias = temp.path().join("alias");
        fs::create_dir_all(real.join("home").join("store")).unwrap();
        fs::create_dir_all(real.join("outside")).unwrap();
        link(&real, &alias);
        link(&real.join("outside"), &real.join("home").join("linked"));
        let home = alias.join("home");
        let anchor = std::slice::from_ref(&home);
        let open =
            |path: &Path, anchors: &[PathBuf]| Node::open(path, anchors).map(|n| n.map(|n| n.kind));

        assert_eq!(open(&home.join("store"), anchor), Ok(Some(Kind::Directory)));
        // Without an anchor the linked ancestor is refused, as before.
        assert_eq!(open(&home.join("store"), &[]), Err(Error::SymlinkRoot));
        // A link below the anchor is never followed.
        assert_eq!(open(&home.join("linked"), anchor), Err(Error::SymlinkRoot));
        assert_eq!(
            open(&home.join("linked/x"), anchor),
            Err(Error::SymlinkRoot)
        );
        // The longest containing anchor wins; naming the link itself trusts it.
        assert_eq!(
            open(&home.join("linked"), &[home.clone(), home.join("linked")]),
            Ok(Some(Kind::Directory))
        );
        // A remainder that climbs out of its anchor gets no anchor: the walk is
        // strict from the filesystem root and meets the linked ancestor.
        assert_eq!(
            open(&home.join("../home/store"), anchor),
            Err(Error::SymlinkRoot)
        );
        // Missing anchors and missing children are absence, not errors.
        assert_eq!(
            open(&home.join("missing/store"), &[home.join("missing")]),
            Ok(None)
        );
        assert_eq!(open(&home.join("missing"), anchor), Ok(None));
        assert!(remainder_within(&home, &home.join("a/../b")).is_some());
        assert!(remainder_within(&home, &home.join("../b")).is_none());
        assert!(remainder_within(&home.join("a"), &home).is_none());
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
        let handle = Node::open(&root, &[]).unwrap().unwrap();
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
        let parent = Node::open(&root, &[]).unwrap().unwrap();
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
