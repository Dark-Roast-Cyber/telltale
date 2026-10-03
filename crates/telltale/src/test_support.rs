use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum EntryContent {
    Directory,
    File(Vec<u8>),
    Symlink(PathBuf),
}

pub(crate) fn tree_snapshot(root: &Path) -> BTreeMap<PathBuf, (EntryContent, u64, SystemTime)> {
    fn visit(
        root: &Path,
        path: &Path,
        entries: &mut BTreeMap<PathBuf, (EntryContent, u64, SystemTime)>,
    ) {
        let metadata = fs::symlink_metadata(path).expect("snapshot metadata");
        let content = if metadata.file_type().is_symlink() {
            EntryContent::Symlink(fs::read_link(path).expect("snapshot symlink target"))
        } else if metadata.is_dir() {
            EntryContent::Directory
        } else {
            assert!(metadata.is_file(), "unsupported fixture entry: {path:?}");
            EntryContent::File(fs::read(path).expect("snapshot file contents"))
        };
        entries.insert(
            path.strip_prefix(root)
                .expect("snapshot path")
                .to_path_buf(),
            (
                content,
                metadata.len(),
                metadata.modified().expect("snapshot modification time"),
            ),
        );
        if metadata.is_dir() {
            for entry in fs::read_dir(path).expect("snapshot directory") {
                visit(root, &entry.expect("snapshot entry").path(), entries);
            }
        }
    }
    let mut entries = BTreeMap::new();
    visit(root, root, &mut entries);
    entries
}

#[test]
fn snapshot_detects_same_length_content_changes() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("synthetic");
    fs::write(&path, "before").unwrap();
    let before = tree_snapshot(root.path());
    fs::write(&path, "after!").unwrap();
    assert_ne!(tree_snapshot(root.path()), before);
}

#[cfg(unix)]
#[test]
fn snapshot_records_symlink_targets_without_following_them() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("synthetic"), "before").unwrap();
    let link = root.path().join("link");
    symlink(outside.path(), &link).unwrap();
    symlink("missing", root.path().join("dangling")).unwrap();
    symlink(".", root.path().join("loop")).unwrap();
    let before = tree_snapshot(root.path());
    assert_eq!(before.len(), 4);
    assert_eq!(
        before[Path::new("link")].0,
        EntryContent::Symlink(outside.path().to_path_buf())
    );
    fs::write(outside.path().join("synthetic"), "after!").unwrap();
    assert_eq!(tree_snapshot(root.path()), before);
    fs::remove_file(&link).unwrap();
    symlink("missing", &link).unwrap();
    assert_ne!(tree_snapshot(root.path()), before);
}
