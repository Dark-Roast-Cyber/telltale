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
fn reader_opens_follow_no_link_below_the_anchor() {
    use std::io::Read;
    let temp = tempfile::tempdir().unwrap();
    let real = temp.path().join("real");
    let alias = temp.path().join("alias");
    let outside = temp.path().join("outside");
    fs::create_dir_all(real.join("home").join("store")).unwrap();
    fs::create_dir_all(&outside).unwrap();
    fs::write(real.join("home/store/inside.jsonl"), b"inside").unwrap();
    fs::write(outside.join("outside.jsonl"), b"outside").unwrap();
    link(&real, &alias);
    link(&outside, &real.join("home").join("linked"));
    let home = alias.join("home");
    let anchor = std::slice::from_ref(&home);
    let read = |path: &Path, anchors: &[PathBuf]| {
        open_file(path, anchors).map(|file| {
            file.map(|mut file| {
                let mut bytes = Vec::new();
                file.read_to_end(&mut bytes).unwrap();
                bytes
            })
        })
    };

    // The anchor alias is resolved once and the caller's spelling is kept.
    assert_eq!(
        read(&home.join("store/inside.jsonl"), anchor),
        Ok(Some(b"inside".to_vec()))
    );
    assert_eq!(
        read(&home.join("store/../store/inside.jsonl"), anchor),
        Ok(Some(b"inside".to_vec()))
    );
    // Without an anchor the linked ancestor is refused.
    assert_eq!(
        read(&home.join("store/inside.jsonl"), &[]),
        Err(Error::SymlinkRoot)
    );
    // A link below the anchor is never followed, nor is one reached by
    // climbing out of the anchor.
    assert_eq!(
        read(&home.join("linked/outside.jsonl"), anchor),
        Err(Error::SymlinkRoot)
    );
    assert_eq!(
        read(&home.join("../home/store/inside.jsonl"), anchor),
        Err(Error::SymlinkRoot)
    );
    assert_eq!(read(&home.join("store/missing.jsonl"), anchor), Ok(None));
    assert_eq!(read(&home.join("missing/x.jsonl"), anchor), Ok(None));
    assert_eq!(
        read(&home.join("store/inside.jsonl/x"), anchor),
        Err(Error::Traversal)
    );
    assert_eq!(read(&home.join(".."), anchor), Err(Error::Traversal));
    // A directory opens; the reader rejects it as a non-regular source.
    assert!(
        open_file(&home.join("store"), anchor)
            .unwrap()
            .unwrap()
            .metadata()
            .unwrap()
            .is_dir()
    );
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(
            outside.join("outside.jsonl"),
            real.join("home/store/leaf.jsonl"),
        )
        .unwrap();
        assert_eq!(
            read(&home.join("store/leaf.jsonl"), anchor),
            Err(Error::SymlinkRoot)
        );
    }
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
