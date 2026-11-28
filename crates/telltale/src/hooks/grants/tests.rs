use super::*;

/// `unix` as an absolute path on this platform: on Windows, on drive
/// `C:`. A relative path stays relative.
fn abs(unix: &str) -> String {
    if cfg!(windows) && unix.starts_with('/') {
        format!("C:{}", unix.replace('/', "\\"))
    } else {
        unix.to_owned()
    }
}

fn project_yaml() -> String {
    format!(
        "version: 1\nscope: project\nproject: {}\nharness: claude-code\ntool: Bash\nrule_ids: [a, b]\ncreated_at: 2026-11-22T00:00:00Z\nfrom_record: tth:1\n",
        abs("/work/app")
    )
}

const USER: &str = "version: 1\nscope: user\nharness: codex-cli\ntool: Bash\nrule_ids: [a]\ncreated_at: 2026-11-22T00:00:00Z\nfrom_record: tth:2\n";

fn put(dir: &Path, name: &str, text: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, text).unwrap();
    path
}

fn ids(ids: &[&str]) -> Vec<String> {
    ids.iter().map(|id| (*id).to_owned()).collect()
}

/// A project and a user file load with their IDs; a missing folder
/// holds nothing and reports nothing.
#[test]
fn valid_project_and_user_files_load() {
    let dir = tempfile::tempdir().unwrap();
    put(dir.path(), "g-00000000000a.yaml", &project_yaml());
    put(dir.path(), "g-00000000000b.yaml", USER);
    let (grants, left_out) = load_dir(dir.path());
    assert_eq!(left_out, []);
    assert_eq!(grants.len(), 2);
    assert_eq!(grants[0].id, "g-00000000000a");
    assert_eq!(grants[0].scope, AlwaysScope::Project);
    assert_eq!(
        grants[0].project.as_deref(),
        Some(Path::new(&abs("/work/app")))
    );
    assert_eq!(grants[0].rule_ids, ids(&["a", "b"]));
    assert_eq!(grants[1].id, "g-00000000000b");
    assert_eq!(grants[1].scope, AlwaysScope::User);
    assert_eq!(grants[1].harness, "codex-cli");
    assert_eq!(load_dir(&dir.path().join("absent")), (vec![], vec![]));
}

/// Each file that cannot be taken is left out with its cause, and the
/// valid file next to them still loads.
#[test]
fn each_defect_leaves_the_file_out() {
    let dir = tempfile::tempdir().unwrap();
    put(dir.path(), "g-000000000000.yaml", USER);
    let cases = [
        ("g-000000000001.yaml", "version: [", "does not parse"),
        (
            "g-000000000002.yaml",
            &format!("{USER}extra: 1\n"),
            "unknown one",
        ),
        (
            "g-000000000003.yaml",
            &USER.replace("rule_ids: [a]", "rule_ids: [tth.tamper.hook_entry_run]"),
            "tth.tamper.",
        ),
        (
            "g-000000000004.yaml",
            &project_yaml().replace(&abs("/work/app"), "work/app"),
            "not absolute",
        ),
        (
            "g-000000000005.yaml",
            &USER.replace("rule_ids: [a]", "rule_ids: []"),
            "names no rule",
        ),
        (
            "g-000000000006.yaml",
            &project_yaml().replace("[a, b]", "[b, a]"),
            "not sorted",
        ),
        (
            "g-000000000007.yaml",
            &project_yaml().replace("[a, b]", "[a, a]"),
            "repeat",
        ),
        (
            "g-000000000008.yaml",
            &project_yaml().replace(&format!("project: {}\n", abs("/work/app")), ""),
            "names no project",
        ),
        (
            "g-000000000009.yaml",
            &USER.replace("codex-cli", "no-such-harness"),
            "no known harness",
        ),
        (
            "g-00000000000a.yaml",
            &USER.replace("version: 1", "version: 2"),
            "unsupported version",
        ),
        (
            "g-00000000000b.yaml",
            &format!("{USER}{}", "#".repeat(64 * 1024)),
            "64 KiB",
        ),
        ("G-00000000000C.yaml", USER, "not a grant ID"),
        ("g-00000000000d.yml", USER, "not a grant ID"),
        ("g-0000000000e.yaml", USER, "not a grant ID"),
    ];
    for (name, text, _) in &cases {
        put(dir.path(), name, text);
    }
    std::fs::create_dir(dir.path().join("g-00000000000f.yaml")).unwrap();
    let (grants, left_out) = load_dir(dir.path());
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].id, "g-000000000000");
    for (name, _, cause) in &cases {
        let entry = left_out
            .iter()
            .find(|entry| entry.path == dir.path().join(name))
            .unwrap_or_else(|| panic!("{name} not left out: {left_out:?}"));
        assert!(entry.cause.contains(cause), "{name}: {}", entry.cause);
    }
    let folder = left_out
        .iter()
        .find(|entry| entry.path.ends_with("g-00000000000f.yaml"))
        .unwrap();
    assert_eq!(folder.cause, "not a regular file (a link or a folder)");
    assert_eq!(left_out.len(), cases.len() + 1);
}

/// A link named like a grant is left out even when its target is a
/// valid grant: the target could be changed outside the root.
#[cfg(unix)]
#[test]
fn a_linked_grant_file_is_left_out() {
    let dir = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let target = put(elsewhere.path(), "grant.yaml", USER);
    std::os::unix::fs::symlink(&target, dir.path().join("g-000000000001.yaml")).unwrap();
    put(dir.path(), "g-000000000002.yaml", USER);
    let (grants, left_out) = load_dir(dir.path());
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].id, "g-000000000002");
    assert_eq!(left_out.len(), 1);
    assert_eq!(left_out[0].cause, "not a regular file (a link or a folder)");
}

/// Past 256 files the rest are left out, in name order.
#[test]
fn at_most_256_files_are_read() {
    let dir = tempfile::tempdir().unwrap();
    for n in 0..MAX_GRANT_FILES + 2 {
        put(dir.path(), &format!("g-{n:012x}.yaml"), USER);
    }
    let (grants, left_out) = load_dir(dir.path());
    assert_eq!(grants.len(), MAX_GRANT_FILES);
    assert_eq!(left_out.len(), 2);
    assert!(
        left_out[0]
            .path
            .ends_with(format!("g-{:012x}.yaml", MAX_GRANT_FILES))
    );
    assert!(left_out.iter().all(|entry| entry.cause.contains("256")));
}

/// A written grant loads back under the ID `write` returned, and
/// `remove` takes it away; a grant `load_dir` would leave out is not
/// written.
#[test]
fn write_then_load_then_remove() {
    let dir = tempfile::tempdir().unwrap();
    let folder = dir.path().join(GRANTS_DIR);
    let mut grant: AlwaysGrant = serde_yaml::from_str(&project_yaml()).unwrap();
    let id = write(&folder, &grant).unwrap();
    assert!(is_grant_id(&id), "{id}");
    let (grants, left_out) = load_dir(&folder);
    assert_eq!(left_out, []);
    grant.id = id.clone();
    assert_eq!(grants, [grant.clone()]);
    remove(&folder, &id).unwrap();
    assert_eq!(load_dir(&folder), (vec![], vec![]));
    assert!(remove(&folder, "../x").is_err());
    grant.rule_ids = ids(&["tth.tamper.x"]);
    assert!(write(&folder, &grant).is_err());
    assert_eq!(load_dir(&folder), (vec![], vec![]));
}

#[test]
fn a_project_covers_itself_and_below_by_components() {
    let dir = &abs("/a/b");
    let dir = Path::new(dir);
    assert!(within(dir, Path::new(&abs("/a/b"))));
    assert!(within(dir, Path::new(&abs("/a/b/"))));
    assert!(within(Path::new(&abs("/a/b/")), Path::new(&abs("/a/b"))));
    assert!(within(dir, Path::new(&abs("/a/b/c/d"))));
    assert!(!within(dir, Path::new(&abs("/a/bc"))));
    assert!(!within(dir, Path::new(&abs("/a"))));
    assert!(within(dir, Path::new(&abs("/a/x/../b/./c"))));
    assert!(!within(dir, Path::new(&abs("/a/b/../c"))));
    assert!(!within(dir, Path::new(&abs("/a/b/.."))));
    assert!(within(
        Path::new(&abs("/a/./b/c/..")),
        Path::new(&abs("/a/b/c"))
    ));
    assert!(!within(dir, Path::new("a/b")));
    assert!(!within(Path::new("a/b"), Path::new("a/b")));
    assert!(within(Path::new(&abs("/")), Path::new(&abs("/../x"))));
}

/// Outside Windows, case matters: another spelling is another directory.
#[cfg(not(windows))]
#[test]
fn outside_windows_case_matters() {
    assert!(!within(Path::new("/Work/App"), Path::new("/work/app/src")));
    assert!(!within(Path::new("/work/app"), Path::new("/WORK/app")));
}

/// On Windows a drive or folder in another case is the same directory.
#[cfg(windows)]
#[test]
fn on_windows_case_does_not_matter() {
    assert!(within(
        Path::new(r"C:\Work\App"),
        Path::new(r"c:\work\app\src")
    ));
    assert!(!within(
        Path::new(r"C:\Work\App"),
        Path::new(r"c:\work\apple")
    ));
}

/// Harness, tool and every detection must match; a project grant needs
/// a known cwd in the project; a project grant wins over a user grant.
#[test]
fn coverage_needs_harness_tool_every_detection_and_the_project() {
    let project: AlwaysGrant = AlwaysGrant {
        id: "g-00000000000a".into(),
        ..serde_yaml::from_str(&project_yaml()).unwrap()
    };
    let user = AlwaysGrant {
        id: "g-00000000000b".into(),
        harness: "claude-code".into(),
        rule_ids: ids(&["a", "b", "c"]),
        ..serde_yaml::from_str(USER).unwrap()
    };
    let both = [user.clone(), project.clone()];
    let found = |cwd: Option<&str>, tool: &str, rules: &[&str]| {
        covering(&both, "claude-code", tool, cwd, &ids(rules)).map(|grant| grant.id.as_str())
    };
    assert_eq!(
        found(Some(abs("/work/app/src").as_str()), "Bash", &["a"]),
        Some("g-00000000000a")
    );
    assert_eq!(
        found(Some(abs("/elsewhere").as_str()), "Bash", &["a", "b"]),
        Some("g-00000000000b")
    );
    assert_eq!(found(None, "Bash", &["b"]), Some("g-00000000000b"));
    assert_eq!(
        found(Some(abs("/work/app").as_str()), "Bash", &["a", "c"]),
        Some("g-00000000000b")
    );
    assert_eq!(
        found(Some(abs("/work/app").as_str()), "Bash", &["a", "d"]),
        None
    );
    assert_eq!(found(Some(abs("/work/app").as_str()), "bash", &["a"]), None);
    assert_eq!(found(Some(abs("/work/app").as_str()), "Bash", &[]), None);
    assert!(!project.covers(
        "codex-cli",
        "Bash",
        Some(abs("/work/app").as_str()),
        &ids(&["a"])
    ));
    assert!(!project.covers("claude-code", "Bash", None, &ids(&["a"])));
    assert!(!project.covers(
        "claude-code",
        "Bash",
        Some(abs("/work/apple").as_str()),
        &ids(&["a"])
    ));
}
