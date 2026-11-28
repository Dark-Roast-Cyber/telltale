use super::*;

#[test]
fn hooks_allow_finds_a_rotated_decision() {
    let fixture = Fixture::new(&decision(|_| {}));
    let active = fixture.dir.path().join("records.jsonl");
    std::fs::rename(&active, active.with_file_name("records-2026-11-26.1.jsonl")).unwrap();
    std::fs::write(active, b"{}\n").unwrap();
    assert!(fixture.allow(true, "allow\n", None).is_ok());
    assert_eq!(fixture.written()[0].from_record, RECORD_ID);
}
#[test]
fn find_record_skips_oversized_lines_and_resumes_at_the_next_line() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("records.jsonl");
    let mut oversized = serde_json::to_vec(&json!({"record_id": "synthetic-oversized"})).unwrap();
    oversized.resize(16 * 1024 * 1024, b' ');
    oversized.extend_from_slice(b"\n{\"record_id\":\"synthetic-next\"}\n");
    std::fs::write(&path, oversized).unwrap();
    assert!(find_record(&path, "synthetic-oversized").is_err());
    assert_eq!(
        find_record(&path, "synthetic-next").unwrap()["record_id"],
        "synthetic-next"
    );
    let mut at_limit = serde_json::to_vec(&json!({"record_id": "synthetic-exact"})).unwrap();
    at_limit.resize(HOOKS_RECORD_MAX_INPUT_BYTES - 1, b' ');
    at_limit.push(b'\n');
    std::fs::write(&path, at_limit).unwrap();
    assert_eq!(
        find_record(&path, "synthetic-exact").unwrap()["record_id"],
        "synthetic-exact"
    );
}

#[test]
fn an_oversized_grant_lifecycle_is_refused_before_storing_the_grant() {
    let mut record = decision(|_| {});
    record["decision"]["rule_ids"] = json!([""]);
    let overhead = serde_json::to_vec(&record).unwrap().len() + 1;
    record["decision"]["rule_ids"][0] = json!("a".repeat(16 * 1024 * 1024 - overhead));
    let dir = tempfile::tempdir().unwrap();
    let records = dir.path().join("records.jsonl");
    std::fs::write(&records, format!("{record}\n")).unwrap();
    let mut config = Config::default();
    config.grants.enabled = true;
    let grants = dir.path().join("grants.d");
    let original_len = std::fs::metadata(&records).unwrap().len();
    let result = allow(
        &config,
        &records,
        &grants,
        RECORD_ID,
        None,
        true,
        &mut "allow\n".as_bytes(),
        &mut std::io::sink(),
    );
    assert!(matches!(result, Err(error) if error.contains("grant record exceeds")));
    assert!(!grants.exists());
    assert_eq!(std::fs::metadata(&records).unwrap().len(), original_len);
}

/// What the confirmation prints cannot be reordered or hidden by the
/// text of a record.
#[test]
fn printable_text_has_no_control_or_reordering_characters() {
    assert_eq!(
        printable("a\u{202e}b\u{1b}[2Jc\u{2066}d\u{200b}e"),
        "a b [2Jc d e"
    );
    assert_eq!(printable("tth.test.deny, Bash"), "tth.test.deny, Bash");
}

const RECORD_ID: &str = "tth:0123456789abcdef0123456789abcdef";

fn decision(edit: impl FnOnce(&mut Value)) -> Value {
    let mut record = json!({
        "record_id": RECORD_ID,
        "kind": "decision",
        "harness": {"name": "claude-code", "hook_event": "PreToolUse", "permission_mode": null},
        "action": {"tool_name": "Bash"},
        "evaluation": {"status": "complete", "visibility_limits": []},
        "decision": {
            "verdict": "ask", "returned": true, "basis": "action_score",
            "rule_ids": ["synthetic.b", "synthetic.a", "synthetic.b"],
        },
    });
    edit(&mut record);
    record
}

struct Fixture {
    dir: tempfile::TempDir,
    config: Config,
}

impl Fixture {
    fn new(record: &Value) -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("records.jsonl"),
            format!("not json\n{{\"record_id\": \"other\"}}\n{record}\n"),
        )
        .unwrap();
        let mut config = Config::default();
        config.grants.enabled = true;
        Self { dir, config }
    }

    fn grants(&self) -> PathBuf {
        self.dir.path().join("grants.d")
    }

    fn allow(
        &self,
        terminal: bool,
        answer: &str,
        project: Option<&str>,
    ) -> Result<Allowed, String> {
        let mut out = Vec::new();
        allow(
            &self.config,
            &self.dir.path().join("records.jsonl"),
            &self.grants(),
            RECORD_ID,
            project.map(PathBuf::from),
            terminal,
            &mut answer.as_bytes(),
            &mut out,
        )
    }

    fn written(&self) -> Vec<AlwaysGrant> {
        let (grants, left_out) = grants::load_dir(&self.grants());
        assert_eq!(left_out, []);
        grants
    }

    fn last_lifecycle(&self) -> Value {
        let wire = std::fs::read_to_string(self.dir.path().join("records.jsonl")).unwrap();
        let record =
            telltale_core::HooksRecordV1::from_json(wire.lines().last().unwrap().as_bytes())
                .unwrap();
        serde_json::to_value(record.lifecycle.unwrap()).unwrap()
    }
}

fn project() -> String {
    if cfg!(windows) {
        r"C:\work\app".to_owned()
    } else {
        "/work/app".to_owned()
    }
}

/// Without a terminal nothing is asked and nothing written.
#[test]
fn without_a_terminal_nothing_is_allowed() {
    let f = Fixture::new(&decision(|_| {}));
    let error = f.allow(false, "allow\n", None).unwrap_err();
    assert_eq!(
        error,
        "run this in a terminal yourself; it asks you to confirm"
    );
    assert!(!f.grants().exists());
}

/// Any answer but `allow` writes nothing.
#[test]
fn another_answer_allows_nothing() {
    let f = Fixture::new(&decision(|_| {}));
    for answer in ["", "\n", "yes\n", "allow it\n", "Allow\n"] {
        assert_eq!(f.allow(true, answer, None).unwrap_err(), "nothing allowed");
    }
    assert!(!f.grants().exists());
}

/// `allow` writes the grant the record names, and says what it allows.
#[test]
fn allow_writes_the_grant_of_the_record() {
    let f = Fixture::new(&decision(|_| {}));
    let mut out = Vec::new();
    let allowed = allow(
        &f.config,
        &f.dir.path().join("records.jsonl"),
        &f.grants(),
        RECORD_ID,
        Some(PathBuf::from(project())),
        true,
        &mut "  allow \n".as_bytes(),
        &mut out,
    )
    .unwrap();
    let shown = String::from_utf8(out).unwrap();
    assert!(
        shown.contains(&format!("scope: project {} and below", project())),
        "{shown}"
    );
    assert!(
        shown.contains("detections: synthetic.a, synthetic.b"),
        "{shown}"
    );
    assert!(shown.ends_with("Type allow to confirm: "), "{shown}");
    let written = f.written();
    assert_eq!(written.len(), 1);
    let grant = &written[0];
    assert_eq!(grant.id, allowed.id);
    assert_eq!(
        allowed.path,
        f.grants().join(format!("{}.yaml", allowed.id))
    );
    assert_eq!(grant.scope, AlwaysScope::Project);
    assert_eq!(grant.project, Some(PathBuf::from(project())));
    assert_eq!(grant.harness, "claude-code");
    assert_eq!(grant.tool, "Bash");
    assert_eq!(grant.rule_ids, ["synthetic.a", "synthetic.b"]);
    assert_eq!(grant.from_record, RECORD_ID);
    let lifecycle = f.last_lifecycle();
    assert_eq!(lifecycle["event"], "grant");
    assert_eq!(lifecycle["scope"], "project");
    assert_eq!(lifecycle["grant_id"], allowed.id.as_str());
    assert_eq!(lifecycle["offer_record_id"], RECORD_ID);
    assert_eq!(
        lifecycle["project_sha256"],
        sha256_hex(project().as_bytes()).as_str()
    );

    let user = f.allow(true, "allow\n", None).unwrap();
    let written = f.written();
    let grant = written.iter().find(|grant| grant.id == user.id).unwrap();
    assert_eq!(grant.scope, AlwaysScope::User);
    assert_eq!(grant.project, None);
    let lifecycle = f.last_lifecycle();
    assert_eq!(lifecycle["grant_id"], user.id);
    assert!(lifecycle.get("project_sha256").is_none());
    assert_eq!(written.len(), 2);
}

#[test]
fn an_escaped_tool_label_requires_its_native_name_before_confirmation() {
    const NATIVE: &str = "AKIASYNTHETIC0000000";
    let f = Fixture::new(&decision(|record| {
        record["action"]["tool_name"] = json!("tth-esc-5faaaacc6cfeecf6f7080b39f21abf8f");
    }));
    let error = f.allow(true, "synthetic-other\nallow\n", None).unwrap_err();
    assert_eq!(
        error,
        "tool name does not match the record; nothing allowed"
    );
    assert!(!f.grants().exists());

    let mut out = Vec::new();
    allow(
        &f.config,
        &f.dir.path().join("records.jsonl"),
        &f.grants(),
        RECORD_ID,
        None,
        true,
        &mut format!("{NATIVE}\nallow\n").as_bytes(),
        &mut out,
    )
    .unwrap();
    assert!(!String::from_utf8(out).unwrap().contains(NATIVE));
    let grant = f.written().remove(0);
    assert!(grant.covers("claude-code", NATIVE, None, &["synthetic.a".into()]));
    assert!(!grant.covers(
        "claude-code",
        "tth-esc-5faaaacc6cfeecf6f7080b39f21abf8f",
        None,
        &["synthetic.a".into()],
    ));
}

/// A record a grant could not cover is refused before anything is
/// asked, with the cause.
#[test]
fn a_record_no_grant_could_cover_is_refused() {
    type Edit = fn(&mut Value);
    let cases: [(&str, Edit); 10] = [
        ("not a decision record", |r| r["kind"] = "outcome".into()),
        ("not stopped", |r| r["decision"]["returned"] = false.into()),
        ("neither ask nor deny", |r| {
            r["decision"]["verdict"] = "allow".into()
        }),
        ("not by the policy's scores", |r| {
            r["decision"]["basis"] = "on_unevaluable".into()
        }),
        ("matched no rule", |r| r["decision"]["rule_ids"] = json!([])),
        ("tth.tamper.", |r| {
            r["decision"]["rule_ids"] = json!(["a", "tth.tamper.x"])
        }),
        ("did not see the whole call", |r| {
            r["evaluation"]["status"] = "visibility_limited".into();
        }),
        ("did not see the whole call", |r| {
            r["evaluation"]["visibility_limits"] = json!(["state_dir_unresolved"]);
        }),
        ("no known harness", |r| {
            r["harness"]["name"] = "other".into()
        }),
        ("no tool", |r| r["action"]["tool_name"] = Value::Null),
    ];
    for (cause, edit) in cases {
        let f = Fixture::new(&decision(edit));
        let error = f.allow(true, "allow\n", None).unwrap_err();
        assert!(error.contains(cause), "{cause}: {error}");
        assert!(error.contains("cannot be allowed"), "{error}");
        assert!(!f.grants().exists(), "{cause}");
    }
}

/// Under `covers: ask` a deny is refused; by default it is allowed.
#[test]
fn covers_ask_refuses_a_deny() {
    let mut f = Fixture::new(&decision(|r| r["decision"]["verdict"] = "deny".into()));
    f.config.grants.covers = GrantCover::Ask;
    let error = f.allow(true, "allow\n", None).unwrap_err();
    assert!(error.contains("hooks.grants.covers is ask"), "{error}");
    assert!(!f.grants().exists());
    f.config.grants.covers = GrantCover::AskAndDeny;
    assert!(f.allow(true, "allow\n", None).is_ok());
}

/// Grants off, an unknown record, or a missing records file: refused.
#[test]
fn grants_off_or_no_record_is_refused() {
    let mut f = Fixture::new(&decision(|_| {}));
    f.config.grants.enabled = false;
    assert_eq!(
        f.allow(true, "allow\n", None).unwrap_err(),
        "grants are off (hooks.grants.enabled: false)"
    );
    let f = Fixture::new(&decision(|r| r["record_id"] = "tth:other".into()));
    assert!(
        f.allow(true, "allow\n", None)
            .unwrap_err()
            .starts_with("no record ")
    );
    std::fs::remove_file(f.dir.path().join("records.jsonl")).unwrap();
    assert!(
        f.allow(true, "allow\n", None)
            .unwrap_err()
            .starts_with("cannot read the records file")
    );
    assert!(!f.grants().exists());
}

/// A relative `--project` is made absolute against the current
/// directory, without resolving symlinks; none means the current one.
#[test]
fn the_project_directory_is_made_absolute() {
    let current = std::env::current_dir().unwrap();
    assert_eq!(project_dir(None).unwrap(), current);
    let dir = project_dir(Some(Path::new("some/dir"))).unwrap();
    assert!(dir.is_absolute());
    assert_eq!(dir, current.join("some").join("dir"));
}

#[test]
fn allow_takes_one_record_and_exactly_one_scope() {
    let parse = |flags: &[&str]| allow_flags(flags).map(|(_, id, scope)| (id, scope));
    assert_eq!(
        parse(&["tth:1", "--user"]),
        Some(("tth:1".into(), AllowScope::User))
    );
    assert_eq!(
        parse(&["tth:1", "--project"]),
        Some(("tth:1".into(), AllowScope::Project(None)))
    );
    assert_eq!(
        parse(&["--project", "dir", "tth:1"]),
        Some(("tth:1".into(), AllowScope::Project(Some("dir".into()))))
    );
    assert_eq!(
        parse(&["tth:1", "--project=dir", "--config-dir", "r"]),
        Some(("tth:1".into(), AllowScope::Project(Some("dir".into()))))
    );
    for refused in [
        &["tth:1"][..],
        &["--user"],
        &["tth:1", "--user", "--project"],
        &["tth:1", "tth:2", "--user"],
        &["tth:1", "--user", "--bogus"],
        &["tth:1", "--project="],
    ] {
        assert_eq!(parse(refused), None, "{refused:?}");
    }
}
