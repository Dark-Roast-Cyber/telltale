use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::event::{Event3Record, path_hash, terminal_session_id};
use telltale_schema::source::Source;
use telltale_sources::opencode_export::{ExportConfig, ExportError, export_session};

const SESSION: &str = "ses_0123456789abcdefghijklmn";

fn helper() -> &'static Path {
    static BINARY: OnceLock<PathBuf> = OnceLock::new();
    BINARY.get_or_init(|| {
        let dir = tempfile::tempdir().unwrap().keep();
        let out = dir.join(format!("helper{}", std::env::consts::EXE_SUFFIX));
        let status = std::process::Command::new("rustc")
            .args(["--edition=2024", "--crate-name", "opencode_export_helper"])
            .arg(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/support/opencode_export_helper.rs"),
            )
            .arg("-o")
            .arg(&out)
            .status()
            .unwrap();
        assert!(status.success());
        out
    })
}

// Known-field slice of the audited OpenCode 1.18.25 native schema.
fn fixture(session: &str) -> serde_json::Value {
    serde_json::json!({"info":{"id":session},"messages":[{
        "info":{"id":"msg_synthetic","sessionID":session,"role":"assistant","time":{"created":1700000000000u64}},
        "parts":[{"id":"prt_synthetic","messageID":"msg_synthetic","sessionID":session,
            "type":"tool","callID":"call_explicit_synthetic","tool":"synthetic_tool",
            "state":{"status":"completed","input":{"redacted":"tool-input:prt_synthetic"},
                "output":"[redacted:tool-output:prt_synthetic]","time":{"start":1700000000001u64,"end":1700000000002u64}}}]
    }]})
}

fn event(source: &Source, session: &str, client: &str) -> Event3Record {
    use telltale_schema::event::{ActivityEventInput, activity_event};
    let native = activity_event(ActivityEventInput {
        client: ClientId::OpenCode,
        agent: None,
        model: None,
        provider: None,
        session_id: session.into(),
        source_path_hash: path_hash(&source.path),
        tool_name: None,
        tags: vec![],
        evidence: vec![],
        risk_contributions: vec![],
        event_time: None,
    })
    .unwrap();
    let mut value = serde_json::to_value(native).unwrap();
    value["session_id"] = terminal_session_id(session).into();
    value["client"] = client.into();
    value["source_path_hash"] = path_hash(&source.path).into();
    Event3Record::from_json(&serde_json::to_vec(&value).unwrap()).unwrap()
}

struct Harness {
    dir: tempfile::TempDir,
    source: Source,
    config: ExportConfig,
}
impl Harness {
    fn new(mode: &str, session: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join(format!(
            "opencode helper;literal{}",
            std::env::consts::EXE_SUFFIX
        ));
        std::fs::copy(helper(), &executable).unwrap();
        for (name, data) in [
            ("mode", mode.to_owned()),
            ("export.json", fixture(session).to_string()),
            (
                "listing.json",
                serde_json::json!([{"id":session,"title":"UNKNOWN_CANARY"}]).to_string(),
            ),
        ] {
            std::fs::write(dir.path().join(name), data).unwrap();
        }
        // Deliberately not a SQLite database. The adapter must never open it.
        std::fs::create_dir(dir.path().join("opencode")).unwrap();
        std::fs::write(
            dir.path().join("opencode/opencode.db"),
            b"SYNTHETIC_NOT_SQLITE",
        )
        .unwrap();
        let source = telltale_sources::discovery::discover_sources(dir.path())
            .unwrap()
            .into_iter()
            .find(|source| {
                source.client == ClientId::OpenCode && source.source_id == "opencode.sqlite"
            })
            .unwrap();
        let config = ExportConfig {
            executable: Some(executable),
            ..Default::default()
        };
        Self {
            dir,
            source,
            config,
        }
    }
    fn run(
        &self,
        session: &str,
    ) -> Result<Vec<telltale_schema::canonical::NormalizedRecordV1>, ExportError> {
        export_session(
            &event(&self.source, session, "opencode"),
            &self.source,
            &self.config,
        )
    }
    fn reclaimed(&self) {
        assert!(self.dir.path().join("ready").exists());
        let address = std::fs::read_to_string(self.dir.path().join("address")).unwrap();
        assert!(
            std::net::TcpListener::bind(&address).is_ok(),
            "direct child still owns listener"
        );
        #[cfg(unix)]
        {
            let pid: libc::pid_t = std::fs::read_to_string(self.dir.path().join("pid"))
                .unwrap()
                .parse()
                .unwrap();
            let mut status = 0;
            // SAFETY: valid status pointer; WNOHANG never waits on a running child.
            let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            assert_eq!(waited, -1, "direct child was not reaped by the adapter");
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ECHILD)
            );
        }
        assert_eq!(
            std::fs::read(&self.source.path).unwrap(),
            b"SYNTHETIC_NOT_SQLITE"
        );
    }
}

#[test]
fn direct_safe_session_and_explicit_linkage() {
    let h = Harness::new("success", SESSION);
    assert_eq!(terminal_session_id(SESSION), SESSION);
    let records = h.run(SESSION).unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(
        std::fs::read_to_string(h.dir.path().join("argv")).unwrap(),
        format!("--pure\nexport\n{SESSION}\n--sanitize")
    );
    assert!(h.dir.path().join("stdin-closed").exists());
    let timeline = telltale_detect::timeline::build_exported_session_timeline(&records).unwrap();
    assert_eq!(timeline.entries[0].linked_entry_index, Some(1));
    assert_eq!(timeline.entries[1].linked_entry_index, Some(0));
    assert_eq!(
        records[0].meta().provenance.source_path_hash,
        path_hash(&h.source.path)
    );
    assert_eq!(
        records[0].meta().provenance.source_event_id.as_deref(),
        Some("prt_synthetic")
    );
    assert!(records[0].meta().provenance.offset.is_none());
    h.reclaimed();
}

#[test]
fn opaque_current_mixed_case_session_fallback() {
    let session = "ses_0123456789ABCdefGHIjklmno";
    assert_ne!(terminal_session_id(session), session);
    let h = Harness::new("success", session);
    assert_eq!(h.run(session).unwrap().len(), 2);
    assert_eq!(
        std::fs::read_to_string(h.dir.path().join("listing-argv")).unwrap(),
        "--pure\nsession\nlist\n--format\njson\n--max-count\n256"
    );
    assert!(
        std::fs::read_to_string(h.dir.path().join("argv"))
            .unwrap()
            .contains(session)
    );
    h.reclaimed();
}

#[test]
fn no_and_multiple_candidates() {
    let session = "ses_0123456789ABCdefGHIjklmno";
    for (list, expected) in [
        ("", ExportError::SessionUnavailable),
        ("[]", ExportError::SessionUnavailable),
        (
            r#"[{"id":"ses_unrelated","title":"UNKNOWN_CANARY"}]"#,
            ExportError::SessionUnavailable,
        ),
        (
            &format!(r#"[{{"id":"{session}"}},{{"id":"{session}"}}]"#),
            ExportError::AmbiguousSession,
        ),
    ] {
        let h = Harness::new("success", session);
        std::fs::write(h.dir.path().join("listing.json"), list).unwrap();
        assert_eq!(h.run(session).unwrap_err(), expected);
        h.reclaimed();
    }
}

#[test]
fn mismatches_prevent_spawn() {
    let h = Harness::new("success", SESSION);
    let wrong = event(&h.source, SESSION, "codex");
    assert_eq!(
        export_session(&wrong, &h.source, &h.config).unwrap_err(),
        ExportError::SourceMismatch
    );
    let mut source = h.source.clone();
    source.path = source.path.with_file_name("different.db");
    assert_eq!(
        export_session(&event(&h.source, SESSION, "opencode"), &source, &h.config).unwrap_err(),
        ExportError::SourceMismatch
    );
    assert!(!h.dir.path().join("argv").exists());
    for which in 0..3 {
        let mut source = h.source.clone();
        match which {
            0 => source.client = ClientId::Codex,
            1 => source.kind = SourceKind::LegacyJson,
            _ => source.source_id = "opencode.legacy_json".into(),
        }
        assert_eq!(
            export_session(&event(&h.source, SESSION, "opencode"), &source, &h.config).unwrap_err(),
            ExportError::SourceMismatch
        );
    }
    assert!(!h.dir.path().join("argv").exists());
}

#[test]
fn subprocess_failures_reclaim_direct_child() {
    for (mode, expected) in [
        ("stdout", ExportError::StdoutLimit),
        ("stderr", ExportError::StderrLimit),
        ("timeout", ExportError::Timeout),
        ("nonzero", ExportError::NonzeroExit),
    ] {
        let mut h = Harness::new(mode, SESSION);
        h.config.limits.deadline = std::time::Duration::from_secs(2);
        h.config.limits.export_bytes = 8192;
        h.config.limits.stderr_bytes = 8192;
        let start = std::time::Instant::now();
        let error = h.run(SESSION).unwrap_err();
        assert_eq!(error, expected);
        assert!(!format!("{error:?} {error}").contains("SYNTHETIC_PRIVATE_STDERR"));
        assert!(start.elapsed() < std::time::Duration::from_secs(5));
        h.reclaimed();
    }
}

#[test]
fn simultaneous_pipes_do_not_deadlock() {
    let mut h = Harness::new("both", SESSION);
    h.config.limits.export_bytes = 8192;
    h.config.limits.stderr_bytes = 8192;
    assert!(matches!(
        h.run(SESSION),
        Err(ExportError::StdoutLimit | ExportError::StderrLimit)
    ));
    h.reclaimed();
}

#[test]
fn malformed_truncated_and_huge_exports_fail_closed() {
    for payload in [
        "{".to_owned(),
        "{}".into(),
        "[".repeat(1000),
        "x".repeat(9 * 1024 * 1024),
    ] {
        let h = Harness::new("success", SESSION);
        std::fs::write(h.dir.path().join("export.json"), payload).unwrap();
        assert!(matches!(
            h.run(SESSION),
            Err(ExportError::MalformedExport | ExportError::JsonDepth | ExportError::StdoutLimit)
        ));
        h.reclaimed();
    }
}

#[test]
fn defaults_are_finite_and_invalid_limits_prevent_spawn() {
    let mut h = Harness::new("success", SESSION);
    let limits = &h.config.limits;
    assert_eq!(limits.candidates, 256);
    assert_eq!(limits.list_bytes, 1024 * 1024);
    assert_eq!(limits.export_bytes, 8 * 1024 * 1024);
    assert_eq!(limits.stderr_bytes, 64 * 1024);
    assert_eq!(limits.deadline, std::time::Duration::from_secs(10));
    assert_eq!(limits.json_depth, 64);
    assert_eq!(limits.records, 8192);
    h.config.limits.records = 0;
    assert_eq!(h.run(SESSION).unwrap_err(), ExportError::InvalidLimits);
    h.config.limits.records = 8193;
    assert_eq!(h.run(SESSION).unwrap_err(), ExportError::InvalidLimits);
    assert!(!h.dir.path().join("argv").exists());
}

#[test]
fn missing_executable_and_source_are_safe() {
    let mut h = Harness::new("success", SESSION);
    h.config.executable = Some(h.dir.path().join(format!(
        "SYNTHETIC_PRIVATE_PATH{}",
        std::env::consts::EXE_SUFFIX
    )));
    assert_eq!(h.run(SESSION).unwrap_err(), ExportError::Spawn);
    std::fs::remove_file(&h.source.path).unwrap();
    assert_eq!(h.run(SESSION).unwrap_err(), ExportError::SourceUnavailable);
    assert!(!h.dir.path().join("argv").exists());
}

#[test]
fn listing_count_bytes_json_and_option_ids_fail_closed() {
    let session = "ses_0123456789ABCdefGHIjklmno";
    for (list, expected) in [
        ("{".into(), ExportError::MalformedListing),
        (
            serde_json::json!([{"id":"--help"}]).to_string(),
            ExportError::InvalidSessionId,
        ),
        (
            serde_json::json!([{"id":"ses_x --help"}]).to_string(),
            ExportError::InvalidSessionId,
        ),
        (
            serde_json::json!([{"id":"ses_x;exit"}]).to_string(),
            ExportError::InvalidSessionId,
        ),
        (
            serde_json::json!(vec![serde_json::json!({"id":"ses_unrelated"}); 257]).to_string(),
            ExportError::CandidateLimit,
        ),
        ("x".repeat(1024 * 1024 + 1), ExportError::StdoutLimit),
        ("[".repeat(65), ExportError::JsonDepth),
    ] {
        let h = Harness::new("success", session);
        std::fs::write(h.dir.path().join("listing.json"), list).unwrap();
        assert_eq!(h.run(session).unwrap_err(), expected);
        assert!(
            std::fs::read_to_string(h.dir.path().join("argv"))
                .unwrap()
                .contains("session\nlist")
        );
        h.reclaimed();
    }
}

#[test]
fn listing_process_failures_reclaim_direct_child() {
    let session = "ses_0123456789ABCdefGHIjklmno";
    for (mode, expected) in [
        ("stdout", ExportError::StdoutLimit),
        ("stderr", ExportError::StderrLimit),
        ("timeout", ExportError::Timeout),
        ("nonzero", ExportError::NonzeroExit),
    ] {
        let mut h = Harness::new(mode, session);
        h.config.limits.deadline = std::time::Duration::from_secs(2);
        h.config.limits.list_bytes = 8192;
        h.config.limits.stderr_bytes = 8192;
        assert_eq!(h.run(session).unwrap_err(), expected);
        h.reclaimed();
    }
}

#[test]
fn all_identity_paths_are_checked_without_linkage_inference() {
    for pointer in [
        "/info/id",
        "/messages/0/info/sessionID",
        "/messages/0/parts/0/sessionID",
        "/messages/0/parts/0/messageID",
        "/messages/0/parts/0/callID",
    ] {
        let h = Harness::new("success", SESSION);
        let mut value = fixture(SESSION);
        *value.pointer_mut(pointer).unwrap() = "".into();
        std::fs::write(h.dir.path().join("export.json"), value.to_string()).unwrap();
        assert_eq!(h.run(SESSION).unwrap_err(), ExportError::IdentityMismatch);
        h.reclaimed();
    }
    let h = Harness::new("success", SESSION);
    let mut value = fixture(SESSION);
    value["messages"][0]["parts"][0]
        .as_object_mut()
        .unwrap()
        .remove("callID");
    std::fs::write(h.dir.path().join("export.json"), value.to_string()).unwrap();
    assert_eq!(h.run(SESSION).unwrap_err(), ExportError::MalformedExport);
    h.reclaimed();
}

#[test]
fn duplicate_calls_and_parts_fail_closed() {
    for distinct_part in [false, true] {
        let h = Harness::new("success", SESSION);
        let mut value = fixture(SESSION);
        let mut second = value["messages"][0]["parts"][0].clone();
        if distinct_part {
            second["id"] = "prt_second".into();
        }
        value["messages"][0]["parts"]
            .as_array_mut()
            .unwrap()
            .push(second);
        std::fs::write(h.dir.path().join("export.json"), value.to_string()).unwrap();
        assert_eq!(h.run(SESSION).unwrap_err(), ExportError::IdentityMismatch);
        h.reclaimed();
    }
}

#[test]
fn canonical_record_and_depth_limits_reject_without_truncation() {
    let mut h = Harness::new("success", SESSION);
    h.config.limits.records = 1;
    assert_eq!(h.run(SESSION).unwrap_err(), ExportError::RecordLimit);
    h.reclaimed();
    h.config.limits.records = 2;
    assert_eq!(h.run(SESSION).unwrap().len(), 2);
    h.config.limits.json_depth = 2;
    assert_eq!(h.run(SESSION).unwrap_err(), ExportError::JsonDepth);
    h.reclaimed();
}

#[test]
fn unknown_fields_are_ignored_and_repeated_parses_are_deterministic() {
    let h = Harness::new("success", SESSION);
    let before = format!("{:?}", h.run(SESSION).unwrap());
    let mut value = fixture(SESSION);
    value["unknown"] = serde_json::json!({"private":"UNKNOWN_CANARY"});
    value["info"]["directory"] = "UNKNOWN_CANARY".into();
    value["messages"][0]["info"]["modelID"] = "UNKNOWN_CANARY".into();
    value["messages"][0]["parts"][0]["metadata"] = serde_json::json!({"private":"UNKNOWN_CANARY"});
    value["messages"][0]["parts"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({"type":"future-part","private":"UNKNOWN_CANARY"}));
    std::fs::write(h.dir.path().join("export.json"), value.to_string()).unwrap();
    assert_eq!(format!("{:?}", h.run(SESSION).unwrap()), before);
    assert_eq!(format!("{:?}", h.run(SESSION).unwrap()), before);
    h.reclaimed();
}

#[test]
fn private_text_arguments_results_and_identifiers_are_terminal_safe() {
    let h = Harness::new("success", SESSION);
    let canaries = [
        "/synthetic/private/FILE_CANARY",
        r"C:\synthetic\PRIVATE_PATH",
        "SYNTHETIC_COMMAND_CANARY",
        "SYNTHETIC_OUTPUT_CANARY",
        "SYNTHETIC_TEXT_CANARY",
        "SYNTHETIC_CREDENTIAL_CANARY",
    ];
    let mut value = fixture(SESSION);
    let part = &mut value["messages"][0]["parts"][0];
    part["callID"] = "SYNTHETIC_CALL_CANARY".into();
    part["tool"] = canaries[0].into();
    part["state"]["input"] =
        serde_json::json!({"command":canaries[2], "path":canaries[1], "api_key":canaries[5]});
    part["state"]["status"] = "error".into();
    part["state"]["error"] = format!("{} {}", canaries[3], canaries[5]).into();
    value["messages"][0]["parts"].as_array_mut().unwrap().push(serde_json::json!({
        "type":"text","id":"prt_text","sessionID":SESSION,"messageID":"msg_synthetic","text":canaries[4]
    }));
    std::fs::write(h.dir.path().join("export.json"), value.to_string()).unwrap();
    let records = h.run(SESSION).unwrap();
    let telltale_schema::canonical::NormalizedRecordV1::ToolCall(call) = &records[0] else {
        panic!("missing call")
    };
    let telltale_schema::canonical::NormalizedRecordV1::ToolResult(result) = &records[1] else {
        panic!("missing result")
    };
    assert_eq!(call.call_id.as_deref(), Some("SYNTHETIC_CALL_CANARY"));
    assert_eq!(call.call_id, result.call_id);
    assert_eq!(result.is_error, Some(true));
    let timeline = telltale_detect::timeline::build_exported_session_timeline(&records).unwrap();
    let public = serde_json::to_string(&timeline).unwrap();
    for (i, canary) in canaries
        .iter()
        .chain(["SYNTHETIC_CALL_CANARY"].iter())
        .enumerate()
    {
        assert!(!public.contains(canary), "terminal marker leak: case {i}");
    }
    assert_eq!(timeline.entries[1].linked_entry_index, Some(0));
    h.reclaimed();
}

#[test]
fn pending_running_completed_and_error_have_distinct_results() {
    for (status, count, error) in [
        ("pending", 1, None),
        ("running", 1, None),
        ("completed", 2, Some(false)),
        ("error", 2, Some(true)),
    ] {
        let h = Harness::new("success", SESSION);
        let mut value = fixture(SESSION);
        value["messages"][0]["parts"][0]["state"]["status"] = status.into();
        value["messages"][0]["parts"][0]["state"]["error"] = "synthetic error".into();
        std::fs::write(h.dir.path().join("export.json"), value.to_string()).unwrap();
        let records = h.run(SESSION).unwrap();
        assert_eq!(records.len(), count);
        if let Some(error) = error {
            let telltale_schema::canonical::NormalizedRecordV1::ToolResult(result) = &records[1]
            else {
                panic!("missing result")
            };
            assert_eq!(result.is_error, Some(error));
        }
        h.reclaimed();
    }
}

#[test]
fn native_1_18_25_synthetic_export_fixture_links() {
    let h = Harness::new("success", SESSION);
    // Native isolated import/export, with only the host-dependent info.path replaced.
    std::fs::write(
        h.dir.path().join("export.json"),
        include_bytes!("fixtures/opencode-export/opencode-1.18.25-sanitized.json"),
    )
    .unwrap();
    let records = h.run(SESSION).unwrap();
    let telltale_schema::canonical::NormalizedRecordV1::ToolCall(call) = &records[0] else {
        panic!("missing call")
    };
    assert_eq!(call.call_id.as_deref(), Some("call_synthetic_explicit"));
    let timeline = telltale_detect::timeline::build_exported_session_timeline(&records).unwrap();
    assert_eq!(timeline.entry_count, 2);
    assert_eq!(timeline.entries[0].linked_entry_index, Some(1));
    assert_eq!(timeline.entries[1].linked_entry_index, Some(0));
    h.reclaimed();
}

#[test]
fn exact_stdout_and_stderr_caps_are_not_truncation() {
    let mut h = Harness::new("stderr-exact", SESSION);
    h.config.limits.export_bytes = fixture(SESSION).to_string().len();
    h.config.limits.stderr_bytes = 8192;
    assert_eq!(h.run(SESSION).unwrap().len(), 2);
    h.reclaimed();
    h.config.limits.export_bytes -= 1;
    assert_eq!(h.run(SESSION).unwrap_err(), ExportError::StdoutLimit);
    h.reclaimed();
    h.config.limits.export_bytes += 1;
    h.config.limits.stderr_bytes -= 1;
    assert_eq!(h.run(SESSION).unwrap_err(), ExportError::StderrLimit);
    h.reclaimed();
}

#[test]
fn empty_native_session_has_no_public_timeline() {
    let h = Harness::new("success", SESSION);
    std::fs::write(
        h.dir.path().join("export.json"),
        serde_json::json!({"info":{"id":SESSION},"messages":[]}).to_string(),
    )
    .unwrap();
    assert_eq!(h.run(SESSION).unwrap_err(), ExportError::SessionUnavailable);
    h.reclaimed();
}

#[cfg(windows)]
#[test]
fn windows_batch_paths_cannot_select_an_implicit_shell() {
    let mut h = Harness::new("success", SESSION);
    for filename in [
        "opencode.cmd",
        "opencode.BAT",
        "opencode.cmd ",
        "opencode.cmd.",
    ] {
        h.config.executable = Some(h.dir.path().join(filename));
        assert_eq!(h.run(SESSION).unwrap_err(), ExportError::InvalidExecutable);
    }
    assert!(!h.dir.path().join("argv").exists());
}
