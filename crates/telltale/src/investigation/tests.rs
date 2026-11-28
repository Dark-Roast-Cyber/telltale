use super::super::investigation::*;
use std::fs;
use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::event::{ActivityEventInput, Event3Record, activity_event, path_hash};
use telltale_schema::source::Source;
use telltale_sources::discovery::discover_sources;

fn tempdir() -> tempfile::TempDir {
    tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap()
}

fn event(source: &Source, session: &str) -> Event3Record {
    Event3Record::from_json(&event_json(source, session)).unwrap()
}

fn event_json(source: &Source, session: &str) -> Vec<u8> {
    let event = activity_event(ActivityEventInput {
        client: source.client,
        session_id: session.into(),
        source_path_hash: path_hash(&source.path),
        agent: None,
        model: None,
        provider: None,
        tool_name: None,
        tags: vec![],
        evidence: vec![],
        risk_contributions: vec![],
        event_time: None,
    })
    .unwrap();
    serde_json::to_vec(&event).unwrap()
}

fn codex(dir: &std::path::Path, payload: &str) -> Source {
    fs::create_dir_all(dir.join("codex/sessions")).unwrap();
    fs::write(dir.join("codex/sessions/synthetic.jsonl"), payload).unwrap();
    discover_sources(dir)
        .unwrap()
        .into_iter()
        .find(|s| s.source_id == "codex.sessions")
        .unwrap()
}

const JSONL: &str = concat!(
    "{\"type\":\"session_meta\",\"payload\":{\"session_id\":\"synthetic-session\"}}\n",
    "{\"type\":\"response_item\",\"payload\":{\"type\":\"function_call\",\"name\":\"shell\",\"call_id\":\"EXPLICIT_CALL_CANARY\",\"arguments\":\"{\\\"command\\\":\\\"ordinary_content_canary\\\"}\"}}\n",
    "{\"type\":\"response_item\",\"payload\":{\"type\":\"function_call_output\",\"call_id\":\"EXPLICIT_CALL_CANARY\",\"output\":\"/synthetic/private/OUTPUT_CANARY\"}}\n"
);

fn context(
    backend: &SessionInvestigator,
    input: &Event3Record,
    index: usize,
    before: usize,
    after: usize,
    content: ContextContent,
) -> ContextInvestigationResult {
    backend.investigate_context(&ContextInvestigationRequest {
        event: input,
        anchor: ContextAnchor::TimelineIndex(index),
        before,
        after,
        content,
    })
}

fn claude(dir: &std::path::Path, payload: &str) -> Source {
    fs::create_dir_all(dir.join("claude/projects")).unwrap();
    fs::write(dir.join("claude/projects/context.jsonl"), payload).unwrap();
    discover_sources(dir)
        .unwrap()
        .into_iter()
        .find(|source| source.source_id == "claude.projects")
        .unwrap()
}

#[test]
fn investigation_opencode_is_deferred_without_launch_or_artifact_changes() {
    let dir = tempdir();
    let store = dir.path().join("opencode");
    fs::create_dir(&store).unwrap();
    let paths = ["opencode.db", "opencode.db-wal", "opencode.db-shm"].map(|name| store.join(name));
    for path in &paths {
        fs::write(path, b"SYNTHETIC_NOT_SQLITE").unwrap();
    }
    let before = paths.each_ref().map(|path| {
        (
            fs::read(path).unwrap(),
            fs::metadata(path).unwrap().modified().unwrap(),
        )
    });
    let bin = dir.path().join("bin");
    fs::create_dir(&bin).unwrap();
    let executable = bin.join(format!("opencode{}", std::env::consts::EXE_SUFFIX));
    assert!(
        std::process::Command::new("rustc")
            .args([
                "--edition=2024",
                "--crate-name",
                "investigation_no_launch_helper"
            ])
            .arg(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("src/investigation/tests/helper.rs")
            )
            .arg("-o")
            .arg(&executable)
            .status()
            .unwrap()
            .success()
    );
    #[cfg(target_os = "linux")]
    let access_probe = {
        use std::os::fd::{FromRawFd, OwnedFd};
        use std::os::unix::ffi::OsStrExt;
        // SAFETY: inotify takes no pointers; ownership is transferred once.
        let raw = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        assert!(raw >= 0);
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        for path in [dir.path(), store.as_path()]
            .into_iter()
            .chain(paths.iter().map(|p| p.as_path()))
        {
            let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
            // SAFETY: valid descriptor and NUL-terminated synthetic pathname.
            assert!(
                unsafe {
                    libc::inotify_add_watch(raw, path.as_ptr(), libc::IN_OPEN | libc::IN_ACCESS)
                } >= 0
            );
        }
        fd
    };
    // Only this child receives a synthetic PATH; no process-global environment
    // mutation or installed/live OpenCode executable can enter the test.
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "investigation::tests::investigation_opencode_deferred_probe",
            "--ignored",
        ])
        .env("PATH", &bin)
        .env("OPENCODE_DB", &paths[0])
        .env("TELLTALE_INVESTIGATION_PROBE_ROOT", dir.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let mut buffer = [0u8; 4096];
        // SAFETY: writable buffer with its exact length and a live descriptor.
        let read = unsafe {
            libc::read(
                access_probe.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
            )
        };
        assert_eq!(
            read, -1,
            "investigation opened/read a synthetic source or discovery directory"
        );
        assert_eq!(
            std::io::Error::last_os_error().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
    assert!(!bin.join("launched").exists());
    assert_eq!(fs::read_dir(&store).unwrap().count(), 3);
    let after = paths.each_ref().map(|path| {
        (
            fs::read(path).unwrap(),
            fs::metadata(path).unwrap().modified().unwrap(),
        )
    });
    assert_eq!(before, after);
}

#[test]
#[ignore = "executed only by the synthetic no-launch subprocess test"]
fn investigation_opencode_deferred_probe() {
    use telltale_sources::acquisition::{
        AcquisitionError, AcquisitionOptions, DirectReadLimits, acquire_source_bounded,
    };
    let root = std::path::PathBuf::from(
        std::env::var_os("TELLTALE_INVESTIGATION_PROBE_ROOT").expect("synthetic probe root"),
    );
    let source = Source {
        client: ClientId::OpenCode,
        kind: SourceKind::Sqlite,
        source_id: "opencode.sqlite".into(),
        path: root.join("opencode/opencode.db"),
    };
    for session in ["ses_synthetic", "ses_SYNTHETIC_Mixed"] {
        for known in [false, true] {
            let mut config = InvestigationConfig::new(&root);
            // A traversal would exhaust this budget; provider deferral wins.
            config.limits.discovery_entries = 1;
            if known {
                config.known_sources.push(source.clone());
            }
            let backend = SessionInvestigator::new(config);
            let input = event(&source, session);
            assert_eq!(
                backend.investigate(&input),
                InvestigationResult::SourceUnavailable(
                    SourceUnavailableReason::ReadOnlyProviderUnavailable
                )
            );
            assert_eq!(
                context(
                    &backend,
                    &input,
                    0,
                    32,
                    32,
                    ContextContent {
                        user_text: true,
                        assistant_text: true,
                        tool_arguments: true
                    }
                ),
                ContextInvestigationResult::SourceUnavailable(
                    SourceUnavailableReason::ReadOnlyProviderUnavailable
                )
            );
        }
    }
    let options = AcquisitionOptions::new(
        telltale_schema::observation::ObservedAt::new("2026-01-01T00:00:00Z").unwrap(),
    );
    assert!(matches!(
        acquire_source_bounded(&root, &source, options, DirectReadLimits::default()),
        Err(AcquisitionError::UnsupportedSourceIdentity)
    ));
    // Deferred means no discovery/source access, even when the configured root
    // is absent. Production scanner acquisition is deliberately unchanged.
    assert_eq!(
        SessionInvestigator::new(InvestigationConfig::new(root.join("absent")))
            .investigate(&event(&source, "ses_synthetic")),
        InvestigationResult::SourceUnavailable(
            SourceUnavailableReason::ReadOnlyProviderUnavailable
        )
    );
}

mod context;
mod fail_closed;
mod source_selection;
