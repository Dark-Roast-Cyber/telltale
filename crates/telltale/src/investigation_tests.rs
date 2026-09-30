use super::investigation::*;
use std::fs;
use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::event::{ActivityEventInput, Event3Record, activity_event, path_hash};
use telltale_schema::source::Source;
use telltale_sources::discovery::discover_sources;

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

#[test]
fn investigation_jsonl_is_content_free_and_preserves_artifacts() {
    let dir = tempfile::tempdir().unwrap();
    let source = codex(dir.path(), JSONL);
    let input = event(&source, "synthetic-session");
    let backend = SessionInvestigator::new(InvestigationConfig::new(dir.path()));
    let result = backend.investigate(&input);
    let InvestigationResult::Found(found) = &result else {
        panic!("{result:?}")
    };
    assert_eq!(found.timeline.entry_count, 2);
    assert_eq!(found.timeline.entries[0].linked_entry_index, Some(1));
    assert_eq!(found.timeline.entries[1].linked_entry_index, Some(0));
    assert!(found.timeline.entries.iter().all(|e| e.evidence.is_empty()));
    let public = format!(
        "{result:?} {}",
        serde_json::to_string(&found.timeline).unwrap()
    );
    for canary in [
        "ordinary_content_canary",
        "OUTPUT_CANARY",
        "EXPLICIT_CALL_CANARY",
        dir.path().to_str().unwrap(),
    ] {
        assert!(!public.contains(canary));
    }
    assert_eq!(backend.investigate(&input), result);
    assert_eq!(fs::read_to_string(&source.path).unwrap(), JSONL);
    assert!(!source.path.with_extension("jsonl-wal").exists());
}

#[test]
fn investigation_exact_identity_and_known_source_loss() {
    let dir = tempfile::tempdir().unwrap();
    let source = codex(dir.path(), JSONL);
    let mut config = InvestigationConfig::new(dir.path());
    config.known_sources = vec![source.clone()];
    let backend = SessionInvestigator::new(config);
    assert_eq!(
        backend.investigate(&event(&source, "different-session")),
        InvestigationResult::SessionUnavailable
    );
    let mut other_client = source.clone();
    other_client.client = ClientId::Claude;
    assert_eq!(
        backend.investigate(&event(&other_client, "synthetic-session")),
        InvestigationResult::NotLocallyResolvable
    );
    fs::rename(&source.path, source.path.with_file_name("moved.jsonl")).unwrap();
    assert_eq!(
        backend.investigate(&event(&source, "synthetic-session")),
        InvestigationResult::SourceUnavailable
    );
    let fresh = SessionInvestigator::new(InvestigationConfig::new(dir.path()));
    assert_eq!(
        fresh.investigate(&event(&source, "synthetic-session")),
        InvestigationResult::NotLocallyResolvable
    );
}

#[test]
fn investigation_bounds_and_ambiguous_source_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let source = codex(dir.path(), JSONL);
    let input = event(&source, "synthetic-session");
    let mut config = InvestigationConfig::new(dir.path());
    config.limits.source_bytes = 16;
    assert_eq!(
        SessionInvestigator::new(config).investigate(&input),
        InvestigationResult::SourceUnavailable
    );
    let mut config = InvestigationConfig::new(dir.path());
    config.limits.discovery_entries = 1;
    assert_eq!(
        SessionInvestigator::new(config).investigate(&input),
        InvestigationResult::NotLocallyResolvable
    );
    let mut conflicting = source.clone();
    conflicting.source_id = "codex.archived_sessions".into();
    conflicting.kind = SourceKind::ArchivedJsonl;
    let mut config = InvestigationConfig::new(dir.path());
    config.known_sources = vec![conflicting, source];
    assert_eq!(
        SessionInvestigator::new(config).investigate(&input),
        InvestigationResult::NotLocallyResolvable
    );
}

#[cfg(unix)]
#[test]
fn investigation_non_regular_source_never_blocks() {
    use std::os::unix::ffi::OsStrExt;
    let dir = tempfile::tempdir().unwrap();
    let source = codex(dir.path(), JSONL);
    let input = event(&source, "synthetic-session");
    fs::remove_file(&source.path).unwrap();
    let path = std::ffi::CString::new(source.path.as_os_str().as_bytes()).unwrap();
    // SAFETY: valid NUL-terminated synthetic pathname.
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    let mut config = InvestigationConfig::new(dir.path());
    config.known_sources = vec![source];
    assert_eq!(
        SessionInvestigator::new(config).investigate(&input),
        InvestigationResult::SourceUnavailable
    );
}

#[test]
fn investigation_malformed_depth_and_exact_byte_record_bounds() {
    let dir = tempfile::tempdir().unwrap();
    let source = codex(dir.path(), JSONL);
    let input = event(&source, "synthetic-session");
    let mut config = InvestigationConfig::new(dir.path());
    config.limits.source_bytes = JSONL.len();
    config.limits.records = 3;
    assert!(matches!(
        SessionInvestigator::new(config).investigate(&input),
        InvestigationResult::Found(_)
    ));
    for payload in ["{\"type\":", "{\"nested\":"] {
        fs::write(&source.path, payload).unwrap();
        assert_eq!(
            SessionInvestigator::new(InvestigationConfig::new(dir.path())).investigate(&input),
            InvestigationResult::SourceUnavailable
        );
        assert_eq!(fs::read_to_string(&source.path).unwrap(), payload);
    }
    fs::write(&source.path, JSONL).unwrap();
    for (bytes, records, depth) in [
        (JSONL.len() - 1, 3, 64),
        (JSONL.len(), 2, 64),
        (JSONL.len(), 3, 1),
    ] {
        let mut config = InvestigationConfig::new(dir.path());
        config.limits.source_bytes = bytes;
        config.limits.records = records;
        config.limits.json_depth = depth;
        assert_eq!(
            SessionInvestigator::new(config).investigate(&input),
            InvestigationResult::SourceUnavailable
        );
    }
    assert_eq!(fs::read_to_string(&source.path).unwrap(), JSONL);
}

#[test]
fn investigation_anchors_are_only_recorded_and_current_indexes() {
    let dir = tempfile::tempdir().unwrap();
    let source = codex(dir.path(), JSONL);
    let mut value =
        serde_json::from_slice::<serde_json::Value>(&event_json(&source, "synthetic-session"))
            .unwrap();
    value["event_type"] = "detection".into();
    value["rule_ids"] = serde_json::json!(["synthetic.rule"]);
    value["categories"] = serde_json::json!(["synthetic"]);
    value["detection_classes"] = serde_json::json!(["security_detection"]);
    value["signal_types"] = serde_json::json!(["atomic"]);
    value["analytic_intents"] = serde_json::json!(["alert"]);
    value["atlas_tags"] = serde_json::json!([]);
    value["response"] = serde_json::json!({"recommended_action":"monitor", "response_playbook":"telltale-playbook-synthetic",
        "investigation_summary":"Synthetic investigation", "escalation":"routine_review"});
    value["timeline_anchors"] = serde_json::json!([
        {"entry_index":0,"rule_ids":["synthetic.rule"],"categories":["synthetic"],"evidence_fields":["arguments"]},
        {"entry_index":99,"rule_ids":["synthetic.rule"],"categories":["synthetic"],"evidence_fields":["arguments"]}
    ]);
    let input = Event3Record::from_json(&serde_json::to_vec(&value).unwrap()).unwrap();
    let InvestigationResult::Found(found) =
        SessionInvestigator::new(InvestigationConfig::new(dir.path())).investigate(&input)
    else {
        panic!("missing session");
    };
    assert_eq!(
        found.anchors,
        vec![
            InvestigationAnchor {
                recorded_entry_index: 0,
                current_entry_index: Some(0)
            },
            InvestigationAnchor {
                recorded_entry_index: 99,
                current_entry_index: None
            }
        ]
    );
}

#[test]
fn investigation_json_object_and_jsonl_with_same_session_keep_clients_separate() {
    let dir = tempfile::tempdir().unwrap();
    let codex_source = codex(dir.path(), JSONL);
    fs::create_dir_all(dir.path().join("claude/projects")).unwrap();
    let payload = r#"{"type":"user","sessionId":"synthetic-session","message":{"role":"user","content":[{"type":"text","text":"CLAUDE_CONTENT_CANARY"}]}}"#;
    fs::write(dir.path().join("claude/projects/synthetic.jsonl"), payload).unwrap();
    let claude_source = discover_sources(dir.path())
        .unwrap()
        .into_iter()
        .find(|s| s.source_id == "claude.projects")
        .unwrap();
    let backend = SessionInvestigator::new(InvestigationConfig::new(dir.path()));
    for source in [&codex_source, &claude_source] {
        let result = backend.investigate(&event(source, "synthetic-session"));
        let InvestigationResult::Found(found) = &result else {
            panic!("{result:?}")
        };
        assert_eq!(found.timeline.client, source.client.as_str());
        assert_eq!(
            found.timeline.entry_count,
            if source.client == ClientId::Codex {
                2
            } else {
                1
            }
        );
        assert!(!format!("{result:?}").contains("CLAUDE_CONTENT_CANARY"));
    }
    let mut wrong_client = codex_source.clone();
    wrong_client.client = ClientId::Claude;
    assert_eq!(
        backend.investigate(&event(&wrong_client, "synthetic-session")),
        InvestigationResult::NotLocallyResolvable
    );
    assert_eq!(fs::read_to_string(&claude_source.path).unwrap(), payload);
}

#[test]
fn investigation_opencode_is_deferred_without_launch_or_artifact_changes() {
    let dir = tempfile::tempdir().unwrap();
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
                    .join("src/investigation_tests/helper.rs")
            )
            .arg("-o")
            .arg(&executable)
            .status()
            .unwrap()
            .success()
    );
    // Only this child receives a synthetic PATH; no process-global environment
    // mutation or installed/live OpenCode executable can enter the test.
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "investigation_tests::investigation_opencode_deferred_probe",
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
            if known {
                config.known_sources.push(source.clone());
            }
            assert_eq!(
                SessionInvestigator::new(config).investigate(&event(&source, session)),
                InvestigationResult::SourceUnavailable
            );
        }
    }
    let options = AcquisitionOptions::new(
        telltale_schema::observation::ObservedAt::new("2026-01-01T00:00:00Z").unwrap(),
    );
    assert!(matches!(
        acquire_source_bounded(&source, options, DirectReadLimits::default()),
        Err(AcquisitionError::UnsupportedSourceIdentity)
    ));
    // Deferred means no discovery/source access, even when the configured root
    // is absent. Production scanner acquisition is deliberately unchanged.
    assert_eq!(
        SessionInvestigator::new(InvestigationConfig::new(root.join("absent")))
            .investigate(&event(&source, "ses_synthetic")),
        InvestigationResult::SourceUnavailable
    );
}
