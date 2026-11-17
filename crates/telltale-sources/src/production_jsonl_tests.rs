use super::*;
use std::io::Write;
use telltale_schema::clients::SourceKind;

const RECORD_BYTES: usize = 8 * 1024 * 1024;
const SOURCE_BYTES: usize = 128 * 1024 * 1024;

fn source(path: std::path::PathBuf) -> Source {
    Source {
        client: ClientId::Codex,
        source_id: "codex.sessions".into(),
        kind: SourceKind::Jsonl,
        path,
    }
}

fn padded_record(bytes: usize, ending: &[u8]) -> Vec<u8> {
    let mut record = vec![b' '; bytes - ending.len()];
    record[..2].copy_from_slice(b"{}");
    record.extend_from_slice(ending);
    record
}

#[test]
fn production_jsonl_physical_record_inclusive_boundaries_and_atomic_tail() {
    let dir = tempfile::tempdir().unwrap();
    let source = source(dir.path().join("synthetic.jsonl"));
    for ending in [b"\n".as_slice(), b"\r\n", b""] {
        fs::write(&source.path, padded_record(RECORD_BYTES, ending)).unwrap();
        assert_eq!(
            read_jsonl_values(&source).unwrap(),
            vec![serde_json::json!({})]
        );
        fs::write(&source.path, padded_record(RECORD_BYTES + 1, ending)).unwrap();
        assert!(
            read_jsonl_values(&source).is_err(),
            "one-over physical record admitted"
        );
        let mut file = fs::File::create(&source.path).unwrap();
        file.write_all(b"{}\n").unwrap();
        file.write_all(&padded_record(RECORD_BYTES + 1, ending))
            .unwrap();
        assert!(
            read_jsonl_values(&source).is_err(),
            "oversized tail admitted"
        );
    }
    fs::write(&source.path, vec![b' '; RECORD_BYTES + 1]).unwrap();
    assert!(
        read_jsonl_values(&source).is_err(),
        "delimiter-free blank record admitted"
    );
}

#[test]
fn production_jsonl_multibyte_physical_record_boundary_counts_bytes_not_characters() {
    let dir = tempfile::tempdir().unwrap();
    let source = source(dir.path().join("synthetic.jsonl"));
    let text = "é".repeat((RECORD_BYTES - 4) / 2);
    let mut record = format!("\"{text}\"\r\n");
    assert_eq!(record.len(), RECORD_BYTES);
    let characters = record.chars().count();
    assert!(characters < RECORD_BYTES);
    fs::write(&source.path, &record).unwrap();
    let values = read_jsonl_values(&source).unwrap();
    assert_eq!(values.len(), 1);
    assert_eq!(values[0].as_str(), Some(text.as_str()));

    // Replace a two-byte code point with a three-byte one, preserving character count.
    record.replace_range(1..3, "中");
    assert_eq!(record.len(), RECORD_BYTES + 1);
    assert_eq!(record.chars().count(), characters);
    assert!(serde_json::from_str::<Value>(record.trim_end()).is_ok());
    fs::write(&source.path, &record).unwrap();
    assert!(read_jsonl_values(&source).is_err());
}

#[test]
fn production_jsonl_aggregate_inclusive_counts_all_blank_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let source = source(dir.path().join("synthetic.jsonl"));
    // Reuse a 1 MiB blank physical record instead of allocating a whole source.
    let mut blank = vec![b' '; 1024 * 1024];
    *blank.last_mut().unwrap() = b'\n';
    let mut file = fs::File::create(&source.path).unwrap();
    for _ in 0..SOURCE_BYTES / blank.len() {
        file.write_all(&blank).unwrap();
    }
    assert!(read_jsonl_values(&source).unwrap().is_empty());
    file.write_all(b"\n").unwrap();
    assert!(
        read_jsonl_values(&source).is_err(),
        "aggregate blank bytes admitted"
    );
}

#[test]
fn production_jsonl_native_units_scale_with_bytes_read() {
    let dir = tempfile::tempdir().unwrap();
    let source = source(dir.path().join("synthetic.jsonl"));
    // 150,000 sixteen-byte units read about 2.3 MiB: over the 100,000 floor,
    // within 100,000 per MiB read.
    let unit = b"{\"p\":\"padding\"}\n";
    assert_eq!(unit.len(), 16);
    fs::write(&source.path, unit.repeat(150_000)).unwrap();
    let (values, bytes) =
        read_jsonl_values_with_limits(&source, crate::acquisition::SourceAccess::ByName)
            .expect("scaled native units");
    assert_eq!((values.len(), bytes), (150_000, 2_400_000));
    // Denser units than 100,000 per MiB read still stop the read.
    fs::write(&source.path, b"{}\n".repeat(524_288)).unwrap();
    assert!(read_jsonl_values(&source).is_err(), "dense units admitted");
}

#[test]
fn production_jsonl_native_unit_inclusive_boundary_and_unicode_blanks() {
    let dir = tempfile::tempdir().unwrap();
    let source = source(dir.path().join("synthetic.jsonl"));
    let mut file = fs::File::create(&source.path).unwrap();
    let block = b"{}\n".repeat(1000);
    for _ in 0..100 {
        file.write_all(&block).unwrap();
        file.write_all("\u{2003}\u{a0}\r\n".as_bytes()).unwrap();
    }
    assert_eq!(read_jsonl_values(&source).unwrap().len(), 100_000);
    file.write_all(b"{}").unwrap();
    assert!(
        read_jsonl_values(&source).is_err(),
        "one-over unit count admitted"
    );
}

#[test]
fn production_jsonl_utf8_crlf_unterminated_and_malformed_tail() {
    let dir = tempfile::tempdir().unwrap();
    let source = source(dir.path().join("synthetic.jsonl"));
    // Multibyte code point straddles the reader's 8 KiB chunk boundary.
    let text = format!("{}é中", "x".repeat(8189));
    let value = serde_json::json!(text);
    let raw = format!("{value}\r\n\u{2003}\u{a0}\n{{}}");
    fs::write(&source.path, &raw).unwrap();
    assert_eq!(
        read_jsonl_values(&source).unwrap(),
        vec![value, serde_json::json!({})]
    );
    fs::write(&source.path, format!("{raw}\n{{malformed")).unwrap();
    assert!(read_jsonl_values(&source).is_err());
    let mut invalid = raw.into_bytes();
    invalid.extend_from_slice(b"\n\xff");
    fs::write(&source.path, invalid).unwrap();
    assert!(read_jsonl_values(&source).is_err());
}

#[cfg(unix)]
#[test]
fn production_jsonl_preserves_symlink_and_directory_behavior() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("synthetic.jsonl");
    fs::write(&path, b"{}\n").unwrap();
    let link = dir.path().join("link.jsonl");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert_eq!(
        read_jsonl_values(&source(link)).unwrap(),
        vec![serde_json::json!({})]
    );
    assert!(matches!(
        read_jsonl_values(&source(dir.path().into())),
        Err(SourceReadError::Io(_))
    ));
}

#[test]
fn production_jsonl_all_six_acquisition_semantics_identity_and_atomic_limits() {
    use crate::acquisition::{
        AcquisitionError, AcquisitionOptions, AcquisitionProgress, acquire_source,
    };
    use telltale_schema::observation::ObservedAt;
    let dir = tempfile::tempdir().unwrap();
    let options = || AcquisitionOptions::new(ObservedAt::new("2026-09-18T12:00:00Z").unwrap());
    for (client, source_id, kind) in [
        (ClientId::Claude, "claude.projects", SourceKind::Jsonl),
        (ClientId::Codex, "codex.sessions", SourceKind::Jsonl),
        (
            ClientId::Codex,
            "codex.archived_sessions",
            SourceKind::ArchivedJsonl,
        ),
        (
            ClientId::Codex,
            "codex.headless_sessions",
            SourceKind::HeadlessJsonl,
        ),
        (ClientId::OpenClaw, "openclaw.agents", SourceKind::Jsonl),
        (ClientId::Qwen, "qwen.projects", SourceKind::Jsonl),
    ] {
        let mut source = Source {
            client,
            source_id: source_id.into(),
            kind,
            path: dir.path().join("PRIVATE-PATH.jsonl"),
        };
        let record = serde_json::json!({"type":"user", "sessionId":"synthetic", "session_id":"synthetic", "content":"synthetic é中"}).to_string();
        fs::write(&source.path, format!("{record}\n{record}\n")).unwrap();
        let before = acquire_source(&source, options()).unwrap();
        assert_eq!(before.progress, AcquisitionProgress::None);
        assert!(!before.observations.is_empty());
        fs::write(
            &source.path,
            format!("\u{2003}\r\n  {record} \r\n\n{record}"),
        )
        .unwrap();
        let after = acquire_source(&source, options()).unwrap();
        assert_eq!(
            before
                .observations
                .iter()
                .map(|o| o.observation_id())
                .collect::<Vec<_>>(),
            after
                .observations
                .iter()
                .map(|o| o.observation_id())
                .collect::<Vec<_>>(),
            "{source_id} formatting changed canonical identity/ordinals"
        );
        for (before, after) in before.observations.iter().zip(&after.observations) {
            assert_eq!(before.body(), after.body());
        }
        assert_eq!(before.accounting, after.accounting);
        let mut file = fs::File::create(&source.path).unwrap();
        file.write_all(record.as_bytes()).unwrap();
        file.write_all(b"\n").unwrap();
        file.write_all(&vec![b' '; RECORD_BYTES + 1]).unwrap();
        let error = acquire_source(&source, options())
            .err()
            .expect("oversized tail must fail atomically");
        assert_eq!(error, AcquisitionError::SourceRead);
        assert_eq!(format!("{error} {error:?}"), "source_read SourceRead");
        fs::write(&source.path, format!("{record}\n{{malformed")).unwrap();
        assert_eq!(
            acquire_source(&source, options()).err(),
            Some(AcquisitionError::SourceRead)
        );
        source.path = dir.path().join("missing.jsonl");
        source.kind = SourceKind::CopilotProcessLog;
        assert_eq!(
            acquire_source(&source, options()).err(),
            Some(AcquisitionError::SourceKindMismatch)
        );
        source.kind = kind;
        source.client = ClientId::Copilot;
        assert_eq!(
            acquire_source(&source, options()).err(),
            Some(AcquisitionError::UnsupportedSourceIdentity)
        );
    }
}

#[test]
fn production_jsonl_reads_growth_after_opened_file_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("synthetic.jsonl");
    fs::write(&path, b"{}\n").unwrap();
    let reader = fs::File::open(&path).unwrap();
    assert_eq!(reader.metadata().unwrap().len(), 3);
    let mut writer = fs::OpenOptions::new().append(true).open(&path).unwrap();
    writer.write_all(&vec![b' '; RECORD_BYTES + 1]).unwrap();
    assert!(read_production_jsonl(reader).is_err());
}

#[test]
fn production_jsonl_short_reads_interruption_and_utf8_boundary() {
    struct ShortReads {
        bytes: std::io::Cursor<Vec<u8>>,
        interrupted: bool,
    }
    impl Read for ShortReads {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            if !self.interrupted {
                self.interrupted = true;
                return Err(std::io::ErrorKind::Interrupted.into());
            }
            self.bytes.read(&mut buffer[..1])
        }
    }
    let reader = ShortReads {
        bytes: std::io::Cursor::new("\u{2003}\r\n\"é中\"\r\n{}".as_bytes().to_vec()),
        interrupted: false,
    };
    assert_eq!(
        read_production_jsonl(reader).unwrap(),
        (vec![serde_json::json!("é中"), serde_json::json!({})], 16)
    );
}

// `acquire_resolved_source` reads an already-resolved path with the production
// limits and semantics, without following a link or blocking.
mod resolved_acquisition {
    use super::*;
    use crate::acquisition::{
        AcquisitionError, AcquisitionOptions, acquire_resolved_source, acquire_source,
    };
    use telltale_schema::observation::ObservedAt;

    const RECORD: &str = "{\"type\":\"user\",\"sessionId\":\"synthetic\",\"session_id\":\"synthetic\",\"content\":\"synthetic\"}\n";
    const COPILOT: &str = concat!(
        "Workspace initialized: synthetic (checkpoints: 0)\n",
        "Accumulated output items (1): [{\"type\":\"function_call\",\"name\":\"view\",\"call_id\":\"synthetic-call\",\"arguments\":\"needle\"}]\n",
        "Session completed.\n"
    );

    fn options() -> AcquisitionOptions {
        AcquisitionOptions::new(ObservedAt::new("2026-09-18T12:00:00Z").unwrap())
    }

    fn codex(path: std::path::PathBuf) -> Source {
        Source {
            client: ClientId::Codex,
            source_id: "codex.sessions".into(),
            kind: SourceKind::Jsonl,
            path,
        }
    }

    fn source_read(source: &Source) -> bool {
        matches!(
            acquire_resolved_source(source, options()),
            Err(AcquisitionError::SourceRead)
        )
    }

    fn link(target: &std::path::Path, path: &std::path::Path) {
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
    fn resolved_acquisition_reads_every_identity_like_acquire_source() {
        let dir = tempfile::tempdir().unwrap();
        for (client, source_id, kind, content) in [
            (
                ClientId::Claude,
                "claude.projects",
                SourceKind::Jsonl,
                RECORD,
            ),
            (ClientId::Codex, "codex.sessions", SourceKind::Jsonl, RECORD),
            (
                ClientId::Codex,
                "codex.archived_sessions",
                SourceKind::ArchivedJsonl,
                RECORD,
            ),
            (
                ClientId::Codex,
                "codex.headless_sessions",
                SourceKind::HeadlessJsonl,
                RECORD,
            ),
            (
                ClientId::OpenClaw,
                "openclaw.agents",
                SourceKind::Jsonl,
                RECORD,
            ),
            (ClientId::Qwen, "qwen.projects", SourceKind::Jsonl, RECORD),
            (
                ClientId::Copilot,
                "copilot.process_log",
                SourceKind::CopilotProcessLog,
                COPILOT,
            ),
        ] {
            let source = Source {
                client,
                source_id: source_id.into(),
                kind,
                path: dir.path().join(format!("{source_id}.log")),
            };
            fs::write(&source.path, content).unwrap();
            let by_name = acquire_source(&source, options()).unwrap();
            let resolved = acquire_resolved_source(&source, options()).unwrap();
            assert!(!resolved.observations.is_empty(), "{source_id}");
            let ids = |batch: &crate::acquisition::AcquisitionBatch| {
                batch
                    .observations
                    .iter()
                    .map(|observation| observation.observation_id().to_owned())
                    .collect::<Vec<_>>()
            };
            assert_eq!(ids(&resolved), ids(&by_name), "{source_id}");
            // The production limits and error shape are unchanged.
            fs::write(&source.path, vec![b' '; RECORD_BYTES + 1]).unwrap();
            let code = |result: Result<_, AcquisitionError>| match result {
                Ok(_) => "ok",
                Err(error) => error.code(),
            };
            assert_eq!(
                code(acquire_resolved_source(&source, options())),
                code(acquire_source(&source, options())),
                "{source_id} limit"
            );
            assert_ne!(code(acquire_resolved_source(&source, options())), "ok");
            fs::remove_file(&source.path).unwrap();
            assert!(source_read(&source), "{source_id} missing");
            fs::create_dir(&source.path).unwrap();
            assert!(source_read(&source), "{source_id} directory");
            fs::remove_dir(&source.path).unwrap();
        }
    }

    #[test]
    fn a_swapped_directory_or_leaf_is_refused_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();
        fs::create_dir_all(base.join("store")).unwrap();
        fs::create_dir_all(base.join("outside")).unwrap();
        fs::write(base.join("store/session.jsonl"), RECORD).unwrap();
        fs::write(base.join("outside/session.jsonl"), RECORD).unwrap();
        let inside = codex(base.join("store/session.jsonl"));
        acquire_resolved_source(&inside, options()).expect("control");
        // The leaf replaced by a link (file links need privilege on Windows).
        #[cfg(unix)]
        {
            fs::rename(&inside.path, base.join("retained.jsonl")).unwrap();
            std::os::unix::fs::symlink(base.join("outside/session.jsonl"), &inside.path).unwrap();
            assert!(source_read(&inside), "leaf link followed");
            // By name, the same replacement is followed: the contrast.
            assert!(acquire_source(&inside, options()).is_ok());
            fs::remove_file(&inside.path).unwrap();
            fs::rename(base.join("retained.jsonl"), &inside.path).unwrap();
        }
        // An ancestor directory replaced by a link.
        fs::rename(base.join("store"), base.join("retained")).unwrap();
        link(&base.join("outside"), &base.join("store"));
        assert!(source_read(&inside), "directory link followed");
        assert!(acquire_source(&inside, options()).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn a_fifo_is_refused_without_blocking() {
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir().unwrap();
        for (source_id, client, kind) in [
            ("codex.sessions", ClientId::Codex, SourceKind::Jsonl),
            (
                "copilot.process_log",
                ClientId::Copilot,
                SourceKind::CopilotProcessLog,
            ),
        ] {
            let path = dir.path().join(format!("{source_id}.fifo"));
            let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
            // SAFETY: valid NUL-terminated synthetic pathname.
            assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
            let source = Source {
                client,
                source_id: source_id.into(),
                kind,
                path: path.clone(),
            };
            let (sender, receiver) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = sender.send(source_read(&source));
            });
            let outcome = receiver.recv_timeout(std::time::Duration::from_secs(10));
            if outcome.is_err() {
                // Release a reader blocked in open(2) so the thread can end.
                let _ = fs::OpenOptions::new().write(true).open(&path);
            }
            assert_eq!(outcome, Ok(true), "{source_id}: a FIFO must not block");
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_path_that_still_contains_a_link_must_be_resolved_first() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().canonicalize().unwrap();
        fs::create_dir_all(base.join("real")).unwrap();
        fs::write(base.join("real/session.jsonl"), RECORD).unwrap();
        std::os::unix::fs::symlink(base.join("real"), base.join("alias")).unwrap();
        let through_link = codex(base.join("alias/session.jsonl"));
        assert!(source_read(&through_link));
        assert!(acquire_source(&through_link, options()).is_ok());
        let canonical = codex(through_link.path.canonicalize().unwrap());
        assert!(acquire_resolved_source(&canonical, options()).is_ok());
    }
}
