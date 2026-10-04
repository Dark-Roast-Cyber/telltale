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
        vec![serde_json::json!("é中"), serde_json::json!({})]
    );
}
