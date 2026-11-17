//! Lookup assertions against the test runtime's append-only telemetry file.
//! Full snapshot/schema assertions still use `Harness::telemetry` independently.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::Path;

use serde_json::Value;

#[derive(Default)]
pub(super) struct TelemetryReader {
    offset: u64,
    first: HashMap<String, HashMap<String, Value>>,
    parsed_records: usize,
}

impl TelemetryReader {
    pub(super) fn record_for(&mut self, path: &Path, kind: &str, id: &str) -> Option<Value> {
        let Ok(mut file) = File::open(path) else {
            self.clear();
            return None;
        };
        if file.metadata().unwrap().len() < self.offset {
            self.clear();
        }
        file.seek(SeekFrom::Start(self.offset)).unwrap();
        let mut reader = BufReader::new(file);
        let mut line = String::new();
        loop {
            line.clear();
            let bytes = reader.read_line(&mut line).unwrap();
            if bytes == 0 {
                break;
            }
            let record: Value = serde_json::from_str(&line).unwrap();
            self.parsed_records += 1;
            if let (Some(kind), Some(id)) = (
                record["kind"].as_str(),
                record["action"]["tool_use_id"].as_str(),
            ) {
                self.first
                    .entry(kind.to_owned())
                    .or_default()
                    .entry(id.to_owned())
                    .or_insert(record);
            }
            // Re-read an unterminated final record if more bytes arrive.
            if !line.ends_with('\n') {
                break;
            }
            self.offset += bytes as u64;
        }
        self.first.get(kind)?.get(id).cloned()
    }

    fn clear(&mut self) {
        self.offset = 0;
        self.first.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    use serde_json::json;

    fn append(path: &Path, kind: &str, id: &str, marker: usize) {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        writeln!(
            file,
            "{}",
            json!({"kind": kind, "action": {"tool_use_id": id}, "marker": marker})
        )
        .unwrap();
    }

    #[test]
    fn repeated_lookups_parse_only_appended_records() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("telemetry.jsonl");
        let mut reader = TelemetryReader::default();
        assert!(reader.record_for(&path, "decision", "first").is_none());
        append(&path, "decision", "first", 1);
        assert_eq!(
            reader.record_for(&path, "decision", "first").unwrap()["marker"],
            1
        );
        assert_eq!(
            reader.record_for(&path, "decision", "first").unwrap()["marker"],
            1
        );
        append(&path, "decision", "second", 2);
        assert_eq!(
            reader.record_for(&path, "decision", "second").unwrap()["marker"],
            2
        );
        assert_eq!(reader.parsed_records, 2);
    }

    #[test]
    fn duplicate_ids_keep_the_first_record_of_each_kind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("telemetry.jsonl");
        let mut reader = TelemetryReader::default();
        for (kind, marker) in [("decision", 1), ("decision", 2), ("outcome", 3)] {
            append(&path, kind, "repeated", marker);
        }
        assert_eq!(
            reader.record_for(&path, "decision", "repeated").unwrap()["marker"],
            1
        );
        assert_eq!(
            reader.record_for(&path, "outcome", "repeated").unwrap()["marker"],
            3
        );
        assert!(reader.record_for(&path, "decision", "missing").is_none());
    }

    #[test]
    fn disappearance_and_truncation_do_not_return_stale_records() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("telemetry.jsonl");
        let mut reader = TelemetryReader::default();
        append(&path, "decision", "first", 1);
        assert!(reader.record_for(&path, "decision", "first").is_some());
        std::fs::write(&path, "").unwrap();
        assert!(reader.record_for(&path, "decision", "first").is_none());
        append(&path, "decision", "second", 2);
        assert!(reader.record_for(&path, "decision", "second").is_some());
        std::fs::remove_file(&path).unwrap();
        assert!(reader.record_for(&path, "decision", "second").is_none());
    }

    #[test]
    fn a_final_record_without_a_newline_can_be_completed_later() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("telemetry.jsonl");
        let mut reader = TelemetryReader::default();
        let record = json!({"kind": "decision", "action": {"tool_use_id": "first"}, "marker": 1});
        std::fs::write(&path, record.to_string()).unwrap();
        assert_eq!(
            reader.record_for(&path, "decision", "first"),
            Some(record.clone())
        );
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        writeln!(file).unwrap();
        drop(file);
        append(&path, "decision", "second", 2);
        assert!(reader.record_for(&path, "decision", "second").is_some());
        assert_eq!(reader.record_for(&path, "decision", "first"), Some(record));
    }

    #[test]
    #[should_panic]
    fn malformed_append_is_checked_even_for_an_already_indexed_id() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("telemetry.jsonl");
        let mut reader = TelemetryReader::default();
        append(&path, "decision", "first", 1);
        assert!(reader.record_for(&path, "decision", "first").is_some());
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        writeln!(file, "not-json").unwrap();
        reader.record_for(&path, "decision", "first");
    }
}
