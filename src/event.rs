//! Re-exports the canonical event model from `telltale-schema` and adds the
//! filesystem-facing JSONL append helper, which stays out of the I/O-free
//! schema crate.

use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::file_lock::{SidecarLock, open_append, safe_path_info, sync_parent};
pub use telltale_schema::event::*;

#[allow(dead_code)]
pub fn append_jsonl_events(
    path: &Path,
    events: &[Event],
) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = serialize_jsonl_events(events)?;
    if bytes.is_empty() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let _lock = SidecarLock::acquire_lock_only(path)?;
    let created = append_jsonl_bytes(path, &bytes)?;
    if created {
        sync_parent(path)?;
    }
    Ok(())
}

pub(crate) fn serialize_jsonl_events(
    events: &[Event],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    for event in events {
        let mut serializer = serde_json::Serializer::new(&mut bytes);
        serialize_event_for_emission(event, &mut serializer)?;
        bytes.push(b'\n');
    }
    Ok(bytes)
}

pub(crate) fn append_jsonl_bytes(
    path: &Path,
    bytes: &[u8],
) -> Result<bool, Box<dyn std::error::Error>> {
    ensure_jsonl_tail(path)?;
    let (mut file, created, info) = open_append(path)?;
    file.write_all(bytes)?;
    file.flush()?;
    file.sync_all()?;
    let current = safe_path_info(path)?.ok_or("log target disappeared during append")?;
    if current.identity != info.identity || current.links != info.links {
        return Err("log target changed during append".into());
    }
    Ok(created)
}

pub(crate) fn ensure_jsonl_tail(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = match OpenOptions::new().read(true).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let length = file.metadata()?.len();
    if length == 0 {
        return Ok(());
    }
    file.seek(SeekFrom::End(-1))?;
    let mut last = [0u8; 1];
    file.read_exact(&mut last)?;
    if last[0] != b'\n' {
        return Err(
            "local JSONL ends with a partial record; repair or replace it before retrying".into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::{append_jsonl_events, serialize_jsonl_events};
    use crate::event::{
        ActivityEventInput, ControlledMarker, Evidence, check_serialized_event_markers,
    };
    use telltale_schema::clients::ClientId;

    #[test]
    fn canonical_jsonl_persists_only_sanitized_event_bytes() {
        let marker = "TT_PRIVACY_JSONL_25";
        let mut event = crate::event::activity_event(ActivityEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "opaque-session".to_string(),
            source_path_hash: "source-hash".to_string(),
            tool_name: Some("shell".to_string()),
            tags: Vec::new(),
            evidence: vec![Evidence {
                field: "tool_result".to_string(),
                redacted_value: format!(
                    "delivery=https://user:{marker}@example.invalid/?%74%6f%6b%65%6e={marker}"
                ),
                hash: None,
                rule_id: None,
            }],
            risk_contributions: Vec::new(),
            event_time: None,
        })
        .expect("activity event");
        event.tags.push(format!("allowlist:{marker}"));
        event.evidence.push(Evidence {
            field: "allowlist".to_string(),
            redacted_value: marker.to_string(),
            hash: None,
            rule_id: None,
        });
        let expected =
            serialize_jsonl_events(std::slice::from_ref(&event)).expect("serialize event");
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("events.jsonl");

        append_jsonl_events(&path, &[event]).expect("append canonical JSONL");
        let persisted = fs::read(path).expect("read canonical JSONL");

        assert_eq!(persisted, expected);
        assert!(
            check_serialized_event_markers(
                &persisted,
                "canonical-jsonl",
                &[ControlledMarker {
                    id: "jsonl-marker",
                    value: marker,
                }],
            )
            .is_ok()
        );
    }

    #[test]
    fn canonical_jsonl_drops_partial_truncated_url_credential_prefix() {
        const INPUT_CAP: usize = 4096;
        let tail = "https://uTT_PRIVACY_JSONL_TAIL_25";
        let start = INPUT_CAP - 10;
        let input = format!(
            "safe-prefix{}{}",
            " ".repeat(start - "safe-prefix".len()),
            tail
        );
        let retained_prefix = &tail[..INPUT_CAP - start];
        let event = crate::event::activity_event(ActivityEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "safe-session".to_string(),
            source_path_hash: "source-hash".to_string(),
            tool_name: Some("shell".to_string()),
            tags: Vec::new(),
            evidence: vec![Evidence {
                field: "url".to_string(),
                redacted_value: input,
                hash: None,
                rule_id: None,
            }],
            risk_contributions: Vec::new(),
            event_time: None,
        })
        .expect("activity event");
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("events.jsonl");

        append_jsonl_events(&path, &[event]).expect("append canonical JSONL");
        let persisted = fs::read_to_string(path).expect("read canonical JSONL");

        assert!(!persisted.contains(retained_prefix));
        assert!(persisted.contains("safe-prefix"));
        assert!(!persisted.contains(tail));
    }

    #[test]
    fn canonical_jsonl_hides_sensitive_filesystem_paths_inside_urls() {
        let marker = "TT_PRIVACY_JSONL_URL_PATH_USER_25";
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("events.jsonl");
        let event = crate::event::activity_event(ActivityEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "safe-session".to_string(),
            source_path_hash: "source-hash".to_string(),
            tool_name: Some("shell".to_string()),
            tags: Vec::new(),
            evidence: vec![Evidence {
                field: "url".to_string(),
                redacted_value: format!(
                    "https://example.invalid/home/{marker}/.ssh/id_rsa?mode=view"
                ),
                hash: None,
                rule_id: None,
            }],
            risk_contributions: Vec::new(),
            event_time: None,
        })
        .expect("activity event");

        append_jsonl_events(&path, &[event]).expect("append canonical JSONL");
        let persisted = fs::read(path).expect("read canonical JSONL");
        assert!(!String::from_utf8_lossy(&persisted).contains(marker));
        assert!(String::from_utf8_lossy(&persisted).contains("[sensitive-path]"));
    }

    #[test]
    fn canonical_jsonl_replaces_malformed_percent_encoded_url_authorities() {
        let path_marker = "TT_PRIVACY_PATH_25";
        let query_marker = "TT_PRIVACY_QUERY_25";
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("events.jsonl");
        let event = crate::event::activity_event(ActivityEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "safe-session".to_string(),
            source_path_hash: "source-hash".to_string(),
            tool_name: Some("shell".to_string()),
            tags: Vec::new(),
            evidence: vec![Evidence {
                field: "url".to_string(),
                redacted_value: format!(
                    "https://@/home/{path_marker}/.ssh/id_rsa?token={query_marker} https://example.invalid%2Fhome%2F{path_marker}%2F.ssh%2Fid_rsa"
                ),
                hash: None,
                rule_id: None,
            }],
            risk_contributions: Vec::new(),
            event_time: None,
        })
        .expect("activity event");

        append_jsonl_events(&path, &[event]).expect("append canonical JSONL");
        let persisted = fs::read(path).expect("read canonical JSONL");
        assert!(
            check_serialized_event_markers(
                &persisted,
                "canonical-malformed-url-authority",
                &[
                    ControlledMarker {
                        id: "path",
                        value: path_marker,
                    },
                    ControlledMarker {
                        id: "query",
                        value: query_marker,
                    },
                ],
            )
            .is_ok(),
            "canonical JSONL retained a malformed URL authority marker"
        );
        assert!(String::from_utf8_lossy(&persisted).contains("[redacted-url]"));
    }

    #[test]
    fn canonical_jsonl_replaces_fully_encoded_url_authority_candidates() {
        let marker = "TT_PRIVACY_JSONL_ENCODED_AUTHORITY_25";
        let cases = [
            format!("https%3A%2F%2Fexample.invalid%252F{marker}%2Fsafe"),
            format!("https%3A%2F%2Fexample.invalid%255C{marker}%2Fsafe"),
            format!("https%3A%2F%2Fexample.invalid%253Fnext%253D{marker}%2Fsafe"),
            format!("https%3A%2F%2Fexample.invalid%2523safe%253D{marker}%2Fsafe"),
            format!("https%3A%2F%2Fexample.invalid%2540{marker}%2Fsafe"),
            format!("https%3A%2F%2Fexample.invalid%252f{marker}%2Fsafe"),
            format!("https%253A%252F%252Fexample.invalid%25252F{marker}%252Fsafe"),
        ];
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("events.jsonl");
        let event = crate::event::activity_event(ActivityEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "safe-session".to_string(),
            source_path_hash: "source-hash".to_string(),
            tool_name: Some("shell".to_string()),
            tags: Vec::new(),
            evidence: vec![Evidence {
                field: "url".to_string(),
                redacted_value: cases.join(" "),
                hash: None,
                rule_id: None,
            }],
            risk_contributions: Vec::new(),
            event_time: None,
        })
        .expect("activity event");

        append_jsonl_events(&path, &[event]).expect("append canonical JSONL");
        let persisted = fs::read(path).expect("read canonical JSONL");
        assert!(
            check_serialized_event_markers(
                &persisted,
                "canonical-fully-encoded-url-authority",
                &[ControlledMarker {
                    id: "authority",
                    value: marker,
                }],
            )
            .is_ok(),
            "canonical JSONL retained a fully encoded URL authority marker"
        );
        let persisted_event: serde_json::Value =
            serde_json::from_slice(&persisted).expect("canonical JSONL event");
        assert_eq!(
            persisted_event["evidence"][0]["redacted_value"],
            "[redacted-url] [redacted-url] [redacted-url] [redacted-url] [redacted-url] [redacted-url] [redacted-url]"
        );
    }

    #[test]
    fn canonical_jsonl_redacts_encoded_url_candidate_prefix_forms_atomically() {
        let path_marker = "TT_PRIVACY_JSONL_ENCODED_CANDIDATE_PATH_25";
        let authority_marker = "TT_PRIVACY_JSONL_ENCODED_CANDIDATE_AUTHORITY_25";
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("events.jsonl");
        let event = crate::event::activity_event(ActivityEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "safe-session".to_string(),
            source_path_hash: "source-hash".to_string(),
            tool_name: Some("shell".to_string()),
            tags: Vec::new(),
            evidence: vec![Evidence {
                field: "url".to_string(),
                redacted_value: format!(
                    "https:%2F%2Fexample.invalid%2Fhome%2F{path_marker}%2F.ssh%2Fid_rsa https%3A//example.invalid%252Fhome%252F{authority_marker}%252F.ssh%252Fid_rsa"
                ),
                hash: None,
                rule_id: None,
            }],
            risk_contributions: Vec::new(),
            event_time: None,
        })
        .expect("activity event");

        append_jsonl_events(&path, std::slice::from_ref(&event)).expect("append canonical JSONL");
        let persisted = fs::read(&path).expect("read canonical JSONL");
        assert!(
            check_serialized_event_markers(
                &persisted,
                "canonical-encoded-url-candidate-prefix",
                &[
                    ControlledMarker {
                        id: "path",
                        value: path_marker,
                    },
                    ControlledMarker {
                        id: "authority",
                        value: authority_marker,
                    },
                ],
            )
            .is_ok(),
            "canonical JSONL retained an encoded URL candidate marker"
        );
        let persisted_event: serde_json::Value =
            serde_json::from_slice(&persisted).expect("canonical JSONL event");
        assert_eq!(
            persisted_event["evidence"][0]["redacted_value"],
            "https://example.invalid/[sensitive-path] [redacted-url]"
        );
    }

    #[test]
    fn canonical_jsonl_redacts_nested_encoded_urls_inside_outer_components() {
        let marker = "TT_PRIVACY_JSONL_NESTED_BOUNDARY_25";
        let values = [
            format!("https://outer.invalid/?next=https%3A%2F%2Finner.invalid%252F{marker}"),
            format!("https://outer.invalid/redirect/https%3A%2F%2Finner.invalid%252F{marker}"),
            format!(
                "https://outer.invalid/#next=https%3A%2F%2Finner.invalid%2523token%253D{marker}"
            ),
        ];
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("events.jsonl");
        let event = crate::event::activity_event(ActivityEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "nested-jsonl-session".to_string(),
            source_path_hash: "nested-jsonl-source".to_string(),
            tool_name: Some("shell".to_string()),
            tags: Vec::new(),
            evidence: vec![Evidence {
                field: "url".to_string(),
                redacted_value: values.join(" "),
                hash: None,
                rule_id: None,
            }],
            risk_contributions: Vec::new(),
            event_time: None,
        })
        .expect("nested URL activity event");

        append_jsonl_events(&path, std::slice::from_ref(&event)).expect("append nested URLs");
        let persisted = fs::read(&path).expect("read nested URL JSONL");
        assert!(
            check_serialized_event_markers(
                &persisted,
                "canonical-jsonl-nested-url-components",
                &[ControlledMarker {
                    id: "nested-url",
                    value: marker,
                }],
            )
            .is_ok(),
            "canonical JSONL retained a nested URL marker"
        );
        let persisted_text = String::from_utf8_lossy(&persisted);
        assert!(
            !persisted_text.contains("https%3A%2F%2Finner.invalid"),
            "canonical JSONL retained a nested encoded URL prefix"
        );
        assert!(persisted_text.contains("[redacted-url]"));
        assert_eq!(
            persisted,
            serialize_jsonl_events(std::slice::from_ref(&event)).expect("repeat nested URLs"),
            "canonical JSONL serialization must be idempotent"
        );
    }
}
