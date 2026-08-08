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
    let _lock = SidecarLock::acquire(path)?;
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
        serde_json::to_writer(&mut bytes, event)?;
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
