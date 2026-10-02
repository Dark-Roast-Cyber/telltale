use crate::{Failure, Normalizer, json, mapping::append};
use serde_json::Value;

/// Consume frames one at a time: no second collection of the wire buffer.
pub(crate) fn sse(
    n: &Normalizer,
    mut event: impl FnMut(&Value) -> Result<(), Failure>,
) -> Result<(), Failure> {
    let wire = std::str::from_utf8(&n.response).map_err(|_| Failure::Malformed)?;
    let mut data = String::new();
    let mut kind: Option<&str> = None;
    for line in wire.split_inclusive('\n') {
        let line = line.strip_suffix('\n').ok_or(Failure::Incomplete)?;
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.contains('\r') {
            return Err(Failure::Malformed);
        }
        if line.is_empty() {
            if !data.is_empty() {
                data.pop();
                let value = json::parse(data.as_bytes(), n.limits)?;
                if kind.is_some_and(|kind| value.get("type").and_then(Value::as_str) != Some(kind))
                {
                    return Err(Failure::Conflict);
                }
                event(&value)?;
                data.clear();
            } else if kind.is_some() {
                return Err(Failure::Malformed);
            }
            kind = None;
        } else if let Some(value) = line.strip_prefix("data:") {
            append(
                &mut data,
                value.strip_prefix(' ').unwrap_or(value),
                n.limits.frame_bytes,
            )?;
            append(&mut data, "\n", n.limits.frame_bytes)?;
        } else if let Some(value) = line.strip_prefix("event:") {
            if kind.is_some() {
                return Err(Failure::Conflict);
            }
            kind = Some(value.strip_prefix(' ').unwrap_or(value));
        } else if !line.starts_with(':') {
            return Err(Failure::Unsupported);
        }
    }
    if !data.is_empty() || kind.is_some() {
        return Err(Failure::Incomplete);
    }
    Ok(())
}
