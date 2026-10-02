use crate::{Failure, Normalizer, ResponseFormat, json, mapping::*};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use telltale_schema::observation::*;

fn message(
    batch: &mut Batch<'_>,
    v: &Value,
    base: u32,
    corr: &CorrelationIds,
    output: bool,
) -> Result<(), Failure> {
    semantic_keys(
        v,
        &["role", "content", "tool_calls", "tool_name", "tool_call_id"],
    )?;
    let role = text(v, "role")?;
    if output && role != "assistant" {
        return Err(Failure::Unsupported);
    }
    if role == "tool" {
        unsupported(v, &["tool_calls"])?;
        let content = v
            .get("content")
            .filter(|v| v.is_string())
            .ok_or(Failure::Unsupported)?;
        // tool_name is not a call identity, even when only one tool was proposed.
        batch.result(
            content,
            None,
            base,
            correlation(corr, optional_text(v, "tool_call_id")?)?,
        )?;
    } else {
        unsupported(v, &["tool_call_id", "tool_name"])?;
        batch.text_message(
            role,
            v.get("content")
                .and_then(Value::as_str)
                .ok_or(Failure::Malformed)?,
            base,
            corr,
            None,
        )?;
        if let Some(calls) = v.get("tool_calls") {
            if role != "assistant" {
                return Err(Failure::Unsupported);
            }
            let mut ids = BTreeSet::new();
            for (i, call) in calls
                .as_array()
                .ok_or(Failure::Malformed)?
                .iter()
                .enumerate()
            {
                semantic_keys(call, &["id", "function"])?;
                let f = call.get("function").ok_or(Failure::Malformed)?;
                semantic_keys(f, &["name", "arguments", "index"])?;
                if f.get("index").is_some_and(|v| v.as_u64().is_none()) {
                    return Err(Failure::Malformed);
                }
                let id = optional_text(call, "id")?;
                if id.is_some_and(|id| !ids.insert(id)) {
                    return Err(Failure::Conflict);
                }
                batch.proposal(
                    text(f, "name")?,
                    f.get("arguments").ok_or(Failure::Malformed)?,
                    base + i as u32 + 1,
                    correlation(corr, id)?,
                    None,
                )?;
            }
        }
    }
    Ok(())
}
pub(crate) fn request(
    n: &Normalizer,
    v: &Value,
    at: ObservedAt,
) -> Result<Vec<CanonicalObservationV2>, Failure> {
    unsupported(v, &["think"])?;
    let mut batch = Batch::new(n, at);
    batch.inference(
        ObservationStage::InferenceRequested,
        None,
        None,
        None,
        &n.correlation,
    )?;
    let messages = array(v, "messages")?;
    if messages.is_empty() {
        return Err(Failure::Malformed);
    }
    for (i, v) in messages.iter().enumerate() {
        message(&mut batch, v, i as u32 * 257, &n.correlation, false)?;
    }
    if let Some(tools) = v.get("tools") {
        for (i, tool) in tools
            .as_array()
            .ok_or(Failure::Malformed)?
            .iter()
            .enumerate()
        {
            semantic_keys(tool, &["type", "function"])?;
            if text(tool, "type")? != "function" {
                return Err(Failure::Unsupported);
            }
            let f = tool.get("function").ok_or(Failure::Malformed)?;
            semantic_keys(f, &["name", "description", "parameters"])?;
            if f.get("description").is_some_and(|v| !v.is_string())
                || f.get("parameters").is_some_and(|v| !v.is_object())
            {
                return Err(Failure::Malformed);
            }
            batch.definition(text(f, "name")?, f, i as u32, &n.correlation)?;
        }
    }
    Ok(batch.values)
}
fn usage(v: &Value) -> Result<Value, Failure> {
    let mut usage = serde_json::Map::new();
    for (key, target) in [
        ("prompt_eval_count", "prompt_tokens"),
        ("eval_count", "completion_tokens"),
    ] {
        if let Some(count) = v.get(key) {
            usage.insert(
                target.to_owned(),
                Value::from(count.as_u64().ok_or(Failure::Malformed)?),
            );
        }
    }
    // Native /api/chat durations are unsigned nanoseconds, never seconds or floats.
    unsupported(v, &["duration_unit", "duration_units"])?;
    for key in [
        "total_duration",
        "load_duration",
        "prompt_eval_duration",
        "eval_duration",
    ] {
        if let Some(value) = v.get(key) {
            let ns = value.as_u64().ok_or(Failure::Malformed)?;
            if key == "total_duration" {
                usage.insert("duration_ms".to_owned(), Value::from(ns / 1_000_000));
            }
        }
    }
    Ok(Value::Object(usage))
}
pub(crate) fn response(
    n: &Normalizer,
    format: ResponseFormat,
    at: ObservedAt,
) -> Result<Vec<CanonicalObservationV2>, Failure> {
    let mut model: Option<String> = None;
    let mut content = String::new();
    let mut calls = Vec::new();
    let mut terminal = None;
    let mut consume = |v: Value| -> Result<(), Failure> {
        if terminal.is_some() {
            return Err(Failure::Conflict);
        }
        if v.get("error").is_some() {
            return Err(Failure::UpstreamError);
        }
        let resolved = text(&v, "model")?;
        if model.as_deref().is_some_and(|m| m != resolved) {
            return Err(Failure::Conflict);
        }
        if model.is_none() {
            model = Some(resolved.to_owned());
        }
        let done = v
            .get("done")
            .and_then(Value::as_bool)
            .ok_or(Failure::Malformed)?;
        let m = v.get("message").ok_or(Failure::Malformed)?;
        semantic_keys(m, &["role", "content", "tool_calls"])?;
        if text(m, "role")? != "assistant" {
            return Err(Failure::Unsupported);
        }
        append(
            &mut content,
            m.get("content")
                .and_then(Value::as_str)
                .ok_or(Failure::Malformed)?,
            n.limits.string_bytes,
        )?;
        if let Some(tools) = m.get("tool_calls") {
            for tool in tools.as_array().ok_or(Failure::Malformed)? {
                if calls.len() + 1 >= n.limits.items {
                    return Err(Failure::Capacity);
                }
                calls.push(tool.clone());
            }
        }
        if done {
            if optional_text(&v, "done_reason")?.is_some_and(|s| !["stop", "length"].contains(&s)) {
                return Err(Failure::Unsupported);
            }
            usage(&v)?;
            terminal = Some(v);
        } else {
            unsupported(
                &v,
                &[
                    "done_reason",
                    "total_duration",
                    "load_duration",
                    "prompt_eval_duration",
                    "eval_duration",
                    "prompt_eval_count",
                    "eval_count",
                ],
            )?;
        }
        Ok(())
    };
    if format == ResponseFormat::Json {
        consume(json::parse(&n.response, n.limits)?)?;
    } else {
        let wire = std::str::from_utf8(&n.response).map_err(|_| Failure::Malformed)?;
        for line in wire.split_inclusive('\n') {
            // A missing final newline is accepted only if the bounded JSON line is complete.
            let line = line.strip_suffix('\n').unwrap_or(line);
            let line = line.strip_suffix('\r').unwrap_or(line);
            if line.is_empty() {
                return Err(Failure::Malformed);
            }
            consume(json::parse(line.as_bytes(), n.limits)?)?;
        }
    }
    let terminal = terminal.ok_or(Failure::Incomplete)?;
    let mut batch = Batch::new(n, at);
    batch.inference(
        ObservationStage::InferenceStarted,
        model.as_deref(),
        None,
        None,
        &n.correlation,
    )?;
    message(
        &mut batch,
        &json!({"role":"assistant", "content":content, "tool_calls":calls}),
        0x8000_0000,
        &n.correlation,
        true,
    )?;
    batch.inference(
        ObservationStage::InferenceCompleted,
        model.as_deref(),
        optional_text(&terminal, "done_reason")?,
        Some(&usage(&terminal)?),
        &n.correlation,
    )?;
    Ok(batch.values)
}
