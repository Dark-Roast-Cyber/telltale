use crate::{Failure, Normalizer, ResponseFormat, facts::token_usage, framing, json, mapping::*};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use telltale_schema::observation::*;

fn item_local(v: &Value) -> Result<Option<LocalEvidence>, Failure> {
    optional_text(v, "id")?
        .map(|id| {
            Ok(LocalEvidence::new().insert(
                "inference.response",
                LocalValue::new(
                    semantic(&json!({"id":id}))?,
                    None::<String>,
                    FactProvenance::Reported,
                    Sensitivity::Sensitive,
                )?,
            )?)
        })
        .transpose()
}
fn message(
    batch: &mut Batch<'_>,
    v: &Value,
    ordinal: u32,
    corr: &CorrelationIds,
    output: bool,
) -> Result<(), Failure> {
    semantic_keys(v, &["type", "id", "role", "status", "content"])?;
    let role = text(v, "role")?;
    if output && role != "assistant" {
        return Err(Failure::Unsupported);
    }
    if let Some(content) = v.get("content").and_then(Value::as_str) {
        if output {
            return Err(Failure::Unsupported);
        }
        return batch.text_message(role, content, ordinal, corr, item_local(v)?);
    }
    for (i, part) in array(v, "content")?.iter().enumerate() {
        semantic_keys(part, &["type", "text", "annotations", "logprobs"])?;
        let kind = text(part, "type")?;
        if !(kind == "output_text" || (!output && kind == "input_text")) {
            return Err(Failure::Unsupported);
        }
        for key in ["annotations", "logprobs"] {
            if part
                .get(key)
                .is_some_and(|v| !v.as_array().is_some_and(Vec::is_empty))
            {
                return Err(Failure::Unsupported);
            }
        }
        batch.text_message(
            role,
            part.get("text")
                .and_then(Value::as_str)
                .ok_or(Failure::Malformed)?,
            ordinal + i as u32,
            corr,
            item_local(v)?,
        )?;
    }
    Ok(())
}
fn items(
    n: &Normalizer,
    batch: &mut Batch<'_>,
    values: &[Value],
    corr: &CorrelationIds,
    output: bool,
) -> Result<(), Failure> {
    let mut ids = BTreeSet::new();
    let mut calls = BTreeSet::new();
    for (i, item) in values.iter().enumerate() {
        if let Some(id) = optional_text(item, "id")?
            && !ids.insert(id)
        {
            return Err(Failure::Conflict);
        }
        if output && optional_text(item, "status")?.is_some_and(|s| s != "completed") {
            return Err(Failure::Incomplete);
        }
        let ordinal = if output { 0x8000_0000 } else { 0 } + i as u32 * 257;
        match optional_text(item, "type")?.unwrap_or("message") {
            "message" => message(batch, item, ordinal, corr, output)?,
            "function_call" => {
                semantic_keys(
                    item,
                    &["type", "id", "call_id", "name", "arguments", "status"],
                )?;
                let call = optional_text(item, "call_id")?;
                if call.is_some_and(|id| !calls.insert(id)) {
                    return Err(Failure::Conflict);
                }
                let args = json::parse(text(item, "arguments")?.as_bytes(), n.limits)?;
                batch.proposal(
                    text(item, "name")?,
                    &args,
                    ordinal,
                    correlation(corr, call)?,
                    item_local(item)?,
                )?;
            }
            "function_call_output" if !output => {
                semantic_keys(item, &["type", "call_id", "output"])?;
                let value = item
                    .get("output")
                    .filter(|v| v.is_string())
                    .ok_or(Failure::Unsupported)?;
                batch.result(
                    value,
                    None,
                    ordinal,
                    correlation(corr, optional_text(item, "call_id")?)?,
                )?;
            }
            _ => return Err(Failure::Unsupported),
        }
    }
    Ok(())
}
pub(crate) fn request(
    n: &Normalizer,
    v: &Value,
    at: ObservedAt,
) -> Result<Vec<CanonicalObservationV2>, Failure> {
    // A referenced conversation cannot truthfully be claimed as visible input.
    unsupported(
        v,
        &[
            "previous_response_id",
            "conversation",
            "reasoning",
            "background",
        ],
    )?;
    let mut batch = Batch::new(n, at);
    batch.inference(
        ObservationStage::InferenceRequested,
        None,
        None,
        None,
        &n.correlation,
    )?;
    if let Some(instructions) = v.get("instructions").filter(|v| !v.is_null()) {
        batch.text_message(
            "system",
            instructions.as_str().ok_or(Failure::Unsupported)?,
            0x4000_0000,
            &n.correlation,
            None,
        )?;
    }
    let input = v.get("input").ok_or(Failure::Malformed)?;
    if let Some(content) = input.as_str() {
        batch.text_message("user", content, 0, &n.correlation, None)?;
    } else {
        items(
            n,
            &mut batch,
            input.as_array().ok_or(Failure::Unsupported)?,
            &n.correlation,
            false,
        )?;
    }
    if let Some(tools) = v.get("tools") {
        for (i, tool) in tools
            .as_array()
            .ok_or(Failure::Malformed)?
            .iter()
            .enumerate()
        {
            semantic_keys(
                tool,
                &["type", "name", "description", "parameters", "strict"],
            )?;
            if text(tool, "type")? != "function" {
                return Err(Failure::Unsupported);
            }
            for (key, valid) in [
                ("parameters", Value::is_object as fn(&Value) -> bool),
                ("description", Value::is_string),
                ("strict", Value::is_boolean),
            ] {
                if tool.get(key).is_some_and(|v| !valid(v)) {
                    return Err(Failure::Malformed);
                }
            }
            batch.definition(text(tool, "name")?, tool, i as u32, &n.correlation)?;
        }
    }
    Ok(batch.values)
}
fn commit(
    n: &Normalizer,
    v: &Value,
    at: ObservedAt,
) -> Result<Vec<CanonicalObservationV2>, Failure> {
    if v.get("error").is_some_and(|v| !v.is_null()) {
        return Err(Failure::UpstreamError);
    }
    if text(v, "status")? != "completed" {
        return Err(Failure::Incomplete);
    }
    if text(v, "object")? != "response" {
        return Err(Failure::Unsupported);
    }
    unsupported(v, &["incomplete_details"])?;
    let corr = n
        .correlation
        .clone()
        .with_response_id(CorrelationId::source_reported(text(v, "id")?)?);
    let model = text(v, "model")?;
    let usage = token_usage(v.get("usage"))?;
    let mut batch = Batch::new(n, at);
    batch.inference(
        ObservationStage::InferenceStarted,
        Some(model),
        None,
        None,
        &corr,
    )?;
    items(n, &mut batch, array(v, "output")?, &corr, true)?;
    // "completed" is lifecycle, not a native stop reason or success status.
    batch.inference(
        ObservationStage::InferenceCompleted,
        Some(model),
        None,
        usage.as_ref(),
        &corr,
    )?;
    Ok(batch.values)
}
struct Item {
    value: Value,
    closed: bool,
    arguments_done: bool,
    parts_done: Vec<bool>,
    text_done: Vec<bool>,
}
pub(crate) fn response(
    n: &Normalizer,
    format: ResponseFormat,
    at: ObservedAt,
) -> Result<Vec<CanonicalObservationV2>, Failure> {
    if format == ResponseFormat::Json {
        return commit(n, &json::parse(&n.response, n.limits)?, at);
    }
    let mut start: Option<Value> = None;
    let mut terminal: Option<Value> = None;
    let mut items: Vec<Item> = Vec::new();
    let mut sequence = None;
    let mut count = 0;
    framing::sse(n, |v| {
        if terminal.is_some() {
            return Err(Failure::Conflict);
        }
        if let Some(s) = v.get("sequence_number") {
            let s = s.as_u64().ok_or(Failure::Malformed)?;
            if sequence.is_some_and(|old| s <= old) {
                return Err(Failure::Conflict);
            }
            sequence = Some(s);
        }
        let kind = text(v, "type")?;
        if v.get("logprobs")
            .is_some_and(|v| !v.as_array().is_some_and(Vec::is_empty))
        {
            return Err(Failure::Unsupported);
        }
        match kind {
            "error" | "response.failed" => return Err(Failure::UpstreamError),
            "response.incomplete" => return Err(Failure::Incomplete),
            "response.created" => {
                if start.is_some() {
                    return Err(Failure::Conflict);
                }
                let r = v.get("response").ok_or(Failure::Malformed)?;
                if text(r, "status")? != "in_progress"
                    || text(r, "object")? != "response"
                    || !array(r, "output")?.is_empty()
                {
                    return Err(Failure::Conflict);
                }
                text(r, "id")?;
                text(r, "model")?;
                start = Some(r.clone());
            }
            "response.in_progress" | "response.completed" => {
                let first = start.as_ref().ok_or(Failure::Conflict)?;
                let r = v.get("response").ok_or(Failure::Malformed)?;
                if r.get("id") != first.get("id") || r.get("model") != first.get("model") {
                    return Err(Failure::Conflict);
                }
                if kind == "response.completed" {
                    if text(r, "status")? != "completed" || items.iter().any(|i| !i.closed) {
                        return Err(Failure::Incomplete);
                    }
                    let output = array(r, "output")?;
                    if output.len() != items.len()
                        || output.iter().zip(&items).any(|(a, b)| a != &b.value)
                    {
                        return Err(Failure::Conflict);
                    }
                    terminal = Some(r.clone());
                } else if text(r, "status")? != "in_progress" || !array(r, "output")?.is_empty() {
                    return Err(Failure::Conflict);
                }
            }
            "response.output_item.added" => {
                if start.is_none() {
                    return Err(Failure::Conflict);
                }
                let index = index_fn(v, "output_index")?;
                if index != items.len() {
                    return Err(Failure::Conflict);
                }
                if count >= n.limits.items {
                    return Err(Failure::Capacity);
                }
                count += 1;
                let item = v.get("item").ok_or(Failure::Malformed)?;
                let id = text(item, "id")?;
                if items
                    .iter()
                    .any(|i| i.value.get("id").and_then(Value::as_str) == Some(id))
                {
                    return Err(Failure::Conflict);
                }
                match text(item, "type")? {
                    "message" if array(item, "content")?.is_empty() => {}
                    "function_call"
                        if item.get("arguments").and_then(Value::as_str) == Some("") => {}
                    _ => return Err(Failure::Unsupported),
                }
                if text(item, "status")? != "in_progress" {
                    return Err(Failure::Conflict);
                }
                items.push(Item {
                    value: item.clone(),
                    closed: false,
                    arguments_done: false,
                    parts_done: Vec::new(),
                    text_done: Vec::new(),
                });
            }
            "response.output_item.done"
            | "response.content_part.added"
            | "response.content_part.done"
            | "response.output_text.delta"
            | "response.output_text.done"
            | "response.function_call_arguments.delta"
            | "response.function_call_arguments.done" => {
                let index = index_fn(v, "output_index")?;
                let item = items.get_mut(index).ok_or(Failure::Conflict)?;
                if item.closed {
                    return Err(Failure::Conflict);
                }
                if kind == "response.output_item.done" {
                    if (text(&item.value, "type")? == "function_call" && !item.arguments_done)
                        || item.parts_done.iter().any(|done| !done)
                    {
                        return Err(Failure::Incomplete);
                    }
                    let done = v.get("item").ok_or(Failure::Malformed)?;
                    item.value["status"] = json!("completed");
                    if done != &item.value {
                        return Err(Failure::Conflict);
                    }
                    item.closed = true;
                } else {
                    if v.get("item_id") != item.value.get("id") {
                        return Err(Failure::Conflict);
                    }
                    if kind.contains("function_call_arguments") {
                        if text(&item.value, "type")? != "function_call" || item.arguments_done {
                            return Err(Failure::Conflict);
                        }
                        if kind.ends_with(".done") {
                            if v.get("arguments") != item.value.get("arguments") {
                                return Err(Failure::Conflict);
                            }
                            if v.get("name")
                                .is_some_and(|name| Some(name) != item.value.get("name"))
                            {
                                return Err(Failure::Conflict);
                            }
                            item.arguments_done = true;
                        } else {
                            append_field(
                                &mut item.value,
                                "arguments",
                                v,
                                "delta",
                                n.limits.string_bytes,
                            )?;
                        }
                    } else {
                        if text(&item.value, "type")? != "message" {
                            return Err(Failure::Conflict);
                        }
                        let ci = index_fn(v, "content_index")?;
                        if kind == "response.content_part.added" {
                            if ci != item.parts_done.len() {
                                return Err(Failure::Conflict);
                            }
                            if count >= n.limits.items {
                                return Err(Failure::Capacity);
                            }
                            count += 1;
                            let part = v.get("part").ok_or(Failure::Malformed)?;
                            if text(part, "type")? != "output_text"
                                || part.get("text").and_then(Value::as_str) != Some("")
                            {
                                return Err(Failure::Unsupported);
                            }
                            item.value["content"]
                                .as_array_mut()
                                .ok_or(Failure::Malformed)?
                                .push(part.clone());
                            item.parts_done.push(false);
                            item.text_done.push(false);
                        } else {
                            if *item.parts_done.get(ci).ok_or(Failure::Conflict)? {
                                return Err(Failure::Conflict);
                            }
                            let part =
                                item.value["content"].get_mut(ci).ok_or(Failure::Conflict)?;
                            if kind == "response.content_part.done" {
                                if !item.text_done[ci] || v.get("part") != Some(part) {
                                    return Err(Failure::Conflict);
                                }
                                item.parts_done[ci] = true;
                            } else {
                                if item.text_done[ci] {
                                    return Err(Failure::Conflict);
                                }
                                if kind.ends_with(".done") {
                                    if v.get("text") != part.get("text") {
                                        return Err(Failure::Conflict);
                                    }
                                    item.text_done[ci] = true;
                                } else {
                                    append_field(part, "text", v, "delta", n.limits.string_bytes)?;
                                }
                            }
                        }
                    }
                }
            }
            _ => return Err(Failure::Unsupported),
        }
        Ok(())
    })?;
    commit(n, &terminal.ok_or(Failure::Incomplete)?, at)
}
fn index_fn(v: &Value, key: &str) -> Result<usize, Failure> {
    let i = v
        .get(key)
        .and_then(Value::as_u64)
        .ok_or(Failure::Malformed)?;
    if i >= 256 {
        return Err(Failure::Capacity);
    }
    Ok(i as usize)
}
fn append_field(
    target: &mut Value,
    key: &str,
    event: &Value,
    field: &str,
    max: usize,
) -> Result<(), Failure> {
    let mut value = target
        .get(key)
        .and_then(Value::as_str)
        .ok_or(Failure::Malformed)?
        .to_owned();
    append(
        &mut value,
        event
            .get(field)
            .and_then(Value::as_str)
            .ok_or(Failure::Malformed)?,
        max,
    )?;
    target[key] = Value::String(value);
    Ok(())
}
