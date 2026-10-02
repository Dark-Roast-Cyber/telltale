use crate::{Failure, Normalizer, ResponseFormat, facts::token_usage, framing, json, mapping::*};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use telltale_schema::observation::*;

fn blocks(
    batch: &mut Batch<'_>,
    role: &str,
    content: &Value,
    base: u32,
    corr: &CorrelationIds,
) -> Result<(), Failure> {
    if let Some(text) = content.as_str() {
        return batch.text_message(role, text, base, corr, None);
    }
    let mut ids = BTreeSet::new();
    for (i, block) in content
        .as_array()
        .ok_or(Failure::Unsupported)?
        .iter()
        .enumerate()
    {
        let ordinal = base + i as u32;
        match text(block, "type")? {
            "text" => {
                semantic_keys(block, &["type", "text"])?;
                batch.text_message(
                    role,
                    block
                        .get("text")
                        .and_then(Value::as_str)
                        .ok_or(Failure::Malformed)?,
                    ordinal,
                    corr,
                    None,
                )?;
            }
            "tool_use" if role == "assistant" => {
                semantic_keys(block, &["type", "id", "name", "input"])?;
                let id = text(block, "id")?;
                if !ids.insert(id) {
                    return Err(Failure::Conflict);
                }
                batch.proposal(
                    text(block, "name")?,
                    block.get("input").ok_or(Failure::Malformed)?,
                    ordinal,
                    correlation(corr, Some(id))?,
                    None,
                )?;
            }
            "tool_result" if role == "user" => {
                semantic_keys(block, &["type", "tool_use_id", "content", "is_error"])?;
                let value = block.get("content").ok_or(Failure::Unsupported)?;
                if !value.is_string() {
                    return Err(Failure::Unsupported);
                }
                let error = block
                    .get("is_error")
                    .map(|v| v.as_bool().ok_or(Failure::Malformed))
                    .transpose()?;
                batch.result(
                    value,
                    error,
                    ordinal,
                    correlation(corr, optional_text(block, "tool_use_id")?)?,
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
    unsupported(v, &["thinking", "mcp_servers", "container"])?;
    let mut batch = Batch::new(n, at);
    batch.inference(
        ObservationStage::InferenceRequested,
        None,
        None,
        None,
        &n.correlation,
    )?;
    if let Some(system) = v.get("system") {
        blocks(&mut batch, "system", system, 0x4000_0000, &n.correlation)?;
    }
    let messages = array(v, "messages")?;
    if messages.is_empty() {
        return Err(Failure::Malformed);
    }
    for (i, message) in messages.iter().enumerate() {
        semantic_keys(message, &["role", "content"])?;
        let role = text(message, "role")?;
        if !["user", "assistant"].contains(&role) {
            return Err(Failure::Unsupported);
        }
        blocks(
            &mut batch,
            role,
            message.get("content").ok_or(Failure::Malformed)?,
            i as u32 * 257,
            &n.correlation,
        )?;
    }
    if let Some(tools) = v.get("tools") {
        for (i, tool) in tools
            .as_array()
            .ok_or(Failure::Malformed)?
            .iter()
            .enumerate()
        {
            semantic_keys(tool, &["name", "description", "input_schema"])?;
            if !tool.get("input_schema").is_some_and(Value::is_object)
                || tool.get("description").is_some_and(|v| !v.is_string())
            {
                return Err(Failure::Unsupported);
            }
            batch.definition(text(tool, "name")?, tool, i as u32, &n.correlation)?;
        }
    }
    Ok(batch.values)
}

fn stop(v: &Value) -> Result<&str, Failure> {
    let stop = text(v, "stop_reason")?;
    if !["end_turn", "max_tokens", "stop_sequence", "tool_use"].contains(&stop) {
        return Err(Failure::Unsupported);
    }
    Ok(stop)
}
fn commit(
    n: &Normalizer,
    v: &Value,
    at: ObservedAt,
) -> Result<Vec<CanonicalObservationV2>, Failure> {
    if v.get("error").is_some() {
        return Err(Failure::UpstreamError);
    }
    if text(v, "type")? != "message" || text(v, "role")? != "assistant" {
        return Err(Failure::Unsupported);
    }
    let corr = n
        .correlation
        .clone()
        .with_response_id(CorrelationId::source_reported(text(v, "id")?)?);
    let model = text(v, "model")?;
    let stop = stop(v)?;
    let usage = token_usage(v.get("usage"))?;
    let mut batch = Batch::new(n, at);
    batch.inference(
        ObservationStage::InferenceStarted,
        Some(model),
        None,
        None,
        &corr,
    )?;
    array(v, "content")?;
    blocks(
        &mut batch,
        "assistant",
        v.get("content").ok_or(Failure::Malformed)?,
        0x8000_0000,
        &corr,
    )?;
    batch.inference(
        ObservationStage::InferenceCompleted,
        Some(model),
        Some(stop),
        usage.as_ref(),
        &corr,
    )?;
    Ok(batch.values)
}

struct Block {
    value: Value,
    fragments: String,
    closed: bool,
}
pub(crate) fn response(
    n: &Normalizer,
    format: ResponseFormat,
    at: ObservedAt,
) -> Result<Vec<CanonicalObservationV2>, Failure> {
    if format == ResponseFormat::Json {
        return commit(n, &json::parse(&n.response, n.limits)?, at);
    }
    let mut message: Option<Value> = None;
    let mut blocks = BTreeMap::<u64, Block>::new();
    let mut delta_seen = false;
    let mut terminal = false;
    framing::sse(n, |v| {
        if terminal {
            return Err(Failure::Conflict);
        }
        match text(v, "type")? {
            "ping" => {}
            "error" => return Err(Failure::UpstreamError),
            "message_start" => {
                if message.is_some() {
                    return Err(Failure::Conflict);
                }
                let start = v.get("message").ok_or(Failure::Malformed)?;
                if !array(start, "content")?.is_empty()
                    || start.get("stop_reason").is_some_and(|v| !v.is_null())
                {
                    return Err(Failure::Conflict);
                }
                if text(start, "type")? != "message" || text(start, "role")? != "assistant" {
                    return Err(Failure::Unsupported);
                }
                text(start, "id")?;
                text(start, "model")?;
                token_usage(start.get("usage"))?;
                message = Some(start.clone());
            }
            "content_block_start" | "content_block_delta" | "content_block_stop" => {
                if message.is_none() || delta_seen {
                    return Err(Failure::Conflict);
                }
                let index = v
                    .get("index")
                    .and_then(Value::as_u64)
                    .ok_or(Failure::Malformed)?;
                if index >= 256 {
                    return Err(Failure::Capacity);
                }
                if text(v, "type")? == "content_block_start" {
                    if blocks.contains_key(&index) {
                        return Err(Failure::Conflict);
                    }
                    if blocks.len() >= n.limits.items {
                        return Err(Failure::Capacity);
                    }
                    // Native positions must be contiguous so JSON and SSE share ordinals.
                    if index != blocks.len() as u64 {
                        return Err(Failure::Conflict);
                    }
                    let block = v.get("content_block").ok_or(Failure::Malformed)?;
                    match text(block, "type")? {
                        "text" => {
                            semantic_keys(block, &["type", "text"])?;
                            block
                                .get("text")
                                .and_then(Value::as_str)
                                .ok_or(Failure::Malformed)?;
                        }
                        "tool_use" => {
                            semantic_keys(block, &["type", "id", "name", "input"])?;
                            text(block, "id")?;
                            text(block, "name")?;
                            if block.get("input") != Some(&json!({})) {
                                return Err(Failure::Unsupported);
                            }
                        }
                        _ => return Err(Failure::Unsupported),
                    }
                    blocks.insert(
                        index,
                        Block {
                            value: block.clone(),
                            fragments: String::new(),
                            closed: false,
                        },
                    );
                } else {
                    let block = blocks.get_mut(&index).ok_or(Failure::Conflict)?;
                    if block.closed {
                        return Err(Failure::Conflict);
                    }
                    if text(v, "type")? == "content_block_stop" {
                        if !block.fragments.is_empty() {
                            block.value["input"] =
                                json::parse(block.fragments.as_bytes(), n.limits)?;
                        }
                        block.closed = true;
                    } else {
                        let delta = v.get("delta").ok_or(Failure::Malformed)?;
                        match (text(&block.value, "type")?, text(delta, "type")?) {
                            ("text", "text_delta") => {
                                semantic_keys(delta, &["type", "text"])?;
                                let mut content = block.value["text"]
                                    .as_str()
                                    .ok_or(Failure::Malformed)?
                                    .to_owned();
                                append(
                                    &mut content,
                                    delta
                                        .get("text")
                                        .and_then(Value::as_str)
                                        .ok_or(Failure::Malformed)?,
                                    n.limits.string_bytes,
                                )?;
                                block.value["text"] = Value::String(content);
                            }
                            ("tool_use", "input_json_delta") => {
                                semantic_keys(delta, &["type", "partial_json"])?;
                                append(
                                    &mut block.fragments,
                                    delta
                                        .get("partial_json")
                                        .and_then(Value::as_str)
                                        .ok_or(Failure::Malformed)?,
                                    n.limits.string_bytes,
                                )?;
                            }
                            _ => return Err(Failure::Unsupported),
                        }
                    }
                }
            }
            "message_delta" => {
                if blocks.values().any(|b| !b.closed) {
                    return Err(Failure::Incomplete);
                }
                let message = message.as_mut().ok_or(Failure::Conflict)?;
                let delta = v.get("delta").ok_or(Failure::Malformed)?;
                semantic_keys(delta, &["stop_reason", "stop_sequence"])?;
                if let Some(old) = message.get("stop_reason").filter(|v| !v.is_null())
                    && delta.get("stop_reason") != Some(old)
                {
                    return Err(Failure::Conflict);
                }
                stop(delta)?;
                message["stop_reason"] = delta["stop_reason"].clone();
                if let Some(usage) = v.get("usage") {
                    token_usage(Some(usage))?;
                    if !message.get("usage").is_some_and(Value::is_object) {
                        message["usage"] = json!({});
                    }
                    for key in ["input_tokens", "output_tokens"] {
                        if let Some(value) = usage.get(key) {
                            message["usage"][key] = value.clone();
                        }
                    }
                }
                delta_seen = true;
            }
            "message_stop" => {
                if !delta_seen || blocks.values().any(|b| !b.closed) {
                    return Err(Failure::Incomplete);
                }
                terminal = true;
            }
            _ => return Err(Failure::Unsupported),
        }
        Ok(())
    })?;
    if !terminal {
        return Err(Failure::Incomplete);
    }
    let mut message = message.ok_or(Failure::Incomplete)?;
    message["content"] = Value::Array(blocks.into_values().map(|b| b.value).collect());
    commit(n, &message, at)
}
