use crate::{Failure, Normalizer, ResponseFormat, json};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use telltale_schema::observation::*;

pub(crate) fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str, Failure> {
    v.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or(Failure::Malformed)
}
pub(crate) fn array<'a>(v: &'a Value, key: &str) -> Result<&'a Vec<Value>, Failure> {
    v.get(key)
        .and_then(Value::as_array)
        .ok_or(Failure::Malformed)
}
pub(crate) fn optional_text<'a>(v: &'a Value, key: &str) -> Result<Option<&'a str>, Failure> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(_) => text(v, key).map(Some),
    }
}
pub(crate) fn unsupported(v: &Value, keys: &[&str]) -> Result<(), Failure> {
    if !v.is_object() {
        return Err(Failure::Malformed);
    }
    if keys
        .iter()
        .any(|key| v.get(key).is_some_and(|x| !x.is_null()))
    {
        return Err(Failure::Unsupported);
    }
    Ok(())
}
pub(crate) fn semantic_keys(v: &Value, keys: &[&str]) -> Result<(), Failure> {
    let object = v.as_object().ok_or(Failure::Malformed)?;
    if object.keys().any(|key| !keys.contains(&key.as_str())) {
        return Err(Failure::Unsupported);
    }
    Ok(())
}
pub(crate) fn semantic(v: &Value) -> Result<JsonValue, Failure> {
    JsonValue::try_from_source_value(v).map_err(|_| Failure::Capacity)
}
pub(crate) fn correlation(
    base: &CorrelationIds,
    call: Option<&str>,
) -> Result<CorrelationIds, Failure> {
    let mut result = base.clone();
    if let Some(call) = call {
        result = result.with_call_id(CorrelationId::source_reported(call)?);
    }
    Ok(result)
}

pub(crate) struct Batch<'a> {
    n: &'a Normalizer,
    at: ObservedAt,
    pub(crate) values: Vec<CanonicalObservationV2>,
    items: usize,
}
impl<'a> Batch<'a> {
    pub(crate) fn new(n: &'a Normalizer, at: ObservedAt) -> Self {
        Self {
            n,
            at,
            values: Vec::new(),
            items: 0,
        }
    }
    pub(crate) fn item(&mut self) -> Result<(), Failure> {
        if self.items >= self.n.limits.items {
            return Err(Failure::Capacity);
        }
        self.items += 1;
        Ok(())
    }
    pub(crate) fn emit(
        &mut self,
        body: ObservationBody,
        stage: ObservationStage,
        ordinal: u32,
        fields: &[(&str, FactProvenance)],
        correlation: CorrelationIds,
        local: Option<LocalEvidence>,
    ) -> Result<(), Failure> {
        if self.values.len() >= self.n.limits.output_observations {
            return Err(Failure::Capacity);
        }
        let command =
            match &body {
                ObservationBody::Tool(tool) if stage == ObservationStage::ToolProposed => {
                    match tool.arguments() {
                        Some(JsonValue::Object(arguments)) => ["command", "cmd"]
                            .into_iter()
                            .find_map(|key| match arguments.get(key) {
                                Some(JsonValue::String(command)) => Some(command.clone()),
                                _ => None,
                            }),
                        _ => None,
                    }
                }
                _ => None,
            };
        let mut builder =
            CanonicalObservationV2::builder(body, stage, self.at.clone(), self.n.source.clone())
                .child_ordinal(ordinal)
                .correlation(correlation)
                .capability_context(
                    CapabilityContext::new()
                        .with_override(
                            CapabilityId::ToolExecution,
                            CapabilityAvailability::Unsupported,
                        )
                        .with_override(CapabilityId::ToolCall, CapabilityAvailability::Supported)
                        .with_override(
                            CapabilityId::UserContext,
                            CapabilityAvailability::Supported,
                        ),
                );
        for &(field, provenance) in fields {
            builder = builder.fact_metadata(
                field,
                FactMetadata::new(provenance, Sensitivity::Sensitive)?,
            );
        }
        if let Some(command) = command {
            builder = builder
                .facet(
                    "command.text",
                    SemanticFacet::new(JsonValue::string(command)),
                )?
                .fact_metadata(
                    "command.text",
                    FactMetadata::new(FactProvenance::Parsed, Sensitivity::Sensitive)?,
                );
        }
        if let Some(local) = local {
            builder = builder.local(local);
        }
        let observation = builder.build()?;
        self.values.reserve_exact(1);
        self.values.push(observation);
        Ok(())
    }
    pub(crate) fn inference(
        &mut self,
        stage: ObservationStage,
        resolved: Option<&str>,
        stop: Option<&str>,
        usage: Option<&Value>,
        corr: &CorrelationIds,
    ) -> Result<(), Failure> {
        let mut body = InferenceObservation::new()
            .with_requested_model(&self.n.requested_model)?
            .with_streaming(self.n.streaming);
        let mut fields = vec![
            ("inference.requested_model", FactProvenance::Reported),
            ("inference.streaming", FactProvenance::Parsed),
        ];
        if let Some(model) = resolved {
            body = body.with_resolved_model(model)?;
            fields.push(("inference.resolved_model", FactProvenance::Reported));
        }
        if let Some(stop) = stop {
            body = body.with_stop_reason(stop)?;
            fields.push(("inference.stop_reason", FactProvenance::Reported));
        }
        if let Some(usage) = usage {
            let mut metrics = InferenceMetrics::default();
            let mut any = false;
            for key in ["prompt_tokens", "completion_tokens"] {
                if let Some(v) = usage.get(key) {
                    let count = v.as_u64().ok_or(Failure::Malformed)?;
                    metrics = if key == "prompt_tokens" {
                        metrics.with_input_tokens(count)
                    } else {
                        metrics.with_output_tokens(count)
                    };
                    any = true;
                }
            }
            if let Some(v) = usage
                .get("completion_tokens_details")
                .and_then(|v| v.get("reasoning_tokens"))
            {
                metrics = metrics.with_reasoning_tokens(v.as_u64().ok_or(Failure::Malformed)?);
                any = true;
            }
            if self.n.profile == crate::Profile::OllamaChat
                && let Some(v) = usage.get("duration_ms")
            {
                metrics = metrics.with_duration_ms(v.as_u64().ok_or(Failure::Malformed)?);
                any = true;
            }
            if any {
                body = body.with_metrics(metrics);
                fields.push(("inference.metrics", FactProvenance::Reported));
            }
        }
        self.emit(
            ObservationBody::Inference(body),
            stage,
            0,
            &fields,
            corr.clone(),
            None,
        )
    }
    fn message(&mut self, v: &Value, ordinal: u32, corr: &CorrelationIds) -> Result<(), Failure> {
        unsupported(
            v,
            &["function_call", "audio", "refusal", "reasoning", "thinking"],
        )?;
        semantic_keys(
            v,
            &[
                "role",
                "content",
                "name",
                "tool_calls",
                "tool_call_id",
                "refusal",
                "audio",
            ],
        )?;
        let role = match text(v, "role")? {
            "system" => MessageRole::System,
            "developer" => MessageRole::Developer,
            "user" => MessageRole::User,
            "assistant" => MessageRole::Assistant,
            "tool" => MessageRole::Tool,
            _ => return Err(Failure::Unsupported),
        };
        if role == MessageRole::Tool {
            self.item()?;
            let content = v
                .get("content")
                .and_then(Value::as_str)
                .ok_or(Failure::Unsupported)?;
            let body =
                ToolObservation::new().with_result(semantic(&Value::String(content.to_owned()))?);
            self.emit(
                ObservationBody::Tool(body),
                ObservationStage::ToolResultReturned,
                ordinal,
                &[("tool.result", FactProvenance::Reported)],
                correlation(corr, optional_text(v, "tool_call_id")?)?,
                None,
            )?;
        } else {
            if v.get("tool_call_id").is_some() {
                return Err(Failure::Unsupported);
            }
            if role != MessageRole::Assistant && !v.get("content").is_some_and(Value::is_string) {
                return Err(Failure::Unsupported);
            }
            self.item()?;
            let mut body = MessageObservation::new(role);
            let mut fields = vec![("message.role", FactProvenance::Reported)];
            if let Some(content) = v.get("content").filter(|v| !v.is_null()) {
                if !content.is_string() {
                    return Err(Failure::Unsupported);
                }
                body = body.with_content(semantic(content)?);
                fields.push(("message.content", FactProvenance::Reported));
            }
            self.emit(
                ObservationBody::Message(body),
                ObservationStage::MessageObserved,
                ordinal,
                &fields,
                corr.clone(),
                None,
            )?;
        }
        if let Some(calls) = v.get("tool_calls") {
            if role != MessageRole::Assistant {
                return Err(Failure::Unsupported);
            }
            let calls = calls.as_array().ok_or(Failure::Malformed)?;
            let mut ids = BTreeSet::new();
            for (i, call) in calls.iter().enumerate() {
                if i >= 256 {
                    return Err(Failure::Capacity);
                }
                let id = optional_text(call, "id")?;
                if id.is_some_and(|id| !ids.insert(id)) {
                    return Err(Failure::Conflict);
                }
                self.tool(call, ordinal + i as u32 + 1, corr)?;
            }
        }
        Ok(())
    }
    fn tool(&mut self, v: &Value, ordinal: u32, corr: &CorrelationIds) -> Result<(), Failure> {
        self.item()?;
        if text(v, "type")? != "function" {
            return Err(Failure::Unsupported);
        }
        let function = v.get("function").ok_or(Failure::Malformed)?;
        let args = json::parse(text(function, "arguments")?.as_bytes(), self.n.limits)?;
        if !args.is_object() {
            return Err(Failure::Unsupported);
        }
        let body = ToolObservation::new()
            .with_name(text(function, "name")?)?
            .with_arguments(semantic(&args)?);
        self.emit(
            ObservationBody::Tool(body),
            ObservationStage::ToolProposed,
            ordinal,
            &[
                ("tool.name", FactProvenance::Reported),
                ("tool.arguments", FactProvenance::Parsed),
            ],
            correlation(corr, optional_text(v, "id")?)?,
            None,
        )
    }
}

pub(crate) fn request(
    n: &Normalizer,
    v: &Value,
    at: ObservedAt,
) -> Result<Vec<CanonicalObservationV2>, Failure> {
    unsupported(v, &["functions", "function_call", "audio", "modalities"])?;
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
    for (i, message) in messages.iter().enumerate() {
        if i >= 256 {
            return Err(Failure::Capacity);
        }
        batch.message(message, i as u32 * 257, &n.correlation)?;
    }
    if let Some(tools) = v.get("tools") {
        for (i, tool) in tools
            .as_array()
            .ok_or(Failure::Malformed)?
            .iter()
            .enumerate()
        {
            batch.item()?;
            if text(tool, "type")? != "function" {
                return Err(Failure::Unsupported);
            }
            let function = tool.get("function").ok_or(Failure::Malformed)?;
            for (key, valid) in [
                ("description", Value::is_string as fn(&Value) -> bool),
                ("parameters", Value::is_object),
                ("strict", Value::is_boolean),
            ] {
                if function.get(key).is_some_and(|v| !valid(v)) {
                    return Err(Failure::Unsupported);
                }
            }
            let body =
                ToolDefinitionObservation::new("present")?.with_name(text(function, "name")?)?;
            // Retain selected definition fields, not the wire object or unknown extensions.
            let mut selected = serde_json::Map::new();
            for key in ["name", "description", "parameters", "strict"] {
                if let Some(value) = function.get(key) {
                    selected.insert(key.to_owned(), value.clone());
                }
            }
            let local = LocalEvidence::new().insert(
                "tool_definition.definition",
                LocalValue::new(
                    semantic(&Value::Object(selected))?,
                    None::<String>,
                    FactProvenance::Parsed,
                    Sensitivity::Sensitive,
                )?,
            )?;
            batch.emit(
                ObservationBody::ToolDefinition(body),
                ObservationStage::DefinitionChanged,
                i as u32,
                &[
                    ("tool_definition.name", FactProvenance::Reported),
                    ("tool_definition.change", FactProvenance::Parsed),
                ],
                n.correlation.clone(),
                Some(local),
            )?;
        }
    }
    Ok(batch.values)
}

#[derive(Default)]
struct Tool {
    id: Option<String>,
    name: Option<String>,
    arguments: String,
    kind: bool,
}
#[derive(Default)]
struct Choice {
    role: bool,
    content: Option<String>,
    tools: BTreeMap<u32, Tool>,
    stop: Option<String>,
}
#[derive(Default)]
struct Response {
    id: Option<String>,
    model: Option<String>,
    choices: BTreeMap<u32, Choice>,
    usage: Option<Value>,
    items: usize,
}

fn fixed(target: &mut Option<String>, value: &str) -> Result<(), Failure> {
    if target.as_ref().is_some_and(|old| old != value) {
        return Err(Failure::Conflict);
    }
    if target.is_none() {
        *target = Some(value.to_owned());
    }
    Ok(())
}
pub(crate) fn append(target: &mut String, value: &str, max: usize) -> Result<(), Failure> {
    if target
        .len()
        .checked_add(value.len())
        .ok_or(Failure::Capacity)?
        > max
    {
        return Err(Failure::Capacity);
    }
    target.reserve_exact(value.len());
    target.push_str(value);
    Ok(())
}
fn index(v: &Value) -> Result<u32, Failure> {
    let value = v
        .get("index")
        .and_then(Value::as_u64)
        .ok_or(Failure::Malformed)?;
    if value >= 256 {
        return Err(Failure::Capacity);
    }
    Ok(value as u32)
}
fn stop(v: &Value) -> Result<Option<&str>, Failure> {
    let value = optional_text(v, "finish_reason")?;
    if value.is_some_and(|s| !["stop", "length", "tool_calls", "content_filter"].contains(&s)) {
        return Err(Failure::Unsupported);
    }
    Ok(value)
}
impl Response {
    fn chunk(&mut self, n: &Normalizer, v: &Value, streaming: bool) -> Result<(), Failure> {
        if v.get("error").is_some() {
            return Err(Failure::UpstreamError);
        }
        unsupported(v, &["event", "type"])?;
        if let Some(object) = optional_text(v, "object")?
            && object
                != if streaming {
                    "chat.completion.chunk"
                } else {
                    "chat.completion"
                }
        {
            return Err(Failure::Unsupported);
        }
        if let Some(id) = optional_text(v, "id")? {
            fixed(&mut self.id, id)?;
        }
        fixed(&mut self.model, text(v, "model")?)?;
        let choices = array(v, "choices")?;
        if self.usage.is_some() {
            return Err(Failure::Conflict);
        }
        if let Some(usage) = v.get("usage").filter(|v| !v.is_null()) {
            if !usage.is_object()
                || (streaming
                    && (!choices.is_empty()
                        || self.choices.is_empty()
                        || self.choices.values().any(|c| c.stop.is_none())))
            {
                return Err(Failure::Conflict);
            }
            self.usage = Some(usage.clone());
        }
        let mut seen = BTreeSet::new();
        for native in choices {
            let i = index(native)?;
            if !seen.insert(i) {
                return Err(Failure::Conflict);
            }
            if let std::collections::btree_map::Entry::Vacant(entry) = self.choices.entry(i) {
                if self.items >= n.limits.items {
                    return Err(Failure::Capacity);
                }
                self.items += 1;
                entry.insert(Choice::default());
            }
            let choice = self.choices.get_mut(&i).ok_or(Failure::Malformed)?;
            if choice.stop.is_some() {
                return Err(Failure::Conflict);
            }
            let delta = native
                .get(if streaming { "delta" } else { "message" })
                .ok_or(Failure::Malformed)?;
            unsupported(
                delta,
                &["function_call", "refusal", "audio", "reasoning", "thinking"],
            )?;
            semantic_keys(
                delta,
                &["role", "content", "tool_calls", "refusal", "audio"],
            )?;
            if let Some(role) = optional_text(delta, "role")? {
                if role != "assistant" {
                    return Err(Failure::Unsupported);
                }
                choice.role = true;
            }
            if let Some(content) = delta.get("content").filter(|v| !v.is_null()) {
                append(
                    choice.content.get_or_insert_with(String::new),
                    content.as_str().ok_or(Failure::Unsupported)?,
                    n.limits.string_bytes,
                )?;
            }
            if let Some(tools) = delta.get("tool_calls") {
                let mut seen_tools = BTreeSet::new();
                for (position, tool) in tools
                    .as_array()
                    .ok_or(Failure::Malformed)?
                    .iter()
                    .enumerate()
                {
                    let ti = if streaming {
                        index(tool)?
                    } else {
                        position as u32
                    };
                    if ti >= 256 {
                        return Err(Failure::Capacity);
                    }
                    if !seen_tools.insert(ti) {
                        return Err(Failure::Conflict);
                    }
                    if let std::collections::btree_map::Entry::Vacant(entry) =
                        choice.tools.entry(ti)
                    {
                        if self.items >= n.limits.items {
                            return Err(Failure::Capacity);
                        }
                        self.items += 1;
                        entry.insert(Tool::default());
                    }
                    let target = choice.tools.get_mut(&ti).ok_or(Failure::Malformed)?;
                    if let Some(id) = optional_text(tool, "id")? {
                        fixed(&mut target.id, id)?;
                    }
                    if let Some(kind) = optional_text(tool, "type")? {
                        if kind != "function" {
                            return Err(Failure::Unsupported);
                        }
                        target.kind = true;
                    }
                    let function = tool.get("function").ok_or(Failure::Malformed)?;
                    if let Some(name) = optional_text(function, "name")? {
                        fixed(&mut target.name, name)?;
                    }
                    if let Some(args) = function.get("arguments") {
                        append(
                            &mut target.arguments,
                            args.as_str().ok_or(Failure::Malformed)?,
                            n.limits.string_bytes,
                        )?;
                    }
                }
            }
            choice.stop = stop(native)?.map(str::to_owned);
        }
        Ok(())
    }
    fn commit(
        self,
        n: &Normalizer,
        at: ObservedAt,
    ) -> Result<Vec<CanonicalObservationV2>, Failure> {
        if self.choices.is_empty() || self.choices.values().any(|c| c.stop.is_none() || !c.role) {
            return Err(Failure::Incomplete);
        }
        let mut corr = n.correlation.clone();
        if let Some(id) = &self.id {
            corr = corr.with_response_id(CorrelationId::source_reported(id)?);
        }
        // COv2 has one inference stop reason, not per-choice lifecycle. Do not
        // collapse conflicting choice outcomes or fabricate independent requests.
        let stop = self
            .choices
            .values()
            .next()
            .and_then(|c| c.stop.as_deref())
            .ok_or(Failure::Incomplete)?;
        if self
            .choices
            .values()
            .any(|c| c.stop.as_deref() != Some(stop))
        {
            return Err(Failure::Unsupported);
        }
        let mut batch = Batch::new(n, at);
        batch.inference(
            ObservationStage::InferenceStarted,
            self.model.as_deref(),
            None,
            None,
            &corr,
        )?;
        let mut ids = BTreeSet::new();
        for (i, choice) in &self.choices {
            let ordinal = 0x8000_0000 + i * 257;
            batch.item()?;
            let mut body = MessageObservation::new(MessageRole::Assistant);
            let mut fields = vec![("message.role", FactProvenance::Reported)];
            if let Some(content) = &choice.content {
                body = body.with_content(semantic(&Value::String(content.clone()))?);
                fields.push(("message.content", FactProvenance::Reported));
            }
            batch.emit(
                ObservationBody::Message(body),
                ObservationStage::MessageObserved,
                ordinal,
                &fields,
                corr.clone(),
                None,
            )?;
            for (ti, tool) in &choice.tools {
                if !tool.kind || tool.name.is_none() {
                    return Err(Failure::Incomplete);
                }
                if tool.id.as_ref().is_some_and(|id| !ids.insert(id)) {
                    return Err(Failure::Conflict);
                }
                let value = serde_json::json!({"type":"function", "id":tool.id,
                    "function":{"name":tool.name,"arguments":tool.arguments}});
                batch.tool(&value, ordinal + ti + 1, &corr)?;
            }
        }
        batch.inference(
            ObservationStage::InferenceCompleted,
            self.model.as_deref(),
            Some(stop),
            self.usage.as_ref(),
            &corr,
        )?;
        Ok(batch.values)
    }
}

pub(crate) fn response(
    n: &Normalizer,
    format: ResponseFormat,
    at: ObservedAt,
) -> Result<Vec<CanonicalObservationV2>, Failure> {
    let mut response = Response::default();
    if format == ResponseFormat::Json {
        response.chunk(n, &json::parse(&n.response, n.limits)?, false)?;
    } else {
        let wire = std::str::from_utf8(&n.response).map_err(|_| Failure::Malformed)?;
        let mut data = String::new();
        let mut terminal = false;
        let mut pending = false;
        for line in wire.split_inclusive('\n') {
            if !line.ends_with('\n') {
                return Err(Failure::Incomplete);
            }
            let line = line.strip_suffix('\n').unwrap_or(line);
            let line = line.strip_suffix('\r').unwrap_or(line);
            if line.contains('\r') {
                return Err(Failure::Malformed);
            }
            if line.is_empty() {
                if !data.is_empty() {
                    data.pop();
                    if terminal {
                        return Err(Failure::Conflict);
                    }
                    if data == "[DONE]" {
                        terminal = true;
                    } else {
                        response.chunk(n, &json::parse(data.as_bytes(), n.limits)?, true)?;
                    }
                    data.clear();
                }
                pending = false;
            } else if !line.starts_with(':') {
                pending = true;
                let Some(value) = line.strip_prefix("data:") else {
                    return Err(Failure::Unsupported);
                };
                let value = value.strip_prefix(' ').unwrap_or(value);
                append(&mut data, value, n.limits.frame_bytes)?;
                append(&mut data, "\n", n.limits.frame_bytes)?;
            }
        }
        if pending || !data.is_empty() || !terminal {
            return Err(Failure::Incomplete);
        }
    }
    response.commit(n, at)
}
