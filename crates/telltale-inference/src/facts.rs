//! Shared COv2 construction, not a wire-protocol translation layer.
use crate::{Failure, mapping::*};
use serde_json::Value;
use telltale_schema::observation::*;

impl Batch<'_> {
    pub(crate) fn text_message(
        &mut self,
        role: &str,
        content: &str,
        ordinal: u32,
        corr: &CorrelationIds,
        local: Option<LocalEvidence>,
    ) -> Result<(), Failure> {
        self.item()?;
        let role = match role {
            "system" => MessageRole::System,
            "developer" => MessageRole::Developer,
            "user" => MessageRole::User,
            "assistant" => MessageRole::Assistant,
            _ => return Err(Failure::Unsupported),
        };
        self.emit(
            ObservationBody::Message(
                MessageObservation::new(role)
                    .with_content(semantic(&Value::String(content.to_owned()))?),
            ),
            ObservationStage::MessageObserved,
            ordinal,
            &[
                ("message.role", FactProvenance::Reported),
                ("message.content", FactProvenance::Reported),
            ],
            corr.clone(),
            local,
        )
    }
    pub(crate) fn proposal(
        &mut self,
        name: &str,
        args: &Value,
        ordinal: u32,
        corr: CorrelationIds,
        local: Option<LocalEvidence>,
    ) -> Result<(), Failure> {
        self.item()?;
        if !args.is_object() {
            return Err(Failure::Unsupported);
        }
        self.emit(
            ObservationBody::Tool(
                ToolObservation::new()
                    .with_name(name)?
                    .with_arguments(semantic(args)?),
            ),
            ObservationStage::ToolProposed,
            ordinal,
            &[
                ("tool.name", FactProvenance::Reported),
                ("tool.arguments", FactProvenance::Parsed),
            ],
            corr,
            local,
        )
    }
    pub(crate) fn result(
        &mut self,
        value: &Value,
        error: Option<bool>,
        ordinal: u32,
        corr: CorrelationIds,
    ) -> Result<(), Failure> {
        self.item()?;
        let mut body = ToolObservation::new().with_result(semantic(value)?);
        let mut fields = vec![("tool.result", FactProvenance::Reported)];
        if let Some(error) = error {
            body = body.with_is_error(error);
            fields.push(("tool.is_error", FactProvenance::Reported));
        }
        self.emit(
            ObservationBody::Tool(body),
            ObservationStage::ToolResultReturned,
            ordinal,
            &fields,
            corr,
            None,
        )
    }
    pub(crate) fn definition(
        &mut self,
        name: &str,
        selected: &Value,
        ordinal: u32,
        corr: &CorrelationIds,
    ) -> Result<(), Failure> {
        self.item()?;
        let local = LocalEvidence::new().insert(
            "tool_definition.definition",
            LocalValue::new(
                semantic(selected)?,
                None::<String>,
                FactProvenance::Parsed,
                Sensitivity::Sensitive,
            )?,
        )?;
        self.emit(
            ObservationBody::ToolDefinition(
                ToolDefinitionObservation::new("present")?.with_name(name)?,
            ),
            ObservationStage::DefinitionChanged,
            ordinal,
            &[
                ("tool_definition.name", FactProvenance::Reported),
                ("tool_definition.change", FactProvenance::Parsed),
            ],
            corr.clone(),
            Some(local),
        )
    }
}

pub(crate) fn token_usage(v: Option<&Value>) -> Result<Option<Value>, Failure> {
    let Some(v) = v.filter(|v| !v.is_null()) else {
        return Ok(None);
    };
    if !v.is_object() {
        return Err(Failure::Malformed);
    }
    let mut usage = serde_json::Map::new();
    for (native, canonical) in [
        ("input_tokens", "prompt_tokens"),
        ("output_tokens", "completion_tokens"),
    ] {
        if let Some(count) = v.get(native) {
            usage.insert(
                canonical.to_owned(),
                Value::from(count.as_u64().ok_or(Failure::Malformed)?),
            );
        }
    }
    if let Some(details) = v.get("output_tokens_details").filter(|v| !v.is_null()) {
        if !details.is_object() {
            return Err(Failure::Malformed);
        }
        if let Some(count) = details.get("reasoning_tokens") {
            let count = count.as_u64().ok_or(Failure::Malformed)?;
            usage.insert(
                "completion_tokens_details".to_owned(),
                serde_json::json!({"reasoning_tokens":count}),
            );
        }
    }
    Ok(Some(Value::Object(usage)))
}
