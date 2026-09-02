use std::collections::BTreeMap;

use super::value::non_empty;
use super::{
    ContentPartKind, JsonValue, LocalReference, OTHER_REGISTRY_VERSION, ObservationError,
    ObservationFamily, ObservationStage, ValidationCode, VersionedReference,
};

#[derive(Debug, Clone, PartialEq)]
pub enum ObservationBody {
    Message(MessageObservation),
    Inference(InferenceObservation),
    Tool(ToolObservation),
    ToolDefinition(ToolDefinitionObservation),
    Mcp(McpObservation),
    Process(ProcessObservation),
    File(FileObservation),
    Network(NetworkObservation),
    Browser(BrowserObservation),
    Runtime(RuntimeObservation),
    Session(SessionObservation),
    Other(OtherObservation),
}

impl ObservationBody {
    pub fn kind(&self) -> ObservationFamily {
        match self {
            Self::Message(_) => ObservationFamily::Message,
            Self::Inference(_) => ObservationFamily::Inference,
            Self::Tool(_) => ObservationFamily::Tool,
            Self::ToolDefinition(_) => ObservationFamily::ToolDefinition,
            Self::Mcp(_) => ObservationFamily::Mcp,
            Self::Process(_) => ObservationFamily::Process,
            Self::File(_) => ObservationFamily::File,
            Self::Network(_) => ObservationFamily::Network,
            Self::Browser(_) => ObservationFamily::Browser,
            Self::Runtime(_) => ObservationFamily::Runtime,
            Self::Session(_) => ObservationFamily::Session,
            Self::Other(_) => ObservationFamily::Other,
        }
    }

    pub(crate) fn semantic_fields(&self) -> Vec<(String, JsonValue)> {
        match self {
            Self::Message(body) => body.semantic_fields(),
            Self::Inference(body) => body.semantic_fields(),
            Self::Tool(body) => body.semantic_fields(),
            Self::ToolDefinition(body) => body.semantic_fields(),
            Self::Mcp(body) => body.semantic_fields(),
            Self::Process(body) => body.semantic_fields(),
            Self::File(body) => body.semantic_fields(),
            Self::Network(body) => body.semantic_fields(),
            Self::Browser(body) => body.semantic_fields(),
            Self::Runtime(body) => body.semantic_fields(),
            Self::Session(body) => body.semantic_fields(),
            Self::Other(body) => body.semantic_fields(),
        }
    }

    pub(crate) fn canonicalize(self) -> Result<Self, super::ObservationError> {
        match self {
            Self::Message(mut body) => {
                body.content = body.content.map(JsonValue::canonicalize).transpose()?;
                body.content_parts = body
                    .content_parts
                    .into_iter()
                    .map(ContentPart::canonicalize)
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(Self::Message(body))
            }
            Self::Tool(mut body) => {
                body.arguments = body.arguments.map(JsonValue::canonicalize).transpose()?;
                body.result = body.result.map(JsonValue::canonicalize).transpose()?;
                Ok(Self::Tool(body))
            }
            body => Ok(body),
        }
    }

    pub(crate) fn validate_minimum(&self, stage: ObservationStage) -> Result<(), ObservationError> {
        match self {
            Self::Message(body) if body.role.is_some() => Ok(()),
            Self::Inference(body)
                if body.provider.is_some()
                    || body.requested_model.is_some()
                    || body.resolved_model.is_some() =>
            {
                Ok(())
            }
            Self::Tool(body) => {
                if body.name.is_none()
                    && body.arguments.is_none()
                    && body.result.is_none()
                    && body.reported_status.is_none()
                {
                    return Err(ObservationError::new(ValidationCode::FamilyMinimum));
                }
                if stage == ObservationStage::ToolExecutionCompleted
                    && body.reported_status.is_none()
                    && body.result.is_none()
                    && body.exit_code.is_none()
                    && body.is_error.is_none()
                {
                    return Err(ObservationError::new(ValidationCode::FamilyMinimum));
                }
                if stage == ObservationStage::ToolResultReturned
                    && body.result.is_none()
                    && body.reported_status.is_none()
                    && body.is_error.is_none()
                {
                    return Err(ObservationError::new(ValidationCode::FamilyMinimum));
                }
                Ok(())
            }
            Self::ToolDefinition(body)
                if body.change.is_some()
                    && (body.identity.is_some()
                        || body.name.is_some()
                        || body.definition_ref.is_some()
                        || body.description_hash.is_some()
                        || body.schema_hash.is_some()) =>
            {
                Ok(())
            }
            Self::Mcp(body) if body.change.is_some() => Ok(()),
            Self::Process(body) if body.operation.is_some() || body.state.is_some() => Ok(()),
            Self::File(body) if body.operation.is_some() || body.state.is_some() => Ok(()),
            Self::Network(body) if body.operation.is_some() || body.state.is_some() => Ok(()),
            Self::Browser(body) if body.state_marker.is_some() => Ok(()),
            Self::Runtime(body) if body.state_marker.is_some() => Ok(()),
            Self::Session(body)
                if body.lifecycle.is_some()
                    && matches!(
                        (stage, body.lifecycle),
                        (
                            ObservationStage::SessionOpened,
                            Some(super::SessionLifecycle::Opened)
                        ) | (
                            ObservationStage::SessionUpdated,
                            Some(super::SessionLifecycle::Updated)
                        ) | (
                            ObservationStage::SessionClosed,
                            Some(super::SessionLifecycle::Closed)
                        )
                    ) =>
            {
                Ok(())
            }
            Self::Other(body)
                if body.registry_version == Some(OTHER_REGISTRY_VERSION.to_owned())
                    && body.registered_kind.is_some()
                    && body.classification.is_some()
                    && (body.summary.is_some() || body.local_reference.is_some()) =>
            {
                Ok(())
            }
            _ => Err(ObservationError::new(ValidationCode::FamilyMinimum)),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct MessageObservation {
    role: Option<super::MessageRole>,
    content: Option<JsonValue>,
    content_parts: Vec<ContentPart>,
}

impl MessageObservation {
    pub fn new(role: super::MessageRole) -> Self {
        Self {
            role: Some(role),
            content: None,
            content_parts: Vec::new(),
        }
    }

    pub fn with_content(mut self, content: JsonValue) -> Self {
        self.content = Some(content);
        self
    }

    pub fn with_content_part(mut self, part: ContentPart) -> Self {
        self.content_parts.push(part);
        self
    }

    pub fn role(&self) -> Option<super::MessageRole> {
        self.role
    }

    pub fn content(&self) -> Option<&JsonValue> {
        self.content.as_ref()
    }

    pub fn content_parts(&self) -> &[ContentPart] {
        &self.content_parts
    }

    fn semantic_fields(&self) -> Vec<(String, JsonValue)> {
        let mut fields = Vec::new();
        fields.push((
            "message.role".to_owned(),
            JsonValue::string(self.role.map_or("other", super::MessageRole::as_str)),
        ));
        if let Some(content) = &self.content {
            fields.push(("message.content".to_owned(), content.clone()));
        }
        if !self.content_parts.is_empty() {
            let parts = self
                .content_parts
                .iter()
                .map(ContentPart::as_json)
                .collect();
            fields.push(("message.content_parts".to_owned(), JsonValue::Array(parts)));
        }
        fields
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ContentPart {
    kind: ContentPartKind,
    value: JsonValue,
}

impl ContentPart {
    pub fn new(kind: ContentPartKind, value: JsonValue) -> Self {
        Self { kind, value }
    }

    pub fn kind(&self) -> ContentPartKind {
        self.kind
    }

    pub fn value(&self) -> &JsonValue {
        &self.value
    }

    fn canonicalize(self) -> Result<Self, super::ObservationError> {
        Ok(Self {
            kind: self.kind,
            value: self.value.canonicalize()?,
        })
    }

    fn as_json(&self) -> JsonValue {
        let mut object = BTreeMap::new();
        object.insert("kind".to_owned(), JsonValue::string(self.kind.as_str()));
        object.insert("value".to_owned(), self.value.clone());
        JsonValue::Object(object)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct InferenceObservation {
    provider: Option<String>,
    requested_model: Option<String>,
    resolved_model: Option<String>,
    streaming: Option<bool>,
    stop_reason: Option<String>,
    metrics: InferenceMetrics,
}

impl InferenceObservation {
    pub fn new() -> Self {
        Self {
            provider: None,
            requested_model: None,
            resolved_model: None,
            streaming: None,
            stop_reason: None,
            metrics: InferenceMetrics::default(),
        }
    }

    pub fn with_provider(mut self, value: impl AsRef<str>) -> Result<Self, ObservationError> {
        self.provider = Some(non_empty(value.as_ref(), ValidationCode::InvalidBody)?);
        Ok(self)
    }

    pub fn with_requested_model(
        mut self,
        value: impl AsRef<str>,
    ) -> Result<Self, ObservationError> {
        self.requested_model = Some(non_empty(value.as_ref(), ValidationCode::InvalidBody)?);
        Ok(self)
    }

    pub fn with_resolved_model(mut self, value: impl AsRef<str>) -> Result<Self, ObservationError> {
        self.resolved_model = Some(non_empty(value.as_ref(), ValidationCode::InvalidBody)?);
        Ok(self)
    }

    pub fn with_streaming(mut self, value: bool) -> Self {
        self.streaming = Some(value);
        self
    }

    pub fn with_stop_reason(mut self, value: impl AsRef<str>) -> Result<Self, ObservationError> {
        self.stop_reason = Some(non_empty(value.as_ref(), ValidationCode::InvalidBody)?);
        Ok(self)
    }

    pub fn with_metrics(mut self, metrics: InferenceMetrics) -> Self {
        self.metrics = metrics;
        self
    }

    pub fn provider(&self) -> Option<&str> {
        self.provider.as_deref()
    }
    pub fn requested_model(&self) -> Option<&str> {
        self.requested_model.as_deref()
    }
    pub fn resolved_model(&self) -> Option<&str> {
        self.resolved_model.as_deref()
    }
    pub fn streaming(&self) -> Option<bool> {
        self.streaming
    }
    pub fn stop_reason(&self) -> Option<&str> {
        self.stop_reason.as_deref()
    }
    pub fn metrics(&self) -> &InferenceMetrics {
        &self.metrics
    }

    fn semantic_fields(&self) -> Vec<(String, JsonValue)> {
        let mut fields = Vec::new();
        push_string(&mut fields, "inference.provider", &self.provider);
        push_string(
            &mut fields,
            "inference.requested_model",
            &self.requested_model,
        );
        push_string(
            &mut fields,
            "inference.resolved_model",
            &self.resolved_model,
        );
        if let Some(value) = self.streaming {
            fields.push(("inference.streaming".to_owned(), JsonValue::Bool(value)));
        }
        push_string(&mut fields, "inference.stop_reason", &self.stop_reason);
        if let Some(metrics) = self.metrics.as_json() {
            fields.push(("inference.metrics".to_owned(), metrics));
        }
        fields
    }
}

impl Default for InferenceObservation {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InferenceMetrics {
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    reasoning_tokens: Option<u64>,
    duration_ms: Option<u64>,
    time_to_first_token_ms: Option<u64>,
}

impl InferenceMetrics {
    pub fn with_input_tokens(mut self, value: u64) -> Self {
        self.input_tokens = Some(value);
        self
    }
    pub fn with_output_tokens(mut self, value: u64) -> Self {
        self.output_tokens = Some(value);
        self
    }
    pub fn with_reasoning_tokens(mut self, value: u64) -> Self {
        self.reasoning_tokens = Some(value);
        self
    }
    pub fn with_duration_ms(mut self, value: u64) -> Self {
        self.duration_ms = Some(value);
        self
    }
    pub fn with_time_to_first_token_ms(mut self, value: u64) -> Self {
        self.time_to_first_token_ms = Some(value);
        self
    }

    fn as_json(&self) -> Option<JsonValue> {
        let mut fields = BTreeMap::new();
        for (key, value) in [
            ("input_tokens", self.input_tokens),
            ("output_tokens", self.output_tokens),
            ("reasoning_tokens", self.reasoning_tokens),
            ("duration_ms", self.duration_ms),
            ("time_to_first_token_ms", self.time_to_first_token_ms),
        ] {
            if let Some(value) = value {
                fields.insert(key.to_owned(), JsonValue::Unsigned(value));
            }
        }
        (!fields.is_empty()).then_some(JsonValue::Object(fields))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ToolObservation {
    name: Option<String>,
    arguments: Option<JsonValue>,
    searchable_arguments: Option<String>,
    result: Option<JsonValue>,
    searchable_result: Option<String>,
    reported_status: Option<super::ToolStatus>,
    is_error: Option<bool>,
    exit_code: Option<i64>,
}

impl ToolObservation {
    pub fn new() -> Self {
        Self {
            name: None,
            arguments: None,
            searchable_arguments: None,
            result: None,
            searchable_result: None,
            reported_status: None,
            is_error: None,
            exit_code: None,
        }
    }

    pub fn with_name(mut self, value: impl AsRef<str>) -> Result<Self, ObservationError> {
        self.name = Some(non_empty(value.as_ref(), ValidationCode::InvalidBody)?);
        Ok(self)
    }
    pub fn with_arguments(mut self, value: JsonValue) -> Self {
        self.arguments = Some(value);
        self
    }
    pub fn with_searchable_arguments(
        mut self,
        value: impl AsRef<str>,
    ) -> Result<Self, ObservationError> {
        self.searchable_arguments = Some(non_empty(value.as_ref(), ValidationCode::InvalidBody)?);
        Ok(self)
    }
    pub fn with_result(mut self, value: JsonValue) -> Self {
        self.result = Some(value);
        self
    }
    pub fn with_searchable_result(
        mut self,
        value: impl AsRef<str>,
    ) -> Result<Self, ObservationError> {
        self.searchable_result = Some(non_empty(value.as_ref(), ValidationCode::InvalidBody)?);
        Ok(self)
    }
    pub fn with_reported_status(mut self, value: super::ToolStatus) -> Self {
        self.reported_status = Some(value);
        self
    }
    pub fn with_is_error(mut self, value: bool) -> Self {
        self.is_error = Some(value);
        self
    }
    pub fn with_exit_code(mut self, value: i64) -> Self {
        self.exit_code = Some(value);
        self
    }

    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
    pub fn arguments(&self) -> Option<&JsonValue> {
        self.arguments.as_ref()
    }
    pub fn searchable_arguments(&self) -> Option<&str> {
        self.searchable_arguments.as_deref()
    }
    pub fn result(&self) -> Option<&JsonValue> {
        self.result.as_ref()
    }
    pub fn searchable_result(&self) -> Option<&str> {
        self.searchable_result.as_deref()
    }
    pub fn reported_status(&self) -> Option<super::ToolStatus> {
        self.reported_status
    }
    pub fn is_error(&self) -> Option<bool> {
        self.is_error
    }
    pub fn exit_code(&self) -> Option<i64> {
        self.exit_code
    }

    fn semantic_fields(&self) -> Vec<(String, JsonValue)> {
        let mut fields = Vec::new();
        push_string(&mut fields, "tool.name", &self.name);
        push_option(&mut fields, "tool.arguments", &self.arguments);
        push_string(
            &mut fields,
            "tool.searchable_arguments",
            &self.searchable_arguments,
        );
        push_option(&mut fields, "tool.result", &self.result);
        push_string(
            &mut fields,
            "tool.searchable_result",
            &self.searchable_result,
        );
        if let Some(value) = self.reported_status {
            fields.push((
                "tool.reported_status".to_owned(),
                JsonValue::string(value.as_str()),
            ));
        }
        if let Some(value) = self.is_error {
            fields.push(("tool.is_error".to_owned(), JsonValue::Bool(value)));
        }
        if let Some(value) = self.exit_code {
            fields.push(("tool.exit_code".to_owned(), JsonValue::Integer(value)));
        }
        fields
    }
}

impl Default for ToolObservation {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ToolDefinitionObservation {
    identity: Option<String>,
    name: Option<String>,
    definition_ref: Option<LocalReference>,
    server_ref: Option<String>,
    description_hash: Option<String>,
    schema_hash: Option<String>,
    change: Option<String>,
    classifications: Vec<String>,
}

impl ToolDefinitionObservation {
    pub fn new(change: impl AsRef<str>) -> Result<Self, ObservationError> {
        Ok(Self {
            identity: None,
            name: None,
            definition_ref: None,
            server_ref: None,
            description_hash: None,
            schema_hash: None,
            change: Some(non_empty(change.as_ref(), ValidationCode::InvalidBody)?),
            classifications: Vec::new(),
        })
    }
    pub fn with_identity(mut self, value: impl AsRef<str>) -> Result<Self, ObservationError> {
        self.identity = Some(non_empty(value.as_ref(), ValidationCode::InvalidBody)?);
        Ok(self)
    }
    pub fn with_name(mut self, value: impl AsRef<str>) -> Result<Self, ObservationError> {
        self.name = Some(non_empty(value.as_ref(), ValidationCode::InvalidBody)?);
        Ok(self)
    }
    pub fn with_definition_ref(mut self, value: LocalReference) -> Self {
        self.definition_ref = Some(value);
        self
    }
    pub fn with_server_ref(mut self, value: impl AsRef<str>) -> Result<Self, ObservationError> {
        self.server_ref = Some(non_empty(value.as_ref(), ValidationCode::InvalidBody)?);
        Ok(self)
    }
    pub fn with_description_hash(
        mut self,
        value: impl AsRef<str>,
    ) -> Result<Self, ObservationError> {
        self.description_hash = Some(non_empty(value.as_ref(), ValidationCode::InvalidBody)?);
        Ok(self)
    }
    pub fn with_schema_hash(mut self, value: impl AsRef<str>) -> Result<Self, ObservationError> {
        self.schema_hash = Some(non_empty(value.as_ref(), ValidationCode::InvalidBody)?);
        Ok(self)
    }
    pub fn with_classification(mut self, value: impl AsRef<str>) -> Result<Self, ObservationError> {
        self.classifications
            .push(non_empty(value.as_ref(), ValidationCode::InvalidBody)?);
        Ok(self)
    }

    pub fn identity(&self) -> Option<&str> {
        self.identity.as_deref()
    }
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
    pub fn definition_ref(&self) -> Option<&LocalReference> {
        self.definition_ref.as_ref()
    }
    pub fn server_ref(&self) -> Option<&str> {
        self.server_ref.as_deref()
    }
    pub fn description_hash(&self) -> Option<&str> {
        self.description_hash.as_deref()
    }
    pub fn schema_hash(&self) -> Option<&str> {
        self.schema_hash.as_deref()
    }
    pub fn change(&self) -> Option<&str> {
        self.change.as_deref()
    }
    pub fn classifications(&self) -> &[String] {
        &self.classifications
    }

    fn semantic_fields(&self) -> Vec<(String, JsonValue)> {
        let mut fields = Vec::new();
        push_string(&mut fields, "tool_definition.identity", &self.identity);
        push_string(&mut fields, "tool_definition.name", &self.name);
        if self.definition_ref.is_some() {
            fields.push(("tool_definition.definition_ref".to_owned(), JsonValue::Null));
        }
        push_string(&mut fields, "tool_definition.server_ref", &self.server_ref);
        push_string(
            &mut fields,
            "tool_definition.description_hash",
            &self.description_hash,
        );
        push_string(
            &mut fields,
            "tool_definition.schema_hash",
            &self.schema_hash,
        );
        push_string(&mut fields, "tool_definition.change", &self.change);
        if !self.classifications.is_empty() {
            fields.push((
                "tool_definition.classifications".to_owned(),
                JsonValue::Array(self.classifications.iter().map(JsonValue::string).collect()),
            ));
        }
        fields
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct McpObservation {
    server_id: Option<String>,
    tool_name: Option<String>,
    transport: Option<String>,
    location_class: Option<String>,
    change: Option<String>,
    inventory_fingerprint: Option<String>,
}

impl McpObservation {
    pub fn new(change: impl AsRef<str>) -> Result<Self, ObservationError> {
        Ok(Self {
            server_id: None,
            tool_name: None,
            transport: None,
            location_class: None,
            change: Some(non_empty(change.as_ref(), ValidationCode::InvalidBody)?),
            inventory_fingerprint: None,
        })
    }
    pub fn with_server_id(mut self, value: impl AsRef<str>) -> Result<Self, ObservationError> {
        self.server_id = Some(non_empty(value.as_ref(), ValidationCode::InvalidBody)?);
        Ok(self)
    }
    pub fn with_tool_name(mut self, value: impl AsRef<str>) -> Result<Self, ObservationError> {
        self.tool_name = Some(non_empty(value.as_ref(), ValidationCode::InvalidBody)?);
        Ok(self)
    }
    pub fn with_transport(mut self, value: impl AsRef<str>) -> Result<Self, ObservationError> {
        self.transport = Some(non_empty(value.as_ref(), ValidationCode::InvalidBody)?);
        Ok(self)
    }
    pub fn with_location_class(mut self, value: impl AsRef<str>) -> Result<Self, ObservationError> {
        self.location_class = Some(non_empty(value.as_ref(), ValidationCode::InvalidBody)?);
        Ok(self)
    }
    pub fn with_inventory_fingerprint(
        mut self,
        value: impl AsRef<str>,
    ) -> Result<Self, ObservationError> {
        self.inventory_fingerprint = Some(non_empty(value.as_ref(), ValidationCode::InvalidBody)?);
        Ok(self)
    }
    pub fn server_id(&self) -> Option<&str> {
        self.server_id.as_deref()
    }
    pub fn tool_name(&self) -> Option<&str> {
        self.tool_name.as_deref()
    }
    pub fn transport(&self) -> Option<&str> {
        self.transport.as_deref()
    }
    pub fn location_class(&self) -> Option<&str> {
        self.location_class.as_deref()
    }
    pub fn change(&self) -> Option<&str> {
        self.change.as_deref()
    }
    pub fn inventory_fingerprint(&self) -> Option<&str> {
        self.inventory_fingerprint.as_deref()
    }
    fn semantic_fields(&self) -> Vec<(String, JsonValue)> {
        let mut fields = Vec::new();
        push_string(&mut fields, "mcp.server_id", &self.server_id);
        push_string(&mut fields, "mcp.tool_name", &self.tool_name);
        push_string(&mut fields, "mcp.transport", &self.transport);
        push_string(&mut fields, "mcp.location_class", &self.location_class);
        push_string(&mut fields, "mcp.change", &self.change);
        push_string(
            &mut fields,
            "mcp.inventory_fingerprint",
            &self.inventory_fingerprint,
        );
        fields
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProcessObservation {
    operation: Option<String>,
    state: Option<String>,
    name: Option<String>,
    pid: Option<u64>,
    instance_id: Option<String>,
    parent_instance_id: Option<String>,
    privilege: Option<String>,
}
impl ProcessObservation {
    pub fn new() -> Self {
        Self {
            operation: None,
            state: None,
            name: None,
            pid: None,
            instance_id: None,
            parent_instance_id: None,
            privilege: None,
        }
    }
    pub fn with_operation(mut self, value: impl AsRef<str>) -> Result<Self, ObservationError> {
        self.operation = Some(non_empty(value.as_ref(), ValidationCode::InvalidBody)?);
        Ok(self)
    }
    pub fn with_state(mut self, value: impl AsRef<str>) -> Result<Self, ObservationError> {
        self.state = Some(non_empty(value.as_ref(), ValidationCode::InvalidBody)?);
        Ok(self)
    }
    pub fn with_name(mut self, value: impl AsRef<str>) -> Result<Self, ObservationError> {
        self.name = Some(non_empty(value.as_ref(), ValidationCode::InvalidBody)?);
        Ok(self)
    }
    pub fn with_pid(mut self, value: u64) -> Self {
        self.pid = Some(value);
        self
    }
    pub fn with_instance_id(mut self, value: impl AsRef<str>) -> Result<Self, ObservationError> {
        self.instance_id = Some(non_empty(value.as_ref(), ValidationCode::InvalidBody)?);
        Ok(self)
    }
    pub fn with_parent_instance_id(
        mut self,
        value: impl AsRef<str>,
    ) -> Result<Self, ObservationError> {
        self.parent_instance_id = Some(non_empty(value.as_ref(), ValidationCode::InvalidBody)?);
        Ok(self)
    }
    pub fn with_privilege(mut self, value: impl AsRef<str>) -> Result<Self, ObservationError> {
        self.privilege = Some(non_empty(value.as_ref(), ValidationCode::InvalidBody)?);
        Ok(self)
    }
    fn semantic_fields(&self) -> Vec<(String, JsonValue)> {
        let mut f = Vec::new();
        push_string(&mut f, "process.operation", &self.operation);
        push_string(&mut f, "process.state", &self.state);
        push_string(&mut f, "process.name", &self.name);
        if let Some(v) = self.pid {
            f.push(("process.pid".to_owned(), JsonValue::Unsigned(v)));
        }
        push_string(&mut f, "process.instance_id", &self.instance_id);
        push_string(
            &mut f,
            "process.parent_instance_id",
            &self.parent_instance_id,
        );
        push_string(&mut f, "process.privilege", &self.privilege);
        f
    }
    pub fn operation(&self) -> Option<&str> {
        self.operation.as_deref()
    }
    pub fn state(&self) -> Option<&str> {
        self.state.as_deref()
    }
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
    pub fn pid(&self) -> Option<u64> {
        self.pid
    }
    pub fn instance_id(&self) -> Option<&str> {
        self.instance_id.as_deref()
    }
    pub fn parent_instance_id(&self) -> Option<&str> {
        self.parent_instance_id.as_deref()
    }
    pub fn privilege(&self) -> Option<&str> {
        self.privilege.as_deref()
    }
}
impl Default for ProcessObservation {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct FileObservation {
    operation: Option<String>,
    state: Option<String>,
    path_class: Option<String>,
    path_reference: Option<LocalReference>,
}
impl FileObservation {
    pub fn new() -> Self {
        Self {
            operation: None,
            state: None,
            path_class: None,
            path_reference: None,
        }
    }
    pub fn with_operation(mut self, value: impl AsRef<str>) -> Result<Self, ObservationError> {
        self.operation = Some(non_empty(value.as_ref(), ValidationCode::InvalidBody)?);
        Ok(self)
    }
    pub fn with_state(mut self, value: impl AsRef<str>) -> Result<Self, ObservationError> {
        self.state = Some(non_empty(value.as_ref(), ValidationCode::InvalidBody)?);
        Ok(self)
    }
    pub fn with_path_class(mut self, value: impl AsRef<str>) -> Result<Self, ObservationError> {
        self.path_class = Some(non_empty(value.as_ref(), ValidationCode::InvalidBody)?);
        Ok(self)
    }
    pub fn with_path_reference(mut self, value: LocalReference) -> Self {
        self.path_reference = Some(value);
        self
    }
    fn semantic_fields(&self) -> Vec<(String, JsonValue)> {
        let mut f = Vec::new();
        push_string(&mut f, "file.operation", &self.operation);
        push_string(&mut f, "file.state", &self.state);
        push_string(&mut f, "file.path_class", &self.path_class);
        if self.path_reference.is_some() {
            f.push(("file.path_reference".to_owned(), JsonValue::Null));
        }
        f
    }
    pub fn operation(&self) -> Option<&str> {
        self.operation.as_deref()
    }
    pub fn state(&self) -> Option<&str> {
        self.state.as_deref()
    }
    pub fn path_class(&self) -> Option<&str> {
        self.path_class.as_deref()
    }
    pub fn path_reference(&self) -> Option<&LocalReference> {
        self.path_reference.as_ref()
    }
}
impl Default for FileObservation {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct NetworkObservation {
    operation: Option<String>,
    state: Option<String>,
    destination_class: Option<String>,
    domain: Option<String>,
    protocol: Option<String>,
    port: Option<u16>,
}
impl NetworkObservation {
    pub fn new() -> Self {
        Self {
            operation: None,
            state: None,
            destination_class: None,
            domain: None,
            protocol: None,
            port: None,
        }
    }
    pub fn with_operation(mut self, value: impl AsRef<str>) -> Result<Self, ObservationError> {
        self.operation = Some(non_empty(value.as_ref(), ValidationCode::InvalidBody)?);
        Ok(self)
    }
    pub fn with_state(mut self, value: impl AsRef<str>) -> Result<Self, ObservationError> {
        self.state = Some(non_empty(value.as_ref(), ValidationCode::InvalidBody)?);
        Ok(self)
    }
    pub fn with_destination_class(
        mut self,
        value: impl AsRef<str>,
    ) -> Result<Self, ObservationError> {
        self.destination_class = Some(non_empty(value.as_ref(), ValidationCode::InvalidBody)?);
        Ok(self)
    }
    pub fn with_domain(mut self, value: impl AsRef<str>) -> Result<Self, ObservationError> {
        self.domain = Some(non_empty(value.as_ref(), ValidationCode::InvalidBody)?);
        Ok(self)
    }
    pub fn with_protocol(mut self, value: impl AsRef<str>) -> Result<Self, ObservationError> {
        self.protocol = Some(non_empty(value.as_ref(), ValidationCode::InvalidBody)?);
        Ok(self)
    }
    pub fn with_port(mut self, value: u16) -> Self {
        self.port = Some(value);
        self
    }
    fn semantic_fields(&self) -> Vec<(String, JsonValue)> {
        let mut f = Vec::new();
        push_string(&mut f, "network.operation", &self.operation);
        push_string(&mut f, "network.state", &self.state);
        push_string(&mut f, "network.destination_class", &self.destination_class);
        push_string(&mut f, "network.domain", &self.domain);
        push_string(&mut f, "network.protocol", &self.protocol);
        if let Some(v) = self.port {
            f.push(("network.port".to_owned(), JsonValue::Unsigned(v as u64)));
        }
        f
    }
    pub fn operation(&self) -> Option<&str> {
        self.operation.as_deref()
    }
    pub fn state(&self) -> Option<&str> {
        self.state.as_deref()
    }
    pub fn destination_class(&self) -> Option<&str> {
        self.destination_class.as_deref()
    }
    pub fn domain(&self) -> Option<&str> {
        self.domain.as_deref()
    }
    pub fn protocol(&self) -> Option<&str> {
        self.protocol.as_deref()
    }
    pub fn port(&self) -> Option<u16> {
        self.port
    }
}
impl Default for NetworkObservation {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct BrowserObservation {
    state_marker: Option<String>,
    surface: Option<String>,
    origin_class: Option<String>,
    page_reference: Option<LocalReference>,
    navigation_id: Option<String>,
}
impl BrowserObservation {
    pub fn new() -> Self {
        Self {
            state_marker: None,
            surface: None,
            origin_class: None,
            page_reference: None,
            navigation_id: None,
        }
    }
    pub fn with_state_marker(mut self, value: impl AsRef<str>) -> Result<Self, ObservationError> {
        self.state_marker = Some(non_empty(value.as_ref(), ValidationCode::InvalidBody)?);
        Ok(self)
    }
    pub fn with_surface(mut self, value: impl AsRef<str>) -> Result<Self, ObservationError> {
        self.surface = Some(non_empty(value.as_ref(), ValidationCode::InvalidBody)?);
        Ok(self)
    }
    pub fn with_origin_class(mut self, value: impl AsRef<str>) -> Result<Self, ObservationError> {
        self.origin_class = Some(non_empty(value.as_ref(), ValidationCode::InvalidBody)?);
        Ok(self)
    }
    pub fn with_page_reference(mut self, value: LocalReference) -> Self {
        self.page_reference = Some(value);
        self
    }
    pub fn with_navigation_id(mut self, value: impl AsRef<str>) -> Result<Self, ObservationError> {
        self.navigation_id = Some(non_empty(value.as_ref(), ValidationCode::InvalidBody)?);
        Ok(self)
    }
    fn semantic_fields(&self) -> Vec<(String, JsonValue)> {
        let mut f = Vec::new();
        push_string(&mut f, "browser.state_marker", &self.state_marker);
        push_string(&mut f, "browser.surface", &self.surface);
        push_string(&mut f, "browser.origin_class", &self.origin_class);
        if self.page_reference.is_some() {
            f.push(("browser.page_reference".to_owned(), JsonValue::Null));
        }
        push_string(&mut f, "browser.navigation_id", &self.navigation_id);
        f
    }
    pub fn state_marker(&self) -> Option<&str> {
        self.state_marker.as_deref()
    }
    pub fn surface(&self) -> Option<&str> {
        self.surface.as_deref()
    }
    pub fn origin_class(&self) -> Option<&str> {
        self.origin_class.as_deref()
    }
    pub fn page_reference(&self) -> Option<&LocalReference> {
        self.page_reference.as_ref()
    }
    pub fn navigation_id(&self) -> Option<&str> {
        self.navigation_id.as_deref()
    }
}
impl Default for BrowserObservation {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RuntimeObservation {
    state_marker: Option<String>,
    execution_mode: Option<String>,
    isolation_state: Option<String>,
    workspace_class: Option<String>,
    privilege: Option<String>,
    state_ref: Option<VersionedReference>,
}
impl RuntimeObservation {
    pub fn new() -> Self {
        Self {
            state_marker: None,
            execution_mode: None,
            isolation_state: None,
            workspace_class: None,
            privilege: None,
            state_ref: None,
        }
    }
    pub fn with_state_marker(mut self, value: impl AsRef<str>) -> Result<Self, ObservationError> {
        self.state_marker = Some(non_empty(value.as_ref(), ValidationCode::InvalidBody)?);
        Ok(self)
    }
    pub fn with_execution_mode(mut self, value: impl AsRef<str>) -> Result<Self, ObservationError> {
        self.execution_mode = Some(non_empty(value.as_ref(), ValidationCode::InvalidBody)?);
        Ok(self)
    }
    pub fn with_isolation_state(
        mut self,
        value: impl AsRef<str>,
    ) -> Result<Self, ObservationError> {
        self.isolation_state = Some(non_empty(value.as_ref(), ValidationCode::InvalidBody)?);
        Ok(self)
    }
    pub fn with_workspace_class(
        mut self,
        value: impl AsRef<str>,
    ) -> Result<Self, ObservationError> {
        self.workspace_class = Some(non_empty(value.as_ref(), ValidationCode::InvalidBody)?);
        Ok(self)
    }
    pub fn with_privilege(mut self, value: impl AsRef<str>) -> Result<Self, ObservationError> {
        self.privilege = Some(non_empty(value.as_ref(), ValidationCode::InvalidBody)?);
        Ok(self)
    }
    pub fn with_state_ref(mut self, value: VersionedReference) -> Self {
        self.state_ref = Some(value);
        self
    }
    fn semantic_fields(&self) -> Vec<(String, JsonValue)> {
        let mut f = Vec::new();
        push_string(&mut f, "runtime.state_marker", &self.state_marker);
        push_string(&mut f, "runtime.execution_mode", &self.execution_mode);
        push_string(&mut f, "runtime.isolation_state", &self.isolation_state);
        push_string(&mut f, "runtime.workspace_class", &self.workspace_class);
        push_string(&mut f, "runtime.privilege", &self.privilege);
        if self.state_ref.is_some() {
            f.push(("runtime.state_ref".to_owned(), JsonValue::Null));
        }
        f
    }
    pub fn state_marker(&self) -> Option<&str> {
        self.state_marker.as_deref()
    }
    pub fn execution_mode(&self) -> Option<&str> {
        self.execution_mode.as_deref()
    }
    pub fn isolation_state(&self) -> Option<&str> {
        self.isolation_state.as_deref()
    }
    pub fn workspace_class(&self) -> Option<&str> {
        self.workspace_class.as_deref()
    }
    pub fn privilege(&self) -> Option<&str> {
        self.privilege.as_deref()
    }
    pub fn state_ref(&self) -> Option<&VersionedReference> {
        self.state_ref.as_ref()
    }
}
impl Default for RuntimeObservation {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SessionObservation {
    lifecycle: Option<super::SessionLifecycle>,
    context_refs: Vec<VersionedReference>,
}
impl SessionObservation {
    pub fn new(lifecycle: super::SessionLifecycle) -> Self {
        Self {
            lifecycle: Some(lifecycle),
            context_refs: Vec::new(),
        }
    }
    pub fn with_context_ref(mut self, value: VersionedReference) -> Self {
        self.context_refs.push(value);
        self
    }
    fn semantic_fields(&self) -> Vec<(String, JsonValue)> {
        let mut fields = vec![(
            "session.lifecycle".to_owned(),
            JsonValue::string(
                self.lifecycle
                    .map_or("opened", super::SessionLifecycle::as_str),
            ),
        )];
        if !self.context_refs.is_empty() {
            fields.push((
                "session.context_refs".to_owned(),
                JsonValue::Array(
                    self.context_refs
                        .iter()
                        .map(|value| JsonValue::string(value.id()))
                        .collect(),
                ),
            ));
        }
        fields
    }
    pub fn lifecycle(&self) -> Option<super::SessionLifecycle> {
        self.lifecycle
    }
    pub fn context_refs(&self) -> &[VersionedReference] {
        &self.context_refs
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct OtherObservation {
    registered_kind: Option<String>,
    registry_version: Option<String>,
    classification: Option<String>,
    summary: Option<String>,
    local_reference: Option<LocalReference>,
}
impl OtherObservation {
    pub fn new(
        kind: impl AsRef<str>,
        classification: impl AsRef<str>,
    ) -> Result<Self, ObservationError> {
        let kind = non_empty(kind.as_ref(), ValidationCode::UnsupportedOther)?;
        let classification = non_empty(classification.as_ref(), ValidationCode::UnsupportedOther)?;
        if !super::other_classification_allowed(&kind, &classification) {
            return Err(ObservationError::new(ValidationCode::UnsupportedOther));
        }
        Ok(Self {
            registered_kind: Some(kind),
            registry_version: Some(OTHER_REGISTRY_VERSION.to_owned()),
            classification: Some(classification),
            summary: None,
            local_reference: None,
        })
    }
    pub fn with_summary(mut self, value: impl AsRef<str>) -> Result<Self, ObservationError> {
        self.summary = Some(non_empty(value.as_ref(), ValidationCode::InvalidBody)?);
        Ok(self)
    }
    pub fn with_local_reference(mut self, value: LocalReference) -> Self {
        self.local_reference = Some(value);
        self
    }
    fn semantic_fields(&self) -> Vec<(String, JsonValue)> {
        let mut fields = Vec::new();
        push_string(&mut fields, "other.registered_kind", &self.registered_kind);
        push_string(
            &mut fields,
            "other.registry_version",
            &self.registry_version,
        );
        push_string(&mut fields, "other.classification", &self.classification);
        push_string(&mut fields, "other.summary", &self.summary);
        if self.local_reference.is_some() {
            fields.push(("other.local_reference".to_owned(), JsonValue::Null));
        }
        fields
    }
    pub fn registered_kind(&self) -> Option<&str> {
        self.registered_kind.as_deref()
    }
    pub fn registry_version(&self) -> Option<&str> {
        self.registry_version.as_deref()
    }
    pub fn classification(&self) -> Option<&str> {
        self.classification.as_deref()
    }
    pub fn summary(&self) -> Option<&str> {
        self.summary.as_deref()
    }
    pub fn local_reference(&self) -> Option<&LocalReference> {
        self.local_reference.as_ref()
    }
}

fn push_string(fields: &mut Vec<(String, JsonValue)>, path: &str, value: &Option<String>) {
    if let Some(value) = value {
        fields.push((path.to_owned(), JsonValue::string(value)));
    }
}
fn push_option(fields: &mut Vec<(String, JsonValue)>, path: &str, value: &Option<JsonValue>) {
    if let Some(value) = value {
        fields.push((path.to_owned(), value.clone()));
    }
}
