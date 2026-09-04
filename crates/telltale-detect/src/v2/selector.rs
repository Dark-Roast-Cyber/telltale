//! Explicit Canonical Observation v2 selector registry.

use std::fmt;

use telltale_schema::observation::{
    CanonicalObservationV2, CapabilityId, CorrelationOrigin, FactMetadata, FactProvenance,
    JsonValue, ObservationBody,
};

use super::types::{DetectionError, metadata_for_path};

const SELECTORS: &[&str] = &[
    "session.id",
    "message.role",
    "message.content",
    "tool.name",
    "tool.arguments",
    "tool.searchable_arguments",
    "tool.result",
    "tool.searchable_result",
    "tool.reported_status",
    "tool.is_error",
    "tool.exit_code",
    "command.text",
    "resource.path",
    "compat.v1.arguments",
    "compat.v1.assistant_context",
    "compat.v1.command",
    "compat.v1.file_path",
    "compat.v1.tool_name",
    "compat.v1.tool_result",
    "compat.v1.url",
    "compat.v1.user_context",
    "message.text",
    "tool.call_id",
    "tool.stage",
    "tool.arguments.text",
    "tool.arguments.keys",
    "tool.result.text",
    "tool.result.is_error",
    "tool.result.exit_code",
    "resource.operation",
    "resource.path_class",
    "network.domain",
    "network.destination_class",
    "network.operation",
    "network.port",
    "network.protocol",
    "process.name",
    "process.pid",
    "process.instance_id",
    "process.privilege",
    "inference.provider",
    "inference.requested_model",
    "inference.resolved_model",
    "inference.streaming",
    "inference.stop_reason",
    "mcp.server.id",
    "mcp.server.transport",
    "mcp.server.location_class",
    "mcp.tool.name",
    "runtime.execution_mode",
    "runtime.isolation.state",
    "runtime.privilege",
    "runtime.workspace.class",
    "browser.surface",
    "browser.origin_class",
    "browser.navigation_id",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SelectorBacking {
    Direct,
    Typed,
    Derived,
    GovernedFacet,
    Compatibility,
}

// This table is the publication audit for the finite registry. A selector is
// not admitted merely because its namespace is permitted by the observation
// schema.
const SELECTOR_BACKING: &[(&str, SelectorBacking)] = &[
    ("session.id", SelectorBacking::Direct),
    ("message.role", SelectorBacking::Typed),
    ("message.content", SelectorBacking::Typed),
    ("tool.name", SelectorBacking::Typed),
    ("tool.arguments", SelectorBacking::Typed),
    ("tool.searchable_arguments", SelectorBacking::Typed),
    ("tool.result", SelectorBacking::Typed),
    ("tool.searchable_result", SelectorBacking::Typed),
    ("tool.reported_status", SelectorBacking::Typed),
    ("tool.is_error", SelectorBacking::Typed),
    ("tool.exit_code", SelectorBacking::Typed),
    ("command.text", SelectorBacking::GovernedFacet),
    ("resource.path", SelectorBacking::GovernedFacet),
    ("compat.v1.arguments", SelectorBacking::Compatibility),
    (
        "compat.v1.assistant_context",
        SelectorBacking::Compatibility,
    ),
    ("compat.v1.command", SelectorBacking::Compatibility),
    ("compat.v1.file_path", SelectorBacking::Compatibility),
    ("compat.v1.tool_name", SelectorBacking::Compatibility),
    ("compat.v1.tool_result", SelectorBacking::Compatibility),
    ("compat.v1.url", SelectorBacking::Compatibility),
    ("compat.v1.user_context", SelectorBacking::Compatibility),
    ("message.text", SelectorBacking::Derived),
    ("tool.call_id", SelectorBacking::Direct),
    ("tool.stage", SelectorBacking::Derived),
    ("tool.arguments.text", SelectorBacking::Derived),
    ("tool.arguments.keys", SelectorBacking::Derived),
    ("tool.result.text", SelectorBacking::Derived),
    ("tool.result.is_error", SelectorBacking::Derived),
    ("tool.result.exit_code", SelectorBacking::Derived),
    ("resource.operation", SelectorBacking::Typed),
    ("resource.path_class", SelectorBacking::Typed),
    ("network.domain", SelectorBacking::Typed),
    ("network.destination_class", SelectorBacking::Typed),
    ("network.operation", SelectorBacking::Typed),
    ("network.port", SelectorBacking::Typed),
    ("network.protocol", SelectorBacking::Typed),
    ("process.name", SelectorBacking::Typed),
    ("process.pid", SelectorBacking::Typed),
    ("process.instance_id", SelectorBacking::Typed),
    ("process.privilege", SelectorBacking::Typed),
    ("inference.provider", SelectorBacking::Typed),
    ("inference.requested_model", SelectorBacking::Typed),
    ("inference.resolved_model", SelectorBacking::Typed),
    ("inference.streaming", SelectorBacking::Typed),
    ("inference.stop_reason", SelectorBacking::Typed),
    ("mcp.server.id", SelectorBacking::Typed),
    ("mcp.server.transport", SelectorBacking::Typed),
    ("mcp.server.location_class", SelectorBacking::Typed),
    ("mcp.tool.name", SelectorBacking::Typed),
    ("runtime.execution_mode", SelectorBacking::Typed),
    ("runtime.isolation.state", SelectorBacking::Typed),
    ("runtime.privilege", SelectorBacking::Typed),
    ("runtime.workspace.class", SelectorBacking::Typed),
    ("browser.surface", SelectorBacking::Typed),
    ("browser.origin_class", SelectorBacking::Typed),
    ("browser.navigation_id", SelectorBacking::Typed),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SelectorId {
    SessionId,
    MessageRole,
    MessageContent,
    ToolName,
    ToolArguments,
    ToolSearchableArguments,
    ToolResult,
    ToolSearchableResult,
    ToolReportedStatus,
    ToolIsError,
    ToolExitCode,
    CommandText,
    ResourcePath,
    CompatArguments,
    CompatAssistantContext,
    CompatCommand,
    CompatFilePath,
    CompatToolName,
    CompatToolResult,
    CompatUrl,
    CompatUserContext,
    GovernedFacet(&'static str),
}

impl SelectorId {
    pub fn parse(value: &str) -> Result<Self, DetectionError> {
        match value {
            "session.id" => Ok(Self::SessionId),
            "message.role" => Ok(Self::MessageRole),
            "message.content" => Ok(Self::MessageContent),
            "tool.name" => Ok(Self::ToolName),
            "tool.arguments" => Ok(Self::ToolArguments),
            "tool.searchable_arguments" => Ok(Self::ToolSearchableArguments),
            "tool.result" => Ok(Self::ToolResult),
            "tool.searchable_result" => Ok(Self::ToolSearchableResult),
            "tool.reported_status" => Ok(Self::ToolReportedStatus),
            "tool.is_error" => Ok(Self::ToolIsError),
            "tool.exit_code" => Ok(Self::ToolExitCode),
            "command.text" => Ok(Self::CommandText),
            "resource.path" => Ok(Self::ResourcePath),
            "compat.v1.arguments" => Ok(Self::CompatArguments),
            "compat.v1.assistant_context" => Ok(Self::CompatAssistantContext),
            "compat.v1.command" => Ok(Self::CompatCommand),
            "compat.v1.file_path" => Ok(Self::CompatFilePath),
            "compat.v1.tool_name" => Ok(Self::CompatToolName),
            "compat.v1.tool_result" => Ok(Self::CompatToolResult),
            "compat.v1.url" => Ok(Self::CompatUrl),
            "compat.v1.user_context" => Ok(Self::CompatUserContext),
            _ => SELECTORS
                .iter()
                .copied()
                .find(|selector| *selector == value)
                .map(Self::GovernedFacet)
                .ok_or(DetectionError::InvalidSelector),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::SessionId => "session.id",
            Self::MessageRole => "message.role",
            Self::MessageContent => "message.content",
            Self::ToolName => "tool.name",
            Self::ToolArguments => "tool.arguments",
            Self::ToolSearchableArguments => "tool.searchable_arguments",
            Self::ToolResult => "tool.result",
            Self::ToolSearchableResult => "tool.searchable_result",
            Self::ToolReportedStatus => "tool.reported_status",
            Self::ToolIsError => "tool.is_error",
            Self::ToolExitCode => "tool.exit_code",
            Self::CommandText => "command.text",
            Self::ResourcePath => "resource.path",
            Self::CompatArguments => "compat.v1.arguments",
            Self::CompatAssistantContext => "compat.v1.assistant_context",
            Self::CompatCommand => "compat.v1.command",
            Self::CompatFilePath => "compat.v1.file_path",
            Self::CompatToolName => "compat.v1.tool_name",
            Self::CompatToolResult => "compat.v1.tool_result",
            Self::CompatUrl => "compat.v1.url",
            Self::CompatUserContext => "compat.v1.user_context",
            Self::GovernedFacet(value) => value,
        }
    }

    pub fn backing(self) -> SelectorBacking {
        SELECTOR_BACKING
            .iter()
            .find(|(name, _)| *name == self.as_str())
            .map(|(_, backing)| *backing)
            .expect("every registered selector has a backing category")
    }

    pub fn required_capability(self) -> Option<CapabilityId> {
        match self {
            Self::CompatAssistantContext | Self::CompatUserContext => {
                Some(CapabilityId::UserContext)
            }
            Self::CompatArguments
            | Self::CompatCommand
            | Self::CompatFilePath
            | Self::CompatToolName
            | Self::CompatToolResult
            | Self::CompatUrl => Some(CapabilityId::ToolCall),
            Self::ToolName
            | Self::ToolArguments
            | Self::ToolSearchableArguments
            | Self::ToolResult
            | Self::ToolSearchableResult
            | Self::ToolReportedStatus
            | Self::ToolIsError
            | Self::ToolExitCode => Some(CapabilityId::ToolCall),
            Self::GovernedFacet(value) if value.starts_with("tool.") => {
                Some(CapabilityId::ToolCall)
            }
            _ => None,
        }
    }

    pub fn all() -> &'static [&'static str] {
        SELECTORS
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectorPresence {
    Present,
    Absent,
    MetadataMissing,
}

#[derive(Clone)]
pub struct SelectorResolution {
    selector: SelectorId,
    presence: SelectorPresence,
    value: Option<JsonValue>,
    metadata: Option<FactMetadata>,
    required_capability: Option<CapabilityId>,
}

impl fmt::Debug for SelectorResolution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SelectorResolution")
            .field("selector", &self.selector)
            .field("presence", &self.presence)
            .field("value", &self.value.as_ref().map(|_| "<redacted>"))
            .field("metadata", &self.metadata)
            .field("required_capability", &self.required_capability)
            .finish()
    }
}

impl SelectorResolution {
    pub fn selector(&self) -> SelectorId {
        self.selector
    }
    pub fn presence(&self) -> SelectorPresence {
        self.presence
    }
    pub fn is_present(&self) -> bool {
        self.presence == SelectorPresence::Present
    }
    pub fn value(&self) -> Option<&JsonValue> {
        self.value.as_ref()
    }
    pub fn metadata(&self) -> Option<&FactMetadata> {
        self.metadata.as_ref()
    }
    pub fn required_capability(&self) -> Option<CapabilityId> {
        self.required_capability
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SelectorRegistry;

impl SelectorRegistry {
    pub fn new() -> Self {
        Self
    }

    pub fn resolve(
        &self,
        selector: SelectorId,
        observation: &CanonicalObservationV2,
    ) -> SelectorResolution {
        let required_capability = selector.required_capability();
        if SelectorId::parse(selector.as_str()).ok() != Some(selector) {
            return absent(selector, required_capability);
        }
        if matches!(
            selector,
            SelectorId::CompatArguments
                | SelectorId::CompatAssistantContext
                | SelectorId::CompatCommand
                | SelectorId::CompatFilePath
                | SelectorId::CompatToolName
                | SelectorId::CompatToolResult
                | SelectorId::CompatUrl
                | SelectorId::CompatUserContext
        ) {
            Self::resolve_compat(selector, observation, required_capability)
        } else {
            Self::resolve_native(selector, observation, required_capability)
        }
    }

    fn resolve_native(
        selector: SelectorId,
        observation: &CanonicalObservationV2,
        required_capability: Option<CapabilityId>,
    ) -> SelectorResolution {
        if let Some((path, value)) = typed_body_value(selector, observation) {
            return field(selector, observation, path, value, required_capability);
        }
        match selector {
            SelectorId::SessionId => observation
                .session_id()
                .map(|value| {
                    let provenance = match value.origin() {
                        CorrelationOrigin::SourceReported => FactProvenance::Reported,
                        CorrelationOrigin::TelltaleOriginated => FactProvenance::Derived,
                    };
                    let metadata = FactMetadata::new(
                        provenance,
                        telltale_schema::observation::Sensitivity::Normal,
                    )
                    .ok();
                    SelectorResolution {
                        selector,
                        presence: metadata
                            .as_ref()
                            .map_or(SelectorPresence::MetadataMissing, |_| {
                                SelectorPresence::Present
                            }),
                        value: Some(JsonValue::string(value.value())),
                        metadata,
                        required_capability,
                    }
                })
                .unwrap_or_else(|| absent(selector, required_capability)),
            SelectorId::MessageRole => match observation.body() {
                ObservationBody::Message(body) => body.role().map_or_else(
                    || absent(selector, required_capability),
                    |value| {
                        field(
                            selector,
                            observation,
                            "message.role",
                            JsonValue::string(value.as_str()),
                            required_capability,
                        )
                    },
                ),
                _ => absent(selector, required_capability),
            },
            SelectorId::MessageContent => match observation.body() {
                ObservationBody::Message(body) => body.content().map_or_else(
                    || absent(selector, required_capability),
                    |value| {
                        field(
                            selector,
                            observation,
                            "message.content",
                            value.clone(),
                            required_capability,
                        )
                    },
                ),
                _ => absent(selector, required_capability),
            },
            SelectorId::GovernedFacet("message.text") => match observation.body() {
                ObservationBody::Message(body) => match body.content() {
                    Some(JsonValue::String(value)) => field(
                        selector,
                        observation,
                        "message.content",
                        JsonValue::string(value),
                        required_capability,
                    ),
                    _ => absent(selector, required_capability),
                },
                _ => absent(selector, required_capability),
            },
            SelectorId::ToolName => match observation.body() {
                ObservationBody::Tool(body) => body.name().map_or_else(
                    || absent(selector, required_capability),
                    |value| {
                        field(
                            selector,
                            observation,
                            "tool.name",
                            JsonValue::string(value),
                            required_capability,
                        )
                    },
                ),
                _ => absent(selector, required_capability),
            },
            SelectorId::ToolArguments => {
                tool_value(selector, observation, true, required_capability)
            }
            SelectorId::ToolSearchableArguments => {
                tool_string(selector, observation, true, required_capability)
            }
            SelectorId::GovernedFacet("tool.arguments.text") => {
                tool_text(selector, observation, true, required_capability)
            }
            SelectorId::GovernedFacet("tool.arguments.keys") => {
                tool_argument_keys(selector, observation, required_capability)
            }
            SelectorId::ToolResult => tool_value(selector, observation, false, required_capability),
            SelectorId::ToolSearchableResult => {
                tool_string(selector, observation, false, required_capability)
            }
            SelectorId::GovernedFacet("tool.result.text") => {
                tool_text(selector, observation, false, required_capability)
            }
            SelectorId::GovernedFacet("tool.result.is_error") => match observation.body() {
                ObservationBody::Tool(body) => body.is_error().map_or_else(
                    || absent(selector, required_capability),
                    |value| {
                        field(
                            selector,
                            observation,
                            "tool.is_error",
                            JsonValue::Bool(value),
                            required_capability,
                        )
                    },
                ),
                _ => absent(selector, required_capability),
            },
            SelectorId::GovernedFacet("tool.result.exit_code") => match observation.body() {
                ObservationBody::Tool(body) => body.exit_code().map_or_else(
                    || absent(selector, required_capability),
                    |value| {
                        field(
                            selector,
                            observation,
                            "tool.exit_code",
                            JsonValue::Integer(value),
                            required_capability,
                        )
                    },
                ),
                _ => absent(selector, required_capability),
            },
            SelectorId::GovernedFacet("tool.call_id") => {
                observation.correlation().call_id().map_or_else(
                    || absent(selector, required_capability),
                    |value| correlation_field(selector, value, required_capability),
                )
            }
            SelectorId::GovernedFacet("tool.stage") => {
                if matches!(observation.body(), ObservationBody::Tool(_)) {
                    derived_field(
                        selector,
                        JsonValue::string(observation.stage().as_str()),
                        required_capability,
                    )
                } else {
                    absent(selector, required_capability)
                }
            }
            SelectorId::ToolReportedStatus => match observation.body() {
                ObservationBody::Tool(body) => body.reported_status().map_or_else(
                    || absent(selector, required_capability),
                    |value| {
                        field(
                            selector,
                            observation,
                            "tool.reported_status",
                            JsonValue::string(value.as_str()),
                            required_capability,
                        )
                    },
                ),
                _ => absent(selector, required_capability),
            },
            SelectorId::ToolIsError => match observation.body() {
                ObservationBody::Tool(body) => body.is_error().map_or_else(
                    || absent(selector, required_capability),
                    |value| {
                        field(
                            selector,
                            observation,
                            "tool.is_error",
                            JsonValue::Bool(value),
                            required_capability,
                        )
                    },
                ),
                _ => absent(selector, required_capability),
            },
            SelectorId::ToolExitCode => match observation.body() {
                ObservationBody::Tool(body) => body.exit_code().map_or_else(
                    || absent(selector, required_capability),
                    |value| {
                        field(
                            selector,
                            observation,
                            "tool.exit_code",
                            JsonValue::Integer(value),
                            required_capability,
                        )
                    },
                ),
                _ => absent(selector, required_capability),
            },
            SelectorId::CommandText => {
                facet(selector, observation, "command.text", required_capability)
            }
            SelectorId::ResourcePath => {
                facet(selector, observation, "resource.path", required_capability)
            }
            SelectorId::GovernedFacet(path) => {
                if matches!(path, "command.text" | "resource.path") {
                    facet(selector, observation, path, required_capability)
                } else {
                    absent(selector, required_capability)
                }
            }
            _ => absent(selector, required_capability),
        }
    }

    fn resolve_compat(
        selector: SelectorId,
        observation: &CanonicalObservationV2,
        required_capability: Option<CapabilityId>,
    ) -> SelectorResolution {
        match selector {
            SelectorId::CompatAssistantContext => {
                message_context(selector, observation, true, required_capability)
            }
            SelectorId::CompatUserContext => {
                message_context(selector, observation, false, required_capability)
            }
            SelectorId::CompatArguments => {
                compat_tool_string(selector, observation, true, required_capability)
            }
            SelectorId::CompatToolResult => {
                compat_tool_string(selector, observation, false, required_capability)
            }
            SelectorId::CompatToolName => {
                let mut resolved =
                    Self::resolve_native(SelectorId::ToolName, observation, required_capability);
                resolved.selector = selector;
                resolved
            }
            SelectorId::CompatCommand => {
                let mut resolved =
                    Self::resolve_native(SelectorId::CommandText, observation, required_capability);
                resolved.selector = selector;
                resolved
            }
            SelectorId::CompatFilePath => {
                let mut resolved = Self::resolve_native(
                    SelectorId::ResourcePath,
                    observation,
                    required_capability,
                );
                resolved.selector = selector;
                resolved
            }
            // The v1 URL view remains absent even when a native network.url
            // facet exists; compatibility must not invent a tool-side URL fact.
            SelectorId::CompatUrl => absent(selector, required_capability),
            _ => absent(selector, required_capability),
        }
    }
}

fn absent(selector: SelectorId, required_capability: Option<CapabilityId>) -> SelectorResolution {
    SelectorResolution {
        selector,
        presence: SelectorPresence::Absent,
        value: None,
        metadata: None,
        required_capability,
    }
}

fn typed_body_value(
    selector: SelectorId,
    observation: &CanonicalObservationV2,
) -> Option<(&'static str, JsonValue)> {
    match selector {
        SelectorId::GovernedFacet("message.text") => match observation.body() {
            ObservationBody::Message(body) => body.content().and_then(|value| match value {
                JsonValue::String(value) => Some(("message.content", JsonValue::string(value))),
                _ => None,
            }),
            _ => None,
        },
        SelectorId::GovernedFacet("tool.arguments.text") => match observation.body() {
            ObservationBody::Tool(body) => body
                .searchable_arguments()
                .map(|value| ("tool.searchable_arguments", JsonValue::string(value)))
                .or_else(|| match body.arguments() {
                    Some(JsonValue::String(value)) => {
                        Some(("tool.arguments", JsonValue::string(value)))
                    }
                    _ => None,
                }),
            _ => None,
        },
        SelectorId::GovernedFacet("tool.result.text") => match observation.body() {
            ObservationBody::Tool(body) => body
                .searchable_result()
                .map(|value| ("tool.searchable_result", JsonValue::string(value)))
                .or_else(|| match body.result() {
                    Some(JsonValue::String(value)) => {
                        Some(("tool.result", JsonValue::string(value)))
                    }
                    _ => None,
                }),
            _ => None,
        },
        SelectorId::GovernedFacet("tool.result.is_error") => match observation.body() {
            ObservationBody::Tool(body) => body
                .is_error()
                .map(|value| ("tool.is_error", JsonValue::Bool(value))),
            _ => None,
        },
        SelectorId::GovernedFacet("tool.result.exit_code") => match observation.body() {
            ObservationBody::Tool(body) => body
                .exit_code()
                .map(|value| ("tool.exit_code", JsonValue::Integer(value))),
            _ => None,
        },
        SelectorId::GovernedFacet("network.domain") => match observation.body() {
            ObservationBody::Network(body) => body
                .domain()
                .map(|value| ("network.domain", JsonValue::string(value))),
            _ => None,
        },
        SelectorId::GovernedFacet("network.destination_class") => match observation.body() {
            ObservationBody::Network(body) => body
                .destination_class()
                .map(|value| ("network.destination_class", JsonValue::string(value))),
            _ => None,
        },
        SelectorId::GovernedFacet("network.operation") => match observation.body() {
            ObservationBody::Network(body) => body
                .operation()
                .map(|value| ("network.operation", JsonValue::string(value))),
            _ => None,
        },
        SelectorId::GovernedFacet("network.port") => match observation.body() {
            ObservationBody::Network(body) => body
                .port()
                .map(|value| ("network.port", JsonValue::Unsigned(value as u64))),
            _ => None,
        },
        SelectorId::GovernedFacet("network.protocol") => match observation.body() {
            ObservationBody::Network(body) => body
                .protocol()
                .map(|value| ("network.protocol", JsonValue::string(value))),
            _ => None,
        },
        SelectorId::GovernedFacet("process.name") => match observation.body() {
            ObservationBody::Process(body) => body
                .name()
                .map(|value| ("process.name", JsonValue::string(value))),
            _ => None,
        },
        SelectorId::GovernedFacet("process.pid") => match observation.body() {
            ObservationBody::Process(body) => body
                .pid()
                .map(|value| ("process.pid", JsonValue::Unsigned(value))),
            _ => None,
        },
        SelectorId::GovernedFacet("process.instance_id") => match observation.body() {
            ObservationBody::Process(body) => body
                .instance_id()
                .map(|value| ("process.instance_id", JsonValue::string(value))),
            _ => None,
        },
        SelectorId::GovernedFacet("process.privilege") => match observation.body() {
            ObservationBody::Process(body) => body
                .privilege()
                .map(|value| ("process.privilege", JsonValue::string(value))),
            _ => None,
        },
        SelectorId::GovernedFacet("inference.provider") => match observation.body() {
            ObservationBody::Inference(body) => body
                .provider()
                .map(|value| ("inference.provider", JsonValue::string(value))),
            _ => None,
        },
        SelectorId::GovernedFacet("inference.requested_model") => match observation.body() {
            ObservationBody::Inference(body) => body
                .requested_model()
                .map(|value| ("inference.requested_model", JsonValue::string(value))),
            _ => None,
        },
        SelectorId::GovernedFacet("inference.resolved_model") => match observation.body() {
            ObservationBody::Inference(body) => body
                .resolved_model()
                .map(|value| ("inference.resolved_model", JsonValue::string(value))),
            _ => None,
        },
        SelectorId::GovernedFacet("inference.streaming") => match observation.body() {
            ObservationBody::Inference(body) => body
                .streaming()
                .map(|value| ("inference.streaming", JsonValue::Bool(value))),
            _ => None,
        },
        SelectorId::GovernedFacet("inference.stop_reason") => match observation.body() {
            ObservationBody::Inference(body) => body
                .stop_reason()
                .map(|value| ("inference.stop_reason", JsonValue::string(value))),
            _ => None,
        },
        SelectorId::GovernedFacet("mcp.server.id") => match observation.body() {
            ObservationBody::Mcp(body) => body
                .server_id()
                .map(|value| ("mcp.server_id", JsonValue::string(value))),
            _ => None,
        },
        SelectorId::GovernedFacet("mcp.server.transport") => match observation.body() {
            ObservationBody::Mcp(body) => body
                .transport()
                .map(|value| ("mcp.transport", JsonValue::string(value))),
            _ => None,
        },
        SelectorId::GovernedFacet("mcp.server.location_class") => match observation.body() {
            ObservationBody::Mcp(body) => body
                .location_class()
                .map(|value| ("mcp.location_class", JsonValue::string(value))),
            _ => None,
        },
        SelectorId::GovernedFacet("mcp.tool.name") => match observation.body() {
            ObservationBody::Mcp(body) => body
                .tool_name()
                .map(|value| ("mcp.tool_name", JsonValue::string(value))),
            _ => None,
        },
        SelectorId::GovernedFacet("runtime.execution_mode") => match observation.body() {
            ObservationBody::Runtime(body) => body
                .execution_mode()
                .map(|value| ("runtime.execution_mode", JsonValue::string(value))),
            _ => None,
        },
        SelectorId::GovernedFacet("runtime.isolation.state") => match observation.body() {
            ObservationBody::Runtime(body) => body
                .isolation_state()
                .map(|value| ("runtime.isolation_state", JsonValue::string(value))),
            _ => None,
        },
        SelectorId::GovernedFacet("runtime.workspace.class") => match observation.body() {
            ObservationBody::Runtime(body) => body
                .workspace_class()
                .map(|value| ("runtime.workspace_class", JsonValue::string(value))),
            _ => None,
        },
        SelectorId::GovernedFacet("runtime.privilege") => match observation.body() {
            ObservationBody::Runtime(body) => body
                .privilege()
                .map(|value| ("runtime.privilege", JsonValue::string(value))),
            _ => None,
        },
        SelectorId::GovernedFacet("browser.surface") => match observation.body() {
            ObservationBody::Browser(body) => body
                .surface()
                .map(|value| ("browser.surface", JsonValue::string(value))),
            _ => None,
        },
        SelectorId::GovernedFacet("browser.origin_class") => match observation.body() {
            ObservationBody::Browser(body) => body
                .origin_class()
                .map(|value| ("browser.origin_class", JsonValue::string(value))),
            _ => None,
        },
        SelectorId::GovernedFacet("browser.navigation_id") => match observation.body() {
            ObservationBody::Browser(body) => body
                .navigation_id()
                .map(|value| ("browser.navigation_id", JsonValue::string(value))),
            _ => None,
        },
        SelectorId::GovernedFacet("resource.operation") => match observation.body() {
            ObservationBody::File(body) => body
                .operation()
                .map(|value| ("file.operation", JsonValue::string(value))),
            _ => None,
        },
        SelectorId::GovernedFacet("resource.path_class") => match observation.body() {
            ObservationBody::File(body) => body
                .path_class()
                .map(|value| ("file.path_class", JsonValue::string(value))),
            _ => None,
        },
        _ => None,
    }
}

fn field(
    selector: SelectorId,
    observation: &CanonicalObservationV2,
    path: &str,
    value: JsonValue,
    required_capability: Option<CapabilityId>,
) -> SelectorResolution {
    match metadata_for_path(observation, path) {
        Ok(Some(metadata)) => SelectorResolution {
            selector,
            presence: SelectorPresence::Present,
            value: Some(value),
            metadata: Some(metadata),
            required_capability,
        },
        _ => SelectorResolution {
            selector,
            presence: SelectorPresence::MetadataMissing,
            value: Some(value),
            metadata: None,
            required_capability,
        },
    }
}

fn derived_field(
    selector: SelectorId,
    value: JsonValue,
    required_capability: Option<CapabilityId>,
) -> SelectorResolution {
    match FactMetadata::new(
        FactProvenance::Derived,
        telltale_schema::observation::Sensitivity::Normal,
    ) {
        Ok(metadata) => SelectorResolution {
            selector,
            presence: SelectorPresence::Present,
            value: Some(value),
            metadata: Some(metadata),
            required_capability,
        },
        Err(_) => SelectorResolution {
            selector,
            presence: SelectorPresence::MetadataMissing,
            value: None,
            metadata: None,
            required_capability,
        },
    }
}

fn correlation_field(
    selector: SelectorId,
    value: &telltale_schema::observation::CorrelationId,
    required_capability: Option<CapabilityId>,
) -> SelectorResolution {
    let provenance = match value.origin() {
        CorrelationOrigin::SourceReported => FactProvenance::Reported,
        CorrelationOrigin::TelltaleOriginated => FactProvenance::Derived,
    };
    match FactMetadata::new(
        provenance,
        telltale_schema::observation::Sensitivity::Normal,
    ) {
        Ok(metadata) => SelectorResolution {
            selector,
            presence: SelectorPresence::Present,
            value: Some(JsonValue::string(value.value())),
            metadata: Some(metadata),
            required_capability,
        },
        Err(_) => SelectorResolution {
            selector,
            presence: SelectorPresence::MetadataMissing,
            value: None,
            metadata: None,
            required_capability,
        },
    }
}

fn facet(
    selector: SelectorId,
    observation: &CanonicalObservationV2,
    path: &str,
    required_capability: Option<CapabilityId>,
) -> SelectorResolution {
    observation.facets().get(path).map_or_else(
        || absent(selector, required_capability),
        |value| {
            field(
                selector,
                observation,
                path,
                value.value().clone(),
                required_capability,
            )
        },
    )
}

fn tool_value(
    selector: SelectorId,
    observation: &CanonicalObservationV2,
    arguments: bool,
    required_capability: Option<CapabilityId>,
) -> SelectorResolution {
    match observation.body() {
        ObservationBody::Tool(body) => {
            let (path, value) = if arguments {
                ("tool.arguments", body.arguments())
            } else {
                ("tool.result", body.result())
            };
            value.map_or_else(
                || absent(selector, required_capability),
                |value| {
                    field(
                        selector,
                        observation,
                        path,
                        value.clone(),
                        required_capability,
                    )
                },
            )
        }
        _ => absent(selector, required_capability),
    }
}

fn tool_string(
    selector: SelectorId,
    observation: &CanonicalObservationV2,
    arguments: bool,
    required_capability: Option<CapabilityId>,
) -> SelectorResolution {
    match observation.body() {
        ObservationBody::Tool(body) => {
            let (path, value) = if arguments {
                ("tool.searchable_arguments", body.searchable_arguments())
            } else {
                ("tool.searchable_result", body.searchable_result())
            };
            value.map_or_else(
                || absent(selector, required_capability),
                |value| {
                    field(
                        selector,
                        observation,
                        path,
                        JsonValue::string(value),
                        required_capability,
                    )
                },
            )
        }
        _ => absent(selector, required_capability),
    }
}

fn tool_text(
    selector: SelectorId,
    observation: &CanonicalObservationV2,
    arguments: bool,
    required_capability: Option<CapabilityId>,
) -> SelectorResolution {
    match observation.body() {
        ObservationBody::Tool(body) => {
            let (search_path, search, value_path, value) = if arguments {
                (
                    "tool.searchable_arguments",
                    body.searchable_arguments(),
                    "tool.arguments",
                    body.arguments(),
                )
            } else {
                (
                    "tool.searchable_result",
                    body.searchable_result(),
                    "tool.result",
                    body.result(),
                )
            };
            if let Some(value) = search {
                return field(
                    selector,
                    observation,
                    search_path,
                    JsonValue::string(value),
                    required_capability,
                );
            }
            match value {
                Some(JsonValue::String(value)) => field(
                    selector,
                    observation,
                    value_path,
                    JsonValue::string(value),
                    required_capability,
                ),
                _ => absent(selector, required_capability),
            }
        }
        _ => absent(selector, required_capability),
    }
}

fn tool_argument_keys(
    selector: SelectorId,
    observation: &CanonicalObservationV2,
    required_capability: Option<CapabilityId>,
) -> SelectorResolution {
    match observation.body() {
        ObservationBody::Tool(body) => match body.arguments() {
            Some(JsonValue::Object(values)) => derived_field(
                selector,
                JsonValue::Array(values.keys().map(JsonValue::string).collect()),
                required_capability,
            ),
            _ => absent(selector, required_capability),
        },
        _ => absent(selector, required_capability),
    }
}

fn compat_tool_string(
    selector: SelectorId,
    observation: &CanonicalObservationV2,
    arguments: bool,
    required_capability: Option<CapabilityId>,
) -> SelectorResolution {
    match observation.body() {
        ObservationBody::Tool(body) => {
            let (search_path, search, value_path, value) = if arguments {
                (
                    "tool.searchable_arguments",
                    body.searchable_arguments(),
                    "tool.arguments",
                    body.arguments(),
                )
            } else {
                (
                    "tool.searchable_result",
                    body.searchable_result(),
                    "tool.result",
                    body.result(),
                )
            };
            if let Some(value) = search {
                return field(
                    selector,
                    observation,
                    search_path,
                    JsonValue::string(value),
                    required_capability,
                );
            }
            match value {
                Some(JsonValue::String(value)) => field(
                    selector,
                    observation,
                    value_path,
                    JsonValue::string(value),
                    required_capability,
                ),
                _ => absent(selector, required_capability),
            }
        }
        _ => absent(selector, required_capability),
    }
}

fn message_context(
    selector: SelectorId,
    observation: &CanonicalObservationV2,
    assistant: bool,
    required_capability: Option<CapabilityId>,
) -> SelectorResolution {
    match observation.body() {
        ObservationBody::Message(body) => {
            let role_matches = body.role().is_some_and(|role| {
                (assistant && role == telltale_schema::observation::MessageRole::Assistant)
                    || (!assistant && role == telltale_schema::observation::MessageRole::User)
            });
            if !role_matches {
                return absent(selector, required_capability);
            }
            match body.content() {
                Some(JsonValue::String(value)) => field(
                    selector,
                    observation,
                    "message.content",
                    JsonValue::string(value),
                    required_capability,
                ),
                _ => absent(selector, required_capability),
            }
        }
        _ => absent(selector, required_capability),
    }
}
