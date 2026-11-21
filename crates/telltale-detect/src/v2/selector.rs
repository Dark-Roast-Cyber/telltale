//! Explicit Canonical Observation v2 selector registry.

use std::fmt;

use telltale_schema::observation::{
    BoundDimension, BoundedTarget, CanonicalObservationV2, CapabilityId, CorrelationOrigin,
    FactMetadata, FactProvenance, JsonValue, ObservationBody,
};

use super::tool_arguments::{
    command_member_has_role, named_tool_kind, reads_by_role, tool_argument_urls, tool_written_paths,
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
    "compat.v1.tool_kind",
    "compat.v1.tool_name",
    "compat.v1.tool_result",
    "compat.v1.url",
    "compat.v1.user_context",
    "compat.v1.written_path",
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

/// The registered selectors that parse as [`SelectorId::GovernedFacet`] and
/// have their own resolver handling. Resolver arms match these names, never a
/// string literal, so a renamed registry entry fails the selector tests instead
/// of falling through to no handling.
pub(super) mod governed {
    pub const MESSAGE_TEXT: &str = "message.text";
    pub const TOOL_CALL_ID: &str = "tool.call_id";
    pub const TOOL_STAGE: &str = "tool.stage";
    pub const TOOL_ARGUMENTS_TEXT: &str = "tool.arguments.text";
    pub const TOOL_ARGUMENTS_KEYS: &str = "tool.arguments.keys";
    pub const TOOL_RESULT_TEXT: &str = "tool.result.text";
    pub const TOOL_RESULT_IS_ERROR: &str = "tool.result.is_error";
    pub const TOOL_RESULT_EXIT_CODE: &str = "tool.result.exit_code";
    pub const RESOURCE_OPERATION: &str = "resource.operation";
    pub const RESOURCE_PATH_CLASS: &str = "resource.path_class";
    pub const NETWORK_DOMAIN: &str = "network.domain";
    pub const NETWORK_DESTINATION_CLASS: &str = "network.destination_class";
    pub const NETWORK_OPERATION: &str = "network.operation";
    pub const NETWORK_PORT: &str = "network.port";
    pub const NETWORK_PROTOCOL: &str = "network.protocol";
    pub const PROCESS_NAME: &str = "process.name";
    pub const PROCESS_PID: &str = "process.pid";
    pub const PROCESS_INSTANCE_ID: &str = "process.instance_id";
    pub const PROCESS_PRIVILEGE: &str = "process.privilege";
    pub const INFERENCE_PROVIDER: &str = "inference.provider";
    pub const INFERENCE_REQUESTED_MODEL: &str = "inference.requested_model";
    pub const INFERENCE_RESOLVED_MODEL: &str = "inference.resolved_model";
    pub const INFERENCE_STREAMING: &str = "inference.streaming";
    pub const INFERENCE_STOP_REASON: &str = "inference.stop_reason";
    pub const MCP_SERVER_ID: &str = "mcp.server.id";
    pub const MCP_SERVER_TRANSPORT: &str = "mcp.server.transport";
    pub const MCP_SERVER_LOCATION_CLASS: &str = "mcp.server.location_class";
    pub const MCP_TOOL_NAME: &str = "mcp.tool.name";
    pub const RUNTIME_EXECUTION_MODE: &str = "runtime.execution_mode";
    pub const RUNTIME_ISOLATION_STATE: &str = "runtime.isolation.state";
    pub const RUNTIME_PRIVILEGE: &str = "runtime.privilege";
    pub const RUNTIME_WORKSPACE_CLASS: &str = "runtime.workspace.class";
    pub const BROWSER_SURFACE: &str = "browser.surface";
    pub const BROWSER_ORIGIN_CLASS: &str = "browser.origin_class";
    pub const BROWSER_NAVIGATION_ID: &str = "browser.navigation_id";

    #[cfg(test)]
    pub const ALL: &[&str] = &[
        MESSAGE_TEXT,
        TOOL_CALL_ID,
        TOOL_STAGE,
        TOOL_ARGUMENTS_TEXT,
        TOOL_ARGUMENTS_KEYS,
        TOOL_RESULT_TEXT,
        TOOL_RESULT_IS_ERROR,
        TOOL_RESULT_EXIT_CODE,
        RESOURCE_OPERATION,
        RESOURCE_PATH_CLASS,
        NETWORK_DOMAIN,
        NETWORK_DESTINATION_CLASS,
        NETWORK_OPERATION,
        NETWORK_PORT,
        NETWORK_PROTOCOL,
        PROCESS_NAME,
        PROCESS_PID,
        PROCESS_INSTANCE_ID,
        PROCESS_PRIVILEGE,
        INFERENCE_PROVIDER,
        INFERENCE_REQUESTED_MODEL,
        INFERENCE_RESOLVED_MODEL,
        INFERENCE_STREAMING,
        INFERENCE_STOP_REASON,
        MCP_SERVER_ID,
        MCP_SERVER_TRANSPORT,
        MCP_SERVER_LOCATION_CLASS,
        MCP_TOOL_NAME,
        RUNTIME_EXECUTION_MODE,
        RUNTIME_ISOLATION_STATE,
        RUNTIME_PRIVILEGE,
        RUNTIME_WORKSPACE_CLASS,
        BROWSER_SURFACE,
        BROWSER_ORIGIN_CLASS,
        BROWSER_NAVIGATION_ID,
    ];
}

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
    ("compat.v1.tool_kind", SelectorBacking::Compatibility),
    ("compat.v1.tool_name", SelectorBacking::Compatibility),
    ("compat.v1.tool_result", SelectorBacking::Compatibility),
    ("compat.v1.url", SelectorBacking::Compatibility),
    ("compat.v1.user_context", SelectorBacking::Compatibility),
    ("compat.v1.written_path", SelectorBacking::Compatibility),
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
    CompatToolKind,
    CompatToolName,
    CompatToolResult,
    CompatUrl,
    CompatUserContext,
    CompatWrittenPath,
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
            "compat.v1.tool_kind" => Ok(Self::CompatToolKind),
            "compat.v1.tool_name" => Ok(Self::CompatToolName),
            "compat.v1.tool_result" => Ok(Self::CompatToolResult),
            "compat.v1.url" => Ok(Self::CompatUrl),
            "compat.v1.user_context" => Ok(Self::CompatUserContext),
            "compat.v1.written_path" => Ok(Self::CompatWrittenPath),
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
            Self::CompatToolKind => "compat.v1.tool_kind",
            Self::CompatToolName => "compat.v1.tool_name",
            Self::CompatToolResult => "compat.v1.tool_result",
            Self::CompatUrl => "compat.v1.url",
            Self::CompatUserContext => "compat.v1.user_context",
            Self::CompatWrittenPath => "compat.v1.written_path",
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
            | Self::CompatToolKind
            | Self::CompatToolName
            | Self::CompatToolResult
            | Self::CompatUrl
            | Self::CompatWrittenPath => Some(CapabilityId::ToolCall),
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
    UnavailableVisibility,
    MetadataMissing,
}

#[derive(Clone)]
pub struct SelectorResolution {
    selector: SelectorId,
    presence: SelectorPresence,
    value: Option<JsonValue>,
    metadata: Option<FactMetadata>,
    required_capability: Option<CapabilityId>,
    partial: bool,
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
            .field("partial", &self.partial)
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
    /// Whether a present value was derived from a call's tool values while
    /// some of them were replaced: it holds whole values, but maybe not all
    /// of them. A match on it counts as it did before; a no-match or a negated
    /// condition is not evaluated.
    pub fn is_partial(&self) -> bool {
        self.partial
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
    ) -> Result<SelectorResolution, super::session::ProcessingError> {
        self.try_resolve(
            selector,
            observation,
            &mut super::session::RetentionBudget::new(),
        )
    }

    pub(crate) fn try_resolve(
        &self,
        selector: SelectorId,
        observation: &CanonicalObservationV2,
        budget: &mut super::session::RetentionBudget,
    ) -> Result<SelectorResolution, super::session::ProcessingError> {
        budget.charge(1)?;
        for (path, metadata) in observation.fact_metadata() {
            budget.charge(path.len())?;
            for fingerprint in metadata.keyed_fingerprints() {
                budget.charge(
                    fingerprint
                        .location()
                        .len()
                        .saturating_add(fingerprint.key_epoch_ref().len())
                        .saturating_add(fingerprint.algorithm().len())
                        .saturating_add(fingerprint.digest().len()),
                )?;
            }
        }
        if matches!(
            selector,
            SelectorId::GovernedFacet(governed::MESSAGE_TEXT)
                | SelectorId::CompatAssistantContext
                | SelectorId::CompatUserContext
        ) {
            return message_text(selector, observation, budget);
        }
        if reads_omitted_searchable_text(selector, observation) {
            return Ok(SelectorResolution {
                selector,
                presence: SelectorPresence::UnavailableVisibility,
                value: None,
                metadata: None,
                required_capability: selector.required_capability(),
                partial: false,
            });
        }
        // Canonical direct result strings are already NFC. Copy the selected
        // text once, without normalizing or reserving unrelated fields for each
        // rule. Keep searchable-text precedence and structured fallbacks intact.
        if matches!(
            selector,
            SelectorId::ToolResult
                | SelectorId::CompatToolResult
                | SelectorId::GovernedFacet(governed::TOOL_RESULT_TEXT)
        ) && let ObservationBody::Tool(tool) = observation.body()
            && (selector == SelectorId::ToolResult || tool.searchable_result().is_none())
            && let Some(JsonValue::String(text)) = tool.result()
        {
            budget.charge(text.len())?;
            return Ok(field(
                selector,
                observation,
                "tool.result",
                JsonValue::String(text.clone()),
                selector.required_capability(),
            ));
        }
        // Closed scalar controls copy only their selected text and metadata,
        // not unrelated authored arguments. Structured facets keep the generic
        // conservative reservation; matcher passes still charge reached input.
        let control_bytes = match selector {
            SelectorId::ToolName | SelectorId::CompatToolName => Some(match observation.body() {
                ObservationBody::Tool(tool) => tool.name().map_or(0, str::len),
                _ => 0,
            }),
            SelectorId::CommandText
            | SelectorId::CompatCommand
            | SelectorId::ResourcePath
            | SelectorId::CompatFilePath => {
                let path = if matches!(
                    selector,
                    SelectorId::CommandText | SelectorId::CompatCommand
                ) {
                    "command.text"
                } else {
                    "resource.path"
                };
                match observation.facets().get(path).map(|facet| facet.value()) {
                    Some(JsonValue::String(text)) => Some(text.len()),
                    None => Some(0),
                    _ => None,
                }
            }
            _ => None,
        };
        if let Some(bytes) = control_bytes {
            budget.charge(bytes.saturating_mul(2))?;
            return Ok(self.resolve_value(selector, observation));
        }
        // Resolution can copy a structured value, canonicalize its strings, and
        // clone field metadata. These closed selectors never visit tool.result;
        // exclude its direct text length in O(1), retaining the conservative
        // allowance for all other fields (and JSON escaping overhead). Charging
        // unrelated output for every control lookup spuriously exhausts work on
        // ordinary compiler/search output. Result selectors still reserve all
        // bytes, and matcher/hash/sanitizer passes charge their reached input.
        let unrelated_result_bytes = if matches!(
            selector,
            SelectorId::SessionId
                | SelectorId::MessageRole
                | SelectorId::MessageContent
                | SelectorId::ToolName
                | SelectorId::ToolArguments
                | SelectorId::ToolSearchableArguments
                | SelectorId::ToolReportedStatus
                | SelectorId::ToolIsError
                | SelectorId::ToolExitCode
                | SelectorId::CommandText
                | SelectorId::ResourcePath
                | SelectorId::CompatArguments
                | SelectorId::CompatCommand
                | SelectorId::CompatFilePath
                | SelectorId::CompatToolKind
                | SelectorId::CompatToolName
                | SelectorId::CompatUrl
                | SelectorId::CompatWrittenPath
        ) {
            match observation.body() {
                ObservationBody::Tool(tool) => match tool.result() {
                    Some(JsonValue::String(text)) => text.len(),
                    _ => 0,
                },
                _ => 0,
            }
        } else {
            0
        };
        budget.charge(
            observation
                .retained_byte_len()
                .saturating_sub(unrelated_result_bytes)
                .saturating_mul(2),
        )?;
        Ok(self.resolve_value(selector, observation))
    }

    fn resolve_value(
        &self,
        selector: SelectorId,
        observation: &CanonicalObservationV2,
    ) -> SelectorResolution {
        let required_capability = selector.required_capability();
        if SelectorId::parse(selector.as_str()).ok() != Some(selector)
            || reads_declared_role_text(selector, observation)
        {
            return absent(selector, required_capability);
        }
        let resolution = if matches!(
            selector,
            SelectorId::CompatArguments
                | SelectorId::CompatAssistantContext
                | SelectorId::CompatCommand
                | SelectorId::CompatFilePath
                | SelectorId::CompatToolKind
                | SelectorId::CompatToolName
                | SelectorId::CompatToolResult
                | SelectorId::CompatUrl
                | SelectorId::CompatUserContext
                | SelectorId::CompatWrittenPath
        ) {
            Self::resolve_compat(selector, observation, required_capability)
        } else {
            Self::resolve_native(selector, observation, required_capability)
        };
        with_bounded_visibility(resolution, observation)
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
                        partial: false,
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
            SelectorId::GovernedFacet(governed::TOOL_ARGUMENTS_TEXT) => {
                tool_text(selector, observation, true, required_capability)
            }
            SelectorId::GovernedFacet(governed::TOOL_ARGUMENTS_KEYS) => {
                tool_argument_keys(selector, observation, required_capability)
            }
            SelectorId::ToolResult => tool_value(selector, observation, false, required_capability),
            SelectorId::ToolSearchableResult => {
                tool_string(selector, observation, false, required_capability)
            }
            SelectorId::GovernedFacet(governed::TOOL_RESULT_TEXT) => {
                tool_text(selector, observation, false, required_capability)
            }
            SelectorId::GovernedFacet(governed::TOOL_RESULT_IS_ERROR) => match observation.body() {
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
            SelectorId::GovernedFacet(governed::TOOL_RESULT_EXIT_CODE) => {
                match observation.body() {
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
                }
            }
            SelectorId::GovernedFacet(governed::TOOL_CALL_ID) => {
                observation.correlation().call_id().map_or_else(
                    || absent(selector, required_capability),
                    |value| correlation_field(selector, value, required_capability),
                )
            }
            SelectorId::GovernedFacet(governed::TOOL_STAGE) => {
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
            _ => absent(selector, required_capability),
        }
    }

    fn resolve_compat(
        selector: SelectorId,
        observation: &CanonicalObservationV2,
        required_capability: Option<CapabilityId>,
    ) -> SelectorResolution {
        match selector {
            SelectorId::CompatArguments => {
                tool_text(selector, observation, true, required_capability)
            }
            SelectorId::CompatToolResult => {
                tool_text(selector, observation, false, required_capability)
            }
            SelectorId::CompatToolName => {
                let mut resolved =
                    Self::resolve_native(SelectorId::ToolName, observation, required_capability);
                resolved.selector = selector;
                resolved
            }
            // The v1 kind view is what the tool a record names does: the kind
            // its source's tool table declares, else the kind of a native name.
            // A record that names no tool, or a tool of neither, has no kind.
            SelectorId::CompatToolKind => match observation.body() {
                ObservationBody::Tool(tool) => named_tool_kind(tool).map_or_else(
                    || absent(selector, required_capability),
                    |kind| {
                        derived_field(
                            selector,
                            JsonValue::string(kind.as_str()),
                            required_capability,
                        )
                    },
                ),
                _ => absent(selector, required_capability),
            },
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
            // The v1 URL view is the URL-keyed top-level string arguments of a
            // tool call. Command text and tool results are separate targets;
            // they are not copied into URL (the action view, unlike this
            // selector, also reads command text as URL).
            SelectorId::CompatUrl => match observation.body() {
                ObservationBody::Tool(tool) => {
                    let urls = tool_argument_urls(tool, true);
                    if urls.is_empty() {
                        absent(selector, required_capability)
                    } else {
                        derived_field(
                            selector,
                            JsonValue::string(urls.join("\n")),
                            required_capability,
                        )
                    }
                }
                _ => absent(selector, required_capability),
            },
            // The v1 written-path view is the file-keyed top-level string
            // arguments of a call that writes them. A path a call only reads
            // stays a `file_path` fact; shell writes remain command text.
            SelectorId::CompatWrittenPath => match observation.body() {
                ObservationBody::Tool(tool) => {
                    let paths = tool_written_paths(tool, true);
                    if paths.is_empty() {
                        absent(selector, required_capability)
                    } else {
                        derived_field(
                            selector,
                            JsonValue::string(paths.join("\n")),
                            required_capability,
                        )
                    }
                }
                _ => absent(selector, required_capability),
            },
            _ => absent(selector, required_capability),
        }
    }
}

/// Whether `selector` would read, as argument or command text, what a call's
/// declaration says is authored or replaced content. A call whose arguments are
/// an object has no such text in these selectors: they read the text of a string
/// and the command facet, and an object is neither. A declared call reads as it
/// would in that shape, so these selectors do not see the content. The typed
/// `tool.arguments` and `tool.searchable_arguments` selectors keep the whole value.
fn reads_declared_role_text(selector: SelectorId, observation: &CanonicalObservationV2) -> bool {
    let ObservationBody::Tool(tool) = observation.body() else {
        return false;
    };
    match selector {
        SelectorId::CompatArguments | SelectorId::GovernedFacet(governed::TOOL_ARGUMENTS_TEXT) => {
            reads_by_role(tool)
        }
        SelectorId::CompatCommand | SelectorId::CommandText => command_member_has_role(tool),
        _ => false,
    }
}

/// Whether `selector` reads a call's searchable text (alone or before its
/// value) that was omitted for its size. Such a selector has no visibility
/// into the call: it is not evaluated, rather than read as absent or from the
/// value it would otherwise fall back to.
fn reads_omitted_searchable_text(
    selector: SelectorId,
    observation: &CanonicalObservationV2,
) -> bool {
    let ObservationBody::Tool(tool) = observation.body() else {
        return false;
    };
    let target = match selector {
        SelectorId::ToolSearchableArguments
        | SelectorId::CompatArguments
        | SelectorId::GovernedFacet(governed::TOOL_ARGUMENTS_TEXT) => {
            BoundedTarget::SearchableArguments
        }
        SelectorId::ToolSearchableResult
        | SelectorId::CompatToolResult
        | SelectorId::GovernedFacet(governed::TOOL_RESULT_TEXT) => BoundedTarget::SearchableResult,
        _ => return false,
    };
    tool.bounded_values()
        .iter()
        .any(|value| value.target() == target)
}

/// How `resolution` reads when the tool value its selector reads, or derives
/// a fact from, has replacements (`null`s a bounded conversion left, listed in
/// `tool.bounded_values`). Telltale did not see that value whole, so:
///
/// - the whole-value selectors (`tool.arguments`, `tool.result`) have no
///   visibility into the call;
/// - a text or fact that reads as absent may be absent only because its
///   operand, or a container holding it, was replaced, so it has no
///   visibility either; a source never builds a fact from a replaced member,
///   and detection cannot tell which member a source would have read, so any
///   replacement in the field counts;
/// - a present text or fact is a value seen whole and stays present, except
///   that a URL or written-path list derived from several members
///   (`compat.v1.url`, `compat.v1.written_path`) may miss the replaced ones:
///   it is partial, so a match on it counts as it did before, and a no-match
///   or a negated condition is not evaluated;
/// - the argument keys stay exact beside a replaced member, which leaves
///   `null` under its key; they are partial only when a member was dropped
///   from the arguments object for its over-long key.
fn with_bounded_visibility(
    mut resolution: SelectorResolution,
    observation: &CanonicalObservationV2,
) -> SelectorResolution {
    let ObservationBody::Tool(tool) = observation.body() else {
        return resolution;
    };
    let (target, whole, list) = match resolution.selector {
        SelectorId::ToolArguments => (BoundedTarget::Arguments, true, false),
        SelectorId::ToolResult => (BoundedTarget::Result, true, false),
        SelectorId::ToolSearchableArguments
        | SelectorId::CompatArguments
        | SelectorId::GovernedFacet(governed::TOOL_ARGUMENTS_TEXT)
        | SelectorId::GovernedFacet(governed::TOOL_ARGUMENTS_KEYS)
        | SelectorId::CommandText
        | SelectorId::CompatCommand
        | SelectorId::ResourcePath
        | SelectorId::CompatFilePath => (BoundedTarget::Arguments, false, false),
        SelectorId::CompatUrl | SelectorId::CompatWrittenPath => {
            (BoundedTarget::Arguments, false, true)
        }
        SelectorId::ToolSearchableResult
        | SelectorId::CompatToolResult
        | SelectorId::GovernedFacet(governed::TOOL_RESULT_TEXT) => {
            (BoundedTarget::Result, false, false)
        }
        _ => return resolution,
    };
    if !tool
        .bounded_values()
        .iter()
        .any(|value| value.target() == target)
    {
        return resolution;
    }
    if resolution.selector == SelectorId::GovernedFacet(governed::TOOL_ARGUMENTS_KEYS)
        && resolution.presence == SelectorPresence::Present
    {
        resolution.partial = tool.bounded_values().iter().any(|value| {
            value.target() == BoundedTarget::Arguments
                && value.pointer().is_empty()
                && value.dimension() == BoundDimension::KeyBytes
        });
        return resolution;
    }
    match resolution.presence {
        SelectorPresence::Present if list => resolution.partial = true,
        SelectorPresence::Present if !whole => {}
        SelectorPresence::Present | SelectorPresence::Absent => {
            resolution.presence = SelectorPresence::UnavailableVisibility;
            resolution.value = None;
            resolution.metadata = None;
        }
        SelectorPresence::UnavailableVisibility | SelectorPresence::MetadataMissing => {}
    }
    resolution
}

fn absent(selector: SelectorId, required_capability: Option<CapabilityId>) -> SelectorResolution {
    SelectorResolution {
        selector,
        presence: SelectorPresence::Absent,
        value: None,
        metadata: None,
        required_capability,
        partial: false,
    }
}

fn typed_body_value(
    selector: SelectorId,
    observation: &CanonicalObservationV2,
) -> Option<(&'static str, JsonValue)> {
    match selector {
        SelectorId::GovernedFacet(governed::TOOL_ARGUMENTS_TEXT) => match observation.body() {
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
        SelectorId::GovernedFacet(governed::TOOL_RESULT_TEXT) => match observation.body() {
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
        SelectorId::GovernedFacet(governed::TOOL_RESULT_IS_ERROR) => match observation.body() {
            ObservationBody::Tool(body) => body
                .is_error()
                .map(|value| ("tool.is_error", JsonValue::Bool(value))),
            _ => None,
        },
        SelectorId::GovernedFacet(governed::TOOL_RESULT_EXIT_CODE) => match observation.body() {
            ObservationBody::Tool(body) => body
                .exit_code()
                .map(|value| ("tool.exit_code", JsonValue::Integer(value))),
            _ => None,
        },
        SelectorId::GovernedFacet(governed::NETWORK_DOMAIN) => match observation.body() {
            ObservationBody::Network(body) => body
                .domain()
                .map(|value| ("network.domain", JsonValue::string(value))),
            _ => None,
        },
        SelectorId::GovernedFacet(governed::NETWORK_DESTINATION_CLASS) => {
            match observation.body() {
                ObservationBody::Network(body) => body
                    .destination_class()
                    .map(|value| ("network.destination_class", JsonValue::string(value))),
                _ => None,
            }
        }
        SelectorId::GovernedFacet(governed::NETWORK_OPERATION) => match observation.body() {
            ObservationBody::Network(body) => body
                .operation()
                .map(|value| ("network.operation", JsonValue::string(value))),
            _ => None,
        },
        SelectorId::GovernedFacet(governed::NETWORK_PORT) => match observation.body() {
            ObservationBody::Network(body) => body
                .port()
                .map(|value| ("network.port", JsonValue::Unsigned(value as u64))),
            _ => None,
        },
        SelectorId::GovernedFacet(governed::NETWORK_PROTOCOL) => match observation.body() {
            ObservationBody::Network(body) => body
                .protocol()
                .map(|value| ("network.protocol", JsonValue::string(value))),
            _ => None,
        },
        SelectorId::GovernedFacet(governed::PROCESS_NAME) => match observation.body() {
            ObservationBody::Process(body) => body
                .name()
                .map(|value| ("process.name", JsonValue::string(value))),
            _ => None,
        },
        SelectorId::GovernedFacet(governed::PROCESS_PID) => match observation.body() {
            ObservationBody::Process(body) => body
                .pid()
                .map(|value| ("process.pid", JsonValue::Unsigned(value))),
            _ => None,
        },
        SelectorId::GovernedFacet(governed::PROCESS_INSTANCE_ID) => match observation.body() {
            ObservationBody::Process(body) => body
                .instance_id()
                .map(|value| ("process.instance_id", JsonValue::string(value))),
            _ => None,
        },
        SelectorId::GovernedFacet(governed::PROCESS_PRIVILEGE) => match observation.body() {
            ObservationBody::Process(body) => body
                .privilege()
                .map(|value| ("process.privilege", JsonValue::string(value))),
            _ => None,
        },
        SelectorId::GovernedFacet(governed::INFERENCE_PROVIDER) => match observation.body() {
            ObservationBody::Inference(body) => body
                .provider()
                .map(|value| ("inference.provider", JsonValue::string(value))),
            _ => None,
        },
        SelectorId::GovernedFacet(governed::INFERENCE_REQUESTED_MODEL) => {
            match observation.body() {
                ObservationBody::Inference(body) => body
                    .requested_model()
                    .map(|value| ("inference.requested_model", JsonValue::string(value))),
                _ => None,
            }
        }
        SelectorId::GovernedFacet(governed::INFERENCE_RESOLVED_MODEL) => match observation.body() {
            ObservationBody::Inference(body) => body
                .resolved_model()
                .map(|value| ("inference.resolved_model", JsonValue::string(value))),
            _ => None,
        },
        SelectorId::GovernedFacet(governed::INFERENCE_STREAMING) => match observation.body() {
            ObservationBody::Inference(body) => body
                .streaming()
                .map(|value| ("inference.streaming", JsonValue::Bool(value))),
            _ => None,
        },
        SelectorId::GovernedFacet(governed::INFERENCE_STOP_REASON) => match observation.body() {
            ObservationBody::Inference(body) => body
                .stop_reason()
                .map(|value| ("inference.stop_reason", JsonValue::string(value))),
            _ => None,
        },
        SelectorId::GovernedFacet(governed::MCP_SERVER_ID) => match observation.body() {
            ObservationBody::Mcp(body) => body
                .server_id()
                .map(|value| ("mcp.server_id", JsonValue::string(value))),
            _ => None,
        },
        SelectorId::GovernedFacet(governed::MCP_SERVER_TRANSPORT) => match observation.body() {
            ObservationBody::Mcp(body) => body
                .transport()
                .map(|value| ("mcp.transport", JsonValue::string(value))),
            _ => None,
        },
        SelectorId::GovernedFacet(governed::MCP_SERVER_LOCATION_CLASS) => {
            match observation.body() {
                ObservationBody::Mcp(body) => body
                    .location_class()
                    .map(|value| ("mcp.location_class", JsonValue::string(value))),
                _ => None,
            }
        }
        SelectorId::GovernedFacet(governed::MCP_TOOL_NAME) => match observation.body() {
            ObservationBody::Mcp(body) => body
                .tool_name()
                .map(|value| ("mcp.tool_name", JsonValue::string(value))),
            _ => None,
        },
        SelectorId::GovernedFacet(governed::RUNTIME_EXECUTION_MODE) => match observation.body() {
            ObservationBody::Runtime(body) => body
                .execution_mode()
                .map(|value| ("runtime.execution_mode", JsonValue::string(value))),
            _ => None,
        },
        SelectorId::GovernedFacet(governed::RUNTIME_ISOLATION_STATE) => match observation.body() {
            ObservationBody::Runtime(body) => body
                .isolation_state()
                .map(|value| ("runtime.isolation_state", JsonValue::string(value))),
            _ => None,
        },
        SelectorId::GovernedFacet(governed::RUNTIME_WORKSPACE_CLASS) => match observation.body() {
            ObservationBody::Runtime(body) => body
                .workspace_class()
                .map(|value| ("runtime.workspace_class", JsonValue::string(value))),
            _ => None,
        },
        SelectorId::GovernedFacet(governed::RUNTIME_PRIVILEGE) => match observation.body() {
            ObservationBody::Runtime(body) => body
                .privilege()
                .map(|value| ("runtime.privilege", JsonValue::string(value))),
            _ => None,
        },
        SelectorId::GovernedFacet(governed::BROWSER_SURFACE) => match observation.body() {
            ObservationBody::Browser(body) => body
                .surface()
                .map(|value| ("browser.surface", JsonValue::string(value))),
            _ => None,
        },
        SelectorId::GovernedFacet(governed::BROWSER_ORIGIN_CLASS) => match observation.body() {
            ObservationBody::Browser(body) => body
                .origin_class()
                .map(|value| ("browser.origin_class", JsonValue::string(value))),
            _ => None,
        },
        SelectorId::GovernedFacet(governed::BROWSER_NAVIGATION_ID) => match observation.body() {
            ObservationBody::Browser(body) => body
                .navigation_id()
                .map(|value| ("browser.navigation_id", JsonValue::string(value))),
            _ => None,
        },
        SelectorId::GovernedFacet(governed::RESOURCE_OPERATION) => match observation.body() {
            ObservationBody::File(body) => body
                .operation()
                .map(|value| ("file.operation", JsonValue::string(value))),
            _ => None,
        },
        SelectorId::GovernedFacet(governed::RESOURCE_PATH_CLASS) => match observation.body() {
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
            partial: false,
        },
        _ => SelectorResolution {
            selector,
            presence: SelectorPresence::MetadataMissing,
            value: Some(value),
            metadata: None,
            required_capability,
            partial: false,
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
            partial: false,
        },
        Err(_) => SelectorResolution {
            selector,
            presence: SelectorPresence::MetadataMissing,
            value: None,
            metadata: None,
            required_capability,
            partial: false,
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
            partial: false,
        },
        Err(_) => SelectorResolution {
            selector,
            presence: SelectorPresence::MetadataMissing,
            value: None,
            metadata: None,
            required_capability,
            partial: false,
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

/// Borrow the direct Rule v1 output view. No payload normalization, metadata
/// cloning, or text copy is needed; canonical input is already validated.
/// Other shapes keep the ordinary resolver, including searchable precedence.
pub(crate) fn borrow_tool_result_text<'a>(
    observation: &'a CanonicalObservationV2,
    budget: &mut super::session::RetentionBudget,
) -> Result<Option<(&'a str, SelectorPresence)>, super::session::ProcessingError> {
    budget.charge(1)?;
    let ObservationBody::Tool(tool) = observation.body() else {
        return Ok(None);
    };
    if tool.searchable_result().is_some()
        || reads_omitted_searchable_text(SelectorId::CompatToolResult, observation)
    {
        return Ok(None);
    }
    let Some(JsonValue::String(text)) = tool.result() else {
        return Ok(None);
    };
    // Conservatively bound key comparisons in the small metadata map before
    // lookup. Fingerprint values are neither traversed nor cloned on this path.
    budget.charge(
        "tool.result"
            .len()
            .saturating_mul(observation.fact_metadata().len()),
    )?;
    let presence = if observation.fact_metadata().contains_key("tool.result") {
        SelectorPresence::Present
    } else {
        SelectorPresence::MetadataMissing
    };
    Ok(Some((text, presence)))
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

fn message_text(
    selector: SelectorId,
    observation: &CanonicalObservationV2,
    budget: &mut super::session::RetentionBudget,
) -> Result<SelectorResolution, super::session::ProcessingError> {
    use telltale_schema::observation::{ContentPartKind, MessageRole};
    let required_capability = selector.required_capability();
    let ObservationBody::Message(body) = observation.body() else {
        return Ok(absent(selector, required_capability));
    };
    if (selector == SelectorId::CompatAssistantContext
        && body.role() != Some(MessageRole::Assistant))
        || (selector == SelectorId::CompatUserContext && body.role() != Some(MessageRole::User))
    {
        return Ok(absent(selector, required_capability));
    }
    if let Some(JsonValue::String(text)) = body.content() {
        budget.charge(text.len())?;
        return Ok(field(
            selector,
            observation,
            "message.content",
            JsonValue::String(text.clone()),
            required_capability,
        ));
    }
    let mut len = 0usize;
    let mut count = 0;
    for part in body.content_parts() {
        budget.charge(1)?;
        if let (ContentPartKind::Text, JsonValue::String(text)) = (part.kind(), part.value()) {
            len += text.len() + usize::from(count != 0);
            count += 1;
        }
    }
    if count == 0 {
        return Ok(absent(selector, required_capability));
    }
    budget.charge(len)?;
    let mut text = String::with_capacity(len);
    let mut first = true;
    for part in body.content_parts() {
        budget.charge(1)?;
        if let (ContentPartKind::Text, JsonValue::String(value)) = (part.kind(), part.value()) {
            if !first {
                text.push('\n');
            }
            text.push_str(value);
            first = false;
        }
    }
    let metadata = observation
        .fact_metadata()
        .get("message.content_parts")
        .map(|metadata| {
            let mut derived = FactMetadata::new(FactProvenance::Derived, metadata.sensitivity())
                .expect("validated sensitivity");
            if let Some(fidelity) = metadata.fidelity_override() {
                derived = derived.with_fidelity_override(fidelity);
            }
            derived
        });
    Ok(SelectorResolution {
        selector,
        presence: if metadata.is_some() {
            SelectorPresence::Present
        } else {
            SelectorPresence::MetadataMissing
        },
        value: Some(JsonValue::String(text)),
        metadata,
        required_capability,
        partial: false,
    })
}
