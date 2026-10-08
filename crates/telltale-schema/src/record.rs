//! Native record kinds that source adapters count for acquisition accounting.

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum RecordKind {
    UserMessage,
    AssistantMessage,
    ToolCall,
    ToolResult,
    SessionMeta,
    Other,
}
