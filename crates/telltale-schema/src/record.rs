#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RecordKind {
    UserMessage,
    AssistantMessage,
    ToolCall,
    ToolResult,
    SessionMeta,
    Other,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct NormalizedRecord {
    pub session_id: String,
    pub client: String,
    pub agent: Option<String>,
    pub model: Option<String>,
    pub provider: Option<String>,
    pub timestamp: Option<String>,
    pub kind: RecordKind,
    pub tool_name: Option<String>,
    pub arguments: Option<String>,
    pub content: String,
}
