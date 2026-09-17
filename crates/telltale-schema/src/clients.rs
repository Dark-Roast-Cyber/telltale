#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[non_exhaustive]
pub enum ClientId {
    Codex,
    Claude,
    OpenClaw,
    Qwen,
    OpenCode,
    Copilot,
}

impl ClientId {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::Claude => "claude",
            Self::OpenClaw => "openclaw",
            Self::Qwen => "qwen",
            Self::OpenCode => "opencode",
            Self::Copilot => "copilot",
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[non_exhaustive]
pub enum SourceKind {
    Json,
    Jsonl,
    ArchivedJsonl,
    HeadlessJsonl,
    Sqlite,
    CopilotProcessLog,
}

impl SourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Jsonl => "jsonl",
            Self::ArchivedJsonl => "archived_jsonl",
            Self::HeadlessJsonl => "headless_jsonl",
            Self::Sqlite => "sqlite",
            Self::CopilotProcessLog => "copilot_process_log",
        }
    }
}
