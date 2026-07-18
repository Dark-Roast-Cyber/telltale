#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum ClientId {
    Codex,
    Claude,
    Gemini,
    OpenClaw,
    Qwen,
    RooCode,
    KiloCode,
    OpenCode,
    Copilot,
}

impl ClientId {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::Claude => "claude",
            Self::Gemini => "gemini",
            Self::OpenClaw => "openclaw",
            Self::Qwen => "qwen",
            Self::RooCode => "roocode",
            Self::KiloCode => "kilocode",
            Self::OpenCode => "opencode",
            Self::Copilot => "copilot",
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum SourceKind {
    Json,
    Jsonl,
    ArchivedJsonl,
    HeadlessJsonl,
    Sqlite,
    LegacyJson,
    UiMessagesJson,
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
            Self::LegacyJson => "legacy_json",
            Self::UiMessagesJson => "ui_messages_json",
            Self::CopilotProcessLog => "copilot_process_log",
        }
    }
}
