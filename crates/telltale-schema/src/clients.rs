//! `ClientId` and `SourceKind`. A source's identity is the exact
//! `(ClientId, source_id)` pair; `SourceKind` is container metadata and never
//! selects how a source is parsed.

/// Declares `ClientId` from one list of variants and names, so `ALL`,
/// `as_str` and `from_name` cannot drift apart. Every other list of client
/// names (output allowlists, schema enums) is built from or tested against
/// `ClientId::ALL`.
macro_rules! client_ids {
    ($($variant:ident => $name:literal),+ $(,)?) => {
        #[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Ord, PartialOrd)]
        #[non_exhaustive]
        pub enum ClientId {
            $($variant),+
        }

        impl ClientId {
            /// Every client, in declaration order.
            pub const ALL: &'static [ClientId] = &[$(Self::$variant),+];

            pub fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $name),+
                }
            }
        }
    };
}

client_ids! {
    Codex => "codex",
    Claude => "claude",
    OpenClaw => "openclaw",
    Qwen => "qwen",
    OpenCode => "opencode",
    Copilot => "copilot",
}

impl ClientId {
    /// The client named exactly `name` (case-sensitive, no aliases).
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|client| client.as_str() == name)
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

#[cfg(test)]
mod tests {
    use super::ClientId;

    #[test]
    fn every_client_name_round_trips() {
        for client in ClientId::ALL {
            assert_eq!(ClientId::from_name(client.as_str()), Some(*client));
        }
        for name in ["", "Claude", "claude-code", "gemini", " codex"] {
            assert_eq!(ClientId::from_name(name), None, "{name:?}");
        }
    }
}
