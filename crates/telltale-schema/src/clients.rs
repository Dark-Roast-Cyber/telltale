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

            /// The source ID of this client's hook journal: `<client name>.hooks`.
            /// See [`ClientId::HOOK_JOURNAL_ADAPTER_TYPE`].
            pub const fn hook_journal_source_id(self) -> &'static str {
                match self {
                    $(Self::$variant => concat!($name, ".hooks")),+
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
    Pi => "pi",
}

impl ClientId {
    /// The adapter type of every hook journal, whichever client's hooks wrote it.
    ///
    /// A hook journal is the file a host's hooks write for Telltale to scan
    /// (the journal encoding of `telltale-core`'s hooks). The pair
    /// `(client, client.hook_journal_source_id())` is that client's hook-journal
    /// identity, for every client: host-fed, never in a source registry, so
    /// never discovered or listed. Acquisition and detection accept it for its own
    /// client only (behind their `hook-journal` features), which makes exact
    /// `(ClientId, source_id)` ownership the check; the type says only what
    /// kind of source it is.
    pub const HOOK_JOURNAL_ADAPTER_TYPE: &'static str = "hook_journal";

    /// Whether `source_id` is this client's hook-journal source ID.
    pub fn owns_hook_journal(self, source_id: &str) -> bool {
        source_id == self.hook_journal_source_id()
    }

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

    /// The rule covers every client, with no table to keep in step: the hook
    /// journal of a client is `<name>.hooks`, owned by that client alone.
    #[test]
    fn every_client_has_its_own_hook_journal_source_id() {
        for client in ClientId::ALL {
            let id = client.hook_journal_source_id();
            assert_eq!(id, format!("{}.hooks", client.as_str()));
            for other in ClientId::ALL {
                assert_eq!(other.owns_hook_journal(id), other == client, "{id}");
            }
        }
        assert!(!ClientId::Claude.owns_hook_journal("claude.hooks.x"));
        assert!(!ClientId::Claude.owns_hook_journal("Claude.hooks"));
    }
}
