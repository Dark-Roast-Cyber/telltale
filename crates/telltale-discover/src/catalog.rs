//! Pinned Tokscale core registry, not the Telltale detection source registry.
//!
//! Root and scanner hints are provisional upstream candidates, not complete
//! installation specifications. No frontend assets or frontend data are used.
//! See `data/TOKSCALE-PROVENANCE.md` for attribution and the completeness fixture.

/// Exact upstream revision used for the catalog and candidate hints.
pub const TOKSCALE_REVISION: &str = "6ff87bdd4eb1e9e3d26a51b0b788d4ccaa154a5e";

/// Meaning of an upstream root. Environment overrides are documentation only;
/// the collector never reads or expands environment variables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogRoot {
    Home,
    Data,
    TokscaleConfig,
    AppData,
    ReasonixHome,
    EnvironmentFallback {
        variable: &'static str,
        home_relative: &'static str,
    },
}

/// Metadata can establish an artifact's existence, not installation or use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    NativeData,
    LegacyNativeData,
    SharedNativeData,
    TokscaleCache,
    TokscaleCapture,
    SyncedUsageMirror,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CandidateType {
    Directory,
    File,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CandidatePlatform {
    Any,
    Linux,
    MacOs,
    Unix,
}

/// Catalog membership carries no detection, installation, or usage capability.
/// Literal hints are public API metadata, not serialized observation paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CatalogEntry {
    pub id: &'static str,
    pub display_name: &'static str,
    pub upstream_root: CatalogRoot,
    pub upstream_relative_path: &'static str,
    /// May be a symbolic scanner name rather than a glob. Never evaluated here.
    pub upstream_pattern: &'static str,
    pub artifact_kind: ArtifactKind,
    pub(crate) candidate_type: CandidateType,
    pub(crate) platform: CandidatePlatform,
}

use ArtifactKind::*;
use CandidatePlatform::{Any, Linux, MacOs, Unix};
use CandidateType::{Directory, File};
use CatalogRoot::{AppData, Data, EnvironmentFallback as Env, Home, ReasonixHome, TokscaleConfig};

macro_rules! entries {
    ($(($id:literal, $name:literal, $root:expr, $path:literal, $pattern:literal, $kind:ident, $ty:ident, $platform:ident)),+ $(,)?) => {
        static CATALOG: &[CatalogEntry] = &[$(CatalogEntry {
            id: $id, display_name: $name, upstream_root: $root,
            upstream_relative_path: $path, upstream_pattern: $pattern,
            artifact_kind: $kind, candidate_type: $ty, platform: $platform,
        }),+];
    };
}

entries!(
    (
        "opencode",
        "OpenCode",
        Data,
        "opencode/storage/message",
        "*.json",
        LegacyNativeData,
        Directory,
        Any
    ),
    (
        "claude",
        "Claude Code",
        Env {
            variable: "CLAUDE_CONFIG_DIR",
            home_relative: ".claude"
        },
        "projects",
        "*.jsonl",
        NativeData,
        Directory,
        Any
    ),
    (
        "codex",
        "Codex CLI",
        Env {
            variable: "CODEX_HOME",
            home_relative: ".codex"
        },
        "sessions",
        "*.jsonl*",
        NativeData,
        Directory,
        Any
    ),
    (
        "cursor",
        "Cursor IDE",
        Env {
            variable: "TOKSCALE_CONFIG_DIR",
            home_relative: ".config/tokscale"
        },
        "cursor-cache",
        "usage*.json|usage*.csv",
        TokscaleCache,
        Directory,
        Any
    ),
    (
        "gemini",
        "Gemini CLI",
        Env {
            variable: "GEMINI_CLI_HOME",
            home_relative: ".gemini"
        },
        "tmp",
        "*.json|*.jsonl",
        NativeData,
        Directory,
        Any
    ),
    (
        "amp",
        "Amp",
        TokscaleConfig,
        "amp-cache/threads",
        "T-*.json",
        TokscaleCache,
        Directory,
        Any
    ),
    (
        "droid",
        "Droid",
        Home,
        ".factory/sessions",
        "*.settings.json",
        NativeData,
        Directory,
        Any
    ),
    (
        "openclaw",
        "OpenClaw",
        Home,
        ".openclaw/agents",
        "*.jsonl*",
        NativeData,
        Directory,
        Any
    ),
    (
        "pi",
        "Pi",
        Home,
        ".pi/agent/sessions",
        "*.jsonl",
        NativeData,
        Directory,
        Any
    ),
    (
        "kimi",
        "Kimi CLI",
        Home,
        ".kimi/sessions",
        "wire.jsonl",
        LegacyNativeData,
        Directory,
        Any
    ),
    (
        "qwen",
        "Qwen CLI",
        Home,
        ".qwen/projects",
        "*.jsonl",
        NativeData,
        Directory,
        Any
    ),
    (
        "roocode",
        "Roo Code",
        Home,
        ".config/Code/User/globalStorage/rooveterinaryinc.roo-cline/tasks",
        "ui_messages.json",
        NativeData,
        Directory,
        Linux
    ),
    (
        "kilocode",
        "Kilo Code",
        Home,
        ".config/Code/User/globalStorage/kilocode.kilo-code/tasks",
        "ui_messages.json",
        NativeData,
        Directory,
        Linux
    ),
    (
        "mux",
        "Mux",
        Home,
        ".mux/sessions",
        "session-usage.json",
        NativeData,
        Directory,
        Any
    ),
    (
        "kilo",
        "Kilo CLI",
        Data,
        "kilo/kilo.db",
        "kilo.db",
        NativeData,
        File,
        Any
    ),
    (
        "crush",
        "Crush",
        Data,
        "crush/projects.json",
        "projects.json",
        NativeData,
        File,
        Any
    ),
    (
        "hermes",
        "Hermes Agent",
        Env {
            variable: "HERMES_HOME",
            home_relative: ".hermes"
        },
        "state.db",
        "state.db",
        NativeData,
        File,
        Any
    ),
    (
        "copilot",
        "Copilot CLI",
        Home,
        ".copilot/otel",
        "*.jsonl",
        NativeData,
        Directory,
        Any
    ),
    (
        "goose",
        "Goose",
        Data,
        "goose/sessions/sessions.db",
        "sessions.db",
        NativeData,
        File,
        Any
    ),
    (
        "codebuff",
        "Codebuff",
        Env {
            variable: "CODEBUFF_DATA_DIR",
            home_relative: ".config/manicode"
        },
        "projects",
        "chat-messages.json",
        SharedNativeData,
        Directory,
        Any
    ),
    (
        "antigravity",
        "Antigravity",
        TokscaleConfig,
        "antigravity-cache/sessions",
        "*.jsonl",
        TokscaleCache,
        Directory,
        Any
    ),
    (
        "zed",
        "Zed Agent",
        Data,
        "zed/threads/threads.db",
        "threads.db",
        NativeData,
        File,
        Any
    ),
    (
        "kiro",
        "Kiro",
        Home,
        ".kiro/sessions/cli",
        "*.json",
        NativeData,
        Directory,
        Any
    ),
    (
        "trae",
        "Trae",
        TokscaleConfig,
        "trae-cache/sessions",
        "*.json",
        TokscaleCache,
        Directory,
        Any
    ),
    (
        "warp",
        "Warp",
        TokscaleConfig,
        "warp-cache",
        "usage*.json",
        TokscaleCache,
        Directory,
        Any
    ),
    (
        "cline",
        "Cline",
        Home,
        ".config/Code/User/globalStorage/saoudrizwan.claude-dev/tasks",
        "ui_messages.json",
        NativeData,
        Directory,
        Linux
    ),
    (
        "gjc",
        "Gajae-Code",
        Env {
            variable: "GJC_CODING_AGENT_DIR",
            home_relative: ".gjc/agent"
        },
        "sessions",
        "*.jsonl",
        NativeData,
        Directory,
        Any
    ),
    (
        "grok",
        "Grok Build",
        Env {
            variable: "GROK_HOME",
            home_relative: ".grok"
        },
        "sessions",
        "updates.jsonl",
        NativeData,
        Directory,
        Any
    ),
    (
        "jcode",
        "Jcode",
        Env {
            variable: "JCODE_HOME",
            home_relative: ".jcode"
        },
        "sessions",
        "session_*.json",
        NativeData,
        Directory,
        Any
    ),
    (
        "commandcode",
        "Command Code",
        Home,
        ".commandcode/projects",
        "*.jsonl",
        NativeData,
        Directory,
        Any
    ),
    (
        "micode",
        "MiMo Code",
        Data,
        "mimocode",
        "*.db",
        SharedNativeData,
        Directory,
        Any
    ),
    (
        "antigravity-cli",
        "Antigravity CLI",
        Env {
            variable: "GEMINI_CLI_HOME",
            home_relative: ".gemini"
        },
        "antigravity-cli/conversations",
        "*.db",
        NativeData,
        Directory,
        Any
    ),
    (
        "junie",
        "Junie",
        Home,
        ".junie/sessions",
        "events.jsonl",
        NativeData,
        Directory,
        Any
    ),
    (
        "zcode",
        "ZCode",
        Home,
        ".zcode/projects",
        "*.jsonl",
        NativeData,
        Directory,
        Any
    ),
    (
        "opencodereview",
        "OpenCodeReview",
        Home,
        ".opencodereview/sessions",
        "*.jsonl",
        NativeData,
        Directory,
        Any
    ),
    (
        "codebuddy",
        "CodeBuddy",
        Home,
        ".codebuddy/projects",
        "*.jsonl",
        NativeData,
        Directory,
        Any
    ),
    (
        "workbuddy",
        "WorkBuddy",
        Home,
        ".workbuddy",
        "workbuddy.db",
        LegacyNativeData,
        Directory,
        Any
    ),
    (
        "devin-cli",
        "Devin CLI",
        Data,
        "devin/cli/sessions.db",
        "sessions.db",
        NativeData,
        File,
        Any
    ),
    (
        "devin-desktop",
        "Devin Desktop",
        Home,
        "Library/Application Support/Devin/User/acp-events",
        "*.ndjson",
        NativeData,
        Directory,
        MacOs
    ),
    (
        "senpi",
        "Senpi (OmO Native)",
        Env {
            variable: "SENPI_CODING_AGENT_DIR",
            home_relative: ".senpi/agent"
        },
        "sessions",
        "*.jsonl",
        LegacyNativeData,
        Directory,
        Any
    ),
    (
        "augment",
        "Augment Code",
        Home,
        ".augment/sessions",
        "*.json",
        NativeData,
        Directory,
        Any
    ),
    (
        "kimchi",
        "Kimchi",
        Env {
            variable: "KIMCHI_CODING_AGENT_DIR",
            home_relative: ".config/kimchi/harness"
        },
        "sessions",
        "*.jsonl",
        NativeData,
        Directory,
        Any
    ),
    (
        "reasonix",
        "Reasonix",
        ReasonixHome,
        "stats",
        "*.jsonl",
        NativeData,
        Directory,
        Any
    ),
    (
        "prime-agent",
        "Prime Agent",
        Env {
            variable: "PRIME_AGENT_CODING_AGENT_DIR",
            home_relative: ".prime/agent"
        },
        "sessions",
        "*.jsonl",
        NativeData,
        Directory,
        Any
    ),
    (
        "freebuff",
        "Freebuff",
        Env {
            variable: "FREEBUFF_DATA_DIR",
            home_relative: ".config/manicode"
        },
        "projects",
        "chat-messages.json",
        SharedNativeData,
        Directory,
        Any
    ),
    (
        "cherrystudio",
        "Cherry Studio",
        AppData,
        "CherryStudio/.claude/projects",
        "*.jsonl",
        LegacyNativeData,
        Directory,
        Any
    ),
    (
        "dsh",
        "DeepSeek Harness",
        Env {
            variable: "DSH_HOME",
            home_relative: ".dsh"
        },
        "sessions",
        "dsh-session-log",
        NativeData,
        Directory,
        Any
    ),
    (
        "mcode",
        "MiniMax Code",
        TokscaleConfig,
        "headless/mcode",
        "*.jsonl",
        TokscaleCapture,
        Directory,
        Any
    ),
    (
        "fx",
        "Fx",
        Home,
        ".fx/sessions",
        "usage-v2.json",
        NativeData,
        Directory,
        Unix
    ),
    (
        "omp",
        "Oh My Pi",
        Home,
        ".omp/agent/sessions",
        "*.jsonl",
        NativeData,
        Directory,
        Any
    ),
    (
        "lmstudio",
        "LM Studio",
        Env {
            variable: "LM_STUDIO_HOME",
            home_relative: ".lmstudio"
        },
        "server-logs",
        "*.log",
        NativeData,
        Directory,
        Any
    ),
    (
        "unsloth",
        "Unsloth",
        Env {
            variable: "UNSLOTH_STUDIO_HOME",
            home_relative: ".unsloth/studio"
        },
        "studio.db",
        "studio.db",
        NativeData,
        File,
        Any
    ),
    (
        "hindsight",
        "Hindsight",
        Env {
            variable: "HINDSIGHT_HOME",
            home_relative: ".hindsight"
        },
        "usage",
        "*.jsonl",
        SyncedUsageMirror,
        Directory,
        Any
    ),
    (
        "micode-desktop",
        "Xiaomi MiMo AI",
        Data,
        "mimocode",
        "*.db",
        SharedNativeData,
        Directory,
        Any
    ),
    (
        "muse",
        "Muse Code",
        Data,
        "muse/sessions",
        "session.jsonl",
        NativeData,
        Directory,
        Any
    ),
    (
        "antigravity-extension",
        "Antigravity IDE Extension",
        Home,
        ".gemini/antigravity/conversations",
        "*.db",
        NativeData,
        Directory,
        Any
    ),
    (
        "aside",
        "Aside",
        Home,
        ".aside/u",
        "messages.jsonl",
        NativeData,
        Directory,
        Any
    ),
    (
        "vibe",
        "Mistral Vibe",
        Env {
            variable: "VIBE_HOME",
            home_relative: ".vibe"
        },
        "logs/session",
        "vibe-session",
        NativeData,
        Directory,
        Any
    ),
    (
        "proma",
        "Proma",
        Home,
        ".proma",
        "proma-session",
        NativeData,
        Directory,
        Any
    ),
    (
        "bb",
        "BB",
        Env {
            variable: "BB_DATA_DIR",
            home_relative: ".bb"
        },
        "bb.db",
        "bb.db",
        NativeData,
        File,
        Any
    ),
    (
        "qoder",
        "Qoder",
        Env {
            variable: "QODER_CONFIG_DIR",
            home_relative: ".qoder"
        },
        "projects",
        "*.jsonl",
        NativeData,
        Directory,
        Any
    ),
);

/// All 61 entries in upstream registry order. Never consults the environment.
pub fn catalog() -> &'static [CatalogEntry] {
    CATALOG
}
