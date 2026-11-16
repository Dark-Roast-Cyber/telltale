//! Shared helpers: drive the runtime with authentic Claude Code payloads.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use telltale_core::hooks::claude_code;
use telltale_core::hooks::config::{Config, Mode};
use telltale_core::hooks::runtime::Runtime;

/// Test data (fixtures, marker rules) of the hooks suites. This module is
/// included by `telltale-core`'s own tests and by the CLI's binary-level tests,
/// so it finds the data from either manifest directory.
pub fn data_dir() -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let core = manifest.join("crates/telltale");
    let root = if core.is_dir() {
        core
    } else {
        manifest.to_path_buf()
    };
    root.join("tests/hooks")
}

/// A fixture directory such as `codex-cli/0.166.0`.
pub fn fixtures(relative: &str) -> PathBuf {
    data_dir().join("fixtures").join(relative)
}

/// A configuration that only says `mode = "enforce"`, for binary-level tests
/// of what a hook returns: with no configuration a hook is detect-only.
pub fn enforce_config() -> PathBuf {
    data_dir().join("enforce.toml")
}

/// Marker rules that the real-harness scripts and these tests share.
pub fn marker_rules() -> PathBuf {
    data_dir().join("e2e-marker-rules.yaml")
}

pub fn claude_fixtures() -> PathBuf {
    fixtures("claude-code/2.1.318")
}

pub fn fixture(name: &str) -> Vec<Value> {
    std::fs::read_to_string(claude_fixtures().join(name))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

/// The first captured payload of `event` (optionally for `tool`), as a template.
pub fn template(event: &str, tool: Option<&str>) -> Value {
    fixture("tool-lifecycle-subagent.jsonl")
        .into_iter()
        .find(|p| {
            p["hook_event_name"] == event
                && tool.is_none_or(|t| p["tool_name"] == t)
                && p.get("agent_id").is_none()
        })
        .unwrap_or_else(|| panic!("no captured {event} payload"))
}

pub struct Harness {
    pub dir: tempfile::TempDir,
    pub runtime: Runtime,
    pub session_id: String,
}

impl Harness {
    pub fn new() -> Self {
        Self::with(|_| {})
    }

    pub fn with(edit: impl FnOnce(&mut Config)) -> Self {
        let dir = tempfile::tempdir().unwrap();
        // The suites test what the hook returns, so they enforce; detect-only
        // (the default) is tested where it is the subject.
        let mut config = Config {
            mode: Mode::Enforce,
            state_dir: Some(dir.path().join("state")),
            telemetry_path: Some(dir.path().join("telemetry.jsonl")),
            ..Config::default()
        };
        edit(&mut config);
        Self {
            dir,
            runtime: Runtime::new(config),
            session_id: "synthetic-session-0001".into(),
        }
    }

    pub fn telemetry_path(&self) -> PathBuf {
        self.dir.path().join("telemetry.jsonl")
    }

    /// Send one native payload through the adapter exactly as the binary does.
    pub fn send(&mut self, payload: &Value) -> Option<Value> {
        let bytes = serde_json::to_vec(payload).unwrap();
        let input = claude_code::parse(&bytes).unwrap();
        let (ctx, event) = claude_code::to_event(&input).unwrap();
        let response = self.runtime.handle(&ctx, event);
        claude_code::render(&ctx.hook_event, &response)
    }

    fn tool_payload(&self, event: &str, tool: &str, id: &str, input: Value) -> Value {
        let mut payload = template(event, Some(if tool == "Bash" { "Bash" } else { "Read" }));
        payload["session_id"] = self.session_id.clone().into();
        payload["tool_name"] = tool.into();
        payload["tool_use_id"] = id.into();
        payload["tool_input"] = input;
        payload
    }

    pub fn pre(&mut self, tool: &str, id: &str, input: Value) -> Option<Value> {
        let payload = self.tool_payload("PreToolUse", tool, id, input);
        self.send(&payload)
    }

    pub fn pre_bash(&mut self, id: &str, command: &str) -> Option<Value> {
        self.pre(
            "Bash",
            id,
            json!({"command": command, "description": "test"}),
        )
    }

    pub fn post_bash(&mut self, id: &str, command: &str, stdout: &str) -> Option<Value> {
        let mut payload = self.tool_payload("PostToolUse", "Bash", id, json!({"command": command}));
        payload["tool_response"] =
            json!({"stdout": stdout, "stderr": "", "interrupted": false, "isImage": false});
        self.send(&payload)
    }

    /// PostToolBatch reporting `id` with the harness's denial text.
    pub fn batch(&mut self, id: &str, tool: &str, response: &str) -> Option<Value> {
        let mut payload = template("PostToolBatch", None);
        payload["session_id"] = self.session_id.clone().into();
        payload["tool_calls"] = json!([{"tool_name": tool, "tool_input": {}, "tool_use_id": id, "tool_response": response}]);
        self.send(&payload)
    }

    pub fn telemetry(&self) -> Vec<Value> {
        match std::fs::read_to_string(self.telemetry_path()) {
            Ok(text) => text
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    pub fn records(&self, kind: &str) -> Vec<Value> {
        self.telemetry()
            .into_iter()
            .filter(|record| record["kind"] == kind)
            .collect()
    }

    pub fn decision_for(&self, tool_use_id: &str) -> Value {
        self.records("decision")
            .into_iter()
            .find(|r| r["action"]["tool_use_id"] == tool_use_id)
            .unwrap_or_else(|| panic!("no decision for {tool_use_id}"))
    }

    pub fn outcome_for(&self, tool_use_id: &str) -> Value {
        self.records("outcome")
            .into_iter()
            .find(|r| r["action"]["tool_use_id"] == tool_use_id)
            .unwrap_or_else(|| panic!("no outcome for {tool_use_id}"))
    }
}

pub fn verdict(output: &Option<Value>) -> Option<&str> {
    output
        .as_ref()
        .and_then(|o| o["hookSpecificOutput"]["permissionDecision"].as_str())
}
