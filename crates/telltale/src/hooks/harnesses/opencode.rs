//! OpenCode v2 request-only pilot. The plugin supplies a random occurrence ID
//! for each callback, not a hash of the input or the reused Code Mode ID.
//! No terminal notifications are accepted: captured inner calls have no
//! independently identifiable terminal event. Pending outcomes remain unknown.
//! Calls are evaluated as OpenCode sent them, through the OpenCode tool table
//! of `telltale-sources` (`Adapter::client`). Captured native shapes:
//! tests/hooks/fixtures/opencode/2.2.5.

use crate::ClientId;
use crate::hooks::harness::{Adapter, HostRules, Install, NamelessBlock, Parsed};
use crate::hooks::runtime::{Context, Event, Response, ToolCall};
use crate::hooks::state::Verdict;
use serde::Deserialize;
use serde_json::{Value, json};

/// The `Context::harness` name of this adapter.
pub const NAME: &str = "opencode";

pub const ADAPTER: Adapter = Adapter {
    name: NAME,
    display_name: "OpenCode v2 (request-only pilot)",
    client: ClientId::OpenCode,
    pre_tool_use: &["execute.before"],
    event_keys: &["hook_event"],
    can_ask: false,
    can_grant: false,
    parse,
    render,
    looks_like_pre_tool_use: |bytes| {
        super::payload::names_event_as(bytes, "hook_event", "execute.before")
    },
    install: Install {
        usage: "  telltale hooks opencode settings                 print pilot plugin configuration notes",
        output: |_, _| {
            Err(
                "OpenCode v2 pilot uses an explicit plugin factory, not a shell command. See docs/hooks/harnesses/opencode.md; unmanaged startup cannot fail closed.",
            )
        },
    },
    nameless_block: NamelessBlock::Exit(1),
    home: None,
    rules: HostRules::Shared,
    launchers: &["opencode"],
    packages: &[],
    harness_protections: &[
        "the pilot plugin denies a tool call when the hook is unavailable, only where its own options say mode: enforce and leave onError at deny",
    ],
};

#[derive(Deserialize)]
struct Request {
    protocol: String,
    hook_event: String,
    occurrence: String,
    cwd: String,
    event: Native,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Native {
    #[serde(rename = "sessionID")]
    session_id: String,
    #[serde(rename = "messageID")]
    message_id: String,
    id: String,
    agent: String,
    tool: String,
    input: Value,
}

pub fn parse(bytes: &[u8]) -> Parsed {
    let Ok(request) = serde_json::from_slice::<Request>(bytes) else {
        return Parsed::Invalid("payload_invalid_json");
    };
    if request.protocol != "telltale.opencode-v2.v1" || request.hook_event != "execute.before" {
        return Parsed::Invalid("payload_invalid_protocol");
    }
    let native = request.event;
    if request.occurrence.is_empty()
        || native.session_id.is_empty()
        || native.id.is_empty()
        || native.message_id.is_empty()
        || native.tool.trim().is_empty()
    {
        return Parsed::Unusable {
            hook_event: request.hook_event,
            code: "payload_missing_field",
        };
    }
    Parsed::Event(
        Context {
            harness: NAME,
            hook_event: request.hook_event,
            session_id: native.session_id,
            agent_id: None,
            agent_type: Some(native.agent),
            prompt_id: None,
            permission_mode: None,
            cwd: Some(request.cwd),
            can_ask: false,
            can_grant: false,
        },
        Event::ToolRequested(ToolCall {
            tool_use_id: Some(request.occurrence),
            tool_name: native.tool,
            input: native.input,
        }),
    )
}

fn render(event: &str, response: &Response) -> Option<Value> {
    if event == "execute.before"
        && let Response::Decision(decision) = response
        && decision.verdict() == Verdict::Deny
    {
        Some(json!({"decision": "deny", "reason": decision.reason()}))
    } else {
        None
    }
}
