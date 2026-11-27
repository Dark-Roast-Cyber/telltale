//! Codex's built-in tools: their kind and where their operands sit in the
//! arguments. See `tool_operation` for how a table is read.

use telltale_schema::observation::{
    JsonValue,
    ToolKind::{Delegate, FileRead, FileWrite, Other, Shell, Web},
    ToolOperation,
};

use crate::tool_operation::ToolSpec;

pub(crate) const TOOLS: &[ToolSpec] = &[
    // The command is an argv array.
    ToolSpec::new("shell", Shell).commands(&["command"]),
    ToolSpec::new("shell_command", Shell).commands(&["command"]),
    ToolSpec::new("exec_command", Shell).commands(&["cmd"]),
    // A patch arrives as freeform text or under one of these keys.
    ToolSpec::new("apply_patch", FileWrite)
        .patch(&["input", "command", "patch"])
        .whole_text(),
    // The code-mode script tools run a script that calls other tools.
    ToolSpec::new("exec", Other)
        .whole_text()
        .script(script_calls),
    ToolSpec::new("multi_tool_use.parallel", Other).script(script_calls),
    // A hosted search carries the action it ran: only opening a page has a URL.
    ToolSpec::new("web_search", Web).urls(&["url"]).optional(),
    ToolSpec::new("spawn_agent", Delegate),
    ToolSpec::new("write_stdin", Other),
    ToolSpec::new("view_image", FileRead).read(&["path"]),
    ToolSpec::new("update_plan", Other),
    ToolSpec::new("request_permissions", Other),
    ToolSpec::new("request_user_input", Other),
    ToolSpec::new("request_user_input_async", Other),
    ToolSpec::new("send_message_to_user_async", Other),
    ToolSpec::new("get_context_remaining", Other),
    ToolSpec::new("new_context", Other),
    ToolSpec::new("curr_time", Other),
    ToolSpec::new("sleep", Other),
    ToolSpec::new("tool_search", Other),
    ToolSpec::new("list_available_plugins_to_install", Other),
    ToolSpec::new("request_plugin_install", Other),
    ToolSpec::new("list_mcp_resources", Other),
    ToolSpec::new("list_mcp_resource_templates", Other),
    ToolSpec::new("read_mcp_resource", Other),
    ToolSpec::new("send_input", Delegate),
    ToolSpec::new("resume_agent", Delegate),
    ToolSpec::new("wait_agent", Other),
    ToolSpec::new("close_agent", Other),
    ToolSpec::new("send_message", Delegate),
    ToolSpec::new("followup_task", Delegate),
    ToolSpec::new("interrupt_agent", Other),
    ToolSpec::new("list_agents", Other),
    ToolSpec::new("wait_for_environment", Other),
    ToolSpec::new("wait", Other),
    ToolSpec::new("imagegen", Other),
    ToolSpec::new("test_sync_tool", Other),
];

const EXEC_CALL: &str = "tools.exec_command(";
const PATCH_CALL: &str = "tools.apply_patch(";

/// The calls a code-mode script names: the literal `cmd` of each
/// `tools.exec_command({…})` and the literal patch of each
/// `tools.apply_patch("…")`. They stand in place of the script, which is
/// JavaScript and never shell input; nothing is executed or evaluated, so a
/// command or patch built at run time is not read.
///
/// A script that names no tool, or an `exec_command` call whose object never
/// closes, is left to the row, as is a script that takes more reading than
/// [`Work`] allows: its text is then read as the command, which can only add
/// matches.
fn script_calls(arguments: Option<&JsonValue>) -> Option<ToolOperation> {
    let script = script_text(arguments)?;
    if !script.contains("tools.") {
        return None;
    }
    let mut work = Work::for_script(script);
    let mut operation = ToolOperation::new(Other).with_replaces_command();
    for (offset, _) in script.match_indices(EXEC_CALL) {
        let (object, _) = script[offset + EXEC_CALL.len()..].split_once('}')?;
        work.charge(object.len())?;
        if let Some((_, value)) = object
            .split_once("cmd:")
            .or_else(|| object.split_once("\"cmd\":"))
            && let Some(command) = script_literal(value, &mut work)?
        {
            operation = operation.with_command(command);
        }
    }
    let mut written = Vec::new();
    for (offset, _) in script.match_indices(PATCH_CALL) {
        let Some(patch) = script_literal(&script[offset + PATCH_CALL.len()..], &mut work)? else {
            continue;
        };
        for line in patch.lines() {
            if let Some(path) = ["*** Add File: ", "*** Update File: ", "*** Delete File: "]
                .iter()
                .find_map(|prefix| line.strip_prefix(prefix))
            {
                operation = operation.with_written_path(path);
            } else if !line.starts_with("+++")
                && let Some(added) = line.strip_prefix('+')
            {
                written.push(added.to_owned());
            }
        }
    }
    Some(operation.with_authored_content(written.join("\n")))
}

/// The script: the argument text, or the command member of an argument object.
fn script_text(arguments: Option<&JsonValue>) -> Option<&str> {
    match arguments? {
        JsonValue::String(text) => Some(text),
        JsonValue::Object(members) => ["cmd", "command"].iter().find_map(|key| {
            members.iter().find_map(|(name, value)| match value {
                JsonValue::String(text) if name == key => Some(text.as_str()),
                _ => None,
            })
        }),
        _ => None,
    }
}

/// Reading left for one script. Calls are read from their own start, so
/// calls that never close would otherwise be read once per call.
struct Work(usize);

impl Work {
    fn for_script(script: &str) -> Self {
        Self(script.len().saturating_mul(8).saturating_add(1024))
    }

    fn charge(&mut self, bytes: usize) -> Option<()> {
        self.0 = self.0.checked_sub(bytes)?;
        Some(())
    }
}

/// A quoted literal at the start of `text`, with its escapes read. The outer
/// `None` is spent [`Work`]; the inner one is text that is no closed literal.
fn script_literal(text: &str, work: &mut Work) -> Option<Option<String>> {
    let mut chars = text.trim_start().chars();
    let Some(quote) = chars.next().filter(|c| matches!(c, '\'' | '"' | '`')) else {
        return Some(None);
    };
    let mut value = String::new();
    while let Some(c) = chars.next() {
        work.charge(c.len_utf8())?;
        if c == quote {
            return Some(Some(value));
        }
        if c == '\\' {
            let Some(next) = chars.next() else {
                return Some(None);
            };
            value.push(match next {
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                c => c,
            });
        } else {
            value.push(c);
        }
    }
    Some(None)
}

#[cfg(test)]
mod tests;
