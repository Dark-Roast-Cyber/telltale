//! Codex's built-in tools: their kind and where their operands sit in the
//! arguments. See `tool_operation` for how a table is read.

use telltale_schema::observation::ToolKind::{Delegate, FileRead, FileWrite, Other, Shell, Web};

use crate::tool_operation::ToolSpec;

pub(crate) const TOOLS: &[ToolSpec] = &[
    // The command is an argv array.
    ToolSpec::new("shell", Shell).commands(&["command"]),
    ToolSpec::new("shell_command", Shell).commands(&["command"]),
    ToolSpec::new("exec_command", Shell).commands(&["cmd"]),
    // A patch arrives as freeform text or under one of these keys.
    ToolSpec::new("apply_patch", FileWrite).patch(&["input", "command", "patch"]),
    // The code-mode script tools run a script that calls other tools. They
    // are kind other until their script reading moves into this module.
    ToolSpec::new("exec", Other),
    ToolSpec::new("multi_tool_use.parallel", Other),
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
