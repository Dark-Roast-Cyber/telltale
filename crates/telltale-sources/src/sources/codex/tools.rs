//! Codex's built-in tools: their kind and where their operands sit in the
//! arguments. See `tool_operation` for how a table is read.

use telltale_schema::observation::ToolKind::{Delegate, FileWrite, Other, Shell, Web};

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
    ToolSpec::new("web_search", Web).urls(&["url"]),
    ToolSpec::new("spawn_agent", Delegate),
];
