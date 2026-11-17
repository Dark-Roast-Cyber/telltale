//! OpenClaw's built-in tools: their kind and where their operands sit in the
//! arguments. See `tool_operation` for how a table is read.

use telltale_schema::observation::ToolKind::{FileRead, FileWrite, Shell};

use crate::tool_operation::ToolSpec;

pub(crate) const TOOLS: &[ToolSpec] = &[
    ToolSpec::new("bash", Shell).commands(&["command", "cmd"]),
    ToolSpec::new("read", FileRead).read(&["path", "file_path"]),
    ToolSpec::new("write", FileWrite).written(&["path", "file_path"]),
    ToolSpec::new("edit", FileWrite).written(&["path", "file_path"]),
];
