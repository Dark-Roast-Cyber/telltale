//! Qwen Code's built-in tools: their kind and where their operands sit in the
//! arguments. See `tool_operation` for how a table is read.

use telltale_schema::observation::ToolKind::{FileRead, FileWrite, Shell};

use crate::tool_operation::ToolSpec;

pub(crate) const TOOLS: &[ToolSpec] = &[
    ToolSpec::new("run_shell_command", Shell).commands(&["command"]),
    ToolSpec::new("read_file", FileRead).read(&["absolute_path", "file_path", "path"]),
    ToolSpec::new("glob", FileRead).read(&["path"]),
    ToolSpec::new("write_file", FileWrite).written(&["file_path", "path"]),
    ToolSpec::new("replace", FileWrite).written(&["file_path", "path"]),
];
