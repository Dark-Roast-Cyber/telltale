//! Claude Code's built-in tools: their kind and where their operands sit in
//! the arguments. See `tool_operation` for how a table is read.

use telltale_schema::observation::ToolKind::{Delegate, FileRead, FileWrite, Other, Shell, Web};

use crate::tool_operation::ToolSpec;

pub(crate) const TOOLS: &[ToolSpec] = &[
    ToolSpec::new("Bash", Shell).commands(&["command"]),
    ToolSpec::new("PowerShell", Shell).commands(&["command"]),
    ToolSpec::new("Read", FileRead).read(&["file_path"]),
    ToolSpec::new("NotebookRead", FileRead).read(&["notebook_path"]),
    ToolSpec::new("Glob", FileRead).read(&["path"]),
    ToolSpec::new("Grep", FileRead).read(&["path"]),
    // Lists a directory by pattern: no file is read by name, so kind other.
    ToolSpec::new("LS", Other),
    ToolSpec::new("Write", FileWrite).written(&["file_path"]),
    ToolSpec::new("Edit", FileWrite).written(&["file_path"]),
    ToolSpec::new("MultiEdit", FileWrite).written(&["file_path"]),
    ToolSpec::new("NotebookEdit", FileWrite).written(&["notebook_path"]),
    ToolSpec::new("WebFetch", Web).urls(&["url"]),
    ToolSpec::new("WebSearch", Web),
    ToolSpec::new("Task", Delegate),
    ToolSpec::new("Agent", Delegate),
];
