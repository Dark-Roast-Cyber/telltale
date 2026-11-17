//! OpenCode's built-in tools: their kind and where their operands sit in the
//! arguments. See `tool_operation` for how a table is read.
//!
//! Stores of every format share this table. v1 file tools name their file
//! `filePath` and v2 file tools `path`; for the search tools `path` is the
//! search root.

use telltale_schema::observation::ToolKind::{Delegate, FileRead, FileWrite, Other, Shell, Web};

use crate::tool_operation::ToolSpec;

pub(crate) const TOOLS: &[ToolSpec] = &[
    ToolSpec::new("bash", Shell).commands(&["command"]),
    // v2 records a user shell command as the bare command text.
    ToolSpec::new("shell", Shell).commands(&["command"]),
    ToolSpec::new("read", FileRead).read(&["filePath", "path"]),
    ToolSpec::new("glob", FileRead).read(&["path"]),
    ToolSpec::new("grep", FileRead).read(&["path"]),
    ToolSpec::new("list", FileRead).read(&["path"]),
    ToolSpec::new("write", FileWrite).written(&["filePath", "path"]),
    ToolSpec::new("edit", FileWrite).written(&["filePath", "path"]),
    ToolSpec::new("multiedit", FileWrite).written(&["filePath", "path"]),
    ToolSpec::new("patch", FileWrite).patch(&["patchText"]),
    ToolSpec::new("apply_patch", FileWrite).patch(&["patchText"]),
    ToolSpec::new("webfetch", Web).urls(&["url"]),
    ToolSpec::new("task", Delegate),
    ToolSpec::new("subagent", Delegate),
    // Runs a script that calls other tools; no operand is declared for it.
    ToolSpec::new("execute", Other),
];
