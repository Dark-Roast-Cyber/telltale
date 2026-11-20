//! Pi's built-in tools: their kind and where their operands sit in the
//! arguments. See `tool_operation` for how a table is read.
//!
//! From `@earendil-works/pi-coding-agent` 1.5.2 `dist/core/tools`. An edit
//! carries its replacements in an `edits` array of `oldText`/`newText` pairs;
//! roles name top-level keys only, so only the single-edit form gets them.

use telltale_schema::observation::ToolKind::{FileRead, FileWrite, Shell};

use crate::tool_operation::ToolSpec;

pub(crate) const TOOLS: &[ToolSpec] = &[
    ToolSpec::new("bash", Shell)
        .commands(&["command"])
        .text(&["command"]),
    ToolSpec::new("powershell", Shell)
        .commands(&["command"])
        .text(&["command"]),
    ToolSpec::new("read", FileRead).read(&["path"]),
    // The search root is optional: a search names none to search the cwd.
    ToolSpec::new("grep", FileRead).read(&["path"]).optional(),
    ToolSpec::new("find", FileRead).read(&["path"]).optional(),
    ToolSpec::new("ls", FileRead).read(&["path"]).optional(),
    ToolSpec::new("write", FileWrite)
        .written(&["path"])
        .authored(&["content"])
        .text(&["content"]),
    ToolSpec::new("edit", FileWrite)
        .written(&["path"])
        .authored(&["newText"])
        .replaced(&["oldText"])
        .text(&["oldText", "newText"]),
];
