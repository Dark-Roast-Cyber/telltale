//! Copilot CLI's built-in tools: their kind and where their operands sit in
//! the arguments. See `tool_operation` for how a table is read.

use telltale_schema::observation::ToolKind::{Delegate, FileRead, FileWrite, Other, Shell, Web};

use crate::tool_operation::ToolSpec;

pub(crate) const TOOLS: &[ToolSpec] = &[
    ToolSpec::new("bash", Shell).commands(&["command"]),
    ToolSpec::new("Bash", Shell).commands(&["command"]),
    ToolSpec::new("view", FileRead).read(&["path"]),
    ToolSpec::new("Read", FileRead).read(&["path"]),
    // Searches by pattern: no file is read by name, so kind other.
    ToolSpec::new("rg", Other),
    ToolSpec::new("grep", FileRead).read(&["path"]),
    ToolSpec::new("Grep", FileRead).read(&["path"]),
    ToolSpec::new("glob", FileRead).read(&["path"]),
    ToolSpec::new("create", FileWrite).written(&["path"]),
    ToolSpec::new("Write", FileWrite).written(&["path"]),
    // `Edit` takes the file keys or, from some clients, a bare patch.
    ToolSpec::new("edit", FileWrite).written(&["path"]),
    ToolSpec::new("Edit", FileWrite)
        .written(&["path"])
        .patch(&[]),
    // The patch is the whole argument text.
    ToolSpec::new("apply_patch", FileWrite).patch(&[]),
    ToolSpec::new("web_fetch", Web).urls(&["url"]),
    ToolSpec::new("WebFetch", Web).urls(&["url"]),
    ToolSpec::new("task", Delegate),
    ToolSpec::new("Agent", Delegate),
];
