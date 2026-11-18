//! Copilot CLI's built-in tools: their kind and where their operands sit in
//! the arguments. See `tool_operation` for how a table is read.

use telltale_schema::observation::ToolKind::{Delegate, FileRead, FileWrite, Shell, Web};

use crate::tool_operation::ToolSpec;

/// The keys the file tools carry text under: what the call writes, and the text
/// it replaces.
const AUTHORED: &[&str] = &["file_text", "new_str"];
const REPLACED: &[&str] = &["old_str"];

pub(crate) const TOOLS: &[ToolSpec] = &[
    ToolSpec::new("bash", Shell).commands(&["command"]),
    ToolSpec::new("Bash", Shell).commands(&["command"]),
    ToolSpec::new("view", FileRead).read(&["path"]),
    ToolSpec::new("Read", FileRead).read(&["path"]),
    // Searches by pattern like `grep`, with the same arguments and an optional
    // root.
    ToolSpec::new("rg", FileRead).read(&["path"]).optional(),
    ToolSpec::new("grep", FileRead).read(&["path"]).optional(),
    ToolSpec::new("Grep", FileRead).read(&["path"]).optional(),
    ToolSpec::new("glob", FileRead).read(&["path"]).optional(),
    ToolSpec::new("create", FileWrite)
        .written(&["path"])
        .authored(AUTHORED)
        .replaced(REPLACED),
    ToolSpec::new("Write", FileWrite)
        .written(&["path"])
        .authored(AUTHORED)
        .replaced(REPLACED),
    // `Edit` takes the file keys or, from some clients, a bare patch.
    ToolSpec::new("edit", FileWrite)
        .written(&["path"])
        .authored(AUTHORED)
        .replaced(REPLACED),
    ToolSpec::new("Edit", FileWrite)
        .written(&["path"])
        .authored(AUTHORED)
        .replaced(REPLACED)
        .patch(&[]),
    // The patch is the whole argument text.
    ToolSpec::new("apply_patch", FileWrite).patch(&[]),
    ToolSpec::new("web_fetch", Web).urls(&["url"]),
    ToolSpec::new("WebFetch", Web).urls(&["url"]),
    ToolSpec::new("task", Delegate),
    ToolSpec::new("Agent", Delegate),
];
