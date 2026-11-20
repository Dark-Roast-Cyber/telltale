//! OpenCode's built-in tools: their kind and where their operands sit in the
//! arguments. See `tool_operation` for how a table is read.
//!
//! Stores of every format share this table. v1 file tools name their file
//! `filePath` and v2 file tools `path`; for the search tools `path` is the
//! search root.

use telltale_schema::observation::ToolKind::{Delegate, FileRead, FileWrite, Other, Shell, Web};

use crate::tool_operation::ToolSpec;

pub(crate) const TOOLS: &[ToolSpec] = &[
    ToolSpec::new("bash", Shell)
        .commands(&["command"])
        .text(&["command"]),
    // v2 records a user shell command as the bare command text.
    ToolSpec::new("shell", Shell)
        .commands(&["command"])
        .text(&["command"])
        .whole_text(),
    ToolSpec::new("read", FileRead).read(&["filePath", "path"]),
    ToolSpec::new("glob", FileRead).read(&["path"]).optional(),
    ToolSpec::new("grep", FileRead).read(&["path"]).optional(),
    ToolSpec::new("list", FileRead).read(&["path"]).optional(),
    ToolSpec::new("write", FileWrite)
        .written(&["filePath", "path"])
        .text(&["content"]),
    // The text an edit writes is authored content; the text it replaces is not.
    ToolSpec::new("edit", FileWrite)
        .written(&["filePath", "path"])
        .authored(&["newString"])
        .replaced(&["oldString"])
        .text(&["oldString", "newString"]),
    ToolSpec::new("multiedit", FileWrite)
        .written(&["filePath", "path"])
        .authored(&["newString"])
        .replaced(&["oldString"]),
    ToolSpec::new("patch", FileWrite)
        .patch(&["patchText"])
        .text(&["patchText"]),
    // A legacy store's patch text must be a string.
    ToolSpec::new("apply_patch", FileWrite)
        .patch(&["patchText"])
        .text(&["patchText"])
        .strict_text(),
    ToolSpec::new("webfetch", Web).urls(&["url"]),
    // A search carries a query, not a URL.
    ToolSpec::new("websearch", Web),
    ToolSpec::new("task", Delegate).text(&["prompt"]),
    ToolSpec::new("subagent", Delegate).text(&["prompt"]),
    // Runs a script that calls other tools; no operand is declared for it.
    ToolSpec::new("execute", Other).text(&["code"]),
    ToolSpec::new("question", Other),
    ToolSpec::new("todowrite", Other),
    ToolSpec::new("skill", Other),
    ToolSpec::new("opencode_list_mcp_resources", Other),
    ToolSpec::new("opencode_read_mcp_resource", Other),
    ToolSpec::new("opencode_session_rename", Other),
    ToolSpec::new("opencode_session_move", Other),
    ToolSpec::new("opencode_worktree_create", Other),
    ToolSpec::new("opencode_worktree_list", Other),
    ToolSpec::new("opencode_worktree_remove", Other),
    ToolSpec::new("opencode_models", Other),
];
