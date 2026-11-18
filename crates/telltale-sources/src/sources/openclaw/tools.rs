//! OpenClaw's built-in tools: their kind and where their operands sit in the
//! arguments. See `tool_operation` for how a table is read.

use telltale_schema::observation::ToolKind::{FileRead, FileWrite, Shell, Web};

use crate::tool_operation::ToolSpec;

pub(crate) const TOOLS: &[ToolSpec] = &[
    ToolSpec::new("bash", Shell).commands(&["command", "cmd"]),
    ToolSpec::new("exec", Shell).commands(&["command"]),
    ToolSpec::new("read", FileRead).read(&["path", "file_path"]),
    ToolSpec::new("write", FileWrite).written(&["path", "file_path"]),
    ToolSpec::new("edit", FileWrite).written(&["path", "file_path"]),
    // The patch text is the `input` argument.
    ToolSpec::new("apply_patch", FileWrite).patch(&["input"]),
    ToolSpec::new("web_fetch", Web).urls(&["url"]),
    // A search carries a query, not a URL.
    ToolSpec::new("web_search", Web),
];
