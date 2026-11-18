//! Claude Code's built-in tools: their kind and where their operands sit in
//! the arguments. See `tool_operation` for how a table is read.

use telltale_schema::observation::ToolKind::{Delegate, FileRead, FileWrite, Other, Shell, Web};

use crate::tool_operation::ToolSpec;

pub(crate) const TOOLS: &[ToolSpec] = &[
    ToolSpec::new("Bash", Shell).commands(&["command"]),
    ToolSpec::new("PowerShell", Shell).commands(&["command"]),
    ToolSpec::new("Read", FileRead).read(&["file_path"]),
    ToolSpec::new("NotebookRead", FileRead).read(&["notebook_path"]),
    // The search root is optional: a search names none to search the working
    // directory.
    ToolSpec::new("Glob", FileRead).read(&["path"]).optional(),
    ToolSpec::new("Grep", FileRead).read(&["path"]).optional(),
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
    ToolSpec::new("SendMessage", Delegate),
    ToolSpec::new("Workflow", Delegate),
    ToolSpec::new("Artifact", Other),
    ToolSpec::new("AskUserQuestion", Other),
    ToolSpec::new("CronCreate", Other),
    ToolSpec::new("CronDelete", Other),
    ToolSpec::new("CronList", Other),
    ToolSpec::new("EndConversation", Other),
    ToolSpec::new("EnterPlanMode", Other),
    ToolSpec::new("EnterWorktree", Other),
    ToolSpec::new("ExitPlanMode", Other),
    ToolSpec::new("ExitWorktree", Other),
    ToolSpec::new("ListAgents", Other),
    ToolSpec::new("ListMcpResourcesTool", Other),
    ToolSpec::new("LSP", Other),
    ToolSpec::new("Monitor", Other),
    ToolSpec::new("PushNotification", Other),
    ToolSpec::new("ReadMcpResourceTool", Other),
    ToolSpec::new("RemoteTrigger", Other),
    ToolSpec::new("ReportFindings", Other),
    ToolSpec::new("ScheduleWakeup", Other),
    ToolSpec::new("SendFeedback", Other),
    ToolSpec::new("SendUserFile", Other),
    ToolSpec::new("ShareOnboardingGuide", Other),
    ToolSpec::new("Skill", Other),
    ToolSpec::new("SubagentHandback", Other),
    ToolSpec::new("TaskCreate", Other),
    ToolSpec::new("TaskGet", Other),
    ToolSpec::new("TaskList", Other),
    ToolSpec::new("TaskStop", Other),
    ToolSpec::new("TaskUpdate", Other),
    ToolSpec::new("TodoWrite", Other),
    ToolSpec::new("ToolSearch", Other),
    ToolSpec::new("WaitForMcpServers", Other),
    // Earlier release: removed in v2.1.277.
    ToolSpec::new("TaskOutput", Other),
];
