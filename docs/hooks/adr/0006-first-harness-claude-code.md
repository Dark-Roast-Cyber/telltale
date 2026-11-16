# ADR 0006: Claude Code first

Status: Accepted (2026-11-04)

Claude Code has the strongest verified enforcement (PreToolUse deny in every
permission mode, `ask`, fail-closed option, managed-only hooks), subagent and
MCP identity in payloads, a schema other harnesses copy (Copilot CLI reads
Claude-style hooks), Telltale's best-validated source adapter, and it runs in
this cloud environment, so enforcement is testable for real. Order for the
next adapters, from `docs/hooks/capability-matrix.md`: Copilot CLI, Codex, OpenCode,
then Cursor, Gemini CLI, OpenClaw and Hermes.
