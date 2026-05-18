# Requirements

## Functional Requirements

- Discover local sessions for Codex, OpenCode, and later Copilot/other agents.
- Parse transcripts into ordered user, assistant, tool-call, and tool-result records.
- Detect tool calls and suspicious context with static regex rules.
- Support multiple simultaneous rule matches and cumulative scoring.
- Log informational events for notable activity such as file reads, downloads, installs, and command execution.
- Trigger Llama Guard and triage-model review when risk exceeds thresholds.
- Emit append-only JSONL events suitable for Universal Forwarder or Filebeat.
- Preserve enough evidence for investigation without logging raw secrets by default.

## Security Requirements

- Redact credential-like strings before logs or LLM calls.
- Hash raw evidence when exact values are not needed.
- Avoid scanning outside configured session locations unless explicitly configured.
- Keep `.env`, state, and logs out of version control.
- Provide allowlists/suppressions for expected local workflows.

## Operational Requirements

- Run as `scan --once` and as a periodic background process.
- Maintain scan state to avoid duplicate alerts.
- Continue processing if one parser or source fails.
- Include source file/db path metadata but avoid raw absolute paths when privacy mode is enabled.
- Use configurable thresholds for informational, low, medium, high, and critical severity.

## Detection Requirements

- Rule fields: id, category, severity, score, target fields, regex, explanation, tags, enabled.
- Rule targets include tool name, command, arguments, file path, URL, user context, assistant context, and tool result.
- Context modifiers can increase risk for chained behaviors: read secret + network call, download + execute, install + persistence, shell + encoded payload.
- Triage output must include verdict, confidence, reason, and recommended severity.
