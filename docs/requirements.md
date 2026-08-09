# Requirements

## Functional Requirements

- Discover local sessions for supported coding-agent sources such as Codex,
  OpenCode, Copilot, Claude Code, Gemini CLI, Qwen CLI, RooCode, KiloCode, and
  OpenClaw as adapters mature.
- Parse transcripts into ordered user, assistant, tool-call, and tool-result records.
- Detect tool calls and suspicious context with static regex rules.
- Support multiple simultaneous rule matches and cumulative scoring.
- Log informational events for notable activity such as file reads, downloads, installs, and command execution.
- Mark above-threshold detections for analyst review without making outbound model
  requests.
- Emit append-only JSONL events suitable for local review or downstream log shippers.
- Preserve enough evidence for investigation without logging raw secrets by default.

## Security Requirements

- Redact credential-like strings before logs and sink delivery.
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

## Publication Requirements

- Treat the public repository as the release and packaging boundary for the
  open-source core.
- Keep host-only planning notes, local automation state, scanner state,
  telemetry output, raw agent session stores, credentials, and
  deployment-specific SIEM settings out of public commits and release
  artifacts.
- Back public examples, validation claims, and support evidence with synthetic
  fixtures, deterministic tests, or already-redacted output.
- Review staged paths, branch, remote, generated archive listings, and checksums
  before publishing tagged release artifacts.
- Keep public install, release, and packaging guidance focused on the single
  public repository workflow used for public commits, tags, and artifacts.

## Detection Requirements

- Rule fields: id, category, severity, score, target fields, regex, explanation, tags, enabled.
- Rule targets include tool name, command, arguments, file path, URL, user context, assistant context, and tool result.
- Context modifiers can increase risk for chained behaviors: read secret + network call, download + execute, install + persistence, shell + encoded payload.
- Native Event 3.0 high-risk detections must retain deterministic response
  metadata and any applicable top-level timeline anchors without embedded triage
  verdicts. Historical Event 1.0/2.0 records remain lossless read/import inputs.
