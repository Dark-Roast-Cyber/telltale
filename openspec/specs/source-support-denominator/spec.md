# source-support-denominator Specification

## Purpose

Define the authoritative built-in source-support denominator.

## Requirements

### Requirement: Built-in support contains eight exact identities

The built-in source registry and exact parser registration table MUST contain
only `claude.projects`, `codex.sessions`, `codex.archived_sessions`,
`codex.headless_sessions`, `opencode.sqlite`, `openclaw.agents`,
`qwen.projects`, and `copilot.process_log`. Every registered identity MUST have
fixture-backed discovery, parsing, and evaluation-corpus representation.

#### Scenario: Registry and parser denominator agree

- **WHEN** built-in source definitions and parser registrations are inspected
- **THEN** both sets contain the same eight exact `(ClientId, source_id)` pairs

### Requirement: Retired identities have no production machinery

`gemini.tmp`, `opencode.legacy_json`, `opencode.project_json`, `roocode.tasks`,
`kilocode.tasks`, and `codex.project_sessions` MUST NOT be registered,
discovered, parsed, canonically projected, or advertised as built-in support.

#### Scenario: Retired identity is supplied directly

- **WHEN** a caller supplies a retired source ID representable under a retained
  client
- **THEN** exact parser lookup returns `UnsupportedSourceIdentity` before reading
  the source path
