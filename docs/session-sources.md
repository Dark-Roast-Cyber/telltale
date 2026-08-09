# Session Sources

> **Website:** For approachable guides to session stores and agent traces, see [AgentArchaeology.ai/field-guide/session-stores](https://agentarchaeology.ai/field-guide/session-stores/) and [AgentArchaeology.ai/field-guide/agent-traces](https://agentarchaeology.ai/field-guide/agent-traces/).

Telltale source definitions live in the per-agent modules under
`crates/telltale-sources/src/sources/` and are collected by
`sources/registry.rs`, which preserves static client and install registration
order. Discovered sources are sorted separately for deterministic scans.
The private exact parser registration table lives in
`crates/telltale-sources/src/parser.rs`; this document records the current
source-of-truth host path candidates used by the scanner.

Session-store discovery answers “where can Telltale parse activity from?” It is
intentionally separate from installed-agent inventory, which answers “which
agent tools appear installed?” using metadata-only checks in
`crates/telltale-sources/src/install_inventory.rs` such as executables on `PATH`, package roots, VS
Code-style extension IDs, and globalStorage presence. Install inventory runs on
a configurable cadence and never reads transcript/session contents.

## Host Discovery Candidates

These are the host-side locations Telltale currently resolves when
`telltale scan --root .` uses host-style discovery instead of a checked-in fixture
tree. Registered `Home`, `ConfigHome`, and `DataHome` sources also resolve on
Windows through the platform-aware root helpers. Windows entries below are not
live-validated and are not by themselves public live-source support claims.

These candidates document expected product behavior and the scanner paths ADR
can resolve. They are not instructions to publish local session stores,
workstation-specific transcript paths, raw agent logs, credentials, or
deployment-specific SIEM paths. Public source-support claims should be backed
by synthetic fixtures and deterministic tests; live host validation records
should stay local-only, redacted, and summarized by client/source kind rather
than by exact private path or transcript content.

| Client | Source Kind | Linux candidate | macOS candidate | Windows candidate | Confidence | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| Codex | `codex.sessions` | `$CODEX_HOME/sessions` or `~/.codex/sessions` | `$CODEX_HOME/sessions` or `~/.codex/sessions` | `%CODEX_HOME%\sessions` or `%USERPROFILE%\.codex\sessions` | Confirmed root; Windows unvalidated | Codex CLI docs confirm `~/.codex/sessions`; ADR also supports `archived_sessions` and `headless` under the same root. |
| Codex | `codex.archived_sessions` | `$CODEX_HOME/archived_sessions` or `~/.codex/archived_sessions` | `$CODEX_HOME/archived_sessions` or `~/.codex/archived_sessions` | `%CODEX_HOME%\archived_sessions` or `%USERPROFILE%\.codex\archived_sessions` | Confirmed root; Windows unvalidated | Same root model as `codex.sessions`. |
| Codex | `codex.headless_sessions` | `$CODEX_HOME/headless` or `~/.codex/headless` | `$CODEX_HOME/headless` or `~/.codex/headless` | `%CODEX_HOME%\headless` or `%USERPROFILE%\.codex\headless` | Confirmed root; Windows unvalidated | Same root model as `codex.sessions`. |
| Claude Code | `claude.projects` | `~/.claude/projects` | `~/.claude/projects` | `%USERPROFILE%\.claude\projects` | Candidate; Windows unvalidated | Claude docs confirm `~/.claude/` as the user root; ADR resolves project JSONL sessions through the platform-aware home root. |
| Gemini CLI | `gemini.tmp` | `~/.gemini/tmp` | `~/.gemini/tmp` | `%USERPROFILE%\.gemini\tmp` | Candidate; Windows unvalidated | Gemini docs confirm `~/.gemini/` and `tmp/` usage; all Windows claims remain bounded and unvalidated. |
| Qwen CLI | `qwen.projects` | `~/.qwen/projects` | `~/.qwen/projects` | `%USERPROFILE%\.qwen\projects` | Candidate; Windows unvalidated | ADR supports this path through the platform-aware home root; upstream and live Windows validation remain incomplete. |
| OpenClaw | `openclaw.agents` | `~/.openclaw/agents` | `~/.openclaw/agents` | `%USERPROFILE%\.openclaw\agents` | Candidate; Windows unvalidated | ADR supports this path through the platform-aware home root; the upstream workspace/storage split still needs review. |
| RooCode | `roocode.tasks` | `~/.config/Code/User/globalStorage/rooveterinaryinc.roo-cline/tasks` | `~/Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/tasks` | `%APPDATA%\Code\User\globalStorage\rooveterinaryinc.roo-cline\tasks` | Confirmed root; Windows unvalidated | VS Code `globalStorage` path plus confirmed extension identifier `rooveterinaryinc.roo-cline`; not a live Windows support claim. |
| KiloCode | `kilocode.tasks` | `~/.config/Code/User/globalStorage/kilocode.kilo-code/tasks` | `~/Library/Application Support/Code/User/globalStorage/kilocode.kilo-code/tasks` | `%APPDATA%\Code\User\globalStorage\kilocode.kilo-code\tasks` | Confirmed root; Windows unvalidated | VS Code `globalStorage` path plus confirmed extension identifier `kilocode.kilo-code`; not a live Windows support claim. |
| OpenCode | `opencode.sqlite` | `$XDG_DATA_HOME/opencode/opencode.db` or `~/.local/share/opencode/opencode.db` | `~/Library/Application Support/opencode/opencode.db` | `%LOCALAPPDATA%\opencode\opencode.db` or `%APPDATA%\opencode\opencode.db` | Confirmed Linux/macOS; Windows unvalidated | ADR resolves Linux through `XDG_DATA_HOME`, macOS through the platform data root, and Windows through the platform data root. Native Windows live validation is incomplete. |
| OpenCode | `opencode.legacy_json` | `$XDG_DATA_HOME/opencode/storage/message` or `~/.local/share/opencode/storage/message` | `~/Library/Application Support/opencode/storage/message` | `%LOCALAPPDATA%\opencode\storage\message` or `%APPDATA%\opencode\storage\message` | Confirmed Linux/macOS; Windows unvalidated | Same root model as `opencode.sqlite`; Windows project/global storage paths are not live-validated. |
| Codex | `codex.project_sessions` | project-local `.codex-worktree` | project-local `.codex-worktree` | project-local `.codex-worktree` | Candidate | Per-project Codex CLI logs; discovered below configured project roots or applicable default project roots. |
| OpenCode | `opencode.project_json` | project-local `.opencode` | project-local `.opencode` | project-local `.opencode` | Candidate | Per-project OpenCode JSON messages; discovered below configured project roots or applicable default project roots. |
| Copilot | `copilot.process_log` | project-local `logs/copilot` | project-local `logs/copilot` | project-local `logs/copilot` | Telltale-local operational model | **Project-local only** — discovered below configured project roots or applicable default project roots. No home-relative source root. |

## Project Roots

Telltale can scan session stores inside project directories in addition to home-relative discovery. By default, Telltale scans `~/github` and `~/projects` if they exist. To customize, operators can declare project roots in a YAML config file:

```yaml
projects:
  - name: my-project
    path: ~/github/my-project
```

Pass the config to scans:

```sh
telltale scan --once --root "$HOME" --project-config projects.yaml
```

Project-local discovery is additive: home-relative sources are still discovered from `--root`. The source definition in `crates/telltale-sources/src/sources/<agent>/mod.rs`, collected by `sources/registry.rs`, defines the per-client subpath for each project (for example, `logs/copilot` for Copilot, `.opencode` for OpenCode, and `.codex-worktree` for Codex). If a project has a non-standard subpath, rename the directory to match the registry subpath rather than overriding per-project paths in the YAML.

The `TELLTALE_PROJECT_CONFIG` environment variable accepts a platform-native path
list when no `--project-config` flag is given. When neither is provided,
Telltale uses the default paths (`~/github` and `~/projects`). Repeat
`--project-config` when that is clearer or when scripts should avoid path-list
escaping rules.

## Fixture Behavior

- When `telltale scan --root` points at a checked-in fixture tree such as `tests/fixtures/session_stores`, Telltale does not use host-path resolution.
- Fixture discovery still uses each source's `fixture_relative_path` directly.
- Platform-aware host-path resolution does not change fixture layout or fixture-path expectations.
- Public verification should prefer checked-in synthetic fixtures and commands that do not touch real agent stores, such as a dry-run fixture scan or focused parser/discovery tests.

## Host Root Rules

- `Home` sources resolve from `HOME` on Linux/macOS and `HOME` or `USERPROFILE` on Windows.
- `CodexHome` resolves from `CODEX_HOME` when set, otherwise `~/.codex`.
- `ConfigHome` resolves to `XDG_CONFIG_HOME` or `~/.config` on Linux, `~/Library/Application Support` on macOS, and `APPDATA` or `%USERPROFILE%\AppData\Roaming` on Windows.
- `DataHome` resolves to `XDG_DATA_HOME` or `~/.local/share` on Linux, `~/Library/Application Support` on macOS, and `LOCALAPPDATA`, then `APPDATA`, then `%USERPROFILE%\AppData\Local` on Windows.

## Linux Operational Notes

Linux-specific live validation should use bounded, redacted excerpts and
fixture-equivalent scans whenever possible. Host-specific shipper setup should
be reviewed before publication or reuse in another environment.

## Parser Notes

Codex parser notes:

- JSONL entries include `session_meta`, `turn_context`, and event payloads.
- `session_meta.payload.source == "exec"` marks headless sessions.
- `session_meta.payload.model_provider` and `agent_nickname` can identify provider and agent.

OpenCode parser notes:

- Newer data lives in `opencode.db`, table `message`, with JSON in `data`.
- SQLite sources open with a 5-second `busy_timeout` so scans fail fast when OpenCode holds a write lock, surfacing a `Locked` parse error instead of hanging indefinitely.
- Per-source parse operations are sequential; a single slow or contended source blocks the current scan (known limitation).
- OpenCode per-message model attribution reflects the model that generated each message, which may differ from the session's primary model when sub-agents are used.
- Live OpenCode SQLite stores also carry a top-level `message.session_id` column even when the JSON payload does not.
- Legacy JSON messages include `role`, `sessionID`, `modelID`, `providerID`, `tokens`, `time`, `agent`, and `mode`.
- Telltale needs all roles and tool records, not only assistant token-usage rows.

Claude Code parser notes:

- JSONL entries commonly use top-level `type` values such as `user` and `assistant`.
- Message payloads can live under `message.role`, `message.model`, and `message.content`.
- `message.content` arrays may include `text`, `tool_use`, and `tool_result` blocks; ADR normalizes `tool_use` blocks as tool calls and `tool_result` blocks as tool results.

Gemini parser notes:

- JSON files under `.gemini/tmp` may contain a top-level `sessionId`, `model`, timestamps, and a `messages` array.
- Telltale normalizes `type: user` as user messages and `type: gemini` or `type: model` as assistant messages.
- Current fixture-backed support covers benign text content plus synthetic tool-call and tool-result records.
- A missing `messages` member remains the established `Empty` result for the
  valid empty-session fixture; malformed or structurally invalid message data
  is a terminal parser error.

Qwen parser notes:

- JSONL files under `.qwen/projects/**/chats` may contain `type`, `model`, `timestamp`, `sessionId`, and `usageMetadata` fields.
- `qwen.projects` uses a source-owned modeled JSONL parser with metadata
  inheritance, tool-call/result classification, and terminal schema/unknown
  boundaries. It is not a generic JSONL fallback.

RooCode parser notes:

- `ui_messages.json` files can appear under task directories below the VS Code extension storage root.
- `roocode.tasks` is a deliberate exact generic JSON-document fallback. Its
  verified UI-message object/array shape is covered by positive, tool, malformed,
  and explicit-unknown tests; it is not an implicit `SourceKind` selection.

KiloCode parser notes:

- `ui_messages.json` files can appear under task directories below the VS Code extension storage root.
- `kilocode.tasks` is a deliberate exact generic JSON-document fallback with the
  same verified UI-message shape and focused failure/unknown coverage as RooCode.
