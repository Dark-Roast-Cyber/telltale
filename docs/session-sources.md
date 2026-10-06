# Session Sources

> **Website:** For approachable guides to session stores and agent traces, see [AgentArchaeology.ai/field-guide/session-stores](https://agentarchaeology.ai/field-guide/session-stores/) and [AgentArchaeology.ai/field-guide/agent-traces](https://agentarchaeology.ai/field-guide/agent-traces/).

Telltale source definitions live in the per-agent modules under
`crates/telltale-sources/src/sources/` and are collected by
`sources/registry.rs`, which preserves static client and install registration
order. Discovered sources are sorted separately for deterministic scans.
Acquisition dispatches those identities to source-owned native extraction.
This document records the current source-of-truth host path candidates used by
the scanner.

Session-store discovery answers “where can Telltale acquire activity from?” It is
intentionally separate from installed-agent inventory, which answers “which
agent tools appear installed?” using metadata-only checks in
`crates/telltale-sources/src/install_inventory.rs` such as executables on `PATH`, package roots, VS
Code-style extension IDs, and globalStorage presence. On Windows, OpenCode
Desktop also has metadata-only executable probes under
`~/AppData/Local/Programs/@opencode-aidesktop/OpenCode.exe` and
`~/AppData/Roaming/ai.opencode.desktop/cli/*/opencode-cli.exe`; these do not
require a PATH shim or Node installation. Install inventory runs on
a configurable cadence and never reads transcript/session contents.

## Host Discovery Candidates

These are the host-side locations Telltale currently resolves when
`telltale scan --root .` uses host-style discovery instead of a checked-in fixture
tree. Registered `Home` and `DataHome` sources also resolve on
Windows through the platform-aware root helpers. Windows entries below remain
unvalidated unless a bounded live validation is explicitly recorded. A single
validated installation does not establish support for every client version or
installation layout.

These candidates document expected product behavior and the scanner paths Telltale
can resolve. They are not instructions to publish local session stores,
workstation-specific transcript paths, raw agent logs, credentials, or
deployment-specific SIEM paths. Public source-support claims should be backed
by synthetic fixtures and deterministic tests; live host validation records
should stay local-only, redacted, and summarized by client/source kind rather
than by exact private path or transcript content.

| Client | Source Kind | Linux candidate | macOS candidate | Windows candidate | Confidence | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| Codex | `codex.sessions` | `$CODEX_HOME/sessions` or `~/.codex/sessions` | `$CODEX_HOME/sessions` or `~/.codex/sessions` | `%CODEX_HOME%\sessions` or `%USERPROFILE%\.codex\sessions` | Confirmed root; Windows unvalidated | Codex CLI docs confirm `~/.codex/sessions`; Telltale also supports `archived_sessions` and `headless` under the same root. |
| Codex | `codex.archived_sessions` | `$CODEX_HOME/archived_sessions` or `~/.codex/archived_sessions` | `$CODEX_HOME/archived_sessions` or `~/.codex/archived_sessions` | `%CODEX_HOME%\archived_sessions` or `%USERPROFILE%\.codex\archived_sessions` | Confirmed root; Windows unvalidated | Same root model as `codex.sessions`. |
| Codex | `codex.headless_sessions` | `$CODEX_HOME/headless` or `~/.codex/headless` | `$CODEX_HOME/headless` or `~/.codex/headless` | `%CODEX_HOME%\headless` or `%USERPROFILE%\.codex\headless` | Confirmed root; Windows unvalidated | Same root model as `codex.sessions`. |
| Claude Code | `claude.projects` | `~/.claude/projects` | `~/.claude/projects` | `%USERPROFILE%\.claude\projects` | Candidate; Windows unvalidated | Claude docs confirm `~/.claude/` as the user root; Telltale resolves project JSONL sessions through the platform-aware home root. |
| Qwen CLI | `qwen.projects` | `~/.qwen/projects` | `~/.qwen/projects` | `%USERPROFILE%\.qwen\projects` | Candidate; Windows unvalidated | Telltale supports this path through the platform-aware home root; upstream and live Windows validation remain incomplete. |
| OpenClaw | `openclaw.agents` | `~/.openclaw/agents` | `~/.openclaw/agents` | `%USERPROFILE%\.openclaw\agents` | Candidate; Windows unvalidated | Telltale supports this path through the platform-aware home root; the upstream workspace/storage split still needs review. |
| OpenCode | `opencode.sqlite` | `$XDG_DATA_HOME/opencode/opencode.db` or `~/.local/share/opencode/opencode.db` | `~/Library/Application Support/opencode/opencode.db` | Windows platform data root plus `%XDG_DATA_HOME%\opencode\opencode.db` when set and `~/.local/share/opencode/opencode.db` | Confirmed Linux/macOS; Windows discovery/inventory live-checked | Windows checks the platform data root (`LOCALAPPDATA`, then `APPDATA`, then `~/AppData/Local`) alongside XDG candidates. Desktop v2.0.24 discovery/inventory validation and the live acquisition limit are recorded below. |
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

Project-local discovery is additive: home-relative sources are still discovered
from `--root`. The retained project-local source is Copilot `logs/copilot`. If a
project uses a non-standard subpath, rename the directory to match the registry
subpath rather than overriding per-project paths in the YAML.

The `TELLTALE_PROJECT_CONFIG` environment variable accepts a platform-native path
list when no `--project-config` flag is given. When neither is provided,
Telltale uses the default paths (`~/github` and `~/projects`). Repeat
`--project-config` when that is clearer or when scripts should avoid path-list
escaping rules.

## Fixture Behavior

- When `telltale scan --root` points at a checked-in fixture tree such as `tests/fixtures/session_stores`, Telltale does not use host-path resolution.
- Fixture discovery still uses each source's `fixture_relative_path` directly.
- A standalone `opencode/opencode.db` does not identify fixtures: real data homes
  use that same layout. Mark an OpenCode-only synthetic root with an empty
  `.telltale-fixtures` file to retain the emitting-scan guard. Other flattened
  client fixture paths continue to identify the checked-in fixture trees.
- Platform-aware host-path resolution does not change fixture layout or fixture-path expectations.
- Public verification should prefer checked-in synthetic fixtures and commands that do not touch real agent stores, such as a dry-run fixture scan or focused acquisition/discovery tests.

## Host Root Rules

- `Home` sources resolve from `HOME` on Linux/macOS and `HOME` or `USERPROFILE` on Windows.
- `CodexHome` resolves from `CODEX_HOME` when set, otherwise `~/.codex`.
- `DataHome` resolves to `XDG_DATA_HOME` or `~/.local/share` on Linux, `~/Library/Application Support` on macOS, and `LOCALAPPDATA`, then `APPDATA`, then `%USERPROFILE%\AppData\Local` on Windows.
- OpenCode on Windows additionally checks `XDG_DATA_HOME` when set and
  `~/.local/share`, retaining any distinct databases found in AppData and XDG
  locations. Scan, watch and bounded discovery use the same candidates. An
  explicit `--root` is isolated from environment overrides and may name either
  a home or a data home containing `opencode/opencode.db`.

## Linux Operational Notes

Linux-specific live validation should use bounded, redacted excerpts and
fixture-equivalent scans whenever possible. Host-specific shipper setup should
be reviewed before publication or reuse in another environment.

## Source Adapter Notes

Codex adapter notes:

- JSONL entries include `session_meta`, `turn_context`, and event payloads.
- `session_meta.payload.source == "exec"` marks headless sessions.
- `session_meta.payload.model_provider` and `agent_nickname` can identify provider and agent.

OpenCode adapter notes:

- Bounded native Windows validation on 2026-10-05 used OpenCode Desktop v2.0.24
  and its live WAL-backed SQLite store. Default-root and explicit home/data-home
  discovery and metadata-only Desktop inventory were checked with isolated
  output/state paths, without `--allow-fixtures`. Emitting scans passed the
  fixture guard, but full-store acquisition reported `unbounded_value`: retained
  tool outputs exceed the existing canonical 4,096-byte string bound. Synthetic
  end-to-end emitting scans passed. This records one installation's discovery
  and inventory, not successful full-store live ingestion or complete history.
  Detailed evidence remains local; canonical limits were not relaxed.

- Newer data lives in `opencode.db`, table `message`, with JSON in `data`.
- SQLite sources open with a 5-second `busy_timeout` so scans fail fast when OpenCode holds a write lock, surfacing a bounded `SourceReadError::Locked` failure instead of hanging indefinitely.
- Per-source acquisition reads are sequential; a single slow or contended source blocks the current scan (known limitation).
- OpenCode per-message model attribution reflects the model that generated each message, which may differ from the session's primary model when sub-agents are used.
- Desktop v2 user messages can carry `model: { modelID, providerID }`, while
  assistant messages carry scalar `modelID` and `providerID`. Both shapes are
  acquired; conflicting metadata remains ambiguous and malformed fields fail
  acquisition atomically.
- Live OpenCode SQLite stores also carry a top-level `message.session_id` column even when the JSON payload does not.
- Telltale needs all roles and tool records, not only assistant token-usage rows.

### OpenCode incremental saturation and recovery

Current development supports source-atomic recovery of an incremental selection
up to 25,000 text/tool parts. Queries return at most 5,000 parts per page from
one read snapshot, including ties in `time_updated`; the complete selection is
mapped and evaluated once. All messages are still read. The public acquisition
default and CLI bootstrap, `--backfill` and `--dry-run` remain newest-5,000
sampling. Those modes do not recover or advance an existing production cursor.
An ordinary bootstrap can initialize a timestamp cursor while omitting older
parts; this sampling does not establish complete historical coverage.

Recognition and safe response:

1. Check scan summaries for an OpenCode parse failure and the bounded
   `canonical_acquisition_failed` scanner error. This can indicate saturation,
   schema/payload failure or contention; it does not uniquely diagnose overflow.
2. Retry ordinary scans with the same state using a binary containing this
   recovery implementation. Successful incremental acquisition must exhaust its
   selection; required output persistence gates cursor installation. A failed
   acquisition or required output write leaves the committed cursor unchanged.
   Restart retries the whole selection from that timestamp minus ten minutes.
   If that unchanged overlap selection still exceeds a budget, retries and
   restarts can remain saturated; they do not drain it in smaller batches.
3. If failures persist, preserve the database, state and output artifacts under
   their existing privacy controls and seek support. More than 25,000 selected
   parts, malformed data, or independent canonical/projection budgets still fail
   closed. There is no supported arbitrary-backlog recovery command. Do not
   delete state, shrink overlap, or use backfill/dry-run as a recovery workaround.

SQLite extraction additionally admits at most 100,000 delivered rows shared by
all messages and selected part pages, 134,217,728 aggregate projected row-envelope
bytes, and 8,388,608 bytes per TEXT/BLOB cell or UTF-8 column name (inclusive).
Every column occurrence charges its name plus SQLite-exposed UTF-8 TEXT bytes,
BLOB bytes, zero for NULL or eight for numeric cells, including unknown fields,
overwritten aliases, suppressed metadata and repeated joined context. Zero-row
schemas check names but charge no aggregate bytes. Oversized sources fail
atomically with safe source-read diagnostics and unchanged source baseline/cursor.
These fixed internal limits have no public configuration.

Admission precedes owned row construction and retains one complete native batch
for suppression/evaluation. It does not bound SQLite preparation, filtering,
UTF-8 conversion or engine allocation, decoded DOM/native heap, RSS, CPU or
end-to-end memory; unselected payloads are outside its scope. The pre-existing
nonunique message-ID join can duplicate keyset coordinates: same-page duplicates
reject, while page-boundary duplicates can be skipped. This is not exhaustive
join recovery. A snapshot captures currently visible rows, not deleted
rows or overwritten intermediate revisions; backdated writes outside overlap
are not guaranteed. Accounting remains partial, not whole-database coverage.

Claude Code adapter notes:

- JSONL entries commonly use top-level `type` values such as `user` and `assistant`.
- Message payloads can live under `message.role`, `message.model`, and `message.content`.
- `message.content` arrays may include `text`, `tool_use`, and `tool_result` blocks; the adapter maps `tool_use` and `tool_result` blocks to their canonical Tool semantics.

Qwen adapter notes:

- JSONL files under `.qwen/projects/**/chats` may contain `type`, `model`, `timestamp`, `sessionId`, and `usageMetadata` fields.
- `qwen.projects` uses source-owned modeled JSONL extraction with metadata
  context, tool-call/result classification, and terminal schema/unknown
  boundaries. It is not a generic JSONL fallback.
