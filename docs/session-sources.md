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
require a PATH shim or Node installation. The Claude desktop app bundles
Claude Code at `~/AppData/Roaming/Claude/claude-code/<version>/<hash>/claude.exe`,
and the MSIX package `Claude_pzs8sxrjxfjjc` mirrors it under
`~/AppData/Local/Packages/Claude_pzs8sxrjxfjjc/LocalCache/Roaming/Claude/claude-code`;
both are probed the same way (`claude-desktop`, `claude-desktop-packaged`).
macOS and Linux desktop bundle locations are not probed until confirmed on a
real install. Install inventory runs on
a configurable cadence and never reads transcript/session contents.

Copilot inventory checks the `copilot` launcher on `PATH` (including Windows
launcher suffixes) and the `@github/copilot` package in the existing Node package
roots, alongside the retained VS Code extension evidence. These metadata-only
signals do not execute Copilot or establish session acquisition support.
The launcher name is ambiguous: [AWS Copilot CLI](https://aws.github.io/copilot-cli/docs/getting-started/install/)
also installs `copilot`. A launcher alone therefore reports `Partial` confidence
and `installed=false`; `@github/copilot` or GitHub extension evidence confirms the
inventory entry. Standalone GitHub Copilot CLI installs without that evidence also remain
`Partial`. Other agents' install-confidence rules are unchanged.

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
| Codex | `codex.sessions` | `$CODEX_HOME/sessions` or `~/.codex/sessions` | `$CODEX_HOME/sessions` or `~/.codex/sessions` | `%CODEX_HOME%\sessions` or `%USERPROFILE%\.codex\sessions` | Confirmed root; Windows bounded live validation (2026-10-14) | Codex CLI docs confirm `~/.codex/sessions`; Telltale also supports `archived_sessions` and `headless` under the same root. |
| Codex | `codex.archived_sessions` | `$CODEX_HOME/archived_sessions` or `~/.codex/archived_sessions` | `$CODEX_HOME/archived_sessions` or `~/.codex/archived_sessions` | `%CODEX_HOME%\archived_sessions` or `%USERPROFILE%\.codex\archived_sessions` | Confirmed root; Windows unvalidated | Same root model as `codex.sessions`. |
| Codex | `codex.headless_sessions` | `$CODEX_HOME/headless` or `~/.codex/headless` | `$CODEX_HOME/headless` or `~/.codex/headless` | `%CODEX_HOME%\headless` or `%USERPROFILE%\.codex\headless` | Confirmed root; Windows unvalidated | Same root model as `codex.sessions`. |
| Claude Code | `claude.projects` | `~/.claude/projects` | `~/.claude/projects` | `%USERPROFILE%\.claude\projects` | Candidate; Windows bounded live validation (desktop Code tab, 2026-10-14) | Claude docs confirm `~/.claude/` as the user root; Telltale resolves project JSONL sessions through the platform-aware home root. When `CLAUDE_CONFIG_DIR` is set in the scanner's environment, `$CLAUDE_CONFIG_DIR/projects` is searched as well; `~/.claude/projects` stays a root because a scanner service may not share the user's environment. An explicit `--root` ignores the variable. |
| Qwen CLI | `qwen.projects` | `~/.qwen/projects` | `~/.qwen/projects` | `%USERPROFILE%\.qwen\projects` | Candidate; Windows unvalidated | Telltale supports this path through the platform-aware home root; upstream and live Windows validation remain incomplete. |
| OpenClaw | `openclaw.agents` | `~/.openclaw/agents` | `~/.openclaw/agents` | `%USERPROFILE%\.openclaw\agents` | Candidate; Windows unvalidated | Telltale supports this path through the platform-aware home root; the upstream workspace/storage split still needs review. |
| OpenCode | `opencode.sqlite` | XDG OpenCode data directory; exact `$OPENCODE_DB` when configured | XDG OpenCode data directory plus retained `~/Library/Application Support/opencode/opencode.db`; exact `$OPENCODE_DB` | XDG OpenCode data directory plus retained Windows platform data and `~/.local/share` candidates; exact `%OPENCODE_DB%` | Default paths have prior bounded validation; relocation/channel discovery is synthetic-conformance tested | Environment-resolved mode adds direct-child channel databases and one configured file; see the OpenCode root rules below. Prior Desktop validation does not qualify these new paths or every version. |
| Copilot | `copilot.process_log` | project-local `logs/copilot` | project-local `logs/copilot` | project-local `logs/copilot` | Existing process format only; current CLI home logs unqualified | **Project-local only** — discovered below configured project roots or applicable default project roots. Neither `~/.copilot/logs` nor `COPILOT_HOME/logs` is discovered; see the qualification gap below. |

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
- OpenCode environment-resolved host discovery (the default `--root .`) uses
  nonempty `XDG_DATA_HOME/opencode`, otherwise `~/.local/share/opencode`, on
  every platform. It retains the existing platform `opencode.db` candidates,
  including macOS Application Support and Windows AppData/`.local/share` paths.
  This follows the pinned CLI's [XDG roots](https://github.com/anomalyco/opencode/blob/a517687fde98a7329ada3ae644a01a9fc6c4e99e/packages/util/src/global-roots.ts#L4-L18),
  without treating Desktop installation metadata as a storage contract.
- In those OpenCode data directories only, direct-child `opencode.db` and
  `opencode-<channel>.db` files are candidates. A channel is nonempty and contains
  only ASCII letters, digits, `.`, `_`, or `-`; the basename predicate is
  case-sensitive. Sidecars, extra extensions and nested files are not candidates.
  Environment-resolved discovery validates directory components before selecting
  defaults or channels and rejects symlinked `opencode.db` files, including
  dangling links. Best-effort skips rejected targets while retaining healthy
  candidates; watch registers only validated directories, never a linked default
  directory target. Non-`.` explicit-root behavior remains unchanged.
  Native filesystem aliases can still be case-insensitive. The pinned
  [filename resolver](https://github.com/anomalyco/opencode/blob/a517687fde98a7329ada3ae644a01a9fc6c4e99e/packages/cli/src/database-path.ts#L4-L13)
  sanitizes the baked build channel; setting runtime `OPENCODE_CHANNEL` does not
  change it. Discovery retains every matching store rather than guessing an
  active channel from the scanner's environment.
- `OPENCODE_DB` adds **one exact file**, with any basename. Absolute values are
  used directly; relative values resolve against the upstream XDG OpenCode data
  directory, not the scanner's working directory or macOS Application Support.
  `..` is normalized lexically and may select a file outside that directory;
  `~` is literal, not expanded. The configured file's parent is never enumerated
  for other databases. Empty values and exact `:memory:` add no persistent file
  (upstream's empty value names the data directory, not a default database).
  Existing path components must not be symlinks and the target must be a regular
  file when present. These are metadata checks, not an atomic filesystem snapshot.
  Bounded discovery retains explicit symlink/traversal errors and charges visited
  directory entries and configured-path components against its budget.
  Rejected roots are checked-discovery errors, not successful empty listings.
  The CLI reports its first error and uses the existing best-effort fallback,
  which can retain healthy/default sources; bounded discovery returns no partial
  listing on failure.
- Scan, watch and bounded discovery share these candidates. Watch subscribes to
  OpenCode directories nonrecursively unless another selected source requires
  recursion there, maps an arbitrary configured filename's WAL to its main file,
  and ignores its reader-generated SHM/journal changes. State, JSONL and outbox
  paths must still be outside watched source directories.
  For a parent used solely by an arbitrary override, unrelated sibling events
  are ignored as well. Other selected source roots keep their own coverage.
  Notification filtering compares native path names without filesystem lookups.
  macOS's native notification backend can miss writes to an already-open SQLite
  WAL ([upstream limitation](https://github.com/notify-rs/notify/issues/613)); a
  native experiment observed no raw event for a second committed insert until
  writer close. On macOS only, watch therefore samples metadata for already-indexed
  `opencode.sqlite` main files and their `-wal` files: up to 64 pairs per second,
  round-robin. Large indexes take proportionally longer for a complete pass.
  Initial indexing and requested scans capture the relevant baselines before
  acquisition, never after it, so commits arriving during a scan remain changes.
  File identity, length and nanosecond modification time are compared; content is
  never read for sampling. Linked path components and nonregular leaves are rejected.
  This adds no directory enumeration, new discovery path, SHM/journal sampling or
  scan for unchanged samples of already-indexed stores. Native events still discover new stores, and metadata
  changes use the same targeted-scan, debounce and minimum-interval rules.
  A newly indexed store gets one conservative extra scan because a post-scan
  baseline could hide a concurrent commit; that scan can consume an iteration.
  Explicit-root aliases with symlinked components remain outside this metadata
  fallback, even where legacy discovery accepts their coordinates. Use a real,
  non-symlinked path for open-WAL monitoring; no-follow checks are not relaxed.
  Native macOS validation is required; metadata sampling is not a promise to detect
  writes that deliberately preserve all compared metadata.
- A non-`.` explicit `--root` ignores `OPENCODE_DB` and retains exact
  `opencode.db` matching and its existing home/data-home candidates. Fixture
  layout is unchanged. Relocation is additive: the scanner may not share the
  harness's environment, and older default stores remain useful. The variable
  must be available to the **scanner process**; the checked-in system service
  uses a non-`.` root, so merely adding the variable to its environment does not
  enable relocation. No service configuration or live validation is implied.

## Linux Operational Notes

Linux-specific live validation should use bounded, redacted excerpts and
fixture-equivalent scans whenever possible. Host-specific shipper setup should
be reviewed before publication or reuse in another environment.

## Source Adapter Notes

### Copilot CLI qualification gap

Copilot CLI v1.0.101's [pinned changelog](https://github.com/github/copilot-cli/blob/84a2bd392a397e3dafaa9a1212b2964c3bd694bc/changelog.md#L1585)
and [official configuration-directory reference](https://github.com/github/docs/blob/92991ed6d17c5023f52e324ee70d36fe7c36dd7d/content/copilot/reference/copilot-cli-reference/cli-config-dir-reference.md#L345-L388)
confirm `~/.copilot/logs/process-{timestamp}-{pid}.log`, with `COPILOT_HOME`
replacing `~/.copilot`. The [pinned README](https://github.com/github/copilot-cli/blob/84a2bd392a397e3dafaa9a1212b2964c3bd694bc/README.md#installation)
also establishes the launcher and package names used by install inventory.

The existing adapter requires workspace initialization and accumulated-output
arrays; a documented directory does not establish that record format. Static
inspection of the official [v1.0.96 Linux runtime archive](https://github.com/github/copilot-cli/releases/download/v1.0.96/github-copilot-1.0.96-linux-x64.tgz)
(`SHA256 e6c9513e7dcff38e424c247a8ae7b5b8a283e93973b77eb31fba9ef769f1c95b`)
defines the named `default` log level as `info` in `cli-main.js`'s logging help,
but does not establish the adapter's `Accumulated output items` format when the
CLI is invoked without logging flags.
That assessment is historical v1.0.96 evidence; it does not qualify the current
v1.0.101 pin's default-level format either.
The published repository does not contain the log writer. No CLI execution,
installation, or live capture was used for this assessment.

Home and relocated discovery therefore remain disabled, and both synthetic
[upstream cases](../tests/upstream_formats/cases/copilot/) remain `known_gap`.
They copy a Telltale fixture to the documented paths, not an upstream-generated
transcript from either version. Promotion requires authoritative format/default-level
evidence followed by successful discovery **and** acquisition, not merely
finding that copied fixture. Explicit `--root`, fixture, and project-local
discovery are unchanged. `session-state/*/events.jsonl` and `session-store.db`
have no qualified schema here and are not acquired.

Codex adapter notes:

- JSONL entries include `session_meta`, `turn_context`, and event payloads.
- `session_meta.payload.source == "exec"` marks headless sessions.
- `session_meta.payload.model_provider` and `agent_nickname` can identify provider and agent.
- A forked thread's rollout starts with `history_base` (`thread_id`,
  `end_ordinal_exclusive`, `end_byte_offset`) and its ordinals continue from
  `end_ordinal_exclusive`. The parent history stays in the parent's rollout
  and is not read again. `subagent_history_start_ordinal` is still rejected.
- Bookkeeping records are skipped: `token_usage_record`, `compacted`,
  `turn_context`, `world_state`, lifecycle and reasoning `event_msg` payloads
  (including `thread_settings_applied` and `turn_aborted`), and completed
  `Reasoning`, `ContextCompaction`, `EnteredReviewMode` and
  `ExitedReviewMode` items.
- Code-mode `exec` and freeform `apply_patch` string inputs get the
  authored-text budget. An all-text `custom_tool_call_output` array is joined
  into one direct result, and a completed command's `aggregated_output` is the
  direct result with `exit_code` as `tool.exit_code`.
- Completed `FileChange` maps to one reported Tool result with bounded structured
  patch evidence and a parsed, field-labeled searchable result, not a file-state
  or execution claim. See the [canonical mapping and bounds](canonical-observation-v2.md).
- Completed `McpToolCall` and `Extension` items are not mapped yet and are
  quarantined by themselves (`unsupported_completed_item`). A
  parent rollout repeats its subagents' completed items under the subagent's
  `thread_id`; those copies are quarantined (`foreign_thread_item`), and the
  subagent's own rollout is the one evaluated.
- An unknown record type, completed item or content part, or a record whose
  own values exceed a canonical bound, is quarantined by itself and reported
  by session, item or call id, sequence and bound, never content; the rest of
  the rollout is still evaluated and coverage is reported as partial.
  Coordinate, ownership and wrapper errors still fail the whole source.

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

- `opencode.db` holds the legacy `message`/`part` tables, OpenCode v2
  `session_v2`/`session_message`, or both after a migration. One schema is
  read per scan, and complete v2 tables take precedence; see
  [OpenCode live ingestion](opencode-live-ingestion.md#native-schemas).
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

This section describes legacy `message`/`part` stores. OpenCode v2
(`session_message`) stores evaluate rolling windows instead: a selection over
the row limit or the 8 MiB retained budget is drained in overlapping windows
within one scan (up to 64), and later scans continue any remainder. Only a
window that cannot pass its resume point fails. For a forensic pass over a
whole v2 store, use `telltale scan --once --history all --client opencode --log-path <file>`,
which reads from the earliest message and never touches scan state. See
[OpenCode live ingestion](opencode-live-ingestion.md).

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
- The Claude desktop app's Code tab writes the same transcripts as the CLI;
  its own `%APPDATA%\Claude\claude-code-sessions` metadata only references
  them by `cliSessionId`.
- Bookkeeping records between turns (`attachment`, `queue-operation`,
  `last-prompt`, `custom-title`, `ai-title`, `agent-name`, `atis-latch`,
  `file-history-snapshot`, `file-history-delta`, `summary`, `system`,
  `progress`) are skipped.
- `thinking`, `redacted_thinking`, `image`, and `document` blocks are dropped
  from messages; reasoning text is not retained.
- A message's `tool_use`/`tool_result` part keeps only its call id, name and
  error state. Arguments and results are carried once, on the linked Tool
  observation. `Bash`/`PowerShell` `command`, `Write` `content`, `Edit`
  `old_string`/`new_string`, `NotebookEdit` `new_source` and `Task`/`Agent`
  `prompt` get the authored-text budget, and an all-text result array is
  joined into one direct string.
- An unknown record type or content block, or a record whose own values
  exceed a canonical bound, is quarantined by itself and reported by session,
  record `uuid`, sequence and bound, never content; the rest of the
  transcript is still evaluated and coverage is reported as partial.
- A full scan in which every selected Claude source fails processing, at
  acquisition, parsing, evaluation or any later stage, also emits a `warning` `operational_alert` with `alert_type=source_parse_outage`; see
  [telemetry-output.md](telemetry-output.md).

Qwen adapter notes:

- JSONL files under `.qwen/projects/**/chats` may contain `type`, `model`, `timestamp`, `sessionId`, and `usageMetadata` fields.
- `qwen.projects` uses source-owned modeled JSONL extraction with metadata
  context, tool-call/result classification, and terminal schema/unknown
  boundaries. It is not a generic JSONL fallback.
