# Claude Code on Windows: Telltale coverage audit (2026-10-14)

**Verdict: Claude Code on Windows is NOT effectively monitored by Telltale.**
Telltale finds the correct transcript, including the Claude desktop app's Code
tab session that this audit ran in. It then rejects the **entire file** while
parsing, so it emits no activity, detection, or session-risk events for it. The
only output is a low-severity `scanner_error` with `check_name=source_parse`.

## Environment

| Item | Value |
|---|---|
| Host | Windows 11 Pro 10.0.26300, single local user profile |
| Claude desktop | MSIX package `Claude_pzs8sxrjxfjjc`; bundled Claude Code `2.1.266` and `2.1.295` |
| Test session | One Claude desktop Code tab session (the session that ran this audit) |
| Telltale | First run on 0.7.0-rc.2 (`6fd8799`). Re-verified on 0.7.0-rc.3 at `main` `6d7dbc8` (after #100–#102): all three failures reproduce |
| Telltale deployment | Not installed on this host (no service, scheduled task, or PATH binary) |

## Where Claude writes data on Windows

| Location | Contents | Telltale scans it? |
|---|---|---|
| `%USERPROFILE%\.claude\projects\<cwd-slug>\<session>.jsonl` | Full transcripts for the CLI and the desktop Code tab | **Yes**: the only Claude source (`claude.projects`) |
| `%APPDATA%\Claude\claude-code-sessions\<org>\<acct>\local_<id>.json` | Desktop session metadata (`cliSessionId`, `cwd`, model, permission mode, title) | No |
| `%APPDATA%\Claude\local-agent-mode-sessions\…` | Cowork / local agent mode working files and skills (no JSONL transcripts on this host) | No |
| `%APPDATA%\Claude\claude-code\<ver>\<hash>\claude.exe` | Desktop-bundled Claude Code binary | No (install inventory checks PATH only) |
| `%LOCALAPPDATA%\Claude\logs\*.log` | App logs (`main.log`, `mcp.log`, `ssh.log`, `remote-control.log`, `cowork_vm_node.log`) | No |
| `%LOCALAPPDATA%\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude` | MSIX-virtualized mirror of `%APPDATA%\Claude` | No |

Path discovery is correct. The desktop app does not redirect transcripts.
The desktop session's `local_<id>.json` maps `cliSessionId` to the transcript UUID, and that transcript
is under `%USERPROFILE%\.claude\projects\<cwd-slug>\`. That is
the path Telltale resolves via `USERPROFILE`
(`crates/telltale-sources/src/discovery.rs:748`).

## Reproduction

```
telltale scan --once --client claude --emit-activity --emit-session-risk-summary \
  --no-local-config --log-path <tmp>\events.jsonl --state-path <tmp>\state.json
```

Health event: `selected_source_count=1`, `parse_success_source_count=0`,
`parse_error_source_count=1`, `parsed_record_count=0`,
`failures=[{acquisition_code: unknown_discriminator}]`, plus the warnings
`selected_sources_produced_no_records` and
`all_selected_sources_parse_failed_or_empty`. No event mentions the session ID.

## Root causes (three independent whole-file failures)

The Claude adapter fails closed **per file**. One record it can't handle drops
the whole session. I peeled the failures off one at a time on copies of the
transcript to confirm each:

### 1. Non-conversational record types: `unknown_discriminator`

`is_known_claude_discriminator` (`crates/telltale-sources/src/sources/claude/native.rs:198`)
accepts only `user`, `assistant`, `tool_*`, `session_meta`, and a few others.
Every current Claude Code transcript also contains metadata records. This
session contains:

| `type` | count |
|---|---|
| `attachment` | 32 |
| `last-prompt`, `agent-name`, `atis-latch`, `custom-title` | 8–9 each |
| `queue-operation` | 2 |
| `file-history-snapshot` | 1 |

Other common types (`summary`, `system`, `progress`) would hit the same path.
`canonical.rs:97-104` turns any of these into a hard error.

### 2. `thinking` content blocks: `unknown_content_block`

`ClaudeContentBlock` (`native.rs:11-28`) knows only `text`, `tool_use`, and
`tool_result`. Assistant `thinking` blocks (17 in this session; also
`redacted_thinking`) map to `Unknown`, and `canonical.rs:125-132` rejects the
file. Any session that uses extended thinking, which is the default on current
Opus models, fails.

### 3. Tool-input bounds: `unbounded_value`

With issues 1 and 2 stripped, the file still fails. Testing one record at a
time isolated the cause to tool-call inputs.

| Probe tool input | Result |
|---|---|
| `{"items":["a","b"]}` | ok |
| `{"o":{"a":"b"}}` | ok |
| `{"items":[{"a":"b"}]}` | **fail** |
| `{"o":{"p":{"a":"b"}}}` | **fail** |
| `Write` with 4,000-char `content` | ok |
| `Write` with 5,000-char `content` | **fail** |

So any tool argument with an object nested inside an array or object fails.
That includes TodoWrite, MultiEdit, AskUserQuestion, and many MCP tools.
`LOCAL_MAX_STRING_BYTES = 4096` (`crates/telltale-schema/src/observation/value.rs:12`)
also fails any `Write`/`Edit` larger than 4 KB. These are the highest-signal
records for detection, and they are exactly the ones Telltale discards.

## Secondary gaps

- **Install inventory misses desktop installs.** The `claude` install def
  (`sources/claude/install.rs`) checks for `claude` on `PATH` and the npm
  package `@anthropic-ai/claude-code`. The desktop-bundled
  `%APPDATA%\Claude\claude-code\<ver>\…\claude.exe` is on neither, so a
  desktop-only host looks like "Claude not installed".
- **`CLAUDE_CONFIG_DIR` is not honored.** Users who relocate the Claude config
  dir won't be discovered (discovery uses `HOME`/`USERPROFILE` + `.claude/projects` only).
- **Failure is quiet.** The only signal is an `informational` `scanner_error`
  and health warnings. A SOC that alerts on detections sees silence, which
  looks the same as "nothing risky happened".
- **The validation claim is stale.** `docs/source-validation-matrix.md:124`
  records bounded live Claude validation with "zero scanner errors". Current
  Claude Code (2.1.2xx) transcript formats don't reproduce that.

## Recommended fixes

1. Change the Claude adapter from fail-whole-file to **skip-and-account** per
   record. Count unknown discriminators and blocks in source-processing
   accounting (coverage `partial`) instead of aborting acquisition.
2. Add the known Claude metadata record types as recognized, ignorable
   discriminators, and add `thinking`/`redacted_thinking` blocks (ignored, or
   kept as assistant reasoning context).
3. **Truncate or summarize** oversized or deeply nested tool inputs, with a
   `truncated` marker, instead of rejecting them. Detection rules need the
   `Bash` command, `Write` path, and a bounded content prefix, not the full value.
4. Add the desktop-bundled `claude.exe` location and the MSIX package family to
   Claude install inventory. Honor `CLAUDE_CONFIG_DIR`.
5. Raise `scanner_error` with `check_name=source_parse` to at least `low`/`medium`
   when a client's selected sources all fail. Total parse failure is a
   monitoring outage.
6. Add a sanitized fixture from a current Claude Code 2.1.x transcript (metadata
   records, thinking, nested tool inputs, a >4 KB Write) to
   `crates/telltale-detect/tests/fixtures/session_stores/claude/`, and re-run
   live validation before the 0.7.0 release claim stands.

## Resolution (branch `fix/windows-claude-code-parsing`)

Implemented recommendations 1–3. Recommendations 4 and 5 (desktop install
inventory, `CLAUDE_CONFIG_DIR`, scanner_error severity) remain open.

- Bookkeeping record types are skipped, including `file-history-delta`, which
  the first live re-scan surfaced through quarantine. `thinking`,
  `redacted_thinking`, `image` and `document` blocks are dropped.
- A message's `tool_use`/`tool_result` part carries only its call id and name.
  Arguments and results live once, on the Tool observation. Claude
  `Bash`/`PowerShell`/`Write`/`Edit`/`NotebookEdit`/`Task`/`Agent` text fields
  get the authored-text budget, and all-text result arrays join into one string.
- An unknown record or block, an oversized record, or an invalid contribution
  quarantines only that record (`AcquisitionBatch.quarantined`, one content-free
  `scanner_error`, coverage `partial`). Ownership/attestation integrity and the
  source-wide retained budget still fail the source.
- Coverage: unit tests for each record shape, and an end-to-end CLI test
  (`tests/cli/claude_code_current_format.rs`) for parsing, quarantine, three
  detections, schema validity and no leakage of secrets or reasoning.

**Live re-validation (Windows 11, this host, release build):**
`telltale scan --once --client claude --emit-activity --emit-session-risk-summary`
on the real `~/.claude/projects` gave `parse_success_source_count=1`,
`parse_error_source_count=0`, 1,032 records, coverage `complete`, and 0
quarantined units. For the desktop session it emitted `activity`, 3
`process_chain`, 1 `detection`, and `session_risk_summary` events, and no
`scanner_error`.
