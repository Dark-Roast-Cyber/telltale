# Claude Code adapter

Pinned and verified against Claude Code **2.1.318** (Linux x86-64). Evidence:
captured payloads in `crates/telltale/tests/hooks/fixtures/claude-code/2.1.318/`, binary strings,
and real headless runs in `docs/hooks/e2e/`.

## Events handled

| Hook event | Runtime event | What telltale-hooks does |
| --- | --- | --- |
| `PreToolUse` | `ToolRequested` | Evaluate with Telltale + session history; print `deny`/`ask` or nothing |
| `PostToolUse` | `ToolFinished(Completed)` | Journal result, evaluate it, settle outcome; advisory `additionalContext` if the result scores at least `action_ask` |
| `PostToolUseFailure` | `ToolFinished(Failed/Interrupted)` | Same, `is_error` result |
| `PostToolBatch` | `BatchSettled` | Calls with a pending decision and no result are `not_executed` |
| `PermissionRequest` | `PermissionPrompt` | Lifecycle record (joined to its decision by `input_sha256`; the payload has no `tool_use_id`) |
| `PermissionDenied` | `BatchSettled` (one call) | Auto mode's classifier denied the call, so it did not run: settled as `not_executed`, `established_by: PermissionDenied`. Shape from the hooks reference (`tool_use_id`, `reason`, `mcp_server`); not yet captured here |
| `UserPromptSubmit` | `UserPrompt` | Journal prompt (bounded) for context rules; telemetry keeps hash and length only |
| `SessionStart`/`SessionEnd` | lifecycle | Session end marks unsettled calls `unknown` and summarizes the ledger |
| `SubagentStart`/`SubagentStop` | lifecycle | Track `agent_id` → `agent_type` |

Other events are accepted and recorded as `lifecycle: other`.

## Output contract

- No opinion: print nothing, exit 0. `allow` is **never** printed (it would
  skip Claude Code's permission prompts).
- Deny / ask:
  `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Telltale Hooks: ... Detections: <rule ids>. Record tth:<id>."}}`
- Post-result warning:
  `{"hookSpecificOutput":{"hookEventName":"PostToolUse","additionalContext":"..."}}`
- Invalid configuration: PreToolUse is denied with a "misconfigured" reason;
  other events exit 1 (a non-blocking error in Claude Code).
- Payload the hook cannot use:
  - A `PreToolUse`, even truncated or missing fields, gets the stricter of
    `on_error` and `on_unevaluable` on stdout.
  - Any other named event exits 1. Exit 2 on a `Stop` is a prompt to continue.
  - A payload that names no event exits 1, or 2 when `on_error = "deny"`, since
    only exit 2 blocks a call without knowing the event. Residual: if that
    payload was a `Stop`, Claude Code documents exit 2 as continuing the turn.
    Not run against real Claude Code.

## Installation choices

| Location | Agent can change it? | Use |
| --- | --- | --- |
| `~/.claude/settings.json`, `.claude/settings*.json` | Yes (self-protection rules raise the bar) | Development, observe mode |
| Managed settings (`/etc/claude-code/managed-settings.json` on Linux) with `allowManagedHooksOnly` | No | Enforcement deployments |
| Plugin `hooks/hooks.json` | Depends on plugin management | Distribution (future issue) |

Always generate the fragment with `telltale hooks claude-code settings
[--fail-closed] "<absolute path> claude-code hook"`. Any other argument starting
with `-` prints the usage and exits 64 on every harness, so a typo cannot silently
drop `onFailure`. `--fail-closed` places
`onFailure: "block"` on the PreToolUse **hook entry**; placed on the matcher
it is silently ignored (verified).

## Verified behaviors (2.1.318)

- PreToolUse runs before permission rules and before the call is written to
  the transcript.
- `deny` is enforced in default and `bypassPermissions` modes and inside
  subagents; `ask` in headless `-p` is declined.
- A crashing hook fails open by default.
- `--bare` / `CLAUDE_CODE_SIMPLE` disables settings, flag, policy and plugin
  hooks (binary strings); the hooks deny such launches by rule.
- MCP tools fire `PreToolUse`/`PostToolUse` as `mcp__<server>__<tool>` with
  an `mcp_server` object; a deny on an MCP call is honored. The model loads
  deferred tools through `ToolSearch` first, which has its own hook events
  (captured: `crates/telltale/tests/hooks/fixtures/claude-code/2.1.318/mcp-tool-*.jsonl`).
- Interactive `ask`: Claude Code shows "Hook PreToolUse:Bash requires
  confirmation for this command" with the hook's reason; after the user
  approves, `PostToolUse` arrives and the outcome is `proceeded_after_ask`
  (tmux-driven run, `scripts/hooks/harness/claude-code-interactive-ask.sh`).
- Hook `timeout` shorter than the hook's run time: the hook process is killed
  and the call runs (fail-open, no decision recorded) unless `onFailure:
  "block"` is on the hook entry, in which case the call is blocked. Keep the
  PreToolUse `timeout` well above the cold pipeline build (the fragment uses
  30 s; a cold in-process build takes about 0.3 to 0.7 s).
- `defer` from a PreToolUse hook in `-p` mode ends the turn with
  `stop_reason: "tool_deferred"` and the call does not run. telltale-hooks
  never answers `defer`.
- Paths that never reach `PreToolUse`: `@file` mentions in the prompt (the
  content is inserted while the prompt is built, no `Read` call), and
  `TodoWrite` is unavailable in `-p` mode. `WebSearch` and `WebFetch` do
  fire hooks (`docs/hooks/capability-matrix.md`).

## Not yet verified

`PermissionDenied` capture (three headless auto-mode probes: the classifier
allowed `rm -rf ./build` and `curl ... | sh` under the sandbox preamble, and
the model refused an exfiltration probe before any tool call; the adapter
handles the documented shape), `Glob`/`Grep` hook events (the model
substituted `Bash` in the probe), Windows and macOS, plugin packaging,
managed-settings install.
