# GitHub Copilot CLI: hook contract

Status: **adapter implemented** (`crates/telltale/src/hooks/copilot_cli.rs`) against
`@github/copilot` **1.0.105** (Linux x86-64). Evidence:

- Contract: stub hooks and a scripted model, `crates/telltale/tests/hooks/fixtures/copilot-cli/1.0.105/`
  (payloads) and `scripts/hooks/harness/capture-copilot.py` (re-runnable scenarios,
  canary method).
- Adapter enforcement: telltale-hooks itself on the real binary with the
  scripted model, `scripts/hooks/harness/copilot-cli-e2e.py`, results in
  [docs/hooks/e2e/2026-11-04-copilot-cli-1.0.105.md](../e2e/2026-11-04-copilot-cli-1.0.105.md).
- A real-model run is pending (it needs the user's Copilot auth; ).

The docs reference is github/docs `content/copilot/reference/hooks-reference`.

## Install

```bash
telltale hooks copilot-cli settings "/path/to/telltale hooks copilot-cli hook" > telltale-hooks.json
```

The output is a complete hook file (`{"version": 1, "hooks": {...}}`, the
camelCase dialect, the cross-platform `command` field). Put it in one place:

| Scope | File | Notes |
| --- | --- | --- |
| Policy (recommended for managed machines) | `/etc/github-copilot/policy.d/telltale-hooks.json`; Windows `C:\ProgramData\GitHub\Copilot\policy.d\telltale-hooks.json` | Root-owned, not group/world-writable; `disableAllHooks` cannot turn it off (Docs) |
| User | `$COPILOT_HOME/hooks/telltale-hooks.json` (default `~/.copilot/hooks/`, Windows `%USERPROFILE%\.copilot\hooks\`) | Writable by the agent's user (E2E) |
| Repository | `.github/hooks/telltale-hooks.json` | Needs folder trust; writable by the agent (Docs) |

On Windows the hook command runs under PowerShell. A binary path with
spaces must be invoked with the call operator, for example
`telltale hooks copilot-cli settings '& "C:\Program Files\telltale-hooks\telltale-hooks.exe" copilot-cli hook'`;
an unquoted path fails to start, which Copilot treats as a block on every
tool call (closed, but a denial of service).

Install it once. Hooks from every source run, so two installations (for
example this file plus a Claude Code installation in the repository's
`.claude/settings.json`) evaluate every call twice and double the session
ledger. `--fail-closed` is accepted for symmetry and changes nothing: Copilot
already blocks a call when a `preToolUse` hook crashes, exits non-zero or is
missing, and nothing can make it block on a timeout.

Evidence levels follow [the capability matrix](../capability-matrix.md):
E2E (real binary, canary checked), Capture, Docs, Src, Unknown.

## Configuration and scope

| Source | Location | Notes |
| --- | --- | --- |
| Policy | `/etc/github-copilot/policy.d/*.json` | Machine-wide, loads first, immune to `disableAllHooks` (Docs) |
| Repository | `.github/hooks/*.json`, inline `hooks` in `.github/copilot/settings{,.local}.json` | Docs |
| User | `$COPILOT_HOME/hooks/*.json` (default `~/.copilot/hooks/`), inline `hooks` in `~/.copilot/settings.json` | E2E via `COPILOT_HOME` |
| Claude Code compatibility | Repository `.claude/settings.json` hooks run when the folder is trusted | E2E |
| Plugins | Plugin `hooks.json` | Docs |

Per-run injection: point `COPILOT_HOME` at a disposable directory holding
`hooks/<name>.json` (`{"version":1,"hooks":{...}}`). Each entry is
`{"type":"command","bash":"<cmd>","timeoutSec":N}` (default timeout 30 s).

## Two payload dialects

The event name's casing selects the dialect (E2E, Capture):

| Registration | stdin | Decision output honored |
| --- | --- | --- |
| camelCase (`preToolUse`, ...) | `{sessionId, timestamp(ms), cwd, toolName, toolArgs}` | flat `{"permissionDecision":"deny","permissionDecisionReason":...}` or exit 2. Claude `hookSpecificOutput` is **ignored** (call ran) |
| PascalCase (`PreToolUse`, ...) | `{hook_event_name, session_id, timestamp(ISO), cwd, tool_name, tool_input}` | Claude `hookSpecificOutput` or flat, or exit 2 |

PascalCase payloads map tool names to Claude names (`bash`→`Bash`,
`view`→`Read`, `create`→`Write`, `edit`/`apply_patch`→`Edit`,
`grep`/`rg`→`Grep`, `web_fetch`→`WebFetch`, `task`→`Agent`). They keep
Copilot's argument keys (`path`, `file_text`, `old_str`/`new_str`). An
adapter that reuses Claude's mapping must not assume Claude argument keys.

`permissionRequest` fires even with `--allow-all-tools` and has its own shape,
`{hookName, sessionId, toolName, toolInput, permissionSuggestions}`. The shape
is the same under a PascalCase registration. MCP tools appear there as
`server/tool`, and edits as `{file_path, diff}` (Capture).

## Tool shapes (Capture)

| Tool | `toolName` | `toolArgs` |
| --- | --- | --- |
| Shell | `bash` | `{command: string, description, ...}`; no argv form |
| Read | `view` | `{path}` |
| Write | `create` | `{path, file_text}` (Claude model ids) |
| Edit | `edit` | `{path, old_str, new_str}` (Claude model ids) |
| Patch | `apply_patch` | **raw patch string**, not an object, no path key (GPT-5 model ids) |
| Web | `web_fetch` | `{url}` |
| MCP | `<server>-<tool>` (e.g. `tthmock-echo`) | tool arguments; no `mcp__` prefix |
| Subagent | `task` | `{agent_type, prompt, ...}` |

The tool set depends on the model id: Claude ids get `create`/`edit`/`grep`,
and GPT-5 ids get freeform `apply_patch` and `rg`.

IDs: `sessionId` only. Inside a subagent, `sessionId` is the **child agentId**,
and the payload adds `agentId`, `agentType` and `parentAgentId`. There is no
turn ID, no permission mode, and **no per-call ID** in any hook payload.

## Verified behaviors (1.0.105)

| Question | Answer | Evidence |
| --- | --- | --- |
| Call correlation | **None in hooks.** The internal `session-state/<id>/events.jsonl` has `toolCallId` and is written before the hook runs, but it is a transcript, not a contract | Capture |
| Deny | flat deny (camelCase) or flat/hso deny (PascalCase), or exit 2 with or without stderr; honored in default `-p`, `--yolo`, `--autopilot`, and inside subagents. Model sees `Denied by preToolUse hook: <reason>` | E2E |
| Ask | In `-p` every mode blocks: `Denied by preToolUse hook (unable to ask user for confirmation)`, also with `--yolo` and `--autopilot`. Interactive (also with `--allow-all-tools` and `--yolo`): a "Hook permission request" dialog asks "Do you want to allow this tool call?"; declining gives the model `Denied by user via preToolUse hook prompt: <reason>`, approving runs the call | E2E |
| Ask, ACP mode (`--acp`) | **Unknown**: the hook's ask may be relayed to the ACP client as a permission request, and a client that auto-approves would run the call. Not tested | — |
| Ask, cloud agent | Turned into deny | Docs |
| Allow | **Loosens native permissions**: hook `allow` ran a call that needed approval, and overrode `--deny-tool=shell` | E2E |
| Failure | exit 1, crash, exit 2, missing binary: **fail-closed** (`hook errored`). Invalid JSON and timeout: **fail-open** | E2E |
| Post events | `postToolUse` on success (including non-zero shell exit; exit code only in text), `postToolUseFailure` with `error` for tool errors. **No post event for hook-denied calls** | Capture |
| Settlement | `agentStop`/`Stop` per turn, with `transcriptPath` but no call list; repeats in autopilot | Capture |
| Subagents | `subagentStart`/`subagentStop`; deny inside honored | E2E |
| Disable | Trusted repo `.github/copilot/settings.json` `disableAllHooks: true` disables user hooks (an agent can write this file). Untrusted folder: ignored | E2E |
| Lockdown | Policy hooks in `/etc/github-copilot/policy.d` | Docs |

## Adapter (`crates/telltale/src/hooks/copilot_cli.rs`)

| Concern | Behavior | Evidence |
| --- | --- | --- |
| Dialects | Both are parsed; every field is read under its camelCase and snake_case name, because some payloads mix them (`permissionRequest` always has `hookName`/`sessionId`, with snake_case agent fields under a PascalCase registration; `.claude/settings.json` `SubagentStart` has `sessionId`, `agentName` and snake_case agent fields, and no event name) | Capture (`subagent.jsonl`, `claude-settings-all.jsonl`) |
| Event name | PascalCase payloads name it (`hook_event_name`), `permissionRequest` too (`hookName`). camelCase payloads do not: it is inferred from the top-level keys Copilot sets, never from tool arguments. A tool payload without `toolResult` or `error` is a `preToolUse` (fails safe). Tested against the registered event of every captured line | Capture, contract tests |
| Correlation | `runtime::synthetic_call_id(session, agent, tool, raw toolArgs)`; post events repeat `toolArgs` byte for byte. `permissionRequest` gets no key (its `toolInput` differs) | Capture, E2E |
| Session and agent | Inside a subagent `sessionId` is the subagent's ID, so the session is `parentAgentId` when present and the subagent is `agent_id`: subagent calls share the parent's journal and ledger (download in the parent, execute in the child correlates), as in Claude Code. A nested subagent (unverified that Copilot allows one) would get its immediate parent as session | Capture, E2E |
| Deny, ask | Flat `{"permissionDecision", "permissionDecisionReason"}` on `preToolUse` and `PreToolUse`: the one form honored on both dialects, so the parsed path and the payload-less path (`render_verdict`) agree. Never `allow` | E2E |
| Ask capability | `CAN_ASK = true`: an ask is shown to the user interactively (also with `--allow-all-tools` and `--yolo`) and refused in `-p`, `--yolo -p` and autopilot ("unable to ask user for confirmation"). No tested mode runs an asked call without a human. ACP mode is untested (follow-up: drive `--acp` with an auto-approving client; if it approves a hook ask, `can_ask` must become false or per-mode) | E2E |
| Settlement | `agentStop`/`Stop` is `Event::TurnSettled` for the agent that stopped (a subagent's own stop carries its `agentId`). Copilot has no turn ID (`prompt_id` is `None`). Post events precede their turn's stop in every capture | Capture, E2E |
| Results | `postToolUse` is `Completed` (a non-zero shell exit is still a success here), `postToolUseFailure` is `Failed`; result text is `textResultForLlm`. A flagged result gets `{"additionalContext": ...}`, which Copilot appends to what the model sees | E2E |
| Subagent prompt | A `userPromptSubmitted` inside a subagent is the task prompt the parent model wrote, so it is recorded as `other`, not journaled as user input | Capture |
| Not registered | `permissionRequest` fires for every call before Copilot's permission service and carries no decision we need (parsed and recorded as `permission_prompt` if registered); `errorOccurred`, `notification`, `preCompact` and `userPromptTransformed` are recorded as `other` when the payload names them (`userPromptTransformed` is also inferred from its keys) | Capture, Docs |
| Unrecognized payload | Valid JSON that names no event and matches none could be a `preToolUse` whose fields changed, so it exits 1 with nothing on stdout: Copilot blocks a `preToolUse` on that, and other events continue. This also applies to a nameless event that the hook file does not register, such as a camelCase `errorOccurred` | Contract tests; exit behavior E2E (`fail-exit1`, `fail-config`) |
| Unusable payload | A `preToolUse` missing fields, or truncated, gets the stricter of `on_error` and `on_unevaluable` on stdout (exit 0), including through the Claude Code entry point. Any other unreadable payload exits 1, whatever `on_error` says. Residual: a truncated, nameless payload at the Claude Code entry point exits 2 under `on_error = "deny"`, and exit 2 on a stop event is untested here | Contract tests (`tests/cli/hooks_unreadable_payloads.rs`); the answer forms E2E |
| Hook timeout | 60 s for tool events, 30 s for lifecycle events (Copilot's default is 30 s). Worst case is the evaluator's request deadline (10 s by default) or a cold in-process pipeline build (about 0.7 s) | Docs, E2E |
| Input shapes | Passed through as reported (raw-string `apply_patch`, `file_text`, `view`); the runtime normalizes for evaluation | Capture |

### Residual: a hook timeout lets the call run

Copilot fails **open** when a hook times out, for every event including
`preToolUse` and policy hooks, and no setting changes that (Docs; E2E
`timeout`: a deny that arrives after `timeoutSec` is ignored and the call
runs). The hook file sets 60 s, well above the worst case. If an operator
raises `[evaluator] request_timeout_ms` past that, or the machine is badly
overloaded, a slow evaluation is an allow. Invalid hook output is also
fail-open in Copilot; telltale-hooks never prints invalid JSON.

### Repository `.claude/settings.json` under Copilot

A trusted folder's `.claude/settings.json` hooks run under Copilot with
Copilot payloads (PascalCase names and fields, Copilot argument keys,
`permissionRequest`'s camelCase shape). The Claude Code entry point
(`telltale hooks claude-code hook`) recognizes them and hands them to this
adapter, so telemetry says `copilot-cli`, keys are synthetic and the runtime
treats them as Copilot input. The discriminator: every Copilot payload carries
`timestamp` and none carries a call or turn ID, while Claude Code 2.1.318
never sends `timestamp` or `sessionId` and sends `tool_use_id` on tool events
and `prompt_id` on every event but `SessionStart`; a `sessionId` payload is
always Copilot's. Every Claude Code and Copilot fixture is classified
correctly (contract tests). The decision is still rendered as Claude's
`hookSpecificOutput`. Copilot honors that form on PascalCase events for both
verdicts: deny blocks the call, and ask is refused in `-p` and put to the user
interactively (E2E `claude-settings`, `claude-settings-ask*`). Default
`on_unevaluable` blocks there too, for input past the projection budget and
for a payload past the 32 MiB limit (E2E `claude-settings-unevaluable`,
`claude-settings-oversized`, each with a control that runs when the policy is
`allow`). Copilot also sets `COPILOT_CLI=1` and `CLAUDE_PROJECT_DIR`
in the hook environment, but that is not used: a Claude Code launched from a
Copilot shell would inherit it, and the long-lived evaluator never sees the
hook's environment.

Limits of this route: telemetry cannot say which entry point was used (no
field fits), and the Claude Code fragment registers no `Stop`, so a call
denied or declined there is settled only at `SessionEnd`, as `unknown`. Install the
Copilot hook file instead of relying on it.

### Self-protection paths

[`copilot-cli-self-protection.yaml`](../../../crates/telltale/src/hooks/rules/copilot-cli-self-protection.yaml)
covers the files that change Copilot's hooks, in POSIX and Windows forms:
`$COPILOT_HOME/hooks/` (default `~/.copilot/hooks/`), `~/.copilot/settings.json`
(inline `hooks`), `.github/hooks/`, `.github/copilot/settings.json` and
`settings.local.json` (inline `hooks`, `disableAllHooks`), `.claude/settings.json`
and `settings.local.json`, `/etc/github-copilot/policy.d/`
(`C:\ProgramData\GitHub\Copilot\policy.d\`), custom agent definitions with
`hooks` frontmatter under `$COPILOT_HOME/agents/`, and plugin `hooks.json` under
`.plugin`, `.claude-plugin`, `.github/plugin`, the home, or a relative path that starts
at `plugin/` or `plugins/`. Writing under `.github/agents/` asks instead: a definition
there can carry hooks too, but writing one is ordinary repository work. A relaunch with another
`COPILOT_HOME` skips user-level hooks (policy hooks still run) and is denied in
every launch form, as is `npx @github/copilot`. Copilot 1.0.105 has no flag that
turns hooks off (`--help`). A home named only by a literal path is covered through
the hook's own `COPILOT_HOME`.

Verified with real Copilot 1.0.105 and a scripted model. The Windows
forms and the plugin layout are not verified at runtime; the layout comes from
Copilot's bundled code at 1.0.56 and the plugin it ships at 1.0.105. In `-p` an ask
is a refusal, so an agent there still cannot write an agent definition: that is the cost of
those files being able to carry hooks.
