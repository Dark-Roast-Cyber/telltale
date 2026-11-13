# Harness capability matrix

Evidence levels: **E2E** = verified by a real harness run in this repository
(canary method); **Capture** = observed in captured payloads; **Bin** =
confirmed in the shipped binary; **Docs/Src** = from official docs or pinned
source via desk research (full report);
**3P** = third-party only; **?** = unknown.

## Implementation status

| Harness | Version pinned | Adapter | Real enforcement tests |
| --- | --- | --- | --- |
| Claude Code | 2.1.318 | Implemented | Yes ([results](e2e/2026-11-04-claude-code-2.1.318.md)) |
| GitHub Copilot CLI | 1.0.105 | Implemented | Yes, scripted model ([results](e2e/2026-11-04-copilot-cli-1.0.105.md)); real-model run pending () |
| OpenAI Codex CLI | 0.166.0 (rust-v0.166.0) | Implemented | Yes, scripted model; real-model run pending ([results](e2e/2026-11-04-codex-cli-0.166.0.md)) |
| OpenCode | 1.19.5 / 2.2.5 | Not started | Plugin contract only: capture plugins, scripted model ([contract](harnesses/opencode.md)) |
| Cursor | unpinned | Not started | — |
| Gemini CLI | 0.66.0 | Not started | — |
| OpenClaw | 2026.10.10 | Not started | — |
| Hermes Agent | 0.19.0 | Not started | — |

## Claude Code 2.1.318

| Capability | Status | Evidence |
| --- | --- | --- |
| Pre-execution interception (`PreToolUse`) | Yes, fires before permission rules | Capture (deny-ruled `rm` still hit PreToolUse) |
| Pending call in transcript at PreToolUse | **No** | Capture |
| Hook `deny` enforced | Yes, default mode | E2E |
| Hook `deny` enforced in `bypassPermissions` | Yes | E2E |
| Hook `deny` enforced in subagents | Yes, payload has `agent_id`/`agent_type` | E2E, Capture |
| `ask` | Yes; headless `-p` declines (no approver); interactive approval runs the call and settles `proceeded_after_ask` | E2E (headless and tmux-driven interactive) |
| Decision values | allow, deny, ask, defer (`defer` ends a `-p` turn with `stop_reason: tool_deferred`; call not run) | Bin, E2E |
| Post-execution | `PostToolUse` (result), `PostToolUseFailure` (non-zero exit, `error`, `is_interrupt`), `PostToolBatch` (all calls, incl. denied, with the text the model saw) | Capture |
| Permission prompt notification | `PermissionRequest`, no `tool_use_id`, fires in `-p` | Capture |
| Default failure behavior | Fail-open on crash/non-zero exit | E2E |
| Fail-closed option | `onFailure: "block"` on the **hook entry**; ignored at matcher level | E2E, Bin |
| Hooks disabled by agent-reachable means | `--bare` / `CLAUDE_CODE_SIMPLE` disables settings, flag, policy and plugin hooks; editing settings files | Bin; mitigated in part by rules |
| Admin lock-down | Managed settings, `allowManagedHooksOnly` | Bin, Docs |
| MCP tools | `mcp__<server>__<tool>`, `mcp_server: {name, source}` in `PreToolUse`/`PostToolUse`/`PostToolBatch`; arguments evaluated; deny honored | E2E, Capture |
| Classifier denial (`PermissionDenied`) | Fires only for auto-mode classifier denials (not hook denies, not deny rules); payload `tool_use_id`, `reason`, `mcp_server` | Docs (3 headless probes did not trigger it) |
| Default hook timeout | 600 s (fragment sets 30 s on tool events) | Docs |
| Hook timeout shorter than run time | Hook killed, call runs (fail-open, no decision); `onFailure: "block"` on the hook entry blocks the call | E2E |

### Which tool paths reach `PreToolUse` (2.1.318)

| Tool or path | `PreToolUse` fires | Evidence |
| --- | --- | --- |
| `Bash`, `Read`, `Write`, `Edit`, `Agent` | Yes | Capture, E2E |
| `mcp__<server>__<tool>` | Yes, plus `ToolSearch` when the tool is deferred | Capture, E2E |
| `WebSearch`, `WebFetch` | Yes (client-side tool wrappers; `PostToolUse` carries the result) | E2E |
| `ToolSearch` | Yes | Capture |
| `@file` mention in the prompt | **No**: content inserted at prompt build time, no `Read` call (`CLAUDE_CODE_DISABLE_FILE_MENTIONS=1` forces a tool call) | E2E, Docs |
| `TodoWrite` | n/a in `-p` (tool unavailable); interactive unverified | E2E |
| `Glob`, `Grep` | Unverified: the model substituted `Bash` in the probe | E2E (inconclusive) |
| `EndConversation` | **No** | Docs |
| `/skill` typed directly | **No** for the `Skill` tool (`UserPromptExpansion` covers it) | Docs |
| Calls rejected by input validation | **No** (neither `PreToolUse` nor `PostToolUseFailure`) | Docs |

## Codex CLI 0.166.0 (adapter)

E2E here means: real Codex 0.166.0, this adapter, Linux x86-64, a **scripted
model**, canary checked ([results](e2e/2026-11-04-codex-cli-0.166.0.md)).
It says how Codex enforces the adapter's output, not how a real model behaves.
Unless a row names another path, hooks were trusted with
`--dangerously-bypass-hook-trust` and decisions were served in-process.

| Capability | Status | Evidence |
| --- | --- | --- |
| Adapter deny enforced, bypass flag | Yes (`hookSpecificOutput` deny, non-empty reason), main agent and subagent | E2E |
| Adapter deny enforced, documented install | Yes: hooks trusted through the real TUI startup review in a pty, then `codex exec` with no bypass flag. The `/hooks` browser and a turn inside the TUI were not exercised | E2E (`trusted`) |
| Deny served by the autostarted evaluator | Yes, once it is up; the first hook autostarts it and falls back in-process | E2E (`deny-evaluator`) |
| `apply_patch` deny | Yes: a patch writing `.codex/hooks.json` is denied after runtime normalization and the file is not created; a benign patch applies | E2E (`patch-deny`, `patch-allow`) |
| Policy `ask` | Returned as deny (Codex cannot ask; a returned ask would run) | E2E |
| Allow | Nothing printed, call runs | E2E |
| Correlation | `session:agent:turn:tool_use_id`, escaped; settled by PostToolUse, `Stop`, `SubagentStop` | E2E, Capture |
| Hook failure (crash, timeout, missing binary) | **Fails open**, no option | E2E |
| Damaged hook payload, tool call | Answered on stdout with the stricter of `on_error` and `on_unevaluable`, and honored. Naming no event: denied under `on_error = "deny"`, otherwise exit 1, so the call runs | E2E (`damaged-pre-*`, `damaged-all-renamed`, via a wrapper that damages stdin) |
| Damaged hook payload, `Stop` | Exits 1 or gets an inert deny, so no continuation prompt and the turn ends | E2E (`damaged-stop-*`) |
| Untrusted hook | Never runs (install needs the one-time trust step) | E2E |
| Trust scope | Per handler: changing a handler un-trusts it and the call runs; reformatting or editing another handler does not; replacing the program at a trusted path keeps trust | E2E |
| `settings --fail-closed` | Refused (no Codex equivalent) | Test |
| Exec-policy backstop | Refuses plain nested Codex launches with the hook absent; literal, and indirect launches escape | E2E |
| Agent removing the protections, healthy hook | **Partly allowed by default:** some configuration and launch-option edits are not covered yet (tracked privately) | Binary probe |
| Real model | Pending | — |
| Interactive use (a turn inside the TUI) | Unverified | — |
| macOS, Windows | Unverified | — |

## Copilot CLI, Codex CLI, OpenCode (hook contract verified)

E2E here means the real harness binary, stub hooks (or capture plugins), and
the canary file checked. The model is scripted (`scripts/hooks/harness/mock-model.py`),
so the results cover harness enforcement, not adapter enforcement. The Copilot
CLI column is also verified with telltale-hooks itself as the hook
([results](e2e/2026-11-04-copilot-cli-1.0.105.md)): deny
in default, `--yolo`, autopilot, PascalCase and subagent runs, ask in every
mode, fail-closed on a missing or failing hook and on invalid configuration.
Details, payloads and fixtures: [harness contracts](harnesses/README.md).

| Capability | Copilot CLI 1.0.105 | Codex CLI 0.166.0 | OpenCode v1 1.19.5 | OpenCode v2 2.2.5 |
| --- | --- | --- | --- | --- |
| Pre-execution interception | `preToolUse` / `PreToolUse` (E2E) | `PreToolUse`; user hooks need trust or they never run (E2E) | `tool.execute.before` (E2E) | `tool.execute.before`, `permission.evaluate` (E2E) |
| Shell command shape | `{command: string}` (Capture) | `Bash {command: string}`; argv tools unsupported (Capture) | `bash {command: string}` (Capture) | `shell {command: string}` (Capture) |
| Patch shape | raw string, no path (Capture) | `apply_patch {command: <patch>}`, no path (Capture) | `apply_patch {patchText}` (Capture) | `patch {patchText}`; paths only in `permission.evaluate` (Capture) |
| Stable call ID pre/post | **No** (Capture) | `tool_use_id` + `turn_id` (Capture) | `callID` (Capture) | `id`; reused by Code Mode inner calls (Capture) |
| Deny honored | flat deny or exit 2; hso on PascalCase only (E2E) | hso deny, `decision: block`, exit 2 + stderr (E2E) | throw (E2E) | throw, `Tool.Error`, evaluate `deny` (E2E) |
| Deny in subagents | Yes (E2E) | Yes (E2E) | Yes (E2E) | Yes (E2E) |
| Ask | `-p`: blocks; interactive: prompts the user, also with `--yolo`, in the flat form and in Claude's form on PascalCase (E2E); `--acp`: unknown; cloud agent: ask becomes deny (Docs) | **No: call runs** (E2E) | **No** (`permission.ask` never fires) (E2E) | evaluate `ask`: `--auto` approves, plain `run` rejects (E2E) |
| Hook allow loosens native permissions | **Yes**, even over `--deny-tool` (E2E) | No (exec-policy rules hold) (E2E) | No (no allow path) (E2E) | **Yes** over native ask; no over native deny (E2E) |
| Failure default | exit 1 / crash / missing: closed; invalid output / timeout: open (E2E) | open for every failure, no fail-closed option (E2E, Src) | load failure: silently skipped; hang: session hangs (E2E) | same as v1 (E2E) |
| Default timeout | 30 s, fail-open (E2E, Docs) | 600 s, fail-open (E2E at 3 s, Src) | none (E2E) | none (E2E) |
| Post event for executed calls | `postToolUse`, `postToolUseFailure` (Capture) | `PostToolUse` for any exit code (Capture) | `tool.execute.after` (completed only) (Capture) | `execute.after` with `status` (Capture) |
| Post event for hook-denied calls | **No** (Capture) | **No** (Capture) | No; part `state: error` event (Capture) | No `after`; `session.tool.failed` event (Capture) |
| Batch / turn settlement | `agentStop` per turn, no call list (Capture) | `Stop` per turn with `turn_id`, no call list (Capture) | per-call part state + `session.idle` (Capture) | per-call `session.tool.*` + `session.execution.*` (Capture) |
| MCP tools | `<server>-<tool>` (Capture) | `mcp__<server>__<tool>` (Capture) | `<server>_<tool>` (Capture) | only via Code Mode `execute`; inner call hooked (E2E) |
| Agent-reachable disable | trusted repo `disableAllHooks` (E2E) | `--disable hooks` (Src), change a hook handler (un-trusts) (E2E) | `run --pure` (E2E), config edits | config / plugin dir edits (Docs) |
| Admin lock-down | `/etc/github-copilot/policy.d` (Docs) | `requirements.toml` managed hooks, `allow_managed_hooks_only` (Src) | managed config (Docs) | managed config, `policies` (Docs) |

## Other harnesses (desk research, not yet verified here)

| Harness | Pre-exec block | Ask | Failure default | Fail-closed option | Notes |
| --- | --- | --- | --- | --- | --- |
| Cursor | Yes | Yes | Open | `failClosed` (3P) | Evidence is third-party only |
| Gemini CLI | Yes (`BeforeTool`) | No | Open | No | Code and docs disagree on exit codes |
| OpenClaw | Yes (`before_tool_call`) | Yes | Closed | default | Gateway architecture |
| Hermes Agent | Yes (`pre_tool_call`) | Yes | Plugins closed, shell hooks open | `fail_closed` | |

Advisory permission handling is not enforcement: a harness is listed as
enforcing only when a real run shows the denied call did not execute.

Hosted and remote platforms (Claude Code Cloud, Antigravity, OpenAI, xAI,
Copilot cloud agent, Cursor, Devin) are covered separately in
research/hosted-platforms.md.
