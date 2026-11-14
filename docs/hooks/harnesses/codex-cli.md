# OpenAI Codex CLI: hook contract

Status: **adapter implemented** (`telltale hooks codex-cli hook`).
Enforcement is verified on the real 0.166.0 binary, on Linux x86-64 with a
scripted model, including the documented install: hooks trusted through the
real TUI, then `codex exec` with no bypass flag
([results](../e2e/2026-11-04-codex-cli-0.166.0.md)). Not
verified: a real model, macOS, Windows. The contract below was verified against
`@openai/codex` **0.166.0** (Linux x86-64; source `rust-v0.166.0`) with stub
hooks and a scripted model on a custom Responses-API provider. Evidence:
`crates/telltale/tests/hooks/fixtures/codex-cli/0.166.0/` and `scripts/hooks/harness/capture-codex.py`.

## Configuration and scope

| Layer | Location | Trusted without review? |
| --- | --- | --- |
| System / MDM / cloud-managed | `requirements.toml` managed hooks, system `config.toml` | Yes (managed) (Src) |
| User | `$CODEX_HOME/hooks.json` or `[hooks]` in `$CODEX_HOME/config.toml` | **No**: needs trust state (Src, E2E) |
| Project | `.codex/hooks.json` / `.codex/config.toml` in a trusted project | No (Src) |
| Session flags | `-c hooks...` | No (Src) |
| Plugins | Plugin hook sources, with plugin trust | Src |

The format is Claude-style:
`{"hooks":{"PreToolUse":[{"matcher":..., "hooks":[{"type":"command","command":...,"timeout":N}]}]}}`.

Per-run injection: set `CODEX_HOME` to a disposable directory holding
`hooks.json` and `config.toml`. **Untrusted user hooks do not run**: with no
trust state and no `--dangerously-bypass-hook-trust`, the stub never ran and
the canary executed (E2E). Trust is per handler: the record's key is the file
path, event and position, and it holds a hash of that handler's normalized
identity (event, matcher, handler fields), not of the file (Src: the Codex hook discovery code).
Changing a handler un-trusts it, which fails open; reformatting the file or
editing another handler does not (E2E). Moving a handler orphans its record
(Src). The hash covers the command text, not the program it names, so replacing
the binary at a trusted path keeps trust (E2E).
`requirements.toml` `allow_managed_hooks_only = true` restricts hooks to
managed sources (Src).

## Payloads (Capture)

PreToolUse:
`{session_id, turn_id, transcript_path, cwd, hook_event_name, model, permission_mode, tool_name, tool_input, tool_use_id}`.
Subagent calls add `agent_id` and `agent_type`. `permission_mode` is
`bypassPermissions` under `--dangerously-bypass-approvals-and-sandbox`.

| Tool | `tool_name` | `tool_input` |
| --- | --- | --- |
| Shell | `Bash` | `{command: string}`. Every tested model id gets `exec_command` with a string `cmd`. The argv tools `shell`/`shell_command` return "unsupported call" in 0.166.0 |
| Patch | `apply_patch` | `{command: "<patch text>"}`: the patch sits under the **`command` key**, and there is no path key |
| MCP | `mcp__<server>__<tool>` | tool arguments; PostToolUse `tool_response` is `{content, isError}` |
| Subagent | `spawn_agent` (namespace `multi_agent_v1`) | Src, Capture |

## Verified behaviors (0.166.0)

| Question | Answer | Evidence |
| --- | --- | --- |
| Call correlation | `tool_use_id` in PreToolUse and PostToolUse, plus `turn_id`. IDs come from the model and are not unique across agents, so key by `(session_id, agent_id, turn_id, tool_use_id)` | Capture |
| Deny | `hookSpecificOutput.permissionDecision: deny`, legacy `{"decision":"block"}`, exit 2 with stderr. Honored with bypass, exec defaults, workspace-write + on-request, and in subagents. Flat Copilot-style output is ignored. Model sees `Command blocked by PreToolUse hook: <reason>` | E2E |
| Ask | **Not supported: the call proceeds.** Parsed as an unsupported decision (hook status Failed, not a block), with no user-visible warning in `exec --json` | E2E, Src |
| Allow | Unsupported; no effect. Allow + `updatedInput` does **not** override exec-policy `forbidden`/`prompt` rules | E2E |
| Failure | exit 1, crash, invalid JSON, exit 2 with empty stderr, timeout, missing binary: **all fail-open**. No fail-closed option | E2E, Src |
| Post events | PostToolUse only for calls that executed, any exit code, no exit-code field. None for hook-denied, exec-policy-rejected, or verification-failed apply_patch calls. Unknown MCP tools never reach PreToolUse | Capture |
| Settlement | `Stop` per turn with `turn_id` and `last_assistant_message`, but no call list. A PreToolUse without a PostToolUse in the same `turn_id` by `Stop` is "not completed" (denied or failed: ambiguous) | Capture |
| Parallel | A denied call's parallel sibling still runs | E2E |
| Subagents | `SubagentStart`/`SubagentStop` with `agent_id`/`agent_type` (`agent_transcript_path` on stop). The child keeps the parent `session_id`; deny is honored | E2E |
| Disable | `--disable hooks` / `-c features.hooks=false` (Src); changing a trusted handler (hash change) (E2E) | Src, E2E |
| Lockdown | Managed hooks in `requirements.toml` with `allow_managed_hooks_only` | Src |

## Adapter (`crates/telltale/src/hooks/codex_cli.rs`)

### Install

```bash
telltale hooks codex-cli settings > "${CODEX_HOME:-$HOME/.codex}/hooks.json"
```

`settings [COMMAND]` prints the `hooks.json` document on stdout (no matcher,
which matches every tool; PreToolUse/PostToolUse timeout 30 s, SessionEnd
3 s, Codex's maximum) and these steps on stderr:

1. Save it as `$CODEX_HOME/hooks.json`, or merge its `hooks` table.
2. **Trust it once**: start `codex` interactively and choose "Trust all and
   continue" (or review in `/hooks`). Untrusted user hooks never run and
   `codex exec` does not ask (E2E: `untrusted`). The picker writes one
   `[hooks.state."<key>"] trusted_hash` per handler to
   `$CODEX_HOME/config.toml`; see [trust semantics](#configuration-and-scope)
   for what un-trusts one. Verified (E2E: `trusted`): the real TUI in a pty,
   startup review reporting 9 new hooks, Down then Enter on "Trust all and
   continue", 9 records written, then `codex exec` with no bypass flag honored a
   deny. Not exercised: the `/hooks` browser, a human's terminal, and a turn
   run inside the TUI itself (the deny was checked under `codex exec`).
   Automation can pass `--dangerously-bypass-hook-trust`, which also runs every
   other enabled, untrusted hook.
3. Optional native backstop (below): `mkdir -p $CODEX_HOME/rules`, then
   `telltale hooks codex-cli execpolicy > $CODEX_HOME/rules/telltale-hooks.rules`.

`settings --fail-closed` prints nothing and exits non-zero with an
explanation: Codex has no fail-closed option, so no `hooks.json` can make
this hook fail closed. Managed hooks (`requirements.toml`,
`allow_managed_hooks_only`) need no trust step and cannot be removed by the
user; they belong to managed deployment.

### Mapping

| Codex event | Runtime event | Notes |
| --- | --- | --- |
| `PreToolUse` | `ToolRequested` | Input reported as Codex sent it (`apply_patch {"command": patch}` included); the runtime normalizes the evaluation encoding (`normalize::CODEX_CLI`, ADR 0002 addendum) |
| `PostToolUse` | `ToolFinished` | `Completed`, because Codex reports no exit code for shell calls; `Failed` only for an MCP `isError: true` or an `apply_patch` result headed `Exit code: N` (N other than 0) |
| `Stop` | `TurnSettled` | Main agent (no `agent_id`), scoped to its `turn_id` |
| `SubagentStop` | `TurnSettled` | Carries the subagent's `agent_id` and `turn_id`, so a parent `Stop` never settles a subagent's calls and a subagent's calls are still settled. **Differs from Claude Code:** no `subagent_stop` lifecycle record is written. It shows only as `established_by: SubagentStop` on outcomes it settles, so a subagent that ends with nothing pending leaves no record of stopping |
| `SubagentStart` | `SubagentStart` | |
| `PermissionRequest` | `PermissionPrompt` | Recorded, never answered |
| `UserPromptSubmit`, `SessionStart`, `SessionEnd` | as named | |
| anything else | `Other` | |

`Context::prompt_id` is `turn_id`; `Context::can_ask` is always `false`.

**Correlation key.** `tool_use_id` is model-supplied and repeats across
agents (a subagent's first call and the parent's are both `call_0_0_0`), so
the key is `session:agent:turn:tool_use_id` (main agent empty), with every byte
outside `[A-Za-z0-9_-]` percent-encoded in each component. Encoding is required,
not cosmetic: Telltale rejects a native ID containing `/`, `\`, `..`, LF or CR
and fails the whole journal source, which makes every later call in the session
unevaluable (regression-tested with those, NUL and non-ASCII). A missing
`tool_use_id` falls back to the runtime's synthetic key: `PermissionRequest`
never has one (its schema has no such field), and `PreToolUse` and `PostToolUse`
always did in the captures.

**Deny.** Rendered only as
`{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"..."}}`,
the form Codex honored in every tested mode and in subagents. The reason is
never empty (Codex ignores a deny without one: Src, `output_parser.rs`). This
is the same shape as Claude Code, so the driver and the evaluator need no
per-harness exit codes; exit 2 with stderr also works but fails open when
stderr is empty. The model sees `Command blocked by PreToolUse hook: <reason>`
(E2E).

**A payload the hook cannot use.** No exit code is safe here: Codex runs a call
on exit 1, and turns exit 2 with stderr on a `Stop` into a prompt to continue
(Src: the Codex stop-event handler). So:

- A `PreToolUse` missing fields, or truncated with its name readable, gets the
  stricter of `on_error` and `on_unevaluable` on stdout. The default returns a
  deny (E2E: `damaged-pre-default`; `damaged-pre-allow` shows an operator's
  explicit `allow`).
- Any other named event exits 1, so a damaged `Stop` ends the turn normally (E2E:
  `damaged-stop-named`, `damaged-stop-mistyped`).
- A payload naming no event gets a deny on stdout under `on_error = "deny"`. Codex
  honors it on a `PreToolUse` and it has no effect on a `Stop` (E2E:
  `damaged-pre-nameless`, `damaged-stop-nameless`, and `damaged-all-renamed`, which
  renames the event key on every event). Under the default `on_error = "allow"` it
  exits 1, so if that payload was a tool call, the call runs.

Exit 2 on a damaged `Stop` was not theoretical: before this rule, one run made
3,586 model requests and was still looping when its 300 s limit ended it.

**Never ask, never allow.** `CAN_ASK = false`, so the runtime returns every
`ask` (policy, `on_unevaluable`, `on_error`, unanswered evaluator) as `deny`;
the renderer also writes any `ask` that reached it as a deny. `allow` prints
nothing.

**PostToolUse context.** A flagged result is answered with
`hookSpecificOutput.additionalContext` (Src: schema; not exercised E2E).

### Enforcement limits (stated, not hidden)

| Condition | Result | Evidence |
| --- | --- | --- |
| Hook crash, timeout, invalid output, missing binary | **The call runs.** No option changes it | E2E (`fail-crash`, `fail-timeout`, `fail-missing`) |
| Hooks not trusted | Hook never runs; the call runs | E2E (`untrusted`) |
| A trusted handler changed after install | That handler never runs; the call runs. `PostToolUse` handlers still trusted record `completed` / `no_decision` | E2E (`trusted-modified`) |
| Program replaced at a trusted path | Trust is kept, so the replacement runs as the hook | E2E (`trusted-binary-swap`) |
| Launch options and configuration overrides that start a Codex session without user hooks | Session runs without user hooks | Src |
| Parallel sibling of a denied call | Runs (separate call, separately evaluated) | E2E (capture) |
| **Healthy hook: the agent removes the protections.** `rm` or `mv` of `~/.codex/rules/telltale-hooks.rules` or `$CODEX_HOME/hooks.json`, a patch to them or to `/etc/codex/requirements.toml`, `codex --disable hooks`, `codex -c features.hooks=false exec ...`, `CODEX_HOME=<other> codex` | Denied | E2E `tamper-*`, and only while the hook runs |

### Exec-policy backstop (`telltale hooks codex-cli execpolicy`)

Codex exec-policy `forbidden` rules are checked natively before a shell
command runs, in every approval and sandbox mode, whether or not any hook ran,
and a hook `allow` cannot override them (E2E). The generated rules forbid
starting another Codex session (`codex`, any absolute path to it, and
`npx`/`pnpx`/`bunx`/`pnpm dlx`/`yarn dlx` `@openai/codex[@latest]`), the
common precondition of every hookless relaunch. Verified on 0.166.0 with the
hook binary missing: a plain hookless relaunch was rejected and the canary
was not created (E2E `execpolicy-backstop`).

Coverage is literal, by Codex's design: prefix rules match each **plain**
command Codex parses out of the script (split at `&&`, `||`, `;`, `|`). A
shell construct that makes Codex match the whole script instead of its plain
commands, and indirect launches (wrappers, nested shells, interpreters),
escape the rules. Exec policy never sees `apply_patch`, and a
prefix rule cannot match a path argument anywhere in a command, so these rules
do **not** cover config edits, including deleting the rules file itself. The
hook's self-protection rules cover those edits, but only while the hook runs
([limits above](#enforcement-limits-stated-not-hidden)); the real fix is managed
requirements. A syntax
error in any rules file makes Codex ignore all user rules; Codex validates
the generated `match`/`not_match` examples at load. Check with
`codex execpolicy check --rules <file> codex exec x`.

### Self-protection inputs ()

[`codex-cli-self-protection.yaml`](../../../crates/telltale/src/hooks/rules/codex-cli-self-protection.yaml)
and the launch rules in
[`telltale-hooks-self-protection.yaml`](../../../crates/telltale/src/hooks/rules/telltale-hooks-self-protection.yaml)
cover what disables or bypasses this hook. Source references are to
`codex-rs/` at rust-v0.166.0. Linux forms ran against real Codex 0.166.0. **Every Windows
form below comes from source only**: it is tested as rule text, not on Windows.

| Input | POSIX | Windows | Source |
| --- | --- | --- | --- |
| User home | `$CODEX_HOME`, `~/.codex` | `%CODEX_HOME%`, `%USERPROFILE%\.codex` | `utils/home-dir/src/lib.rs` |
| Hook files in a layer | `<layer>/hooks.json` | same | `hooks/src/engine/discovery.rs:178,394`, `config/src/state.rs:219-243` |
| Rules (the backstop) | `<layer>/rules/*.rules` | same | `core/src/exec_policy.rs:54-56,667-690` |
| User and profile config | `$CODEX_HOME/config.toml`, `<name>.config.toml` | same | `config/src/loader/mod.rs:131` |
| Project | `.codex/hooks.json`, `.codex/config.toml`, `.codex/rules/` | same | `config/src/state.rs:219-243` |
| Requirements | `/etc/codex/requirements.toml` | `%ProgramData%\OpenAI\Codex\requirements.toml` | `config/src/loader/mod.rs:113-114,807-816` |
| System config | `/etc/codex/config.toml` | `%ProgramData%\OpenAI\Codex\config.toml` | `config/src/loader/mod.rs:80,127-128,835-838` |
| Legacy managed config | `/etc/codex/managed_config.toml` | ignored on Windows | `config/src/loader/mod.rs:116-121`, `layer_io.rs:74-100` |
| Requirements override | none | `HKLM\SOFTWARE\Policies\OpenAI\Codex` `RequirementsPath` | `config/src/loader/mod.rs:819-832` |
| Turn hooks off | `--disable hooks`, `-c features.hooks=false` (legacy `codex_hooks`), `codex features disable hooks` | same | `cli/src/main.rs:966,1959`, `features/src/lib.rs:1433`, `features/src/legacy.rs:49` |
| Skip trust records or rules | `exec --ignore-user-config`, `exec --ignore-rules` | same | `exec/src/cli.rs:45-50` |
| Other launches | `CODEX_HOME=<other> codex`, `npx`, `bunx`, `pnpm dlx @openai/codex` | `$env:CODEX_HOME=...; codex`, `set CODEX_HOME=...&& codex` | `utils/home-dir/src/lib.rs` |

macOS managed preferences are not a bypass an agent can use: only forced preferences
count, and `defaults write` does not force them (`config/src/loader/macos.rs:1,34`).

**`--dangerously-bypass-hook-trust` has its own rule, `hook_trust_bypass`,** rather than
joining `hookless_harness_launch`. Hooks stay on with this flag, this one included, so
"hookless" would be false in telemetry and in the deny reason. What it does is run every
enabled hook whether or not anyone reviewed it (`hooks/src/engine/discovery.rs:918`), so a
hook the agent planted in a project would run. `--ignore-user-config` skipping the trust
records is an inference from where they are stored, not a run.

**Custom homes.** The static rules know `$CODEX_HOME`, `${CODEX_HOME}`, `%CODEX_HOME%`
and `$env:CODEX_HOME`. A literal path gets rules generated from the hook's own
`CODEX_HOME`, which Codex passes to hooks (E2E `tamper-custom-home`). Some
spellings of a home are not covered (tracked privately).
