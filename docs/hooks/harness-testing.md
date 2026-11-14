# Real-harness tests

`scripts/hooks/harness/claude-code-e2e.sh` runs real, isolated, headless Claude Code
sessions with `telltale hooks` registered and checks that the harness actually
honored each decision (canary method). It costs model tokens: one short
session per scenario. Run it after changes to the adapter, policy or
enforcement rendering, and when bumping the Claude Code pin; commit the
summary under `docs/hooks/e2e/`.

```bash
cargo build --release
```

```bash
scripts/hooks/harness/claude-code-e2e.sh            # all scenarios
```

```bash
scripts/hooks/harness/claude-code-e2e.sh deny tamper  # selected scenarios
```

Requirements: `claude` on `PATH` and model access. Two ways to get it:

- **host** (Claude Code Cloud): the container's host-managed provider
  variables are passed through; each run gets a disposable `HOME`.
  Selected automatically when `CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST` is set.
- **local** (a workstation where `claude` is logged in): the real `HOME` is
  kept so the stored login resolves, `--setting-sources project` keeps the
  user's own settings, hooks and MCP servers out of the run (the disposable
  working directory has no project settings), and the test settings are
  injected with `--settings`. Scenario commands never name a real user file:
  `__HOME__` in a command expands to the run's fake home. The user's
  `~/.claude` is not modified; Claude Code writes only its usual transcript
  for the disposable working directory. Force with `E2E_AUTH=host|local`.

`IS_SANDBOX=1` is set only for the `bypass` scenario, which the container
runs as root.

## Scenarios

| Scenario | Checks |
| --- | --- |
| `benign`, `deny`, `ask`, `bypass`, `subagent`, `tamper`, `chain`, `bare`, `exfil` | Enforcement of hook decisions (see `results/2026-11-04-claude-code-2.1.318.md`) |
| `noexec-tamper`, `noexec-bare`, `noexec-ask` | Tamper-shaped commands with an empty allow list, so no shell can run them even if the hook fails: `-p` mode declines. An absent canary proves nothing here. They pass on telemetry (verdict, `returned`, rule ID) and the hook's reason in `permission_denials` or the transcript, which shows the decision reached the harness. The marker scenarios are the evidence that it honors one |
| `failopen`, `failblock-hook`, `failblock-matcher` | Hook crash: fail-open default, `onFailure: "block"` placement |
| `mcp-benign`, `mcp-deny` | MCP tool calls through a disposable stdio server; the deny marker travels in a tool argument. Both record raw payloads (`hooks.jsonl`) for fixtures |
| `timeout-open`, `timeout-block` | Hook `timeout` (1 s) shorter than the hook's run time, without and with `onFailure: "block"` |
| `defer` | A hook answering `defer` in `-p` mode (`stop_reason: tool_deferred`) |
| `permdenied` | Auto mode (`--permission-mode auto`) with telltale-hooks in observe mode, recorder on `PermissionDenied` |
| `nofire-mention`, `nofire-builtin`, `nofire-web` | Which tool paths reach `PreToolUse` (`@file` mentions, TodoWrite/Glob/Grep, WebSearch/WebFetch) |

`scripts/hooks/harness/claude-code-interactive-ask.sh [approve|decline]` drives a
real interactive session in a detached tmux pane (local mode only): the model
asks for the ask-marker command, telltale-hooks answers `ask`, Claude Code
shows its permission prompt with the hook's reason, the script approves it,
and the outcome must settle as `proceeded_after_ask`.

## Codex CLI adapter

`scripts/hooks/harness/codex-cli-e2e.py` runs the real Codex CLI against this
adapter in a disposable `CODEX_HOME` per scenario. The model is scripted
(`mock-model.py` as a custom Responses-API provider), so it needs no OpenAI
credentials and costs no tokens; it never reads or writes `~/.codex`, and it
points Codex at a dead proxy so the loopback mock is all it can reach. It covers
deny (main agent, subagent, `apply_patch`, autostarted evaluator), ask returned
as deny, allow, the fail-open residuals (crash, timeout, missing binary,
untrusted) and the exec-policy backstop
(`results/2026-11-04-codex-cli-0.166.0.md`).

The `damaged-*` scenarios put a wrapper in front of the hook that damages one
event's stdin, and pass only if the damage happened. They check a damaged tool
call is still answered, and a damaged `Stop` costs no extra model request.

The `trusted*` scenarios run the documented install with no bypass flag: they
start the real TUI in a pty and choose "Trust all and continue". The TUI's
app-server daemon and the evaluator need Unix sockets, so run those scenarios
outside any sandbox that blocks them.

```bash
CODEX_BIN=/path/to/codex scripts/hooks/harness/codex-cli-e2e.py [scenario ...]
```

## Files

- `scripts/hooks/harness/evaluator-driver.py <binary> <root> <mode>`: drives the real hook and
  `serve` with synthetic sessions and reads verdicts from telemetry, with no harness or
  model; `BUSY=N` loads the CPU. Commands go only to the hook's stdin.
- `e2e-marker-rules.yaml`: test-only Rule v1 markers (`TTH_E2E_DENY_MARKER`,
  `TTH_E2E_ASK_MARKER`) on `command` and `arguments`, and
  `TTH_E2E_RESULT_MARKER` in tool results, loaded through the normal
  `telltale.rules` config, so enforcement is tested independently of
  model-side refusals.
- `scripts/hooks/harness/mcp-canary-server.js`: dependency-free stdio MCP server
  with one tool, `touch_canary`, that creates the canary file.
- `scripts/hooks/harness/recorder.py`: records raw hook payloads for new contract
  fixtures (`E2E_RECORD=1` registers it next to the hook); sanitize with
  `scripts/hooks/sanitize-capture.py <hooks.jsonl> <run dir>`. The sanitizer
  rewrites the run directory and the capturing user's home directory, but
  not other directory names under that home: review a fixture's
  `transcript_path` and `cwd` before committing it.

## Copilot CLI enforcement (scripted model)

`scripts/hooks/harness/copilot-cli-e2e.py` runs the real Copilot CLI binary with
telltale-hooks registered from its own `copilot-cli settings` output, against
the scripted model below (no credentials, no tokens), and checks the canary,
telemetry and what each hook invocation printed. Interactive scenarios drive
Copilot's TUI under a pseudo-terminal, so the script is Unix-only
(`pty`, `termios`, `fcntl`). Unix sockets for the evaluator must be allowed
(`E2E_SOCKET_DIR` keeps their paths short).

```bash
COPILOT_BIN=/path/to/copilot scripts/hooks/harness/copilot-cli-e2e.py [scenario ...]
```

## Hook contract captures (Copilot CLI, Codex CLI, OpenCode)

Capture tooling, not adapters. It runs the real harness binaries against a
scripted model, so it needs no credentials and spends no model tokens. Stub
hooks record each payload and apply a configured decision to a canary call,
and the scripts check whether the harness honored it. Each run gets a fresh
`HOME`/XDG/harness home under a temporary root, and the user's harness
configuration is never read or written.

```bash
COPILOT_BIN=/path/to/copilot scripts/hooks/harness/capture-copilot.py [scenario ...]
CODEX_BIN=/path/to/codex     scripts/hooks/harness/capture-codex.py [scenario ...]
OPENCODE_V1_BIN=/path/to/opencode scripts/hooks/harness/capture-opencode.py v1 [scenario ...]
OPENCODE_V2_BIN=/path/to/opencode scripts/hooks/harness/capture-opencode.py v2 [scenario ...]
```

Each scenario writes `hooks.jsonl`, `model-requests.jsonl`,
`tool-results-seen.json` and `summary.json` (canary verdict) under
`$CAPTURE_ROOT/<scenario>/`. Turn a capture into a fixture with
`scripts/hooks/sanitize-capture.py --envelope [--only REGEX] <hooks.jsonl> <run-dir>`.

- `mock-model.py`: scripted OpenAI-compatible server (Chat Completions and
  Responses API, including custom/freeform tools) on loopback.
- `mock-mcp.py`: minimal stdio MCP server (`tthmock`, tool `echo`).
- `stubs/stub-hook.py`: command-hook stub (`<label> <mode>`). Modes: deny,
  ask and allow in flat and `hookSpecificOutput` forms, `block-legacy`, exit
  codes, crash, invalid output, sleep.
- `opencode/{v1,v2}/tth-capture.js`: OpenCode capture plugins (`STUB_MODE`:
  throw, toolerror, hang, init-throw, perm-deny/ask/allow).
- `show-capture.py`: pretty-print a `hooks.jsonl`.
