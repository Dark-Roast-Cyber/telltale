# GitHub Copilot CLI 1.0.105 hook payload captures

Authentic hook stdin payloads from the real Copilot CLI binary, driven by a
scripted model. Contract evidence for a future Copilot adapter; do not
edit payload fields by hand. Re-capture with `scripts/hooks/harness/capture-copilot.py`.

| Item | Value |
| --- | --- |
| Harness | `@github/copilot` `1.0.105` (npm, lockfile sha512 verified), Linux x86-64 |
| Captured | 2026-11-04 |
| Model | Scripted OpenAI-compatible mock (`scripts/hooks/harness/mock-model.py`) on loopback via BYOK (`COPILOT_PROVIDER_BASE_URL`, `COPILOT_OFFLINE=true`). No credentials, no model tokens. The requested model id selects Copilot's tool set: a Claude id for `lifecycle`, `gpt-5.4` for `lifecycle-patch` |
| Run | `copilot -p <prompt> --no-auto-update --disable-builtin-mcps --allow-all-tools` (unless the file notes otherwise), plus a stdio MCP server `tthmock` (`scripts/hooks/harness/mock-mcp.py`) |
| Isolation | Fresh `HOME`, `COPILOT_HOME`, XDG dirs and working directory per run; the user's `~/.copilot` was never read or written |
| Hooks | `scripts/hooks/harness/stubs/stub-hook.py` registered in `$COPILOT_HOME/hooks/tth-capture.json` (`version: 1`) |
| Sanitizer | `scripts/hooks/sanitize-capture.py --envelope`: run directory rewritten to `/home/synthetic/run` |

Each line is `{"event", "stub", "payload"}`. `event` is the registered event
name. `Pascal:<Event>` marks the PascalCase (Claude-compatible) registration,
and `claude:<Event>` marks a hook read from the repository's
`.claude/settings.json`. `stub` is the stub's mode when it acted on the canary
call (`noop` otherwise). The stub only acts when stdin contains `TTH_CANARY`.
The canary command is `touch <run>/work/canary.txt && echo TTH_CANARY`.

## Files

| File | Scenario | Canary result |
| --- | --- | --- |
| `lifecycle.jsonl` | camelCase and PascalCase registrations side by side: bash, view, create, edit, failing bash, two parallel bash, grep, blocked web_fetch (`postToolUseFailure`), MCP `tthmock-echo`, canary | ran (noop) |
| `lifecycle-patch.jsonl` | `gpt-5.4` tool set: freeform `apply_patch` (add, update) and `rg`; `toolArgs` is a raw patch string | n/a |
| `deny-flat.jsonl` | camelCase `preToolUse` prints `{"permissionDecision":"deny",...}` | **blocked** |
| `deny-pascal-hso.jsonl` | PascalCase `PreToolUse` prints Claude `hookSpecificOutput` deny | **blocked** |
| `deny-camel-hso.jsonl` | camelCase event prints Claude `hookSpecificOutput` deny | ran: output ignored |
| `deny-exit2.jsonl` | exit 2 with stderr | **blocked** |
| `ask-flat.jsonl` | `permissionDecision: ask` in `-p` | blocked ("unable to ask user") |
| `allow-vs-denytool.jsonl` | hook `allow` with `--deny-tool=shell` | **ran**: hook allow overrides the CLI deny |
| `fail-exit1.jsonl` | hook exits 1 | blocked (fail-closed) |
| `fail-invalid.jsonl` | hook prints invalid JSON | ran (fail-open) |
| `fail-timeout.jsonl` | hook sleeps past `timeoutSec: 3` | ran (fail-open) |
| `subagent-deny.jsonl` | `task` subagent runs the canary; child payloads carry the child `agentId` as `sessionId` | **blocked** |
| `claude-settings.jsonl` | `--trust-folder`; repo `.claude/settings.json` PreToolUse hook runs under Copilot | **blocked** |
| `claude-settings-all.jsonl` | `--trust-folder`; repo `.claude/settings.json` registers every Claude Code event (no Copilot hooks), parent and `task` subagent calls: which events fire (no `PostToolBatch`, `Notification`, `PostToolUseFailure` here) and their mixed shapes | n/a |
| `subagent.jsonl` | Both registrations; a `task` subagent's allowed call with its post events, the child's own `agentStop`/`Stop`, and `subagentStop` | ran (noop) |

Without fixture (no hook ran, so the capture is empty): with `--trust-folder`,
a repository `.github/copilot/settings.json` containing `disableAllHooks: true`
disabled the user-level hooks and the canary ran. In an untrusted folder the
same file was ignored.

Payloads carry no per-call ID. Copilot's internal session log
(`$COPILOT_HOME/session-state/<sessionId>/events.jsonl`, not a hook surface)
has `toolCallId`. It is not included here because it is a transcript.
