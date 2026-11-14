# OpenCode 1.19.5 (v1 plugin API) captures

Authentic plugin hook inputs from the real OpenCode 1.x binary, recorded by an
in-process capture plugin and driven by a scripted model. Contract evidence for
a future OpenCode v1 shim; do not edit by hand. Re-capture with
`scripts/hooks/harness/capture-opencode.py v1`.

| Item | Value |
| --- | --- |
| Harness | `opencode-ai` `1.19.5` (npm, `opencode-linux-x64` binary, lockfile sha512 verified) |
| Captured | 2026-11-04 |
| Model | Scripted mock (`scripts/hooks/harness/mock-model.py`) as a custom `@ai-sdk/openai-compatible` provider on loopback. No credentials, no model tokens. Model id `mock-model`, or `gpt-5.4` for `lifecycle-patch` |
| Run | `opencode run --format json --auto <prompt>` (unless noted); local MCP server `tthmock` |
| Isolation | Fresh `HOME` and XDG dirs per run; config and plugin in `$XDG_CONFIG_HOME/opencode/`; the user's `~/.config/opencode` was never read or written |
| Plugin | `scripts/hooks/harness/opencode/v1/tth-capture.js` (capture tooling, not the shim) |
| Sanitizer | `scripts/hooks/sanitize-capture.py --envelope --only <hooks and tool/permission/session events>` |

Each line is `{"event", "stub", "payload"}`.
- `tool.execute.before` payloads are `{input:{tool,sessionID,callID}, output:{args}}`.
- `tool.execute.after` payloads are `{input:{tool,sessionID,callID,args}, output}`.
- `event:*` lines are bus events delivered to the plugin's `event` hook.
- `message.part.updated` tool parts carry `state.status` (`pending`, `running`, `completed`, `error`). This is the only signal for calls that never reach `tool.execute.after`.

## Files

| File | Scenario | Canary result |
| --- | --- | --- |
| `lifecycle.jsonl` | bash, write, edit, read, failing bash (`metadata.exit: 3`), two parallel bash, failing webfetch (part `error`, no `after`), MCP `tthmock_echo`, canary | ran |
| `lifecycle-patch.jsonl` | `apply_patch` `{patchText}` (no path key) | n/a |
| `deny-throw.jsonl` | `tool.execute.before` throws | **blocked**; part `error` with the thrown message; no `after` |
| `deny-throw-parallel.jsonl` | throw on one of two parallel calls | **blocked**; sibling ran |
| `hang.jsonl` | `tool.execute.before` never resolves | blocked, but the session hangs (no timeout; killed at 45 s) |
| `init-throw.jsonl` | plugin throws during init | ran: plugin skipped silently (fail-open) |
| `native-ask-noauto.jsonl` | native `permission: {bash: ask}`, no `--auto` | rejected (`permission.asked` then `replied: reject`) |
| `perm-allow-vs-ask.jsonl` | plugin sets `permission.ask` output to allow | rejected: the `permission.ask` hook never fired |
| `subagent.jsonl` | `task` subagent runs the canary under a throwing plugin; child calls carry the child `sessionID` | **blocked** |

Without fixture: a plugin file that fails to parse is skipped silently, and
the canary ran. `--pure` ("run without external plugins") loaded no plugin,
and the canary ran.
