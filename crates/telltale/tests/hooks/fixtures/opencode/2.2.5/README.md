# OpenCode 2.2.5 (v2 plugin API) captures

Authentic plugin hook inputs from the real OpenCode 2.x binary, recorded by an
in-process capture plugin and driven by a scripted model. Contract evidence for
a future OpenCode v2 shim; do not edit by hand. Re-capture with
`scripts/hooks/harness/capture-opencode.py v2`.

| Item | Value |
| --- | --- |
| Harness | `@opencode/cli` `2.2.5` (npm with `--ignore-scripts`; platform binary `@opencode/cli-linux-x64`, lockfile sha512 verified); source tag `v2.2.5` |
| Captured | 2026-11-04 |
| Model | Scripted mock (`scripts/hooks/harness/mock-model.py`) as a custom `providers.mock` (`@ai-sdk/openai-compatible`) on loopback. No credentials, no model tokens. Model id `mock-model`, or `gpt-5.4` for `lifecycle-patch` |
| Run | `opencode run --standalone --format json --auto <prompt>` (unless noted); `--standalone` keeps the run off any shared background service; local MCP server `tthmock` |
| Isolation | Fresh `HOME` and XDG dirs per run; config and plugin in `$XDG_CONFIG_HOME/opencode/`; the user's config, data and service were never touched |
| Plugin | `scripts/hooks/harness/opencode/v2/tth-capture.js` (`{id, setup}` Promise API; capture tooling, not the shim) |
| Sanitizer | `scripts/hooks/sanitize-capture.py --envelope --only <hooks and tool/permission/session events>` |

Each line is `{"event", "stub", "payload"}`.
- `tool.execute.before` payloads are `{tool,sessionID,agent,messageID,id,input}`.
- `tool.execute.after` adds `status` (`completed` with `result`, or `error` with `error`).
- `permission.evaluate` payloads are `{sessionID,agent,action,resources,metadata,source:{type,messageID,id},effect}`. They are recorded before the plugin mutates `effect`.
- `event:session.tool.called|success|failed` are bus events keyed by the same call `id`.

## Files

| File | Scenario | Canary result |
| --- | --- | --- |
| `lifecycle.jsonl` | shell, write, edit, read (all `path`), failing shell (`exit: 3`, status completed), parallel shells, failing webfetch (`after` status `error`), unknown tool `tthmock_echo` (before fires; `session.tool.failed`), canary | ran |
| `lifecycle-patch.jsonl` | `patch` `{patchText}`; only `permission.evaluate` resolves `resources`/`metadata.files` paths | n/a |
| `deny-throw.jsonl` | `execute.before` throws `Error` | **blocked**; `session.tool.failed`; no `after` |
| `deny-toolerror.jsonl` | `execute.before` throws `Tool.Error` | **blocked** |
| `deny-throw-parallel.jsonl` | throw on one of two parallel calls | **blocked**; sibling ran |
| `hang.jsonl` | `execute.before` never resolves | blocked, but the session hangs (no timeout; killed at 45 s) |
| `init-throw.jsonl` | `setup` throws | ran: plugin skipped silently (fail-open) |
| `perm-deny.jsonl` | `permission.evaluate` sets `effect: deny` | **blocked** (`permission.rejected` with the plugin's message) |
| `perm-ask.jsonl` | evaluate `ask` with `--auto` | **ran**: `--auto` approved the ask (`replied: once`) |
| `perm-ask-noauto.jsonl` | evaluate `ask` without `--auto` | blocked: non-interactive run rejects |
| `perm-allow-vs-ask.jsonl` | evaluate `allow` over a native `shell` ask rule, no `--auto` | **ran**: plugin allow loosens native ask |
| `perm-allow-vs-deny.jsonl` | evaluate `allow` with a native `shell` deny rule | blocked: evaluate is not consulted for a native deny |
| `subagent.jsonl` | `subagent` child runs the canary; child calls carry the child `sessionID` and `agent`; the parent link appears only in `session.created` (`parentID`) | **blocked** |
| `mcp-codemode.jsonl` | MCP tools exist only inside Code Mode (`execute`); the inner `tthmock.echo` call fires `execute.before` as `tthmock_echo` with the **outer call's id**, and throwing blocks it | **blocked** (inner call) |

Without fixture: a plugin file that fails to parse is skipped silently, and
the canary ran.
