# OpenAI Codex CLI 0.166.0 hook payload captures

Authentic hook stdin payloads from the real Codex CLI binary, driven by a
scripted model. Contract evidence for a future Codex adapter; do not edit
payload fields by hand. Re-capture with `scripts/hooks/harness/capture-codex.py`.

| Item | Value |
| --- | --- |
| Harness | `@openai/codex` `0.166.0` (npm, linux-x64 package, lockfile sha512 verified); source reference tag `rust-v0.166.0` |
| Captured | 2026-11-04 |
| Model | Scripted mock (`scripts/hooks/harness/mock-model.py`) as a custom `model_providers.mock` with `wire_api = "responses"` on loopback. No credentials, no model tokens |
| Run | `codex exec --json --skip-git-repo-check --dangerously-bypass-approvals-and-sandbox --dangerously-bypass-hook-trust` unless the file notes another mode; stdio MCP server `tthmock` |
| Isolation | Fresh `CODEX_HOME`, `HOME`, XDG dirs and working directory per run; the user's `~/.codex` was never read or written |
| Hooks | `scripts/hooks/harness/stubs/stub-hook.py` in `$CODEX_HOME/hooks.json` (Claude-style `{"hooks":{Event:[{"hooks":[{"type":"command",...}]}]}}`) |
| Sanitizer | `scripts/hooks/sanitize-capture.py --envelope`: run directory rewritten to `/home/synthetic/run` |

Each line is `{"event", "stub", "payload"}`. The stub acts only on stdin
containing `TTH_CANARY`. The canary is `touch <run>/work/canary.txt && echo TTH_CANARY`.

## Files

| File | Scenario | Canary result |
| --- | --- | --- |
| `lifecycle.jsonl` | exec_command (string `cmd`, reported as `Bash` `{"command"}`), `apply_patch` (reported as `{"command": <patch text>}`), parallel calls, MCP `mcp__tthmock__echo`, canary | ran (noop) |
| `lifecycle-failures.jsonl` | deny hook active: apply_patch that fails verification (PreToolUse, no PostToolUse), missing binary (non-zero exit, PostToolUse still fires), unknown MCP tool (no PreToolUse at all), canary denied while its parallel sibling ran | **blocked** |
| `deny-hso.jsonl` | `hookSpecificOutput.permissionDecision: deny` | **blocked** |
| `deny-legacy.jsonl` | `{"decision":"block","reason":...}` | **blocked** |
| `deny-flat.jsonl` | Copilot-style flat `{"permissionDecision":"deny"}` | ran: output ignored |
| `ask-hso.jsonl` | `permissionDecision: ask` | **ran**: unsupported, treated as a failed hook, not a block |
| `allow-hso.jsonl` | `permissionDecision: allow` | ran (allow unsupported; no effect) |
| `rule-forbidden-allow.jsonl` | exec-policy rule `forbidden` for `touch` + hook allow with `updatedInput` | blocked by the rule: hook allow does not override |
| `fail-exit1.jsonl` | hook exits 1 | ran (fail-open) |
| `fail-timeout.jsonl` | hook sleeps past `timeout: 3` | ran (fail-open) |
| `subagent.jsonl` | `spawn_agent` child runs the canary under a deny hook; child payloads keep the parent `session_id` and add `agent_id`/`agent_type` | **blocked** |

Without fixture: when `--dangerously-bypass-hook-trust` is omitted and no
trust state exists, user hooks do not run at all. The capture was empty and
the canary ran.
