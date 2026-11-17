# Claude Code 2.1.318 hook payload captures

Authentic hook stdin payloads recorded from real, isolated, headless Claude Code
sessions. They are the contract evidence for `src/claude_code.rs`; do not edit
payload fields by hand. Re-capture instead (see `scripts/hooks/harness/`).

| Item | Value |
| --- | --- |
| Harness | Claude Code `2.1.318` (`claude --version`), Linux x86-64 |
| Captured | 2026-11-04, Claude Code Cloud container (`tool-lifecycle-*`, `headless-*`) and a Linux workstation (`mcp-tool-*`) |
| Model | `claude-sonnet-5-5` via `claude -p ... --output-format json` |
| Isolation | Fresh disposable working directory per run, `env -i`; disposable `HOME` in the container, `--setting-sources project --settings <run>/settings.json` on the workstation (see `scripts/hooks/harness/claude-code-e2e.sh`, local mode) |
| Recorder | `scripts/hooks/harness/recorder.py` registered for every hook event (`E2E_RECORD=1`) |
| Sanitizer | `scripts/hooks/sanitize-capture.py`: the run directory prefix and the capturing user's home directory are rewritten to `/home/synthetic/run` and `/home/synthetic` |

Content is synthetic: the prompts ask for harmless commands in a disposable
directory. Session and tool-use IDs are the harness's own random values.

## Files

- `tool-lifecycle-subagent.jsonl`: settings allowed `Bash`, `Read`, `Write`,
  `Agent` and denied `Bash(rm:*)`. Steps: `echo hello > out.txt` (completes),
  `Read out.txt`, `ls /nonexistent-dir-for-test` (non-zero exit:
  `PostToolUseFailure`), `rm out.txt` (harness deny rule: `PreToolUse` fires,
  no `PostToolUse`, settled in `PostToolBatch`), and an `Agent` subagent running
  `pwd` (calls carry `agent_id`/`agent_type`; `SubagentStart`/`SubagentStop`).
- `headless-default-permission-request.jsonl`: default permission mode with
  only `Bash(echo:*)` allowed. `echo hello > out.txt` needs approval:
  `PreToolUse` fires, then `PermissionRequest` (even in `-p` mode), then the
  call is denied for lack of an interactive approver and settled in
  `PostToolBatch`.
- `mcp-tool-benign.jsonl`: a disposable stdio MCP server
  (`scripts/hooks/harness/mcp-canary-server.js`, loaded with `--mcp-config
  --strict-mcp-config`) exposing `touch_canary`. Only
  `mcp__tth-canary__touch_canary` was allowed. The model first loads the
  deferred tool through `ToolSearch` (its own `PreToolUse`/`PostToolUse`),
  then calls the MCP tool: `PreToolUse` and `PostToolUse` carry
  `tool_name: "mcp__tth-canary__touch_canary"` and `mcp_server: {"name":
  "tth-canary", "source": "dynamic"}`; `tool_response` is the MCP content
  array. Both calls completed (the canary file existed afterwards).
- `mcp-tool-denied.jsonl`: the same flow with the test marker
  `TTH_E2E_DENY_MARKER` in the `note` argument. telltale-hooks (with
  `crates/telltale/tests/hooks/e2e-marker-rules.yaml`) denied the `PreToolUse`; no
  `PostToolUse` followed and `PostToolBatch` reports the call with the hook's
  reason as `tool_response`. The canary file did not exist afterwards.

## Observations established by these captures

1. At `PreToolUse` time the pending `tool_use` is **not yet** in
   `transcript_path`; it is written after the batch. The hook must synthesize
   the pending call itself.
2. `PreToolUse` runs **before** permission rules: it fired for the deny-ruled
   `rm`. A hook verdict is therefore evaluated even for calls the harness would
   deny anyway.
3. `PermissionRequest` carries no `tool_use_id`; join it to its call by tool
   name and input.
4. `PostToolBatch` lists every call of the batch with the text the model saw,
   including denials, which lets the hook mark unexecuted calls.
5. Subagent tool calls share the parent `session_id` and add `agent_id` and
   `agent_type`; the subagent transcript is separate (`agent_transcript_path`
   on `SubagentStop`).
6. MCP tools fire the same hooks as built-ins under the name
   `mcp__<server>__<tool>`, with an extra `mcp_server` object. Their
   arguments reach Telltale as `arguments` (keys that are not command, path
   or URL keys), so marker and bundled `arguments` rules apply to them. A
   hook `deny` on an MCP call is honored (settled in `PostToolBatch`).
