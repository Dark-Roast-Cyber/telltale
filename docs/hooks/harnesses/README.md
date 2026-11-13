# Harness contracts

One page per harness: how hooks are configured, what the pre-execution
payload looks like, and which decisions the harness actually honors.

| Harness | Page | Version verified | Adapter |
| --- | --- | --- | --- |
| Claude Code | [claude-code.md](claude-code.md) | 2.1.318 | Implemented |
| GitHub Copilot CLI | [copilot-cli.md](copilot-cli.md) | 1.0.105 | Implemented; real-model run pending |
| OpenAI Codex CLI | [codex-cli.md](codex-cli.md) | 0.166.0 | Implemented; scripted-model E2E, real-model run pending |
| OpenCode | [opencode.md](opencode.md) | 1.19.5 (v1 API), 2.2.5 (v2 API) | Not started |

Copilot, Codex and OpenCode were verified with stub hooks (or capture
plugins) on the real harness binaries, driven by a scripted model
(`scripts/hooks/harness/mock-model.py`). This needs no credentials and spends no
model tokens. Real-model runs are still needed before claiming adapter
enforcement (see blockers in each page).

## Runtime contract gaps

The runtime (`crates/telltale/src/hooks/runtime.rs`, `crates/telltale/src/hooks/policy.rs`) was shaped by Claude Code.
These are the places where the other three harnesses do not fit that shape.
Evidence levels: E2E, Capture, Src, Docs.

Status: gaps 1 to 3 are closed in the runtime (`Context::can_ask` with
`Harness::can_ask`, FIFO correlation with `runtime::synthetic_call_id`,
`Event::TurnSettled`; ADR 0004 addendum, `crates/telltale/tests/hooks/harness_contract.rs`).
Gaps 4 and 5 are adapter work (rendering, input normalization).

### 1. Ask

| Harness | Native ask from hook | What a returned `ask` does |
| --- | --- | --- |
| Claude Code | Yes | Prompts; headless `-p` declines (E2E) |
| Copilot CLI | Yes | `-p` (also `--yolo`, autopilot): blocks ("unable to ask user"). Interactive (also `--allow-all-tools`, `--yolo`): prompts the user (E2E) |
| Codex CLI | **No** | **The call runs.** Ask is an unsupported decision, the hook is marked failed, and nothing blocks (E2E) |
| OpenCode v1 | **No** (`permission.ask` never fires) | No plugin way to ask; throwing is the only lever (E2E) |
| OpenCode v2 | Yes (`permission.evaluate` `effect = "ask"`) | `--auto` **approves** it (call ran); `run` without `--auto` rejects it (E2E) |

Runtime need: render the policy's `ask` per harness and per mode. On Codex,
OpenCode v1 and OpenCode v2 with `--auto`, an `ask` must become `deny` (or be
downgraded to allow-and-record by explicit policy), never passed through.

### 2. Stable call ID

| Harness | Pre/post call ID | Caveat |
| --- | --- | --- |
| Claude Code | `tool_use_id` | |
| Copilot CLI | **None** | Only the internal `session-state/.../events.jsonl` has `toolCallId` (Capture; not a contract) |
| Codex CLI | `tool_use_id` + `turn_id` | Model-supplied; not unique across agents: key by `(session_id, agent_id, turn_id, tool_use_id)` (Capture) |
| OpenCode v1 | `callID` | Model-supplied; repeats across child sessions: key by `(sessionID, callID)` (Capture) |
| OpenCode v2 | `id` | Code Mode inner calls reuse the outer `execute` id (Capture) |

Runtime need: a correlation key built from several fields, plus a synthetic
key for Copilot, e.g. `(sessionId, toolName, sha256(toolArgs), ordinal)`
matched first-in-first-out to post events.

### 3. Batch settlement

Only Claude Code has `PostToolBatch`. No other harness emits a post event for
a hook-denied call.

| Harness | Event that can settle unexecuted calls | Strength |
| --- | --- | --- |
| Copilot CLI | `agentStop`/`Stop` per turn (no call list): a pre without post by then is "not completed" | Capture. The internal log's `tool.execution_complete` has `error.code: "denied"` (Capture, internal) |
| Codex CLI | `Stop` per turn with `turn_id` (no call list): a pre without post in that turn is "not completed" | Capture |
| OpenCode v1 | Per-call `message.part.updated` tool part, `state.status: "error"` (via the plugin `event` hook) | Capture: explicit per call |
| OpenCode v2 | Per-call `session.tool.failed`/`success` bus events, and `execute.after` `status` | Capture: explicit per call |

Runtime need: a `TurnSettled` event (no call list). Calls still pending at
that point become `not_executed` only when this hook returned `deny`;
otherwise they become `unknown` (another hook, a native rule, or a failure
may have stopped them). OpenCode can settle each call directly.

### 4. Deny forms that work

| Harness | Honored | Ignored / not a deny |
| --- | --- | --- |
| Copilot CLI | camelCase: flat `{"permissionDecision":"deny"}`; PascalCase: flat or `hookSpecificOutput`; exit 2 (with or without stderr) | `hookSpecificOutput` on camelCase events (call ran) |
| Codex CLI | `hookSpecificOutput.permissionDecision: deny`; `{"decision":"block"}`; exit 2 **with** stderr | flat output (ran); exit 2 with empty stderr (fail-open) |
| OpenCode v1 | throw in `tool.execute.before` | `permission.ask` output (hook never fires) |
| OpenCode v2 | throw (`Error` or `Tool.Error`) in `execute.before`; `permission.evaluate` `effect = "deny"` | `effect = "allow"` against a native deny rule (no loosening there) |

Failure defaults differ. Copilot fails closed on crash, exit 1 or a missing
binary, and open on invalid output or timeout. Codex fails open on every
failure, with no option to change it. In OpenCode a load failure is skipped
silently (open) and a hung hook hangs the session (no timeout).

"Allow" is never safe to emit. Copilot's hook allow overrides
`--deny-tool`, and OpenCode v2's evaluate allow overrides native ask rules
(both E2E).

### 5. The Claude Code JSONL journal encoding loses information

`crates/telltale/src/hooks/journal.rs` writes each call as a Claude `tool_use` with the input
unchanged, and Telltale evaluates it through its Claude adapter. Detection v2
routes by **argument key**, not by tool name (Src, pinned
`telltale-core` 0249eaf: `telltale-inference/src/mapping.rs`,
`telltale-detect/src/v2/{actions,selector}.rs`):

- **argv-array commands.** The `command.text` facet is emitted only when
  `command`/`cmd` is a string. An argv array gets joined into action command
  text, but has no `command.text` facet, so rules that select `command.text`
  miss it. In the tested versions every shell tool sends a string (Copilot
  `bash`, Codex `exec_command` reported as `Bash`, OpenCode `bash`/`shell`).
  Codex's argv `shell` tool still exists in source but answers "unsupported
  call" in 0.166.0. Adapters must still join argv into a string before
  journaling.
- **Path-less patch writes.** None of the patch tools carries a path key, so
  no `written_path` or `file_path` is derived and path rules cannot fire:
  - Codex `apply_patch` sends `{"command": "<patch>"}`. The patch text is
    routed as a **shell command** (`command` is a command key).
  - Copilot `apply_patch` (GPT ids) sends a **raw string**. Telltale treats a
    non-JSON string argument as command text, and a Claude `tool_use` input
    is normally an object.
  - OpenCode `apply_patch`/`patch` sends `{patchText}`, which is an unknown
    key and is routed as generic text.

  `normalize` moves the patch text to `content` and extracts the
  `*** Add/Update/Delete File:` / `*** Move to:` targets into a path key.
  OpenCode v2's `permission.evaluate` already gives resolved paths in
  `resources`.
- **Authored content keys.** Written-path detection recognizes Copilot
  `file_text`/`new_str` and OpenCode `newString` (selector). The action
  router's authored-content list (`content`, `new_string`, `new_source`) does
  not, so those values fall through as generic text (Src). Code that only
  mentions `cat ~/.aws/credentials | curl ...` then asks, where Claude
  `Write`/`Edit` does not (parity test). `normalize` renames these keys.
- **Read tools.** Copilot `view` and `rg` are not on Telltale's read-tool
  list, so a private-key read through them is missed (parity test).
  `normalize` maps them to `Read`/`Grep`.
- **Copilot camelCase** payloads (`toolName`/`toolArgs`) and the Copilot
  `permissionRequest` shape need translation. Copilot's PascalCase payloads
  look like Claude's but keep Copilot argument keys.

**Status.** The runtime applies `normalize` (`crates/telltale/src/hooks/normalize.rs`) to the
evaluation encoding of each call, keyed by harness and tool name. Adapters
do not call it. `crates/telltale/tests/hooks/normalize_parity.rs` shows each harness's native
shape, the normalized shape and the Claude reference side by side. Of 39
variants, 25 differ natively and all 39 match once normalized. Already at
parity without normalization:

- `path`/`filePath` write keys
- download-then-execute across calls
- argv commands (in probes)

The upstream fix is requested in
a recorded upstream request;
see ADR 0002, "Addendum: interim input normalization".
