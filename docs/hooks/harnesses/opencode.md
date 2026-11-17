# OpenCode: plugin contract (v1 and v2)

Status: **contract verified, shim not started**. OpenCode has no shell
hooks; enforcement is an in-process JavaScript plugin, one per API generation:

| Generation | Release tested | Plugin API |
| --- | --- | --- |
| v1 | `opencode-ai` **1.19.5** | `export const P = async (ctx) => ({ "tool.execute.before": async (input, output) => ..., ... })` (`@opencode-ai/plugin`) |
| v2 | `@opencode/cli` **2.2.5** | `export default { id, setup: async (ctx) => { await ctx.tool.hook("execute.before", e => ...) } }` (`@opencode/plugin` Promise API) |

Both were tested on Linux x86-64 with the capture plugins in
`scripts/hooks/harness/opencode/{v1,v2}/tth-capture.js` and a scripted model on a
custom OpenAI-compatible provider. Evidence: `crates/telltale/tests/hooks/fixtures/opencode/{1.19.5,2.2.5}/`
and `scripts/hooks/harness/capture-opencode.py`.

## Configuration and scope

- Plugin files: `plugin/` or `plugins/` under each config root, either global
  `$XDG_CONFIG_HOME/opencode/` or project `.opencode/`. npm packages go in the
  config `plugin` key (v1) or `plugins` key (v2) (E2E for the global dir; Src
  and Docs for the rest).
- Per-run injection: isolated `HOME`/`XDG_*` with
  `$XDG_CONFIG_HOME/opencode/{opencode.json,plugins/}`. v2 also needs
  `--standalone`, or `run` attaches to the shared background service.
- Lockdown: managed config and `policies` (v2). Docs only, not tested.

## Payloads (Capture)

v1 `tool.execute.before(input, output)`: `input = {tool, sessionID, callID}`,
`output = {args}`. `tool.execute.after` repeats `args` plus `{title, metadata, output}`.

v2 `execute.before`: `{tool, sessionID, agent, messageID, id, input}`.
`execute.after` adds `status: "completed"` with `result`, or `status: "error"`
with `error`. v2 also has `permission.evaluate`:
`{sessionID, agent, action, resources[], metadata, source:{type, messageID, id}, effect}`.
This hook is mutable: a plugin can set `effect` (`allow`/`deny`/`ask`) and
`message`. For edits, `resources` and `metadata.files` carry resolved
relative paths and diffs.

| Tool | v1 | v2 |
| --- | --- | --- |
| Shell | `bash {command: string, description}` | `shell {command: string}` |
| Write | `write {filePath, content}` | `write {path, content}` |
| Edit | `edit {filePath, oldString, newString}` | `edit {path, oldString, newString}` |
| Read | `read {filePath}` | `read {path}` |
| Patch (GPT ids) | `apply_patch {patchText}`, replaces edit/write | `patch {patchText}` |
| Web | `webfetch {url, format}` | `webfetch {url, format}` |
| MCP | `<server>_<tool>` directly | **Only inside Code Mode** (`execute {code}`): the inner call fires `execute.before` as `<server>_<tool>` with the **outer call's id** |
| Subagent | `task {description, prompt, subagent_type}` | `subagent {agent, description, prompt}` |

v2 fires `execute.before` even for tools that do not exist; the call then fails.

## Verified behaviors

| Question | v1 1.19.5 | v2 2.2.5 | Evidence |
| --- | --- | --- | --- |
| Call correlation | `callID` in before/after and in tool part events | `id` in before/after, `permission.evaluate.source.id`, `session.tool.*`. Not unique for Code Mode inner calls | Capture |
| Deny | Throw in `tool.execute.before`; the model sees the message | Throw `Error` or `Tool.Error` in `execute.before`, or `permission.evaluate` `effect = "deny"` | E2E |
| Ask | No plugin ask: `permission.ask` never fired, even for a native ask rule | `effect = "ask"`: `--auto` approves it (call ran); without `--auto`, `run` rejects it | E2E |
| Allow loosens native | `permission.ask` not invoked (no effect) | **Yes for native ask** (ran without `--auto`); no for native deny (evaluate not consulted) | E2E |
| Plugin throw | Deny (see above) | Deny | E2E |
| Load failure | init throw or syntax error: plugin skipped **silently**, run continues (fail-open) | Same | E2E |
| Never-resolving hook | No timeout: the session hangs (call never runs) | Same | E2E |
| Post events | `tool.execute.after` only for completed calls. Thrown or denied calls and tool errors produce only a `message.part.updated` tool part with `state.status: "error"` | `execute.after` for completed and tool-error calls (`status`), and for permission-denied calls. Not for plugin-thrown calls. Bus events `session.tool.called/success/failed` cover every call | Capture |
| Settlement | Per-call part state (`completed`/`error`) through the `event` hook; `session.idle` per turn | `session.tool.failed`/`success` per call; `session.execution.succeeded` per turn | Capture |
| Parallel | A denied call's sibling runs | Same | E2E |
| Subagents | Child calls carry the child `sessionID`; the `task` result names it. Deny honored | Child calls carry the child `sessionID` and `agent`; the parent link is only in `session.created.parentID`. Deny honored | E2E |
| Agent-reachable bypass | `opencode run --pure` loads no external plugins (canary ran); config edits | Config and plugin-directory edits; `opencode plugin` subcommand | E2E (v1 `--pure`), Docs |

## Shim implications

- The shim decides from `tool.execute.before` (both generations). In v2 it can
  also use `permission.evaluate` to deny. It should not use it to allow, since
  that loosens native ask rules.
- The shim must bound its own work (a hung shim hangs the session) and must
  load reliably (a load failure silently disables enforcement). It needs a
  startup self-check that can be observed from outside the process.
- Key calls by `(sessionID, callID|id)`; v2 Code Mode inner calls need an
  extra discriminator (tool name + input hash).
- Normalize `filePath`/`path` and `patchText` before journaling. `patchText`
  has no path key, so extract paths from the patch headers.
