# OpenCode: plugin contract (v1 and v2)

Status: **v2 request-only pilot implemented; service mode unqualified**.
OpenCode has no shell hooks. The pilot uses an in-process JavaScript plugin
and the integrated executable. v1 below is retained historical capture
evidence, not an implementation target:

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
| Post events | `tool.execute.after` only for completed calls. Thrown or denied calls and tool errors produce only a `message.part.updated` tool part with `state.status: "error"` | `execute.after` for completed and tool-error calls (`status`), and for permission-denied calls. Not for plugin-thrown calls. Bus events `session.tool.called/success/failed` cover the captured outer calls; the denied inner MCP capture has no independent terminal notification | Capture |
| Terminal signals | Tool part state (`completed`/`error`); `session.idle` per turn | `session.tool.failed`/`success` for outer calls; `session.execution.succeeded` per turn. No independent terminal signal in the denied inner-call capture | Capture |
| Parallel | A denied call's sibling runs | Same | E2E |
| Subagents | Child calls carry the child `sessionID`; the `task` result names it. Deny honored | Child calls carry the child `sessionID` and `agent`; the parent link is only in `session.created.parentID`. Deny honored | E2E |
| Agent-reachable bypass | `opencode run --pure` loads no external plugins (canary ran); config edits | Config and plugin-directory edits; `opencode plugin` subcommand | E2E (v1 `--pure`), Docs |

## V2 pilot design

Start with `execute.before` on one pinned v2 release. The plugin owns the
native callback: forward its event to the installed `telltale hooks` process,
throw on denial and leave native permissions untouched on pass. Do not add a
second decision point at `permission.evaluate` or promise interactive `ask`:
v2 auto mode can approve it. The Rust adapter owns parsing, ask capability
and rendering. The existing evaluator owns policy and journaling; do not
evaluate rules or persist raw arguments in JavaScript. Calls are journaled
as sent (`filePath`/`path`, `patchText`): the OpenCode tool table declares
the patch headers as written paths and reads `patchText` as authored
content.

**Occurrence identity.** An ordinary tool's `(sessionID, id)` can link its
before and terminal events. In [the Code Mode capture](../../../crates/telltale/tests/hooks/fixtures/opencode/2.2.5/mcp-codemode.jsonl)
the outer call succeeds after the inner call is denied. Tool name and input
hash identify a shape, not an invocation. Give each forwarded inner request
an occurrence distinct from the outer request and its siblings. Emit a
terminal event only when the harness identifies that same occurrence;
otherwise leave settlement unknown. A returned decision records what the
hook answered, not what the tool did.

Choose one authoritative callback per transition. Duplicate direct/bus
notifications must not increment the score twice or settle another request.
A generic error does not distinguish denial from execution followed by
failure; even successful shell calls in the linked fixture carry
`executed: false`. Neither field alone justifies a settlement.

The implementation deliberately forwards **requests only**. Neither direct
`execute.after` nor bus or turn notifications are registered. This is one
authoritative callback per request, not a claim that a returned decision
proves execution or non-execution. Ordinary and nested outcomes both remain
unsettled/unknown; no `honored` outcome is fabricated. Agent names such as
`build` populate `agent_type`, not an invented agent identity. The assistant
message ID is not treated as a user prompt/turn ID. The pilot forwards no
event for the user's prompt, so `can_grant` is `false`: no grant is offered
and no grant line is taken (ADR 0010).

### Install the pilot

The plugin is `scripts/hooks/opencode-v2.mjs` (Node built-ins only, no npm
dependencies). Copy it to an operator-owned absolute path. Create
`$XDG_CONFIG_HOME/opencode/plugins/telltale.js`:

```js
import { createPlugin } from "/absolute/operator-owned/opencode-v2.mjs"
export default createPlugin({
  executable: "/absolute/operator-owned/telltale",
  configDirs: ["/absolute/operator-owned/telltale-config"],
  mode: "detect_only",
})
```

The config root uses normal `settings.d` and `rules.d`. To enforce, set
`hooks.mode: enforce` there **and** `mode: "enforce"` in the wrapper.
The plugin's default is detect-only: it supplies the CLI's restrictive
`--detect-only` flag, so even an enforcing config records `returned: false`.
`telltale hooks opencode settings` refuses command-hook installation; it
cannot honestly produce a shell-hook fragment or promise fail-closed startup.

The wrapper spawns the trusted executable directly, with explicit config
roots, `--json-reply`, no shell and no evaluator autostart. The optional
`telltale.hook-reply.v1` envelope frames the **gated** native output:
`output: null` is a successful no-op, never an explicit native allow.
Empty output, nonzero exit, an invalid reply and a lost reply are transport
failures, not no-ops. The reply carries `mode` and `protocol`; a non-null
output must be a nonblank deny in enforce mode.

The factory's limits are operator configuration, for an operator editing the
wrapper and for an embedder that ships its own. A value outside its bounds
fails when the plugin is created.

| Option | Default | Bounds | Meaning |
| --- | --- | --- | --- |
| `timeoutMs` | 15000 | 1 to 30000 | Deadline for one callback: waiting for a slot plus the child |
| `maxConcurrent` | 4 | 1 to 16 | Children running at once |
| `maxQueued` | 32 | 0 to 256 | Callbacks that may wait for a slot; `0` disables waiting |
| `maxReplyBytes` | 65536 | 1 to 1048576 | Largest reply accepted |

A request is limited to 1 MiB. A callback that finds every slot busy waits
its turn, oldest first, and is forwarded when a slot frees. A callback that
finds the queue full, or whose deadline passes while it waits, takes the
failure policy and is never forwarded. The diagnostic line names the failure
class (`capacity`, `timeout` and so on) and nothing else. Caller deadline and
child reaping are separate: a timeout closes the plugin's streams and returns
the failure policy without waiting for inherited pipe handles to close.
The capacity slot remains occupied until the caller has settled **and** the
direct child has been reaped; a failed or delayed kill cannot free a live slot.
Cleanup is idempotent. On Linux it signals the child process group only while
the direct child is not known to have exited; it never signals an old group ID
after observing exit. It cannot kill detached descendants after their parent
exits. Windows subtree cleanup is not qualified.
Infrastructure failures default to deny **only in enforce mode**;
`onError: "noop"` explicitly selects failure no-op. Detect-only never throws,
including on transport failure. Diagnostics contain no raw arguments/replies.

**Remaining gates and limits:**

- Through the documented install, pair a runnable control with a denied
  twin for both an ordinary tool and an inner MCP tool. Check the specific
  canary and returned decision. Repeat identical inner calls and run siblings
  concurrently; replay and reorder notifications. Outer completion must never
  settle a child or its sibling.
- Use a trusted executable path and direct process arguments. Bound callback
  time and reply size; clean up the child on timeout. Exercise an unavailable
  executable, invalid reply and a hung child under the advertised failure
  policy, including a reply lost after the decision was recorded. Require an
  unambiguous successful no-op reply; empty output alone is not proof of
  success. Bound concurrency and reap timed-out children. Detect-only mode
  must never throw; never convert a failure to an explicit native allow.
- Break plugin initialization separately. The capture shows a skipped plugin
  cannot deny anything. Check installation from outside the plugin with a
  denied canary and a working control; a startup message alone is insufficient.
  Do not claim fail-closed startup for an unmanaged install. Qualify
  standalone and service mode separately.
- Record plugin and executable revisions, host release, mode, outcomes and
  uncovered tool paths. Keep v1 as historical evidence; qualify Kilo separately.

No service run was attempted: this work may not start a competing service or
touch the managed database. Standalone evidence does not qualify service
loading, reload, trust policies or managed startup. Complete plugin/config
self-protection and an automated install manifest are not shipped by this
pilot; do not treat an unmanaged wrapper as tamper-proof or fail-closed at
startup. Request identities do not survive plugin restart for deduplication.
No terminal correlation map or replay cache exists; terminal replay/reorder
cannot settle a request because those notifications are not consumed.
