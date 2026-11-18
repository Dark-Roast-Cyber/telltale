# Architecture

Status: first vertical slice (Claude Code), now three harnesses. Module paths below are relative to `crates/telltale/src/`. Decisions: [ADRs](adr/).

## Purpose and scope

Telltale Hooks evaluates AI agent tool calls **before they execute**, using
Telltale's detection, and returns `ask` or `deny` where the harness enforces
hook decisions. It records attempted, decided, executed, failed and
unexecuted actions as telemetry that forwards Telltale's own records.

It is not a detection engine (Telltale owns detection semantics), not an EDR,
and not a sandbox. It is one enforcement point among several; see the
[threat model](../security/hooks-threat-model.md).

## Data flow

```text
 harness (Claude Code, Codex CLI, Copilot CLI)
   │  hook process per event: JSON on stdin
   ▼
 registry (hooks/harness.rs)       `telltale hooks <harness> hook` and the
   │                              evaluator's `harness` field pick the adapter
 adapter (hooks/harnesses/*.rs)      native payload  ->  runtime::Event
   │                              runtime::Response -> native stdout
   ▼
 runtime (hooks/runtime.rs)  ── harness-neutral ─────────────────────────────────────────────────┐
   │ 1. lock session dir (state.rs)                                         │
   │ 2. read bounded journal tail (journal.rs)                              │
   │ 3. append the pending call as a native Claude Code `tool_use` line     │
   │    with a unique, strictly increasing source time                      │
   │ 4. engine.rs: write window -> Telltale scan_sources_detailed           │
   │    -> ActionRecordV1 anchored at the pending call's source time        │
   │ 5. policy.rs: action score + session ledger -> allow | ask | deny      │
   │ 6. journal the attempt, remember the decision, save state              │
   │ 7. telemetry.rs: decision envelope {host fields + ActionRecordV1[]}    │
   │ Post events: journal result, evaluate result, settle outcome           │
   └────────────────────────────────────────────────────────────────────────┘
```

## Components

| Module | Responsibility |
| --- | --- |
| `harness` | Registry: `enum Harness` maps a harness name to its adapter's descriptor (`Adapter`: names, events, parse, render, install output, normalization, config home, rules). The CLI driver, the evaluator, normalization and the engine read only the descriptor. |
| `harnesses/` | One module per harness, each exporting its `ADAPTER`; `payload` holds what adapters share, and `opencode` the tool shapes captured ahead of that adapter. The three rows below are its adapters. |
| `claude_code` | Parse Claude Code hook payloads (2.1.318 contract, unknown fields ignored); render `permissionDecision` / `additionalContext`; generate the settings fragment. Never renders `allow`. |
| `copilot_cli` | Parse Copilot CLI hook payloads in both dialects (1.0.105 contract), with synthetic correlation keys and `agentStop` settlement; render the flat `permissionDecision` / `additionalContext`; generate the hook file. Also receives Copilot payloads sent to the Claude Code entry point by a repository `.claude/settings.json`. Never renders `allow`. |
| `runtime` | Harness-neutral events: `ToolRequested` (the only enforcement point), `ToolFinished`, `BatchSettled`, `UserPrompt`, `PermissionPrompt`, session and subagent lifecycle. Infallible: failures become `error` records plus `on_error`. |
| `gate` | The one place an answer is released to the harness. Detect-only unless the configuration was read and says `hooks.mode: enforce`: then nothing is written to stdout and the exit status is 0, whatever the rest of the hook built ([ADR 0008](adr/0008-detect-only-by-default.md)). |
| `journal` | Per-session append-only native Claude Code JSONL of what hooks reported, scanned under the harness's own hook-journal identity. Bounded tail reads. |
| `engine` | The only Telltale touchpoint: `Pipeline` build (bundled core + community + host rules), `scan_sources_detailed`, focus selection, quarantine/visibility handling. |
| `policy` | Host promotion thresholds (Telltale's contract assigns these to the host). |
| `state` | Session directory (hashed ID), advisory lock, cumulative score, denied/asked counts, pending decisions for outcome correlation. |
| `telemetry` | `telltale_hooks.record.v1` JSONL envelopes ([schema](../../schemas/telltale-hooks-record-v1.schema.json)). |
| `projection` | Bounded, every-byte projection of tool input that Telltale quarantined. Keeps short top-level values and the head of a command with every variant, and reports what it had to separate (`pending_input_separated`, floored at `on_unevaluable`). |
| `codex_cli` | Parse Codex CLI 0.166.0 hook payloads; composite, escaped correlation key (`session:agent:turn:tool_use_id`); `Stop`/`SubagentStop` settle by `turn_id`; render only `hookSpecificOutput` deny (ask becomes deny, allow prints nothing); generate `hooks.json` and the exec-policy backstop rules. |
| `normalize` | Interim input-shape normalization of the evaluation encoding (patch targets, authored-content keys, read-tool names), from the shapes each adapter declares. Applied by the runtime, not by adapters; ADR 0002. |
| `evaluator` | Long-lived evaluator: Unix-socket protocol, trust checks, autostart, fallback rules (`evaluator/unix.rs`). Other platforms report `evaluator_unsupported_platform` and evaluate in-process. |
| `rules/` | Host-owned Rule v1 content (hook self-protection), the shared document and each adapter's own (`Adapter::rules`), loaded additively into the one pipeline that serves every harness, plus a generated rule for this installation's own paths. |

## Runtime contract for adapters

A new harness adapter (OpenCode, Cursor, ...) must:

1. Map the harness's pre-execution interception to `Event::ToolRequested`
   with a per-call correlation key (`ToolCall::tool_use_id`) that the
   harness's post events can reproduce. Use the harness ID when it is
   unique; build a composite statelessly when it is not (Codex:
   `(session, agent, turn, tool_use_id)`; OpenCode v1: `(session, callID)`);
   synthesize `runtime::synthetic_call_id(session, agent, tool, input)`
   (`tth-syn-` prefix) when there is none (Copilot). Keys may repeat: the
   runtime settles them first in, first out and keeps journal identities
   unique itself. The runtime encodes what reaches the journal
   (`journal::safe_id`, `journal::safe_tool_name`): a key, session ID or
   tool name that is empty, blank, over 256 bytes or has a control
   character, or a key or session ID with `/`, `\` or `..`, is replaced by
   `tth-esc-<hash>`; every other value (non-ASCII included) stays
   as reported, except that a key of about 243 bytes or more is hashed
   once the runtime adds `~<ms>`. An encoded or whitespace-padded tool
   name matches no name-based rule, so such a call is floored at
   `on_unevaluable`.
   Telemetry and correlation keep the raw value, so an adapter
   need not escape these for the journal. It must still build a key that
   is stable across the harness's pre and post events and unique per
   call. Never fabricate execution; a
   requested call is only requested.
2. Map post-execution reports to `Event::ToolFinished` with `Completed`,
   `Failed` or `Interrupted` as the harness reports them. Map a settlement
   that lists its calls (Claude Code `PostToolBatch`, OpenCode's per-call
   tool state) to `Event::BatchSettled` (`not_executed`), and a turn end
   without a call list (Copilot `agentStop`, Codex `Stop`) to
   `Event::TurnSettled`, scoped by the context's `agent_id` and, when the
   harness has turn IDs, `prompt_id` (`not_executed` only for calls this
   hook decided, else `unknown`; see ADR 0004 addendum).
3. Set `Context::can_ask` per event: `true` only when a returned `ask` is
   put to a human or refused by the harness when none is available; `false`
   when it would run or auto-approve the call (Codex, OpenCode v1,
   OpenCode v2 `--auto`). `Harness::can_ask` (the payload-less path, which
   has no run mode) must be `false` if *any* run mode of the harness
   auto-approves an ask; the adapter starts from that constant and may only
   refine it to `true` per event for a run mode verified to prompt or
   refuse. The runtime then returns `deny` for every `ask` on such events
   (`Response::decision`, the only constructor of a decision); the adapter
   never maps verdicts itself.
4. Set `Context::prompt_id` to the harness's per-turn identity (Claude Code
   `prompt_id`, Codex `turn_id`), or `None`.
5. Render `Response::Decision` only where the harness enforces it, and
   never a decision that loosens the harness's own permissions (no
   pre-execution `allow`).
6. Ship authentic captured payload fixtures with provenance and a real
   enforcement test using the canary method (`scripts/hooks/harness/`).
7. Record harness identity in `Context::harness`. The journal encoding is
   Claude Code JSONL, but the engine scans each window under the identity
   of the harness named there: its adapter's `client` and that client's
   hook-journal source ID (`ClientId::hook_journal_source_id`, `<client>.hooks`),
   so Telltale records carry that harness's client and source (ADR 0002, addendum of 2026-11-17). A name with no registered adapter is
   not evaluated and takes `on_error`.
8. Do not reshape tool inputs. Report them as the harness sent them. The
   runtime applies `normalize::tool_call(ctx.harness, call)` once, at the
   start of `tool_requested`, to the evaluation encoding only: the pending
   line, the projection input and the journaled history. Telemetry
   `action`, the ledger, reasons and outcomes keep the reported call;
   `telltale[]` records describe the normalized encoding (ADR 0002
   addendum).

### Adding an adapter

Everything about one harness's hook protocol lives in its adapter module,
`crates/telltale/src/hooks/harnesses/<name>.rs`, which exports one descriptor:
`pub const ADAPTER: Adapter` (`crates/telltale/src/hooks/harness.rs`). The CLI
driver (`src/cli/hooks.rs`), the evaluator, normalization and the generated
self-protection rules read the descriptor; none of them names a harness. Adding
a harness means:

1. The adapter module, with a parser to `(Context, Event)`, a renderer from
   `Response` to the harness's stdout JSON, and the descriptor. The compiler
   asks for every field:
   - `name` (`<product>-<cli>`, also `Context::harness`) and `display_name`.
   - `client`: the harness's Telltale client. Its evaluation windows are
     scanned as that client's hook-journal source, `<client name>.hooks`, which
     is one rule for every `ClientId` (host-fed, behind `hook-journal`, never in
     the source registry), so nothing in `telltale-sources` or
     `telltale-detect` changes for a new harness. A client new to Telltale needs
     its `ClientId` value (`telltale-schema`), with the follow-ups that value
     brings (action-record schema enum, evaluation-manifest client list); a test
     accepts every registered adapter's pair through acquisition.
   - `pre_tool_use`: the pre-execution event names. The first answers a call
     whose payload could not be read.
   - `event_keys`: the top-level payload keys that name the hook event. An
     unreadable payload with no registered harness's key "names no event".
   - `can_ask`: see the runtime contract, point 3.
   - `parse`: return `Parsed::Unusable` when the hook event is known but the
     payload is not, and `Parsed::Invalid` when nothing is readable.
   - `render`: never a pre-execution `allow`.
   - `looks_like_pre_tool_use`: recognize an unparseable or oversized
     pre-execution payload so it gets a policy verdict instead of a
     non-blocking error.
   - `install`: the settings or hook-file document that
     `telltale hooks <name> settings` prints, its usage lines, the notes for
     the operator, and what `--fail-closed` means: honored, a note that it
     changes nothing, or a refusal when the harness cannot fail closed.
   - `nameless_block`: what blocks a tool call when the payload names no
     event under `on_error: deny`. What it does on a stop event matters as
     much as what it does on a tool call.
   - `normalization`: `Identity` only if the harness's tools already have the
     evaluation encoding's names and argument keys; otherwise the captured
     shapes that need reshaping, with parity cases and benign twins in
     `crates/telltale/tests/hooks/normalize_parity.rs`.
   - `home`: the environment variable that relocates the harness's config
     home, if it has one, and the pattern for the hook files below it. The
     engine generates rules for the resolved path.
   - `rules`: the adapter's own Rule v1 document in
     `crates/telltale/src/hooks/rules/<name>-self-protection.yaml`, or
     `Shared`. Every document is always loaded, because one pipeline serves
     every harness; a test fails if a file in `rules/` belongs to no adapter.
     Pattern text several rules share is written once in `engine.rs` and named
     in the YAML as `{{NAME}}` (`engine::RULE_FRAGMENTS`), expanded when the
     rules load.
   - `launchers`: the program names an agent starts the harness by.
2. One `Harness` variant, added to `Harness::ALL`, and its arm in
   `Harness::adapter`, the only `match` on a harness.
3. Nothing else in the driver or the evaluator. `telltale hooks <name> hook`
   and `settings` work at once, `telltale hooks harnesses` and the usage text
   list the harness, and the evaluator accepts the name in the request's
   existing `harness` field. Protocol v2 is unchanged; the build fingerprint
   guarantees that the client and the daemon share one registry. An unknown
   name is a `bad_request`, which nothing records, and the hook evaluates
   in-process.
4. If the harness also runs another harness's hook settings, its payloads
   arrive at that harness's entry point. Route them inside the receiving
   adapter, as the Claude Code adapter hands Copilot CLI payloads on;
   otherwise they are labeled and rendered as the wrong harness's.
5. The shared self-protection document names harness launchers and packages
   in several of its rules. Add the harness there, with corpus cases in
   `crates/telltale/tests/hooks/self_protection_corpus.rs`.
6. Evidence and tests: captured payloads with a provenance README in
   `crates/telltale/tests/hooks/fixtures/<name>/<version>/` (a test fails
   without them), the pinned version in
   `tests/upstream_formats/harnesses.json`, contract tests
   (`tests/cli/hooks_<name>_contract.rs` and cases in
   `crates/telltale/tests/hooks/harness_contract.rs`), the home variable in
   `tests/cli/hooks_generated_rule_paths.rs` if there is one, and a real
   enforcement run recorded under `docs/hooks/e2e/`.
7. Docs: an "Implemented" row and a capability section in
   [capability-matrix.md](capability-matrix.md) (a test checks the row), the
   harness page in [harnesses/](harnesses/README.md), and the CHANGELOG.

A harness-specific subcommand that is not install output (`codex-cli
execpolicy`) stays a CLI route of its own.

Changes to `Event`, `Response` or `Context` (for example ask capability or
turn settlement) are a separate shared-interface PR, not part of an adapter
PR.

## Trust and failure model

- **Detect-only by default.** A hook builds an answer (stdout JSON and an exit
  status) and never writes it itself; `gate` releases it only when the
  configuration was read and says `hooks.mode: enforce`. Otherwise nothing
  reaches the harness: empty stdout, exit 0, and an exit after 20 s if the hook
  has not finished. Everything below about `ask`, `deny` and failure policies
  describes what is returned while enforcing and what is only recorded
  otherwise.
- **Fail-open by default** (`on_error: allow`) because Claude Code itself
  fails open; operators can choose `ask`/`deny`, and `settings --fail-closed`
  makes hook crashes and timeouts block (verified).
- A configuration that does not load denies tool calls when it asks for
  enforcement (an operator error should be loud), and is detect-only on the
  defaults when it does not.
- A panic while evaluating is caught at the process boundary: a tool call gets
  the stricter of `on_error` and `on_unevaluable` while enforcing, and nothing
  in detect-only mode.
- Telemetry write failures go to stderr and never change a verdict.
- Telltale fails a source as a whole, and tool input can cause that. A failed
  scan is retried on a reduced window (`Engine::evaluate`, ADR 0002 addendum):
  the call keeps its rule verdict, as much history as a bounded cost allows stays
  in, and the record says `history_lost`. A lock timeout, or an oversized call past
  its piece limit under load, can still cost that verdict (threat model).
- Waiting is bounded. A call waits 10 s for its session's lock, then gets the
  strict policy. The evaluator never records what its client stopped waiting for,
  and a client that gets no answer returns what was recorded or evaluates in-process
  (ADR 0003).
- State and journal are written by the same OS user as the agent. They are
  integrity-relevant but not tamper-proof; self-protection rules raise the
  bar, and managed settings plus out-of-user placement are the real fix.

## Platforms

The crate builds and its tests run on Linux, macOS and Windows (CI matrix).

| | Linux, macOS | Windows |
| --- | --- | --- |
| Config roots (`settings.d` `hooks:` section, rule folders) | `/etc/telltale`, then `$XDG_CONFIG_HOME/telltale` or `~/.config/telltale`; `--config-dir` replaces them | `%ProgramData%\telltale` (the `ProgramData` known folder, on any system drive), then `$XDG_CONFIG_HOME\telltale` or `$HOME\.config\telltale`; `--config-dir` replaces them |
| System config root trust | `/etc` is writable only by root | The system root, its folders and every file read from it must be owned by, and writable only by, Administrators, SYSTEM or TrustedInstaller, and not be links; otherwise the load fails, also when the root is named with `--config-dir`. The `\etc\telltale` root of earlier releases is refused ([install.md](../install.md#windows-system-config-root)) |
| State default | `$XDG_STATE_HOME/telltale/hooks`, else `~/.local/state/telltale/hooks` | `%LOCALAPPDATA%\telltale\hooks` |
| State directory permissions | `0700` | Inherited ACL (no explicit hardening) |
| Long-lived evaluator | Unix socket, autostarted | None: the client reports `evaluator_unsupported_platform`, nothing is autostarted, and every hook evaluates in-process |
| Executable identity in the fingerprint | device, inode, size, mtime (Linux: of `/proc/self/exe`); unique to the process if unreadable | path, size, mtime; unique to the process if unreadable |

Residual risks, both deferred until the **first verified Windows harness
E2E** (see the [threat model](../security/hooks-threat-model.md)):

- **No Windows evaluator.** A named-pipe transport with the same trust
  checks (owner-only pipe ACL, client and server identity, deadlines) is not
  built. Windows hooks pay the in-process pipeline build (about 0.6 s) on
  every evaluated event; decisions are unchanged and never fail open.
- **No Windows ACL hardening.** State, journal and telemetry directories
  inherit their parent's ACL instead of getting an explicit owner-only one.

Prerequisite for any Windows evaluator transport: the Windows
`executable_identity` (path, size, mtime) must also include the file index
from `GetFileInformationByHandle`. Without it, an in-place rewrite of the
binary that keeps its size and mtime keeps the fingerprint, and a stale
evaluator could keep serving the new client. Today Windows has no
evaluator, so nothing consumes this fingerprint there.

## Performance

In-process, an evaluated hook takes about 690 ms end-to-end on a 4 vCPU
container. Telltale's `Pipeline::build()` accounts for about 550-650 ms of
that, and the scan for about 25 ms. With the long-lived evaluator
(`telltale hooks serve`, autostarted, ADR 0003) the PreToolUse p50 is 19 ms in a
short window and 44 to about 190 ms in a full one, depending on what it holds.
Sources: the experiment and
`scripts/hooks/bench-hook.sh`. Any evaluator failure falls back to in-process
evaluation.
