# Architecture

Status: three command-hook adapters and an OpenCode v2 request-only pilot.
Module paths below are relative to `crates/telltale/src/`. Decisions: [ADRs](adr/).

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
| `harness` | Registry: `enum Harness` maps a harness name to its adapter's descriptor (`Adapter`: names, events, parse, render, install output, Telltale client, config home, rules). The CLI driver, the evaluator and the engine read only the descriptor; the client selects the tool table its calls are read with. |
| `harnesses/` | One module per harness, each exporting its `ADAPTER`; `payload` holds what adapters share. |
| `opencode` | v2 request-only pilot. The JavaScript plugin forwards `execute.before` with a fresh occurrence ID; Rust owns parsing and deny rendering; calls are read with the OpenCode tool table. No terminal forwarding or inferred settlement. Explicit manual plugin install; command-hook settings are refused. |
| `claude_code` | Parse Claude Code hook payloads (2.1.318 contract, unknown fields ignored); render `permissionDecision` / `additionalContext`; generate the settings fragment. Never renders `allow`. |
| `copilot_cli` | Parse Copilot CLI hook payloads in both dialects (1.0.105 contract), with synthetic correlation keys and `agentStop` settlement; render the flat `permissionDecision` / `additionalContext`; generate the hook file. Also receives Copilot payloads sent to the Claude Code entry point by a repository `.claude/settings.json`. Never renders `allow`. |
| `runtime` | Harness-neutral events: `ToolRequested` (the only enforcement point), `ToolFinished`, `BatchSettled`, `UserPrompt`, `PermissionPrompt`, session and subagent lifecycle. Infallible: failures become `error` records plus `on_error`. |
| `gate` | The one place an answer is released to the harness. Detect-only unless the configuration was read and says `hooks.mode: enforce`: then nothing is written to stdout and the exit status is 0, whatever the rest of the hook built ([ADR 0008](adr/0008-detect-only-by-default.md)). |
| `journal` | Per-session append-only native Claude Code JSONL of what hooks reported, scanned under the harness's own hook-journal identity. Bounded tail reads. |
| `engine` | The only Telltale touchpoint: `Pipeline` build (bundled core + community + host rules), `scan_sources_detailed`, focus selection, quarantine/visibility handling. |
| `policy` | Host promotion thresholds (Telltale's contract assigns these to the host). |
| `state` | Session directory (hashed ID), advisory lock, cumulative score, denied/asked counts, pending decisions for outcome correlation. |
| `telemetry` | `telltale_hooks.record.v1` JSONL envelopes ([schema](../../schemas/telltale-hooks-record-v1.schema.json)). |
| `projection` | Bounded, every-byte projection of tool input that Telltale quarantined. Keeps short top-level values with every variant and the head of a command with each of its later chunks; more than one command member (read by Telltale as one command text) is evaluated in variants without the others. Reports what it had to separate (`pending_input_separated`, floored at `on_unevaluable`). Past its budget it still yields a bounded set of variants: a short command and the first block of short top-level values with every variant, every chunk of a longer command ahead of other values, then the start of other values while variants remain; the rest is unprojected and reported as truncated (`pending_input_truncated`, floored the same way). |
| `codex_cli` | Parse Codex CLI 0.166.0 hook payloads; composite, escaped correlation key (`session:agent:turn:tool_use_id`); `Stop`/`SubagentStop` settle by `turn_id`; render only `hookSpecificOutput` deny (ask becomes deny, allow prints nothing); generate `hooks.json` and the exec-policy backstop rules. |
| `evaluator` | Long-lived evaluator: Unix-socket protocol, trust checks, autostart, fallback rules (`evaluator/unix.rs`). Other platforms report `evaluator_unsupported_platform` and evaluate in-process. |
| `rules/` | Host-owned Rule v2 content (hook self-protection), the shared document and each adapter's own (`Adapter::rules`), loaded additively into the one pipeline that serves every harness, plus a generated rule for this installation's own paths. |

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
   `Failed` or `Interrupted` only with evidence the tool actually executed.
   A generic error can also describe a pre-execution denial. Map a settlement
   that establishes non-execution for identified pending calls (Claude Code
   `PostToolBatch`) to `Event::BatchSettled` (`not_executed`), and a turn end
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
   runtime journals each call in that native shape, and the journal reader
   declares it with the harness's own tool table (`telltale-sources`,
   `tool_operation::table`), so patch targets, authored-content keys and read
   tools are read from the native call (ADR 0002, addendum of 2026-11-17).

### Adding an adapter

Everything about one harness's hook protocol lives in its adapter module,
`crates/telltale/src/hooks/harnesses/<name>.rs`, which exports one descriptor:
`pub const ADAPTER: Adapter` (`crates/telltale/src/hooks/harness.rs`). The CLI
driver (`src/cli/hooks.rs`), the evaluator and the generated
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
     event and the stricter of `on_error` and `on_unevaluable` is `ask` or
     `deny`, or a configuration that asks for enforcement did not load. What
     it does on a stop event matters as much as what it does on a tool call.
   - Tool shapes are not declared here: the harness's built-in tools belong
     in its source's tool table (`crates/telltale-sources/src/sources/<agent>/tools.rs`),
     with parity cases and benign twins in
     `crates/telltale/tests/hooks/native_parity.rs`.
   - `home`: the environment variable that relocates the harness's config
     home, if it has one, and the pattern for the hook files below it. The
     engine generates rules for the resolved path.
   - `rules`: the adapter's own Rule v2 document in
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

### Subprocess plugin reply

`hook --json-reply` is optional CLI framing, not a new runtime event, telemetry
schema or evaluator protocol. It wraps the native answer **after** `Gate::release`
as `{protocol: "telltale.hook-reply.v1", mode, output}`. `output: null` confirms a
successful no-op; empty stdout is an unavailable reply. Existing native
command-hook output is unchanged without the flag. `--detect-only` can only
restrict loaded configuration and runtime accounting, including broken config;
it cannot enable enforcement. The v2 pilot plugin uses both flags and has its
own bounded subprocess/failure policy. Startup plugin load failure remains an
upstream fail-open limit, not a CLI guarantee.

The plugin's caller deadline is independent of stdio closure and child
reaping. On failure it settles once, destroys its streams and attempts cleanup
only for a direct child not known to have exited. A capacity slot is released
only after both caller settlement and direct-child reaping. Delayed inherited
pipes cannot extend the caller deadline or cause a signal to an old process
group; failed cleanup cannot release a still-live slot.

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
- A panic on the way to an answer is caught at the process boundary and
  answered like a payload the hook could not read, with an `error` record
  (`hook_panicked`): a tool call gets the stricter of `on_error` and
  `on_unevaluable` while enforcing, and nothing in detect-only mode. A panic
  in the evaluator leaves that connection unanswered and retires the
  evaluator; the client evaluates in-process and the next hook starts a fresh
  one.
- Telemetry write failures go to stderr and never change a verdict.
- Telltale fails a source as a whole, and tool input can cause that. A failed
  scan is retried on a reduced window (`Engine::evaluate`, ADR 0002 addendum):
  the call keeps its rule verdict, as much history as a bounded cost allows stays
  in, and the record says `history_lost`. A lock timeout, or an oversized call past
  its piece limit under load, can still cost that verdict (threat model). The scans
  ahead of the piece loop are bounded too: the whole window only starts within the
  recovery budget, a call with no history is not scanned a second time on its own,
  a projection past its budget is not scanned whole or with its variants together
  but goes straight to its pieces, a longer command's first, and a projected call's
  variants are not scanned at all once the piece limit has passed
  (`pending_pieces_unscanned`, then `on_unevaluable`). After its pieces, a call
  past the projection budget that has session history is also read with it: one
  scan of the history and the line the call is journaled as (what later calls
  read), started only if the recovery budget still admits it and the piece time
  limit has not passed. What that scan finds is added to what the pieces found,
  and nothing is taken away: the call keeps the `on_unevaluable` floor and
  `pending_input_truncated`, because its full input still was not evaluated, and
  a scan that finds nothing does not make a call whose pieces were all refused
  count as evaluated. When the budget does not admit the scan or Telltale refuses
  it, nothing else is tried: a call with an evaluated piece records
  `history_lost`, and a call with none stays `not_evaluated`;
  `evaluation.scans.history` says which happened (null when there was no history
  to read).
- Waiting is bounded, by one deadline per hook: 25 s from the hook's start
  (`HOOK_DEADLINE`, below the timeouts of 30 s or more that the tool-call hooks
  are installed with). Every later wait is cut to what is left of it: the wait
  for the evaluator, the wait for the session's lock (10 s at most), the
  recovery budget and the piece time limit (`Limits::within`). The default
  waits fit in it; a `hooks.evaluator.request_timeout_ms` raised well above its
  default can use it up. A call waits for its session's lock, then gets the
  strict policy (`state_lock_timeout`). How long it waited is recorded apart
  from its scans, in milliseconds: `evaluation.lock_wait_ms` on its decision
  or result finding (from the process that took the lock, the evaluator's
  included), and `lock_wait_ms` on the `error` record of a call that gave up
  waiting or failed after it. A call that has no time left before its
  evaluation starts is not evaluated: it records no decision and journals
  nothing, and gets the strict policy and one `error` record (`hook_deadline`).
  A decision already evaluated is always recorded and delivered, however late.
  One scan already in flight is not interrupted, so a single slow scan can
  still run past the deadline. The evaluator never records what its client
  stopped waiting for, and a client that gets no answer returns what was
  recorded or evaluates in-process (ADR 0003).
  The limits are values the runtime is built with (`engine::Limits`, defaults
  only in production); tests use generous ones to prove coverage and tiny ones
  to prove the degraded outcome.
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

### Load benchmark

`make hooks-load-bench` builds the release binary and runs
`scripts/hooks/load-bench.py`, which starts `telltale hooks claude-code hook`
processes in parallel and reports what they cost. It answers whether the time
limits above (the 25 s hook deadline, the session lock wait, the 5 s piece
limit, the recovery budget) hold under load. Run it on a host that is otherwise
idle, or say how busy it was. Pass options in `ARGS`:

    make hooks-load-bench ARGS="--concurrency 8 --calls 4 --payload small,projected,past-budget --session same,distinct --evaluator on,off --check"
    make hooks-load-bench ARGS="--concurrency 8 --calls 4 --cpus 0,1 --out target/hooks-load.json"

Each combination of `--payload`, `--session` and `--evaluator` is a scenario
with a fresh temporary hooks home: configuration (`hooks.mode: enforce`),
state, telemetry, the evaluator socket, `HOME`, the `XDG_*` folders and
`TMPDIR` are all in one temporary directory, nothing else from the environment
but `PATH` is passed on, and the directory and any evaluator started in it are
removed at the end. A real installation's configuration, state and journals
are never read or written. In a scenario, `--concurrency` workers start
together and each sends `--calls` PreToolUse Bash calls, one after another,
with synthetic input:

| `--payload` | Input |
| --- | --- |
| `small` | a short command |
| `projected` | a short command beside a few hundred short values, quarantined by Telltale and projected within the projection budget |
| `past-budget` | a short command beside 3,000 short values, past the projection budget (`pending_input_truncated`, so the verdict is floored at `on_unevaluable`) |

`--session same` puts every call in one session, so calls wait for its lock;
`distinct` gives each worker its own. `--evaluator on` starts the long-lived
evaluator with a warm-up call and waits for it; `off` evaluates in-process.
`--cpus 0,1` runs the hooks, and the evaluator they start, under
`taskset -c 0,1`, as on a 2 vCPU host; the rest of the host is not limited.

The report is JSON (stdout or `--out`), with a table on stderr. It holds
counts, closed codes and milliseconds, never payload text or paths:

- `host`: logical CPUs, the CPUs the benchmark may use, and the load average
  at the start and the end; `telltale_version` names the build.
- Per scenario, `wall_ms`: p50, p95, p99 and maximum wall time of a hook
  process, as a harness waits for it, and how many calls took more than 25 s
  (the deadline), 30 s (the timeout Claude Code and Codex CLI hooks are
  installed with) and the `--check` limit.
- `answers` (`allow`: exit 0 and nothing printed; `ask`, `deny`) and
  `unanswered`: calls that exited non-zero, printed something else or were
  killed at `--timeout-s` (120 s).
- `records`, from the run's hooks records: decisions and their `basis`,
  `floored` (decisions floored at `on_unevaluable`, basis
  `unevaluable_input`), error codes with `hook_deadline` and
  `state_lock_timeout` counted apart, evaluation status, visibility limits,
  which evaluator answered and why one fell back, and calls with no record.
- `build_ms`, `scan_ms` and `scans`: percentiles of the pipeline build, of
  the whole evaluation and of each scan phase in `evaluation.scans`
  (`whole_ms`, `together_ms`, `pieces_ms`, `history_ms`), pieces scanned of
  those offered, pieces refused with the first refusal codes, and how the
  whole, together and history scans ended.
- `lock_wait_ms`: percentiles of how long calls waited for the session lock
  (`evaluation.lock_wait_ms` of decisions, and `lock_wait_ms` of the error
  records of calls that gave up waiting with `state_lock_timeout`); the table's
  `lock99` column is its p99. Null for a build that does not record the wait.
- `evaluator_ready` is false when `--evaluator on` was asked for and no
  evaluator answered; those calls evaluated in-process.

`--check` exits 1 when a call took longer than `--deadline-ms` (25,000) plus
`--margin-ms` (5,000), or ended without an answer, so "the bounds hold" is a
command. The benchmark does not observe a harness: what a harness does when
its own timeout kills a hook, a harness that runs calls in parallel
differently, and other platforms are outside it. On Linux the evaluator needs
a Unix socket; in a sandbox that refuses one, `evaluator_ready` is false.
`tests/hooks_load_bench_test.py` (in `make hooks-plugin-check`) checks the
report, the isolation and `--check` against a stand-in binary.

#### Figures, 2026-11-21

Release build of the 0.8 line on a 20-CPU Linux host that was otherwise
lightly used (load average 4 to 8, no builds). Sixteen workers, four calls
each, so 64 calls per scenario; wall time of the hook process in
milliseconds. Reproduce with:

    make hooks-load-bench ARGS="--concurrency 16 --calls 4 --payload small,projected,past-budget --session same,distinct --evaluator on,off --cpus 0,1 --check"

Pinned to two CPUs (`--cpus 0,1`):

| Payload | Session | Evaluator | p50 | p95 | p99 | max |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| small | same | on | 20 | 351 | 471 | 471 |
| small | same | off | 2,561 | 3,548 | 3,835 | 3,835 |
| small | distinct | on | 7 | 166 | 205 | 205 |
| small | distinct | off | 2,688 | 2,734 | 2,739 | 2,739 |
| projected | same | on | 119 | 2,477 | 3,203 | 3,203 |
| projected | same | off | 1,686 | 8,362 | 9,530 | 9,530 |
| projected | distinct | on | 23 | 946 | 1,089 | 1,089 |
| projected | distinct | off | 2,882 | 2,914 | 2,922 | 2,922 |
| past-budget | same | on | 1,274 | 8,746 | 10,521 | 10,521 |
| past-budget | same | off | 2,900 | 10,331 | 12,898 | 12,898 |
| past-budget | distinct | on | 1,076 | 7,328 | 7,370 | 7,370 |
| past-budget | distinct | off | 5,036 | 5,122 | 5,141 | 5,141 |

Without the pin (all 20 CPUs), the same scenarios:

| Payload | Session | Evaluator | p50 | p95 | p99 | max |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| small | same | on | 16 | 374 | 681 | 681 |
| small | same | off | 303 | 594 | 1,351 | 1,351 |
| small | distinct | on | 5 | 338 | 398 | 398 |
| small | distinct | off | 313 | 374 | 376 | 376 |
| projected | same | on | 83 | 2,712 | 3,249 | 3,249 |
| projected | same | off | 551 | 2,086 | 3,863 | 3,863 |
| projected | distinct | on | 295 | 575 | 714 | 714 |
| projected | distinct | off | 346 | 405 | 411 | 411 |
| past-budget | same | on | 1,870 | 5,927 | 7,397 | 7,397 |
| past-budget | same | off | 1,225 | 7,764 | 9,020 | 9,020 |
| past-budget | distinct | on | 860 | 4,463 | 4,563 | 4,563 |
| past-budget | distinct | off | 620 | 720 | 729 | 729 |

What the runs show:

- **The deadline held.** In all 1,536 calls every hook answered, none
  recorded `hook_deadline`, and none ran past 25 s. The slowest call took
  12.9 s (two CPUs, one session, in-process, past-budget input), about half
  the deadline.
- **Per-call evaluation is small beside the waits.** With the evaluator, the
  evaluation of a small call took 1 to 8 ms at the median and 18 ms at most;
  a projected call 13 to 32 ms (54 ms at most); a past-budget call about
  200 ms at the median, nearly all of it the piece scans. Most of a slow call's wall time
  is waiting: for the session's lock when calls share a session, and for a
  CPU.
- **Without the evaluator, building the pipeline dominates.** In-process,
  each hook builds it: about 0.2 to 0.35 s on the full host and up to 2.5 s
  when sixteen processes share two CPUs. The evaluator pays
  that once (about 0.2 to 0.3 s at warm-up).
- **Lock wait is not recorded by the hook.** It shows only as wall time
  beyond the build and scan times. Four of the 64 in-process past-budget
  calls in one session on two CPUs gave up waiting for the session's lock
  (`state_lock_timeout`) and were answered through `on_error`; no other
  scenario recorded one.
- **Past-budget input.** Every such call was floored at `on_unevaluable`
  (`ask`), as designed. With the evaluator on, 12 to 17 of 64 such calls were
  answered in-process after an `evaluator_expired` or `evaluator_busy`
  fallback, and still within the deadline.

These figures are from one host and one harness adapter; they bound nothing
on a slower disk or a busier machine.
