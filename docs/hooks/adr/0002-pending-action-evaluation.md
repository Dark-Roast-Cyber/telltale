# ADR 0002: Evaluate pending calls by scanning a hook-built native journal window

Status: Accepted (2026-11-04)

## Context

Telltale has no API to evaluate one pending action; it scans sources.
Claude Code passes `transcript_path` to hooks, but captures from 2.1.318 show
that at `PreToolUse` time the pending `tool_use` is **not** yet in the
transcript (it is written after the batch), subagent calls live in separate
transcripts, and transcripts carry full prompts and outputs
(crates/telltale/tests/hooks/fixtures/claude-code/2.1.318/README.md).

## Decision

The runtime keeps a per-session **journal** of what hooks reported (user
prompts, requested calls, results, settlements) in Claude Code's native
session JSONL shape. For each evaluation it writes a bounded window
(default 256 records / 2 MiB tail) plus the pending line to a stable
per-session path and scans it as a `claude.projects` source.

Findings for the pending call are the action records whose `stage` is
`requested` and whose `occurred_at` equals the pending line's source time.
The runtime writes strictly increasing, unique millisecond source times on
every journal line, so that equality identifies exactly one observation.
If Telltale quarantines the pending line (by native `uuid`) or the source
fails, the call is `not_evaluated` and `on_error` applies. *Superseded: a
quarantined line is now projected and then gets `on_unevaluable`, and a failed
source is retried on a reduced window (addendum of 2026-11-05).*

## Evidence

Scenario and real-harness tests: download in call N and execution in call
N+1 produce `chain.download_then_execute` anchored at N+1; subagent calls in
the same session correlate with the parent's earlier calls.

## Rejected alternatives

- **Read the harness transcript**: lacks the pending call at decision time,
  splits subagents, maximizes sensitive content, and its format is not ours.
- **Pick the highest `timeline_index`**: misattributes an earlier finding when
  the pending call has none.
- **Compute the pending observation ID**: requires Telltale internals.

## Consequences and open questions

- Journal content is bounded per string (`max_result_bytes`); the pending
  call itself is evaluated unmodified.
- Chains whose first step left the window are not reconstructed; the host
  session ledger (ADR 0004) still carries cumulative risk.
- Every Telltale record says `client: "claude"` and `source_id:
  "claude.projects"` because that is the evaluation encoding. For other
  harnesses this is a provenance mismatch: the envelope's `harness.name` is
  authoritative. A first-class "evaluate host-supplied canonical activity"
  facade would remove the temp file and the encoding mismatch; it is a
  candidate upstream request once a second harness proves the need.
- The encoding also loses detection facts for other harnesses' input
  shapes. Parity tests (`crates/telltale/tests/hooks/normalize_parity.rs`) proved this, and it
  is requested upstream as
  a recorded upstream request:
  a Supported way to evaluate pending actions in harness-native shapes,
  or the narrower fixes. Until then, see the addendum below.

## Addendum (2026-11-04): interim input normalization

Status: Accepted. Exit criterion: a recorded upstream request (or equivalent) lands in a
pinned Telltale revision.

Telltale's Claude adapter routes tool arguments by key, and read detection
by tool name. Journaling Copilot CLI, Codex CLI and OpenCode inputs
unchanged gives these results against the Claude-native equivalent
(Telltale `0249eaf`, 39 variants over 11 cases; 25 differ):

- **Patch writes** (Codex `{"command": patch}`, Copilot raw string,
  OpenCode `{"patchText": patch}`) derive no `written_path`. A patch to
  hook settings asks or passes where Claude `Write`/`Edit` is denied, and
  code inside a patch is matched as a command or as arguments.
- **Authored-content keys** (Copilot `file_text`/`new_str`/`old_str`,
  OpenCode `newString`/`oldString`) are generic argument text. Code that
  only mentions a risky command asks where Claude `Write`/`Edit` does not.
- **Read tools** Copilot `view` and `rg` miss `secret.private_key.read`.

Already at parity, so no normalization is applied:

- `path`/`filePath` on writes
- download-then-execute across calls
- argv command arrays: no tested harness sends them, and our probes reached
  the same rules as the string form

The runtime therefore normalizes each tool call once, at the start of
`tool_requested`, with `normalize::tool_call(ctx.harness, call)`
(`crates/telltale/src/hooks/normalize.rs`). Adapters do not call it. The change
applies only to the evaluation encoding: the pending line, the projection
input and the journaled history. Telemetry `action.tool_name` and
`input_sha256`, `PendingDecision` and the decision reason keep the call the
harness reported. Telltale's own `telltale[]` records describe the
normalized encoding, so they may differ from `action.tool_name`, for
example `Read` versus Copilot `view`.

Each rule applies only to the tool names and shapes captured for one harness
(`copilot-cli`, `codex-cli`, `opencode`). `claude-code`, unknown harnesses,
MCP tools, shell tools and every other shape pass through unchanged, so
normalization can never make a call look safer than its native form (tested
with review probes). The rules are:

- **Patch tools** (Copilot raw-string `apply_patch`/`Edit`, Codex
  `apply_patch` `command`, OpenCode `apply_patch`/`patch` `patchText`): the
  patch body moves to `content`, which is authored content and never a
  command key. The `*** Add/Update/Delete File:` and `*** Move to:` targets
  go, newline-separated, into a path key Telltale reads. That is the first
  key that is absent, null or empty; otherwise the targets are appended to
  an existing string path key. A string counts as a patch only under
  Codex's lenient boundary check (0.166.0): after trimming, the text runs
  from `*** Begin Patch` to `*** End Patch`, optionally wrapped in a
  `<<EOF`/`<<'EOF'`/`<<"EOF"` line and a closing `EOF` line. Any text
  before or after those boundaries leaves the input native, so command text
  cannot hide around a patch. Header lines are trimmed as Codex trims
  them, so an indented context line that quotes a header also counts. That
  can only add paths, so it fails closed.
- **Authored keys** on Copilot `create`/`edit`/`Write`/`Edit` and OpenCode
  `edit`/`multiedit` get their Claude names.
- **Copilot `view`/`rg`** become `Read`/`Grep`.

No JSON value is dropped; a key that would collide stays where it is.
Evaluation still changes by design, matching the Claude reference:

- Renamed `old_*` values become replaced text, which Telltale ignores.
- Every patch line, including removed and context lines, becomes authored
  content.

Parsing is linear and cannot panic. Oversized results still go through the
projection and `on_unevaluable`.

The parity tests pin each native result, so an upstream fix shows up as a
failing "native result changed" assertion. At that point, delete the
matching normalization.

## Addendum (2026-11-04): Codex CLI journal encoding

Status: Accepted.

Telltale has a Codex source adapter (`codex.sessions`), so the hook could
journal Codex calls as a synthesized Codex rollout instead of Claude Code
JSONL. `crates/telltale/tests/hooks/codex_journal_encoding.rs` evaluates the same pending calls,
taken from the 0.166.0 captures, in both encodings through
`scan_sources_detailed` (Telltale `0249eaf`, host rules loaded). The results
are identical in all five cases: a credential exfiltration (score at least
90), download-then-execute (`chain.download_then_execute`), a shell write to
hook settings (`tth.tamper.hook_settings_*`, deny), an `apply_patch` to the
hook configuration (`tth.tamper.hook_settings_reference`, 60: ask, where
Claude `Edit` is denied), and a benign patch (no detection).

Decision: Codex calls use the existing Claude Code JSONL journal, and the
runtime's normalization (addendum above, `normalize::CODEX_CLI`) closes the
patch gap: through the adapter, a patch to the Codex hook file is denied
(`tests/cli/hooks_codex_cli_contract.rs`). The rollout encoding gains no detection, has no lever for a
patch's `written_path` either, and would add a second journal writer whose
format is Codex-internal. The encoding test pins both results, so a Telltale bump
that makes the encodings differ fails it and reopens this decision.

Constraint found on the way: Telltale rejects a native ID containing `/`,
`\`, `..`, LF or CR and fails the whole source, which leaves that call and
every later call whose window includes the line `not_evaluated`. Codex
`tool_use_id` is model-supplied, so the adapter percent-encodes every byte
outside `[A-Za-z0-9_-]` in its composite key, which keeps the key injective
(`crates/telltale/src/hooks/codex_cli.rs`, regression-tested). Making journal IDs safe for every
adapter is separate runtime work.

## Addendum (2026-11-05): recovering from a failed source

Telltale fails a source as a whole and has no partial result, and this
decision scans one source per call. Tool input the model controls can fail it:
a line Telltale refuses (keys that collide under NFC) or capacity used up across
lines (contribution keys, projection items, evaluation budget).

Rescanning the pending line alone, as first proposed, recovers the rule verdict
and loses every multi-call chain: poison followed by a chain's second stage
would be a bypass. Dropping the oldest lines until a scan succeeds has the same
hole, since everything before the newest poison goes. So:

- Colliding keys are renamed in the evaluation encoding (`journal::safe_input_keys`),
  so that shape loses nothing and needs no recovery.
- If a scan still fails at source level, the pending call is scanned alone,
  which secures its rule verdict. History then goes back in stages, and a block
  Telltale refuses is split, so a line that fails on its own is found and dropped
  wherever it sits. This needs no knowledge of the cause, so it also covers
  sessions an older version poisoned and failures added upstream. It stops at 32
  scans, at 2 capacity refusals after a pass (no search finds a culprit for
  capacity, so a further refusal only trims the result and costs a full scan), or
  at 2 s, checked before each of these scans against a forecast of its cost. The cost
  matters twice: a hook timeout runs the call, and scans that outlast
  `DEADLINE_MARGIN` used to make telemetry disagree with the harness.
- Lines go back in a chosen order and are always scanned in their original order:
  the newest 8, then older lines under 1 KB smallest first, then the rest newest
  first. Compared on the debug build with the 2-refusal limit, before the harness
  self-protection rules (the pinned cases still hold with them); a miss is a chain
  stage lost, out of the sizes swept:

  | Case | Newest first | Smallest first | Chosen |
  | --- | --- | --- | --- |
  | Flood filling capacity exactly (20 lines + a last line of 40-136 hosts) | 44/97 | 0/97 | 0/97 |
  | Flood of 13 lines | 7/16 | 0/16 | 0/16 |
  | 20 quiet calls, then a flood of 20 | 10/16 | 0/16 | 0/16 |
  | 200 flood lines under 1 KB | 7/8 | 0/8 | 0/8 |
  | Full window of flood lines | 1/1 | 0/1 | 0/1 |
  | Deny-level stage padded past the flood, 2 lines back | 0/21 | **11/21, deny lost** | 0/21 |
  | Benign 3.8 KB session, short stage older than all | 1/1 | 0/1 | 0/1 |
  | Benign 3.8 KB session, short stage 3 lines back | 0/1 | 0/1 | 0/1 |
  | Benign 3.8 KB session, long stage in the middle | 0/1 | 1/1 | 0/1 |

  Smallest first drops a recent line for an old one, which is the wrong trade when
  chains link within 3 calls, and it cost a deny. Newest first gives the capacity to
  the flood. The mix keeps what links, then what is cheap. With no refusal limit
  newest first misses less (1/97, 0/16, 0/16) but still loses the benign old stage,
  and it costs each benign call 1.7 s against 1.1 s in the same build. The order
  protects ordinary stages, not one built to be lost; that limit is accepted.
- History loss never raises the verdict of a call with no finding. Floor and
  plain verdict were weighed: a floor recreates the wedge (every call denied where
  the harness cannot ask), a floor for the first N calls delays it and still
  wedges, and a floor for rule families with chains would put chain knowledge in
  the host, the second engine this project does not build. It would also not address
  losses that involve no failure, which are tracked privately.
  `history_lost` tells telemetry what was lost; it reaches neither the harness nor
  a person answering a prompt.
- A pending call past capacity on its own keeps `on_unevaluable` as a floor: it
  was only evaluated in pieces, it is one call, and later calls are unaffected.
  Its pieces do not ask the 2 s budget, because under load that dropped the piece
  carrying a deny and a call can bring that load itself. With no limit at all they
  outran the evaluator's margin and the hook's timeout: 24.8 s of evaluation at 80
  busy processes on 20 logical CPUs, and 43 s for one hook. So they stop 5 s after the
  evaluation started, which leaves `DEADLINE_MARGIN` about 250 ms for the piece in
  flight. Findings so far keep their force and the pieces left get `on_unevaluable`
  and the limit `pending_pieces_unscanned`, so a deny in a piece past the limit
  becomes `ask`. That is the trade for a hook that answers more often. It does not
  bound the scans ahead of the pieces.

Nothing about the recovery is persisted, so a poisoned window pays for it on
every call until the line leaves. That is simple and bounded; remembering what
was dropped is the next step if the cost shows up in practice.
