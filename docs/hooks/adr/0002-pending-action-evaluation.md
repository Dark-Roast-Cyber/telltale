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
fails, the call is `not_evaluated` and `on_error` applies.

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
