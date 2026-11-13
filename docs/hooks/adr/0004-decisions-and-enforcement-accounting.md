# ADR 0004: Host promotion policy, never `allow`, outcome-based enforcement accounting

Status: Accepted (2026-11-04)

## Decision

1. **Policy is host-owned** (Telltale's contract: promotion thresholds belong
   to the host). Defaults follow Telltale's bands: `ask` at action score 50,
   `deny` at 90; cumulative session score `ask` at 150, `deny` at 300; after
   3 denied attempts any scored call is denied. Unscored calls are always
   allowed: history raises scrutiny of risky calls, it never blocks benign
   ones. The session ledger counts denied attempts too, because intent
   matters for repeated bypass attempts.
2. **Never return `allow`**. In Claude Code a hook `allow` skips permission
   prompts; the hook only adds restrictions. No-opinion is "print nothing".
3. **Enforcement is accounted from outcomes, not decisions.** A returned
   `deny` is `honored` only when the harness settles the call without a
   result (`PostToolBatch`); a later `PostToolUse` for it is `violated`.
   `ask` resolves to `declined` or `proceeded_after_ask`; we never claim who
   approved. Session end marks unsettled calls `unknown`.
4. **Observe mode** records the verdict it would return (`returned: false`).
5. **Failure**: `on_error` (`allow` default, `ask`, `deny`) for evaluation
   gaps; invalid configuration denies tool calls; `settings --fail-closed`
   adds Claude Code's `onFailure: "block"` on the PreToolUse hook entry.
6. **Agent-controllable evaluation gaps never fail open by default.**
   `on_error` covers hook infrastructure failures; `on_unevaluable`
   (default `ask`) covers tool input Telltale cannot evaluate. Before
   applying it, a quarantined call is re-evaluated as a bounded projection
   that covers every byte (`crates/telltale/src/hooks/projection.rs`). Added after an independent
   security review showed a padded `description` turned a deny into an allow.
7. **Batch settlement is provisional.** A result that arrives after
   `PostToolBatch` settled the call supersedes the settlement
   (`outcome.supersedes`), so a denied call that ran is reported `violated`.
8. **Deny reasons** name Telltale rule IDs and the record ID, never evidence
   text. (Trade-off: rule IDs help a benign user and slightly help an
   adversarial agent; revisit with a `reason_detail` option.)

## Evidence

Real Claude Code 2.1.318 runs (docs/hooks/e2e/): deny honored in
default and `bypassPermissions` modes and inside a subagent; `ask` declined
in headless `-p`; crash fails open by default and closed with `onFailure`
on the hook entry, while matcher-level `onFailure` is ignored.

## Rejected alternatives

- Using `PermissionRequest` as the decision point: it fires only when the
  harness would prompt, so it misses calls already allowed by rules.
- Treating `deny` as proof of prevention.

## Addendum (2026-11): harnesses that cannot ask, turn-end settlement, synthetic correlation

Context: the Copilot CLI, Codex CLI and OpenCode contracts
(docs/hooks/harnesses/README.md, "Runtime contract gaps"), verified against the
real binaries with stub hooks.

9. **An `ask` the harness cannot put to a human is returned as `deny`.**
   Evidence: on Codex a returned `ask` lets the call run (E2E); OpenCode v1
   has no ask; OpenCode v2 `--auto` approves an ask (E2E). The adapter states
   per event whether an ask reaches a human (`Context::can_ask`; it depends
   on run mode in OpenCode v2) from one adapter constant that the registry
   (`Harness::can_ask`) also reads, so the payload-less path
   (`render_verdict`) and the runtime cannot disagree. That path has no run
   mode, so the registry value must be `false` for a harness where *any*
   run mode auto-approves an ask; the adapter may only refine it to `true`
   per event for a run mode verified to prompt or refuse. Every decision is
   a `Decision` with private fields, constructible only through
   `Response::decision`, which applies the substitution: a type guarantee
   covering policy verdicts, `on_unevaluable`, `on_error` (`fail`,
   `fail_strict`, `policy_response`) and any failure policy added later.
   The reason says approval was required and the harness
   cannot ask. Telemetry keeps the policy verdict (`decision.verdict`,
   ledger counts) and records the substitution as `decision.returned_verdict`
   and `outcome.prior_returned_verdict`, present only when they differ.
   Enforcement is accounted against the returned verdict: a substituted deny
   that held is `honored`, one that ran is `violated`. Claude Code and
   Copilot (`-p` refuses an ask it cannot show) keep `ask`. Deferred, not
   added: a knob that downgrades `ask` to allow-and-record on such a harness
   (it would make an evaluation-driven ask fail open by configuration).
10. **Turn-end settlement is weaker evidence than `PostToolBatch`.** No
   harness except Claude Code has a batch event or a post event for a
   hook-denied call; Copilot `agentStop` and Codex `Stop` (with `turn_id`)
   end a turn without a call list. `Event::TurnSettled` settles the pending
   calls of the context's agent and, when the harness has turn IDs, of its
   turn (`Context::prompt_id`: Claude Code `prompt_id`, Codex `turn_id`;
   no harness has both, so no new field). A call becomes `not_executed`
   only when this hook returned a decision for it (a deny, or an ask that
   was put to a human: `honored` / `declined`); otherwise it is `unknown`
   (`not_returned`), because another hook, a native rule or a failure may
   have stopped it. `outcome.established_by` names the event, so consumers
   can weigh `PostToolBatch` above `Stop`/`agentStop`. Like batch
   settlement it is provisional: a late result supersedes it (point 7),
   but only from the same agent and, when the result carries one, the same
   turn. Settlement is idempotent: the state is saved before the settlement
   lines are journaled, so a journal failure (reported as an error record)
   never makes a retry settle or journal the same call twice. OpenCode
   settles each call explicitly (`tool.execute.after`, tool part
   `state.status`, `session.tool.*`), which fits `BatchSettled` per call;
   it needs no turn event.
11. **Correlation keys may repeat; journal identities may not.** Copilot
   hooks carry no call ID; OpenCode v2 Code Mode inner calls reuse the outer
   call's id; Codex and OpenCode v1 IDs are model-supplied and only unique
   in composite form, which the adapter builds statelessly. The runtime
   settles repeated keys first in, first out (pending before provisionally
   settled). Every journal `tool_use` is identified by the harness key plus
   the pending line's source time (`<key>~<ms>`, unique per session), so
   every journal line identity is unique and each result links to its own
   request inside the window Telltale scans, whether the key repeats in
   parallel or in sequence. (A superseded settlement leaves two result
   lines for one request; the later one is authoritative.) Telemetry
   always reports the harness key. Synthetic keys follow one convention,
   `tth-syn-<sha256(session, agent, tool, canonical input)[..32]>`
   (`runtime::synthetic_call_id`), so consumers tell them from harness IDs
   by the prefix alone; Copilot post events repeat `toolArgs`, so the key is
   rebuilt identically. A synthetic key names a call shape, not a call: a
   result under one that only matches a *settled* entry may belong to that
   call or to a later identical call whose request left no record (hook
   failure, timeout, eviction). It is never resolved toward `honored` or
   `violated`: the settlement is superseded by `result: unknown` with
   `error_code: outcome_ambiguous`, and the execution the harness reported
   is recorded as a second outcome for the same `tool_use_id` with the
   reported result (`completed`/`failed`) and `enforcement: no_decision`.
   Read the pair as: "the earlier claim for this call is withdrawn; a call
   of this shape ran, and no decision of ours is known to apply to it". A
   consumer that keeps only the latest outcome per `tool_use_id` sees the
   `no_decision` execution; the withdrawal is the record with
   `supersedes` set. In every Copilot and Codex capture a
   call's post event precedes its turn's stop event (24 files), so a result
   arriving after a turn settlement is the exception this rule bounds.
   Remaining limit: identical calls pending at the same time, or a repeat
   whose request this hook never recorded while the first is still pending,
   are attributed in request order.

## Addendum (2026-11-04): a harness that fails open on every failure

Codex CLI 0.166.0 fails open on hook crash, timeout, invalid output and a
missing binary, has no fail-closed option, and never runs an untrusted user
hook (E2E, `docs/hooks/e2e/2026-11-04-codex-cli-0.166.0.md`).
Decisions:

1. `codex-cli settings --fail-closed` prints nothing and exits non-zero
   with the reason. A flag that changes nothing would claim protection that
   does not exist.
2. Codex `forbidden` exec-policy rules are the only native control that
   holds when the hook is absent. `codex-cli execpolicy` prints rules that
   forbid starting another Codex session, the precondition of every
   hookless relaunch (verified with the hook binary missing). They are
   documented as literal and partial: Codex matches whole commands only
   for plain scripts, so some shell constructs and indirect launches
   escape them, and they cannot protect the hook's files: the
   agent can delete them while the hook is healthy.
   They are an optional backstop, never counted as enforcement in
   telemetry (no hook decision exists for a call they refuse).
3. Managed hooks (`requirements.toml`, `allow_managed_hooks_only`) need no
   trust and cannot be removed by the agent. Shipping them belongs to
   managed deployment.
4. A payload the hook cannot use is answered on stdout when it may be a tool
   call, never with an exit code alone, because no exit code means the same
   thing everywhere: exit 1 blocks on Copilot, runs the call on Codex and is a
   non-blocking error on Claude Code. Exit 2 on a stop event is a prompt to
   continue, so a damaged `Stop` looped on real Codex until the run was killed;
   other named events now always exit 1. A payload naming no event gets each
   harness's own block under `on_error = "deny"`. A verdict here takes the
   stricter of `on_error` and `on_unevaluable`, the runtime's rule for failures
   an agent can bring about.
