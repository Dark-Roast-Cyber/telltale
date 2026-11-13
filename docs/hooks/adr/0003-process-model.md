# ADR 0003: Per-invocation process now; long-lived evaluator next

Status: Accepted; evaluator implemented (2026-11-04)

## Context

Claude Code runs a command hook as a fresh process per event. Measured on a
4 vCPU container: `Pipeline::build()` 540-700 ms (about 230 ms without the
community package), scan of a 100-row window about 25-55 ms; end-to-end
PreToolUse hook p50 688 ms, PostToolUse p50 623 ms, lifecycle events 3 ms
(`scripts/hooks/bench-hook.sh`).

## Decision

Ship the simplest correct model first: one process per hook event that
builds the pipeline lazily (lifecycle events never build it). Next, add a
long-lived local evaluator (`telltale hooks serve`) holding one `Pipeline`,
reached over a user-private Unix socket, with the per-invocation path kept as
an automatic in-process fallback, so correctness never depends on the daemon.

## Rejected alternatives

- **Daemon only**: a missing daemon would turn into fail-open or fail-closed
  outages; the fallback keeps decisions correct, only slower.
- **Drop the community package to save 300 ms**: loses coverage; operators
  can still choose it (`telltale.community_rules = false`).
- **HTTP hook transport**: Claude Code supports HTTP hooks, but a network
  listener is a larger attack surface than a private socket and fails open on
  error in several harnesses.

## Consequences

About 1.3 s added per tool call (Pre + Post) until the evaluator lands.
Window scans grow linearly, so the window stays bounded.

## Outcome (implemented)

`telltale hooks serve` (`crates/telltale/src/hooks/evaluator.rs`) keeps one `Runtime` with a built
`Engine`. Measured with `scripts/hooks/bench-hook.sh`: PreToolUse p50 16-18 ms, p95
22-30 ms with the evaluator, against 672 ms in-process. Real Claude Code
2.1.318 sessions made every decision through an evaluator autostarted by
the session's first hook
(`docs/hooks/e2e/2026-11-04-claude-code-2.1.318-evaluator.summary.jsonl`).

Safety properties (protocol v2, after an independent review of v1 found a
stalled daemon could turn late answers into allows and a stale build could
keep serving old rules):

- Undelivered or rejected requests fall back to in-process evaluation:
  unreachable, untrusted, connect timeout, busy, expired, fingerprint
  mismatch, bad request. Every non-"ok" status means nothing was recorded.
- Each request carries a deadline. The daemon starts processing only before
  it; the client waits a further 2 s margin. A delivered request that still
  gets no answer is not re-evaluated, and a PreToolUse then gets the
  stricter of `on_error` and `on_unevaluable`, never allow by default.
- Reads run on a thread per connection (capped at 32) with a 5 s total
  deadline. Evaluation is serialized on one `Runtime`. A trickling client
  cannot stall other hooks (tested). `connect()` has a 500 ms timeout.
- Both ends check the peer's UID (`SO_PEERCRED` / `getpeereid`). That covers
  the race between the path check and `connect()`.
- The fingerprint covers the package version, the host build metadata and
  the executable's identity (see [ADR 0007](0007-hooks-inside-telltale.md); it
  replaced a source-hash build ID). It also covers config, referenced rule bytes,
  and every path input to `Engine::new`, including environment-derived
  defaults. The fingerprint is recomputed after the pipeline build, and the
  build is retried if a rule file changed during it.
- Relative configured paths are made absolute at load time.
- On fingerprint mismatch the daemon retires. It stops accepting, finishes
  in-flight requests, and exits; the next hook starts a current one.
- Clients connect only to a socket whose file and directory are owned by the
  same UID and are not group- or world-writable. A planted socket could
  otherwise answer "no opinion".
- Socket paths beyond the Unix limit fall back to a short per-user path.
  This was found in a real run, where every bind failed and each hook spawned
  a doomed daemon. Autostart has a 30 s backoff.
- The daemon exits when idle, when orphaned (its socket is gone or replaced,
  or its state dir is gone), and on SIGTERM/SIGINT. It removes its socket
  only if the inode is still the one it bound, so it never deletes a newer
  daemon's socket.

Residual risk: if a request starts processing just before its deadline and
the evaluation takes longer than the 2 s margin, the daemon records a
decision while the hook returns the stricter failure verdict. An `error`
record (`evaluator_no_answer`) lets consumers spot the mismatch.
