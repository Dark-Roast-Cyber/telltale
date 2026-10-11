# Resource-bounded continuous observer

**Status: not shipped.** This page is the public boundary for a proposed
continuous observer. It is not current `scan` or `watch` behavior, and it does
not authorize service, packaging, or deployment changes.

The previous long plan was removed from the public tree because it mixed a
shipped admission limit with an unbuilt service. Git history still has that
plan. Do not treat it as a build or deployment instruction.

## What is current

`telltale scan` and `telltale watch` are the shipped observation modes. Watch
scheduling and storage placement are in the [install guide](install.md).

Production JSONL admission limits are shipped. They are specified in the
[source-support denominator](../openspec/specs/source-support-denominator/spec.md)
and [canonical accounting coverage](../openspec/specs/canonical-accounting-coverage/spec.md).
These JSONL limits exclude Copilot process logs and OpenCode SQLite. OpenCode's
separate limits are documented in [OpenCode live ingestion](opencode-live-ingestion.md).
Admission bounds are not a process-memory promise, a heap limit, or a continuous
service.

## What remains proposed

A later observer would run continuously with explicit start, stop, and status,
optional reboot persistence, and the same acquisition, detection, privacy, and
durable-output contracts as one-shot scanning. It would not be a tamper-proof
agent or an active blocking control.

That service, any resource policy beyond the shipped admission limits, and a
dedicated health model are not implemented. [Roadmap](../ROADMAP.md) lists the
direction. [Development principles](development-principles.md) constrain it.
Neither page approves the work.
