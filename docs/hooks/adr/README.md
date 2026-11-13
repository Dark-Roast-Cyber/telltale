# Architecture decision records

Short records of consequential decisions: context, decision, evidence,
rejected alternatives, consequences. Supersede rather than rewrite.

| ADR | Decision | Status |
| --- | --- | --- |
| [0001](0001-rust-and-telltale-embedding.md) | Rust, Telltale through the supported embedding facade | Accepted |
| [0002](0002-pending-action-evaluation.md) | Evaluate pending calls by scanning a hook-built native journal window | Accepted |
| [0003](0003-process-model.md) | Per-invocation process now; long-lived evaluator next | Accepted (interim) |
| [0004](0004-decisions-and-enforcement-accounting.md) | Host promotion policy; never `allow`; outcome-based enforcement accounting | Accepted |
| [0005](0005-telemetry-envelope.md) | Host envelope around unmodified `ActionRecordV1` | Accepted |
| [0006](0006-first-harness-claude-code.md) | Claude Code first | Accepted |
| [0007](0007-hooks-inside-telltale.md) | Hooks live inside Telltale as a default-on feature; build identity follows the executable | Accepted; supersedes the pin and build-ID parts of 0001 and 0003 |
