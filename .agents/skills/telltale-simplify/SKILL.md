---
name: telltale-simplify
description: Plan and implement bounded Telltale code reduction, consolidation, and refactoring while preserving accepted semantic, privacy, delivery, and consumer contracts. Use when explicitly asked to simplify or remove complexity, not for every coding task.
---

# Bounded simplification

Start from the requested subsystem or accepted issue. Read the relevant portions
of root `AGENTS.md`, `docs/development-principles.md`, `ROADMAP.md`, and the affected
`openspec/specs/` contracts. Inspect current code, callers, feature gates, tests,
and recent history. Distinguish shipped behavior, accepted future direction,
intentional compatibility, and completed migration residue.

## Find a real reduction

Trace one behavior end to end. Identify its authoritative semantic owner and
look for repeated conversions, duplicated state/validation, pass-through layers,
obsolete compatibility or shadow paths, and tests coupled to retiring internals.
Choose a bounded candidate that makes complexity disappear rather than moving it
to callers. Prefer existing domain types and native mechanisms.

Do not call code dead from one search, a private name, or one platform's build.
Check public/embedding callers, registration, feature combinations, packaging,
platform-specific paths, and serialized/persisted contracts. Do not delete an
intentional compatibility boundary merely to reach a line-count target.

Before editing, state the observed problem, proposed single owner/end state,
what becomes unnecessary, protected behavior, and decisive validation. When a
migration is involved, identify activation and deletion gates. Reject speculative
frameworks, mass renaming, file splitting for size alone, and simultaneous
foundational rewrites. Respect accepted scope and release freeze boundaries.

## Implement and prove

Make one coherent change. Update affected callers and remove superseded private
code, fixtures, and documentation in that same bounded change when safe. Keep
regressions through durable behavior, not copies of every retired helper test.
Preserve error distinctions, source progress/cursor rules, privacy before export,
resource bounds, event wire/persistence contracts, and delivery/recovery behavior
where touched. Consult their authoritative documents instead of reconstructing
new rules here.

Use focused synthetic tests first and the existing Makefile/scripts for required
integration, consumer, platform, and publication checks. Exercise real boundaries
when acceptance depends on them. A mock or unit test is not proof of a packaged
install, Windows runtime, crash recovery, or external sink. Never inspect personal
session stores or activate live services for convenient test data.

Keep implementation and diagnosis together. Delegate only independent evidence,
a genuinely separate change in another worktree, or a consequential review.
Inspect the resulting diff and validate the combined revision. If the proposed
removal exposes a protected contract, narrow the change rather than hide the
failure with a second compatibility layer.

## Return

Summarize what responsibility now has one owner, which code/concepts/dependencies
were removed, behavior intentionally unchanged or changed, actual validation,
and remaining uncertainty. Report line counts only as a secondary measurement;
do not compress readable code or weaken tests to improve the number. Leave
unrelated candidates as short follow-up observations, not a new architecture
program. Keep execution notes local and durable product truth in existing docs.
