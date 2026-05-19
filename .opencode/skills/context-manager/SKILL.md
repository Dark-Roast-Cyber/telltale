---
name: context-manager
description: Use ONLY when long-running OpenCode project work needs durable `.ai/` memory, DCP compression, or model-managed context compaction.
compatibility: opencode
---

# context-manager

Use this skill for long-running project sessions where the model should actively manage context without losing important project state.

## Goals

- Keep one long-running OpenCode session useful for hours.
- Treat DCP as the primary context-management mechanism.
- Keep native OpenCode compaction enabled as a fallback safety net.
- Persist the important truth to disk before compression.
- Keep context across related planned items instead of resetting for every task-list entry.
- Allow small batches of related items to move together like a feature slice.

## Durable project memory

Use `.ai/working-state.md` as the main durable memory file.

- `.ai/working-state.md`

Optional:

- `.ai/task-queue.md`

If `working-state.md` does not exist, create it before starting meaningful work.

For each coherent batch, update `working-state.md` twice:

1. when the batch is selected, before non-`.ai/` edits begin
2. when the batch is verified and complete

## Required behavior before compression

Before using DCP `compress` or relying on OpenCode compaction:

1. Make sure `.ai/working-state.md` already captured the selected active batch and planned validation before feature work started.
2. Update `.ai/working-state.md` with:
   - completed work
   - changed files
   - validation run
   - current architecture or workflow assumptions
   - decisions worth keeping
   - unresolved issues or risks
   - next recommended batch
3. Re-read `.ai/working-state.md` and verify it reflects the finished batch.
4. If `.ai/task-queue.md` exists, update it for completed and newly discovered tasks.

Do not compress active debugging detail, current failing output, unwritten decisions, or the current edit plan until `working-state.md` is updated.

## When to compress

Prefer compression when:

- a coherent batch is complete
- the next batch moves to a different feature area
- stale logs, repeated file reads, duplicated tool results, or failed attempts are no longer needed verbatim
- the session is approaching DCP nudges or context thresholds

After compression, re-read `.ai/working-state.md` and continue from the next bounded batch.

## Work style

- Keep one coherent batch active at a time.
- A coherent batch may include 1-3 tightly related planned items that share one milestone and one validation path.
- Do not reset context or restart planning between related items inside the same batch unless the workstream truly changes.
- Prefer the narrowest verification that proves the batch.
- Keep summaries concise and durable.
- Use `working-state.md` as the canonical resume point, not the raw chat transcript.
- If DCP is unavailable, continue the same workflow and let native compaction be the fallback.

## Suggested `.ai/working-state.md` structure

```md
# Working State

## Current focus

## Active batch

## Planned validation

## Last completed batch

## Changed files

## Current assumptions

## Decisions

## Open issues / risks

## Next recommended batch
```

## Optional `.ai/task-queue.md` structure

```md
# Task Queue

## In Progress

## Pending

## Done
```
