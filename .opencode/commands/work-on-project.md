---
description: Work this project in iterative batches with durable state and model-managed context.
---

Load the `context-manager` skill immediately if it is available, then continue in the current primary session.

Treat this as long-running project work for the current repository.

Command arguments: `$ARGUMENTS`

Parse these optional flags from the command arguments:

- `--iterations <n>`: maximum number of bounded work iterations to run in this session. Default to `15`.
- `--iteration-delay <ms>`: soft pacing hint between iteration boundaries. Default to `100`. Do not waste tool calls on `sleep` unless a short delay is actually useful for command sequencing or polling.

Workflow requirements:

1. Before starting, read `AGENTS.md`, `.ai/working-state.md`, and `.ai/task-queue.md` if it exists.
2. If `.ai/working-state.md` is missing, create it with a concise structure before continuing.
3. Pick exactly one coherent batch of related work at a time.
4. A batch may include `1-3` tightly related planned items when they share one milestone, one file area, and one validation story. Do **not** reset context between those related planned items just because one item is complete.
5. Treat iteration boundaries as batch boundaries. Within an active batch, keep going until the related slice is implemented and verified, or until you are blocked.
6. Before editing non-`.ai/` repo files for a new batch, update `.ai/working-state.md` with:
   - current focus
   - active batch
   - planned validation
7. Immediately re-read `.ai/working-state.md` after that pre-work update and verify it reflects the batch you are about to execute.
8. Implement only that batch, using the narrowest correct verification for the change.
9. A batch is **not complete** until `.ai/working-state.md` has been updated for that batch.
10. After each completed batch, update `.ai/working-state.md` with durable project memory:
   - completed work
   - changed files
   - validation run
   - current assumptions or decisions
   - open issues or risks
   - next recommended batch
11. Immediately re-read `.ai/working-state.md` after that completion update and verify the file now reflects the batch you just finished.
12. Do **not** start another batch, switch topics, compress context, or give a completion summary until that re-read verification has happened.
13. If any repo files changed during the session and `.ai/working-state.md` does not yet mention those changes, stop feature work and update `.ai/working-state.md` before doing anything else.
14. Keep `.ai/task-queue.md` only if it is useful. If it exists, update it to match the current state. If it does not exist, do not create extra files unless they clearly help.
15. Let the model manage context proactively:
    - use the DCP `compress` tool only after a coherent batch is complete **and** `.ai/working-state.md` has been updated and re-read
    - use the DCP `compress` tool before switching feature areas
    - use the DCP `compress` tool when old investigation detail, repeated reads, stale logs, or failed attempts are no longer needed verbatim
    - do **not** compress active implementation details, current failing errors, or unwritten decisions before they are captured in `.ai/working-state.md`
16. If the DCP tool is unavailable, rely on native OpenCode compaction as the fallback and keep updating `.ai/working-state.md` before moving on.
17. After compression, re-read `.ai/working-state.md` and continue from the next batch.
18. Stop when the requested iteration limit is reached, the session is blocked, or there is no safe next batch. Before stopping, make sure `.ai/working-state.md` reflects the latest completed batch in the session.

Operate autonomously, but prefer small reversible changes and keep the project state on disk ahead of context compression.
