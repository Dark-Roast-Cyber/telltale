# Durable Session Workflow

For long-running work in this repository, keep one session useful across a coherent workstream instead of resetting context for each planned item.

## Required behavior

1. Keep context across related planned items when they belong to the same milestone, touch the same area, and share one validation story.
2. Batch 1-3 tightly related planned items together the same way you would batch a small feature slice.
3. Treat an iteration boundary as a batch boundary, not as a mandatory reset after every individual task list item.
4. Before changing non-`.ai/` repo files for a new batch, update `.ai/working-state.md` with:
   - current focus
   - active batch
   - planned validation
5. Re-read `.ai/working-state.md` immediately after that update so the active batch is anchored in durable state before feature work continues.
6. After verification, update `.ai/working-state.md` again with:
   - completed work
   - changed files
   - validation run
   - current assumptions or decisions
   - open issues or risks
   - next recommended batch
7. If `.ai/task-queue.md` exists, keep its statuses aligned with the active and completed batch.
8. Do not compress context, switch to an unrelated area, or end the session while repo changes are missing from `.ai/working-state.md`.

## Intent

- Preserve durable project memory on disk before model-managed compression.
- Allow the model to continue through a related mini-batch without unnecessary context resets.
- Keep summaries and next-step handoffs short, current, and easy to resume.
