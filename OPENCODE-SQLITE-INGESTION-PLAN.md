# OpenCode SQLite Ingestion Plan

Temporary working plan for improving mutable OpenCode SQLite ingestion without redesigning all Telltale sources.

Status: initial live-ingestion slice implemented. Historical full-DB backfill remains deferred.

## Problem

OpenCode SQLite is a monolithic mutable database. Treating `opencode.db` as one source fingerprint is weak for correctness and performance because rows are appended and updated independently. JSON/JSONL file sources can keep content-level fingerprinting; SQLite needs record-level ingestion semantics.

## Direction

1. Treat OpenCode SQLite as a record stream.
2. Track high-water state per SQLite source/table instead of relying only on the DB file fingerprint.
3. Re-read a small recent overlap so rows that move from running to completed are not missed.
4. Normalize `part` tool/text rows into meaningful activity records before detection.
5. Preserve legacy `message` table support.
6. Keep live scan bounded; make complete historical DB backfill explicit later.

## Minimal Slice

1. Add scanner state for SQLite cursors keyed by stable source identity and table name. Done.
2. For OpenCode `part`, query rows newer than the stored cursor with a small overlap and a per-scan limit. Done.
3. Save the max observed `time_updated` after a successful non-dry-run scan. Done.
4. Keep dry-run behavior from advancing persistent state. Done.
5. Prefer host OpenCode SQLite over host legacy storage/message JSON when both are present. Done.
6. Preserve fixture coverage for both SQLite and legacy JSON. Done.
7. Emit enough health evidence to diagnose bounded SQLite ingestion later if needed. Deferred.

## Deferred

1. Dedicated historical DB backfill command or mode.
2. First-class canonical schema fields such as `source_record_id`, `activity_type`, `tool_status`, and `call_id`.
3. Rich joins to `session`, `project`, and `workspace` for model/agent/worktree attribution.
4. Full timeline/action ledger modeling for tool lifecycle events.

## Acceptance

1. No committed copied live DBs or fixture residue.
2. Tests create temporary SQLite databases at runtime only.
3. Full verification passes.
4. Repeated non-backfill scans do not repeatedly process the same old OpenCode SQLite `part` rows once cursor state exists.
