## Why

The archived Phase 6 validation proved the synthetic and deterministic Telltale
contracts but left the two locally resolvable release gates, `G-HOST-SOURCE` and
`G-SERVICE`, blocked. This bounded follow-up records whether the current Linux
host can truthfully provide one usable supported source and a reversible
user-systemd proof, without turning an absent source or host prerequisite into a
product failure.

## What Changes

- Reconfirm the current branch, tracked worktree boundary, archived Phase 6
  evidence, active OpenSpec state, and Draft PR #9 CI status before execution.
- Diagnose each supported current-host Codex and OpenCode source independently
  with bounded metadata, discovery, permission, usability, and smallest
  representative-read checks; retain only redacted counts, statuses, classes,
  and hashes where needed.
- Investigate the previous OpenCode timeout with bounded status/read operations
  against the configured source, without exposing session contents, prompts,
  messages, transcripts, or raw database rows. Do not fabricate Codex data.
- Diagnose the prior isolated service-staging failure against the approved
  installer/service contract and, only when safe, validate canonical Telltale
  user-systemd staging, reload, least-invasive execution, observation, and
  cleanup using temporary synthetic paths.
- Record a PASS, BLOCKED, or FAIL disposition for `G-HOST-SOURCE` and
  `G-SERVICE`, including whether the result is source absence, an environment or
  permission limitation, a corrected validation procedure, or a reproducible
  Telltale defect. Product defects must be handed to a separate change.
- Preserve the existing `G-HEC` and `G-SPLUNK` BLOCKED dispositions and do not
  perform HEC, Splunk, hosted cutover, merge, release, or publication work.

## Capabilities

### New Capabilities

None. This is an evidence and environment-resolution batch; it introduces no
runtime capability.

### Modified Capabilities

None. No product requirement, schema, parser, rule, state, sink, installer, or
service behavior changes. `.openspec.yaml` sets `skip_specs: true` deliberately.

## Impact

- **Product/runtime:** no Rust or configuration behavior changes are authorized.
- **Validation environment:** bounded inspection may read supported local source
  metadata and may create temporary synthetic roots, logs, state, staged units,
  and units under the current user's systemd scope only. Any pre-existing
  Telltale user units/configuration must be recorded and restored exactly.
- **Evidence/status:** add a redacted ledger and measured release-readiness or
  durable-state updates only when supported by execution; never retain raw
  session/source/service output or secrets.
- **Compatibility and safety:** use the canonical `telltale` executable and
  approved user-service contract, avoid unrelated services, leave no newly
  persistent timer, and stop with an exact prerequisite when user-systemd
  activation is unsafe or unavailable.

## Acceptance Criteria

- Every supported live source on this host has an evidence-backed A/B/C
  classification and the host gate ends as PASS, BLOCKED, or FAIL.
- The OpenCode timeout is either explained and safely resolved with a bounded
  representative check, or recorded as an exact environment/procedure blocker;
  no private source content is retained.
- The service gate either proves reversible user-systemd staging and bounded
  execution with cleanup/restoration, or records the exact environmental
  prerequisite; no service mutation is papered over.
- No product defect is silently repaired, the archived Phase 6 change is not
  modified, and `G-HEC`/`G-SPLUNK` remain BLOCKED and out of scope.
- Evidence is reviewed by `coder-quality`, tracked changes pass the appropriate
  repository checks, the change is committed, pushed normally, archived, and
  the Draft status of PR #9 is preserved.

## Non-goals

- Reopening or modifying `phase-6-host-validation`.
- HEC credentials, HEC delivery, Splunk searches, Splunk configuration, or any
  work intended to resolve `G-HEC` or `G-SPLUNK`.
- Creating synthetic data in a real Codex/OpenCode user source directory merely
  to obtain a PASS, or dumping private sessions, transcripts, prompts,
  messages, database rows, credentials, `.env` values, or exact private paths.
- Rust, rule, parser, schema, state, sink, installer, service implementation,
  OpenCode configuration, or unrelated service changes.
- Merging or marking PR #9 ready, tagging, releasing, publishing, hosted
  cutover, or changing the preserved README/docs stash or
  `tokscale-export-20260809-013857.json`.
