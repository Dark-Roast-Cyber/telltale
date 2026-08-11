## 1. Preflight and evidence boundary

- [x] 1.1 Reconfirm `release/0.5.0-maturation` and its upstream, tracked
  worktree cleanliness, zero active OpenSpec changes before this change, the
  intact archived Phase 6 evidence, and Draft PR #9 check status; stop if a
  completed post-Phase-6 product check is actually failed.
- [x] 1.2 Create a private, redacted evidence ledger and record the immutable
  boundaries: do not inspect or modify the README/docs stash or
  `tokscale-export-20260809-013857.json`, do not reopen Phase 6, and preserve
  `G-HEC`/`G-SPLUNK` as BLOCKED.

## 2. G-HOST-SOURCE diagnosis

- [x] 2.1 For every supported Codex and OpenCode live identity relevant to this
  Linux host, perform bounded metadata-only existence, discovery-path,
  ownership/permission, and usability checks; retain only source classes,
  counts, modes/statuses, and redacted failure categories.
- [x] 2.2 Run one bounded dry-run per applicable client using the canonical
  `telltale` discovery path with `--client` and `--max-sources`; project parsed,
  failed, empty, and timeout results without retaining source records or raw
  stdout.
- [x] 2.3 Diagnose the OpenCode timeout with the actual configured/current
  storage source using a bounded schema/lock/status query and the smallest
  representative validation read; make at most one safe narrower retry, then
  classify the cause as A/B/C without changing parser code or OpenCode config.
- [x] 2.4 Determine whether Codex is absent/not applicable, inaccessible, empty,
  or usable on this host without creating data in a real Codex directory; record
  `G-HOST-SOURCE` as PASS only if a real supported source is exercised, otherwise
  BLOCKED/FAIL with exact redacted evidence and a separate-defect handoff if C.

## 3. G-SERVICE user-systemd validation

- [x] 3.1 Inspect the approved installer/service implementation, current user
  systemd availability, canonical service/timer pre-state, unit ownership, and
  the exact prior isolated-staging failure category using bounded metadata only;
  record a reversible backup/restore plan before any mutation.
- [x] 3.2 In a private temporary HOME/XDG/install/root/log/state workspace, run
  the approved source staging path with `--no-timer`, verify canonical unit
  identity and temporary path overrides, and correct the staging procedure once
  if the failure is procedural; do not fall back to the real profile silently.
- [x] 3.3 If isolated staging is loadable and safe, run the least-invasive
  user-systemd proof (`daemon-reload` and bounded canonical service execution,
  plus timer linkage only if safe), observe status/result and synthetic output,
  then stop/disable/remove temporary units and restore exact prior state.
- [x] 3.4 Compare pre/post unit and override hashes/state classes, verify no new
  persistent timer, staged binary, config, log, state, or drop-in remains, and
  record `G-SERVICE` as PASS only for operations actually exercised; otherwise
  record BLOCKED/FAIL with the exact environmental or defect classification.

## 4. Review and release-status reconciliation

- [x] 4.1 Reconcile the evidence ledger, task dispositions, `PLAN.md`, and
  `.ai/working-state.md` so both requested gates end as PASS, BLOCKED, or FAIL,
  no product defect is papered over, HEC/Splunk remain outside scope, and the
  privacy/cleanup boundary is explicit.
- [x] 4.2 Obtain one fresh `coder-quality` / Luna Max review of source
  classification, OpenCode timeout evidence, user-systemd exercise and
  restoration proof, product-change avoidance, and scope boundaries; apply only
  concrete evidence/documentation corrections.

## 5. Verification, commit, and archive

- [x] 5.1 Run the narrowest evidence/OpenSpec validation and `git diff --check`,
  then run `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
  and `cargo test`; confirm the untracked Tokscale export and preserved stash
  remain untouched.
- [ ] 5.2 Commit only legitimate evidence/status/OpenSpec changes, push normally
  to `origin/release/0.5.0-maturation`, confirm PR #9 remains Draft and report
  its current CI state without marking it ready or merging.
- [ ] 5.3 Archive `resolve-linux-host-validation-gates`, validate that no active
  OpenSpec change remains, update durable state with changed files, validation,
  decisions, risks, and next batch, and stop without beginning HEC/Splunk work.
