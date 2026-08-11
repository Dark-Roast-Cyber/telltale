## Why

The 0.5.0 installer and service contracts are implemented and covered by
fixtures, unit tests, and checked-in examples, but `G-SERVICE` remains
`BLOCKED/B` because the previous Linux user-systemd attempt could not make
private-XDG units visible to the already-running user manager. A new bounded
evidence batch is needed to resolve the validation procedure or record a safe,
reproducible host prerequisite without changing product behavior.

## What Changes

- Freeze the release-gate contract for the Linux current-user installer path
  from the synced installer/service specification, `scripts/install-telltale`,
  checked-in unit examples, installer tests, and release-readiness guidance.
- Distinguish the user-installer units and paths from the separate managed
  system-profile examples; do not use system scope for this gate.
- Define a later apply-session procedure that records bounded pre-state for
  canonical and legacy unit identities, stages canonical artifacts under
  temporary user-owned paths, and proves manager visibility before activation.
- If the manager-visible procedure is safe, exercise the approved canonical
  service path, timer linkage/behavior required by the contract, reload and
  restart behavior, canonical output/state, and exact cleanup/restoration.
- Retain only redacted statuses, counts, path classes, unit identity booleans,
  and hashes where useful; classify the gate as `PASS`, `BLOCKED`, or `FAIL`.
- Hand any reproducible installer/service contract defect to a separate change;
  this batch must not repair it.

## Capabilities

### New Capabilities

None. This is a validation and environment-resolution batch.

### Modified Capabilities

None. No observable product requirement changes. The change declares
`skip_specs: true` in `.openspec.yaml` so it does not invent a behavioral delta
spec for validation evidence.

## Impact

- **Product/runtime:** no Rust, installer, unit-template, schema, state, sink,
  or configuration behavior changes are authorized.
- **Apply-time host scope:** only the current user's Linux user-systemd manager
  may be considered. Temporary binary, configuration, unit, source-root,
  log, and state paths must be user-owned and removed after the bounded proof.
- **Host safety:** before any mutation, the apply session must record bounded
  state and hashes for `telltale-scan.service`, `telltale-scan.timer`,
  `adr-scan.service`, and `adr-scan.timer` when present. It may touch only the
  approved identities and only with an explicit restoration plan.
- **Release evidence:** later evidence may reconcile `G-SERVICE` in local
  planning/readiness state, but it must not make native Windows/macOS,
  HEC/Splunk, publication, or public-release claims.

## Acceptance Criteria

- The authoritative contract states the canonical user binary, unit/timer
  identities, install namespace, executable invocation, temporary/runtime
  configuration paths, migration behavior, and existing-unit semantics.
- The later apply session proves real user-systemd manager visibility and the
  release-required service behavior, or records the exact safe prerequisite
  that keeps `G-SERVICE` blocked. Unit templates, fake-manager tests, or CI
  alone cannot produce `PASS`.
- The service proof uses the reviewed 0.5.0 binary/tag and records only its
  version/hash; a missing matching release candidate blocks before manager
  mutation rather than silently exercising a different public release.
- A `PASS` includes sufficient redacted evidence for staging/install,
  `daemon-reload`, bounded service execution, required timer behavior,
  restart/status, canonical JSONL/state outcomes, and complete restoration.
- `BLOCKED` is used for an unavailable or unsafe host/session prerequisite;
  `FAIL` is reserved for a reproducible violation of the approved contract.
  Neither outcome authorizes product repair in this batch.
- No service is left enabled unless it was enabled before validation; no
  unrelated service, system scope, secret, private transcript, preserved
  README/docs stash, or Tokscale export is touched.

## Non-goals

- Reopening or modifying archived OpenSpec changes.
- G-HEC, G-SPLUNK, live Splunk work, HEC credentials, or endpoint discovery.
- Native Windows/macOS host validation or cross-platform release claims.
- Release preflight, tagging, publication, hosted-site cutover, PR merge, or
  changing PR #9's Draft state.
- Rust, installer, service, timer, schema, parser, state, sink, or OpenCode
  configuration changes.
- Removal or migration of a legacy unit unless the existing approved installer
  contract explicitly requires it and the later validation safely exercises
  that already-approved behavior.
- Modification, inspection, application, or removal of the preserved README/docs
  stash or `tokscale-export-20260809-013857.json`.
