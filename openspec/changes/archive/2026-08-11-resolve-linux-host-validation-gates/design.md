## Context

See `proposal.md` for the motivation and bounded acceptance contract. The
archived Phase 6 ledger is the baseline and must not be edited. The applicable
source contract is `docs/source-validation-matrix.md` and
`docs/session-sources.md`; the applicable service contract is the accumulated
`openspec/specs/installer-service-archive/spec.md` and the current
`scripts/install-telltale` implementation.

The host is Linux. The prior source attempt returned no usable Codex sources
and timed out while checking OpenCode. The prior service attempt detected a
reachable user-systemd manager but failed before isolated staged units became
loadable. These are hypotheses to investigate, not product failures to assume.

## Goals / Non-Goals

**Goals:**

- Produce a redacted evidence ledger that separates source existence,
  discovery, permissions, parse usability, timeout/lock behavior, and service
  manager behavior for the two gates.
- Use the smallest bounded read that can establish whether the current host has
  usable `codex.*` or `opencode.*` records. Preserve source absence as
  not-applicable rather than manufacturing a source.
- Exercise only current-user systemd with a private, temporary validation
  workspace, a canonical `telltale` binary/unit, synthetic fixtures, and an
  explicit restore plan. Prove cleanup before classifying the gate.
- Distinguish one safe procedure correction/retry (A), an unavailable host
  prerequisite (B), and a reproducible product defect (C); do not repair C here.

**Non-Goals:**

- Any product/runtime implementation, parser performance change, schema/rule
  change, installer change, OpenCode configuration change, or new service
  manager support.
- HEC/Splunk validation, credentials or endpoint discovery, hosted cutover,
  publication, release, merge, or PR readiness changes.

## Decisions

1. **Evidence-only artifact, no delta spec.** Keep `skip_specs: true` because
   the observable product contract is unchanged. Store only a redacted
   `evidence.md`, task dispositions, and narrowly justified durable/readiness
   status updates.

2. **Source diagnosis is per client and per registered identity.** First inspect
   candidate roots using metadata-only checks (existence, type, ownership/mode,
   readability, size/mtime class, and database schema/table presence without
   row values). Then run at most one bounded dry-run per relevant client with
   `--client` and `--max-sources`; discard stdout after projecting counts and
   error categories. If the initial result is inconclusive, make one bounded A
   retry with a smaller cap or a narrower representative check, then stop.
   Alternatives rejected: broad home scans, repeated timeout hammering, and
   synthetic files in real user source directories.

3. **OpenCode timeout diagnosis uses metadata before Telltale parsing.** The
   current configured source is checked with a read-only, bounded SQLite
   metadata/status query (or equivalent filesystem metadata for legacy JSON),
   followed by one smallest representative Telltale read. Do not print rows,
   JSON payloads, prompts, messages, transcripts, or database contents. A
   busy/locked or oversized/slow source is recorded as an environment/procedure
   limitation unless a narrowly reproducible Telltale defect is demonstrated;
   any such defect is evidence-only and handed to a separate change.

4. **Systemd proof uses the approved user installer path but isolates execution.**
   Record manager availability and bounded pre-state for
   `telltale-scan.service` and `.timer` without environment dumps. Use a private
   temporary `HOME`, XDG config/state roots, install directory, synthetic source
   root, and output paths; stage with `--from-source --install-dir <temp>
   --no-timer`. Inspect only canonical identity/path booleans and hashes. Since
   `%h` is resolved by the already-running user manager, do not execute an
   unmodified staged unit: use a temporary user-unit override/drop-in or another
   manager-supported private path mechanism, hash it before/after, and remove it
   before restore.

5. **Least-invasive activation and exact restoration.** Prefer a direct bounded
   `systemctl --user start` of the temporary canonical service after a
   successful `daemon-reload`; timer activation is optional evidence and must
   not be left enabled. If current-user units must be touched, back up exact
   bytes, enablement, active state, and drop-in state first, mutate only owned
   Telltale units, then stop/disable/remove temporary units, reload, restore,
   compare hashes/states, and verify no staged path remains. Any unproven
   restoration stops the service path with `G-SERVICE` BLOCKED.

6. **Gate semantics remain conservative.** `G-HOST-SOURCE` passes only when at
   least one real current-host supported source yields usable bounded records;
   source absence on this host is A (not applicable) or B (environment) and is
   not a defect. `G-SERVICE` passes only after real user-systemd reload and
   bounded execution/observation plus cleanup; manager or session limitations
   remain B. Wrong canonical identity, wrong temporary paths, duplicate
   schedules, data loss, or failed restoration are C and remain an unpassed
   gate.

## Risks / Trade-offs

- **[Risk]** A live source may be large or actively written and exceed the
  bounded read window. **Mitigation:** metadata-first checks, a strict timeout,
  one retry maximum, no raw capture, and explicit B/C classification.
- **[Risk]** The current user manager may resolve `%h` or unit directories from
  the real session rather than temporary environment roots. **Mitigation:**
  preflight unit resolution and a hashed temporary override; never fall back to
  the real profile without a complete backup/restore plan.
- **[Risk]** A pre-existing Telltale unit or timer could be changed by an
  installer smoke path. **Mitigation:** record pre-state and exact bytes,
  require ownership checks, keep timer disabled unless it existed enabled, and
  verify post-state equivalence.
- **[Risk]** CI or fixture success could be mistaken for native host proof.
  **Mitigation:** keep synthetic/CI evidence separate and classify only the
  commands actually exercised on this Linux host.
- **[Risk]** Evidence could reveal private source details. **Mitigation:** retain
  counts, classes, booleans, redacted error categories, and short hashes only;
  discard raw stdout, unit bytes, database output, logs, and temporary paths.

## Migration Plan

No product migration or deployment occurs. Apply-time work creates only the
OpenSpec evidence/status files and temporary validation material. On every
service path, stop/disable temporary units, remove overrides and staged units,
restore any pre-existing bytes and enablement, reload user-systemd, compare
pre/post hashes and state classes, and remove temporary binary/config/log/state
roots. Archive the change only after review, validation, cleanup, commit, and
normal push.

## Open Questions

None. The remaining uncertainty is an execution result to classify within this
contract, not a design decision to defer.
