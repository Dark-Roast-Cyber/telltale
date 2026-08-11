## Context

See `proposal.md` for motivation and scope. The current authoritative product
contract is `openspec/specs/installer-service-archive/spec.md` together with
`scripts/install-telltale`, `docs/install.md`, the checked-in unit examples,
installer tests, and the archived Phase 6 service tasks. The prior host evidence
is redacted in
`openspec/changes/archive/2026-08-11-resolve-linux-host-validation-gates/evidence.md`.

This is an evidence-only change. It does not alter the installer, unit files,
Rust code, schemas, state semantics, or service behavior.

## Goals / Non-Goals

**Goals:**

- Establish one unambiguous Linux current-user systemd contract for the 0.5.0
  gate, including what the installer owns and what the managed system-profile
  examples do not prove.
- Give the later apply session a least-invasive, manager-visible validation
  path with explicit pre-state capture, bounded mutations, and exact restore
  checks.
- Prove only operations actually exercised by a real user-systemd manager and
  retain privacy-safe evidence sufficient to classify `G-SERVICE`.
- Treat an unavailable or unsafe manager/session as `BLOCKED`, and a
  reproducible contract violation as `FAIL` with a separate defect handoff.

**Non-Goals:**

- Creating a new service manager integration or changing private-XDG/systemd
  behavior in the installer.
- Proving the separate managed system-profile service path, native Windows or
  macOS behavior, HEC/Splunk delivery, or release publication.
- Inventing an uninstall command. The installer has install/upgrade and
  rollback semantics; validation cleanup removes only marker-owned temporary
  material and restores the prior host state.

## Authoritative Linux user-systemd contract

### Installed identities and locations

The current-user installer is Linux-only, rejects root/system scope, and
requires every install path to remain under the current user's home. With
`INSTALL_DIR` defaulting to `~/.local/bin`, the canonical executable is:

- `${INSTALL_DIR}/telltale` (normally `~/.local/bin/telltale`).

The installer resolves these roots before creating or mutating anything:

- configuration root: `${XDG_CONFIG_HOME:-$HOME/.config}`;
- state root: `${XDG_STATE_HOME:-$HOME/.local/state}`;
- user-unit directory: `<configuration root>/systemd/user`;
- canonical log: `<state root>/telltale/logs/telltale-events.jsonl`;
- canonical state: `<state root>/telltale/telltale-state.json`;
- optional environment file: `<configuration root>/telltale/telltale.env`.

`stage_units` always generates both user units in that user-unit directory:

- `telltale-scan.service`: a `Type=oneshot` service with
  `TELLTALE_LOG_PATH`, `TELLTALE_STATE_PATH`, and
  `TELLTALE_SCAN_ROOT=%h`; it invokes the canonical executable as
  `telltale scan --once --emit-activity --root "${TELLTALE_SCAN_ROOT}" --path-profile user`.
- `telltale-scan.timer`: `OnActiveSec=1min`, `OnUnitActiveSec=5min`,
  `Persistent=true`, and `Unit=telltale-scan.service`.

The normal installer transaction installs units disabled. `--no-timer` keeps
the canonical schedule disabled; `--with-timer` enables only
`telltale-scan.timer` with `enable --now` after smoke tests. The installer does
not install the checked-in `config/examples/telltale-scan.service` and
`.timer` files. Those examples describe a separate managed system-profile
deployment using `/usr/local/bin/telltale`, `/var/log/telltale`,
`/var/lib/telltale`, `/etc/telltale`, a service account, and
`--path-profile system`; using those paths or system scope would be a different
release claim.

### Candidate binary provenance

The service proof must exercise the reviewed 0.5.0 candidate, not whichever
public release happens to be latest. The current `--from-source` implementation
fetches release metadata and runs `cargo install --git ... --tag
<version_tag> --locked`; it does not build the current checkout. Therefore the
later apply session must first obtain an approved expected tag and artifact
digest from the release candidate and verify the public metadata/checksum
without invoking the installer. It must then verify the installed temporary
binary's version and digest before any service start. Because the current
installer refetches `latest` and has no tag/digest input, a tag or digest
mismatch after staging requires cleanup and `G-SERVICE=BLOCKED/B`; do not use
`--skip-checksum` or proceed to activation. With the current unpublished 0.5.0
branch and no matching approved tag/archive, the session must stop before
service-manager mutation with the bounded release artifact prerequisite. A
locally built or public 0.3.x binary must not be substituted silently, and this
validation change does not authorize changing the installer to accept one.

### Existing-unit and migration semantics

The approved installer owns the current user's user-unit directory and
explicitly considers these identities only:

- `adr-scan.service` and `adr-scan.timer` as identified historical units;
- `telltale-scan.service` and `telltale-scan.timer` as canonical units.

Before staging, it reloads the user manager, queries bounded state, and proves
all four schedules are disabled/inactive before unit or binary mutation. If
both old and new timers are enabled or active, it disables/quiesces the known
schedules and fails closed rather than leaving duplicate schedules.

For an owned regular legacy unit in the installer's exact user-unit directory,
the approved transaction may quiesce and stage it, install canonical units,
and remove the old unit from the active directory on a successful commit. It
does not delete an unidentified, non-owned, symlinked, externally located, or
otherwise ambiguous service definition. Legacy state, event-log, and
environment migration runs before activation and retains the old bytes until
commit; rollback restores the staged old units and binary without clobbering
unrelated files. A pre-existing canonical unit is likewise staged and replaced
only through the transaction, with exact rollback bytes available.

There is no approved generic uninstall operation. For this gate, “uninstall”
means stopping/disabling validation-owned runtime objects, removing
validation-owned temporary units/overrides/binaries/config/log/state, and
restoring every pre-existing file and enablement state. A legacy unit observed
on the host is evidence to account for, not permission to delete outside the
approved installer transaction.

### Release-gate operation matrix

The 0.5.0 host gate is the Linux `user-systemd` service/timer behavior from
PLAN Phase 6 and archived Phase 6 tasks 7.1–7.2. The following distinctions
prevent a unit-template check from being mistaken for live proof:

| Operation | Gate requirement and evidence |
| --- | --- |
| Install/stage | Required. Use the approved installer path and prove canonical binary/unit identity, manager-visible fragment paths, disabled initial schedule, and temporary user-profile paths. |
| `daemon-reload` | Required after any unit install/override change. Record bounded success and manager load state. |
| Service start | Required. Run the canonical oneshot with a synthetic source root and temporary log/state paths; observe bounded success/result and canonical invocation. |
| Re-execution/restart | Required. Run two separate `systemctl --user start telltale-scan.service` invocations and one `systemctl --user restart telltale-scan.service`; inspect bounded exit/result properties and prove state continuity with no duplicate emission on unchanged input. Restarting the user manager itself is not allowed. |
| Status | Required after reload, execution, timer activation, and cleanup. Retain only state/result/exit/path-class projections, not journal or environment dumps. |
| Timer behavior | Required for an unqualified `G-SERVICE` PASS: prove canonical linkage/schedule loading and one timer-triggered service result after a bounded wait of no more than 75 seconds for the documented one-minute first fire. If timer fire cannot be safely awaited, retain linkage as partial evidence but leave `G-SERVICE` `BLOCKED/B`; do not claim the full gate passed. |
| Canonical output/state | Required. Use the checked-in two-record `install-persistence-chain` fixture: the first run must emit one detection, the unchanged second run must emit zero new detections and count one state-deduplicated detection, JSONL lines must validate against Event 3.0, and the state commit/schema class must be present. |
| Disable/stop | Required cleanup. Stop validation-owned active units and disable any validation-owned enablement. Never disable a unit that was not enabled by the validation unless restoring an installer-quiesced pre-state requires it. |
| Uninstall/restore | Required as cleanup, not as a product feature. The fallback blocks initially enabled/active units; for an eligible disabled/inactive pre-state, remove only validation-owned temporary artifacts, restore exact pre-existing unit/drop-in bytes and state classes, reload, and verify equality/residue absence. |

Existing installer tests remain the authoritative fixture proof for migration,
rollback, `--with-timer` sequencing, duplicate conflict, canonical unit
generation, and XDG escaping. Live proof must not silently substitute those
tests or CI for the manager operations above.

The live service sequence has a fixed bounded expectation: the two-record
`install-persistence-chain` fixture yields first-run
`parsed_records=2, emitted_detections=1, state_deduplicated=0`; the unchanged
second start, service restart, and isolated timer-triggered run each yield
`emitted_detections=0, state_deduplicated=1`, with no new detection event ID.
Other activity/health line counts may be projected but do not replace these
detection-flow assertions.

## Decisions

### 1. Keep the delta spec intentionally skipped

The batch records evidence for already-approved behavior. `.openspec.yaml`
therefore sets `skip_specs: true`; creating a service behavior spec here would
claim a product change that is not authorized.

### 2. Classify the prior private-XDG failure as B

The primary classification is **B: expected systemd user-manager limitation**.
`systemctl --user` addressed the already-running manager, while supplying a
private `HOME`/XDG configuration root to the installer changed the installer's
expected unit directory but did not establish a separate manager with that
unit search path. The manager therefore retained a visible legacy unit from
the real user namespace and the installer correctly failed its fragment/path
ownership check before staging or activation.

The private-XDG directory was treated as manager isolation without first
proving manager visibility, and a pre-existing legacy unit was the host
condition that exposed the mismatch. Those are observations, not additional
classification labels: under the repository's evidence taxonomy the attempt is
`failure_class=B`. In the user's A/B/C/D diagnostic wording, A is the
procedure assumption, C is the legacy host condition, and D would mean an
installer/product defect; the primary result remains B. A later apply session
may reclassify only on new evidence. If it reproduces a product defect, record
repository `failure_class=C` and user-facing D, hand it to a separate change,
and do not repair it here.

### 3. Use a real manager-visible path, in least-invasive order

The later apply session must choose one of these paths before any activation:

1. **Existing isolated manager only:** use a separately managed current-user
   systemd session/manager only when the host already provides an approved,
   documented way to bind the real `systemctl --user` endpoint to a private
   runtime bus and unit search path. Prove the manager's fragment paths and
   `%h` expansion resolve to the temporary workspace. This change does not
   authorize launching an ad-hoc second manager or inventing a manager socket;
   manager lifecycle operations are outside the mutation allowlist.
2. **Explicitly backed-up real user manager:** if the isolated prerequisite is
   unavailable, use the already-running manager with its actual user-unit
   directory, `HOME` set to the real current-user home for installer path
   validation, a fresh temporary `XDG_STATE_HOME` and install directory under
   that home, and a test-only service override. The override sets
   `TELLTALE_SCAN_ROOT`, `TELLTALE_LOG_PATH`, `TELLTALE_STATE_PATH`, and
   sanitized process `XDG_CONFIG_HOME`/`XDG_STATE_HOME` to temporary paths. It
   clears the generated `EnvironmentFile` or replaces it with an empty,
   validation-owned file, clears `TELLTALE_PROJECT_CONFIG`, and replaces
   `ExecStart` only to append the existing `--install-inventory-disabled`
   safety flag. This prevents real install-inventory metadata and user output
   configuration from entering synthetic evidence.
   Since `%h` would otherwise resolve to the real home, the override is the
   required safety boundary and the canonical `%h` text is inspected
   separately. The override is created only after disabled units are staged,
   hashed before/after, and removed before final restoration.

If neither path can prove that the manager will execute the canonical unit
against temporary data, stop with `G-SERVICE=BLOCKED/B`. Do not run an
unmodified `%h` unit against the real home and do not blindly rewrite the real
user namespace.

### 4. Capture bounded pre-state before mutation

The apply session must first inspect only the four approved unit names. For
each, retain state classes for `LoadState`, `FragmentPath` location class,
`UnitFileState`, `ActiveState`, `SubState`, `Result`, and drop-in count. Hash
existing owned regular unit files and any approved validation override; do not
retain raw unit bytes, journal output, environment values, `.env` contents, or
exact private paths.

The exact real-user files that may be backed up, when the fallback is used, are
`${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/` plus only:

- `telltale-scan.service`;
- `telltale-scan.timer`;
- `adr-scan.service`;
- `adr-scan.timer`;
- a newly created `telltale-scan.service.d/g-service-validation.conf` or
  `telltale-scan.timer.d/g-service-validation.conf` override, only when the
  corresponding drop-in directory was absent before the test. The service
  override may also clear the generated `EnvironmentFile` and set the
  temporary XDG roots, clear `TELLTALE_PROJECT_CONFIG`, and append the
  inventory-disabled flag to the canonical command; it must not retain secret
  values.

The timer activation link, if it is created in an isolated manager, is only
`timers.target.wants/telltale-scan.timer` beneath the selected temporary unit
directory. No real-manager target link or manager-owned persistent timer state
may be touched by the fallback.

The fallback may additionally create and later remove only these
installer-owned, user-owned paths: `$HOME/.telltale-installer.lock` when it
was absent before the test; a fresh install directory under `$HOME`; a fresh
`XDG_STATE_HOME` subtree under `$HOME`; a fresh `TMPDIR`, `CARGO_HOME`, and
`CARGO_TARGET_DIR` under the validation workspace; the marker-owned
`.telltale-units.*` staging directory; and an empty `<real config root>/telltale`
directory if the installer creates it. Record existence/type/hash classes
before and after.
If the real config root contains `adr.env`, if legacy state/event files would
be migrated, if an installer staging directory already exists, or if any of
these paths cannot be removed safely, stop as `BLOCKED` rather than backing up
or exposing their contents.

The installer's built-in smoke command is fixed in the current script: it uses
`--dry-run --no-local-config` and does not pass
`--install-inventory-disabled`. It may therefore perform bounded metadata-only
install-inventory probes while validating the binary. The apply session must
run it only with the sanitized allowlisted environment, discard its output,
retain no inventory event or path data, and never treat that smoke as service
proof. If those bounded probes cannot be allowed without exposing or writing
outside the workspace, classify the prerequisite as `BLOCKED` rather than
changing the installer.

Before service execution, perform metadata-only checks for the system config
root `/etc/telltale`. Because the current scan command does not include
`--no-local-config` and the binary always considers that root, each of
`organization-rules.d`, `rules.d`, `ui-rules.d`, `overrides.d`, `policies.d`,
`allowlists.d`, and `outputs.d` must be absent or an owned, non-symlink,
readable empty directory. “Owned” here means root-owned or current-user-owned;
the directory and parent must be non-symlink, readable, and not group/world
writable. Any discoverable YAML file, symlink, inaccessible directory,
unexpected owner/type, non-empty relevant directory, or unrecognized entry
under the parent is a blocking prerequisite; the `/etc/telltale` parent itself
must be absent or satisfy the same owner/type/readability/mode predicate. Do
not inspect credential values or attempt a system configuration workaround.

For an isolated manager, the runtime bus, unit search path, and timer
persistence root must all be inside a fresh private workspace owned by the
validation. Record only root type/mode, pre/post timer-entry counts, and hashes
of validation-created entries. If the manager cannot identify and clean its
`Persistent=true` timer state without touching a real runtime directory, do
not activate the timer and leave the timer portion `BLOCKED/B`.

An unexpected owner, symlink, unmanaged fragment path, existing drop-in, or
unit outside this set is a stop condition. It is never repaired or deleted by
the validation.

### 5. Limit live mutations to an explicit allowlist

Allowed manager operations are user-level only and only for the four approved
identities: bounded read-only `show`/state queries, `daemon-reload`, `start`,
`restart`, `stop`, `enable`, and `disable`. `enable` and timer activation are
permitted only inside the isolated manager; the real-manager fallback may use
`start` only if its timer state and cleanup are fully bounded, otherwise its
timer subcheck is `BLOCKED/B`. All validation-created activation must be
reversed because the preflight refuses an initially enabled/active fallback
unit. No system-level `systemctl`,
`loginctl` lingering change, unrelated unit operation, manager lifecycle
operation, or system installation path is allowed.

Allowed files are the temporary validation workspace and the exact user-unit
files/override listed above when the real-manager fallback is selected. The
installer's own identified legacy-unit staging/removal is allowed only because
the synced transaction contract explicitly requires it; cleanup must restore
those pre-existing legacy bytes rather than treating the validation as a
general migration.

The backed-up real-manager path is eligible only when all four approved units
are initially `ActiveState=inactive` with the expected inactive/dead substate,
`Result=success` (or the documented not-found/empty equivalent), a disabled or
static unit-file state, and an owned regular file under the exact user-unit
directory when loaded. An enabled, active, failed, ambiguous, or otherwise
non-restorable unit is an unexpected live workload; record it and block before
installer mutation rather than promising that installer rollback can recreate
its state. A `LoadState=not-found` unit is eligible only when its fragment path
is empty, its unit-file state is empty or `not-found`, its active/substate pair
is `inactive` plus `dead` or empty, its result is `success` or empty, its
destination file is absent, and its drop-in count is zero. A loaded unit must
have the corresponding owned regular file, no drop-ins, `UnitFileState` in the
approved disabled/static set, `ActiveState=inactive`, the expected dead
substate, and `Result=success`.

### 6. Make cleanup transactional and conservative

The later apply session registers cleanup before any mutation. It must stop and
disable validation-owned units, remove the test override, issue a bounded
`daemon-reload`, restore pre-existing bytes and the recorded disabled/inactive
classes, and compare post-state and hashes with the recorded pre-state. It then
removes the temporary binary, source root, config, log, state, staging, lock,
and runtime workspace, and verifies zero validation residue. If any restoration
or cleanup assertion is unknown, the session must not mark `G-SERVICE` passed.

### 7. Use conservative gate semantics

- **PASS:** the real Linux user-systemd manager loaded manager-visible canonical
  units; required service/timer operations actually ran; canonical executable,
  temporary paths, output/state/deduplication, status/restart, and cleanup
  evidence all passed; and pre-state was restored exactly.
- **BLOCKED:** the manager/session prerequisite is unavailable, private units
  cannot be made visible safely, timer/restart behavior cannot be exercised as
  required, an unexpected pre-existing unit prevents safe proof, or cleanup
  cannot be proven. Preserve the exact redacted blocker.
- **FAIL:** a bounded, reproducible check demonstrates a violation such as a
  wrong executable/path, duplicate schedule, data/state loss, unsafe mutation,
  or failed restoration. Record the minimal redacted reproduction and create a
  separate defect/change; do not repair it here.

## Risks / Trade-offs

- **[Risk]** A separate user manager may not be available on the host. →
  Require an actual manager-visible prerequisite and leave the gate blocked
  rather than using a fake manager or the real profile unsafely.
- **[Risk]** `%h` may resolve to the real home even when the installer process
  has a temporary `HOME`. → Prove manager expansion or install a hashed,
  temporary override before execution; otherwise do not start the unit.
- **[Risk]** A legacy `adr-scan` unit or drop-in may be manager-visible outside
  the private target. → Record its bounded class/hash, do not delete it, and
  stop as `BLOCKED` unless the approved real-user fallback can prove ownership
  and byte-for-byte restoration.
- **[Risk]** Timer testing can leave a persistent schedule. → Prefer a
  non-enabled bounded start in an isolated scope; do not enable a timer in the
  real-manager fallback, and explicitly stop it and remove the isolated target
  link during cleanup.
- **[Risk]** Cargo or the installer can write outside the validation workspace.
  → Set `TMPDIR`, `CARGO_HOME`, and `CARGO_TARGET_DIR` to fresh private
  directories, record their residue classes, and block if any write escapes
  the allowlist.
- **[Risk]** The scan can emit real install-inventory metadata or inherit a
  project configuration. → Use the existing
  `--install-inventory-disabled` validation override, clear
  `TELLTALE_PROJECT_CONFIG`, and retain only synthetic output projections.
- **[Risk]** Live output or environment could expose private data. → Use only
  synthetic fixtures, a sanitized configuration with no HEC sink, bounded
  projections, hashes, counts, and status classes; reject relevant `/etc/telltale`
  configuration without reading values; discard raw output.
- **[Risk]** `--from-source` may select a public tag different from the reviewed
  0.5.0 candidate. → Verify the exact tag/version/hash before any manager
  mutation and classify an unavailable matching artifact as `BLOCKED/B`.
- **[Risk]** A successful service run could be mistaken for a 0.5.0 release.
  → Keep the result limited to Linux user-systemd `G-SERVICE`; native
  Windows/macOS, HEC/Splunk, release-preflight, and publication remain open.

## Migration Plan

No product migration or deployment occurs in this change. The later apply
session creates temporary validation material only, or the explicitly allowed
backed-up current-user unit files and one test override. On every exit path it
stops/disables temporary schedules, removes the override, reloads the user
manager, restores exact bytes and the recorded disabled/inactive classes,
compares pre/post state and hashes, removes temporary roots and installer lock,
and verifies no residue. The change may be
archived only after the evidence ledger, review, validation, and durable status
reconciliation are complete.

## Open Questions

None. Whether the host can satisfy the isolated-manager or backed-up real-user
prerequisite is an apply-time result, not a planning ambiguity.
