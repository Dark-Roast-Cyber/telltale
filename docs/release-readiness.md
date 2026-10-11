# Release Readiness

Use this checklist before preparing a tagged Telltale Core release or publishing
release artifacts from the public repository. The single local Telltale checkout is
the release source of truth; public release curation stages reviewed public-safe
material from this checkout to the public remote.

## Scope

A public release should include the open-source core, public technical
documentation, synthetic fixtures, schemas, bundled rules, and reviewed example
configuration. It should not include local scanner state, telemetry logs, raw
agent transcripts, credentials, private planning notes, local agent workflow
state, or deployment-specific SIEM settings.

Release archives should contain only the canonical `telltale` command-line
binary, the Apache-2.0 license, a concise quick-start README, and reviewed
deployment examples generated from checked-in public repository contents.

Public release evidence should be reproducible from synthetic fixtures or
already-redacted telemetry output. Keep live host validation notes local-only;
public summaries should cite deterministic fixture commands, supported client
families, schema checks, or aggregate results without exposing workstation
paths, raw transcript excerpts, SIEM endpoints, scanner state, or credentials.

Version selection and package/tag alignment follow
[Versioning and Releases](versioning.md). Official `v0.5.0` is published and
immutable. `v0.7.0-rc.1` is published from
`e2386cb53454a8384449ea0729f0e3b71072006c` as Release ID `397543935`; its
five-target publication workflow passed (run `36299868695`). Downloaded archive
digests match Release metadata and `SHA256SUMS`; extracted binary digests were
computed. Five-platform candidate-native qualification passed in run
`36305581215` using verifier tooling
`c5c955f57a83cbfc7bd9827932a5e7d54a2fd077`; each job exercised the exact
published archive, attestation, pinned archive and binary identity, bundled
rules, synthetic positive fixture, and Event 3.0 validation. The historical
rc.3 verifier and qualification do not establish 0.7 evidence. Subsequent
source modifications on `main` invalidate the Issue #87 exact-source
CI/CodeQL/local-Git/consumer/preflight release qualification that qualified
`v0.7.0-rc.1`. Release qualification is distinct from development progress;
unpublished changed source does not require a new RC solely due to unpublished
changes, but changed source cannot claim earlier exact-source qualification evidence.
The published `v0.6.0-rc.3`
prerelease is Release ID `386482697` from
source SHA `db9cf63434a6e1fdf1373e82d96d709f6fbabc58`.
Publication/provenance, the static-CRT publication gate, and five-platform native
verification passed. Issue #23 clean-Windows static-CRT qualification and functional
acceptance passed, followed by a successful live Linux canary. Official stable
`v0.6.0` was then published from
`f8e00162a3f9ac1cf8d2f270e6db078d3917d186` and deployed successfully. `v0.5.0`
is the previous stable release; Issues #23 and #37 are complete. The previous immutable
`v0.6.0-rc.2` prerelease is Release ID `385903701` from source SHA
`158b18ce78c6f503c38619e816790035f88b09db`; G-SERVICE and five-platform native
verification passed, with native run `34444628698` using verifier tooling SHA
`8b65c1f517a9910b0dc197633d6bebd41859ee46`. The published immutable
`v0.6.0-rc.1` candidate passed publication/provenance and failed G-SERVICE
because the current-user generated `EnvironmentFile` declaration was ignored as
a non-absolute quoted path. It is historical failed-candidate evidence, not an
official stable release or a qualification input to retry. The real systemd
parser consumes this directive's complete value without shell-unquoting it; the
repaired canonical shape is `EnvironmentFile=-/absolute/path`, including when
the path contains spaces. Distinguish every candidate with full Git SHA
and archive/binary SHA-256. Use the post-publication-safe metadata gates for an
already published candidate; do not run a pre-tag check that requires the rc.3
tag to be absent. The [version gate contract](versioning.md#authoritative-version-gate)
owns package, RC/stable tag and published-version separation. Do not reuse
`v0.5.0` artifacts.

A separate rc.1 synthetic qualification invocation used the environment file as
an override channel and started with the ordinary user scan root instead of the
intended synthetic-only root. That is a qualification-tooling defect and did not
establish additional candidate behavior. No raw event content is retained as
release evidence, and state/log consistency was preserved.

The authoritative rc.2 G-SERVICE result is **PASS** on Fedora 44 x86_64 under
`systemd --user`. The one-shot and timer-triggered executions retained
`PrivateTmp=yes`, used `--no-local-config`, proved `remote_sink_count=0`, did not
scan the normal user root, did not enable remote delivery, and passed Event3
validation against schema SHA-256
`9014a15c010bc613b4deb7e0195ec56f702e9e950fb13a12c6937a733e38d754`.
Aggregate synthetic Event3 evidence was activity 2 / detection 1 / health 1 for
the one-shot execution and activity 1 / detection 1 / health 1 newly appended by
the timer, for totals of activity 3 / detection 2 / health 2. The expected
detection occurred in both executions, and every emitted event reported
`telltale_version=0.6.0-rc.2`. No raw event payload is repository evidence.

The rc.3 five-platform native verification passed in workflow run `34678037610`
using verifier revision `be81e8ef048f623096cd8680c89acabe738e7eb9`. Clean-Windows
qualification passed for the exact published rc.3 artifact without the VC++
Redistributable or relevant redistributable runtime DLLs present. The Windows
acceptance helper exercised the canonical fixture and reported the expected Event3
detection. The project owner accepted that captured helper output as Windows
functional evidence; frozen Event3 schema conformance was independently revalidated
from the exact rc.3 source and canonical fixture.

The prior `v0.5.0-rc.1` tag is immutable history at reviewed commit
`8f261317022352ebc812c30814aa776964c84e6b`. Windows packaging failed; no
GitHub Release or complete five-target asset/checksum/attestation set was
created. Never reuse `rc.1`.

`v0.5.0-rc.2` is immutable history at reviewed commit
`973ce825550941a824aa568a07f80036cd89f497`; do not mutate its tag, Release,
assets, or evidence. `v0.5.0-rc.3` is immutable history at reviewed commit
`a791ebf8894b3329030fad9e252e22d21e8b7e07` and has no GitHub Release. `rc.4`
is historical; the immutable `rc.5` publication/provenance passed, but G-SERVICE
failed on the canonical optional `EnvironmentFile` defect. The immutable `rc.6`
publication/provenance passed and repaired that defect, but G-SERVICE then failed
before binary replacement on user-manager `WorkingDirectory` normalization.
`rc.7` is published and immutable at reviewed commit
`6696888cd5d559fa47b8252e3495524da9fbd1eb`; its GitHub Release and assets are
the accepted candidate artifacts. The resulting `v0.5.0` tag and stable GitHub
Release are now published and immutable. Subsequent development version alignment
does not replace those artifacts or the separately pinned controlled-development lab.

`v0.7.0-rc.2` is published as prerelease Release ID `409281155` from frozen
source `c3132f22f0758912fbcbc7451f5fefee514c5bdb` (Issue #87). Exact-source
preflight, five-platform native verification of the published artifacts and the
full settled soak passed; clean-host gates are blocked (see the checklist below).
It is a qualified-in-part prerelease, not a stable release. RC1 evidence applies
solely to the immutable RC1 artifact. A validation-relevant change after
publication requires the next unused RC; the published tag, Release and assets
are never replaced.

## 0.7 RC1 current-host qualification

[Issue #66](https://github.com/Dark-Roast-Cyber/telltale/issues/66#issuecomment-5860306266)
records the 2026-09-27 qualification of the exact published RC1 on Fedora 44
x86_64 with systemd 259.9. This was an existing installation, not a clean host.
Source-bound attestation and pinned archive/binary checks were observed passing.
Synthetic G-SERVICE one-shot and genuine timer-triggered runs were observed
passing with `PrivateTmp=yes`, `NoNewPrivileges=yes`, `--no-local-config`, and
zero remote sinks. All six synthetic records passed Event3 and candidate-version
checks: two health, two activity, and two expected detections.

The bounded live canary did **not** pass: a one-source Codex dry run exited zero
but reported one parse failure and no successfully parsed sources or records.
The writing scan was withheld. The underlying error was not retained, so this
does not establish a candidate defect or successful live qualification. Official
`v0.6.0` was restored, rollback synthetic health passed, and the original timer
and configuration were restored. Post-restart inspection confirmed stable binary
identity, canonical units, and removal of qualification overrides.

Evidence limitation: detailed private execution logs and backups were unavailable
after a server restart. Retained execution summaries establish the observations
above; surviving journal metadata corroborates service starts but does not replace
the lost Event3 or provenance artifacts. Issue #66 remains open, clean-Windows
qualification is blocked on an available host, and no clean-host or stable
promotion gate is marked complete by this result. RC1 evidence applies only to
`e2386cb53454a8384449ea0729f0e3b71072006c`, not subsequent substantive changes.

## 0.7 development-commit local host test

On 2026-09-30 a reversible local host test exercised the exact development
commit `0f4350085c5c611f980b910f1b800682a8ad942c` (which includes the
post-RC1 hardening, OpenCode incremental recovery, and recovery test
hardening). A synthetic-only one-shot run and a genuine timer-triggered run
both passed on Fedora 44 x86_64 with systemd 259.9: six Event3-valid records
(health, activity, and expected detection per run), deterministic producer
provenance, candidate version identity, `--no-local-config`, and zero remote
sinks. The original `v0.6.0` installation, configuration, state, and units
were byte-verified and restored, with the original timer resumed only after
integrity verification. Evidence is retained privately.

This was a manual reversible installation, not installer qualification: the
local installer mode rejects RC-versioned development builds, so the supported
installer path was not exercised. It is not published-artifact, clean-host,
Windows, or live-source qualification, does not satisfy any Issue #66 gate, and
applies only to that development commit. Splunk/reporting catch-up after the
test window was not assessed.

## 0.7 stable-readiness decisions

These are decisions and required future gates, not evidence that a gate has
passed. Development through `43344648edf450a13a1cb3b3a29cd310acad3b34`
and the subsequent 0.7 embedding-contract preparation commits are not a
frozen replacement candidate. Issue #87's earlier freeze at
`5a47eaab406c8cb5b139476861722155b0fdf227` was invalidated by subsequent merged
code; historical evidence is not rebound. Development CI run `37361823509` and
CodeQL run `37361823885` passed for `7511307b64424e54ee13fa77007d0eb9775acedc`,
not the current tree, and do not qualify a release artifact. A new
reviewed final source SHA and exact standalone Git-consumer proof/preflight are
required after polish. Freezing that source remains a separate acceptance action;
integration pins and acceptance are a distinct gate.

The 0.7 source scope remains the six families/eight exact identities in the
[supported-source denominator](migrations/0.7.0.md#supported-source-denominator).
Do not restore retired adapters or expand scope to Event 4 or active blocking.
Event 3 remains the production contract. Keep action-promotion scores distinct
from native finding assessments and Event 3 session scores. Retain
`rusqlite = "=0.32.1"`, SQLx coexistence, and the Rust 1.88 supported embedding
subset; do not claim the CLI/workspace has Rust 1.88 MSRV or full historical
client parity.

Before stable qualification, finish supported-source synthetic fixture coverage
and make documentation limits truthful. OpenClaw and Qwen CLI remain
fixture-only/preview for live stores until bounded, approved validation uses
client-generated synthetic stores; handwritten fixtures do not prove live
compatibility, and existing personal stores must not be scanned. Keep their
current labels until that evidence is accepted. This is a stable-qualification
gate, not a retroactive change to fixture-based source support. Any unavailable
host gate remains BLOCKED, never PASS.

**Accepted risk — UPGRADE-01 (deferred), accepted 2026-10-05.** Lossless
legacy-state upgrades, an executable drain runbook, coordinated
host-version migration, and upgrade rollback qualification are deferred; they
are not current 0.7 polish or release prerequisites. Old persisted state without
pending identities may absorb undelivered actions once on semantic/version
change. Mixed host protocol versions and rollback of newer state remain
unqualified; no lossless-upgrade claim is made. The downstream integration
maintainer owns this follow-up, to revisit before supported in-place migration
or existing-install rollout is advertised or enabled (not for current fresh-install
development). Closure remains pending: executable old/new state fixtures
covering pending work, partial delivery/restart acknowledgment, compatible IPC,
and rollback preserving new pending work, plus a documented runbook.

This decision permits controlled fresh-install testing only; it does not
authorize live-source or deployment work. It waives only cross-version upgrade
safety work. Same-version retry, durability, privacy, and restart recovery, and
artifact provenance and clean-host gates remain mandatory. A release canary may
still roll back to its pre-test host baseline; that is separate from qualifying
cross-version migration rollback.

Performance qualification must use bounded synthetic native Windows and Linux
cold, warm, steady, and saturated workloads, including slow delivery and restart
recovery. Record fixture hash, source SHA, toolchain/features/rule options, host
specification, commands, latency percentiles/max, peak RSS, queue and exclusion
counts/bytes, and recovery results. Require latency within configured cadence,
retention within configured caps, no post-warm-up monotonic growth, and no silent
loss, duplicate promotion, or privacy regression. A byte-visit budget is not an
RSS bound. Oversized inputs must fail closed without partial source success or
cursor advance, and queue admission/retry must recover. These are gates, not
measurements already performed.

Keep standalone published-artifact qualification distinct from downstream
integration acceptance. Exact-artifact gates remain mandatory; stable promotion
also requires separately authorized bounded canary and rollback. An integration
claim additionally requires a real downstream-consumer Windows build and
integration test; upstream Windows CI is not that evidence. Telltale remains
useful independently of any downstream consumer. No artifact, workflow dispatch,
live authorization, or promotion is implied here. Telltale maintainers own source,
docs, bounds, and consumer contracts; downstream maintainers own vendor pins,
lockfiles and host integration; the release owner owns freeze, artifact gates,
and canary approval.

Defer the dependency-update PR as-is. Do not merge major upgrades or loosen the
SQLite pin merely to repair CI. Security advisories remain mandatory; make only
targeted necessary fixes before freeze. An unrelated candidate failure in a
separate open PR is not by itself a release blocker.

### Post-RC1 embedding qualification

The current RC2 development embedding facade is an intended 0.7.0 contract, not
qualification evidence. Before claiming the upstream facade qualified, bind
results to the reviewed candidate SHA and retain results for
`make embedding-contract-check`, the explicit Rust 1.88 embedding subset, and an
exact standalone Git consumer using strict Event 3 and the public facade. Native
platform/artifact qualification is a separate upstream gate. Integrated
downstream-consumer host validation is a separate integration gate, not a
prerequisite to Telltale's standalone usability or upstream release qualification.
None is an RC1 gate retroactively; RC1 evidence remains bound to its published
artifact. Do not report a gate as passed until its candidate-bound evidence exists.

### Current candidate blocking checklist

Statuses below are bound to `v0.7.0-rc.2` (`c3132f2`) unless stated; exact
commands, run IDs and limits are on Issue #87. Earlier development results are
supporting evidence, not release passes. Bind local results to source base, tracked
patch hash, relevant untracked-input manifest/hashes, toolchain/features, exact
commands/exits and logs. That identifies a tested tree, not an exact Git revision.
An uncommitted tree cannot satisfy the exact Git-candidate gate; reviewed
commit/push and subsequent lifecycle checks require separate authorization.

| Required gate | Current status and completion evidence |
| --- | --- |
| Canonical local CI, source coverage/privacy and same-version durability/retry | PASS for the source tree: `make ci-local` passed on PR #90 (3,783 tests) and exact-source CI passed at `c3132f2`; focused synthetic WAL, large-output, safe-read/retry and concurrency results are supporting evidence only. Live client WAL append was not demonstrated. |
| Strict OpenSpec and independent review | PASS: strict OpenSpec validation (21 specs) and independent automated review (cubic, cloud ultrareview) on PR #90, all findings resolved. |
| Full local two-hour settled soak | PASS at `c3132f2`: 7,201/7,201 one-second cycles, no override, 0 cadence misses, exit 0 with final report; FD 6 throughout. Linux only. |
| Public facade feature matrix and Rust 1.88 subset | PASS at `c3132f2`: all eight feature combinations and the explicit Rust 1.88.0 subset (160 tests each); no global workspace/CLI MSRV claim. |
| Exact standalone Git consumer, CI/CodeQL and preflight | PASS at `c3132f2`: Git-rev consumer across five feature sets, CI 10/10, CodeQL 3/3, `make release-preflight` exit 0 on clean canonical `main`. |
| Real downstream-consumer candidate adoption | PENDING integration gate: isolated public-facade suites (33 + 75 tests) passed, but require final candidate rebinding and native Windows build/integration evidence for an integrated claim. Not a dependency of standalone Telltale. |
| Native platforms and performance | Functional PASS on GitHub-hosted runners for all five targets (published-artifact run `38098389234`). Bounded cold/warm/steady/saturated performance on native Windows, Linux ARM and macOS is NOT RUN. No native Windows access; unavailable required targets remain blocked, not passed by Linux tests. |
| Five-platform RC2 artifacts and clean-host qualification | Artifacts PASS: Release `409281155`, checksums, attestations and native execution verified. Clean Linux installer/G-SERVICE and clean Windows no-Redistributable: BLOCKED (no authorized clean host). RC1 evidence is historical only. |

The [selected-window aggregate limitation](opencode-live-ingestion.md#failure-recovery-and-coverage)
is nonblocking only for the existing session-aggregate/conditional-replay contract,
not a new-action, cumulative-snapshot, or exactly-once promise. Embedding performs
the CLI cursor transition only through a host-persisted resume token. Retain source-bound coordinate fallback
and empty whole-source baselines for OpenCode `PartialSource` accounting.
UPGRADE-01 defers only cross-version migration; same-version privacy/durability
and release gates remain required. Current adoption is fresh-install scope, with
OpenClaw/Qwen live-store support still preview. No checklist authorizes lifecycle
actions or claims stable qualification.

## Historical RC Candidate Handoff

The `v0.5.0-rc.7` handoff completed before stable publication: the reviewed commit was tagged and its
immutable GitHub Release is explicitly marked `prerelease=true`. Native
validation used those published artifacts. Final stable preflight ran against
the reviewed `0.5.0` commit before the now-published `v0.5.0` tag existed.
If code, package metadata, installer behavior, workflow, archive, checksum, or
attestation provenance changes, use a new reviewed commit and the next unused
RC tag; do not overwrite a published candidate. A transient environment
failure with unchanged artifacts may receive only a bounded recheck.

For each of the five target archives, retain a redacted ledger row containing:
the package/tag pair, reviewed `main` SHA and ancestry result, canonical archive
name and member-manifest result, archive and extracted-binary SHA-256 values,
the exact `SHA256SUMS` line, archive attestation subject, Release ID/URL and
`draft`/`prerelease` metadata, workflow run/ref/source identity, and the exact
tagged installer blob and executable-mode result. Do not record credentials,
endpoints, local paths, raw service output, or session contents.

For the published rc.3 candidate, publication/provenance, the static-CRT
publication gate, and five-platform native verification passed. Issue #23
clean-Windows static-CRT qualification and functional acceptance passed. The
previous rc.2 G-SERVICE and native run `34444628698` remain
historical evidence and are not rebound to rc.3. Each native gate may be
satisfied by an authorized native host or appropriate GitHub-hosted native runners.
The gate
must download and execute the final published Release artifact for that
architecture; cross-compilation, archive inspection, Linux source-unit tests,
and staged or rebuilt binaries are not native-release evidence. Run the
manually dispatched `.github/workflows/release-native-verify.yml` workflow for
the GitHub-hosted path. Live G-HEC and G-SPLUNK are environment-dependent:
`SKIPPED: EXTERNAL HEC ENVIRONMENT NOT AVAILABLE` does not block stable
promotion, while deterministic HEC/JSONL-parity and Splunk-format gates remain
mandatory. Each gate has its own PASS/BLOCKED/FAIL status; a BLOCKED gate is
never silently reclassified as PASS. Preparing the reversible `0.5.0` version
commit is a prerequisite for final stable preflight and is not itself tagging
or publication. Stable GitHub tagging and GitHub binary Release require
explicit PASS evidence for the required gates plus release preflight against
that `0.5.0` commit, public artifact-boundary review, and GitHub publication
prerequisites. Crates.io publication is a separate later distribution action
and does not block stable GitHub `v0.5.0`.

## OpenCode incremental coverage qualification (#77)

The accepted development recovery is source-atomic and finite: incremental CLI
selections up to 25,000 text/tool parts use 5,000-row snapshot-scoped keyset pages
and one canonical evaluation. The public default and uncursored CLI modes remain
5,000-part sampling; persisted timestamp state and output-gated installation are
unchanged. Older binaries can read this state but may again saturate at 5,000.
This is not a persisted cross-cycle continuation or arbitrary-backlog guarantee.
Independent canonical/projection limits can reject a selection below 25,000.

Before claiming recovery in a candidate, retain synthetic evidence for tied
timestamps across pages, aggregate exhaustion/overflow, coherent concurrent
updates, cross-page suppression/correlation, and failure/restart cursor replay.
Bind that evidence to the candidate's reviewed source; current development tests
do not qualify a previously published artifact. Preserve the residual limitation
and [safe operator response](session-sources.md#opencode-incremental-saturation-and-recovery)
in candidate coverage claims. No release or stable promotion is authorized here.

## Pre-Release Checks

Run these checks from a clean working tree in the local Telltale checkout before
tagging a release:

```sh
make release-preflight
```

The preflight target wraps the same public release checks shown below:

```sh
make release-context-check
make release-tag-review
make release-crate-manifest
make package-verify
make producer-provenance-check
make release-public-docs-check
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
make release-fixture-smoke
```

`make release-fixture-smoke` runs the fixture scan with
`--root tests/fixtures/session_stores`, `--dry-run`, `--emit-activity`, and
`--emit-session-risk-summary`, then validates the bundled rules. The fixture
scan must use `--dry-run` unless you are intentionally writing synthetic fixture
output in CI or local development.

### Synthetic watch soak

Before broadening watch reliability claims, run the ignored Linux soak
explicitly:

```sh
cargo test --test cli scan_watch::watch_synthetic_multi_cycle_soak -- --ignored --nocapture
```

The test uses temporary synthetic stores only. It exercises six triggered scan
cycles, unchanged-state persistence, bounded process file descriptors, built-in
JSONL rotation and retention, deduplicated malformed-source errors followed by
valid detections, and clean finite-cycle exit. It requires Linux procfs/inotify,
so it is evidence for that bounded runtime path rather than a macOS or Windows
live-watch claim.

#### Reproducible workload measurements (development, not qualification)

The existing CLI cases can additionally write opt-in, machine-readable Linux
process measurements. From the checkout root, use a persistent private evidence
directory outside the checkout and set `TMPDIR` to its `tmp` subdirectory:

```sh
mkdir -p "$EVIDENCE/tmp" "$EVIDENCE/reports"
export TMPDIR="$EVIDENCE/tmp"
export TELLTALE_WORKLOAD_REPORT_DIR="$EVIDENCE/reports"
cargo test --locked --release --test cli production_jsonl_cli_limit_failure_retains_baseline_and_recovers -- --nocapture
cargo test --locked --release --test cli watch_synthetic_multi_cycle_soak -- --ignored --nocapture
cargo test --locked --release --test cli watch_idle_durable_future_pending_and_crash_gap_recover -- --nocapture
cargo test --locked --release --test cli watch_idle_durable_attempt_budget_with_delayed_receiver -- --nocapture
```

Save commands, exit statuses, and logs beside the reports. Reports include the
source SHA, tracked dirty-patch hash, CLI binary hash, scoped fixture fingerprint,
toolchain, profile, features, rule/options description, and host OS/architecture,
kernel, CPU model and memory (not hostname or host paths). An untracked-file flag
means the tracked-patch identity alone is incomplete; retain and hash any relevant
untracked input separately. Fingerprint encoding is length-prefixed ordered input
bytes, not a directory hash. Source/watch fingerprints cover the listed source
fixture bytes; construction/repetition/write order comes from the source-bound
case generator. Durable fingerprints instead cover a deterministic normalized
generator recipe stored in the report: empty source and setup health generation,
pending-row seed, crash-gap append, receiver and watch parameters. Paths, random
setup IDs, runtime timestamps/metadata and ephemeral receiver ports are explicit
placeholders; seed timing is a relative offset. This binds reproducible inputs and
operations to the source/patch, not the actual generated event/state/database
bytes: complete durable byte identity is explicitly unavailable. Different durable
case parameters produce different recipe fingerprints. Reports overwrite the same case name on rerun, so
use a separate evidence directory per reviewed tree/profile/run.

The source case measures cold **state** (not cold OS cache), five warm same-version
process restarts, an oversized physical record, repair/restart and repeated retry.
It asserts whole-source failure, unchanged baseline/cursor state, no partial
activity/detection promotion, successful retry, and synthetic-secret absence in
CLI output, state and canonical JSONL. Cold/repaired activity promotion followed by
zero warm promotion characterizes activity deduplication with benign input; positive
detection/dedup evidence comes from the watch case, not that source case.
The watch case measures six write-to-health
latencies including debounce, with unchanged-state/dedup, descriptor and rotation
assertions. Durable cases use an isolated loopback receiver, a seeded pending row
and fsynced JSONL crash-gap record; they assert persisted retry/recovery or terminal
budget outcomes without source writes. The slow receiver delays acceptance by
5.5 seconds. Remote delivery remains **at least once**, not exactly once.

Latency samples and nearest-rank p50/p95/max are descriptive; scan invocation
latency includes startup and exit. Watch latency excludes its later quiet-period
check. The durable single sample includes the two post-terminal idle intervals and
shutdown, not per-event delivery latency. Linux `/proc/<pid>/status` supplies
observed `VmHWM` (process RSS high-water) and sampled `VmRSS`; short-lived children
can exit before the final read, so observed high-water is a lower bound, not an
exact exit peak. Scan invocations additionally use Linux `wait4` `ru_maxrss` for
the actual child-process exit peak in KiB; watch exit peaks remain unavailable.
These are distinct kernel accounting views and can differ; do not replace one
with the other or treat sampled RSS as an exact bound.
Watch HWM and sampled RSS maxima are process-lifetime cumulative through each
observation, not independent per-cycle peaks.
Scan polling is every 2 ms; watch sampling follows its existing
poll loop. Measurement overhead is included. Missing measurements are JSON `null`,
never zero or a pass. State/active-log bytes, source-processing counters, retained
watch generations/events/bytes, descriptors, and durable retained payload rows/
bytes are recorded where available. Pending limits do not cap retained terminal
outbox history; source exclusion bytes and byte visits are unavailable here.
Byte-visit limits are not RSS bounds.

The original cases above do not establish a memory-leak trend,
post-warm-up growth bound, latency-within-cadence gate, queue-saturation performance,
all-source saturation, native Windows/macOS behavior, arbitrary backlog recovery,
cross-version upgrades, or published-artifact qualification. The additional
process cases below address settled sampling and small configured-capacity
recovery, not general performance qualification. UPGRADE-01 remains deferred as
documented above.

#### Settled watch and real-process capacity follow-up

Using the same evidence environment above, run these Linux-only ignored cases:

```sh
cargo test --locked --release --test cli scan_watch::watch_synthetic_sustained_settled_cycles -- --ignored --exact --test-threads=1
cargo test --locked --release --test cli scan_watch::watch_synthetic_durable_count_capacity_recovery -- --ignored --exact --test-threads=1
cargo test --locked --release --test cli scan_watch::watch_synthetic_durable_byte_capacity_recovery -- --ignored --exact --test-threads=1
```

The sustained case alternates two equal-size synthetic phases at one fixed
Codex source path/session: 708 bytes, three records, compiled default rules.
All 60 cycles parse and evaluate; cycles 0–11 are designated warm-up. Writes are
scheduled at `epoch + cycle * 1000 ms`, not one second after the previous scan.
Write-to-health latency includes the 100 ms debounce. After each health summary,
at least 250 ms without another summary precedes a live current `VmRSS` read,
lifetime `VmHWM`, descriptors, persisted state bytes/collection counts, and
retained journal files/events/bytes. The final sample precedes shutdown. These
are settled observations, not allocator-live-byte measurements or exact peaks.

On 2026-10-05, all three release-profile commands exited 0, each executing one
test. Source was `d53eb1d7b6c32661dd19eb33555432e1b47550e2` plus the archived
test-only tracked patch SHA-256
`0f4afbabfb923ddac474911adac6d4e1e30ba5566af7f5645b34c264c7472bc4`.
The actual CLI binary SHA-256 was
`607349fdae2c6ecb80da15d57ed31e9c52c415aa336bfa33c2b67ff2364351e0`,
unchanged across the tested restarts; the test-runner binary is a separate artifact.
Host: Linux x86_64, kernel `7.2.8-200.fc44.x86_64`, Intel i7-12700F,
`MemTotal` 65,637,792 KiB, Rust/Cargo 1.95.0, root CLI default features.
Machine-readable reports, exact commands/exits/logs and the measured patch are
retained privately. Later documentation edits are not rebound to that patch.
The reports retain fixture/recipe fingerprints and every settled sample:
`watch-sustained-60-settled.json`, `durable-real-process-count-capacity.json`, and
`durable-real-process-byte-capacity.json`.

| Sustained watch observation | Result |
| --- | --- |
| Write-to-health p50 / p95 / max | 196.509 / 199.997 / 249.918 ms; all below 1000 ms cadence |
| Scheduled writes at least 10 ms late | 0; the threshold reports scheduling jitter, not an RSS limit |
| Current settled RSS, first / final | 149,916 / 152,404 KiB |
| Post-warm-up current RSS range | 150,936–153,920 KiB; repeatedly returned to 150,936 KiB |
| Consecutive 12-sample post-warm-up means | 151,425 / 152,059 / 152,460 / 151,852 KiB |
| Cumulative HWM, first / final | 149,916 / 153,944 KiB; not independent cycle peaks |
| Descriptors | 6 throughout |
| Post-warm-up persisted state | 2,533 bytes; fixed counts: 2 source fingerprints, 2 detection fingerprints, 1 source observation, 1 source contribution, 2 baseline snapshots, 0 SQLite source cursors |
| Post-warm-up journal retention | 2 files, 2 events, 9,410 bytes; no further promotion |

**Accepted for this workload:** cadence, deduplication, stable retained state and
descriptors, and no sampled post-warm-up monotonic RSS growth. The initial two
phases populate retained state (2,389 to 2,533 bytes). RSS oscillates rather than
continuing the earlier six-cycle high-water rise. This does not identify that
earlier rise's cause, prove absence of a leak, or establish an RSS cap.

Capacity cases generate and admit detections through the actual watch process;
they do not seed or mutate outbox rows. A synthetic loopback HEC receiver returns
503 during outage, then 200 with `code: 0`. Retry budgets keep committed work
pending during the finite test. An admitted process is stopped with TERM and the
same binary/configuration restarted while full. Overflow exits nonzero with the
specific capacity diagnostic, without journal append, ingest cursor movement or
new source dedup/baseline progress. Restoring delivery and restarting recovers
the committed identity/payload hash, admits the previously rejected source on
retry, and deduplicates its next scan. Exposed queue health agrees with read-only
SQLite snapshots. Remote semantics remain **at least once**.

| Process capacity observation | Count-limited case | Byte-limited case |
| --- | --- | --- |
| Configured pending limits | 1 event / 1,048,576 bytes | 16 events / 5,000 bytes |
| Full-for-workload pending rows / bytes | 1 / 4,704 | 1 / 4,704 |
| Rejected projection | 2 events exceeds 1 | 9,408 bytes exceeds 5,000 |
| Fill / rejection / recovered-source write-to-result latency (health or rejection exit) | 251.919 / 264.415 / 254.496 ms | 256.289 / 264.094 / 260.135 ms |
| Restore/restart-to-persisted-ACK | 2,145.281 ms | 132.436 ms |
| Final pending / blocked / dead rows | 0 / 0 / 0 | 0 / 0 / 0 |
| Final retained ACK history rows / payload bytes | 2 / 9,408 | 2 / 9,408 |
| SQLite file bytes, full / final | 81,920 / 86,016 | 81,920 / 86,016 |

**Accepted for these configured caps:** explicit fail-before-append admission,
same-version pending restart/recovery without silent loss or duplicate promotion,
and separate pending versus terminal history accounting. Fill-to-reject writes
were scheduled 1000 ms apart (less than 0.1 ms late); measured processing latencies
fit that cadence. Recovery is a separate 15-second deadline, not a claim that
retry-delayed delivery fits one second. “Full” means another fixed-size event
cannot fit; it does not require filling every byte of headroom. After ACK,
retained terminal payload bytes exceed the byte-case pending cap, as permitted
by the documented retention contract. Pending limits cap neither total SQLite
bytes nor terminal history.

**Remaining gaps:** one minute of one small source is not a multi-hour soak,
all-source/load-scale or growing-identity characterization, a statistical leak
analysis, an allocator/heap profile, or a memory bound. Capacity tests use small
caps and prompt synthetic 503 responses, not large-queue throughput, a slow or
timed-out transport, forced process death, or disk failure. No SQLite source
parser cursor, native Windows/macOS, cold OS cache, arbitrary backlog,
cross-version upgrade or published artifact is qualified by these results.
Source exclusion bytes and byte visits remain unavailable; byte-visit budgets
are not RSS bounds. General performance/release qualification remains incomplete.

#### Extended load, transport, and artifact evidence

Evidence dated 2026-10-06 UTC (2026-10-05 local) extends the settled
watch/capacity observations above; it is not release qualification. All five
completed release-profile commands exited 0 (one ignored test each), against
source `d53eb1d7b6c32661dd19eb33555432e1b47550e2`, test-only patch SHA-256
`46e5c187f9dacf4a9156203c9fe830e065a13124a1d754c20940274f3475ceb1`, and the
same actual CLI binary SHA-256 `607349fdae2c6ecb80da15d57ed31e9c52c415aa336bfa33c2b67ff2364351e0`.
The evidence environment and execution controls are those described above;
`TELLTALE_WORKLOAD_CYCLES` was unset. Later documentation edits are not rebound
to these measurements.

```sh
for case in \
  watch_synthetic_durable_slow_count_capacity_recovery \
  watch_synthetic_durable_timeout_byte_capacity_recovery \
  watch_synthetic_fixed_load_1_settled_cycles \
  watch_synthetic_fixed_load_16_settled_cycles \
  watch_synthetic_fixed_load_64_settled_cycles; do
  cargo test --locked --release --test cli "scan_watch::$case" -- --ignored --exact --test-threads=1
done
# Full-duration gate below remains incomplete; no cycle override:
cargo test --locked --release --test cli scan_watch::watch_synthetic_multi_hour_settled_cycles -- --ignored --exact --test-threads=1
```

The three fixed-load cases ran 120 two-second cycles, including 12 warm-up cycles,
with at least 250 ms quiet before current RSS, lifetime HWM, state, descriptor,
and journal observations. Each source was fixed at 708 bytes/three records;
the tiers used 1/16/64 distinct fixed source paths/session IDs and compiled
default rules. Queue and terminal history were not configured, not measured as
zero-capacity queues.

| Sources | Health latency p50 / p95 / max (ms) | Post-warm current RSS range (KiB) | State final (bytes) | Journal files / events / bytes | FD | Duration |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 195.043 / 199.069 / 255.256 | 150,172–153,504 | 2,533 | 2 / 2 / 9,410 | 6 | 238.447 s |
| 16 | 213.637 / 218.765 / 275.930 | 150,256–155,168 | 26,837 | 2 / 32 / 150,560 | 6 | 238.466 s |
| 64 | 275.417 / 285.155 / 352.355 | 150,928–155,608 | 104,598 | 2 / 128 / 602,240 | 6 | 238.536 s |

All three had zero write-to-health or scheduled cadence misses. State counts,
phase-specific state bytes, and journal contents were stable after warm-up.
Fitted RSS slopes and short-window trends are
diagnostic, not universal bounds; no sampled monotonic growth is not proof of
no leak, and these results establish neither a byte budget nor a memory bound.
The earlier sustained one-source case remains the separate 60-cycle result.

Two transport cases passed. The count-cap-1 case used 750 ms delayed 503 and
restored 200/code 0 responses with a 2,000 ms transport timeout. The byte-cap
5,000/count-cap-16 case stalled 1,500 ms against a 500 ms timeout, then restored
prompt 200/code 0. Each persisted its first-attempt error and 30-second retry
schedule unchanged across same-binary
restart; no early resend occurred. Capacity rejection preceded append and
progress; identities/hashes, receiver/journal/outbox parity, retry admission,
and subsequent deduplication were preserved. Recovery took 28,915.736 and
28,176.577 ms respectively against separate 30,000 ms deadlines. Source-to-
health fill took 1,007.970 and 754.304 ms (includes transport, not processing
alone); retry after restore took 1,010.001 and 259.641 ms. Final pending,
blocked, dead rows were 0/0/0, ACK history 2 rows/9,408 bytes, and SQLite grew
from 81,920 to 86,016 bytes. Delivery remains at-least-once, including uncertain
success, not exactly-once. Retry configuration allowed 100 total attempts.
The current shared prompt cases also use 30-second retry,
2-second fill cadence; previously reported 2-second retry/1-second cadence is
historical evidence from a different recipe.

The planned 7,201-cycle, one-second soak was **INCOMPLETE** at this source: the
last retained checkpoint had 2,701 cycles over 2,700.442 seconds, with no terminal
exit or final report. The full soak later passed at `c3132f2` (checklist above);
that result is not rebound to this source. Partial tier checkpoints were
superseded by the valid complete 120-cycle reports, not failed tier runs.
Native Windows/macOS/Linux ARM runs were **BLOCKED** at this source: no
authorized native host or self-hosted runner, and no dispatch approval. Functional
native verification of the published rc.2 artifacts later passed (checklist above). Persistent Windows durable
storage remains unsupported and fail-closed, not best-effort fallback.

RC2 artifact qualification at the time of this evidence was **NOT RUN**. RC2 was
later published from `c3132f2` and its artifacts verified (checklist above). The
older Issue #87 freeze at `5a47eaab406c8cb5b139476861722155b0fdf227` was
superseded; it is not rebound. Existing RC1 pins above apply
only to exact tag `v0.7.0-rc.1`: archive SHA-256
`0da936ff86dbafbf3d2f9260a3579bb44535977de188912c31da0bc87d1ccfaa`, binary
SHA-256 `0fffed5248f6d46f42e97e3107c131b3e2d6525b449327ffc9ab775827fdf1fe`,
and provenance workflow run `36299868695`, attempt 1. Its actual watch passed
12 finite cycles with three records/cycle and deduplication, exiting 0; a separate
unbounded-watch TERM also exited 0. Frozen Event 3/rules passed. This is
**PASS** current-host exact-RC1 artifact evidence
only, not clean-host, service/installer, live-source, or current-source
qualification; no remote state was mutated. Private evidence retains exact
commands/exits, patches and provenance, `watch-fixed-load-{1,16,64}-settled.json`,
`durable-real-process-slow-count-capacity.json`,
`durable-real-process-timeout-byte-capacity.json`,
`watch-multi-hour-settled.partial.json`, and the separate artifact ledger.
General all-source and growing-
identity load, large queues, forced death, disk failure, cold cache, other
platforms, and release gates remain unresolved.

### Development evidence before a candidate

For bounded prerelease development, keep evidence tied to the reviewed source
and distinguish tests from host or integration qualification. Timeline and
direct-record regressions cover overflow handling and finalized-event behavior.
Private clock injection tests establish failure precedence within one batch,
not failures of the actual host clock. Normalized-core public tests using protected stores and
synthetic lifecycle, claim/replay/reopen, and collision cases exercise the store
contract, not native source activation or integrated downstream consumer support.
Check that default feature isolation remains intact.

For final source freeze, retain source SHA, toolchain, environment, exact command,
exit status, and logs privately; public evidence should be sanitized summaries.
Windows availability is not a blocker for Linux development, but Windows remains
a release qualification gate. Do not claim checks passed until full CI has
completed. These development checks do not authorize tagging or publication;
final source provenance and preflight must be bound to the exact reviewed source.

When only public documentation or release guidance changed, run the focused
boundary check before the full release preflight:

```sh
make release-public-docs-check
```

The target runs the existing public Markdown link, tracked-target,
host-absolute-path, host-only-link, host-only-ignore-pattern, example-config,
release-workflow path, and retired repository workflow wording regressions
without scanning fixtures or building release artifacts.

It is intentionally limited to these focused commands:

```sh
cargo test --quiet public_docs_
```

`make release-context-check` verifies the working tree is clean, the current
branch is `main`, the `origin` fetch and push URLs point at the public
Telltale repository, and `HEAD` is not behind the public upstream. For an
intentional alternate public release branch or remote, override
`PUBLIC_RELEASE_BRANCH` or `PUBLIC_RELEASE_REMOTE` when running the target.
It also prints staged paths for review. `make release-tag-review` derives the
Cargo package version, expects the public tag to be `v<version>` unless
`PUBLIC_RELEASE_TAG` is overridden, and fails if that tag already exists
locally. If you are reviewing a release-preparation commit before it is created,
inspect `git diff --cached --name-only` and confirm each staged path belongs in
the public repository boundary described below.

Before any public push, stage only reviewed public-safe files from this
checkout, keep ignored host-only material local, and review
`git diff --cached --name-only`. `make public-push-review` prints the current
branch, public remote URLs, short working-tree status, staged path list, and the
release-readiness reminder in one reviewable summary.

`make release-crate-manifest` lists all six functional Cargo package inventories
with `cargo package --list` and fails if a package would include host-only
planning, local automation, telemetry, scanner state, or deployment-specific
Splunk material. It also requires the package-owned default rules data in
`telltale-rules`. Use it to review source package contents before publishing a
crate or tagged source release.

`make package-verify` performs full locked `cargo package` verification in
dependency order using temporary local crates.io patches for unpublished
workspace packages. It then compiles a registry-style external consumer and
installs the normalized `telltale-cli` package into a temporary root, checking
the canonical `telltale` install, `telltale --version`, and packaged provenance
materialization. The target supports Linux and macOS and cleans
its temporary normalized sources, consumer manifests and installation roots on
exit. All Cargo gates reuse the caller's `CARGO_TARGET_DIR` (or Cargo's configured
workspace target directory); cleanup never deletes that shared cache. Normalized
packages are freshly generated by locked package verification, then copied into
the isolated temporary source tree; cache reuse does not skip any gate.

`make producer-provenance-check` is the authoritative focused gate for the
closed manifest. It validates the schema/rules/allowlist/core/CLI tests, runs
the command twice from an isolated directory, checks byte determinism and the
closed top-level fields, and verifies that the command creates no application
files. Keep it separate from `event3-contract-check`; the latter remains the
authoritative frozen Event 3.0 gate.

Cargo package readiness from those targets remains a mandatory GitHub
stable-release gate. It is not crates.io publication authorization and does
not weaken version lockstep, internal pins, lock entries, package-boundary
checks, or registry-style consumer and CLI installation verification.

For the actual publication pass, first recheck crates.io ownership and name
availability. Publish in dependency order, waiting for each prerequisite to
appear in the index and verifying that it resolves without a local patch before
publishing the next dependent package. After all six packages are available,
repeat the external consumer and CLI installation checks with every local
`patch.crates-io` override removed. Those final checks must resolve only the
`=0.7.0-rc.2` registry packages while that remains the workspace version, before
publication is declared complete. That
crates.io pass is a separate later distribution action, not a prerequisite for
creating the stable Git tag or GitHub binary Release. Deferring it does not
block a stable GitHub Release. When crates.io publication is later attempted,
those registry-specific safety requirements remain mandatory.

## Artifact Boundary

Before publishing release artifacts, verify that the staged or tagged content
does not contain:

- local scanner state or baseline files;
- telemetry output such as `logs/telltale-events.jsonl`;
- raw agent session stores or copied transcripts;
- credentials, API keys, tokens, or `.env` values;
- host-specific filesystem paths, IP addresses, or SIEM endpoints;
- private planning, local agent workflow state, or internal release notes.

Keep environment-specific service files and SIEM shipper configuration outside
the archive unless they are reviewed public examples with placeholder values.

For generated binary archives, inspect the archive listing before upload. The
archive should contain only the `telltale` binary, `LICENSE`, `README.md`, and
the curated `config/examples/` deployment files
(`telltale-outputs.yaml`,
`telltale-scan.service`, `telltale-scan.timer`, `telltale-scan-task.xml`,
`elastic-telltale-index-template.json`, `elastic-telltale-role.json`) only. It should not
contain checked-out working-tree residue, scanner state, telemetry output,
session stores, local planning notes, local agent workflow state, or
deployment-specific configuration.

Use the archive format's listing command, such as:

```sh
tar -tzf telltale-<target>.tar.gz
unzip -l telltale-<target>.zip
shasum -a 256 telltale-<target>.tar.gz telltale-<target>.zip
```

After downloading workflow artifacts into the default `release-downloads/`
directory, run the reusable manifest check:

```sh
make release-artifact-manifest
```

The tagged release contains exactly five target archives plus the fixed
`telltale-sbom.cdx.json` SBOM. The target lists every `.tar.gz` and `.zip`
archive and verifies that each archive contains exactly the expected canonical
bundle manifest: the `telltale` binary (or its `.exe` form), `LICENSE`,
`README.md`, and the curated `config/examples/` deployment files. For the
complete release set, run `REQUIRE_SBOM=1 make release-artifact-manifest`; it
requires `SHA256SUMS` in the same directory, verifies exactly six entries (the
five archives and SBOM), and validates every checksum. The default
`release-downloads/` directory is local review residue and is ignored and
excluded from source packages; legacy local `artifacts/` review directories
remain ignored and excluded as well. Use `RELEASE_ARTIFACT_DIR=<path>` when
reviewing artifacts from another directory.

The tagged release workflow verifies the downloaded SBOM against the tagged
locked release graph before generating `SHA256SUMS`; it then generates the
manifest from the five `.tar.gz`/`.zip` archives and SBOM in its temporary
`release-downloads` directory and uploads the checksum file with the GitHub
release. See the detailed procedure in
`docs/security/operations.md#release-integrity-verification` for the complete
SBOM, checksum, and attestation verification procedure.

The Windows release job uses `scripts/release-windows-zip.ps1` for both package
creation and finalized-archive validation. It reopens the serialized ZIP
read-only and reads every canonical member before the staged binary smoke test,
attestation, or upload.

The official `x86_64-pc-windows-msvc` release build sets
`-C target-feature=+crt-static`. Before packaging, the release job runs
`scripts/verify-windows-runtime.ps1` with `dumpbin /DEPENDENTS` against the exact
staged `telltale.exe` that the ZIP helper consumes. The verifier fails closed if
inspection fails or if imports include `VCRUNTIME*.dll`, `MSVCP*.dll`,
`MSVCR*.dll`, or `CONCRT*.dll`. Linux and macOS release builds do not receive
this Windows target feature. The published rc.3 artifact passed this
publication-time gate, five-platform native verification, and clean-Windows
static-CRT and functional acceptance.

The default installer selects the latest stable Release. For candidate
validation, pass the exact tag, for example:

```sh
RC_TAG='v0.7.0-rc.1' # published prerelease; qualify before production use
./scripts/install-telltale --release-tag "$RC_TAG" --no-timer
./scripts/install-telltale --release-tag "$RC_TAG" --from-source --no-timer
```

The candidate path verifies exact Release metadata, the canonical archive
manifest, the tag-derived `SHA256SUMS` entry, and the extracted binary version
before acquiring its installer lock. It never uses `--skip-checksum` for the
G-SERVICE procedure and never falls back to `releases/latest`.

For a synthetic G-SERVICE run, install the candidate with `--no-timer`, then add
the temporary qualification drop-in before the first candidate service start.
Keep the base unit's `PrivateTmp=true`; host `/tmp` is a different namespace and
must not hold the qualification inputs. Instead create a service-visible
directory under the current user's runtime directory, conceptually
`${XDG_RUNTIME_DIR}/telltale-qualification`, and render its concrete absolute
path into the drop-in. Do not expect shell-variable expansion inside unit
`Environment=` values. Keep the session store, JSONL log, and scanner state
synthetic and confined to that directory.

Do not use `telltale.env` as the synthetic override channel. Reset the base
environment-file list and `ExecStart`, set the three qualification paths as
unit-level values, and reproduce the canonical installed command with
`--no-local-config` added for qualification. In this generalized example,
replace `<qualification-root>` and `<installed-candidate>` with reviewed concrete
absolute paths:

```ini
[Service]
EnvironmentFile=
Environment="TELLTALE_SCAN_ROOT=<qualification-root>/sessions"
Environment="TELLTALE_LOG_PATH=<qualification-root>/events.jsonl"
Environment="TELLTALE_STATE_PATH=<qualification-root>/state.json"
ExecStart=
ExecStart=/usr/bin/env -- "<installed-candidate>" scan --once --emit-activity --root "${TELLTALE_SCAN_ROOT}" --path-profile user --no-local-config
PrivateTmp=true
```

Run `systemctl --user daemon-reload`, then verify both the empty
`EnvironmentFiles` property and the three effective `Environment` values with
`systemctl --user show telltale-scan.service --property=EnvironmentFiles --property=Environment`
before starting the service. Also verify the effective command includes
`--no-local-config`, the service property reports `PrivateTmp=yes`, and effective
configuration reports `remote_sink_count = 0` before the first candidate scan
execution. Only then run the one-shot and timer-triggered synthetic checks. The
installer intentionally rejects unit-specific drop-ins, so create this
qualification-only override only after installation. After the test, remove the
temporary qualification drop-in and synthetic runtime directory, reload the
manager, and confirm the canonical unit has no remaining drop-ins before any
installer rerun. This procedure changes no production defaults.

## Post-Release Smoke Test

After downloading a release archive, run a fixture-safe smoke test before
scanning real session stores:

```sh
telltale scan --once --dry-run --no-local-config --root tests/fixtures/session_stores
telltale rules validate --no-local-config
```

Only point Telltale at real session-store roots after the fixture scan and rule
validation complete successfully.

## Related Boundaries

- [privacy-model.md](privacy-model.md) defines evidence classes, redaction, and
  public-example privacy expectations.
- [telemetry-output.md](telemetry-output.md) describes the JSONL sink, SIEM
  forwarding model, and public evidence boundary.
- [trust-boundaries.md](trust-boundaries.md) explains how untrusted session
  content handling carries into publication guidance.
