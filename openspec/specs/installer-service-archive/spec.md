# installer-service-archive Specification

## Purpose
TBD — Update Purpose after archive.
## Requirements
### Requirement: Canonical installer identity
The user installer SHALL install only the canonical `telltale` executable and
`telltale-*` release assets. It SHALL NOT install, alias, or probe an active
ADR technical executable, archive, service, task, or installer identity.
Historical migration artifacts are exempt.

#### Scenario: Fresh install
- GIVEN a target user directory with no prior Telltale or ADR install
- WHEN the installer runs to completion
- THEN only the canonical `telltale` binary is installed
- AND no ADR executable, service, or timer is installed

#### Scenario: Active ADR asset refusal
- GIVEN a release archive or manifest containing an active ADR technical identity
- WHEN the installer or release workflow validates the archive
- THEN validation fails with a static error
- AND no install or release proceeds

### Requirement: Transactional installer sequencing

The installer SHALL resolve and validate the selected release provenance before
any installer or systemd mutation. For an explicit candidate tag, it SHALL
require exact release-tag identity, the matching package/binary version, the
canonical archive manifest, and the archive digest from that tag's
`SHA256SUMS`; for the default stable path it SHALL apply the same checks to the
selected latest release. Only after those checks pass SHALL it acquire the
installer lock, detect or quiesce schedules, stage the sole canonical archive
and binary, run explicit state/log/env migration before activation, install new
units disabled, remove only an identified obsolete compatibility binary, reload
and smoke-test, and enable only the canonical schedule. Checksum bypass is not
permitted for approved G-SERVICE validation.

#### Scenario: Candidate provenance fails before mutation

- **GIVEN** an explicit `v0.5.0-rc.1` selection whose release metadata, tag,
  archive, manifest, or `SHA256SUMS` digest is missing or inconsistent
- **WHEN** the installer starts
- **THEN** it fails before acquiring an installer lock or changing files,
  schedules, units, or the systemd manager

#### Scenario: Exact candidate staging

- **GIVEN** a published `v0.5.0-rc.1` Release with matching metadata,
  canonical archive, and verified `SHA256SUMS` entry
- **WHEN** the installer runs with that explicit release tag
- **THEN** it stages and verifies only the matching canonical `telltale`
  artifact before proceeding with the existing journaled transaction

#### Scenario: Successful upgrade

- **GIVEN** an existing 0.3.0 user install with active `adr-scan` schedule and
  a release whose provenance checks have already passed
- **WHEN** the installer runs
- **THEN** it acquires the installer lock
- **AND** it quiesces the old `adr-scan` schedule
- **AND** it runs explicit state/log/env migration before activation
- **AND** it installs the canonical `telltale` units disabled
- **AND** it reloads and smoke-tests
- **AND** it enables only the canonical `telltale-scan` schedule

#### Scenario: Interrupted migration recovery

- **GIVEN** an installer transaction interrupted after staging but before
  activation
- **WHEN** the installer runs again
- **THEN** it recovers to a known state without clobbering existing bytes
- **AND** it leaves all schedules disabled or rolls back to one known schedule

### Requirement: Fail-closed ownership and schedule safety
The installer SHALL fail closed on ownership ambiguity, duplicate-schedule
risk, or destructive deletion of an unidentified file. It SHALL refuse
unmanaged/system scope and ambiguous ownership.

#### Scenario: Unmanaged system scope refusal
- GIVEN an installer invocation targeting a system-managed unit directory
- WHEN the installer validates scope
- THEN it fails with a static error
- AND no system units are modified

#### Scenario: Duplicate schedule conflict
- GIVEN both old `adr-scan` and new `telltale-scan` schedules are active
- WHEN the installer detects the conflict
- THEN it fails closed or rolls back to one known schedule
- AND never leaves both schedules enabled

### Requirement: Migration before activation
The installer SHALL run explicit state/log/env migration before activating the
canonical runtime. No migration SHALL rewrite historical events. Existing
legacy files SHALL remain recoverable until the installer transaction commits.

#### Scenario: Legacy state migration before activation
- GIVEN an existing `adr-state.json` with detection fingerprints
- WHEN the installer runs
- THEN explicit state migration runs before the canonical units are enabled
- AND the legacy state file remains recoverable until the transaction commits
- AND previously seen detections remain deduplicated after migration

### Requirement: Canonical service and timer identity
Systemd user service and timer units SHALL use canonical `telltale-scan.service`
and `telltale-scan.timer` identity with `TELLTALE_*` environment and the
canonical JSONL path. Timer de-duplication SHALL prevent duplicate schedules.

#### Scenario: Canonical unit installation
- GIVEN a fresh user install
- WHEN the installer installs the service units
- THEN `telltale-scan.service` and `telltale-scan.timer` are installed disabled
- AND they reference `TELLTALE_*` environment and `telltale-events.jsonl`

### Requirement: Canonical release archive identity
Release archives and manifests SHALL contain no active ADR technical identity.
Public docs, examples, and CI assertions SHALL agree with the canonical
identity. Historical migration artifacts are exempt.

#### Scenario: Archive manifest validation
- GIVEN a built release archive and manifest
- WHEN the release workflow validates the manifest
- THEN no active ADR executable, archive, service, task, or installer identity
  is present
- AND CI assertions agree with the canonical `telltale-*` identity

### Requirement: Installer scope
The user installer owns only the current Linux user install and its user-unit
directory. (Previously: the installer handled both `adr` and `telltale`
compatibility identities during the 0.2.0 transition.)

#### Scenario: User-only scope
- GIVEN an installer invocation
- WHEN it determines its install scope
- THEN it acts only within the current user's home and user-unit directory
- AND refuses any system or unmanaged path
