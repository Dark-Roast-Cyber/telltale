## MODIFIED Requirements

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
