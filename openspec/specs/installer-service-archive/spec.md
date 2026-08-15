# installer-service-archive Specification

## Purpose

Define the canonical current-user Telltale install, archive, and service safety
contract.

## Requirements

### Requirement: Canonical clean-install identity

The user installer SHALL install only the platform-canonical `telltale`
executable (`telltale.exe` on Windows), reviewed `telltale-*` release assets,
and canonical Telltale destinations and units within current-user scope.

#### Scenario: Fresh canonical install

- **GIVEN** a target user directory with no canonical Telltale installation
- **WHEN** the installer runs to completion
- **THEN** only the platform-canonical executable and canonical units are installed
- **AND** no unrelated executable, service, timer, or alias is installed

#### Scenario: Unrelated resources outside scope

- **GIVEN** unrelated files, executables, units, timers, state, configuration, or
  logs exist outside canonical Telltale destinations
- **WHEN** the installer runs
- **THEN** it ignores them without querying, classifying, warning, disabling,
  deleting, or migrating them

### Requirement: Canonical transactional sequencing

The installer SHALL resolve and validate selected release provenance before any
installer or systemd mutation. For an explicit candidate it SHALL require exact
tag identity, matching package/binary version, the exact canonical archive
manifest, and the archive digest from that tag's `SHA256SUMS`. Only after those
checks pass SHALL it acquire the installer lock, validate canonical destinations,
stage the sole canonical artifact, install canonical units disabled, smoke-test,
and enable only the canonical schedule when requested.

#### Scenario: Candidate provenance fails before mutation

- **GIVEN** release metadata, tag, archive, manifest, or checksum is missing or inconsistent
- **WHEN** the installer starts
- **THEN** it fails before acquiring the installer lock or changing files, units,
  schedules, or the systemd manager

#### Scenario: Interrupted canonical transaction recovery

- **GIVEN** a transaction is interrupted after staging but before activation
- **WHEN** the installer runs again
- **THEN** it recovers only marker-owned canonical files without clobbering bytes
- **AND** it leaves the canonical schedule disabled or in one known state

### Requirement: Fail-closed canonical safety

The installer SHALL fail closed on ownership ambiguity, unsafe canonical path
aliases, unexpected canonical drop-ins, ambiguous effective configuration,
non-regular destinations, unsafe modes, archive violations, or destructive
deletion of an unidentified canonical file. It SHALL refuse system scope and
unmanaged paths.

#### Scenario: Canonical effective-unit ambiguity

- **GIVEN** a canonical service or timer has an unexpected manager-reported
  drop-in, local drop-in namespace, or ambiguous effective fragment
- **WHEN** the installer validates the unit
- **THEN** it fails before staging, replacement, enablement, disablement, or deletion

#### Scenario: Canonical collision

- **GIVEN** a canonical executable, unit, state, configuration, or log destination
  is a symlink, non-regular file, unsafe alias, or owned by an unexpected principal
- **WHEN** the installer validates the destination
- **THEN** it fails closed before destructive mutation

### Requirement: Canonical service and timer identity

Systemd user units SHALL use only `telltale-scan.service` and
`telltale-scan.timer`, with `TELLTALE_*` environment and the canonical JSONL
path. A successful transaction SHALL leave at most one canonical schedule.

#### Scenario: Canonical unit installation

- **GIVEN** a fresh user install passes provenance and canonical safety checks
- **WHEN** the installer installs units
- **THEN** the canonical service and timer are installed disabled
- **AND** they reference `TELLTALE_*` and `telltale-events.jsonl`

### Requirement: Unrelated resource isolation

Non-canonical host resources SHALL be outside the installer's support boundary.
Their presence SHALL neither block a clean install nor cause Telltale to assume
responsibility for their lifecycle. A resource that aliases or changes a
canonical destination or effective unit remains a canonical safety failure.

#### Scenario: Non-canonical host state is ignored

- **GIVEN** unrelated files, executables, units, timers, state, configuration, or
  logs exist and do not alias a canonical Telltale resource
- **WHEN** the installer performs its normal preflight and transaction
- **THEN** it does not query or operate on those resources
- **AND** the canonical installation proceeds according to its provenance and
  safety contract

#### Scenario: Canonical resource remains fail-closed

- **GIVEN** an unrelated resource aliases, replaces, or changes the effective
  configuration of a canonical Telltale destination or unit
- **WHEN** the installer validates the canonical resource
- **THEN** it fails closed using the canonical ownership or effective-unit
  safety rule

### Requirement: Exact canonical release archive identity

Release archives and manifests SHALL contain exactly the approved canonical
member set, regular-file types, modes, and names. Public docs, examples, and CI
assertions SHALL validate this positive set and reject unexpected members
generically, including missing, duplicate, traversal, link, wrong-type, and
non-regular members.

#### Scenario: Exact archive manifest validation

- **GIVEN** a built release archive and manifest
- **WHEN** the release workflow or package verifier validates the artifact
- **THEN** validation succeeds only for the exact canonical member set
- **AND** invalid or unexpected members fail before publication or installation

### Requirement: Explicit data migration boundary

The installer SHALL perform no product migration or automated cleanup. Explicit
`telltale migrate state` and `telltale migrate events` commands remain available
for operator-selected Telltale state and historical Event 1.0/2.0 inputs, with
their existing bytes, IDs, cursors, fingerprints, locks, manifests, collision,
no-clobber, and idempotence guarantees.

There is no in-place upgrade or compatibility path for another product; external
cleanup is the operator's responsibility.

#### Scenario: No automatic product migration

- **GIVEN** unrelated state, configuration, logs, or service resources exist
  outside canonical Telltale destinations
- **WHEN** the installer performs a canonical transaction
- **THEN** it invokes no migration command and performs no automated cleanup
- **AND** explicit state or historical-event migration remains an operator-run
  CLI operation

### Requirement: Installer scope

The user installer SHALL own only the current Linux user's installation and
user-unit directory. It SHALL not manage system scope or resources outside
canonical user destinations.

#### Scenario: User-only scope

- **GIVEN** an installer invocation
- **WHEN** it determines its install scope
- **THEN** it acts only within the current user's home and user-unit directory
- **AND** it refuses any system or unmanaged path
