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
 quiesce canonical schedules, recover only proven marker-owned staging, stage the
sole canonical artifact, install canonical units disabled, prove the base
canonical service declaration and allowed inherited policy, validate effective
canonical behavior, smoke-test, and enable only the canonical schedule when
requested. Effective validation and all declaration/drop-in proofs SHALL
complete before binary replacement, and activation SHALL remain the last
mutating step. It SHALL never activate a canonical schedule before the
validated candidate binary is installed.

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

#### Scenario: Environment policy is validated before replacement and activation

- **GIVEN** provenance, retained-transaction recovery, canonical destinations,
  quiescence, and staging have succeeded
- **WHEN** canonical service declaration proof or effective policy validation fails
- **THEN** the installer fails before replacing the installed binary or enabling
  the canonical schedule

### Requirement: Fail-closed canonical safety

The installer SHALL fail closed on ownership ambiguity, unsafe canonical path
aliases, unsafe or unproven canonical service declarations, Telltale-specific
or ambiguous effective drop-ins, unsafe effective configuration, non-regular
destinations, unsafe modes, archive violations, or destructive deletion of an
unidentified canonical file. It SHALL refuse system scope and
unmanaged paths. The base canonical service declaration SHALL be positively
proven from its canonical path and exact generated representation or equivalent
integrity-bound bytes; a separately duplicated divergent template SHALL not be
used as the authority. Unit-specific drop-ins SHALL remain forbidden. Inherited
type-wide or global drop-ins MAY coexist only when each allowed file is
independently inspected and proven to contain no `EnvironmentFile` directive,
reset, injection, ambiguous continuation, or other unreviewed environment
contribution. Benign inherited lifecycle-only policy MAY coexist only when the
effective canonical execution, identity, environment, path, security, and
timer contract remains unchanged.

#### Scenario: Canonical effective-unit ambiguity

- **GIVEN** a canonical service or timer has a Telltale-specific or ambiguous
  manager-reported drop-in, local drop-in namespace, or unsafe effective
  fragment/property
- **WHEN** the installer validates the unit
- **THEN** it fails before staging, replacement, enablement, disablement, or deletion

#### Scenario: Benign inherited type-wide policy

- **GIVEN** a canonical service has the expected fragment and effective
  execution contract
- **AND** every inherited type-wide `service.d` policy is proven to contain no
  environment-file directive or ambiguous continuation
- **AND** an inherited type-wide `service.d` policy changes only benign
  lifecycle behavior such as `TimeoutStopFailureMode`
- **WHEN** the installer validates the unit
- **THEN** validation succeeds without requiring an empty `DropInPaths` list

#### Scenario: Unproven global environment policy

- **GIVEN** an allowed type-wide or global drop-in contains an `EnvironmentFile=`
  directive, an empty assignment that resets prior values, an environment
  injection, a continuation whose meaning is ambiguous, or unreadable content
- **WHEN** the installer validates the unit
- **THEN** it fails closed before staging, replacement, or activation

#### Scenario: Unit-specific drop-in remains forbidden

- **GIVEN** `telltale-scan.service` has a unit-specific drop-in even if its
  contents appear benign
- **WHEN** the installer validates the unit
- **THEN** it fails closed before staging, replacement, or activation

#### Scenario: Canonical collision

- **GIVEN** a canonical executable, unit, state, configuration, or log destination
  is a symlink, non-regular file, unsafe alias, or owned by an unexpected principal
- **WHEN** the installer validates the destination
- **THEN** it fails closed before destructive mutation

### Requirement: Canonical service and timer identity

Systemd user units SHALL use only `telltale-scan.service` and
`telltale-scan.timer`, with the expected canonical `FragmentPath`,
`TELLTALE_*` environment, canonical executable/path identity, and canonical
JSONL path. The service's base declaration SHALL include exactly one optional
canonical environment-file declaration for
`${XDG_CONFIG_HOME:-$HOME/.config}/telltale/telltale.env`, with missing-file
errors ignored, and that declaration SHALL be proven independently of the
effective `EnvironmentFiles` report. An empty effective `EnvironmentFiles`
report SHALL be accepted only after that declaration proof succeeds. A
non-empty report SHALL contain exactly the canonical optional path with the
missing-file-ignore form; extra, alternate, reset, glob, or unknown forms SHALL
fail closed. The effective service execution/security properties and timer's
effective target, two-entry monotonic cadence, empty calendar schedule, and
persistence contract SHALL be validated independently. A successful transaction
SHALL leave at most one canonical schedule.

#### Scenario: Canonical unit installation

- **GIVEN** a fresh user install passes provenance and canonical safety checks
- **WHEN** the installer installs units
- **THEN** the canonical service and timer are installed disabled
- **AND** they reference `TELLTALE_*` and `telltale-events.jsonl`

#### Scenario: Absent optional environment file

- **GIVEN** the generated canonical declaration is proven
- **AND** the optional environment file is absent
- **AND** the effective environment-file report is empty
- **WHEN** the installer validates the service
- **THEN** validation succeeds

#### Scenario: Unsafe effective environment-file report

- **GIVEN** the generated canonical declaration is proven
- **AND** the effective report contains an extra, alternate, reset, glob, or
  ambiguous source
- **WHEN** the installer validates the service
- **THEN** validation fails closed before replacement or activation

#### Scenario: Benign inherited lifecycle policy

- **GIVEN** inherited policy is independently readable and contains only benign
  lifecycle behavior
- **AND** all effective execution and security properties remain canonical
- **WHEN** the installer validates the service
- **THEN** validation succeeds

#### Scenario: Absent canonical optional environment file

- **GIVEN** the canonical generated service declaration is positively proven
- **AND** the canonical environment file is absent
- **AND** systemd reports an empty effective `EnvironmentFiles` property
- **WHEN** the installer validates the effective canonical service
- **THEN** validation succeeds
- **AND** no alternate or unknown environment source is accepted by inference

#### Scenario: Present canonical optional environment file

- **GIVEN** the canonical generated service declaration is positively proven
- **AND** the canonical environment file is present and satisfies the existing
  current-user regular-file, ownership, non-symlink, single-link, and private-mode contract
- **AND** systemd reports exactly the canonical path with missing-file errors ignored
- **WHEN** the installer validates the effective canonical service
- **THEN** validation succeeds

#### Scenario: Effective environment report has an extra or alternate source

- **GIVEN** the canonical declaration is proven
- **AND** systemd reports an extra, alternate, reset, glob, noncanonical, or
  non-optional environment-file form
- **WHEN** the installer validates the effective canonical service
- **THEN** it fails closed before binary replacement or activation

#### Scenario: Environment report is not declaration proof

- **GIVEN** systemd reports an empty effective `EnvironmentFiles` property
- **AND** the base canonical declaration or allowed inherited policy cannot be
  independently proven
- **WHEN** the installer validates the effective canonical service
- **THEN** it fails closed rather than treating the empty report as proof of a
  safe declaration

#### Scenario: Unsafe global effective mutation

- **GIVEN** a type-wide or manager-wide policy changes `ExecStart`, command
  hooks, environment, environment files, execution identity, required path or
  security properties, timer target, or timer cadence
- **WHEN** the installer validates the effective canonical units
- **THEN** it fails closed even though the policy source is global

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
