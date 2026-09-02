# Semantic Foundation

> **Status:** **Accepted architecture.** These contracts are reviewed and
> accepted as Telltale's intended future architecture. **Current
> implementation:** Event4, Detection v2, and Telemetry/Output v2 are **not
> implemented yet**. Canonical Observation v2 core types/scaffolding are
> implemented in `telltale-schema`; production adapter migration has not
> started. **Existing compatibility:**
> Event 3.0 remains the current frozen external compatibility and output
> contract.

This page is the map for the future semantic boundaries. It describes accepted
architecture, not shipped runtime behavior.

## The semantic path

```text
source-native activity
        ↓
Canonical Observation v2
        ↓
Detector
        ↓
DetectorResult
        ↓
Signal
        ↓
Finding
        ↓
telemetry / policy boundary
        ↓
Event3 compatibility projection and/or Event4 future projection
        ↓
terminal privacy / validation / serialization
        ↓
CanonicalPayload
        ↓
durability
        ↓
projection
        ↓
transport
```

The first half preserves meaning: source adapters report native facts, the
canonical observation model preserves evidence, and detection turns evidence
into security meaning. The second half decides what may leave the process,
terminalizes it, and delivers immutable bytes. A destination does not become the
owner of event meaning by receiving a projection.

A later policy/action path is separate:

```text
Finding / state / direct policy facts
        ↓
Policy
        ↓
Decision
        ↓
Action
```

Decision and Action are reserved accepted Event4 body families and future policy
concepts. Their runtime is not present today. Detection has no enforcement
authority, and a Finding is not a Decision or an Action.

## Core invariants

- **Canonical Observation is the unit of evidence.** It is the local semantic
  input to analytics and policy; a flattened compatibility record is not a
  second source of truth.
- **Signal is the unit of detection.** One observation may produce multiple
  signals, and signals are internal by default.
- **Finding is the unit of security meaning.** Findings preserve detector and
  observation provenance without carrying policy or enforcement semantics.
- **Session is the primary agent correlation boundary, not a detection unit.**
  A meaningful session may group evidence, but a detector evaluates declared
  observations, signals, or findings.
- **Proposal is not execution.** Requested, started, completed, and returned
  tool lifecycle facts remain distinct.
- **Parsed or derived is not observed.** Parsing a command, path, or URL does
  not prove process, file, or network activity.
- **Unsupported or unknown visibility is not clean.** Lack of capability is
  represented explicitly and cannot become a no-match or false value.
- **Detection policy is not telemetry/export policy.** Export profiles may omit
  or sanitize output but cannot change whether a detector matched.
- **Finding is not Decision, and Decision is not Action.** Policy intent,
  capability degradation, and an adapter's result remain separately auditable.
- **Event identity is not transport identity.** Event IDs and observation IDs
  are semantic identities; receipt, attempt, retry, and delivery IDs belong to
  transport boundaries.
- **Telltale remains standalone and offline.** Managed collection is an
  optional boundary, not a core dependency or a prerequisite for local use.
- **Tenant, device, authentication, routing, and collector metadata remain
  outside canonical events.** They belong to an external collector or
  destination envelope.
- **Event3 is frozen.** Future semantics are not backported to Event3, and
  existing persisted or replayed Event3 bytes remain unchanged.
- **Future runtime semantics belong to this accepted future architecture.**
  Documentation here does not activate an emitter, validator, adapter,
  detector, policy engine, collector, or sink.

## Compatibility boundary

> **Event 3.0: FROZEN / CURRENT COMPATIBILITY CONTRACT**

Event3 remains supported. Existing Event3 JSONL is the current sidecar and
non-Rust compatibility path. Existing persisted and replayed Event3 bytes are
unchanged. Event4 is independently versioned and does not replace Event3 until
explicit migration gates are satisfied. Future semantics are not backported to
Event3.

Event3 and Event4 are independent projections from common accepted internal
semantics, not canonical conversions of one another. A future dual projection
must preserve Event3's existing IDs, rule semantics, scoring, privacy behavior,
and output bytes. Facts that have no lossless Event3 representation remain
local or Event4-only.

Future managed adoption targets Event4, CanonicalPayload, and a vendor-neutral
collector boundary. Tenant, device, authentication, routing, receipt, and
collector metadata stay outside Event4 and CanonicalPayload. A managed adopter
may own collection, storage, tenancy, and cloud concerns around those payloads.
Emusary is not a Telltale core dependency; Telltale remains useful without a
managed adopter and does not depend on one.

## Documentation map

Accepted future contracts:

- [Event4](event4.md) — sparse envelope, typed bodies, identity, validation,
  privacy, and coexistence with Event3.
- [Canonical Observation v2](canonical-observation-v2.md) — local evidence,
  provenance, capability, fidelity, structured values, and lifecycle.
- [Detection v2](detection-v2.md) — DetectorResult, Signal, Finding, bounded
  content, grouping, and Rule v1 compatibility.
- [Telemetry/output architecture](telemetry-output-architecture.md) — policy,
  terminal bytes, CanonicalPayload, durability, projection, and transport.

Current implementation documentation:

- [Current architecture](architecture.md) — the shipped scanner pipeline.
- [Development principles](development-principles.md) — architectural
  direction and engineering constraints.
- [Current telemetry output](telemetry-output.md) — current Event3 JSONL and
  sink behavior.
- [Current detection model](detection-model.md) — current Rule v1 scoring and
  process-chain behavior.
- [Current normalization schema](normalization-schema.md) — current
  `NormalizedRecordV1` compatibility contract.

Architecture-only machine-readable references:

- [Event4 draft schema](../schemas/event4-draft.schema.json) (**architecture
  draft / not runtime-supported**).
- [Detection Content v2 draft schema](../schemas/detection-content-v2-draft.schema.json)
  (**architecture draft / not runtime-supported**).
- [Telemetry profile draft schema](../schemas/telemetry-profile-draft.schema.json)
  (**architecture draft / not runtime-supported**).
