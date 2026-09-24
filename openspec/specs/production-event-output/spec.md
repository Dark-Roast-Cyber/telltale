# production-event-output Specification

## Purpose

Define the Telltale 0.7 production event output selection and the gate for any
later Event4 activation. This status contract does not alter the Event3
conformance, privacy, or durable-delivery requirements owned by
`event-schema-conformance`, `privacy-boundary`, and `durable-delivery`.

## Requirements

### Requirement: 0.7 production event output is Event3 only

Telltale 0.7 MUST emit Event3 as its sole production external event format for
scan, watch, and supported embedding. Event4 MUST remain inactive in production:
there MUST be no Event4 runtime opt-in or Event3/Event4 dual emission. Runtime
telemetry profiles named `minimal`, `standard`, `verbose`, or `forensic_safe`
MUST NOT be activated in 0.7. The existing Event3 consumer, sink, privacy,
durability, replay, and platform contracts MUST remain unchanged.

#### Scenario: Production event surface

- **WHEN** scan, watch, or supported embedding produces an external event in 0.7
- **THEN** that event uses the existing Event3 output boundary, with no Event4
  event or profile-selected alternative emitted

### Requirement: Event4 foundation does not authorize production activation

Event4 4.0 schema types, validation, and canonical `event4-json-v1` encoding MAY
exist as non-production foundations. An experimental Tool-only emitter MUST NOT
be treated as production support or as evidence that other Event4 families have
production projectors. Any future Event4 production activation MUST have a
separately reviewed activation boundary, justified by at least one concrete
production capability that Event3 cannot cleanly represent; conceptual family
definitions alone MUST NOT trigger activation. Event3 and Event4 MUST be
independent projections from accepted internal semantics, never conversion
stages from one event format into the other.

#### Scenario: Schema foundation is present without an output path

- **WHEN** Event4 types, validation, encoding, or the experimental Tool emitter
  are available
- **THEN** production output remains Event3-only, and no Event4 family is
  activated by their presence

#### Scenario: Future production capability requires Event4

- **WHEN** an Event4 production family is proposed
- **THEN** its concrete Event3-inexpressible need and independent semantic
  projection require a separately reviewed activation boundary before emission

### Requirement: Durable byte ownership remains Event3-specific in 0.7

Telltale 0.7 MUST NOT introduce a production multi-schema `CanonicalPayload`
envelope. The private Event3 outbox payload representation MUST remain an
Event3-specific durability detail, not a claim that the future multi-schema
architecture exists. A generalized `CanonicalPayload` MUST be introduced only
when a real second production terminal payload format requires one authoritative
durable-byte owner. Any future output architecture MUST preserve exact durable
historical Event3 bytes rather than reconstructing them through newer
structures. Destination sinks and transports MUST NOT own event semantics or
terminal privacy.

#### Scenario: Current Event3 replay

- **WHEN** an existing Event3 payload is replayed or delivered to a destination
- **THEN** its exact durable bytes remain authoritative under the existing
  durable-delivery and privacy contracts; the destination does not reinterpret
  event meaning or rerun terminal privacy

#### Scenario: A second production terminal format is considered

- **WHEN** a future production format needs shared durable-byte ownership
- **THEN** a separately reviewed generalized payload boundary may own terminal
  bytes without reserializing historical Event3 content
