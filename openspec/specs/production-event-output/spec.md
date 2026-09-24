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

Event4 4.0 schema types, validation, and canonical `event4-json-v1` encoding
MUST remain non-production foundations in 0.7; schema support MUST NOT imply a
production projector for any Event4 family. Any future Event4 production
activation MUST have a separately reviewed activation boundary, justified by
at least one concrete production capability that Event3 cannot cleanly
represent; conceptual family definitions alone MUST NOT trigger activation.
Event3 and Event4 MUST be independent projections from accepted internal
semantics, never conversion stages from one event format into the other.

#### Scenario: Schema foundation is present without an output path

- **WHEN** Event4 types, validation, or encoding are available
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
architecture exists. A generalized `CanonicalPayload` MUST NOT be introduced
as preparatory indirection; it is deferred until a real second production
terminal payload format requires shared durable-byte ownership. Existing
Event3 exact-byte replay, terminal privacy, and sink boundaries remain governed
by `durable-delivery`, `privacy-boundary`, and `event-schema-conformance`.

#### Scenario: Event3-specific outbox remains in use

- **WHEN** a 0.7 Event3 payload is persisted for durable delivery
- **THEN** the current Event3-specific outbox remains the durability mechanism,
  without a production multi-schema payload envelope

#### Scenario: A second production terminal format is considered

- **WHEN** a generalized payload boundary is proposed
- **THEN** it is not introduced without a real second production terminal
  format needing shared durable-byte ownership
