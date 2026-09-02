# Telltale Development Principles

Status: Authoritative architecture and engineering guidance for Telltale maintainers and contributors.
Scope: Telltale core, adapters, rule content, policy, enforcement, gateway work, integrations, and future extension points.

## Direction, Not Sequencing

These principles define architectural direction and constraints. They do not
define implementation sequencing: `ROADMAP.md`, accepted GitHub Issues, and
milestone planning determine what is built now.

A capability described here as future work must not be implemented merely
because it is described in this document. Implementation requires separately
accepted, bounded work. Where this document and current behavior differ, the
difference is intended architecture, not a claim about what exists today.

The accepted semantic-foundation contracts are documented in [Semantic
foundation](semantic-foundation.md) and its related [Event4](event4.md),
[Canonical Observation v2](canonical-observation-v2.md), [Detection v2](detection-v2.md),
and [telemetry/output architecture](telemetry-output-architecture.md) pages.
Those pages describe accepted future architecture, not implemented capability;
these principles remain the direction for evaluating future work.

## Product Direction

Telltale is an open-source, agent-focused Agent Detection and Response (ADR) engine.

Telltale should turn observations about AI agents, model interactions, harness behavior, and agent-requested tool activity into normalized facts; evaluate detection content against those facts; apply configurable policy; produce auditable decisions; and enforce those decisions wherever the deployment has the capability to do so.

Telltale is not a general-purpose EDR, endpoint telemetry collector, or Emusary-specific component.

The project should remain simple, clean, modular, composable, useful offline, and useful as a standalone open-source project.

## Core Architecture

Prefer this conceptual flow:

```text
Observation
    -> Normalization
    -> Detection
    -> Signals
    -> Policy
    -> Decision
    -> Action
    -> Audit / Telemetry
```

Keep the responsibilities distinct.

### Observation

An observation is a fact about what an agent, model, harness, or agent-requested tool did or attempted to do.

Examples include:

- user or assistant messages
- model requests and responses
- tool calls and tool results
- shell or process execution requested by an agent
- file access performed through an agent tool
- network destinations exposed through an agent or gateway
- execution mode such as auto-approve or dangerous mode
- whether the agent is running inside an approved container or sandbox
- source, session, timing, identity, provenance, and capability metadata

Telltale may use optional OS-context components to enrich agent activity, but the core should not attempt to collect arbitrary endpoint activity unrelated to an agent.

### Normalization

Normalize source-specific activity into canonical observations before analytics.

The preferred data path is:

```text
source-native structure -> canonical observation -> analytics / policy / telemetry
```

Avoid designs that flatten rich source data into a legacy representation and later attempt to reconstruct the canonical form.

Canonical observations should preserve structured tool arguments and results, call IDs, error state, provenance, timing, source capabilities, and other information needed for correlation and enforcement.

### Intent Versus Side Effects

A model-generated tool call, a harness execution request, an authorization or
approval decision, an execution attempt, an execution completion, and a tool
result are distinct facts. A model asking for an action is not the same event
as the harness performing it, and neither is the same as the result coming
back.

Canonical observations must preserve these distinctions wherever the source
exposes them, including sufficient call/correlation identity, ordering, and
stage or outcome fields to tell them apart after normalization. Collapsing
them loses exactly the evidence needed to explain what was requested, what
was permitted, what ran, and what it produced.

Observing a proposed tool call, especially through an inference gateway, does
not by itself imply the ability to prevent host-side execution. The gateway
sees model output; the execution happens in the harness or on the host.
Pre-execution enforcement requires a synchronous enforcement boundary with
the capability to block that specific action before it occurs. Observing
after the fact is still valuable, and supported degradation must be explicit:
adapters that cannot enforce a requested action report it rather than
claiming prevention.

### Detection

Detection rules are signatures or analytics. They describe recognized behavior and produce signals.

A detection should answer questions such as:

- What behavior was observed?
- Which rule or analytic matched?
- What evidence caused the match?
- How confident or severe is the signal?

Detection logic should generally not hard-code an enforcement action.

### Signals

Signals are analytic findings produced by detections or correlation.

The same signal may result in different responses under different policies or environments.

### Policy

Policy decides what response is appropriate.

Policy may evaluate:

- canonical observations and facts directly
- detection signals
- execution context
- workspace or environment context
- source and action capabilities
- managed and local configuration

Policy does not require a detection to fire first.

Examples of direct policy conditions include:

- agent is running in auto-approve mode
- dangerous mode is enabled
- execution is outside an approved container
- a shell command is about to run in a protected workspace
- a particular class of tool requires confirmation

Do not create fake detections merely to represent configuration or environmental state when policy can evaluate that state directly.

### Decisions

Policy should produce provider-neutral decision intents such as:

- allow
- observe
- warn
- require approval
- reprompt
- block
- remediate

Do not encode product-specific actions such as `AskEmusary`. Prefer semantic actions such as `RequireApproval` and let an adapter or provider implement them.

### Actions

Action adapters implement decisions where the current deployment can support them.

Examples include:

- harness-native blocking
- gateway blocking
- harness reprompting
- user approval prompts
- externally hosted approval services
- warning or remediation

Enforcement must be capability-driven. Different harnesses and deployment modes will expose different capabilities.

If policy requests an action the current adapter cannot perform, the default behavior is:

```text
observe + emit an explicit enforcement-degraded event
```

Never claim that enforcement occurred when it did not.

Telemetry should preserve at least:

- requested action
- effective action
- degradation reason when they differ

## Deployment Modes

The same semantic engine should be reusable across deployment modes.

### Session and Store Scanning

Existing file, database, and session-store parsing remains a useful observation adapter.

It should not define the architecture of the entire product.

### Direct Harness Integration

Direct agent or harness integrations can provide richer, lower-latency observations and action capabilities.

### Inference Gateway

Start strongly with an inference gateway that supports OpenAI-compatible, Anthropic Messages-compatible, and Ollama-compatible inference traffic.

The gateway is another observation and action adapter, not a separate detection product.

Gateway observations should normalize into the same canonical model and use the same detection, policy, decision, and telemetry semantics as local sources.

Longer term, the gateway or harness may pause selected actions and route them to a human approval provider. The approval provider may be:

- Emusary
- a separately hosted approval service
- a service co-hosted with the gateway
- a local desktop UI
- a harness-native approval mechanism

The core decision remains `require approval`; the deployment chooses how approval is obtained.

## Agent Focus and OS Context

Telltale stays agent-focused.

Operating-system information matters when it explains or enriches agent activity, for example an agent-requested shell command, its process lineage, execution identity, container state, or destination.

If deeper OS monitoring is useful, prefer separate optional crates or adapters that feed agent-relevant context into Telltale rather than expanding the core into a general-purpose endpoint sensor.

## Capability Model

Design around explicit capabilities rather than assumptions.

Observation adapters should be able to describe which facts they can reliably provide. Action adapters should be able to describe which responses they can perform.

Policy and evaluation should account for these capabilities.

A source that cannot supply a field must not silently pretend that it can. An adapter that cannot block must not silently no-op a block decision.

## Rules and Detection Content

Rules are content, not application-specific configuration.

Use one common detection model and engine for:

- bundled Telltale rules
- community rules
- local custom rules
- organization rules
- third-party commercial rules
- raw HTTP-hosted rule packages
- future authenticated rule feeds
- Emusary-managed rule content

Commercial or proprietary rule content should be able to use licensing terms independent of the Telltale engine license. The engine loads and evaluates content without requiring all rule packages to use the Telltale license.

### Rule Sources and Packages

Keep rule acquisition separate from rule evaluation.

Conceptually:

```text
RuleSource
    -> RulePackage
    -> Validation
    -> Compilation
    -> Active Rule Set
```

Do not create separate rule engines for local, HTTP, commercial, or Emusary-delivered content.

### Stable Rule Identity Across Sources

The same stable rule identity can appear in more than one rule source or
package. When that happens, content must not silently replace other content
merely because an ID matches.

Prefer stable identities that are globally unique or explicitly namespaced by
origin (bundled, organization, local, remote, or integration provider), and
prefer explicit replacement or override semantics where superseding content is
intended. Which source wins, which was overridden, and why should be knowable
from provenance rather than discovered from behavior.

A future package manifest may carry identity, version, and origin metadata
needed for this. Do not build a package manager or expand the current
tiered-resolution behavior to get there; the tier order documented in
`docs/install.md` remains the current implementation.

A rule package should eventually have a small manifest that can identify items such as:

- package ID
- package version
- rule schema compatibility
- publisher
- license
- contained rules
- integrity information

Do not build a complex package manager prematurely.

Telltale should know what rule content it loaded, where it came from, which version is active, and whether activation succeeded.

### Remote Content Safety

Remote rule, policy, and configuration updates should use last-known-good activation semantics:

```text
fetch/load -> parse -> validate -> compile -> compatibility check -> atomic activate
```

If a new package is invalid, unavailable, corrupt, or incompatible, retain the previous valid active package and emit a clear failure event.

Do not replace a working ruleset with an unusable one merely because a newer download exists.

### Imported and Translated Rules

Telltale may eventually translate or adapt detection logic authored for Sigma, Sysmon, EDRs, or other ecosystems when the semantics can be represented using agent-visible observations.

Translation must report whether a rule is:

- fully representable
- partially representable
- unsupported

Never silently discard unsupported conditions and claim full equivalence.

## Configuration and Policy

Configuration should be layered, explainable, and introspectable.

For every meaningful effective value, it should eventually be possible to explain:

- the effective value
- where it came from
- what it overrode
- whether it is locally managed or externally managed

Expose meaningful operator choices without turning every internal tuning value into a public configuration option.

Major capabilities should be optional and composable where practical.

### Managed Policy Maturity

For now, local configuration may weaken or override externally managed policy.

Preserve enough provenance to support this maturity path:

1. Local overrides are allowed.
2. Local weakening remains allowed, but Telltale emits explicit override/weakening telemetry.
3. Future managed constraints may be marked non-overridable or establish a minimum allowed action.

Do not prematurely implement strict organizational locking, but do not discard provenance that will be needed later.

## Telltale and Emusary Boundary

Telltale must remain fully useful without Emusary.

Emusary should be an excellent management and collection implementation for Telltale, not a dependency baked into the core.

Telltale should own open, vendor-neutral semantics for:

- canonical agent observations
- rule language or rule intermediate representation
- detection semantics
- policy semantics
- decision and response semantics
- capabilities
- source, harness, gateway, and action adapter contracts
- privacy and redaction behavior
- event schemas
- local standalone configuration

Emusary may own managed capabilities such as:

- fleet identity and tenancy
- authentication and authorization
- deployment and update orchestration
- organization-wide rule and policy lifecycle
- config distribution
- central approval workflows
- central storage and search
- endpoint inventory
- remote evidence collection

Avoid spreading Emusary-specific types throughout Telltale core. Prefer generic management, control-plane, approval, sink, and configuration contracts.

## Data Plane and Control Plane

Keep telemetry delivery separate from management/control functions.

Data plane examples:

- detections
- observations selected for export
- decisions
- audit events
- health and delivery state when appropriate

Control plane examples:

- rules
- policy
- configuration
- capabilities
- management commands
- approval coordination
- version and compatibility state

Canonical Telltale event semantics belong to Telltale. Transport-specific envelopes and tenancy metadata belong at adapter or integration boundaries.

## Reliability and Failure Behavior

Fail safely, explicitly, and observably.

Never silently:

- lose security events
- disable requested enforcement
- accept incompatible rule or config content
- switch parsers after a known schema failure and guess at data
- drop unsupported translated conditions
- claim an action succeeded when it did not

Durable delivery, retries, blocked states, poison handling, deduplication, capacity behavior, and recovery should have explicit contracts and tests.

## Privacy

Privacy and redaction occur before arbitrary export or sink boundaries.

Integrations should receive only the data Telltale has intentionally made safe for that contract.

Do not require every downstream integration to rediscover Telltale's privacy rules independently.

## Reproducibility and Explainability

A significant Telltale decision should eventually be reproducible and explainable from recorded state.

Preserve or make available information such as:

- canonical evidence and provenance
- rule ID and rule/package version
- rule or content hash where appropriate
- policy version
- configuration provenance
- runtime capabilities
- requested action
- effective action
- degradation reason

## Extensibility

Use a stable semantic core with replaceable edges.

The detection and policy core should not need to know the details of OpenCode, Claude Code, Codex, Windows, Linux, Splunk, Elastic, Emusary, or a particular model provider.

For the near term, compiled-in Rust source adapters are acceptable. Do not introduce a dynamic plugin ABI merely to make the project appear extensible.

Design internal adapter boundaries so that a future third party can build proprietary source or action integrations without requiring permanent changes to the core.

If an external extension mechanism becomes necessary, prefer a versioned subprocess or IPC/protocol boundary over loading arbitrary shared libraries into the process.

Where reasonable, avoid internal contracts that could never be represented across a versioned external boundary.

## Modularity

Modularity means clear responsibilities and dependency direction, not maximizing the number of crates.

Keep domain/schema concepts near the center. Analytics and policy build on those concepts. Harness, platform, gateway, transport, storage, and product integrations depend inward on the semantic core.

Create a new crate when it establishes a useful ownership, dependency, test, or optionality boundary. Do not create crates solely for organizational aesthetics.

## Equivalence Across Adapters

Equivalent canonical observations should produce equivalent detection semantics regardless of whether they originated from:

- a session log
- a live harness adapter
- an inference gateway
- another supported observation adapter

Build contract and fixture tests that exercise the same synthetic behavior through multiple adapters and verify canonical and analytic equivalence where the source capabilities permit it.

## Compatibility Before 1.0

Telltale is early and pre-1.0.

Do not sacrifice long-term architecture to preserve accidental internal compatibility.

Prefer correcting foundational abstractions now rather than carrying them indefinitely.

Be more cautious with intentional external contracts such as:

- released stable rule IDs
- documented event semantics
- privacy guarantees
- security guarantees
- data-loss and delivery guarantees

Internal crate layout, private traits, module organization, and experimental implementation details may be refactored aggressively when doing so improves the architecture.

## Current Architectural Priority

Before building substantial realtime enforcement or gateway functionality, complete the transition toward canonical observations as the native internal representation.

Source adapters and future direct integrations should emit canonical observations directly rather than relying on a legacy flattened record as the center of the architecture.

This is important because future enforcement and correlation will depend on structured tool calls, exact call/result relationships, errors, timing, provenance, and runtime context that cannot always be reconstructed after flattening.

## Development Heuristics

When evaluating a proposed change, prefer the design that answers yes to more of these questions:

- Does the core remain agent-focused?
- Does source-specific data normalize before analytics?
- Are detection, policy, decision, and action responsibilities still separate?
- Can the same semantics work in scanner, harness, and gateway deployments?
- Does the design preserve standalone use without Emusary?
- Is a product-specific behavior implemented as an adapter rather than embedded in the core?
- Can unsupported capabilities fail or degrade explicitly?
- Are remote rules/config activated transactionally with last-known-good behavior?
- Can operators explain the effective config and why a decision was made?
- Does the design stay simple enough for an open-source contributor to understand?
- Is optional functionality actually optional?
- Are we fixing an architectural problem now instead of protecting accidental pre-1.0 compatibility?

If a change violates these principles, the implementation should either be revised or explicitly document why an exception is justified.
