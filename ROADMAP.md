# Telltale Roadmap

Telltale is an open-source detection layer for AI coding agents and the foundation
for the Agent Detection and Response (ADR) category.

This file is the public milestone-level roadmap. It intentionally does not carry
detailed task state. Durable architecture and behavior are documented under
`docs/`; durable formal requirements live under `openspec/specs/`; accepted
bounded work belongs in GitHub Issues; detailed active implementation planning is
kept in local OpenSpec changes and other host-only planning state.

The authoritative architecture philosophy lives in
[development principles](docs/development-principles.md). Where a roadmap summary
and an accepted architecture document differ in technical detail, the architecture
document governs.

## Current Focus: 0.6.x Stabilization and Architecture Convergence

Telltale 0.6.0 established the trust, privacy, durable-delivery, release, and
controlled-adoption foundations needed for the next phase of development.

The 0.6.x development series is the period for maintenance, cleanup, and
foundational convergence before the project begins treating 0.7.0 as a long-lived
near-production baseline.

### 0.6.1: dependency and maintenance stabilization

The immediate priority is a deliberate dependency-maintenance sprint centered on
the pending Rust dependency updates represented by PR #35.

This is not treated as a blind generated dependency bump. The update crosses
major dependency boundaries and must leave the supported workspace, package
verification, security checks, and platform CI green as one coherent dependency
graph.

Priorities include:

1. **Align dependency versions across the workspace** - avoid split native-library
   dependency lines and other graph inconsistencies between the CLI and internal
   crates.
2. **Handle breaking dependency API changes deliberately** - update Telltale code
   only where required by the accepted dependency versions rather than carrying
   compatibility shims without a defined purpose.
3. **Regenerate and review the lockfile as one release input** - dependency
   movement should be explainable and reproducible.
4. **Re-run the full release-quality validation surface** - Clippy, tests,
   security/supply-chain checks, package verification, console checks, and
   supported platform CI must validate the resulting graph.
5. **Keep scope narrow** - do not mix the dependency migration with the broader
   code-volume and architecture cleanup planned for 0.6.2.

### 0.6.2: consolidation and cleanup

After dependency stabilization, make the repository smaller, clearer, and easier
for humans and coding agents to work in before more architecture is migrated.

Priorities include:

1. **Clean planning and documentation ownership** - keep roadmap, architecture,
   durable requirements, accepted work, active plans, raw ideas, and shipped
   history in distinct authoritative locations rather than duplicating the same
   state across several files.
2. **Reduce implementation and test volume** - remove obsolete code, stale
   migration scaffolding, redundant tests, outdated comments, and unnecessary
   abstractions where behavior can be preserved.
3. **Split oversized modules along existing responsibilities** - improve review
   and agent-editing boundaries without introducing architecture solely for file
   organization.
4. **Reconcile documentation with reality** - clearly distinguish current
   behavior, accepted future architecture, compatibility surfaces, and work that
   has not yet been implemented.
5. **Prepare clean migration boundaries** - make the subsequent Canonical
   Observation v2, Detection v2, and event/telemetry cutovers easier to perform
   without maintaining unnecessary parallel paths.

The cleanup phase should avoid product expansion for its own sake. Its value is a
smaller and more legible base for the remaining 0.6.x work.

### Remaining 0.6.x: move the accepted architecture into production

After stabilization and cleanup, the main objective is to stop treating the newer
architecture as a parallel or experimental path and make it the normal
implementation.

The major themes are:

- **Canonical Observation v2 becomes the native internal evidence model.**
  Supported source adapters should emit canonical observations directly rather
  than relying on a legacy flattened record as the architectural center.
- **Detection v2 becomes the production detection path.** Shadow/equivalence
  machinery is useful during migration, but it is transition tooling, not the
  intended steady state.
- **The newer event and telemetry/output model replaces transitional output
  paths.** Event and transport boundaries should converge on the accepted
  semantic architecture rather than accumulating another compatibility layer.
- **Supported source adapters converge on the current model.** Legacy and
  candidate source paths should either be migrated, explicitly retained for a
  defined compatibility reason, or removed.
- **Detection content and evaluation move with the architecture.** Rules,
  fixtures, evaluation, and analyst-facing evidence should validate the native
  data and detection paths rather than preserving old paths merely because they
  existed first.
- **Migration scaffolding is deleted as replacements become authoritative.** The
  goal is not to finish the new architecture while keeping every predecessor in
  production indefinitely.

The accepted semantic direction is documented in:

- [Semantic foundation](docs/semantic-foundation.md)
- [Canonical Observation v2](docs/canonical-observation-v2.md)
- [Detection v2](docs/detection-v2.md)
- [Event4](docs/event4.md)
- [Telemetry/output architecture](docs/telemetry-output-architecture.md)

Those documents define architecture. They are not task trackers.

## 0.7.0: Near-Production Baseline

0.7.0 is the first milestone intended to be close to a production-ready,
long-lived architectural baseline.

The release should represent convergence rather than another transition point.
Before final 0.7.0, the normal production tree should satisfy these principles:

- one authoritative canonical observation path;
- one authoritative production detection path;
- one current event/telemetry architecture;
- no normal production feature described as beta, shadow, fixture-only,
  experimental, or a planned replacement for another normal production path;
- no legacy implementation retained without an explicit compatibility purpose;
- supported sources have truthful capability and validation status;
- major oversized modules and generated/repetitive test surfaces have been
  reduced or decomposed where that materially improves maintainability;
- public documentation and OpenSpec requirements describe the product that
  actually ships;
- privacy, durability, release, installation, and platform guarantees continue to
  have explicit validation;
- the supported embedding surface is deliberate enough for downstream adoption.

After 0.7.0, the bias should shift toward stability. Foundational rewrites should
become exceptional rather than routine, and new capabilities should build on the
0.7 semantic core instead of introducing competing foundations.

Crates.io publication is intentionally deferred while these boundaries are still
moving. Revisit registry publication after the 0.7 architecture and embedding
surface have stabilized enough to support external Rust consumers deliberately.

## Beyond 0.7.0

The longer-term direction remains broader than session-store detection, but new
capabilities should reuse the same semantic core rather than becoming separate
products inside the repository.

Likely later areas include:

- direct harness integrations and lower-latency observation;
- inference-gateway observation and policy boundaries;
- policy, decisions, approvals, and capability-driven enforcement;
- additional rule-package and managed-content mechanisms;
- richer correlation and investigation workflows;
- optional agent-relevant operating-system context;
- mature external embedding and integration surfaces.

These are direction, not automatically approved implementation scope. Accepted
work should be bounded independently before implementation.

## Planning and Sources of Truth

Telltale deliberately separates durable product truth from temporary execution
state.

| Artifact | Responsibility |
| --- | --- |
| `README.md` | Current product overview, supported user-facing behavior, and entry points |
| `ROADMAP.md` | Public milestone-level direction and sequencing |
| `docs/` | Durable architecture, contracts, operating guidance, and contributor documentation |
| `openspec/specs/` | Durable formal behavioral requirements |
| GitHub Issues | Accepted, bounded backlog and work items |
| Local `openspec/changes/` | Detailed active implementation packages and task state |
| Local idea/planning files | Raw intake or a small now/next index only; not durable product truth |
| `CHANGELOG.md` and Git history | Shipped and completed history |

The public repository should remain sufficient to understand what Telltale is,
how it behaves, and where it is going without publishing local session state,
private evidence, scratch plans, or agent handoff material.

Completed work should leave active planning context once its durable requirements,
documentation, and release history are in the proper locations.

## Principles

- **Visibility first, detection second, response later.** First produce trustworthy
  telemetry from agent activity. Then make detections understandable. Add active
  response only where the data and capability model can support it truthfully.
- **Normalize before analytics.** Source-specific activity should become canonical
  observations before detection, policy, and telemetry semantics depend on it.
- **Deterministic detection is authoritative.** AI enrichment may complement the
  system but should not replace deterministic security behavior.
- **Detection remains separate from action.** A signal describes observed
  behavior; policy and deployment capability determine what can be done about it.
- **Privacy by default.** Do not emit raw secrets, unnecessary transcript bodies,
  or avoidable sensitive evidence.
- **Agent-agnostic by design.** Source-specific implementations belong at adapter
  boundaries behind common semantics.
- **Fail explicitly.** Unsupported observation or enforcement capabilities must
  degrade truthfully rather than pretending the requested behavior occurred.
- **Prefer one current architecture over permanent transition layers.** Migration
  compatibility is useful only while it has a defined purpose.

## License

Telltale Core is open source under Apache-2.0.
