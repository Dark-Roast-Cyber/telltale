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

## Current Focus: 0.6.x Architecture Convergence

The earlier dependency-maintenance and repository-cleanup phases are no longer
active roadmap sections. Completed implementation history belongs in Git history
and `CHANGELOG.md`. Semantic architecture convergence is complete through step 6;
the remaining 0.6.x objective is the final 0.7 event/telemetry decision in step 7.

The migration should reduce parallel machinery as it progresses. New compatibility
layers are acceptable only when they have a specific migration purpose and a
clear deletion gate.

### 0.7 target agent set

The required session/store adapter families for the 0.7 baseline are:

- **Claude Code**: `claude.projects`
- **Codex**: `codex.sessions`, `codex.archived_sessions`, and
  `codex.headless_sessions`
- **OpenCode**: `opencode.sqlite`
- **OpenClaw**: `openclaw.agents`
- **Qwen**: `qwen.projects`
- **GitHub Copilot**: `copilot.process_log`

Claude and Codex desktop-app-specific acquisition is deferred when it requires
separate source contracts. The core Claude Code and Codex session sources above
are the 0.7 convergence requirement.

The following former source identities were retired during 0.6.x convergence
and are not built-in discovery or parser paths:

- `gemini.tmp`
- `opencode.legacy_json`
- `roocode.tasks`
- `kilocode.tasks`
- `opencode.project_json`
- `codex.project_sessions`

Git history preserves their former implementations and fixtures. They must not
return as compatibility registrations or receive Canonical Observation v2 work
without a separately accepted source contract. OpenCode support for 0.7 is the
current `opencode.sqlite` database only; prior OpenCode source layouts and
source-backed record/export compatibility are not protected contracts.

### Remaining 0.6.x migration sequence

The intended convergence order is:

1. **Contract the production support denominator.** Make the target agent set
   explicit in code, tests, support documentation, and migration gates. Retire or
   reclassify non-target sources instead of porting them to the new semantic
   architecture.
2. **Make Detection v2 capable of replacing Rule v1 execution.** Keep Rule v1 as
   a supported content format, but move its compiled evaluation, modifier,
   contribution, and scoring behavior onto the Detection v2 runtime rather than
   maintaining two authoritative detector engines.
3. **Move shipped process-chain behavior onto the Detection v2 result path.**
   Preserve its matching, suppression, correlation, and risk behavior without
   manufacturing directly observed Process facts from parsed command text.
4. **Promote Canonical Observation v2 to the production acquisition contract for
   the target source set — complete.** The public `telltale-sources` acquisition
   API is the single cross-source COv2 acquisition owner for all eight identities.
   Source-native extraction feeds source-owned canonical mapping directly, with
   caller-owned observed time and separate operational progress. The parallel
   experimental projection router is removed; no legacy conversion bridge is
   introduced. This acquisition step did not activate runtime callers by itself;
   that coordinated cutover is step 5.
5. **Cut scan, watch, and the supported embedding facade over together —
   complete.** The normal production path is Canonical Observation v2 -> Detection
   v2, with Event 3.0 retained as the compatibility projection during the
   migration. Record-level compatibility APIs remain intentionally separate.
6. **Delete transitional machinery after activation - complete.** Source-backed
   legacy record projection APIs, parser registrations, compatibility-only
   source fields, duplicate scoring/grouping logic, shadow/equivalence
   infrastructure, migration-only fixtures and reports, and stale documentation
   have been retired. OpenCode retains only the current `opencode.sqlite`
   native/canonical path and its bounded cursor semantics. Event 3.0 and
   deliberate caller-provided direct-record compatibility remain separate
   contracts.
7. **Decide the final 0.7 event/telemetry cutover after semantic convergence.**
   Event4 remains an independent projection from accepted semantic truth. Do not
   expand Event4 persistence, dual emission, or transport merely to compensate
   for an unfinished internal migration.

Step 5 activation is implemented under Issue #51. The shared source-atomic
runtime owns CLI scan/watch and the supported embedding facade, including
acquisition, Detection v2 evaluation, canonical activity, baseline replacement,
and cursor eligibility. Tranche B1's processing-success rule remains in force:
OpenCode cursors do not advance after downstream operational failure. Event 3.0
remains unchanged in schema, wire contract, constructors, privacy behavior, and
already persisted bytes; newly emitted canonical evidence, hashes, or severity
are not required to be identical to legacy output. Event4 remains inactive.

Step 6 convergence completed under Issue #54 with
`597a86d6ff7c1cf07d15f993969547bb617711f2`
(`refactor: retire source record compatibility`). Remote CI run
`35973580992` and CodeQL run `35973576412` passed on that commit across the
repository's Linux, macOS, Windows, package, test, format, Clippy, security, and
code-scanning gates.

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

Before final 0.7.0, the normal production tree should satisfy these principles:

- one authoritative Canonical Observation v2 production path for the target
  source set;
- one authoritative Detection v2 production path;
- Rule v1 retained as content compatibility rather than a second detector engine;
- shipped process-chain behavior converged on the same detector result model;
- Event 3.0 retained only as a deliberate external compatibility contract while
  the current telemetry contract is finalized;
- no normal production feature described as shadow, fixture-only, experimental,
  or a planned replacement for another normal production path;
- no legacy implementation retained without an explicit continuing compatibility
  purpose;
- supported sources have truthful capability and validation status;
- migration-only shadow/equivalence machinery removed after its activation gate
  has been satisfied;
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
- Claude and Codex desktop-app-specific acquisition when separate source work is
  justified;
- runtime observation such as OpenShell integration;
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
