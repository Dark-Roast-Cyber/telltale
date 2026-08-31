# Telltale threat model

Status: reviewed security-program baseline for Issue #27. This is a model of
the current repository and release path, not a claim that all residual risks
are eliminated.

## System and trust boundaries

Telltale reads agent session stores and source-specific files, normalizes them
through the owned `(ClientId, source_id)` parser, applies deterministic rules,
and emits Event 3.0 telemetry. The normal durable path is:

```text
session/source files -> parser -> normalized records -> deterministic rules
    -> terminal privacy boundary -> canonical JSONL -> optional SQLite outbox
    -> configured remote sink
```

The cooperating local process and its OS principal own the configured source
roots, configuration, rules, canonical JSONL, state, and outbox. A source file,
session record, rule/config value, sink response, downloaded release, and
dependency source are untrusted inputs unless a separate integrity check says
otherwise. The core `Pipeline` is I/O-free; the host owns file and network I/O.

The public release path is a separate boundary:

```text
reviewed source + Cargo.lock -> CI/build -> archives/SBOM
    -> checksums + attestations -> GitHub Release -> installer/operator
```

GitHub-hosted runners, workflow actions, Cargo/RustSec indexes, the registry,
and remote release consumers are not treated as local trusted code merely
because the workflow invokes them.

## Assets and abuse cases

| Asset or boundary | Threat | Current mitigation and residual |
| --- | --- | --- |
| Session stores, transcripts, and source metadata | Hostile or malformed content causes parser confusion, resource exhaustion, secret leakage, or unsafe diagnostics. | Source-specific parsers fail closed on known parser/schema failures; bounded parsing and the centralized privacy boundary apply before emitted Event 3.0 text. Residual: a cooperating principal can read inputs available to that principal; parser coverage is finite. |
| Normalized records and detection evidence | Crafted content causes false matches, missed matches, or evidence that is mistaken for authorization. | Deterministic detection/scoring remains authoritative; evidence is bounded and source ownership is exact. Detection does not itself claim enforcement. Residual: efficacy outside the measured synthetic baseline is not established. |
| Local config and rules | A local or deployment rule changes detection output, leaks a path, or is mistaken for trusted policy. | Configuration and rule provenance are represented and validated; rule precedence and trust boundaries are documented in [agent policy authoring](../agent-policy-authoring.md) and [trust boundaries](../trust-boundaries.md). Residual: a user who controls the configured local trust boundary can change local behavior. |
| Parser and source discovery boundary | A file is assigned to the wrong client/parser or malformed known data silently falls through to generic semantics. | Ownership is the exact `(ClientId, source_id)` pair and known parser failures are not silently downgraded. Residual: unsupported source families remain outside scope. |
| Canonical JSONL, scanner state, and SQLite outbox | Same-principal tampering, replacement, truncation, crash, lock contention, full storage, or replay collision causes loss or duplicate delivery. | JSONL is durably first-written before acceptance in durable mode; cursor identity/integrity, private locks, SQLite transactions, capacity checks, collision handling, and fail-closed corruption/permission behavior are covered by the durable-delivery contract. At-least-once replay permits duplicates. Privileged/root/admin actors, same-principal hostile writers, and unsupported network filesystems remain residuals. |
| Remote sink and transport | Network interception, endpoint impersonation, unauthorized sink access, rejection, outage, or receiver replay causes disclosure or loss. | Existing TLS/secret validation, bounded transport retries, structured durable retry states, blocked auth outcomes, terminal privacy sanitization, and receiver event-ID deduplication guidance apply. Residual: remote endpoint compromise and remote retention are outside Telltale's control; best-effort mode can lose data after bounded failure. |
| Dependencies and Cargo registry | A vulnerable, yanked, wildcard, duplicate, unapproved-source, or incompatible-license dependency enters the build. | `Cargo.lock` is checked by RustSec cargo-audit and cargo-deny; sources fail closed, wildcards fail, and the checked-in policy records only graph-derived duplicate/license decisions. Residual: a newly discovered issue remains a supply-chain risk until the advisory database and lock are updated. |
| Build and CI runner | A compromised compiler/tool, mutable action, checkout, cache, or workflow privilege changes tested or released code. | Tool versions are exact and installed with `--locked`; all external actions use full commit SHAs with readable tag comments; jobs use least-privilege permissions and release publication depends on preflight/build gates. Hosted-runner compromise is outside this repository's model. |
| Release package, SBOM, checksums, and attestations | Artifact substitution, tag confusion, incomplete target set, or a misleading dependency inventory reaches an operator. | Tag/version/ancestry, package boundaries, archive manifests, fixed-name deterministic CycloneDX SBOM, SHA256SUMS, archive attestations, and SBOM attestation are required before publication. Residual: operators must verify the published checksum and attestation; GitHub account/repository compromise is not solved here. |
| Installer and update path | A user installs an unintended tag, archive, or binary. | The existing installer validates release identity, canonical archive contents, checksums, and version before mutation; see [install](../install.md) and [release readiness](../release-readiness.md). Residual: local operator choices and a compromised trusted release authority remain out of scope. |

## Attacker classes

In scope are: an attacker who controls or supplies session/config/rule text;
an attacker who can write malformed source records or remote sink responses;
a dependency or registry compromise; a workflow/action or build-input
compromise; an attacker attempting release archive substitution; and an
unauthorized remote sink or network intermediary.

The model excludes a privileged/root/administrator attacker, a hostile process
with the same cooperating OS principal and unrestricted access to the same
storage, a compromised GitHub organization/account or hosted runner, a
compromised operator workstation, and compromise of a configured remote sink
after it accepts data. These exclusions are explicit limitations, not
security claims.

## Security properties and residuals

Telltale aims to preserve confidentiality at emitted textual boundaries,
integrity of deterministic detection and terminal Event 3.0 output, durable
first-write/no-silent-loss behavior when durable mode is selected, and
reviewable release provenance. It does not promise perfect redaction,
exactly-once delivery, production detection efficacy, prevention at an
observation-only boundary, or protection from actors excluded above.

Windows clean-host runtime/CRT validation remains the independent Issue #23
release gate. Issue #27 pins and verifies the release supply chain but does not
claim to solve the Windows runtime prerequisite.

## Related controls

- [Privacy model](../privacy-model.md) and [trust boundaries](../trust-boundaries.md)
- [Durable delivery specification](../../openspec/specs/durable-delivery/spec.md)
- [Release readiness](../release-readiness.md) and [installation](../install.md)
- [Security operations](operations.md)
