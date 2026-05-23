# License And Packaging

Telltale Core is licensed under the Apache License 2.0. The root `LICENSE`
file applies to the open-source core in this repository.

## Apache-2.0 Core Boundary

The open-source core includes the local batch scanner and the files needed to
build, test, configure, and operate it:

- Rust crate metadata, build files, and source code under `src/`.
- The command-line workflows for scan, watch, export, status, and rules
  management.
- Client discovery, parser, normalization, scoring, redaction, evidence,
  event, baseline, correlation, timeline, and triage integration code that
  ships in the core crate.
- JSON event schemas under `schemas/`.
- Bundled detection rules, ad-hoc examples, policy-violation examples,
  allowlist examples, and selected configuration examples under `config/`
  that ship in the open-source core.
- Synthetic tests, fixtures, and benchmarks under `tests/` and `benches/`.
- Public technical documentation under `docs/`, plus reviewed examples and
  assets that ship in the open-source core.

The core must remain buildable and testable without private services,
proprietary modules, managed rule feeds, hosted control planes, or enterprise
integrations.

## Separate-License Territory

Future commercial or separately licensed features must stay outside the
Apache-2.0 public tree unless they carry their own explicit license file and
clear packaging boundary. Candidate separate-license areas include:

- AI-assisted rule and policy authoring.
- Managed or signed detection feeds.
- Continuous policy monitoring services.
- Local AI review or endpoint elevation features beyond the core triage client.
- EDR, SOAR, case-management, or containment integrations.
- Enterprise dashboards, compliance packs, fleet management, and hosted
  management services.
- Premium detection packs for specific agent ecosystems or regulated
  environments.

Do not make open-source core builds, tests, or fixture verification depend on
these separate-license areas.

## Public Release Boundary

The public repository is the release and packaging boundary for Telltale Core.
Public commits should contain the open-source core, public technical
documentation, synthetic fixtures, and reviewed examples. Host-specific
operations, private planning notes, local credentials, raw agent transcripts,
and environment-specific deployment assumptions must stay out of public commits
instead of being managed through a separate exported tree.
