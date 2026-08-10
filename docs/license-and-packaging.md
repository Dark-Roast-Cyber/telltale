# License And Packaging

The crates.io package name `telltale` is an unrelated session-types crate. It is
not this project; Telltale's embedding facade is packaged as `telltale-core`.

Telltale Core is licensed under the Apache License 2.0. The root `LICENSE`
file applies to the open-source core in this repository.

## Apache-2.0 Core Boundary

The open-source core includes the local batch scanner and the files needed to
build, test, configure, and operate it:

- Rust crate metadata, build files, and source code under `src/`.
- The command-line workflows for scan, watch, export, status, and rules
  management.
- Client discovery, parser, normalization, scoring, redaction, evidence,
  event, baseline, correlation, timeline, and deterministic review metadata code that
  ships in the core crate.
- JSON event schemas under `schemas/`.
- Bundled detection rules, ad-hoc examples, policy-violation examples,
  allowlist examples, and selected configuration examples under `config/`
  that ship in the open-source core. The release bundle is narrower and ships
  only the reviewed deployment examples listed below.
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
- Local AI review or endpoint elevation features beyond the deterministic core.
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
operations, private planning notes, local agent workflow state, local
credentials, raw agent transcripts, and environment-specific deployment
assumptions must stay out of public commits and remain local-only.

## Release Artifacts

Tagged GitHub releases build the checked-in Rust crate from the public
repository and publish canonical platform-specific `telltale-*` binary
archives. Every archive contains exactly these file members:

```text
telltale                    # or telltale.exe on Windows
LICENSE
README.md                   # release quick start
config/examples/telltale-outputs.yaml
config/examples/telltale-scan.service
config/examples/telltale-scan.timer
config/examples/telltale-scan-task.xml
config/examples/elastic-telltale-index-template.json
config/examples/elastic-telltale-role.json
```

The examples are intentionally curated. Existing `config/examples/splunk-*`
files and other host-only or vendor-specific deployment material are not
release members. `SHA256SUMS` is published alongside the archives as a separate
release asset.

The release workflow also creates a GitHub artifact attestation for each
archive using the workflow's short-lived GitHub/Sigstore identity. Canonical
assets use `telltale-v<version>-...`. Verify a download before extraction with
the GitHub CLI:

```sh
gh attestation verify telltale-v0.5.0-x86_64-unknown-linux-gnu.tar.gz \
  --repo Dark-Roast-Cyber/telltale
```

Use the matching archive filename for another platform. The Linux installer
checks `SHA256SUMS`; it does not verify GitHub artifact attestations.

Release artifacts must not bundle local scanner state, telemetry logs, session
stores, private planning notes, local agent workflow state, machine-specific
configuration, or credentials. Operational examples can ship as reviewed
repository files, but environment values such as SIEM endpoints, tokens, host
paths, and live transcript material belong in deployment-specific
configuration outside the release package.
