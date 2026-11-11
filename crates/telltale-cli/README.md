# telltale-cli


Telltale's command-line scanner for discovering, acquiring, and detecting risky
AI coding-agent activity. The package is not published to crates.io yet; install
a GitHub release or build from source using the repository install guide.

Do not use `cargo install telltale`: that crates.io package is an unrelated
session-types crate. The Telltale CLI package is `telltale-cli`.

The package installs one binary:

- `telltale` is the sole CLI and Cargo binary identity.

The supported Rust embedding surface is `telltale-core`, imported as
`telltale_core`; the CLI package is not the embedding API.

The runtime uses canonical paths and `TELLTALE_*` environment variables. Unknown
inherited non-canonical variables are ignored. Native events use
`telltale_version`, `telltale-<UUIDv4>` IDs, and Splunk `index=telltale`,
`sourcetype=telltale:json`, `source=telltale`. Current journal readers accept
Event 3.0 only; existing historical records are never rewritten in place.

`telltale config provenance --no-local-config` prints a deterministic,
privacy-safe `ProducerProvenanceManifestV1` for the effective compiled rules,
suppression semantics, thresholds, and audited producer switches. It writes no
event, state, sidecar, journal, or manifest file; the manifest is not Event 3.0
telemetry, authentication, attestation, or proof that an event used it.
This command uses the same scan configuration and rule resolvers; the public
Rust assembler consumes the resulting effective values and does not resolve
configuration paths itself.

Installer, service, archive, and release-workflow examples use the canonical
Telltale identity. The Linux installer is limited to the current user's
install and user units; managed system paths remain deployment-specific.

## Older state and journals

This CLI no longer provides `migrate state` or `migrate events`. Use a retained
[v0.7.0 binary](https://github.com/Dark-Roast-Cyber/telltale/releases/tag/v0.7.0)
for explicit legacy-state migration before upgrading. Unsupported state fails
closed; it is not reset. Invalid current state must be investigated rather than
assumed repairable by an older migration command.

Read or export Event 1.0/2.0 journals with that older binary. Its event relocation
command preserves the old schema; it does not convert events into Event 3.0.
Select a separate Event3 journal for current scanning without truncating or
relabeling old evidence. See the [state and journal compatibility contract](https://github.com/Dark-Roast-Cyber/telltale/blob/main/docs/migration-contract.md).

- [Repository](https://github.com/Dark-Roast-Cyber/telltale)
- [Install and verification guide](https://github.com/Dark-Roast-Cyber/telltale/blob/main/docs/install.md)
- [Embedding guide](https://github.com/Dark-Roast-Cyber/telltale/blob/main/docs/embedding.md)
- [Versioning and package policy](https://github.com/Dark-Roast-Cyber/telltale/blob/main/docs/versioning.md)
