# telltale-cli

[![crates.io](https://img.shields.io/crates/v/telltale-cli.svg)](https://crates.io/crates/telltale-cli)

Telltale's command-line scanner for discovering, parsing, and detecting risky
AI coding-agent activity. Install it with:

```sh
cargo install telltale-cli
```

Do not use `cargo install telltale`: that crates.io package is an unrelated
session-types crate. The Telltale CLI package is `telltale-cli`.

The package installs both binaries:

- `telltale` is the canonical CLI.
- `adr` is the deprecated compatibility command retained through every `0.2.x`
  release. Matching `adr-*` release archives remain exact copies of the
  canonical `telltale-*` archives.

The supported Rust embedding surface is [`telltale-core`](https://crates.io/crates/telltale-core),
imported as `telltale_core`; the CLI package is not the embedding API.

The executable rename does not rename data or configuration namespaces. Keep
`ADR_*`, `adr-events.jsonl`, `adr-state.json`, `/etc/telltale/adr.env`,
`adr_version`, `adr-` event IDs, Splunk `index=adr` and `sourcetype=adr:json`,
and the existing `telltale:adr` / `telltale:adr-events` source identities.

- [Repository](https://github.com/Dark-Roast-Cyber/telltale)
- [Install and verification guide](https://github.com/Dark-Roast-Cyber/telltale/blob/main/docs/install.md)
- [Embedding guide](https://github.com/Dark-Roast-Cyber/telltale/blob/main/docs/embedding.md)
- [Versioning and package policy](https://github.com/Dark-Roast-Cyber/telltale/blob/main/docs/versioning.md)
