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
- `adr` is the deprecated compatibility command retained by the current release
  contract. Matching `adr-*` release archives remain exact copies of the
  canonical `telltale-*` archives; this migration does not schedule its removal.

The supported Rust embedding surface is [`telltale-core`](https://crates.io/crates/telltale-core),
imported as `telltale_core`; the CLI package is not the embedding API.

The Event 3.0 cut does not rename local paths, services, executables, or
environment variables. Keep `ADR_*`, `adr-events.jsonl`, `adr-state.json`, and
`/etc/telltale/adr.env` for this transition. Native events use
`telltale_version`, `telltale-<UUIDv4>` IDs, and Splunk `index=telltale`,
`sourcetype=telltale:json`, `source=telltale`; `adr_version`, old IDs, and old
SIEM identities remain historical-only values.

## Explicit Migration

Migration is opt-in and does not change runtime defaults:

```sh
telltale migrate state --from <OLD> --to <NEW>
telltale migrate events --pair <OLD> <NEW>
telltale migrate env --from <OLD> --to <NEW>
```

Event and environment migrations validate before no-clobber installation and
use bounded streaming budgets. The packaged limits are 16 MiB per event frame,
512 MiB each for event raw/decompressed bytes, 1 GiB for event output plus
spools, 1,000,000 event records/frames, 100,000 blank frames and collision IDs,
256 MiB gzip expansion, 64 event pairs, 32 unique event destinations,
and 16 MiB each for environment input/output with 1,000,000 lines (1 MiB per
line) and 100,000 assignments. The full contract,
gzip behavior, ownership policy, and recovery procedure are documented in the [migration
contract](https://github.com/Dark-Roast-Cyber/telltale/blob/main/docs/migration-contract.md).

- [Repository](https://github.com/Dark-Roast-Cyber/telltale)
- [Install and verification guide](https://github.com/Dark-Roast-Cyber/telltale/blob/main/docs/install.md)
- [Embedding guide](https://github.com/Dark-Roast-Cyber/telltale/blob/main/docs/embedding.md)
- [Versioning and package policy](https://github.com/Dark-Roast-Cyber/telltale/blob/main/docs/versioning.md)
