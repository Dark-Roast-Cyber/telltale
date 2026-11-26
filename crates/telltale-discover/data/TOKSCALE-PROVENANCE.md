# Pinned catalog provenance

Source: [junhoyeo/tokscale](https://github.com/junhoyeo/tokscale), revision
`6ff87bdd4eb1e9e3d26a51b0b788d4ccaa154a5e`.

Adopted metadata comes exclusively from MIT-licensed Rust core files:

- [`crates/tokscale-core/src/clients.rs`](https://github.com/junhoyeo/tokscale/blob/6ff87bdd4eb1e9e3d26a51b0b788d4ccaa154a5e/crates/tokscale-core/src/clients.rs):
  registry order, identifiers, display names, root classes, fallback roots,
  relative paths and scanner patterns. Downloaded source SHA-256:
  `ec63e80b233e40914e203faccf7aae4b273bd430823a812876fc0188de4329b1`.
- [`crates/tokscale-core/src/scanner.rs`](https://github.com/junhoyeo/tokscale/blob/6ff87bdd4eb1e9e3d26a51b0b788d4ccaa154a5e/crates/tokscale-core/src/scanner.rs):
  the additional exact `opencode/opencode.db` data-root candidate and
  `.copilot/session-store.db` home-root candidate. Channel databases,
  configured extra roots, and other scanner paths are not implemented by the
  inventory collector. Existing supported-source discovery in `discovery.rs`
  retains its separate channel-database and configured-root behavior.
- [Root `LICENSE`](https://github.com/junhoyeo/tokscale/blob/6ff87bdd4eb1e9e3d26a51b0b788d4ccaa154a5e/LICENSE):
  retained verbatim in `TOKSCALE-LICENSE-MIT`, copyright (c) 2025 Junho Yeo.

Changes: metadata is transcribed into a standalone static Rust catalog; the
inventory collector is new and does not adopt upstream parsers, traversal, environment
resolution, network calls, execution, or usage calculations. Artifact categories
and conservative platform restrictions are Telltale annotations. No code,
assets, or data from `packages/frontend` or other AGPL/CC-BY frontend material
is adopted. Logo URLs and images are not used.

## Completeness evidence

`tokscale-registry.tsv` was extracted separately from the downloaded source,
not generated from Telltale's catalog. The extraction takes every declaration
between `define_clients!(` and its terminating `);`, retaining the upstream
sequential index, Rust variant, id, display, root, environment variable,
fallback, relative path, and pattern. `catalog_contract.rs` checks the complete
ordered mapping against this fixture, not just a count. Changes to the pin
require fetching/reviewing upstream again and updating both provenance and
fixture, rather than regenerating expectations from this implementation.

Exactly 61 registry entries are retained. `synthetic`, `9router`, and `cc-mirror`
are upstream provider/wrapper attributions outside this registry, not three
additional installed products. They are deliberately not fabricated entries.

## Interpretation limits

These are provisional upstream candidates, not authoritative or exhaustive
installation specifications. A primary path may represent historical native
data, a shared store, a synchronized mirror, or a Tokscale-owned cache/capture.
The collector checks exact candidate metadata only and does not evaluate
scanner globs or symbolic scanner patterns. An empty directory is an indicator
of retained data, not evidence of active usage or a runnable installation.

Cursor, Amp, Antigravity, Trae and Warp candidates are Tokscale caches; MiniMax
Code is a Tokscale headless capture. Hindsight is a synchronized usage mirror.
Codebuff/Freebuff share the manicode store; MiMo Code/Xiaomi MiMo AI share the
mimocode store. Metadata cannot independently attribute these shared artifacts.
Antigravity CLI and Antigravity IDE are separate catalog entries; no launcher
mapping or binary inference is attempted.

OpenCode's registry primary is a legacy JSON tree. The additional default
SQLite filename is checked without opening its contents. Copilot's additional
session-store filename is likewise metadata-only. Presence does not validate a
database, session format, or parser compatibility.

Four other primary locations are marked `legacy_native_data` from explicit
migration evidence in the pinned `scanner.rs`:

| Entry | Checked legacy location | Upstream migration evidence |
| --- | --- | --- |
| Kimi | `.kimi/sessions` | Lines 2601–2624 distinguish legacy Kimi from Kimi Code's `.kimi-code/sessions`. |
| WorkBuddy | `.workbuddy` | Lines 2482–2498 identify the 5.5 move to `.workbuddy-ai`. |
| Senpi | `.senpi/agent/sessions` | Lines 969–971 identify OmO Native 5.1.0+'s `.omo/agent/sessions`. |
| Cherry Studio | `CherryStudio/.claude/projects` under app-data | Lines 2209–2215 and 3043–3063 identify V1 history and the V2 `Data/Agents/.claude/projects` location receiving new writes. |

These annotations describe the checked locations, not the age or activity of
an installation. The replacement locations are documented here as provenance
only; they are not additional candidates in this slice. The boundary remains
61 catalog entries and 63 metadata candidates, with `additional_locations`
explicitly `not_implemented`.

Home-relative candidates are checked under the supplied home; data roots
default to `.local/share`, Tokscale config to `.config/tokscale` (Windows:
`AppData/Roaming/tokscale`), and app-data to the selected platform convention.
These preserve upstream fixed-home conventions, not ambient environment rules.
Explicit config/app-data/data bases override their own root class only.
Upstream tool-specific environment relocations remain unimplemented.

Linux-specific VS Code storage candidates and the macOS Devin Desktop path are
not applied to other platform contexts. Fx is Unix-only. Unknown platform
contexts produce unverified candidates. Other candidate paths remain explicitly
`upstream_candidate_only`; these are not native platform qualification claims.
Inventory uses descriptor-relative metadata probes on Unix and handle-relative
probes on Windows. Other execution platforms return a typed unsupported-platform
error without filesystem work.
Synthetic non-Linux platform contexts on Unix exercise path resolution only,
not native macOS/Windows qualification.
