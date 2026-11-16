# telltale-discover

**Experimental:** local AI-tool metadata inventory, separate from session
acquisition, detection and token collection. This is not a complete installed
software survey.

Supported-source callers pass explicit descriptors to `discovery`; the crate
owns filesystem traversal, root resolution, watch-root selection and project
configuration. It does not register parsers, run tools, schedule scans or ship
events. `telltale-sources` retains the supported acquisition-source registry and
its existing public discovery entry points.

Bounded on-demand source discovery (`discover_sources_bounded`) and OpenCode
store checks walk from the filesystem root using directory handles. Every
component is inspected without following symbolic links, junctions or other
reparse points, and enumeration stays on the opened handle if a pathname is
replaced. A symlinked ancestor anywhere in a candidate path, including a
system-level alias above the home directory, fails as `SymlinkRoot` rather than
being followed. Returned source paths are coordinates, not opened capabilities:
a later read must apply its own protection.

## Inventory without token counts

```sh
telltale discover --root /synthetic/home > inventory.jsonl
telltale discover --licenses
```

`discover` writes one compact `telltale.inventory/v1` snapshot to stdout. It
does not append Event3, update scanner state, start a watcher or send telemetry.
Run it on a caller-owned schedule; redirect stdout to a separate inventory log,
never `telltale-events.jsonl`. A downstream consumer supplies its own trusted
host/user/tenant envelope and fleet check-in state.

The snapshot includes all **61 registry entries** from the pinned Tokscale
core catalog, including tools without a Telltale detection adapter. It checks
63 exact metadata candidates: primary upstream locations plus current default
OpenCode and Copilot database filenames. It never reads database/session bytes,
lists source directories, executes tools, authenticates or accesses a network.

Each entry distinguishes native, legacy, shared, cached, captured or synchronized
data indicators. `indicator_present` means only that metadata matches the expected
file/directory type; an empty or stale directory is not a runnable installation
or activity. `not_found_in_checked_candidate` is not all-system absence. Symlink
refusal, wrong type, permissions, metadata errors, exhausted budgets and unverified
platforms remain distinct outcomes.

Installation probes and token collection are **not implemented** in this first
slice. Records explicitly say `installation: not_assessed` and
`usage: not_implemented`; there are no invented token totals, costs or `installed`
booleans. Additional paths, tool-specific relocations and scanner patterns are
also marked unimplemented. Tokscale-owned caches and shared stores cannot confirm
independent product installation.

## Roots, limits and platforms

- Without `--root`, the CLI selects `HOME`, then `USERPROFILE`. An explicit root
  ignores those variables. There is no implicit expansion of harness overrides,
  XDG variables, `PATH` or application settings.
- `--data-root`, `--config-root` and `--app-data-root` supply explicit generic
  directory bases. They must exist. Relative CLI roots resolve against the
  working directory; parent components and symlinked ancestors remain rejected.
  These flags affect their own root classes only: `--config-root` does not
  relocate Cursor's pinned home-relative fallback candidate.
- The Rust collector takes absolute roots, platform, time and limits from its
  caller, never the environment. Default aggregate budget: 4,096 filesystem
  operations, including root validation and every ancestor metadata/open call.
  Accepted limits are 1–65,536. Candidate counts are static; no directory entries
  are enumerated. Memory and candidate work do not grow with session history.
- Invalid/inaccessible explicit roots fail with content-free typed errors and
  no snapshot. Exhaustion after root validation is visible in candidate outcomes
  and `check_limit_reached`; a snapshot does not promise complete coverage or an
  atomic filesystem view. Consumers must not turn incomplete checks into absence.
- The new no-follow inventory backend currently supports **Unix execution
  only**. Native Windows returns `UnsupportedExecutionPlatform`. Platform-context
  tests do not qualify native macOS/Windows installations. Existing scanner
  discovery remains portable and unchanged.

```rust,no_run
use telltale_discover::inventory::{discover, InventoryContext, InventoryLimits, Platform};

let context = InventoryContext::from_home("/synthetic/home".into(), Platform::Linux);
let snapshot = discover(&context, 1234, InventoryLimits::default())?;
assert_eq!(snapshot.schema(), "telltale.inventory/v1");
# Ok::<(), telltale_discover::inventory::InventoryError>(())
```

Records are producer-only with private fields and read-only accessors. They
contain only compiled labels and numeric/enum outcomes, never host paths,
account names, session titles, arbitrary OS diagnostics or conversation content.
Scheduling, persistence, delivery and trusted fleet attribution belong to callers.

## Provenance and maintenance

Run the inventory permission tests as an unprivileged user. A root test runner
fails explicitly because root can bypass the DAC boundary; it is not counted as
permission-classification evidence.

[Pinned provenance](data/TOKSCALE-PROVENANCE.md) records the upstream revision,
adopted fields, modifications and interpretation limits. The independently
extracted [registry fixture](data/tokscale-registry.tsv) verifies every ordered
entry, not just the catalog count. Upgrades require reviewing upstream changes
and refreshing that independent evidence.

Telltale's implementation is Apache-2.0. Adopted Tokscale core catalog metadata
retains its [MIT notice](data/TOKSCALE-LICENSE-MIT), packaged with this crate and
embedded in the CLI's `discover --licenses` output. No Tokscale frontend code,
assets, data, pricing, parser runtime or remote integrations are included.
