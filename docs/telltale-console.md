# Telltale Console

The optional console is a local, read-only Event3 desktop viewer. It does not
start the scanner. Overview, Detections, and Sensor Health show terminal events
from the existing JSONL journal through `telltale_core::LocalEventFeed`.

```sh
cargo run --locked -p telltale-console -- --help
cargo run --locked -p telltale-console
cargo run --locked -p telltale-console -- --path-profile project
cargo run --locked -p telltale-console -- --log-path synthetic-events.jsonl
make telltale-console-check
```

## Defaults and paths

Defaults are `--path-profile user`, no explicit log override, and bounded
`Recent { max_events: 100, max_bytes: 262144 }` startup. The existing path
resolver applies explicit `--log-path`, then `TELLTALE_LOG_PATH`, then profile
defaults. No configuration or event file is created by the console.

| Profile | Default journal |
| --- | --- |
| User, Linux | `$XDG_STATE_HOME/telltale/logs/telltale-events.jsonl`, falling back to `~/.local/state/telltale/logs/telltale-events.jsonl` |
| User, macOS | `~/Library/Logs/Telltale/telltale-events.jsonl` |
| User, Windows | `%LOCALAPPDATA%\Telltale\Logs\telltale-events.jsonl` (existing resolver fallbacks apply) |
| Project | `logs/telltale-events.jsonl` relative to the working directory |
| System | Linux `/var/log/telltale/telltale-events.jsonl`; macOS `/Library/Logs/Telltale/telltale-events.jsonl`; Windows `%ProgramData%\Telltale\Logs\telltale-events.jsonl` |

The selected profile and resolved path are shown locally as secondary context.
Missing journals show **Waiting for Telltale events.** Recoverable feed notices
do not close the app. Host polling is 500 ms when caught up or making no read /
record progress (including unavailable or incomplete journals), and 1 ms / at
most one bounded poll per frame while draining backlog. An idle partial tail
does not force a busy repaint loop.

## Reading the views

- Counts describe the recent **in-memory window**, not a scan/session total.
  Up to 2000 records are retained in physical journal order, with newest-first
  views. IDs deduplicate only while retained; restart/eviction ends that window.
- Findings are exactly Detection, ProcessChain, and Correlation. High/critical
  counts and maximum **event** risk are not combined session risk or a verdict.
  Severity/client filters and rule/category/session search never search raw
  sources, evidence, process commands, or paths.
- Selection shows typed family details and distinct Event3 timing fields.
  Evidence is already terminal/redacted. Response text is **Recommended response
  / Investigation guidance**, not an executed action. Timeline anchors are
  non-clickable normalized-entry metadata, not immutable observation IDs.
- Sensor Health shows the last retained health event in journal order plus
  recent scanner errors and operational alerts. Last observed health does not
  prove current liveness; Event3 supplies no host/sensor identity. Missing health
  is unavailable, not healthy.
- Feed notices are separate structured code/count aggregates for this app
  session. Integrity/gap/unsafe/bound/collision/race/replacement/truncation
  notices keep status **Degraded** until restart; a later successful poll cannot
  repair missing history. Restart is not a repair. Replay suppression and dedup
  eviction are informational. **Live** means a drained feed with retained data,
  never “safe” or “no threats.” **Catching up** means the feed is not drained.

## Implementation and limits

The separate, unpublished `telltale-console` package is excluded from workspace
default members and headless build/install dependencies. Core and CLI never
depend on the GUI. State is independent of egui; rendering cannot poll the feed.

`eframe = 0.36.1` and `egui = 0.36.1` are pinned and require this repository's
stable Rust 1.95. This version avoids the unmaintained font parser in 0.33.
eframe defaults are disabled; only
`default_fonts`, `glow`, and `x11` are selected. egui defaults are disabled
(fonts are enabled through eframe). Glow avoids WGPU; X11 supports Linux and
XWayland while native Windows/macOS use their platform backends. Native Wayland,
accessibility integration, link opening, persistence, and web features are not enabled.
Linux needs a desktop with X11/XWayland and OpenGL; the check target needs no
display. Upstream native platform dependencies may contain optional facilities
the app does not call; the app itself has no network or clipboard/export actions.

State is count-bounded; individual events remain bounded by the feed's 1 MiB
frame limit. Maximum-sized retained events can still use substantial memory.
Lists are virtualized and row previews clipped; selecting a record displays
its terminal fields. Notice counters saturate and use only the finite code set.

The test gate renders egui frames without a native window and exercises a
synthetic temporary journal through the real Recent feed, including absence,
mixed events, malformed input, append, selection, and screen navigation. Native
Linux/Windows/macOS CI checks compile and test, not launch windows.

Deferred: installers/release archives, session readers/timelines, raw-source or
outbox inspection, per-event provenance, remote feeds/networking, persistence,
IPC, watchers, scanner/process management, actions, and enforcement. No database,
feed thread, Tokio runtime, scanner subprocess, or source reconstruction exists
in the console.
