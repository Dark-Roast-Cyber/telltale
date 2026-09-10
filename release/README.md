# Telltale quick start

This archive contains the canonical `telltale` command (`telltale.exe` on
Windows), the Apache-2.0 license, and reviewed deployment examples. Detection
rules are embedded in the binary; no rule bundle is needed for a first scan.

Release archives and assets use only the canonical `telltale-*` identity.

## First scan

On Linux or macOS, install the executable somewhere on your `PATH`, then run a
read-only, bounded real-store check:

```sh
mkdir -p ~/.local/bin
install -m 0755 telltale ~/.local/bin/telltale
telltale --version
telltale scan --once --dry-run --no-local-config --root "$HOME" --max-sources 5
```

On Windows, place `telltale.exe` in a user-writable directory such as
`%LOCALAPPDATA%\Telltale` and run `telltale.exe --version`. The included
`config/examples/telltale-scan-task.xml` is a Scheduled Task template; replace
its `YOUR_WINDOWS_USERNAME` values before importing it.

The `telltale.exe` packaged in the `x86_64-pc-windows-msvc` archive for this
release is statically linked against the applicable MSVC CRT and does not require
a separately installed Microsoft Visual C++ Redistributable. Microsoft runtime
DLLs are not bundled.

The included `config/examples/telltale-outputs.yaml` is optional output
configuration. The systemd service/timer and Windows task files are examples;
`config/examples/elastic-telltale-index-template.json` provides unsigned 64-bit
risk mappings for Elasticsearch-compatible consumers. None are enabled by
extracting this archive.

To compare the effective packaged configuration without writing telemetry or
state, run:

```sh
telltale config provenance --no-local-config
```

This produces a separate content-integrity manifest, not an Event 3.0 record or
attestation of individual events.

Explicit Telltale state and historical-event inputs remain outside the active
release identity and are handled only by their migration commands.
