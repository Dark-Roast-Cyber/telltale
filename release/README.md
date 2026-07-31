# Telltale quick start

This archive contains the primary `telltale` command (`telltale.exe` on
Windows) and the compiled `adr` compatibility command (`adr.exe` on Windows),
the Apache-2.0 license, and reviewed deployment examples. Detection rules are
embedded in both binaries; no rule bundle is needed for a first scan.

Use `telltale` for new integrations. `adr` is the compiled deprecated
compatibility command retained by the current release contract. The canonical
`telltale-*` archive and its matching `adr-*` compatibility asset are exact
byte-for-byte copies. This migration does not schedule removal of `adr`.

## First scan

On Linux or macOS, install the executable somewhere on your `PATH`, then run a
read-only, bounded real-store check:

```sh
mkdir -p ~/.local/bin
install -m 0755 telltale ~/.local/bin/telltale
install -m 0755 adr ~/.local/bin/adr
telltale --version
telltale scan --once --dry-run --no-local-config --root "$HOME" --max-sources 5
```

On Windows, place `telltale.exe` and `adr.exe` in a user-writable directory
such as `%LOCALAPPDATA%\Telltale` and run `telltale.exe --version`. The included
`config/examples/adr-scan-task.xml` is a Scheduled Task template; replace its
`YOUR_WINDOWS_USERNAME` values before importing it.

The included `config/examples/telltale-outputs.yaml` is optional output
configuration. The systemd service/timer and Windows task files are examples;
`config/examples/elastic-telltale-index-template.json` provides unsigned 64-bit
risk mappings for Elasticsearch-compatible consumers. None are enabled by
extracting this archive. Use `adr` only when compatibility with older scripts
is required; both commands preserve the existing ADR environment, log, state,
event, and service identities.
