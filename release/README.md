# Telltale quick start

This archive contains the `adr` command (`adr.exe` on Windows), the Apache-2.0
license, and reviewed deployment examples. Detection rules are embedded in the
binary; no rule bundle is needed for a first scan.

## First scan

On Linux or macOS, install the executable somewhere on your `PATH`, then run a
read-only, bounded real-store check:

```sh
mkdir -p ~/.local/bin
install -m 0755 adr ~/.local/bin/adr
adr --version
adr scan --once --dry-run --no-local-config --root "$HOME" --max-sources 5
```

On Windows, place `adr.exe` in a user-writable directory such as
`%LOCALAPPDATA%\Telltale` and run `adr.exe --version`. The included
`config/examples/adr-scan-task.xml` is a Scheduled Task template; replace its
`YOUR_WINDOWS_USERNAME` values before importing it.

The included `config/examples/telltale-outputs.yaml` is optional output
configuration. The systemd service/timer and Windows task files are examples;
none are enabled by extracting this archive.
