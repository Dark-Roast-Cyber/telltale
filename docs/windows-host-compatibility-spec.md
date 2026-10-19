# Windows host tooling specification

Status: implemented on this branch for the Windows development build helper, build provenance, and read-only live-host verifier. Codex and Claude parser behaviour is owned by its own contracts and is not changed here.

## Scope

Make a local Windows development build report the revision it was built from, and give operators a read-only way to check a live host's scanner output before any deployment step. This specification does not install, schedule, or publish anything, and it is not an instruction to deploy on a personal host.

## Deterministic build provenance

The packaged `.cargo_vcs_info.json` precedence and the twelve-lowercase-hex public revision format are unchanged. There is no environment override that can claim an unrelated revision.

Both `build.rs` scripts (the root package and `telltale-schema`):

1. Rerun when `build.rs`, `.cargo_vcs_info.json`, or `PATH` changes, so a changed Git location invalidates cached provenance.
2. Use Git to locate the real metadata paths, including linked worktrees whose `.git` is a file. They watch `HEAD`, the active loose ref when present, and `packed-refs`, so a new commit on the same branch refreshes provenance without editing source.
3. Verify the checkout root and run Git with argument arrays only. `GIT_DIR`, `GIT_WORK_TREE`, and `GIT_COMMON_DIR` are removed from the Git environment, so only the checkout root selects the repository. Metadata paths use `rev-parse --git-path`, which Git has supported since 2.5.
4. On discovery failure, keep `unknown` and emit only a bounded category: `git_unavailable`, `git_failed`, `checkout_root_mismatch`, or `invalid_revision`. Git stderr, environments, and private paths are not printed.

## Windows development build helper

`scripts/build-windows-development.ps1` runs on Windows PowerShell 5.1 and PowerShell 7.

- Resolves `git.exe` and `cargo.exe` as applications and prepends the Git directory to the child `PATH` only.
- Runs `cargo build --locked --release --bin telltale`. `-Target` accepts `x86_64-pc-windows-msvc` (default) or `x86_64-pc-windows-gnu`, the latter for development-only verification.
- For MSVC, adds `-C target-feature=+crt-static` to the first rustflags source Cargo reads (`CARGO_ENCODED_RUSTFLAGS`, then `RUSTFLAGS`, then `CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS`), keeping its existing flags, and fails on a conflicting CRT flag. It never falls back to GNU.
- Runs `telltale --version` and requires the checked-out revision in the version string.
- Returns the binary path, target, version, source revision, and SHA-256. It does not install tools or the binary, and it restores the saved environment in a `finally` block.

## Read-only live-host verifier

`scripts/verify-live-host.ps1` runs on Windows PowerShell 5.1 and PowerShell 7. It takes a mandatory `BinaryPath` and `Root`, repeatable `Client` values (`codex`, `claude`, `opencode`, `copilot`, `openclaw`, `qwen`), a bounded `MaxSources` (default 5), a per-scan `TimeoutSeconds` (default 600, at most 3600), an optional `RequiredClient`, and an optional `ReportPath`.

For each selected client it runs one `scan --once --dry-run --no-local-config --emit-activity` with dedicated temporary log and state paths, and it fails the client if dry-run wrote runtime outputs. It does not install, register tasks, modify source stores, or configure delivery. A scan that exceeds `TimeoutSeconds` is stopped and its client fails with `scanner_timeout`.

The report contains the binary version and SHA-256, start and completion timestamps, the source cap and timeout, and one entry per client with its classification, error codes, bounded counters, coverage, counts of known quarantine reasons, and a check timestamp. Session IDs, source paths, quarantine identifiers, and transcript contents are removed.

Results are classified from the scanner output rather than the exit status alone:

| Classification | Conditions |
| --- | --- |
| `failed` | Nonzero scanner exit, timeout, invalid or inconsistent summary (including record-kind counts that do not add up to `parsed_record_count`), discovery error, any parse failure, or a required client with no sources |
| `passed_with_limits` | Selected sources parse, but coverage is partial, quarantine is nonzero, or supported activity is absent from the bounded sample |
| `passed` | Selected sources parse with complete accounting, no quarantine, and supported message or tool activity present |
| `not_available` | No sources selected for a client that is not required |

The script exits 1 if any check failed and 0 otherwise. Zero detections is not an error. In the report, use `checks[].counters.emitted_detection_count` for the emitted-detection count; the verifier reads it from the scanner's `detection_flow.emitted_detection_count`. Validate authored configuration separately with `config validate`; this verifier deliberately tests the bundled rules.

## Tests

- `tests/build_windows_development.ps1` covers conflicting-flag rejection, environment restoration, and the static-CRT flag reaching each supported rustflags source. It runs in CI under `pwsh` and `powershell.exe`.
- `tests/windows_host_verification.ps1` covers classification, record-kind reconciliation, the scan timeout, and report redaction, including runs against the built binary. It runs in CI under both PowerShell versions.
- `tests/provenance_build.rs` covers the build-script provenance behaviour, including linked worktrees.
- `tests/codex_live_compatibility.rs` runs a synthetic Codex transcript with a referenced history suffix through acquisition, embedding, CLI, and replay. It executes no personal transcript or command.

## Operational acceptance

Deployment is a separate operator step. Before relying on a development build on a host:

1. Run the build helper and confirm the reported revision matches the checkout.
2. Run `scripts/verify-live-host.ps1` for the required clients and review the classification.
3. Use the existing installer's receipt and rollback behaviour. This specification does not change the managed scheduled task.

If the host lacks the MSVC linker or SDK, the official static-CRT qualification cannot be performed locally. A GNU development build shows local behaviour only and does not replace the repository's MSVC runtime gate.
