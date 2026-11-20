# Telltale v0.7.3 native verification

All five published targets passed the native release gates in GitHub Actions. The independent Windows run also passed and produced the same archive and executable SHA-256 digests as the Windows job. [GitHub Actions run 44823131496](https://github.com/Dark-Roast-Cyber/telltale/actions/runs/44823131496)

Additional local macOS validation passed 18 of 19 checks. JSONL and Elastic bulk export reproduced an Event 3.0 schema failure for credential rule identifiers. The passing native release gates do not cover that export failure; see [Remaining export issue](#remaining-export-issue).

| Release | GitHub Release ID | Release source commit | Verification workflow commit on `main` |
| --- | --- | --- | --- |
| `v0.7.3` | `453067866` | `7da3922168ab2173d652a38124b22ce326d66438` | `d54e8f21b03cde0d84d2376f2fef6cc6f96be1d5` |

## GitHub Actions evidence

Every `NATIVE_RELEASE_EVIDENCE` block recorded version `telltale 0.7.3 (7da3922168ab)` and reported `PASS` for `bundled_rules`, `positive_fixture`, `event_3_0`, and `provenance`. Each job executed its downloaded release binary.

| Target | Observed OS | Observed architecture | Runner label | Result | Job log |
| --- | --- | --- | --- | --- | --- |
| `x86_64-pc-windows-msvc` | Windows | `AMD64` | `windows-latest` | PASS | [Windows x64](https://github.com/Dark-Roast-Cyber/telltale/actions/runs/44823131496/job/136588842601) |
| `x86_64-apple-darwin` | macOS | `x86_64` | `macos-15-intel` | PASS | [macOS Intel](https://github.com/Dark-Roast-Cyber/telltale/actions/runs/44823131496/job/136588842806) |
| `aarch64-apple-darwin` | macOS | `arm64` | `macos-latest` | PASS | [macOS ARM](https://github.com/Dark-Roast-Cyber/telltale/actions/runs/44823131496/job/136588842329) |
| `x86_64-unknown-linux-gnu` | Linux | `x86_64` | `ubuntu-latest` | PASS | [Linux x64](https://github.com/Dark-Roast-Cyber/telltale/actions/runs/44823131496/job/136588842713) |
| `aarch64-unknown-linux-gnu` | Linux | `aarch64` | `ubuntu-24.04-arm` | PASS | [Linux ARM](https://github.com/Dark-Roast-Cyber/telltale/actions/runs/44823131496/job/136588842242) |

### SHA-256 digests

All five archive digests and all five executable digests matched the release pin. The Windows executable was `telltale.exe`. The other executables were named `telltale`.

```text
telltale-v0.7.3-x86_64-pc-windows-msvc.zip
  archive  6e056825c3e0ec20a03a658bbc8bcf53b1787b5ed20fb35cd136fa5731a7efbf
  binary   b8e7db27630d9eb3f4accda624b4ecc6e7e3d97a7a63e06eba66f79ef7e3b5e9

telltale-v0.7.3-x86_64-apple-darwin.tar.gz
  archive  2233ce2c85def80d8280445641979d86b9bce5efa9022212cfb9dcc75f32bc4d
  binary   4a8bdf1d21610244e4b515be9cfe78fc60339faa2dc783ba895b2ef28a8bc7f8

telltale-v0.7.3-aarch64-apple-darwin.tar.gz
  archive  7850a1d02da79921e94049b1448b76c21e72e1a797b5b2708fdcf3c0d9cd815b
  binary   1cd98b10132842c04423d6cf7f4d71a49b0bf7a5b0515dc02a9dadeb48797388

telltale-v0.7.3-x86_64-unknown-linux-gnu.tar.gz
  archive  95d419f0a47460a8ad0e1f9b2610dd8346eef2ff2c49416ae64e54ab04b3ebc5
  binary   1f9ff50a5c3ecf67e8999f08ef52d6fe2dd6a92fd9e8a063b64a3f78cec281d5

telltale-v0.7.3-aarch64-unknown-linux-gnu.tar.gz
  archive  ac3ca715072b46c746b3f2ef5400f509eeffe33d71ba337c66a8ffc9bddf31a8
  binary   40240176f8a09a9ac92192d2aad38fe4a91f3af01e399c7a87a7ecb69ec5e7ad
```

## Independent local Windows evidence

The published ZIP ran natively on Windows 11 Pro 26H2, build `26300.10075`, on x86_64 (`AMD64`). Microsoft Visual C++ v14 Redistributable `14.51.36247.0` was installed for x64 and x86.

| Gate | Result | Evidence |
| --- | --- | --- |
| Archive SHA-256 | PASS | Matched both `SHA256SUMS` and the release pin |
| Attestation | PASS | Signed source ref `refs/tags/v0.7.3` and source digest `7da3922168ab2173d652a38124b22ce326d66438` |
| Executable SHA-256 | PASS | Matched the release pin and the Windows job above |
| `telltale.exe --version` | PASS | `telltale 0.7.3 (7da3922168ab)` |
| Native verification script | PASS | Exit code `0` |

The local verifier ended with these four lines.

```text
bundled_rules=PASS
positive_fixture=PASS
event_3_0=PASS
provenance=PASS
```

### Local Windows deviations

- The procedure ran in PowerShell using the host’s authenticated GitHub CLI and a temporary sparse checkout of `main` at the workflow commit above. The verifier printed `verification_workflow_sha=not-provided`.
- The two archive checksum comparisons ran before attestation. The attestation command used `--format json` to confirm the signed source ref and digest.
- The Event 3.0 validator dependency was installed in a scratch Python virtual environment.
- `RUNNER_LABEL=windows-latest` was set manually for the verifier invocation only. The script checked the actual Windows OS and architecture.

The scratch directory was deleted and its removal was confirmed.

## Independent local macOS evidence

On 2026-11-20, the published `aarch64-apple-darwin` archive ran on macOS 27.2.1 with architecture `arm64`. The executable is a Mach-O 64-bit ARM64 binary, and `sysctl.proc_translated` returned `0`. The run used the published executable with the pinned SHA-256 above; it did not build a replacement binary.

The archive digest matched the release pin, published `SHA256SUMS`, and GitHub asset digest. The executable digest matched the release pin. Signed build attestations passed for all five downloaded archives, enforcing the release workflow, source ref `refs/tags/v0.7.3`, source commit `7da3922168ab2173d652a38124b22ce326d66438`, and GitHub-hosted builder. The exact bundle inventory and CycloneDX SBOM also passed validation.

The existing native verification script passed on this Mac with the same four terminal gates as the Windows run. Its `RUNNER_LABEL=macos-latest` was set manually to satisfy the script contract. The host was a local Mac, not a GitHub runner. The verifier used the workflow source snapshot at `d54e8f21b03cde0d84d2376f2fef6cc6f96be1d5`; the extra checks used fixtures and the schema from the exact `v0.7.3` release.

### Additional checks

The [machine-readable results](release-verification-v0.7.3-macos.json) record 18 passes and one failed export check. Rotated files followed the documented date-stamped names. The macOS output-alias guard rejected differing non-ASCII output filenames before writes. Export filters returned matching session-risk summaries as well as detections.

| Gate | Result | Observed behavior |
| --- | --- | --- |
| Native identity | PASS | Pinned executable, expected version, ARM64, no Rosetta translation |
| Bundled rules and configuration | PASS | 31 rules; configuration and rules validation returned `ok` |
| Deterministic provenance | PASS | Two invocations produced identical bytes and producer manifest ID |
| Source acquisition and Event 3.0 | PASS | 61 synthetic sources, all eight registered source identities, 140 parsed records, zero parse errors; all 159 directly emitted events passed the release schema |
| Positive and negative detection contracts | PASS | UC-001 chain matched Codex, Claude, OpenClaw, OpenCode and Qwen fixtures; Copilot UC-002 and Codex DNS-exfiltration fixtures matched; the benign MCP fixture had zero matches |
| Duplicate suppression | PASS | Repeating the scan emitted no additional detections; detection count stayed at 34 |
| Explicit backfill | PASS | Re-emitted the 34 detections |
| Stateless history | PASS | Found 34 detections without changing existing scan-state bytes |
| Dry run | PASS | Created no event, state, lock or output directory |
| Paths | PASS with boundary | Unicode source directory and ASCII output paths containing spaces worked; differing non-ASCII output filenames were rejected before writes |
| Failure handling | PASS | Missing root with `--fail-on-source-errors` returned 3; malformed state was preserved and no event was appended |
| Status | PASS | Read-only inspection preserved state and event bytes |
| Native filesystem watch | PASS | Readiness observed, an appended source record triggered a scan, and `--iterations 1` exited successfully |
| Watch shutdown and heartbeat | PASS | Idle SIGTERM exited 0 without telemetry; opt-in idle heartbeat triggered a scan and exited 0 |
| Log rotation | PASS | Active file plus two retained rotations; all six retained events passed the release schema |
| JSONL and Elastic bulk export | FAIL | 16 of 318 exported documents in each format failed Event 3.0 validation; filters and bulk action/document framing worked |

The initial full scan emitted one health event, 62 activity events, 34 detections and 62 session-risk summaries. The export corpus includes the repeated backfill events. Source coverage remained partial, with five visibility-limited sources. These are synthetic fixture checks: they do not extend current-format or live-store qualification for OpenClaw, Qwen or Copilot, and Copilot's documented UC-001 capability gap remains.

### Remaining export issue

A native detection containing `credential.api_key.pattern` passes `schemas/event.schema.json`. Export exits 0 but changes nested rule identifiers to `[redacted-secret].api_key.pattern` in `risk_contributions[].id`, `evidence[].rule_id` and `timeline_anchors[].rule_ids`. The top-level `rule_ids` retains `credential.api_key.pattern`. The changed nested identifiers fail the canonical rule-ID constraint and break agreement with the top-level IDs. The same behavior affects `credential.cloud_harvest`, session-risk summaries, and Elastic bulk document payloads.

A minimal reproduction with one directly emitted detection confirmed:

| Step | Exit code |
| --- | --- |
| Validate native input with `scripts/validate-event-jsonl` | 0 |
| Export native input with the published executable | 0 |
| Validate exported JSONL with the same validator and schema | 1 |

From a `v0.7.3` source checkout with the downloaded ARM64 executable at `./telltale` and the validator dependency installed, the fixture-based reproduction is:

```sh
verification_root=$(mktemp -d)
mkdir -p "$verification_root/stores/codex/sessions/2026/04"
cp tests/fixtures/session_stores/codex/sessions/2026/04/api-key-pattern.jsonl \
  "$verification_root/stores/codex/sessions/2026/04/"
./telltale scan --once --no-local-config --install-inventory-disabled \
  --allow-fixtures --root "$verification_root/stores" \
  --state-path "$verification_root/state.json" \
  --log-path "$verification_root/native.jsonl"
python3 scripts/validate-event-jsonl --schema schemas/event.schema.json \
  --events "$verification_root/native.jsonl"  # exits 0
./telltale export --log-path "$verification_root/native.jsonl" \
  > "$verification_root/export.jsonl"  # exits 0
python3 scripts/validate-event-jsonl --schema schemas/event.schema.json \
  --events "$verification_root/export.jsonl"  # exits 1
```

This report records the observed failure. It does not contain an export fix or qualify exported credential detections for strict Event 3.0 consumers. Direct native JSONL emission passed the schema checks above.

### Local macOS procedure boundaries

- All scanner inputs were copied synthetic fixtures. No real session stores were scanned, hooks installed, or remote telemetry sinks configured.
- Configuration discovery and installed-agent inventory were disabled. Inherited `TELLTALE_*` values were removed, and the extra checks used an isolated home directory with explicit state and event paths.
- Test outputs and the validator environment remain local. The committed evidence contains aggregate results and the synthetic reproduction, without host paths or raw session records.
- macOS output-path validation intentionally fails closed when differing non-ASCII names make alias comparison ambiguous. This boundary was observed, not repaired by this verification.

