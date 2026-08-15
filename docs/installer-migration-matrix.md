# Linux installer matrix

This matrix describes the current-user Linux installer. It owns only canonical
Telltale destinations and never probes or modifies unrelated host resources.

## Canonical identity

| Surface | Canonical value |
| --- | --- |
| executable | `telltale` |
| environment names | `TELLTALE_*` |
| event log | `telltale-events.jsonl` |
| state | `telltale-state.json` |
| user units | `telltale-scan.service`, `telltale-scan.timer` |
| release assets | `telltale-*` archives with the exact canonical regular-member set |

The installer writes only the current user's install, canonical state/config/log
destinations, and `~/.config/systemd/user`. System scope and unmanaged paths are
refused.

## Cases

| Case | Required transaction result |
| --- | --- |
| Fresh or repeat install | Verify provenance, stage one canonical binary, install canonical units disabled, smoke-test, and enable only the canonical timer when requested. |
| Unrelated host resources | Ignore files, executables, units, timers, state, configuration, and logs that do not alias a canonical destination or alter a canonical effective unit. Do not query, warn about, classify, disable, delete, or migrate them. |
| Explicit state relocation | `telltale migrate state --from OLD --to NEW` preserves source bytes, fingerprints, cursors, locks, manifests, no-clobber, and idempotence. |
| Explicit historical-event import | `telltale migrate events --pair OLD NEW` preserves Event 1.0/2.0 bytes, order, IDs, unknown fields, duplicate handling, locks, and manifests. |
| Interrupted transaction | Recover only marker-owned canonical staging without clobbering existing bytes, then rerun idempotently. |
| Canonical collision | A symlink, non-regular file, unsafe alias, ownership violation, unexpected canonical drop-in, or ambiguous effective unit fails closed before staging or mutation. |

There is no in-place upgrade, compatibility binary, automatic product-data
migration, migration warning, or cleanup path for another product. Operators own
cleanup of unrelated software outside Telltale.

## Transaction evidence

Provenance is resolved and validated before the installer lock or mutation.
Checks include exact release-tag/package version, checksum, archive membership,
regular-file type, path safety, ownership, mode, canonical unit fragment and
drop-in state, and effective-unit safety. The journal records only bounded
canonical phases (`staging`, `schedules`, `units`, `smoke`, `activation`,
`committed`, `failed`, and `recovered`).

Canonical service and timer checks are repeated before mutation, smoke testing,
and optional timer activation. A failed check leaves unrelated resources alone;
transaction rollback and recovery retain their existing no-clobber guarantees.

Native Windows/macOS execution, managed system installation, and hosted-site
changes are outside this matrix and remain separate release gates.
