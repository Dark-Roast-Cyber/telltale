# Upstream harness format cases

Each case is a small synthetic session store shaped like what a pinned release
of a monitored harness writes, plus the upstream source lines that define that
shape and Telltale's recorded outcome. `tests/upstream_formats.rs` runs every
case that applies to the current OS in one test
(`cargo test --locked --test upstream_formats`, a few seconds).

The cases answer two questions without a live capture: does Telltale read what
current harness releases write, and which shapes are known not to work yet.
They are synthetic conformance evidence, not live-host validation; see the
[source validation matrix](../../docs/source-validation-matrix.md).

## Layout

- `harnesses.json`: one entry per upstream harness, with the repository, the
  researched release tag, its full commit, the date it was checked, and the tag
  pattern used by `scripts/check-harness-drift`.
- `cases/<client>/<case>.json`: one case per shape.

## Case fields

| Field | Meaning |
| --- | --- |
| `description` | What the harness writes, in upstream terms. |
| `harness` | Key in `harnesses.json`. |
| `upstream` | Links to the upstream lines that define the shape. At least one must point into the harness repository at its pinned commit (`https://github.com/<repository>/blob/<commit>/...`). |
| `status` | `supported`, `known_gap` or `out_of_scope`. |
| `note` | Required unless `supported`: why the gap exists and what promoting it needs. Also say when no upstream source defines the shape. |
| `platforms` | Optional, non-empty list of `linux`, `macos` or `windows` when a path is platform-specific. |
| `acquire` | One source read through `telltale_sources::acquisition::acquire_source`: `source_id` plus one input. |
| `discover` | Files under a synthetic home, scanned by the `telltale` binary with environment-resolved discovery: `client`, `files` (home-relative path to input) and optional `env` (`{home}` expands to the synthetic home). |
| `expect` | The outcome. See below. |

An input is exactly one of `jsonl` (records, one per line), `text`, `hex`
(raw bytes), `fixture` (a repository path to copy) or `sqlite` (`schema`
statements and `rows` per table; object and array cells are stored as JSON
text, the way harnesses store their `data` columns).

`acquire` expectations: `error` (the acquisition error code, or absent for
success), `observations` (exact), `min_observations`, `min_families`
(minimum canonical observations per family, such as `tool` or `message`),
`quarantine_codes` (the exact sorted unique codes of quarantined native units,
none when absent) and `empty_messages` (the exact number of message
observations with no content, zero when absent).
`discover` expectations: `selected_sources` (exact), `min_records`, and
`failure_codes` (the sorted unique acquisition codes in the health event).

## Status rules

- `supported` cases assert a floor, so richer mapping does not break them. They
  must quarantine nothing and keep every message's content, and a supported
  `discover` case must select a source and read records.
- `known_gap` and `out_of_scope` cases assert the current failure exactly. When
  Telltale starts reading the shape, the case fails with a promotion hint:
  change it to `supported` with floor expectations in the same change as the
  fix. Do not loosen a gap's expectation to make it pass.
- `out_of_scope` marks shapes the project has decided not to pursue, such as
  legacy formats. It still records the outcome so a change is visible.

## Adding a case

1. Read the harness's storage or serialization code at the pinned commit (or
   update the pin first). Cite the exact lines in `upstream`. When the harness
   does not publish that code, cite its pinned release notes or official
   documentation and say so in `note`. Do not infer a field, path or record
   type from another tool, a fixture, or memory.
2. Keep values synthetic: placeholder IDs, `/synthetic/work` paths and
   `.invalid` hosts. Never copy a real session, even redacted.
3. Run the case once with a deliberately wrong `expect` to see the recorded
   outcome in the failure message, then set `status` from the upstream facts
   (does the harness really write this?) and `expect` from the outcome.

Use `scripts/check-harness-drift` to verify each pin and list newer upstream
releases; a newer release is a prompt to re-read the cited code and add cases,
not proof that anything changed.
