# Generated catalog

These files are generated from code by `tests/catalog.rs`. Read them instead
of inferring a source path, pattern, rule field, or accepted value from prose,
another project, or memory.

| File | Generated from |
| --- | --- |
| [`sources.json`](sources.json) | The built-in source registry: every source identity with its client, kind, path root, relative path, file pattern, recursion, and fixture path, plus how each path root resolves. |
| [`rule-vocabulary.json`](rule-vocabulary.json) | The Rule v1 validator: accepted rule and detection fields, match targets, detection classes, signal types, analytic intents, and severities. |

`cargo test --locked --test catalog` fails when a file is stale, and when the
source tables in [session sources](../session-sources.md) or the
[source validation matrix](../source-validation-matrix.md) name a different set
of identities than the registry. Regenerate with `make catalog-update` in the
same change as the code.

The path-root descriptions in `sources.json` summarize resolution code in
`crates/telltale-sources/src/discovery.rs`; behavior per harness release is
exercised by the [upstream format cases](../../tests/upstream_formats/README.md).
