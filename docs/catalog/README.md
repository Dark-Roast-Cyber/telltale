# Generated catalog

These files are generated from code by `tests/catalog.rs`. Read them instead
of inferring a source path, pattern, rule field, or accepted value from prose,
another project, or memory.

| File | Generated from |
| --- | --- |
| [`sources.json`](sources.json) | The built-in source registry: every source identity with its client, kind, path root, relative path, file pattern, recursion, and fixture path, plus how each path root resolves. |
| [`rule-vocabulary.json`](rule-vocabulary.json) | The Rule v2 reader ([rule format](../rule-format.md)): accepted and required keys of rules, chains, `logsource`, the `telltale` block, `correlation` and rule package headers (read back from the reader itself); fields with the evidence field each reads and whether it takes scope modifiers; value modifiers, regex flags, scope modifiers and the Sigma modifiers level 1 rejects; condition forms; statuses, related types, levels, analytic intents, detection classes, signal types and `telltale` defaults; and limits such as `max_pattern_bytes`. `levels.event3_global_values` separately records the broader Event3 vocabulary, including operational `warning`, which is not a rule level. Field descriptions, condition meanings and tag notes are prose written in the generator. |

`cargo test --locked --test catalog` fails when a file is stale, and when the
source tables in [session sources](../session-sources.md) or the
[source validation matrix](../source-validation-matrix.md) name a different set
of identities than the registry. Regenerate with `make catalog-update` in the
same change as the code.

Two parts of `sources.json` are written by hand rather than generated: the
`path_roots` and `source_specific_discovery` descriptions. They summarize
resolution code in `crates/telltale-discover/src/discovery.rs`, and the staleness
check only confirms the committed text matches the test. Their behavior per
harness release is exercised by the
[upstream format cases](../../tests/upstream_formats/README.md) where a case
exists.

This catalog describes supported acquisition sources, not the independent
AI-tool inventory catalog. An inventory entry does not add a source here.
