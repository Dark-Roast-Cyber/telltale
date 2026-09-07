# telltale-core

[![crates.io](https://img.shields.io/crates/v/telltale-core.svg)](https://crates.io/crates/telltale-core)

The supported Telltale embedding facade. `Pipeline` combines discovery,
parsing, and detection while returning events to the host application. It does
not write JSONL, connect to a SIEM, or exit the process. The source directory
remains `crates/telltale` for repository compatibility.

The opt-in `assignment` module owns a local protected-assignment SQLite store
for Canonical Observation v2 facts that lack a stable source coordinate. It is
not wired into production scanning or adapter projection. Callers must provide
a separately proven, mutation-stable replay association; the store does not
derive one from paths, timestamps, ordinals, or content. Each association also
requires a closed, code-reviewed `AssignmentAdapterDomain` registered from
non-sensitive adapter identifiers; unknown and dynamic source, tenant, or
credential values are rejected. Durable assignment is currently Linux-only; other
platforms fail closed until equivalent descriptor/ACL profiles are validated. New
state must be created explicitly with `ProtectedAssignmentStore::initialize`;
`open` never recreates missing authority, database, key, or receipt state.
Domain registration does not establish replay-association readiness or enable a
projector; RooCode and KiloCode remain blocked.

Operational limits: the store targets a single local filesystem under the owning
user's private directory; network filesystems are unsupported. Assignment and
receipt state grows without bound and operators own capacity. Interrupted
initialization can leave a partial store root that must be removed manually
before reinitializing; `open` never repairs or recreates state. Replacement of
the entire trusted store boundary by a same-UID attacker is out of scope.

Returned native events use the Event 3.0 contract, deterministic `response`
metadata, and optional top-level `timeline_anchors`; the embedding host owns
transport and any historical-event handling.

```rust
use telltale_core::Pipeline;

let pipeline = Pipeline::builder().build()?;
println!("{} rules", pipeline.rule_count());
# Ok::<(), Box<dyn std::error::Error>>(())
```

This package follows Telltale's pre-1.0 release and compatibility policy.

> **Crates.io name warning:** The package named `telltale` is an unrelated
> session-types crate. Use `telltale-core` and `telltale_core` for this project.

- [API documentation](https://docs.rs/telltale-core)
- [Repository](https://github.com/Dark-Roast-Cyber/telltale)
