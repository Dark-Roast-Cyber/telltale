# telltale-core

[![crates.io](https://img.shields.io/crates/v/telltale-core.svg)](https://crates.io/crates/telltale-core)

The supported Telltale embedding facade. `Pipeline` combines discovery,
parsing, and detection while returning events to the host application. It does
not write JSONL, connect to a SIEM, or exit the process. The source directory
remains `crates/telltale` for repository compatibility.

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
