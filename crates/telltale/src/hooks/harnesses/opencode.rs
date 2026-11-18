//! OpenCode: the name its hooks adapter will use.
//!
//! There is no OpenCode adapter in the registry yet. Its tool shapes were
//! captured from OpenCode 1.19.5 and 2.2.5 (tests/hooks/fixtures/opencode) and
//! are evaluated through the OpenCode tool table of `telltale-sources`, so the
//! adapter starts from evaluated shapes.

/// The `Context::harness` name the adapter will use.
pub const NAME: &str = "opencode";
