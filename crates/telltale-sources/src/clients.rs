//! Supported acquisition-source registry and compatibility discovery descriptors.
//!
//! The independent tool inventory is not an acquisition or detection registry.

pub use telltale_discover::clients::{ClientDef, ClientSourceDef, PathRoot, SourcePattern};

pub fn supported_clients() -> &'static [ClientDef] {
    crate::sources::registry::builtin_client_defs()
}
