//! Per-agent source adapter scaffolding.
//!
//! This module is the future home of built-in source adapters. Phase 1 only
//! introduces the directory layout, a minimal adapter trait placeholder, and a
//! delegated registry that the existing `crate::clients::supported_clients()`
//! wraps. Parser code, install inventory, and runtime dispatch are intentionally
//! unchanged in Phase 1.

pub mod adapter;
pub mod registry;

pub use crate::clients::{
    ClientDef, ClientId, ClientSourceDef, PathRoot, SourceKind, SourcePattern, supported_clients,
};
