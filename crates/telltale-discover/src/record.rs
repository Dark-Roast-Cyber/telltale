//! Producer-only, content-free inventory records, independent of Event 3.0.
//!
//! Fields containing text come only from the compiled catalog. Deserialization
//! is deliberately unavailable: accepting arbitrary strings would defeat that
//! invariant. A downstream consumer owns its fleet identity and envelope.

use crate::catalog::ArtifactKind;
use serde::Serialize;

pub const INVENTORY_SCHEMA: &str = "telltale.inventory/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Linux,
    MacOs,
    Windows,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeImplementation {
    ExactMetadataCandidates,
    PlatformUnverified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NotImplemented {
    NotImplemented,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallationAssessment {
    NotAssessed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LocatorQualification {
    UpstreamCandidateOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateId {
    UpstreamPrimary,
    OpenCodeDefaultDatabase,
    CopilotSessionStoreDatabase,
}

/// These outcomes never assert that a product is uninstalled or active.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateOutcome {
    IndicatorPresent,
    NotFoundInCheckedCandidate,
    SymlinkRefused,
    WrongType,
    PermissionDenied,
    MetadataUnavailable,
    CheckLimitReached,
    PlatformUnverified,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CandidateRecord {
    pub(crate) candidate: CandidateId,
    pub(crate) artifact_kind: ArtifactKind,
    pub(crate) outcome: CandidateOutcome,
}

impl CandidateRecord {
    pub fn candidate(&self) -> CandidateId {
        self.candidate
    }
    pub fn artifact_kind(&self) -> ArtifactKind {
        self.artifact_kind
    }
    pub fn outcome(&self) -> CandidateOutcome {
        self.outcome
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InventoryRecord {
    pub(crate) id: &'static str,
    pub(crate) display_name: &'static str,
    pub(crate) probe_implementation: ProbeImplementation,
    pub(crate) locator_qualification: LocatorQualification,
    pub(crate) installation: InstallationAssessment,
    pub(crate) usage: NotImplemented,
    pub(crate) additional_locations: NotImplemented,
    pub(crate) environment_relocations: NotImplemented,
    pub(crate) scanner_patterns: NotImplemented,
    pub(crate) candidates: Vec<CandidateRecord>,
}

impl InventoryRecord {
    pub fn id(&self) -> &'static str {
        self.id
    }
    pub fn display_name(&self) -> &'static str {
        self.display_name
    }
    pub fn probe_implementation(&self) -> ProbeImplementation {
        self.probe_implementation
    }
    pub fn locator_qualification(&self) -> LocatorQualification {
        self.locator_qualification
    }
    pub fn installation(&self) -> InstallationAssessment {
        self.installation
    }
    pub fn usage(&self) -> NotImplemented {
        self.usage
    }
    pub fn additional_locations(&self) -> NotImplemented {
        self.additional_locations
    }
    pub fn environment_relocations(&self) -> NotImplemented {
        self.environment_relocations
    }
    pub fn scanner_patterns(&self) -> NotImplemented {
        self.scanner_patterns
    }
    pub fn candidates(&self) -> &[CandidateRecord] {
        &self.candidates
    }
}

/// Only `discover` produces this type. It cannot accept caller-controlled text.
/// Empty directories count as indicators; no file is opened to establish usage.
///
/// ```compile_fail
/// # let json = "{}";
/// let _: telltale_discover::record::InventorySnapshot =
///     serde_json::from_str(json).unwrap();
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InventorySnapshot {
    pub(crate) schema: &'static str,
    pub(crate) catalog_revision: &'static str,
    pub(crate) observed_at_unix_ms: u64,
    pub(crate) platform: Platform,
    pub(crate) checks_performed: u32,
    pub(crate) check_limit_reached: bool,
    pub(crate) entries: Vec<InventoryRecord>,
}

impl InventorySnapshot {
    pub fn schema(&self) -> &'static str {
        self.schema
    }
    pub fn catalog_revision(&self) -> &'static str {
        self.catalog_revision
    }
    pub fn observed_at_unix_ms(&self) -> u64 {
        self.observed_at_unix_ms
    }
    pub fn platform(&self) -> Platform {
        self.platform
    }
    pub fn entries(&self) -> &[InventoryRecord] {
        &self.entries
    }
    /// Includes context validation, ancestor checks, and root-access checks.
    pub fn checks_performed(&self) -> u32 {
        self.checks_performed
    }
    pub fn check_limit_reached(&self) -> bool {
        self.check_limit_reached
    }
}
