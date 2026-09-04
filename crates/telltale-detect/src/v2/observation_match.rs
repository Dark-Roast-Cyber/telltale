//! The only active Detection v2 detector: a bounded observation matcher.

use std::collections::BTreeSet;

use telltale_schema::observation::{
    CanonicalObservationV2, CapabilityId, ObservationFamily, ObservationStage,
};

use super::matcher::{
    CompiledMatcher, MatchState, MatcherEvaluation, MatcherSpec, preflight_required_capabilities,
};
use super::types::{
    DetectionError, DetectorIdentity, DetectorResult, EvaluationStatus, FindingMetadata,
};

pub const MAX_REQUIRED_CAPABILITIES: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchSurface {
    Text,
    Structured,
}

impl MatchSurface {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Structured => "structured",
        }
    }
}

/// Content/compatibility IR for an observation-match detector.
#[derive(Clone)]
pub struct ObservationMatchSpec {
    detector: DetectorIdentity,
    families: Vec<ObservationFamily>,
    stages: Vec<ObservationStage>,
    match_surface: MatchSurface,
    matcher: MatcherSpec,
    required_capabilities: Vec<CapabilityId>,
    metadata: FindingMetadata,
}

pub type ObservationMatchContent = ObservationMatchSpec;

impl ObservationMatchSpec {
    pub fn new(
        detector: DetectorIdentity,
        family: ObservationFamily,
        stages: Vec<ObservationStage>,
        matcher: MatcherSpec,
        metadata: FindingMetadata,
    ) -> Self {
        Self::new_for_families(detector, vec![family], stages, matcher, metadata)
    }

    pub fn new_for_families(
        detector: DetectorIdentity,
        families: Vec<ObservationFamily>,
        stages: Vec<ObservationStage>,
        matcher: MatcherSpec,
        metadata: FindingMetadata,
    ) -> Self {
        Self {
            detector,
            families,
            stages,
            match_surface: MatchSurface::Text,
            matcher,
            required_capabilities: Vec::new(),
            metadata,
        }
    }

    pub fn with_match_surface(mut self, value: MatchSurface) -> Self {
        self.match_surface = value;
        self
    }

    pub fn with_required_capabilities(mut self, values: Vec<CapabilityId>) -> Self {
        self.required_capabilities = values;
        self
    }

    pub fn detector(&self) -> &DetectorIdentity {
        &self.detector
    }
    pub fn families(&self) -> &[ObservationFamily] {
        &self.families
    }
    pub fn stages(&self) -> &[ObservationStage] {
        &self.stages
    }
    pub fn match_surface(&self) -> MatchSurface {
        self.match_surface
    }
    pub fn matcher(&self) -> &MatcherSpec {
        &self.matcher
    }

    pub fn compile(self) -> Result<CompiledObservationMatchDetector, DetectionError> {
        if self.detector.kind() != super::types::DetectorKind::ObservationMatch {
            return Err(DetectionError::UnsupportedDetectorKind);
        }
        if self.families.is_empty()
            || self.families.len() > 12
            || self.stages.is_empty()
            || self.stages.len() > 16
            || self.required_capabilities.len() > MAX_REQUIRED_CAPABILITIES
        {
            return Err(DetectionError::InvalidBounds);
        }
        let mut families = self.families;
        families.sort_by_key(|family| family.as_str());
        families.dedup();
        let mut stages = self.stages;
        stages.sort_by_key(|stage| stage.as_str());
        stages.dedup();
        if stages
            .iter()
            .any(|stage| !family_compatible_with_any(*stage, &families))
        {
            return Err(DetectionError::InvalidMetadata);
        }
        let matcher = self.matcher.compile()?;
        let mut required_capabilities = self
            .required_capabilities
            .into_iter()
            .collect::<BTreeSet<_>>();
        required_capabilities.extend(matcher.required_capabilities());
        Ok(CompiledObservationMatchDetector {
            detector: self.detector,
            families,
            stages,
            match_surface: self.match_surface,
            matcher,
            required_capabilities,
            metadata: self.metadata,
        })
    }
}

#[derive(Debug, Clone)]
pub struct CompiledObservationMatchDetector {
    detector: DetectorIdentity,
    families: Vec<ObservationFamily>,
    stages: Vec<ObservationStage>,
    match_surface: MatchSurface,
    matcher: CompiledMatcher,
    required_capabilities: BTreeSet<CapabilityId>,
    metadata: FindingMetadata,
}

impl CompiledObservationMatchDetector {
    pub fn detector(&self) -> &DetectorIdentity {
        &self.detector
    }
    pub fn families(&self) -> &[ObservationFamily] {
        &self.families
    }
    pub fn stages(&self) -> &[ObservationStage] {
        &self.stages
    }
    pub fn match_surface(&self) -> MatchSurface {
        self.match_surface
    }
    pub fn required_capabilities(&self) -> impl Iterator<Item = CapabilityId> + '_ {
        self.required_capabilities.iter().copied()
    }

    pub fn evaluate(&self, observation: &CanonicalObservationV2) -> DetectorResult {
        let capability_context = observation.capability_context().cloned();
        let metadata = self.metadata.clone();
        if !self.families.contains(&observation.kind())
            || !self.stages.contains(&observation.stage())
        {
            let result = DetectorResult::evaluated(
                self.detector.clone(),
                EvaluationStatus::NotApplicable,
                None,
                None,
                metadata,
                capability_context,
                Vec::new(),
            )
            .expect("validated detector metadata remains valid");
            return result
                .with_match_surface(self.match_surface.as_str())
                .expect("validated match surface remains valid");
        }
        if let Some(reason) = preflight_required_capabilities(
            &self.required_capabilities,
            observation.capability_context(),
        ) {
            let result = DetectorResult::evaluated(
                self.detector.clone(),
                EvaluationStatus::NotEvaluated,
                Some(reason),
                None,
                metadata,
                capability_context,
                Vec::new(),
            )
            .expect("validated detector metadata remains valid");
            return result
                .with_match_surface(self.match_surface.as_str())
                .expect("validated match surface remains valid");
        }

        let evaluation: MatcherEvaluation = self.matcher.evaluate(observation);
        let (status, reason, paths) = match evaluation.state() {
            MatchState::Match => (
                EvaluationStatus::EvaluatedMatch,
                None,
                evaluation.matched_selector_paths().to_vec(),
            ),
            MatchState::NoMatch => (EvaluationStatus::EvaluatedNoMatch, None, Vec::new()),
            MatchState::NotEvaluated(reason) => {
                (EvaluationStatus::NotEvaluated, Some(*reason), Vec::new())
            }
        };
        let result = DetectorResult::evaluated(
            self.detector.clone(),
            status,
            reason,
            Some(observation),
            metadata,
            capability_context,
            paths,
        )
        .expect("validated detector metadata remains valid");
        result
            .with_match_surface(self.match_surface.as_str())
            .expect("validated match surface remains valid")
    }

    pub fn evaluate_to_signal(
        &self,
        observation: &CanonicalObservationV2,
    ) -> (DetectorResult, Option<super::types::Signal>) {
        let result = self.evaluate(observation);
        let signal = result.signal().expect("evaluated result identity is valid");
        (result, signal)
    }

    pub fn evaluate_to_finding(
        &self,
        observation: &CanonicalObservationV2,
    ) -> (DetectorResult, Option<super::types::Finding>) {
        let result = self.evaluate(observation);
        let finding = result
            .finding()
            .expect("evaluated result identity is valid");
        (result, finding)
    }
}

fn family_compatible_with_any(stage: ObservationStage, families: &[ObservationFamily]) -> bool {
    families.iter().any(|family| match family {
        ObservationFamily::Message => stage == ObservationStage::MessageObserved,
        ObservationFamily::Inference => matches!(
            stage,
            ObservationStage::InferenceRequested
                | ObservationStage::InferenceStarted
                | ObservationStage::InferenceCompleted
                | ObservationStage::InferenceFailed
        ),
        ObservationFamily::Tool => matches!(
            stage,
            ObservationStage::ToolProposed
                | ObservationStage::ToolRequested
                | ObservationStage::ToolExecutionStarted
                | ObservationStage::ToolExecutionCompleted
                | ObservationStage::ToolResultReturned
        ),
        ObservationFamily::ToolDefinition => stage == ObservationStage::DefinitionChanged,
        ObservationFamily::Mcp => stage == ObservationStage::McpInventoryChanged,
        ObservationFamily::Process => stage == ObservationStage::ProcessObserved,
        ObservationFamily::File => stage == ObservationStage::FileObserved,
        ObservationFamily::Network => stage == ObservationStage::NetworkObserved,
        ObservationFamily::Browser => stage == ObservationStage::BrowserObserved,
        ObservationFamily::Runtime => matches!(
            stage,
            ObservationStage::RuntimeObserved | ObservationStage::RuntimeChanged
        ),
        ObservationFamily::Session => matches!(
            stage,
            ObservationStage::SessionOpened
                | ObservationStage::SessionUpdated
                | ObservationStage::SessionClosed
        ),
        ObservationFamily::Other => stage == ObservationStage::OtherObserved,
    })
}
