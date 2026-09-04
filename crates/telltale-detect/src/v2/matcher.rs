//! Bounded, typed observation-match matcher.

use std::{cmp::Ordering, collections::BTreeSet, fmt};

use regex::Regex;
use telltale_schema::observation::{
    CanonicalObservationV2, CapabilityAvailability, CapabilityContext, CapabilityId,
    FactProvenance, JsonValue,
};

use super::selector::{SelectorId, SelectorPresence, SelectorRegistry};
use super::types::{DetectionError, NonEvaluationReason};

pub const MAX_MATCHER_DEPTH: usize = 8;
pub const MAX_MATCHER_BRANCHES: usize = 64;
pub const MAX_PATTERN_BYTES: usize = 1_024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatcherOperator {
    Equals,
    NotEquals,
    Contains,
    Regex,
    Glob,
    Exists,
    NotExists,
    In,
    NotIn,
    StartsWith,
    EndsWith,
    Gt,
    Gte,
    Lt,
    Lte,
}

impl MatcherOperator {
    pub fn parse(value: &str) -> Result<Self, DetectionError> {
        match value {
            "equals" => Ok(Self::Equals),
            "not_equals" => Ok(Self::NotEquals),
            "contains" => Ok(Self::Contains),
            "regex" => Ok(Self::Regex),
            "glob" => Ok(Self::Glob),
            "exists" => Ok(Self::Exists),
            "not_exists" => Ok(Self::NotExists),
            "in" => Ok(Self::In),
            "not_in" => Ok(Self::NotIn),
            "starts_with" => Ok(Self::StartsWith),
            "ends_with" => Ok(Self::EndsWith),
            "gt" => Ok(Self::Gt),
            "gte" => Ok(Self::Gte),
            "lt" => Ok(Self::Lt),
            "lte" => Ok(Self::Lte),
            _ => Err(DetectionError::InvalidOperator),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Equals => "equals",
            Self::NotEquals => "not_equals",
            Self::Contains => "contains",
            Self::Regex => "regex",
            Self::Glob => "glob",
            Self::Exists => "exists",
            Self::NotExists => "not_exists",
            Self::In => "in",
            Self::NotIn => "not_in",
            Self::StartsWith => "starts_with",
            Self::EndsWith => "ends_with",
            Self::Gt => "gt",
            Self::Gte => "gte",
            Self::Lt => "lt",
            Self::Lte => "lte",
        }
    }

    fn is_presence(self) -> bool {
        matches!(self, Self::Exists | Self::NotExists)
    }
}

/// Content IR for a single predicate or boolean composition.  A predicate has
/// exactly one operator and a value is required for every non-presence
/// operator.
#[derive(Clone)]
pub enum MatcherSpec {
    Predicate {
        selector: String,
        operator: MatcherOperator,
        value: Option<JsonValue>,
        require_provenance: Option<FactProvenance>,
        require_capability: Option<CapabilityId>,
    },
    All(Vec<MatcherSpec>),
    Any(Vec<MatcherSpec>),
    Not(Box<MatcherSpec>),
}

impl MatcherSpec {
    pub fn predicate(
        selector: impl Into<String>,
        operator: MatcherOperator,
        value: Option<JsonValue>,
    ) -> Self {
        Self::Predicate {
            selector: selector.into(),
            operator,
            value,
            require_provenance: None,
            require_capability: None,
        }
    }

    /// Add optional provenance and capability eligibility requirements.
    ///
    /// A present fact with a provenance different from `require_provenance`
    /// evaluates as `NotEvaluated(IneligibleInput)` before any operator runs,
    /// including negated and presence operators. An absent fact has no
    /// provenance mismatch and follows the normal absence semantics.
    pub fn predicate_with_requirements(
        selector: impl Into<String>,
        operator: MatcherOperator,
        value: Option<JsonValue>,
        require_provenance: Option<FactProvenance>,
        require_capability: Option<CapabilityId>,
    ) -> Self {
        Self::Predicate {
            selector: selector.into(),
            operator,
            value,
            require_provenance,
            require_capability,
        }
    }

    pub fn predicate_named(
        selector: impl Into<String>,
        operator: &str,
        value: Option<JsonValue>,
    ) -> Result<Self, DetectionError> {
        Ok(Self::predicate(
            selector,
            MatcherOperator::parse(operator)?,
            value,
        ))
    }

    pub fn all(branches: Vec<Self>) -> Self {
        Self::All(branches)
    }

    pub fn any(branches: Vec<Self>) -> Self {
        Self::Any(branches)
    }

    #[allow(clippy::should_implement_trait)]
    pub fn not(branch: Self) -> Self {
        Self::Not(Box::new(branch))
    }

    pub fn equals(selector: impl Into<String>, value: JsonValue) -> Self {
        Self::predicate(selector, MatcherOperator::Equals, Some(value))
    }

    pub fn exists(selector: impl Into<String>) -> Self {
        Self::predicate(selector, MatcherOperator::Exists, None)
    }

    pub fn contains(selector: impl Into<String>, value: JsonValue) -> Self {
        Self::predicate(selector, MatcherOperator::Contains, Some(value))
    }

    pub fn not_exists(selector: impl Into<String>) -> Self {
        Self::predicate(selector, MatcherOperator::NotExists, None)
    }

    pub fn compile(self) -> Result<CompiledMatcher, DetectionError> {
        compile_matcher(self, 0)
    }
}

#[derive(Debug, Clone)]
enum CompiledMatcherNode {
    Predicate(CompiledPredicate),
    All(Vec<CompiledMatcherNode>),
    Any(Vec<CompiledMatcherNode>),
    Not(Box<CompiledMatcherNode>),
}

#[derive(Debug, Clone)]
struct CompiledPredicate {
    selector: SelectorId,
    operator: MatcherOperator,
    value: Option<JsonValue>,
    require_provenance: Option<FactProvenance>,
    require_capability: Option<CapabilityId>,
    pattern: Option<Regex>,
}

#[derive(Clone)]
pub struct CompiledMatcher {
    node: CompiledMatcherNode,
    required_capabilities: BTreeSet<CapabilityId>,
}

impl fmt::Debug for CompiledMatcher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompiledMatcher")
            .field(
                "required_capabilities",
                &self.required_capabilities.iter().collect::<Vec<_>>(),
            )
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchState {
    Match,
    NoMatch,
    NotEvaluated(NonEvaluationReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatcherEvaluation {
    state: MatchState,
    matched_selector_paths: Vec<String>,
}

impl MatcherEvaluation {
    pub fn state(&self) -> &MatchState {
        &self.state
    }

    pub fn matched_selector_paths(&self) -> &[String] {
        &self.matched_selector_paths
    }
}

impl CompiledMatcher {
    pub fn required_capabilities(&self) -> impl Iterator<Item = CapabilityId> + '_ {
        self.required_capabilities.iter().copied()
    }

    pub fn evaluate(&self, observation: &CanonicalObservationV2) -> MatcherEvaluation {
        if let Some(reason) = preflight_capabilities(
            &self.required_capabilities,
            observation.capability_context(),
        ) {
            return MatcherEvaluation {
                state: MatchState::NotEvaluated(reason),
                matched_selector_paths: Vec::new(),
            };
        }
        let registry = SelectorRegistry::new();
        let (state, paths) = evaluate_node(&self.node, observation, &registry);
        MatcherEvaluation {
            state,
            matched_selector_paths: normalize_paths(paths),
        }
    }
}

fn compile_matcher(spec: MatcherSpec, depth: usize) -> Result<CompiledMatcher, DetectionError> {
    if depth > MAX_MATCHER_DEPTH {
        return Err(DetectionError::BooleanDepthExceeded);
    }
    let mut required_capabilities = BTreeSet::new();
    let mut branch_count = 0;
    let node = compile_node(spec, depth, &mut required_capabilities, &mut branch_count)?;
    Ok(CompiledMatcher {
        node,
        required_capabilities,
    })
}

fn compile_node(
    spec: MatcherSpec,
    depth: usize,
    required_capabilities: &mut BTreeSet<CapabilityId>,
    branch_count: &mut usize,
) -> Result<CompiledMatcherNode, DetectionError> {
    if depth > MAX_MATCHER_DEPTH {
        return Err(DetectionError::BooleanDepthExceeded);
    }
    match spec {
        MatcherSpec::Predicate {
            selector,
            operator,
            value,
            require_provenance,
            require_capability,
        } => {
            let selector = SelectorId::parse(&selector)?;
            if operator.is_presence() != value.is_none() {
                return Err(DetectionError::InvalidValue);
            }
            let pattern = match operator {
                MatcherOperator::Regex | MatcherOperator::Glob => {
                    let Some(JsonValue::String(pattern)) = value.as_ref() else {
                        return Err(DetectionError::InvalidValue);
                    };
                    if pattern.len() > MAX_PATTERN_BYTES {
                        return Err(DetectionError::PatternTooLong);
                    }
                    Some(match operator {
                        MatcherOperator::Regex => {
                            Regex::new(pattern).map_err(|_| DetectionError::InvalidPattern)?
                        }
                        MatcherOperator::Glob => compile_glob(pattern)?,
                        _ => unreachable!(),
                    })
                }
                _ => None,
            };
            if let Some(capability) = selector.required_capability() {
                required_capabilities.insert(capability);
            }
            if let Some(capability) = require_capability {
                required_capabilities.insert(capability);
            }
            Ok(CompiledMatcherNode::Predicate(CompiledPredicate {
                selector,
                operator,
                value,
                require_provenance,
                require_capability,
                pattern,
            }))
        }
        MatcherSpec::All(branches) => {
            validate_branches(&branches)?;
            *branch_count = branch_count
                .checked_add(branches.len())
                .ok_or(DetectionError::BooleanBranchLimit)?;
            if *branch_count > MAX_MATCHER_BRANCHES {
                return Err(DetectionError::BooleanBranchLimit);
            }
            branches
                .into_iter()
                .map(|branch| compile_node(branch, depth + 1, required_capabilities, branch_count))
                .collect::<Result<Vec<_>, _>>()
                .map(CompiledMatcherNode::All)
        }
        MatcherSpec::Any(branches) => {
            validate_branches(&branches)?;
            *branch_count = branch_count
                .checked_add(branches.len())
                .ok_or(DetectionError::BooleanBranchLimit)?;
            if *branch_count > MAX_MATCHER_BRANCHES {
                return Err(DetectionError::BooleanBranchLimit);
            }
            branches
                .into_iter()
                .map(|branch| compile_node(branch, depth + 1, required_capabilities, branch_count))
                .collect::<Result<Vec<_>, _>>()
                .map(CompiledMatcherNode::Any)
        }
        MatcherSpec::Not(branch) => {
            *branch_count = branch_count
                .checked_add(1)
                .ok_or(DetectionError::BooleanBranchLimit)?;
            if *branch_count > MAX_MATCHER_BRANCHES {
                return Err(DetectionError::BooleanBranchLimit);
            }
            Ok(CompiledMatcherNode::Not(Box::new(compile_node(
                *branch,
                depth + 1,
                required_capabilities,
                branch_count,
            )?)))
        }
    }
}

fn validate_branches(branches: &[MatcherSpec]) -> Result<(), DetectionError> {
    if branches.is_empty() {
        return Err(DetectionError::EmptyBooleanGroup);
    }
    if branches.len() > MAX_MATCHER_BRANCHES {
        return Err(DetectionError::BooleanBranchLimit);
    }
    Ok(())
}

fn compile_glob(pattern: &str) -> Result<Regex, DetectionError> {
    let mut expression = String::from("^");
    let mut chars = pattern.chars().peekable();
    while let Some(character) = chars.next() {
        match character {
            '*' => expression.push_str(".*"),
            '?' => expression.push('.'),
            '[' => {
                expression.push('[');
                let mut closed = false;
                for character in chars.by_ref() {
                    if character == ']' {
                        closed = true;
                        break;
                    }
                    if character == '\\' {
                        expression.push_str("\\\\");
                    } else {
                        expression.push(character);
                    }
                }
                if !closed {
                    return Err(DetectionError::InvalidPattern);
                }
                expression.push(']');
            }
            character => expression.push_str(&regex::escape(&character.to_string())),
        }
        if expression.len() > MAX_PATTERN_BYTES * 2 {
            return Err(DetectionError::PatternTooLong);
        }
    }
    expression.push('$');
    Regex::new(&expression).map_err(|_| DetectionError::InvalidPattern)
}

fn evaluate_node(
    node: &CompiledMatcherNode,
    observation: &CanonicalObservationV2,
    registry: &SelectorRegistry,
) -> (MatchState, Vec<String>) {
    match node {
        CompiledMatcherNode::Predicate(predicate) => {
            evaluate_predicate(predicate, observation, registry)
        }
        CompiledMatcherNode::All(branches) => {
            let evaluations = branches
                .iter()
                .map(|branch| evaluate_node(branch, observation, registry))
                .collect::<Vec<_>>();
            let mut paths = Vec::new();
            let mut unknown = Vec::new();
            let mut has_no_match = false;
            for (state, branch_paths) in evaluations {
                match state {
                    MatchState::NoMatch => has_no_match = true,
                    MatchState::NotEvaluated(reason) => unknown.push(reason),
                    MatchState::Match => paths.extend(branch_paths),
                }
            }
            if has_no_match {
                (MatchState::NoMatch, Vec::new())
            } else if let Some(reason) = strongest_reason(&unknown) {
                (MatchState::NotEvaluated(reason), Vec::new())
            } else {
                (MatchState::Match, paths)
            }
        }
        CompiledMatcherNode::Any(branches) => {
            let evaluations = branches
                .iter()
                .map(|branch| evaluate_node(branch, observation, registry))
                .collect::<Vec<_>>();
            let mut paths = Vec::new();
            let mut unknown = Vec::new();
            let mut has_match = false;
            for (state, branch_paths) in evaluations {
                match state {
                    MatchState::Match => {
                        has_match = true;
                        paths.extend(branch_paths);
                    }
                    MatchState::NotEvaluated(reason) => unknown.push(reason),
                    MatchState::NoMatch => {}
                }
            }
            if has_match {
                (MatchState::Match, paths)
            } else if let Some(reason) = strongest_reason(&unknown) {
                (MatchState::NotEvaluated(reason), Vec::new())
            } else {
                (MatchState::NoMatch, Vec::new())
            }
        }
        CompiledMatcherNode::Not(branch) => {
            let (state, paths) = evaluate_node(branch, observation, registry);
            match state {
                MatchState::Match => (MatchState::NoMatch, Vec::new()),
                MatchState::NoMatch => (MatchState::Match, paths),
                MatchState::NotEvaluated(reason) => (MatchState::NotEvaluated(reason), Vec::new()),
            }
        }
    }
}

fn evaluate_predicate(
    predicate: &CompiledPredicate,
    observation: &CanonicalObservationV2,
    registry: &SelectorRegistry,
) -> (MatchState, Vec<String>) {
    if let Some(capability) = predicate.require_capability
        && let Some(reason) = preflight_capability(capability, observation.capability_context())
    {
        return (MatchState::NotEvaluated(reason), Vec::new());
    }
    let resolved = registry.resolve(predicate.selector, observation);
    if resolved.presence() == SelectorPresence::MetadataMissing {
        return (
            MatchState::NotEvaluated(NonEvaluationReason::IneligibleInput),
            Vec::new(),
        );
    }
    if let Some(required) = predicate.require_provenance
        && resolved.presence() != SelectorPresence::Absent
    {
        // Provenance is an eligibility gate, not an operator input. This
        // applies equally to positive, negative, and presence operators;
        // absence is handled separately below and has no provenance to check.
        match resolved.metadata() {
            Some(metadata) if metadata.provenance() == required => {}
            _ => {
                return (
                    MatchState::NotEvaluated(NonEvaluationReason::IneligibleInput),
                    Vec::new(),
                );
            }
        }
    }
    if !resolved.is_present() {
        return match predicate.operator {
            MatcherOperator::NotExists => (
                MatchState::Match,
                vec![predicate.selector.as_str().to_owned()],
            ),
            MatcherOperator::NotEquals | MatcherOperator::NotIn => (
                MatchState::NotEvaluated(NonEvaluationReason::IneligibleInput),
                Vec::new(),
            ),
            _ => (MatchState::NoMatch, Vec::new()),
        };
    }
    if predicate.operator == MatcherOperator::NotExists {
        return (MatchState::NoMatch, Vec::new());
    }
    if predicate.operator == MatcherOperator::Exists {
        return (
            MatchState::Match,
            vec![predicate.selector.as_str().to_owned()],
        );
    }
    let Some(actual) = resolved.value() else {
        return (
            MatchState::NotEvaluated(NonEvaluationReason::IneligibleInput),
            Vec::new(),
        );
    };
    let Some(expected) = predicate.value.as_ref() else {
        return (
            MatchState::NotEvaluated(NonEvaluationReason::TypeMismatch),
            Vec::new(),
        );
    };
    match apply_operator(predicate, actual, expected) {
        Ok(true) => (
            MatchState::Match,
            vec![predicate.selector.as_str().to_owned()],
        ),
        Ok(false) => (MatchState::NoMatch, Vec::new()),
        Err(reason) => (MatchState::NotEvaluated(reason), Vec::new()),
    }
}

fn apply_operator(
    predicate: &CompiledPredicate,
    actual: &JsonValue,
    expected: &JsonValue,
) -> Result<bool, NonEvaluationReason> {
    match predicate.operator {
        MatcherOperator::Equals => compatible_equals(actual, expected),
        MatcherOperator::NotEquals => compatible_equals(actual, expected).map(|value| !value),
        MatcherOperator::Contains => {
            string_pair(actual, expected).map(|(left, right)| left.contains(right))
        }
        MatcherOperator::StartsWith => {
            string_pair(actual, expected).map(|(left, right)| left.starts_with(right))
        }
        MatcherOperator::EndsWith => {
            string_pair(actual, expected).map(|(left, right)| left.ends_with(right))
        }
        MatcherOperator::Regex | MatcherOperator::Glob => {
            let JsonValue::String(value) = actual else {
                return Err(NonEvaluationReason::TypeMismatch);
            };
            Ok(predicate
                .pattern
                .as_ref()
                .is_some_and(|pattern| pattern.is_match(value)))
        }
        MatcherOperator::In | MatcherOperator::NotIn => {
            let result = membership(actual, expected)?;
            Ok(if predicate.operator == MatcherOperator::NotIn {
                !result
            } else {
                result
            })
        }
        MatcherOperator::Gt | MatcherOperator::Gte | MatcherOperator::Lt | MatcherOperator::Lte => {
            let ordering = numeric_order(actual, expected)?;
            Ok(match predicate.operator {
                MatcherOperator::Gt => ordering == Ordering::Greater,
                MatcherOperator::Gte => ordering != Ordering::Less,
                MatcherOperator::Lt => ordering == Ordering::Less,
                MatcherOperator::Lte => ordering != Ordering::Greater,
                _ => unreachable!(),
            })
        }
        MatcherOperator::Exists | MatcherOperator::NotExists => unreachable!(),
    }
}

fn compatible_equals(
    actual: &JsonValue,
    expected: &JsonValue,
) -> Result<bool, NonEvaluationReason> {
    match (actual, expected) {
        (JsonValue::String(left), JsonValue::String(right)) => Ok(left == right),
        (JsonValue::Bool(left), JsonValue::Bool(right)) => Ok(left == right),
        (left, right) if is_numeric(left) && is_numeric(right) => {
            Ok(numeric_order(left, right)? == Ordering::Equal)
        }
        (JsonValue::Null, JsonValue::Null) => Ok(true),
        (JsonValue::Array(left), JsonValue::Array(right)) => Ok(left == right),
        (JsonValue::Object(left), JsonValue::Object(right)) => Ok(left == right),
        _ => Err(NonEvaluationReason::TypeMismatch),
    }
}

fn is_numeric(value: &JsonValue) -> bool {
    match value {
        JsonValue::Integer(_) | JsonValue::Unsigned(_) => true,
        JsonValue::Number(value) => value.is_finite(),
        _ => false,
    }
}

fn string_pair<'a>(
    actual: &'a JsonValue,
    expected: &'a JsonValue,
) -> Result<(&'a str, &'a str), NonEvaluationReason> {
    match (actual, expected) {
        (JsonValue::String(actual), JsonValue::String(expected)) => Ok((actual, expected)),
        _ => Err(NonEvaluationReason::TypeMismatch),
    }
}

fn membership(actual: &JsonValue, expected: &JsonValue) -> Result<bool, NonEvaluationReason> {
    let expected_values = match expected {
        JsonValue::String(value) => vec![value.as_str()],
        JsonValue::Array(values) => values
            .iter()
            .map(|value| match value {
                JsonValue::String(value) => Ok(value.as_str()),
                _ => Err(NonEvaluationReason::TypeMismatch),
            })
            .collect::<Result<Vec<_>, _>>()?,
        _ => return Err(NonEvaluationReason::TypeMismatch),
    };
    match actual {
        JsonValue::String(value) => Ok(expected_values.iter().any(|candidate| *candidate == value)),
        _ => Err(NonEvaluationReason::TypeMismatch),
    }
}

fn numeric_order(
    actual: &JsonValue,
    expected: &JsonValue,
) -> Result<Ordering, NonEvaluationReason> {
    // Integer pairs use exact signed/unsigned ordering. An integer may be
    // compared with an f64 only when its conversion round-trips exactly; this
    // rejects the lossy region above 2^53 instead of silently changing value
    // identity. Non-finite floats are never comparable.
    match (actual, expected) {
        (JsonValue::Integer(left), JsonValue::Integer(right)) => Ok(left.cmp(right)),
        (JsonValue::Unsigned(left), JsonValue::Unsigned(right)) => Ok(left.cmp(right)),
        (JsonValue::Integer(left), JsonValue::Unsigned(right)) => {
            if *left < 0 {
                Ok(Ordering::Less)
            } else {
                Ok((*left as u64).cmp(right))
            }
        }
        (JsonValue::Unsigned(left), JsonValue::Integer(right)) => {
            if *right < 0 {
                Ok(Ordering::Greater)
            } else {
                Ok(left.cmp(&(*right as u64)))
            }
        }
        (JsonValue::Number(left), JsonValue::Number(right))
            if left.is_finite() && right.is_finite() =>
        {
            left.partial_cmp(right)
                .ok_or(NonEvaluationReason::TypeMismatch)
        }
        (JsonValue::Integer(left), JsonValue::Number(right)) => signed_float_order(*left, *right),
        (JsonValue::Unsigned(left), JsonValue::Number(right)) => {
            unsigned_float_order(*left, *right)
        }
        (JsonValue::Number(left), JsonValue::Integer(right)) => {
            signed_float_order(*right, *left).map(Ordering::reverse)
        }
        (JsonValue::Number(left), JsonValue::Unsigned(right)) => {
            unsigned_float_order(*right, *left).map(Ordering::reverse)
        }
        _ => Err(NonEvaluationReason::TypeMismatch),
    }
}

fn signed_float_order(integer: i64, float: f64) -> Result<Ordering, NonEvaluationReason> {
    if !float.is_finite() {
        return Err(NonEvaluationReason::TypeMismatch);
    }
    let integer_as_float = integer as f64;
    if integer_as_float as i128 != integer as i128 {
        return Err(NonEvaluationReason::TypeMismatch);
    }
    integer_as_float
        .partial_cmp(&float)
        .ok_or(NonEvaluationReason::TypeMismatch)
}

fn unsigned_float_order(integer: u64, float: f64) -> Result<Ordering, NonEvaluationReason> {
    if !float.is_finite() {
        return Err(NonEvaluationReason::TypeMismatch);
    }
    let integer_as_float = integer as f64;
    if integer_as_float as i128 != integer as i128 {
        return Err(NonEvaluationReason::TypeMismatch);
    }
    integer_as_float
        .partial_cmp(&float)
        .ok_or(NonEvaluationReason::TypeMismatch)
}

fn preflight_capabilities(
    capabilities: &BTreeSet<CapabilityId>,
    context: Option<&CapabilityContext>,
) -> Option<NonEvaluationReason> {
    let mut availability = Vec::new();
    for capability in capabilities {
        let status = context
            .map(|context| context.resolve(*capability))
            .unwrap_or(CapabilityAvailability::Unknown);
        availability.push(status);
    }
    if availability.contains(&CapabilityAvailability::Unsupported) {
        Some(NonEvaluationReason::RequiredCapabilityUnsupported)
    } else if availability.contains(&CapabilityAvailability::Unknown) {
        Some(NonEvaluationReason::RequiredCapabilityUnknown)
    } else {
        None
    }
}

pub(crate) fn preflight_required_capabilities(
    capabilities: &BTreeSet<CapabilityId>,
    context: Option<&CapabilityContext>,
) -> Option<NonEvaluationReason> {
    preflight_capabilities(capabilities, context)
}

fn preflight_capability(
    capability: CapabilityId,
    context: Option<&CapabilityContext>,
) -> Option<NonEvaluationReason> {
    let status = context
        .map(|context| context.resolve(capability))
        .unwrap_or(CapabilityAvailability::Unknown);
    match status {
        CapabilityAvailability::Supported => None,
        CapabilityAvailability::Unsupported => {
            Some(NonEvaluationReason::RequiredCapabilityUnsupported)
        }
        CapabilityAvailability::Unknown => Some(NonEvaluationReason::RequiredCapabilityUnknown),
    }
}

fn strongest_reason(reasons: &[NonEvaluationReason]) -> Option<NonEvaluationReason> {
    reasons.iter().copied().min()
}

fn normalize_paths(mut paths: Vec<String>) -> Vec<String> {
    paths.sort();
    paths.dedup();
    paths
}
