use std::collections::{BTreeMap, BTreeSet};

use telltale_detect::process_chain::{ProcessChainConfig, correlate_process_chain_events};
use telltale_rules::process_chain::{
    ChainRuleDefinition, ProcessChainPack, ProcessObservation, ProcessRef,
    StandaloneRuleDefinition, bundled_process_chain_yaml, load_default_process_chain_rules,
};
use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::event::{ProcessChainEventInput, ProcessContext, process_chain_event};
use telltale_schema::scoring::{RiskContribution, RiskContributionType};
use telltale_schema::source::Source;

#[derive(Debug, Clone)]
pub struct ProcessChainCoverage {
    pub enabled_chain_count: usize,
    pub enabled_standalone_count: usize,
    pub enabled_correlation_count: usize,
    pub covered_chain_and_standalone_ids: BTreeSet<String>,
    pub covered_correlation_ids: BTreeSet<String>,
    pub uncovered_ids: Vec<String>,
    pub rationales: BTreeMap<String, String>,
    pub evaluator_path: String,
    pub independent_scenario_tested_count: usize,
    pub independent_benign_scenario_count: usize,
    pub pipeline_integration: String,
}

#[derive(Clone)]
struct ProcessMeta {
    id: String,
    title: String,
    category: String,
    severity: String,
    score: u64,
    confidence: String,
    reason: String,
    mitre: Vec<String>,
    signal_type: String,
    detection_class: String,
    analytic_intent: String,
}

#[derive(Clone)]
struct GeneratedDefinition {
    observation: ProcessObservation,
    meta: ProcessMeta,
    matched_ids: BTreeSet<String>,
}

pub fn evaluate_process_chain_coverage() -> Result<ProcessChainCoverage, String> {
    let pack: ProcessChainPack = serde_yaml::from_str(bundled_process_chain_yaml())
        .map_err(|error| format!("process-chain pack parse: {error}"))?;
    let rules = load_default_process_chain_rules().map_err(|error| error.to_string())?;
    let mut generated = BTreeMap::<String, GeneratedDefinition>::new();
    let mut covered_chain_and_standalone_ids = BTreeSet::new();
    let mut enabled_chain_count = 0;
    let mut enabled_standalone_count = 0;
    for definition in &pack.rules {
        if !definition.enabled.unwrap_or(pack.defaults.enabled) {
            continue;
        }
        enabled_chain_count += 1;
        let observation = chain_observation(definition);
        let matched_ids = matched_ids(&rules.evaluate(&observation));
        if matched_ids.contains(&definition.id) {
            covered_chain_and_standalone_ids.insert(definition.id.clone());
        }
        generated.insert(
            definition.id.clone(),
            GeneratedDefinition {
                observation,
                meta: chain_meta(&pack, definition)?,
                matched_ids,
            },
        );
    }
    for definition in &pack.standalone {
        if !definition.enabled.unwrap_or(pack.defaults.enabled) {
            continue;
        }
        enabled_standalone_count += 1;
        let observation = standalone_observation(definition);
        let matched_ids = matched_ids(&rules.evaluate(&observation));
        if matched_ids.contains(&definition.id) {
            covered_chain_and_standalone_ids.insert(definition.id.clone());
        }
        generated.insert(
            definition.id.clone(),
            GeneratedDefinition {
                observation,
                meta: standalone_meta(&pack, definition)?,
                matched_ids,
            },
        );
    }
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".to_string(),
        path: "tests/evaluation/process-chain.synthetic".into(),
    };
    let mut covered_correlation_ids = BTreeSet::new();
    let config = ProcessChainConfig::default();
    for correlation in &pack.correlations {
        if !correlation.enabled.unwrap_or(pack.defaults.enabled) {
            continue;
        }
        let mut events = Vec::new();
        for (index, step) in correlation.sequence.iter().enumerate() {
            let generated = generated_for_step(step, &generated).ok_or_else(|| {
                format!(
                    "no generated process observation satisfies correlation {} step {}",
                    correlation.id,
                    index + 1
                )
            })?;
            if !generated.matched_ids.contains(&generated.meta.id) {
                return Err(format!(
                    "generated observation did not evaluate {} for correlation {}",
                    generated.meta.id, correlation.id
                ));
            }
            events.push(process_event(generated, index)?);
        }
        let correlation_events = correlate_process_chain_events(&source, &events, &rules, &config)
            .map_err(|error| format!("process-chain correlation {}: {error}", correlation.id))?;
        if correlation_events.iter().any(|event| {
            event
                .rule_ids
                .first()
                .is_some_and(|rule_id| rule_id == &correlation.id)
        }) {
            covered_correlation_ids.insert(correlation.id.clone());
        }
    }
    let enabled_chain_ids = pack
        .rules
        .iter()
        .filter(|definition| definition.enabled.unwrap_or(pack.defaults.enabled))
        .map(|definition| definition.id.clone());
    let enabled_standalone_ids = pack
        .standalone
        .iter()
        .filter(|definition| definition.enabled.unwrap_or(pack.defaults.enabled))
        .map(|definition| definition.id.clone());
    let enabled_correlation_ids = pack
        .correlations
        .iter()
        .filter(|definition| definition.enabled.unwrap_or(pack.defaults.enabled))
        .map(|definition| definition.id.clone());
    let all_enabled = enabled_chain_ids
        .chain(enabled_standalone_ids)
        .chain(enabled_correlation_ids)
        .collect::<BTreeSet<_>>();
    let covered = covered_chain_and_standalone_ids
        .iter()
        .chain(&covered_correlation_ids)
        .cloned()
        .collect::<BTreeSet<_>>();
    let uncovered_ids = all_enabled.difference(&covered).cloned().collect();
    Ok(ProcessChainCoverage {
        enabled_chain_count,
        enabled_standalone_count,
        enabled_correlation_count: pack
            .correlations
            .iter()
            .filter(|definition| definition.enabled.unwrap_or(pack.defaults.enabled))
            .count(),
        covered_chain_and_standalone_ids,
        covered_correlation_ids,
        uncovered_ids,
        rationales: BTreeMap::new(),
        evaluator_path: "CompiledProcessChainRules::evaluate + process_chain_event + correlate_process_chain_events"
            .to_string(),
        independent_scenario_tested_count: 0,
        independent_benign_scenario_count: 0,
        pipeline_integration:
            "not_invoked_by_Pipeline_scan_root_detect_records_or_evaluate_session".to_string(),
    })
}

fn chain_observation(definition: &ChainRuleDefinition) -> ProcessObservation {
    let command_line = if definition
        .id
        .starts_with("procchain.persistence.reg_run_key")
    {
        r"reg add currentversion\\run".to_string()
    } else {
        definition
            .child_command_line_any
            .first()
            .map(|pattern| format!("{} {}", definition.child, sample_from_pattern(pattern)))
            .unwrap_or_else(|| definition.child.clone())
    };
    let child = ProcessRef::named(&definition.child)
        .with_command_line(command_line)
        .with_path(
            definition
                .child_path_any
                .first()
                .map(|pattern| format!(r"C:\temp\{}", sample_from_pattern(pattern)))
                .unwrap_or_else(|| format!(r"C:\temp\{}.exe", definition.child)),
        );
    ProcessObservation {
        parent: ProcessRef::named(&definition.parent),
        child,
        host: Some("eval-host".to_string()),
        ..ProcessObservation::default()
    }
}

fn standalone_observation(definition: &StandaloneRuleDefinition) -> ProcessObservation {
    let mut child = ProcessRef::named("evaluation-process");
    match definition.r#match.as_str() {
        "process_name" => child.name = sample_from_pattern(&definition.patterns[0]),
        "process_path" => {
            child.path = Some(r"C:\temp\evaluation.exe".to_string());
        }
        "command_line" => {
            child.name = "powershell".to_string();
            child.command_line = Some(command_line_sample(&definition.patterns[0]));
        }
        _ => {}
    }
    ProcessObservation {
        parent: ProcessRef::named("evaluation-parent"),
        child,
        host: Some("eval-host".to_string()),
        ..ProcessObservation::default()
    }
}

fn sample_from_pattern(pattern: &str) -> String {
    let mut sample = pattern
        .replace(r"\b", "")
        .replace(r"\s+", " ")
        .replace(r"\s*", " ")
        .replace(r"\s", " ")
        .replace(r"\S+", "x")
        .replace(r"\S", "x")
        .replace(".*", " evaluation ")
        .replace(".+", "evaluation")
        .replace(['^', '$'], "");
    while let Some(start) = sample.find('(') {
        let Some(relative_end) = sample[start..].find(')') else {
            break;
        };
        let end = start + relative_end;
        let selected = sample[start + 1..end]
            .trim_start_matches("?:")
            .split('|')
            .next()
            .unwrap_or("evaluation")
            .to_string();
        sample.replace_range(start..=end, &selected);
    }
    while let Some(start) = sample.find('[') {
        let Some(relative_end) = sample[start..].find(']') else {
            break;
        };
        let end = start + relative_end;
        sample.replace_range(start..=end, "x");
    }
    while let Some(start) = sample.find('{') {
        let Some(relative_end) = sample[start..].find('}') else {
            break;
        };
        let end = start + relative_end;
        sample.replace_range(start..=end, "");
    }
    sample = sample
        .replace(r"\\", r"\")
        .replace(r"\.", ".")
        .replace(r"\", "")
        .replace(['?', '+'], "")
        .replace('|', "");
    let sample = sample.trim();
    if sample.is_empty() {
        "evaluation".to_string()
    } else {
        sample.to_string()
    }
}

fn command_line_sample(pattern: &str) -> String {
    if pattern.contains("[A-Za-z0-9+/=]{16,}") {
        return "powershell -enc QUJDREVGR0hJSktMTU5PUA==".to_string();
    }
    sample_from_pattern(pattern)
}

fn matched_ids(
    detections: &[telltale_rules::process_chain::ProcessChainDetection],
) -> BTreeSet<String> {
    detections
        .iter()
        .flat_map(|detection| {
            std::iter::once(detection.rule_id.clone())
                .chain(detection.secondary_rule_ids.iter().cloned())
        })
        .collect()
}

fn chain_meta(
    pack: &ProcessChainPack,
    definition: &ChainRuleDefinition,
) -> Result<ProcessMeta, String> {
    let category = pack
        .categories
        .get(&definition.category)
        .ok_or_else(|| format!("missing process-chain category {}", definition.category))?;
    Ok(ProcessMeta {
        id: definition.id.clone(),
        title: definition.title.clone(),
        category: definition.category.clone(),
        severity: definition.severity.clone(),
        score: definition.score,
        confidence: definition.confidence.clone(),
        reason: definition.reason.clone(),
        mitre: definition.mitre.clone(),
        signal_type: "chain".to_string(),
        detection_class: category.detection_class.clone(),
        analytic_intent: category.analytic_intent.clone(),
    })
}

fn standalone_meta(
    pack: &ProcessChainPack,
    definition: &StandaloneRuleDefinition,
) -> Result<ProcessMeta, String> {
    let category = pack
        .categories
        .get(&definition.category)
        .ok_or_else(|| format!("missing process-chain category {}", definition.category))?;
    Ok(ProcessMeta {
        id: definition.id.clone(),
        title: definition.title.clone(),
        category: definition.category.clone(),
        severity: definition.severity.clone(),
        score: definition.score,
        confidence: definition.confidence.clone(),
        reason: definition.reason.clone(),
        mitre: definition.mitre.clone(),
        signal_type: "atomic".to_string(),
        detection_class: category.detection_class.clone(),
        analytic_intent: category.analytic_intent.clone(),
    })
}

fn generated_for_step<'a>(
    step: &telltale_rules::process_chain::CorrelationStepDefinition,
    generated: &'a BTreeMap<String, GeneratedDefinition>,
) -> Option<&'a GeneratedDefinition> {
    if !step.any_rule_id.is_empty() {
        return step
            .any_rule_id
            .iter()
            .find_map(|rule_id| generated.get(rule_id));
    }
    generated.values().find(|generated| {
        (step.any_category.is_empty() || step.any_category.contains(&generated.meta.category))
            && (step.any_child.is_empty()
                || step
                    .any_child
                    .contains(&generated.observation.child.normalized_name()))
    })
}

fn process_event(
    generated: &GeneratedDefinition,
    index: usize,
) -> Result<telltale_schema::event::Event, String> {
    let meta = &generated.meta;
    let contribution = (meta.score > 0)
        .then(|| {
            RiskContribution::new(
                &meta.id,
                RiskContributionType::DeterministicRule,
                meta.score,
                "evaluation process-chain definition",
            )
        })
        .transpose()
        .map_err(|error| error.to_string())?
        .into_iter()
        .collect();
    process_chain_event(ProcessChainEventInput {
        client: ClientId::Codex,
        agent: Some("evaluation".to_string()),
        model: None,
        provider: None,
        session_id: format!("evaluation-process-chain-{index}"),
        source_path_hash: "evaluation-process-chain-source".to_string(),
        tool_name: Some("process_observation".to_string()),
        rule_ids: vec![meta.id.clone()],
        categories: vec![meta.category.clone()],
        detection_classes: vec![meta.detection_class.clone()],
        signal_types: vec![meta.signal_type.clone()],
        analytic_intents: vec![meta.analytic_intent.clone()],
        tags: vec!["evaluation".to_string(), "process_chain".to_string()],
        evidence: Vec::new(),
        risk_contributions: contribution,
        event_time: Some(format!("2026-06-01T00:00:{index:02}Z")),
        confidence: meta.confidence.clone(),
        detection_reason: meta.reason.clone(),
        mitre_attack_techniques: meta.mitre.clone(),
        risk_entity_type: "host".to_string(),
        risk_entity_value: Some("eval-host".to_string()),
        process: ProcessContext {
            host: Some("eval-host".to_string()),
            user: None,
            source_process_name: generated.observation.parent.normalized_name(),
            source_process_path: generated.observation.parent.path.clone(),
            source_process_id: None,
            source_process_command_line: generated.observation.parent.command_line.clone(),
            target_process_name: generated.observation.child.normalized_name(),
            target_process_path: generated.observation.child.path.clone(),
            target_process_id: None,
            target_process_command_line: generated.observation.child.command_line.clone(),
            parent_process_name: None,
            parent_process_path: None,
            source_event_id: None,
            source_process_inferred: false,
            rule_name: meta.title.clone(),
            secondary_rule_ids: Vec::new(),
            investigation_fields: Vec::new(),
            falsepositives: Vec::new(),
            dedup_key: format!("evaluation:{}", meta.id),
            suppression_window_seconds: 0,
            rule_severity: meta.severity.clone(),
            risk_adjustment: None,
        },
    })
    .map_err(|error| error.to_string())
}
