use std::fs;
use std::path::Path;

use serde::Deserialize;

use telltale_schema::event::{Event, Evidence};
use telltale_sources::discovery::Source;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Allowlist {
    #[serde(default)]
    pub version: Option<u32>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    suppressions: Vec<Suppression>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Suppression {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    clients: Vec<String>,
    #[serde(default)]
    session_ids: Vec<String>,
    #[serde(default)]
    tool_names: Vec<String>,
    #[serde(default)]
    rule_ids: Vec<String>,
    #[serde(default)]
    categories: Vec<String>,
    #[serde(default)]
    source_path_hashes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuppressionMatch {
    pub name: String,
}

pub fn load_allowlist(path: Option<&Path>) -> Result<Allowlist, Box<dyn std::error::Error>> {
    let Some(path) = path else {
        return Ok(Allowlist::default());
    };
    let raw = fs::read_to_string(path)?;
    Ok(serde_yaml::from_str::<Allowlist>(&raw)?)
}

impl Allowlist {
    pub fn suppression_for(&self, source: &Source, event: &Event) -> Option<SuppressionMatch> {
        self.suppressions
            .iter()
            .find(|suppression| suppression.matches(source, event))
            .map(|suppression| SuppressionMatch {
                name: suppression
                    .name
                    .clone()
                    .unwrap_or_else(|| "unnamed_suppression".to_string()),
            })
    }
}

impl Suppression {
    fn matches(&self, source: &Source, event: &Event) -> bool {
        let tool_names = optional_slice(event.tool_name.as_deref());
        let rule_ids = string_slice(&event.rule_ids);
        let categories = string_slice(&event.categories);
        let source_path_hashes = optional_slice(event.source_path_hash.as_deref());

        self.has_any_criteria()
            && matches_optional(
                &self.clients,
                &[source.client.as_str(), event.client.as_str()],
            )
            && matches_optional(&self.session_ids, &[event.session_id.as_str()])
            && matches_optional(&self.tool_names, &tool_names)
            && matches_optional(&self.rule_ids, &rule_ids)
            && matches_optional(&self.categories, &categories)
            && matches_optional(&self.source_path_hashes, &source_path_hashes)
    }

    fn has_any_criteria(&self) -> bool {
        !self.clients.is_empty()
            || !self.session_ids.is_empty()
            || !self.tool_names.is_empty()
            || !self.rule_ids.is_empty()
            || !self.categories.is_empty()
            || !self.source_path_hashes.is_empty()
    }
}

pub fn suppress_detection(event: &mut Event, suppression_match: &SuppressionMatch) {
    event.severity = "informational".to_string();
    event.risk_score = 0;
    event.risk_contributions.clear();
    push_tag(&mut event.tags, "suppressed");
    push_tag(
        &mut event.tags,
        &format!("allowlist:{}", suppression_match.name),
    );
    event.evidence.push(Evidence {
        field: "allowlist".to_string(),
        redacted_value: suppression_match.name.clone(),
        hash: None,
        rule_id: None,
    });
    event.triage = Some(serde_json::json!({
        "required": false,
        "verdict": "not_required"
    }));
    event.response = None;
}

fn push_tag(tags: &mut Vec<String>, tag: &str) {
    if !tags.iter().any(|existing| existing == tag) {
        tags.push(tag.to_string());
    }
}

fn matches_optional(allowed: &[String], values: &[&str]) -> bool {
    allowed.is_empty()
        || allowed
            .iter()
            .any(|allowed| values.iter().any(|value| allowed == value))
}

fn string_slice(values: &[String]) -> Vec<&str> {
    values.iter().map(String::as_str).collect()
}

fn optional_slice(value: Option<&str>) -> Vec<&str> {
    value.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use telltale_schema::event::{DetectionEventInput, detection_event};
    use telltale_schema::scoring::{RiskContribution, RiskContributionType};
    use telltale_sources::clients::{ClientId, SourceKind};
    use telltale_sources::discovery::Source;

    use super::{Allowlist, Suppression, suppress_detection};

    fn source() -> Source {
        Source {
            client: ClientId::Codex,
            kind: SourceKind::Jsonl,
            source_id: "fixture".to_string(),
            path: PathBuf::from("fixture.jsonl"),
        }
    }

    fn event() -> telltale_schema::event::Event {
        detection_event(DetectionEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "session-a".to_string(),
            source_path_hash: "hash".to_string(),
            tool_name: Some("shell".to_string()),
            rule_ids: vec!["secret.env.read".to_string()],
            categories: vec!["secret_access".to_string()],
            detection_classes: Vec::new(),
            signal_types: Vec::new(),
            analytic_intents: Vec::new(),
            atlas_tags: Vec::new(),
            tags: vec!["secret".to_string()],
            evidence: Vec::new(),
            risk_contributions: vec![
                RiskContribution::new(
                    "secret.env.read",
                    RiskContributionType::DeterministicRule,
                    90,
                    "matched synthetic secret path",
                )
                .expect("contribution"),
            ],
            event_time: Some("2026-05-01T00:00:00.000Z".to_string()),
        })
        .expect("build detection event")
    }

    #[test]
    fn suppression_requires_all_specified_criteria_to_match() {
        let allowlist = Allowlist {
            suppressions: vec![Suppression {
                name: Some("known-fixture".to_string()),
                clients: vec!["codex".to_string()],
                session_ids: vec!["session-a".to_string()],
                rule_ids: vec!["secret.env.read".to_string()],
                ..Suppression::default()
            }],
            ..Allowlist::default()
        };

        assert_eq!(
            allowlist
                .suppression_for(&source(), &event())
                .expect("suppressed")
                .name,
            "known-fixture"
        );
    }

    #[test]
    fn suppressed_detection_remains_a_detection_but_drops_risk() {
        let mut event = event();
        let suppression_match = super::SuppressionMatch {
            name: "known-fixture".to_string(),
        };

        suppress_detection(&mut event, &suppression_match);

        assert_eq!(event.event_type, "detection");
        assert_eq!(event.severity, "informational");
        assert_eq!(event.risk_score, 0);
        assert!(event.risk_contributions.is_empty());
        assert!(event.tags.iter().any(|tag| tag == "suppressed"));
        assert!(event.response.is_none());
        assert_eq!(
            event.triage.as_ref().expect("triage")["verdict"],
            "not_required"
        );
    }
}
