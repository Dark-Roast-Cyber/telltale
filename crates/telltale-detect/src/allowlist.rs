//! Allowlist suppression: loads suppression entries, matches them against
//! projected detections, marks suppressed events, and fingerprints the
//! effective suppressions for producer provenance. Allowlists run once, after
//! detection and Event3 projection.

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use telltale_schema::event::{Event, Evidence};
use telltale_schema::provenance::{
    ProducerSuppressionProvenance, ProducerSuppressionState, SUPPRESSION_V1_CANONICALIZATION,
};
use telltale_schema::source::Source;

const SUPPRESSION_FINGERPRINT_DOMAIN: &[u8] = b"telltale:producer-suppression-v1-fingerprint:v1\0";

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Allowlist {
    #[serde(default)]
    pub version: Option<u32>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    suppressions: Vec<Suppression>,
    #[serde(skip)]
    configured: bool,
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
    Allowlist::from_yaml(&raw)
}

impl Allowlist {
    pub fn from_yaml(raw: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mut allowlist = serde_yaml::from_str::<Allowlist>(raw)?;
        allowlist.configured = true;
        Ok(allowlist)
    }

    pub fn suppression_provenance(&self) -> ProducerSuppressionProvenance {
        if !self.configured {
            return ProducerSuppressionProvenance::none();
        }

        let entries = self
            .suppressions
            .iter()
            .map(CanonicalSuppression::from)
            .collect::<Vec<_>>();
        let canonical = serde_json::to_vec(&CanonicalSuppressions { entries })
            .expect("suppression provenance payload is serializable");
        let mut hasher = Sha256::new();
        hasher.update(SUPPRESSION_FINGERPRINT_DOMAIN);
        hasher.update(canonical);
        let fingerprint = format!("sha256:{}", hex::encode(hasher.finalize()));
        ProducerSuppressionProvenance {
            canonicalization: SUPPRESSION_V1_CANONICALIZATION.to_string(),
            state: ProducerSuppressionState::Configured,
            fingerprint: Some(fingerprint),
            count: self.suppressions.len() as u64,
        }
    }

    pub fn suppression_for(&self, source: &Source, event: &Event) -> Option<SuppressionMatch> {
        if event.event_type != "detection" {
            return None;
        }
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

#[derive(Serialize)]
struct CanonicalSuppressions {
    entries: Vec<CanonicalSuppression>,
}

#[derive(Serialize)]
struct CanonicalSuppression {
    name: String,
    clients: Vec<String>,
    session_ids: Vec<String>,
    tool_names: Vec<String>,
    rule_ids: Vec<String>,
    categories: Vec<String>,
    source_path_hashes: Vec<String>,
}

impl From<&Suppression> for CanonicalSuppression {
    fn from(suppression: &Suppression) -> Self {
        Self {
            name: canonical_suppression_name(suppression),
            clients: sorted_unique(&suppression.clients),
            session_ids: sorted_unique(&suppression.session_ids),
            tool_names: sorted_unique(&suppression.tool_names),
            rule_ids: sorted_unique(&suppression.rule_ids),
            categories: sorted_unique(&suppression.categories),
            source_path_hashes: sorted_unique(&suppression.source_path_hashes),
        }
    }
}

fn canonical_suppression_name(suppression: &Suppression) -> String {
    let name = suppression.name.as_deref().unwrap_or("unnamed_suppression");
    telltale_schema::event::opaque_identifier("suppression", name)
}

fn sorted_unique(values: &[String]) -> Vec<String> {
    let mut values = values.to_vec();
    values.sort_unstable();
    values.dedup();
    values
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
    if event.event_type != "detection" {
        return;
    }
    event.severity = "informational".to_string();
    event.risk_score = 0;
    event.risk_contributions.clear();
    event.timeline_anchors.clear();
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
mod tests;
