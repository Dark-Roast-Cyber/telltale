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
        let fingerprint = format!("sha256:{:x}", hasher.finalize());
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
mod tests {
    use std::path::PathBuf;

    use telltale_schema::clients::{ClientId, SourceKind};
    use telltale_schema::event::{
        ControlledMarker, DetectionEventInput, check_serialized_event_markers, detection_event,
    };
    use telltale_schema::scoring::{RiskContribution, RiskContributionType};
    use telltale_schema::source::Source;

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
            detection_classes: vec!["security_detection".to_string()],
            signal_types: vec!["atomic".to_string()],
            analytic_intents: vec!["alert".to_string()],
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
        event.timeline_anchors = vec![telltale_schema::event::TimelineAnchor {
            entry_index: 3,
            rule_ids: vec!["secret.env.read".to_string()],
            categories: vec!["secret_access".to_string()],
            evidence_fields: vec!["tool_result".to_string()],
        }];
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
        assert!(event.timeline_anchors.is_empty());
    }

    #[test]
    fn suppression_keeps_raw_matching_values_but_terminal_bytes_hide_its_name() {
        let marker = "TT_PRIVACY_ALLOWLIST_25";
        let mut event = event();
        event.tool_name = Some(marker.to_string());
        let allowlist = Allowlist {
            suppressions: vec![Suppression {
                name: Some(marker.to_string()),
                tool_names: vec![marker.to_string()],
                ..Suppression::default()
            }],
            ..Allowlist::default()
        };

        let suppression = allowlist
            .suppression_for(&source(), &event)
            .expect("raw tool name must still match the allowlist");
        suppress_detection(&mut event, &suppression);

        assert!(
            event
                .tags
                .iter()
                .any(|tag| tag == &format!("allowlist:{marker}"))
        );
        assert!(
            event
                .evidence
                .iter()
                .any(|evidence| evidence.field == "allowlist" && evidence.redacted_value == marker)
        );
        let bytes = serde_json::to_vec(&event.emittable()).expect("terminal event serialization");
        assert!(
            check_serialized_event_markers(
                &bytes,
                "allowlist-suppression",
                &[ControlledMarker {
                    id: "allowlist-marker",
                    value: marker,
                }],
            )
            .is_ok()
        );
    }

    #[test]
    fn allowlist_does_not_mutate_non_detection_events() {
        let mut event = event();
        event.event_type = "process_chain".to_string();
        let original = event.clone();
        suppress_detection(
            &mut event,
            &super::SuppressionMatch {
                name: "not-applicable".to_string(),
            },
        );
        assert_eq!(event.event_type, original.event_type);
        assert_eq!(event.risk_score, original.risk_score);
        assert_eq!(event.tags, original.tags);
        assert_eq!(event.response, original.response);
    }

    #[test]
    fn suppression_provenance_is_explicit_and_does_not_include_criteria() {
        let markers = [
            "TT_PRIVACY_SUPPRESSION_CLIENT_39",
            "TT_PRIVACY_SUPPRESSION_SESSION_39",
            "TT_PRIVACY_SUPPRESSION_TOOL_39",
            "TT_PRIVACY_SUPPRESSION_RULE_39",
            "TT_PRIVACY_SUPPRESSION_CATEGORY_39",
            "TT_PRIVACY_SUPPRESSION_PATH_39",
        ];
        let allowlist = Allowlist::from_yaml(&format!(
            "version: 1\nsuppressions:\n  - name: known-fixture\n    clients: [{client}]\n    session_ids: [{session}]\n    tool_names: [{tool}]\n    rule_ids: [{rule}]\n    categories: [{category}]\n    source_path_hashes: [{path}]\n",
            client = markers[0],
            session = markers[1],
            tool = markers[2],
            rule = markers[3],
            category = markers[4],
            path = markers[5],
        ))
        .expect("allowlist");
        let provenance = allowlist.suppression_provenance();
        assert_eq!(
            provenance.state,
            telltale_schema::provenance::ProducerSuppressionState::Configured
        );
        assert_eq!(
            provenance.canonicalization,
            telltale_schema::provenance::SUPPRESSION_V1_CANONICALIZATION
        );
        assert_eq!(provenance.count, 1);
        let serialized = serde_json::to_vec(&provenance).expect("provenance JSON");
        let serialized = String::from_utf8_lossy(&serialized);
        for marker in markers {
            assert!(!serialized.contains(marker));
        }
        assert_eq!(
            Allowlist::default().suppression_provenance(),
            telltale_schema::provenance::ProducerSuppressionProvenance::none()
        );
    }

    #[test]
    fn criterion_order_is_ignored_but_entry_order_is_preserved() {
        let first = Allowlist::from_yaml(
            "version: 1\nsuppressions:\n  - name: first\n    clients: [codex, claude, codex]\n  - name: second\n    categories: [b, a]\n",
        )
        .expect("allowlist")
        .suppression_provenance();
        let reordered_criteria = Allowlist::from_yaml(
            "version: 1\nsuppressions:\n  - name: first\n    clients: [codex, claude]\n  - name: second\n    categories: [a, b]\n",
        )
        .expect("allowlist")
        .suppression_provenance();
        assert_eq!(first.fingerprint, reordered_criteria.fingerprint);

        let changed_name = Allowlist::from_yaml(
            "version: 1\nsuppressions:\n  - name: renamed\n    clients: [claude, codex]\n  - name: second\n    categories: [a, b]\n",
        )
        .expect("allowlist")
        .suppression_provenance();
        assert_ne!(first.fingerprint, changed_name.fingerprint);

        let reordered_entries = Allowlist::from_yaml(
            "version: 1\nsuppressions:\n  - name: second\n    categories: [a, b]\n  - name: first\n    clients: [claude, codex]\n",
        )
        .expect("allowlist")
        .suppression_provenance();
        assert_ne!(first.fingerprint, reordered_entries.fingerprint);
    }

    #[test]
    fn suppression_names_are_absent_from_public_provenance() {
        let marker = "TT_PRIVACY_SUPPRESSION_NAME_39";
        let allowlist = Allowlist::from_yaml(&format!(
            "version: 1\nsuppressions:\n  - name: '{marker}'\n    clients: [codex]\n"
        ))
        .expect("allowlist");
        let provenance = allowlist.suppression_provenance();
        assert!(
            !serde_json::to_string(&provenance)
                .expect("JSON")
                .contains(marker)
        );
    }
}
