//! Projection of facade action findings into the versioned action record.
use telltale_schema::action_record::{
    ACTION_RECORD_V1_ID, ActionRecordContext, ActionRecordContribution, ActionRecordEvidence,
    ActionRecordFinding, ActionRecordV1,
};
use telltale_schema::event::{TELLTALE_VERSION, path_hash};

use crate::{ActionFinding, SourceScan};

impl SourceScan {
    /// This scan's action findings as [`ActionRecordV1`] values, in
    /// `action_findings` order: the serializable form for a host's own wire.
    /// Empty for a failed source and for compatibility scans.
    ///
    /// `session_event_id` names an event in this scan's `events`; deliver the
    /// records and those events together if the link matters to the receiver.
    pub fn action_records(&self) -> Vec<ActionRecordV1> {
        let Some(provenance) = &self.semantic_provenance else {
            return Vec::new();
        };
        let source_path_hash = path_hash(&self.source.path);
        self.action_findings
            .iter()
            .map(|action| self.record(action, provenance.identity(), &source_path_hash))
            .collect()
    }

    fn record(
        &self,
        action: &ActionFinding,
        semantic_identity: &str,
        source_path_hash: &str,
    ) -> ActionRecordV1 {
        ActionRecordV1 {
            schema: ACTION_RECORD_V1_ID.to_owned(),
            telltale_version: TELLTALE_VERSION.to_owned(),
            semantic_identity: semantic_identity.to_owned(),
            client: self.source.client.as_str().to_owned(),
            source_id: self.source.source_id.clone(),
            source_path_hash: source_path_hash.to_owned(),
            session_id: action.session_id().map(str::to_owned),
            session_event_id: action
                .session_event_index()
                .and_then(|index| self.events.get(index))
                .map(|event| event.event_id.clone()),
            coordinate: action.coordinate().as_str().to_owned(),
            replay_identity: action.replay_identity().map(|id| id.as_str().to_owned()),
            detector_kind: action.detector_kind().to_owned(),
            finding_kind: action.finding_kind().as_str().to_owned(),
            observation_family: action.kind(),
            stage: action.stage(),
            tool_name: action.tool_name().map(str::to_owned),
            occurred_at: action.occurred_at().map(str::to_owned),
            timeline_index: action.timeline_index() as u64,
            severity: action.severity().as_str().to_owned(),
            promotion_score: action.promotion_score(),
            rule_ids: action.rule_ids().to_vec(),
            categories: action.categories().to_vec(),
            contributions: action
                .contributions()
                .iter()
                .map(|contribution| ActionRecordContribution {
                    id: contribution.id().to_owned(),
                    contribution_type: contribution.contribution_type(),
                    points: contribution.points(),
                    rationale: contribution.rationale().to_owned(),
                })
                .collect(),
            evidence: action
                .evidence()
                .iter()
                .map(|evidence| ActionRecordEvidence {
                    field: evidence.field().to_owned(),
                    rule_id: evidence.rule_id().to_owned(),
                    redacted_value: evidence.redacted_value().to_owned(),
                })
                .collect(),
            supporting_observation_ids: action.supporting_observation_ids().to_vec(),
            canonical_findings: action
                .canonical_findings()
                .iter()
                .map(|finding| ActionRecordFinding {
                    finding_id: finding.finding_id().to_owned(),
                    signal_ids: finding.signal_ids().to_vec(),
                    observation_ids: finding.observation_ids().to_vec(),
                    detector_id: finding.detector_id().to_owned(),
                    finding_kind: finding.finding_kind().to_owned(),
                    category: finding.category().to_owned(),
                    severity: finding.severity().as_str().to_owned(),
                    risk_points: finding.risk_points(),
                })
                .collect(),
            context: action
                .context()
                .iter()
                .map(|entry| ActionRecordContext {
                    offset: entry.offset(),
                    kind: entry.kind().as_str().to_owned(),
                    stage: entry.stage(),
                    occurred_at: entry.occurred_at().map(str::to_owned),
                    tool_name: entry.tool_name().map(str::to_owned),
                    redacted_text: entry.redacted_text().to_owned(),
                })
                .collect(),
        }
    }
}

#[cfg(test)]
#[path = "action_record_tests.rs"]
mod tests;
