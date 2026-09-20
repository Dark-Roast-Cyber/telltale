//! Canonical input bridge to the existing baseline model. No state or source I/O.

use super::*;
use telltale_schema::clients::ClientId;
use telltale_sources::acquisition::{AttestedValue, SessionAccounting};

pub(crate) fn summary(
    client: ClientId,
    session: &SessionAccounting,
) -> Result<Option<BaselineSummary>, RiskAccountingError> {
    let metadata = &session.metadata;
    if [&metadata.agent, &metadata.model, &metadata.provider].contains(&&AttestedValue::Ambiguous) {
        return Ok(None);
    }
    let counts = &session.counts.record_counts;
    let records = [
        counts.user_message,
        counts.assistant_message,
        counts.tool_call,
        counts.tool_result,
        counts.session_meta,
        counts.other,
    ]
    .into_iter()
    .try_fold(0_u64, |sum, count| {
        sum.checked_add(count).ok_or(RiskAccountingError::Overflow)
    })?;
    let contributions = &session.counts.contributions;
    let mut network_host_counts = BTreeMap::new();
    for (host, &count) in &contributions.network_hosts {
        add(
            &mut network_host_counts,
            baseline_host_identity(host),
            count,
        )?;
    }
    Ok(Some(BaselineSummary {
        key: BaselineKey {
            client: client.as_str().to_owned(),
            agent: metadata.agent.known().and_then(blank_to_none),
            model: metadata.model.known().and_then(blank_to_none),
            provider: metadata.provider.known().and_then(blank_to_none),
        },
        observations: BaselineObservationTotals {
            records,
            user_messages: counts.user_message,
            assistant_messages: counts.assistant_message,
            tool_calls: counts.tool_call,
            tool_results: counts.tool_result,
            session_meta: counts.session_meta,
            other: counts.other,
        },
        tool_call_counts: contributions.tool_calls.clone(),
        path_class_counts: contributions.path_classes.clone(),
        network_host_counts,
    }))
}

fn add<K: Ord>(
    counts: &mut BTreeMap<K, u64>,
    key: K,
    count: u64,
) -> Result<(), RiskAccountingError> {
    let value = counts.entry(key).or_default();
    *value = value
        .checked_add(count)
        .ok_or(RiskAccountingError::Overflow)?;
    Ok(())
}
