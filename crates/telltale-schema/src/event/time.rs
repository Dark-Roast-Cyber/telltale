use ::time::OffsetDateTime;

pub(crate) struct ResolvedEventTime {
    pub(crate) timestamp: String,
    pub(crate) event_time: Option<String>,
    pub(crate) time_source: String,
    pub(crate) time_confidence: String,
    pub(crate) time_override_reason: Option<String>,
}

pub(crate) fn resolve_event_time(
    source_event_time: Option<&str>,
    observed_at: OffsetDateTime,
) -> ResolvedEventTime {
    let observed_timestamp = format_timestamp(observed_at);
    let Some(raw_event_time) = source_event_time else {
        return ResolvedEventTime {
            timestamp: observed_timestamp.clone(),
            event_time: None,
            time_source: "observed".to_string(),
            time_confidence: "low".to_string(),
            time_override_reason: Some("missing_source_timestamp".to_string()),
        };
    };

    let Some(parsed_event_time) = parse_event_timestamp(raw_event_time) else {
        return ResolvedEventTime {
            timestamp: observed_timestamp.clone(),
            event_time: Some(raw_event_time.to_string()),
            time_source: "override".to_string(),
            time_confidence: "low".to_string(),
            time_override_reason: Some("unparseable_source_timestamp".to_string()),
        };
    };

    let normalized_event_time = format_timestamp(parsed_event_time);
    let future_skew_limit = ::time::Duration::minutes(5);
    if parsed_event_time > observed_at + future_skew_limit {
        return ResolvedEventTime {
            timestamp: observed_timestamp,
            event_time: Some(normalized_event_time),
            time_source: "override".to_string(),
            time_confidence: "low".to_string(),
            time_override_reason: Some("source_timestamp_future_skew".to_string()),
        };
    }

    ResolvedEventTime {
        timestamp: normalized_event_time.clone(),
        event_time: Some(normalized_event_time),
        time_source: "source".to_string(),
        time_confidence: "high".to_string(),
        time_override_reason: None,
    }
}

pub fn parse_event_timestamp(value: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(value, &::time::format_description::well_known::Rfc3339).ok()
}

pub fn format_timestamp(timestamp: OffsetDateTime) -> String {
    let timestamp = timestamp
        .to_offset(::time::UtcOffset::UTC)
        .replace_microsecond(0)
        .expect("valid microsecond replacement")
        .replace_nanosecond(0)
        .expect("valid nanosecond replacement");
    timestamp
        .format(&::time::macros::format_description!(
            "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z"
        ))
        .expect("fixed RFC3339 millisecond timestamp")
}

pub(crate) fn response_metadata(
    severity: &str,
    rule_ids: &[String],
    categories: &[String],
    high_required: bool,
) -> super::ResponseMetadata {
    super::ResponseMetadata {
        recommended_action: recommended_action(severity).to_string(),
        response_playbook: response_playbook(rule_ids, categories).to_string(),
        investigation_summary: investigation_summary(severity, rule_ids, categories),
        escalation: if high_required {
            "security_review_required".to_string()
        } else {
            "routine_review".to_string()
        },
    }
}

fn recommended_action(severity: &str) -> &'static str {
    match severity {
        "critical" => "investigate_immediately",
        "high" => "investigate",
        "medium" => "review",
        _ => "monitor",
    }
}

fn response_playbook(rule_ids: &[String], categories: &[String]) -> &'static str {
    let has_rule = |needle: &str| rule_ids.iter().any(|rule_id| rule_id.contains(needle));
    let has_category = |needle: &str| categories.iter().any(|category| category.contains(needle));

    if has_rule("mcp") || has_category("mcp") {
        "telltale-playbook-mcp-prompt-injection"
    } else if has_rule("credential") || has_rule("secret") || has_category("credential") {
        "telltale-playbook-credential-access"
    } else if has_rule("exfil") || has_category("network") || has_category("exfil") {
        "telltale-playbook-network-egress"
    } else if has_rule("persistence") || has_category("persistence") {
        "telltale-playbook-persistence"
    } else {
        "telltale-playbook-general-investigation"
    }
}

fn investigation_summary(severity: &str, rule_ids: &[String], categories: &[String]) -> String {
    let rule_summary = if rule_ids.is_empty() {
        "no rule id".to_string()
    } else {
        rule_ids.join(",")
    };
    let category_summary = if categories.is_empty() {
        "uncategorized".to_string()
    } else {
        categories.join(",")
    };
    format!(
        "{severity} Telltale detection matched {rule_summary} in {category_summary}; review redacted evidence, timeline anchors when present, and the local source session before containment."
    )
}

#[cfg(test)]
mod tests {
    use super::{format_timestamp, parse_event_timestamp};

    #[test]
    fn format_timestamp_normalizes_non_utc_offsets() {
        let timestamp =
            parse_event_timestamp("2026-05-01T12:00:00+02:00").expect("parse timestamp");

        assert_eq!(format_timestamp(timestamp), "2026-05-01T10:00:00.000Z");
    }
}
