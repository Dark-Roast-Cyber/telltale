//! Synthetic Rule v2 documents for this crate's tests.

use sha2::{Digest, Sha256};

/// A lowercase UUIDv4 derived from `name`, so synthetic documents with
/// different names never share an `id`.
pub(crate) fn uuid(name: &str) -> String {
    let hex = hex::encode(&Sha256::digest(name.as_bytes())[..16]);
    format!(
        "{}-{}-4{}-8{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[13..16],
        &hex[17..20],
        &hex[20..32]
    )
}

/// The `logsource.category` that fits the fields `detection` reads.
fn logsource_category(detection: &str) -> &'static str {
    match (detection.contains("tool."), detection.contains("message.")) {
        (true, true) => "agent_activity",
        (false, true) => "message",
        _ => "tool_activity",
    }
}

fn indent(block: &str) -> String {
    block.lines().map(|line| format!("    {line}\n")).collect()
}

/// A Rule v2 rule document named `name` in `category`, level `high`, score 60
/// and explanation `Synthetic explanation.`. `detection` is the body of the
/// `detection` block and `telltale` extra lines of the `telltale` block, both
/// unindented; replace a line of the result to change anything else.
pub(crate) fn rule(name: &str, category: &str, detection: &str, telltale: &str) -> String {
    format!(
        "title: Synthetic rule {name}\nid: {}\nname: {name}\ntaxonomy: telltale\n\
         logsource:\n    product: ai_agent\n    category: {}\n\
         detection:\n{}level: high\n\
         telltale:\n    category: {category}\n    score: 60\n    explanation: Synthetic explanation.\n{}",
        uuid(name),
        logsource_category(detection),
        indent(detection),
        indent(telltale),
    )
}

/// A Rule v2 chain document named `name` with score 7. `correlation` is the
/// body of the `correlation` block after its `type`, and `telltale` extra lines
/// of the `telltale` block, both unindented.
pub(crate) fn chain(name: &str, correlation: &str, telltale: &str) -> String {
    format!(
        "title: Synthetic chain {name}\nid: {}\nname: {name}\ntaxonomy: telltale\n\
         correlation:\n    type: telltale_chain\n{}\
         telltale:\n    score: 7\n    explanation: Synthetic chain explanation.\n{}",
        uuid(name),
        indent(correlation),
        indent(telltale),
    )
}

/// Documents joined into one rule file.
pub(crate) fn file(documents: &[String]) -> String {
    documents.join("---\n")
}
