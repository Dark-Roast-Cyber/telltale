//! Native-derived activity contributions, not baseline state or retained source text.
use std::{collections::BTreeMap, fmt};

use serde_json::Value;
use telltale_schema::{
    activity_facts::{PathClass, classify_path_token, host_from_url_token},
    observation::LOCAL_MAX_STRING_BYTES,
};

use super::AcquisitionError;

/// Across all buckets and native units in one acquisition.
pub const MAX_CONTRIBUTION_KEYS: usize = 4096;

#[derive(Clone, Default, Eq, PartialEq)]
pub struct ActivityContributions {
    pub tool_calls: BTreeMap<String, u64>,
    pub path_classes: BTreeMap<PathClass, u64>,
    pub network_hosts: BTreeMap<String, u64>,
}

impl fmt::Debug for ActivityContributions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ActivityContributions")
            .field("tool_keys", &self.tool_calls.len())
            .field("path_keys", &self.path_classes.len())
            .field("host_keys", &self.network_hosts.len())
            .finish()
    }
}

impl ActivityContributions {
    fn text(&mut self, text: &str, keys: &mut usize) -> Result<(), AcquisitionError> {
        for token in text
            .split_whitespace()
            .map(|s| s.trim_matches(|c: char| c.is_ascii_control()))
        {
            // Bound potential retained facts before classifiers allocate normalized
            // candidates. Irrelevant long prose is neither retained nor rejected.
            if token.len() > LOCAL_MAX_STRING_BYTES {
                let candidate = token.contains('/')
                    || token.contains('.')
                    || token.starts_with("~/")
                    || token.starts_with("./")
                    || token.starts_with("../");
                if candidate {
                    return Err(AcquisitionError::InvalidContribution);
                }
                continue;
            }
            if let Some(class) = classify_path_token(token) {
                add(&mut self.path_classes, class, keys)?;
            }
            if let Some(host) = host_from_url_token(token) {
                validate_label(&host)?;
                add(&mut self.network_hosts, host, keys)?;
            }
        }
        Ok(())
    }

    fn argument_strings(
        &mut self,
        value: &Value,
        keys: &mut usize,
    ) -> Result<(), AcquisitionError> {
        match value {
            Value::String(text) => self.text(text, keys)?,
            Value::Array(values) => {
                for value in values {
                    self.argument_strings(value, keys)?;
                }
            }
            Value::Object(values) => {
                for value in values.values() {
                    self.argument_strings(value, keys)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Borrow existing native fields; never retain a per-unit map.
    pub(super) fn observe<'a>(
        &mut self,
        name: Option<&str>,
        arguments: Option<&str>,
        content: impl IntoIterator<Item = &'a str>,
        keys: &mut usize,
    ) -> Result<(), AcquisitionError> {
        let name = name.unwrap_or("unknown");
        validate_label(name)?;
        add(&mut self.tool_calls, name.trim().to_ascii_lowercase(), keys)?;
        if let Some(arguments) = arguments {
            match serde_json::from_str::<Value>(arguments) {
                Ok(value) => self.argument_strings(&value, keys)?,
                Err(_) => self.text(arguments, keys)?,
            }
        }
        for text in content {
            self.text(text, keys)?;
        }
        Ok(())
    }
}

fn validate_label(value: &str) -> Result<(), AcquisitionError> {
    if value.len() > LOCAL_MAX_STRING_BYTES || value.chars().any(char::is_control) {
        return Err(AcquisitionError::InvalidContribution);
    }
    Ok(())
}

fn add<K: Ord>(
    map: &mut BTreeMap<K, u64>,
    key: K,
    keys: &mut usize,
) -> Result<(), AcquisitionError> {
    match map.entry(key) {
        std::collections::btree_map::Entry::Occupied(mut entry) => {
            *entry.get_mut() = entry
                .get()
                .checked_add(1)
                .ok_or(AcquisitionError::AccountingOverflow)?;
        }
        std::collections::btree_map::Entry::Vacant(entry) => {
            if *keys >= MAX_CONTRIBUTION_KEYS {
                return Err(AcquisitionError::ContributionCapacity);
            }
            entry.insert(1);
            *keys += 1;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_preserve_multiplicity_and_capacity_fails_without_candidates() {
        let mut facts = ActivityContributions::default();
        let mut keys = 0;
        facts
            .text(
                "https://same.example/x https://same.example/y /tmp/a /tmp/b",
                &mut keys,
            )
            .unwrap();
        assert_eq!(facts.network_hosts["same.example"], 2);
        assert_eq!(facts.path_classes[&PathClass::Temp], 2);
        facts.network_hosts.insert("same.example".into(), u64::MAX);
        assert_eq!(
            facts.text("https://same.example/z", &mut keys),
            Err(AcquisitionError::AccountingOverflow)
        );
        let mut facts = ActivityContributions::default();
        let mut keys = 0;
        for index in 0..MAX_CONTRIBUTION_KEYS {
            facts
                .text(&format!("https://synthetic-{index}.example/"), &mut keys)
                .unwrap();
        }
        let error = facts
            .text("https://PRIVATE.example/", &mut keys)
            .unwrap_err();
        assert_eq!(error, AcquisitionError::ContributionCapacity);
        assert!(!format!("{error:?} {error} {facts:?}").contains("PRIVATE"));
    }
}
