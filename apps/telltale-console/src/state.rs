use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use telltale_core::{Event3Record, FeedBatch, FeedNoticeCode};
use telltale_schema::event::{Event3Family, Event3Health, Event3Severity};

pub const RETENTION: usize = 2000;
pub const NO_FINDINGS: &str = "No security findings in the retained local window";
pub const NO_FILTERED_FINDINGS: &str = "No retained security findings match the current filters.";
pub const NO_HEALTH: &str = "No scanner health event has been observed yet.";
pub const WAITING: &str = "Waiting for Telltale events.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedStatus {
    Waiting,
    CatchingUp,
    Live,
    Degraded,
}

impl FeedStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Waiting => "Waiting",
            Self::CatchingUp => "Catching up",
            Self::Live => "Live",
            Self::Degraded => "Degraded",
        }
    }
}

#[derive(Default)]
pub struct FindingFilter {
    pub severity: Option<Event3Severity>,
    pub client: Option<String>,
    pub query: String,
}

impl FindingFilter {
    pub fn is_active(&self) -> bool {
        self.severity.is_some() || self.client.is_some() || !self.query.trim().is_empty()
    }

    pub fn matches(&self, record: &Event3Record) -> bool {
        let Some((rules, categories)) = finding_metadata(record) else {
            return false;
        };
        let common = record.common();
        if self
            .severity
            .is_some_and(|severity| severity != common.severity)
            || self
                .client
                .as_ref()
                .is_some_and(|client| client != &common.client)
        {
            return false;
        }
        let query = self.query.trim().to_lowercase();
        query.is_empty()
            || rules
                .iter()
                .chain(categories)
                .map(String::as_str)
                .chain(std::iter::once(common.session_id.as_str()))
                .any(|value| value.to_lowercase().contains(&query))
    }
}

pub fn finding_metadata(record: &Event3Record) -> Option<(&[String], &[String])> {
    match record.family() {
        Event3Family::Detection(value) => Some((&value.rule_ids, &value.categories)),
        Event3Family::ProcessChain(value) => Some((&value.rule_ids, &value.categories)),
        Event3Family::Correlation(value) => Some((&value.rule_ids, &value.categories)),
        _ => None,
    }
}

#[derive(Default, Debug, PartialEq, Eq)]
pub struct Summary<'a> {
    pub findings: usize,
    pub critical: usize,
    pub high: usize,
    pub highest_event_risk: Option<u64>,
    pub latest_finding_time: Option<&'a str>,
}

pub struct ConsoleState {
    capacity: usize,
    records: VecDeque<Event3Record>,
    ids: HashSet<String>,
    selected: Option<String>,
    notices: BTreeMap<FeedNoticeCode, u64>,
    caught_up: bool,
    polled: bool,
    unavailable: bool,
    degraded: bool,
    health_seen: bool,
    pub accepted_total: u64,
    pub last_poll_records: usize,
    pub bytes_read: u64,
}

impl Default for ConsoleState {
    fn default() -> Self {
        Self::with_capacity(RETENTION)
    }
}

impl ConsoleState {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity: capacity.clamp(1, RETENTION),
            records: VecDeque::new(),
            ids: HashSet::new(),
            selected: None,
            notices: BTreeMap::new(),
            caught_up: false,
            polled: false,
            unavailable: false,
            degraded: false,
            health_seen: false,
            accepted_total: 0,
            last_poll_records: 0,
            bytes_read: 0,
        }
    }

    pub fn ingest(&mut self, batch: FeedBatch) {
        self.polled = true;
        self.caught_up = batch.caught_up;
        self.unavailable = batch
            .notices
            .iter()
            .any(|n| n.code == FeedNoticeCode::JournalUnavailable);
        self.bytes_read = self.bytes_read.saturating_add(batch.bytes_read as u64);
        self.last_poll_records = 0;
        for notice in batch.notices {
            let count = self.notices.entry(notice.code).or_default();
            *count = count.saturating_add(notice.count);
            self.degraded |= is_integrity_notice(notice.code);
        }
        for record in batch.records {
            if self.ids.contains(&record.common().event_id) {
                continue;
            }
            if self.records.len() == self.capacity {
                let oldest = self.records.pop_front().expect("nonzero retention");
                self.ids.remove(&oldest.common().event_id);
                if self.selected.as_ref() == Some(&oldest.common().event_id) {
                    self.selected = None;
                }
            }
            self.ids.insert(record.common().event_id.clone());
            self.health_seen |= matches!(record.family(), Event3Family::Health(_));
            self.records.push_back(record);
            self.accepted_total = self.accepted_total.saturating_add(1);
            self.last_poll_records += 1;
        }
    }

    pub fn mark_feed_error(&mut self) {
        self.degraded = true;
    }

    pub fn status(&self) -> FeedStatus {
        if self.degraded || (self.unavailable && !self.records.is_empty()) {
            FeedStatus::Degraded
        } else if !self.polled || (self.records.is_empty() && (self.unavailable || self.caught_up))
        {
            FeedStatus::Waiting
        } else if !self.caught_up {
            FeedStatus::CatchingUp
        } else {
            FeedStatus::Live
        }
    }

    pub fn records(&self) -> &VecDeque<Event3Record> {
        &self.records
    }
    pub fn notices(&self) -> &BTreeMap<FeedNoticeCode, u64> {
        &self.notices
    }
    pub fn notice_count(&self) -> u64 {
        self.notices
            .values()
            .fold(0u64, |sum, n| sum.saturating_add(*n))
    }
    pub fn select(&mut self, id: &str) {
        self.selected = self.ids.contains(id).then(|| id.to_owned());
    }
    pub fn clear_selection(&mut self) {
        self.selected = None;
    }
    pub fn selected(&self) -> Option<&Event3Record> {
        let id = self.selected.as_ref()?;
        self.records.iter().find(|r| &r.common().event_id == id)
    }

    pub fn findings(&self, filter: &FindingFilter) -> Vec<&Event3Record> {
        self.records
            .iter()
            .rev()
            .filter(|r| filter.matches(r))
            .collect()
    }

    pub fn clients(&self) -> BTreeSet<&str> {
        self.records
            .iter()
            .filter(|r| finding_metadata(r).is_some())
            .map(|r| r.common().client.as_str())
            .collect()
    }

    pub fn summary(&self) -> Summary<'_> {
        let mut summary = Summary::default();
        for record in self
            .records
            .iter()
            .filter(|r| finding_metadata(r).is_some())
        {
            let common = record.common();
            summary.findings += 1;
            summary.critical += usize::from(common.severity == Event3Severity::Critical);
            summary.high += usize::from(common.severity == Event3Severity::High);
            summary.highest_event_risk = Some(
                summary
                    .highest_event_risk
                    .unwrap_or(0)
                    .max(common.risk_score),
            );
            summary.latest_finding_time = Some(&common.timestamp);
        }
        summary
    }

    pub fn latest_health(&self) -> Option<(&Event3Record, &Event3Health)> {
        self.records.iter().rev().find_map(|r| match r.family() {
            Event3Family::Health(health) => Some((r, health)),
            _ => None,
        })
    }

    pub fn health_unavailable_message(&self) -> &'static str {
        if self.health_seen {
            "No scanner health event remains in the retained local window."
        } else {
            NO_HEALTH
        }
    }
}

fn is_integrity_notice(code: FeedNoticeCode) -> bool {
    !matches!(
        code,
        FeedNoticeCode::JournalUnavailable
            | FeedNoticeCode::ActivePartialFrame
            | FeedNoticeCode::ReplaySuppressed
            | FeedNoticeCode::DedupEvicted
    )
}

pub fn severity_label(severity: Event3Severity) -> &'static str {
    match severity {
        Event3Severity::Informational => "Informational",
        Event3Severity::Low => "Low",
        Event3Severity::Medium => "Medium",
        Event3Severity::High => "High",
        Event3Severity::Critical => "Critical",
        Event3Severity::Warning => "Warning",
    }
}
