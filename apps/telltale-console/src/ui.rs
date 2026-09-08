use egui::{RichText, ScrollArea, Ui};
use telltale_core::Event3Record;
use telltale_schema::event::*;

use crate::state::{
    ConsoleState, FeedStatus, FindingFilter, NO_FILTERED_FINDINGS, NO_FINDINGS, WAITING,
    finding_metadata, severity_label,
};

pub const GUIDANCE_HEADING: &str = "Recommended response / Investigation guidance";

#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub enum Screen {
    #[default]
    Overview,
    Detections,
    SensorHealth,
}

#[derive(Default)]
pub struct ConsoleUi {
    pub screen: Screen,
    pub filter: FindingFilter,
}

impl ConsoleUi {
    pub fn render(&mut self, root: &mut Ui, state: &mut ConsoleState, location: &str) {
        egui::Panel::top("navigation").show(root, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.heading("Telltale Console");
                for (screen, label) in [
                    (Screen::Overview, "Overview"),
                    (Screen::Detections, "Detections"),
                    (Screen::SensorHealth, "Sensor Health"),
                ] {
                    ui.selectable_value(&mut self.screen, screen, label);
                }
            });
            ui.horizontal_wrapped(|ui| {
                ui.strong(state.status().label());
                ui.weak(format!(
                    "{} feed notices (this app session)",
                    state.notice_count()
                ));
            });
            ui.add(egui::Label::new(RichText::new(location).small().weak()).wrap());
            ui.weak(
                "Local, read-only, partial visibility — feed status is not a security verdict.",
            );
        });

        if state.selected().is_some() {
            let mut close = false;
            egui::Panel::right("detail")
                .resizable(true)
                .default_size(460.0)
                .min_size(220.0)
                .show(root, |ui| {
                    ui.horizontal(|ui| {
                        ui.heading("Event detail");
                        close = ui.button("Close").clicked();
                    });
                    ScrollArea::vertical()
                        .id_salt("detail_scroll")
                        .show(ui, |ui| {
                            if let Some(record) = state.selected() {
                                detail(ui, record);
                            }
                        });
                });
            if close {
                state.clear_selection();
            }
        }

        egui::CentralPanel::default().show(root, |ui| {
            match self.screen {
                Screen::Overview => {
                    ScrollArea::vertical().id_salt("overview").show(ui, |ui| overview(ui, state));
                }
                Screen::Detections => {
                    ui.heading("Security findings");
                    ui.weak("Recent / in-memory window. Journal order, newest first. Event-level risk only.");
                    self.filters(ui, state);
                    let records = state.findings(&self.filter);
                    if records.is_empty() {
                        let message = if state.summary().findings > 0 && self.filter.is_active() {
                            NO_FILTERED_FINDINGS
                        } else {
                            NO_FINDINGS
                        };
                        ui.label(message);
                        if self.filter.is_active() {
                            ui.weak("Clear filters to inspect the full retained window.");
                        }
                    }
                    let selected_id = state
                        .selected()
                        .map(|record| record.common().event_id.clone());
                    let selection =
                        finding_list(ui, &records, "detections", selected_id.as_deref());
                    if let Some(id) = selection { state.select(&id); }
                }
                Screen::SensorHealth => {
                    ScrollArea::vertical().id_salt("sensor_health").show(ui, |ui| sensor_health(ui, state));
                }
            }
        });
    }

    fn filters(&mut self, ui: &mut Ui, state: &ConsoleState) {
        ui.horizontal_wrapped(|ui| {
            egui::ComboBox::from_id_salt("severity")
                .selected_text(
                    self.filter
                        .severity
                        .map(severity_label)
                        .unwrap_or("All severities"),
                )
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.filter.severity, None, "All severities");
                    for severity in [
                        Event3Severity::Informational,
                        Event3Severity::Low,
                        Event3Severity::Medium,
                        Event3Severity::High,
                        Event3Severity::Critical,
                        Event3Severity::Warning,
                    ] {
                        ui.selectable_value(
                            &mut self.filter.severity,
                            Some(severity),
                            severity_label(severity),
                        );
                    }
                });
            egui::ComboBox::from_id_salt("client")
                .selected_text(self.filter.client.as_deref().unwrap_or("All clients"))
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.filter.client, None, "All clients");
                    for client in state.clients() {
                        ui.selectable_value(
                            &mut self.filter.client,
                            Some(client.to_owned()),
                            preview(client),
                        );
                    }
                });
            if ui.button("Clear filters").clicked() {
                self.filter = FindingFilter::default();
            }
        });
        ui.add(
            egui::TextEdit::singleline(&mut self.filter.query)
                .char_limit(256)
                .hint_text("Search rule / category / session metadata"),
        );
    }
}

fn overview(ui: &mut Ui, state: &mut ConsoleState) {
    ui.heading("Overview");
    if state.records().is_empty() {
        ui.label(match state.status() {
            FeedStatus::Waiting => WAITING,
            FeedStatus::CatchingUp => "Catching up; no Event3 records are retained yet.",
            FeedStatus::Live => "No Event3 records are retained.",
            FeedStatus::Degraded => "No Event3 records are retained; feed visibility is degraded.",
        });
    }
    let summary = state.summary();
    ui.label(format!(
        "Recent / in-memory findings: {}   Critical: {}   High: {}",
        summary.findings, summary.critical, summary.high
    ));
    field(
        ui,
        "Highest recent event risk",
        summary
            .highest_event_risk
            .map(|v| v.to_string())
            .as_deref()
            .unwrap_or("Unavailable"),
    );
    optional(
        ui,
        "Recent finding timestamp (last in journal order)",
        summary.latest_finding_time,
    );
    ui.label(format!(
        "Retained events: {} / {}   Accepted this app session: {}   Last poll: {} events",
        state.records().len(),
        crate::state::RETENTION,
        state.accepted_total,
        state.last_poll_records
    ));
    ui.weak(format!(
        "Journal bytes read this app session: {} (includes malformed frames and replay)",
        state.bytes_read
    ));
    if let Some(latest) = state.records().back() {
        field(
            ui,
            "Latest retained event",
            &format!("{} · {}", latest.event_type(), latest.common().timestamp),
        );
    }
    ui.separator();
    ui.heading("Latest scanner health");
    latest_health(ui, state);
    ui.separator();
    ui.heading("Latest security findings");
    let records: Vec<_> = state
        .records()
        .iter()
        .rev()
        .filter(|r| finding_metadata(r).is_some())
        .take(8)
        .collect();
    if records.is_empty() {
        ui.label(NO_FINDINGS);
    }
    let mut selected = None;
    for record in records {
        if finding_row(
            ui,
            record,
            state
                .selected()
                .is_some_and(|r| r.common().event_id == record.common().event_id),
        ) {
            selected = Some(record.common().event_id.clone());
        }
    }
    if let Some(id) = selected {
        state.select(&id);
    }
    ui.separator();
    notices(ui, state);
}

fn finding_list(
    ui: &mut Ui,
    records: &[&Event3Record],
    salt: &str,
    selected_id: Option<&str>,
) -> Option<String> {
    let mut selected = None;
    ScrollArea::vertical()
        .id_salt(salt)
        .show_rows(ui, 46.0, records.len(), |ui, rows| {
            for row in rows {
                let record = records[row];
                if finding_row(
                    ui,
                    record,
                    selected_id == Some(record.common().event_id.as_str()),
                ) {
                    selected = Some(record.common().event_id.clone());
                }
            }
        });
    selected
}

fn finding_row(ui: &mut Ui, record: &Event3Record, selected: bool) -> bool {
    let common = record.common();
    let (rules, categories) = finding_metadata(record).expect("finding rows only");
    let title = format!(
        "{} · Risk {} · {} · {} · {}",
        severity_label(common.severity),
        common.risk_score,
        record.event_type(),
        preview(&common.client),
        common.timestamp
    );
    let subtitle = format!(
        "Session {} · Rules {} · Categories {}",
        preview(&common.session_id),
        preview_list(rules),
        preview_list(categories)
    );
    ui.push_id(&common.event_id, |ui| {
        ui.add_sized(
            [ui.available_width(), 44.0],
            egui::Button::new(format!("{title}\n{subtitle}"))
                .selected(selected)
                .wrap_mode(egui::TextWrapMode::Truncate),
        )
        .clicked()
    })
    .inner
}

fn latest_health(ui: &mut Ui, state: &ConsoleState) {
    if let Some((record, health)) = state.latest_health() {
        field(
            ui,
            "Health timestamp (last in journal order)",
            &record.common().timestamp,
        );
        health_fields(ui, health);
        ui.weak("Last observed telemetry, not proof the scanner is currently running. Event3 has no host/sensor identity.");
    } else {
        ui.label(state.health_unavailable_message());
    }
}

fn health_fields(ui: &mut Ui, health: &Event3Health) {
    field(ui, "Component", &health.component);
    field(ui, "Check", &health.check_name);
    field(ui, "Recorded status", &health.status);
    field(
        ui,
        "Scan duration (ms)",
        &health.scan_duration_ms.to_string(),
    );
    field(ui, "Rules", &health.rule_count.to_string());
    let thresholds = health.threshold_config;
    field(
        ui,
        "Thresholds (low / medium / high / critical)",
        &format!(
            "{} / {} / {} / {}",
            thresholds.low, thresholds.medium, thresholds.high, thresholds.critical
        ),
    );
    optional(ui, "Active policy", health.active_policy_name.as_deref());
    field(
        ui,
        "Emitted / suppressed / scanner errors",
        &format!(
            "{} / {} / {}",
            health.emitted_count, health.suppressed_count, health.scanner_error_count
        ),
    );
    ui.strong("Source counts");
    for (source, count) in &health.source_counts {
        field(ui, source, &count.to_string());
    }
}

fn sensor_health(ui: &mut Ui, state: &mut ConsoleState) {
    ui.heading("Sensor Health");
    latest_health(ui, state);
    let mut selected = None;
    for (heading, event_type) in [
        ("Recent scanner errors", "scanner_error"),
        ("Recent operational alerts", "operational_alert"),
    ] {
        ui.separator();
        ui.heading(heading);
        ui.weak("Latest 20 in the retained local window, newest first.");
        let records: Vec<_> = state
            .records()
            .iter()
            .rev()
            .filter(|r| r.event_type() == event_type)
            .take(20)
            .collect();
        if records.is_empty() {
            ui.label("No retained events of this type.");
        }
        for record in records {
            let (component, check, status) = match record.family() {
                Event3Family::ScannerError(v) => (&v.component, &v.check_name, &v.status),
                Event3Family::OperationalAlert(v) => (&v.component, &v.check_name, &v.status),
                _ => unreachable!(),
            };
            if ui
                .button(format!(
                    "{} · {} · {} · {} · {}",
                    record.common().timestamp,
                    preview(&record.common().client),
                    preview(component),
                    preview(check),
                    preview(status)
                ))
                .clicked()
            {
                selected = Some(record.common().event_id.clone());
            }
        }
    }
    if let Some(id) = selected {
        state.select(&id);
    }
    ui.separator();
    notices(ui, state);
}

fn notices(ui: &mut Ui, state: &ConsoleState) {
    ui.group(|ui| {
        ui.heading("LocalEventFeed notices — not sensor telemetry");
        ui.weak("Aggregated for this app session. Integrity degradation remains visible until restart; restart does not repair missing history.");
        if state.notices().is_empty() { ui.label("No feed notices recorded. This does not establish scanner health."); }
        for (code, count) in state.notices() { field(ui, &code.to_string(), &count.to_string()); }
    });
}

pub fn detail(ui: &mut Ui, record: &Event3Record) {
    let common = record.common();
    field(ui, "Event ID", &common.event_id);
    field(ui, "Event3 family / type", record.event_type());
    field(ui, "Telltale version", &common.telltale_version);
    field(ui, "Severity", severity_label(common.severity));
    field(ui, "Event risk score", &common.risk_score.to_string());
    field(ui, "Client", &common.client);
    field(ui, "Session ID", &common.session_id);
    optional(ui, "Agent", common.agent.as_deref());
    optional(ui, "Model", common.model.as_deref());
    optional(ui, "Provider", common.provider.as_deref());
    field(ui, "timestamp", &common.timestamp);
    optional(ui, "event_time", common.event_time.as_deref());
    field(ui, "observed_at", &common.observed_at);
    field(ui, "ingested_at", &common.ingested_at);
    field(ui, "Time source", &format!("{:?}", common.time_source));
    field(
        ui,
        "Time confidence",
        &format!("{:?}", common.time_confidence),
    );
    optional(
        ui,
        "Time override reason",
        common.time_override_reason.as_deref(),
    );
    strings(ui, "Tags", &common.tags);
    ui.separator();
    match record.family() {
        Event3Family::Detection(v) => {
            taxonomy(
                ui,
                &v.rule_ids,
                &v.categories,
                &v.detection_classes,
                &v.signal_types,
                &v.analytic_intents,
            );
            strings(ui, "ATLAS tags", &v.atlas_tags);
            field(
                ui,
                "Source correlation hash (not a path)",
                &v.source_path_hash,
            );
            optional(ui, "Tool", v.tool_name.as_deref());
            if !v.timeline_anchors.is_empty() {
                ui.heading("Timeline anchor metadata");
                ui.weak("Normalized entry indexes, not immutable observation IDs. No session lookup is available.");
                for anchor in &v.timeline_anchors {
                    field(ui, "Entry index", &anchor.entry_index.to_string());
                    strings(ui, "Anchor rules", &anchor.rule_ids);
                    strings(ui, "Anchor categories", &anchor.categories);
                    strings(ui, "Evidence fields", &anchor.evidence_fields);
                }
            }
            if let Some(response) = &v.response {
                guidance(ui, response);
            }
        }
        Event3Family::ProcessChain(v) => {
            taxonomy(
                ui,
                &v.rule_ids,
                &v.categories,
                &v.detection_classes,
                &v.signal_types,
                &v.analytic_intents,
            );
            field(
                ui,
                "Source correlation hash (not a path)",
                &v.source_path_hash,
            );
            optional(ui, "Tool", v.tool_name.as_deref());
            field(ui, "Detection reason", &v.detection_reason);
            field(ui, "Confidence", &format!("{:?}", v.confidence));
            field(ui, "Informational chain", &v.informational.to_string());
            strings(ui, "MITRE ATT&CK", &v.mitre_attack_techniques);
            field(ui, "Risk entity type", &format!("{:?}", v.risk_entity_type));
            field(ui, "Risk entity value", &v.risk_entity_value);
            process_fields(ui, &v.process);
            guidance(ui, &v.response);
        }
        Event3Family::Correlation(v) => {
            taxonomy(
                ui,
                &v.rule_ids,
                &v.categories,
                &v.detection_classes,
                &v.signal_types,
                &v.analytic_intents,
            );
            field(ui, "Correlation event time", &v.event_time);
        }
        Event3Family::Health(v) => health_fields(ui, v),
        Event3Family::ScannerError(v) => {
            field(ui, "Component", &v.component);
            field(ui, "Check", &v.check_name);
            field(ui, "Recorded status", &v.status);
            field(
                ui,
                "Source correlation hash (not a path)",
                &v.source_path_hash,
            );
        }
        Event3Family::OperationalAlert(v) => {
            field(ui, "Component", &v.component);
            field(ui, "Check", &v.check_name);
            field(ui, "Recorded status", &v.status);
            taxonomy(
                ui,
                &[],
                &v.categories,
                &v.detection_classes,
                &v.signal_types,
                &v.analytic_intents,
            );
            optional(
                ui,
                "Scan duration (ms)",
                v.scan_duration_ms.map(|n| n.to_string()).as_deref(),
            );
            optional(
                ui,
                "Scanner errors",
                v.scanner_error_count.map(|n| n.to_string()).as_deref(),
            );
        }
        Event3Family::Activity(_) | Event3Family::SessionRiskSummary(_) => {
            ui.label("Context telemetry, not a security finding.");
        }
    }
    if !common.risk_contributions.is_empty() {
        ui.heading("Event risk contributions");
        for c in &common.risk_contributions {
            field(ui, "Contribution ID", c.id());
            field(
                ui,
                "Contribution type",
                &format!("{:?}", c.contribution_type()),
            );
            field(ui, "Points", &c.points().to_string());
            field(ui, "Rationale", c.rationale());
        }
    }
    if !common.evidence.is_empty() {
        ui.heading("Redacted / terminal evidence");
        ui.weak("As projected by Event3. Original values cannot be reconstructed here.");
        for evidence in &common.evidence {
            ui.separator();
            field(ui, "Field", &evidence.field);
            field(ui, "Redacted value", &evidence.redacted_value);
            optional(ui, "Hash", evidence.hash.as_deref());
            optional(ui, "Rule ID", evidence.rule_id.as_deref());
        }
    }
}

fn process_fields(ui: &mut Ui, p: &Event3ProcessContext) {
    ui.heading("Terminal process context");
    optional(ui, "Host", p.host.as_deref());
    optional(ui, "User", p.user.as_deref());
    field(ui, "Source process", &p.source_process_name);
    optional(ui, "Source process path", p.source_process_path.as_deref());
    optional(
        ui,
        "Source process ID",
        p.source_process_id.map(|n| n.to_string()).as_deref(),
    );
    optional(
        ui,
        "Source command line",
        p.source_process_command_line.as_deref(),
    );
    field(ui, "Target process", &p.target_process_name);
    optional(ui, "Target process path", p.target_process_path.as_deref());
    optional(
        ui,
        "Target process ID",
        p.target_process_id.map(|n| n.to_string()).as_deref(),
    );
    optional(
        ui,
        "Target command line",
        p.target_process_command_line.as_deref(),
    );
    optional(ui, "Parent process", p.parent_process_name.as_deref());
    optional(ui, "Parent process path", p.parent_process_path.as_deref());
    optional(ui, "Source event ID", p.source_event_id.as_deref());
    field(
        ui,
        "Source process inferred",
        &p.source_process_inferred.to_string(),
    );
    field(ui, "Rule name", &p.rule_name);
    strings(ui, "Secondary rules", &p.secondary_rule_ids);
    strings(ui, "Investigation fields", &p.investigation_fields);
    strings(ui, "False positives", &p.falsepositives);
    field(ui, "Dedup key", &p.dedup_key);
    field(
        ui,
        "Suppression window (seconds)",
        &p.suppression_window_seconds.to_string(),
    );
    field(ui, "Rule severity (not event severity)", &p.rule_severity);
    optional(ui, "Risk adjustment", p.risk_adjustment.as_deref());
}

fn taxonomy(
    ui: &mut Ui,
    rules: &[String],
    categories: &[String],
    classes: &[Event3DetectionClass],
    signals: &[Event3SignalType],
    intents: &[Event3AnalyticIntent],
) {
    strings(ui, "Rule IDs", rules);
    strings(ui, "Categories", categories);
    enums(ui, "Detection classes", classes);
    enums(ui, "Signal types", signals);
    enums(ui, "Analytic intents", intents);
}

fn guidance(ui: &mut Ui, response: &Event3Response) {
    ui.heading(GUIDANCE_HEADING);
    ui.weak("Guidance only. No action has been executed by this console.");
    field(ui, "Recommendation", &response.recommended_action);
    field(ui, "Playbook", &response.response_playbook);
    field(ui, "Investigation summary", &response.investigation_summary);
    field(ui, "Escalation guidance", &response.escalation);
}

fn field(ui: &mut Ui, label: &str, value: &str) {
    ui.strong(label);
    ui.add(egui::Label::new(value).wrap());
}
fn optional(ui: &mut Ui, label: &str, value: Option<&str>) {
    if let Some(value) = value {
        field(ui, label, value);
    }
}
fn strings(ui: &mut Ui, label: &str, values: &[String]) {
    if !values.is_empty() {
        ui.strong(label);
        for value in values {
            ui.add(egui::Label::new(value).wrap());
        }
    }
}
fn enums(ui: &mut Ui, label: &str, values: &[impl std::fmt::Debug]) {
    if !values.is_empty() {
        field(
            ui,
            label,
            &values
                .iter()
                .map(|v| format!("{v:?}"))
                .collect::<Vec<_>>()
                .join(", "),
        );
    }
}
fn preview(value: &str) -> String {
    let mut chars = value.chars();
    let mut result: String = chars.by_ref().take(72).collect();
    if chars.next().is_some() {
        result.push('…');
    }
    result
}
fn preview_list(values: &[String]) -> String {
    let mut result = values
        .iter()
        .take(2)
        .map(|v| preview(v))
        .collect::<Vec<_>>()
        .join(", ");
    if values.len() > 2 {
        result.push_str(" …");
    }
    result
}
