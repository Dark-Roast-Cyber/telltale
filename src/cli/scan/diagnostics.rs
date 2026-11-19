//! The scan diagnostics record: how long each phase of one `scan` took and
//! what the process used, written when an operator enables a diagnostics
//! category. The shared clock, resource readers and writer live in
//! `crate::diagnostics`; this module only names the scan's phases and fields.
//!
//! A recorder built with no enabled category does nothing: no clock reads, no
//! counter reads, no file. `watch` scans use such a recorder.
//!
//! Phases are contiguous from the scan's start, so they add up to `total_us`,
//! and the phases up to and including `detection_assembly` end exactly where
//! `scan_duration_ms` is measured. That field keeps its meaning: it excludes
//! event selection, state save and delivery.

use std::path::Path;
use std::time::{Duration, Instant};

use serde::Serialize;

use super::{ScanConfig, ScanExecutionConfig};
use crate::diagnostics::phases::{Phase, PhaseClock};
use crate::diagnostics::resources::{self, CpuTime, PeakMemoryMeasure};
use crate::diagnostics::{self, Categories, WriteFailure, micros};

pub(crate) const SCHEMA: &str = "telltale.scan_diagnostics";
pub(crate) const VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ScanPhase {
    /// From the command's start to the scan's start. Only a failure stage
    /// inside the clock: its time is measured separately.
    Startup,
    Discovery,
    Preparation,
    SourceProcessing,
    DetectionAssembly,
    EventSelection,
    StateSave,
    CanonicalWrite,
    DurableAdmission,
    RemoteDelivery,
    Report,
}

impl Phase for ScanPhase {
    const ALL: &'static [Self] = &[
        Self::Startup,
        Self::Discovery,
        Self::Preparation,
        Self::SourceProcessing,
        Self::DetectionAssembly,
        Self::EventSelection,
        Self::StateSave,
        Self::CanonicalWrite,
        Self::DurableAdmission,
        Self::RemoteDelivery,
        Self::Report,
    ];
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ScanCommand {
    ScanOnce,
    ScanInterval,
}

/// What the operator enabled, and where records go.
#[derive(Clone, Copy)]
pub(crate) struct ScanDiagnosticsOptions<'a> {
    pub(crate) categories: Categories,
    pub(crate) path: &'a Path,
    pub(crate) command: ScanCommand,
    pub(crate) command_started: Instant,
}

/// Counts the scan summary already reports, with the same meaning.
#[derive(Clone, Copy, Debug, Serialize)]
pub(super) struct ScanCounts {
    pub(super) selected_source_count: u64,
    pub(super) parsed_record_count: u64,
    pub(super) evaluated_window_count: u64,
    pub(super) emitted_count: u64,
}

pub(crate) struct ScanRecorder<'a> {
    options: Option<ScanDiagnosticsOptions<'a>>,
    first_scan: bool,
    startup: Option<Duration>,
    clock: Option<PhaseClock<ScanPhase>>,
    cpu_at_start: Option<CpuTime>,
    failure_stage: Option<ScanPhase>,
    scan_duration_ms: Option<u64>,
    counts: Option<ScanCounts>,
}

impl<'a> ScanRecorder<'a> {
    pub(crate) fn disabled() -> Self {
        Self::new(None, false)
    }

    /// A recorder for one scan; `first_scan` is the command's first, the only
    /// one with a startup time.
    pub(crate) fn new(options: Option<ScanDiagnosticsOptions<'a>>, first_scan: bool) -> Self {
        Self {
            options: options.filter(|options| options.categories.any()),
            first_scan,
            startup: None,
            clock: None,
            cpu_at_start: None,
            failure_stage: None,
            scan_duration_ms: None,
            counts: None,
        }
    }

    /// The scan starts at `at`, the instant `scan_duration_ms` counts from.
    pub(super) fn start(&mut self, at: Instant) {
        let Some(options) = self.options else {
            return;
        };
        if self.first_scan {
            self.startup = Some(at.saturating_duration_since(options.command_started));
        }
        if options.categories.process_resources {
            self.cpu_at_start = resources::process_cpu_time();
        }
        self.clock = Some(PhaseClock::start_at(ScanPhase::Discovery, at));
    }

    pub(super) fn enter(&mut self, phase: ScanPhase) {
        if let Some(clock) = &mut self.clock {
            clock.enter(phase);
        }
    }

    pub(super) fn enter_at(&mut self, phase: ScanPhase, at: Instant) {
        if let Some(clock) = &mut self.clock {
            clock.enter_at(phase, at);
        }
    }

    /// Names the stage a failure belongs to when the error surfaces later.
    pub(super) fn fail_in(&mut self, phase: ScanPhase) {
        self.failure_stage = Some(phase);
    }

    pub(super) fn observe_scan_duration(&mut self, scan_duration_ms: u64) {
        if self.options.is_some() {
            self.scan_duration_ms = Some(scan_duration_ms);
        }
    }

    pub(super) fn observe_counts(&mut self, counts: ScanCounts) {
        if self.options.is_some() {
            self.counts = Some(counts);
        }
    }

    /// Writes this scan's record, if any category is enabled. A failure to
    /// write prints one fixed warning and changes nothing else.
    pub(super) fn finish(mut self, config: &ScanConfig<'_>, completed: bool) {
        let Some(options) = self.options else {
            return;
        };
        let finished = Instant::now();
        if let Some(clock) = &mut self.clock {
            clock.close_at(finished);
        }
        let record = self.record(options, config, completed, finished);
        if let Err(failure) = write(options.path, config.execution, &record) {
            diagnostics::warn_not_written(failure);
        }
    }

    fn record(
        &self,
        options: ScanDiagnosticsOptions<'_>,
        config: &ScanConfig<'_>,
        completed: bool,
        finished: Instant,
    ) -> Record {
        let failure_stage = (!completed).then(|| {
            self.failure_stage
                .or(self.clock.as_ref().map(PhaseClock::current))
                .unwrap_or(ScanPhase::Startup)
        });
        Record {
            schema: SCHEMA,
            version: VERSION,
            recorded_at: diagnostics::recorded_at(),
            telltale_version: env!("CARGO_PKG_VERSION"),
            command: options.command,
            dry_run: config.execution.dry_run,
            history: config.history,
            backfill: config.backfill,
            delivery_posture: config.execution.sinks.delivery_posture().as_str(),
            outcome: if completed {
                Outcome::Completed
            } else {
                Outcome::Failed
            },
            failure_stage,
            scan_duration_ms: self.scan_duration_ms,
            counts: self.counts,
            scan_phases: options.categories.scan_phases.then(|| self.phase_times()),
            process_resources: options
                .categories
                .process_resources
                .then(|| self.process_resources(options, finished)),
        }
    }

    fn phase_times(&self) -> PhaseTimes {
        let spent = |phase| {
            self.clock
                .as_ref()
                .and_then(|clock| clock.spent(phase))
                .map(micros)
        };
        PhaseTimes {
            startup_us: self.startup.map(micros),
            discovery_us: spent(ScanPhase::Discovery),
            preparation_us: spent(ScanPhase::Preparation),
            source_processing_us: spent(ScanPhase::SourceProcessing),
            detection_assembly_us: spent(ScanPhase::DetectionAssembly),
            event_selection_us: spent(ScanPhase::EventSelection),
            state_save_us: spent(ScanPhase::StateSave),
            canonical_write_us: spent(ScanPhase::CanonicalWrite),
            durable_admission_us: spent(ScanPhase::DurableAdmission),
            remote_delivery_us: spent(ScanPhase::RemoteDelivery),
            report_us: spent(ScanPhase::Report),
            total_us: self.clock.as_ref().map(|clock| micros(clock.total())),
        }
    }

    fn process_resources(
        &self,
        options: ScanDiagnosticsOptions<'_>,
        finished: Instant,
    ) -> ProcessResources {
        let cpu = resources::process_cpu_time();
        let peak = resources::process_peak_memory();
        let scan_cpu = cpu
            .zip(self.cpu_at_start)
            .and_then(|(now, start)| now.since(start));
        ProcessResources {
            process: ProcessUse {
                wall_us: micros(finished.saturating_duration_since(options.command_started)),
                user_cpu_us: cpu.map(|cpu| cpu.user_us),
                kernel_cpu_us: cpu.map(|cpu| cpu.kernel_us),
                peak_memory_bytes: peak.map(|peak| peak.bytes),
                peak_memory_measure: peak.map(|peak| peak.measure),
            },
            scan: ScanUse {
                wall_us: self.clock.as_ref().map(|clock| micros(clock.total())),
                user_cpu_us: scan_cpu.map(|cpu| cpu.user_us),
                kernel_cpu_us: scan_cpu.map(|cpu| cpu.kernel_us),
            },
        }
    }
}

/// Refuses a path that would land on the scanner's own files or in a log
/// directory, then appends the record.
fn write(
    path: &Path,
    execution: ScanExecutionConfig<'_>,
    record: &Record,
) -> Result<(), WriteFailure> {
    let logs = execution.sinks.local_persistence_paths();
    let namespaces = execution.sinks.local_rotation_namespaces();
    let outbox: Vec<&Path> = execution.sinks.durable_outbox_path().into_iter().collect();
    for candidate in [path.to_path_buf(), diagnostics::rotated_path(path)] {
        match crate::file_lock::conflicts_with_runtime_paths(
            &candidate,
            execution.state_path,
            &logs,
            &outbox,
            &namespaces,
        ) {
            Ok(false) => {}
            Ok(true) => return Err(WriteFailure::Overlap),
            Err(_) => return Err(WriteFailure::UnsafeTarget),
        }
    }
    diagnostics::append_record(path, record)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Outcome {
    Completed,
    Failed,
}

/// One line of the diagnostics file. Fields of a category that is off are
/// absent; a value the scan or the OS could not provide is null.
#[derive(Serialize)]
struct Record {
    schema: &'static str,
    version: u32,
    recorded_at: String,
    telltale_version: &'static str,
    command: ScanCommand,
    dry_run: bool,
    history: bool,
    backfill: bool,
    delivery_posture: &'static str,
    outcome: Outcome,
    failure_stage: Option<ScanPhase>,
    scan_duration_ms: Option<u64>,
    counts: Option<ScanCounts>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scan_phases: Option<PhaseTimes>,
    #[serde(skip_serializing_if = "Option::is_none")]
    process_resources: Option<ProcessResources>,
}

#[derive(Serialize)]
struct PhaseTimes {
    startup_us: Option<u64>,
    discovery_us: Option<u64>,
    preparation_us: Option<u64>,
    source_processing_us: Option<u64>,
    detection_assembly_us: Option<u64>,
    event_selection_us: Option<u64>,
    state_save_us: Option<u64>,
    canonical_write_us: Option<u64>,
    durable_admission_us: Option<u64>,
    remote_delivery_us: Option<u64>,
    report_us: Option<u64>,
    total_us: Option<u64>,
}

#[derive(Serialize)]
struct ProcessResources {
    /// The whole process: CPU since it started, the lifetime memory peak,
    /// and wall time since the command started.
    process: ProcessUse,
    /// This scan only. There is no per-scan memory peak.
    scan: ScanUse,
}

#[derive(Serialize)]
struct ProcessUse {
    wall_us: u64,
    user_cpu_us: Option<u64>,
    kernel_cpu_us: Option<u64>,
    peak_memory_bytes: Option<u64>,
    peak_memory_measure: Option<PeakMemoryMeasure>,
}

#[derive(Serialize)]
struct ScanUse {
    wall_us: Option<u64>,
    user_cpu_us: Option<u64>,
    kernel_cpu_us: Option<u64>,
}
