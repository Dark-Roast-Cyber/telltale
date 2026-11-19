//! macOS: CPU time and peak memory from `getrusage`. On macOS `ru_maxrss` is
//! the maximum resident set size in bytes.

use super::{CpuTime, PeakMemory, PeakMemoryMeasure, rusage};

pub(super) fn cpu_time() -> Option<CpuTime> {
    rusage::cpu_time(&rusage::self_usage()?)
}

pub(super) fn peak_memory() -> Option<PeakMemory> {
    let usage = rusage::self_usage()?;
    Some(PeakMemory {
        bytes: u64::try_from(usage.ru_maxrss).ok()?,
        measure: PeakMemoryMeasure::MacosMaxRss,
    })
}
