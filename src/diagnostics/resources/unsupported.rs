//! Operating systems Telltale does not support report no resource counters.

use super::{CpuTime, PeakMemory};

pub(super) fn cpu_time() -> Option<CpuTime> {
    None
}

pub(super) fn peak_memory() -> Option<PeakMemory> {
    None
}
