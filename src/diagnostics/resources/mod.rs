//! Process resource use, read from each operating system's own counters.
//!
//! CPU time is the whole process's user and kernel time since it started, all
//! threads included, in microseconds. Peak memory is the process-lifetime
//! high-water mark of the operating system's own measure, in bytes:
//!
//! | OS | Measure | Source |
//! | --- | --- | --- |
//! | Linux | `linux_vm_hwm` | `VmHWM` in `/proc/self/status` |
//! | macOS | `macos_max_rss` | `ru_maxrss` from `getrusage` |
//! | Windows | `windows_peak_working_set` | `PeakWorkingSetSize` from `K32GetProcessMemoryInfo` |
//!
//! The measures count different things, so a value always carries its measure
//! and is never compared across operating systems. A peak covers the whole
//! process, never one scan inside it. Reading a counter has no side effect and
//! never resets it. A counter the operating system does not report is `None`,
//! never zero.
//!
//! Each operating system has its own module; this one only selects it. Linux
//! and macOS share the `getrusage` call in `rusage`.

#[cfg(unix)]
mod rusage;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux as platform;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos as platform;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as platform;

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
mod unsupported;
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
use unsupported as platform;

/// Process user and kernel CPU time, in microseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CpuTime {
    pub(crate) user_us: u64,
    pub(crate) kernel_us: u64,
}

impl CpuTime {
    /// The CPU time used since `earlier`, or `None` if a counter went
    /// backwards.
    pub(crate) fn since(self, earlier: Self) -> Option<Self> {
        Some(Self {
            user_us: self.user_us.checked_sub(earlier.user_us)?,
            kernel_us: self.kernel_us.checked_sub(earlier.kernel_us)?,
        })
    }
}

/// Which operating-system measure a peak memory value came from. Each
/// operating system builds only its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PeakMemoryMeasure {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    LinuxVmHwm,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    MacosMaxRss,
    #[cfg_attr(not(windows), allow(dead_code))]
    WindowsPeakWorkingSet,
}

/// The process-lifetime peak of one operating-system memory measure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PeakMemory {
    pub(crate) bytes: u64,
    pub(crate) measure: PeakMemoryMeasure,
}

/// This process's CPU time, or `None` where the OS does not report it.
pub(crate) fn process_cpu_time() -> Option<CpuTime> {
    platform::cpu_time()
}

/// This process's peak memory, or `None` where the OS does not report it.
pub(crate) fn process_peak_memory() -> Option<PeakMemory> {
    platform::peak_memory()
}

#[cfg(test)]
mod tests;
