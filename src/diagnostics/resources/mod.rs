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
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    const SUPPORTED: bool = cfg!(any(target_os = "linux", target_os = "macos", windows));

    /// A memory spike of known size must raise the peak by at least that much,
    /// in bytes: a counter read in the wrong unit fails here.
    #[test]
    fn peak_memory_reports_a_touched_allocation_in_bytes() {
        if !SUPPORTED {
            assert_eq!(process_peak_memory(), None);
            return;
        }
        const SPIKE: usize = 64 << 20;
        let spike = vec![1u8; SPIKE];
        std::hint::black_box(&spike);
        let peak = process_peak_memory().expect("peak memory is reported");
        drop(spike);
        assert!(
            peak.bytes >= SPIKE as u64,
            "peak {} bytes is below the {SPIKE}-byte spike",
            peak.bytes
        );
        assert!(
            peak.bytes < 64 << 30,
            "peak {} bytes is implausible",
            peak.bytes
        );
        let expected = if cfg!(target_os = "linux") {
            PeakMemoryMeasure::LinuxVmHwm
        } else if cfg!(target_os = "macos") {
            PeakMemoryMeasure::MacosMaxRss
        } else {
            PeakMemoryMeasure::WindowsPeakWorkingSet
        };
        assert_eq!(peak.measure, expected);
        // A lifetime peak still holds the freed spike, where current use
        // would fall by all of it. Linux reads the peak through per-CPU
        // counters, so a later reading may sit slightly lower (measured up
        // to 716 KiB on a 20-CPU host).
        let slack: u64 = if cfg!(target_os = "linux") {
            16 << 20
        } else {
            0
        };
        let later = process_peak_memory().expect("peak memory is reported");
        assert!(
            later.bytes + slack >= peak.bytes,
            "peak fell from {} to {} bytes after the spike was freed",
            peak.bytes,
            later.bytes
        );
    }

    /// Spinning for 200 ms must add CPU time in microseconds: a unit a
    /// thousand times too small stays under the floor, and one a thousand
    /// times too large exceeds what the cores could have done.
    #[test]
    fn cpu_time_counts_spinning_in_microseconds() {
        if !SUPPORTED {
            assert_eq!(process_cpu_time(), None);
            return;
        }
        let before = process_cpu_time().expect("CPU time is reported");
        let started = Instant::now();
        while started.elapsed() < Duration::from_millis(200) {
            std::hint::black_box((0..10_000u64).fold(0u64, u64::wrapping_add));
        }
        let elapsed = started.elapsed();
        let used = process_cpu_time()
            .expect("CPU time is reported")
            .since(before)
            .expect("CPU time never decreases");
        let used_us = used.user_us + used.kernel_us;
        // Even a crowded host gives a spinning process a tenth of the time.
        assert!(
            used_us >= 20_000,
            "{used:?} is below 20 ms for a 200 ms spin"
        );
        // Twice what the cores allow, plus a tick: CPU quotas and tick-based
        // accounting stay inside it.
        let cores = std::thread::available_parallelism().map_or(64, usize::from) as u64;
        let ceiling = (super::super::micros(elapsed) + 20_000) * cores * 2;
        assert!(
            used_us <= ceiling,
            "{used:?} exceeds {ceiling} us for {cores} cores"
        );
    }

    #[test]
    fn cpu_time_difference_refuses_a_counter_that_went_backwards() {
        let later = CpuTime {
            user_us: 10,
            kernel_us: 5,
        };
        let earlier = CpuTime {
            user_us: 4,
            kernel_us: 5,
        };
        assert_eq!(
            later.since(earlier),
            Some(CpuTime {
                user_us: 6,
                kernel_us: 0
            })
        );
        assert_eq!(earlier.since(later), None);
    }
}
