//! Windows: CPU time from `GetProcessTimes`, peak memory from the peak working
//! set reported by `K32GetProcessMemoryInfo`.
//!
//! Process times are in 100-nanosecond units. The peak working set counts
//! shared pages, so it is not a resident set size.

use windows_sys::Win32::Foundation::FILETIME;
use windows_sys::Win32::System::ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};

use super::{CpuTime, PeakMemory, PeakMemoryMeasure};

pub(super) fn cpu_time() -> Option<CpuTime> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: the pseudo-handle from `GetCurrentProcess` needs no closing,
    // and every pointer is a live, writable `FILETIME`.
    let succeeded = unsafe {
        GetProcessTimes(
            GetCurrentProcess(),
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    };
    (succeeded != 0).then(|| CpuTime {
        user_us: hundred_nanoseconds(user) / 10,
        kernel_us: hundred_nanoseconds(kernel) / 10,
    })
}

pub(super) fn peak_memory() -> Option<PeakMemory> {
    let size = u32::try_from(std::mem::size_of::<PROCESS_MEMORY_COUNTERS>()).ok()?;
    let mut counters = PROCESS_MEMORY_COUNTERS {
        cb: size,
        ..Default::default()
    };
    // SAFETY: the pseudo-handle needs no closing, and `counters` is a live,
    // writable structure of the size passed.
    let succeeded = unsafe { K32GetProcessMemoryInfo(GetCurrentProcess(), &mut counters, size) };
    if succeeded == 0 {
        return None;
    }
    Some(PeakMemory {
        bytes: u64::try_from(counters.PeakWorkingSetSize).ok()?,
        measure: PeakMemoryMeasure::WindowsPeakWorkingSet,
    })
}

fn hundred_nanoseconds(value: FILETIME) -> u64 {
    (u64::from(value.dwHighDateTime) << 32) | u64::from(value.dwLowDateTime)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filetime_joins_both_halves() {
        let value = FILETIME {
            dwLowDateTime: 5,
            dwHighDateTime: 1,
        };
        assert_eq!(hundred_nanoseconds(value), (1 << 32) + 5);
    }
}
