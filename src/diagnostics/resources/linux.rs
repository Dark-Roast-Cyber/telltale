//! Linux: CPU time from `getrusage`, peak memory from `VmHWM` in
//! `/proc/self/status`.
//!
//! `ru_maxrss` is not used for peak memory. Linux carries the high-water mark
//! of the image that called `exec` into it, so a small process started by a
//! larger parent reports the parent's peak. `VmHWM` covers only this program's
//! address space. Without a readable `/proc`, peak memory is unavailable.
//!
//! The kernel keeps both through per-CPU counters, so `VmHWM` is approximate:
//! after memory is freed a reading can sit a few hundred KiB below an earlier
//! one.

use std::io::Read;

use super::{CpuTime, PeakMemory, PeakMemoryMeasure, rusage};

/// `/proc/self/status` is a few kilobytes; more is not a status file.
const MAX_STATUS_BYTES: u64 = 64 * 1024;

pub(super) fn cpu_time() -> Option<CpuTime> {
    rusage::cpu_time(&rusage::self_usage()?)
}

pub(super) fn peak_memory() -> Option<PeakMemory> {
    let mut status = String::new();
    std::fs::File::open("/proc/self/status")
        .ok()?
        .take(MAX_STATUS_BYTES)
        .read_to_string(&mut status)
        .ok()?;
    Some(PeakMemory {
        bytes: vm_hwm_kib(&status)?.checked_mul(1024)?,
        measure: PeakMemoryMeasure::LinuxVmHwm,
    })
}

/// The `VmHWM` value, which the kernel always prints in kB (KiB).
fn vm_hwm_kib(status: &str) -> Option<u64> {
    let value = status
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))?;
    let mut fields = value.split_whitespace();
    let kib = fields.next()?.parse().ok()?;
    (fields.next() == Some("kB") && fields.next().is_none()).then_some(kib)
}

#[cfg(test)]
mod tests {
    use super::vm_hwm_kib;

    #[test]
    fn vm_hwm_is_read_only_from_its_own_well_formed_line() {
        let status = "Name:\ttelltale\nVmPeak:\t  900 kB\nVmHWM:\t    2640 kB\nVmRSS:\t 2000 kB\n";
        assert_eq!(vm_hwm_kib(status), Some(2640));
        assert_eq!(vm_hwm_kib("VmRSS:\t 2000 kB\n"), None);
        assert_eq!(vm_hwm_kib("VmHWM:\t 2640 MB\n"), None);
        assert_eq!(vm_hwm_kib("VmHWM:\t 2640\n"), None);
        assert_eq!(vm_hwm_kib("VmHWM:\t -1 kB\n"), None);
    }
}
