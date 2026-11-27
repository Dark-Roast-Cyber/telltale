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
