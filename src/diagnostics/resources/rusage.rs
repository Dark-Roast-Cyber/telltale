//! `getrusage(RUSAGE_SELF)`, shared by Linux and macOS.
//!
//! Its CPU fields mean the same on both. `ru_maxrss` does not: Linux reports
//! kibibytes and carries the high-water mark of the image that called `exec`,
//! macOS reports bytes. Each platform module decides whether to read it.

use super::CpuTime;

pub(super) fn self_usage() -> Option<libc::rusage> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    // SAFETY: `usage` is a writable `rusage`; the call fills it on success.
    let status = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
    // SAFETY: `getrusage` returned 0, so it initialized `usage`.
    (status == 0).then(|| unsafe { usage.assume_init() })
}

pub(super) fn cpu_time(usage: &libc::rusage) -> Option<CpuTime> {
    Some(CpuTime {
        user_us: timeval_micros(usage.ru_utime)?,
        kernel_us: timeval_micros(usage.ru_stime)?,
    })
}

fn timeval_micros(value: libc::timeval) -> Option<u64> {
    let seconds = u64::try_from(value.tv_sec).ok()?;
    let micros = u64::try_from(value.tv_usec).ok()?;
    seconds.checked_mul(1_000_000)?.checked_add(micros)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeval_converts_to_microseconds_and_refuses_negative_values() {
        let value = |tv_sec, tv_usec| libc::timeval { tv_sec, tv_usec };
        assert_eq!(timeval_micros(value(2, 500)), Some(2_000_500));
        assert_eq!(timeval_micros(value(-1, 0)), None);
        assert_eq!(timeval_micros(value(0, -1)), None);
    }
}
