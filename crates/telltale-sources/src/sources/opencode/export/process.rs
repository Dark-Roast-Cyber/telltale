use super::ExportError;
use std::io::{self, Read};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

// No drain threads: each pipe is read only when a nonblocking read can progress.
// The trusted harness owns descendants; only the direct child is managed here.
pub(super) fn capture(
    command: &mut Command,
    stdout_cap: usize,
    stderr_cap: usize,
    deadline: Duration,
) -> Result<Vec<u8>, ExportError> {
    let start = Instant::now();
    let child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| ExportError::Spawn)?;
    let mut guard = ChildGuard(child);
    let mut stdout = guard.0.stdout.take().ok_or(ExportError::Capture)?;
    let mut stderr = guard.0.stderr.take().ok_or(ExportError::Capture)?;
    nonblocking(&stdout).map_err(|_| ExportError::Capture)?;
    nonblocking(&stderr).map_err(|_| ExportError::Capture)?;
    let mut output = Vec::new();
    let mut stderr_count = 0usize;
    let mut exit: Option<std::process::ExitStatus> = None;
    loop {
        if start.elapsed() >= deadline {
            return Err(ExportError::Timeout);
        }
        let mut buffer = [0u8; 8192];
        let out = available_read(&mut stdout, &mut buffer).map_err(|_| ExportError::Capture)?;
        if let Some(n) = out {
            if n > stdout_cap.saturating_sub(output.len()) {
                return Err(ExportError::StdoutLimit);
            }
            output.extend_from_slice(&buffer[..n]);
        }
        let err = available_read(&mut stderr, &mut buffer).map_err(|_| ExportError::Capture)?;
        if let Some(n) = err {
            if n > stderr_cap.saturating_sub(stderr_count) {
                return Err(ExportError::StderrLimit);
            }
            stderr_count += n;
        }
        if let Some(status) = exit
            && out.unwrap_or(0) == 0
            && err.unwrap_or(0) == 0
        {
            return if status.success() {
                Ok(output)
            } else {
                Err(ExportError::NonzeroExit)
            };
        }
        exit = guard.0.try_wait().map_err(|_| ExportError::Capture)?;
        if out.unwrap_or(0) == 0 && err.unwrap_or(0) == 0 && exit.is_none() {
            std::thread::sleep(
                Duration::from_millis(2).min(deadline.saturating_sub(start.elapsed())),
            );
        }
    }
}

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        // wait is required even after kill; on normal completion try_wait already reaped.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[cfg(unix)]
fn nonblocking(pipe: &impl std::os::fd::AsRawFd) -> io::Result<()> {
    let fd = pipe.as_raw_fd();
    // SAFETY: fd is a borrowed, live anonymous pipe owned by the caller.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
fn available_read(pipe: &mut impl Read, buffer: &mut [u8]) -> io::Result<Option<usize>> {
    match pipe.read(buffer) {
        Ok(n) => Ok(Some(n)),
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) =>
        {
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

#[cfg(windows)]
fn nonblocking(_: &impl std::os::windows::io::AsRawHandle) -> io::Result<()> {
    Ok(())
}

#[cfg(windows)]
fn available_read(
    pipe: &mut (impl Read + std::os::windows::io::AsRawHandle),
    buffer: &mut [u8],
) -> io::Result<Option<usize>> {
    use windows_sys::Win32::{Foundation::ERROR_BROKEN_PIPE, System::Pipes::PeekNamedPipe};
    let mut available = 0u32;
    // SAFETY: live pipe handle, no data buffer, and valid available-byte output pointer.
    let success = unsafe {
        PeekNamedPipe(
            pipe.as_raw_handle(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            &mut available,
            std::ptr::null_mut(),
        )
    };
    if success == 0 {
        let error = io::Error::last_os_error();
        return if error.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) {
            Ok(Some(0))
        } else {
            Err(error)
        };
    }
    if available == 0 {
        return Ok(None);
    }
    let count = buffer.len().min(available as usize);
    // This is the sole reader, so bytes observed by PeekNamedPipe cannot be consumed elsewhere.
    pipe.read(&mut buffer[..count]).map(Some)
}
