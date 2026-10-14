//! Fixed, bounded diagnostic children; failures never reflect captured stderr.
use anyhow::{Context, ensure};
use std::os::{fd::AsFd, unix::process::CommandExt};
use std::{
    io::Read,
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};
fn drain(
    reader: &mut impl Read,
    bytes: &mut Vec<u8>,
    closed: &mut bool,
    maximum: usize,
) -> anyhow::Result<()> {
    if *closed {
        return Ok(());
    }
    let mut buffer = [0u8; 4096];
    let limit = (maximum + 1).saturating_sub(bytes.len()).min(buffer.len());
    ensure!(limit > 0, "diagnostic output exceeds byte bound");
    match reader.read(&mut buffer[..limit]) {
        Ok(0) => *closed = true,
        Ok(count) => bytes.extend_from_slice(&buffer[..count]),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}
pub fn bounded(
    program: &Path,
    arguments: &[String],
    seconds: u64,
    maximum: usize,
) -> anyhow::Result<Vec<u8>> {
    ensure!(
        (1..=30).contains(&seconds) && maximum <= 64 * 1024,
        "diagnostic bounds exceed limits"
    );
    let mut child = Command::new(program)
        .args(arguments)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C.UTF-8")
        .env("TZ", "UTC")
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let result = (|| {
        let mut stdout = child.stdout.take().context("diagnostic stdout missing")?;
        let mut stderr = child.stderr.take().context("diagnostic stderr missing")?;
        for descriptor in [stdout.as_fd(), stderr.as_fd()] {
            let flags = rustix::fs::fcntl_getfl(descriptor)?;
            rustix::fs::fcntl_setfl(descriptor, flags | rustix::fs::OFlags::NONBLOCK)?;
        }
        let mut output = Vec::new();
        let mut errors = Vec::new();
        let mut closed_out = false;
        let mut closed_err = false;
        let mut status = None;
        let deadline = Instant::now() + Duration::from_secs(seconds);
        loop {
            ensure!(Instant::now() < deadline, "diagnostic child timed out");
            drain(&mut stdout, &mut output, &mut closed_out, maximum)?;
            drain(&mut stderr, &mut errors, &mut closed_err, maximum)?;
            ensure!(
                output.len() <= maximum && errors.len() <= maximum,
                "diagnostic output exceeds limit"
            );
            if status.is_none() {
                status = child.try_wait()?;
            }
            if status.is_some() && closed_out && closed_err {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        ensure!(
            status.is_some_and(|status| status.success()),
            "diagnostic child failed"
        );
        Ok(output)
    })();
    if result.is_err() {
        if let Some(pid) = rustix::process::Pid::from_raw(child.id() as i32) {
            let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
        }
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}
