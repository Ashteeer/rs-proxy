use std::{
    fs,
    io::{self, Read},
    os::unix::{fs::PermissionsExt, process::CommandExt},
    path::Path,
    process::{Child, Command, ExitStatus, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

const MAX_CAPTURE_BYTES: usize = 4 * 1024 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const TERMINATION_GRACE: Duration = Duration::from_secs(2);

#[derive(Debug)]
pub struct SupervisionError {
    pub error: io::Error,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

pub fn run_with_timeout(
    command: &mut Command,
    deadline: Duration,
    timeout_message: &'static str,
) -> Result<Output, SupervisionError> {
    let group_kill = group_kill_tool().ok_or_else(|| SupervisionError {
        error: io::Error::new(
            io::ErrorKind::NotFound,
            "executable /bin/kill or /usr/bin/kill is required for process-group supervision",
        ),
        stdout: Vec::new(),
        stderr: Vec::new(),
    })?;
    let mut child = command
        .process_group(0)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| SupervisionError {
            error,
            stdout: Vec::new(),
            stderr: Vec::new(),
        })?;
    let stdout = child.stdout.take().expect("supervised child stdout pipe");
    let stderr = child.stderr.take().expect("supervised child stderr pipe");
    let stdout_reader = drain_output(stdout);
    let stderr_reader = drain_output(stderr);
    let started = Instant::now();
    let mut status = None;
    let mut failure = None;
    let mut termination_started = None;

    loop {
        if status.is_none() {
            match child.try_wait() {
                Ok(Some(exit_status)) => status = Some(exit_status),
                Ok(None) => {}
                Err(error) => {
                    failure.get_or_insert(error);
                }
            }
        }

        let readers_finished = stdout_reader.is_finished() && stderr_reader.is_finished();
        if let Some(exit_status) = status
            && readers_finished
        {
            let stdout = join_reader(stdout_reader, "stdout");
            let stderr = join_reader(stderr_reader, "stderr");
            return match failure {
                Some(error) => finish_failure(error, stdout, stderr),
                None => finish_success(exit_status, stdout, stderr),
            };
        }

        if termination_started.is_none() && (failure.is_some() || started.elapsed() >= deadline) {
            let primary = failure
                .take()
                .unwrap_or_else(|| io::Error::new(io::ErrorKind::TimedOut, timeout_message));
            failure = Some(if terminate_process_group(&mut child, group_kill) {
                primary
            } else {
                io::Error::other(format!(
                    "{primary}; failed to terminate process group {}",
                    child.id()
                ))
            });
            termination_started = Some(Instant::now());
            continue;
        }

        if termination_started
            .is_some_and(|instant: Instant| instant.elapsed() >= TERMINATION_GRACE)
        {
            let _ = child.kill();
            if status.is_none() {
                match child.try_wait() {
                    Ok(Some(exit_status)) => status = Some(exit_status),
                    Ok(None) => {}
                    Err(error) => {
                        failure.get_or_insert(error);
                    }
                }
            }
            let stdout = collect_reader(stdout_reader, "stdout");
            let stderr = collect_reader(stderr_reader, "stderr");
            let mut error =
                failure.unwrap_or_else(|| io::Error::new(io::ErrorKind::TimedOut, timeout_message));
            if status.is_none() {
                error = io::Error::new(
                    error.kind(),
                    format!(
                        "{error}; process-group leader {} did not exit within the termination grace",
                        child.id()
                    ),
                );
            }
            return finish_failure(error, stdout, stderr);
        }

        thread::sleep(POLL_INTERVAL);
    }
}

fn group_kill_tool() -> Option<&'static Path> {
    [Path::new("/bin/kill"), Path::new("/usr/bin/kill")]
        .into_iter()
        .find(|path| {
            fs::metadata(path).is_ok_and(|metadata| {
                metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
            })
        })
}

pub fn group_kill_available() -> bool {
    group_kill_tool().is_some()
}

fn terminate_process_group(child: &mut Child, kill: &Path) -> bool {
    let process_group = format!("-{}", child.id());
    let group_killed = Command::new(kill)
        .args(["-KILL", "--", &process_group])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if !group_killed {
        let _ = child.kill();
    }
    group_killed
}

struct CapturedOutput {
    bytes: Vec<u8>,
    truncated: bool,
    read_error: Option<String>,
}

fn drain_output<R>(mut reader: R) -> thread::JoinHandle<CapturedOutput>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut kept = Vec::new();
        let mut truncated = false;
        let mut read_error = None;
        let mut buffer = [0_u8; 8 * 1024];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => {
                    let remaining = MAX_CAPTURE_BYTES.saturating_sub(kept.len());
                    let retained = read.min(remaining);
                    kept.extend_from_slice(&buffer[..retained]);
                    truncated |= retained != read;
                }
                Err(error) => {
                    if error.kind() != io::ErrorKind::Interrupted {
                        read_error = Some(error.to_string());
                        break;
                    }
                }
            }
        }
        CapturedOutput {
            bytes: kept,
            truncated,
            read_error,
        }
    })
}

fn join_reader(reader: thread::JoinHandle<CapturedOutput>, stream: &str) -> CapturedOutput {
    reader.join().unwrap_or_else(|_| CapturedOutput {
        bytes: Vec::new(),
        truncated: true,
        read_error: Some(format!("{stream} reader panicked")),
    })
}

fn collect_reader(reader: thread::JoinHandle<CapturedOutput>, stream: &str) -> CapturedOutput {
    if reader.is_finished() {
        join_reader(reader, stream)
    } else {
        drop(reader);
        CapturedOutput {
            bytes: Vec::new(),
            truncated: true,
            read_error: Some(format!(
                "{stream} pipe did not close within the termination grace"
            )),
        }
    }
}

fn finish_success(
    status: ExitStatus,
    stdout: CapturedOutput,
    stderr: CapturedOutput,
) -> Result<Output, SupervisionError> {
    let issues = capture_issues(&stdout, &stderr);
    if !issues.is_empty() {
        return Err(SupervisionError {
            error: io::Error::new(io::ErrorKind::InvalidData, issues.join("; ")),
            stdout: stdout.bytes,
            stderr: stderr.bytes,
        });
    }
    Ok(Output {
        status,
        stdout: stdout.bytes,
        stderr: stderr.bytes,
    })
}

fn finish_failure(
    error: io::Error,
    stdout: CapturedOutput,
    stderr: CapturedOutput,
) -> Result<Output, SupervisionError> {
    let issues = capture_issues(&stdout, &stderr);
    let error = if issues.is_empty() {
        error
    } else {
        io::Error::new(error.kind(), format!("{error}; {}", issues.join("; ")))
    };
    Err(SupervisionError {
        error,
        stdout: stdout.bytes,
        stderr: stderr.bytes,
    })
}

fn capture_issues(stdout: &CapturedOutput, stderr: &CapturedOutput) -> Vec<String> {
    let mut issues = Vec::new();
    for (stream, captured) in [("stdout", stdout), ("stderr", stderr)] {
        if captured.truncated {
            issues.push(format!(
                "{stream} capture was truncated at {MAX_CAPTURE_BYTES} bytes"
            ));
        }
        if let Some(error) = &captured.read_error {
            issues.push(format!("{stream} capture failed: {error}"));
        }
    }
    issues
}

pub fn successful_status(status: ExitStatus) -> bool {
    status.success()
}
