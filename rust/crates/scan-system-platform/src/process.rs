//! Cancellable, hidden-window process execution — ported from
//! `_run_cancellable`/`run_powershell`/`run_hidden_command` in `scanner_windows.py`.
//!
//! Differs from a plain `Command::output()` in three ways the Python original needed:
//! 1. **Hidden window** — `CREATE_NO_WINDOW`, so `powershell.exe`/`netsh`/`tracert` never
//!    flash a console when the GUI shells out to them.
//! 2. **Cancellable** — an in-flight audit's "Stop" button ([`AuditHandle::request_cancel`])
//!    kills whatever child process is currently running, checked between polls rather
//!    than only before starting a new command.
//! 3. **OEM codepage decoding** — a process with no allocated console (which
//!    `CREATE_NO_WINDOW` guarantees) writes its stdout/stderr in the machine's OEM
//!    codepage (e.g. CP850 on French Windows), not UTF-8 — confirmed the hard way in
//!    the Python original (accented characters in `Get-WinEvent` messages were
//!    corrupted before this was special-cased). [`decode_oem`] calls `GetOEMCP` +
//!    `MultiByteToWideChar` to decode exactly the codepage Windows itself would use,
//!    the same fix Python's `encoding="oem"` alias applies.

use std::{
    io::Read,
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

use std::os::windows::process::CommandExt;

/// From `<winbase.h>` — suppresses the console window a child process would otherwise
/// briefly allocate.
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// How often the wait loop polls the child's exit status / checks for cancellation —
/// matches the Python original's `communicate(timeout=0.5)` polling granularity closely
/// enough that a cancel or timeout is noticed within a fraction of a second.
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Decodes bytes using the machine's OEM codepage (`GetOEMCP`), not UTF-8 — see the
/// module doc. Falls back to lossy UTF-8 only if the Win32 call itself fails (should not
/// happen on a real Windows machine), rather than panicking on process output.
#[must_use]
pub fn decode_oem(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    // SAFETY: `GetOEMCP` takes no arguments and cannot fail in a way that's unsafe to
    // observe. `MultiByteToWideChar` is called twice, first with a null output buffer
    // (per its documented contract) to size the output, then with a `wide` buffer sized
    // exactly to the value it just returned — both calls pass `bytes.len()` as the
    // input length, matching the slice's real size, and `wide`'s capacity is never
    // exceeded because it's allocated from the same call's return value.
    unsafe {
        let codepage = windows_sys::Win32::Globalization::GetOEMCP();
        let wide_len = windows_sys::Win32::Globalization::MultiByteToWideChar(
            codepage,
            0,
            bytes.as_ptr(),
            bytes.len() as i32,
            std::ptr::null_mut(),
            0,
        );
        if wide_len <= 0 {
            return String::from_utf8_lossy(bytes).into_owned();
        }
        let mut wide = vec![0u16; wide_len as usize];
        let written = windows_sys::Win32::Globalization::MultiByteToWideChar(
            codepage,
            0,
            bytes.as_ptr(),
            bytes.len() as i32,
            wide.as_mut_ptr(),
            wide_len,
        );
        if written <= 0 {
            return String::from_utf8_lossy(bytes).into_owned();
        }
        String::from_utf16_lossy(&wide)
    }
}

/// Result of a command that always completes with an "ok/not ok" verdict rather than a
/// hard error — mirrors `run_hidden_command`'s 4-tuple return.
#[derive(Debug, Clone)]
pub struct HiddenCommandOutput {
    pub ok: bool,
    pub stdout: String,
    pub stderr: String,
    pub return_code: i32,
}

/// Result of a PowerShell invocation — mirrors `run_powershell`'s 2-tuple return: `ok`
/// plus either the trimmed stdout (success) or a formatted `Code=...; STDERR=...;
/// STDOUT=...` diagnostic string (failure), same shape callers already parse/display.
#[derive(Debug, Clone)]
pub struct PowerShellOutput {
    pub ok: bool,
    pub output: String,
}

/// Raised instead of returned — a caller mid-audit that gets this must unwind to "audit
/// cancelled" state, not treat it as a per-command failure to report and continue past
/// (same distinction the Python original's `AuditCancelled` exception makes against a
/// plain `(False, ...)` return).
#[derive(Debug)]
pub enum ProcessError {
    Cancelled,
    Timeout(Duration),
    Spawn(std::io::Error),
}

impl std::fmt::Display for ProcessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => write!(f, "annule par l'utilisateur"),
            Self::Timeout(d) => write!(f, "timeout apres {}s", d.as_secs()),
            Self::Spawn(e) => write!(f, "echec du lancement du process: {e}"),
        }
    }
}

impl std::error::Error for ProcessError {}

/// Shared cancellation state for one audit run — one instance lives for the duration of
/// a "Lancer audit complet"/CLI invocation, handed to every function in this crate that
/// shells out. Cloning is cheap (`Arc` internally) so the GUI's "Stop" button handler
/// can hold its own clone independent of the worker thread running the audit.
#[derive(Clone, Default)]
pub struct AuditHandle {
    cancelled: Arc<AtomicBool>,
    current_child: Arc<Mutex<Option<Child>>>,
}

impl AuditHandle {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Clears a previous cancellation before starting a new audit — matches
    /// `reset_audit_cancel()`, needed because one `AuditHandle` can run more than one
    /// audit over its lifetime (the GUI keeps one around, the CLI makes a fresh one).
    pub fn reset(&self) {
        self.cancelled.store(false, Ordering::SeqCst);
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    /// Requests cancellation and kills whatever child process is currently running, if
    /// any — matches `request_audit_cancel()`. Safe to call from a different thread
    /// than the one running the audit (that's the whole point: a GUI button click).
    pub fn request_cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        if let Ok(mut guard) = self.current_child.lock() {
            if let Some(child) = guard.as_mut() {
                let _ = child.kill();
            }
        }
    }

    fn check_cancelled(&self) -> Result<(), ProcessError> {
        if self.is_cancelled() {
            Err(ProcessError::Cancelled)
        } else {
            Ok(())
        }
    }

    /// Spawns `command` hidden (`CREATE_NO_WINDOW`), draining stdout/stderr on
    /// background threads while polling for exit/cancellation/timeout on this one —
    /// draining concurrently (not just after the process exits) avoids the classic
    /// pipe-buffer deadlock a chatty child (e.g. a large `Get-WinEvent` JSON dump) would
    /// otherwise cause once it fills the OS pipe buffer and blocks on write. Mirrors
    /// `_run_cancellable`, which gets the same property for free from Python's
    /// `Popen.communicate()`.
    ///
    /// # Errors
    ///
    /// [`ProcessError::Spawn`] if the process can't be started at all;
    /// [`ProcessError::Cancelled`]/[`ProcessError::Timeout`] if it had to be killed.
    pub fn run_raw(
        &self,
        mut command: Command,
        timeout: Duration,
    ) -> Result<(String, String, ExitStatus), ProcessError> {
        self.check_cancelled()?;
        command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .creation_flags(CREATE_NO_WINDOW);
        let mut child = command.spawn().map_err(ProcessError::Spawn)?;

        let mut stdout_pipe = child.stdout.take().expect("stdout was piped above");
        let mut stderr_pipe = child.stderr.take().expect("stderr was piped above");
        let stdout_reader = thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = stdout_pipe.read_to_end(&mut buf);
            buf
        });
        let stderr_reader = thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = stderr_pipe.read_to_end(&mut buf);
            buf
        });

        *self.current_child.lock().expect("lock poisoned") = Some(child);

        let deadline = Instant::now() + timeout;
        let wait_result = loop {
            let mut guard = self.current_child.lock().expect("lock poisoned");
            let child_ref = guard.as_mut().expect("set just above, cleared only below");
            match child_ref.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) => {
                    if self.is_cancelled() {
                        let _ = child_ref.kill();
                        let _ = child_ref.wait();
                        break Err(ProcessError::Cancelled);
                    }
                    if Instant::now() >= deadline {
                        let _ = child_ref.kill();
                        let _ = child_ref.wait();
                        break Err(ProcessError::Timeout(timeout));
                    }
                    drop(guard);
                    thread::sleep(POLL_INTERVAL);
                }
                Err(_) => {
                    let _ = child_ref.kill();
                    break Err(ProcessError::Timeout(timeout)); // process handle went bad; treat like a hang
                }
            }
        };
        *self.current_child.lock().expect("lock poisoned") = None;

        let stdout_bytes = stdout_reader.join().unwrap_or_default();
        let stderr_bytes = stderr_reader.join().unwrap_or_default();
        let status = wait_result?;
        Ok((decode_oem(&stdout_bytes), decode_oem(&stderr_bytes), status))
    }

    /// Runs an arbitrary argv command hidden — `netsh`, `tracert`, and similar. Mirrors
    /// `run_hidden_command`.
    ///
    /// # Errors
    ///
    /// Only [`ProcessError::Cancelled`] propagates (an audit-level unwind signal); every
    /// other failure (spawn error, timeout) is folded into `ok: false` in the returned
    /// [`HiddenCommandOutput`], matching the Python original's `except Exception`
    /// catch-all.
    pub fn run_hidden_command(
        &self,
        command: Command,
        timeout: Duration,
    ) -> Result<HiddenCommandOutput, ProcessError> {
        match self.run_raw(command, timeout) {
            Ok((stdout, stderr, status)) => Ok(HiddenCommandOutput {
                ok: status.success(),
                stdout: stdout.trim().to_string(),
                stderr: stderr.trim().to_string(),
                return_code: status.code().unwrap_or(1),
            }),
            Err(ProcessError::Cancelled) => Err(ProcessError::Cancelled),
            Err(other) => Ok(HiddenCommandOutput {
                ok: false,
                stdout: String::new(),
                stderr: other.to_string(),
                return_code: 1,
            }),
        }
    }

    /// Runs `script` via `powershell -NoProfile -ExecutionPolicy Bypass -Command
    /// <script>`, hidden. Mirrors `run_powershell`.
    ///
    /// # Errors
    ///
    /// Only [`ProcessError::Cancelled`] propagates; every other failure becomes `ok:
    /// false` with a formatted diagnostic in [`PowerShellOutput::output`] (`Code=...;
    /// STDERR=...; STDOUT=...`), matching the Python original exactly so downstream
    /// error-message parsing (e.g. crash logs quoting this string) doesn't need to
    /// change.
    pub fn run_powershell(
        &self,
        script: &str,
        timeout: Duration,
    ) -> Result<PowerShellOutput, ProcessError> {
        let mut command = Command::new("powershell");
        command.args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ]);

        match self.run_raw(command, timeout) {
            Ok((stdout, stderr, status)) => {
                let out = stdout.trim();
                let err = stderr.trim();
                if !status.success() {
                    return Ok(PowerShellOutput {
                        ok: false,
                        output: format!(
                            "Code={}; STDERR={err}; STDOUT={out}",
                            status.code().unwrap_or(-1)
                        ),
                    });
                }
                Ok(PowerShellOutput {
                    ok: true,
                    output: out.to_string(),
                })
            }
            Err(ProcessError::Cancelled) => Err(ProcessError::Cancelled),
            Err(other) => Ok(PowerShellOutput {
                ok: false,
                output: format!("ERREUR execution PowerShell: {other}"),
            }),
        }
    }
}
