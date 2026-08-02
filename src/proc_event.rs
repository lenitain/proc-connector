//! Process event types from the Linux Proc Connector.
//!
//! This module contains the `ProcEvent` enum and its `Display` implementation.

use std::fmt;

/// A parsed process event from the Linux Proc Connector.
///
/// Each variant corresponds to a `PROC_EVENT_*` constant from
/// `<linux/cn_proc.h>`, with all relevant fields extracted into
/// named fields.
///
/// The `Unknown` variant provides forward compatibility: if the kernel
/// emits an event type this version of the library does not know about,
/// it is returned as `Unknown` with the raw payload.
///
/// # Example: pattern matching
///
/// ```
/// use proc_connector::ProcEvent;
///
/// fn describe(event: &ProcEvent) -> String {
///     match event {
///         ProcEvent::Exec { pid, .. } => format!("process {pid} exec'd"),
///         ProcEvent::Fork { child_pid, .. } => format!("forked child {child_pid}"),
///         ProcEvent::Exit { pid, exit_code, .. } => {
///             format!("process {pid} exited with code {exit_code}")
///         }
///         ProcEvent::Uid { pid, ruid, euid, .. } => {
///             format!("process {pid} uid changed {ruid}->{euid}")
///         }
///         ProcEvent::Gid { pid, rgid, egid, .. } => {
///             format!("process {pid} gid changed {rgid}->{egid}")
///         }
///         ProcEvent::Sid { pid, .. } => format!("process {pid} session changed"),
///         ProcEvent::Ptrace { pid, tracer_pid, .. } => {
///             format!("process {pid} traced by {tracer_pid}")
///         }
///         ProcEvent::Comm { pid, comm, .. } => {
///             let name = String::from_utf8_lossy(comm);
///             let name = name.trim_end_matches('\0');
///             format!("process {pid} renamed to {name}")
///         }
///         ProcEvent::Coredump { pid, .. } => format!("process {pid} dumped core"),
///         ProcEvent::Unknown { what, .. } => format!("unknown event 0x{what:08x}"),
///     }
/// }
///
/// let exec = ProcEvent::Exec { cpu: 0, seq: 0, pid: 42, tgid: 42, timestamp_ns: 0 };
/// assert_eq!(describe(&exec), "process 42 exec'd");
///
/// let exit = ProcEvent::Exit { cpu: 0, seq: 0, pid: 7, tgid: 7, exit_code: 0, exit_signal: 17,
///     parent_pid: 1, parent_tgid: 1, timestamp_ns: 0 };
/// assert_eq!(describe(&exit), "process 7 exited with code 0");
/// ```
///
/// # Example: Display formatting
///
/// ```
/// use proc_connector::ProcEvent;
///
/// let event = ProcEvent::Fork {
///     cpu: 0,
///     seq: 42,
///     parent_pid: 100,
///     parent_tgid: 100,
///     child_pid: 200,
///     child_tgid: 200,
///     timestamp_ns: 0,
/// };
/// assert_eq!(event.to_string(), "FORK parent=(100,100) child=(200,200) ts=0");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcEvent {
    /// A process called `execve(2)`.
    Exec {
        /// CPU that generated this event.
        cpu: u32,
        /// Per-CPU monotonic message sequence (gap detection within one CPU).
        seq: u32,
        pid: u32,
        tgid: u32,
        /// Kernel timestamp (nanoseconds since boot).
        timestamp_ns: u64,
    },
    /// A new process was created via `fork`/`clone`.
    Fork {
        /// CPU that generated this event.
        cpu: u32,
        /// Per-CPU monotonic message sequence (gap detection within one CPU).
        seq: u32,
        parent_pid: u32,
        parent_tgid: u32,
        child_pid: u32,
        child_tgid: u32,
        /// Kernel timestamp (nanoseconds since boot).
        timestamp_ns: u64,
    },
    /// A process exited.
    Exit {
        /// CPU that generated this event.
        cpu: u32,
        /// Per-CPU monotonic message sequence (gap detection within one CPU).
        seq: u32,
        pid: u32,
        tgid: u32,
        exit_code: u32,
        exit_signal: u32,
        parent_pid: u32,
        parent_tgid: u32,
        /// Kernel timestamp (nanoseconds since boot).
        timestamp_ns: u64,
    },
    /// Real or effective UID changed.
    Uid {
        /// CPU that generated this event.
        cpu: u32,
        /// Per-CPU monotonic message sequence (gap detection within one CPU).
        seq: u32,
        pid: u32,
        tgid: u32,
        ruid: u32,
        euid: u32,
        /// Kernel timestamp (nanoseconds since boot).
        timestamp_ns: u64,
    },
    /// Real or effective GID changed.
    Gid {
        /// CPU that generated this event.
        cpu: u32,
        /// Per-CPU monotonic message sequence (gap detection within one CPU).
        seq: u32,
        pid: u32,
        tgid: u32,
        rgid: u32,
        egid: u32,
        /// Kernel timestamp (nanoseconds since boot).
        timestamp_ns: u64,
    },
    /// Session ID changed (`setsid`).
    Sid {
        /// CPU that generated this event.
        cpu: u32,
        /// Per-CPU monotonic message sequence (gap detection within one CPU).
        seq: u32,
        pid: u32,
        tgid: u32,
        /// Kernel timestamp (nanoseconds since boot).
        timestamp_ns: u64,
    },
    /// `ptrace` attach or detach.
    Ptrace {
        /// CPU that generated this event.
        cpu: u32,
        /// Per-CPU monotonic message sequence (gap detection within one CPU).
        seq: u32,
        pid: u32,
        tgid: u32,
        tracer_pid: u32,
        tracer_tgid: u32,
        /// Kernel timestamp (nanoseconds since boot).
        timestamp_ns: u64,
    },
    /// Process name (`comm`) changed (max 16 bytes, may include trailing NUL).
    Comm {
        /// CPU that generated this event.
        cpu: u32,
        /// Per-CPU monotonic message sequence (gap detection within one CPU).
        seq: u32,
        pid: u32,
        tgid: u32,
        /// The new process name (up to 16 bytes, usually NUL-terminated).
        comm: [u8; 16],
        /// Kernel timestamp (nanoseconds since boot).
        timestamp_ns: u64,
    },
    /// A core dump occurred.
    Coredump {
        /// CPU that generated this event.
        cpu: u32,
        /// Per-CPU monotonic message sequence (gap detection within one CPU).
        seq: u32,
        pid: u32,
        tgid: u32,
        parent_pid: u32,
        parent_tgid: u32,
        /// Kernel timestamp (nanoseconds since boot).
        timestamp_ns: u64,
    },
    /// An unknown event type (forward-compatibility).
    Unknown {
        /// The raw `what` field value.
        what: u32,
        /// Raw bytes of the `event_data` union (may be empty).
        raw_data: Vec<u8>,
    },
}

impl ProcEvent {
    /// Extract the exit status from an `Exit` event's `exit_code` field.
    ///
    /// Returns the value that would be returned by `WEXITSTATUS(exit_code)`,
    /// i.e. the low 8 bits of the exit code. Returns `None` if the process
    /// was terminated by a signal.
    ///
    /// # Example
    ///
    /// ```
    /// use proc_connector::ProcEvent;
    /// let e = ProcEvent::Exit { cpu: 0, seq: 0, pid:1, tgid:1, exit_code: (1 << 8), exit_signal:0,
    ///     parent_pid:0, parent_tgid:0, timestamp_ns:0 };
    /// assert_eq!(e.exit_status(), Some(1));
    /// ```
    pub fn exit_status(&self) -> Option<i32> {
        if let ProcEvent::Exit {
            exit_code,
            exit_signal,
            ..
        } = self
        {
            if *exit_signal == 0 {
                Some(((exit_code >> 8) & 0xFF) as i32)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Extract the terminating signal from an `Exit` event's `exit_code` field.
    ///
    /// Returns the signal number that caused the process to terminate,
    /// i.e. `WTERMSIG(exit_code)`. Returns `None` if the process exited
    /// normally (not by signal).
    pub fn terminating_signal(&self) -> Option<i32> {
        if let ProcEvent::Exit {
            exit_code,
            exit_signal,
            ..
        } = self
        {
            if *exit_signal != 0 || (*exit_code & 0x7F) != 0 {
                Some((exit_code & 0x7F) as i32)
            } else {
                None
            }
        } else {
            None
        }
    }
}

impl fmt::Display for ProcEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProcEvent::Exec {
                pid,
                tgid,
                timestamp_ns,
                ..
            } => write!(f, "EXEC pid={pid} tgid={tgid} ts={timestamp_ns}"),
            ProcEvent::Fork {
                parent_pid,
                parent_tgid,
                child_pid,
                child_tgid,
                timestamp_ns,
                ..
            } => write!(
                f,
                "FORK parent=({parent_pid},{parent_tgid}) child=({child_pid},{child_tgid}) ts={timestamp_ns}"
            ),
            ProcEvent::Exit {
                pid,
                tgid,
                exit_code,
                exit_signal,
                parent_pid,
                parent_tgid,
                timestamp_ns,
                ..
            } => write!(
                f,
                "EXIT pid={pid} tgid={tgid} code={exit_code} signal={exit_signal} parent=({parent_pid},{parent_tgid}) ts={timestamp_ns}"
            ),
            ProcEvent::Uid {
                pid,
                tgid,
                ruid,
                euid,
                timestamp_ns,
                ..
            } => write!(
                f,
                "UID pid={pid} tgid={tgid} ruid={ruid} euid={euid} ts={timestamp_ns}"
            ),
            ProcEvent::Gid {
                pid,
                tgid,
                rgid,
                egid,
                timestamp_ns,
                ..
            } => write!(
                f,
                "GID pid={pid} tgid={tgid} rgid={rgid} egid={egid} ts={timestamp_ns}"
            ),
            ProcEvent::Sid {
                pid,
                tgid,
                timestamp_ns,
                ..
            } => write!(f, "SID pid={pid} tgid={tgid} ts={timestamp_ns}"),
            ProcEvent::Ptrace {
                pid,
                tgid,
                tracer_pid,
                tracer_tgid,
                timestamp_ns,
                ..
            } => write!(
                f,
                "PTRACE pid={pid} tgid={tgid} tracer=({tracer_pid},{tracer_tgid}) ts={timestamp_ns}"
            ),
            ProcEvent::Comm {
                pid,
                tgid,
                comm,
                timestamp_ns,
                ..
            } => {
                let end = comm.iter().position(|&b| b == 0).unwrap_or(16);
                let name = std::str::from_utf8(&comm[..end]).unwrap_or("<invalid>");
                write!(
                    f,
                    "COMM pid={pid} tgid={tgid} name=\"{name}\" ts={timestamp_ns}"
                )
            }
            ProcEvent::Coredump {
                pid,
                tgid,
                parent_pid,
                parent_tgid,
                timestamp_ns,
                ..
            } => {
                write!(
                    f,
                    "COREDUMP pid={pid} tgid={tgid} parent=({parent_pid},{parent_tgid}) ts={timestamp_ns}"
                )
            }
            ProcEvent::Unknown { what, raw_data } => {
                write!(f, "UNKNOWN what=0x{what:08x} len={}", raw_data.len())
            }
        }
    }
}
