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
/// let exec = ProcEvent::Exec { pid: 42, tgid: 42, timestamp_ns: 0 };
/// assert_eq!(describe(&exec), "process 42 exec'd");
///
/// let exit = ProcEvent::Exit { pid: 7, tgid: 7, exit_code: 0, exit_signal: 17, timestamp_ns: 0 };
/// assert_eq!(describe(&exit), "process 7 exited with code 0");
/// ```
///
/// # Example: Display formatting
///
/// ```
/// use proc_connector::ProcEvent;
///
/// let event = ProcEvent::Fork {
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
        pid: u32,
        tgid: u32,
        /// Kernel timestamp (nanoseconds since boot).
        timestamp_ns: u64,
    },
    /// A new process was created via `fork`/`clone`.
    Fork {
        parent_pid: u32,
        parent_tgid: u32,
        child_pid: u32,
        child_tgid: u32,
        /// Kernel timestamp (nanoseconds since boot).
        timestamp_ns: u64,
    },
    /// A process exited.
    Exit {
        pid: u32,
        tgid: u32,
        exit_code: u32,
        exit_signal: u32,
        /// Kernel timestamp (nanoseconds since boot).
        timestamp_ns: u64,
    },
    /// Real or effective UID changed.
    Uid {
        pid: u32,
        tgid: u32,
        ruid: u32,
        euid: u32,
        /// Kernel timestamp (nanoseconds since boot).
        timestamp_ns: u64,
    },
    /// Real or effective GID changed.
    Gid {
        pid: u32,
        tgid: u32,
        rgid: u32,
        egid: u32,
        /// Kernel timestamp (nanoseconds since boot).
        timestamp_ns: u64,
    },
    /// Session ID changed (`setsid`).
    Sid {
        pid: u32,
        tgid: u32,
        /// Kernel timestamp (nanoseconds since boot).
        timestamp_ns: u64,
    },
    /// `ptrace` attach or detach.
    Ptrace {
        pid: u32,
        tgid: u32,
        tracer_pid: u32,
        tracer_tgid: u32,
        /// Kernel timestamp (nanoseconds since boot).
        timestamp_ns: u64,
    },
    /// Process name (`comm`) changed (max 16 bytes, may include trailing NUL).
    Comm {
        pid: u32,
        tgid: u32,
        /// The new process name (up to 16 bytes, usually NUL-terminated).
        comm: [u8; 16],
        /// Kernel timestamp (nanoseconds since boot).
        timestamp_ns: u64,
    },
    /// A core dump occurred.
    Coredump {
        pid: u32,
        tgid: u32,
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

impl fmt::Display for ProcEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProcEvent::Exec {
                pid,
                tgid,
                timestamp_ns,
            } => write!(f, "EXEC pid={pid} tgid={tgid} ts={timestamp_ns}"),
            ProcEvent::Fork {
                parent_pid,
                parent_tgid,
                child_pid,
                child_tgid,
                timestamp_ns,
            } => write!(
                f,
                "FORK parent=({parent_pid},{parent_tgid}) child=({child_pid},{child_tgid}) ts={timestamp_ns}"
            ),
            ProcEvent::Exit {
                pid,
                tgid,
                exit_code,
                exit_signal,
                timestamp_ns,
            } => write!(
                f,
                "EXIT pid={pid} tgid={tgid} code={exit_code} signal={exit_signal} ts={timestamp_ns}"
            ),
            ProcEvent::Uid {
                pid,
                tgid,
                ruid,
                euid,
                timestamp_ns,
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
            } => write!(
                f,
                "GID pid={pid} tgid={tgid} rgid={rgid} egid={egid} ts={timestamp_ns}"
            ),
            ProcEvent::Sid {
                pid,
                tgid,
                timestamp_ns,
            } => write!(f, "SID pid={pid} tgid={tgid} ts={timestamp_ns}"),
            ProcEvent::Ptrace {
                pid,
                tgid,
                tracer_pid,
                tracer_tgid,
                timestamp_ns,
            } => write!(
                f,
                "PTRACE pid={pid} tgid={tgid} tracer=({tracer_pid},{tracer_tgid}) ts={timestamp_ns}"
            ),
            ProcEvent::Comm {
                pid,
                tgid,
                comm,
                timestamp_ns,
            } => {
                // Find NUL terminator for clean display
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
                timestamp_ns,
            } => {
                write!(f, "COREDUMP pid={pid} tgid={tgid} ts={timestamp_ns}")
            }
            ProcEvent::Unknown { what, raw_data } => {
                write!(f, "UNKNOWN what=0x{what:08x} len={}", raw_data.len())
            }
        }
    }
}
