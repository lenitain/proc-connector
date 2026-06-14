//! Kernel constants for the Linux Process Event Connector.
//!
//! All values are derived from Linux kernel headers:
//! - `<linux/netlink.h>`
//! - `<linux/connector.h>`
//! - `<linux/cn_proc.h>`

// ---------------------------------------------------------------------------
// Netlink protocol constants
// ---------------------------------------------------------------------------

/// Netlink protocol family for the Connector.
pub const NETLINK_CONNECTOR: i32 = 11;

// NLMSG_* message types
/// No-operation message type (ignored by netlink).
pub const NLMSG_NOOP: u16 = 1;
/// Error message type: contains `nlmsgerr` struct.
pub const NLMSG_ERROR: u16 = 2;
/// Done message type: marks the end of a multi-part message.
pub const NLMSG_DONE: u16 = 3;
/// Overrun message type: data was lost due to buffer overflow.
pub const NLMSG_OVERRUN: u16 = 4;
/// Minimum valid message type for application-specific messages.
pub const NLMSG_MIN_TYPE: u16 = 16;

/// Alignment boundary for netlink message headers (4 bytes).
pub const NLMSG_ALIGNTO: usize = 4;

/// Round `len` up to the nearest multiple of `NLMSG_ALIGNTO`.
#[inline]
pub const fn nlmsg_align(len: usize) -> usize {
    (len + NLMSG_ALIGNTO - 1) & !(NLMSG_ALIGNTO - 1)
}

/// Total header length of `nlmsghdr` after alignment.
#[inline]
pub const fn nlmsg_hdrlen() -> usize {
    nlmsg_align(size_of_nlmsghdr())
}

/// Full message length: `len` bytes of payload plus aligned header.
#[inline]
pub const fn nlmsg_length(len: usize) -> usize {
    len + nlmsg_hdrlen()
}

/// Size of `struct nlmsghdr` in bytes (without alignment).
pub const SIZE_NLMSGHDR: usize = 16;

#[inline]
const fn size_of_nlmsghdr() -> usize {
    SIZE_NLMSGHDR
}

// Netlink socket options
/// Socket option to disable `ENOBUFS` errors on recv.
pub const NETLINK_NO_ENOBUFS: i32 = 5;

// NLM_F flags
/// Netlink message flag: this is a request message.
pub const NLM_F_REQUEST: u16 = 1;

// ---------------------------------------------------------------------------
// Connector constants
// ---------------------------------------------------------------------------

/// Connector index for process events.
pub const CN_IDX_PROC: u32 = 1;
/// Connector value for process events.
pub const CN_VAL_PROC: u32 = 1;

/// Multicast operation: start listening.
pub const PROC_CN_MCAST_LISTEN: u32 = 1;
/// Multicast operation: stop listening.
pub const PROC_CN_MCAST_IGNORE: u32 = 2;

/// Size of `struct cn_msg` header (excluding flexible `data` array).
pub const SIZE_CN_MSG: usize = 20;

/// Maximum message size for the connector protocol.
pub const CONNECTOR_MAX_MSG_SIZE: usize = 16384;

// ---------------------------------------------------------------------------
// Process event constants
// ---------------------------------------------------------------------------

/// A process was forked.
pub const PROC_EVENT_FORK: u32 = 0x00000001;
/// A process executed a new program (exec).
pub const PROC_EVENT_EXEC: u32 = 0x00000002;
/// Real/effective UID changed.
pub const PROC_EVENT_UID: u32 = 0x00000004;
/// Real/effective GID changed.
pub const PROC_EVENT_GID: u32 = 0x00000040;
/// Session ID changed.
pub const PROC_EVENT_SID: u32 = 0x00000080;
/// ptrace attach/detach.
pub const PROC_EVENT_PTRACE: u32 = 0x00000100;
/// Process name (comm) changed.
pub const PROC_EVENT_COMM: u32 = 0x00000200;
/// Process dumped core.
pub const PROC_EVENT_COREDUMP: u32 = 0x40000000;
/// Process exited.
pub const PROC_EVENT_EXIT: u32 = 0x80000000;

// ---------------------------------------------------------------------------
// proc_event struct layout helpers
// ---------------------------------------------------------------------------

/// Offset from `proc_event` base to `event_data` union.
///
/// `proc_event` layout:
///   - `what` (u32, 4 bytes)
///   - `cpu` (u32, 4 bytes)
///   - `timestamp_ns` (u64, 8 bytes)
///   - `event_data` (union, varies)
pub const PROC_EVENT_HEADER_SIZE: usize = 16;

/// Per-event sub-structure sizes (all within the `event_data` union):
/// Size of fork event data (4 × i32: parent_pid, parent_tgid, child_pid, child_tgid).
pub const SIZE_FORK_EVENT: usize = 16;
/// Size of exec event data (2 × i32: pid, tgid).
pub const SIZE_EXEC_EVENT: usize = 8;
/// Size of uid/gid event data (2 × i32 + ruid/rgid union + euid/egid union).
pub const SIZE_ID_EVENT: usize = 16;
/// Size of session ID event data (2 × i32: pid, tgid).
pub const SIZE_SID_EVENT: usize = 8;
/// Size of ptrace event data (4 × i32: pid, tgid, tracer_pid, tracer_tgid).
pub const SIZE_PTRACE_EVENT: usize = 16;
/// Size of comm event data (2 × i32 + char\[16\]: pid, tgid, comm).
pub const SIZE_COMM_EVENT: usize = 24;
/// Size of coredump event data (4 × i32: pid, tgid, parent_pid, parent_tgid).
pub const SIZE_COREDUMP_EVENT: usize = 16;
/// Size of exit event data (4 × i32 + u32 + u32: pid, tgid, exit_code, exit_signal, parent_pid, parent_tgid).
pub const SIZE_EXIT_EVENT: usize = 24;

// ---------------------------------------------------------------------------
// proc_event sub-struct field offsets (relative to event_data union base)
// ---------------------------------------------------------------------------

// --- fork ---
/// Offset to parent PID in fork event data.
pub const FORK_PARENT_PID: usize = 0;
/// Offset to parent TGID in fork event data.
pub const FORK_PARENT_TGID: usize = 4;
/// Offset to child PID in fork event data.
pub const FORK_CHILD_PID: usize = 8;
/// Offset to child TGID in fork event data.
pub const FORK_CHILD_TGID: usize = 12;

// --- exec ---
/// Offset to PID in exec event data.
pub const EXEC_PID: usize = 0;
/// Offset to TGID in exec event data.
pub const EXEC_TGID: usize = 4;

// --- id (uid/gid share same layout) ---
/// Offset to PID in uid/gid event data.
pub const ID_PID: usize = 0;
/// Offset to TGID in uid/gid event data.
pub const ID_TGID: usize = 4;
/// Offset to real UID/GID in uid/gid event data.
pub const ID_RUID_RGID: usize = 8;
/// Offset to effective UID/GID in uid/gid event data.
pub const ID_EUID_EGID: usize = 12;

// --- sid ---
/// Offset to PID in session ID event data.
pub const SID_PID: usize = 0;
/// Offset to TGID in session ID event data.
pub const SID_TGID: usize = 4;

// --- ptrace ---
/// Offset to PID in ptrace event data.
pub const PTRACE_PID: usize = 0;
/// Offset to TGID in ptrace event data.
pub const PTRACE_TGID: usize = 4;
/// Offset to tracer PID in ptrace event data.
pub const PTRACE_TRACER_PID: usize = 8;
/// Offset to tracer TGID in ptrace event data.
pub const PTRACE_TRACER_TGID: usize = 12;

// --- comm ---
/// Offset to PID in comm event data.
pub const COMM_PID: usize = 0;
/// Offset to TGID in comm event data.
pub const COMM_TGID: usize = 4;
/// Offset to comm string (16 bytes) in comm event data.
pub const COMM_DATA: usize = 8;

// --- coredump ---
/// Offset to PID in coredump event data.
pub const COREDUMP_PID: usize = 0;
/// Offset to TGID in coredump event data.
pub const COREDUMP_TGID: usize = 4;
/// Offset to parent PID in coredump event data.
pub const COREDUMP_PARENT_PID: usize = 8;
/// Offset to parent TGID in coredump event data.
pub const COREDUMP_PARENT_TGID: usize = 12;

// --- exit ---
/// Offset to PID in exit event data.
pub const EXIT_PID: usize = 0;
/// Offset to TGID in exit event data.
pub const EXIT_TGID: usize = 4;
/// Offset to exit code in exit event data.
pub const EXIT_CODE: usize = 8;
/// Offset to exit signal in exit event data.
pub const EXIT_SIGNAL: usize = 12;
/// Offset to parent PID in exit event data.
pub const EXIT_PARENT_PID: usize = 16;
/// Offset to parent TGID in exit event data.
pub const EXIT_PARENT_TGID: usize = 20;
