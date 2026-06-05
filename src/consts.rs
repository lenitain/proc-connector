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
pub const NLMSG_NOOP: u16 = 1;
pub const NLMSG_ERROR: u16 = 2;
pub const NLMSG_DONE: u16 = 3;
pub const NLMSG_OVERRUN: u16 = 4;
/// Minimum valid message type for application-specific messages.
pub const NLMSG_MIN_TYPE: u16 = 16;

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
pub const NETLINK_NO_ENOBUFS: i32 = 5;

// NLM_F flags
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
pub const SIZE_FORK_EVENT: usize = 16; // 4 × i32 (pid/tgid)
pub const SIZE_EXEC_EVENT: usize = 8; // 2 × i32
pub const SIZE_ID_EVENT: usize = 16; // 2 × i32 + ruid/rgid(union) + euid/egid(union)
pub const SIZE_SID_EVENT: usize = 8; // 2 × i32
pub const SIZE_PTRACE_EVENT: usize = 16; // 4 × i32
pub const SIZE_COMM_EVENT: usize = 24; // 2 × i32 + char[16]
pub const SIZE_COREDUMP_EVENT: usize = 16; // 4 × i32
pub const SIZE_EXIT_EVENT: usize = 24; // 4 × i32 + u32 + u32

// ---------------------------------------------------------------------------
// proc_event sub-struct field offsets (relative to event_data union base)
// ---------------------------------------------------------------------------

// --- fork ---
pub const FORK_PARENT_PID: usize = 0;
pub const FORK_PARENT_TGID: usize = 4;
pub const FORK_CHILD_PID: usize = 8;
pub const FORK_CHILD_TGID: usize = 12;

// --- exec ---
pub const EXEC_PID: usize = 0;
pub const EXEC_TGID: usize = 4;

// --- id (uid/gid share same layout) ---
pub const ID_PID: usize = 0;
pub const ID_TGID: usize = 4;
pub const ID_RUID_RGID: usize = 8;
pub const ID_EUID_EGID: usize = 12;

// --- sid ---
pub const SID_PID: usize = 0;
pub const SID_TGID: usize = 4;

// --- ptrace ---
pub const PTRACE_PID: usize = 0;
pub const PTRACE_TGID: usize = 4;
pub const PTRACE_TRACER_PID: usize = 8;
pub const PTRACE_TRACER_TGID: usize = 12;

// --- comm ---
pub const COMM_PID: usize = 0;
pub const COMM_TGID: usize = 4;
pub const COMM_DATA: usize = 8;

// --- coredump ---
pub const COREDUMP_PID: usize = 0;
pub const COREDUMP_TGID: usize = 4;
pub const COREDUMP_PARENT_PID: usize = 8;
pub const COREDUMP_PARENT_TGID: usize = 12;

// --- exit ---
pub const EXIT_PID: usize = 0;
pub const EXIT_TGID: usize = 4;
pub const EXIT_CODE: usize = 8;
pub const EXIT_SIGNAL: usize = 12;
pub const EXIT_PARENT_PID: usize = 16;
pub const EXIT_PARENT_TGID: usize = 20;
