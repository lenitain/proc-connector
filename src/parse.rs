//! Netlink message parsing for process events.
//!
//! This module contains the parsing logic for netlink messages,
//! including `parse_netlink_message`, `parse_cn_msg`, and `parse_proc_event`.

use crate::consts::*;
use crate::error::{Error, Result};
use crate::proc_event::ProcEvent;

// ---------------------------------------------------------------------------
// Wire format helpers (private)
// ---------------------------------------------------------------------------

/// Read a `u32` from a byte slice at a given offset (native endian).
#[inline]
fn read_u32(buf: &[u8], off: usize) -> u32 {
    let arr: [u8; 4] = buf[off..off + 4].try_into().unwrap();
    u32::from_ne_bytes(arr)
}

/// Read a `u16` from a byte slice at a given offset (native endian).
#[inline]
fn read_u16(buf: &[u8], off: usize) -> u16 {
    let arr: [u8; 2] = buf[off..off + 2].try_into().unwrap();
    u16::from_ne_bytes(arr)
}

/// Read an `i32` from a byte slice at a given offset (native endian).
#[inline]
fn read_i32(buf: &[u8], off: usize) -> i32 {
    let arr: [u8; 4] = buf[off..off + 4].try_into().unwrap();
    i32::from_ne_bytes(arr)
}

/// Read a `u64` from a byte slice at a given offset (native endian).
#[inline]
fn read_u64(buf: &[u8], off: usize) -> u64 {
    let arr: [u8; 8] = buf[off..off + 8].try_into().unwrap();
    u64::from_ne_bytes(arr)
}

// ---------------------------------------------------------------------------
// Parsing entry point
// ---------------------------------------------------------------------------

/// Parse a single netlink message payload (starting after `nlmsghdr`) into
/// a `ProcEvent`.
///
/// `payload` is the full received buffer starting at the `nlmsghdr`.
/// `len` is the number of valid bytes in `payload`.
///
/// This function handles:
/// - `NLMSG_NOOP` → `None` (caller should continue reading)
/// - `NLMSG_DONE` (with no payload, i.e., true multi-part terminator) → `None`
///   Note: the kernel connector protocol uses `NLMSG_DONE` with a payload for all
///   data messages, so only 16-byte `NLMSG_DONE` is treated as a control message.
/// - `NLMSG_ERROR` → `Err`
/// - `NLMSG_OVERRUN` → `Err(Overrun)`
/// - `NLMSG_DATA` + valid `cn_msg` + `proc_event` → `Some(ProcEvent)`
///
/// # Example
///
/// ```
/// use proc_connector::{parse_netlink_message, Error};
///
/// // Too short → Truncated
/// let buf = [0u8; 4];
/// assert!(matches!(parse_netlink_message(&buf, 4), Err(Error::Truncated)));
///
/// // NLMSG_NOOP → None
/// let mut buf = [0u8; 16];
/// buf[0..4].copy_from_slice(&16u32.to_ne_bytes()); // nlmsg_len
/// buf[4..6].copy_from_slice(&1u16.to_ne_bytes());   // nlmsg_type = NLMSG_NOOP
/// assert!(parse_netlink_message(&buf, 16).unwrap().is_none());
/// ```
pub fn parse_netlink_message(payload: &[u8], len: usize) -> Result<Option<ProcEvent>> {
    if len > payload.len() {
        return Err(Error::Truncated);
    }
    let payload = &payload[..len];

    if payload.len() < SIZE_NLMSGHDR {
        return Err(Error::Truncated);
    }

    let nlmsg_type = read_u16(payload, 4);
    let nlmsg_len = read_u32(payload, 0) as usize;

    if nlmsg_len > payload.len() {
        return Err(Error::Truncated);
    }

    match nlmsg_type {
        NLMSG_NOOP => Ok(None),
        NLMSG_DONE if nlmsg_len == SIZE_NLMSGHDR => Ok(None),
        NLMSG_ERROR => {
            if payload.len() < SIZE_NLMSGERR {
                return Err(Error::Truncated);
            }
            let errno = read_i32(payload, SIZE_NLMSGHDR);
            if errno == 0 {
                // ACK (error == 0 means success), ignore
                return Ok(None);
            }
            // Kernel stores errno as negative (e.g. -EPERM = -1).
            // std::io::Error::from_raw_os_error expects positive values.
            let pos_errno = errno.checked_neg().unwrap_or(errno);
            Err(Error::Os(std::io::Error::from_raw_os_error(pos_errno)))
        }
        NLMSG_OVERRUN => Err(Error::Overrun),
        _ => {
            // Normal data message: parse cn_msg + proc_event.
            // Payload starts after nlmsghdr.
            let cn_offset = nlmsg_hdrlen();
            if nlmsg_len < cn_offset {
                return Err(Error::Truncated);
            }
            let cn_payload = &payload[cn_offset..nlmsg_len];
            parse_cn_msg(cn_payload).map(Some)
        }
    }
}

/// Parse a `cn_msg` payload (starting from `cb_id`) into a `ProcEvent`.
///
/// # Example
///
/// ```
/// use proc_connector::{parse_cn_msg, Error};
///
/// // Too short → Truncated
/// let buf = [0u8; 10];
/// assert!(matches!(parse_cn_msg(&buf), Err(Error::Truncated)));
///
/// // Wrong connector index → UnexpectedConnector
/// let mut buf = [0u8; 20];
/// buf[0..4].copy_from_slice(&999u32.to_ne_bytes()); // wrong idx
/// assert!(matches!(parse_cn_msg(&buf), Err(Error::UnexpectedConnector)));
/// ```
pub fn parse_cn_msg(buf: &[u8]) -> Result<ProcEvent> {
    if buf.len() < SIZE_CN_MSG {
        return Err(Error::Truncated);
    }

    let idx = read_u32(buf, 0);
    let val = read_u32(buf, 4);

    // Only handle proc events
    if idx != CN_IDX_PROC || val != CN_VAL_PROC {
        return Err(Error::UnexpectedConnector);
    }

    let data_len = read_u16(buf, 16) as usize;

    // proc_event data starts at offset 20 (after fixed cn_msg header)
    let proc_off = SIZE_CN_MSG;
    let proc_data = if buf.len() >= proc_off + data_len {
        &buf[proc_off..proc_off + data_len]
    } else {
        return Err(Error::Truncated);
    };

    parse_proc_event(proc_data)
}

/// Parse a `proc_event` struct into a `ProcEvent` enum.
fn parse_proc_event(buf: &[u8]) -> Result<ProcEvent> {
    if buf.len() < PROC_EVENT_HEADER_SIZE {
        return Err(Error::Truncated);
    }

    let what = read_u32(buf, 0);
    let cpu = read_u32(buf, 4);
    let timestamp_ns = read_u64(buf, 8);
    let data = &buf[PROC_EVENT_HEADER_SIZE..];

    build_proc_event(what, cpu, timestamp_ns, data)
}

fn build_proc_event(what: u32, cpu: u32, timestamp_ns: u64, data: &[u8]) -> Result<ProcEvent> {
    match what {
        PROC_EVENT_EXEC => {
            if data.len() < SIZE_EXEC_EVENT {
                return Err(Error::Truncated);
            }
            Ok(ProcEvent::Exec {
                cpu,
                pid: read_i32(data, EXEC_PID) as u32,
                tgid: read_i32(data, EXEC_TGID) as u32,
                timestamp_ns,
            })
        }

        PROC_EVENT_FORK => {
            if data.len() < SIZE_FORK_EVENT {
                return Err(Error::Truncated);
            }
            Ok(ProcEvent::Fork {
                cpu,
                parent_pid: read_i32(data, FORK_PARENT_PID) as u32,
                parent_tgid: read_i32(data, FORK_PARENT_TGID) as u32,
                child_pid: read_i32(data, FORK_CHILD_PID) as u32,
                child_tgid: read_i32(data, FORK_CHILD_TGID) as u32,
                timestamp_ns,
            })
        }

        PROC_EVENT_EXIT => {
            if data.len() < SIZE_EXIT_EVENT {
                return Err(Error::Truncated);
            }
            Ok(ProcEvent::Exit {
                cpu,
                pid: read_i32(data, EXIT_PID) as u32,
                tgid: read_i32(data, EXIT_TGID) as u32,
                exit_code: read_u32(data, EXIT_CODE),
                exit_signal: read_u32(data, EXIT_SIGNAL),
                parent_pid: read_i32(data, EXIT_PARENT_PID) as u32,
                parent_tgid: read_i32(data, EXIT_PARENT_TGID) as u32,
                timestamp_ns,
            })
        }

        PROC_EVENT_UID => {
            if data.len() < SIZE_ID_EVENT {
                return Err(Error::Truncated);
            }
            Ok(ProcEvent::Uid {
                cpu,
                pid: read_i32(data, ID_PID) as u32,
                tgid: read_i32(data, ID_TGID) as u32,
                ruid: read_u32(data, ID_RUID_RGID),
                euid: read_u32(data, ID_EUID_EGID),
                timestamp_ns,
            })
        }

        PROC_EVENT_GID => {
            if data.len() < SIZE_ID_EVENT {
                return Err(Error::Truncated);
            }
            Ok(ProcEvent::Gid {
                cpu,
                pid: read_i32(data, ID_PID) as u32,
                tgid: read_i32(data, ID_TGID) as u32,
                rgid: read_u32(data, ID_RUID_RGID),
                egid: read_u32(data, ID_EUID_EGID),
                timestamp_ns,
            })
        }

        PROC_EVENT_SID => {
            if data.len() < SIZE_SID_EVENT {
                return Err(Error::Truncated);
            }
            Ok(ProcEvent::Sid {
                cpu,
                pid: read_i32(data, SID_PID) as u32,
                tgid: read_i32(data, SID_TGID) as u32,
                timestamp_ns,
            })
        }

        PROC_EVENT_PTRACE => {
            if data.len() < SIZE_PTRACE_EVENT {
                return Err(Error::Truncated);
            }
            Ok(ProcEvent::Ptrace {
                cpu,
                pid: read_i32(data, PTRACE_PID) as u32,
                tgid: read_i32(data, PTRACE_TGID) as u32,
                tracer_pid: read_i32(data, PTRACE_TRACER_PID) as u32,
                tracer_tgid: read_i32(data, PTRACE_TRACER_TGID) as u32,
                timestamp_ns,
            })
        }

        PROC_EVENT_COMM => {
            if data.len() < SIZE_COMM_EVENT {
                return Err(Error::Truncated);
            }
            let mut comm = [0u8; 16];
            comm.copy_from_slice(&data[COMM_DATA..COMM_DATA + 16]);
            Ok(ProcEvent::Comm {
                cpu,
                pid: read_i32(data, COMM_PID) as u32,
                tgid: read_i32(data, COMM_TGID) as u32,
                comm,
                timestamp_ns,
            })
        }

        PROC_EVENT_COREDUMP => {
            if data.len() < SIZE_COREDUMP_EVENT {
                return Err(Error::Truncated);
            }
            Ok(ProcEvent::Coredump {
                cpu,
                pid: read_i32(data, COREDUMP_PID) as u32,
                tgid: read_i32(data, COREDUMP_TGID) as u32,
                parent_pid: read_i32(data, COREDUMP_PARENT_PID) as u32,
                parent_tgid: read_i32(data, COREDUMP_PARENT_TGID) as u32,
                timestamp_ns,
            })
        }

        _ => Ok(ProcEvent::Unknown {
            what,
            raw_data: data.to_vec(),
        }),
    }
}

// ---------------------------------------------------------------------------
// Convenience: find first event from a buffer
// ---------------------------------------------------------------------------

/// Find the first real event from a buffer.
pub fn first_event_from_buf(buf: &[u8], n: usize) -> Result<Option<ProcEvent>> {
    let iter = crate::iter::NetlinkMessageIter::new(buf, n);
    for msg in iter {
        match msg? {
            Some(event) => return Ok(Some(event)),
            None => continue,
        }
    }
    Ok(None)
}
