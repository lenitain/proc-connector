//! Netlink message iterator for multi-part messages.
//!
//! This module contains the `NetlinkMessageIter` struct for iterating
//! over multiple netlink messages packed into a single receive buffer.

use crate::consts::*;
use crate::error::{Error, Result};
use crate::parse::parse_netlink_message;
use crate::proc_event::ProcEvent;

/// Iterator over multiple netlink messages packed into a single receive buffer.
///
/// The netlink protocol can deliver multiple messages in one `recv` call
/// (multi-part messages). This iterator handles walking through them.
///
/// # Example
///
/// ```no_run
/// use proc_connector::{ProcConnector, NetlinkMessageIter};
///
/// let conn = ProcConnector::new().unwrap();
/// let mut buf = vec![0u8; 4096];
/// let n = conn.recv_raw(&mut buf).unwrap();
///
/// for msg in NetlinkMessageIter::new(&buf, n) {
///     match msg {
///         Ok(Some(event)) => println!("{event}"),
///         Ok(None) => continue, // control message
///         Err(e) => eprintln!("error: {e}"),
///     }
/// }
/// ```
pub struct NetlinkMessageIter<'a> {
    buf: &'a [u8],
    pos: usize,
    len: usize,
}

impl<'a> NetlinkMessageIter<'a> {
    /// Create a new iterator over `len` bytes starting at `buf`.
    ///
    /// # Example
    ///
    /// ```
    /// use proc_connector::NetlinkMessageIter;
    ///
    /// let buf = vec![0u8; 4096];
    /// let iter = NetlinkMessageIter::new(&buf, 0);
    /// assert_eq!(iter.count(), 0);
    /// ```
    pub fn new(buf: &'a [u8], len: usize) -> Self {
        NetlinkMessageIter { buf, pos: 0, len }
    }
}

impl<'a> Iterator for NetlinkMessageIter<'a> {
    type Item = Result<Option<ProcEvent>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.len {
            return None;
        }

        let remaining = self.len - self.pos;
        if remaining < SIZE_NLMSGHDR {
            return Some(Err(Error::Truncated));
        }

        let nlmsg_len = read_u32(&self.buf[self.pos..], 0) as usize;
        if nlmsg_len < SIZE_NLMSGHDR || nlmsg_len > remaining {
            return Some(Err(Error::Truncated));
        }

        let msg_slice = &self.buf[self.pos..self.pos + nlmsg_len];
        let nlmsg_type = read_u16(msg_slice, 4);

        // Check for end of multi-part message.
        // Kernel connector protocol uses NLMSG_DONE as the message type for
        // ALL data messages (including proc events). A true multi-part DONE
        // has no payload (nlmsg_len == SIZE_NLMSGHDR), while connector data
        // messages have a cn_msg payload (nlmsg_len > SIZE_NLMSGHDR).
        if nlmsg_type == NLMSG_DONE && nlmsg_len == SIZE_NLMSGHDR {
            self.pos = self.len; // consume all remaining
            return None; // Done is not an event, stop iteration
        }

        // Parse this single message
        let result = parse_netlink_message(msg_slice, nlmsg_len);

        // Advance position (aligned)
        self.pos += nlmsg_align(nlmsg_len);

        Some(result)
    }
}

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
