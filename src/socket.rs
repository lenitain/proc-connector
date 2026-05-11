//! Core `ProcConnector` type — safe wrapper around a Linux Netlink Proc Connector socket.
//!
//! # Lifecycle
//!
//! 1. `ProcConnector::new()` — creates the netlink socket, binds to `CN_IDX_PROC`, subscribes.
//! 2. `recv()` / `recv_timeout()` — receive and parse process events.
//! 3. `unsubscribe()` / `subscribe()` — toggle subscription (useful after reconnect).
//! 4. Drop — automatically unsubscribes and closes the socket.

use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::time::Duration;

use crate::consts::*;
use crate::error::{Error, Result};

/// A safe handle to a Linux Netlink Proc Connector socket.
///
/// The socket is created, bound, and subscribed in `new()`. On drop, the
/// subscription is cancelled and the file descriptor is closed automatically.
///
/// # Examples
///
/// ```no_run
/// use proc_connector::ProcConnector;
///
/// let conn = ProcConnector::new().unwrap();
/// let mut buf = vec![0u8; 4096];
///
/// loop {
///     match conn.recv(&mut buf) {
///         Ok(event) => println!("got event: {event:?}"),
///         Err(e) => eprintln!("error: {e}"),
///     }
/// }
/// ```
pub struct ProcConnector {
    fd: OwnedFd,
}

impl ProcConnector {
    /// Create a new `ProcConnector`.
    ///
    /// This is a convenience constructor that:
    /// 1. Creates a `PF_NETLINK` / `SOCK_DGRAM` socket of family `NETLINK_CONNECTOR`.
    /// 2. Binds to the `CN_IDX_PROC` multicast group.
    /// 3. Sends a `PROC_CN_MCAST_LISTEN` subscription message.
    ///
    /// # Errors
    ///
    /// Returns `Error::Os` if any system call fails.
    pub fn new() -> Result<Self> {
        let fd = create_socket()?;
        let connector = Self { fd };
        connector.bind()?;
        connector.subscribe()?;
        Ok(connector)
    }

    /// Bind the socket to the `CN_IDX_PROC` netlink group.
    fn bind(&self) -> Result<()> {
        let mut sa: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        sa.nl_family = libc::AF_NETLINK as u16;
        // nl_pad left as zeroed
        sa.nl_pid = 0; // let kernel pick a port ID
        sa.nl_groups = CN_IDX_PROC;

        let ret = unsafe {
            libc::bind(
                self.fd.as_raw_fd(),
                &sa as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as u32,
            )
        };

        if ret < 0 {
            return Err(Error::Os(std::io::Error::last_os_error()));
        }
        Ok(())
    }

        /// (Re-)subscribe to process events.
    ///
    /// Sends a `PROC_CN_MCAST_LISTEN` message via the netlink socket.
    /// This is safe to call multiple times (e.g. after a reconnection).
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use proc_connector::ProcConnector;
    /// let mut conn = ProcConnector::new().unwrap();
    /// conn.subscribe().expect("subscribe");
    /// ```
    pub fn subscribe(&self) -> Result<()> {
        self.send_mcast_op(PROC_CN_MCAST_LISTEN)
    }

    /// Unsubscribe from process events.
    ///
    /// Sends a `PROC_CN_MCAST_IGNORE` message. Automatically called on drop.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use proc_connector::ProcConnector;
    /// let conn = ProcConnector::new().unwrap();
    /// conn.unsubscribe().expect("unsubscribe");
    /// // Re-subscribe later:
    /// conn.subscribe().expect("re-subscribe");
    /// ```
    pub fn unsubscribe(&self) -> Result<()> {
        self.send_mcast_op(PROC_CN_MCAST_IGNORE)
    }

    /// Send a `proc_cn_mcast_op` command to the kernel.
    fn send_mcast_op(&self, op: u32) -> Result<()> {
        let nlmsg_payload_len = SIZE_CN_MSG + std::mem::size_of::<u32>();
        let nlmsg_len = nlmsg_length(nlmsg_payload_len);

        let mut buf = vec![0u8; nlmsg_len];
        let pid = std::process::id();

        // --- nlmsghdr (16 bytes, little-endian wire format) ---
        let hdr = &mut buf[..SIZE_NLMSGHDR];
        hdr[0..4].copy_from_slice(&(nlmsg_len as u32).to_ne_bytes()); // nlmsg_len
        hdr[4..6].copy_from_slice(&NLMSG_MIN_TYPE.to_ne_bytes());      // nlmsg_type (≥ 16 = application-defined)
        hdr[6..8].copy_from_slice(&NLM_F_REQUEST.to_ne_bytes());      // nlmsg_flags (request)
        hdr[8..12].copy_from_slice(&0u32.to_ne_bytes());              // nlmsg_seq
        hdr[12..16].copy_from_slice(&pid.to_ne_bytes());              // nlmsg_pid

        // --- cn_msg (20 bytes header + op payload) ---
        let cn_off = nlmsg_hdrlen();
        let cn = &mut buf[cn_off..cn_off + SIZE_CN_MSG + std::mem::size_of::<u32>()];
        // id.idx
        cn[0..4].copy_from_slice(&CN_IDX_PROC.to_ne_bytes());
        // id.val
        cn[4..8].copy_from_slice(&CN_VAL_PROC.to_ne_bytes());
        // seq
        cn[8..12].copy_from_slice(&0u32.to_ne_bytes());
        // ack
        cn[12..16].copy_from_slice(&0u32.to_ne_bytes());
        // len (u16) = sizeof(proc_cn_mcast_op) = 4
        cn[16..18]
            .copy_from_slice(&(std::mem::size_of::<u32>() as u16).to_ne_bytes());
        // flags
        cn[18..20].copy_from_slice(&0u16.to_ne_bytes());
        // data = proc_cn_mcast_op
        cn[20..24].copy_from_slice(&op.to_ne_bytes());

        let iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: nlmsg_len,
        };

        let msg_hdr = libc::msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: &iov as *const libc::iovec as *mut libc::iovec,
            msg_iovlen: 1,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };

        let ret = unsafe { libc::sendmsg(self.fd.as_raw_fd(), &msg_hdr, 0) };
        if ret < 0 {
            return Err(Error::Os(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Receive a raw netlink message into `buf`.
    ///
    /// On success returns the number of bytes written to `buf`.
    ///
    /// This is a thin wrapper around `recv(2)`. The caller is responsible
    /// for providing a sufficiently large buffer (a page size, 4096 bytes,
    /// is a safe default).
    ///
    /// # Errors
    ///
    /// - `Interrupted` if `EINTR` — retry the call.
    /// - `ConnectionClosed` if recv returns 0.
    /// - `Os` for other system call errors.
    pub fn recv_raw(&self, buf: &mut [u8]) -> Result<usize> {
        let len = unsafe {
            libc::recv(
                self.fd.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
            )
        };

        if len < 0 {
            let err = std::io::Error::last_os_error();
            return match err.raw_os_error() {
                Some(libc::EINTR) => Err(Error::Interrupted),
                Some(libc::EAGAIN) => Err(Error::WouldBlock), // EWOULDBLOCK == EAGAIN on Linux
                _ => Err(Error::Os(err)),
            };
        }

        if len == 0 {
            return Err(Error::ConnectionClosed);
        }

        Ok(len as usize)
    }

    /// Receive a raw netlink message with a timeout.
    ///
    /// Returns `Ok(None)` if the timeout expires before data is available.
    /// Otherwise behaves the same as `recv_raw`.
    ///
    /// Uses `poll(2)` internally and only calls `recv` when data is ready.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use proc_connector::ProcConnector;
    /// # use std::time::Duration;
    /// let conn = ProcConnector::new().unwrap();
    /// let mut buf = vec![0u8; 4096];
    ///
    /// match conn.recv_timeout(&mut buf, Duration::from_secs(5)) {
    ///     Ok(Some(event)) => println!("{event}"),
    ///     Ok(None) => eprintln!("timeout, no event in 5s"),
    ///     Err(e) => eprintln!("error: {e}"),
    /// }
    /// ```
    pub fn recv_raw_timeout(&self, buf: &mut [u8], timeout: Duration) -> Result<Option<usize>> {
        let poll_fd = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };

        let timeout_ms = timeout
            .as_millis()
            .try_into()
            .unwrap_or(libc::c_int::MAX);

        let ret = unsafe { libc::poll(&poll_fd as *const libc::pollfd as *mut _, 1, timeout_ms) };

        if ret < 0 {
            let err = std::io::Error::last_os_error();
            return match err.raw_os_error() {
                Some(libc::EINTR) => Err(Error::Interrupted),
                _ => Err(Error::Os(err)),
            };
        }

        if ret == 0 {
            return Ok(None);
        }

        // recv_raw may return WouldBlock if the fd was set to non-blocking
        // between poll() and recv(). Treat as timeout.
        match self.recv_raw(buf) {
            Ok(n) => Ok(Some(n)),
            Err(Error::WouldBlock) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Expose the raw file descriptor for integration with async runtimes
    /// (`tokio::AsyncFd`, `mio`, etc.).
    ///
    /// The returned `RawFd` remains valid for the lifetime of this
    /// `ProcConnector`. Do not close it manually.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use proc_connector::ProcConnector;
    /// # use std::os::fd::AsRawFd;
    /// let conn = ProcConnector::new().unwrap();
    /// let raw = conn.as_raw_fd();
    /// assert!(raw >= 0);
    ///
    /// // Use with tokio:
    /// // let async_fd = tokio::io::unix::AsyncFd::new(conn).unwrap();
    /// ```
    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Set the socket to non-blocking mode.
    ///
    /// After calling this, `recv_raw` will return `Error::WouldBlock`
    /// when no data is available, instead of blocking.
    ///
    /// # Errors
    ///
    /// Returns `Error::Os` if `fcntl(2)` fails.
    pub fn set_nonblocking(&self) -> Result<()> {
        let flags = unsafe { libc::fcntl(self.fd.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(Error::Os(std::io::Error::last_os_error()));
        }
        let ret = unsafe { libc::fcntl(self.fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) };
        if ret < 0 {
            return Err(Error::Os(std::io::Error::last_os_error()));
        }
        Ok(())
    }
}

impl AsRawFd for ProcConnector {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl AsFd for ProcConnector {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl Drop for ProcConnector {
    fn drop(&mut self) {
        // Best-effort unsubscribe; ignore errors since we're closing anyway.
        let _ = self.unsubscribe();
    }
}

// ---------------------------------------------------------------------------
// Helper: create the netlink socket
// ---------------------------------------------------------------------------

fn create_socket() -> Result<OwnedFd> {
    let fd = unsafe {
        let fd = libc::socket(libc::PF_NETLINK, libc::SOCK_DGRAM, NETLINK_CONNECTOR);
        if fd < 0 {
            return Err(Error::Os(std::io::Error::last_os_error()));
        }
        OwnedFd::from_raw_fd(fd)
    };

    // Enable NETLINK_NO_ENOBUFS so the kernel doesn't silently drop
    // our subscription message when the socket buffer is full.
    let val: libc::c_int = 1;
    let ret = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_NETLINK,
            NETLINK_NO_ENOBUFS,
            &val as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as u32,
        )
    };
    if ret < 0 {
        // Non-fatal: proceed even if this option fails.
        let _ = std::io::Error::last_os_error();
    }

    Ok(fd)
}
