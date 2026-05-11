//! Error types for proc-connector operations.

use std::fmt;

/// Errors that can occur during proc connector operations.
///
/// # Example: matching on errors
///
/// ```
/// use proc_connector::Error;
///
/// fn handle_error(e: Error) -> String {
///     match &e {
///         Error::Os(e) => format!("os error: {e}"),
///         Error::Truncated => "truncated message".into(),
///         Error::BufferTooSmall { needed } => {
///             format!("need {needed} bytes")
///         }
///         Error::Interrupted => "interrupted, retry".into(),
///         Error::ConnectionClosed => "connection closed".into(),
///         Error::Overrun => "events dropped".into(),
///     }
/// }
///
/// assert_eq!(handle_error(Error::Truncated), "truncated message");
/// assert_eq!(
///     handle_error(Error::BufferTooSmall { needed: 4096 }),
///     "need 4096 bytes"
/// );
/// ```
///
/// # Example: using the `From<std::io::Error>` impl
///
/// ```
/// use proc_connector::Error;
///
/// fn returns_error() -> Result<(), Error> {
///     // std::io::Error is automatically converted via From
///     let _file = std::fs::File::open("/nonexistent")?;
///     Ok(())
/// }
///
/// let err = returns_error().unwrap_err();
/// assert!(matches!(err, Error::Os(_)));
/// ```
#[derive(Debug)]
pub enum Error {
    /// System call failed (socket/bind/sendmsg/recvmsg).
    ///
    /// Wraps `std::io::Error` for maximum compatibility.
    Os(std::io::Error),

    /// Received message is shorter than the minimum protocol header size.
    Truncated,

    /// Provided receive buffer is too small.
    BufferTooSmall {
        /// Minimum buffer size required in bytes.
        needed: usize,
    },

    /// Receive was interrupted by a signal; the operation should be retried.
    Interrupted,

    /// The netlink connection was closed (recv returned 0).
    ConnectionClosed,

    /// Kernel reports message overrun; some events may have been dropped.
    ///
    /// The caller should increase buffer size or consume events faster.
    Overrun,

    /// Non-blocking recv found no data available (EAGAIN / EWOULDBLOCK).
    ///
    /// Only returned when the socket is in non-blocking mode. Callers
    /// should wait for fd readiness (e.g. via poll/AsyncFd) and retry.
    WouldBlock,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Os(e) => write!(f, "system call error: {e}"),
            Error::Truncated => write!(f, "truncated message"),
            Error::BufferTooSmall { needed } => {
                write!(f, "buffer too small, need at least {needed} bytes")
            }
            Error::Interrupted => write!(f, "interrupted by signal"),
            Error::ConnectionClosed => write!(f, "connection closed"),
            Error::Overrun => write!(f, "message overrun, events may have been dropped"),
            Error::WouldBlock => write!(f, "operation would block"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Os(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Os(e)
    }
}

/// Convenience alias for `Result<T, Error>`.
pub type Result<T> = std::result::Result<T, Error>;
