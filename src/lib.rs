//! # proc-connector
//!
//! A safe, modern Rust wrapper for the **Linux Process Event Connector**
//! (netlink `NETLINK_CONNECTOR` + `CN_IDX_PROC`).
//!
//! Provides full coverage of all 10+ kernel process event types via a
//! type-safe, zero-overhead, and fully safe API.
//!
//! ## Quick start
//!
//! ```no_run
//! # use proc_connector::{ProcConnector, ProcEvent};
//! # use std::time::Duration;
//!
//! // Create connector (requires CAP_NET_ADMIN)
//! let conn = ProcConnector::new().expect("create connector");
//! let mut buf = vec![0u8; 4096];
//!
//! // Blocking receive with timeout
//! match conn.recv_timeout(&mut buf, Duration::from_secs(1)) {
//!     Ok(Some(event)) => println!("got event: {event}"),
//!     Ok(None) => println!("timeout"),
//!     Err(e) => eprintln!("error: {e}"),
//! }
//! ```
//!
//! ## Async integration
//!
//! ```no_run
//! # use proc_connector::ProcConnector;
//! # use std::os::fd::AsRawFd;
//! let conn = ProcConnector::new().unwrap();
//! let raw_fd = conn.as_raw_fd();
//! // Use with tokio:
//! // let async_fd = tokio::io::unix::AsyncFd::new(conn).unwrap();
//! ```
//!
//! ## Design philosophy (inspired by `fanotify-fid`)
//!
//! - **Safe API**: internal `unsafe` is confined to protocol parsing;
//!   callers receive a fully safe interface.
//! - **Complete event coverage**: all `PROC_EVENT_*` variants are exposed
//!   as a `ProcEvent` enum with structured fields.
//! - **Zero-copy where possible**: parsing happens only after a successful
//!   `recv`, with buffer ownership left to the caller.
//! - **Async-ready**: `as_raw_fd()` exposes the underlying socket fd for
//!   integration with `tokio::AsyncFd`, `mio`, or other event loops.
//! - **No overreach**: does NOT manage threads, cache `/proc` data, or
//!   impose any event processing policy.

mod consts;
mod error;
mod iter;
mod parse;
mod proc_event;
mod socket;

// Re-exports — the full public API
pub use consts::*;
pub use error::{Error, Result};
pub use iter::NetlinkMessageIter;
pub use parse::{parse_cn_msg, parse_netlink_message};
pub use proc_event::ProcEvent;
pub use socket::ProcConnector;
