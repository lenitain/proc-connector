//! Demonstrates async integration via `as_raw_fd()` with `std::os::unix::io::OwnedFd`.
//!
//! This example shows how to use `ProcConnector` with a simple event loop
//! (or with `tokio::AsyncFd`, `mio`, etc.) by polling the raw file descriptor.
//!
//! Usage:
//! ```sh
//! cargo run --example async_integration
//! ```

use proc_connector::ProcConnector;
use std::time::Duration;

fn main() {
    let conn = ProcConnector::new().expect("failed to create proc connector (try as root)");
    let mut buf = vec![0u8; 4096];

    println!("polling for events with 2s timeout... (Ctrl+C to stop)");

    // Example: poll-based timeout (no external dependencies needed)
    loop {
        match conn.recv_timeout(&mut buf, Duration::from_secs(2)) {
            Ok(Some(event)) => println!("{event}"),
            Ok(None) => {
                // Timeout expired, do other work
                print!(".");
                std::io::Write::flush(&mut std::io::stdout()).ok();
            }
            Err(e) => {
                eprintln!("error: {e}");
                break;
            }
        }
    }

    // The raw fd can be used with tokio::AsyncFd, mio, etc.:
    let _raw_fd = conn.as_raw_fd();
    // With tokio:
    // let async_fd = tokio::io::unix::AsyncFd::new(conn)?;
    // loop {
    //     let mut guard = async_fd.readable().await?;
    //     match conn.recv(&mut buf) { ... }
    //     guard.clear_ready();
    // }
}
