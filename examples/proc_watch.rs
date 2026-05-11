//! Simple process event monitor.
//!
//! Prints all process events as they happen.
//! Requires root or `CAP_NET_ADMIN` to run.
//!
//! Usage:
//! ```sh
//! cargo run --example proc_watch
//! ```
//!
//! Example output:
//! ```text
//! [2026-05-11T21:30:00Z] EXEC pid=1234 tgid=1234
//! [2026-05-11T21:30:01Z] FORK parent=(1000,1000) child=(1235,1235)
//! [2026-05-11T21:30:05Z] EXIT pid=1235 tgid=1235 code=0 signal=17
//! ```

use proc_connector::ProcConnector;
use std::time::Instant;

fn main() {
    // Create connector (requires root / CAP_NET_ADMIN)
    let conn = ProcConnector::new().expect("failed to create proc connector (try as root)");
    let mut buf = vec![0u8; 4096];

    println!("listening for process events... (Ctrl+C to stop)");

    // Example 1: blocking recv loop
    loop {
        match conn.recv(&mut buf) {
            Ok(event) => {
                let now = humantime_or_iso(Instant::now());
                println!("[{now}] {event}");
            }
            Err(e) => {
                eprintln!("recv error: {e}");
                break;
            }
        }
    }
}

/// Format an Instant as a human-readable timestamp.
fn humantime_or_iso(instant: Instant) -> String {
    // Simple ISO-like timestamp since process start
    let secs = instant.elapsed().as_secs();
    let hours = secs / 3600;
    let mins = (secs % 3600) / 60;
    let secs = secs % 60;
    format!("{:02}:{:02}:{:02}", hours, mins, secs)
}
