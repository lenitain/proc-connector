//! Integration tests for proc-connector.
//!
//! These tests require:
//! - Linux with `CONFIG_CONNECTOR` and `CONFIG_PROC_EVENTS` enabled
//! - Root privileges (or `CAP_NET_ADMIN` + `CAP_NET_RAW`)
//!
//! Run with: `cargo test -- --ignored --test-threads=1`
//! Run as root: `sudo env "CARGO_TARGET_DIR=$CARGO_TARGET_DIR" cargo test -- --ignored --test-threads=1`

use proc_connector::ProcConnector;
use std::time::Duration;

/// Verify that we can create a connector and receive at least one event
/// within a reasonable timeout.
#[test]
#[ignore = "requires root / CAP_NET_ADMIN + Linux proc connector support"]
fn test_receive_exec_event() {
    let conn = ProcConnector::new().expect("ProcConnector::new() failed");
    let mut buf = vec![0u8; 4096];

    // Fork a child that does exec (just run /bin/true)
    let mut child = std::process::Command::new("/bin/true")
        .spawn()
        .expect("failed to spawn /bin/true");

    // Wait for the event with a timeout
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut found_exec = false;

    while std::time::Instant::now() < deadline {
        match conn.recv_timeout(&mut buf, Duration::from_millis(500)) {
            Ok(Some(event)) => {
                if matches!(event, proc_connector::ProcEvent::Exec { .. }) {
                    found_exec = true;
                    break;
                }
            }
            Ok(None) => continue,
            Err(e) => {
                // EINTR can happen, just retry
                if matches!(e, proc_connector::Error::Interrupted) {
                    continue;
                }
                panic!("recv error: {e}");
            }
        }
    }

    assert!(found_exec, "did not receive an Exec event within 5 seconds");

    let _ = child.wait();
}

/// Verify subscribe/unsubscribe round-trip does not error.
#[test]
#[ignore = "requires root / CAP_NET_ADMIN + Linux proc connector support"]
fn test_subscribe_unsubscribe() {
    let conn = ProcConnector::new().expect("ProcConnector::new() failed");

    // Subscribe again (should be idempotent)
    conn.subscribe().expect("subscribe failed");

    // Unsubscribe
    conn.unsubscribe().expect("unsubscribe failed");

    // Re-subscribe
    conn.subscribe().expect("re-subscribe failed");
}


