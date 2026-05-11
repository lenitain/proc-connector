# proc-connector

[![Crates.io](https://img.shields.io/crates/v/proc-connector.svg)](https://crates.io/crates/proc-connector)
[![Docs.rs](https://docs.rs/proc-connector/badge.svg)](https://docs.rs/proc-connector)

Linux **Process Event Connector** (`NETLINK_CONNECTOR` + `CN_IDX_PROC`) — safe,
zero-overhead, full-coverage parser for all 10+ `PROC_EVENT_*` types.

## Installation

```bash
cargo add proc-connector
```

Minimum supported Rust version: **1.85** (edition 2024).

## Requirements

- Linux kernel with `CONFIG_CONNECTOR` and `CONFIG_PROC_EVENTS` enabled
- **`CAP_NET_ADMIN`** capability (run as root or with `cap_net_admin+ep`)

The crate compiles on any platform, but all runtime operations require a Linux
kernel with proc connector support. Non-Linux platforms will fail at runtime
with `Error::Os(ENOSYS)`.

## Testing

### Unit tests (no privileges needed)

```bash
cargo test
```

67 unit tests covering all protocol parsing (every event variant, truncation
edge cases, malformed headers, kernel boundary conditions, multi-message
iteration), error formatting, alignment helpers, and alignment math.

### Integration tests (require root)

2 additional tests verify end-to-end behavior against a real Linux kernel.
Build as normal user, run under `sudo`:

```bash
cargo test --test integration_test --no-run
sudo -E ~/.cargo/bin/cargo test --test integration_test -- --ignored
```

| Test | What it checks |
|------|----------------|
| `test_receive_exec_event` | Create connector → spawn `/bin/true` → receive `Exec` event within 5s |
| `test_subscribe_unsubscribe` | Subscribe → unsubscribe → re-subscribe, no errors |

---

## About this crate

The Linux kernel exposes process lifecycle events (exec, fork, exit, uid/gid
change, ptrace, etc.) through the **Proc Connector** — a netlink protocol
multiplexed over `NETLINK_CONNECTOR` with `CN_IDX_PROC`.

The only existing Rust wrapper, [`cnproc`], covers only 4 event types (exec,
fork, exit, coredump) and exposes them as raw `libc::c_int` values — no tgid,
no uid/gid/sid data, no `as_raw_fd()` for async integration, and a `VecDeque`
internal cache that violates separation of concerns.

This crate is to `cnproc` what [`fanotify-fid`] is to `fanotify-rs`: a
complete, safe, modern replacement that covers **every** event type with a
properly structured API.

[`cnproc`]: https://crates.io/crates/cnproc
[`fanotify-fid`]: https://crates.io/crates/fanotify-fid

### Event coverage

| Event | Kernel constant | Fields |
|-------|----------------|--------|
| `Exec` | `PROC_EVENT_EXEC` | `pid`, `tgid` |
| `Fork` | `PROC_EVENT_FORK` | `parent_pid`, `parent_tgid`, `child_pid`, `child_tgid` |
| `Exit` | `PROC_EVENT_EXIT` | `pid`, `tgid`, `exit_code`, `exit_signal` |
| `Uid` | `PROC_EVENT_UID` | `pid`, `tgid`, `ruid`, `euid` |
| `Gid` | `PROC_EVENT_GID` | `pid`, `tgid`, `rgid`, `egid` |
| `Sid` | `PROC_EVENT_SID` | `pid`, `tgid` |
| `Ptrace` | `PROC_EVENT_PTRACE` | `pid`, `tgid`, `tracer_pid`, `tracer_tgid` |
| `Comm` | `PROC_EVENT_COMM` | `pid`, `tgid`, `comm: [u8; 16]` |
| `Coredump` | `PROC_EVENT_COREDUMP` | `pid`, `tgid` |

## Quick example

```rust,no_run
use proc_connector::ProcConnector;
use std::time::Duration;

// Requires CAP_NET_ADMIN
let conn = ProcConnector::new().expect("create connector");
let mut buf = [0u8; 4096];

loop {
    match conn.recv_timeout(&mut buf, Duration::from_secs(1)) {
        Ok(Some(event)) => println!("{event}"),
        Ok(None) => eprintln!("timeout"),
        Err(e) => { eprintln!("{e}"); break; }
    }
}
```

### Async integration

```rust,no_run
use proc_connector::ProcConnector;

let conn = ProcConnector::new().unwrap();
let raw_fd = conn.as_raw_fd();

// With tokio:
// let async_fd = tokio::io::unix::AsyncFd::new(conn).unwrap();
```

---

## Modules

```
src/
├── consts.rs   # All kernel constants (PROC_EVENT_*, CN_IDX_PROC, NLMSG_*, layout offsets)
├── error.rs    # Error enum (Os, Truncated, BufferTooSmall, Interrupted, ConnectionClosed, Overrun)
├── socket.rs   # ProcConnector (new, subscribe, unsubscribe, recv_raw, as_raw_fd)
├── event.rs    # ProcEvent enum + netlink/cn_msg/proc_event three-layer parser
└── lib.rs      # Re-exports, prelude
```

---

## Error handling

All fallible operations return `Result<T, Error>`. The `Error` enum covers both
system-level and protocol-level failures:

| Variant | Meaning |
|---------|---------|
| `Os(io::Error)` | System call failed (socket, bind, sendmsg, recv) |
| `Truncated` | Message shorter than minimum protocol header |
| `BufferTooSmall { needed }` | Provided buffer too small |
| `Interrupted` | recv interrupted by signal (retry) |
| `ConnectionClosed` | recv returned 0 |
| `Overrun` | Kernel reporting dropped events (increase buffer / consume faster) |

```rust,no_run
use proc_connector::Error;

fn handle(e: Error) {
    match &e {
        Error::Os(e) => eprintln!("os error: {e}"),
        Error::BufferTooSmall { needed } => eprintln!("need buffer of {needed} bytes"),
        Error::Overrun => eprintln!("events dropped!"),
        _ => eprintln!("{e}"),
    }
}
```

## License

[MIT License](./LICENSE)
