# proc-connector

Linux Process Event Connector — safe, zero-overhead, full-coverage parser for all PROC_EVENT_* types.

[![Crates.io](https://img.shields.io/crates/v/proc-connector.svg)](https://crates.io/crates/proc-connector)
[![Docs.rs](https://docs.rs/proc-connector/badge.svg)](https://docs.rs/proc-connector)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/lenitain/proc-connector/actions/workflows/ci.yml/badge.svg)](https://github.com/lenitain/proc-connector/actions/workflows/ci.yml)

## Overview

**proc-connector** provides a safe, efficient Rust interface to Linux's Process Event Connector (`NETLINK_CONNECTOR` + `CN_IDX_PROC`). It parses all 10+ `PROC_EVENT_*` types including exec, fork, exit, uid/gid changes, ptrace, and more. The library offers zero-overhead abstractions with comprehensive error handling and async integration support.

### Why proc-connector?

Unlike other process monitoring solutions that rely on polling `/proc` or using incomplete netlink implementations, **proc-connector** provides complete coverage of all kernel process events with a type-safe API. It handles the complexities of netlink protocol parsing, message alignment, and error recovery internally, letting you focus on reacting to process lifecycle events. For system tools that need real-time process monitoring without the overhead of polling, proc-connector offers the most complete and ergonomic Rust interface to Linux's proc connector.

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
proc-connector = "0.2"
```

### Requirements

- Linux kernel with `CONFIG_CONNECTOR` and `CONFIG_PROC_EVENTS` enabled
- **`CAP_NET_ADMIN`** capability (run as root or with `cap_net_admin+ep`)

This crate is Linux-only and will fail to compile on other platforms.

### Quick start

```rust
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
