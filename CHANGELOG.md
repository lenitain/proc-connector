# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-08-02

### Breaking

- Every `ProcEvent` variant gains a `seq: u32` field: the per-CPU monotonic
  message sequence from the `cn_msg` header (previously dropped during
  parsing). Consumers can now build exact cursors `(cpu << 32) | seq` and
  quantify lost events on sequence jumps.

## [0.2.0] - 2026-07-29

### Breaking

- Every `ProcEvent` variant gains a `cpu: u32` field (the CPU that generated the event).
- `ProcEvent::Exit` gains `parent_pid`, `parent_tgid` fields.
- `ProcEvent::Coredump` gains `parent_pid`, `parent_tgid` fields.
- `NETLINK_NO_ENOBUFS` is no longer set by default.
- Non-Linux compilation now fails with a clear `compile_error!` instead of obscure linker errors.

### Added

- `EventMask` bitflags (`FORK`, `EXEC`, `EXIT`, `UID`, `GID`, `SID`, `PTRACE`, `COMM`, `COREDUMP`, `ALL`) and `subscribe_filtered()` for event filtering.
- `set_recv_buf_size()` to set `SO_RCVBUF` on the netlink socket.
- `subscribe()` now validates the kernel's subscription ACK.
- `ProcEvent::exit_status()` / `terminating_signal()` helpers for decoding `wait(2)` status.
- `SOCK_CLOEXEC` on the netlink socket to prevent fd leaks to child processes.
- `SIZE_NLMSGERR` constant.
- Property test (`proptest`) verifying public parse functions never panic on arbitrary input.

### Fixed

- `recv_raw_timeout`: `pollfd` is now `mut`, fixing undefined behavior from casting `&T` to `*mut T`.
- `parse_netlink_message`: no longer panics when `len > payload.len()` or when `NLMSG_ERROR` message is shorter than 20 bytes.
- `recv_raw`: `ENOBUFS` now maps to `Error::Overrun` instead of a generic `Os` error.
- `NetlinkMessageIter`: truncated/corrupt messages no longer loop forever; implements `FusedIterator`.
- `recv_timeout`: uses a deadline instead of restarting the full timeout on each skipped control message.

## [0.1.6] - 2026-06-29

### Fixed

- **`ProcConnector` implements `Debug`** ([C-DEBUG](https://rust-lang.github.io/api-guidelines/development.html#all-types-have-good-developer-experience-c-good-dev-experience)):
  ```rust
  let conn = ProcConnector::new().unwrap();
  println!("{:?}", conn); // ProcConnector { fd: 3 }
  ```

## [0.1.5] - 2026-06-14

### Added

- Comprehensive API documentation examples for all public items
- Detailed API documentation for all public items
- Crates.io, docs.rs, license, and CI badges to README

### Changed

- Translated all Chinese comments to English for international accessibility
- Removed unnecessary `#[allow(dead_code)]` and relocated test helper to `tests/parse.rs`
- Removed project structure tree from README

### Removed

- `.cargoignore` file (no longer needed)

## [0.1.4] - 2026-06-05

### Added

- `UnexpectedConnector` error variant for more precise error handling when receiving non-proc-connector messages

### Changed

- **Major refactor**: split `event.rs` (1888 lines) into focused modules:
  - `proc_event.rs` — `ProcEvent` enum and `Display` implementation
  - `parse.rs` — netlink message parsing functions (`parse_netlink_message`, `parse_cn_msg`, `parse_proc_event`)
  - `iter.rs` — `NetlinkMessageIter` for iterating over multi-part netlink messages
  - `tests/` — reorganized test code with shared helpers
- Moved `recv` and `recv_timeout` methods back to `socket.rs` (where `ProcConnector` is defined)
- Extracted `first_event_from_buf` helper to eliminate duplicate loop logic in `recv`/`recv_timeout`
- Extracted test helper functions (`make_proc_event_payload`, `make_cn_msg`, `make_netlink_message`) to `tests/helpers.rs`

## [0.1.3] - 2026-05-13

### Added

- `timestamp_ns` field to `ProcEvent::Exec`, `ProcEvent::Fork`, `ProcEvent::Exit`,
  `ProcEvent::Uid`, `ProcEvent::Gid`, `ProcEvent::Sid`, and `ProcEvent::Comm`
  variants, exposing the kernel's monotonic timestamp for each process event.
- Test for non-zero `timestamp_ns` parsing.

## [0.1.2] - 2026-05-12

### Changed

- README improvements.

## [0.1.1] - 2026-05-12

### Fixed

- Kernel connector protocol: use `NLMSG_DONE` for all data messages (was incorrectly
  using `NLMSG_ERROR` for some message types).

## [0.1.0] - 2026-05-11

### Added

- Initial release of `proc-connector`.
- `ProcConnector`: safe wrapper around the Linux `CONNECTOR` / `cn_proc` netlink interface
  for receiving process events (fork, exec, exit, uid/gid/sid changes, comm changes).
- `ProcEvent` enum with variants: `Exec`, `Fork`, `Exit`, `Uid`, `Gid`, `Sid`, `Comm`.
- `NetlinkMessageIter` for iterating over raw netlink messages.
- `set_nonblocking` for non-blocking event reception.
- `AsRawFd` / `AsFd` trait implementations.
- `Error` type with `WouldBlock`, `Truncated`, `Overrun`, `Interrupted` variants.
- 69 unit tests for netlink message parsing.
- Doc-tests for all public API items.
