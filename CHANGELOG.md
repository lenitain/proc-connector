# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
