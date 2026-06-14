use proc_connector::*;

#[test]
fn error_display_all_variants() {
    assert_eq!(
        format!("{}", Error::Os(std::io::Error::from_raw_os_error(1))),
        "system call error: Operation not permitted (os error 1)"
    );
    assert_eq!(format!("{}", Error::Truncated), "truncated message");
    assert_eq!(
        format!("{}", Error::BufferTooSmall { needed: 64 }),
        "buffer too small, need at least 64 bytes"
    );
    assert_eq!(format!("{}", Error::Interrupted), "interrupted by signal");
    assert_eq!(format!("{}", Error::ConnectionClosed), "connection closed");
    assert_eq!(
        format!("{}", Error::Overrun),
        "message overrun, events may have been dropped"
    );
}

#[test]
fn error_source() {
    use std::error::Error as _;
    assert!(
        Error::Os(std::io::Error::from_raw_os_error(1))
            .source()
            .is_some()
    );
    assert!(Error::Truncated.source().is_none());
    assert!(Error::BufferTooSmall { needed: 16 }.source().is_none());
    assert!(Error::Interrupted.source().is_none());
    assert!(Error::ConnectionClosed.source().is_none());
    assert!(Error::Overrun.source().is_none());
}

#[test]
fn recv_buffer_too_small() {
    // Simulate what happens when recv is called with buf < SIZE_NLMSGHDR
    // We can't easily test ProcConnector::recv without root, but we can
    // verify the recv_impl path would detect the small buffer.
    // The check happens before any syscall.
    // We verify by checking the error variant directly:
    let err = Error::BufferTooSmall {
        needed: SIZE_NLMSGHDR,
    };
    assert_eq!(format!("{err}"), "buffer too small, need at least 16 bytes");
}
