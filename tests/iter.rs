use proc_connector::*;

mod helpers;
use helpers::*;

#[test]
fn multi_part_message_iteration() {
    // Two exec events packed into one buffer
    let exec_data = [42i32.to_ne_bytes(), 100i32.to_ne_bytes()].concat();
    let msg1 = make_full_message(PROC_EVENT_EXEC, &exec_data);

    let exec_data2 = [43i32.to_ne_bytes(), 101i32.to_ne_bytes()].concat();
    let msg2 = make_full_message(PROC_EVENT_EXEC, &exec_data2);

    let mut combined = Vec::new();
    combined.extend_from_slice(&msg1);
    combined.extend_from_slice(&msg2);

    let iter = NetlinkMessageIter::new(&combined, combined.len());
    let events: Vec<_> = iter.filter_map(|r| r.ok().flatten()).collect();
    assert_eq!(events.len(), 2);
    assert_eq!(
        events[0],
        ProcEvent::Exec {
            cpu: 0,

            seq: 0,
            pid: 42,
            tgid: 100,
            timestamp_ns: 0
        }
    );
    assert_eq!(
        events[1],
        ProcEvent::Exec {
            cpu: 0,

            seq: 0,
            pid: 43,
            tgid: 101,
            timestamp_ns: 0
        }
    );
}

#[test]
fn iter_empty_buffer() {
    let iter = NetlinkMessageIter::new(&[], 0);
    assert_eq!(iter.count(), 0);
}

#[test]
fn iter_single_done_message() {
    let buf = make_netlink_message(NLMSG_DONE, &[]);
    let iter = NetlinkMessageIter::new(&buf, buf.len());
    let results: Vec<_> = iter.collect();
    // NLMSG_DONE should stop iteration, returning no items
    assert_eq!(results.len(), 0);
}

#[test]
fn iter_done_terminates_early() {
    // Two messages: EXEC + DONE. Should only yield the EXEC.
    let exec_data = [42i32.to_ne_bytes(), 100i32.to_ne_bytes()].concat();
    let msg_exec = make_full_message(PROC_EVENT_EXEC, &exec_data);
    let msg_done = make_netlink_message(NLMSG_DONE, &[]);

    let mut combined = Vec::new();
    combined.extend_from_slice(&msg_exec);
    combined.extend_from_slice(&msg_done);

    let iter = NetlinkMessageIter::new(&combined, combined.len());
    let events: Vec<_> = iter.filter_map(|r| r.ok().flatten()).collect();
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0],
        ProcEvent::Exec {
            cpu: 0,

            seq: 0,
            pid: 42,
            tgid: 100,
            timestamp_ns: 0
        }
    );
}

#[test]
fn iter_interleaved_control_messages() {
    // NOOP + EXEC + NOOP + FORK + DONE
    let exec_data = [42i32.to_ne_bytes(), 100i32.to_ne_bytes()].concat();
    let fork_data = [
        10i32.to_ne_bytes(),
        10i32.to_ne_bytes(),
        20i32.to_ne_bytes(),
        20i32.to_ne_bytes(),
    ]
    .concat();

    let msg_noop = make_netlink_message(NLMSG_NOOP, &[]);
    let msg_exec = make_full_message(PROC_EVENT_EXEC, &exec_data);
    let msg_fork = make_full_message(PROC_EVENT_FORK, &fork_data);
    let msg_done = make_netlink_message(NLMSG_DONE, &[]);

    let mut combined = Vec::new();
    combined.extend_from_slice(&msg_noop);
    combined.extend_from_slice(&msg_exec);
    combined.extend_from_slice(&msg_noop);
    combined.extend_from_slice(&msg_fork);
    combined.extend_from_slice(&msg_done);

    let iter = NetlinkMessageIter::new(&combined, combined.len());
    let events: Vec<_> = iter.filter_map(|r| r.ok().flatten()).collect();
    assert_eq!(events.len(), 2);
    assert_eq!(
        events[0],
        ProcEvent::Exec {
            cpu: 0,

            seq: 0,
            pid: 42,
            tgid: 100,
            timestamp_ns: 0
        }
    );
    assert_eq!(
        events[1],
        ProcEvent::Fork {
            cpu: 0,

            seq: 0,
            parent_pid: 10,
            parent_tgid: 10,
            child_pid: 20,
            child_tgid: 20,
            timestamp_ns: 0,
        }
    );
}

#[test]
fn iter_malformed_zero_length() {
    // nlmsg_len = 0 should cause Truncated error
    let mut buf = vec![0u8; 16];
    buf[0..4].copy_from_slice(&0u32.to_ne_bytes()); // nlmsg_len = 0
    let mut iter = NetlinkMessageIter::new(&buf, buf.len());
    let result = iter.next().unwrap();
    assert!(matches!(result, Err(Error::Truncated)));
}

#[test]
fn iter_remaining_too_small_for_header() {
    // Only 4 bytes remaining but need 16 for nlmsghdr
    let buf = vec![0u8; 4];
    let mut iter = NetlinkMessageIter::new(&buf, 4);
    let result = iter.next().unwrap();
    assert!(matches!(result, Err(Error::Truncated)));
}

#[test]
fn iter_no_valid_msgs_returns_none_on_second_call() {
    let buf = make_netlink_message(NLMSG_DONE, &[]);
    let mut iter = NetlinkMessageIter::new(&buf, buf.len());
    // First call: done stops iteration
    assert!(iter.next().is_none());
    // Second call: should also be None
    assert!(iter.next().is_none());
}

#[test]
fn iter_many_messages() {
    let exec_data = [42i32.to_ne_bytes(), 100i32.to_ne_bytes()].concat();
    let mut combined = Vec::new();

    for _ in 0..100 {
        let msg = make_full_message(PROC_EVENT_EXEC, &exec_data);
        combined.extend_from_slice(&msg);
    }

    let iter = NetlinkMessageIter::new(&combined, combined.len());
    let count = iter.filter_map(|r| r.ok().flatten()).count();
    assert_eq!(count, 100);
}

#[test]
fn iter_alignment_correct() {
    // Messages should be at proper nlmsg_align boundaries
    let msg1 = make_netlink_message(NLMSG_NOOP, &[]); // 16 bytes
    let msg2 = make_full_message(
        PROC_EVENT_EXEC,
        &[42i32.to_ne_bytes(), 100i32.to_ne_bytes()].concat(),
    );
    let msg3 = make_netlink_message(NLMSG_DONE, &[]);

    let mut combined = Vec::new();
    combined.extend_from_slice(&msg1);
    combined.extend_from_slice(&msg2);
    combined.extend_from_slice(&msg3);

    // Manually walk the buffer to verify alignment
    let mut pos = 0;

    // msg1 (NOOP): len=16
    let len1 = u32::from_ne_bytes(msg1[0..4].try_into().unwrap()) as usize;
    assert_eq!(len1, 16);
    pos += nlmsg_align(len1);

    // msg2 (EXEC)
    let len2 = u32::from_ne_bytes(msg2[0..4].try_into().unwrap()) as usize;
    assert!(len2 > 16);
    assert_eq!(pos, 16); // after first 16-byte message
    pos += nlmsg_align(len2);

    // msg3 (DONE)
    let len3 = u32::from_ne_bytes(msg3[0..4].try_into().unwrap()) as usize;
    assert_eq!(len3, 16);
    assert_eq!(pos, 16 + nlmsg_align(len2)); // after second message

    // Iteration should succeed
    let iter = NetlinkMessageIter::new(&combined, combined.len());
    let events: Vec<_> = iter.filter_map(|r| r.ok().flatten()).collect();
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0],
        ProcEvent::Exec {
            cpu: 0,

            seq: 0,
            pid: 42,
            tgid: 100,
            timestamp_ns: 0
        }
    );
}
