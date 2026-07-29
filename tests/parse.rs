use proc_connector::*;

mod helpers;
use helpers::*;

#[test]
fn parse_exec() {
    let data = [
        42i32.to_ne_bytes(),  // process_pid
        100i32.to_ne_bytes(), // process_tgid
    ]
    .concat();
    let buf = make_full_message(PROC_EVENT_EXEC, &data);
    let event = parse_netlink_message(&buf, buf.len()).unwrap().unwrap();
    assert_eq!(
        event,
        ProcEvent::Exec {
            cpu: 0,
            pid: 42,
            tgid: 100,
            timestamp_ns: 0,
        }
    );
}

#[test]
fn parse_fork() {
    let data = [
        10i32.to_ne_bytes(), // parent_pid
        10i32.to_ne_bytes(), // parent_tgid
        20i32.to_ne_bytes(), // child_pid
        20i32.to_ne_bytes(), // child_tgid
    ]
    .concat();
    let buf = make_full_message(PROC_EVENT_FORK, &data);
    let event = parse_netlink_message(&buf, buf.len()).unwrap().unwrap();
    assert_eq!(
        event,
        ProcEvent::Fork {
            cpu: 0,
            parent_pid: 10,
            parent_tgid: 10,
            child_pid: 20,
            child_tgid: 20,
            timestamp_ns: 0,
        }
    );
}

#[test]
fn parse_exit() {
    let data = [
        1i32.to_ne_bytes(),  // process_pid
        1i32.to_ne_bytes(),  // process_tgid
        0u32.to_ne_bytes(),  // exit_code
        17u32.to_ne_bytes(), // exit_signal (SIGCHLD)
        0i32.to_ne_bytes(),  // parent_pid
        0i32.to_ne_bytes(),  // parent_tgid
    ]
    .concat();
    let buf = make_full_message(PROC_EVENT_EXIT, &data);
    let event = parse_netlink_message(&buf, buf.len()).unwrap().unwrap();
    assert_eq!(
        event,
        ProcEvent::Exit {
            cpu: 0,
            pid: 1,
            tgid: 1,
            exit_code: 0,
            exit_signal: 17,
            parent_pid: 0,
            parent_tgid: 0,
            timestamp_ns: 0,
        }
    );
}

#[test]
fn parse_uid() {
    let data = [
        5i32.to_ne_bytes(),    // process_pid
        5i32.to_ne_bytes(),    // process_tgid
        1000u32.to_ne_bytes(), // ruid
        0u32.to_ne_bytes(),    // euid (root)
    ]
    .concat();
    let buf = make_full_message(PROC_EVENT_UID, &data);
    let event = parse_netlink_message(&buf, buf.len()).unwrap().unwrap();
    assert_eq!(
        event,
        ProcEvent::Uid {
            cpu: 0,
            pid: 5,
            tgid: 5,
            ruid: 1000,
            euid: 0,
            timestamp_ns: 0,
        }
    );
}

#[test]
fn parse_gid() {
    let data = [
        5i32.to_ne_bytes(),   // process_pid
        5i32.to_ne_bytes(),   // process_tgid
        100u32.to_ne_bytes(), // rgid
        200u32.to_ne_bytes(), // egid
    ]
    .concat();
    let buf = make_full_message(PROC_EVENT_GID, &data);
    let event = parse_netlink_message(&buf, buf.len()).unwrap().unwrap();
    assert_eq!(
        event,
        ProcEvent::Gid {
            cpu: 0,
            pid: 5,
            tgid: 5,
            rgid: 100,
            egid: 200,
            timestamp_ns: 0,
        }
    );
}

#[test]
fn parse_sid() {
    let data = [
        7i32.to_ne_bytes(), // process_pid
        7i32.to_ne_bytes(), // process_tgid
    ]
    .concat();
    let buf = make_full_message(PROC_EVENT_SID, &data);
    let event = parse_netlink_message(&buf, buf.len()).unwrap().unwrap();
    assert_eq!(
        event,
        ProcEvent::Sid {
            cpu: 0,
            pid: 7,
            tgid: 7,
            timestamp_ns: 0
        }
    );
}

#[test]
fn parse_ptrace() {
    let data = [
        1i32.to_ne_bytes(),   // process_pid
        1i32.to_ne_bytes(),   // process_tgid
        999i32.to_ne_bytes(), // tracer_pid
        999i32.to_ne_bytes(), // tracer_tgid
    ]
    .concat();
    let buf = make_full_message(PROC_EVENT_PTRACE, &data);
    let event = parse_netlink_message(&buf, buf.len()).unwrap().unwrap();
    assert_eq!(
        event,
        ProcEvent::Ptrace {
            cpu: 0,
            pid: 1,
            tgid: 1,
            tracer_pid: 999,
            tracer_tgid: 999,
            timestamp_ns: 0,
        }
    );
}

#[test]
fn parse_comm() {
    let data = [
        42i32.to_ne_bytes(), // process_pid
        42i32.to_ne_bytes(), // process_tgid
    ]
    .concat();
    let mut comm_event = data;
    let mut comm = [0u8; 16];
    comm[..7].copy_from_slice(b"bash\0\0\0");
    comm_event.extend_from_slice(&comm);

    let buf = make_full_message(PROC_EVENT_COMM, &comm_event);
    let event = parse_netlink_message(&buf, buf.len()).unwrap().unwrap();
    assert_eq!(
        event,
        ProcEvent::Comm {
            cpu: 0,
            pid: 42,
            tgid: 42,
            comm,
            timestamp_ns: 0,
        }
    );
}

#[test]
fn parse_coredump() {
    let data = [
        1i32.to_ne_bytes(), // process_pid
        1i32.to_ne_bytes(), // process_tgid
        0i32.to_ne_bytes(), // parent_pid
        0i32.to_ne_bytes(), // parent_tgid
    ]
    .concat();
    let buf = make_full_message(PROC_EVENT_COREDUMP, &data);
    let event = parse_netlink_message(&buf, buf.len()).unwrap().unwrap();
    assert_eq!(
        event,
        ProcEvent::Coredump {
            cpu: 0,
            pid: 1,
            tgid: 1,
            parent_pid: 0,
            parent_tgid: 0,
            timestamp_ns: 0
        }
    );
}

#[test]
fn parse_unknown_skipped() {
    let data = [1u8, 2, 3, 4];
    let buf = make_full_message(0xDEAD, &data);
    let event = parse_netlink_message(&buf, buf.len()).unwrap().unwrap();
    match event {
        ProcEvent::Unknown { what, raw_data } => {
            assert_eq!(what, 0xDEAD);
            assert_eq!(raw_data, data);
        }
        _ => panic!("expected Unknown event"),
    }
}

#[test]
fn parse_nlmsg_noop() {
    let buf = make_netlink_message(NLMSG_NOOP, &[]);
    let result = parse_netlink_message(&buf, buf.len()).unwrap();
    assert!(result.is_none());
}

#[test]
fn parse_nlmsg_done() {
    let buf = make_netlink_message(NLMSG_DONE, &[]);
    let result = parse_netlink_message(&buf, buf.len()).unwrap();
    assert!(result.is_none());
}

#[test]
fn parse_nlmsg_error() {
    // NLMSG_ERROR with non-zero error code
    let errno = -libc::EPERM;
    let mut payload = vec![0u8; SIZE_NLMSGHDR + 20]; // nlmsgerr = int(4) + nlmsghdr(16)
    payload[0..4].copy_from_slice(&errno.to_ne_bytes());

    let buf = make_netlink_message(NLMSG_ERROR, &payload);
    let result = parse_netlink_message(&buf, buf.len());
    assert!(result.is_err());
    match result {
        Err(Error::Os(e)) => assert_eq!(e.raw_os_error(), Some(libc::EPERM)),
        _ => panic!("expected Os error"),
    }
}

#[test]
fn parse_nlmsg_overrun() {
    let buf = make_netlink_message(NLMSG_OVERRUN, &[]);
    let result = parse_netlink_message(&buf, buf.len());
    match result {
        Err(Error::Overrun) => {} // expected
        _ => panic!("expected Overrun error"),
    }
}

#[test]
fn parse_cn_msg_truncated_no_data() {
    // Buffer smaller than SIZE_CN_MSG
    let result = parse_cn_msg(&[0u8; 15]);
    assert!(matches!(result, Err(Error::Truncated)));
}

#[test]
fn parse_cn_msg_data_len_mismatch() {
    // cn_msg says data len = 100 but buffer is smaller
    let mut buf = vec![0u8; SIZE_CN_MSG + 4];
    buf[0..4].copy_from_slice(&CN_IDX_PROC.to_ne_bytes());
    buf[4..8].copy_from_slice(&CN_VAL_PROC.to_ne_bytes());
    buf[16..18].copy_from_slice(&100u16.to_ne_bytes()); // data len = 100
    // but only 4 bytes of data available
    let result = parse_cn_msg(&buf);
    assert!(matches!(result, Err(Error::Truncated)));
}

/// Create a proc_event payload with a specific timestamp (local to this test file).
fn make_proc_event_payload_with_ts(what: u32, timestamp_ns: u64, event_data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(PROC_EVENT_HEADER_SIZE + event_data.len());
    buf.extend_from_slice(&what.to_ne_bytes());
    buf.extend_from_slice(&0u32.to_ne_bytes()); // cpu
    buf.extend_from_slice(&timestamp_ns.to_ne_bytes());
    buf.extend_from_slice(event_data);
    buf
}

#[test]
fn parse_exec_timestamp_nonzero() {
    // Verify that timestamp_ns is correctly parsed from raw bytes.
    let ts: u64 = 123456789012345;
    let data = [42i32.to_ne_bytes(), 100i32.to_ne_bytes()].concat();
    let proc_payload = make_proc_event_payload_with_ts(PROC_EVENT_EXEC, ts, &data);
    let cn_payload = make_cn_msg(&proc_payload);
    let buf = make_netlink_message(NLMSG_MIN_TYPE, &cn_payload);
    let event = parse_netlink_message(&buf, buf.len()).unwrap().unwrap();
    match event {
        ProcEvent::Exec {
            pid,
            tgid,
            timestamp_ns,
            ..
        } => {
            assert_eq!(pid, 42);
            assert_eq!(tgid, 100);
            assert_eq!(timestamp_ns, ts, "timestamp_ns should be preserved");
        }
        _ => panic!("expected Exec event"),
    }
    // Also test Display includes the timestamp
    assert!(
        event.to_string().contains(&format!("ts={ts}")),
        "Display should include ts=... but got: {}",
        event
    );
}

#[test]
fn parse_exec_negative_pid() {
    // Kernel uses i32 for pids; negative shouldn't happen but test robustness
    let data = [(-1i32).to_ne_bytes(), (-1i32).to_ne_bytes()].concat();
    let buf = make_full_message(PROC_EVENT_EXEC, &data);
    let event = parse_netlink_message(&buf, buf.len()).unwrap().unwrap();
    // Since we cast i32 -> u32, -1 becomes 0xFFFFFFFF
    assert_eq!(
        event,
        ProcEvent::Exec {
            cpu: 0,
            pid: u32::MAX,
            tgid: u32::MAX,
            timestamp_ns: 0,
        }
    );
}

#[test]
fn parse_comm_no_nul() {
    // Full 16 bytes with no NUL terminator (valid in kernel, comm is fixed-size)
    let data = [
        42i32.to_ne_bytes(), // process_pid
        42i32.to_ne_bytes(), // process_tgid
    ]
    .concat();
    let mut comm_event = data;
    let comm: [u8; 16] = *b"abcdefghijklmnop";
    comm_event.extend_from_slice(&comm);

    let buf = make_full_message(PROC_EVENT_COMM, &comm_event);
    let event = parse_netlink_message(&buf, buf.len()).unwrap().unwrap();
    assert_eq!(
        event,
        ProcEvent::Comm {
            cpu: 0,
            pid: 42,
            tgid: 42,
            comm,
            timestamp_ns: 0,
        }
    );
    // Display should show all 16 chars
    let s = format!("{event}");
    assert_eq!(s, "COMM pid=42 tgid=42 name=\"abcdefghijklmnop\" ts=0");
}

#[test]
fn parse_comm_invalid_utf8() {
    // Bad UTF-8 bytes in comm should display as <invalid>
    let data = [
        1i32.to_ne_bytes(), // process_pid
        1i32.to_ne_bytes(), // process_tgid
    ]
    .concat();
    let mut comm_event = data;
    let mut comm = [0u8; 16];
    comm[0] = 0xFF; // invalid UTF-8 start byte
    comm[1] = 0xFE;
    comm[2] = 0;
    comm_event.extend_from_slice(&comm);

    let buf = make_full_message(PROC_EVENT_COMM, &comm_event);
    let event = format!(
        "{}",
        parse_netlink_message(&buf, buf.len()).unwrap().unwrap()
    );
    assert!(event.contains("<invalid>"));
}

#[test]
fn parse_unknown_large_data_skipped() {
    let data = vec![0xABu8; 1024];
    let buf = make_full_message(0xFFFFFFFF, &data);
    let event = parse_netlink_message(&buf, buf.len()).unwrap().unwrap();
    match event {
        ProcEvent::Unknown { what, raw_data } => {
            assert_eq!(what, 0xFFFFFFFF);
            assert_eq!(raw_data.len(), 1024);
            assert_eq!(raw_data[0], 0xAB);
            assert_eq!(raw_data[1023], 0xAB);
        }
        _ => panic!("expected Unknown"),
    }
}

#[test]
fn parse_zero_length_proc_event_data() {
    // proc_event header but no event_data at all
    let proc_payload = make_proc_event_payload(PROC_EVENT_EXEC, &[]);
    let cn_payload = make_cn_msg(&proc_payload);
    let buf = make_netlink_message(NLMSG_MIN_TYPE, &cn_payload);
    let result = parse_netlink_message(&buf, buf.len());
    assert!(matches!(result, Err(Error::Truncated)));
}

#[test]
fn parse_with_nlm_f_request_flag() {
    // Verify that NLM_F_REQUEST flag doesn't interfere with parsing
    let exec_data = [42i32.to_ne_bytes(), 100i32.to_ne_bytes()].concat();
    let proc_payload = make_proc_event_payload(PROC_EVENT_EXEC, &exec_data);
    let cn_payload = make_cn_msg(&proc_payload);
    let mut buf = make_netlink_message(NLMSG_MIN_TYPE, &cn_payload);
    buf[6..8].copy_from_slice(&NLM_F_REQUEST.to_ne_bytes());

    let event = parse_netlink_message(&buf, buf.len()).unwrap().unwrap();
    assert_eq!(
        event,
        ProcEvent::Exec {
            cpu: 0,
            pid: 42,
            tgid: 100,
            timestamp_ns: 0
        }
    );
}
