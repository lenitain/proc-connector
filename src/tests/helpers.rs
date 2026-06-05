//! Test helper functions for proc-connector tests.
//!
//! This module contains helper functions used by tests across different modules.

use crate::consts::*;

/// Create a proc_event payload with the given `what` and event data.
pub fn make_proc_event_payload(what: u32, event_data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(PROC_EVENT_HEADER_SIZE + event_data.len());
    buf.extend_from_slice(&what.to_ne_bytes()); // what
    buf.extend_from_slice(&0u32.to_ne_bytes()); // cpu
    buf.extend_from_slice(&0u64.to_ne_bytes()); // timestamp_ns
    buf.extend_from_slice(event_data);
    buf
}

/// Create a proc_event payload with a specific timestamp.
pub fn make_proc_event_payload_with_ts(what: u32, timestamp_ns: u64, event_data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(PROC_EVENT_HEADER_SIZE + event_data.len());
    buf.extend_from_slice(&what.to_ne_bytes());
    buf.extend_from_slice(&0u32.to_ne_bytes()); // cpu
    buf.extend_from_slice(&timestamp_ns.to_ne_bytes());
    buf.extend_from_slice(event_data);
    buf
}

/// Create a cn_msg payload with the given data.
pub fn make_cn_msg(data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(SIZE_CN_MSG + data.len());
    buf.extend_from_slice(&CN_IDX_PROC.to_ne_bytes()); // id.idx
    buf.extend_from_slice(&CN_VAL_PROC.to_ne_bytes()); // id.val
    buf.extend_from_slice(&0u32.to_ne_bytes()); // seq
    buf.extend_from_slice(&0u32.to_ne_bytes()); // ack
    buf.extend_from_slice(&(data.len() as u16).to_ne_bytes()); // len
    buf.extend_from_slice(&0u16.to_ne_bytes()); // flags
    buf.extend_from_slice(data);
    buf
}

/// Create a netlink message with the given type and payload.
pub fn make_netlink_message(nlmsg_type: u16, payload: &[u8]) -> Vec<u8> {
    let hdr_len = nlmsg_hdrlen();
    let total_len = nlmsg_length(payload.len());

    let mut buf = vec![0u8; total_len];
    buf[0..4].copy_from_slice(&(total_len as u32).to_ne_bytes()); // nlmsg_len
    buf[4..6].copy_from_slice(&nlmsg_type.to_ne_bytes()); // nlmsg_type
    buf[6..8].copy_from_slice(&0u16.to_ne_bytes()); // nlmsg_flags
    buf[8..12].copy_from_slice(&0u32.to_ne_bytes()); // nlmsg_seq
    buf[12..16].copy_from_slice(&0u32.to_ne_bytes()); // nlmsg_pid
    buf[hdr_len..hdr_len + payload.len()].copy_from_slice(payload);

    buf
}

/// Create a full netlink message with proc_event payload.
pub fn make_full_message(what: u32, event_data: &[u8]) -> Vec<u8> {
    let proc_payload = make_proc_event_payload(what, event_data);
    let cn_payload = make_cn_msg(&proc_payload);
    make_netlink_message(NLMSG_MIN_TYPE, &cn_payload)
}
