use proptest::prelude::*;

proptest! {
    #[test]
    fn parse_never_panics(data: Vec<u8>) {
        let _ = proc_connector::parse_netlink_message(&data, data.len());
        let _ = proc_connector::parse_cn_msg(&data);
    }
}
