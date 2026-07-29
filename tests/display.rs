use proc_connector::ProcEvent;

#[test]
fn display_exec() {
    let event = ProcEvent::Exec {
        cpu: 0,
        pid: 42,
        tgid: 100,
        timestamp_ns: 0,
    };
    assert_eq!(format!("{event}"), "EXEC pid=42 tgid=100 ts=0");
}

#[test]
fn display_comm() {
    let mut comm = [0u8; 16];
    comm[..4].copy_from_slice(b"bash");
    let event = ProcEvent::Comm {
        cpu: 0,
        pid: 1,
        tgid: 1,
        comm,
        timestamp_ns: 0,
    };
    assert_eq!(format!("{event}"), "COMM pid=1 tgid=1 name=\"bash\" ts=0");
}

#[test]
fn display_fork() {
    let event = ProcEvent::Fork {
        cpu: 0,
        parent_pid: 100,
        parent_tgid: 100,
        child_pid: 200,
        child_tgid: 200,
        timestamp_ns: 0,
    };
    assert_eq!(
        format!("{event}"),
        "FORK parent=(100,100) child=(200,200) ts=0"
    );
}

#[test]
fn display_exit() {
    let event = ProcEvent::Exit {
        cpu: 0,
        pid: 42,
        tgid: 42,
        exit_code: 0,
        exit_signal: 17,
        parent_pid: 1,
        parent_tgid: 1,
        timestamp_ns: 0,
    };
    assert_eq!(
        format!("{event}"),
        "EXIT pid=42 tgid=42 code=0 signal=17 parent=(1,1) ts=0"
    );
}

#[test]
fn display_uid() {
    let event = ProcEvent::Uid {
        cpu: 0,
        pid: 1,
        tgid: 1,
        ruid: 1000,
        euid: 0,
        timestamp_ns: 0,
    };
    assert_eq!(format!("{event}"), "UID pid=1 tgid=1 ruid=1000 euid=0 ts=0");
}

#[test]
fn display_gid() {
    let event = ProcEvent::Gid {
        cpu: 0,
        pid: 2,
        tgid: 2,
        rgid: 100,
        egid: 200,
        timestamp_ns: 0,
    };
    assert_eq!(
        format!("{event}"),
        "GID pid=2 tgid=2 rgid=100 egid=200 ts=0"
    );
}

#[test]
fn display_sid() {
    let event = ProcEvent::Sid {
        cpu: 0,
        pid: 3,
        tgid: 3,
        timestamp_ns: 0,
    };
    assert_eq!(format!("{event}"), "SID pid=3 tgid=3 ts=0");
}

#[test]
fn display_ptrace() {
    let event = ProcEvent::Ptrace {
        cpu: 0,
        pid: 10,
        tgid: 10,
        tracer_pid: 99,
        tracer_tgid: 99,
        timestamp_ns: 0,
    };
    assert_eq!(
        format!("{event}"),
        "PTRACE pid=10 tgid=10 tracer=(99,99) ts=0"
    );
}

#[test]
fn display_coredump() {
    let event = ProcEvent::Coredump {
        cpu: 0,
        pid: 7,
        tgid: 7,
        parent_pid: 1,
        parent_tgid: 1,
        timestamp_ns: 0,
    };
    assert_eq!(
        format!("{event}"),
        "COREDUMP pid=7 tgid=7 parent=(1,1) ts=0"
    );
}
