use agent_bridge_lifecycle::{
    launch, parse_host_invocation, stop, LaunchOptions, LifecycleError, StopOptions,
};
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static SEQ: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);
impl TempDir {
    fn new(label: &str) -> Self {
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = { let t = std::env::temp_dir(); if cfg!(unix) { std::fs::canonicalize(&t).unwrap_or(t) } else { t } }.join(format!(
            "ab-lifecycle-test-{label}-{}-{n}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp dir");
        Self(dir)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn host_invocation_parsing_and_fail_closed_lifecycle_guards() {
    // 1. Normal CLI args return Ok(None)
    assert!(parse_host_invocation(&[OsString::from("start"), OsString::from("--port")])
        .unwrap()
        .is_none());

    // 2. Malformed internal host args fail closed
    assert!(matches!(
        parse_host_invocation(&[OsString::from("--agent-bridge-lifecycle-host")]),
        Err(LifecycleError::Invalid(_))
    ));
    assert!(matches!(
        parse_host_invocation(&[
            OsString::from("--agent-bridge-lifecycle-host"),
            OsString::from("--state-dir"),
            OsString::from("/tmp/state"),
            OsString::from("--session-id"),
            OsString::from("../bad-id"),
            OsString::from("--"),
        ]),
        Err(LifecycleError::Invalid(_))
    ));

    // 3. Valid internal host invocation parses cleanly
    let valid_id = "0123456789abcdef0123456789abcdef";
    let parsed = parse_host_invocation(&[
        OsString::from("--agent-bridge-lifecycle-host"),
        OsString::from("--state-dir"),
        OsString::from("C:\\temp\\state"),
        OsString::from("--session-id"),
        OsString::from(valid_id),
        OsString::from("--"),
        OsString::from("--port"),
        OsString::from("18888"),
    ])
    .expect("parse valid host invocation")
    .expect("Some(HostInvocation)");
    assert_eq!(parsed.session_id(), valid_id);
    assert_eq!(parsed.host_args().len(), 2);

    // 4. Launch refuses directory containing arbitrary non-lifecycle files (never adopts foreign data)
    let dirty = TempDir::new("dirty");
    fs::write(dirty.0.join("missions.sqlite"), b"not-lifecycle").unwrap();
    let dirty_res = launch(LaunchOptions {
        state_dir: dirty.0.clone(),
        host_args: vec![],
        timeout: Duration::from_secs(2),
    });
    assert!(dirty_res.is_err(), "launch must refuse foreign directory: {dirty_res:?}");

    // 5. Out-of-bounds timeout rejected
    let empty = TempDir::new("timeout");
    let bad_timeout = launch(LaunchOptions {
        state_dir: empty.0.join("fresh"),
        host_args: vec![],
        timeout: Duration::from_millis(5),
    });
    assert!(matches!(bad_timeout, Err(LifecycleError::Invalid(_))));

    // 6. Stop on nonexistent state directory fails closed (no PID-only or force-kill fallback)
    let missing_stop = stop(StopOptions {
        state_dir: empty.0.join("never-created"),
        timeout: Duration::from_secs(2),
    });
    assert!(missing_stop.is_err(), "stop on missing dir must fail: {missing_stop:?}");
}
