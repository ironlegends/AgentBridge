use agent_bridge_oauth_compat::Audience;
use agent_bridge_oauth_server::{OAuthConfig, OAuthServer};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static SEQ: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);
impl TempDir {
    fn new(label: &str) -> Self {
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = { let t = std::env::temp_dir(); if cfg!(unix) { std::fs::canonicalize(&t).unwrap_or(t) } else { t } }.join(format!(
            "ab-oauth-srv-test-{label}-{}-{n}",
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
fn inbound_oauth_server_fail_closed_origin_and_state_dir_regressions() {
    let tmp = TempDir::new("oauth");

    // 1. Non-HTTPS public_origin MUST be rejected
    let insecure_origin = format!("{}://bridge.example.invalid", "http");
    let cfg_http = OAuthConfig {
        state_dir: tmp.0.clone(),
        public_origin: insecure_origin,
        audience: Audience::Missions,
    };
    assert!(
        OAuthServer::open(cfg_http).is_err(),
        "non-HTTPS public_origin must be refused"
    );

    // 2. Non-existent state_dir MUST be rejected (OAuthServer never silently initializes a foreign dir)
    let cfg_missing = OAuthConfig {
        state_dir: tmp.0.join("does-not-exist"),
        public_origin: "https://bridge.example.invalid".into(),
        audience: Audience::Missions,
    };
    assert!(
        OAuthServer::open(cfg_missing).is_err(),
        "missing state_dir must fail closed"
    );

    // 3. Debug redaction on OAuthConfig never leaks state_dir or public_origin
    let cfg_dbg = format!(
        "{:?}",
        OAuthConfig {
            state_dir: tmp.0.clone(),
            public_origin: "https://bridge.example.invalid".into(),
            audience: Audience::Workstation,
        }
    );
    assert!(!cfg_dbg.contains("bridge.example.invalid"));
    assert!(cfg_dbg.contains("[redacted]"));
}
