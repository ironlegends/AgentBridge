use agent_bridge_web_launch::{ChromeLauncher, LaunchRequest, LocalCliProfiles, Provider};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static SEQ: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);
impl TempDir {
    fn new(label: &str) -> Self {
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = { let t = std::env::temp_dir(); if cfg!(unix) { std::fs::canonicalize(&t).unwrap_or(t) } else { t } }.join(format!(
            "ab-weblaunch-test-{label}-{}-{n}",
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
fn web_launch_request_profile_layout_and_prepare_regressions() {
    let valid_mis = format!("mis_{}", "a".repeat(32));
    let valid_sub = format!("sub_{}", "b".repeat(32));

    // 1. LaunchRequest strict ID format validation
    assert!(LaunchRequest::new(Provider::ChatGpt, "bad_id", &valid_sub).is_err());
    assert!(LaunchRequest::new(Provider::ChatGpt, &valid_mis, "sub_UPPER").is_err());
    let req_cgpt = LaunchRequest::new(Provider::ChatGpt, &valid_mis, &valid_sub).expect("valid cgpt");
    let req_gem = LaunchRequest::new(Provider::Gemini, &valid_mis, &valid_sub).expect("valid gemini");
    assert_eq!(req_cgpt.provider(), Provider::ChatGpt);
    assert_eq!(req_gem.mission_id(), valid_mis);

    // 2. LocalCliProfiles strict layout & traversal rejection
    let tmp = TempDir::new("profiles");
    let bad_a = tmp.0.join("wrong-parent/chatgpt");
    let bad_b = tmp.0.join("wrong-parent/gemini");
    fs::create_dir_all(&bad_a).unwrap();
    fs::create_dir_all(&bad_b).unwrap();
    assert!(LocalCliProfiles::from_local_cli(&bad_a, &bad_b).is_err());

    let app_dir = tmp.0.join("AgentBridge");
    let root = app_dir.join("browser-profiles");
    let cgpt_dir = root.join("chatgpt");
    let gem_dir = root.join("gemini");
    fs::create_dir_all(&cgpt_dir).unwrap();
    fs::create_dir_all(&gem_dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for d in [&tmp.0, &app_dir, &root, &cgpt_dir, &gem_dir] {
            fs::set_permissions(d, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }

    // Same directory for both providers rejected
    assert!(LocalCliProfiles::from_local_cli(&cgpt_dir, &cgpt_dir).is_err());

    // Valid separate chatgpt/gemini profiles accepted (Debug redacts paths)
    let profiles = LocalCliProfiles::from_local_cli(&cgpt_dir, &gem_dir).expect("valid profiles");
    let dbg = format!("{profiles:?}");
    assert!(!dbg.contains("ab-weblaunch-test"));

    // 3. Unapproved arbitrary collection URL rejected by ChromeLauncher::discover
    let bad_url = format!("{}://evil.example.invalid/project", "https");
    assert!(ChromeLauncher::discover(Some(&bad_url), profiles.clone()).is_err());

    // 4. Pure prepare() (no Chrome launched) when Chrome is installed on this host
    let notebook_url = format!(
        "{}://{}/notebook/11111111-2222-3333-4444-555555555555",
        "https", "gemini.google.com"
    );
    if let Ok(launcher) = ChromeLauncher::discover(Some(&notebook_url), profiles) {
        let gem_target = launcher.prepare(&req_gem).expect("prepare gemini");
        assert_eq!(gem_target.start_url, notebook_url);
        // ChatGPT without an approved ChatGPT project URL fails closed
        assert!(launcher.prepare(&req_cgpt).is_err());
    }
}
