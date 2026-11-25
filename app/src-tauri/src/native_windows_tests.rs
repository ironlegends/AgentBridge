use super::*;
use crate::native_tunnel::ManagedTunnel;
use std::io::Write;
use std::os::windows::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);
const KEY: &str = "fixture-tunnel-key-only";
struct Directory(std::path::PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("native-tunnel-{}-{}",
            std::process::id(), SEQUENCE.fetch_add(1, Ordering::Relaxed)));
        std::fs::create_dir(&path).unwrap();
        let path = std::fs::canonicalize(path).unwrap();
        Self(std::path::PathBuf::from(path.to_string_lossy().strip_prefix(r"\\?\").unwrap_or(&path.to_string_lossy())))
    }
}
impl Drop for Directory { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); } }
struct Witness(Child);
impl Drop for Witness { fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); } }

fn await_file(path: &Path) -> serde_json::Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(bytes) = std::fs::read(path) {
            if let Ok(value) = serde_json::from_slice(&bytes) { return value; }
        }
        assert!(Instant::now() < deadline, "fixture did not become ready");
        std::thread::sleep(Duration::from_millis(20));
    }
}
fn await_exit(handle: HANDLE) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let mut code = 0;
        unsafe { GetExitCodeProcess(handle, &mut code).unwrap(); }
        if code != 259 { return; }
        assert!(Instant::now() < deadline, "owned child survived Job cleanup");
        std::thread::sleep(Duration::from_millis(20));
    }
}
fn config(root: &Directory) -> TunnelConfig {
    for path in ["profiles", "state", "state/logs", "state/health"] {
        std::fs::create_dir(root.0.join(path)).unwrap();
    }
    let credentials = root.0.join("credentials");
    agent_bridge_lifecycle::initialize_operator_settings(&credentials).unwrap();
    let program = root.0.join("fixture-tunnel.exe");
    std::fs::copy(std::env::current_exe().unwrap(), &program).unwrap();
    let sha256 = format!("{:x}", Sha256::digest(std::fs::read(&program).unwrap()));
    let config = TunnelConfig {
        program, sha256, profile: "fixture".into(), profile_dir: root.0.join("profiles"),
        state_dir: root.0.join("state"), dpapi_key_path: credentials.join("runtime-key.dpapi"),
        expected_mcp_url: "https://native.example.invalid/mcp".into(),
        expected_origin: "https://native.example.invalid".into(),
    };
    let profile = serde_json::json!({
        "config_version": 1, "admin_ui": { "open_browser": false },
        "control_plane": { "api_key": "env:AGENT_BRIDGE_TUNNEL_API_KEY",
            "base_url": "https://api.openai.com", "tunnel_id": "tunnel_fixture" },
        "health": { "listen_addr": "127.0.0.1:0", "url_file": config.state_dir.join("health/fixture.url") },
        "log": { "file": config.state_dir.join("logs/fixture.log"), "format": "json", "level": "info" },
        "mcp": { "server_urls": [{ "channel": "main", "url": config.expected_mcp_url }] },
    });
    std::fs::write(config.profile_dir.join("fixture.yaml"), profile.to_string()).unwrap();
    let powershell = std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap())
        .join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let encrypted = Command::new(powershell).args(["-NoProfile", "-NonInteractive", "-Command",
        "$s=ConvertTo-SecureString -String 'fixture-tunnel-key-only' -AsPlainText -Force; ConvertFrom-SecureString $s"])
        .creation_flags(CREATE_NO_WINDOW.0).stdin(Stdio::null()).output().unwrap();
    assert!(encrypted.status.success(), "fixture DPAPI creation failed");
    private_log(&config.dpapi_key_path).unwrap().write_all(&encrypted.stdout).unwrap();
    config
}
fn fixture_environment(config: &TunnelConfig, directory: &Path) -> Zeroizing<Vec<u16>> {
    let public = format!("AB_NATIVE_FIXTURE_ROOT={}", directory.display());
    let mut env = Zeroizing::new(public.encode_utf16().collect::<Vec<_>>());
    env.push(0);
    env.extend_from_slice(&child_environment(config, KEY).unwrap());
    env
}
fn query_handle(pid: u32) -> Handle {
    Handle(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).unwrap() })
}

#[test]
fn dpapi_interoperates_with_powershell_and_bad_inputs_fail_before_spawn() {
    let root = Directory::new();
    let mut selected = config(&root);
    let mut pins = Vec::new();
    let key_file = pinned_file(&selected.dpapi_key_path, &mut pins).unwrap();
    assert_eq!(&*unprotect_key(&key_file).unwrap(), KEY);
    drop(key_file);
    drop(pins);
    selected.sha256 = "0".repeat(64);
    let failure = TunnelChild::spawn(&selected, &mut None).err().expect("wrong hash must fail");
    assert!(failure.contains("SHA-256"));
    assert!(!selected.state_dir.join("logs/native-tunnel.stdout.log").exists());
    selected.sha256 = format!("{:x}", Sha256::digest(std::fs::read(&selected.program).unwrap()));
    std::fs::write(&selected.dpapi_key_path, b"0000").unwrap();
    let failure = TunnelChild::spawn(&selected, &mut None).err().expect("invalid DPAPI must fail");
    assert!(failure.contains("DPAPI"));
    assert!(!failure.contains(KEY));
    assert!(!selected.state_dir.join("logs/native-tunnel.stdout.log").exists());
}

#[test]
fn silent_owned_job_drains_descendants_and_preserves_foreign_process_and_diagnostics() {
    let root = Directory::new();
    let config = config(&root);
    let foreign_dir = Directory::new();
    let mut foreign = Witness(Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "native_windows::tests::owned_leaf_fixture", "--ignored", "--nocapture"])
        .env("AB_NATIVE_FIXTURE_ROOT", &foreign_dir.0).creation_flags(CREATE_NO_WINDOW.0)
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
    await_file(&foreign_dir.0.join("leaf.json"));
    for explicit in [true, false] {
        let run = Directory::new();
        let out = private_log(&run.0.join("stdout.log")).unwrap();
        let err = private_log(&run.0.join("stderr.log")).unwrap();
        let args: &[&OsStr] = &[
            OsStr::new("--exact"), OsStr::new("native_windows::tests::owned_child_fixture"),
            OsStr::new("--ignored"), OsStr::new("--nocapture"),
        ];
        let mut environment = fixture_environment(&config, &run.0);
        let mut child = OwnedProcess::spawn(&std::env::current_exe().unwrap(), args,
            &run.0, &mut environment, &out, &err).unwrap();
        let parent = await_file(&run.0.join("parent.json"));
        let leaf = await_file(&run.0.join("leaf.json"));
        assert_eq!(parent["console"], false);
        assert_eq!(leaf["console"], false);
        assert_eq!(parent["keyInEnvironment"], true);
        assert_eq!(parent["keyInArguments"], false);
        assert_eq!(parent["inheritedPath"], false);
        assert_eq!(parent["trusted"], config.expected_origin);
        assert_eq!(parent["forward"], config.expected_origin);
        assert_eq!(parent["plaintext"], "false");
        let parent_handle = query_handle(child.pid);
        let leaf_handle = query_handle(leaf["pid"].as_u64().unwrap() as u32);
        if explicit {
            child.stop().unwrap();
            assert_eq!(child.exited().unwrap(), Some(1));
        }
        drop(child);
        await_exit(parent_handle.0);
        await_exit(leaf_handle.0);
        assert!(foreign.0.try_wait().unwrap().is_none(), "unrelated child must survive");
        let stdout = std::fs::read_to_string(run.0.join("stdout.log")).unwrap();
        let stderr = std::fs::read_to_string(run.0.join("stderr.log")).unwrap();
        assert!(stdout.contains("fixture stdout"));
        assert!(stderr.contains("fixture stderr"));
        assert!(!stdout.contains(KEY) && !stderr.contains(KEY));
    }
}

#[test]
fn tunnel_retry_rechecks_image_and_stop_cancels_the_pending_generation() {
    let root = Directory::new();
    let selected = config(&root);
    let mut tunnel = ManagedTunnel::new(selected.clone());
    tunnel.start();
    assert!(tunnel.snapshot().child_running, "{:?}", tunnel.snapshot().error);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        tunnel.tick();
        if tunnel.snapshot().state == "backoff" { break; }
        assert!(Instant::now() < deadline, "fixture did not exit");
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(tunnel.snapshot().last_exit_code.is_some());
    std::fs::write(&selected.program, b"changed image must never run").unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        tunnel.tick();
        if tunnel.snapshot().state == "configuration-error" { break; }
        assert!(Instant::now() < deadline, "retry did not revalidate its image");
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(tunnel.snapshot().error.unwrap().contains("SHA-256"));
    assert!(!tunnel.snapshot().child_running);
    tunnel.stop().unwrap();
    assert!(!tunnel.tick());
}

#[test]
#[ignore = "owned process fixture"]
fn owned_child_fixture() {
    let root = std::path::PathBuf::from(std::env::var_os("AB_NATIVE_FIXTURE_ROOT").unwrap());
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "native_windows::tests::owned_leaf_fixture", "--ignored", "--nocapture"])
        .creation_flags(CREATE_NO_WINDOW.0).stdin(Stdio::null())
        .stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    println!("fixture stdout");
    eprintln!("fixture stderr");
    std::io::stdout().flush().unwrap();
    std::io::stderr().flush().unwrap();
    std::fs::write(root.join("parent.json"), serde_json::json!({
        "pid": std::process::id(), "child": child.id(),
        "console": !unsafe { GetConsoleWindow() }.0.is_null(),
        "keyInEnvironment": std::env::var("AGENT_BRIDGE_TUNNEL_API_KEY").ok().as_deref() == Some(KEY),
        "keyInArguments": std::env::args().any(|arg| arg.contains(KEY)),
        "inheritedPath": std::env::var_os("PATH").is_some(),
        "trusted": std::env::var("MCP_OAUTH_TRUSTED_ORIGINS").unwrap(),
        "forward": std::env::var("HARPOON_OAUTH_FORWARD_ORIGINS").unwrap(),
        "plaintext": std::env::var("HARPOON_ALLOW_PLAINTEXT_HTTP").unwrap(),
    }).to_string()).unwrap();
    loop { std::thread::sleep(Duration::from_secs(1)); }
}
#[test]
#[ignore = "owned process fixture"]
fn owned_leaf_fixture() {
    let root = std::path::PathBuf::from(std::env::var_os("AB_NATIVE_FIXTURE_ROOT").unwrap());
    std::fs::write(root.join("leaf.json"), serde_json::json!({
        "pid": std::process::id(), "console": !unsafe { GetConsoleWindow() }.0.is_null(),
    }).to_string()).unwrap();
    loop { std::thread::sleep(Duration::from_secs(1)); }
}

#[test]
fn tunnel_retry_refuses_a_different_remote_identity_under_the_same_profile_alias() {
    let root = Directory::new();
    let selected = config(&root);
    let profile_path = selected.profile_dir.join("fixture.yaml");
    let mut tunnel = ManagedTunnel::new(selected.clone());
    tunnel.start();
    assert!(tunnel.snapshot().child_running, "{:?}", tunnel.snapshot().error);
    let deadline = Instant::now() + Duration::from_secs(10);
    while tunnel.snapshot().state != "backoff" {
        tunnel.tick();
        assert!(Instant::now() < deadline, "fixture did not reach retry backoff");
        std::thread::sleep(Duration::from_millis(20));
    }
    let mut profile: serde_json::Value = serde_json::from_slice(&std::fs::read(&profile_path).unwrap()).unwrap();
    profile["control_plane"]["tunnel_id"] = serde_json::json!("tunnel_other_identity");
    std::fs::write(&profile_path, profile.to_string()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while tunnel.snapshot().state == "backoff" {
        tunnel.tick();
        assert!(Instant::now() < deadline, "retry did not read its profile");
        std::thread::sleep(Duration::from_millis(20));
    }
    let refused = tunnel.snapshot();
    assert_eq!(refused.state, "configuration-error", "a retry must retain the first validated remote identity");
    assert!(!refused.child_running);
    assert!(refused.error.unwrap().contains("identity"));
    tunnel.stop().unwrap();
    assert!(!tunnel.tick());
}
