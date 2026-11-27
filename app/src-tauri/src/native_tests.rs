use crate::{backend, state::{save_settings_to_disk, AppRuntime, PanelSettings}};
use std::fs;
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct TestRoot(PathBuf);
impl TestRoot {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "agent-bridge-native-owned-{}-{}",
            std::process::id(), SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        let canonical = fs::canonicalize(path).unwrap();
        #[cfg(windows)]
        let canonical = PathBuf::from(canonical.to_string_lossy().strip_prefix(r"\\?\").unwrap_or(&canonical.to_string_lossy()));
        Self(canonical)
    }
}
impl Drop for TestRoot {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}

#[test]
fn present_invalid_native_config_never_initializes_legacy_state() {
    for invalid in [
        "{",
        r#"{"version":99,"arguments":[]}"#,
        r#"{"version":1,"arguments":["serve"],"unexpected":true}"#,
    ] {
        let root = TestRoot::new();
        let probe = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let mut settings = PanelSettings::default();
        settings.database_path = root.0.join("private/missions.sqlite").display().to_string();
        settings.settings_dir = root.0.join("private/settings").display().to_string();
        settings.lifecycle_dir = root.0.join("private/lifecycle").display().to_string();
        settings.gateway_port = probe.local_addr().unwrap().port();
        save_settings_to_disk(&root.0, &settings).unwrap();
        let settings_before = fs::read(root.0.join("panel-settings.json")).unwrap();
        fs::write(root.0.join("workstation-app.json"), invalid).unwrap();

        let runtime = AppRuntime::new(root.0.clone());
        let result = backend::initialize_local_state(&runtime);
        assert!(result.is_err(), "present native config must never fall back to legacy initialization");
        assert!(!root.0.join("private").exists(), "invalid config must not create runtime state");
        assert_eq!(fs::read(root.0.join("panel-settings.json")).unwrap(), settings_before);
    }
}
#[test]
fn invalid_native_config_cannot_persist_a_legacy_profile_change() {
    let root = TestRoot::new();
    let probe = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let mut settings = PanelSettings::default();
    settings.database_path = root.0.join("legacy/missions.sqlite").display().to_string();
    settings.settings_dir = root.0.join("legacy/settings").display().to_string();
    settings.lifecycle_dir = root.0.join("legacy/lifecycle").display().to_string();
    settings.gateway_port = probe.local_addr().unwrap().port();
    save_settings_to_disk(&root.0, &settings).unwrap();
    fs::write(root.0.join("workstation-app.json"), "{").unwrap();
    let before = fs::read(root.0.join("panel-settings.json")).unwrap();
    let runtime = AppRuntime::new(root.0.clone());
    assert!(backend::set_permission_profile(&runtime, "workspace-write", true).is_err());
    assert_eq!(fs::read(root.0.join("panel-settings.json")).unwrap(), before);
    assert!(!root.0.join("legacy").exists());
}

fn native_fixture(root: &TestRoot) -> (AppRuntime, TcpListener) {
    use agent_bridge_core::CoreDatabase;
    let private = root.0.join("private");
    let project = root.0.join("project");
    fs::create_dir_all(&private).unwrap();
    fs::create_dir(&project).unwrap();
    fs::create_dir(private.join("db")).unwrap();
    let db = private.join("db/missions.sqlite");
    drop(CoreDatabase::initialize_new(&db).unwrap());
    let settings_dir = private.join("settings");
    agent_bridge_lifecycle::initialize_operator_settings(&settings_dir).unwrap();
    for name in ["oauth-workstation", "oauth-missions", "lifecycle"] {
        let path = private.join(name);
        agent_bridge_lifecycle::initialize_operator_settings(&path).unwrap();
        for entry in fs::read_dir(&path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_file() { fs::remove_file(path).unwrap(); }
        }
    }
    let port_reservation = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = port_reservation.local_addr().unwrap().port();
    let arguments = vec![
        "gemini".to_owned(), "workstation".to_owned(), db.display().to_string(),
        private.join("oauth-workstation").display().to_string(),
        "https://workstation.native.example.invalid".to_owned(), port.to_string(),
        "--project".to_owned(), project.display().to_string(),
        "--profile".to_owned(), "fully-unlocked".to_owned(),
        "--missions-state".to_owned(), private.join("oauth-missions").display().to_string(),
        "--missions-origin".to_owned(), "https://missions.native.example.invalid".to_owned(),
        "--settings-dir".to_owned(), settings_dir.display().to_string(),
        "--lifecycle-dir".to_owned(), private.join("lifecycle").display().to_string(),
        "--enable-task-rooms".to_owned(), "--enable-settings-tools".to_owned(),
    ];
    let legacy_probe = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let mut saved = PanelSettings::default();
    saved.database_path = root.0.join("legacy/missions.sqlite").display().to_string();
    saved.settings_dir = root.0.join("legacy/settings").display().to_string();
    saved.lifecycle_dir = root.0.join("legacy/lifecycle").display().to_string();
    saved.gateway_port = legacy_probe.local_addr().unwrap().port();
    save_settings_to_disk(&root.0, &saved).unwrap();
    fs::write(root.0.join("workstation-app.json"), serde_json::json!({
        "version": 1, "arguments": arguments,
    }).to_string()).unwrap();
    drop(port_reservation);
    (AppRuntime::new(root.0.clone()), legacy_probe)
}

struct StopOwned<'a>(&'a AppRuntime);
impl Drop for StopOwned<'_> {
    fn drop(&mut self) { let _ = backend::stop_gateway(self.0); }
}

#[test]
fn native_commands_use_authoritative_live_state_and_serialize_restarts() {
    let root = TestRoot::new();
    let (runtime, _legacy_probe) = native_fixture(&root);
    let initial = backend::get_panel_state(&runtime).unwrap();
    assert_eq!(initial["gateway"]["native"], true, "native configuration must select native ownership");
    assert_eq!(initial["gateway"]["controls"]["canStart"], true);
    assert_eq!(backend::get_sessions(&runtime).unwrap()["available"], false);
    let before = fs::read(root.0.join("panel-settings.json")).unwrap();
    let running = backend::start_or_restart_gateway(&runtime, backend::GatewayIntent::Start).unwrap();
    let _cleanup = StopOwned(&runtime);
    assert_eq!(running["gateway"]["ownedRunning"], true);
    assert_eq!(running["liveProfile"]["activeProfile"], "fully-unlocked");
    let generation = running["gateway"]["generation"].as_u64().unwrap();
    assert!(backend::start_or_restart_gateway(&runtime, backend::GatewayIntent::Start).is_err());
    assert_eq!(backend::get_panel_state(&runtime).unwrap()["gateway"]["generation"], generation);

    let lowered = backend::set_permission_profile(&runtime, "workspace-write", true).unwrap();
    assert_eq!(lowered["liveProfile"]["activeProfile"], "workspace-write");
    assert_eq!(lowered["gateway"]["generation"], generation);
    assert_eq!(fs::read(root.0.join("panel-settings.json")).unwrap(), before);
    assert!(!root.0.join("legacy").exists());
    let snapshot = backend::get_missions_snapshot(&runtime).unwrap();
    assert_eq!(snapshot["exists"], true);
    let sessions = backend::get_sessions(&runtime).unwrap();
    assert_eq!(sessions["available"], true);
    assert_eq!(sessions["liveWindowSeconds"], 120);
    assert_eq!(sessions["sessions"], serde_json::json!([]));

    let restarted = backend::start_or_restart_gateway(&runtime, backend::GatewayIntent::Restart).unwrap();
    assert!(restarted["gateway"]["generation"].as_u64().unwrap() > generation);
    assert_eq!(restarted["liveProfile"]["activeProfile"], "fully-unlocked");
    let stopped = backend::stop_gateway(&runtime).unwrap();
    assert_eq!(stopped["gateway"]["live"], false);
    assert_eq!(stopped["gateway"]["controls"]["canStart"], true);
    assert_eq!(stopped["gateway"]["controls"]["canRestart"], false);
}

#[test]
fn native_cleanup_timeout_keeps_owner_and_disables_replacement_until_drain() {
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpStream;
    use std::time::Duration;
    let root = TestRoot::new();
    let (runtime, _legacy_probe) = native_fixture(&root);
    let panel = backend::start_or_restart_gateway(&runtime, backend::GatewayIntent::Start).unwrap();
    let _cleanup = StopOwned(&runtime);
    let port = panel["gateway"]["port"].as_u64().unwrap() as u16;
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(stream, "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: 10\r\nExpect: 100-continue\r\n\r\n").unwrap();
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    assert!(line.contains("100 Continue"), "{line}");
    assert!(runtime.native_runtime.stop_with_timeout(Duration::from_millis(50)).is_err());
    let incomplete = backend::get_panel_state(&runtime).unwrap();
    assert_eq!(incomplete["gateway"]["controls"]["canStart"], false);
    assert_eq!(incomplete["gateway"]["controls"]["canRestart"], false);
    assert_eq!(incomplete["gateway"]["controls"]["canStop"], true);
    assert!(backend::start_or_restart_gateway(&runtime, backend::GatewayIntent::Start).is_err());
    drop(reader);
    backend::stop_gateway(&runtime).unwrap();
    backend::start_or_restart_gateway(&runtime, backend::GatewayIntent::Start).unwrap();
}

#[test]
fn tunnel_hash_refusal_is_explicit_without_losing_native_backend() {
    let root = TestRoot::new();
    let (initial, legacy_probe) = native_fixture(&root);
    drop(initial);
    let profiles = root.0.join("profiles");
    let tunnel_state = root.0.join("tunnel-state");
    fs::create_dir(&profiles).unwrap();
    fs::create_dir(&tunnel_state).unwrap();
    let program = root.0.join("fixture-tunnel.exe");
    fs::write(&program, b"not an executable and never to be run").unwrap();
    let key = root.0.join("fixture.dpapi");
    fs::write(&key, b"0000").unwrap();
    let config_path = root.0.join("workstation-app.json");
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&config_path).unwrap()).unwrap();
    value["tunnel"] = serde_json::json!({
        "program": program, "sha256": "0".repeat(64), "profile": "native-fixture",
        "profileDir": profiles, "stateDir": tunnel_state, "dpapiKeyPath": key,
        "expectedOrigin": "https://workstation.native.example.invalid",
        "expectedMcpUrl": "https://workstation.native.example.invalid/mcp",
    });
    fs::write(config_path, value.to_string()).unwrap();
    let runtime = AppRuntime::new(root.0.clone());
    let panel = backend::start_or_restart_gateway(&runtime, backend::GatewayIntent::Start).unwrap();
    let _cleanup = StopOwned(&runtime);
    assert_eq!(panel["gateway"]["live"], true);
    assert_eq!(panel["tunnel"]["childRunning"], false);
    assert_eq!(panel["tunnel"]["state"], "configuration-error");
    assert!(panel["tunnel"]["error"].as_str().unwrap().contains("SHA-256"));
    assert!(panel["tunnel"]["remoteReady"].is_null());
    let diagnostics = runtime.native_runtime.read(
        agent_bridge_runtime::backend::OperatorRead::Diagnostics).unwrap();
    let audit = &diagnostics["mcp_request_audit"];
    let records = audit["records"].as_array().unwrap();
    let tunnel_event = records.iter().find(|record| record["method"] == "tunnel/start").unwrap();
    assert_eq!(tunnel_event["outcome"], "lifecycle_error");
    assert_eq!(tunnel_event["error_code"], "tunnel_start_failed");
    assert!(tunnel_event["http_status"].is_null());
    assert!(tunnel_event["provider"].is_null());
    assert!(!audit.to_string().contains("fixture-tunnel.exe"));
    assert!(!audit.to_string().contains("SHA-256"));
    drop(legacy_probe);
}

#[test]
fn native_profile_receipt_never_crosses_a_stopped_or_replaced_generation() {
    for restart in [true, false] {
        let root = TestRoot::new();
        let (runtime, _legacy_probe) = native_fixture(&root);
        let runtime = std::sync::Arc::new(runtime);
        let started = backend::start_or_restart_gateway(&runtime, backend::GatewayIntent::Start).unwrap();
        let _cleanup = StopOwned(&runtime);
        let previous = started["gateway"]["generation"].as_u64().unwrap();
        let transitioning = std::sync::Arc::clone(&runtime);
        runtime.checkpoints.lock().unwrap().insert("after-profile-write", Box::new(move || {
            transitioning.native_runtime.stop().unwrap();
            if restart {
                transitioning.native_runtime.start(transitioning.native_config.require().unwrap()).unwrap();
            }
        }));
        let result = backend::set_permission_profile(&runtime, "read-only", true);
        assert!(result.is_err(), "a mutation receipt must be invalidated after its owner stops or changes: {result:?}");
        let current = backend::get_panel_state(&runtime).unwrap();
        if restart {
            assert!(current["gateway"]["generation"].as_u64().unwrap() > previous);
            assert_eq!(current["liveProfile"]["activeProfile"], "fully-unlocked");
            assert_eq!(current["gateway"]["live"], true);
        } else {
            assert_eq!(current["gateway"]["live"], false);
            assert_eq!(current["gateway"]["stopped"], true);
            assert!(current["gateway"]["lastError"].is_null());
        }
    }
}

#[test]
fn native_panel_does_not_mix_reads_across_a_restart_or_publish_live_after_stop() {
    for restart in [true, false] {
        let root = TestRoot::new();
        let (runtime, _legacy_probe) = native_fixture(&root);
        let runtime = std::sync::Arc::new(runtime);
        backend::start_or_restart_gateway(&runtime, backend::GatewayIntent::Start).unwrap();
        let _cleanup = StopOwned(&runtime);
        backend::set_permission_profile(&runtime, "read-only", true).unwrap();
        let transitioning = std::sync::Arc::clone(&runtime);
        runtime.checkpoints.lock().unwrap().insert("after-panel-profile", Box::new(move || {
            transitioning.native_runtime.stop().unwrap();
            if restart {
                transitioning.native_runtime.start(transitioning.native_config.require().unwrap()).unwrap();
            }
        }));
        let result = backend::get_panel_state(&runtime);
        assert!(result.is_err(), "a panel collected across a lifecycle transition must be discarded: {result:?}");
        let current = backend::get_panel_state(&runtime).unwrap();
        assert_eq!(current["gateway"]["live"], restart);
        assert_eq!(current["gateway"]["ownedRunning"], restart);
        if restart { assert_eq!(current["liveProfile"]["activeProfile"], "fully-unlocked"); }
        else {
            assert_eq!(current["gateway"]["stopped"], true);
            assert!(current["liveProfile"]["error"].is_null());
            assert_eq!(current["gateway"]["controls"]["canStart"], true);
        }
    }
}

#[test]
fn legacy_start_and_restart_recheck_quit_admission_under_the_gateway_mutex() {
    for intent in [backend::GatewayIntent::Start, backend::GatewayIntent::Restart] {
        let root = TestRoot::new();
        let mut settings = PanelSettings::default();
        settings.database_path.clear();
        settings.settings_dir.clear();
        settings.lifecycle_dir.clear();
        save_settings_to_disk(&root.0, &settings).unwrap();
        let runtime = std::sync::Arc::new(AppRuntime::new(root.0.clone()));
        let quitting = std::sync::Arc::clone(&runtime);
        runtime.checkpoints.lock().unwrap().insert("before-legacy-start-lock", Box::new(move || {
            quitting.native_runtime.set_closing(true);
            quitting.gateway.lock().unwrap().stop().unwrap();
        }));
        let error = backend::start_or_restart_gateway(&runtime, intent).unwrap_err();
        assert!(error.contains("quitting"), "Quit must refuse admission before initialization or spawn: {error}");
        assert!(!runtime.gateway.lock().unwrap().is_owned_running());
        assert!(!root.0.join("missions.sqlite").exists());
    }
}

#[test]
fn native_automatic_start_keeps_success_when_its_presentation_read_is_busy() {
    let root = TestRoot::new();
    let (runtime, _legacy_probe) = native_fixture(&root);
    let runtime = std::sync::Arc::new(runtime);
    let _cleanup = StopOwned(&runtime);
    let (begin, begin_rx) = std::sync::mpsc::channel();
    let (held, held_rx) = std::sync::mpsc::channel();
    let (release, release_rx) = std::sync::mpsc::channel();
    let reader = std::sync::Arc::clone(&runtime);
    let competing_read = std::thread::spawn(move || {
        begin_rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap();
        reader.native_runtime.with_ownership_lock(|| {
            held.send(()).unwrap();
            release_rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap();
        });
    });
    runtime.checkpoints.lock().unwrap().insert("after-panel-profile", Box::new(move || {
        begin.send(()).unwrap();
        held_rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap();
    }));
    let initialized = backend::initialize_native_for_app(&runtime);
    release.send(()).unwrap();
    competing_read.join().unwrap();
    let initialized = initialized.expect("a successful backend Start is not a fatal startup failure when presentation is busy");
    assert!(initialized.panel.is_err(), "the contended panel is deferred, never fabricated");
    assert!(runtime.native_runtime.snapshot().running);
    assert!(!runtime.native_runtime.is_closing());
    let fresh = backend::get_panel_state(&runtime).unwrap();
    assert_eq!(fresh["gateway"]["live"], true);
    assert_eq!(fresh["liveProfile"]["activeProfile"], "fully-unlocked");
    assert_eq!(fresh["gateway"]["generation"],
        runtime.native_runtime.snapshot().descriptor.unwrap().generation);
}

#[test]
fn native_panel_contention_is_busy_without_claiming_a_generation_change() {
    let root = TestRoot::new();
    let (runtime, _legacy_probe) = native_fixture(&root);
    backend::start_or_restart_gateway(&runtime, backend::GatewayIntent::Start).unwrap();
    let _cleanup = StopOwned(&runtime);
    let original = runtime.native_runtime.snapshot();
    runtime.native_runtime.with_ownership_lock(|| {
        let error = runtime.native_runtime.revalidate_view(&original).err().unwrap();
        assert!(error.contains("busy"), "an occupied mutex is a retryable presentation state: {error}");
        assert!(!error.contains("changed"), "contention alone proves no generation transition");
    });
    let current = runtime.native_runtime.revalidate_view(&original).unwrap();
    assert!(current.running);
    assert_eq!(current.descriptor.unwrap().generation, original.descriptor.unwrap().generation);
}

#[test]
fn native_automatic_start_still_reports_a_real_backend_start_failure() {
    let root = TestRoot::new();
    let (runtime, _legacy_probe) = native_fixture(&root);
    let port: u16 = runtime.native_config.require().unwrap().arguments[5].parse().unwrap();
    let _occupied = TcpListener::bind(("127.0.0.1", port)).unwrap();
    assert!(backend::initialize_native_for_app(&runtime).is_err());
    let view = runtime.native_runtime.snapshot();
    assert!(!view.running && !view.owned);
    assert!(view.error.is_some());
    assert!(!root.0.join("legacy").exists());
}

fn configured_tunnel_fixture(root: &TestRoot) -> serde_json::Value {
    let (runtime, _probe) = native_fixture(root);
    assert!(!runtime.native_runtime.snapshot().owned);
    let mut value: serde_json::Value = serde_json::from_slice(
        &fs::read(root.0.join("workstation-app.json")).unwrap()).unwrap();
    value["tunnel"] = serde_json::json!({
        "program": root.0.join("fixture-client.exe"), "sha256": "0".repeat(64),
        "profile": "fixture", "profileDir": root.0.join("tunnel/profiles"),
        "stateDir": root.0.join("tunnel/state"), "dpapiKeyPath": root.0.join("tunnel/key.dpapi"),
        "expectedOrigin": "https://workstation.native.example.invalid",
        "expectedMcpUrl": "https://workstation.native.example.invalid/mcp",
    });
    value
}

#[test]
fn native_tunnel_origin_accepts_only_the_shared_parser_equivalences() {
    let root = TestRoot::new();
    let template = configured_tunnel_fixture(&root);
    for origin in [
        "https://workstation.native.example.invalid",
        "https://workstation.native.example.invalid/",
        "https://WORKSTATION.NATIVE.EXAMPLE.INVALID",
        "https://workstation.native.example.invalid:443",
        "https://WORKSTATION.NATIVE.EXAMPLE.INVALID:0443/",
    ] {
        let mut value = template.clone();
        value["arguments"][4] = serde_json::json!(origin);
        fs::write(root.0.join("workstation-app.json"), value.to_string()).unwrap();
        let selected = crate::native_config::NativeConfig::load(&root.0, None);
        let config = selected.require().unwrap_or_else(|error| panic!("{origin}: {error}"));
        assert_eq!(config.arguments[4], origin, "comparison must not rewrite the selected CLI arguments");
        assert_eq!(config.tunnel.as_ref().unwrap().expected_mcp_url,
            "https://workstation.native.example.invalid/mcp");
    }
    assert!(!root.0.join("legacy").exists());
    assert!(!root.0.join("tunnel").exists(), "config comparison never initializes or starts the companion");
}

#[test]
fn native_tunnel_origin_refuses_other_resources_and_preserves_the_literal_target_pin() {
    let root = TestRoot::new();
    let template = configured_tunnel_fixture(&root);
    for (origin, target) in [
        ("https://other.native.example.invalid", "https://workstation.native.example.invalid"),
        ("https://workstation.native.example.invalid:444", "https://workstation.native.example.invalid"),
        ("https://workstation.native.example.invalid/path", "https://workstation.native.example.invalid"),
        ("https://workstation.native.example.invalid//", "https://workstation.native.example.invalid"),
        ("https://workstation.native.example.invalid", "https://WORKSTATION.NATIVE.EXAMPLE.INVALID"),
        ("https://workstation.native.example.invalid", "https://workstation.native.example.invalid:443"),
        ("https://127.1", "https://127.0.0.1"),
    ] {
        let mut value = template.clone();
        value["arguments"][4] = serde_json::json!(origin);
        value["tunnel"]["expectedOrigin"] = serde_json::json!(target);
        value["tunnel"]["expectedMcpUrl"] = serde_json::json!(format!("{target}/mcp"));
        fs::write(root.0.join("workstation-app.json"), value.to_string()).unwrap();
        assert!(crate::native_config::NativeConfig::load(&root.0, None).require().is_err(),
            "a different or invalid identity must not become equivalent: {origin} => {target}");
    }
    assert!(!root.0.join("tunnel").exists());
}

#[test]
fn native_quit_blocks_start_and_retains_owner_on_stop_timeout() {
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    let root = TestRoot::new();
    let (runtime, _legacy_probe) = native_fixture(&root);
    let panel = backend::start_or_restart_gateway(&runtime, backend::GatewayIntent::Start).unwrap();
    let _cleanup = StopOwned(&runtime);
    let port = panel["gateway"]["port"].as_u64().unwrap() as u16;
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(stream, "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: 10\r\nExpect: 100-continue\r\n\r\n").unwrap();
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    assert!(line.contains("100 Continue"), "{line}");

    runtime.native_runtime.set_closing(true);
    let closing_panel = backend::get_panel_state(&runtime).unwrap();
    assert_eq!(closing_panel["gateway"]["controls"]["canStart"], false);
    assert_eq!(closing_panel["gateway"]["controls"]["canRestart"], false);
    let refused_start = runtime.native_runtime.start(runtime.native_config.require().unwrap()).unwrap_err();
    assert!(refused_start.contains("quitting"), "{refused_start}");

    assert!(runtime.native_runtime.stop_with_timeout(Duration::from_millis(50)).is_err());
    runtime.native_runtime.set_closing(false);
    let incomplete = backend::get_panel_state(&runtime).unwrap();
    let snapshot = runtime.native_runtime.snapshot();
    assert!(snapshot.owned && snapshot.cleanup_failed);
    assert_eq!(incomplete["gateway"]["controls"]["canStart"], false);
    assert_eq!(incomplete["gateway"]["controls"]["canRestart"], false);
    assert_eq!(incomplete["gateway"]["controls"]["canStop"], true);
    assert!(backend::start_or_restart_gateway(&runtime, backend::GatewayIntent::Start).is_err());

    drop(reader);
    runtime.native_runtime.set_closing(true);
    runtime.native_runtime.stop().unwrap();
    let stopped = runtime.native_runtime.snapshot();
    assert!(!stopped.owned && !stopped.running && !stopped.cleanup_failed);
    let refused_after_stop = runtime.native_runtime.start(runtime.native_config.require().unwrap()).unwrap_err();
    assert!(refused_after_stop.contains("quitting"), "{refused_after_stop}");
}
