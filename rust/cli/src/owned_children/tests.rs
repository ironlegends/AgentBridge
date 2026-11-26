//! Real Windows children exercise ownership, pipes and per-child configuration.
use super::*;
use serde_json::{json, Value};
use crate::test_process_fixture::{program as fixture_program, args as fixture_args};
use std::time::{Duration, Instant};

const FIXTURE: &str = "owned_children::tests::protocol_fixture";

thread_local! {
    static BIRTH_READ_FAULT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
pub(super) fn birth_read_fault() -> bool { BIRTH_READ_FAULT.get() }
struct BirthReadFault;
impl BirthReadFault {
    fn arm() -> Self { BIRTH_READ_FAULT.set(true); Self }
}
impl Drop for BirthReadFault {
    fn drop(&mut self) { BIRTH_READ_FAULT.set(false); }
}


fn spec() -> ChildSpec {
    ChildSpec {
        executable:fixture_program(),
        arguments:fixture_args(FIXTURE,&[]).into_iter().map(OsString::from).collect(),
        cwd: std::env::temp_dir(),
        env_overrides: BTreeMap::new(),
    }
}

fn send(child: &mut OwnedChild, value: Value) {
    let mut bytes = serde_json::to_vec(&value).unwrap();
    bytes.push(b'\n');
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut offset = 0;
    while offset < bytes.len() {
        match child.write_stdin(&bytes[offset..]) {
            Ok(count) => offset += count,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => panic!("fixture input failed: {error}"),
        }
        assert!(Instant::now() < deadline, "fixture input blocked");
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn read_until(child: &mut OwnedChild, needle: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match child.read_stdout(&mut buf) {
            Ok(count) => out.extend_from_slice(&buf[..count]),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => panic!("fixture output failed: {error}"),
        }
        let text = String::from_utf8_lossy(&out);
        if text.split_once(needle).is_some_and(|(_, tail)| tail.contains('\n')) { return text.into_owned(); }
        assert!(Instant::now() < deadline, "missing {needle:?}: {text}");
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn finish(child: &mut OwnedChild) -> (ChildExit, String, String) {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        for (is_err, output) in [(false, &mut stdout), (true, &mut stderr)] {
            loop {
                let result = if is_err { child.read_stderr(&mut buf) }
                    else { child.read_stdout(&mut buf) };
                match result {
                    Ok(0) => break,
                    Ok(count) => output.extend_from_slice(&buf[..count]),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => panic!("drain failed: {error}"),
                }
            }
        }
        if let Some(exit) = child.finish().unwrap() {
            // Root and all Job members are gone; drain any final kernel pipe data.
            for (is_err, output) in [(false, &mut stdout), (true, &mut stderr)] {
                loop {
                    let result = if is_err { child.read_stderr(&mut buf) }
                        else { child.read_stdout(&mut buf) };
                    match result {
                        Ok(0) => break,
                        Ok(count) => output.extend_from_slice(&buf[..count]),
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        Err(error) => panic!("final drain failed: {error}"),
                    }
                }
            }
            return (exit, String::from_utf8_lossy(&stdout).into_owned(),
                String::from_utf8_lossy(&stderr).into_owned());
        }
        assert!(Instant::now() < deadline, "owned cleanup did not finish");
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn probe(text: &str) -> Value {
    let line = text.lines().find_map(|line| line.split_once("probe:").map(|(_, rest)| rest))
        .unwrap_or_else(|| panic!("missing probe: {text}"));
    serde_json::from_str(line).unwrap()
}

#[test]
fn child_environment_and_literal_arguments_do_not_change_parent_or_open_console() {
    let before_marker = std::env::var_os("AGENT_BRIDGE_OWNED_TEST_MARKER");
    let before_cpu = std::env::var_os("CARGO_MANIFEST_DIR");
    assert!(before_cpu.is_some(), "Cargo must supply the inherited variable being removed");
    let literal = r#"quoted "value" \tail\ ; $HOME & literal €"#;
    let mut launch = spec();
    launch.arguments.extend(["--skip".into(), literal.into()]);
    launch.env_overrides.insert("agent_bridge_owned_test_marker".into(), Some("isolated €".into()));
    launch.env_overrides.insert("cargo_manifest_dir".into(), None);
    let mut child = OwnedChild::spawn(&launch).expect("provider boundary must launch an owned child");
    read_until(&mut child, "fixture-ready");
    send(&mut child, json!({"action":"probe"}));
    let observed = probe(&read_until(&mut child, "probe:"));
    assert_eq!(observed["pid"], child.root_pid());
    assert_eq!(observed["console"], false);
    assert_eq!(observed["argv"].as_array().unwrap().last().unwrap(), literal);
    assert_eq!(observed["marker"], "isolated €");
    assert_eq!(observed["cargo_manifest_dir"], Value::Null);
    assert_eq!(std::env::var_os("AGENT_BRIDGE_OWNED_TEST_MARKER"), before_marker);
    assert_eq!(std::env::var_os("CARGO_MANIFEST_DIR"), before_cpu);
    send(&mut child, json!({"action":"exit","code":7}));
    let (exit, _, stderr) = finish(&mut child);
    assert_eq!(exit.code, Some(7));
    assert!(stderr.contains("owned-child-stderr"));
}

#[test]
fn finish_requires_empty_job_and_owned_membership_rejects_foreign_and_exited_pids() {
    let mut child = OwnedChild::spawn(&spec()).unwrap();
    read_until(&mut child, "fixture-ready");
    assert!(child.owns_process(child.root_pid()).unwrap());
    assert!(!child.owns_process(std::process::id()).unwrap());
    assert!(!child.owns_process(0).unwrap());
    assert!(!child.owns_process(u32::MAX).unwrap());
    let heartbeat = std::env::temp_dir().join(format!(
        "agent-bridge-owned-heartbeat-{}-{}", std::process::id(), child.root_pid()));
    assert!(!heartbeat.exists());
    send(&mut child, json!({"action":"spawn","path":heartbeat}));
    let out = read_until(&mut child, "descendant:");
    let descendant: u32 = out.lines().find_map(|line|
        line.split_once("descendant:").map(|(_, pid)| pid.parse().unwrap())).unwrap();
    assert!(child.owns_process(descendant).unwrap());
    let deadline = Instant::now() + Duration::from_secs(5);
    while std::fs::metadata(&heartbeat).map(|m| m.len()).unwrap_or(0) < 3 {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    send(&mut child, json!({"action":"exit","code":3}));
    let deadline = Instant::now() + Duration::from_secs(5);
    while child.try_exit().unwrap().is_none() {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(child.finish().unwrap().is_none(), "live descendant must retain cleanup ownership");
    assert!(!child.owns_process(child.root_pid()).unwrap(), "exited root is no longer a live placement target");
    assert!(child.owns_process(descendant).unwrap());
    child.terminate().unwrap();
    let (exit, _, _) = finish(&mut child);
    assert_eq!(exit.code, Some(3));
    assert!(!child.owns_process(descendant).unwrap());
    let size = std::fs::metadata(&heartbeat).unwrap().len();
    std::thread::sleep(Duration::from_millis(60));
    assert_eq!(std::fs::metadata(&heartbeat).unwrap().len(), size);
    std::fs::remove_file(heartbeat).unwrap();
}

#[test]
fn full_input_pipe_is_nonblocking_and_owner_survives_a_caller_timeout() {
    let mut child = OwnedChild::spawn(&spec()).unwrap();
    read_until(&mut child, "fixture-ready");
    send(&mut child, json!({"action":"block-input"}));
    read_until(&mut child, "input-blocked");
    let mut small = [0u8; 8];
    assert_eq!(child.read_stdout(&mut small).unwrap_err().kind(), io::ErrorKind::WouldBlock);
    let bytes = vec![b'x'; 64 * 1024];
    let start = Instant::now();
    let mut blocked = false;
    for _ in 0..128 {
        match child.write_stdin(&bytes) {
            Ok(count) => assert!(count <= bytes.len()),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => { blocked = true; break; }
            Err(error) => panic!("unexpected stdin failure: {error}"),
        }
    }
    assert!(blocked, "unread finite pipe should fill");
    assert!(start.elapsed() < Duration::from_secs(1), "stdin operation blocked");
    assert!(child.finish().unwrap().is_none(), "caller timeout is not cleanup");
    assert!(child.owns_process(child.root_pid()).unwrap());
    child.terminate().unwrap();
    finish(&mut child);
}

#[test]
fn invalid_launch_and_ambiguous_environment_fail_before_creating_a_child() {
    let mut launch = spec();
    launch.executable = PathBuf::from("relative.exe");
    assert_eq!(OwnedChild::spawn(&launch).err().unwrap().kind(), io::ErrorKind::InvalidInput);
    launch = spec();
    launch.executable = std::env::temp_dir().join("agent-bridge-definitely-missing-provider.exe");
    assert_eq!(OwnedChild::spawn(&launch).err().unwrap().kind(), io::ErrorKind::NotFound);
    for (name, value) in [
        ("", Some("x")), ("BAD=KEY", Some("x")), ("BAD\0KEY", None),
        ("OK", Some("bad\0value")),
    ] {
        launch = spec();
        launch.env_overrides.insert(name.into(), value.map(OsString::from));
        assert_eq!(OwnedChild::spawn(&launch).err().unwrap().kind(), io::ErrorKind::InvalidInput);
    }
    launch = spec();
    launch.env_overrides.insert("CASE_COLLISION".into(), Some("one".into()));
    launch.env_overrides.insert("case_collision".into(), Some("two".into()));
    assert_eq!(OwnedChild::spawn(&launch).err().unwrap().kind(), io::ErrorKind::InvalidInput);
}
#[test]
fn birth_metadata_failure_never_discards_a_successfully_launched_child() {
    let fault = BirthReadFault::arm();
    let mut child = OwnedChild::spawn(&spec())
        .expect("post-launch metadata failure must return the still-owned process");
    read_until(&mut child, "fixture-ready");
    let pid = child.root_pid();
    assert_eq!(child.owns_process(pid).unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    assert!(child.finish().unwrap().is_none(), "metadata error is not cleanup");
    drop(fault);
    assert!(child.owns_process(pid).unwrap(), "root incarnation remains verifiable through its owned handle");
    child.terminate().unwrap();
    let (exit, _, _) = finish(&mut child);
    assert_eq!(exit.code, Some(1));
    assert!(!child.owns_process(pid).unwrap());
}

#[test]
fn exact_environment_block_contains_only_supplied_entries() {
    assert!(std::env::var_os("CARGO_MANIFEST_DIR").is_some(), "Cargo must supply an inherited variable");
    let decode = |block: Vec<u16>| String::from_utf16(&block).unwrap();
    let supplied = BTreeMap::from([
        (OsString::from("Zeta"), OsString::from("last €")),
        (OsString::from("alpha"), OsString::from("")),
        (OsString::from("AGENT_BRIDGE_OWNED_TEST_MARKER"), OsString::from("1")),
    ]);
    // Case-insensitive ordinal order, nothing inherited, double-NUL ended.
    assert_eq!(decode(platform::exact_environment_block(&supplied).unwrap()),
        "AGENT_BRIDGE_OWNED_TEST_MARKER=1\0alpha=\0Zeta=last €\0\0");
    assert_eq!(platform::exact_environment_block(&BTreeMap::new()).unwrap(), vec![0, 0]);
    for (name, value) in [("", "x"), ("BAD=KEY", "x"), ("BAD\0KEY", "x"), ("OK", "bad\0value")] {
        let invalid = BTreeMap::from([(OsString::from(name), OsString::from(value))]);
        assert_eq!(platform::exact_environment_block(&invalid).unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }
    let ambiguous = BTreeMap::from([
        (OsString::from("CASE_COLLISION"), OsString::from("one")),
        (OsString::from("case_collision"), OsString::from("two")),
    ]);
    assert_eq!(platform::exact_environment_block(&ambiguous).unwrap_err().kind(), io::ErrorKind::InvalidInput);
    // The overlay block keeps inheriting this process environment.
    let overlay = BTreeMap::from([(OsString::from("AGENT_BRIDGE_OWNED_TEST_MARKER"), Some(OsString::from("1")))]);
    let inherited = decode(platform::environment_block(&overlay).unwrap().unwrap()).to_ascii_uppercase();
    assert!(inherited.starts_with("CARGO_MANIFEST_DIR=") || inherited.contains("\0CARGO_MANIFEST_DIR="));
}

#[test]
fn stdio_launcher_child_has_no_console_owned_job_and_exact_env() {
    use crate::extensions::stdio_child::{spawn_contained, ContainedLauncher};
    use agent_bridge_extensions::stdio::{StdioChild, StdioLaunch, StdioLauncher};
    assert!(std::env::var_os("CARGO_MANIFEST_DIR").is_some(), "Cargo must supply an inherited variable");
    let literal = r#"two words "quoted""#;
    let executable = fixture_program();
    let arguments = fixture_args(FIXTURE, &["--literal", literal]);
    let cwd = std::env::temp_dir();
    let mut environment = BTreeMap::from([
        (OsString::from("AGENT_BRIDGE_OWNED_TEST_MARKER"), OsString::from("stdio exact €")),
    ]);
    if let Some(root) = std::env::var_os("SystemRoot") {
        environment.insert("SystemRoot".into(), root);
    }
    let launch = StdioLaunch { executable: &executable, arguments: &arguments, cwd: &cwd, environment: &environment };

    let mut child = spawn_contained(&launch).expect("stdio launch must reach the owned Job");
    read_until(&mut child, "fixture-ready");
    send(&mut child, json!({"action":"probe"}));
    let observed = probe(&read_until(&mut child, "probe:"));
    assert_eq!(observed["pid"], child.root_pid());
    assert!(child.owns_process(child.root_pid()).unwrap(), "root must be a live Job member");
    assert_eq!(observed["console"], false);
    assert_eq!(observed["argv"].as_array().unwrap().last().unwrap(), literal);
    assert_eq!(observed["marker"], "stdio exact €");
    assert_eq!(observed["cargo_manifest_dir"], Value::Null, "environment must not be inherited");
    // Drive the remaining lifecycle through the extension seam only.
    let seam: &mut dyn StdioChild = &mut child;
    let mut buf = [0u8; 64];
    let mut stderr = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !String::from_utf8_lossy(&stderr).contains("owned-child-stderr") {
        match seam.read_stderr(&mut buf) {
            Ok(count) => stderr.extend_from_slice(&buf[..count]),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => panic!("stderr failed: {error}"),
        }
        assert!(Instant::now() < deadline, "stderr witness missing");
        std::thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(seam.read_stdout(&mut buf).unwrap_err().kind(), io::ErrorKind::WouldBlock);
    assert!(!seam.finish().unwrap(), "a live child is not finished");
    seam.terminate().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !seam.finish().unwrap() {
        assert!(Instant::now() < deadline, "terminated Job did not empty");
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(seam.write_stdin(b"x").is_err(), "terminate closes stdin");
    assert!(!child.owns_process(child.root_pid()).unwrap());

    // The boxed production launcher yields the same contained child.
    let mut boxed = ContainedLauncher.launch(&launch).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut out = Vec::new();
    while !String::from_utf8_lossy(&out).contains("fixture-ready") {
        match boxed.read_stdout(&mut buf) {
            Ok(count) => out.extend_from_slice(&buf[..count]),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => panic!("stdout failed: {error}"),
        }
        assert!(Instant::now() < deadline, "boxed child did not start");
        std::thread::sleep(Duration::from_millis(2));
    }
    boxed.close_stdin();
    // Stdin EOF ends the fixture loop; finish then proves the Job emptied.
    let deadline = Instant::now() + Duration::from_secs(5);
    while !boxed.finish().unwrap() {
        assert!(Instant::now() < deadline, "boxed child did not exit after stdin EOF");
        std::thread::sleep(Duration::from_millis(5));
    }
}
