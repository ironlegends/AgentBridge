use super::{open_new, read_private, Store, MAX_SMALL};
use crate::{model::Policy, platform, Audience};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::Duration;

static NEXT: AtomicU64 = AtomicU64::new(0);
const CHILD_ROOT: &str = "AGENT_BRIDGE_OAUTH_GATE_TEST_ROOT";
const READY: &str = "OAUTH_GATE_READY";

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let base = fs::canonicalize(std::env::temp_dir()).unwrap();
        let base = base.to_str().and_then(|path| path.strip_prefix(r"\\?\"))
            .map(PathBuf::from).unwrap_or(base);
        let root = base.join(format!("oauth-gate-lifetime-{}-{}",
            std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        assert!(!root.exists(), "fixture path must be new");
        platform::create_requests(&root).unwrap();
        Self(root)
    }

    fn open(&self) -> Store {
        let policy = Policy::new("https://oauth-gate.example.invalid", Audience::Workstation).unwrap();
        Store::open(&self.0, &policy, 1_800_000_000_000).unwrap().0
    }

    fn refused(&self) -> bool {
        let policy = Policy::new("https://oauth-gate.example.invalid", Audience::Workstation).unwrap();
        Store::open(&self.0, &policy, 1_800_000_000_000).is_err()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct OwnerChild(Child);

impl OwnerChild {
    fn start(root: &Fixture) -> Self {
        let mut child = Self(Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "store::windows_tests::owner_child", "--nocapture"])
            .env(CHILD_ROOT, &root.0)
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit())
            .spawn().unwrap());
        let output = child.0.stdout.take().unwrap();
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let ready = BufReader::new(output).lines()
                .any(|line| line.is_ok_and(|line| line == READY));
            let _ = sender.send(ready);
        });
        assert!(receiver.recv_timeout(Duration::from_secs(15)).unwrap(),
            "child must acquire the real OAuth store");
        child
    }

    fn terminate(&mut self) {
        self.0.kill().unwrap();
        assert!(!self.0.wait().unwrap().success());
    }
}

impl Drop for OwnerChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "subprocess entry point; invoked by the owner-lifetime test"]
fn owner_child() {
    let root = PathBuf::from(std::env::var_os(CHILD_ROOT).expect("fixture root"));
    assert!(root.file_name().unwrap().to_string_lossy().starts_with("oauth-gate-lifetime-"));
    let policy = Policy::new("https://oauth-gate.example.invalid", Audience::Workstation).unwrap();
    let (store, data) = Store::open(&root, &policy, 1_800_000_000_000).unwrap();
    store.save(&data).unwrap();
    println!("{READY}");
    std::io::stdout().flush().unwrap();
    let mut input = [0];
    let _ = std::io::stdin().read_exact(&mut input);
    drop(store);
}

#[test]
fn windows_gate_releases_after_forced_owner_exit_and_reopens_state() {
    let fixture = Fixture::new();
    let mut child = OwnerChild::start(&fixture);
    let marker = fixture.0.join("running.lock");
    assert!(marker.is_file());
    assert!(fixture.refused(), "a live owner must retain exclusive access");
    let oauth = fixture.0.join("oauth-workstation.json");
    let before = fs::read(&oauth).unwrap();

    child.terminate();

    assert!(!marker.exists(), "an exited Windows owner must not strand its marker");
    let reopened = fixture.open();
    assert_eq!(fs::read(&oauth).unwrap(), before, "reopening must preserve OAuth data");
    assert!(fixture.refused(), "the replacement owner must also be exclusive");
    drop(reopened);
    assert!(!marker.exists());
}

#[test]
fn windows_gate_refuses_existing_foreign_marker_without_changing_it() {
    let fixture = Fixture::new();
    let marker = fixture.0.join("running.lock");
    let foreign = [b'L'; 43];
    let mut file = open_new(&marker).unwrap();
    file.write_all(&foreign).unwrap();
    file.sync_all().unwrap();
    drop(file);

    assert!(fixture.refused(), "unknown legacy ownership must remain fail-closed");
    assert_eq!(fs::read(&marker).unwrap(), foreign);
    assert!(!fixture.0.join("oauth-workstation.json").exists());
}

#[test]
fn windows_gate_refuses_a_second_owner_and_releases_on_normal_drop() {
    let fixture = Fixture::new();
    let first = fixture.open();
    let marker = fixture.0.join("running.lock");
    let nonce = read_private(&marker, MAX_SMALL).unwrap().unwrap();

    assert!(fixture.refused());
    assert_eq!(read_private(&marker, MAX_SMALL).unwrap().unwrap(), nonce);
    drop(first);
    assert!(!marker.exists());
    drop(fixture.open());
}

#[test]
fn windows_gate_never_deletes_a_replacement_file() {
    let fixture = Fixture::new();
    let owner = fixture.open();
    let marker = fixture.0.join("running.lock");
    let retired = fixture.0.join("renamed-owned-marker");
    let nonce = read_private(&marker, MAX_SMALL).unwrap().unwrap();

    match fs::rename(&marker, &retired) {
        Ok(()) => {
            let mut replacement = open_new(&marker).unwrap();
            replacement.write_all(&nonce).unwrap();
            replacement.sync_all().unwrap();
            drop(replacement);
            drop(owner);
            assert!(marker.is_file(), "the replacement marker must survive its predecessor");
            assert_eq!(fs::read(&marker).unwrap(), nonce,
                "equal contents do not make a replacement file our original object");
        }
        Err(error) => {
            assert!(matches!(error.raw_os_error(), Some(5 | 32)),
                "only an explicit Windows sharing/access refusal is acceptable: {error}");
            assert_eq!(read_private(&marker, MAX_SMALL).unwrap().unwrap(), nonce);
            assert!(fixture.refused());
            drop(owner);
            assert!(!marker.exists());
        }
    }
}
