mod common;
use common::{Fixture, result};
use agent_bridge_desktop::{DesktopProfile, unified::{FileScope, UnifiedFiles}};
use serde_json::json;
use std::io::Write;

fn large_file(path: &std::path::Path, size: usize) {
    let mut file = std::fs::File::create(path).unwrap();
    let block = [b'Z'; 65536];
    for _ in 0..size / block.len() { file.write_all(&block).unwrap(); }
    file.write_all(&block[..size % block.len()]).unwrap();
}

#[test]
fn published_large_file_is_read_in_bounded_verified_chunks() {
    let f = Fixture::new();
    let path = f.workspace.join("large.bin");
    let size = 6 * 1024 * 1024 + 7;
    large_file(&path, size);
    let files = UnifiedFiles::open(f.config(FileScope::Workspace)).unwrap();
    let (failed, published) = result(&files, DesktopProfile::FullyUnlocked, "desktop_artifact_manage",
        json!({"action":"publish","path":path}));
    assert!(!failed, "real files above the historical memory limit must publish: {published}");
    assert_eq!(published["artifact"]["size_bytes"], size);
    let id = published["artifact"]["artifact_id"].as_str().unwrap();
    let (failed, chunk) = result(&files, DesktopProfile::ReadOnly, "desktop_artifact_manage",
        json!({"action":"read","artifact_id":id,"offset":size-11,"length":11,"encoding":"utf8"}));
    assert!(!failed, "{chunk}");
    assert_eq!(chunk["content"], "ZZZZZZZZZZZ");
    assert_eq!(chunk["bytes_read"], 11);
    assert_eq!(chunk["next_offset"], size);
    assert_eq!(chunk["eof"], true);
    assert!(result(&files, DesktopProfile::ReadOnly, "desktop_artifact_manage",
        json!({"action":"delete","artifact_id":id})).0);
    assert!(!result(&files, DesktopProfile::FullyUnlocked, "desktop_artifact_manage",
        json!({"action":"delete","artifact_id":id})).0);
    assert!(result(&files, DesktopProfile::ReadOnly, "desktop_artifact_manage",
        json!({"action":"read","artifact_id":id})).0);
}

#[test]
fn file_over_sixty_four_mib_is_refused_without_publishing_partial_bytes() {
    let f = Fixture::new();
    let path = f.workspace.join("too-large.bin");
    std::fs::File::create(&path).unwrap().set_len(64 * 1024 * 1024 + 1).unwrap();
    let files = UnifiedFiles::open(f.config(FileScope::Workspace)).unwrap();
    assert!(result(&files, DesktopProfile::FullyUnlocked, "desktop_artifact_manage",
        json!({"action":"publish","path":path})).0);
    let (_, listed) = result(&files, DesktopProfile::ReadOnly, "desktop_artifact_manage", json!({"action":"list"}));
    assert_eq!(listed["count"], 0);
}

#[test]
fn uploads_are_copied_from_authorized_files_to_private_session_staging() {
    let f = Fixture::new();
    let source = f.external.join("payload.bin");
    large_file(&source, 2 * 1024 * 1024 + 3);
    let session = f.private.join("browser-session");
    std::fs::create_dir(&session).unwrap();
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&session, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let files = UnifiedFiles::open(f.config(FileScope::AllowedRoots(vec![f.external.clone()]))).unwrap();
    let staged = files.stage_uploads(DesktopProfile::FullControl, &[source.to_string_lossy().into_owned()], &session).unwrap();
    assert_eq!(staged.len(), 1);
    assert!(staged[0].starts_with(&session));
    assert_eq!(std::fs::read(&staged[0]).unwrap(), std::fs::read(&source).unwrap());
    assert!(files.stage_uploads(DesktopProfile::FullControl, &[source.to_string_lossy().into_owned()], &f.workspace).is_err());
    assert!(files.stage_uploads(DesktopProfile::ReadOnly, &[source.to_string_lossy().into_owned()], &session).is_err());
    assert!(files.stage_uploads(DesktopProfile::FullyUnlocked, &[staged[0].to_string_lossy().into_owned()], &session).is_err(),
        "ordinary upload paths must not expose private application files");
}

#[test]
fn private_download_publishes_only_through_the_owned_callback() {
    let f = Fixture::new();
    let download = f.private.join("owned-download.bin");
    large_file(&download, 5 * 1024 * 1024 + 1);
    let files = UnifiedFiles::open(f.config(FileScope::OsUser)).unwrap();
    let published = files.publish_download(DesktopProfile::FullControl, &download, "download.bin").unwrap();
    assert!(common::read(&files, &download).0);
    let id = published["artifact"]["artifact_id"].as_str().unwrap();
    assert_eq!(published["artifact"]["size_bytes"], 5 * 1024 * 1024 + 1);
    assert!(!published.to_string().contains(f.private.to_str().unwrap()));
    let (failed, value) = result(&files, DesktopProfile::ReadOnly, "desktop_artifact_manage",
        json!({"action":"read","artifact_id":id,"offset":0,"length":4,"encoding":"base64"}));
    assert!(!failed, "{value}");
    assert_eq!(value["content"], "WlpaWg==");
    assert!(result(&files, DesktopProfile::FullyUnlocked, "desktop_artifact_manage",
        json!({"action":"publish","path":download})).0);
    let outside = f.workspace.join("unowned.bin");
    std::fs::write(&outside, "not a worker download").unwrap();
    assert!(files.publish_download(DesktopProfile::FullControl, &outside, "download.bin").is_err());
}

#[test]
fn exact_size_limit_count_limit_and_shutdown_release_physical_files() {
    let f = Fixture::new();
    let large = f.workspace.join("limit.bin");
    large_file(&large, 64 * 1024 * 1024);
    let small = f.workspace.join("small.txt");
    std::fs::write(&small, "owned").unwrap();
    let files = UnifiedFiles::open(f.config(FileScope::Workspace)).unwrap();
    assert!(UnifiedFiles::open(f.config(FileScope::Workspace)).is_err(), "the private store has one owner");
    let (failed, artifact) = result(&files, DesktopProfile::FullyUnlocked, "desktop_artifact_manage",
        json!({"action":"publish","path":large}));
    assert!(!failed, "the documented64MiB boundary must be usable: {artifact}");
    assert_eq!(artifact["artifact"]["size_bytes"], 64 * 1024 * 1024);
    for _ in 1..64 {
        assert!(!result(&files, DesktopProfile::FullyUnlocked, "desktop_artifact_manage",
            json!({"action":"publish","path":small})).0);
    }
    let (failed, error) = result(&files, DesktopProfile::FullyUnlocked, "desktop_artifact_manage",
        json!({"action":"publish","path":small}));
    assert!(failed);
    assert_eq!(error["code"], "ARTIFACT_STORAGE_LIMIT_EXCEEDED");
    files.shutdown().unwrap();
    files.shutdown().unwrap();
    assert!(result(&files, DesktopProfile::ReadOnly, "desktop_artifact_manage", json!({"action":"list"})).0);
    let names = std::fs::read_dir(f.private.join("artifacts")).unwrap()
        .map(|entry| entry.unwrap().file_name()).collect::<Vec<_>>();
    assert_eq!(names, vec![std::ffi::OsString::from("owner.lock")]);
    let replacement = UnifiedFiles::open(f.config(FileScope::Workspace)).unwrap();
    assert_eq!(result(&replacement, DesktopProfile::ReadOnly, "desktop_artifact_manage", json!({"action":"list"})).1["count"], 0);
}

#[test]
fn process_crash_does_not_leave_artifact_bytes_or_an_exclusive_owner() {
    use std::io::BufRead;
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::time::Duration;
    let f = Fixture::new();
    large_file(&f.workspace.join("crash.bin"), 6 * 1024 * 1024 + 1);
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args(["--exact", "artifact_crash_fixture", "--nocapture"])
        .env("AGENT_BRIDGE_ARTIFACT_TEST_ROOT", &f.root)
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    #[cfg(windows)] { use std::os::windows::process::CommandExt; command.creation_flags(0x08000000); }
    let mut child = command.spawn().unwrap();
    let output = child.stdout.take().unwrap();
    let (send, receive) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in std::io::BufReader::new(output).lines() {
            match line { Ok(line) if line == "ARTIFACT_READY" => { let _ = send.send(()); return; }, Ok(_) => {}, Err(_) => return }
        }
    });
    let ready = receive.recv_timeout(Duration::from_secs(20));
    let killed = child.kill();
    let waited = child.wait();
    reader.join().unwrap();
    assert!(ready.is_ok(), "fixture did not publish an artifact: {ready:?}");
    killed.unwrap(); waited.unwrap();
    let replacement = UnifiedFiles::open(f.config(FileScope::Workspace)).unwrap();
    assert_eq!(result(&replacement, DesktopProfile::ReadOnly, "desktop_artifact_manage", json!({"action":"list"})).1["count"], 0);
    let names = std::fs::read_dir(f.private.join("artifacts")).unwrap()
        .map(|entry| entry.unwrap().file_name()).collect::<Vec<_>>();
    assert_eq!(names, vec![std::ffi::OsString::from("owner.lock")]);
}

/// Child of the crash test above; it returns at once in an ordinary run.
#[test]
fn artifact_crash_fixture() {
    use agent_bridge_desktop::unified::UnifiedFileConfig;
    let Some(root) = std::env::var_os("AGENT_BRIDGE_ARTIFACT_TEST_ROOT") else { return };
    let root = std::path::PathBuf::from(root);
    let files = UnifiedFiles::open(UnifiedFileConfig { workspace:root.join("workspace"),
        scope:FileScope::Workspace, protected_roots:vec![root.join("private")], private_root:root.join("private") }).unwrap();
    assert!(!result(&files, DesktopProfile::FullyUnlocked, "desktop_artifact_manage",
        json!({"action":"publish","path":"crash.bin"})).0);
    println!("ARTIFACT_READY"); std::io::stdout().flush().unwrap();
    let mut line = String::new(); std::io::stdin().read_line(&mut line).unwrap();
    panic!("parent should terminate the fixture before its input closes");
}
