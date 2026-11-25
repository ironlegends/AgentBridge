#![cfg(unix)]

use agent_bridge_desktop::{DesktopConfig, DesktopFiles};
use serde_json::{json, Value};
use std::fs;
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct Sandbox(PathBuf);
impl Sandbox {
    fn new() -> Self {
        let path = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "ab-root-handle-{}-{}", std::process::id(), SEQUENCE.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Sandbox {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}

fn payload(files: &DesktopFiles, name: &str, args: Value) -> (bool, Value) {
    let response = files.dispatch(name, &args);
    (response["isError"] == true,
        serde_json::from_str(response["content"][0]["text"].as_str().unwrap()).unwrap())
}

#[test]
fn received_root_preserves_read_only_metadata_and_link_restrictions() {
    let sandbox = Sandbox::new();
    let project = sandbox.0.join("project");
    fs::create_dir(&project).unwrap();
    fs::write(project.join("public.txt"), "public\n").unwrap();
    let outside = sandbox.0.join("secret.txt");
    fs::write(&outside, "private\n").unwrap();
    symlink(&outside, project.join("symbolic.txt")).unwrap();
    fs::hard_link(&outside, project.join("hard.txt")).unwrap();

    let source = DesktopFiles::open(DesktopConfig::new(&project).allow_workspace_write()).unwrap();
    let child = DesktopFiles::open_read_only_from_workspace_handle(
        &project, source.clone_workspace_root_handle().unwrap(),
    ).unwrap();
    let (error, result) = payload(&child, "desktop_get_file_info", json!({"path":"public.txt"}));
    assert!(!error, "{result}");
    assert_eq!(result["bytes"], 7);
    for path in ["symbolic.txt", "hard.txt", "../secret.txt"] {
        assert!(payload(&child, "desktop_get_file_info", json!({"path":path})).0);
    }
    assert!(payload(&child, "desktop_write_file", json!({
        "path":"new.txt","content":"forbidden","mode":"rewrite",
    })).0);
    assert!(!project.join("new.txt").exists());
}

#[test]
fn received_root_and_source_reject_replacement_or_symlinked_selection() {
    let sandbox = Sandbox::new();
    let project = sandbox.0.join("project");
    let moved = sandbox.0.join("original");
    fs::create_dir(&project).unwrap();
    let source = DesktopFiles::open(DesktopConfig::new(&project)).unwrap();
    let handle = source.clone_workspace_root_handle().unwrap();
    let child = DesktopFiles::open_read_only_from_workspace_handle(&project, handle.try_clone().unwrap()).unwrap();
    fs::rename(&project, &moved).unwrap();
    fs::create_dir(&project).unwrap();
    assert!(source.clone_workspace_root_handle().is_err());
    assert!(child.verify_workspace_root_identity().is_err());
    assert!(DesktopFiles::open_read_only_from_workspace_handle(&project, handle.try_clone().unwrap()).is_err());
    fs::remove_dir(&project).unwrap();
    symlink(&moved, &project).unwrap();
    assert!(child.verify_workspace_root_identity().is_err());
    assert!(DesktopFiles::open_read_only_from_workspace_handle(&project, handle).is_err());
}
