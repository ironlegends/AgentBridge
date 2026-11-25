use agent_bridge_desktop::{DesktopProfile, unified::{FileScope, UnifiedFileConfig, UnifiedFiles}};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

#[cfg(windows)]
pub mod windows;

pub struct Fixture { pub root: PathBuf, pub workspace: PathBuf, pub external: PathBuf, pub private: PathBuf }
impl Fixture {
    pub fn new() -> Self {
        let root = std::env::temp_dir().join(format!("bridge-unified-files-{}", uuid::Uuid::new_v4()));
        let workspace = root.join("workspace");
        let external = root.join("external");
        let private = root.join("private");
        for path in [&workspace, &external, &private] { std::fs::create_dir_all(path).unwrap(); }
        #[cfg(windows)] windows::make_private(&private);
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self { root, workspace, external, private }
    }
    pub fn config(&self, scope: FileScope) -> UnifiedFileConfig {
        UnifiedFileConfig { workspace: self.workspace.clone(), scope,
            protected_roots: vec![self.private.clone()], private_root: self.private.clone() }
    }
}
impl Drop for Fixture { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.root); } }
pub fn result(files: &UnifiedFiles, profile: DesktopProfile, name: &str, args: Value) -> (bool, Value) {
    let envelope = files.dispatch(profile, name, &args);
    let error = envelope.get("isError").and_then(Value::as_bool).unwrap_or(false);
    let value: Value = serde_json::from_str(envelope["content"][0]["text"].as_str().unwrap()).unwrap();
    (error, value)
}
pub fn read(files: &UnifiedFiles, path: &Path) -> (bool, Value) {
    result(files, DesktopProfile::FullyUnlocked, "desktop_read_file", json!({"path":path}))
}
