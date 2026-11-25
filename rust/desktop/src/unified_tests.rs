use super::*;

thread_local! {
    static AFTER_RESOLVE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}
pub(super) fn after_resolve() {
    let hook = AFTER_RESOLVE.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook { hook(); }
}

#[cfg(windows)]
#[path = "../tests/common/windows.rs"]
mod windows;

#[cfg(windows)]
fn remap_after_root_validation(workspace_scope: bool) {
    use std::cell::RefCell;
    use std::rc::Rc;
    let root = std::env::temp_dir().join(format!("bridge-root-swap-{}", Uuid::new_v4()));
    let private = root.join("private");
    let original = root.join("original");
    let replacement = root.join("replacement");
    let workspace = root.join("workspace");
    for path in [&private, &workspace, &original.join("selected"), &replacement.join("selected")] {
        std::fs::create_dir_all(path).unwrap();
    }
    windows::make_private(&private);
    std::fs::write(original.join("selected/value.txt"), "selected-physical-file").unwrap();
    std::fs::write(replacement.join("selected/value.txt"), "UNSELECTED_REPLACEMENT").unwrap();
    let alias = Rc::new(RefCell::new(windows::DosAlias::new(&original)));
    let chosen = alias.borrow().root().join("selected");
    let files = UnifiedFiles::open(UnifiedFileConfig {
        workspace:if workspace_scope { chosen.clone() } else { workspace },
        scope:if workspace_scope { FileScope::Workspace } else { FileScope::AllowedRoots(vec![chosen.clone()]) },
        protected_roots:vec![private.clone()], private_root:private,
    }).unwrap();
    let switch = Rc::clone(&alias);
    AFTER_RESOLVE.with(|slot| *slot.borrow_mut() = Some(Box::new(move || switch.borrow_mut().replace(&replacement))));
    let value = files.dispatch(DesktopProfile::FullyUnlocked, "desktop_read_file", &json!({"path":chosen.join("value.txt")}));
    let body: Value = serde_json::from_str(value["content"][0]["text"].as_str().unwrap()).unwrap();
    let refused = value["isError"] == true;
    files.shutdown().unwrap();
    drop(files);
    drop(alias);
    std::fs::remove_dir_all(root).unwrap();
    assert!(refused || body["content"] == "selected-physical-file",
        "resolution reopened a replacement directory after granting the original handle: {body}");
}

#[cfg(windows)]
#[test]
fn task5_workspace_swap_after_validation_cannot_redirect_read() { remap_after_root_validation(true); }

#[cfg(windows)]
#[test]
fn task5_allowed_root_swap_after_validation_cannot_redirect_read() { remap_after_root_validation(false); }
