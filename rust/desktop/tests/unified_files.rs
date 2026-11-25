mod common;
use common::{Fixture, result, read};
use agent_bridge_desktop::{DesktopProfile, unified::{FileScope, UnifiedFiles}};
use serde_json::json;

#[test]
fn absolute_selected_root_read_and_observed_rewrite_are_real() {
    let f = Fixture::new();
    let path = f.external.join("note.txt");
    std::fs::write(&path, "before").unwrap();
    let files = UnifiedFiles::open(f.config(FileScope::AllowedRoots(vec![f.external.clone()]))).unwrap();
    let (failed, observed) = read(&files, &path);
    assert!(!failed, "selected absolute path must be readable: {observed}");
    assert_eq!(observed["content"], "before");
    let token = observed["observation_id"].as_str().unwrap();
    let args = json!({"path":path,"mode":"rewrite","content":"after","observation_id":token});
    assert!(!result(&files, DesktopProfile::FullyUnlocked, "desktop_write_file", args.clone()).0);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "after");
    assert!(result(&files, DesktopProfile::FullyUnlocked, "desktop_write_file", args).0,
        "the same observation must not authorize a second write");
}

#[test]
fn protected_subtree_is_absent_from_direct_reads_listing_and_content_search() {
    let f = Fixture::new();
    std::fs::write(f.private.join("credential.txt"), "PRIVATE_SENTINEL_71").unwrap();
    std::fs::write(f.root.join("public.txt"), "public text").unwrap();
    let files = UnifiedFiles::open(f.config(FileScope::AllowedRoots(vec![f.root.clone()]))).unwrap();
    assert!(read(&files, &f.private.join("credential.txt")).0);
    for (tool,args) in [
        ("desktop_list_directory",json!({"path":f.root,"depth":4})),
        ("desktop_search",json!({"path":f.root,"pattern":"PRIVATE_SENTINEL_71","search_type":"content","include_hidden":true}))
    ] {
        let (failed, value) = result(&files, DesktopProfile::FullyUnlocked, tool, args);
        assert!(!failed, "permitted parent remains useful: {value}");
        let text = value.to_string();
        assert!(!text.contains("credential.txt"), "must not enumerate private entries");
        assert!(!text.contains("PRIVATE_SENTINEL_71"), "must not read private content while searching");
    }
}

#[test]
fn root_scope_and_profile_are_checked_before_effects() {
    let f = Fixture::new();
    let file = f.external.join("outside.txt");
    std::fs::write(&file, "retain").unwrap();
    let limited = UnifiedFiles::open(f.config(FileScope::Workspace)).unwrap();
    assert!(read(&limited, &file).0);
    limited.shutdown().unwrap();
    let all = UnifiedFiles::open(f.config(FileScope::OsUser)).unwrap();
    assert_eq!(read(&all, &file).1["content"], "retain");
    assert!(result(&all, DesktopProfile::FullControl, "desktop_read_file", json!({"path":file})).0,
        "downgrade must remove OS-user authority outside the workspace");
    assert!(result(&all, DesktopProfile::ReadOnly, "desktop_write_file",
        json!({"path":f.workspace.join("denied.txt"),"content":"bad","mode":"rewrite"})).0);
    assert!(!f.workspace.join("denied.txt").exists());
}

#[test]
fn protected_directory_identity_survives_rename() {
    let f = Fixture::new();
    std::fs::write(f.private.join("secret.txt"), "PRIVATE_RENAMED_89").unwrap();
    let files = UnifiedFiles::open(f.config(FileScope::AllowedRoots(vec![f.root.clone()]))).unwrap();
    let renamed = f.root.join("renamed-private");
    // Windows may deny the rename while the protection handle is held. That is
    // also fail-closed; if permitted, identity-based exclusion must still hold.
    if std::fs::rename(&f.private, &renamed).is_ok() {
        assert!(read(&files, &renamed.join("secret.txt")).0);
        let (failed, value) = result(&files, DesktopProfile::FullyUnlocked,
            "desktop_search", json!({"path":f.root,"pattern":"PRIVATE_RENAMED_89","search_type":"content"}));
        assert!(!failed);
        assert!(!value.to_string().contains("PRIVATE_RENAMED_89"));
    } else { assert!(read(&files, &f.private.join("secret.txt")).0); }
}

#[cfg(unix)]
#[test]
fn symbolic_alias_cannot_enter_an_unselected_or_protected_root() {
    let f = Fixture::new();
    std::fs::write(f.private.join("secret.txt"), "secret").unwrap();
    std::os::unix::fs::symlink(&f.private, f.workspace.join("alias")).unwrap();
    let files = UnifiedFiles::open(f.config(FileScope::OsUser)).unwrap();
    assert!(read(&files, &f.workspace.join("alias/secret.txt")).0);
}

#[test]
fn os_user_external_parent_rewrite_append_edit_and_downgrade() {
    let f = Fixture::new();
    let files = UnifiedFiles::open(f.config(FileScope::OsUser)).unwrap();
    // The exact shape used by the integrated router: a file in the parent
    // of the workspace and private state, reached from the volume authority.
    for i in 0..12 {
        let path = f.root.join(format!("external-{i}.txt"));
        std::fs::write(&path, "before").unwrap();
        let (failed, observed) = read(&files, &path);
        assert!(!failed, "{observed}");
        let (failed, rewritten) = result(&files, DesktopProfile::FullyUnlocked,
            "desktop_write_file", json!({"path":path,"mode":"rewrite",
                "content":"after","observation_id":observed["observation_id"]}));
        assert!(!failed, "rewrite fixture {i}: {rewritten}");
        let (failed, view) = read(&files, &path);
        assert!(!failed, "{view}");
        assert_eq!(view["content"], "after");
        let (failed, appended) = result(&files, DesktopProfile::FullyUnlocked,
            "desktop_write_file", json!({"path":path,"mode":"append",
                "content":" tail","observation_id":view["observation_id"]}));
        assert!(!failed, "append fixture {i}: {appended}");
        let (failed, view) = read(&files, &path);
        assert!(!failed, "{view}");
        let (failed, edited) = result(&files, DesktopProfile::FullyUnlocked,
            "desktop_edit_file", json!({"path":path,"old_string":"tail","new_string":"end",
                "observation_id":view["observation_id"],"expected_replacements":1}));
        assert!(!failed, "edit fixture {i}: {edited}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "after end");
        assert!(result(&files, DesktopProfile::FullControl, "desktop_read_file",
            json!({"path":path})).0);
    }
    files.shutdown().unwrap();
}

#[cfg(windows)]
#[test]
fn os_user_sharing_violation_preserves_original_and_consumes_observation() {
    use std::os::windows::fs::OpenOptionsExt;
    let f = Fixture::new();
    let path = f.root.join("locked.txt");
    std::fs::write(&path, "before").unwrap();
    let files = UnifiedFiles::open(f.config(FileScope::OsUser)).unwrap();
    let (_, observed) = read(&files, &path);
    // Allow concurrent reads/writes but intentionally disallow delete/rename.
    let lock = std::fs::OpenOptions::new().read(true).share_mode(3).open(&path).unwrap();
    let request = json!({"path":path,"mode":"rewrite","content":"after",
        "observation_id":observed["observation_id"]});
    let (failed, reply) = result(&files, DesktopProfile::FullyUnlocked,
        "desktop_write_file", request.clone());
    assert!(failed, "{reply}");
    assert_eq!(reply["code"], "UNCERTAIN_RESULT");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "before");
    assert!(std::fs::read_dir(&f.root).unwrap().all(|entry|
        !entry.unwrap().file_name().to_string_lossy().starts_with(".agent-bridge-tmp-")));
    drop(lock);
    assert!(result(&files, DesktopProfile::FullyUnlocked, "desktop_write_file", request).0);
    let (_, fresh) = read(&files, &path);
    let (failed, reply) = result(&files, DesktopProfile::FullyUnlocked,
        "desktop_write_file", json!({"path":path,"mode":"rewrite","content":"after",
        "observation_id":fresh["observation_id"]}));
    assert!(!failed, "{reply}");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "after");
    files.shutdown().unwrap();
}
