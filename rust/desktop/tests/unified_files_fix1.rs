mod common;
use common::{Fixture, result, read};
use agent_bridge_desktop::{DesktopProfile, unified::{FileScope, UnifiedFiles}};
use serde_json::json;

#[cfg(windows)]
#[test]
fn task5_private_descendant_presented_as_drive_root_is_excluded() {
    let f = Fixture::new();
    let descendant = f.private.join("nested").join("session");
    std::fs::create_dir_all(&descendant).unwrap();
    std::fs::write(descendant.join("synthetic.txt"), "PRIVATE_SYNTHETIC_DESCENDANT").unwrap();
    let alias = common::windows::DosAlias::new(&descendant);
    let files = UnifiedFiles::open(f.config(FileScope::OsUser)).unwrap();
    let path = alias.root().join("synthetic.txt");
    let (failed, value) = read(&files, &path);
    assert!(failed, "private descendant leaked through a drive root: {value}");
    assert_eq!(value["code"], "PROTECTED_PRIVATE_PATH");
    for (tool, args) in [
        ("desktop_search", json!({"path":alias.root(),"pattern":"PRIVATE_SYNTHETIC_DESCENDANT","search_type":"content"})),
        ("desktop_artifact_manage", json!({"action":"publish","path":path})),
    ] {
        let (failed, value) = result(&files, DesktopProfile::FullyUnlocked, tool, args);
        assert!(failed, "private alias operation was permitted: {value}");
        assert_eq!(value["code"], "PROTECTED_PRIVATE_PATH");
    }
}

#[cfg(windows)]
#[test]
fn task5_case_distinct_sibling_is_not_an_allowed_root() {
    let f = Fixture::new();
    let parent = f.root.join("case-sensitive");
    std::fs::create_dir(&parent).unwrap();
    common::windows::enable_case_sensitive(&parent).expect("real NTFS case-sensitive fixture must be available");
    let allowed = parent.join("selected");
    let sibling = parent.join("SELECTED");
    std::fs::create_dir(&allowed).unwrap();
    std::fs::create_dir(&sibling).unwrap();
    std::fs::write(allowed.join("value.txt"), "approved").unwrap();
    std::fs::write(sibling.join("value.txt"), "UNSELECTED_SIBLING").unwrap();
    let files = UnifiedFiles::open(f.config(FileScope::AllowedRoots(vec![allowed]))).unwrap();
    let (failed, value) = read(&files, &sibling.join("value.txt"));
    assert!(failed, "case-distinct sibling obtained authority: {value}");
    assert_eq!(value["code"], "PATH_OUTSIDE_SCOPE");
}

#[cfg(windows)]
#[test]
fn task5_existing_session_with_inheritable_public_read_is_refused_before_upload() {
    let f = Fixture::new();
    let files = UnifiedFiles::open(f.config(FileScope::Workspace)).unwrap();
    let session = f.private.join("public-staging");
    std::fs::create_dir(&session).unwrap();
    common::windows::set_acl(&session, "(A;OICI;FR;;;WD)");
    let source = f.workspace.join("upload.txt");
    std::fs::write(&source, "SYNTHETIC_UPLOAD_ONLY").unwrap();
    let outcome = files.stage_uploads(DesktopProfile::FullyUnlocked,
        &[source.to_string_lossy().into_owned()], &session);
    assert!(outcome.is_err(), "staging with Everyone inherited read copied private upload: {outcome:?}");
    assert_eq!(std::fs::read_dir(&session).unwrap().count(), 0, "refusal must precede any upload copy");
}

#[cfg(windows)]
#[test]
fn task5_existing_public_artifact_directory_is_refused() {
    let f = Fixture::new();
    let store = f.private.join("artifacts");
    std::fs::create_dir(&store).unwrap();
    common::windows::set_acl(&store, "(A;OICI;FR;;;WD)");
    assert!(UnifiedFiles::open(f.config(FileScope::Workspace)).is_err(),
        "a pre-existing public artifact directory must not acquire a private owner");
    assert_eq!(std::fs::read_dir(&store).unwrap().count(), 0);
}

#[test]
fn task5_total_boundary_and_historical_policy_field_match_enforced_budget() {
    let f = Fixture::new();
    let source = f.workspace.join("64mib.bin");
    std::fs::File::create(&source).unwrap().set_len(64 * 1024 * 1024).unwrap();
    let extra = f.workspace.join("one-byte.bin");
    std::fs::write(&extra, b"x").unwrap();
    let files = UnifiedFiles::open(f.config(FileScope::Workspace)).unwrap();
    let mut stored = 0u64;
    for _ in 0..4 {
        let (failed, value) = result(&files, DesktopProfile::FullyUnlocked, "desktop_artifact_manage",
            json!({"action":"publish","path":source}));
        assert!(!failed, "exact 256MiB boundary must remain usable: {value}");
        stored += value["artifact"]["size_bytes"].as_u64().unwrap();
    }
    assert_eq!(stored, 268_435_456);
    let (failed, value) = result(&files, DesktopProfile::FullyUnlocked, "desktop_artifact_manage",
        json!({"action":"publish","path":extra}));
    assert!(failed);
    assert_eq!(value["code"], "ARTIFACT_STORAGE_LIMIT_EXCEEDED");
    let (failed, policy) = result(&files, DesktopProfile::FullyUnlocked, "desktop_policy_status", json!({}));
    assert!(!failed);
    assert_eq!(policy["limits"]["artifact_max_total_bytes"], stored,
        "historical field must report the successfully enforced total budget");
    assert_eq!(policy["limits"]["artifact_total_bytes"], stored);
}

#[test]
fn task5_move_between_independent_roots_keeps_both_capabilities_and_one_use_observation() {
    let f = Fixture::new();
    let source = f.workspace.join("same-name.txt");
    let target = f.external.join("same-name.txt");
    std::fs::write(&source, "approved move").unwrap();
    let files = UnifiedFiles::open(f.config(FileScope::AllowedRoots(vec![f.external.clone()]))).unwrap();
    let (failed, observed) = read(&files, &source);
    assert!(!failed);
    let request = json!({"source":source,"destination":target,
        "source_observation_id":observed["observation_id"]});
    let (failed, moved) = result(&files, DesktopProfile::FullyUnlocked, "desktop_move_file", request.clone());
    assert!(!failed, "separately authorized roots on the same physical volume remain usable: {moved}");
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "approved move");
    assert!(!source.exists());
    std::fs::write(&source, "new incarnation").unwrap();
    assert!(result(&files, DesktopProfile::FullyUnlocked, "desktop_move_file", request).0);
    assert_eq!(std::fs::read_to_string(&source).unwrap(), "new incarnation");
}

#[cfg(windows)]
#[test]
fn task5_synthetic_dos_alias_lifetimes_are_serialized() {
    use std::sync::mpsc;
    use std::time::Duration;
    let f = Fixture::new();
    std::fs::write(f.workspace.join("alias-witness.txt"), "first-fixture").unwrap();
    std::fs::write(f.external.join("alias-witness.txt"), "second-fixture").unwrap();
    let external = &f.external;
    std::thread::scope(|scope| {
        let first = common::windows::DosAlias::new(&f.workspace);
        assert_eq!(std::fs::read_to_string(first.root().join("alias-witness.txt")).unwrap(), "first-fixture");
        let (attempt_tx, attempt_rx) = mpsc::channel();
        let (result_tx, result_rx) = mpsc::channel();
        scope.spawn(move || {
            attempt_tx.send(()).unwrap();
            let second = common::windows::DosAlias::new(external);
            let observed = std::fs::read_to_string(second.root().join("alias-witness.txt")).unwrap();
            drop(second);
            result_tx.send(observed).unwrap();
        });
        attempt_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let early = result_rx.recv_timeout(Duration::from_millis(750));
        // Release the first fixture before joining or reporting an assertion.
        let first_value = std::fs::read_to_string(first.root().join("alias-witness.txt"));
        drop(first);
        let (overlapped, second_value) = match early {
            Ok(value) => (true, value),
            Err(mpsc::RecvTimeoutError::Timeout) => (false, result_rx.recv_timeout(Duration::from_secs(10)).unwrap()),
            Err(error) => panic!("second alias fixture failed: {error}"),
        };
        assert_eq!(first_value.unwrap(), "first-fixture");
        assert_eq!(second_value, "second-fixture");
        assert!(!overlapped, "a competing alias fixture entered before the first released its DOS mapping");
    });
}
