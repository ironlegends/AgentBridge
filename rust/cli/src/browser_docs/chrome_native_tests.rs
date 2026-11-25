use super::*;

fn blocked_file(tree: &PrivateTree, name: &str) -> (PathBuf, File) {
    let path = tree.data_dir().unwrap().join(name);
    fs::write(&path, b"owned fixture").unwrap();
    let reader = OpenOptions::new().read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .open(&path).unwrap();
    (path, reader)
}

#[test]
fn cleanup_retries_only_after_observing_a_released_sharing_lock() {
    let mut tree = PrivateTree::create(&std::env::temp_dir()).unwrap();
    let root = tree.download_root().unwrap();
    let (path, reader) = blocked_file(&tree, "held.bin");
    let expected = id(&file_info(reader.as_raw_handle().cast()).unwrap());
    let mut held = Some(reader);
    let mut observed = None;

    // The native open first sees an incompatible, still-open file HANDLE.
    // Release only after that exact error, so no scheduler delay can make
    // the first attempt succeed and accidentally bypass the regression.
    let result = retry_sharing(&Budget::new(), || {
        let result = open_pin(&path, true);
        if let Err(error) = &result {
            if error.raw_os_error() == Some(32) {
                observed = Some(32);
                drop(held.take());
            }
        }
        result
    });
    drop(held);
    let actual = result.as_ref().map(|pin| pin.identity)
        .map_err(|error| error.raw_os_error());
    drop(result); // release the successful delete pin before tree cleanup
    tree.cleanup().unwrap();
    assert!(!root.exists());
    assert_eq!(observed, Some(32), "the fixture must exercise real sharing exclusion");
    assert_eq!(actual, Ok(expected), "cleanup must wait for release and retain identity");
}

#[test]
fn cleanup_refuses_a_persistent_lock_and_drop_does_not_renew_its_budget() {
    let mut tree = PrivateTree::create(&std::env::temp_dir()).unwrap();
    let root = tree.download_root().unwrap();
    let (path, reader) = blocked_file(&tree, "persistent.bin");

    let error = tree.cleanup().unwrap_err();
    assert_eq!(error.raw_os_error(), Some(32));
    assert!(!tree.cleaned && path.exists());
    assert!(tree.cleanup_budget.as_ref().unwrap().started.elapsed() >= CLEANUP_DEADLINE);
    let budget = tree.cleanup_budget.as_ref().unwrap();
    let state = (budget.started, budget.entries, budget.bytes);
    assert!(tree.cleanup().is_err(), "explicit retries must not renew the budget");
    let budget = tree.cleanup_budget.as_ref().unwrap();
    assert_eq!((budget.started, budget.entries, budget.bytes), state);

    // Keep the conflicting handle alive across Drop. A fresh five-second
    // budget would block this completion; reuse of the exhausted one cannot.
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let dropper = std::thread::spawn(move || {
        drop(tree);
        let _ = done_tx.send(());
    });
    let completed = done_rx.recv_timeout(Duration::from_secs(4));
    let preserved = path.exists();
    drop(reader);
    dropper.join().unwrap();
    fs::remove_dir_all(&root).unwrap();
    assert!(completed.is_ok(), "Drop renewed an already-exhausted cleanup budget");
    assert!(preserved, "a timed-out cleanup must not certify or perform deletion");
}

#[test]
fn cleanup_refuses_a_hardlink_substituted_after_a_sharing_conflict() {
    let mut tree = PrivateTree::create(&std::env::temp_dir()).unwrap();
    let mut external = PrivateTree::create(&std::env::temp_dir()).unwrap();
    let external_path = external.data_dir().unwrap().join("must-survive.bin");
    fs::write(&external_path, b"external content").unwrap();
    let (path, reader) = blocked_file(&tree, "replace.bin");
    let mut held = Some(reader);
    let mut observed = None;

    let result = retry_sharing(&Budget::new(), || {
        let result = open_pin(&path, true);
        if let Err(error) = &result {
            if error.raw_os_error() == Some(32) && held.is_some() {
                observed = Some(32);
                drop(held.take());
                fs::remove_file(&path).unwrap();
                fs::hard_link(&external_path, &path).unwrap();
            }
        }
        result
    });
    drop(held);
    let outcome = result.as_ref().map(|_| ())
        .map_err(|error| (error.kind(), error.raw_os_error()));
    drop(result);
    let outside = fs::read(&external_path).unwrap();
    let substituted = fs::read(&path).unwrap();
    fs::remove_file(&path).unwrap();
    tree.cleanup().unwrap();
    external.cleanup().unwrap();

    assert_eq!(observed, Some(32));
    assert_eq!(outcome, Err((io::ErrorKind::PermissionDenied, None)),
        "the second native open must reject the multiply-linked object");
    assert_eq!(outside, b"external content");
    assert_eq!(substituted, b"external content",
        "cleanup must leave a refused replacement untouched");
}

#[test]
fn abandoned_cleanup_preserves_the_tree_and_releases_its_pins() {
    let mut tree = PrivateTree::create(&std::env::temp_dir()).unwrap();
    let root_path = tree.download_root().unwrap();
    let expected = tree.root.as_ref().unwrap().identity;
    let file = tree.data_dir().unwrap().join("preserved.bin");
    fs::write(&file, b"must remain after unconfirmed stop").unwrap();

    tree.abandon_cleanup();
    let refused = tree.cleanup().is_err();
    let truthful = !tree.cleaned;
    drop(tree);
    let preserved = fs::read(&file).ok();
    let reopened = open_pin(&root_path, true);
    let same_identity = reopened.as_ref().is_ok_and(|pin| pin.identity == expected);

    // A DELETE pin could not coexist with the original pins. Delete only
    // after reopening and verifying the exact fixture root we created.
    if same_identity {
        let root = reopened.unwrap();
        erase_children(&root, 0, &mut Budget::new()).unwrap();
        mark_delete(&root).unwrap();
        drop(root);
        assert!(!root_path.exists());
    }

    assert!(refused && truthful, "abandoning cleanup cannot certify successful removal");
    assert_eq!(preserved.as_deref(), Some(b"must remain after unconfirmed stop".as_slice()));
    assert!(same_identity, "abandonment must release pins without deleting the owned tree");
}
