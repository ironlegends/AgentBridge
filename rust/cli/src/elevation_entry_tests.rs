use std::ffi::OsString;

#[test]
fn elevation_private_roles_reject_malformed_input_without_starting_the_gui() {
    for mode in ["__terminal-elevation-broker-v1", "__terminal-elevated-command-v1"] {
        for suffix in [vec![], vec!["unexpected"], vec!["0", "0", "0", "0", "0"]] {
            let arguments = std::iter::once(mode).chain(suffix).map(OsString::from).collect::<Vec<_>>();
            assert!(crate::backend::dispatch_private_child(&arguments).is_err(),
                "recognized private role {mode} must fail before GUI or public runtime startup");
        }
    }
}

#[test]
fn elevation_private_dispatch_preserves_unrelated_native_startup() {
    for arguments in [vec![], vec![OsString::from("--unrelated-mode")]] {
        assert!(crate::backend::dispatch_private_child(&arguments).unwrap().is_none());
    }
}

#[test]
fn elevation_private_roles_refuse_even_well_formed_requests_before_admission() {
    let nonce = "a".repeat(32);
    let digest = "b".repeat(64);
    for mode in ["__terminal-elevation-broker-v1", "__terminal-elevated-command-v1"] {
        let args = [mode.to_owned(), nonce.clone(), std::process::id().to_string(), digest.clone()]
            .into_iter().map(OsString::from).collect::<Vec<_>>();
        let error = crate::backend::dispatch_private_child(&args).unwrap_err();
        assert_eq!(error.to_string(), "ELEVATION_PROVIDER_UNAVAILABLE");
    }
}
