//! Test-only subprocess selection. Windows parents fail, rather than skip,
//! when the separate example is not built. Unix keeps its existing routing.
use std::path::PathBuf;
#[cfg(windows)]
pub(crate) fn debug_artifact(relative: impl AsRef<std::path::Path>) -> PathBuf {
    let relative = relative.as_ref();
    if let Some(dir) = std::env::var_os("AGENT_BRIDGE_TEST_DEBUG_DIR") {
        let dir = PathBuf::from(dir);
        assert!(dir.is_absolute(), "AGENT_BRIDGE_TEST_DEBUG_DIR must be an absolute path: {}", dir.display());
        return dir.join(relative);
    }
    let test = std::env::current_exe().expect("test executable");
    let default_dir = test.parent().and_then(|p| p.parent()).expect("Cargo deps path");
    let candidate = default_dir.join(relative);
    if candidate.is_file() {
        return candidate;
    }
    if let Some(build_dir) = default_dir.parent().and_then(|p| p.parent()) {
        if build_dir.file_name() == Some(std::ffi::OsStr::new("build")) {
            if let Some(profile_dir) = build_dir.parent() {
                let fallback = profile_dir.join(relative);
                if fallback.is_file() {
                    return fallback;
                }
            }
        }
    }
    candidate
}

pub(crate) fn program()->PathBuf {
    #[cfg(windows)]
    {
        let fixture=debug_artifact(std::path::Path::new("examples").join("agent_bridge_process_fixture.exe"));
        assert!(fixture.is_file(),"missing subprocess witness: cargo build -p agent-bridge --example agent_bridge_process_fixture");
        fixture
    }
    #[cfg(not(windows))]
    {std::env::current_exe().expect("test executable")}
}
pub(crate) fn args(name:&str,tail:&[&str])->Vec<String>{
    #[cfg(windows)]
    let mut result=vec![match name{
        "terminal::unrestricted::tests::child_fixture"=>"terminal-child",
        "terminal::unrestricted::tests::argv_fixture"=>"terminal-argv",
        "terminal::unrestricted::tests::no_console_child_fixture"=>"terminal-no-console",
        "terminal::unrestricted::tests::unified_windows::console_handles_fixture"=>"terminal-console",
        "owned_children::tests::protocol_fixture"=>"owned-protocol",
        _=>panic!("unknown subprocess fixture: {name}"),
    }.to_owned()];
    #[cfg(not(windows))]
    let mut result=vec!["--exact".into(),name.into(),"--nocapture".into()];
    result.extend(tail.iter().map(|s|s.to_string()));result
}

/// A Unix child fixture runs only when its parent selected it by exact name.
/// An ordinary test run returns from it at once instead of ignoring it.
#[cfg(not(windows))]
pub(crate) fn selected(name:&str)->bool{
    let args:Vec<String>=std::env::args().collect();
    args.iter().any(|arg|arg=="--exact")&&args.iter().any(|arg|arg==name)
}

/// A native fixture is externally pinned, not accepted from a path alone.
/// Retain the image handle across the complete test, including child cleanup.
#[cfg(all(windows, feature = "qualification"))]
pub(crate) fn native_gui_fixture()->(PathBuf,std::fs::File){
    use sha2::{Digest,Sha256};
    use std::io::Read;
    let path=PathBuf::from(std::env::var_os("AGENT_BRIDGE_NATIVE_TEST_FIXTURE").expect("explicit native GUI fixture"));
    let path=crate::windows_tools::bundle::ordinary(&path).unwrap();
    let expected=std::env::var("AGENT_BRIDGE_NATIVE_TEST_FIXTURE_SHA256").expect("externally pinned GUI fixture digest");
    let mut handle=crate::windows_tools::bundle::pin(&path,false).unwrap();
    let size=handle.metadata().unwrap().len();
    assert!(size>0&&size<=512*1024*1024);
    let mut hash=Sha256::new();let mut buf=[0u8;65536];let mut count=0u64;
    loop{let n=handle.read(&mut buf).unwrap();if n==0{break;}count+=n as u64;
        assert!(count<=512*1024*1024);hash.update(&buf[..n]);}
    assert_eq!(count,size);
    assert_eq!(hash.finalize().iter().map(|b| format!("{b:02x}")).collect::<String>(),expected);
    (path,handle)
}
