//! Test-only subprocess selection. Windows parents fail, rather than skip,
//! when the separate example is not built. Unix keeps its existing routing.
use std::path::PathBuf;
pub(crate) fn program()->PathBuf {
    let test=std::env::current_exe().expect("test executable");
    #[cfg(windows)]
    {
        let fixture=test.parent().and_then(|p|p.parent()).expect("Cargo deps path")
            .join("examples").join("agent_bridge_process_fixture.exe");
        assert!(fixture.is_file(),"missing subprocess witness: cargo build -p agent-bridge --example agent_bridge_process_fixture");
        fixture
    }
    #[cfg(not(windows))]
    {test}
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
    let mut result=vec!["--ignored".into(),"--exact".into(),name.into(),"--nocapture".into()];
    result.extend(tail.iter().map(|s|s.to_string()));result
}

/// A native fixture is externally pinned, not accepted from a path alone.
/// Retain the image handle across the complete test, including child cleanup.
#[cfg(windows)]
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
    assert_eq!(format!("{:x}",hash.finalize()),expected);
    (path,handle)
}
