#![cfg(all(windows, feature = "low-il-specimen"))]
// Read-only, opt-in diagnosis of the existing pinned project specimen.
// Never consumes a PreparedProjectCommand, changes ACLs or spawns a child.
use agent_bridge_lifecycle::{initialize_operator_settings, git_revision_windows::{prepare_project_command, ProjectCommandSpec, GitRevisionError}};
use std::{path::PathBuf, time::Duration};

#[test]
fn exact_low_il_specimen_preflight_without_launch() {
    let exe=PathBuf::from(std::env::var_os("AB_LOW_IL_SPECIMEN").expect("explicit specimen"));
    let root=exe.parent().expect("specimen parent");
    let expected=std::env::var("AB_LOW_IL_SHA256").expect("explicit previously approved digest");
    assert_eq!(expected.len(),64);
    let mut sha=[0u8;32];
    for (i,byte) in sha.iter_mut().enumerate() { *byte=u8::from_str_radix(&expected[i*2..i*2+2],16).unwrap(); }
    let target=PathBuf::from(std::env::var_os("AB_LOW_IL_SCRATCH").expect("explicit existing scratch directory"));
    assert!(target.is_absolute() && target.is_dir());
    let state=target.join(format!("low-il-preflight-{}",std::process::id()));
    assert!(!state.exists());
    initialize_operator_settings(&state).expect("separate private witnesses");
    let catalog=state.join("commands.json");
    let database=state.join("extensions.json");
    let spec=ProjectCommandSpec { executable:&exe, expected_sha256:sha, workspace:root, cwd:root,
        args:&[],operator_catalog_file:&catalog,database_file:&database,additional_private_paths:&[],
        deadline:Duration::from_secs(5) };
    match prepare_project_command(&spec) {
        Ok(prepared)=> {drop(prepared);println!("LOW_IL_PREFLIGHT=PREPARED_NO_LAUNCH");},
        Err(GitRevisionError::Os{stage,error})=>{
            println!("LOW_IL_PREFLIGHT=DENIED stage={stage} win32={:?} detail={error}",error.raw_os_error());
        },
        Err(error)=>println!("LOW_IL_PREFLIGHT=DENIED {error}"),
    }
    std::fs::remove_dir_all(state).expect("remove only test witnesses");
    println!("LOW_IL_CHILD_STARTED=false ACL_MODIFIED=false CONSENT_REQUESTED=false");
}

#[test]
fn exact_low_il_specimen_prepares_with_private_boundaries() {
    let exe=PathBuf::from(std::env::var_os("AB_LOW_IL_SPECIMEN").expect("explicit specimen"));
    let root=exe.parent().expect("specimen parent");
    let expected=std::env::var("AB_LOW_IL_SHA256").expect("explicit approved digest");
    assert_eq!(expected.len(),64);
    let mut sha=[0u8;32];
    for (i,byte) in sha.iter_mut().enumerate(){*byte=u8::from_str_radix(&expected[i*2..i*2+2],16).unwrap();}
    let scratch=PathBuf::from(std::env::var_os("AB_LOW_IL_SCRATCH").expect("explicit scratch"));
    assert!(scratch.is_absolute()&&scratch.is_dir());
    let state=scratch.join(format!("low-il-boundary-{}",std::process::id()));
    assert!(!state.exists());
    initialize_operator_settings(&state).unwrap();
    struct Cleanup(PathBuf);
    impl Drop for Cleanup{fn drop(&mut self){std::fs::remove_dir_all(&self.0).expect("remove exact private fixture");}}
    let _cleanup=Cleanup(state.clone());
    let catalog=state.join("commands.json");let database=state.join("extensions.json");
    // The private directory and both regular private files must still be
    // denied by the same kernel access mechanism as the permitted specimen.
    let private=[state.as_path()];
    let spec=ProjectCommandSpec{executable:&exe,expected_sha256:sha,workspace:root,cwd:root,args:&[],
        operator_catalog_file:&catalog,database_file:&database,additional_private_paths:&private,
        deadline:Duration::from_secs(5)};
    let prepared=prepare_project_command(&spec).unwrap_or_else(|error|panic!("LOW_IL_FUNCTIONAL_PREFLIGHT_BLOCKED: {error}"));
    drop(prepared);
    println!("LOW_IL_FUNCTIONAL_PREFLIGHT=PREPARED private_file_and_directory_boundaries_verified=true launched=false");
}

#[test]
fn exact_low_il_public_echo_starts_interacts_and_drains() {
    use std::time::Instant;
    let exe=PathBuf::from(std::env::var_os("AB_LOW_IL_SPECIMEN").expect("explicit specimen"));
    let root=exe.parent().expect("specimen parent");
    // The previously reviewed executable implements only a public echo
    // protocol. Never turn this test into a general executable launcher.
    const EXPECTED:&str="9e2539258010733f503c4333ee034f2981a13ee63c5391101644477346b9ea45";
    assert_eq!(std::env::var("AB_LOW_IL_SHA256").unwrap(),EXPECTED);
    assert_eq!(exe.file_name().unwrap(),"project_echo_staging.exe");
    let mut sha=[0u8;32];
    for (i,byte) in sha.iter_mut().enumerate(){*byte=u8::from_str_radix(&EXPECTED[i*2..i*2+2],16).unwrap();}
    let scratch=PathBuf::from(std::env::var_os("AB_LOW_IL_SCRATCH").expect("explicit scratch"));
    assert!(scratch.is_absolute()&&scratch.is_dir());
    let state=scratch.join(format!("low-il-live-{}",std::process::id()));
    assert!(!state.exists());
    initialize_operator_settings(&state).unwrap();
    struct Cleanup(PathBuf);
    impl Drop for Cleanup{fn drop(&mut self){std::fs::remove_dir_all(&self.0).expect("remove exact private fixture");}}
    let _cleanup=Cleanup(state.clone());
    let catalog=state.join("commands.json");let database=state.join("extensions.json");
    let private=[state.as_path()];
    let spec=ProjectCommandSpec{executable:&exe,expected_sha256:sha,workspace:root,cwd:root,args:&[],
        operator_catalog_file:&catalog,database_file:&database,additional_private_paths:&private,
        deadline:Duration::from_secs(8)};
    let prepared=prepare_project_command(&spec).unwrap();
    println!("LOW_IL_LIVE_PREFLIGHT=PREPARED");
    let mut process=prepared.start().unwrap_or_else(|error|panic!("LOW_IL_START_BLOCKED: {error}"));
    let result=(||->Result<(),String>{
        let until=Instant::now()+Duration::from_secs(3);
        loop {
            let snap=process.snapshot().map_err(|e|e.to_string())?;
            if !snap.running{
                return Err(format!("LOW_IL_PRE_MAIN_EXIT code={:?} hex={} output_complete={} stdout={:?} stderr={:?}",
                    snap.exit_code,snap.exit_code.map(|c|format!("0x{c:08X}")).unwrap_or_default(),
                    snap.output_complete,snap.stdout,snap.stderr));
            }
            if snap.stdout.contains("READY public-echo-v1"){break;}
            if Instant::now()>=until{return Err("LOW_IL_READY_TIMEOUT".into());}
            std::thread::sleep(Duration::from_millis(20));
        }
        println!("LOW_IL_READY=true");
        process.input(b"{\"delay_ms\":700,\"operation\":\"echo\",\"phrase\":\"Agent_Bridge_Low_IL\"}\n").map_err(|e|e.to_string())?;
        let until=Instant::now()+Duration::from_secs(3);
        let mut accepted_before_response=false;
        loop {
            let snap=process.snapshot().map_err(|e|e.to_string())?;
            if !snap.running{return Err(format!("LOW_IL_EARLY_EXIT {:?}",snap.exit_code));}
            if snap.stdout.contains("ACCEPTED")&&!snap.stdout.contains("RESPONSE Agent_Bridge_Low_IL"){accepted_before_response=true;}
            if snap.stdout.contains("RESPONSE Agent_Bridge_Low_IL"){
                if !accepted_before_response{return Err("no progressive accepted witness".into());}
                break;
            }
            if Instant::now()>=until{return Err("LOW_IL_RESPONSE_TIMEOUT".into());}
            std::thread::sleep(Duration::from_millis(20));
        }
        println!("LOW_IL_ACCEPTED_AND_DELAYED_RESPONSE_WHILE_RUNNING=true");
        Ok(())
    })();
    let stopped=process.terminate().unwrap_or_else(|error|panic!("LOW_IL_CLEANUP_UNCERTAIN: {error}; prior={result:?}"));
    println!("LOW_IL_JOB_DRAINED={} code={:?} output_complete={}",!stopped.running,stopped.exit_code,stopped.output_complete);
    assert!(!stopped.running&&stopped.output_complete,"job and pipe cleanup must be confirmed");
    result.unwrap();
}


// Separate negative capability qualification. Never replace the real
// positive echo recipe above with an expected failure.
#[test]
fn exact_prepared_low_il_specimen_refuses_before_native_creation() {
    use agent_bridge_lifecycle::git_revision_windows::PROJECT_LOW_IL_UNQUALIFIED;
    let exe=PathBuf::from(std::env::var_os("AB_LOW_IL_SPECIMEN").expect("exact approved specimen"));
    let root=exe.parent().expect("specimen parent");
    const EXPECTED:&str="9e2539258010733f503c4333ee034f2981a13ee63c5391101644477346b9ea45";
    assert_eq!(std::env::var("AB_LOW_IL_SHA256").unwrap(),EXPECTED);
    assert_eq!(exe.file_name().unwrap(),"project_echo_staging.exe");
    let mut sha=[0u8;32];
    for (i,byte) in sha.iter_mut().enumerate(){*byte=u8::from_str_radix(&EXPECTED[i*2..i*2+2],16).unwrap();}
    let scratch=PathBuf::from(std::env::var_os("AB_LOW_IL_SCRATCH").expect("explicit scratch"));
    assert!(scratch.is_absolute()&&scratch.is_dir());
    let state=scratch.join(format!("low-il-explicit-refusal-{}",std::process::id()));
    assert!(!state.exists());
    initialize_operator_settings(&state).unwrap();
    struct Cleanup(PathBuf);
    impl Drop for Cleanup{fn drop(&mut self){std::fs::remove_dir_all(&self.0).unwrap();}}
    let _cleanup=Cleanup(state.clone());
    let catalog=state.join("commands.json");let database=state.join("extensions.json");
    let private=[state.as_path()];
    let spec=ProjectCommandSpec{executable:&exe,expected_sha256:sha,workspace:root,cwd:root,args:&[],
        operator_catalog_file:&catalog,database_file:&database,additional_private_paths:&private,
        deadline:Duration::from_secs(5)};
    let prepared=prepare_project_command(&spec).expect("previously qualified access boundary");
    match prepared.start(){
        Err(GitRevisionError::Refused(reason))=>assert_eq!(reason,PROJECT_LOW_IL_UNQUALIFIED),
        Err(other)=>panic!("expected pre-start compatibility refusal, not {other}"),
        Ok(mut unexpected)=>{
            let cleanup=unexpected.terminate();
            panic!("unqualified launcher unexpectedly created a process; cleanup_confirmed={}",cleanup.is_ok());
        }
    }
    println!("LOW_IL_PREPARED_REFUSAL=VERIFIED no_child_handle_returned=true outcome=refused_before_start");
}
