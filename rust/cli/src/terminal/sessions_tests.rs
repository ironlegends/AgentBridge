//! A real, privately owned Windows Job tests the supervisor's cleanup order.
//! The normal-token fixture exists only in cfg(test); it is never a fallback
//! for production restricted-token launch, whose type remains unchanged.
use super::*;
use std::mem::{size_of,zeroed};
use std::ptr;
use windows_sys::Win32::{
    Foundation::{CloseHandle,HANDLE,WAIT_OBJECT_0,WAIT_TIMEOUT},
    System::{
        JobObjects::{
            CreateJobObjectW,AssignProcessToJobObject,TerminateJobObject,
            SetInformationJobObject,QueryInformationJobObject,
            JobObjectExtendedLimitInformation,JobObjectBasicAccountingInformation,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION,JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        },
        Threading::{
            CreateProcessW,ResumeThread,WaitForSingleObject,GetExitCodeProcess,TerminateProcess,
            STARTUPINFOW,PROCESS_INFORMATION,CREATE_NO_WINDOW,CREATE_SUSPENDED,
        },
    },
};

pub(super) enum ProjectProcessUnderTest {
    Restricted(RestrictedProjectProcess),
    OwnedFixture(OwnedJobFixture),
}
impl From<RestrictedProjectProcess> for ProjectProcessUnderTest {
    fn from(process:RestrictedProjectProcess)->Self {Self::Restricted(process)}
}
impl ProjectProcessUnderTest {
    pub(super) fn snapshot(&mut self)->io::Result<ProjectProcessSnapshot> {
        match self {
            Self::Restricted(process)=>process.snapshot().map_err(io::Error::other),
            Self::OwnedFixture(process)=>process.snapshot(),
        }
    }
    pub(super) fn input(&mut self,bytes:&[u8])->io::Result<()> {
        match self {
            Self::Restricted(process)=>process.input(bytes).map_err(io::Error::other),
            Self::OwnedFixture(_)=>Err(io::Error::other("owned Job fixture has no input protocol")),
        }
    }
    pub(super) fn terminate(&mut self)->io::Result<ProjectProcessSnapshot> {
        match self {
            Self::Restricted(process)=>process.terminate().map_err(io::Error::other),
            Self::OwnedFixture(process)=>process.terminate(),
        }
    }
}

#[derive(Clone, Copy)]
enum SnapshotFailure { Observation, Deadline }

pub(super) struct OwnedJobFixture {
    job:HANDLE,
    process:HANDLE,
    fail_next:Arc<AtomicBool>,
    snapshot_failure:Option<SnapshotFailure>,
}
// SAFETY: the fixture exclusively owns both handles and LiveProject serializes
// every access with its mutex, exactly as the production process owner does.
unsafe impl Send for OwnedJobFixture {}
impl OwnedJobFixture {
    fn start(fail_next:Arc<AtomicBool>)->Self {
        let job=unsafe{CreateJobObjectW(ptr::null(),ptr::null())};
        assert!(!job.is_null(),"{}",io::Error::last_os_error());
        let mut owner=Self{job,process:ptr::null_mut(),fail_next,snapshot_failure:None};
        let mut limits:JOBOBJECT_EXTENDED_LIMIT_INFORMATION=unsafe{zeroed()};
        limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        assert_ne!(unsafe{SetInformationJobObject(job,JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32)},0);
        let executable=crate::test_process_fixture::program();
        let mut command:Vec<u16>=format!("\"{}\" owned-job-idle",
            executable.display()).encode_utf16().chain(Some(0)).collect();
        let image:Vec<u16>=executable.to_str().unwrap().encode_utf16().chain(Some(0)).collect();
        let mut startup:STARTUPINFOW=unsafe{zeroed()};
        startup.cb=size_of::<STARTUPINFOW>() as u32;
        let mut info:PROCESS_INFORMATION=unsafe{zeroed()};
        assert_ne!(unsafe{CreateProcessW(image.as_ptr(),command.as_mut_ptr(),
            ptr::null(),ptr::null(),0,CREATE_NO_WINDOW|CREATE_SUSPENDED,
            ptr::null(),ptr::null(),&startup,&mut info)},0,"{}",io::Error::last_os_error());
        owner.process=info.hProcess;
        let assigned=unsafe{AssignProcessToJobObject(job,owner.process)};
        if assigned==0 {
            unsafe{CloseHandle(info.hThread)};
            panic!("assign private fixture Job: {}",io::Error::last_os_error());
        }
        let resumed=unsafe{ResumeThread(info.hThread)};
        unsafe{CloseHandle(info.hThread)};
        assert_ne!(resumed,u32::MAX);
        thread::sleep(Duration::from_millis(50));
        assert!(owner.snapshot().unwrap().running,"owned child fixture must still be alive");
        owner
    }
    fn active(&self)->io::Result<u32> {
        let mut accounting:JOBOBJECT_BASIC_ACCOUNTING_INFORMATION=unsafe{zeroed()};
        if unsafe{QueryInformationJobObject(self.job,JobObjectBasicAccountingInformation,
            (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
            size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,ptr::null_mut())}==0 {
            return Err(io::Error::last_os_error());
        }
        Ok(accounting.ActiveProcesses)
    }
    fn snapshot(&mut self)->io::Result<ProjectProcessSnapshot> {
        if let Some(failure)=self.snapshot_failure.take() {
            return match failure {
                SnapshotFailure::Observation=>Err(io::Error::other("injected Job observation uncertainty")),
                SnapshotFailure::Deadline=>{
                    // Match the native deadline boundary: request the exact
                    // Job's termination, then report error without waiting.
                    if unsafe{TerminateJobObject(self.job,7)}==0 {return Err(io::Error::last_os_error());}
                    Err(io::Error::new(io::ErrorKind::TimedOut,"injected owned Job deadline"))
                }
            };
        }
        self.observe()
    }
    fn observe(&self)->io::Result<ProjectProcessSnapshot> {
        let wait=unsafe{WaitForSingleObject(self.process,0)};
        if wait!=WAIT_OBJECT_0 && wait!=WAIT_TIMEOUT {return Err(io::Error::last_os_error());}
        let running=wait==WAIT_TIMEOUT || self.active()?!=0;
        let mut code=0;
        let exit_code=if running {None} else {
            if unsafe{GetExitCodeProcess(self.process,&mut code)}==0 {return Err(io::Error::last_os_error());}
            Some(code)
        };
        Ok(ProjectProcessSnapshot{running,exit_code,stdout:String::new(),stderr:String::new(),
            stdout_truncated:false,stderr_truncated:false,output_complete:!running})
    }
    fn terminate(&mut self)->io::Result<ProjectProcessSnapshot> {
        if self.fail_next.swap(false,Ordering::SeqCst) {
            return Err(io::Error::other("injected cleanup uncertainty before stopping the real Job"));
        }
        if unsafe{TerminateJobObject(self.job,7)}==0 {return Err(io::Error::last_os_error());}
        let until=Instant::now()+Duration::from_secs(2);
        loop {
            let state=self.snapshot()?;
            if !state.running {return Ok(state);}
            if Instant::now()>=until {return Err(io::Error::new(io::ErrorKind::TimedOut,"owned Job still active"));}
            thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for OwnedJobFixture {
    fn drop(&mut self) {
        // Also handles a failed assignment while the exact child is suspended.
        if !self.process.is_null() {unsafe{TerminateProcess(self.process,7);CloseHandle(self.process);}}
        unsafe{TerminateJobObject(self.job,7);CloseHandle(self.job);}
    }
}

fn supervisor_fixture(fail_next:Arc<AtomicBool>)->(SessionSupervisor,Arc<Mutex<LiveProject>>) {
    let native=ProjectProcessUnderTest::OwnedFixture(OwnedJobFixture::start(fail_next));
    let limits=EngineLimits::default();
    let policy=OperatorPolicy::builder(std::env::temp_dir()).build(&FsEnvironmentVerifier,&limits).unwrap();
    let (_,_,gate)=CommandDecisionEngine::with_fs_verifier(policy,limits).split();
    let retained=Arc::new(Mutex::new(LiveProject{native,gate,permit:None,typed_stdin:false,
        started:Instant::now(),last_used:Instant::now(),completed_at:None}));
    let registry=Arc::new(Mutex::new(Registry::default()));
    registry.lock().unwrap().project_sessions.insert(
        "f1a00000-0000-4000-8000-000000000001".to_owned(),Arc::clone(&retained));
    (SessionSupervisor::start(registry).unwrap(),retained)
}

#[test]
fn shutdown_waits_for_real_job_even_with_other_project_session_references() {
    let (mut supervisor,retained)=supervisor_fixture(Arc::new(AtomicBool::new(false)));
    supervisor.shutdown().unwrap();
    let after=retained.lock().unwrap().snapshot().unwrap();
    // Always stop the exact private fixture, including on the old faulty path.
    retained.lock().unwrap().terminate().unwrap();
    assert!(!after.running,"shutdown reported clean while the exact owned Job was still alive");
    assert_eq!(after.exit_code,Some(7));
    assert!(supervisor.registry.lock().unwrap().project_sessions.is_empty());
}

#[test]
fn shutdown_retains_failed_project_job_owner_and_can_retry() {
    let failure=Arc::new(AtomicBool::new(true));
    let (mut supervisor,retained)=supervisor_fixture(Arc::clone(&failure));
    let refused=supervisor.shutdown().is_err();
    let count=supervisor.registry.lock().unwrap().project_sessions.len();
    let running=retained.lock().unwrap().snapshot().unwrap().running;
    failure.store(false,Ordering::SeqCst);
    let retried=supervisor.shutdown();
    let after=retained.lock().unwrap().snapshot().unwrap();
    retained.lock().unwrap().terminate().unwrap();
    assert!(refused,"an uncertain native termination must not report clean");
    assert_eq!(count,1,"the failed owner's registry entry must be retained");
    assert!(running,"the injected failure did not actually stop the owned Job");
    assert!(retried.is_ok());
    assert!(!after.running);
    assert!(supervisor.registry.lock().unwrap().project_sessions.is_empty());
}
fn owned_fixture(project:&mut LiveProject)->&mut OwnedJobFixture {
    match &mut project.native {
        ProjectProcessUnderTest::OwnedFixture(fixture)=>fixture,
        ProjectProcessUnderTest::Restricted(_)=>panic!("test requires its exact owned Job fixture"),
    }
}

#[test]
fn prune_terminates_expired_real_job_before_publishing_tombstone() {
    let (mut supervisor,retained)=supervisor_fixture(Arc::new(AtomicBool::new(false)));
    let (removed,expired,after)={
        let mut registry=supervisor.registry.lock().unwrap();
        retained.lock().unwrap().started=Instant::now()-MAX_SESSION_AGE;
        registry.prune();
        (registry.project_sessions.is_empty(),
            registry.ended.values().any(|mark|mark.reason=="expired"),
            owned_fixture(&mut retained.lock().unwrap()).observe().unwrap())
    };
    let stopped=supervisor.shutdown();
    retained.lock().unwrap().terminate().unwrap();
    assert!(!after.running,"prune published a tombstone while the retained Job was still alive");
    assert_eq!(after.exit_code,Some(7));
    assert!(removed && expired);
    assert!(stopped.is_ok());
}

fn prune_uncertainty_then_shutdown_retry(expired:bool) {
    let failure=Arc::new(AtomicBool::new(true));
    let (mut supervisor,retained)=supervisor_fixture(Arc::clone(&failure));
    let (count,ended,running)={
        let mut registry=supervisor.registry.lock().unwrap();
        {
            let mut project=retained.lock().unwrap();
            if expired {
                project.started=Instant::now()-MAX_SESSION_AGE;
            } else {
                owned_fixture(&mut project).snapshot_failure=Some(SnapshotFailure::Observation);
            }
        }
        registry.prune();
        let running=owned_fixture(&mut retained.lock().unwrap()).observe().unwrap().running;
        // Freeze the watchdog while retaining the owner, so Stop exercises
        // a fresh failed termination rather than a successful automatic retry.
        supervisor.stop.store(true,Ordering::Release);
        // An already admitted watchdog pass may still acquire this lock.
        // Keep it from considering this fixture expired on that final pass.
        retained.lock().unwrap().started=Instant::now();
        (registry.project_sessions.len(),registry.ended.len(),running)
    };
    failure.store(true,Ordering::SeqCst);
    let refused=supervisor.shutdown().is_err();
    let (after_stop_count,after_stop_ended)={
        let registry=supervisor.registry.lock().unwrap();
        (registry.project_sessions.len(),registry.ended.len())
    };
    failure.store(false,Ordering::SeqCst);
    let retried=supervisor.shutdown();
    let after=owned_fixture(&mut retained.lock().unwrap()).observe().unwrap();
    retained.lock().unwrap().terminate().unwrap();
    assert_eq!(count,1,"prune must retain an owner whose termination was not confirmed");
    assert_eq!(ended,0,"prune must not publish an uncertain Job's tombstone");
    assert!(running,"the injected termination failure must leave the real Job alive");
    assert!(refused,"Stop must still encounter the retained owner's cleanup failure");
    assert_eq!(after_stop_count,1);
    assert_eq!(after_stop_ended,0);
    assert!(retried.is_ok());
    assert!(!after.running);
    assert_eq!(after.exit_code,Some(7));
    assert!(supervisor.registry.lock().unwrap().project_sessions.is_empty());
}

#[test]
fn prune_retains_expired_job_after_uncertain_termination_until_stop_retry() {
    prune_uncertainty_then_shutdown_retry(true);
}

#[test]
fn prune_retains_snapshot_error_job_after_uncertain_termination_until_stop_retry() {
    prune_uncertainty_then_shutdown_retry(false);
}

#[test]
fn prune_retains_deadline_job_until_a_later_prune_confirms_termination() {
    let failure=Arc::new(AtomicBool::new(true));
    let (mut supervisor,retained)=supervisor_fixture(Arc::clone(&failure));
    let (first_count,first_ended,removed,ended,after)={
        let mut registry=supervisor.registry.lock().unwrap();
        owned_fixture(&mut retained.lock().unwrap()).snapshot_failure=Some(SnapshotFailure::Deadline);
        registry.prune();
        let first_count=registry.project_sessions.len();
        let first_ended=registry.ended.len();
        // The native deadline keeps returning an error until terminate has
        // confirmed the root handle and empty Job. Repeat that boundary.
        owned_fixture(&mut retained.lock().unwrap()).snapshot_failure=Some(SnapshotFailure::Deadline);
        failure.store(false,Ordering::SeqCst);
        registry.prune();
        (first_count,first_ended,registry.project_sessions.is_empty(),
            registry.ended.values().any(|mark|mark.reason=="restricted_uncertain"),
            owned_fixture(&mut retained.lock().unwrap()).observe().unwrap())
    };
    let stopped=supervisor.shutdown();
    // Remove only the fixture's unconsumed injection on the pre-fix path.
    owned_fixture(&mut retained.lock().unwrap()).snapshot_failure=None;
    retained.lock().unwrap().terminate().unwrap();
    assert_eq!(first_count,1,"requesting Job termination is not confirmation");
    assert_eq!(first_ended,0,"deadline uncertainty must not become a tombstone");
    assert!(removed && ended,"the later confirmed prune must reap the retained owner");
    assert!(!after.running);
    assert_eq!(after.exit_code,Some(7));
    assert!(stopped.is_ok());
}


// A deliberately nonexistent image is safe even on the pre-fix path:
// it cannot reach confirmation or process creation. The new compatibility
// decision must take precedence over executable verification for otherwise
// valid catalog policy, without ignoring explicit local denials.
#[test]
fn project_low_il_admission_refuses_before_permit_or_launch() {
    let base=std::fs::canonicalize(std::env::temp_dir()).unwrap();
    let base=base.to_str().and_then(|value|value.strip_prefix(r"\\?\"))
        .map(PathBuf::from).unwrap_or(base);
    let root=base.join(format!("ab-low-il-closed-{}-{}",std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
    let project=root.join("project");
    let settings=root.join("settings");
    std::fs::create_dir_all(&project).unwrap();
    struct Cleanup(PathBuf);
    impl Drop for Cleanup{fn drop(&mut self){std::fs::remove_dir_all(&self.0).unwrap();}}
    let _cleanup=Cleanup(root.clone());
    agent_bridge_lifecycle::initialize_operator_settings(&settings).unwrap();
    let image=project.join("never-created.exe");
    assert!(!image.exists());
    let registry=Arc::new(Mutex::new(Registry::default()));
    let request=json!({"command":"project-program","executable":image,
        "arguments":[],"cwd":project});
    let expected="PROCESS_LOW_IL_UNQUALIFIED: Windows restricted project startup is not qualified; no process started";
    for (policy,reason) in [
        (json!({}),expected),
        (json!({"project-program":{"executable":image,"sha256":"0".repeat(64),
            "preapproved":true,"arguments":[],"cwd":project,"stdin_protocol":"public-echo-v1"}}),expected),
        (json!({"project-program":{"executable":image,"sha256":"0".repeat(64),
            "preapproved":false,"arguments":[],"cwd":project}}),
            "PROCESS_NOT_LOCALLY_APPROVED: preapproved:false expressly denies this project command"),
        (json!({"project-program":{"executable":image,"sha256":"0".repeat(64),
            "preapproved":true,"arguments":[],"cwd":project,"stdin_protocol":"invalid-test-protocol"}}),
            "PROCESS_INPUT_POLICY_DENIED: unknown private stdin protocol"),
    ] {
        std::fs::write(settings.join("commands.json"),json!({"version":1,"programs":policy}).to_string()).unwrap();
        let bound=super::super::CommandCatalogueSnapshot::load(&settings).unwrap();
        for snapshot in [None,Some(&bound)] {
            let reply=serde_json::to_value(result(start_with_snapshot(&registry,&settings,&project,
                &root.join("nonexistent.sqlite"),None,request.as_object().unwrap(),snapshot))).unwrap();
            assert_eq!(reply["isError"],true,"{reply}");
            assert_eq!(reply["content"][0]["text"],reason,"{reply}");
            assert!(reply.get("session_id").is_none());
            let owner=registry.lock().unwrap();
            assert!(owner.sessions.is_empty()&&owner.project_sessions.is_empty());
            assert_eq!(owner.active_count(),0);
        }
    }
    assert!(!image.exists());
    println!("LOW_IL_ADMISSION_REFUSAL verified_legacy_and_bound_catalog=true session_count=0");
}
