// Copyright 2026 Agent Bridge contributors. Apache-2.0.
//! Live, bounded, Windows-only process inside the existing verified restricted
//! project token and kill-on-close Job. All handles are instance-owned.

use super::*;
use std::io::Write;

const MAX_STDIN_TOTAL: usize = 2048;

/// Compatibility decision #96: the exact approved public echo image passes
/// the access/identity preflight but exits in loader initialization with
/// STATUS_DLL_INIT_FAILED (0xC0000142). Access to required system DLLs is
/// denied by the unchanged restricted token. No safe compatible launcher
/// has been qualified. This is a capability refusal, not a permission grant
/// or an uncertain command outcome. A local command approval is insufficient.
pub const PROJECT_LOW_IL_UNQUALIFIED: &str =
    "PROCESS_LOW_IL_UNQUALIFIED: Windows restricted project startup is not qualified; no process started";

/// No runtime toggle, request parameter, token replacement or fallback.
/// Reopening requires a reviewed product change and actual launch qualification.
pub fn require_project_launch_qualification() -> Result<()> {
    Err(refused(PROJECT_LOW_IL_UNQUALIFIED))
}


/// Output and status observed from this exact owned Job, never an external PID.
pub struct ProjectProcessSnapshot {
    pub running: bool,
    pub exit_code: Option<u32>,
    pub stdout: String,
    pub stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub output_complete: bool,
}

pub struct RestrictedProjectProcess {
    _prepared: PreparedGitRevision,
    child: Child,
    stdin: Option<fs::File>,
    stdout: PipeCapture,
    stderr: PipeCapture,
    deadline: Instant,
    exit: Option<u32>,
    input_written: usize,
}

// SAFETY: all Windows HANDLEs are owned exclusively by this object and may be
// used across threads; the caller protects each operation with one Mutex.
unsafe impl Send for RestrictedProjectProcess {}

impl PreparedProjectCommand {
    pub fn start(self) -> Result<RestrictedProjectProcess> {
        // Enforce even for a direct lifecycle caller with a fully prepared,
        // locally authorized command. No Job, pipe or child is created.
        require_project_launch_qualification()?;
        self.start_impl(
            #[cfg(all(test, feature = "low-il-specimen"))]
            false,
        )
    }
    fn start_impl(self, #[cfg(all(test, feature = "low-il-specimen"))] observe_loader:bool) -> Result<RestrictedProjectProcess> {
        let mut prepared=self.inner;
        if prepared.project_run.is_none() {
            return Err(refused("Only the confirmed project program may create a live session"));
        }
        let until=Instant::now()+prepared.deadline;
        verify_access(
            &prepared.primary,&prepared.workspace,&prepared.image,&prepared.protected,
        )?;
        prepared.image.reverify()?;
        let job=job_owner()?;
        // Inherit ONLY this child's stdin read end. A large pipe reserve and
        // strict aggregate write budget prevent a non-reading child from
        // blocking the owning session indefinitely.
        let (stdin_read,stdin_write)=inherited_pipe_with_size(65536)?;
        // Capture pipes make their read end private to the parent; stdin has
        // the opposite direction. HANDLE_LIST requires its child end to be
        // inheritable, and the parent's writer must never enter the child.
        if unsafe {SetHandleInformation(
            stdin_read.raw(),HANDLE_FLAG_INHERIT,HANDLE_FLAG_INHERIT,
        )} == 0 || unsafe {SetHandleInformation(
            stdin_write.raw(),HANDLE_FLAG_INHERIT,0,
        )} == 0 {
            return Err(os("PROJECT_STDIN_INHERITANCE",io::Error::last_os_error()));
        }
        let (stdout_read,stdout_write)=inherited_pipe()?;
        let (stderr_read,stderr_write)=inherited_pipe()?;
        let attrs=Attributes::new(
            job.raw(),stdin_read.raw(),stdout_write.raw(),stderr_write.raw(),
        )?;
        let mut startup:STARTUPINFOEXW=unsafe{zeroed()};
        startup.StartupInfo.cb=size_of::<STARTUPINFOEXW>() as u32;
        startup.StartupInfo.dwFlags=STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput=stdin_read.raw();
        startup.StartupInfo.hStdOutput=stdout_write.raw();
        startup.StartupInfo.hStdError=stderr_write.raw();
        startup.lpAttributeList=attrs.list;
        let exe_path=wide(prepared.image.path.as_os_str())?;
        let project=prepared.project_run.as_ref().ok_or_else(||refused("No exact project command"))?;
        let workdir=wide(project.cwd.as_os_str())?;
        let mut argv=quote_project_command(&prepared.image.path,&project.args)?;
        let environment=minimal_project_environment()?;
        for witness in &prepared.protected {verify_private_same(witness)?;}
        prepared.image.reverify()?;
        if Instant::now()>=until {return Err(refused("Project startup deadline exceeded"));}
        let mut info:PROCESS_INFORMATION=unsafe{zeroed()};
        let flags=EXTENDED_STARTUPINFO_PRESENT|CREATE_SUSPENDED
            |CREATE_NO_WINDOW|CREATE_UNICODE_ENVIRONMENT;
        // Only the exact local specimen test can request launch-time debug
        // events. The same primary token, Job, pipes, image pins, environment
        // and physical boundaries remain mandatory. No debug attach.
        #[cfg(all(test, feature = "low-il-specimen"))]
        let flags=flags|if observe_loader {windows_sys::Win32::System::Threading::DEBUG_ONLY_THIS_PROCESS}else{0};
        // SAFETY: a verified Low-IL restricted primary token and atomic Job
        // plus inherited-handle list are supplied to CreateProcessAsUserW.
        let started=unsafe{CreateProcessAsUserW(
            prepared.primary.raw(),exe_path.as_ptr(),argv.as_mut_ptr(),
            ptr::null(),ptr::null(),1,flags,
            environment.as_ptr().cast(),workdir.as_ptr(),
            &startup.StartupInfo,&mut info,
        )};
        if started==0 {
            return Err(os("PROJECT_RESTRICTED_CREATE",io::Error::last_os_error()));
        }
        let child=Child{
            job,
            process:Owned::wrap(info.hProcess,"PROJECT_PROCESS")
                .map_err(|_|uncertain("Missing restricted process handle"))?,
            thread:Owned::wrap(info.hThread,"PROJECT_THREAD")
                .map_err(|_|uncertain("Missing restricted thread handle"))?,
        };
        drop(attrs);
        drop(stdin_read);
        drop(stdout_write);
        drop(stderr_write);
        let mut actual=vec![0u16;32768];
        let mut count=actual.len() as u32;
        if unsafe{QueryFullProcessImageNameW(
            child.process.raw(),0,actual.as_mut_ptr(),&mut count,
        )}==0 || count==0 || count as usize>actual.len() {
            return Err(uncertain("Cannot attest suspended project executable"));
        }
        let mapped=PathBuf::from(OsString::from_wide(&actual[..count as usize]));
        if !same_path(&mapped,&prepared.image.path)
            .map_err(|_|uncertain("Cannot compare suspended project image"))? {
            return Err(uncertain("Suspended project image differs from pin"));
        }
        prepared.image.reverify()
            .map_err(|_|uncertain("Project executable changed before first instruction"))?;
        for witness in &prepared.protected {
            verify_private_same(witness)
                .map_err(|_|uncertain("Protected private object changed before resume"))?;
        }
        if Instant::now()>=until {return Err(GitRevisionError::Deadline);}
        if unsafe{ResumeThread(child.thread.raw())}==u32::MAX {
            return Err(uncertain("Cannot resume restricted project primary thread"));
        }
        #[cfg(all(test, feature = "low-il-specimen"))]
        if observe_loader {loader_diagnostic::observe(&child,info.dwProcessId,until)?;}
        Ok(RestrictedProjectProcess{
            _prepared:prepared,child,
            stdin:Some(stdin_write.into_file()),
            stdout:PipeCapture::new(stdout_read),
            stderr:PipeCapture::new(stderr_read),
            deadline:until,exit:None,input_written:0,
        })
    }
}

impl RestrictedProjectProcess {
    /// Nonblocking observation; read buffers are capped and polled even if
    /// the agent stops calling read (the owner's watchdog also polls).
    pub fn snapshot(&mut self)->Result<ProjectProcessSnapshot> {
        if self.exit.is_none() && Instant::now()>=self.deadline {
            self.child.kill();
            self.stdin.take();
            return Err(GitRevisionError::Deadline);
        }
        let _=self.stdout.poll()?;
        let _=self.stderr.poll()?;
        if self.exit.is_none() {
            let wait=unsafe{WaitForSingleObject(self.child.process.raw(),0)};
            if wait!=WAIT_OBJECT_0 && wait!=WAIT_TIMEOUT {
                return Err(uncertain("Cannot inspect restricted project child handle"));
            }
            if wait==WAIT_OBJECT_0 && self.stdout.closed && self.stderr.closed
                && active_job_processes(self.child.job.raw())?==0 {
                let mut exit=0u32;
                if unsafe{GetExitCodeProcess(self.child.process.raw(),&mut exit)}==0 {
                    return Err(uncertain("Restricted project exit unavailable"));
                }
                self.exit=Some(exit);
                self.stdin.take();
            }
        }
        Ok(ProjectProcessSnapshot{
            running:self.exit.is_none(),
            exit_code:self.exit,
            stdout:String::from_utf8_lossy(&self.stdout.bytes).into_owned(),
            stderr:String::from_utf8_lossy(&self.stderr.bytes).into_owned(),
            stdout_truncated:self.stdout.truncated,
            stderr_truncated:self.stderr.truncated,
            output_complete:self.stdout.closed && self.stderr.closed,
        })
    }

    /// Aggregate at most 2 KiB over the entire child lifetime; each write is
    /// at most 1024 bytes in the preallocated 64 KiB anonymous stdin pipe.
    pub fn input(&mut self,bytes:&[u8])->Result<()> {
        if bytes.is_empty()||bytes.len()>1024
            ||self.input_written.checked_add(bytes.len()).is_none_or(|n|n>MAX_STDIN_TOTAL) {
            return Err(refused("Project process stdin exceeds the approved bound"));
        }
        if !self.snapshot()?.running {
            return Err(refused("Project process has already exited"));
        }
        self.stdin.as_mut()
            .ok_or_else(||refused("Restricted project stdin closed"))?
            .write_all(bytes)
            .map_err(|e|os("PROJECT_INPUT_WRITE",e))?;
        self.input_written+=bytes.len();
        Ok(())
    }

    pub fn close_input(&mut self) {self.stdin.take();}

    /// Terminate only the owned Job, wait for the exact process and child
    /// descendants to disappear, and drain the bounded pipes.
    pub fn terminate(&mut self)->Result<ProjectProcessSnapshot> {
        self.stdin.take();
        self.child.kill();
        let until=Instant::now()+Duration::from_secs(2);
        loop {
            let _=self.stdout.poll()?;
            let _=self.stderr.poll()?;
            let count=active_job_processes(self.child.job.raw())?;
            let waited=unsafe{WaitForSingleObject(self.child.process.raw(),0)};
            if count==0 && waited==WAIT_OBJECT_0 {
                let mut exit=0u32;
                if unsafe{GetExitCodeProcess(self.child.process.raw(),&mut exit)}==0 {
                    return Err(uncertain("Cannot inspect terminated project exit"));
                }
                self.exit=Some(exit);
                let _=self.stdout.poll()?;
                let _=self.stderr.poll()?;
                return self.snapshot();
            }
            if Instant::now()>=until {
                return Err(uncertain("Owned project Job did not drain before deadline"));
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}
#[cfg(test)]
#[test]
fn unqualified_project_launch_has_a_deterministic_pre_start_refusal() {
    assert!(matches!(require_project_launch_qualification(),
        Err(GitRevisionError::Refused(reason)) if reason==PROJECT_LOW_IL_UNQUALIFIED));
}

// Test-only passive observation of Windows launch-time debug events. No
// remote memory access, debugger attachment, exception injection, token
// changes, privilege enabling, loader snaps, registry or system changes.
#[cfg(all(test, feature = "low-il-specimen"))]
mod loader_diagnostic {
    use super::*;
    use windows_sys::Win32::{
        Foundation::{DBG_CONTINUE,DBG_EXCEPTION_NOT_HANDLED,EXCEPTION_BREAKPOINT},
        Storage::FileSystem::GetFinalPathNameByHandleW,
        System::Diagnostics::Debug::{WaitForDebugEvent,ContinueDebugEvent,DEBUG_EVENT,
            CREATE_PROCESS_DEBUG_EVENT,LOAD_DLL_DEBUG_EVENT,UNLOAD_DLL_DEBUG_EVENT,EXCEPTION_DEBUG_EVENT,EXIT_PROCESS_DEBUG_EVENT},
    };
    fn file_name(handle:HANDLE)->String{
        if handle.is_null()||handle==INVALID_HANDLE_VALUE{return "unavailable".into();}
        let file=Owned(handle);let mut units=[0u16;4096];
        let n=unsafe{GetFinalPathNameByHandleW(file.raw(),units.as_mut_ptr(),units.len() as u32,0)} as usize;
        if n==0||n>=units.len(){return format!("unavailable(win32={:?})",io::Error::last_os_error().raw_os_error());}
        PathBuf::from(OsString::from_wide(&units[..n])).file_name()
            .map(|name|name.to_string_lossy().into_owned()).unwrap_or_else(||"unavailable".into())
    }
    #[link(name="kernel32")]
    extern "system" {
        fn K32GetMappedFileNameW(process:HANDLE,address:*const c_void,name:*mut u16,size:u32)->u32;
    }
    fn mapped_name(process:HANDLE,address:*const c_void)->String{
        let mut units=[0u16;4096];
        let n=unsafe{K32GetMappedFileNameW(process,address,units.as_mut_ptr(),units.len() as u32)} as usize;
        if n==0||n>=units.len(){return format!("unavailable(win32={:?})",io::Error::last_os_error().raw_os_error());}
        PathBuf::from(OsString::from_wide(&units[..n])).file_name()
            .map(|name|name.to_string_lossy().into_owned()).unwrap_or_else(||"unavailable".into())
    }
    pub(super) fn observe(child:&Child,pid:u32,until:Instant)->Result<()>{
        let deadline=until.min(Instant::now()+Duration::from_secs(4));
        let mut initial_breakpoint=false;
        let mut modules=std::collections::BTreeMap::new();
        for ordinal in 0..256 {
            if Instant::now()>=deadline{
                child.kill();
                return Err(uncertain("Loader diagnostic deadline; owned Job stopped"));
            }
            let mut event=DEBUG_EVENT::default();
            if unsafe{WaitForDebugEvent(&mut event,50)}==0 {
                let error=io::Error::last_os_error();
                if error.raw_os_error()==Some(121){continue;}
                child.kill();return Err(os("LOADER_DEBUG_EVENT",error));
            }
            if event.dwProcessId!=pid{
                child.kill();
                // DEBUG_ONLY_THIS_PROCESS must never deliver a different
                // process. Refuse without acting on its address space.
                return Err(uncertain("Unexpected process in loader diagnostic"));
            }
            let mut status=DBG_CONTINUE;let mut exit=None;
            match event.dwDebugEventCode {
                CREATE_PROCESS_DEBUG_EVENT=>{
                    let info=unsafe{event.u.CreateProcessInfo};
                    println!("LOADER_EVENT {ordinal} create_image={} mapped={}",file_name(info.hFile),
                        mapped_name(child.process.raw(),info.lpBaseOfImage));
                },
                LOAD_DLL_DEBUG_EVENT=>{
                    let info=unsafe{event.u.LoadDll};
                    let name=mapped_name(child.process.raw(),info.lpBaseOfDll);
                    println!("LOADER_EVENT {ordinal} load_dll={} mapped={name}",file_name(info.hFile));
                    modules.insert(info.lpBaseOfDll as usize,name);
                },
                UNLOAD_DLL_DEBUG_EVENT=>{
                    let base=unsafe{event.u.UnloadDll.lpBaseOfDll} as usize;
                    println!("LOADER_EVENT {ordinal} unload_dll={}",modules.remove(&base).unwrap_or_else(||"unobserved".into()));
                },
                EXCEPTION_DEBUG_EVENT=>{
                    let info=unsafe{event.u.Exception};
                    let code=info.ExceptionRecord.ExceptionCode;
                    println!("LOADER_EVENT {ordinal} exception=0x{:08X} first_chance={}",code as u32,info.dwFirstChance);
                    // A debugger's own initial breakpoint is acknowledged.
                    // Real exceptions are passed back, not swallowed.
                    if code==EXCEPTION_BREAKPOINT&&!initial_breakpoint&&info.dwFirstChance!=0{
                        initial_breakpoint=true;
                    }else{status=DBG_EXCEPTION_NOT_HANDLED;}
                },
                EXIT_PROCESS_DEBUG_EVENT=>{
                    let code=unsafe{event.u.ExitProcess.dwExitCode};
                    println!("LOADER_EVENT {ordinal} exit=0x{code:08X}");
                    exit=Some(code);
                },
                code=>println!("LOADER_EVENT {ordinal} kind={code}"),
            }
            if unsafe{ContinueDebugEvent(event.dwProcessId,event.dwThreadId,status)}==0{
                child.kill();return Err(os("LOADER_DEBUG_CONTINUE",io::Error::last_os_error()));
            }
            if exit.is_some(){return Ok(());}
        }
        child.kill();Err(uncertain("Loader diagnostic event count exceeded"))
    }
    // Only the already mapped base DLLs and the exact specimen's known
    // CRT dependencies. Metadata access checks, never LoadLibrary, DLL
    // execution, file copying, ACL changes or alternative search paths.
    fn inspect_system_inputs(primary:&PrimaryRestrictedToken)->Result<()>{
        #[link(name="kernel32")]
        extern "system" {fn GetSystemDirectoryW(name:*mut u16,size:u32)->u32;}
        let mut name=[0u16;4096];
        let count=unsafe{GetSystemDirectoryW(name.as_mut_ptr(),name.len() as u32)} as usize;
        if count==0||count>=name.len(){return Err(os("LOADER_SYSTEM_DIRECTORY",io::Error::last_os_error()));}
        let root=PathBuf::from(OsString::from_wide(&name[..count]));
        let mut inputs=Vec::new();let mut pins=Vec::new();
        for module in ["ntdll.dll","kernel32.dll","KernelBase.dll","VCRUNTIME140.dll","ucrtbase.dll"] {
            let path=root.join(module);
            let path=match normal_local(&path,false){
                Ok(path)=>path,
                Err(error)=>{println!("LOADER_INPUT {module} ordinary_path_unavailable={error}");continue;}
            };
            let handle=open_path(&path,FILE_READ_ATTRIBUTES,false,SHARE_ALL)?;
            let id=identity(handle.raw())?;
            inputs.push((module,path,id));
            pins.push(handle);
        }
        let observed=workspace_access::probe_with_primary_token(primary,move||{
            let rights=FILE_READ_DATA|FILE_EXECUTE|FILE_READ_ATTRIBUTES;
            Ok(inputs.into_iter().map(|(name,path,expected)|{
                let exact=classify_target(probe_open(&path,rights,false),expected);
                let sync=classify_target(probe_open(&path,rights|0x00100000,false),expected);
                let win32=classify_target(probe_open_win32(&path,rights,false),expected);
                (name,exact,sync,win32)
            }).collect::<Vec<_>>())
        }).map_err(|error|os("LOADER_SYSTEM_INPUT_PROBE",error))?;
        for (name,exact,sync,win32) in observed {
            println!("LOADER_INPUT {name} native_exact={exact:?} native_with_sync={sync:?} win32={win32:?}");
        }
        drop(pins);
        Ok(())
    }
    /// Requires exact existing approved Low-IL echo specimen; test-only launch-time event observation.
    #[test]
    fn exact_approved_low_il_loader_events(){
        let exe=PathBuf::from(std::env::var_os("AB_LOW_IL_SPECIMEN").expect("explicit approved specimen"));
        let root=exe.parent().unwrap();
        assert_eq!(exe.file_name().unwrap(),"project_echo_staging.exe");
        const HASH:&str="9e2539258010733f503c4333ee034f2981a13ee63c5391101644477346b9ea45";
        assert_eq!(std::env::var("AB_LOW_IL_SHA256").unwrap(),HASH);
        assert_eq!(workspace_access::project_read_sid(root).unwrap(),std::env::var("AB_LOW_IL_EXPECTED_SID").unwrap());
        let mut expected=[0u8;32];
        for (i,byte) in expected.iter_mut().enumerate(){*byte=u8::from_str_radix(&HASH[i*2..i*2+2],16).unwrap();}
        let scratch=PathBuf::from(std::env::var_os("AB_LOW_IL_SCRATCH").expect("explicit scratch"));
        assert!(scratch.is_absolute()&&scratch.is_dir());
        let state=scratch.join(format!("low-il-loader-events-{}",std::process::id()));
        assert!(!state.exists());
        crate::initialize_operator_settings(&state).unwrap();
        struct Cleanup(PathBuf);
        impl Drop for Cleanup{fn drop(&mut self){fs::remove_dir_all(&self.0).unwrap();}}
        let _cleanup=Cleanup(state.clone());
        let catalog=state.join("commands.json");let database=state.join("extensions.json");
        let private=[state.as_path()];
        let spec=ProjectCommandSpec{executable:&exe,expected_sha256:expected,workspace:root,cwd:root,args:&[],
            operator_catalog_file:&catalog,database_file:&database,additional_private_paths:&private,
            deadline:Duration::from_secs(8)};
        let prepared=prepare_project_command(&spec).unwrap();
        println!("LOADER_DIAGNOSTIC preflight=true same_restricted_token=true no_privilege_change=true");
        inspect_system_inputs(&prepared.inner.primary).unwrap();
        let mut process=prepared.start_impl(true).unwrap_or_else(|error|panic!("LOADER_DIAGNOSTIC_BLOCKED {error}"));
        let until=Instant::now()+Duration::from_secs(2);
        let observed=loop{
            let snapshot=process.snapshot().unwrap();
            if !snapshot.running{break snapshot;}
            assert!(Instant::now()<until,"diagnostic exit not recovered");
            thread::sleep(Duration::from_millis(10));
        };
        assert!(observed.output_complete);
        println!("LOADER_DIAGNOSTIC natural_exit={:?} stdout={:?} stderr={:?} output_complete={}",
            observed.exit_code,observed.stdout,observed.stderr,observed.output_complete);
        let cleaned=process.terminate().unwrap();
        assert!(!cleaned.running&&cleaned.output_complete);
        println!("LOADER_DIAGNOSTIC job_drained=true; diagnostic_not_functional_qualification=true");
    }
}
