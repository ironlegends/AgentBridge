//! Private, not yet admitted, Windows UAC broker primitives.
//! This module prepares requests and authenticates local IPC peers only.
//! There is intentionally no transition from a review display to approval.
//! An ordinary interactive dialog is automatable by same-account MCP tools.
//! Neither helper role nor public admin admission may launch until a separate,
//! trusted operator control and elevated Job/relay are qualified.
use super::protocol::{self, Payload, MAX_REQUEST};
use crate::runtime::RuntimeError;
use agent_bridge_lifecycle::workspace_access::PinnedProjectDirectory;
use crate::windows_tools::bundle;
use sha2::{Digest, Sha256};
use std::{fs::File, io::{self, Read}, mem::size_of, path::{Path, PathBuf}, ptr};
use std::os::windows::{ffi::{OsStrExt, OsStringExt}, io::{AsRawHandle, FromRawHandle, OwnedHandle}};
use windows_sys::Win32::{
    Foundation::{HANDLE, INVALID_HANDLE_VALUE, ERROR_PIPE_CONNECTED, ERROR_PIPE_LISTENING,
        FILETIME, WAIT_TIMEOUT, LocalFree},
    Security::{SECURITY_ATTRIBUTES, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation, GetTokenInformation},
    Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW,
    Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX},
    System::{Pipes::{CreateNamedPipeW, ConnectNamedPipe, GetNamedPipeClientProcessId, GetNamedPipeServerProcessId,
        PeekNamedPipe, PIPE_NOWAIT, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE},
        Threading::{GetCurrentProcess, GetProcessId, GetProcessTimes, OpenProcess, OpenProcessToken,
            QueryFullProcessImageNameW, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION,
            PROCESS_SYNCHRONIZE}},
};

const IMAGE_LIMIT: u64 = 512 * 1024 * 1024;
const DISPLAY_LIMIT: usize = 10_000;

fn wide(value: &std::ffi::OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}
fn path_units(value: &[u16]) -> PathBuf {
    PathBuf::from(std::ffi::OsString::from_wide(value))
}
fn digest(bytes: &[u8]) -> String { format!("{:x}", Sha256::digest(bytes)) }
fn os_handle(handle: HANDLE) -> io::Result<OwnedHandle> {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE { return Err(io::Error::last_os_error()); }
    // SAFETY: newly returned Win32 handle, transferred exactly once.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}
fn elevated(process: HANDLE) -> io::Result<bool> {
    let mut token = ptr::null_mut();
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 { return Err(io::Error::last_os_error()); }
    let token = os_handle(token)?;
    let mut result = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut bytes = 0u32;
    if unsafe { GetTokenInformation(token.as_raw_handle(), TokenElevation,
        (&mut result as *mut TOKEN_ELEVATION).cast(), size_of::<TOKEN_ELEVATION>() as u32, &mut bytes) } == 0
        || bytes != size_of::<TOKEN_ELEVATION>() as u32 {
        return Err(io::Error::last_os_error());
    }
    Ok(result.TokenIsElevated != 0)
}
fn image_path(process: HANDLE) -> io::Result<PathBuf> {
    let mut units = vec![0u16; 32_768];
    let mut length = units.len() as u32;
    if unsafe { QueryFullProcessImageNameW(process, 0, units.as_mut_ptr(), &mut length) } == 0
        || length == 0 || length as usize >= units.len() { return Err(io::Error::last_os_error()); }
    Ok(path_units(&units[..length as usize]))
}

struct ImagePin {
    path: PathBuf,
    file: File,
    identity: String,
    sha256: String,
    _parent: PinnedProjectDirectory,
}
impl ImagePin {
    fn open(path: &Path) -> Result<Self, RuntimeError> {
        let path = bundle::ordinary(path)?;
        if !path.extension().and_then(|p| p.to_str()).is_some_and(|s|s.eq_ignore_ascii_case("exe")) {
            return Err("ELEVATION_EXECUTABLE_NOT_EXE".into());
        }
        let parent = PinnedProjectDirectory::open(path.parent().ok_or("ELEVATION_IMAGE_PARENT")?)?;
        let mut file = bundle::pin(&path, false)?;
        let identity = agent_bridge_core::physical_file_identity(&file)?;
        let metadata = file.metadata()?;
        if metadata.len() == 0 || metadata.len() > IMAGE_LIMIT { return Err("ELEVATION_IMAGE_SIZE".into()); }
        let mut hash = Sha256::new();
        let mut buffer = [0; 65536]; let mut count = 0u64;
        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {break;}
            count += n as u64;
            if count > IMAGE_LIMIT {return Err("ELEVATION_IMAGE_SIZE".into());}
            hash.update(&buffer[..n]);
        }
        if count != metadata.len() {return Err("ELEVATION_IMAGE_CHANGED".into());}
        Ok(Self {path, file, identity, sha256:format!("{:x}",hash.finalize()), _parent:parent})
    }
    fn verify(&self) -> Result<(), RuntimeError> {
        if agent_bridge_core::physical_file_identity(&self.file)? != self.identity
            || agent_bridge_core::physical_file_identity(&bundle::pin(&self.path, false)?)? != self.identity {
            return Err("ELEVATION_IMAGE_CHANGED".into());
        }
        Ok(())
    }
    fn matches_process(&self, process: HANDLE) -> Result<(),RuntimeError> {
        self.verify()?;
        if agent_bridge_core::physical_file_identity(&bundle::pin(&image_path(process)?,false)?)? != self.identity {
            return Err("ELEVATION_PEER_IMAGE_MISMATCH".into());
        }
        Ok(())
    }
}

struct LocalPipe { handle: OwnedHandle, name: String }
impl LocalPipe {
    fn create(nonce: &str) -> Result<Self, RuntimeError> {
        if !protocol::valid_nonce(nonce) {return Err("ELEVATION_INVALID_NONCE".into());}
        let name = format!(r"\\.\pipe\AgentBridge.Elevation.{nonce}");
        // Use the existing verified, non-elevated interactive user SID.
        // Explicit local user + SYSTEM DACL, no inherited or Everyone ACE.
        let sddl = agent_bridge_lifecycle::private_directory_sddl()?.replace(";OICI;",";;");
        let mut descriptor = ptr::null_mut();
        let encoded = wide(std::ffi::OsStr::new(&sddl));
        if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(encoded.as_ptr(),1,&mut descriptor,ptr::null_mut()) } == 0
            || descriptor.is_null() {return Err(io::Error::last_os_error().into());}
        let attrs = SECURITY_ATTRIBUTES {nLength:size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor:descriptor,bInheritHandle:0};
        let path = wide(std::ffi::OsStr::new(&name));
        let raw = unsafe { CreateNamedPipeW(path.as_ptr(), PIPE_ACCESS_DUPLEX|FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE|PIPE_READMODE_BYTE|PIPE_NOWAIT|PIPE_REJECT_REMOTE_CLIENTS,1,
            64*1024,64*1024,0,&attrs) };
        // Capture last error before freeing descriptor.
        let result = os_handle(raw);
        unsafe {LocalFree(descriptor.cast());}
        Ok(Self {handle:result?,name})
    }
    fn peer_pid(&self) -> Result<Option<u32>, RuntimeError> {
        let raw = self.handle.as_raw_handle();
        if unsafe {ConnectNamedPipe(raw,ptr::null_mut())} == 0 {
            match io::Error::last_os_error().raw_os_error().map(|n|n as u32) {
                Some(ERROR_PIPE_LISTENING) => return Ok(None),
                Some(ERROR_PIPE_CONNECTED) => {},
                _ => return Err(io::Error::last_os_error().into()),
            }
        }
        let mut pid=0;
        if unsafe {GetNamedPipeClientProcessId(raw,&mut pid)}==0 || pid==0 {
            return Err("ELEVATION_PIPE_PEER_UNAVAILABLE".into());
        }
        Ok(Some(pid))
    }
}

fn escaped(units:&[u16]) -> Result<String,RuntimeError> {
    Ok(String::from_utf16(units)?.chars().flat_map(char::escape_default).collect())
}
struct PreparedBroker {
    payload: Vec<u8>,
    payload_sha256: String,
    nonce: String,
    helper: ImagePin,
    server_identity: PeerIdentity,
    target: ImagePin,
    cwd_path: PathBuf,
    cwd_pin: PinnedProjectDirectory,
    cwd_identity: String,
    pipe: LocalPipe,
    display: String,
}
impl PreparedBroker {
    /// No prompt, process creation, network, credential read, or elevation.
    fn prepare(mut payload:Payload) -> Result<Self,RuntimeError> {
        if elevated(unsafe {GetCurrentProcess()})? {return Err("ELEVATION_ALREADY_ELEVATED_REFUSED".into());}
        let mut entropy=[0u8;16];
        getrandom::getrandom(&mut entropy).map_err(|_|"ELEVATION_NONCE_UNAVAILABLE")?;
        let nonce=entropy.iter().map(|b|format!("{b:02x}")).collect::<String>();
        payload.request.nonce=nonce.clone();
        payload.validate(&nonce)?;
        let helper=ImagePin::open(&std::env::current_exe()?)?;
        let server_identity=observe_peer(unsafe{GetCurrentProcess()},&helper)?;
        let target=ImagePin::open(&path_units(&payload.request.executable))?;
        let cwd_path=bundle::ordinary(&path_units(&payload.request.cwd))?;
        let cwd_pin=PinnedProjectDirectory::open(&cwd_path)?;
        let cwd_identity=agent_bridge_core::physical_file_identity(&bundle::pin(&cwd_path,true)?)?;
        // Display exactly what is authorized, including escaped Unicode/control
        // characters. Never truncate a long command or a private environment.
        let payload_bytes=protocol::frame(&payload,MAX_REQUEST)?;
        let payload_sha256=digest(&payload_bytes);
        let display=format!("LOCAL APPROVAL — one administrator command\n\nExecutable: {}\nImage SHA-256: {}\nCommand line: {}\nWorking directory: {}\nVisible: {}\nEnvironment UTF-16 block: {}\nRequest SHA-256: {}\n\nReview only. Administrator admission remains closed.",
            escaped(&payload.request.executable)?,target.sha256,
            escaped(&payload.request.command[..payload.request.command.len()-1])?,
            escaped(&payload.request.cwd)?,payload.request.visible,escaped(&payload.environment)?,payload_sha256);
        if display.encode_utf16().count()>DISPLAY_LIMIT {return Err("ELEVATION_EXACT_DISPLAY_TOO_LONG".into());}
        let pipe=LocalPipe::create(&nonce)?;
        Ok(Self{payload:payload_bytes,payload_sha256,nonce,helper,server_identity,target,cwd_path,cwd_pin,cwd_identity,pipe,display})
    }
    fn verify(&self)->Result<(),RuntimeError>{
        self.helper.verify()?;self.target.verify()?;
        if observe_peer(unsafe{GetCurrentProcess()},&self.helper)?!=self.server_identity {
            return Err("ELEVATION_SERVER_INCARNATION_MISMATCH".into());
        }
        let _held=&self.cwd_pin;
        if agent_bridge_core::physical_file_identity(&bundle::pin(&self.cwd_path,true)?)?!=self.cwd_identity
            || digest(&self.payload)!=self.payload_sha256 {
            return Err("ELEVATION_REQUEST_CHANGED".into());
        }
        Ok(())
    }
    // No consent-returning method is provided. The review text and digest are
    // inert. Real operator consent must come from a separately qualified
    // trusted surface, not an ordinary window or terminal input.
}

// The expected incarnation is captured by an existing trusted process owner,
// not accepted as authority from an incoming client message or a PID alone.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PeerIdentity {
    pid: u32,
    birth: u64,
    image_identity: String,
    image_sha256: String,
    elevated: bool,
}
fn process_birth(handle: HANDLE) -> io::Result<u64> {
    let mut birth=FILETIME::default(); let mut exit=FILETIME::default();
    let mut kernel=FILETIME::default(); let mut user=FILETIME::default();
    if unsafe { GetProcessTimes(handle,&mut birth,&mut exit,&mut kernel,&mut user) }==0 {
        return Err(io::Error::last_os_error());
    }
    Ok((u64::from(birth.dwHighDateTime)<<32)|u64::from(birth.dwLowDateTime))
}
fn observe_peer(process: HANDLE, image: &ImagePin) -> Result<PeerIdentity,RuntimeError> {
    if unsafe {WaitForSingleObject(process,0)}!=WAIT_TIMEOUT {return Err("ELEVATION_PEER_NOT_RUNNING".into());}
    let pid=unsafe{GetProcessId(process)};
    let birth=process_birth(process)?;
    if pid==0 || birth==0 {return Err("ELEVATION_PEER_IDENTITY_UNAVAILABLE".into());}
    image.matches_process(process)?;
    let identity=PeerIdentity {pid,birth,image_identity:image.identity.clone(),image_sha256:image.sha256.clone(),elevated:elevated(process)?};
    if unsafe {WaitForSingleObject(process,0)}!=WAIT_TIMEOUT {return Err("ELEVATION_PEER_NOT_RUNNING".into());}
    Ok(identity)
}
struct PeerPin { process:OwnedHandle, expected:PeerIdentity, image:ImagePin }
impl PeerPin {
    fn open(expected:PeerIdentity, image:ImagePin) -> Result<Self,RuntimeError> {
        let process=os_handle(unsafe {OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|PROCESS_SYNCHRONIZE,0,expected.pid)})?;
        let pin=Self{process,expected,image};
        pin.verify()?;
        Ok(pin)
    }
    fn verify(&self)->Result<(),RuntimeError>{
        if observe_peer(self.process.as_raw_handle(),&self.image)?!=self.expected {
            return Err("ELEVATION_PEER_INCARNATION_MISMATCH".into());
        }
        Ok(())
    }
    fn verify_endpoint(&self, handle:HANDLE, server:bool)->Result<(),RuntimeError>{
        let endpoint_pid=||->Result<u32,RuntimeError>{
            let mut pid=0;
            let ok=unsafe {if server {GetNamedPipeServerProcessId(handle,&mut pid)}
                else {GetNamedPipeClientProcessId(handle,&mut pid)}};
            if ok==0||pid==0{return Err("ELEVATION_PIPE_PEER_UNAVAILABLE".into());}
            Ok(pid)
        };
        if endpoint_pid()?!=self.expected.pid{return Err("ELEVATION_PIPE_PEER_MISMATCH".into());}
        self.verify()?;
        if endpoint_pid()?!=self.expected.pid{return Err("ELEVATION_PIPE_PEER_MISMATCH".into());}
        Ok(())
    }
}

/// Retains the server process incarnation and the connected channel. A live
/// server PID alone or a syntactically valid nonce cannot authorize a command.
pub(super) struct AuthenticatedServer { pipe:File, pin:PeerPin }
impl AuthenticatedServer {
    fn connect(nonce:&str, expected:PeerIdentity, image:ImagePin)->Result<Self,RuntimeError>{
        use std::os::windows::fs::OpenOptionsExt;
        if !protocol::valid_nonce(nonce){return Err("ELEVATION_INVALID_NONCE".into());}
        let name=format!(r"\\.\pipe\AgentBridge.Elevation.{nonce}");
        // Identification-only SQOS prevents the server from impersonating
        // this client with its token. Connection is local, no WaitNamedPipe.
        let pipe=std::fs::OpenOptions::new().read(true).write(true)
            .security_qos_flags(0x0001_0000).open(name)?;
        let pin=PeerPin::open(expected,image)?;
        let owner=Self{pipe,pin};
        owner.verify()?;
        Ok(owner)
    }
    pub(super) fn verify(&self)->Result<(),RuntimeError>{
        let handle=self.pipe.as_raw_handle();
        self.pin.verify_endpoint(handle,true)?;
        let mut available=0;
        if unsafe{PeekNamedPipe(handle,ptr::null_mut(),0,ptr::null_mut(),&mut available,ptr::null_mut())}==0 {
            return Err("ELEVATION_CONTROL_CHANNEL_LOST".into());
        }
        // Until an independently qualified control-message protocol exists,
        // the connected server channel is only a lifetime witness. Any byte
        // is unexpected, never consent, input or a command.
        if available!=0{return Err("ELEVATION_UNEXPECTED_CONTROL_DATA".into());}
        Ok(())
    }
}

// Future helper-side command ownership. The command must already be created
// by OwnedChild's atomic JOB_LIST launch, never adopted by a supplied PID.
// This does not create, elevate, or admit a helper. A relay loop must call
// poll_control before effects and at bounded intervals.
struct RelayState {
    control: Option<AuthenticatedServer>,
    child: Option<crate::owned_children::OwnedChild>,
    closed: bool,
    exit: Option<crate::owned_children::ChildExit>,
}
impl RelayState {
    fn cleanup(&mut self)->Result<(),RuntimeError>{
        self.closed=true;
        self.control.take(); // revoke the channel before draining the Job
        let Some(child)=self.child.as_mut() else{return Ok(());};
        child.close_stdin();
        child.terminate()?;
        let until=std::time::Instant::now()+std::time::Duration::from_secs(2);
        loop {
            // Cancellation discards bounded output; it is not a receipt
            // for a completed output stream or successful command.
            let mut buffer=[0u8;8192];
            let _=child.read_stdout(&mut buffer);
            let _=child.read_stderr(&mut buffer);
            if let Some(exit)=child.finish()? {
                self.exit=Some(exit);
                self.child.take();
                return Ok(());
            }
            if std::time::Instant::now()>=until {
                return Err("ELEVATION_JOB_CLEANUP_PENDING".into());
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}
struct RelayOwner {
    state: std::sync::Arc<std::sync::Mutex<RelayState>>,
    lifecycle: crate::provider_owner::ProviderOwner,
}
impl RelayOwner {
    fn new(child:crate::owned_children::OwnedChild,control:AuthenticatedServer)->Self {
        let state=std::sync::Arc::new(std::sync::Mutex::new(RelayState{
            control:Some(control),child:Some(child),closed:false,exit:None,
        }));
        let cleanup=state.clone();
        let hook:crate::provider_owner::Cleanup=std::sync::Arc::new(move||
            cleanup.lock().unwrap_or_else(|error|error.into_inner()).cleanup());
        Self{state,lifecycle:crate::provider_owner::ProviderOwner::new(hook.clone(),hook)}
    }
    fn poll_control(&mut self)->Result<(),RuntimeError>{
        let result=match self.state.lock(){
            Ok(state) if !state.closed=>match state.control.as_ref(){
                Some(control)=>control.verify(),
                None=>Err("ELEVATION_CONTROL_CHANNEL_LOST".into()),
            },
            Ok(_)=>Err("ELEVATION_RELAY_CLOSED".into()),
            Err(_)=>Err("ELEVATION_RELAY_STATE_UNAVAILABLE".into()),
        };
        if let Err(error)=result {
            // Keep the real cause when cancellation succeeds. If cleanup
            // cannot be proved, retain the Job owner and report that failure.
            self.lifecycle.shutdown()?;
            return Err(error);
        }
        Ok(())
    }
    fn cancel(&mut self)->Result<(),RuntimeError>{self.lifecycle.shutdown()}
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::protocol::Request;
    fn request()->Payload{
        let path=bundle::ordinary(&std::env::current_exe().unwrap()).unwrap();
        let cwd=path.parent().unwrap().to_path_buf();
        Payload{request:Request{version:1,nonce:"0".repeat(32),
            executable:path.as_os_str().encode_wide().collect(),
            command:wide(std::ffi::OsStr::new(&format!("\"{}\" --help",path.display()))),
            cwd:cwd.as_os_str().encode_wide().collect(),visible:false},environment:vec![0,0]}
    }
    #[test]
    fn broker_preparation_pins_exact_bytes_without_consent_or_launch(){
        let prepared=PreparedBroker::prepare(request()).unwrap();
        assert_eq!(prepared.payload_sha256,digest(&prepared.payload));
        assert!(prepared.display.contains(&prepared.target.sha256));
        assert!(prepared.display.contains(&prepared.payload_sha256));
        assert!(prepared.pipe.name.ends_with(&prepared.nonce));
        assert_eq!(prepared.pipe.peer_pid().unwrap(),None);
        prepared.verify().unwrap();
    }
    #[test]
    fn local_review_cannot_use_a_mcp_clickable_dialog() {
        // A source guard, not consent simulation. Never invoke the former
        // MessageBox path, nor ShellExecuteExW, even in a test.
        let source=include_str!("broker.rs").split("#[cfg(test)]").next().unwrap();
        for forbidden in ["MessageBoxW", "IDYES", "ShellExecuteExW"] {
            assert!(!source.contains(forbidden),"unqualified local approval or launch primitive: {forbidden}");
        }
    }


    fn server_image()->ImagePin {ImagePin::open(&std::env::current_exe().unwrap()).unwrap()}
    fn connect(server:&PreparedBroker)->AuthenticatedServer {
        let channel=AuthenticatedServer::connect(&server.nonce,server.server_identity.clone(),server_image()).unwrap();
        assert_eq!(server.pipe.peer_pid().unwrap(),Some(std::process::id()));
        let client=PeerPin::open(server.server_identity.clone(),server_image()).unwrap();
        client.verify_endpoint(server.pipe.handle.as_raw_handle(),false).unwrap();
        channel
    }
    #[test]
    fn real_pipe_requires_expected_server_incarnation_and_image() {
        let server=PreparedBroker::prepare(request()).unwrap();
        let channel=connect(&server);
        channel.verify().unwrap();
        for field in ["birth","pid","image","sha256","elevation"] {
            let mut wrong=server.server_identity.clone();
            match field {
                "birth"=>wrong.birth^=1,
                "pid"=>wrong.pid=0,
                "image"=>wrong.image_identity.push_str("-wrong"),
                "sha256"=>wrong.image_sha256="0".repeat(64),
                "elevation"=>wrong.elevated=true,
                _=>unreachable!(),
            }
            assert!(PeerPin::open(wrong,server_image()).is_err(),"{field}");
        }
        drop(server);
        assert!(channel.verify().is_err(),"closed server must not retain authority");
    }
    fn until_output(child:&mut crate::owned_children::OwnedChild,needle:&str)->String{
        let until=std::time::Instant::now()+std::time::Duration::from_secs(5);
        let mut data=Vec::new();
        loop {
            let mut buffer=[0u8;4096];
            match child.read_stdout(&mut buffer) {
                Ok(n)=>data.extend_from_slice(&buffer[..n]),
                Err(e) if e.kind()==io::ErrorKind::WouldBlock=>{},
                Err(e)=>panic!("{e}"),
            }
            assert!(data.len()<=64*1024,"fixture output bound");
            let text=String::from_utf8_lossy(&data);
            if text.split_once(needle).is_some_and(|(_,rest)|rest.contains('\n')) {return text.into_owned();}
            assert!(std::time::Instant::now()<until,"fixture did not emit {needle}");
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
    #[test]
    fn relay_channel_loss_cancels_real_normal_token_job_including_descendants() {
        use crate::owned_children::{ChildSpec,OwnedChild};
        use std::time::{Duration,Instant};
        let server=PreparedBroker::prepare(request()).unwrap();
        let control=connect(&server);
        let exe=crate::test_process_fixture::program();
        let mut child=OwnedChild::spawn(&ChildSpec{
            cwd:exe.parent().unwrap().to_path_buf(),executable:exe,
            arguments:crate::test_process_fixture::args("owned_children::tests::protocol_fixture",&[])
                .into_iter().map(Into::into).collect(),env_overrides:Default::default(),
        }).unwrap();
        until_output(&mut child,"fixture-ready");
        assert!(child.owns_process(child.root_pid()).unwrap());
        let heartbeat=std::env::temp_dir().join(format!("ab-relay-heartbeat-{}-{}",std::process::id(),child.root_pid()));
        assert!(!heartbeat.exists());
        let mut message=serde_json::to_vec(&serde_json::json!({"action":"spawn","path":heartbeat})).unwrap();
        message.push(b'\n');
        let mut sent=0;let until=Instant::now()+Duration::from_secs(5);
        while sent<message.len() {
            match child.write_stdin(&message[sent..]) {
                Ok(n)=>sent+=n,
                Err(e) if e.kind()==io::ErrorKind::WouldBlock=>{},
                Err(e)=>panic!("{e}"),
            }
            assert!(Instant::now()<until);
            std::thread::sleep(Duration::from_millis(2));
        }
        let out=until_output(&mut child,"descendant:");
        let pid=out.lines().find_map(|line|line.split_once("descendant:").map(|(_,s)|s.parse::<u32>().unwrap())).unwrap();
        assert!(child.owns_process(pid).unwrap());
        while std::fs::metadata(&heartbeat).map(|m|m.len()).unwrap_or(0)<3 {
            assert!(Instant::now()<until);
            std::thread::sleep(Duration::from_millis(10));
        }
        let mut relay=RelayOwner::new(child,control);
        relay.poll_control().unwrap();
        drop(server);
        assert!(relay.poll_control().is_err());
        {
            let state=relay.state.lock().unwrap();
            assert!(state.closed&&state.control.is_none()&&state.child.is_none()&&state.exit.is_some());
        }
        relay.cancel().unwrap();
        let len=std::fs::metadata(&heartbeat).unwrap().len();
        std::thread::sleep(Duration::from_millis(80));
        assert_eq!(std::fs::metadata(&heartbeat).unwrap().len(),len);
        std::fs::remove_file(heartbeat).unwrap();
    }

    #[test]
    fn relay_refuses_unsolicited_control_bytes_before_any_effect() {
        use windows_sys::Win32::Storage::FileSystem::WriteFile;
        let server=PreparedBroker::prepare(request()).unwrap();
        let control=connect(&server);
        control.verify().unwrap();
        // This byte is malformed input, not simulated consent or a command.
        let bytes=[0xffu8];let mut written=0;
        assert_ne!(unsafe{WriteFile(server.pipe.handle.as_raw_handle(),bytes.as_ptr(),1,&mut written,ptr::null_mut())},0);
        assert_eq!(written,1);
        assert_eq!(control.verify().unwrap_err().to_string(),"ELEVATION_UNEXPECTED_CONTROL_DATA");
        // The same malformed channel must also cancel a real ordinary-token
        // Job. No elevated token, local confirmation or helper role is used.
        let exe=crate::test_process_fixture::program();
        let mut child=crate::owned_children::OwnedChild::spawn(&crate::owned_children::ChildSpec{
            cwd:exe.parent().unwrap().to_path_buf(),executable:exe,
            arguments:crate::test_process_fixture::args("owned_children::tests::protocol_fixture",&[])
                .into_iter().map(Into::into).collect(),env_overrides:Default::default(),
        }).unwrap();
        until_output(&mut child,"fixture-ready");
        assert!(child.owns_process(child.root_pid()).unwrap());
        let mut relay=RelayOwner::new(child,control);
        assert_eq!(relay.poll_control().unwrap_err().to_string(),"ELEVATION_UNEXPECTED_CONTROL_DATA");
        let state=relay.state.lock().unwrap();
        assert!(state.closed&&state.control.is_none()&&state.child.is_none()&&state.exit.is_some());
    }

    #[test]
    fn broker_refuses_ambiguous_or_injected_environment_before_prompt(){
        let mut p=request();
        p.environment="PATH=C:\\untrusted\0\0".encode_utf16().collect();
        assert!(PreparedBroker::prepare(p).is_err());
        let mut p=request();
        p.environment="TMP=C:\\a\0tmp=C:\\b\0\0".encode_utf16().collect();
        assert!(PreparedBroker::prepare(p).is_err());
        let mut p=request();
        p.environment="TEMP=C:\\a\0".encode_utf16().collect();
        assert!(PreparedBroker::prepare(p).is_err());
        let mut p=request();
        p.environment="SystemRoot=C:\\Windows\0TEMP=C:\\temp\0\0".encode_utf16().collect();
        assert!(p.validate(&p.request.nonce).is_ok());
    }
}
