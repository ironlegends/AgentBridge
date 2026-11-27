use agent_bridge_lifecycle::rotating_log::{RotatingLogPolicy, RotatingLogStats, RotatingLogWriter};
use crate::native_config::TunnelConfig;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::mem::{size_of, size_of_val};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::*;
use windows::Win32::Security::*;
use windows::Win32::Security::Authorization::*;
use windows::Win32::Security::Cryptography::*;
use windows::Win32::Storage::FileSystem::*;
use windows::Win32::System::Console::*;
use windows::Win32::System::JobObjects::*;
use windows::Win32::System::Threading::*;
use zeroize::{Zeroize, Zeroizing};

struct Handle(HANDLE);
// These owned handles are used only through the serialized native owner.
unsafe impl Send for Handle {}
impl Drop for Handle { fn drop(&mut self) { unsafe { let _ = CloseHandle(self.0); } } }

struct LocalMemory(*mut std::ffi::c_void);
impl Drop for LocalMemory { fn drop(&mut self) { unsafe { let _ = LocalFree(Some(HLOCAL(self.0))); } } }

fn wide(value: &OsStr) -> Result<Vec<u16>, String> {
    let mut value = value.encode_wide().collect::<Vec<_>>();
    if value.contains(&0) { return Err("A native process path contains a null character.".into()); }
    value.push(0);
    Ok(value)
}
fn failure(stage: &str, error: windows::core::Error) -> String {
    format!("{stage} (Windows code 0x{:08x}).", error.code().0 as u32)
}
fn regular(file: &File) -> Result<(), String> {
    let meta = file.metadata().map_err(|_| "A pinned native file is unavailable.")?;
    if !meta.is_file() || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        return Err("A native input must be a regular file without a reparse point.".into());
    }
    Ok(())
}
fn pin_directories(path: &Path) -> Result<Vec<File>, String> {
    if !crate::operator_connection::local_absolute_path(path) {
        return Err("Native paths must be absolute local paths.".into());
    }
    let mut pins = Vec::new();
    for ancestor in path.ancestors().collect::<Vec<_>>().into_iter().rev() {
        if ancestor.as_os_str().is_empty() { continue; }
        let file = OpenOptions::new().access_mode(FILE_READ_ATTRIBUTES.0)
            .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0)
            .open(ancestor).map_err(|_| "A native directory cannot be pinned.")?;
        let meta = file.metadata().map_err(|_| "A native directory cannot be inspected.")?;
        if !meta.is_dir() || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
            return Err("Native directories must not contain reparse points.".into());
        }
        pins.push(file);
    }
    Ok(pins)
}
fn pinned_file(path: &Path, pins: &mut Vec<File>) -> Result<File, String> {
    pins.extend(pin_directories(path.parent().ok_or("A native file has no parent.")?)?);
    let file = OpenOptions::new().read(true).share_mode(FILE_SHARE_READ.0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0).open(path)
        .map_err(|_| "A native input is unavailable or is being modified.")?;
    regular(&file)?;
    Ok(file)
}
fn bounded(file: &File, limit: u64) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes).map_err(|_| "A native input cannot be read.")?;
    if bytes.len() as u64 > limit { return Err("A native input exceeds its size limit.".into()); }
    Ok(bytes)
}
fn current_sid() -> Result<String, String> {
    let sddl = agent_bridge_lifecycle::private_directory_sddl()
        .map_err(|_| "The current Windows identity is unavailable.")?;
    sddl.strip_prefix("O:").and_then(|s| s.split_once("D:").map(|(owner, _)| owner))
        .filter(|sid| sid.starts_with("S-1-") && sid.bytes().all(|b| b.is_ascii_digit() || b == b'S' || b == b'-'))
        .map(str::to_owned)
        .ok_or_else(|| "The current Windows identity is invalid.".into())
}
fn private_file_acl(file: &File, inherited: bool) -> Result<(), String> {
    let sid = current_sid()?;
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    let info = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    unsafe {
        GetSecurityInfo(HANDLE(file.as_raw_handle()), SE_FILE_OBJECT, info,
            None, None, None, None, Some(&mut descriptor))
            .ok().map_err(|e| failure("Private file ACL inspection failed", e))?;
        let _memory = LocalMemory(descriptor.0);
        let mut text = PWSTR::null();
        ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor, 1, info, &mut text, None)
            .map_err(|e| failure("Private file ACL decoding failed", e))?;
        let _text = LocalMemory(text.0.cast());
        let actual = text.to_string().map_err(|_| "Private file ACL text is invalid.")?;
        let prefix = format!("O:{sid}");
        let accepted = [
            format!("{prefix}D:P(A;;FA;;;{sid})"),
            format!("{prefix}D:PAI(A;;FA;;;{sid})"),
        ];
        let inherited_acl = format!("{prefix}D:AI(A;ID;FA;;;{sid})");
        if !accepted.contains(&actual) && !(inherited && actual == inherited_acl) {
            return Err("A private native file must be owned and accessible only by the current Windows user.".into());
        }
    }
    Ok(())
}

pub fn private_log(path: &Path) -> Result<File, String> {
    let _parents = pin_directories(path.parent().ok_or("A private log has no parent.")?)?;
    let sid = current_sid()?;
    let sddl = wide(OsStr::new(&format!("D:P(A;;FA;;;{sid})")))?;
    let name = wide(path.as_os_str())?;
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(sddl.as_ptr()), 1,
            &mut descriptor, None).map_err(|e| failure("Private log security creation failed", e))?;
        let _security = LocalMemory(descriptor.0);
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: false.into(),
        };
        let access = FILE_APPEND_DATA.0 | FILE_READ_ATTRIBUTES.0 | READ_CONTROL.0;
        let share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
        let handle = match CreateFileW(PCWSTR(name.as_ptr()), access,
            share, Some(&attributes), CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, None) {
            Ok(handle) => handle,
            Err(error) if error.code() == windows::core::HRESULT::from_win32(ERROR_FILE_EXISTS.0)
                || error.code() == windows::core::HRESULT::from_win32(ERROR_ALREADY_EXISTS.0) => {
                CreateFileW(PCWSTR(name.as_ptr()), access, share,
                    None, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, None)
                    .map_err(|e| failure("Private log opening failed", e))?
            }
            Err(error) => return Err(failure("Private log creation failed", error)),
        };
        let file = File::from_raw_handle(handle.0);
        regular(&file)?;
        private_file_acl(&file, false)?;
        Ok(file)
    }
}

pub(crate) struct RotatingStdioPipe {
    writer_end: Option<std::io::PipeWriter>,
    pump: Option<JoinHandle<RotatingLogStats>>,
}

impl RotatingStdioPipe {
    pub(crate) fn open(path: &Path, policy: RotatingLogPolicy) -> Result<Self, String> {
        let mut writer = RotatingLogWriter::open_with_opener(
            path,
            policy,
            Box::new(|target| private_log(target).map_err(std::io::Error::other)),
        )
        .map_err(|e| format!("Private rotating log setup failed: {e}"))?;
        let (mut reader, writer_end) = std::io::pipe()
            .map_err(|e| format!("Private stdio log pipe creation failed: {e}"))?;
        let pump = std::thread::Builder::new()
            .name("ab-stdio-log".to_owned())
            .spawn(move || {
                let mut buf = [0u8; 8192];
                loop {
                    match reader.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => writer.write_best_effort(&buf[..n]),
                        Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(_) => break,
                    }
                }
                writer.stats()
            })
            .map_err(|e| format!("Private stdio log thread failed: {e}"))?;
        Ok(Self {
            writer_end: Some(writer_end),
            pump: Some(pump),
        })
    }

    pub(crate) fn handle(&self) -> &std::io::PipeWriter {
        self.writer_end.as_ref().expect("pipe writer active")
    }

    pub(crate) fn into_pump(mut self) -> JoinHandle<RotatingLogStats> {
        self.writer_end.take();
        self.pump.take().expect("pipe pump active")
    }
}

pub fn initialize_diagnostics(root: &Path) -> Result<(), String> {
    static OUTPUTS: Mutex<Option<(PathBuf, RotatingStdioPipe, RotatingStdioPipe)>> = Mutex::new(None);
    let _parents = pin_directories(root.parent().ok_or("The diagnostics directory has no parent.")?)?;
    match std::fs::create_dir(root) {
        Ok(()) => {},
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {},
        Err(_) => return Err("The private diagnostics directory cannot be created.".into()),
    }
    let mut outputs = OUTPUTS.lock().map_err(|_| "Native diagnostics ownership unavailable.")?;
    if outputs.is_none() {
        let stdout = RotatingStdioPipe::open(&root.join("native.stdout.log"), RotatingLogPolicy::default())?;
        let stderr = RotatingStdioPipe::open(&root.join("native.stderr.log"), RotatingLogPolicy::default())?;
        *outputs = Some((root.to_owned(), stdout, stderr));
    }
    let (active_root, stdout, stderr) = outputs.as_ref().expect("diagnostic streams initialized");
    if active_root != root { return Err("Native diagnostics already use a different directory.".into()); }
    unsafe {
        let previous = GetStdHandle(STD_OUTPUT_HANDLE).unwrap_or_default();
        SetStdHandle(STD_OUTPUT_HANDLE, HANDLE(stdout.handle().as_raw_handle()))
            .map_err(|e| failure("Native stdout redirection failed", e))?;
        if let Err(error) = SetStdHandle(STD_ERROR_HANDLE, HANDLE(stderr.handle().as_raw_handle())) {
            let _ = SetStdHandle(STD_OUTPUT_HANDLE, previous);
            return Err(failure("Native stderr redirection failed", error));
        }
    }
    drop(outputs);
    std::panic::set_hook(Box::new(|info| {
        if let Some(location) = info.location() {
            eprintln!("native-panic {}:{}", location.file(), location.line());
        } else { eprintln!("native-panic"); }
    }));
    Ok(())
}

fn unprotect_key(file: &File) -> Result<Zeroizing<String>, String> {
    private_file_acl(file, true)?;
    let bytes = bounded(file, 128 * 1024)?;
    let encoded = if bytes.starts_with(&[0xff, 0xfe]) {
        if bytes.len() % 2 != 0 { return Err("The tunnel DPAPI file is truncated.".into()); }
        let units = bytes[2..].chunks_exact(2).map(|b| u16::from_le_bytes([b[0], b[1]])).collect::<Vec<_>>();
        String::from_utf16(&units).map_err(|_| "The tunnel DPAPI file is invalid.")?
    } else {
        String::from_utf8(bytes).map_err(|_| "The tunnel DPAPI file is invalid.")?
            .trim_start_matches('\u{feff}').to_owned()
    };
    let encoded = encoded.trim();
    if encoded.is_empty() || encoded.len() % 2 != 0 || !encoded.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("The tunnel DPAPI file is invalid.".into());
    }
    let encrypted = (0..encoded.len()).step_by(2)
        .map(|i| u8::from_str_radix(&encoded[i..i + 2], 16).unwrap()).collect::<Vec<_>>();
    let input = CRYPT_INTEGER_BLOB { cbData: encrypted.len() as u32, pbData: encrypted.as_ptr().cast_mut() };
    let mut output = CRYPT_INTEGER_BLOB::default();
    unsafe {
        CryptUnprotectData(&input, None, None, None, None, CRYPTPROTECT_UI_FORBIDDEN, &mut output)
            .map_err(|_| "The tunnel DPAPI key cannot be decrypted by this Windows user.")?;
        let _memory = LocalMemory(output.pbData.cast());
        let clear = std::slice::from_raw_parts_mut(output.pbData, output.cbData as usize);
        if clear.is_empty() || clear.len() > 16 * 1024 || clear.len() % 2 != 0 {
            clear.zeroize();
            return Err("The tunnel DPAPI plaintext format is invalid.".into());
        }
        let units = Zeroizing::new(clear.chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]])).collect::<Vec<_>>());
        clear.zeroize();
        let key = Zeroizing::new(String::from_utf16(&units).map_err(|_| "The tunnel DPAPI plaintext is invalid.")?);
        if key.len() < 8 || key.len() > 4096 || !key.bytes().all(|b| b.is_ascii_graphic()) {
            return Err("The tunnel DPAPI key format is invalid.".into());
        }
        Ok(key)
    }
}

fn keys(value: &serde_json::Value, expected: &[&str]) -> bool {
    value.as_object().is_some_and(|o| o.len() == expected.len() && expected.iter().all(|k| o.contains_key(*k)))
}
fn validate_profile(file: &File, config: &TunnelConfig) -> Result<String, String> {
    let value: serde_json::Value = serde_json::from_slice(&bounded(file, 64 * 1024)?)
        .map_err(|_| "The tunnel profile must use its generated JSON-compatible YAML format.")?;
    let profile = &value;
    let control = &profile["control_plane"];
    let targets = &profile["mcp"]["server_urls"];
    let paths = [
        (&profile["health"]["url_file"], config.state_dir.join("health").join(format!("{}.url", config.profile))),
        (&profile["log"]["file"], config.state_dir.join("logs").join(format!("{}.log", config.profile))),
    ];
    if !keys(profile, &["admin_ui", "config_version", "control_plane", "health", "log", "mcp"])
        || !keys(&profile["admin_ui"], &["open_browser"])
        || !keys(control, &["api_key", "base_url", "tunnel_id"])
        || !keys(&profile["health"], &["listen_addr", "url_file"])
        || !keys(&profile["log"], &["file", "format", "level"])
        || !keys(&profile["mcp"], &["server_urls"])
        || profile["config_version"] != 1 || profile["admin_ui"]["open_browser"] != false
        || control["api_key"] != "env:AGENT_BRIDGE_TUNNEL_API_KEY"
        || control["base_url"] != "https://api.openai.com"
        || !control["tunnel_id"].as_str().is_some_and(|s| s.starts_with("tunnel_") && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
        || profile["health"]["listen_addr"] != "127.0.0.1:0"
        || profile["log"]["format"] != "json" || profile["log"]["level"] != "info"
        || !targets.as_array().is_some_and(|v| v.len() == 1 && keys(&v[0], &["channel", "url"])
            && v[0]["channel"] == "main" && v[0]["url"] == config.expected_mcp_url)
        || paths.iter().any(|(actual, expected)| actual.as_str().map(Path::new) != Some(expected.as_path()))
    {
        return Err("The tunnel profile does not match its pinned identity, HTTPS target or private paths.".into());
    }
    Ok(control["tunnel_id"].as_str().unwrap().to_owned())
}

fn child_environment(config: &TunnelConfig, key: &str) -> Result<Zeroizing<Vec<u16>>, String> {
    let mut public = BTreeMap::new();
    for name in ["SystemRoot", "WINDIR", "USERPROFILE", "LOCALAPPDATA", "APPDATA", "TEMP", "TMP"] {
        if let Some(value) = std::env::var_os(name) { public.insert(name.to_uppercase(), value); }
    }
    for (name, value) in [
        ("TUNNEL_CLIENT_STATE_DIR", config.state_dir.as_os_str()),
        ("MCP_OAUTH_TRUSTED_ORIGINS", OsStr::new(&config.expected_origin)),
        ("HARPOON_OAUTH_FORWARD_ORIGINS", OsStr::new(&config.expected_origin)),
        ("HARPOON_ALLOW_PLAINTEXT_HTTP", OsStr::new("false")),
        ("OPEN_WEB_UI", OsStr::new("false")),
        ("ALLOW_REMOTE_UI", OsStr::new("false")),
    ] { public.insert(name.to_owned(), value.to_os_string()); }
    let mut environment = Zeroizing::new(Vec::new());
    public.insert("AGENT_BRIDGE_TUNNEL_API_KEY".to_owned(), Default::default());
    for (name, value) in public {
        environment.extend(name.encode_utf16());
        environment.push(b'=' as u16);
        if name == "AGENT_BRIDGE_TUNNEL_API_KEY" { environment.extend(key.encode_utf16()); }
        else {
            let units = wide(&value)?;
            environment.extend_from_slice(&units[..units.len() - 1]);
        }
        environment.push(0);
    }
    environment.push(0);
    Ok(environment)
}

fn quote(value: &OsStr) -> Result<Vec<u16>, String> {
    let units = wide(value)?;
    let mut output = vec![b'"' as u16];
    let mut slashes = 0;
    for &unit in &units[..units.len() - 1] {
        if unit == b'\\' as u16 { slashes += 1; continue; }
        output.extend(std::iter::repeat_n(b'\\' as u16, if unit == b'"' as u16 { slashes * 2 + 1 } else { slashes }));
        output.push(unit);
        slashes = 0;
    }
    output.extend(std::iter::repeat_n(b'\\' as u16, slashes * 2));
    output.push(b'"' as u16);
    Ok(output)
}

struct InheritedHandles(Vec<HANDLE>);
impl InheritedHandles {
    fn new(handles: &[HANDLE]) -> Result<Self, String> {
        let mut inherited = Self(Vec::new());
        for &handle in handles {
            unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT)
                .map_err(|e| failure("Native child output inheritance failed", e))?; }
            inherited.0.push(handle);
        }
        Ok(inherited)
    }
}
impl Drop for InheritedHandles {
    fn drop(&mut self) {
        for &handle in &self.0 {
            unsafe { let _ = SetHandleInformation(handle, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0)); }
        }
    }
}

struct Attributes {
    pointer: LPPROC_THREAD_ATTRIBUTE_LIST,
    _storage: Vec<usize>,
}
impl Attributes {
    fn new(job: &HANDLE, handles: &[HANDLE]) -> Result<Self, String> {
        unsafe {
            let mut size = 0;
            let _ = InitializeProcThreadAttributeList(None, 2, None, &mut size);
            if size == 0 { return Err("Native process attribute sizing failed.".into()); }
            let mut storage = vec![0usize; size.div_ceil(size_of::<usize>())];
            let pointer = LPPROC_THREAD_ATTRIBUTE_LIST(storage.as_mut_ptr().cast());
            InitializeProcThreadAttributeList(Some(pointer), 2, None, &mut size)
                .map_err(|e| failure("Native process attributes failed", e))?;
            let attributes = Self { pointer, _storage: storage };
            UpdateProcThreadAttribute(pointer, 0, PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
                Some((job as *const HANDLE).cast()), size_of::<HANDLE>(), None, None)
                .map_err(|e| failure("Native process Job binding failed", e))?;
            UpdateProcThreadAttribute(pointer, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                Some(handles.as_ptr().cast()), std::mem::size_of_val(handles), None, None)
                .map_err(|e| failure("Native process handle binding failed", e))?;
            Ok(attributes)
        }
    }
}
impl Drop for Attributes { fn drop(&mut self) { unsafe { DeleteProcThreadAttributeList(self.pointer); } } }

pub struct OwnedProcess {
    process: Handle,
    job: Handle,
    pub pid: u32,
}
impl OwnedProcess {
    pub fn spawn(program: &Path, arguments: &[&OsStr], cwd: &Path, environment: &mut [u16],
        stdout: &impl AsRawHandle, stderr: &impl AsRawHandle) -> Result<Self, String> {
        let image = wide(program.as_os_str())?;
        let directory = wide(cwd.as_os_str())?;
        let mut command = quote(program.as_os_str())?;
        for arg in arguments { command.push(b' ' as u16); command.extend(quote(arg)?); }
        if command.len() >= 32766 { return Err("The native child command is too long.".into()); }
        command.push(0);
        unsafe {
            let job = Handle(CreateJobObjectW(None, PCWSTR::null())
                .map_err(|e| failure("Native child Job creation failed", e))?);
            let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            SetInformationJobObject(job.0, JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(), size_of_val(&limits) as u32)
                .map_err(|e| failure("Native child Job limits failed", e))?;
            let nul_name = wide(OsStr::new("NUL"))?;
            let security = SECURITY_ATTRIBUTES { nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: std::ptr::null_mut(), bInheritHandle: true.into() };
            let input = Handle(CreateFileW(PCWSTR(nul_name.as_ptr()), GENERIC_READ.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE, Some(&security), OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None)
                .map_err(|e| failure("Native child stdin creation failed", e))?);
            let outputs = [HANDLE(stdout.as_raw_handle()), HANDLE(stderr.as_raw_handle())];
            let _inherited = InheritedHandles::new(&outputs)?;
            let handles = [input.0, outputs[0], outputs[1]];
            let attributes = Attributes::new(&job.0, &handles)?;
            let mut startup = STARTUPINFOEXW::default();
            startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
            startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
            startup.StartupInfo.hStdInput = input.0;
            startup.StartupInfo.hStdOutput = outputs[0];
            startup.StartupInfo.hStdError = outputs[1];
            startup.lpAttributeList = attributes.pointer;
            let mut information = PROCESS_INFORMATION::default();
            let result = CreateProcessW(PCWSTR(image.as_ptr()), Some(PWSTR(command.as_mut_ptr())),
                None, None, true, CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
                Some(environment.as_ptr().cast()), PCWSTR(directory.as_ptr()), &startup.StartupInfo, &mut information);
            result.map_err(|e| failure("Native child launch failed", e))?;
            let _thread = Handle(information.hThread);
            Ok(Self { process: Handle(information.hProcess), job, pid: information.dwProcessId })
        }
    }
    pub fn exited(&self) -> Result<Option<u32>, String> {
        unsafe {
            match WaitForSingleObject(self.process.0, 0) {
                WAIT_TIMEOUT => Ok(None),
                WAIT_OBJECT_0 => {
                    let mut code = 0;
                    GetExitCodeProcess(self.process.0, &mut code).map_err(|e| failure("Native child exit inspection failed", e))?;
                    Ok(Some(code))
                }
                _ => Err("Native child wait failed; ownership is retained.".into()),
            }
        }
    }
    pub fn stop(&mut self) -> Result<(), String> {
        unsafe { TerminateJobObject(self.job.0, 1).map_err(|e| failure("Native child Job termination failed", e))?; }
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
            unsafe {
                QueryInformationJobObject(Some(self.job.0), JobObjectBasicAccountingInformation,
                    (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                    size_of_val(&accounting) as u32, None)
                    .map_err(|e| failure("Native child Job drain inspection failed", e))?;
            }
            if accounting.ActiveProcesses == 0 && self.exited()?.is_some() { return Ok(()); }
            if Instant::now() >= deadline { return Err("Native child Job cleanup timed out; ownership is retained.".into()); }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

pub struct TunnelChild {
    pub process: OwnedProcess,
    _inputs: Vec<File>,
    log_pumps: Vec<JoinHandle<RotatingLogStats>>,
}
impl TunnelChild {
    pub fn stop(&mut self) -> Result<(), String> {
        self.process.stop()?;
        let deadline = Instant::now() + Duration::from_secs(2);
        while self.log_pumps.iter().any(|pump| !pump.is_finished()) {
            if Instant::now() >= deadline {
                return Err("Native tunnel log drain timed out; ownership is retained.".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        for pump in self.log_pumps.drain(..) {
            pump.join().map_err(|_| "Native tunnel log drain failed.".to_owned())?;
        }
        Ok(())
    }

    pub fn spawn(config: &TunnelConfig, identity: &mut Option<String>) -> Result<Self, String> {
        config.validate()?;
        let mut pins = Vec::new();
        let mut program = pinned_file(&config.program, &mut pins)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let count = program.read(&mut buffer).map_err(|_| "The tunnel SHA-256 cannot be read.")?;
            if count == 0 { break; }
            hasher.update(&buffer[..count]);
        }
        if format!("{:x}", hasher.finalize()) != config.sha256.to_ascii_lowercase() {
            return Err("The tunnel executable SHA-256 does not match the selected configuration.".into());
        }
        let profile = pinned_file(&config.profile_dir.join(format!("{}.yaml", config.profile)), &mut pins)?;
        let selected_identity = validate_profile(&profile, config)?;
        if identity.as_ref().is_some_and(|expected| expected != &selected_identity) {
            return Err("The tunnel profile identity changed during this generation; no retry was started.".into());
        }
        if identity.is_none() { *identity = Some(selected_identity); }
        let key_file = pinned_file(&config.dpapi_key_path, &mut pins)?;
        let key = unprotect_key(&key_file)?;
        pins.extend(pin_directories(&config.state_dir)?);
        pins.extend(pin_directories(&config.state_dir.join("logs"))?);
        pins.extend(pin_directories(&config.state_dir.join("health"))?);
        let stdout = RotatingStdioPipe::open(
            &config.state_dir.join("logs/native-tunnel.stdout.log"),
            RotatingLogPolicy::default(),
        )?;
        let stderr = RotatingStdioPipe::open(
            &config.state_dir.join("logs/native-tunnel.stderr.log"),
            RotatingLogPolicy::default(),
        )?;
        let mut environment = child_environment(config, &key)?;
        let arguments = [
            OsStr::new("run"), OsStr::new("--profile"), OsStr::new(&config.profile),
            OsStr::new("--profile-dir"), config.profile_dir.as_os_str(),
            OsStr::new("--open-web-ui=false"), OsStr::new("--allow-remote-ui=false"),
        ];
        let process = OwnedProcess::spawn(
            &config.program,
            &arguments,
            &config.state_dir,
            &mut environment,
            stdout.handle(),
            stderr.handle(),
        )?;
        let log_pumps = vec![stdout.into_pump(), stderr.into_pump()];
        pins.extend([program, profile, key_file]);
        Ok(Self { process, _inputs: pins, log_pumps })
    }
}
#[cfg(test)]
#[path = "native_windows_tests.rs"]
mod tests;
