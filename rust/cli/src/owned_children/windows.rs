//! Shared Windows owner extracted from terminal/unrestricted/windows.rs.
//! Job assignment is atomic at creation, before any child instruction.
use super::ChildSpec;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::ffi::{c_void, OsStr, OsString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::Path;
use std::ptr;
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, SetHandleInformation, ERROR_BROKEN_PIPE, ERROR_NO_DATA,
        ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, FILETIME,
        ERROR_PIPE_CONNECTED, ERROR_PIPE_NOT_CONNECTED, GENERIC_WRITE, HANDLE,
        HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::{
        CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, OPEN_EXISTING, PIPE_ACCESS_INBOUND,
    },
    System::{
        JobObjects::{
            CreateJobObjectW, IsProcessInJob, JobObjectBasicAccountingInformation,
            JobObjectExtendedLimitInformation, QueryInformationJobObject,
            SetInformationJobObject, TerminateJobObject,
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        },
        Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, CreatePipe, GetNamedPipeClientProcessId,
            PeekNamedPipe, SetNamedPipeHandleState, PIPE_NOWAIT, PIPE_READMODE_BYTE,
            PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
        },
        Threading::{
            CreateProcessW, DeleteProcThreadAttributeList, GetCurrentProcessId,
            GetExitCodeProcess, GetProcessTimes, OpenProcess, InitializeProcThreadAttributeList,
            UpdateProcThreadAttribute, WaitForSingleObject, CREATE_NEW_CONSOLE, CREATE_NO_WINDOW,
            CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT,
            PROCESS_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            PROC_THREAD_ATTRIBUTE_JOB_LIST, STARTF_USESTDHANDLES, STARTUPINFOEXW,
        },
    },
};

const PIPE_BUFFER: u32 = 64 * 1024;
const STOP_EXIT_CODE: u32 = 1;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn would_block() -> io::Error {
    io::Error::from(io::ErrorKind::WouldBlock)
}

fn stage(name: &'static str) -> io::Error {
    let error = io::Error::last_os_error();
    io::Error::new(error.kind(), format!("{name}: {error}"))
}

struct Owned(HANDLE);

// SAFETY: these uniquely owned kernel handles have no thread affinity. The
// Process and all its handles move together to one worker and are never shared.
unsafe impl Send for Owned {}

impl Owned {
    fn from_raw(raw: HANDLE, operation: &'static str) -> io::Result<Self> {
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            Err(stage(operation))
        } else {
            Ok(Self(raw))
        }
    }

    fn raw(&self) -> HANDLE {
        self.0
    }

    fn into_file(mut self) -> File {
        let handle = self.0;
        self.0 = ptr::null_mut();
        // SAFETY: ownership is transferred once; Owned no longer closes it.
        unsafe { File::from_raw_handle(handle) }
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this is the uniquely owned, valid kernel handle.
            unsafe { CloseHandle(self.0) };
        }
    }
}

struct Attributes {
    _storage: Vec<usize>,
    list: *mut c_void,
    handles: Option<Box<[HANDLE; 3]>>,
    jobs: Box<[HANDLE; 1]>,
}

impl Attributes {
    fn new(handles: Option<[HANDLE; 3]>, job: HANDLE) -> io::Result<Self> {
        let mut bytes = 0usize;
        let count = 1 + u32::from(handles.is_some());
        // SAFETY: the first call only reports the allocation size.
        unsafe { InitializeProcThreadAttributeList(ptr::null_mut(), count, 0, &mut bytes) };
        if bytes == 0 || bytes > 64 * 1024 {
            return Err(io::Error::other("Windows process attributes unavailable"));
        }
        let mut storage = vec![0usize; bytes.div_ceil(size_of::<usize>())];
        let list = storage.as_mut_ptr().cast::<c_void>();
        // SAFETY: the usize allocation provides the required alignment and size.
        if unsafe { InitializeProcThreadAttributeList(list, count, 0, &mut bytes) } == 0 {
            return Err(stage("ATTRIBUTE_INITIALIZE"));
        }
        let attributes = Self {
            _storage: storage,
            list,
            handles: handles.map(Box::new),
            jobs: Box::new([job]),
        };
        // SAFETY: both boxed arrays remain stable until after CreateProcessW.
        if let Some(handles) = &attributes.handles {
            if unsafe {
                UpdateProcThreadAttribute(
                    attributes.list,
                    0,
                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                    handles.as_ptr().cast(),
                    size_of::<[HANDLE; 3]>(),
                    ptr::null_mut(),
                    ptr::null(),
                )
            } == 0
            {
                return Err(stage("ATTRIBUTE_HANDLE_LIST"));
            }
        }
        // Assigning at creation closes the launch/AssignProcessToJobObject race.
        if unsafe {
            UpdateProcThreadAttribute(
                attributes.list,
                0,
                PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
                attributes.jobs.as_ptr().cast(),
                size_of::<HANDLE>(),
                ptr::null_mut(),
                ptr::null(),
            )
        } == 0
        {
            return Err(stage("ATTRIBUTE_JOB_LIST"));
        }
        Ok(attributes)
    }
}

impl Drop for Attributes {
    fn drop(&mut self) {
        // SAFETY: this list was initialized successfully and is no longer used.
        unsafe { DeleteProcThreadAttributeList(self.list) };
    }
}

fn wide(raw: &OsStr) -> io::Result<Vec<u16>> {
    let mut units: Vec<u16> = raw.encode_wide().collect();
    if units.contains(&0) {
        return Err(invalid("NUL is not valid in a Windows process argument"));
    }
    units.push(0);
    Ok(units)
}

pub(crate) fn quote_argument(raw: &OsStr) -> io::Result<Vec<u16>> {
    let mut quoted = vec![b'"' as u16];
    let mut slashes = 0usize;
    for unit in raw.encode_wide() {
        match unit {
            0 => return Err(invalid("NUL is not valid in a Windows process argument")),
            92 => slashes += 1,
            34 => {
                quoted.extend(std::iter::repeat_n(92, slashes * 2 + 1));
                quoted.push(34);
                slashes = 0;
            }
            _ => {
                quoted.extend(std::iter::repeat_n(92, slashes));
                quoted.push(unit);
                slashes = 0;
            }
        }
    }
    quoted.extend(std::iter::repeat_n(92, slashes * 2));
    quoted.push(34);
    Ok(quoted)
}


pub(crate) fn literal_command_line(executable: &Path, arguments: &[OsString]) -> io::Result<Vec<u16>> {
    let mut line = quote_argument(executable.as_os_str())?;
    for argument in arguments {
        line.push(32);
        let units: Vec<u16> = argument.encode_wide().collect();
        if units.is_empty() || units.iter().any(|unit| matches!(*unit, 0 | 9 | 32 | 34)) {
            line.extend(quote_argument(argument)?);
        } else { line.extend(units); }
    }
    line.push(0);
    if line.len() > 32_767 {
        return Err(invalid("Windows command line exceeds 32767 UTF-16 units"));
    }
    Ok(line)
}

#[link(name = "kernel32")]
extern "system" {
    fn CompareStringOrdinal(first: *const u16, first_len: i32,
        second: *const u16, second_len: i32, ignore_case: i32) -> i32;
}
fn compare_names(first: &[u16], second: &[u16]) -> io::Result<Ordering> {
    match unsafe { CompareStringOrdinal(first.as_ptr(), first.len() as i32,
        second.as_ptr(), second.len() as i32, 1) } {
        1 => Ok(Ordering::Less), 2 => Ok(Ordering::Equal), 3 => Ok(Ordering::Greater),
        _ => Err(stage("COMPARE_ENVIRONMENT_NAMES")),
    }
}
/// Encodes one supplied variable; the name and value rules apply to both blocks.
fn supplied_entry(key: &OsStr, value: Option<&OsStr>) -> io::Result<(Vec<u16>, Option<Vec<u16>>)> {
    let name: Vec<u16> = key.encode_wide().collect();
    if name.is_empty() || name.len() > 32_767 || name.iter().any(|unit| matches!(*unit, 0 | 61)) {
        return Err(invalid("Invalid child environment name"));
    }
    let value = value.map(|value| value.encode_wide().collect::<Vec<_>>());
    if value.as_ref().is_some_and(|value| value.len() > 32_767 || value.contains(&0)) {
        return Err(invalid("Invalid child environment value"));
    }
    Ok((name, value))
}

/// Supplied names must stay distinct under Windows case-insensitive lookup.
fn supplied_entries<'a>(
    entries: impl Iterator<Item = (&'a OsString, Option<&'a OsString>)>,
) -> io::Result<Vec<(Vec<u16>, Option<Vec<u16>>)>> {
    let mut changes: Vec<(Vec<u16>, Option<Vec<u16>>)> = Vec::new();
    for (key, value) in entries {
        let (name, value) = supplied_entry(key, value.map(OsString::as_os_str))?;
        for (existing, _) in &changes {
            if compare_names(existing, &name)? == Ordering::Equal {
                return Err(invalid("Child environment overrides contain case-ambiguous names"));
            }
        }
        changes.push((name, value));
    }
    Ok(changes)
}

pub(super) fn environment_block(
    overrides: &BTreeMap<OsString, Option<OsString>>,
) -> io::Result<Option<Vec<u16>>> {
    if overrides.is_empty() { return Ok(None); }
    if overrides.len() > 1024 {
        return Err(invalid("Too many child environment overrides"));
    }
    let changes = supplied_entries(overrides.iter().map(|(key, value)| (key, value.as_ref())))?;
    // Snapshot only; never temporarily mutate process-global environment.
    let mut entries: Vec<(Vec<u16>, Vec<u16>)> = std::env::vars_os()
        .map(|(key, value)| (key.encode_wide().collect(), value.encode_wide().collect())).collect();
    for (name, replacement) in changes {
        let mut retained = Vec::with_capacity(entries.len() + usize::from(replacement.is_some()));
        for (key, value) in entries {
            if compare_names(&key, &name)? != Ordering::Equal { retained.push((key, value)); }
        }
        if let Some(value) = replacement { retained.push((name, value)); }
        entries = retained;
    }
    sorted_block(entries).map(Some)
}

/// A block holding exactly the supplied variables; nothing is inherited from
/// this process. An empty map yields an empty (double-NUL) block.
pub(super) fn exact_environment_block(
    environment: &BTreeMap<OsString, OsString>,
) -> io::Result<Vec<u16>> {
    if environment.len() > 1024 {
        return Err(invalid("Too many child environment overrides"));
    }
    let entries = supplied_entries(environment.iter().map(|(key, value)| (key, Some(value))))?
        .into_iter()
        .map(|(name, value)| (name, value.unwrap_or_default()))
        .collect();
    sorted_block(entries)
}

/// Sorts entries as CreateProcessW requires and encodes the bounded block.
fn sorted_block(mut entries: Vec<(Vec<u16>, Vec<u16>)>) -> io::Result<Vec<u16>> {
    let mut comparison_error = None;
    entries.sort_by(|(first, _), (second, _)| match compare_names(first, second) {
        Ok(order) => order,
        Err(error) => { comparison_error = Some(error); Ordering::Equal }
    });
    if let Some(error) = comparison_error { return Err(error); }
    for pair in entries.windows(2) {
        if compare_names(&pair[0].0, &pair[1].0)? == Ordering::Equal {
            return Err(invalid("Inherited child environment contains ambiguous names"));
        }
    }
    let mut block = Vec::new();
    for (key, value) in entries {
        if key.is_empty() || key.contains(&0) || value.contains(&0) {
            return Err(invalid("Inherited child environment is invalid"));
        }
        let needed = key.len().saturating_add(value.len()).saturating_add(2);
        if block.len().saturating_add(needed) > 1_048_576 {
            return Err(invalid("Child environment exceeds its bounded allocation"));
        }
        block.extend(key);
        block.push(61);
        block.extend(value);
        block.push(0);
    }
    if block.is_empty() { block.push(0); }
    block.push(0);
    Ok(block)
}
fn process_birth(process: HANDLE) -> io::Result<u64> {
    #[cfg(test)]
    if super::tests::birth_read_fault() {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "fixture birth read failure"));
    }
    let mut creation: FILETIME = unsafe { zeroed() };
    let mut exit: FILETIME = unsafe { zeroed() };
    let mut kernel: FILETIME = unsafe { zeroed() };
    let mut user: FILETIME = unsafe { zeroed() };
    if unsafe { GetProcessTimes(process, &mut creation, &mut exit, &mut kernel, &mut user) } == 0 {
        return Err(stage("READ_PROCESS_BIRTH"));
    }
    Ok((u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime))
}

fn create_job() -> io::Result<Owned> {
    let job = Owned::from_raw(
        // SAFETY: null attributes produce a private noninheritable Job handle.
        unsafe { CreateJobObjectW(ptr::null(), ptr::null()) },
        "CREATE_JOB",
    )?;
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    // No breakaway flag: normal descendants remain owned until the session ends.
    if unsafe {
        SetInformationJobObject(
            job.raw(),
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    } == 0
    {
        return Err(stage("SET_JOB_LIMITS"));
    }
    Ok(job)
}

fn active_processes(job: &Owned) -> io::Result<u32> {
    let mut accounting: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { zeroed() };
    if unsafe {
        QueryInformationJobObject(
            job.raw(),
            JobObjectBasicAccountingInformation,
            (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
            size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(stage("QUERY_JOB_PROCESSES"));
    }
    Ok(accounting.ActiveProcesses)
}

fn output_pipe() -> io::Result<(File, Owned)> {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: ptr::null_mut(),
        bInheritHandle: 1,
    };
    let (mut read, mut write) = (ptr::null_mut(), ptr::null_mut());
    if unsafe { CreatePipe(&mut read, &mut write, &attributes, PIPE_BUFFER) } == 0 {
        return Err(stage("CREATE_OUTPUT_PIPE"));
    }
    let read = Owned::from_raw(read, "OUTPUT_READ_HANDLE")?;
    let write = Owned::from_raw(write, "OUTPUT_WRITE_HANDLE")?;
    if unsafe { SetHandleInformation(read.raw(), HANDLE_FLAG_INHERIT, 0) } == 0 {
        return Err(stage("OUTPUT_PARENT_NONINHERITABLE"));
    }
    Ok((read.into_file(), write))
}

fn input_pipe() -> io::Result<(File, Owned)> {
    let mut random = [0u8; 16];
    getrandom::fill(&mut random)
        .map_err(|error| io::Error::other(format!("PIPE_RANDOM: {error}")))?;
    let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    let name = wide(OsStr::new(&format!(r"\\.\pipe\agent-bridge-stdin-{suffix}")))?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: ptr::null_mut(),
        bInheritHandle: 1,
    };
    // The child receives the server/read endpoint, matching anonymous-pipe
    // stdin semantics. The private client/write endpoint is made nonblocking.
    let child_input = Owned::from_raw(
        unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                0,
                PIPE_BUFFER,
                0,
                &attributes,
            )
        },
        "CREATE_INPUT_PIPE",
    )?;
    // CreateFile can connect immediately after CreateNamedPipe. No waiting
    // connect or retry is used; an unexpected competing connection fails closed.
    let parent_input = Owned::from_raw(
        unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_WRITE,
                0,
                ptr::null(),
                OPEN_EXISTING,
                0,
                ptr::null_mut(),
            )
        },
        "OPEN_INPUT_WRITER",
    )?;
    // Our client is already connected, so this synchronous call cannot wait
    // for a peer. ERROR_PIPE_CONNECTED confirms the expected connection state.
    if unsafe { ConnectNamedPipe(child_input.raw(), ptr::null_mut()) } != 0 {
        return Err(io::Error::other("Unexpected input pipe connection state"));
    }
    if io::Error::last_os_error().raw_os_error() != Some(ERROR_PIPE_CONNECTED as i32) {
        return Err(stage("CONNECT_INPUT_PIPE"));
    }
    let mut client_pid = 0;
    if unsafe { GetNamedPipeClientProcessId(child_input.raw(), &mut client_pid) } == 0 {
        return Err(stage("VERIFY_INPUT_PIPE_CLIENT"));
    }
    // This is an identity check on the newly created pipe, never a process
    // lookup, authorization input, or process-termination target.
    if client_pid != unsafe { GetCurrentProcessId() } {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "Input pipe peer changed"));
    }
    let mode = PIPE_NOWAIT | PIPE_READMODE_BYTE;
    if unsafe { SetNamedPipeHandleState(parent_input.raw(), &mode, ptr::null(), ptr::null()) } == 0 {
        return Err(stage("INPUT_NONBLOCKING_MODE"));
    }
    Ok((parent_input.into_file(), child_input))
}

fn read_available(pipe: &mut File, buffer: &mut [u8]) -> io::Result<usize> {
    if buffer.is_empty() {
        return Ok(0);
    }
    let mut available = 0u32;
    if unsafe {
        PeekNamedPipe(
            pipe.as_raw_handle(),
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            &mut available,
            ptr::null_mut(),
        )
    } == 0
    {
        let error = io::Error::last_os_error();
        if matches!(error.raw_os_error(), Some(code) if code == ERROR_BROKEN_PIPE as i32
            || code == ERROR_PIPE_NOT_CONNECTED as i32 || code == ERROR_NO_DATA as i32)
        {
            return Ok(0);
        }
        return Err(error);
    }
    if available == 0 {
        return Err(would_block());
    }
    // Only this worker reads this endpoint. Reading no more than the observed
    // bytes cannot block on an empty pipe, even while the child keeps running.
    let count = buffer.len().min(available as usize);
    pipe.read(&mut buffer[..count])
}

struct StdioPipes {
    input: (File, Owned),
    output: (File, Owned),
    error: (File, Owned),
}

impl StdioPipes {
    fn create() -> io::Result<Self> {
        Ok(Self { input: input_pipe()?, output: output_pipe()?, error: output_pipe()? })
    }
}

pub(super) struct Process {
    root: Owned,
    root_pid: u32,
    job: Owned,
    stdin: Option<File>,
    stdout: Option<File>,
    stderr: Option<File>,
    exit: Option<Option<i32>>,
}

impl Process {
    fn check_launch(executable: &Path, cwd: &Path) -> io::Result<()> {
        if !executable.is_absolute() || !cwd.is_absolute() {
            return Err(invalid("Provider executable and working directory must be absolute"));
        }
        if !std::fs::metadata(executable)?.is_file() {
            return Err(invalid("Provider executable is not a file"));
        }
        if !std::fs::metadata(cwd)?.is_dir() {
            return Err(invalid("Provider working directory is not a directory"));
        }
        Ok(())
    }

    pub(super) fn spawn(specification: &ChildSpec) -> io::Result<Self> {
        Self::check_launch(&specification.executable, &specification.cwd)?;
        let mut command = literal_command_line(&specification.executable, &specification.arguments)?;
        let mut environment = environment_block(&specification.env_overrides)?;
        Self::spawn_prepared(&specification.executable, &mut command,
            &specification.cwd, environment.as_deref_mut(), false)
    }

    /// Same owner as `spawn`, but the child receives exactly `environment`.
    pub(super) fn spawn_with_environment(
        executable: &Path, arguments: &[OsString], cwd: &Path,
        environment: &BTreeMap<OsString, OsString>,
    ) -> io::Result<Self> {
        Self::check_launch(executable, cwd)?;
        let mut command = literal_command_line(executable, arguments)?;
        let mut block = exact_environment_block(environment)?;
        Self::spawn_prepared(executable, &mut command, cwd, Some(&mut block), false)
    }

    pub(super) fn spawn_prepared(
        executable: &Path, command: &mut [u16], cwd_path: &Path,
        environment: Option<&mut [u16]>, visible_console: bool,
    ) -> io::Result<Self> {
        if !executable.is_absolute() || !cwd_path.is_absolute()
            || command.last() != Some(&0) || command.len() > 32_767
            || command[..command.len().saturating_sub(1)].contains(&0)
        {
            return Err(invalid("Invalid prepared Windows process launch"));
        }
        let image = wide(executable.as_os_str())?;
        let cwd = wide(cwd_path.as_os_str())?;
        let job = create_job()?;
        let pipes = if visible_console { None } else { Some(StdioPipes::create()?) };
        let handles = pipes.as_ref().map(|pipes| {
            [pipes.input.1.raw(), pipes.output.1.raw(), pipes.error.1.raw()]
        });
        let attributes = Attributes::new(handles, job.raw())?;
        let mut startup: STARTUPINFOEXW = unsafe { zeroed() };
        startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        if let Some([input, output, error]) = handles {
            startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
            startup.StartupInfo.hStdInput = input;
            startup.StartupInfo.hStdOutput = output;
            startup.StartupInfo.hStdError = error;
        }
        startup.lpAttributeList = attributes.list;
        let console_flag = if visible_console { CREATE_NEW_CONSOLE } else { CREATE_NO_WINDOW };
        let mut information: PROCESS_INFORMATION = unsafe { zeroed() };
        // CreateProcessW uses the existing process token. There is no UAC,
        // credential substitution, restricted-token path, or fallback launch.
        if unsafe {
            CreateProcessW(
                image.as_ptr(),
                command.as_mut_ptr(),
                ptr::null(),
                ptr::null(),
                i32::from(handles.is_some()),
                console_flag | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
                environment.map_or(ptr::null(), |block| block.as_mut_ptr().cast()),
                cwd.as_ptr(),
                &startup.StartupInfo,
                &mut information,
            )
        } == 0
        {
            return Err(stage("CREATE_OWNED_PROCESS"));
        }
        // Success guarantees valid process/thread handles. Adopt them without
        // any fallible post-launch work so the caller always receives the Job
        // owner and can verify root and descendant cleanup.
        let root = Owned(information.hProcess);
        let primary_thread = Owned(information.hThread);
        drop(primary_thread);
        drop(attributes);
        let (stdin, stdout, stderr) = match pipes {
            Some(pipes) => (Some(pipes.input.0), Some(pipes.output.0), Some(pipes.error.0)),
            None => (None, None, None),
        };
        let root_pid = information.dwProcessId;
        Ok(Self { root, root_pid, job, stdin, stdout, stderr, exit: None })
    }

    pub(super) fn root_pid(&self) -> u32 { self.root_pid }

    pub(super) fn owns_process(&self, pid: u32) -> io::Result<bool> {
        if pid == 0 || active_processes(&self.job)? == 0 { return Ok(false); }
        let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE, 0, pid) };
        if raw.is_null() {
            let error = io::Error::last_os_error();
            return match error.raw_os_error() {
                Some(code) if code == ERROR_INVALID_PARAMETER as i32 || code == ERROR_ACCESS_DENIED as i32
                    => Ok(false),
                _ => Err(error),
            };
        }
        let candidate = Owned::from_raw(raw, "OPEN_OWNED_CANDIDATE")?;
        // The handle pins this incarnation during the ownership check.
        match unsafe { WaitForSingleObject(candidate.raw(), 0) } {
            WAIT_OBJECT_0 => return Ok(false),
            WAIT_TIMEOUT => {}
            _ => return Err(stage("POLL_OWNED_CANDIDATE")),
        }
        let mut member = 0;
        if unsafe { IsProcessInJob(candidate.raw(), self.job.raw(), &mut member) } == 0 {
            return Err(stage("VERIFY_JOB_MEMBERSHIP"));
        }
        if member == 0 { return Ok(false); }
        if pid == self.root_pid && process_birth(candidate.raw())? != process_birth(self.root.raw())? {
            return Ok(false);
        }
        match unsafe { WaitForSingleObject(candidate.raw(), 0) } {
            // A terminated process may still have a transient Job association.
            WAIT_TIMEOUT => Ok(active_processes(&self.job)? > 0), WAIT_OBJECT_0 => Ok(false),
            _ => Err(stage("RECHECK_OWNED_CANDIDATE")),
        }
    }

    pub(super) fn read_stdout(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match &mut self.stdout {
            Some(pipe) => read_available(pipe, buffer),
            None => Ok(0),
        }
    }

    pub(super) fn read_stderr(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match &mut self.stderr {
            Some(pipe) => read_available(pipe, buffer),
            None => Ok(0),
        }
    }

    pub(super) fn write_stdin(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let stdin = self.stdin.as_mut().ok_or_else(|| {
            if self.stdout.is_none() {
                io::Error::new(io::ErrorKind::Unsupported, "Visible console stdin is unavailable over MCP")
            } else {
                io::Error::new(io::ErrorKind::BrokenPipe, "Process stdin is closed")
            }
        })?;
        if buffer.is_empty() {
            return Ok(0);
        }
        // PIPE_NOWAIT byte pipes return immediately with a partial write (or
        // zero) when their buffer is full. Never use write_all or flush here.
        match stdin.write(buffer) {
            Ok(0) => Err(would_block()),
            result => result,
        }
    }

    pub(super) fn close_stdin(&mut self) {
        // Closing the client/write endpoint delivers EOF after buffered input;
        // do not use DisconnectNamedPipe, which would discard unread bytes.
        self.stdin.take();
    }

    pub(super) fn try_exit(&mut self) -> io::Result<Option<Option<i32>>> {
        if self.exit.is_some() {
            return Ok(self.exit);
        }
        match unsafe { WaitForSingleObject(self.root.raw(), 0) } {
            WAIT_TIMEOUT => Ok(None),
            WAIT_OBJECT_0 => {
                let mut code = 0;
                if unsafe { GetExitCodeProcess(self.root.raw(), &mut code) } == 0 {
                    return Err(stage("READ_PROCESS_EXIT"));
                }
                self.exit = Some(Some(code as i32));
                Ok(self.exit)
            }
            _ => Err(stage("POLL_PROCESS_EXIT")),
        }
    }

    pub(super) fn terminate(&mut self) -> io::Result<()> {
        self.close_stdin();
        if active_processes(&self.job)? == 0 {
            return Ok(());
        }
        if unsafe { TerminateJobObject(self.job.raw(), STOP_EXIT_CODE) } == 0 {
            let error = stage("TERMINATE_OWNED_JOB");
            if active_processes(&self.job)? != 0 {
                return Err(error);
            }
        }
        Ok(())
    }

    pub(super) fn finish(&mut self) -> io::Result<Option<Option<i32>>> {
        let exit = self.try_exit()?;
        if exit.is_some() && active_processes(&self.job)? == 0 {
            Ok(exit)
        } else {
            Ok(None)
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        self.close_stdin();
        // The caller polls finish() before claiming cleanup succeeded. Drop is
        // a nonblocking final fallback, including unwinding during worker setup.
        let _ = unsafe { TerminateJobObject(self.job.raw(), STOP_EXIT_CODE) };
        // Closing job below independently enforces KILL_ON_JOB_CLOSE.
    }
}