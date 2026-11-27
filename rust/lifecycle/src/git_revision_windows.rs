// Copyright 2026 Agent Bridge contributors. Apache-2.0.
//! Execute only the locally pinned `git.exe --no-pager rev-parse --verify HEAD`.
//! Preparation holds the image and project paths and checks access with an
//! impersonation duplicate of the low-integrity primary token. Git alone
//! adds a project-specific SID to the restricting SID list,
//! keeping the original S-1-5-12 restriction and DISABLE_MAX_PRIVILEGE.
//! ACLs must grant only the specific project SID, never S-1-5-12.
//! The caller
//! must obtain command authorization before consuming that prepared operation.
//! The child starts suspended in its own job with only its three stdio handles.
//! Access checks cover the supplied private objects at the time of inspection.
//! Output and runtime are bounded after creation. Filesystem and Windows API
//! calls during preparation can block independently of the process deadline.

#[path = "native_git_revision.rs"]
mod native_git_revision;
#[path = "native_project_session.rs"]
mod native_project_session;
pub use native_project_session::{RestrictedProjectProcess, ProjectProcessSnapshot,
    PROJECT_LOW_IL_UNQUALIFIED, require_project_launch_qualification};
pub use native_git_revision::{
    prepare_native_revision, NativeRevision, NativeRevisionSpec, PreparedNativeRevision,
};

use crate::workspace_access::{self, PrimaryRestrictedToken, PinnedProjectDirectory};
use sha2::{Digest, Sha256};
use std::{
    ffi::{c_void, OsStr, OsString},
    fmt, fs,
    io::{self, Read, Seek, SeekFrom},
    mem::{size_of, zeroed},
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        fs::{MetadataExt, OpenOptionsExt},
        io::{AsRawHandle, FromRawHandle, RawHandle},
    },
    path::{Component, Path, PathBuf, Prefix},
    ptr,
    thread,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, SetHandleInformation, ERROR_ACCESS_DENIED, ERROR_BROKEN_PIPE, ERROR_PIPE_NOT_CONNECTED, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
        WAIT_TIMEOUT,
    },
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::{
        CreateFileW, GetFileInformationByHandle,
        BY_HANDLE_FILE_INFORMATION, DELETE, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY,
        FILE_APPEND_DATA, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_DELETE_CHILD, FILE_EXECUTE, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES,
        FILE_READ_DATA, FILE_READ_EA, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, FILE_TRAVERSE, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA,
        FILE_WRITE_EA, OPEN_EXISTING, READ_CONTROL, WRITE_DAC, WRITE_OWNER,
    },
    System::{
        JobObjects::{
            CreateJobObjectW, JobObjectBasicAccountingInformation,
            JobObjectExtendedLimitInformation, QueryInformationJobObject,
            SetInformationJobObject, TerminateJobObject,
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_JOB_MEMORY,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        },
        Pipes::{CreatePipe, PeekNamedPipe},
        Threading::{
            CreateProcessAsUserW, DeleteProcThreadAttributeList, GetExitCodeProcess,
            InitializeProcThreadAttributeList, QueryFullProcessImageNameW, ResumeThread,
            UpdateProcThreadAttribute, WaitForSingleObject,
            CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
            EXTENDED_STARTUPINFO_PRESENT, PROCESS_INFORMATION, STARTF_USESTDHANDLES,
            STARTUPINFOEXW,
        },
    },
};

const MAX_OUTPUT: usize = 64 * 1024;
const MAX_IMAGE: u64 = 512 * 1024 * 1024;
const MAX_PRIVATE: usize = 32;
const MAX_PATH: usize = 4096;
const MAX_PROCESSES: u32 = 8;
const JOB_MEMORY: usize = 512 * 1024 * 1024;
const ATTRIBUTE_HANDLE_LIST: usize = 0x0002_0002;
const ATTRIBUTE_JOB_LIST: usize = 0x0002_000d;
const HANDLE_FLAG_INHERIT: u32 = 1;
const SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
const MAX_DEADLINE: Duration = Duration::from_secs(30);
const MIN_DEADLINE: Duration = Duration::from_millis(250);

/// Trusted, locally pinned policy data; no command text or optional flags.
/// The catalogue and SQLite paths MUST refer to existing genuine files.
/// Additional private paths may be existing files or directories, including
/// private settings and credential stores. No data is read from them.
pub struct GitRevisionSpec<'a> {
    pub git_executable: &'a Path,
    pub expected_sha256: [u8; 32],
    pub workspace: &'a Path,
    pub operator_catalog_file: &'a Path,
    pub database_file: &'a Path,
    pub additional_private_paths: &'a [&'a Path],
    pub deadline: Duration,
}

#[derive(Debug)]
pub struct GitRevisionResult {
    pub exit_code: u32,
    pub stdout: String,
    pub stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

#[derive(Debug)]
pub enum GitRevisionError {
    /// Nothing has been started. The failed precondition must be resolved
    /// locally; the launcher will never weaken its token.
    Refused(&'static str),
    /// Process may have started or cleanup may be incomplete. No replay.
    Uncertain(&'static str),
    /// Deadline elapsed. The owned Job is terminated on return.
    Deadline,
    /// OS returned an actionable native error BEFORE process creation.
    Os { stage: &'static str, error: io::Error },
}
impl fmt::Display for GitRevisionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(s) => write!(f, "RESTRICTED_GIT_REFUSED: {s}"),
            Self::Uncertain(s) => write!(f, "RESTRICTED_GIT_UNCERTAIN: {s}; no automatic retry"),
            Self::Deadline => f.write_str("RESTRICTED_GIT_DEADLINE: job cleanup requested; command outcome uncertain"),
            Self::Os { stage, error } => write!(f, "RESTRICTED_GIT_OS_{stage}: {error}"),
        }
    }
}
impl std::error::Error for GitRevisionError {}
type Result<T> = std::result::Result<T, GitRevisionError>;

fn os(stage: &'static str, e: io::Error) -> GitRevisionError {
    GitRevisionError::Os { stage, error: e }
}
fn refused(message: &'static str) -> GitRevisionError { GitRevisionError::Refused(message) }
fn uncertain(message: &'static str) -> GitRevisionError { GitRevisionError::Uncertain(message) }

/// Win32 HANDLE owned by this module; closing the Job handle is independently
/// protected by JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.
struct Owned(HANDLE);
impl Owned {
    fn wrap(raw: HANDLE, stage: &'static str) -> Result<Self> {
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            Err(os(stage, io::Error::last_os_error()))
        } else {
            Ok(Self(raw))
        }
    }
    fn raw(&self) -> HANDLE { self.0 }
    fn into_file(mut self) -> fs::File {
        let raw = self.0;
        self.0 = ptr::null_mut();
        // SAFETY: this uniquely owned valid Win32 file/pipe handle is
        // transferred to std::fs::File; it will be closed exactly once.
        unsafe { fs::File::from_raw_handle(raw as RawHandle) }
    }
}
impl Drop for Owned {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(self.0); }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NativeIdentity { volume: u32, file_index: u64, links: u32, directory: bool }

fn identity(handle: HANDLE) -> Result<NativeIdentity> {
    let mut md: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
    if unsafe { GetFileInformationByHandle(handle, &mut md) } == 0 {
        return Err(os("FILE_IDENTITY", io::Error::last_os_error()));
    }
    if md.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(refused("A file handle resolved to a reparse point"));
    }
    let n = (u64::from(md.nFileIndexHigh) << 32) | u64::from(md.nFileIndexLow);
    if n == 0 || md.dwVolumeSerialNumber == 0 {
        return Err(refused("Filesystem does not expose a reliable file identity"));
    }
    Ok(NativeIdentity {
        volume: md.dwVolumeSerialNumber,
        file_index: n,
        links: md.nNumberOfLinks,
        directory: md.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0,
    })
}

fn wide(value: &OsStr) -> Result<Vec<u16>> {
    let mut buf: Vec<u16> = value.encode_wide().collect();
    if buf.is_empty() || buf.len() > 32760 || buf.contains(&0) {
        return Err(refused("Invalid Windows string"));
    }
    buf.push(0);
    Ok(buf)
}

fn normal_local(path: &Path, dir: bool) -> Result<PathBuf> {
    let raw = path.to_str().ok_or_else(|| refused("Non-Unicode path refused"))?;
    if raw.len() > MAX_PATH || !path.is_absolute() {
        return Err(refused("Executable, workspace and private paths must be absolute"));
    }
    let mut drive = false;
    let mut root = false;
    let mut count = 0;
    for part in path.components() {
        match part {
            Component::Prefix(p) => match p.kind() {
                Prefix::Disk(_) => drive = true,
                _ => return Err(refused("UNC, network, verbatim and device paths are refused")),
            },
            Component::RootDir => root = true,
            Component::Normal(s) => {
                let name = s.to_str().ok_or_else(|| refused("Invalid path component"))?;
                if name.is_empty() || name.ends_with('.') || name.ends_with(' ')
                    || name.contains(':') || name.chars().any(char::is_control) {
                    return Err(refused("Non-normal Windows path component refused"));
                }
                count += 1;
            }
            Component::CurDir | Component::ParentDir =>
                return Err(refused("Relative dot components are refused")),
        }
    }
    if !drive || !root || count == 0 { return Err(refused("Volume roots and relative paths are refused")); }
    if !dir && !path.is_file() {
        return Err(refused("Required policy file is absent or nonregular"));
    }
    // Require no reparse points from volume root down to the selected entry.
    for ancestor in path.ancestors() {
        let md = fs::symlink_metadata(ancestor).map_err(|e| os("PATH", e))?;
        if md.is_symlink() || md.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(refused("Symlink, junction or reparse ancestor refused"));
        }
        if ancestor != path && !md.is_dir() { return Err(refused("Non-directory ancestor refused")); }
    }
    let md = fs::symlink_metadata(path).map_err(|e| os("PATH",e))?;
    if (dir && !md.is_dir()) || (!dir && !md.is_file()) {
        return Err(refused("Unexpected policy file or directory type"));
    }
    let physical = fs::canonicalize(path).map_err(|e| os("CANONICAL",e))?;
    if !same_path(path, &physical)? {
        return Err(refused("Path differs from its physical identity"));
    }
    Ok(path.to_owned())
}

fn normalize_comparable(raw: &Path) -> Result<Vec<String>> {
    let t = raw.to_str().ok_or_else(|| refused("Non-Unicode path refused"))?;
    let normalized = t.replace('/', "\\");
    let value = normalized.strip_prefix(r"\\?\").unwrap_or(&normalized);
    let bytes = value.as_bytes();
    if bytes.len() < 3 || !bytes[0].is_ascii_alphabetic()
        || bytes[1] != b':' || bytes[2] != b'\\' {
        return Err(refused("Nonlocal resolved path refused"));
    }
    let mut v = vec![value[..2].to_owned()];
    v.extend(value[3..].trim_end_matches('\\').split('\\')
        .filter(|p| !p.is_empty()).map(str::to_owned));
    Ok(v)
}
fn ordinal_same(a: &str, b: &str) -> Result<bool> {
    #[link(name = "kernel32")]
    extern "system" {
        fn CompareStringOrdinal(a: *const u16, al: i32, b: *const u16, bl: i32, ignore: i32) -> i32;
    }
    let a: Vec<u16> = a.encode_utf16().collect();
    let b: Vec<u16> = b.encode_utf16().collect();
    if a.len() > i32::MAX as usize || b.len() > i32::MAX as usize {
        return Err(refused("Uncomparable Windows paths"));
    }
    // SAFETY: UTF-16 pointers are live for the entire Windows call.
    let result = unsafe {
        CompareStringOrdinal(a.as_ptr(), a.len() as i32, b.as_ptr(), b.len() as i32, 1)
    };
    if result == 0 { return Err(refused("Windows ordinal comparison unavailable")); }
    Ok(result == 2)
}
fn same_path(a: &Path, b: &Path) -> Result<bool> {
    let a = normalize_comparable(a)?;
    let b = normalize_comparable(b)?;
    Ok(a.len() == b.len() && a.iter().zip(&b).all(|(x,y)| ordinal_same(x,y).unwrap_or(false)))
}
fn overlap(a: &Path, b: &Path) -> Result<bool> {
    let a = normalize_comparable(a)?;
    let b = normalize_comparable(b)?;
    let min = a.len().min(b.len());
    for (x,y) in a.iter().zip(&b).take(min) {
        if !ordinal_same(x,y)? { return Ok(false); }
    }
    Ok(true)
}

fn open_path(path: &Path, rights: u32, directory: bool, sharing: u32) -> Result<Owned> {
    let path = wide(path.as_os_str())?;
    // SAFETY: the NUL-terminated UTF-16 buffer remains alive for CreateFileW;
    // OPEN_EXISTING guarantees these probes never create or modify a file.
    let raw = unsafe { CreateFileW(
        path.as_ptr(), rights, sharing, ptr::null(),
        OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT |
            if directory { FILE_FLAG_BACKUP_SEMANTICS } else { 0 },
        ptr::null_mut()
    ) };
    Owned::wrap(raw,"OPEN_HANDLE")
}

struct PrivateWitness { path: PathBuf, kind: PrivateKind, id: NativeIdentity }
#[derive(Clone, Copy)]
enum PrivateKind { File, Directory }

fn private_witness(path: &Path, required_file: bool) -> Result<PrivateWitness> {
    let dir = !required_file && fs::symlink_metadata(path)
        .map_err(|e| os("PRIVATE_PATH",e))?.is_dir();
    let path = normal_local(path,dir)?;
    let kind = if dir { PrivateKind::Directory } else { PrivateKind::File };
    // Sharing ALL is intentional: a share violation must NOT be confused with
    // an access denial during restricted-token probes.
    let handle = open_path(&path, FILE_READ_ATTRIBUTES, dir, SHARE_ALL)?;
    let id = identity(handle.raw())?;
    if id.directory != dir || (!dir && id.links != 1) {
        return Err(refused("Private object is not a single-link regular file or directory"));
    }
    Ok(PrivateWitness { path, kind, id })
}
fn verify_private_same(witness: &PrivateWitness) -> Result<()> {
    let now = private_witness(&witness.path, matches!(witness.kind, PrivateKind::File))?;
    if now.id != witness.id {
        return Err(refused("A private operator path changed during qualification"));
    }
    Ok(())
}
fn probe_open_win32(path: &Path, right: u32, dir: bool) -> io::Result<Option<NativeIdentity>> {
    let path = wide(path.as_os_str())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid probe path"))?;
    let raw = unsafe {
        CreateFileW(path.as_ptr(), right, SHARE_ALL, ptr::null(), OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT |
                if dir { FILE_FLAG_BACKUP_SEMANTICS } else { 0 },
            ptr::null_mut())
    };
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        let err = io::Error::last_os_error();
        return if err.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) {
            Ok(None)
        } else {
            Err(err)
        };
    }
    let handle = Owned(raw);
    let actual = identity(handle.raw())
        .map_err(|_| io::Error::other("restricted token opened an unidentifiable target"))?;
    Ok(Some(actual))
}
// Native exact-mask probe. CreateFileW can request extra access even
// when the caller supplies the narrow approved RD/X/RA mask. The native
// kernel check still runs under the same impersonated restricted token;
// neither positive nor negative qualification relies on theoretical DACLs.
// Inputs are already physically validated by normal_local and pinned by the
// caller. Reject ambiguous spellings again before entering the NT namespace.
#[repr(C)]
struct ProbeUnicodeString {length:u16,maximum_length:u16,buffer:*mut u16}
#[repr(C)]
struct ProbeObjectAttributes {length:u32,root:HANDLE,name:*mut ProbeUnicodeString,attributes:u32,security:*mut c_void,sqos:*mut c_void}
#[link(name="ntdll")]
extern "system" {
    fn NtOpenFile(file:*mut HANDLE,access:u32,attributes:*mut ProbeObjectAttributes,iosb:*mut usize,share:u32,options:u32)->i32;
    fn RtlNtStatusToDosError(status:i32)->u32;
}
fn exact_probe_name(path:&Path)->io::Result<Vec<u16>>{
    let invalid=||io::Error::new(io::ErrorKind::InvalidInput,"non-normal local restricted probe path");
    let text=path.to_str().ok_or_else(invalid)?.replace('/',"\\");
    let bytes=text.as_bytes();
    if bytes.len()<4||bytes.len()>MAX_PATH||!bytes[0].is_ascii_alphabetic()||bytes[1]!=b':'||bytes[2]!=b'\\' {
        return Err(invalid());
    }
    for part in text[3..].split('\\'){
        if part.is_empty()||matches!(part,"."|"..")||part.ends_with('.')||part.ends_with(' ')
            ||part.chars().any(|ch|ch.is_control()||"<>:\"|?*".contains(ch)){
            return Err(invalid());
        }
        let stem=part.split('.').next().unwrap_or("").to_ascii_uppercase();
        if matches!(stem.as_str(),"CON"|"PRN"|"AUX"|"NUL"|"CONIN$"|"CONOUT$")
            || ["COM","LPT"].into_iter().any(|prefix|stem.strip_prefix(prefix)
                .is_some_and(|tail|tail.chars().count()==1&&tail.chars().next().is_some_and(|ch|matches!(ch,'1'..='9'|'¹'|'²'|'³')))){
            return Err(invalid());
        }
    }
    Ok(format!(r"\??\{text}").encode_utf16().collect())
}
fn nt_probe_open(path:&Path,right:u32,dir:bool)->io::Result<Option<Owned>>{
    let mut units=exact_probe_name(path)?;
    let bytes=u16::try_from(units.len()*2).map_err(io::Error::other)?;
    let mut name=ProbeUnicodeString{length:bytes,maximum_length:bytes,buffer:units.as_mut_ptr()};
    let mut attrs=ProbeObjectAttributes{length:size_of::<ProbeObjectAttributes>() as u32,root:ptr::null_mut(),name:&mut name,
        // OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE. No inherited handles,
        // backup intent, alternate namespace, security descriptor or SQOS.
        attributes:0x40|0x1000,security:ptr::null_mut(),sqos:ptr::null_mut()};
    let mut handle=ptr::null_mut();let mut iosb=[0usize;2];
    let status=unsafe{NtOpenFile(&mut handle,right,&mut attrs,iosb.as_mut_ptr(),SHARE_ALL,
        0x00200000|if dir{1}else{0x40})};
    // Adopt any unexpectedly returned real handle before evaluating the
    // status. STATUS_ACCESS_DENIED alone is a negative proof.
    let owner=if handle.is_null()||handle==INVALID_HANDLE_VALUE{None}else{Some(Owned(handle))};
    if status==0{return owner.map(Some).ok_or_else(||io::Error::other("native probe returned no handle"));}
    if status as u32==0xc0000022 && owner.is_none(){return Ok(None);}
    drop(owner);
    Err(io::Error::other(format!("native probe unverified: NTSTATUS=0x{:08X}, Win32={}",
        status as u32,unsafe{RtlNtStatusToDosError(status)})))
}
fn probe_open(path:&Path,right:u32,dir:bool)->io::Result<Option<NativeIdentity>>{
    let Some(handle)=nt_probe_open(path,right,dir)? else{return Ok(None);};
    let actual=identity(handle.raw()).map_err(|_|io::Error::other("restricted token opened an unidentifiable target"))?;
    if actual.directory!=dir{return Err(io::Error::other("restricted path type mismatch"));}
    Ok(Some(actual))
}
fn assert_access(path: &Path, right: u32, dir: bool, id: NativeIdentity) -> io::Result<()> {
    let actual = probe_open(path,right,dir)?
        .ok_or_else(|| io::Error::from_raw_os_error(ERROR_ACCESS_DENIED as i32))?;
    if actual != id { return Err(io::Error::other("restricted path identity mismatch")); }
    Ok(())
}
fn assert_private_denied(target: &PrivateWitness) -> io::Result<()> {
    const FILE_RIGHTS: &[u32] = &[
        FILE_READ_DATA, FILE_READ_EA, FILE_READ_ATTRIBUTES, READ_CONTROL,
        FILE_WRITE_DATA, FILE_APPEND_DATA, FILE_WRITE_EA, FILE_WRITE_ATTRIBUTES,
        DELETE, WRITE_DAC, WRITE_OWNER,
    ];
    const DIR_RIGHTS: &[u32] = &[
        FILE_LIST_DIRECTORY, FILE_READ_EA, FILE_READ_ATTRIBUTES, READ_CONTROL,
        FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_DELETE_CHILD,
        FILE_WRITE_EA, FILE_WRITE_ATTRIBUTES, DELETE, WRITE_DAC, WRITE_OWNER,
    ];
    let dir = matches!(target.kind,PrivateKind::Directory);
    for right in if dir { DIR_RIGHTS } else { FILE_RIGHTS } {
        // A successful open (even an unidentifiable handle) is never a
        // denial. Preserve the old Win32 negative check as well: a private
        // path must be inaccessible through both access boundaries.
        if probe_open(&target.path,*right,dir)?.is_some()
            || probe_open_win32(&target.path,*right,dir)?.is_some() {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied,
                "restricted token can access an operator private object"));
        }
    }
    Ok(())
}

struct PinnedImage {
    _parent: PinnedProjectDirectory,
    path: PathBuf,
    file: fs::File,
    identity: NativeIdentity,
    sha256: [u8;32],
}
impl PinnedImage {
    fn open(path: &Path, expected_hash: [u8;32]) -> Result<Self> {
        Self::open_exact(path, expected_hash, true)
    }
    fn open_project(path: &Path, expected_hash: [u8;32]) -> Result<Self> {
        Self::open_exact(path, expected_hash, false)
    }
    fn open_exact(path: &Path, expected_hash: [u8;32], git_only: bool) -> Result<Self> {
        let path = normal_local(path,false)?;
        let filename=path.file_name().and_then(|n|n.to_str())
            .ok_or_else(||refused("Executable has no filename"))?;
        if git_only && !filename.eq_ignore_ascii_case("git.exe") {
            return Err(refused("Only a pinned git.exe is supported"));
        }
        if !git_only && !filename.to_ascii_lowercase().ends_with(".exe") {
            return Err(refused("Project program must be a direct .exe image"));
        }
        let parent = path.parent().ok_or_else(||refused("Missing Git executable directory"))?;
        let parent_guard = PinnedProjectDirectory::open(parent).map_err(|e|os("IMAGE_DIRECTORY",e))?;
        let mut options = fs::OpenOptions::new();
        options.read(true)
            // This handle is retained until process termination. It excludes
            // all new write and delete handles, preventing image substitution.
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        let file=options.open(&path).map_err(|e|os("GIT_PIN",e))?;
        let id = identity(file.as_raw_handle() as HANDLE)?;
        if id.directory || id.links != 1 { return Err(refused("Git binary must be a single-link regular image")); }
        let mut pin=Self {_parent:parent_guard,path,file,identity:id,sha256:expected_hash};
        pin.reverify()?;
        Ok(pin)
    }

    fn reverify(&mut self) -> Result<()> {
        let handle=self.file.as_raw_handle() as HANDLE;
        if identity(handle)? != self.identity {
            return Err(refused("Pinned Git image identity changed"));
        }
        let metadata=self.file.metadata().map_err(|e|os("GIT_METADATA",e))?;
        if !metadata.is_file() || metadata.len()>MAX_IMAGE {
            return Err(refused("Git image is not a bounded regular file"));
        }
        self.file.seek(SeekFrom::Start(0)).map_err(|e|os("GIT_SEEK",e))?;
        let mut digest=Sha256::new();
        let mut buffer=[0u8;64*1024];
        let mut count=0u64;
        loop {
            let n=self.file.read(&mut buffer).map_err(|e|os("GIT_READ",e))?;
            if n==0 {break;}
            count=count.checked_add(n as u64)
                .ok_or_else(||refused("Git image length overflow"))?;
            if count>MAX_IMAGE {return Err(refused("Git image too large"));}
            digest.update(&buffer[..n]);
        }
        let observed: [u8; 32] = digest.finalize().into();
        if count != metadata.len() || observed != self.sha256 {
            return Err(refused("Git image differs from the policy SHA-256 pin"));
        }
        let fresh=open_path(&self.path,FILE_READ_ATTRIBUTES,false,FILE_SHARE_READ)?;
        if identity(fresh.raw())? != self.identity {
            return Err(refused("Git path was replaced while pinned"));
        }
        Ok(())
    }
}

struct Attributes {
    _buffer: Vec<usize>,
    list: *mut c_void,
    handles: Box<[HANDLE;3]>,
    jobs: Box<[HANDLE;1]>,
}
impl Attributes {
    fn new(job:HANDLE, input:HANDLE, out:HANDLE, err:HANDLE) -> Result<Self> {
        let mut size=0usize;
        unsafe { InitializeProcThreadAttributeList(ptr::null_mut(),2,0,&mut size); }
        if size == 0 || size > 64*1024 {return Err(refused("Windows startup attributes unavailable"));}
        let words=(size+size_of::<usize>()-1)/size_of::<usize>();
        let mut buffer=vec![0usize;words];
        let list=buffer.as_mut_ptr().cast::<c_void>();
        if unsafe { InitializeProcThreadAttributeList(list,2,0,&mut size) } == 0 {
            return Err(os("ATTRIBUTE_INITIALIZE",io::Error::last_os_error()));
        }
        let attrs=Self {_buffer:buffer,list,handles:Box::new([input,out,err]),jobs:Box::new([job])};
        if unsafe { UpdateProcThreadAttribute(attrs.list,0,ATTRIBUTE_HANDLE_LIST,
            attrs.handles.as_ptr().cast(),size_of::<[HANDLE;3]>(),
            ptr::null_mut(),ptr::null()) } == 0 {
            return Err(os("ATTRIBUTE_HANDLE_LIST",io::Error::last_os_error()));
        }
        if unsafe { UpdateProcThreadAttribute(attrs.list,0,ATTRIBUTE_JOB_LIST,
            attrs.jobs.as_ptr().cast(),size_of::<HANDLE>(),
            ptr::null_mut(),ptr::null()) } == 0 {
            return Err(os("ATTRIBUTE_JOB_LIST",io::Error::last_os_error()));
        }
        Ok(attrs)
    }
}
impl Drop for Attributes {
    fn drop(&mut self) { unsafe { DeleteProcThreadAttributeList(self.list); } }
}

fn job_owner() -> Result<Owned> {
    let job=Owned::wrap(unsafe{CreateJobObjectW(ptr::null(),ptr::null())},"CREATE_JOB")?;
    let mut limit: JOBOBJECT_EXTENDED_LIMIT_INFORMATION=unsafe{zeroed()};
    limit.BasicLimitInformation.LimitFlags=
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS |
        JOB_OBJECT_LIMIT_JOB_MEMORY;
    limit.BasicLimitInformation.ActiveProcessLimit=MAX_PROCESSES;
    limit.JobMemoryLimit=JOB_MEMORY;
    if unsafe {SetInformationJobObject(job.raw(),JobObjectExtendedLimitInformation,
        (&limit as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
        size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32)} == 0 {
        return Err(os("JOB_LIMITS",io::Error::last_os_error()));
    }
    Ok(job)
}
fn active_job_processes(job: HANDLE) -> Result<u32> {
    let mut accounting: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION=unsafe{zeroed()};
    if unsafe {QueryInformationJobObject(job,JobObjectBasicAccountingInformation,
        (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
        size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
        ptr::null_mut())} == 0 {
        return Err(os("JOB_ACCOUNTING",io::Error::last_os_error()));
    }
    Ok(accounting.ActiveProcesses)
}
fn inherited_pipe() -> Result<(Owned,Owned)> {
    inherited_pipe_with_size(0)
}
fn inherited_pipe_with_size(size: u32) -> Result<(Owned,Owned)> {
    let sa=SECURITY_ATTRIBUTES {
        nLength:size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor:ptr::null_mut(),bInheritHandle:1,
    };
    let mut read=ptr::null_mut();
    let mut write=ptr::null_mut();
    if unsafe{CreatePipe(&mut read,&mut write,&sa,size)} == 0 {
        return Err(os("CREATE_PIPE",io::Error::last_os_error()));
    }
    let read=Owned::wrap(read,"PIPE_READ")?;
    let write=Owned::wrap(write,"PIPE_WRITE")?;
    if unsafe {SetHandleInformation(read.raw(),HANDLE_FLAG_INHERIT,0)} == 0 {
        return Err(os("PIPE_NONINHERIT",io::Error::last_os_error()));
    }
    Ok((read,write))
}
fn null_stdin() -> Result<Owned> {
    let sa=SECURITY_ATTRIBUTES {
        nLength:size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor:ptr::null_mut(),bInheritHandle:1,
    };
    let name=wide(OsStr::new("NUL"))?;
    let handle=unsafe {CreateFileW(name.as_ptr(),FILE_READ_DATA,
        FILE_SHARE_READ|FILE_SHARE_WRITE,&sa,OPEN_EXISTING,0,ptr::null_mut())};
    Owned::wrap(handle,"NULL_STDIN")
}
fn quote_image(path:&Path) -> Result<Vec<u16>> {
    // Full executable path is quoted as argv[0]. A Windows filename cannot
    // contain a double quote; no caller controls any argument after it.
    let name=path.to_str().ok_or_else(||refused("Non-Unicode executable"))?;
    if name.contains('"') || name.contains('\0') {
        return Err(refused("Invalid pinned image path"));
    }
    wide(OsStr::new(&format!(
        "\"{name}\" --no-pager rev-parse --verify HEAD"
    )))
}

/// Quote each UTF-16 argument as a literal Windows argv item for a single
/// pinned .exe via CreateProcessAsUserW, never cmd.exe or a shell language.
fn quote_windows_arg(raw: &str) -> Result<String> {
    if raw.contains('\0') || raw.chars().any(|c| c == '\r' || c == '\n') {
        return Err(refused("Project program argument contains a control character"));
    }
    let mut result = String::from("\"");
    let mut slashes=0usize;
    for ch in raw.chars() {
        match ch {
            '\\' => slashes+=1,
            '"' => {
                result.push_str(&"\\".repeat(slashes*2+1));
                result.push('"');
                slashes=0;
            }
            _ => {
                result.push_str(&"\\".repeat(slashes));
                slashes=0;
                result.push(ch);
            }
        }
    }
    result.push_str(&"\\".repeat(slashes*2));
    result.push('"');
    Ok(result)
}
fn quote_project_command(path:&Path, args:&[String]) -> Result<Vec<u16>> {
    if args.len()>64 || args.iter().any(|s| s.len()>4096) {
        return Err(refused("Project program argument count or size exceeds limit"));
    }
    let mut text=quote_windows_arg(
        path.to_str().ok_or_else(||refused("Non-Unicode project program"))?
    )?;
    for arg in args {
        text.push(' ');
        text.push_str(&quote_windows_arg(arg)?);
        if text.encode_utf16().count()>32700 {
            return Err(refused("Project program command line exceeds Windows limit"));
        }
    }
    wide(OsStr::new(&text))
}
fn minimal_project_environment() -> Result<Vec<u16>> {
    // No inherited environment, credentials, proxy configuration, user
    // profile, temp directory, PATH or project-specific secrets.
    let root=windows_root()?;
    let mut entries=[format!("SystemRoot={root}"),format!("WINDIR={root}")];
    entries.sort_by_key(|s|s.to_ascii_lowercase());
    let mut out=Vec::new();
    for pair in entries {
        out.extend(pair.encode_utf16());
        out.push(0);
    }
    out.push(0);
    Ok(out)
}
fn windows_root() -> Result<String> {
    #[link(name = "kernel32")]
    extern "system" {
        fn GetWindowsDirectoryW(buffer: *mut u16,length:u32)->u32;
    }
    let mut b=vec![0u16;32768];
    let len=unsafe{GetWindowsDirectoryW(b.as_mut_ptr(),b.len() as u32)} as usize;
    if len==0 || len>=b.len() {return Err(refused("Windows system root unavailable"));}
    OsString::from_wide(&b[..len]).into_string()
        .map_err(|_|refused("Non-Unicode Windows system root"))
}
/// Select the same repository while starting the Windows loader outside the
/// project. A linked worktree has a .git file; a bare repository is its own
/// Git directory. Other I/O errors must not select a different repository.
pub fn repository_directories(workspace: &Path) -> io::Result<(PathBuf, Option<&Path>)> {
    let dot_git = workspace.join(".git");
    match fs::symlink_metadata(&dot_git) {
        Ok(_) => Ok((dot_git, Some(workspace))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok((workspace.to_owned(), None)),
        Err(error) => Err(error),
    }
}

fn minimal_environment(workspace: &Path) -> Result<Vec<u16>> {
    let system_root=windows_root()?;
    let mut pairs=vec![
        format!("SystemRoot={system_root}"),
        format!("WINDIR={system_root}"),
        "GIT_CONFIG_NOSYSTEM=1".to_owned(),
        "GIT_CONFIG_GLOBAL=NUL".to_owned(),
        format!("GIT_CEILING_DIRECTORIES={}", workspace.parent().ok_or_else(||refused("Project has no parent directory"))?.display()),
        "GIT_TERMINAL_PROMPT=0".to_owned(),
        "GIT_NO_LAZY_FETCH=1".to_owned(),
        "GIT_NO_OPTIONAL_LOCKS=1".to_owned(),
    ];
    let (git_dir, tree) = repository_directories(workspace).map_err(|e| os("PROJECT_GIT_DIR", e))?;
    pairs.push(format!("GIT_DIR={}", git_dir.display()));
    if let Some(tree) = tree {
        pairs.push(format!("GIT_WORK_TREE={}", tree.display()));
    }
    pairs.sort_by_key(|s| s.to_ascii_lowercase());
    let mut out=Vec::new();
    for pair in pairs {
        out.extend(pair.encode_utf16());
        out.push(0);
    }
    out.push(0);
    Ok(out)
}
struct Child {
    job: Owned,
    process: Owned,
    thread: Owned,
}
impl Child {
    fn kill(&self) {
        unsafe { TerminateJobObject(self.job.raw(),1); }
    }
}
impl Drop for Child {
    fn drop(&mut self) {
        // Killing even on early errors guarantees no escaped child remains
        // from a suspended or partially initialized creation attempt.
        self.kill();
    }
}

struct PipeCapture {
    file: fs::File,
    bytes: Vec<u8>,
    truncated: bool,
    closed: bool,
}

impl PipeCapture {
    fn new(handle: Owned) -> Self {
        Self { file: handle.into_file(), bytes: Vec::new(), truncated: false, closed: false }
    }

    // This is the only reader. Never wait for EOF in a read or reader join:
    // a descendant or a duplicated writer must not extend the deadline.
    fn poll(&mut self) -> Result<bool> {
        if self.closed { return Ok(false); }
        let mut available = 0;
        let ok = unsafe { PeekNamedPipe(self.file.as_raw_handle().cast(), ptr::null_mut(), 0,
            ptr::null_mut(), &mut available, ptr::null_mut()) };
        if ok == 0 {
            let code = io::Error::last_os_error().raw_os_error().map(|v|v as u32);
            if matches!(code, Some(ERROR_BROKEN_PIPE | ERROR_PIPE_NOT_CONNECTED)) {
                self.closed = true;
                return Ok(false);
            }
            return Err(uncertain("Cannot inspect restricted Git output"));
        }
        if available == 0 { return Ok(false); }
        let mut buffer = [0u8; 8192];
        let size = buffer.len().min(available as usize);
        let count = self.file.read(&mut buffer[..size]).map_err(|_|uncertain("Cannot read restricted Git output"))?;
        if count == 0 { self.closed = true; return Ok(false); }
        let keep = count.min(MAX_OUTPUT - self.bytes.len());
        self.bytes.extend_from_slice(&buffer[..keep]);
        self.truncated |= keep < count;
        Ok(true)
    }
}

/// Prepare the exact process token and pin the image and directory before
/// asking the operator for consent. Dropping this value never starts Git.
pub struct PreparedGitRevision {
    _directory: PinnedProjectDirectory,
    workspace: PathBuf,
    image: PinnedImage,
    protected: Vec<PrivateWitness>,
    primary: PrimaryRestrictedToken,
    deadline: Duration,
    project_run: Option<ProjectRun>,
}
struct ProjectRun {
    args: Vec<String>,
    cwd: PathBuf,
    // Hold the exact qualified CWD directory HANDLE across human consent,
    // process creation and Job cleanup: a path cannot be swapped meanwhile.
    _cwd_guard: PinnedProjectDirectory,
}
/// A locally approved project executable, confined to the same restricted
/// primary token and kill-on-close Job as the pinned Git revision reader.
/// No shell, user environment, stdout redirection path, or private state.
pub struct ProjectCommandSpec<'a> {
    pub executable: &'a Path,
    pub expected_sha256: [u8;32],
    pub workspace: &'a Path,
    pub cwd: &'a Path,
    pub args: &'a [String],
    pub operator_catalog_file: &'a Path,
    pub database_file: &'a Path,
    pub additional_private_paths: &'a [&'a Path],
    pub deadline: Duration,
}
pub struct PreparedProjectCommand {
    inner: PreparedGitRevision,
}
pub type ProjectCommandResult = GitRevisionResult;

impl PreparedProjectCommand {
    pub fn run(self) -> Result<ProjectCommandResult> { self.inner.run() }
}

pub fn prepare_project_command(spec: &ProjectCommandSpec<'_>) -> Result<PreparedProjectCommand> {
    if spec.deadline < MIN_DEADLINE || spec.deadline > MAX_DEADLINE {
        return Err(refused("Project command deadline outside permitted range"));
    }
    if spec.additional_private_paths.len() > MAX_PRIVATE {
        return Err(refused("Too many private boundaries for project command"));
    }
    // The project tree, working directory and executable must be physically
    // qualified and linked to the operator-selected project, not aliases.
    let workspace = normal_local(spec.workspace,true)?;
    let cwd = normal_local(spec.cwd,true)?;
    if !overlap(&workspace, &cwd)? {
        return Err(refused("Project program cwd is outside the selected project"));
    }
    let _pinned_workspace = PinnedProjectDirectory::open(&workspace)
        .map_err(|e|os("PROJECT_WORKSPACE_PIN",e))?;
    let _pinned_cwd = PinnedProjectDirectory::open(&cwd)
        .map_err(|e|os("PROJECT_CWD_PIN",e))?;
    let image = PinnedImage::open_project(spec.executable, spec.expected_sha256)?;
    let parent = image.path.parent().ok_or_else(||refused("Missing project executable directory"))?;
    if !overlap(&workspace, parent)? {
        return Err(refused("Project executable is outside the selected workspace"));
    }
    let mut protected = vec![
        private_witness(spec.operator_catalog_file,true)?,
        private_witness(spec.database_file,true)?,
    ];
    for path in spec.additional_private_paths {
        protected.push(private_witness(path,false)?);
    }
    for item in &protected {
        // Private project subtrees (e.g. .git history) are permitted as
        // DENIED witnesses. Reject only a private witness that contains the
        // project, the executable or the selected CWD; never grant it access.
        if overlap(&item.path,&workspace)? || overlap(&item.path,&image.path)?
            || overlap(&item.path,&cwd)? {
            return Err(refused("Private Bridge state contains the project program"));
        }
    }
    // The low-integrity, restricted-code, project-SID primary token is
    // derived from the *pinned* root. Verify private paths are denied with it,
    // and verify the exact executable can be read and executed.
    let primary = workspace_access::primary_restricted_token(&_pinned_workspace)
        .map_err(|e|os("PROJECT_RESTRICTED_TOKEN",e))?;
    verify_access(&primary,&workspace,&image,&protected)?;
    Ok(PreparedProjectCommand {
        inner: PreparedGitRevision {
            _directory:_pinned_workspace,workspace,image,protected,primary,
            deadline:spec.deadline,
            project_run:Some(ProjectRun{
                args:spec.args.to_vec(),cwd,_cwd_guard:_pinned_cwd,
            }),
        },
    })
}

pub fn prepare_git_revision(spec: &GitRevisionSpec<'_>) -> Result<PreparedGitRevision> {
    if spec.deadline<MIN_DEADLINE || spec.deadline>MAX_DEADLINE {
        return Err(refused("Deadline must be between 250 milliseconds and 30 seconds"));
    }
    if spec.additional_private_paths.len()>MAX_PRIVATE {
        return Err(refused("Too many operator private paths"));
    }
    let workspace=normal_local(spec.workspace,true)?;
    let _pinned_workspace= PinnedProjectDirectory::open(&workspace)
        .map_err(|e|os("WORKSPACE_PIN",e))?;
    let image=PinnedImage::open(spec.git_executable,spec.expected_sha256)?;
    if overlap(&workspace,&image.path)? {
        return Err(refused("Git executable must not be within/above the agent workspace"));
    }
    let mut protected=vec![
        private_witness(spec.operator_catalog_file,true)?,
        private_witness(spec.database_file,true)?,
    ];
    for path in spec.additional_private_paths {
        protected.push(private_witness(path,false)?);
    }
    for item in &protected {
        if overlap(&workspace,&item.path)? || overlap(&image.path,&item.path)? {
            return Err(refused("Private paths must be disjoint from Git and the workspace"));
        }
    }

    // Derive the extra project-specific restricting SID from the SAME
    // physically pinned workspace. Never accept a SID or flag from a caller.
    // No ACL here (or in the operator setup) may grant to S-1-5-12.
    let primary:PrimaryRestrictedToken=workspace_access::primary_restricted_token(&_pinned_workspace)
        .map_err(|e|os("RESTRICTED_PRIMARY",e))?;
    verify_access(&primary, &workspace, &image, &protected)?;
    Ok(PreparedGitRevision { _directory: _pinned_workspace, workspace, image, protected, primary, deadline: spec.deadline, project_run:None })
}

// Keep actual path-open outcomes separate from token setup/revert failures
// and from physical identity failures. AccessCheck alone is never a substitute.
#[derive(Debug, PartialEq, Eq)]
enum TargetAccess {
    Matched,
    Denied,
    OpenError(i32),
    IdentityMismatch,
    Unverified,
}
fn classify_target(result:io::Result<Option<NativeIdentity>>,expected:NativeIdentity)->TargetAccess {
    match result {
        Ok(Some(actual)) if actual==expected=>TargetAccess::Matched,
        Ok(Some(_))=>TargetAccess::IdentityMismatch,
        Ok(None)=>TargetAccess::Denied,
        Err(error)=>match error.raw_os_error(){
            Some(code)=>TargetAccess::OpenError(code),
            None=>TargetAccess::Unverified,
        },
    }
}
fn require_target_access(protected_count:usize,project:TargetAccess,image:TargetAccess)->Result<()>{
    if project==TargetAccess::Matched&&image==TargetAccess::Matched{return Ok(());}
    // Keep the native code in the structured local diagnostic (an aggregate
    // is not itself a single Win32 error). Never include private paths.
    let describe=|outcome:&TargetAccess|match outcome {
        TargetAccess::Matched=>"matched".to_owned(),
        TargetAccess::Denied=>"open_win32=5".to_owned(),
        TargetAccess::OpenError(code)=>format!("open_win32={code}"),
        TargetAccess::IdentityMismatch=>"physical_identity_mismatch".to_owned(),
        TargetAccess::Unverified=>"physical_identity_or_probe_unverified".to_owned(),
    };
    Err(os("LOW_TOKEN_ACCESS",io::Error::new(io::ErrorKind::PermissionDenied,
        format!("private_objects_denied={protected_count}; project={}; executable={}",describe(&project),describe(&image)))))
}

#[cfg(test)]
mod access_result_tests {
    use super::*;
    #[test]
    fn private_boundary_rejects_an_actually_accessible_owned_file(){
        let root=std::env::temp_dir().join(format!("ab-native-probe-negative-control-{}-{}",
            std::process::id(),std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        fs::create_dir(&root).unwrap();
        struct Cleanup(PathBuf);
        impl Drop for Cleanup{fn drop(&mut self){fs::remove_dir_all(&self.0).unwrap();}}
        let _cleanup=Cleanup(root.clone());
        let file=root.join("witness.txt");
        fs::write(&file,b"synthetic negative control").unwrap();
        let witness=private_witness(&file,true).unwrap();
        let id=probe_open(&file,FILE_READ_DATA|FILE_READ_ATTRIBUTES,false).unwrap().unwrap();
        assert_eq!(id,witness.id);
        // Run with the ordinary test token. This proves the denial checker
        // cannot report success just because the object is a private witness.
        assert!(assert_private_denied(&witness).is_err());
        assert_eq!(fs::read(&file).unwrap(),b"synthetic negative control");
    }
    #[test]
    fn exact_native_probe_rejects_aliases_and_preserves_literal_path(){
        for bad in [r"relative",r"C:relative",r"\\server\share\file",r"\\?\C:\project\file",
            r"C:\project\..\file",r"C:\project\file:stream",r"C:\project\NUL.txt",
            r"C:\project\file.",r"C:\project\\file",r"C:\"] {
            assert!(exact_probe_name(Path::new(bad)).is_err(),"{bad}");
        }
        let exact=exact_probe_name(Path::new(r"C:/École/projet/program.exe")).unwrap();
        assert_eq!(String::from_utf16(&exact).unwrap(),r"\??\C:\École\projet\program.exe");
    }
    #[test]
    fn access_report_never_confuses_open_denial_or_wrong_identity_with_success(){
        let expected=NativeIdentity{volume:1,file_index:2,links:1,directory:false};
        let other=NativeIdentity{file_index:3,..expected};
        assert_eq!(classify_target(Ok(Some(expected)),expected),TargetAccess::Matched);
        assert_eq!(classify_target(Ok(None),expected),TargetAccess::Denied);
        assert_eq!(classify_target(Ok(Some(other)),expected),TargetAccess::IdentityMismatch);
        assert_eq!(classify_target(Err(io::Error::from_raw_os_error(32)),expected),TargetAccess::OpenError(32));
        assert_eq!(classify_target(Err(io::Error::other("unidentifiable")),expected),TargetAccess::Unverified);
        let error=require_target_access(2,TargetAccess::Denied,TargetAccess::IdentityMismatch).unwrap_err().to_string();
        assert!(error.contains("LOW_TOKEN_ACCESS")&&error.contains("project=open_win32=5")&&error.contains("executable=physical_identity_mismatch"),"{error}");
        assert!(require_target_access(2,TargetAccess::Matched,TargetAccess::Matched).is_ok());
        assert!(require_target_access(2,TargetAccess::Matched,TargetAccess::Unverified).is_err());
    }
}

fn verify_access(primary: &PrimaryRestrictedToken, workspace: &Path, image: &PinnedImage, protected: &[PrivateWitness]) -> Result<()> {
    // These initial unprivileged directory/file identities must be the
    // objects observed by the restricted token (not merely matching names).
    let workspace_handle=open_path(&workspace, FILE_READ_ATTRIBUTES,true,SHARE_ALL)?;
    let workspace_id=identity(workspace_handle.raw())?;
    if !workspace_id.directory {return Err(refused("Workspace is not a directory"));}
    let image_id=image.identity;
    let work=workspace.to_owned();
    let exe=image.path.clone();
    let probe_privates=protected.iter().map(|i| (i.path.clone(),i.kind,i.id))
        .collect::<Vec<_>>();
    workspace_access::probe_with_primary_token(primary,move || {
        let protected_count = probe_privates.len();
        for (path,kind,id) in probe_privates {
            if let Err(error)=assert_private_denied(&PrivateWitness{path,kind,id}) {
                return Ok(Err(os("LOW_TOKEN_PRIVATE_BOUNDARY",error)));
            }
        }
        let project=classify_target(probe_open(&work,FILE_LIST_DIRECTORY|FILE_TRAVERSE|FILE_READ_ATTRIBUTES,true),workspace_id);
        let image=classify_target(probe_open(&exe,FILE_READ_DATA|FILE_EXECUTE|FILE_READ_ATTRIBUTES,false),image_id);
        Ok(require_target_access(protected_count,project,image))
    }).map_err(|e|os("LOW_TOKEN_PROBE",e))??;

    for item in protected { verify_private_same(item)?; }
    Ok(())
}

impl PreparedGitRevision {
    /// Consume the prepared operation only after command-policy approval.
    pub fn run(self) -> Result<GitRevisionResult> {
        let Self { _directory, workspace, mut image, protected, primary, deadline, project_run } = self;
        let until = Instant::now() + deadline;
        verify_access(&primary, &workspace, &image, &protected)?;
        image.reverify()?;
        let job=job_owner()?;
        let (stdout_read,stdout_write)=inherited_pipe()?;
        let (stderr_read,stderr_write)=inherited_pipe()?;
        let stdin_null=null_stdin()?;
        let attr=Attributes::new(job.raw(),stdin_null.raw(),stdout_write.raw(),stderr_write.raw())?;
        let mut startup:STARTUPINFOEXW=unsafe{zeroed()};
        startup.StartupInfo.cb=size_of::<STARTUPINFOEXW>() as u32;
        startup.StartupInfo.dwFlags=STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput=stdin_null.raw();
        startup.StartupInfo.hStdOutput=stdout_write.raw();
        startup.StartupInfo.hStdError=stderr_write.raw();
        startup.lpAttributeList=attr.list;
        let image_path=wide(image.path.as_os_str())?;
        let (workdir, mut command_line, environment) = if let Some(project) = &project_run {
            (
                wide(project.cwd.as_os_str())?,
                quote_project_command(&image.path, &project.args)?,
                minimal_project_environment()?,
            )
        } else {
            let image_dir = image.path.parent().ok_or_else(|| refused("Missing Git image directory"))?;
            (
                wide(image_dir.as_os_str())?,
                quote_image(&image.path)?,
                minimal_environment(&workspace)?,
            )
        };
        for item in &protected {verify_private_same(item)?;}
        image.reverify()?;
        if Instant::now()>=until {return Err(refused("Deadline elapsed before process creation"));}

        let mut info:PROCESS_INFORMATION=unsafe{zeroed()};
        let flags=EXTENDED_STARTUPINFO_PRESENT|CREATE_SUSPENDED|
            CREATE_NO_WINDOW|CREATE_UNICODE_ENVIRONMENT;
        // SAFETY: token is a verified primary, Low IL, restricted-code token
        // derived from this non-elevated process. STARTUPINFOEX has a valid
        // initialized 2-entry attribute list and THREE fixed inherited stdio
        // handles; JOB_LIST assigns the child atomically during creation.
        // Absolute executable is passed via lpApplicationName. No alternate
        // process creation API or unrestricted retry exists.
        let started=unsafe{CreateProcessAsUserW(
            primary.raw(),image_path.as_ptr(),command_line.as_mut_ptr(),
            ptr::null(),ptr::null(),1,flags,
            environment.as_ptr().cast(),workdir.as_ptr(),
            &startup.StartupInfo,&mut info)};
        if started==0 {
            return Err(os("CREATE_RESTRICTED_PROCESS",io::Error::last_os_error()));
        }
        let child=Child {
            job,
            process:Owned::wrap(info.hProcess,"CHILD_PROCESS").map_err(|_|uncertain("Created Git process handle missing"))?,
            thread:Owned::wrap(info.hThread,"CHILD_THREAD").map_err(|_|uncertain("Created Git thread handle missing"))?,
        };
        // Parent must close all three inherited-only handle copies; child retains
        // its own handles obtained at process creation.
        drop(attr);
        drop(stdin_null);
        drop(stdout_write);
        drop(stderr_write);

        // While the initial thread is still suspended, attest its actual image
        // path and verify the pinned original file by HANDLE plus SHA-256.
        let mut actual=vec![0u16;32768];
        let mut length=actual.len() as u32;
        if unsafe{QueryFullProcessImageNameW(child.process.raw(),0,actual.as_mut_ptr(),&mut length)}==0
            || length==0 || length as usize>actual.len() {
            return Err(uncertain("Cannot attest suspended Git image"));
        }
        let mapped=PathBuf::from(OsString::from_wide(&actual[..length as usize]));
        if !same_path(&mapped,&image.path).map_err(|_|uncertain("Cannot compare suspended image path"))? {
            return Err(uncertain("Suspended image path differs from pinned Git"));
        }
        image.reverify().map_err(|_|uncertain("Pinned Git changed before first instruction"))?;
        for item in &protected {
            verify_private_same(item).map_err(|_|uncertain("Private path changed before first instruction"))?;
        }
        if Instant::now()>=until {return Err(GitRevisionError::Deadline);}
        if unsafe{ResumeThread(child.thread.raw())}==u32::MAX {
            return Err(uncertain("Failed to resume restricted suspended process"));
        }
        let mut stdout = PipeCapture::new(stdout_read);
        let mut stderr = PipeCapture::new(stderr_read);
        loop {
            if Instant::now() >= until { return Err(GitRevisionError::Deadline); }
            let read_out = stdout.poll()?;
            let read_err = stderr.poll()?;
            let wait = unsafe { WaitForSingleObject(child.process.raw(), 0) };
            if wait != WAIT_OBJECT_0 && wait != WAIT_TIMEOUT {
                return Err(uncertain("Cannot query restricted Git process"));
            }
            if wait == WAIT_OBJECT_0 && stdout.closed && stderr.closed &&
                active_job_processes(child.job.raw()).map_err(|_|uncertain("Job accounting unavailable"))? == 0 {
                break;
            }
            if !read_out && !read_err { thread::sleep(Duration::from_millis(10)); }
        }
        let mut exit=0u32;
        if unsafe{GetExitCodeProcess(child.process.raw(),&mut exit)}==0 {
            return Err(uncertain("Restricted Git exit code unavailable"));
        }
        Ok(GitRevisionResult {
            exit_code:exit,
            stdout:String::from_utf8_lossy(&stdout.bytes).into_owned(),
            stderr:String::from_utf8_lossy(&stderr.bytes).into_owned(),
            stdout_truncated:stdout.truncated,
            stderr_truncated:stderr.truncated,
        })
    }
}
#[cfg(all(test, feature = "low-il-specimen"))]
mod restricted_access_diagnostics {
    use super::*;
    // The known, previously approved project specimen is used only for
    // metadata and handle-open checks. No executable or shell is started.
    /// Requires explicit local specimen; read-only restricted-token probe.
    #[test]
    fn exact_project_token_access_matrix() {
        let executable=PathBuf::from(std::env::var_os("AB_LOW_IL_SPECIMEN").expect("exact local specimen"));
        let root=executable.parent().unwrap().to_owned();
        let pinned=PinnedProjectDirectory::open(&root).unwrap();
        let sid=workspace_access::project_read_sid(&root).unwrap();
        let expected=std::env::var("AB_LOW_IL_EXPECTED_SID").expect("previously approved project SID");
        assert_eq!(sid,expected,"physical workspace identity changed; do not change ACLs");
        let primary=workspace_access::primary_restricted_token(&pinned).unwrap();
        let mut probes=Vec::new();
        // Ancestors: traverse/attributes only; never list their contents.
        for (depth,path) in root.ancestors().take(16).enumerate() {
            probes.push((format!("directory_depth_{depth}_traverse"),path.to_owned(),FILE_TRAVERSE,true));
            probes.push((format!("directory_depth_{depth}_attributes"),path.to_owned(),FILE_READ_ATTRIBUTES,true));
        }
        probes.push(("project_exact_RD_X_RA".into(),root.clone(),FILE_LIST_DIRECTORY|FILE_TRAVERSE|FILE_READ_ATTRIBUTES,true));
        probes.push(("image_exact_RD_X_RA".into(),executable.clone(),FILE_READ_DATA|FILE_EXECUTE|FILE_READ_ATTRIBUTES,false));
        probes.push(("image_zero_access".into(),executable,0,false));
        let observations=workspace_access::probe_with_primary_token(&primary,move||{
            let mut result=Vec::new();
            for (label,path,rights,directory) in probes {
                // Inspect CreateFileW's immediate result, not an error
                // transformed by the later physical-identity check.
                let units=wide(path.as_os_str()).map_err(io::Error::other)?;
                let handle=unsafe{CreateFileW(units.as_ptr(),rights,SHARE_ALL,ptr::null(),OPEN_EXISTING,
                    FILE_FLAG_OPEN_REPARSE_POINT|if directory{FILE_FLAG_BACKUP_SEMANTICS}else{0},ptr::null_mut())};
                if handle.is_null()||handle==INVALID_HANDLE_VALUE {
                    result.push((label,io::Error::last_os_error().raw_os_error(),false));
                } else {
                    let handle=Owned(handle);
                    let verified=identity(handle.raw()).is_ok_and(|actual|actual.directory==directory);
                    result.push((label,None,verified));
                }
            }
            Ok(result)
        }).unwrap();
        println!("LOW_IL_PROJECT_SID_MATCH=true; primary_token_created=true; no ACL changes or process launch");
        for (name,win32,identity) in observations {
            println!("LOW_IL_ACCESS {name} win32={win32:?} identifiable_handle={identity}");
        }
    }
}

#[cfg(all(test, feature = "low-il-specimen"))]
mod restricted_access_layers {
    use super::*;
    use windows_sys::Win32::{
        Foundation::{LocalFree,LUID},
        Security::{AccessCheck,DuplicateTokenEx,GetTokenInformation,LookupPrivilegeValueW,
            SecurityImpersonation,TokenImpersonation,TokenPrivileges,TOKEN_QUERY,
            TOKEN_PRIVILEGES,LUID_AND_ATTRIBUTES,SE_PRIVILEGE_ENABLED,GENERIC_MAPPING,
            OWNER_SECURITY_INFORMATION,GROUP_SECURITY_INFORMATION,DACL_SECURITY_INFORMATION},
        Security::Authorization::{GetSecurityInfo,SE_FILE_OBJECT},
        Storage::FileSystem::FILE_FLAG_OVERLAPPED,
    };
    const SYNC:u32=0x00100000;
    struct Descriptor(*mut c_void);
    impl Drop for Descriptor {fn drop(&mut self){unsafe{LocalFree(self.0);}}}
    fn sd(handle:HANDLE)->io::Result<Descriptor>{
        let mut value=ptr::null_mut();
        let code=unsafe{GetSecurityInfo(handle,SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION|GROUP_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,
            ptr::null_mut(),ptr::null_mut(),ptr::null_mut(),ptr::null_mut(),&mut value)};
        if code!=0{return Err(io::Error::from_raw_os_error(code as i32));}
        if value.is_null(){return Err(io::Error::other("descriptor absent"));}
        Ok(Descriptor(value))
    }
    fn check(sd:&Descriptor, token:HANDLE, rights:u32)->io::Result<bool>{
        let mapping=GENERIC_MAPPING{GenericRead:0x120089,GenericWrite:0x120116,GenericExecute:0x1200a0,GenericAll:0x1f01ff};
        let mut buf=[0usize;256];
        let mut len=size_of_val(&buf) as u32;let mut granted=0;let mut status=0;
        if unsafe{AccessCheck(sd.0,token,rights,&mapping,buf.as_mut_ptr().cast(),&mut len,&mut granted,&mut status)}==0 {
            return Err(io::Error::last_os_error());
        }
        Ok(status!=0&&granted&rights==rights)
    }
    fn traverse_privilege(token:HANDLE)->io::Result<Option<bool>>{
        let name=wide(OsStr::new("SeChangeNotifyPrivilege")).map_err(io::Error::other)?;
        let mut luid=LUID::default();
        if unsafe{LookupPrivilegeValueW(ptr::null(),name.as_ptr(),&mut luid)}==0{return Err(io::Error::last_os_error());}
        let mut needed=0u32;
        unsafe{GetTokenInformation(token,TokenPrivileges,ptr::null_mut(),0,&mut needed);}
        let offset=std::mem::offset_of!(TOKEN_PRIVILEGES,Privileges);
        if (needed as usize)<offset||needed>65536{return Err(io::Error::other("token privileges length"));}
        let mut buf=vec![0usize;(needed as usize).div_ceil(size_of::<usize>())];
        let mut read=0u32;
        if unsafe{GetTokenInformation(token,TokenPrivileges,buf.as_mut_ptr().cast(),needed,&mut read)}==0{return Err(io::Error::last_os_error());}
        if read>needed||(read as usize)<offset{return Err(io::Error::other("token privileges invalid"));}
        let count=unsafe{*buf.as_ptr().cast::<u32>()} as usize;
        if count.checked_mul(size_of::<LUID_AND_ATTRIBUTES>()).and_then(|n|n.checked_add(offset)).is_none_or(|n|n>read as usize){return Err(io::Error::other("token privileges invalid"));}
        let groups=unsafe{std::slice::from_raw_parts(buf.as_ptr().cast::<u8>().add(offset).cast::<LUID_AND_ATTRIBUTES>(),count)};
        Ok(groups.iter().find(|x|x.Luid.HighPart==luid.HighPart&&x.Luid.LowPart==luid.LowPart)
            .map(|x|x.Attributes&SE_PRIVILEGE_ENABLED!=0))
    }
    fn attempt(path:&Path,rights:u32,dir:bool,overlapped:bool,expected:NativeIdentity)->(Option<i32>,bool){
        let units=wide(path.as_os_str()).unwrap();
        let raw=unsafe{CreateFileW(units.as_ptr(),rights,SHARE_ALL,ptr::null(),OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT|if dir{FILE_FLAG_BACKUP_SEMANTICS}else{0}|
            if overlapped{FILE_FLAG_OVERLAPPED}else{0},ptr::null_mut())};
        if raw.is_null()||raw==INVALID_HANDLE_VALUE{return (io::Error::last_os_error().raw_os_error(),false);}
        let h=Owned(raw);(None,identity(h.raw()).is_ok_and(|id|id==expected))
    }
    // Read-only diagnostic against the already approved exact two objects.
    // Direct NT open is NOT a product fallback and requests no additional
    // access, inheritance, backup/restore privilege, or alternate path.
    fn nt_attempt(path:&Path,rights:u32,dir:bool,expected:NativeIdentity)->(u32,u32,bool){
        // Same ordinary DOS spelling, represented in the NT DOS namespace.
        let mut name=OsString::from(r"\??\");name.push(path.as_os_str());
        let mut units=name.encode_wide().collect::<Vec<_>>();
        let bytes=u16::try_from(units.len()*2).unwrap();
        let mut name=ProbeUnicodeString{length:bytes,maximum_length:bytes,buffer:units.as_mut_ptr()};
        let mut attrs=ProbeObjectAttributes{length:size_of::<ProbeObjectAttributes>() as u32,root:ptr::null_mut(),name:&mut name,
            attributes:0x40,security:ptr::null_mut(),sqos:ptr::null_mut()};
        let mut handle=ptr::null_mut();let mut status_block=[0usize;2];
        let status=unsafe{NtOpenFile(&mut handle,rights,&mut attrs,status_block.as_mut_ptr(),SHARE_ALL,
            0x00200000|if dir{1}else{0x40})};
        if status<0{return (status as u32,unsafe{RtlNtStatusToDosError(status)},false);}
        assert!(!handle.is_null()&&handle!=INVALID_HANDLE_VALUE);
        let handle=Owned(handle);
        (status as u32,0,identity(handle.raw()).is_ok_and(|actual|actual==expected))
    }
    fn token_stats(token:HANDLE)->io::Result<windows_sys::Win32::Security::TOKEN_STATISTICS>{
        use windows_sys::Win32::Security::{TokenStatistics,TOKEN_STATISTICS};
        let mut stats=TOKEN_STATISTICS::default();let mut read=0;
        if unsafe{GetTokenInformation(token,TokenStatistics,(&mut stats as *mut TOKEN_STATISTICS).cast(),size_of::<TOKEN_STATISTICS>() as u32,&mut read)}==0{
            return Err(io::Error::last_os_error());
        }
        Ok(stats)
    }
    fn label_flags(handle:HANDLE)->io::Result<Vec<(u32,u32)>>{
        use windows_sys::Win32::Security::{GetAce,GetSecurityDescriptorSacl,GetSidSubAuthority,GetSidSubAuthorityCount,IsValidSid,LABEL_SECURITY_INFORMATION, SYSTEM_MANDATORY_LABEL_ACE};
        let mut descriptor=ptr::null_mut();
        let code=unsafe{GetSecurityInfo(handle,SE_FILE_OBJECT,LABEL_SECURITY_INFORMATION,
            ptr::null_mut(),ptr::null_mut(),ptr::null_mut(),ptr::null_mut(),&mut descriptor)};
        if code!=0{return Err(io::Error::from_raw_os_error(code as i32));}
        if descriptor.is_null(){return Err(io::Error::other("mandatory label descriptor absent"));}
        let descriptor=Descriptor(descriptor);
        let mut present=0;let mut defaulted=0;let mut acl=ptr::null_mut();
        if unsafe{GetSecurityDescriptorSacl(descriptor.0,&mut present,&mut acl,&mut defaulted)}==0{return Err(io::Error::last_os_error());}
        if present==0||acl.is_null(){return Ok(vec![]);}
        let count=unsafe{(*acl).AceCount} as u32;
        if count>256{return Err(io::Error::other("mandatory label count bound"));}
        let mut labels=Vec::new();
        for i in 0..count {
            let mut ace=ptr::null_mut();
            if unsafe{GetAce(acl,i,&mut ace)}==0||ace.is_null(){return Err(io::Error::last_os_error());}
            let header=unsafe{&*ace.cast::<windows_sys::Win32::Security::ACE_HEADER>()};
            if header.AceType!=0x11{continue;}
            if (header.AceSize as usize)<size_of::<SYSTEM_MANDATORY_LABEL_ACE>(){return Err(io::Error::other("short label ACE"));}
            let item=unsafe{&*ace.cast::<SYSTEM_MANDATORY_LABEL_ACE>()};
            let sid=std::ptr::addr_of!(item.SidStart).cast_mut().cast();
            if unsafe{IsValidSid(sid)}==0{return Err(io::Error::other("invalid mandatory SID"));}
            let n=unsafe{*GetSidSubAuthorityCount(sid)} as u32;
            if n==0{return Err(io::Error::other("empty mandatory SID"));}
            labels.push((unsafe{*GetSidSubAuthority(sid,n-1)},item.Mask));
        }
        Ok(labels)
    }
    /// Requires exact approved local specimen; read-only native open and token metadata.
    #[test]
    fn exact_low_il_kernel_open_diagnostic(){
        use windows_sys::Win32::{Security::{IsTokenRestricted,TokenMandatoryPolicy,TOKEN_MANDATORY_POLICY},System::Threading::{GetCurrentThread,OpenThreadToken}};
        let exe=PathBuf::from(std::env::var_os("AB_LOW_IL_SPECIMEN").expect("exact local specimen"));
        let root=exe.parent().unwrap().to_owned();
        let pinned=PinnedProjectDirectory::open(&root).unwrap();
        assert_eq!(workspace_access::project_read_sid(&root).unwrap(),std::env::var("AB_LOW_IL_EXPECTED_SID").unwrap());
        let expected_hash=std::env::var("AB_LOW_IL_SHA256").unwrap();
        assert!(fs::metadata(&exe).unwrap().len()<=MAX_IMAGE);
        assert_eq!(hex::encode(Sha256::digest(fs::read(&exe).unwrap())),expected_hash);
        let primary=workspace_access::primary_restricted_token(&pinned).unwrap();
        let primary_stats=token_stats(primary.raw()).unwrap();
        let auth=(primary_stats.AuthenticationId.HighPart,primary_stats.AuthenticationId.LowPart);
        let mut cases=Vec::new();
        let mut handles=Vec::new();
        for (name,path,dir,rights) in [("project",root.clone(),true,FILE_LIST_DIRECTORY|FILE_TRAVERSE|FILE_READ_ATTRIBUTES),
            ("image",exe.clone(),false,FILE_READ_DATA|FILE_EXECUTE|FILE_READ_ATTRIBUTES)]{
            let handle=open_path(&path,READ_CONTROL|FILE_READ_ATTRIBUTES,dir,SHARE_ALL).unwrap();
            let id=identity(handle.raw()).unwrap();
            let labels=label_flags(handle.raw()).map_err(|error|error.to_string());
            println!("LOW_IL_KERNEL {name} mandatory_labels_rid_mask={labels:?}");
            let result=nt_attempt(&path,rights,dir,id);
            assert_eq!(result,(0,0,true),"normal-token native control");
            println!("LOW_IL_KERNEL {name} ordinary_nt_open={result:?}");
            cases.push((name,path,dir,rights,id));
            handles.push(handle);
        }
        let observed=workspace_access::probe_with_primary_token(&primary,move||{
            let mut raw=ptr::null_mut();
            let opened=unsafe{OpenThreadToken(GetCurrentThread(),TOKEN_QUERY,1,&mut raw)};
            let query=if opened==0 {
                println!("LOW_IL_KERNEL OpenThreadToken failed win32={:?}",io::Error::last_os_error().raw_os_error());
                None
            } else {Some(Owned(raw))};
            // A documented thread-token pseudo handle is a read-only
            // metadata alternative; it is not an impersonation or launch.
            let token=query.as_ref().map_or((-5isize) as HANDLE,|handle|handle.raw());
            match token_stats(token) {
                Ok(stats)=>{
                    assert_eq!((stats.AuthenticationId.HighPart,stats.AuthenticationId.LowPart),auth);
                    assert_eq!(stats.TokenType,TokenImpersonation);
                    assert_eq!(stats.ImpersonationLevel,SecurityImpersonation);
                    assert_ne!(unsafe{IsTokenRestricted(token)},0);
                    println!("LOW_IL_KERNEL effective_thread_token=restricted_impersonation; same_logon=true");
                },
                Err(error)=>println!("LOW_IL_KERNEL effective_thread_token_metadata_unavailable win32={:?}",error.raw_os_error()),
            }
            let mut policy=TOKEN_MANDATORY_POLICY::default();let mut read=0;
            if unsafe{GetTokenInformation(token,TokenMandatoryPolicy,(&mut policy as *mut TOKEN_MANDATORY_POLICY).cast(),
                size_of::<TOKEN_MANDATORY_POLICY>() as u32,&mut read)}==0{
                println!("LOW_IL_KERNEL mandatory_policy_unavailable win32={:?}",io::Error::last_os_error().raw_os_error());
            }else{println!("LOW_IL_KERNEL mandatory_policy={}",policy.Policy);}
            println!("LOW_IL_KERNEL traverse_privilege={:?}",traverse_privilege(token).map_err(|e|e.raw_os_error()));
            Ok(cases.into_iter().map(|(name,path,dir,rights,id)|{
                let win32=attempt(&path,rights,dir,true,id);
                let nt=nt_attempt(&path,rights,dir,id);
                (name,win32,nt)
            }).collect::<Vec<_>>())
        }).unwrap();
        for (name,win32,nt) in observed {println!("LOW_IL_KERNEL {name} restricted_win32={win32:?} restricted_nt_open=(0x{:08X},dos={},identity={})",nt.0,nt.1,nt.2);}
        assert_eq!(workspace_access::project_read_sid(&root).unwrap(),std::env::var("AB_LOW_IL_EXPECTED_SID").unwrap());
        assert_eq!(hex::encode(Sha256::digest(fs::read(&exe).unwrap())),expected_hash);
        drop(handles);
        println!("LOW_IL_KERNEL diagnostic_only=true ACL_modified=false child_started=false identity_rechecked=true");
    }

    /// Requires explicit approved local specimen; metadata/DACL and token queries only.
    #[test]
    fn exact_low_il_access_layers(){
        let exe=PathBuf::from(std::env::var_os("AB_LOW_IL_SPECIMEN").expect("explicit specimen"));
        let root=exe.parent().unwrap().to_owned();
        let pinned=PinnedProjectDirectory::open(&root).unwrap();
        let expected=std::env::var("AB_LOW_IL_EXPECTED_SID").expect("approved SID");
        assert_eq!(workspace_access::project_read_sid(&root).unwrap(),expected);
        let expected_hash=std::env::var("AB_LOW_IL_SHA256").expect("approved image hash");
        let hash=hex::encode(Sha256::digest(fs::read(&exe).unwrap()));
        assert_eq!(hash,expected_hash);
        let primary=workspace_access::primary_restricted_token(&pinned).unwrap();
        let mut duplicate=ptr::null_mut();
        assert_ne!(unsafe{DuplicateTokenEx(primary.raw(),TOKEN_QUERY,ptr::null(),SecurityImpersonation,TokenImpersonation,&mut duplicate)},0);
        let duplicate=Owned::wrap(duplicate,"TEST_TOKEN").unwrap();
        println!("LOW_IL_LAYERS traverse_privilege_primary={:?} duplicate={:?}",traverse_privilege(primary.raw()).unwrap(),traverse_privilege(duplicate.raw()).unwrap());
        let mut cases=Vec::new();
        for (label,path,dir,mask) in [("project",root.clone(),true,FILE_LIST_DIRECTORY|FILE_TRAVERSE|FILE_READ_ATTRIBUTES),
            ("image",exe.clone(),false,FILE_READ_DATA|FILE_EXECUTE|FILE_READ_ATTRIBUTES),
            ("parent",root.parent().unwrap().to_owned(),true,FILE_TRAVERSE)] {
            let owner=open_path(&path,READ_CONTROL|FILE_READ_ATTRIBUTES,dir,SHARE_ALL).unwrap();
            let physical=identity(owner.raw()).unwrap();
            let descriptor=sd(owner.raw()).unwrap();
            println!("LOW_IL_LAYERS {label} dacl_exact={:?} dacl_with_sync={:?} dacl_sync={:?}",
                check(&descriptor,duplicate.raw(),mask),check(&descriptor,duplicate.raw(),mask|SYNC),check(&descriptor,duplicate.raw(),SYNC));
            for (mode,rights,overlapped) in [("exact_sync",mask,false),("exact_overlapped",mask,true),
                ("explicit_sync",mask|SYNC,true),("zero_overlapped",0,true)] {
                println!("LOW_IL_LAYERS {label} {mode} owner_open={:?}",attempt(&path,rights,dir,overlapped,physical));
                cases.push((label,mode,path.clone(),dir,rights,overlapped,physical));
            }
        }
        let results=workspace_access::probe_with_primary_token(&primary,move||{
            Ok(cases.into_iter().map(|(label,mode,path,dir,rights,overlapped,physical)|
                (label,mode,attempt(&path,rights,dir,overlapped,physical))).collect::<Vec<_>>())
        }).unwrap();
        for (label,mode,result) in results {println!("LOW_IL_LAYERS {label} {mode} restricted_open={result:?}");}
        assert_eq!(workspace_access::project_read_sid(&root).unwrap(),expected);
        assert_eq!(hex::encode(Sha256::digest(fs::read(&exe).unwrap())),expected_hash);
        println!("LOW_IL_LAYERS diagnostic_only=true ACL_modified=false child_started=false identity_rechecked=true");
    }
}
