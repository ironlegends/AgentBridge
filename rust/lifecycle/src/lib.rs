// Copyright 2026 Agent Bridge contributors. Apache-2.0.
//! Portable, fail-closed lifecycle for ONE incarnation of the current Rust executable.
//!
//! Integration (the CLI is deliberately NOT changed by this crate):
//!
//! 1. At the very beginning of main, call parse_host_invocation(args_os).
//!    When it returns Some(invocation), call serve_host(invocation, runtime) and
//!    exit the executable immediately on return. Never resume the normal CLI.
//! 2. For explicit operator start, call launch(LaunchOptions { state_dir,
//!    host_args, timeout }). Each host argument is a separate OsString, never
//!    an interpolated shell command. The only executable spawned is current_exe.
//! 3. For explicit operator stop, call stop(StopOptions { state_dir, timeout }).
//!    Do not repeat this call after an Uncertain outcome. The owner must
//!    reconcile that session out of band; this crate deliberately has no
//!    force-kill, automatic recovery, replay or PID-only cleanup API.
//!
//! HostRuntime::start must return only after it has bound the actual service.
//! approve_stop is a read-only admission decision and must refuse active work.
//! cooperative_stop must close admission, drain all owned actions and release
//! the service before it returns. It is called ONCE, after an approved intent
//! has been durably recorded. Caller must make serve_host the last action of
//! its host code path so that exit follows completion.
//!
//! Session state is separate from historic Agent Bridge / portable-v2 captures:
//! no external ports, vendor processes, DBs or old session files are adopted.
//! A private local state directory is an explicit caller-supplied capability.

mod platform;
pub mod workspace_access;
#[cfg(unix)]
pub mod unix_project_handle;
#[cfg(windows)]
pub mod git_revision_windows;

use fs2::FileExt;
use hmac::{Hmac, Mac};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    ffi::{OsStr, OsString},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

type HmacSha256 = Hmac<Sha256>;
const FORMAT: u32 = 1;
const MAX_MARKER_BYTES: u64 = 8192;
const POLL: Duration = Duration::from_millis(80);
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(45);

#[derive(Debug, thiserror::Error)]
pub enum LifecycleError {
    #[error("invalid lifecycle configuration: {0}")]
    Invalid(&'static str),
    #[error("another lifecycle operation or host is busy")]
    Busy,
    #[error("lifecycle identity or result is uncertain: {0}")]
    Uncertain(&'static str),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
pub type Result<T> = std::result::Result<T, LifecycleError>;

/// Private, explicit directory outside any production capture. It must either
/// not exist (launch creates it privately) or pass platform-specific checks.
#[derive(Debug, Clone)]
pub struct LaunchOptions {
    pub state_dir: PathBuf,
    /// Arguments delivered only to HostRuntime::start, after the fixed "--".
    pub host_args: Vec<OsString>,
    /// Time to wait for the actual host-ready receipt; 50ms..180s.
    pub timeout: Duration,
}
#[derive(Debug, Clone)]
pub struct StopOptions {
    pub state_dir: PathBuf,
    /// Total wait for admission, cooperative completion and process exit.
    pub timeout: Duration,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchedSession {
    pub id: String, // public attempt identifier; NOT an authorization token
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopOutcome {
    Stopped,
    Busy,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopApproval {
    Approved,
    Busy,
    Uncertain,
}
pub type HostResult = std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>;

/// Called by the CURRENT executable's dedicated host entry point. No
/// callbacks are executed by the controller, including after timeouts.
pub trait HostRuntime {
    fn start(&mut self, host_args: &[OsString]) -> HostResult;
    /// Read-only gate; never start a stop or mutate work from this method.
    fn approve_stop(&mut self) -> StopApproval;
    /// Shutdown and wait for all originally owned actions, without kill().
    fn cooperative_stop(&mut self) -> HostResult;
}

#[derive(Debug, Clone)]
pub struct HostInvocation {
    state_dir: PathBuf,
    session_id: String,
    host_args: Vec<OsString>,
}
impl HostInvocation {
    pub fn state_dir(&self) -> &Path { &self.state_dir }
    pub fn session_id(&self) -> &str { &self.session_id }
    pub fn host_args(&self) -> &[OsString] { &self.host_args }
}

/// Recognizes only the fixed, private child entry and leaves normal CLI
/// arguments untouched. The host's own arguments are explicitly separated.
pub fn parse_host_invocation(args: &[OsString]) -> Result<Option<HostInvocation>> {
    if args.first().map(OsString::as_os_str)
        != Some(OsStr::new("--agent-bridge-lifecycle-host"))
    {
        return Ok(None);
    }
    if args.len() < 6 || args[1] != "--state-dir"
        || args[3] != "--session-id" || args[5] != "--"
    {
        return Err(LifecycleError::Invalid("malformed internal host invocation"));
    }
    let session_id = args[4].to_str().ok_or(LifecycleError::Invalid("invalid session ID"))?;
    check_id(session_id)?;
    Ok(Some(HostInvocation {
        state_dir: PathBuf::from(&args[2]),
        session_id: session_id.to_owned(),
        host_args: args[6..].to_vec(),
    }))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Current {
    format: u32,
    session_id: String,
    secret: String, // only in a private, owner-owned state file; never in argv
    executable: String,
    sha256: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ready {
    format: u32,
    session_id: String,
    pid: u32,
    birth: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    format: u32,
    session_id: String,
    request_id: String,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ReplyKind {
    Approved,
    Busy,
    Uncertain,
    Stopped,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    format: u32,
    session_id: String,
    request_id: String,
    kind: ReplyKind,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Signed<T> {
    payload: T,
    mac: String,
}
struct Layout {
    root: PathBuf,
    session: PathBuf,
}
impl Layout {
    fn new(root: &Path, id: &str) -> Result<Self> {
        check_id(id)?;
        Ok(Self {
            root: root.to_path_buf(),
            session: root.join("sessions").join(id),
        })
    }
    fn current(&self) -> PathBuf { self.root.join("current.json") }
    fn controller_lock(&self) -> PathBuf { self.root.join("controller.lock") }
    fn instance_lock(&self) -> PathBuf { self.root.join("instance.lock") }
    fn ready(&self) -> PathBuf { self.session.join("ready.json") }
    fn intent(&self) -> PathBuf { self.session.join("stop.intent.json") }
    fn reply(&self) -> PathBuf { self.session.join("stop.reply.json") }
    fn approved(&self) -> PathBuf { self.session.join("stop.approved.json") }
    fn finished(&self) -> PathBuf { self.session.join("stop.finished.json") }
}

// The first launch refuses directories containing arbitrary data or historic
// Agent Bridge captures. It never creates lifecycle state beside a real DB.
fn verify_lifecycle_namespace(root: &Path) -> Result<()> {
    for item in fs::read_dir(root)? {
        let item = item?;
        let name = item.file_name();
        match name.to_str() {
            Some("controller.lock" | "instance.lock" | "current.json") => {
                check_regular_file(&item.path())?;
            }
            Some("sessions") => {
                platform::verify_private_directory(&item.path())?;
            }
            _ => return Err(LifecycleError::Uncertain(
                "state directory contains non-lifecycle data",
            )),
        }
    }
    Ok(())
}

fn check_id(id: &str) -> Result<()> {
    if id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
        Ok(())
    } else {
        Err(LifecycleError::Invalid("invalid incarnation identifier"))
    }
}
fn random_hex() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes)
        .map_err(|_| LifecycleError::Uncertain("system randomness unavailable"))?;
    Ok(hex::encode(bytes))
}
fn random_id() -> Result<String> { Ok(random_hex()?[..32].to_owned()) }

fn deadline(timeout: Duration) -> Result<Instant> {
    if timeout < Duration::from_millis(50) || timeout > Duration::from_secs(180) {
        return Err(LifecycleError::Invalid("timeout must be between 50ms and 180s"));
    }
    Instant::now().checked_add(timeout)
        .ok_or(LifecycleError::Invalid("timeout overflow"))
}

fn expected_binary() -> Result<(PathBuf, String)> {
    let path = fs::canonicalize(std::env::current_exe()?)?;
    if !path.is_file() {
        return Err(LifecycleError::Uncertain("current executable is not a file"));
    }
    let mut file = File::open(&path)?;
    let mut hash = Sha256::new();
    let mut buf = [0u8; 32 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 { break; }
        hash.update(&buf[..n]);
    }
    Ok((path, hex::encode(hash.finalize())))
}
fn match_binary(current: &Current) -> Result<PathBuf> {
    let (path, hash) = expected_binary()?;
    if current.executable != path.to_string_lossy().as_ref() || current.sha256 != hash {
        return Err(LifecycleError::Uncertain("different executable or changed binary"));
    }
    Ok(path)
}

fn valid_root(raw: &Path, create: bool) -> Result<PathBuf> {
    if !raw.is_absolute() || raw.file_name().is_none()
        || raw.components().any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(LifecycleError::Invalid("absolute canonical state directory required"));
    }
    #[cfg(windows)]
    {
        let value = raw.to_string_lossy();
        if value.starts_with(r"\\") || value.starts_with("//") {
            return Err(LifecycleError::Invalid("network/device state directory refused"));
        }
    }
    let parent = raw.parent()
        .ok_or(LifecycleError::Invalid("state directory needs a parent"))?;
    check_real_ancestors(parent)?;
    if create && !raw.exists() {
        platform::create_private_directory(raw)?;
    }
    check_real_ancestors(raw)?;
    platform::verify_private_directory(raw)?;
    Ok(raw.to_path_buf())
}
fn check_real_ancestors(path: &Path) -> Result<()> {
    for candidate in path.ancestors() {
        let md = fs::symlink_metadata(candidate)?;
        if !md.is_dir() || md.file_type().is_symlink() || platform::is_reparse(&md) {
            return Err(LifecycleError::Uncertain("reparse or non-directory state ancestor"));
        }
    }
    Ok(())
}

/// Only the local CLI creates operator settings. The caller supplies a
/// separate directory outside any workspace exposed to an agent.
pub fn initialize_operator_settings(path: &Path) -> Result<()> {
    let root = valid_root(path, true)?;
    for (name, bytes) in [
        ("extensions.json", b"{\"version\":1,\"servers\":{}}\n".as_slice()),
        ("commands.json", b"{\"version\":1,\"programs\":{}}\n".as_slice()),
    ] {
        let path = root.join(name);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        platform::private_open_options(&mut options);
        match options.open(&path) {
            Ok(mut file) => { file.write_all(bytes)?; file.sync_all()?; }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
        let _ = read_operator_setting(&root, name)?;
    }
    Ok(())
}

/// Protected inheritable DACL used when creating private Windows directories.
#[cfg(windows)]
pub fn private_directory_sddl() -> Result<String> {
    platform::private_directory_sddl()
}

pub fn operator_skill_directory(settings: &Path) -> Result<PathBuf> {
    let root = valid_root(settings, false)?;
    valid_root(&root.join("skills"), true)
}

pub fn browser_profiles(settings: &Path) -> Result<(PathBuf, PathBuf)> {
    let root = valid_root(settings, false)?;
    let group = valid_root(&root.join("browser-profiles"), true)?;
    Ok((valid_root(&group.join("chatgpt"), true)?, valid_root(&group.join("gemini"), true)?))
}

pub fn read_operator_setting(root: &Path, name: &str) -> Result<Vec<u8>> {
    if !matches!(name, "extensions.json" | "commands.json" | "unified-v1.json") {
        return Err(LifecycleError::Invalid("unknown operator setting"));
    }
    use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
    use cap_std::fs::{Dir, OpenOptions as RelativeOptions};
    let root = valid_root(root, false)?;
    let mut base = PathBuf::new();
    let mut parts = Vec::new();
    for part in root.components() {
        match part {
            Component::RootDir | Component::Prefix(_) => base.push(part.as_os_str()),
            Component::Normal(part) => parts.push(part.to_owned()),
            _ => return Err(LifecycleError::Invalid("invalid settings directory")),
        }
    }
    let mut dir = Dir::open_ambient_dir(base, cap_std::ambient_authority())?;
    for part in parts {
        dir = dir.open_dir_nofollow(part)?;
        let handle = dir.try_clone()?.into_std_file();
        if platform::is_reparse(&handle.metadata()?) { return Err(LifecycleError::Invalid("reparse settings directory")); }
    }
    platform::verify_private_handle(&dir.try_clone()?.into_std_file(), true)?;
    let mut options = RelativeOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let file = dir.open_with(name, &options)?.into_std();
    platform::verify_private_handle(&file, false)?;
    let mut bytes = Vec::new();
    file.take(128 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 128 * 1024 { return Err(LifecycleError::Invalid("settings file exceeds limit")); }
    Ok(bytes)
}

fn ensure_session_directories(root: &Path, id: &str) -> Result<()> {
    let sessions = root.join("sessions");
    if !sessions.exists() {
        platform::create_private_directory(&sessions)?;
    }
    platform::verify_private_directory(&sessions)?;
    let own = sessions.join(id);
    if fs::symlink_metadata(&own).is_ok() {
        return Err(LifecycleError::Uncertain("session name already exists"));
    }
    platform::create_private_directory(&own)?;
    platform::verify_private_directory(&own)
}

fn check_regular_file(path: &Path) -> Result<()> {
    let md = fs::symlink_metadata(path)?;
    if !md.is_file() || md.file_type().is_symlink() || platform::is_reparse(&md)
        || md.len() > MAX_MARKER_BYTES
    {
        return Err(LifecycleError::Uncertain("unsafe lifecycle marker"));
    }
    platform::verify_private_file(path, &md)
}

fn existing_file(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => { check_regular_file(path)?; Ok(true) }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

fn read_marker<T: DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    if !existing_file(path)? { return Ok(None); }
    let mut options = OpenOptions::new();
    options.read(true);
    platform::private_open_options(&mut options);
    // Read the opened handle, never fs::read(path) after a separate link check.
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || platform::is_reparse(&metadata)
        || metadata.len() > MAX_MARKER_BYTES
    {
        return Err(LifecycleError::Uncertain("unsafe opened lifecycle marker"));
    }
    platform::verify_private_file(path, &metadata)?;
    let mut bytes = Vec::new();
    file.take(MAX_MARKER_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() > MAX_MARKER_BYTES as usize {
        return Err(LifecycleError::Uncertain("unbounded lifecycle marker"));
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| LifecycleError::Uncertain("invalid lifecycle marker"))
}

fn write_marker<T: Serialize>(path: &Path, payload: &T) -> Result<()> {
    if existing_file(path)? {
        return Err(LifecycleError::Uncertain("lifecycle marker already exists"));
    }
    let bytes = serde_json::to_vec(payload)?;
    if bytes.len() > MAX_MARKER_BYTES as usize {
        return Err(LifecycleError::Invalid("lifecycle marker too large"));
    }
    let mut pending_name = path.as_os_str().to_os_string();
    pending_name.push(format!(".pending.{}", random_id()?));
    let pending = PathBuf::from(pending_name);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    platform::private_open_options(&mut options);
    {
        let mut f = options.open(&pending)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
    }
    if existing_file(path)? {
        return Err(LifecycleError::Uncertain("lifecycle marker raced publication"));
    }
    fs::rename(&pending, path)?;
    Ok(())
}

/// Owns the published credential for the lifetime of the session-view listener.
#[must_use = "keep the descriptor alive while the session-view listener is running"]
pub struct SessionViewDescriptor {
    file: File,
    #[cfg(unix)]
    path: PathBuf,
}

#[cfg(windows)]
impl Drop for SessionViewDescriptor {
    fn drop(&mut self) {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            FileDispositionInfoEx, SetFileInformationByHandle, FILE_DISPOSITION_FLAG_DELETE,
            FILE_DISPOSITION_FLAG_ON_CLOSE, FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
            FILE_DISPOSITION_INFO_EX,
        };

        // Release the name when this handle closes, even during an operator read.
        // On filesystems without POSIX disposition, delete-on-close still applies.
        let disposition = FILE_DISPOSITION_INFO_EX {
            Flags: FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_ON_CLOSE
                | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
        };
        // The descriptor still owns the handle and the OS only reads the buffer.
        let _ = unsafe {
            SetFileInformationByHandle(self.file.as_raw_handle(), FileDispositionInfoEx,
                (&disposition as *const FILE_DISPOSITION_INFO_EX).cast(),
                std::mem::size_of_val(&disposition) as u32)
        };
    }
}

#[cfg(unix)]
impl Drop for SessionViewDescriptor {
    fn drop(&mut self) {
        retire_unix_descriptor(&self.file, &self.path);
    }
}

/// Move the name aside atomically, then unlink it only when it is still the
/// owned inode. A replacement installed after publication is put back without
/// overwriting a newer entry, and is never unlinked.
#[cfg(unix)]
fn retire_unix_descriptor(file: &File, path: &Path) {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};

    let (Ok(owned), Some(parent), Ok(nonce)) = (file.metadata(), path.parent(), random_hex()) else {
        return;
    };
    // A fresh owner-only directory with an unguessable name keeps the staged
    // entry away from other writers in the descriptor directory.
    let stage = parent.join(format!(".session-view-retired-{}", &nonce[..32]));
    if fs::DirBuilder::new().mode(0o700).create(&stage).is_err() {
        return;
    }
    // A regular-file slot makes rename(2) refuse a replacement directory
    // atomically (ENOTDIR or EISDIR) instead of moving it aside.
    let staged = stage.join("descriptor");
    if OpenOptions::new().write(true).create_new(true).open(&staged).is_ok() {
        if fs::rename(path, &staged).is_ok() {
            match fs::symlink_metadata(&staged) {
                Ok(current) if (owned.dev(), owned.ino()) == (current.dev(), current.ino()) => {
                    let _ = fs::remove_file(&staged);
                }
                _ => {
                    // link(2) refuses an existing target, so a newer entry stays intact.
                    if fs::hard_link(&staged, path).is_ok() {
                        let _ = fs::remove_file(&staged);
                    }
                }
            }
        } else {
            let _ = fs::remove_file(&staged);
        }
    }
    // Succeeds only when empty: a replacement that could not be restored keeps
    // its staging directory instead of being deleted.
    let _ = fs::remove_dir(&stage);
}

#[cfg(all(test, unix))]
mod session_view_retire_tests {
    use super::*;

    fn fresh_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ab-retire-{}", random_hex().unwrap()));
        fs::create_dir(&dir).unwrap();
        dir
    }

    fn leftovers(dir: &Path) -> Vec<String> {
        fs::read_dir(dir).unwrap().map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with(".session-view-retired-")).collect()
    }

    #[test]
    fn retiring_removes_only_the_owned_descriptor() {
        let dir = fresh_dir();
        let path = dir.join("session.json");
        let owned = OpenOptions::new().read(true).write(true).create_new(true).open(&path).unwrap();
        retire_unix_descriptor(&owned, &path);
        assert!(!path.exists());
        assert!(leftovers(&dir).is_empty());

        let replaced = OpenOptions::new().read(true).write(true).create_new(true).open(&path).unwrap();
        fs::remove_file(&path).unwrap();
        fs::write(&path, b"replacement").unwrap();
        retire_unix_descriptor(&replaced, &path);
        assert_eq!(fs::read(&path).unwrap(), b"replacement");
        assert!(leftovers(&dir).is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn retiring_leaves_a_replacement_directory_or_symlink_in_place() {
        let dir = fresh_dir();
        let path = dir.join("session.json");
        let owned = OpenOptions::new().read(true).write(true).create_new(true).open(&path).unwrap();
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        fs::write(path.join("kept"), b"data").unwrap();
        retire_unix_descriptor(&owned, &path);
        assert_eq!(fs::read(path.join("kept")).unwrap(), b"data");
        assert!(leftovers(&dir).is_empty());

        fs::remove_dir_all(&path).unwrap();
        let target = dir.join("target.json");
        fs::write(&target, b"target").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        retire_unix_descriptor(&owned, &path);
        assert!(fs::symlink_metadata(&path).unwrap().file_type().is_symlink());
        assert_eq!(fs::read(&target).unwrap(), b"target");
        assert!(leftovers(&dir).is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }
}

/// Publish a local session-view credential into an existing owner-private
/// directory. The selected file must not exist. Dropping the owner removes it.
pub fn publish_session_view_descriptor(
    path: &Path, record: &serde_json::Value,
) -> Result<SessionViewDescriptor> {
    let directory = path.parent().ok_or(LifecycleError::Invalid("operator descriptor directory required"))?;
    let directory = valid_root(directory, false)?;
    let name = path.file_name().and_then(|name| name.to_str())
        .filter(|name| name.len() <= 128 && name.ends_with(".json")
            && name.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte)))
        .ok_or(LifecycleError::Invalid("invalid operator descriptor filename"))?;
    let bytes = serde_json::to_vec(record)?;
    if bytes.len() > MAX_MARKER_BYTES as usize {
        return Err(LifecycleError::Invalid("operator descriptor exceeds limit"));
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    platform::private_open_options(&mut options);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
        use windows_sys::Win32::Storage::FileSystem::{
            DELETE, FILE_FLAG_DELETE_ON_CLOSE, FILE_FLAG_OPEN_REPARSE_POINT,
        };

        // Remove the exact file object owned by this handle at close.
        options.access_mode(GENERIC_READ | GENERIC_WRITE | DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_DELETE_ON_CLOSE);
    }
    let path = directory.join(name);
    let mut descriptor = SessionViewDescriptor {
        file: options.open(&path)?,
        #[cfg(unix)]
        path,
    };
    platform::verify_private_handle(&descriptor.file, false)?;
    descriptor.file.write_all(&bytes)?;
    descriptor.file.sync_all()?;
    Ok(descriptor)
}

fn open_lock(path: &Path) -> Result<File> {
    if existing_file(path)? {
        return lock_file(path, false);
    }
    lock_file(path, true)
}
fn lock_file(path: &Path, create: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    if create { options.create_new(true); }
    platform::private_open_options(&mut options);
    let file = options.open(path)?;
    check_regular_file(path)?;
    Ok(file)
}
fn exclusive_lock(path: &Path) -> Result<File> {
    let f = open_lock(path)?;
    match f.try_lock_exclusive() {
        Ok(()) => Ok(f),
        Err(e) if lock_contended(&e) => Err(LifecycleError::Busy),
        Err(e) => Err(e.into()),
    }
}
fn owner_held(path: &Path) -> Result<bool> {
    // Observation must NEVER create a missing owner-lock file.
    let file = lock_file(path, false)
        .map_err(|_| LifecycleError::Uncertain("owner lock unavailable"))?;
    match file.try_lock_exclusive() {
        Ok(()) => {
            FileExt::unlock(&file)?;
            Ok(false)
        }
        Err(e) if lock_contended(&e) => Ok(true),
        Err(e) => Err(e.into()),
    }
}
fn lock_contended(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::WouldBlock
        || (cfg!(windows) && error.raw_os_error() == Some(33))
}
fn sign<'a, T: Serialize>(record: &Current, purpose: &str, payload: &'a T) -> Result<Signed<&'a T>> {
    let key = hex::decode(&record.secret)
        .map_err(|_| LifecycleError::Uncertain("invalid session key"))?;
    if key.len() != 32 {
        return Err(LifecycleError::Uncertain("invalid session key length"));
    }
    let mut mac = HmacSha256::new_from_slice(&key)
        .map_err(|_| LifecycleError::Uncertain("invalid MAC configuration"))?;
    mac.update(purpose.as_bytes());
    mac.update(&[0]);
    mac.update(&serde_json::to_vec(payload)?);
    Ok(Signed { payload, mac: hex::encode(mac.finalize().into_bytes()) })
}
fn verify<T: DeserializeOwned + Serialize>(
    record: &Current, purpose: &str, path: &Path
) -> Result<Option<T>> {
    let frame: Signed<T> = match read_marker(path)? {
        Some(x) => x,
        None => return Ok(None),
    };
    let key = hex::decode(&record.secret)
        .map_err(|_| LifecycleError::Uncertain("invalid session key"))?;
    if key.len() != 32 { return Err(LifecycleError::Uncertain("invalid session key length")); }
    let value = hex::decode(&frame.mac)
        .map_err(|_| LifecycleError::Uncertain("malformed session proof"))?;
    let mut mac = HmacSha256::new_from_slice(&key)
        .map_err(|_| LifecycleError::Uncertain("invalid MAC configuration"))?;
    mac.update(purpose.as_bytes());
    mac.update(&[0]);
    mac.update(&serde_json::to_vec(&frame.payload)?);
    mac.verify_slice(&value)
        .map_err(|_| LifecycleError::Uncertain("session authentication failed"))?;
    Ok(Some(frame.payload))
}
fn signed_write<T: Serialize>(
    record: &Current, purpose: &str, path: &Path, payload: &T
) -> Result<()> {
    write_marker(path, &sign(record, purpose, payload)?)
}
fn read_current(root: &Path) -> Result<Current> {
    let current: Current = read_marker(&root.join("current.json"))?
        .ok_or(LifecycleError::Uncertain("no qualified current attempt"))?;
    check_id(&current.session_id)?;
    if current.format != FORMAT || current.sha256.len() != 64 {
        return Err(LifecycleError::Uncertain("unknown session format or executable hash"));
    }
    Ok(current)
}
fn check_ready(record: &Current, layout: &Layout) -> Result<Ready> {
    let ready: Ready = verify(record, "ready", &layout.ready())?
        .ok_or(LifecycleError::Uncertain("host has no READY receipt"))?;
    if ready.format != FORMAT || ready.session_id != record.session_id || ready.pid == 0 {
        return Err(LifecycleError::Uncertain("READY does not match this attempt"));
    }
    Ok(ready)
}

pub fn launch(options: LaunchOptions) -> Result<LaunchedSession> {
    let until = deadline(options.timeout)?;
    let root = valid_root(&options.state_dir, true)?;
    verify_lifecycle_namespace(&root)?;
    let unknown_layout = Layout::new(&root, "00000000000000000000000000000000")?;
    let _controller = exclusive_lock(&unknown_layout.controller_lock())?;
    if existing_file(&unknown_layout.current())? {
        return if owner_held(&unknown_layout.instance_lock())? {
            Err(LifecycleError::Busy)
        } else {
            Err(LifecycleError::Uncertain("previous attempt not retired"))
        };
    }
    // First creation is reserved under controller.lock; subsequent
    // observations may never manufacture an absent owner lock.
    if !existing_file(&unknown_layout.instance_lock())? {
        drop(open_lock(&unknown_layout.instance_lock())?);
    }
    if owner_held(&unknown_layout.instance_lock())? {
        return Err(LifecycleError::Busy);
    }

    let (binary, hash) = expected_binary()?;
    let id = random_id()?;
    let record = Current {
        format: FORMAT, session_id: id.clone(), secret: random_hex()?,
        executable: binary.to_string_lossy().into_owned(), sha256: hash,
    };
    ensure_session_directories(&root, &id)?;
    let layout = Layout::new(&root, &id)?;
    // The durable pointer is installed BEFORE creating the process. A failed
    // spawn is not silently forgotten; a separate explicit recovery is needed.
    write_marker(&layout.current(), &record)?;

    let mut cmd = Command::new(&binary);
    cmd.arg("--agent-bridge-lifecycle-host")
        .arg("--state-dir").arg(&root)
        .arg("--session-id").arg(&id)
        .arg("--")
        .args(&options.host_args)
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // CREATE_NO_WINDOW; no shell, extra console, PowerShell, or elevation.
        cmd.creation_flags(0x0800_0000);
    }
    let mut child = cmd.spawn().map_err(|_| {
        LifecycleError::Uncertain("spawn failed; attempt retained for reconciliation")
    })?;
    loop {
        if let Some(ready) = verify::<Ready>(&record, "ready", &layout.ready())? {
            if ready.format != FORMAT || ready.session_id != id || ready.pid != child.id()
                || !owner_held(&layout.instance_lock())?
            {
                return Err(LifecycleError::Uncertain("host incarnation mismatch"));
            }
            if child.try_wait()?.is_some() {
                return Err(LifecycleError::Uncertain("host exited at READY boundary"));
            }
            #[cfg(windows)]
            {
                // Match the actual Windows process creation time and image.
                let _witness = platform::observe_process(&ready, &binary)?;
            }
            return Ok(LaunchedSession { id });
        }
        if child.try_wait()?.is_some() {
            return Err(LifecycleError::Uncertain("host exited before READY"));
        }
        if Instant::now() >= until {
            return Err(LifecycleError::Uncertain("host READY timed out; no respawn"));
        }
        thread::sleep(POLL);
    }
}

fn response_matches(reply: &Reply, record: &Current, request: &Intent) -> Result<()> {
    if reply.format != FORMAT || reply.session_id != record.session_id
        || reply.request_id != request.request_id
    {
        return Err(LifecycleError::Uncertain("response belongs to another request"));
    }
    Ok(())
}

/// One explicit cooperative stop request. Never repeats a pending command.
/// A Busy reply is authenticated and archived, so a later explicit operator
/// invocation can ask again; any lost/uncertain reply preserves the intent.
pub fn stop(options: StopOptions) -> Result<StopOutcome> {
    let until = deadline(options.timeout)?;
    let root = valid_root(&options.state_dir, false)?;
    verify_lifecycle_namespace(&root)?;
    if !existing_file(&root.join("controller.lock"))? {
        return Err(LifecycleError::Uncertain("controller lock is missing"));
    }
    let _controller = exclusive_lock(&root.join("controller.lock"))?;
    let record = read_current(&root)?;
    let binary = match_binary(&record)?;
    let layout = Layout::new(&root, &record.session_id)?;
    platform::verify_private_directory(&root.join("sessions"))?;
    platform::verify_private_directory(&layout.session)?;
    if !owner_held(&layout.instance_lock())? {
        return Err(LifecycleError::Uncertain("original host lock is not held"));
    }
    let ready = check_ready(&record, &layout)?;
    let witness = platform::observe_process(&ready, &binary)?;
    if existing_file(&layout.intent())? || existing_file(&layout.reply())?
        || existing_file(&layout.approved())? || existing_file(&layout.finished())?
    {
        return Err(LifecycleError::Uncertain("prior stop command needs reconciliation"));
    }

    let request = Intent {
        format: FORMAT, session_id: record.session_id.clone(),
        request_id: random_id()?,
    };
    signed_write(&record, "stop-intent", &layout.intent(), &request)?;

    loop {
        if let Some(reply) = verify::<Reply>(&record, "stop-reply", &layout.reply())? {
            response_matches(&reply, &record, &request)?;
            match reply.kind {
                ReplyKind::Busy => {
                    // Only a verified Busy has no shutdown side effect.
                    // Rename rather than delete: previous intent is retained.
                    fs::rename(layout.intent(),
                        layout.session.join(format!("{}.busy.intent.json", request.request_id)))?;
                    fs::rename(layout.reply(),
                        layout.session.join(format!("{}.busy.reply.json", request.request_id)))?;
                    return Ok(StopOutcome::Busy);
                }
                ReplyKind::Uncertain => return Err(LifecycleError::Uncertain(
                    "host refused to attest a safe stop")),
                ReplyKind::Stopped => return Err(LifecycleError::Uncertain(
                    "unexpected completion without approval")),
                ReplyKind::Approved => {
                    let accepted: Reply = verify(&record, "stop-approved", &layout.approved())?
                        .ok_or(LifecycleError::Uncertain("approval marker absent"))?;
                    response_matches(&accepted, &record, &request)?;
                    if accepted.kind != ReplyKind::Approved {
                        return Err(LifecycleError::Uncertain("approval marker mismatch"));
                    }
                    if let Some(final_result) = verify::<Reply>(
                        &record, "stop-final", &layout.finished()
                    )? {
                        response_matches(&final_result, &record, &request)?;
                        if final_result.kind != ReplyKind::Stopped {
                            return Err(LifecycleError::Uncertain("host completion uncertain"));
                        }
                        if !owner_held(&layout.instance_lock())? {
                            let remaining = until.saturating_duration_since(Instant::now());
                            if !platform::wait_process_exit(&witness, remaining)? {
                                return Err(LifecycleError::Uncertain(
                                    "original process has not exited"));
                            }
                            if existing_file(&layout.session.join("retired.json"))? {
                                return Err(LifecycleError::Uncertain("attempt already retired"));
                            }
                            fs::rename(layout.current(), layout.session.join("retired.json"))?;
                            return Ok(StopOutcome::Stopped);
                        }
                    }
                }
            }
        }
        if Instant::now() >= until {
            return Err(LifecycleError::Uncertain("stop timed out; intent preserved"));
        }
        thread::sleep(POLL);
    }
}

/// Runs only in the spawned executable. The instance file lock is held for
/// the entire lifetime of this method. No callback or stop is ever replayed.
pub fn serve_host(invocation: HostInvocation, mut runtime: impl HostRuntime) -> Result<()> {
    let root = valid_root(&invocation.state_dir, false)?;
    let record = read_current(&root)?;
    if record.session_id != invocation.session_id {
        return Err(LifecycleError::Uncertain("host assigned another session"));
    }
    match_binary(&record)?;
    let layout = Layout::new(&root, &record.session_id)?;
    platform::verify_private_directory(&root.join("sessions"))?;
    platform::verify_private_directory(&layout.session)?;
    let _owner = exclusive_lock(&layout.instance_lock())?;
    if existing_file(&layout.ready())? || existing_file(&layout.intent())?
        || existing_file(&layout.reply())? || existing_file(&layout.finished())?
    {
        return Err(LifecycleError::Uncertain("host session already admitted"));
    }
    // The CLI must ensure start does not start more than once for this process.
    runtime.start(&invocation.host_args)
        .map_err(|_| LifecycleError::Uncertain("host start failed"))?;
    let ready = Ready {
        format: FORMAT, session_id: record.session_id.clone(),
        pid: std::process::id(), birth: platform::self_birth()?,
    };
    signed_write(&record, "ready", &layout.ready(), &ready)?;

    let mut handled = None::<String>;
    loop {
        let intent: Intent = match verify(&record, "stop-intent", &layout.intent())? {
            Some(x) => x,
            None => { thread::sleep(POLL); continue; }
        };
        if intent.format != FORMAT || intent.session_id != record.session_id {
            return Err(LifecycleError::Uncertain("foreign stop request"));
        }
        check_id(&intent.request_id)?;
        if handled.as_ref() == Some(&intent.request_id) {
            thread::sleep(POLL);
            continue;
        }
        handled = Some(intent.request_id.clone());
        let reply = |kind: ReplyKind| Reply {
            format: FORMAT,
            session_id: record.session_id.clone(),
            request_id: intent.request_id.clone(),
            kind,
        };
        match runtime.approve_stop() {
            StopApproval::Busy => {
                signed_write(&record, "stop-reply", &layout.reply(), &reply(ReplyKind::Busy))?;
            }
            StopApproval::Uncertain => {
                signed_write(&record, "stop-reply", &layout.reply(),
                    &reply(ReplyKind::Uncertain))?;
                // Preserve intent: no retry or re-admission of this request.
            }
            StopApproval::Approved => {
                // Persist approval BEFORE invoking any shutdown code. A crash
                // after this point must NEVER recreate/retry the shutdown.
                signed_write(&record, "stop-approved", &layout.approved(),
                    &reply(ReplyKind::Approved))?;
                signed_write(&record, "stop-reply", &layout.reply(),
                    &reply(ReplyKind::Approved))?;
                if runtime.cooperative_stop().is_err() {
                    signed_write(&record, "stop-final", &layout.finished(),
                        &reply(ReplyKind::Uncertain))?;
                    return Err(LifecycleError::Uncertain("cooperative shutdown failed"));
                }
                signed_write(&record, "stop-final", &layout.finished(),
                    &reply(ReplyKind::Stopped))?;
                // Drop the owner lock only AFTER all owned work has stopped.
                // The CLI must now exit immediately, without another action.
                return Ok(());
            }
        }
        thread::sleep(POLL);
    }
}
