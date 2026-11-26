//! Outbound stdio MCP extensions: the pinned launch specification, the
//! executable pin and the process seam the CLI implements. The CLI owns
//! process containment; this crate owns policy and the MCP session.
//!
//! The pin covers the native image that is started. For an interpreter such
//! as `node.exe` with a script argument, only the interpreter is pinned; the
//! script is an exact argument, not a hashed file. On Unix the check happens
//! on a held descriptor but the launcher executes the path, so a narrow
//! check-to-exec window remains; the post-launch re-check detects a swapped
//! directory entry but cannot prove which image the kernel loaded.
//!
//! On Windows the held handle denies write and delete sharing, and the
//! post-launch re-check compares the volume serial number and file index.
//! A process of the same user that redefines a drive letter in its logon
//! session and restores it within the launch window is not detected: such a
//! process can already alter the bridge itself and is inside its trust
//! boundary.

use crate::{error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

/// Largest executable image the bridge hashes.
const MAX_IMAGE_BYTES: u64 = 512 * 1024 * 1024;
/// Process-wide bound on live stdio sessions. A further session is refused,
/// never queued.
const MAX_LIVE_SESSIONS: usize = 4;
/// Bytes of the most recent child diagnostics kept in memory.
const STDERR_TAIL_BYTES: usize = 4096;

/// One operator-approved stdio server: exact executable, its SHA-256, exact
/// arguments and environment references. No field holds a secret value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StdioSpec {
    pub executable: String,
    pub executable_sha256: String,
    #[serde(default)]
    pub args: Vec<String>,
    /// Child variable name mapped to the bridge variable that supplies it.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// Append the bridge's own PATH after the fixed one, for launchers such
    /// as `npx` that resolve their tools through it. Off by default; a
    /// spec without it keeps its existing pin.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub inherit_path: bool,
}

impl StdioSpec {
    /// Pure shape validation: no filesystem or environment access.
    pub fn validate(&self) -> Result<()> {
        if !valid_path(&self.executable, true) {
            return Err(error("Stdio extension executable must be an exact absolute native path"));
        }
        if !lowercase_sha256(&self.executable_sha256) {
            return Err(error("Stdio extension executable pin must be a lowercase SHA-256"));
        }
        let total = self.args.iter().map(String::len).fold(0usize, usize::saturating_add);
        if self.args.len() > 64 || total > 16 * 1024
            || self.args.iter().any(|arg| arg.len() > 4096 || arg.contains('\0')) {
            return Err(error("Stdio extension arguments exceed their bounds"));
        }
        let mut names = BTreeSet::new();
        if self.env.len() > 32 || !self.env.iter().all(|(name, source)| valid_child_env_name(name)
            && names.insert(name.to_ascii_uppercase())
            && crate::oauth::valid_secret_env_name(source)) {
            return Err(error("Invalid, duplicate or reserved stdio extension environment reference"));
        }
        if self.cwd.as_deref().is_some_and(|cwd| !valid_path(cwd, false)) {
            return Err(error("Stdio extension working directory must be an exact absolute path"));
        }
        Ok(())
    }
}

/// Copied from the bridge environment when present. These names, and the
/// ones below, are never settable through a reference.
const SAFE_WINDOWS: &[&str] = &["SystemRoot", "SystemDrive", "windir", "TEMP", "TMP", "USERPROFILE",
    "APPDATA", "LOCALAPPDATA", "ProgramData", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE", "OS"];
const SAFE_UNIX: &[&str] = &["HOME", "USER", "LOGNAME", "TMPDIR", "LANG", "LC_ALL"];
/// Loader, interpreter and shell controls that would change what runs.
const DENIED: &[&str] = &["PATH", "PATHEXT", "COMSPEC", "NODE_OPTIONS", "NODE_PATH", "PYTHONPATH",
    "PYTHONHOME", "PYTHONSTARTUP", "PERL5OPT", "PERL5LIB", "RUBYOPT", "RUBYLIB", "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "CLASSPATH", "BASH_ENV", "ENV", "ELECTRON_RUN_AS_NODE",
    "GLIBC_TUNABLES"];
/// Prefixes of dynamic loader and managed runtime controls (.NET startup
/// hooks, profilers and runtime selection).
const DENIED_PREFIXES: &[&str] = &["LD_", "DYLD_", "DOTNET_", "COR_", "CORECLR_"];

/// True for a child environment variable name the bridge may set.
pub fn valid_child_env_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    let shaped = name.len() <= 128
        && bytes.next().is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_');
    let upper = name.to_ascii_uppercase();
    shaped && !SAFE_WINDOWS.iter().chain(SAFE_UNIX).chain(DENIED).any(|denied| denied.eq_ignore_ascii_case(name))
        && !DENIED_PREFIXES.iter().any(|prefix| upper.starts_with(prefix))
}

fn lowercase_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Absolute, already normalized, no relative component and, on Windows, a
/// drive path without a UNC, device or verbatim prefix.
fn valid_path(raw: &str, executable: bool) -> bool {
    if raw.is_empty() || raw.len() > 1024 || raw.contains('\0') { return false; }
    let path = Path::new(raw);
    if !path.is_absolute() || (executable && path.file_name().is_none()) { return false; }
    let mut rebuilt = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir | Component::ParentDir => return false,
            #[cfg(windows)]
            Component::Prefix(prefix) if !matches!(prefix.kind(), std::path::Prefix::Disk(_)) => return false,
            #[cfg(windows)]
            Component::Normal(part) => {
                let Some(part) = part.to_str() else { return false };
                let stem = part.split('.').next().unwrap_or_default().to_ascii_lowercase();
                if part.ends_with('.') || part.ends_with(' ')
                    || part.chars().any(|c| matches!(c, ':' | ';' | '*' | '?' | '"' | '<' | '>' | '|') || c.is_control())
                    || matches!(stem.as_str(), "con" | "prn" | "aux" | "nul" | "conin$" | "conout$")
                    || (stem.len() == 4 && (stem.starts_with("com") || stem.starts_with("lpt"))
                        && stem.as_bytes()[3].is_ascii_digit()) {
                    return false;
                }
            }
            _ => {}
        }
        rebuilt.push(component);
    }
    if rebuilt.as_os_str() != path.as_os_str() { return false; }
    #[cfg(windows)]
    if executable && !path.extension().and_then(|e| e.to_str()).is_some_and(|e| e.eq_ignore_ascii_case("exe")) {
        return false;
    }
    // The executable directory leads the fixed child PATH.
    #[cfg(not(windows))]
    if executable && raw.contains(':') { return false; }
    true
}

/// Pins and hashes a native executable, returning its lowercase SHA-256.
pub fn observe_executable(path: &Path) -> Result<String> {
    let raw = path.to_str().filter(|raw| valid_path(raw, true))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Stdio extension executable must be an exact absolute native path"))?;
    PinnedExecutable::open(Path::new(raw))?.sha256()
}

/// Fails unless the native executable at `path` still has `expected` SHA-256.
/// Only a hash mismatch returns `ErrorKind::InvalidData`; a missing,
/// non-native, oversized or redirected executable returns another kind.
pub fn verify_executable(path: &Path, expected: &str) -> Result<()> {
    if !lowercase_sha256(expected) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Stdio extension executable pin must be a lowercase SHA-256"));
    }
    if observe_executable(path)? != expected {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Stdio extension executable changed; local reapproval required"));
    }
    Ok(())
}

fn unavailable(source: io::Error) -> io::Error {
    // Keep the kind for the caller, never the path; InvalidData is reserved
    // for a hash mismatch.
    let kind = match source.kind() { io::ErrorKind::InvalidData => io::ErrorKind::Other, kind => kind };
    io::Error::new(kind, "Stdio extension executable is unavailable")
}

fn refused(message: &'static str) -> io::Error { io::Error::new(io::ErrorKind::Unsupported, message) }

/// No ancestor, nor the file itself, may be a symbolic link or, on
/// Windows, any reparse point (junction, mount point or link). On Unix no
/// ancestor directory may be replaceable by another user: each is owned by
/// root or the bridge user, and is not writable by others unless sticky.
pub(crate) fn check_ancestors(path: &Path) -> Result<()> {
    let mut prefix = PathBuf::new();
    for component in path.components() {
        prefix.push(component);
        if matches!(component, Component::Prefix(_)) { continue; }
        let metadata = fs::symlink_metadata(&prefix).map_err(unavailable)?;
        if redirected(&metadata) { return Err(refused("Stdio extension executable path contains a link or reparse point")); }
        #[cfg(unix)]
        if metadata.is_dir() {
            use std::os::unix::fs::MetadataExt;
            let mode = metadata.mode();
            if (metadata.uid() != 0 && metadata.uid() != unix_identity::effective_uid())
                || (mode & 0o002 != 0 && mode & 0o1000 == 0) {
                return Err(refused("Stdio extension path has a directory another user can replace"));
            }
        }
    }
    Ok(())
}

fn redirected(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)] {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 { return true; }
    }
    metadata.file_type().is_symlink()
}

#[cfg(unix)]
mod unix_identity {
    extern "C" { fn geteuid() -> u32; }
    pub(super) fn effective_uid() -> u32 {
        // SAFETY: geteuid has no preconditions and cannot fail.
        unsafe { geteuid() }
    }
    /// Never follow a final link, and never block opening a FIFO.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub(super) const OPEN_FLAGS: i32 = 0o400000 | 0o4000;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    pub(super) const OPEN_FLAGS: i32 = 0x0100 | 0x0004;
}

#[cfg(windows)]
mod windows_identity {
    use std::os::windows::io::AsRawHandle;

    #[repr(C)]
    #[derive(Default)]
    struct FileInformation {
        attributes: u32,
        times: [u32; 6],
        volume_serial_number: u32,
        size_high: u32,
        size_low: u32,
        links: u32,
        index_high: u32,
        index_low: u32,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetFileInformationByHandle(file: *mut core::ffi::c_void, information: *mut FileInformation) -> i32;
    }

    /// The volume serial number and the file index of an open file.
    pub(super) fn of(file: &std::fs::File) -> std::io::Result<(u64, u64)> {
        let mut information = FileInformation::default();
        // SAFETY: the handle is open for the duration of the call and the
        // structure matches BY_HANDLE_FILE_INFORMATION.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok((u64::from(information.volume_serial_number),
            (u64::from(information.index_high) << 32) | u64::from(information.index_low)))
    }
}

/// An executable held open from inspection until after launch. On Windows
/// the handle denies write and delete sharing, so the image cannot change
/// while it is pinned.
pub(crate) struct PinnedExecutable {
    file: File,
    path: PathBuf,
    identity: (u64, u64),
}

impl PinnedExecutable {
    pub(crate) fn open(path: &Path) -> Result<Self> {
        check_ancestors(path)?;
        let mut options = fs::OpenOptions::new();
        options.read(true);
        #[cfg(windows)] {
            use std::os::windows::fs::OpenOptionsExt;
            // FILE_SHARE_READ only; FILE_FLAG_OPEN_REPARSE_POINT.
            options.share_mode(0x1).custom_flags(0x0020_0000);
        }
        #[cfg(unix)] {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(unix_identity::OPEN_FLAGS);
        }
        let file = options.open(path).map_err(unavailable)?;
        let metadata = file.metadata().map_err(unavailable)?;
        if redirected(&metadata) || !metadata.is_file() {
            return Err(refused("Stdio extension executable is not a regular file"));
        }
        if metadata.len() > MAX_IMAGE_BYTES { return Err(refused("Stdio extension executable exceeds the size bound")); }
        let identity = Self::identity(&file, &metadata)?;
        #[cfg(unix)] {
            use std::os::unix::fs::MetadataExt;
            let named = fs::symlink_metadata(path).map_err(unavailable)?;
            let mode = metadata.mode();
            if (named.dev(), named.ino()) != identity || mode & 0o111 == 0 || mode & 0o022 != 0
                || (metadata.uid() != 0 && metadata.uid() != unix_identity::effective_uid()) {
                return Err(refused("Stdio extension executable ownership or mode is unsafe"));
            }
        }
        Ok(Self { file, path: path.to_path_buf(), identity })
    }

    #[cfg(unix)]
    fn identity(_file: &File, metadata: &fs::Metadata) -> Result<(u64, u64)> {
        use std::os::unix::fs::MetadataExt;
        Ok((metadata.dev(), metadata.ino()))
    }

    #[cfg(windows)]
    fn identity(file: &File, _metadata: &fs::Metadata) -> Result<(u64, u64)> {
        windows_identity::of(file).map_err(unavailable)
    }

    #[cfg(not(any(unix, windows)))]
    fn identity(_file: &File, metadata: &fs::Metadata) -> Result<(u64, u64)> { Ok((metadata.len(), 0)) }

    /// The identity of whatever the named path designates now, without
    /// following a final link.
    fn named_identity(&self) -> Result<(u64, u64)> {
        #[cfg(windows)] {
            use std::os::windows::fs::OpenOptionsExt;
            // FILE_READ_ATTRIBUTES; full sharing; FILE_FLAG_OPEN_REPARSE_POINT.
            let named = fs::OpenOptions::new().access_mode(0x80).share_mode(0x7)
                .custom_flags(0x0020_0000).open(&self.path).map_err(unavailable)?;
            let metadata = named.metadata().map_err(unavailable)?;
            if redirected(&metadata) {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Stdio extension executable changed during launch"));
            }
            Self::identity(&named, &metadata)
        }
        #[cfg(not(windows))] {
            let metadata = fs::symlink_metadata(&self.path).map_err(unavailable)?;
            if redirected(&metadata) {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Stdio extension executable changed during launch"));
            }
            Self::identity(&self.file, &metadata)
        }
    }

    /// Hashes the image through the held handle and refuses anything but a
    /// native console executable for this platform.
    pub(crate) fn sha256(&mut self) -> Result<String> {
        self.file.seek(SeekFrom::Start(0)).map_err(unavailable)?;
        let mut digest = Sha256::new();
        let mut head = Vec::with_capacity(4096);
        let mut buffer = vec![0u8; 64 * 1024];
        let mut total = 0u64;
        loop {
            let read = match self.file.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => read,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(unavailable(e)),
            };
            total += read as u64;
            if total > MAX_IMAGE_BYTES { return Err(refused("Stdio extension executable exceeds the size bound")); }
            let room = 4096usize.saturating_sub(head.len()).min(read);
            head.extend_from_slice(&buffer[..room]);
            digest.update(&buffer[..read]);
        }
        if !native_image(&head) {
            return Err(refused("Stdio extension executable is not a native console image"));
        }
        Ok(hex::encode(digest.finalize()))
    }

    /// After launch: the named path still resolves, without a link, to the
    /// pinned file.
    pub(crate) fn verify_unchanged(&self) -> Result<()> {
        check_ancestors(&self.path)?;
        if self.named_identity()? != self.identity {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Stdio extension executable changed during launch"));
        }
        Ok(())
    }
}

/// Scripts are refused: the pinned file must be what the kernel loads.
fn native_image(head: &[u8]) -> bool {
    if head.starts_with(b"#!") { return false; }
    #[cfg(windows)] {
        // MZ, then PE\0\0 at e_lfanew, an executable (not DLL) COFF image
        // and an optional header whose Subsystem is the console (3).
        let u16_at = |at: usize| head.get(at..at + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
        let Some(pe) = head.get(0x3c..0x40).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize) else { return false };
        head.starts_with(b"MZ") && pe <= 3072
            && head.get(pe..pe + 4) == Some(b"PE\0\0".as_slice())
            && u16_at(pe + 22).is_some_and(|c| c & 0x0002 != 0 && c & 0x2000 == 0)
            && matches!(u16_at(pe + 24), Some(0x10b | 0x20b))
            && u16_at(pe + 24 + 68) == Some(3)
    }
    #[cfg(not(windows))] {
        const MAGIC: &[[u8; 4]] = &[[0x7f, b'E', b'L', b'F'], [0xfe, 0xed, 0xfa, 0xce], [0xfe, 0xed, 0xfa, 0xcf],
            [0xce, 0xfa, 0xed, 0xfe], [0xcf, 0xfa, 0xed, 0xfe], [0xca, 0xfe, 0xba, 0xbe], [0xca, 0xfe, 0xba, 0xbf]];
        MAGIC.iter().any(|magic| head.starts_with(magic))
    }
}

/// The exact child environment: a fixed safe set copied when present, a
/// fixed PATH (followed by the bridge PATH when the spec opts in), then
/// each operator reference resolved through `resolve` (the bridge
/// environment in production). Nothing else is inherited.
/// Errors never name a variable or include a value.
pub(crate) fn child_environment(spec: &StdioSpec, resolve: &dyn Fn(&str) -> Option<OsString>)
    -> Result<BTreeMap<OsString, OsString>> {
    let mut environment = BTreeMap::new();
    let safe = if cfg!(windows) { SAFE_WINDOWS } else { SAFE_UNIX };
    for name in safe {
        if let Some(value) = resolve(name).filter(|value| !value.is_empty()) {
            environment.insert(OsString::from(name), value);
        }
    }
    let directory = Path::new(&spec.executable).parent()
        .ok_or_else(|| error("Stdio extension executable has no directory"))?;
    let mut path = directory.as_os_str().to_owned();
    if cfg!(windows) {
        // Without an exact SystemRoot, system components would resolve
        // `\System32` against the current drive.
        let root = environment.get(&OsString::from("SystemRoot")).cloned()
            .filter(|root| root.to_str().is_some_and(|raw| valid_path(raw, false)))
            .ok_or_else(|| error("The bridge environment has no valid SystemRoot"))?;
        path.push(";"); path.push(&root); path.push("\\System32;"); path.push(&root);
    } else {
        path.push(":/usr/bin:/bin");
    }
    if spec.inherit_path {
        // System directories stay first, so the inherited entries cannot
        // shadow them.
        let inherited = resolve("PATH")
            .filter(|value| !value.is_empty() && value.len() <= 32 * 1024 && !value.as_encoded_bytes().contains(&0))
            .ok_or_else(|| error("The bridge environment has no usable PATH to inherit"))?;
        path.push(if cfg!(windows) { ";" } else { ":" });
        path.push(&inherited);
        // Windows refuses an environment value above 32 767 characters.
        if path.len() > 32_767 {
            return Err(error("The bridge environment has no usable PATH to inherit"));
        }
    }
    environment.insert(OsString::from("PATH"), path);
    for (name, source) in &spec.env {
        let value = resolve(source).ok_or_else(|| error("A configured stdio extension variable is unavailable"))?;
        let bytes = value.as_encoded_bytes();
        if bytes.is_empty() || bytes.len() > 8192 || bytes.contains(&0) {
            return Err(error("A configured stdio extension variable exceeds its bounds"));
        }
        environment.insert(OsString::from(name), value);
    }
    let total = environment.iter()
        .map(|(name, value)| name.len() + value.len() + 2)
        .fold(0usize, usize::saturating_add);
    if total > 64 * 1024 { return Err(error("Stdio extension environment exceeds its byte budget")); }
    Ok(environment)
}

static LIVE_SESSIONS: AtomicUsize = AtomicUsize::new(0);

/// True when no live-session slot is free now.
pub(crate) fn slots_exhausted() -> bool { LIVE_SESSIONS.load(Ordering::SeqCst) >= MAX_LIVE_SESSIONS }

/// One of the process-wide live stdio session slots.
pub(crate) struct SessionSlot(());

impl SessionSlot {
    pub(crate) fn acquire() -> Result<Self> {
        let mut live = LIVE_SESSIONS.load(Ordering::SeqCst);
        loop {
            if live >= MAX_LIVE_SESSIONS {
                return Err(error("Too many stdio extensions are running; try again later"));
            }
            match LIVE_SESSIONS.compare_exchange_weak(live, live + 1, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => return Ok(Self(())),
                Err(current) => live = current,
            }
        }
    }
}

impl Drop for SessionSlot {
    fn drop(&mut self) { LIVE_SESSIONS.fetch_sub(1, Ordering::SeqCst); }
}

/// Child diagnostics: a byte count and the last 4 KiB. They are never put
/// into a tool result or the journal; only the local refresh check reports
/// the count.
#[derive(Default)]
pub(crate) struct StderrTail {
    pub(crate) bytes: u64,
    tail: VecDeque<u8>,
}

impl StderrTail {
    pub(crate) fn push(&mut self, chunk: &[u8]) {
        self.bytes = self.bytes.saturating_add(chunk.len() as u64);
        self.tail.extend(chunk);
        let excess = self.tail.len().saturating_sub(STDERR_TAIL_BYTES);
        self.tail.drain(..excess);
    }

    #[cfg(test)]
    fn tail(&self) -> Vec<u8> { self.tail.iter().copied().collect() }
}

/// Everything a launcher needs; the environment is exact, never inherited.
pub struct StdioLaunch<'a> {
    pub executable: &'a Path,
    pub arguments: &'a [String],
    pub cwd: &'a Path,
    pub environment: &'a BTreeMap<OsString, OsString>,
}

/// A contained child process. Reads and writes return `WouldBlock` when idle.
pub trait StdioChild: Send {
    fn read_stdout(&mut self, buf: &mut [u8]) -> io::Result<usize>;
    fn read_stderr(&mut self, buf: &mut [u8]) -> io::Result<usize>;
    fn write_stdin(&mut self, buf: &[u8]) -> io::Result<usize>;
    fn close_stdin(&mut self);
    fn terminate(&mut self) -> io::Result<()>;
    /// True once the child has exited and been reaped.
    fn finish(&mut self) -> io::Result<bool>;
}

/// Starts contained children; implemented by the CLI per platform.
pub trait StdioLauncher: Send + Sync {
    fn launch(&self, launch: &StdioLaunch) -> io::Result<Box<dyn StdioChild>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(executable: &str) -> StdioSpec {
        StdioSpec { executable: executable.into(), executable_sha256: "a".repeat(64), args: vec![],
            env: BTreeMap::new(), cwd: None, inherit_path: false }
    }

    #[cfg(windows)]
    const EXE: &str = "C:\\Tools\\example\\example-mcp.exe";
    #[cfg(not(windows))]
    const EXE: &str = "/opt/example/example-mcp";

    #[test]
    fn stdio_environment_is_exact_and_missing_reference_fails() {
        let mut with_ref = spec(EXE);
        with_ref.env.insert("EXAMPLE_TOKEN".into(), "AGENT_BRIDGE_EXTENSION_EXAMPLE_TOKEN".into());
        with_ref.validate().unwrap();
        let source: BTreeMap<&str, &str> = BTreeMap::from([
            ("SystemRoot", "C:\\Windows"), ("TEMP", "C:\\Temp"), ("HOME", "/home/example"), ("LANG", "C"),
            ("PATH", "/should/not/leak"), ("NODE_OPTIONS", "--require=/x"), ("SECRET_OTHER", "leak"),
            ("AGENT_BRIDGE_EXTENSION_EXAMPLE_TOKEN", "fixture-only-value"), ("EXAMPLE_TOKEN", "parent-leak"),
        ]);
        let resolve = |name: &str| source.get(name).map(OsString::from);
        let environment = child_environment(&with_ref, &resolve).unwrap();
        let mut expected = BTreeMap::new();
        if cfg!(windows) {
            expected.insert("SystemRoot", "C:\\Windows".to_owned());
            expected.insert("TEMP", "C:\\Temp".to_owned());
            expected.insert("PATH", "C:\\Tools\\example;C:\\Windows\\System32;C:\\Windows".to_owned());
        } else {
            expected.insert("HOME", "/home/example".to_owned());
            expected.insert("LANG", "C".to_owned());
            expected.insert("PATH", "/opt/example:/usr/bin:/bin".to_owned());
        }
        expected.insert("EXAMPLE_TOKEN", "fixture-only-value".to_owned());
        let expected: BTreeMap<OsString, OsString> = expected.into_iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v))).collect();
        assert_eq!(environment, expected);

        // A missing, empty, oversized or NUL reference fails before launch
        // without naming the variable or echoing the value.
        for value in [None, Some(String::new()), Some("x".repeat(8193)), Some("a\0b".to_owned())] {
            let resolve = |name: &str| if name.starts_with("AGENT_BRIDGE_EXTENSION_") {
                value.clone().map(OsString::from) } else { source.get(name).map(OsString::from) };
            let failure = child_environment(&with_ref, &resolve).unwrap_err().to_string();
            assert!(!failure.contains("EXAMPLE") && !failure.contains("xxxx"), "{failure}");
            assert!(failure.contains("stdio extension variable"), "{failure}");
        }

        // On Windows a missing, relative or list-shaped SystemRoot refuses the
        // launch instead of letting `\System32` resolve against the drive.
        if cfg!(windows) {
            for root in [None, Some("Windows"), Some("C:\\Windows;C:\\Evil")] {
                let resolve = |name: &str| if name == "SystemRoot" { root.map(OsString::from) }
                    else { source.get(name).map(OsString::from) };
                assert!(child_environment(&with_ref, &resolve).is_err(), "{root:?}");
            }
        }

        // Opting in appends the bridge PATH after the fixed directories and
        // changes nothing else; without a usable bridge PATH it refuses.
        let mut inheriting = with_ref.clone();
        inheriting.inherit_path = true;
        let mut widened = expected.clone();
        let fixed = widened[&OsString::from("PATH")].clone();
        let mut path = fixed; path.push(if cfg!(windows) { ";/should/not/leak" } else { ":/should/not/leak" });
        widened.insert(OsString::from("PATH"), path);
        assert_eq!(child_environment(&inheriting, &resolve).unwrap(), widened);
        for value in [None, Some(String::new()), Some("x".repeat(32 * 1024 + 1)), Some("a\0b".to_owned())] {
            let resolve = |name: &str| if name == "PATH" { value.clone().map(OsString::from) }
                else { source.get(name).map(OsString::from) };
            let failure = child_environment(&inheriting, &resolve).unwrap_err().to_string();
            assert!(failure.contains("no usable PATH"), "{failure}");
        }
        // The default keeps the serialized form, hence every existing pin.
        let encoded = serde_json::to_value(&with_ref).unwrap();
        assert!(encoded.get("inherit_path").is_none());
        assert_eq!(serde_json::to_value(&inheriting).unwrap()["inherit_path"], true);
    }

    #[test]
    fn stderr_tail_keeps_count_and_last_bytes() {
        let mut tail = StderrTail::default();
        tail.push(&[b'a'; 5000]);
        tail.push(b"end");
        assert_eq!(tail.bytes, 5003);
        let kept = tail.tail();
        assert_eq!(kept.len(), STDERR_TAIL_BYTES);
        assert!(kept.ends_with(b"aend"));
    }
}
