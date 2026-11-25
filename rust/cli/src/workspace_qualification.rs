//! Fail-closed, read-only qualification of an operator-selected workstation root.
//! Runs BEFORE opening Core SQLite or exposing workstation tools. It does not
//! change permissions, create directories, execute programs or open DB files.
//!
//! Windows physical-directory/reparse checks follow the established lifecycle
//! primitive (symlink_metadata + FILE_ATTRIBUTE_REPARSE_POINT). As elsewhere in
//! the repository, this is a preflight validation, not a cross-process lock:
//! a malicious concurrent filesystem rename cannot be made atomic with a
//! later open solely through path-based checks.

use std::env;
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

const MAX_PATH_BYTES: usize = 4096;

#[derive(Debug)]
pub(super) struct WorkspaceError {
    code: &'static str,
    detail: String,
}
impl WorkspaceError {
    fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self { code, detail: detail.into() }
    }
}
impl fmt::Display for WorkspaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}
impl Error for WorkspaceError {}

type Result<T> = std::result::Result<T, WorkspaceError>;

fn fail(code: &'static str, message: impl Into<String>) -> WorkspaceError {
    WorkspaceError::new(code, message)
}

/// The returned path retains ordinary Windows drive syntax (not \\?\), which
/// is required by agent_bridge_desktop::DesktopFiles::open. Path comparisons
/// below use physical canonicalized locations and case-insensitive components
/// on Windows; unrelated sibling directories never compare as ancestors.
pub(super) fn qualify(
    selected: &Path,
    database_path: &Path,
    settings: Option<&Path>,
) -> Result<PathBuf> {
    let workspace = parse_normal_workspace(selected)?;
    inspect_physical_directory_chain(&workspace)?;
    let physical = canonical_directory(&workspace, "WORKSPACE_UNAVAILABLE")?;
    let workspace_key = compare_key(&physical)?;
    if !same_key(&compare_key(&workspace)?, &workspace_key) {
        return Err(fail("WORKSPACE_NONCANONICAL",
            "Selected folder is not its normal physical path (alias, substitution or link); choose the real absolute directory"));
    }
    let home = canonical_directory(&operator_home()?, "OPERATOR_DIRECTORY_UNAVAILABLE")?;
    if is_ancestor_or_same(&workspace_key, &compare_key(&home)?) {
        return Err(fail("WORKSPACE_OPERATOR_DIRECTORY",
            "The selected workspace is the operator's home folder or an ancestor of it; select a project subdirectory instead"));
    }
    let db_parent = database_path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    reject_overlap(&workspace_key, db_parent, "WORKSPACE_OVERLAPS_DATABASE",
        "the directory containing the SQLite database")?;
    // A database file can be a symlink into a different directory. Resolve an
    // existing file too; do not open or read its contents.
    match fs::symlink_metadata(database_path) {
        Ok(md) => {
            if !md.is_file() || md.file_type().is_symlink() || is_reparse(&md) {
                return Err(fail("WORKSPACE_DATABASE_UNSAFE",
                    "SQLite database must be a regular non-reparse file for workspace qualification"));
            }
            let physical_db_file = fs::canonicalize(database_path).map_err(|e|
                fail("WORKSPACE_DATABASE_UNAVAILABLE", format!("Cannot resolve database file: {e}")))?;
            let real_parent = physical_db_file.parent().ok_or_else(||
                fail("WORKSPACE_DATABASE_UNAVAILABLE", "Resolved database has no parent directory"))?;
            reject_overlap(&workspace_key, real_parent, "WORKSPACE_OVERLAPS_DATABASE",
                "the physical SQLite database directory")?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // The core open_existing call will separately report a missing DB.
        }
        Err(e) => return Err(fail("WORKSPACE_DATABASE_UNAVAILABLE",
            format!("Cannot inspect SQLite database file without opening it: {e}"))),
    }

    if let Some(private) = settings {
        reject_overlap(&workspace_key, private, "WORKSPACE_OVERLAPS_SETTINGS",
            "private Bridge operator settings")?;
    }

    let executable = env::current_exe().map_err(|e|
        fail("WORKSPACE_EXECUTABLE_UNAVAILABLE", format!("Cannot locate the current executable: {e}")))?;
    let executable_directory = executable.parent().ok_or_else(||
        fail("WORKSPACE_EXECUTABLE_UNAVAILABLE", "Current executable has no containing directory"))?;
    reject_overlap(&workspace_key, executable_directory, "WORKSPACE_OVERLAPS_EXECUTABLE",
        "the directory containing the running agent-bridge executable")?;

    // Double-check the selected physical path just before returning it to the
    // caller. The caller still needs capability-based open-time validation.
    inspect_physical_directory_chain(&workspace)?;
    if !same_key(&compare_key(&canonical_directory(&workspace, "WORKSPACE_CHANGED")?)?, &workspace_key) {
        return Err(fail("WORKSPACE_CHANGED",
            "Selected directory changed while qualification was in progress"));
    }
    Ok(workspace)
}

fn reject_overlap(
    workspace: &[String],
    reference: &Path,
    code: &'static str,
    description: &str,
) -> Result<()> {
    let other = canonical_directory(reference, "WORKSPACE_REFERENCE_UNAVAILABLE")?;
    let other_key = compare_key(&other)?;
    if is_ancestor_or_same(workspace, &other_key)
        || is_ancestor_or_same(&other_key, workspace)
    {
        return Err(fail(code, format!(
            "Workspace must not contain or be inside {description} ({})", other.display()
        )));
    }
    Ok(())
}

/// Compare complete path components, never byte-string prefixes.
fn is_ancestor_or_same(candidate: &[String], descendant: &[String]) -> bool {
    candidate.len() <= descendant.len()
        && candidate.iter().zip(descendant).all(|(a, b)| same_component(a, b))
}

fn same_key(a: &[String], b: &[String]) -> bool {
    a.len() == b.len() && is_ancestor_or_same(a, b)
}

#[cfg(windows)]
fn same_component(a: &str, b: &str) -> bool {
    #[link(name = "kernel32")]
    extern "system" {
        fn CompareStringOrdinal(left: *const u16, left_len: i32,
            right: *const u16, right_len: i32, ignore_case: i32) -> i32;
    }
    let left: Vec<u16> = a.encode_utf16().collect();
    let right: Vec<u16> = b.encode_utf16().collect();
    if left.len() > i32::MAX as usize || right.len() > i32::MAX as usize {
        return true; // Fail closed if Windows cannot compare lengths.
    }
    // SAFETY: live UTF-16 buffers with exact element counts. 2 means equal;
    // 0 means system failure, conservatively treated as possibly equal.
    let result = unsafe {
        CompareStringOrdinal(left.as_ptr(), left.len() as i32,
            right.as_ptr(), right.len() as i32, 1)
    };
    result == 2 || result == 0
}

#[cfg(not(windows))]
fn same_component(a: &str, b: &str) -> bool { a == b }

fn canonical_directory(path: &Path, code: &'static str) -> Result<PathBuf> {
    let physical = fs::canonicalize(path).map_err(|e| fail(
        code, format!("Cannot resolve directory {}: {e}", path.display())
    ))?;
    let metadata = fs::metadata(&physical).map_err(|e| fail(
        code, format!("Cannot inspect directory {}: {e}", path.display())
    ))?;
    if !metadata.is_dir() {
        return Err(fail(code, format!("Not a directory: {}", path.display())));
    }
    Ok(physical)
}

fn inspect_physical_directory_chain(path: &Path) -> Result<()> {
    // The root is checked too. A Windows reparse point anywhere in the chain
    // is refused (including junctions), not silently followed.
    for component in path.ancestors() {
        let md = fs::symlink_metadata(component).map_err(|e| fail(
            "WORKSPACE_UNAVAILABLE",
            format!("Selected directory or ancestor {} unavailable: {e}", component.display()),
        ))?;
        if !md.is_dir() || md.file_type().is_symlink() || is_reparse(&md) {
            return Err(fail("WORKSPACE_LINK_OR_REPARSE",
                format!("Linked, reparse, special or non-directory workspace component: {}",
                    component.display())));
        }
    }
    Ok(())
}

#[cfg(windows)]
fn is_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x0000_0400 != 0
}
#[cfg(not(windows))]
fn is_reparse(_metadata: &fs::Metadata) -> bool { false }

#[cfg(windows)]
fn parse_normal_workspace(raw: &Path) -> Result<PathBuf> {
    let text = raw.to_str().ok_or_else(||
        fail("WORKSPACE_NON_NORMAL", "Workspace path must use valid Unicode"))?;
    if text.len() > MAX_PATH_BYTES || !raw.is_absolute() {
        return Err(fail("WORKSPACE_NOT_ABSOLUTE",
            "Select an absolute local drive path, for example C:\\Users\\...\\project"));
    }
    let normal = text.replace('/', "\\");
    let bytes = normal.as_bytes();
    if bytes.len() < 3 || !bytes[0].is_ascii_alphabetic()
        || bytes[1] != b':' || bytes[2] != b'\\'
        || normal.starts_with(r"\\")
    {
        return Err(fail("WORKSPACE_NON_NORMAL",
            "Only ordinary absolute drive paths are supported (not UNC, device, verbatim or drive-relative paths)"));
    }
    if bytes.len() == 3 {
        return Err(fail("WORKSPACE_VOLUME_ROOT",
            "A volume root is not a workspace; select a real project directory"));
    }
    for component in normal[3..].split('\\') {
        if !valid_windows_component(component) {
            return Err(fail("WORKSPACE_NON_NORMAL",
                "Workspace path contains empty, dot, parent, reserved, or non-normal components"));
        }
    }
    Ok(PathBuf::from(normal))
}

#[cfg(windows)]
fn valid_windows_component(name: &str) -> bool {
    if name.is_empty() || matches!(name, "." | "..")
        || name.ends_with(' ') || name.ends_with('.')
        || name.chars().any(|c| c.is_control() || "<>:\"/\\|?*".contains(c))
    {
        return false;
    }
    let stem = name.split('.').next().unwrap_or("").to_ascii_uppercase();
    if matches!(stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$")
    {
        return false;
    }
    !(stem.len() == 4 &&
        (stem.starts_with("COM") || stem.starts_with("LPT")) &&
        matches!(stem.as_bytes()[3], b'1'..=b'9'))
}

#[cfg(not(windows))]
fn parse_normal_workspace(raw: &Path) -> Result<PathBuf> {
    let text = raw.to_str().ok_or_else(||
        fail("WORKSPACE_NON_NORMAL", "Workspace path must use valid UTF-8"))?;
    if text.len() > MAX_PATH_BYTES || !raw.is_absolute() {
        return Err(fail("WORKSPACE_NOT_ABSOLUTE", "Select an absolute project directory"));
    }
    if text.starts_with("//") || text.ends_with('/')
        || text.split('/').skip(1).any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(fail("WORKSPACE_NON_NORMAL",
            "Workspace must not contain redundant, dot, parent or trailing separators"));
    }
    if raw.file_name().is_none() {
        return Err(fail("WORKSPACE_VOLUME_ROOT", "Filesystem root is not a workspace"));
    }
    Ok(raw.to_path_buf())
}

#[cfg(windows)]
fn compare_key(path: &Path) -> Result<Vec<String>> {
    // Canonical Windows paths commonly use \\?\C:\...; normalize that
    // OS-returned prefix for comparisons but NEVER accept it from the user.
    let raw = path.to_str().ok_or_else(||
        fail("WORKSPACE_NON_NORMAL", "Cannot compare a non-Unicode path"))?;
    let normalized = raw.replace('/', "\\");
    let value = normalized.strip_prefix(r"\\?\").unwrap_or(&normalized);
    let bytes = value.as_bytes();
    if bytes.len() < 3 || !bytes[0].is_ascii_alphabetic()
        || bytes[1] != b':' || bytes[2] != b'\\'
    {
        return Err(fail("WORKSPACE_UNSUPPORTED_VOLUME",
            "Cannot compare this volume type with a local Windows workspace"));
    }
    let mut key = vec![value[..2].to_ascii_lowercase()];
    let rest = value[3..].trim_end_matches('\\');
    if !rest.is_empty() {
        key.extend(rest.split('\\').map(str::to_lowercase));
    }
    Ok(key)
}

#[cfg(not(windows))]
fn compare_key(path: &Path) -> Result<Vec<String>> {
    let text = path.to_str().ok_or_else(||
        fail("WORKSPACE_NON_NORMAL", "Cannot compare a non-UTF8 path"))?;
    if !path.is_absolute() {
        return Err(fail("WORKSPACE_NON_NORMAL", "Cannot compare a relative path"));
    }
    Ok(text.split('/').filter(|part| !part.is_empty()).map(str::to_owned).collect())
}

#[cfg(windows)]
fn operator_home() -> Result<PathBuf> {
    // FOLDERID_Profile: {5E6C858F-0E22-4760-9AFE-EA3317B67173}.
    // Resolve via Windows Known Folders, not mutable USERPROFILE variables.
    use std::ffi::{c_void, OsString};
    use std::os::windows::ffi::OsStringExt;
    use std::ptr;
    #[repr(C)]
    struct Guid { a: u32, b: u16, c: u16, d: [u8;8] }
    const PROFILE: Guid = Guid {
        a: 0x5e6c858f, b: 0x0e22, c: 0x4760,
        d: [0x9a,0xfe,0xea,0x33,0x17,0xb6,0x71,0x73],
    };
    #[link(name = "shell32")]
    extern "system" {
        fn SHGetKnownFolderPath(folder: *const Guid, flags: u32,
            token: *mut c_void, out: *mut *mut u16) -> i32;
    }
    #[link(name = "ole32")]
    extern "system" {
        fn CoTaskMemFree(ptr: *mut c_void);
    }
    let mut pointer: *mut u16 = ptr::null_mut();
    // SAFETY: PROFILE has the Win32 GUID ABI; Windows allocates the returned
    // null-terminated buffer and CoTaskMemFree releases it in every case.
    let hr = unsafe { SHGetKnownFolderPath(&PROFILE, 0, ptr::null_mut(), &mut pointer) };
    if hr < 0 || pointer.is_null() {
        if !pointer.is_null() { unsafe { CoTaskMemFree(pointer.cast()); } }
        return Err(fail("OPERATOR_DIRECTORY_UNAVAILABLE",
            "Windows could not resolve the operator's known Profile directory"));
    }
    let mut len=0usize;
    unsafe {
        while len < 32768 && *pointer.add(len) != 0 { len += 1; }
    }
    let path = if len == 32768 {
        None
    } else {
        // SAFETY: length bounded above, pointer is allocated and remains live.
        Some(OsString::from_wide(unsafe { std::slice::from_raw_parts(pointer, len) }))
    };
    unsafe { CoTaskMemFree(pointer.cast()); }
    let path = path.ok_or_else(||fail("OPERATOR_DIRECTORY_UNAVAILABLE",
        "Windows operator profile directory is invalid"))?;
    Ok(PathBuf::from(path))
}

#[cfg(not(windows))]
fn operator_home() -> Result<PathBuf> {
    let value=env::var_os("HOME").ok_or_else(||
        fail("OPERATOR_DIRECTORY_UNAVAILABLE", "HOME is unavailable; refusing broad workspace"))?;
    let path=PathBuf::from(value);
    if !path.is_absolute() {
        return Err(fail("OPERATOR_DIRECTORY_UNAVAILABLE",
            "HOME must be absolute to qualify the workspace"));
    }
    Ok(path)
}