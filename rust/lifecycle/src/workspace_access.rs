// Copyright 2026 Agent Bridge contributors. Apache-2.0.
//! Read-only Windows direct-access inspection for a qualified project directory.
//!
//! Derives a Low-integrity (`S-1-16-4096`), Restricted Code (`S-1-5-12`),
//! privilege-disabled (`DISABLE_MAX_PRIVILEGE`) impersonation token from the
//! current non-elevated process token and probes four exact directory handle
//! rights on a fresh, ephemeral OS thread without modifying ACLs or creating
//! any file or process.
//!
//! Scope boundary: a report describes ONLY direct handle-open rights on the
//! inspected directory itself. It is never proof of process confinement and
//! never attests permissions on existing files or subdirectories inside it.

use serde::Serialize;
use std::io;
use std::path::Path;

/// Fixed scope identifier emitted in every [`ProjectAccessReport`].
pub const REPORT_SCOPE: &str = "direct_directory_rights_only";

/// Fixed token profile identifier emitted in every [`ProjectAccessReport`].
pub const TOKEN_PROFILE: &str = "low_integrity_restricted_code_disable_max_privilege";

/// Outcome of probing one exact directory access right under the derived
/// Low-integrity restricted token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RightAccess {
    /// Directory handle opened with the requested right and verified to match
    /// the exact same real, non-reparse directory identity.
    Allowed,
    /// Access was denied after the token resolved the same directory.
    Denied,
    /// The path, identity, or cause of the denial could not be established.
    Unknown { os_error: Option<i32>, reason: &'static str },
}

/// Direct handle-open rights probed on the target directory itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DirectoryRightsProbe {
    /// `FILE_LIST_DIRECTORY` (`0x0001`).
    pub list_directory: RightAccess,
    /// `FILE_TRAVERSE` (`0x0020`).
    pub traverse: RightAccess,
    /// `FILE_ADD_FILE` (`0x0002`).
    pub add_file: RightAccess,
    /// `FILE_ADD_SUBDIRECTORY` (`0x0004`).
    pub add_subdirectory: RightAccess,
}

/// Serializable result of [`inspect_project_access`].
///
/// Describes only direct handle rights on `path`; does not prove process
/// confinement or report permissions on existing files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProjectAccessReport {
    pub path: String,
    pub scope: &'static str,
    pub token_profile: &'static str,
    pub direct_directory_rights: DirectoryRightsProbe,
}

/// Inspects direct access rights on an existing, already-qualified project
/// directory using a derived Low-integrity Restricted Code token with
/// privileges disabled.
///
/// Returns `ErrorKind::Unsupported` on non-Windows platforms.
pub fn inspect_project_access(path: &Path) -> io::Result<ProjectAccessReport> {
    #[cfg(windows)]
    {
        imp::inspect_project_access(path)
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "direct project directory access inspection is only supported on Windows",
        ))
    }
}

#[cfg(windows)]
pub use imp::PinnedProjectDirectory;

/// Reuse the EXACT existing restricted-token construction for a primary token;
/// no alternate/nonrestricted process creation path may use this API.
#[cfg(windows)]
pub(crate) use imp::PrimaryRestrictedToken;
#[cfg(windows)]
pub(crate) fn primary_restricted_token(project: &PinnedProjectDirectory) -> io::Result<PrimaryRestrictedToken> {
    imp::make_primary_restricted_token(project)
}

/// Derive a stable SID for an existing, physically qualified Windows project.
///
/// Hash the domain tag, normalized physical DOS path (lowercase UTF-16LE),
/// and tagged volume and file ID from the pinned directory handle. The
/// eight 32-bit words of the digest identify the project under S-1-0.
/// Only the restricted SID list receives this SID. No profile is created.
/// Never grant project access to the collective Restricted Code SID S-1-5-12.
///
/// Project moves or normalization changes require reevaluating the SID and
/// operator ACLs. Call this function to display the exact planned SID.
pub fn project_read_sid(path: &Path) -> io::Result<String> {
    #[cfg(windows)]
    {
        imp::project_read_sid(path)
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err(io::Error::new(io::ErrorKind::Unsupported,
            "project read SID is only available on Windows"))
    }
}
/// Execute direct-access probes on a new short-lived thread impersonating a
/// duplicate of the SAME restricted primary token used by process creation.
#[cfg(windows)]
pub(crate) fn probe_with_primary_token<T, F>(
    token: &PrimaryRestrictedToken,
    probe: F,
) -> io::Result<T>
where
    F: FnOnce() -> io::Result<T> + Send + 'static,
    T: Send + 'static,
{
    imp::probe_with_primary_token(token, probe)
}

#[cfg(windows)]
mod imp {
    use super::{
        DirectoryRightsProbe, ProjectAccessReport, RightAccess, REPORT_SCOPE, TOKEN_PROFILE,
    };
    use std::ffi::{c_void, OsStr, OsString};
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::io;
    use std::mem::{size_of, zeroed};
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::os::windows::fs::MetadataExt;
    use std::path::{Component, Path, Prefix};
    use std::ptr;
    use std::thread;
    use windows_sys::Win32::Foundation::{
        CloseHandle, LocalFree, ERROR_ACCESS_DENIED, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSidToSidW,
    };
    use windows_sys::Win32::Security::{
        CreateRestrictedToken, DuplicateTokenEx, GetLengthSid, GetTokenInformation, IsTokenRestricted, RevertToSelf,
        SecurityImpersonation, SetTokenInformation, TokenElevation,
        TokenImpersonation, TokenPrimary, TokenType, TokenIntegrityLevel, TokenUser, DISABLE_MAX_PRIVILEGE,
        SID_AND_ATTRIBUTES, TOKEN_ADJUST_DEFAULT, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_ELEVATION,
        TOKEN_IMPERSONATE, TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FileIdInfo, GetFileInformationByHandle, GetFileInformationByHandleEx,
        GetFinalPathNameByHandleW, BY_HANDLE_FILE_INFORMATION, FILE_ADD_FILE,
        FILE_ADD_SUBDIRECTORY, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO,
        FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, FILE_TRAVERSE, OPEN_EXISTING,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken, SetThreadToken};

    const SE_GROUP_INTEGRITY: u32 = 0x0000_0020;
    const VOLUME_NAME_DOS: u32 = 0;
    const RESTRICTED_CODE_SID: &str = "S-1-5-12";
    const LOW_INTEGRITY_SID: &str = "S-1-16-4096";
    const SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    const OPEN_DIR_NO_REPARSE: u32 = FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT;

    struct OwnedHandle(HANDLE);

    // SAFETY: Win32 kernel HANDLEs are process-wide and safe to move to the
    // ephemeral probe thread when exclusively owned.
    unsafe impl Send for OwnedHandle {}

    impl OwnedHandle {
        fn new(raw: HANDLE) -> io::Result<Self> {
            if raw.is_null() || raw == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }
            Ok(Self(raw))
        }

        fn as_raw(&self) -> HANDLE {
            self.0
        }
    }

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
    }

    struct LocalSid(*mut c_void);

    impl LocalSid {
        fn from_str(sddl_sid: &str) -> io::Result<Self> {
            let wide = wide_os(OsStr::new(sddl_sid))?;
            let mut sid: *mut c_void = ptr::null_mut();
            if unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut sid) } == 0 || sid.is_null() {
                return Err(io::Error::last_os_error());
            }
            Ok(Self(sid))
        }

        fn as_ptr(&self) -> *mut c_void {
            self.0
        }
    }

    impl Drop for LocalSid {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    LocalFree(self.0);
                }
            }
        }
    }

    // Restricting identity in the Null authority, with a namespace-specific
    // digest. This neither creates an account nor grants ordinary token rights.
    fn project_sid_text(project: &PinnedProjectDirectory) -> io::Result<String> {
        let normalized = project.display_path.to_lowercase();
        if normalized.is_empty() || normalized.contains('\0') {
            return Err(io::Error::new(io::ErrorKind::InvalidInput,
                "canonical project path is invalid"));
        }
        let mut sha = Sha256::new();
        sha.update(b"agent-bridge.project-read.v1\0");
        for word in normalized.encode_utf16() {
            sha.update(word.to_le_bytes());
        }
        // Two distinct directories can share a case-folded name. Also
        // distinguish a new workspace created at an old approved path.
        match project.identity {
            DirectoryIdentity::Extended { volume, file_id } => {
                sha.update([1]);
                sha.update(volume.to_le_bytes());
                sha.update(file_id.to_le_bytes());
            }
            DirectoryIdentity::Legacy { volume, file_index } => {
                sha.update([2]);
                sha.update(volume.to_le_bytes());
                sha.update(file_index.to_le_bytes());
            }
        }
        let mut sid = String::from("S-1-0");
        for chunk in sha.finalize().chunks_exact(4) {
            let rid = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            sid.push_str(&format!("-{rid}"));
        }
        Ok(sid)
    }

    // The CLI can show exactly which SID the Git launcher plans. This reads
    // only the workspace path/handle metadata and does not create a profile.
    pub(super) fn project_read_sid(path: &Path) -> io::Result<String> {
        let project = qualify_target_directory(path)?;
        project_sid_text(&project)
    }

    struct ThreadImpersonationGuard {
        active: bool,
    }

    impl ThreadImpersonationGuard {
        fn enter(token: &OwnedHandle) -> io::Result<Self> {
            if unsafe { SetThreadToken(ptr::null(), token.as_raw()) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self { active: true })
        }

        fn revert(mut self) -> io::Result<()> {
            self.active = false;
            if unsafe { RevertToSelf() } == 0 {
                let err = io::Error::last_os_error();
                unsafe {
                    let _ = SetThreadToken(ptr::null(), ptr::null_mut());
                }
                return Err(err);
            }
            Ok(())
        }
    }

    impl Drop for ThreadImpersonationGuard {
        fn drop(&mut self) {
            if self.active {
                self.active = false;
                unsafe {
                    if RevertToSelf() == 0 {
                        let _ = SetThreadToken(ptr::null(), ptr::null_mut());
                    }
                }
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum DirectoryIdentity {
        Extended { volume: u64, file_id: u128 },
        Legacy { volume: u32, file_index: u64 },
    }

    /// Holds the names of a local project and its ancestors against Windows
    /// rename/delete while path-based tools are using the selection.
    pub struct PinnedProjectDirectory {
        display_path: String,
        verbatim_wide: Vec<u16>,
        identity: DirectoryIdentity,
        _path_handles: Vec<OwnedHandle>,
    }

    impl PinnedProjectDirectory {
        pub fn open(path: &Path) -> io::Result<Self> {
            qualify_target_directory(path)
        }
    }

    pub(super) fn inspect_project_access(path: &Path) -> io::Result<ProjectAccessReport> {
        let target = qualify_target_directory(path)?;
        let impersonation_token = build_low_restricted_impersonation_token()?;

        let probe_wide = target.verbatim_wide.clone();
        let expected_identity = target.identity;

        let worker = thread::Builder::new()
            .name("ab-workspace-access".to_owned())
            .spawn(move || -> io::Result<DirectoryRightsProbe> {
                let guard = ThreadImpersonationGuard::enter(&impersonation_token)?;
                let probe_result = (|| -> io::Result<DirectoryRightsProbe> {
                    let list_directory =
                        probe_right(&probe_wide, FILE_LIST_DIRECTORY, expected_identity)?;
                    let traverse = probe_right(&probe_wide, FILE_TRAVERSE, expected_identity)?;
                    let add_file = probe_right(&probe_wide, FILE_ADD_FILE, expected_identity)?;
                    let add_subdirectory =
                        probe_right(&probe_wide, FILE_ADD_SUBDIRECTORY, expected_identity)?;
                    Ok(DirectoryRightsProbe {
                        list_directory,
                        traverse,
                        add_file,
                        add_subdirectory,
                    })
                })();
                let revert_result = guard.revert();
                match (probe_result, revert_result) {
                    (Ok(rights), Ok(())) => Ok(rights),
                    (Err(err), _) => Err(err),
                    (Ok(_), Err(revert_err)) => Err(revert_err),
                }
            })?;

        let rights = worker.join().map_err(|_| {
            io::Error::new(
                io::ErrorKind::Other,
                "project directory access inspection thread panicked",
            )
        })??;

        // Re-verify after probing so any concurrent directory swap or reparse
        // point substitution during a Denied probe is rejected as ambiguous.
        let post = qualify_target_directory(path)?;
        if post.identity != target.identity
            || !post.display_path.eq_ignore_ascii_case(&target.display_path)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "project directory identity changed during access inspection",
            ));
        }

        Ok(ProjectAccessReport {
            path: target.display_path,
            scope: REPORT_SCOPE,
            token_profile: TOKEN_PROFILE,
            direct_directory_rights: rights,
        })
    }

    fn wide_os(value: &OsStr) -> io::Result<Vec<u16>> {
        let mut units: Vec<u16> = value.encode_wide().collect();
        if units.is_empty() || units.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid Windows string containing NUL or empty value",
            ));
        }
        units.push(0);
        Ok(units)
    }

    unsafe fn from_wide_ptr(value: *const u16) -> String {
        let mut len = 0usize;
        while len < 65536 && *value.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(value, len))
    }

    fn normalize_local_dos_path(raw: &str) -> io::Result<String> {
        let stripped = raw.strip_prefix(r"\\?\").unwrap_or(raw);
        let replaced = stripped.replace('/', r"\");
        let bytes = replaced.as_bytes();
        if bytes.len() < 3
            || !bytes[0].is_ascii_alphabetic()
            || bytes[1] != b':'
            || bytes[2] != b'\\'
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "qualified local Windows drive path required",
            ));
        }
        if replaced.len() > 3 {
            Ok(replaced.trim_end_matches('\\').to_owned())
        } else {
            Ok(replaced)
        }
    }

    fn check_non_reparse_ancestors(path: &Path) -> io::Result<()> {
        for ancestor in path.ancestors() {
            if ancestor.as_os_str().is_empty() {
                continue;
            }
            let md = fs::symlink_metadata(ancestor)?;
            if !md.is_dir()
                || md.file_type().is_symlink()
                || (md.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "reparse point or non-directory ancestor refused",
                ));
            }
        }
        Ok(())
    }

    fn qualify_target_directory(path: &Path) -> io::Result<PinnedProjectDirectory> {
        let raw_str = path.to_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "qualified project path must be valid UTF-8",
            )
        })?;
        if raw_str.is_empty() || !path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "absolute qualified project directory required",
            ));
        }

        let mut saw_local_disk_prefix = false;
        let mut saw_root = false;
        for component in path.components() {
            match component {
                Component::Prefix(prefix) => match prefix.kind() {
                    Prefix::Disk(_) | Prefix::VerbatimDisk(_) => saw_local_disk_prefix = true,
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "network, UNC, or device project directory refused",
                        ));
                    }
                },
                Component::RootDir => saw_root = true,
                Component::Normal(_) => {}
                Component::CurDir | Component::ParentDir => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "non-canonical relative segment in project directory refused",
                    ));
                }
            }
        }
        if !saw_local_disk_prefix || !saw_root {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "qualified local drive project directory required",
            ));
        }

        let expected_dos = normalize_local_dos_path(raw_str)?;
        check_non_reparse_ancestors(path)?;

        // Keep all names on the manual selection stable for the complete probe.
        // The handles request metadata access only and exclude delete sharing.
        let mut path_handles = Vec::new();
        let ancestors: Vec<_> = path.ancestors().collect();
        for ancestor in ancestors.into_iter().rev() {
            let wide = wide_os(ancestor.as_os_str())?;
            let handle = open_shared(&wide, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE)?;
            read_directory_identity(handle.as_raw())?;
            path_handles.push(handle);
        }
        let baseline = path_handles.last().ok_or_else(||
            io::Error::new(io::ErrorKind::InvalidInput, "missing project directory"))?;
        let identity = read_directory_identity(baseline.as_raw())?;
        let final_verbatim = final_verbatim_dos_path(baseline.as_raw())?;

        if final_verbatim
            .get(..8)
            .map(|p| p.eq_ignore_ascii_case(r"\\?\UNC\"))
            .unwrap_or(false)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "network-backed project directory refused",
            ));
        }
        let final_dos = normalize_local_dos_path(&final_verbatim)?;
        if !final_dos.eq_ignore_ascii_case(&expected_dos) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "project directory path does not match resolved final local path",
            ));
        }

        let verbatim_wide = wide_os(OsStr::new(&final_verbatim))?;
        Ok(PinnedProjectDirectory {
            display_path: final_dos,
            verbatim_wide,
            identity,
            _path_handles: path_handles,
        })
    }

    fn open_directory_handle(wide_path: &[u16], desired_access: u32) -> io::Result<OwnedHandle> {
        open_shared(wide_path, desired_access, SHARE_ALL)
    }

    fn open_shared(wide_path: &[u16], desired_access: u32, sharing: u32) -> io::Result<OwnedHandle> {
        let raw = unsafe {
            CreateFileW(
                wide_path.as_ptr(),
                desired_access,
                sharing,
                ptr::null(),
                OPEN_EXISTING,
                OPEN_DIR_NO_REPARSE,
                ptr::null_mut(),
            )
        };
        OwnedHandle::new(raw)
    }

    fn read_directory_identity(handle: HANDLE) -> io::Result<DirectoryIdentity> {
        let mut basic: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
        if unsafe { GetFileInformationByHandle(handle, &mut basic) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if basic.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "opened handle refers to a reparse point",
            ));
        }
        if basic.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "opened handle does not refer to a directory",
            ));
        }

        let mut extended: FILE_ID_INFO = unsafe { zeroed() };
        let ok = unsafe {
            GetFileInformationByHandleEx(
                handle,
                FileIdInfo,
                (&mut extended as *mut FILE_ID_INFO).cast(),
                size_of::<FILE_ID_INFO>() as u32,
            )
        };
        if ok != 0 {
            let file_id = u128::from_le_bytes(extended.FileId.Identifier);
            if file_id == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "zero Windows directory file ID",
                ));
            }
            return Ok(DirectoryIdentity::Extended {
                volume: extended.VolumeSerialNumber,
                file_id,
            });
        }

        let err = io::Error::last_os_error();
        if !matches!(err.raw_os_error(), Some(50) | Some(87)) {
            return Err(err);
        }
        let file_index =
            (u64::from(basic.nFileIndexHigh) << 32) | u64::from(basic.nFileIndexLow);
        if file_index == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "zero legacy Windows directory file index",
            ));
        }
        Ok(DirectoryIdentity::Legacy {
            volume: basic.dwVolumeSerialNumber,
            file_index,
        })
    }

    fn final_verbatim_dos_path(handle: HANDLE) -> io::Result<String> {
        let mut capacity = 1024usize;
        loop {
            let mut buf = vec![0u16; capacity];
            let len = unsafe {
                GetFinalPathNameByHandleW(
                    handle,
                    buf.as_mut_ptr(),
                    buf.len() as u32,
                    VOLUME_NAME_DOS,
                )
            } as usize;
            if len == 0 {
                return Err(io::Error::last_os_error());
            }
            if len < buf.len() {
                let path = OsString::from_wide(&buf[..len]);
                return path.into_string().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "resolved Windows path is not valid UTF-8",
                    )
                });
            }
            if len > 65536 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "resolved Windows path exceeds maximum length",
                ));
            }
            capacity = len + 1;
        }
    }

    fn verify_probe_handle(handle: &OwnedHandle, expected: DirectoryIdentity) -> io::Result<()> {
        let actual = read_directory_identity(handle.as_raw())?;
        if actual != expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "probed directory handle identity mismatch",
            ));
        }
        Ok(())
    }

    fn is_access_denied(err: &io::Error) -> bool {
        err.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32)
    }

    fn probe_right(
        wide_path: &[u16],
        exact_right: u32,
        expected: DirectoryIdentity,
    ) -> io::Result<RightAccess> {
        let verify = |handle: &OwnedHandle, result: RightAccess, reason| -> io::Result<RightAccess> {
            match verify_probe_handle(handle, expected) {
                Ok(()) => Ok(result),
                Err(e) if e.raw_os_error().is_some() || e.kind() == io::ErrorKind::Unsupported =>
                    Ok(RightAccess::Unknown { os_error: e.raw_os_error(), reason }),
                Err(e) => Err(e), // The opened object positively differs from the selected directory.
            }
        };
        match open_directory_handle(wide_path, exact_right) {
            Ok(handle) => {
                let reason = "opened_identity_unavailable";
                let first = verify(&handle, RightAccess::Allowed, reason)?;
                if !matches!(first, RightAccess::Unknown { .. }) { return Ok(first); }
                match open_directory_handle(wide_path, exact_right | FILE_READ_ATTRIBUTES) {
                    Ok(identified) => verify(&identified, RightAccess::Allowed, reason),
                    Err(_) => Ok(first),
                }
            }
            Err(e) if is_access_denied(&e) => {
                // The path can fail at a parent before the target directory is reached.
                let reason = "path_denied_target_unverified";
                match open_directory_handle(wide_path, 0) {
                    Ok(target) => verify(&target, RightAccess::Denied, reason),
                    Err(unresolved) => Ok(RightAccess::Unknown { os_error: unresolved.raw_os_error(), reason }),
                }
            }
            Err(e) => Ok(RightAccess::Unknown { os_error: e.raw_os_error(), reason: "open_failed" }),
        }
    }

    fn verify_non_elevated_interactive_token(token: HANDLE) -> io::Result<()> {
        let mut elevation: TOKEN_ELEVATION = unsafe { zeroed() };
        let mut count = 0u32;
        if unsafe {
            GetTokenInformation(
                token,
                TokenElevation,
                (&mut elevation as *mut TOKEN_ELEVATION).cast(),
                size_of::<TOKEN_ELEVATION>() as u32,
                &mut count,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if elevation.TokenIsElevated != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "refusing access inspection from an elevated Windows token",
            ));
        }

        let mut needed = 0u32;
        unsafe {
            GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut needed);
        }
        if needed == 0 || needed > 65536 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Windows user SID unavailable",
            ));
        }
        let word_count = (needed as usize + size_of::<usize>() - 1) / size_of::<usize>();
        let mut storage = vec![0usize; word_count];
        if unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                storage.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let raw_user = unsafe { &*(storage.as_ptr().cast::<TOKEN_USER>()) };
        let mut sid_ptr = ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(raw_user.User.Sid, &mut sid_ptr) } == 0
            || sid_ptr.is_null()
        {
            return Err(io::Error::last_os_error());
        }
        let sid = unsafe { from_wide_ptr(sid_ptr) };
        unsafe {
            LocalFree(sid_ptr.cast());
        }
        if !sid.starts_with("S-1-") || matches!(sid.as_str(), "S-1-5-18" | "S-1-5-19" | "S-1-5-20")
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "refusing access inspection from a non-interactive Windows service account",
            ));
        }
        Ok(())
    }

    // Canonical builder used by both the inspector and the Git-only process
    // launcher. Derived ONLY from the local non-elevated primary token, with
    // S-1-5-12 restricting SID, DISABLE_MAX_PRIVILEGE and Low IL.
    fn build_low_restricted_token(
        for_process: bool,
        project: Option<&LocalSid>,
    ) -> io::Result<OwnedHandle> {
        let mut raw_process_token: HANDLE = ptr::null_mut();
        if unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ADJUST_DEFAULT
                    | if for_process { TOKEN_ASSIGN_PRIMARY } else { 0 },
                &mut raw_process_token,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let process_token = OwnedHandle::new(raw_process_token)?;
        verify_non_elevated_interactive_token(process_token.as_raw())?;

        let restricted_sid = LocalSid::from_str(RESTRICTED_CODE_SID)?;
        let low_il_sid = LocalSid::from_str(LOW_INTEGRITY_SID)?;

        // Keep the original collective Restricted Code restriction. Only Git
        // adds a second, path-specific restricting SID. Neither SID is added
        // to normal token groups; no ACL is created or modified here.
        let mut sids_to_restrict = vec![SID_AND_ATTRIBUTES {
            Sid: restricted_sid.as_ptr(),
            Attributes: 0,
        }];
        if let Some(project_sid) = project {
            sids_to_restrict.push(SID_AND_ATTRIBUTES {
                Sid: project_sid.as_ptr(),
                Attributes: 0,
            });
        }
        let mut raw_restricted: HANDLE = ptr::null_mut();
        if unsafe {
            CreateRestrictedToken(
                process_token.as_raw(),
                DISABLE_MAX_PRIVILEGE,
                0,
                ptr::null(),
                0,
                ptr::null(),
                sids_to_restrict.len() as u32,
                sids_to_restrict.as_ptr(),
                &mut raw_restricted,
            )
        } == 0
        {
            return Err(io::Error::other(format!("CreateRestrictedToken: {}", io::Error::last_os_error())));
        }
        let restricted_token = OwnedHandle::new(raw_restricted)?;

        let sid_len = unsafe { GetLengthSid(low_il_sid.as_ptr()) } as usize;
        if sid_len == 0 || sid_len > 256 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid Windows Low integrity SID length",
            ));
        }
        let total_bytes = size_of::<TOKEN_MANDATORY_LABEL>() + sid_len;
        let word_count = (total_bytes + size_of::<usize>() - 1) / size_of::<usize>();
        let mut label_buf = vec![0usize; word_count];
        unsafe {
            let base = label_buf.as_mut_ptr().cast::<u8>();
            let sid_dst = base.add(size_of::<TOKEN_MANDATORY_LABEL>());
            ptr::copy_nonoverlapping(low_il_sid.as_ptr().cast::<u8>(), sid_dst, sid_len);
            ptr::write(
                base.cast::<TOKEN_MANDATORY_LABEL>(),
                TOKEN_MANDATORY_LABEL {
                    Label: SID_AND_ATTRIBUTES {
                        Sid: sid_dst.cast(),
                        Attributes: SE_GROUP_INTEGRITY,
                    },
                },
            );
            if SetTokenInformation(
                restricted_token.as_raw(),
                TokenIntegrityLevel,
                base.cast(),
                total_bytes as u32,
            ) == 0
            {
                return Err(io::Error::last_os_error());
            }
        }

        Ok(restricted_token)
    }

    fn duplicate_impersonation(primary: HANDLE) -> io::Result<OwnedHandle> {
        let mut raw_impersonation: HANDLE = ptr::null_mut();
        if unsafe {
            DuplicateTokenEx(
                primary,
                TOKEN_IMPERSONATE | TOKEN_QUERY,
                ptr::null(),
                SecurityImpersonation,
                TokenImpersonation,
                &mut raw_impersonation,
            )
        } == 0 {
            return Err(io::Error::last_os_error());
        }
        OwnedHandle::new(raw_impersonation)
    }

    fn build_low_restricted_impersonation_token() -> io::Result<OwnedHandle> {
        let primary = build_low_restricted_token(false, None)?;
        duplicate_impersonation(primary.as_raw())
    }

    /// Handle remains owned by this module and can never be replaced by the
    /// calling process token. Only this restricted token can reach the launcher.
    pub(crate) struct PrimaryRestrictedToken(OwnedHandle);
    impl PrimaryRestrictedToken {
        pub(crate) fn raw(&self) -> HANDLE { self.0.as_raw() }
    }

    // Read back the actual restricting list rather than inferring its
    // contents from IsTokenRestricted. This is a stricter preflight only.
    fn attest_restricting_sids(token:HANDLE, project:&LocalSid)->io::Result<usize> {
        use windows_sys::Win32::Security::{EqualSid, IsValidSid, TokenRestrictedSids, TOKEN_GROUPS};
        let mut needed=0u32;
        unsafe {GetTokenInformation(token,TokenRestrictedSids,ptr::null_mut(),0,&mut needed);}
        let offset=std::mem::offset_of!(TOKEN_GROUPS,Groups);
        if (needed as usize)<offset || needed>65536 {
            return Err(io::Error::other("restricted SID list unavailable"));
        }
        let mut storage=vec![0usize;(needed as usize).div_ceil(size_of::<usize>())];
        let mut read=0u32;
        if unsafe{GetTokenInformation(token,TokenRestrictedSids,storage.as_mut_ptr().cast(),needed,&mut read)}==0 {
            return Err(io::Error::last_os_error());
        }
        if read>needed || (read as usize)<offset {return Err(io::Error::other("invalid restricted SID list size"));}
        // The flexible array starts at the native ABI's Groups offset.
        let count=unsafe{(*storage.as_ptr().cast::<TOKEN_GROUPS>()).GroupCount} as usize;
        let bytes=count.checked_mul(size_of::<SID_AND_ATTRIBUTES>()).and_then(|n|n.checked_add(offset))
            .ok_or_else(||io::Error::other("restricted SID count overflow"))?;
        if count==0 || bytes>read as usize {return Err(io::Error::other("invalid restricted SID count"));}
        let groups=unsafe{std::slice::from_raw_parts(storage.as_ptr().cast::<u8>().add(offset).cast::<SID_AND_ATTRIBUTES>(),count)};
        let collective=LocalSid::from_str(RESTRICTED_CODE_SID)?;
        let mut found_project=false;let mut found_collective=false;
        for group in groups {
            if group.Sid.is_null()||unsafe{IsValidSid(group.Sid)}==0 {return Err(io::Error::other("invalid restricting SID"));}
            found_project|=unsafe{EqualSid(group.Sid,project.as_ptr())}!=0;
            found_collective|=unsafe{EqualSid(group.Sid,collective.as_ptr())}!=0;
        }
        if !found_project||!found_collective {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied,"required project/Restricted Code SID absent"));
        }
        Ok(count)
    }

    pub(super) fn make_primary_restricted_token(
        project: &PinnedProjectDirectory,
    ) -> io::Result<PrimaryRestrictedToken> {
        // Derive directly from the same pinned physical path that Git will
        // use. An unsuccessful derivation fails before any process is started.
        let project_sid = LocalSid::from_str(&project_sid_text(project)?)?;
        let token = build_low_restricted_token(true, Some(&project_sid))?;
        let mut token_type: i32 = 0;
        let mut read = 0u32;
        if unsafe {
            GetTokenInformation(token.as_raw(), TokenType,
                (&mut token_type as *mut i32).cast(),
                size_of::<i32>() as u32, &mut read)
        } == 0 || token_type != TokenPrimary {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied,
                "restricted process token is not primary"));
        }
        if unsafe { IsTokenRestricted(token.as_raw()) } == 0 {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied,
                "restricted process token lost its restricting SID"));
        }
        let mut needed = 0u32;
        unsafe {
            GetTokenInformation(token.as_raw(), TokenIntegrityLevel,
                ptr::null_mut(), 0, &mut needed);
        }
        if needed < size_of::<TOKEN_MANDATORY_LABEL>() as u32 || needed > 4096 {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied,
                "restricted process token integrity unavailable"));
        }
        let word_count = (needed as usize + size_of::<usize>() - 1) / size_of::<usize>();
        let mut raw = vec![0usize; word_count];
        if unsafe {
            GetTokenInformation(token.as_raw(), TokenIntegrityLevel,
                raw.as_mut_ptr().cast(), needed, &mut needed)
        } == 0 {
            return Err(io::Error::last_os_error());
        }
        let label = unsafe { &*(raw.as_ptr().cast::<TOKEN_MANDATORY_LABEL>()) };
        let mut sid_str = ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(label.Label.Sid, &mut sid_str) } == 0
            || sid_str.is_null()
        {
            return Err(io::Error::last_os_error());
        }
        let actual = unsafe { from_wide_ptr(sid_str) };
        unsafe { LocalFree(sid_str.cast()); }
        if actual != LOW_INTEGRITY_SID {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied,
                "restricted process token is not Low integrity"));
        }
        attest_restricting_sids(token.as_raw(),&project_sid)?;
        Ok(PrimaryRestrictedToken(token))
    }

    pub(super) fn probe_with_primary_token<T, F>(
        primary: &PrimaryRestrictedToken,
        probe: F,
    ) -> io::Result<T>
    where
        F: FnOnce() -> io::Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let impersonation = duplicate_impersonation(primary.raw())?;
        let worker = thread::Builder::new()
            .name("ab-git-low-token-probe".into())
            .spawn(move || {
                let guard = ThreadImpersonationGuard::enter(&impersonation)?;
                let observation = probe();
                let reverted = guard.revert();
                match (observation, reverted) {
                    (Ok(value), Ok(())) => Ok(value),
                    (Err(error), _) => Err(error),
                    (Ok(_), Err(error)) => Err(error),
                }
            })?;
        worker.join().map_err(|_| io::Error::other("restricted access-probe thread panicked"))?
    }
}
