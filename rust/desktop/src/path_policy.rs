use super::*;
use workspace_write::{dir_identity, Identity};

pub(super) struct PinnedDirectory {
    pub path: PathBuf,
    pub directory: Dir,
    identity: Identity,
}

impl PinnedDirectory {
    pub fn open(path: &Path) -> Result<Self> {
        let path = normalize_absolute(path)?;
        let directory = open_filesystem_root(&path, true)?;
        let identity = dir_identity(&directory)?;
        Ok(Self { path, directory, identity })
    }
    pub fn verify(&self) -> Result<()> {
        let current = open_filesystem_root(&self.path, true)?;
        if dir_identity(&current)? != self.identity {
            return Err(DesktopError::new("ROOT_IDENTITY_CHANGED", "An approved directory was replaced or moved"));
        }
        Ok(())
    }

    pub fn relative_authorized_path(&self, path: &Path) -> Result<Option<String>> {
        if !contains_path(&self.path, path) { return Ok(None); }
        self.verify()?;
        let count = self.path.components().count();
        let requested_root = path.components().take(count).collect::<PathBuf>();
        let requested = open_filesystem_root(&requested_root, true)?;
        if dir_identity(&requested)? != self.identity { return Ok(None); }
        let parts = path.components().skip(count).map(|part| {
            part.as_os_str().to_str().map(str::to_owned)
                .ok_or_else(|| DesktopError::new("INVALID_PATH", "Path must be UTF-8"))
        }).collect::<Result<Vec<_>>>()?;
        Ok(Some(display_parts(&parts)))
    }
}

pub(super) struct ProtectedPaths { roots: Vec<PinnedDirectory> }
impl ProtectedPaths {
    pub fn open(paths: &[PathBuf]) -> Result<Self> {
        if paths.is_empty() || paths.len() > 64 {
            return Err(DesktopError::new("INVALID_FILE_POLICY", "Choose 1..64 private directory exclusions"));
        }
        let roots = paths.iter().map(|path| PinnedDirectory::open(path)).collect::<Result<Vec<_>>>()?;
        Ok(Self { roots })
    }
    pub fn check_absolute(&self, path: &Path) -> Result<()> {
        if self.roots.iter().any(|root| contains_path(&root.path, path)) {
            return Err(protected());
        }
        Ok(())
    }
    pub fn check_relative(&self, root: &Path, relative: &str) -> Result<()> {
        let parts = relative_parts(relative, true)?;
        let mut path = root.to_owned();
        for part in parts { path.push(part); }
        self.check_absolute(&path)
    }
    pub fn check_directory(&self, dir: &Dir) -> Result<()> {
        let id = dir_identity(dir)?;
        if self.roots.iter().any(|root| root.identity == id) { return Err(protected()); }
        #[cfg(windows)] {
            let physical = physical_directory_path(dir)?;
            for root in &self.roots {
                if contains_path(&physical_directory_path(&root.directory)?, &physical) {
                    return Err(protected());
                }
            }
        }
        Ok(())
    }
}

#[cfg(windows)]
pub(super) fn physical_directory_path(directory: &Dir) -> Result<PathBuf> {
    use std::os::windows::{ffi::OsStringExt, io::AsRawHandle};
    use windows_sys::Win32::Storage::FileSystem::{GetFinalPathNameByHandleW, VOLUME_NAME_NT};
    // NT volume names resolve DOS aliases, including aliases whose root is
    // already a descendant of a protected directory. The held handles are the
    // witnesses; a path captured at startup would miss a later rename.
    let mut buffer = vec![0u16; 32768];
    let length = unsafe { GetFinalPathNameByHandleW(directory.as_raw_handle(),
        buffer.as_mut_ptr(), buffer.len() as u32, VOLUME_NAME_NT) } as usize;
    if length == 0 || length >= buffer.len() {
        return Err(DesktopError::new("PHYSICAL_PATH_UNAVAILABLE", "Cannot establish the physical directory ancestry"));
    }
    Ok(PathBuf::from(OsString::from_wide(&buffer[..length])))
}

fn protected() -> DesktopError {
    DesktopError::new("PROTECTED_PRIVATE_PATH", "Private application state is excluded from desktop file access")
}

pub(super) fn contains_path(root: &Path, path: &Path) -> bool {
    let mut components = path.components();
    root.components().all(|left| components.next().is_some_and(|right| {
        #[cfg(windows)]
        { left.as_os_str().to_string_lossy().eq_ignore_ascii_case(&right.as_os_str().to_string_lossy()) }
        #[cfg(not(windows))]
        { left == right }
    }))
}

pub(super) fn normalize_absolute(path: &Path) -> Result<PathBuf> {
    let raw = path.to_str().ok_or_else(|| DesktopError::new("INVALID_PATH", "Path must be UTF-8"))?;
    if raw.is_empty() || raw.len() > MAX_PATH_BYTES || raw.contains('\0') || !path.is_absolute() {
        return Err(DesktopError::new("INVALID_PATH", "An ordinary absolute filesystem path is required"));
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => {
                #[cfg(windows)]
                match prefix.kind() {
                    std::path::Prefix::Disk(letter) => normalized.push(format!("{}:", char::from(letter).to_ascii_uppercase())),
                    _ => return Err(DesktopError::new("INVALID_PATH", "Device and UNC paths are not selected by this local-drive capability")),
                }
                #[cfg(not(windows))]
                normalized.push(prefix.as_os_str());
            }
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::Normal(segment) => {
                validate_segment(segment.to_str().ok_or_else(|| DesktopError::new("INVALID_PATH", "Path must be UTF-8"))?)?;
                normalized.push(segment);
            }
            Component::CurDir | Component::ParentDir => return Err(DesktopError::new("INVALID_PATH", "Dot and parent traversal is refused")),
        }
    }
    Ok(normalized)
}

pub(super) fn volume_and_relative(path: &Path) -> Result<(PathBuf, String)> {
    let mut root = PathBuf::new();
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => root.push(component.as_os_str()),
            Component::Normal(name) => parts.push(name.to_str().ok_or_else(|| DesktopError::new("INVALID_PATH", "Path must be UTF-8"))?.to_owned()),
            _ => return Err(DesktopError::new("INVALID_PATH", "Invalid path component")),
        }
    }
    Ok((root, display_parts(&parts)))
}
