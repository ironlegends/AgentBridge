//! Owned Unix scratch trees. Every component is opened with O_NOFOLLOW;
//! files and cleanup use openat/unlinkat relative to retained directory FDs.
//! A temporary profile is mode 0700 and is never a personal Chrome profile.
use super::{at_stage, operator_error, random_id, refused};
use std::ffi::{CStr, CString, OsStr};
use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

fn name(value: &OsStr) -> io::Result<CString> {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes == b"." || bytes == b".." || bytes.contains(&b'/') {
        return Err(refused());
    }
    CString::new(bytes).map_err(|_| refused())
}
fn identity(metadata: &Metadata) -> (u64, u64) { (metadata.dev(), metadata.ino()) }
fn open_at(parent: RawFd, child: &OsStr, flags: i32, mode: libc::mode_t) -> io::Result<File> {
    let child = name(child)?;
    let fd = unsafe { libc::openat(parent, child.as_ptr(),
        flags | libc::O_CLOEXEC | libc::O_NOFOLLOW, mode as libc::c_uint) };
    if fd < 0 { return Err(io::Error::last_os_error()); }
    Ok(unsafe { File::from_raw_fd(fd) })
}

pub(in crate::browser_docs) struct DirectoryPin {
    path: PathBuf,
    nodes: Vec<File>,
}
impl DirectoryPin {
    pub(in crate::browser_docs) fn open(path: &Path) -> io::Result<Self> {
        if !path.is_absolute() { return Err(refused()); }
        let root = OpenOptions::new().read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC).open("/")?;
        let mut nodes = vec![root];
        for component in path.components() {
            match component {
                Component::RootDir => {},
                Component::Normal(part) => {
                    let parent = nodes.last().ok_or_else(refused)?.as_raw_fd();
                    nodes.push(open_at(parent, part, libc::O_RDONLY | libc::O_DIRECTORY, 0)?);
                }
                _ => return Err(refused()),
            }
        }
        Ok(Self { path: path.to_owned(), nodes })
    }
    fn file(&self) -> &File { self.nodes.last().expect("directory always retains its root") }
    pub(in crate::browser_docs) fn verify(&self) -> io::Result<()> {
        let current = Self::open(&self.path)?;
        if current.nodes.len() != self.nodes.len() { return Err(refused()); }
        for (held, named) in self.nodes.iter().zip(current.nodes.iter()) {
            if identity(&held.metadata()?) != identity(&named.metadata()?) { return Err(refused()); }
        }
        Ok(())
    }
    pub(in crate::browser_docs) fn path(&self) -> &Path { &self.path }
    fn trusted_ancestors(&self) -> io::Result<()> {
        for directory in &self.nodes {
            let metadata = directory.metadata()?;
            // A sticky system temp root is allowed; a writable non-sticky
            // ancestor would let another account replace our private name.
            if ![0, unsafe { libc::geteuid() }].contains(&metadata.uid())
                || (metadata.mode() & 0o022 != 0 && metadata.mode() & 0o1000 == 0)
            { return Err(refused()); }
        }
        Ok(())
    }
    pub(in crate::browser_docs) fn require_private(&self) -> io::Result<()> {
        self.verify()?;
        self.trusted_ancestors()?;
        let metadata = self.file().metadata()?;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
            return Err(refused());
        }
        Ok(())
    }
    pub(in crate::browser_docs) fn create_child(&self, child: &OsStr) -> io::Result<Self> {
        self.verify()?;
        self.trusted_ancestors()?;
        let child_name = name(child)?;
        if unsafe { libc::mkdirat(self.file().as_raw_fd(), child_name.as_ptr(), 0o700) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let node = open_at(self.file().as_raw_fd(), child, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
        let mut nodes = self.nodes.iter().map(File::try_clone).collect::<io::Result<Vec<_>>>()?;
        nodes.push(node);
        let directory = Self { path: self.path.join(child), nodes };
        directory.require_private()?;
        Ok(directory)
    }
    pub(in crate::browser_docs) fn open_file(&self, child: &OsStr, flags: i32) -> io::Result<File> {
        self.verify()?;
        let file = open_at(self.file().as_raw_fd(), child, flags | libc::O_NONBLOCK, 0o600)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.nlink() != 1 { return Err(refused()); }
        self.verify_file(child, &file)?;
        Ok(file)
    }
    pub(in crate::browser_docs) fn verify_file(&self, child: &OsStr, file: &File) -> io::Result<()> {
        self.verify()?;
        let current = open_at(self.file().as_raw_fd(), child, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
        let held = file.metadata()?;
        let named = current.metadata()?;
        if !held.is_file() || held.nlink() != 1 || !named.is_file()
            || identity(&held) != identity(&named) { return Err(refused()); }
        Ok(())
    }
}

pub(in crate::browser_docs) fn ensure_private_directory(path: &Path) -> io::Result<DirectoryPin> {
    let pin = match DirectoryPin::open(path) {
        Ok(pin) => pin,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let parent = DirectoryPin::open(path.parent().ok_or_else(refused)?)?;
            parent.create_child(path.file_name().ok_or_else(refused)?)?
        }
        Err(error) => return Err(error),
    };
    pin.require_private()?;
    Ok(pin)
}

pub(super) struct BrowserPins {
    _parent: DirectoryPin,
    _file: File,
}
pub(super) fn pin_browser(path: &Path) -> io::Result<BrowserPins> {
    let parent = at_stage("chrome.pin.parent_open",
        DirectoryPin::open(path.parent().ok_or_else(refused)?))?;
    at_stage("chrome.pin.parent_trust", parent.trusted_ancestors())?;
    let file = at_stage("chrome.pin.file_open",
        parent.open_file(path.file_name().ok_or_else(refused)?, libc::O_RDONLY))?;
    let metadata = at_stage("chrome.pin.file_metadata", file.metadata())?;
    if metadata.mode() & 0o111 == 0 || metadata.mode() & 0o022 != 0
        || ![0, unsafe { libc::geteuid() }].contains(&metadata.uid())
    { return Err(operator_error("chrome.pin.file_owner_mode", refused())); }
    Ok(BrowserPins { _parent: parent, _file: file })
}

pub(super) struct PrivateTree {
    parent: DirectoryPin,
    root: DirectoryPin,
    data: DirectoryPin,
    downloads: DirectoryPin,
    cleaned: bool,
}
impl PrivateTree {
    pub(super) fn create(base: &Path) -> io::Result<Self> {
        // macOS's normal temp root can begin at /var -> /private/var. Resolve
        // that OS-provided base once, then pin every canonical component.
        let base = std::fs::canonicalize(base)?;
        let parent = DirectoryPin::open(&base)?;
        let root = parent.create_child(OsStr::new(&format!("agent-bridge-chrome-{}", random_id()?)))?;
        let data = root.create_child(OsStr::new("profile"))?;
        let downloads = root.create_child(OsStr::new("downloads"))?;
        Ok(Self { parent, root, data, downloads, cleaned: false })
    }
    pub(super) fn data_dir(&self) -> io::Result<PathBuf> {
        self.data.require_private()?;
        Ok(self.data.path.clone())
    }
    pub(super) fn download_root(&self) -> io::Result<PathBuf> {
        self.downloads.require_private()?;
        Ok(self.downloads.path.clone())
    }
    pub(super) fn read_download(&self, guid: &str, max: usize) -> io::Result<Vec<u8>> {
        super::super::transfer::read_private_download(&self.downloads, guid, max)
    }
    pub(super) fn html(&self, html: &str) -> io::Result<(PathBuf, File)> {
        if html.is_empty() || html.len() > 512 * 1024 { return Err(refused()); }
        let child = format!("document-{}.html", random_id()?);
        let mut file = self.root.open_file(OsStr::new(&child), libc::O_CREAT | libc::O_EXCL | libc::O_RDWR)?;
        file.write_all(html.as_bytes())?;
        file.sync_all()?;
        self.root.verify_file(OsStr::new(&child), &file)?;
        Ok((self.root.path.join(child), file))
    }
    pub(super) fn cleanup(&mut self) -> io::Result<()> {
        if self.cleaned { return Ok(()); }
        self.root.require_private()?;
        self.parent.verify()?;
        let mut budget = CleanupBudget { entries: 0, bytes: 0, deadline: Instant::now() + Duration::from_secs(5) };
        clean_directory(self.root.file().as_raw_fd(), 0, &mut budget)?;
        // The final unlink is relative to the retained parent and checks the
        // still-named root identity. Renames/replacements never certify close.
        self.root.verify()?;
        let child = name(self.root.path.file_name().ok_or_else(refused)?)?;
        if unsafe { libc::unlinkat(self.parent.file().as_raw_fd(), child.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
            return Err(io::Error::last_os_error());
        }
        self.cleaned = true;
        Ok(())
    }
}

pub(in crate::browser_docs) fn remove_private_tree(path: &Path) -> io::Result<()> {
    let parent = DirectoryPin::open(path.parent().ok_or_else(refused)?)?;
    let root = DirectoryPin::open(path)?;
    root.require_private()?;
    let mut budget = CleanupBudget { entries: 0, bytes: 0, deadline: Instant::now() + Duration::from_secs(5) };
    clean_directory(root.file().as_raw_fd(), 0, &mut budget)?;
    root.verify()?;
    parent.verify()?;
    let child = name(path.file_name().ok_or_else(refused)?)?;
    if unsafe { libc::unlinkat(parent.file().as_raw_fd(), child.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

struct CleanupBudget { entries: usize, bytes: u64, deadline: Instant }
struct DirectoryStream(*mut libc::DIR);
impl Drop for DirectoryStream {
    fn drop(&mut self) { unsafe { libc::closedir(self.0); } }
}
fn stat_child(fd: RawFd, child: &CStr) -> io::Result<libc::stat> {
    let mut metadata = std::mem::MaybeUninit::uninit();
    if unsafe { libc::fstatat(fd, child.as_ptr(), metadata.as_mut_ptr(), libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { metadata.assume_init() })
}
fn clean_directory(fd: RawFd, depth: usize, budget: &mut CleanupBudget) -> io::Result<()> {
    if depth > 16 || Instant::now() >= budget.deadline { return Err(refused()); }
    // Open a fresh directory description: dup() would share the cursor and
    // make a retry miss entries already seen by an earlier cleanup attempt.
    let reader = unsafe { libc::openat(fd, c".".as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC, 0) };
    if reader < 0 { return Err(io::Error::last_os_error()); }
    let stream = unsafe { libc::fdopendir(reader) };
    if stream.is_null() {
        let error = io::Error::last_os_error();
        unsafe { libc::close(reader); }
        return Err(error);
    }
    let stream = DirectoryStream(stream);
    loop {
        #[cfg(target_os = "linux")]
        unsafe { *libc::__errno_location() = 0; }
        #[cfg(target_os = "macos")]
        unsafe { *libc::__error() = 0; }
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let error = io::Error::last_os_error();
            if error.raw_os_error().unwrap_or(0) != 0 { return Err(error); }
            break;
        }
        let child = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        if matches!(child.to_bytes(), b"." | b"..") { continue; }
        let metadata = stat_child(fd, child)?;
        budget.entries += 1;
        budget.bytes = budget.bytes.checked_add(metadata.st_size.max(0) as u64).ok_or_else(refused)?;
        if budget.entries > 4096 || budget.bytes > 256 * 1024 * 1024 || Instant::now() >= budget.deadline {
            return Err(refused());
        }
        let directory = metadata.st_mode & libc::S_IFMT == libc::S_IFDIR;
        if directory {
            let owned = open_at(fd, OsStr::from_bytes(child.to_bytes()), libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
            let held = owned.metadata()?;
            if held.dev() != metadata.st_dev as u64 || held.ino() != metadata.st_ino as u64 { return Err(refused()); }
            clean_directory(owned.as_raw_fd(), depth + 1, budget)?;
        } else if !matches!(metadata.st_mode & libc::S_IFMT, libc::S_IFREG | libc::S_IFLNK | libc::S_IFSOCK) {
            return Err(refused());
        }
        let current = stat_child(fd, child)?;
        if current.st_dev != metadata.st_dev || current.st_ino != metadata.st_ino
            || current.st_mode & libc::S_IFMT != metadata.st_mode & libc::S_IFMT {
            return Err(refused());
        }
        // Chrome creates Singleton* symlinks on Unix. Remove only the link
        // itself; its target is never opened or traversed during cleanup.
        if unsafe { libc::unlinkat(fd, child.as_ptr(), if directory { libc::AT_REMOVEDIR } else { 0 }) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_profile_cleanup_unlinks_symlinks_without_following_them() {
        let base = std::env::temp_dir();
        let external = base.join(format!("bridge-external-{}", random_id().unwrap()));
        std::fs::create_dir(&external).unwrap();
        std::fs::write(external.join("preserve.txt"), b"unrelated").unwrap();
        let mut tree = PrivateTree::create(&base).unwrap();
        let root = tree.root.path.clone();
        assert_eq!(std::fs::metadata(&root).unwrap().mode() & 0o777, 0o700);
        let data = tree.data_dir().unwrap();
        std::os::unix::fs::symlink(&external, data.join("SingletonLock")).unwrap();
        tree.html("<h1>selected</h1>").unwrap();
        tree.cleanup().unwrap();
        assert!(!root.exists());
        assert_eq!(std::fs::read(external.join("preserve.txt")).unwrap(), b"unrelated");
        tree.cleanup().unwrap();
        std::fs::remove_dir_all(external).unwrap();
    }
    #[test]
    fn replaced_profile_root_is_refused_and_unrelated_files_are_preserved() {
        let mut tree = PrivateTree::create(&std::env::temp_dir()).unwrap();
        let root = tree.root.path.clone();
        let moved = root.with_extension("moved");
        std::fs::rename(&root, &moved).unwrap();
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("unrelated.txt"), b"preserve").unwrap();
        assert!(tree.cleanup().is_err());
        assert_eq!(std::fs::read(root.join("unrelated.txt")).unwrap(), b"preserve");
        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_dir_all(moved).unwrap();
    }
    #[test]
    fn directory_pin_refuses_symlink_components() {
        let base = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        let alias = base.join(format!("bridge-link-{}", random_id().unwrap()));
        std::os::unix::fs::symlink(&base, &alias).unwrap();
        assert!(DirectoryPin::open(&alias).is_err());
        std::fs::remove_file(alias).unwrap();
    }

    #[test]
    fn browser_pin_refuses_writable_untrusted_ancestors() {
        use std::os::unix::fs::PermissionsExt;
        let ancestor = std::fs::canonicalize(std::env::temp_dir()).unwrap()
            .join(format!("bridge-browser-parent-{}", random_id().unwrap()));
        std::fs::create_dir(&ancestor).unwrap();
        std::fs::set_permissions(&ancestor, std::fs::Permissions::from_mode(0o700)).unwrap();
        let binary_dir = ancestor.join("bin");
        std::fs::create_dir(&binary_dir).unwrap();
        let executable = binary_dir.join("chrome");
        std::fs::write(&executable, b"qualification fixture; never executed").unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
        let private_accepted = pin_browser(&executable).is_ok();
        // A safe-looking executable does not protect its name when an
        // ancestor lets another account replace the containing directory.
        std::fs::set_permissions(&ancestor, std::fs::Permissions::from_mode(0o777)).unwrap();
        let writable_refused = pin_browser(&executable).is_err();
        std::fs::remove_dir_all(&ancestor).unwrap();
        assert!(private_accepted, "private owned installation fixture was refused");
        assert!(writable_refused, "browser pin accepted a writable non-sticky ancestor");
    }
}
