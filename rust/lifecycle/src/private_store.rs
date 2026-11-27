use super::{platform, valid_root, LifecycleError, Result};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenMode {
    Read,
    CreateNew,
    Append,
    ReadWrite,
    CreateOrReadWrite,
}

pub struct FileLock(File);

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = File::unlock(&self.0);
    }
}

pub fn ensure_private_dir(path: &Path) -> Result<PathBuf> {
    valid_root(path, true)
}

pub fn verify_private_dir(path: &Path) -> Result<PathBuf> {
    valid_root(path, false)
}

pub fn is_reparse(md: &Metadata) -> bool {
    platform::is_reparse(md)
}

fn base_open_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    platform::private_open_options(&mut options);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // Allow shared reading and POSIX-style unlink during rotation while
        // coordinating concurrent access through explicit OS file locks.
        options.share_mode(0x1 | 0x2 | 0x4);
    }
    options
}

fn open_existing_checked(path: &Path, append: bool, write: bool) -> Result<File> {
    let md = fs::symlink_metadata(path)?;
    if !md.is_file() || md.file_type().is_symlink() || platform::is_reparse(&md) {
        return Err(LifecycleError::Uncertain("unsafe private file"));
    }
    let mut options = base_open_options();
    if append {
        options.append(true);
    } else {
        options.read(true).write(write);
    }
    let file = options.open(path)?;
    platform::verify_private_handle(&file, false)?;
    Ok(file)
}

pub fn open_private_file(path: &Path, mode: OpenMode) -> Result<File> {
    match mode {
        OpenMode::Read => open_existing_checked(path, false, false),
        OpenMode::Append => open_existing_checked(path, true, false),
        OpenMode::ReadWrite => open_existing_checked(path, false, true),
        OpenMode::CreateNew => {
            let mut options = base_open_options();
            options.read(true).write(true).create_new(true);
            let file = options.open(path)?;
            platform::verify_private_handle(&file, false)?;
            Ok(file)
        }
        OpenMode::CreateOrReadWrite => match open_private_file(path, OpenMode::CreateNew) {
            Ok(file) => Ok(file),
            Err(LifecycleError::Io(err)) if err.kind() == ErrorKind::AlreadyExists => {
                open_existing_checked(path, false, true)
            }
            Err(err) => Err(err),
        },
    }
}

fn lock_file(file: File, shared: bool) -> Result<Option<FileLock>> {
    let deadline = Instant::now() + Duration::from_millis(250);
    loop {
        let result = if shared { file.try_lock_shared() } else { file.try_lock() };
        match result {
            Ok(()) => return Ok(Some(FileLock(file))),
            Err(std::fs::TryLockError::WouldBlock) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(std::fs::TryLockError::WouldBlock) => return Err(LifecycleError::Busy),
            Err(std::fs::TryLockError::Error(error)) => return Err(error.into()),
        }
    }
}

pub fn lock_exclusive(path: &Path, create: bool) -> Result<Option<FileLock>> {
    if !create
        && matches!(fs::symlink_metadata(path), Err(err) if err.kind() == ErrorKind::NotFound)
    {
        return Ok(None);
    }
    let file = open_private_file(
        path,
        if create {
            OpenMode::CreateOrReadWrite
        } else {
            OpenMode::ReadWrite
        },
    )?;
    lock_file(file, false)
}

pub fn lock_shared(path: &Path) -> Result<Option<FileLock>> {
    if matches!(fs::symlink_metadata(path), Err(err) if err.kind() == ErrorKind::NotFound) {
        return Ok(None);
    }
    let file = open_private_file(path, OpenMode::Read)?;
    lock_file(file, true)
}

#[cfg(test)]
mod tests {
    use super::{
        ensure_private_dir, lock_exclusive, lock_shared, open_private_file, verify_private_dir,
        OpenMode,
    };
    use std::fs;
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    static SEQ: AtomicU64 = AtomicU64::new(0);

    struct TempRoot(PathBuf);
    impl TempRoot {
        fn new(label: &str) -> Self {
            let n = SEQ.fetch_add(1, Ordering::Relaxed);
            #[cfg(unix)]
            let base = {
                use std::os::unix::fs::PermissionsExt;
                let base = PathBuf::from(std::env::var_os("HOME").expect("HOME"))
                    .join(".ab-lifecycle-tests");
                fs::create_dir_all(&base).unwrap();
                fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
                base
            };
            #[cfg(not(unix))]
            let base = {
                let base = fs::canonicalize(std::env::temp_dir()).unwrap();
                base.to_str()
                    .and_then(|s| s.strip_prefix(r"\\?\"))
                    .map(PathBuf::from)
                    .unwrap_or(base)
            };
            let dir = base.join(format!("ab-pstore-{label}-{}-{n}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
            }
            Self(dir)
        }
    }
    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn private_store_enforces_owner_private_dir_handle_hardlink_and_path_checks() {
        let root = TempRoot::new("checks");
        assert!(ensure_private_dir(std::path::Path::new("relative/dir")).is_err());
        assert!(ensure_private_dir(&root.0.join("..").join("escape")).is_err());
        #[cfg(windows)]
        assert!(ensure_private_dir(std::path::Path::new(r"\\server\share\audit")).is_err());

        let private_dir = ensure_private_dir(&root.0.join("private")).unwrap();
        assert_eq!(verify_private_dir(&private_dir).unwrap(), private_dir);

        let file_path = private_dir.join("data.jsonl");
        {
            let mut file = open_private_file(&file_path, OpenMode::CreateNew).unwrap();
            writeln!(file, "line1").unwrap();
        }
        {
            let mut file = open_private_file(&file_path, OpenMode::Append).unwrap();
            writeln!(file, "line2").unwrap();
        }
        let read_back = fs::read_to_string(&file_path).unwrap();
        assert_eq!(read_back, "line1\nline2\n");

        // Hardlink (nlink == 2) must be refused on open_private_file.
        let alias = private_dir.join("alias.jsonl");
        fs::hard_link(&file_path, &alias).unwrap();
        assert!(open_private_file(&file_path, OpenMode::Read).is_err());
        fs::remove_file(&alias).unwrap();
        assert!(open_private_file(&file_path, OpenMode::Read).is_ok());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let open_dir = root.0.join("open-dir");
            fs::create_dir(&open_dir).unwrap();
            fs::set_permissions(&open_dir, fs::Permissions::from_mode(0o755)).unwrap();
            assert!(verify_private_dir(&open_dir).is_err());
            let link = root.0.join("link-dir");
            std::os::unix::fs::symlink(&private_dir, &link).unwrap();
            assert!(verify_private_dir(&link).is_err());
        }
    }

    #[test]
    fn existing_private_root_is_verified_after_competing_creation() {
        let root = TempRoot::new("existing");
        let dir = ensure_private_dir(&root.0.join("history")).unwrap();
        let second = crate::platform::create_private_directory(&dir);
        assert!(matches!(second, Err(crate::LifecycleError::Io(e))
            if e.kind() == std::io::ErrorKind::AlreadyExists));
        assert_eq!(verify_private_dir(&dir).unwrap(), dir);
    }

    #[test]
    fn private_store_std_locks_serialize_exclusive_and_shared_handles() {
        let root = TempRoot::new("locks");
        let dir = ensure_private_dir(&root.0.join("store")).unwrap();
        let lock_path = dir.join("test.lock");

        // Absent lock returns Ok(None) without creating the file.
        assert!(lock_shared(&lock_path).unwrap().is_none());
        assert!(!lock_path.exists());

        let exclusive = lock_exclusive(&lock_path, true).unwrap().unwrap();
        let (tx, rx) = mpsc::channel();
        let lock_path_clone = lock_path.clone();
        let waiter = std::thread::spawn(move || {
            let shared = lock_shared(&lock_path_clone).unwrap().unwrap();
            tx.send(Instant::now()).unwrap();
            drop(shared);
        });

        std::thread::sleep(Duration::from_millis(80));
        assert!(
            rx.try_recv().is_err(),
            "shared lock must block while exclusive lock is held"
        );
        drop(exclusive);
        rx.recv_timeout(Duration::from_secs(2))
            .expect("shared lock must acquire once exclusive lock drops");
        waiter.join().unwrap();

        // Two shared locks must coexist simultaneously without blocking.
        let s1 = lock_shared(&lock_path).unwrap().unwrap();
        let s2 = lock_shared(&lock_path).unwrap().unwrap();
        drop((s1, s2));
    }
}
