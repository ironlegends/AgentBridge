//! Bounded size- and age-based rotation for local server and stdio logs.

use crate::{check_real_ancestors, private_store, LifecycleError, Result};
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime};

pub const DEFAULT_MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;
pub const DEFAULT_MAX_BACKUPS: usize = 3;
pub const DEFAULT_MAX_AGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RotatingLogPolicy {
    pub max_file_bytes: u64,
    pub max_backups: usize,
    pub max_age: Duration,
}

impl Default for RotatingLogPolicy {
    fn default() -> Self {
        Self {
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_backups: DEFAULT_MAX_BACKUPS,
            max_age: DEFAULT_MAX_AGE,
        }
    }
}

impl RotatingLogPolicy {
    pub fn normalized(mut self) -> Self {
        self.max_file_bytes = self.max_file_bytes.max(64);
        self.max_backups = self.max_backups.max(1);
        self
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RotatingLogStats {
    pub bytes_written: u64,
    pub bytes_dropped: u64,
    pub rotations: u64,
    pub io_errors: u64,
}

type LogOpener = Box<dyn Fn(&Path) -> std::io::Result<File> + Send>;
type LogClock = Box<dyn Fn() -> SystemTime + Send>;

pub struct RotatingLogWriter {
    path: PathBuf,
    policy: RotatingLogPolicy,
    opener: LogOpener,
    clock: LogClock,
    file: Option<File>,
    current_bytes: u64,
    stats: RotatingLogStats,
}

impl RotatingLogWriter {
    pub fn open_private(path: &Path, policy: RotatingLogPolicy) -> Result<Self> {
        let parent = path
            .parent()
            .ok_or(LifecycleError::Invalid("rotating log needs a parent directory"))?;
        private_store::verify_private_dir(parent)?;
        Self::open_with_opener(
            path,
            policy,
            Box::new(|target| {
                private_store::open_private_file(target, private_store::OpenMode::CreateOrReadWrite)
                    .and_then(|file| {
                        drop(file);
                        private_store::open_private_file(target, private_store::OpenMode::Append)
                    })
                    .map_err(std::io::Error::other)
            }),
        )
    }

    pub fn open_with_opener(
        path: &Path,
        policy: RotatingLogPolicy,
        opener: LogOpener,
    ) -> Result<Self> {
        Self::open_with_opener_and_clock(path, policy, opener, Box::new(SystemTime::now))
    }

    pub fn open_with_opener_and_clock(
        path: &Path,
        policy: RotatingLogPolicy,
        opener: LogOpener,
        clock: LogClock,
    ) -> Result<Self> {
        validate_log_path(path)?;
        let parent = path
            .parent()
            .ok_or(LifecycleError::Invalid("rotating log needs a parent directory"))?;
        check_real_ancestors(parent)?;

        let policy = policy.normalized();
        let mut writer = Self {
            path: path.to_path_buf(),
            policy,
            opener,
            clock,
            file: None,
            current_bytes: 0,
            stats: RotatingLogStats::default(),
        };
        writer.prepare_startup()?;
        Ok(writer)
    }

    pub fn stats(&self) -> RotatingLogStats {
        self.stats
    }

    pub fn write_chunk(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        validate_log_path(&self.path)?;
        if let Some(parent) = self.path.parent() {
            check_real_ancestors(parent)?;
        }

        if self.file.is_none() {
            self.reopen_active()?;
        }

        let cap = usize::try_from(self.policy.max_file_bytes).unwrap_or(usize::MAX);
        for chunk in bytes.chunks(cap) {
            if self.current_bytes > 0
                && self.current_bytes.saturating_add(chunk.len() as u64) > self.policy.max_file_bytes
            {
                self.rotate_active()?;
            }
            let file = self.file.as_mut().ok_or(LifecycleError::Uncertain("rotating log handle unavailable"))?;
            file.write_all(chunk)?;
            file.flush()?;
            self.current_bytes = self.current_bytes.saturating_add(chunk.len() as u64);
            self.stats.bytes_written = self.stats.bytes_written.saturating_add(chunk.len() as u64);
        }
        Ok(())
    }

    pub fn write_best_effort(&mut self, bytes: &[u8]) {
        let before = self.stats.bytes_written;
        if self.write_chunk(bytes).is_err() {
            self.file = None;
            self.current_bytes = 0;
            self.stats.io_errors = self.stats.io_errors.saturating_add(1);
            let written = self.stats.bytes_written.saturating_sub(before);
            self.stats.bytes_dropped = self.stats.bytes_dropped.saturating_add((bytes.len() as u64).saturating_sub(written));
        }
    }

    fn prepare_startup(&mut self) -> Result<()> {
        self.prune_excess_and_expired_backups()?;
        match fs::symlink_metadata(&self.path) {
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
            Ok(md) => {
                if !md.is_file() || md.file_type().is_symlink() || private_store::is_reparse(&md) {
                    return Err(LifecycleError::Uncertain("unsafe rotating log path"));
                }
                if md.len() >= self.policy.max_file_bytes {
                    self.shift_and_rename_active()?;
                }
            }
        }
        self.reopen_active()?;
        Ok(())
    }

    fn reopen_active(&mut self) -> Result<()> {
        let md_before = fs::symlink_metadata(&self.path);
        if let Ok(md) = md_before {
            if !md.is_file() || md.file_type().is_symlink() || private_store::is_reparse(&md) {
                return Err(LifecycleError::Uncertain("unsafe active rotating log file"));
            }
        }
        let file = (self.opener)(&self.path)?;
        let md = file.metadata()?;
        if !md.is_file() || private_store::is_reparse(&md) {
            return Err(LifecycleError::Uncertain("opened rotating log is not a regular file"));
        }
        self.current_bytes = md.len();
        self.file = Some(file);
        Ok(())
    }

    fn rotate_active(&mut self) -> Result<()> {
        self.file = None;
        self.current_bytes = 0;
        self.shift_and_rename_active()?;
        self.prune_excess_and_expired_backups()?;
        self.reopen_active()?;
        Ok(())
    }

    fn shift_and_rename_active(&mut self) -> Result<()> {
        let max = self.policy.max_backups;
        let oldest = backup_path(&self.path, max);
        remove_if_regular_file(&oldest)?;

        for index in (1..max).rev() {
            let src = backup_path(&self.path, index);
            let dst = backup_path(&self.path, index + 1);
            if check_regular_if_present(&src)? {
                remove_if_regular_file(&dst)?;
                fs::rename(&src, &dst)?;
            }
        }

        if check_regular_if_present(&self.path)? {
            let first_backup = backup_path(&self.path, 1);
            remove_if_regular_file(&first_backup)?;
            fs::rename(&self.path, &first_backup)?;
            self.stats.rotations = self.stats.rotations.saturating_add(1);
        }
        Ok(())
    }

    pub fn prune_expired_backups(&mut self) -> Result<()> {
        self.prune_excess_and_expired_backups()
    }

    fn prune_excess_and_expired_backups(&self) -> Result<()> {
        let now = (self.clock)();
        for index in 1..=self.policy.max_backups {
            let candidate = backup_path(&self.path, index);
            match fs::symlink_metadata(&candidate) {
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                Err(err) => return Err(err.into()),
                Ok(md) => {
                    if !md.is_file() || md.file_type().is_symlink() || private_store::is_reparse(&md) {
                        return Err(LifecycleError::Uncertain("unsafe rotating log backup"));
                    }
                    if let Ok(modified) = md.modified() {
                        if let Ok(age) = now.duration_since(modified) {
                            if age >= self.policy.max_age {
                                fs::remove_file(&candidate)?;
                            }
                        }
                    }
                }
            }
        }
        // Clean up any stale backups beyond a lowered max_backups limit.
        let mut extra = self.policy.max_backups + 1;
        while extra <= self.policy.max_backups + 16 {
            let candidate = backup_path(&self.path, extra);
            match fs::symlink_metadata(&candidate) {
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => break,
                Err(err) => return Err(err.into()),
                Ok(md) => {
                    if !md.is_file() || md.file_type().is_symlink() || private_store::is_reparse(&md) {
                        return Err(LifecycleError::Uncertain("unsafe surplus rotating log backup"));
                    }
                    fs::remove_file(&candidate)?;
                }
            }
            extra += 1;
        }
        Ok(())
    }
}

pub fn backup_path(base: &Path, index: usize) -> PathBuf {
    let mut name: OsString = base.as_os_str().to_os_string();
    name.push(format!(".{index}"));
    PathBuf::from(name)
}

fn validate_log_path(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path.file_name().is_none()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(LifecycleError::Invalid("absolute canonical log path required"));
    }
    #[cfg(windows)]
    {
        let value = path.to_string_lossy();
        if value.starts_with(r"\\") || value.starts_with("//") {
            return Err(LifecycleError::Invalid("network/device log path refused"));
        }
    }
    Ok(())
}

fn check_regular_if_present(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err.into()),
        Ok(md) => {
            if !md.is_file() || md.file_type().is_symlink() || private_store::is_reparse(&md) {
                return Err(LifecycleError::Uncertain("unsafe log rotation target"));
            }
            Ok(true)
        }
    }
}

fn remove_if_regular_file(path: &Path) -> Result<()> {
    if check_regular_if_present(path)? {
        fs::remove_file(path)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

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
            let dir = base.join(format!("ab-rotlog-{label}-{}-{n}", std::process::id()));
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
    fn one_large_write_keeps_each_file_bounded_and_preserves_the_stream() {
        let root = TempRoot::new("large-write");
        let dir = private_store::ensure_private_dir(&root.0.join("logs")).unwrap();
        let path = dir.join("server.stdout.log");
        let mut writer = RotatingLogWriter::open_private(&path, RotatingLogPolicy {
            max_file_bytes: 64, max_backups: 2, ..Default::default()
        }).unwrap();
        let bytes: Vec<_> = (0..151).collect();
        writer.write_chunk(&bytes).unwrap();
        drop(writer);
        let mut restored = Vec::new();
        for part in [backup_path(&path, 2), backup_path(&path, 1), path] {
            let contents = fs::read(part).unwrap();
            assert!(contents.len() <= 64);
            restored.extend(contents);
        }
        assert_eq!(restored, bytes);
    }

    #[test]
    fn rotating_log_rotates_live_and_enforces_max_backups() {
        let root = TempRoot::new("live");
        let dir = private_store::ensure_private_dir(&root.0.join("logs")).unwrap();
        let path = dir.join("server.stdout.log");

        let mut writer = RotatingLogWriter::open_private(
            &path,
            RotatingLogPolicy {
                max_file_bytes: 100,
                max_backups: 2,
                max_age: Duration::from_secs(3600),
            },
        )
        .unwrap();

        for i in 0..8 {
            let line = format!("event-{i:02}-payload-0123456789abcdef0123456789\n");
            writer.write_chunk(line.as_bytes()).unwrap();
        }

        assert!(path.is_file());
        assert!(backup_path(&path, 1).is_file());
        assert!(backup_path(&path, 2).is_file());
        assert!(!backup_path(&path, 3).exists());
        assert!(writer.stats().rotations >= 2);
        assert_eq!(writer.stats().bytes_dropped, 0);
        assert!(fs::read_to_string(&path).unwrap().contains("event-07"));
    }

    #[test]
    fn rotating_log_preserves_and_rotates_across_restart() {
        let root = TempRoot::new("restart");
        let dir = private_store::ensure_private_dir(&root.0.join("logs")).unwrap();
        let path = dir.join("native.stderr.log");
        let policy = RotatingLogPolicy {
            max_file_bytes: 80,
            max_backups: 2,
            max_age: Duration::from_secs(3600),
        };

        {
            let mut w1 = RotatingLogWriter::open_private(&path, policy).unwrap();
            w1.write_chunk(b"boot-1-line-0123456789abcdef0123456789abcdef0123456789abcdef\n")
                .unwrap();
            assert!(fs::metadata(&path).unwrap().len() < 80);
        }

        // Restart 1: appends under cap without losing boot-1 line.
        {
            let mut w2 = RotatingLogWriter::open_private(&path, policy).unwrap();
            w2.write_chunk(b"boot-2-overflow-line-0123456789abcdef0123456789abcdef\n")
                .unwrap();
            assert!(w2.stats().rotations >= 1);
            assert!(fs::read_to_string(backup_path(&path, 1))
                .unwrap()
                .contains("boot-1-line"));
            assert!(fs::read_to_string(&path).unwrap().contains("boot-2-overflow"));
        }

        // Restart 2: pre-existing oversized active file rotates on startup.
        fs::write(&path, "oversized-line-".repeat(10)).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let w3 = RotatingLogWriter::open_private(&path, policy).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().len(), 0);
        assert!(fs::read_to_string(backup_path(&path, 1))
            .unwrap()
            .contains("oversized-line"));
        assert!(w3.stats().rotations >= 1);
    }

    #[test]
    fn rotating_log_prunes_backups_older_than_max_age() {
        let root = TempRoot::new("age");
        let dir = private_store::ensure_private_dir(&root.0.join("logs")).unwrap();
        let path = dir.join("server.log");
        let now_secs = Arc::new(AtomicU64::new(0));
        let now_clone = Arc::clone(&now_secs);
        let initial_now = SystemTime::now();
        now_secs.store(
            initial_now
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            Ordering::Relaxed,
        );

        let mut writer = RotatingLogWriter::open_with_opener_and_clock(
            &path,
            RotatingLogPolicy {
                max_file_bytes: 64,
                max_backups: 3,
                max_age: Duration::from_secs(30),
            },
            Box::new(|target| {
                private_store::open_private_file(target, private_store::OpenMode::CreateOrReadWrite)
                    .and_then(|file| {
                        drop(file);
                        private_store::open_private_file(target, private_store::OpenMode::Append)
                    })
                    .map_err(std::io::Error::other)
            }),
            Box::new(move || {
                SystemTime::UNIX_EPOCH + Duration::from_secs(now_clone.load(Ordering::Relaxed))
            }),
        )
        .unwrap();

        writer.write_chunk(&[b'a'; 50]).unwrap();
        writer.write_chunk(&[b'b'; 50]).unwrap();
        assert!(backup_path(&path, 1).is_file());

        // Advance logical clock past max_age and trigger rotation/prune.
        now_secs.fetch_add(600, Ordering::Relaxed);
        writer.prune_expired_backups().unwrap();
        assert!(!backup_path(&path, 1).exists());
    }

    #[test]
    fn rotating_log_survives_disk_outage_and_recovers_without_blocking() {
        let root = TempRoot::new("outage");
        let dir = private_store::ensure_private_dir(&root.0.join("logs")).unwrap();
        let path = dir.join("native.stdout.log");

        let mut writer = RotatingLogWriter::open_private(
            &path,
            RotatingLogPolicy {
                max_file_bytes: 64,
                max_backups: 2,
                max_age: Duration::from_secs(3600),
            },
        )
        .unwrap();

        writer.write_best_effort(b"before-outage-line-0123456789abcdef0123456789abcdef\n");
        assert_eq!(writer.stats().io_errors, 0);

        // Induce outage on next rotation by putting a directory at backup `.1`.
        let blocked_backup = backup_path(&path, 1);
        fs::create_dir(&blocked_backup).unwrap();

        writer.write_best_effort(b"triggers-rotation-failure-0123456789abcdef01234567\n");
        assert_eq!(writer.stats().io_errors, 1);
        assert!(writer.stats().bytes_dropped > 0);

        // Heal outage and verify subsequent writes recover automatically.
        fs::remove_dir(&blocked_backup).unwrap();
        writer.write_best_effort(b"after-recovery-line\n");
        assert_eq!(writer.stats().io_errors, 1);
        assert!(fs::read_to_string(&path).unwrap().contains("after-recovery-line"));
    }

    #[test]
    fn rotating_log_refuses_symlinks_and_reparse_points() {
        let root = TempRoot::new("unsafe");
        let dir = private_store::ensure_private_dir(&root.0.join("logs")).unwrap();
        assert!(RotatingLogWriter::open_private(
            Path::new("relative.log"),
            RotatingLogPolicy::default(),
        )
        .is_err());

        #[cfg(unix)]
        {
            let target = dir.join("target.log");
            fs::write(&target, b"x").unwrap();
            let link = dir.join("alias.log");
            std::os::unix::fs::symlink(&target, &link).unwrap();
            assert!(RotatingLogWriter::open_private(&link, RotatingLogPolicy::default()).is_err());
        }

        // Pre-existing directory at active log path must be refused.
        let dir_as_file = dir.join("dir.log");
        fs::create_dir(&dir_as_file).unwrap();
        assert!(RotatingLogWriter::open_private(&dir_as_file, RotatingLogPolicy::default()).is_err());
    }
}
