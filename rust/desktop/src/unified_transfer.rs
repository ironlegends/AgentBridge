use super::*;
use std::io::{Seek, SeekFrom, Write};
use workspace_write::Identity;

pub(super) const MAX_TRANSFER_BYTES: usize = 64 * 1024 * 1024;
pub(super) const BLOCK_BYTES: usize = 65536;

#[cfg(test)]
#[path = "unified_transfer_tests.rs"]
mod tests;

#[cfg(windows)]
#[path = "unified_transfer_windows.rs"]
mod windows;

pub(super) struct Source {
    parent: Dir,
    name: String,
    file: File,
    before: Metadata,
    identity: Identity,
}

pub(super) struct Copied {
    pub bytes: usize,
    pub sha256: String,
    pub blocks: Vec<[u8; 32]>,
}

impl Source {
    pub fn open(parent: Dir, name: String) -> Result<Self> {
        let before = parent.symlink_metadata(&name)?;
        ensure_regular(&before)?;
        if before.len() > MAX_TRANSFER_BYTES as u64 {
            return Err(DesktopError::new("TRANSFER_TOO_LARGE", "A transfer is limited to64MiB"));
        }
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        #[cfg(unix)] { use cap_std::fs::OpenOptionsExt; options.custom_flags(libc::O_NONBLOCK); }
        let file = parent.open_with(&name, &options)?;
        ensure_regular(&file.metadata()?)?;
        let identity = workspace_write::identity(&file, 1)?;
        if !same_file(&before, &file.metadata()?) { return Err(changed()); }
        let source = Self { parent, name, file, before, identity };
        source.verify()?;
        Ok(source)
    }

    pub fn len(&self) -> usize { self.before.len() as usize }

    fn verify(&self) -> Result<()> {
        let after = self.file.metadata()?;
        ensure_regular(&after)?;
        if !same_file(&self.before, &after) || workspace_write::identity(&self.file, 1)? != self.identity {
            return Err(changed());
        }
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        #[cfg(unix)] { use cap_std::fs::OpenOptionsExt; options.custom_flags(libc::O_NONBLOCK); }
        ensure_regular(&self.parent.symlink_metadata(&self.name)?)?;
        let selected = self.parent.open_with(&self.name, &options)?;
        ensure_regular(&selected.metadata()?)?;
        if workspace_write::identity(&selected, 1)? != self.identity || !same_file(&self.before, &selected.metadata()?) {
            return Err(changed());
        }
        Ok(())
    }

    pub fn copy_to(&mut self, destination: &mut File) -> Result<Copied> {
        self.verify()?;
        self.file.seek(SeekFrom::Start(0))?;
        let mut buffer = [0u8; BLOCK_BYTES];
        let mut bytes = 0usize;
        let mut digest = Sha256::new();
        let mut blocks = Vec::new();
        loop {
            let mut filled = 0;
            while filled < buffer.len() {
                let n = self.file.read(&mut buffer[filled..])?;
                if n == 0 { break; }
                filled += n;
            }
            if filled == 0 { break; }
            bytes = bytes.checked_add(filled).filter(|n| *n <= MAX_TRANSFER_BYTES)
                .ok_or_else(|| DesktopError::new("TRANSFER_TOO_LARGE", "File grew beyond64MiB"))?;
            if bytes > self.len() { return Err(changed()); }
            destination.write_all(&buffer[..filled])?;
            #[cfg(test)] tests::after_copy_block(destination);
            digest.update(&buffer[..filled]);
            blocks.push(Sha256::digest(&buffer[..filled]).into());
        }
        if bytes != self.len() { return Err(changed()); }
        self.verify()?;
        destination.flush()?;
        destination.sync_all()?;
        destination.seek(SeekFrom::Start(0))?;
        Ok(Copied { bytes, sha256: format!("{:x}", digest.finalize()), blocks })
    }
}

fn changed() -> DesktopError {
    DesktopError::new("TRANSFER_SOURCE_CHANGED", "Source identity, size or content metadata changed during transfer")
}

pub(super) fn private_file_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true).follow(FollowSymlinks::No);
    #[cfg(unix)] { use cap_std::fs::OpenOptionsExt; options.mode(0o600); }
    options
}

pub(super) fn verify_private_directory(directory: &Dir) -> Result<()> {
    let metadata = directory.dir_metadata()?;
    ensure_directory(&metadata)?;
    #[cfg(unix)] {
        use cap_std::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o7777 != 0o700 {
            return Err(private_permissions());
        }
    }
    #[cfg(windows)] {
        use std::os::windows::io::AsRawHandle;
        windows::verify(directory.as_raw_handle())?;
    }
    #[cfg(not(any(unix, windows)))] { return Err(private_permissions()); }
    Ok(())
}

pub(super) fn verify_private_file(file: &File) -> Result<()> {
    workspace_write::ensure_single_hard_link(file)?;
    #[cfg(unix)] {
        use cap_std::fs::MetadataExt;
        let metadata = file.metadata()?;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o7777 != 0o600 {
            return Err(private_permissions());
        }
    }
    #[cfg(windows)] {
        use std::os::windows::io::AsRawHandle;
        windows::verify(file.as_raw_handle())?;
    }
    #[cfg(not(any(unix, windows)))] { return Err(private_permissions()); }
    Ok(())
}

fn private_permissions() -> DesktopError {
    DesktopError::new("PRIVATE_PERMISSIONS_REQUIRED", "Private transfer state must be owned by the current user and inaccessible to other accounts")
}

pub(super) struct AnonymousFile {
    pub file: Option<File>,
    name: String,
    #[cfg(unix)]
    unlinked: bool,
}

impl AnonymousFile {
    pub fn unlink_early(&mut self, directory: &Dir) -> Result<()> {
        #[cfg(unix)]
        if !self.unlinked {
            directory.remove_file(&self.name)?;
            self.unlinked = true;
        }
        #[cfg(not(unix))]
        let _ = directory;
        Ok(())
    }

    pub fn close(&mut self, directory: &Dir) -> Result<()> {
        // Keep the owner and its directory available if unlink cannot yet be
        // confirmed. A caller may retry this after a failed shutdown.
        self.unlink_early(directory)?;
        drop(self.file.take());
        match directory.symlink_metadata(&self.name) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            _ => Err(DesktopError::new("ARTIFACT_CLEANUP_PENDING", "Private artifact removal is not yet confirmed")),
        }
    }
}

pub(super) fn anonymous_file(directory: &Dir) -> Result<AnonymousFile> {
    let name = format!("art_{}.tmp", Uuid::new_v4().simple());
    let options = private_file_options();
    #[cfg(windows)]
    let options = {
        use cap_std::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_DELETE_ON_CLOSE;
        let mut options = options;
        // GENERIC_READ | GENERIC_WRITE | DELETE. Exclusive ownership prevents
        // another process from retaining a handle past this artifact's lifetime.
        options.access_mode(0xc001_0000).share_mode(0).custom_flags(FILE_FLAG_DELETE_ON_CLOSE);
        options
    };
    let file = directory.open_with(&name, &options)?;
    #[cfg(not(any(unix, windows)))] {
        drop(file);
        directory.remove_file(&name)?;
        return Err(DesktopError::new("UNSUPPORTED_PLATFORM", "Owned temporary artifacts require Windows or Unix"));
    }
    #[cfg(any(unix, windows))]
    Ok(AnonymousFile { file:Some(file), name, #[cfg(unix)] unlinked:false })
}

pub(super) fn private_child_directory(parent: &Dir, name: &str) -> Result<Dir> {
    verify_private_directory(parent)?;
    #[cfg(unix)]
    let builder = { use cap_std::fs::DirBuilderExt; let mut builder = DirBuilder::new(); builder.mode(0o700); builder };
    #[cfg(not(unix))]
    let builder = DirBuilder::new();
    match parent.create_dir_with(name, &builder) {
        Ok(()) => {},
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {},
        Err(error) => return Err(error.into()),
    }
    let child = open_child_dir(parent, name)?;
    verify_private_directory(&child)?;
    Ok(child)
}

pub(super) fn ownership_lock(directory: &Dir) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).follow(FollowSymlinks::No);
    #[cfg(unix)] { use cap_std::fs::OpenOptionsExt; options.mode(0o600); }
    #[cfg(windows)] { use cap_std::fs::OpenOptionsExt; options.share_mode(0); }
    let lock = directory.open_with("owner.lock", &options)
        .map_err(|_| DesktopError::new("ARTIFACT_STORE_BUSY", "Artifact state is owned by another instance or unavailable"))?;
    verify_private_file(&lock)?;
    #[cfg(unix)] {
        use std::os::fd::AsRawFd;
        // SAFETY: the descriptor remains live in the returned lock owner.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(DesktopError::new("ARTIFACT_STORE_BUSY", "Artifact state is owned by another instance"));
        }
    }
    if lock.metadata()?.len() != 0 { return Err(DesktopError::new("ARTIFACT_STATE_INVALID", "Artifact ownership marker is not empty")); }
    Ok(lock)
}
