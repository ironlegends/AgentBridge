//! Transfer one already-owned, read-only project directory to a fixed child.
//! The private socket becomes stdin. Its first byte carries one SCM_RIGHTS
//! descriptor; subsequent bytes are the existing bounded JSON protocol.
//! No path is opened here, and argv never supplies a raw descriptor number.

use std::fs::File;
use std::io;
use std::mem::{size_of, size_of_val, zeroed};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::process::Stdio;

const BINDING_PREFIX: &str = "agent-bridge.metadata.unix.fd.v1";
const MARKER: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DirectoryIdentity { device: u64, inode: u64 }

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn directory_identity(file: &File) -> io::Result<DirectoryIdentity> {
    let metadata = file.metadata()?;
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 { return Err(io::Error::last_os_error()); }
    if !metadata.is_dir() || metadata.nlink() == 0 || metadata.ino() == 0
        || flags & libc::O_ACCMODE != libc::O_RDONLY
    {
        return Err(invalid("Project capability is not a live read-only directory"));
    }
    Ok(DirectoryIdentity { device: metadata.dev(), inode: metadata.ino() })
}

fn parse_binding(binding: &str) -> io::Result<DirectoryIdentity> {
    if binding.len() > 128 { return Err(invalid("Project binding is oversized")); }
    let mut parts = binding.split(':');
    if parts.next() != Some(BINDING_PREFIX) { return Err(invalid("Invalid project binding")); }
    let mut number = || -> io::Result<u64> {
        let value = parts.next().ok_or_else(|| invalid("Incomplete project binding"))?;
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(invalid("Invalid project identity"));
        }
        value.parse().map_err(|_| invalid("Invalid project identity"))
    };
    let identity = DirectoryIdentity { device: number()?, inode: number()? };
    if parts.next().is_some() || identity.inode == 0 {
        return Err(invalid("Invalid project binding fields"));
    }
    Ok(identity)
}

/// A preloaded, private stdin channel for exactly one fixed child.
/// Dropping it before spawn closes both endpoints and the queued capability.
pub struct PreparedProjectDirectory {
    child: UnixStream,
    parent: UnixStream,
    binding: String,
}

impl PreparedProjectDirectory {
    /// `directory` must be cloned from the caller's existing project root.
    /// The one-byte handle transfer is nonblocking and occurs before spawn.
    pub fn new(directory: File) -> io::Result<Self> {
        let identity = directory_identity(&directory)?;
        let (parent, child) = UnixStream::pair()?;
        #[cfg(target_vendor = "apple")]
        {
            let enabled: libc::c_int = 1;
            if unsafe { libc::setsockopt(parent.as_raw_fd(), libc::SOL_SOCKET,
                libc::SO_NOSIGPIPE, (&enabled as *const libc::c_int).cast(),
                size_of::<libc::c_int>() as libc::socklen_t) } != 0
            { return Err(io::Error::last_os_error()); }
        }
        let mut marker = MARKER;
        let mut vector = libc::iovec {
            iov_base: (&mut marker as *mut u8).cast(), iov_len: 1,
        };
        // usize gives the alignment required by cmsghdr on supported Unix.
        let mut control = [0usize; 8];
        let space = unsafe { libc::CMSG_SPACE(size_of::<RawFd>() as _) } as usize;
        if space > size_of_val(&control) { return Err(invalid("Ancillary header exceeds bound")); }
        let mut message: libc::msghdr = unsafe { zeroed() };
        message.msg_iov = &mut vector;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = space as _;
        let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
        if header.is_null() { return Err(invalid("Ancillary header unavailable")); }
        // SAFETY: the aligned buffer covers CMSG_SPACE for one valid owned FD.
        unsafe {
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(size_of::<RawFd>() as _) as _;
            std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<RawFd>(), directory.as_raw_fd());
        }
        #[cfg(target_vendor = "apple")]
        let flags = libc::MSG_DONTWAIT;
        #[cfg(not(target_vendor = "apple"))]
        let flags = libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL;
        let sent = unsafe { libc::sendmsg(parent.as_raw_fd(), &message, flags) };
        if sent < 0 { return Err(io::Error::last_os_error()); }
        if sent != 1 { return Err(invalid("Project capability was not transferred")); }
        Ok(Self {
            child, parent,
            binding: format!("{BINDING_PREFIX}:{}:{}", identity.device, identity.inode),
        })
    }

    pub fn binding(&self) -> &str { &self.binding }

    /// Supply stdin to Command and retain the peer as the child's sole writer.
    /// Both sockets retain CLOEXEC; Command duplicates only the child end to 0.
    pub fn into_stdio(self) -> (Stdio, File) {
        let child: OwnedFd = self.child.into();
        let parent: OwnedFd = self.parent.into();
        (Stdio::from(child), File::from(parent))
    }
}

/// Receive the preloaded capability at the private child's early entry point,
/// before starting worker threads. Missing data, extra handles, mismatched
/// identities and ordinary pipe/file stdin all fail closed without path opens.
pub fn receive_project_directory(input: BorrowedFd<'_>, binding: &str) -> io::Result<File> {
    let expected = parse_binding(binding)?;
    let mut marker = 0u8;
    let mut vector = libc::iovec {
        iov_base: (&mut marker as *mut u8).cast(), iov_len: 1,
    };
    let mut control = [0usize; 8];
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = size_of_val(&control) as _;
    #[cfg(target_os = "linux")]
    let flags = libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let flags = libc::MSG_DONTWAIT;
    let received = unsafe { libc::recvmsg(input.as_raw_fd(), &mut message, flags) };
    if received < 0 { return Err(io::Error::last_os_error()); }

    // Own every delivered descriptor before validating the frame, including
    // unexpected extra rights. Error paths must close all received handles.
    let mut descriptors = Vec::<OwnedFd>::new();
    let mut valid = received == 1 && marker == MARKER
        && message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) == 0;
    let end = control.as_ptr() as usize + message.msg_controllen as usize;
    let base = unsafe { libc::CMSG_LEN(0) } as usize;
    let mut header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    while !header.is_null() {
        // SAFETY: recvmsg supplies kernel-generated ancillary headers in the
        // aligned bounded buffer. Bounds are checked before reading FD data.
        let length = unsafe { (*header).cmsg_len } as usize;
        if length < base || (header as usize).checked_add(length).is_none_or(|n| n > end) {
            valid = false;
            break;
        }
        if unsafe { (*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_RIGHTS } {
            let bytes = length - base;
            valid &= bytes % size_of::<RawFd>() == 0;
            for index in 0..bytes / size_of::<RawFd>() {
                let raw = unsafe { std::ptr::read_unaligned(
                    libc::CMSG_DATA(header).cast::<RawFd>().add(index),
                ) };
                if raw < 0 { valid = false; continue; }
                // SCM_RIGHTS creates a new descriptor owned by this receiver.
                descriptors.push(unsafe { OwnedFd::from_raw_fd(raw) });
            }
        } else { valid = false; }
        header = unsafe { libc::CMSG_NXTHDR(&message, header) };
    }
    for descriptor in &descriptors {
        let previous = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFD) };
        if previous < 0 || unsafe {
            libc::fcntl(descriptor.as_raw_fd(), libc::F_SETFD, previous | libc::FD_CLOEXEC)
        } < 0 { return Err(io::Error::last_os_error()); }
    }
    if !valid || descriptors.len() != 1 {
        return Err(invalid("Expected exactly one owned project directory capability"));
    }
    let directory = File::from(descriptors.pop().expect("one verified descriptor"));
    if directory_identity(&directory)? != expected {
        return Err(invalid("Received project directory identity mismatch"));
    }
    Ok(directory)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::AsFd;

    #[test]
    fn socket_transfers_the_owned_directory_and_restores_cloexec() {
        let directory = File::open(std::env::temp_dir()).unwrap();
        let expected = directory_identity(&directory).unwrap();
        let prepared = PreparedProjectDirectory::new(directory).unwrap();
        let received = receive_project_directory(prepared.child.as_fd(), prepared.binding()).unwrap();
        assert_eq!(directory_identity(&received).unwrap(), expected);
        assert_ne!(unsafe { libc::fcntl(received.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC, 0);
    }

    #[test]
    fn socket_rejects_a_handle_with_a_different_directory_identity() {
        let directory = File::open(std::env::temp_dir()).unwrap();
        let expected = directory_identity(&directory).unwrap();
        let prepared = PreparedProjectDirectory::new(directory).unwrap();
        let wrong = format!("{BINDING_PREFIX}:{}:{}", expected.device ^ 1, expected.inode);
        assert!(receive_project_directory(prepared.child.as_fd(), &wrong).is_err());
    }

    #[test]
    fn binding_without_a_transferred_descriptor_never_opens_a_path() {
        let (mut parent, child) = UnixStream::pair().unwrap();
        parent.write_all(&[MARKER]).unwrap();
        assert!(receive_project_directory(child.as_fd(), &format!("{BINDING_PREFIX}:1:1")).is_err());
        assert!(receive_project_directory(child.as_fd(), "../arbitrary-path").is_err());
    }
}
