//! No Unix project transfer grant is issued until equivalent file pins are
//! implemented. Browser pages, DOM actions and CDP remain available; neither
//! a project path nor a downloaded byte bypasses the existing transfer gate.
use std::io;
use std::path::PathBuf;
use super::chrome::native::DirectoryPin;

pub(super) const MAX_INPUT_BYTES: usize = 256 * 1024;
pub(super) const MAX_DOWNLOAD_BYTES: usize = 1024 * 1024;
fn unavailable() -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, "UNIX_PROJECT_BROWSER_TRANSFERS_UNAVAILABLE")
}
pub(super) struct ProjectInputPin {
    pub(super) relative: String,
    pub(super) basename: String,
    pub(super) size: u64,
    pub(super) sha256: String,
}
impl ProjectInputPin {
    pub(super) fn verify(&mut self) -> io::Result<PathBuf> { Err(unavailable()) }
}
pub(super) struct ProjectOutputPin { pub(super) relative: String }
impl ProjectOutputPin {
    pub(super) fn write_new(&self, _filename: &str, _bytes: &[u8]) -> io::Result<(String, u64, String)> {
        Err(unavailable())
    }
}
fn transfer_refused() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "BRIDGE_PROJECT_TRANSFER_REFUSED")
}

fn download_identity(metadata: &std::fs::Metadata) -> io::Result<(u64, u64, u64, u32, i64, i64, i64, i64)> {
    use std::os::unix::fs::MetadataExt;
    if !metadata.is_file() || metadata.nlink() != 1
        || metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o022 != 0
    {
        return Err(transfer_refused());
    }
    Ok((metadata.dev(), metadata.ino(), metadata.len(), metadata.mode(),
        metadata.mtime(), metadata.mtime_nsec(), metadata.ctime(), metadata.ctime_nsec()))
}

/// Read only from the download directory retained by the original Chrome
/// profile. A replacement directory, link, special file or changing file
/// cannot supply a successful transfer receipt.
pub(super) fn read_private_download(root: &DirectoryPin, guid: &str, max: usize) -> io::Result<Vec<u8>> {
    use std::io::Read;
    if max == 0 || max > MAX_DOWNLOAD_BYTES || guid.len() != 36
        || !guid.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) { b == b'-' } else { b.is_ascii_hexdigit() }
        })
    {
        return Err(transfer_refused());
    }
    root.require_private()?;
    let name = std::ffi::OsStr::new(guid);
    let mut file = root.open_file(name, libc::O_RDONLY)?;
    let before = download_identity(&file.metadata()?)?;
    if before.2 == 0 || before.2 > max as u64 {
        return Err(transfer_refused());
    }
    let mut bytes = Vec::new();
    (&mut file).take(max as u64 + 1).read_to_end(&mut bytes)?;
    root.require_private()?;
    root.verify_file(name, &file)?;
    let after = download_identity(&file.metadata()?)?;
    if after != before || bytes.len() as u64 != before.2 || bytes.len() > max {
        return Err(transfer_refused());
    }
    Ok(bytes)
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::Path;

    const GUID: &str = "12345678-1234-1234-1234-123456789abc";

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let base = fs::canonicalize(std::env::temp_dir()).unwrap();
            let parent = DirectoryPin::open(&base).unwrap();
            let pin = parent.create_child(std::ffi::OsStr::new(&format!(
                "agent-bridge-transfer-test-{}", super::super::chrome::random_id().unwrap()
            ))).unwrap();
            Self(pin.path().to_owned())
        }
        fn pin(&self) -> DirectoryPin {
            DirectoryPin::open(&self.0).unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = super::super::chrome::native::remove_private_tree(&self.0);
        }
    }
    fn write(root: &Path, bytes: &[u8]) {
        fs::write(root.join(GUID), bytes).unwrap();
        fs::set_permissions(root.join(GUID), fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn reads_exact_bounded_regular_download() {
        let fixture = Fixture::new();
        let pin = fixture.pin();
        write(&fixture.0, b"project witness");
        assert_eq!(read_private_download(&pin, GUID, 15).unwrap(), b"project witness");
        assert!(read_private_download(&pin, GUID, 14).is_err());
        assert!(read_private_download(&pin, GUID, 0).is_err());
        assert!(read_private_download(&pin, GUID, MAX_DOWNLOAD_BYTES + 1).is_err());
        for name in ["../outside", ".", "", "12345678-1234-1234-1234-123456789abz"] {
            assert!(read_private_download(&pin, name, MAX_DOWNLOAD_BYTES).is_err());
        }
        write(&fixture.0, b"");
        assert!(read_private_download(&pin, GUID, MAX_DOWNLOAD_BYTES).is_err());
    }

    #[test]
    fn refuses_linked_special_and_nonprivate_downloads() {
        let fixture = Fixture::new();
        let outside = Fixture::new();
        let pin = fixture.pin();
        write(&outside.0, b"unrelated");
        symlink(outside.0.join(GUID), fixture.0.join(GUID)).unwrap();
        assert!(read_private_download(&pin, GUID, MAX_DOWNLOAD_BYTES).is_err());
        fs::remove_file(fixture.0.join(GUID)).unwrap();
        fs::hard_link(outside.0.join(GUID), fixture.0.join(GUID)).unwrap();
        assert!(read_private_download(&pin, GUID, MAX_DOWNLOAD_BYTES).is_err());
        fs::remove_file(fixture.0.join(GUID)).unwrap();
        fs::create_dir(fixture.0.join(GUID)).unwrap();
        assert!(read_private_download(&pin, GUID, MAX_DOWNLOAD_BYTES).is_err());
        fs::remove_dir(fixture.0.join(GUID)).unwrap();
        let fifo = std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(
            fixture.0.join(GUID).as_os_str()
        )).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(read_private_download(&pin, GUID, MAX_DOWNLOAD_BYTES).is_err());
        fs::remove_file(fixture.0.join(GUID)).unwrap();
        write(&fixture.0, b"witness");
        fs::set_permissions(fixture.0.join(GUID), fs::Permissions::from_mode(0o666)).unwrap();
        assert!(read_private_download(&pin, GUID, MAX_DOWNLOAD_BYTES).is_err());
        fs::set_permissions(fixture.0.join(GUID), fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(read_private_download(&pin, GUID, MAX_DOWNLOAD_BYTES).is_err());
        fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(fs::read(outside.0.join(GUID)).unwrap(), b"unrelated");
    }

    #[test]
    fn refuses_replaced_download_root() {
        let fixture = Fixture::new();
        let pin = fixture.pin();
        let moved = fixture.0.with_extension("moved");
        fs::rename(&fixture.0, &moved).unwrap();
        fs::create_dir(&fixture.0).unwrap();
        fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o700)).unwrap();
        write(&fixture.0, b"replacement");
        let result = read_private_download(&pin, GUID, MAX_DOWNLOAD_BYTES);
        fs::remove_file(fixture.0.join(GUID)).unwrap();
        fs::remove_dir(&fixture.0).unwrap();
        fs::rename(&moved, &fixture.0).unwrap();
        assert!(result.is_err());
    }
}
