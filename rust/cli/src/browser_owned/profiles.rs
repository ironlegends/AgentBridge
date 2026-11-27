#[cfg(windows)]
use super::resources::check_physical;
use super::resources::relative;
use crate::runtime::RuntimeError;
#[cfg(windows)]
use serde_json::{json, Value};
#[cfg(windows)]
use std::fs::{self, File, OpenOptions};
#[cfg(windows)]
use std::path::{Path, PathBuf};

#[cfg(windows)]
pub(super) struct Profiles { pub root: PathBuf, _lock: File }
#[cfg(windows)]
pub(super) struct SessionPaths { pub session: PathBuf, pub profile: PathBuf, pub persistent: bool }

pub(super) fn opaque_id() -> Result<String, RuntimeError> {
    let mut bytes = [0u8; 16]; getrandom::fill(&mut bytes).map_err(|_| "BROWSER_RANDOM_UNAVAILABLE")?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40; bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(format!("{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],bytes[1],bytes[2],bytes[3],bytes[4],bytes[5],bytes[6],bytes[7],bytes[8],bytes[9],bytes[10],bytes[11],bytes[12],bytes[13],bytes[14],bytes[15]))
}
pub(super) fn profile_id(id: &str) -> Result<(), RuntimeError> {
    if id.is_empty() || id.len() > 64 || !id.as_bytes()[0].is_ascii_alphanumeric()
        || !id.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-')) || relative(id).is_err() {
        return Err("BROWSER_PROFILE_ID_INVALID".into());
    }
    Ok(())
}
#[cfg(windows)]
pub(super) fn physical_directory(path: &Path) -> Result<PathBuf, RuntimeError> {
    check_physical(path)?;
    if !fs::metadata(path)?.is_dir() { return Err("BROWSER_PRIVATE_DIRECTORY_REQUIRED".into()); }
    Ok(path.canonicalize()?)
}
#[cfg(windows)]
pub(super) fn remove_physical_tree(path: &Path) -> Result<(), RuntimeError> {
    if !path.try_exists()? { return Ok(()); }
    check_physical(path)?;
    let mut pending = vec![path.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            let path = entry?.path(); check_physical(&path)?;
            if fs::metadata(&path)?.is_dir() { pending.push(path); }
        }
    }
    fs::remove_dir_all(path)?;
    Ok(())
}
// Only final cleanup after verified Job drain may wait for transient Windows
// sharing locks. Ordinary reap remains nonblocking for healthy sessions.
#[cfg(windows)]
pub(super) fn retire_after_verified_drain(
    mut attempt: impl FnMut() -> Result<(), RuntimeError>,
    mut observe: impl FnMut(&RuntimeError),
) -> Result<(), RuntimeError> {
    let mut delays = [20, 50, 100].into_iter();
    loop {
        match attempt() {
            Ok(()) => return Ok(()),
            Err(error) => {
                observe(&error);
                let sharing = cfg!(windows) && matches!(
                    error.downcast_ref::<std::io::Error>().and_then(std::io::Error::raw_os_error),
                    Some(32 | 33)
                );
                match (sharing, delays.next()) {
                    (true, Some(ms)) => std::thread::sleep(std::time::Duration::from_millis(ms)),
                    _ => return Err(error),
                }
            }
        }
    }
}
#[cfg(windows)]
impl Profiles {
    pub(super) fn open(root: &Path) -> Result<Self, RuntimeError> {
        if !root.is_absolute() { return Err("BROWSER_STATE_ROOT_NOT_ABSOLUTE".into()); }
        fs::create_dir_all(root)?;
        let root = physical_directory(root)?;
        let mut options = OpenOptions::new(); options.read(true).write(true).create(true).truncate(false);
        #[cfg(windows)] { use std::os::windows::fs::OpenOptionsExt; options.share_mode(0).custom_flags(0x00200000); }
        let lock = options.open(root.join("provider.lock"))?;
        check_physical(&root.join("provider.lock"))?;
        for name in ["profiles", "sessions"] { fs::create_dir_all(root.join(name))?; physical_directory(&root.join(name))?; }
        Ok(Self { root, _lock:lock })
    }
    pub(super) fn prepare(&self, session_id: &str, persistent: Option<&str>) -> Result<SessionPaths, RuntimeError> {
        let session = self.root.join("sessions").join(session_id);
        fs::create_dir(&session)?;
        let session = physical_directory(&session)?;
        let profile = if let Some(id) = persistent {
            profile_id(id)?;
            let path = self.root.join("profiles").join(id);
            fs::create_dir_all(&path)?;
            physical_directory(&path)?
        } else {
            let path = session.join("temporary-profile"); fs::create_dir(&path)?; physical_directory(&path)?
        };
        for name in ["uploads", "downloads", "raw-downloads"] { fs::create_dir(session.join(name))?; }
        Ok(SessionPaths { session, profile, persistent:persistent.is_some() })
    }
    pub(super) fn list(&self, active: &[String]) -> Result<Value, RuntimeError> {
        let mut rows = Vec::new();
        for entry in fs::read_dir(self.root.join("profiles"))? {
            let entry = entry?;
            let id = entry.file_name().to_string_lossy().into_owned(); profile_id(&id)?;
            physical_directory(&entry.path())?;
            rows.push(json!({"profile_id":id,"in_use":active.iter().any(|item| item.eq_ignore_ascii_case(&id))}));
        }
        rows.sort_by(|a,b| a["profile_id"].as_str().cmp(&b["profile_id"].as_str()));
        Ok(json!({"profiles":rows,"count":rows.len()}))
    }
    pub(super) fn delete(&self, id: &str, active: &[String]) -> Result<Value, RuntimeError> {
        profile_id(id)?;
        if active.iter().any(|item| item.eq_ignore_ascii_case(id)) { return Err("BROWSER_PROFILE_IN_USE".into()); }
        let path = self.root.join("profiles").join(id);
        if !path.try_exists()? { return Err("BROWSER_PROFILE_NOT_FOUND".into()); }
        remove_physical_tree(&path)?;
        Ok(json!({"profile_id":id,"deleted":true}))
    }
    pub(super) fn retire(paths: &SessionPaths) -> Result<(), RuntimeError> {
        for name in ["uploads", "downloads", "raw-downloads"] { remove_physical_tree(&paths.session.join(name))?; }
        if !paths.persistent { remove_physical_tree(&paths.profile)?; }
        // Retain only bounded diagnostics after verified Job cleanup.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(windows)]
    #[test]
    fn final_retirement_retries_a_released_sharing_lock_without_waiving_physical_checks() {
        use std::os::windows::fs::OpenOptionsExt;
        let root = std::env::temp_dir().canonicalize().unwrap().join(format!("ab-retire-{}",opaque_id().unwrap()));
        fs::create_dir(&root).unwrap();
        let profiles = Profiles::open(&root).unwrap();
        let paths = profiles.prepare(&opaque_id().unwrap(), None).unwrap();
        let witness = paths.profile.join("held.txt");
        let mut held = Some(OpenOptions::new().write(true).create_new(true).share_mode(0).open(&witness).unwrap());
        let mut attempts = 0;
        retire_after_verified_drain(|| {
            attempts += 1;
            let result = Profiles::retire(&paths);
            if attempts == 1 {
                let error = result.as_ref().unwrap_err();
                assert_eq!(error.downcast_ref::<std::io::Error>().and_then(std::io::Error::raw_os_error), Some(32));
                drop(held.take());
            }
            result
        }, |_| {}).unwrap();
        assert_eq!(attempts, 2);
        assert!(!paths.profile.exists());
        assert!(paths.session.exists());
        drop(profiles);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn final_retirement_preserves_persistent_lock_and_refuses_nonsharing_errors() {
        use std::os::windows::fs::OpenOptionsExt;
        let root = std::env::temp_dir().canonicalize().unwrap().join(format!("ab-retire-{}",opaque_id().unwrap()));
        fs::create_dir(&root).unwrap();
        let profiles = Profiles::open(&root).unwrap();
        let paths = profiles.prepare(&opaque_id().unwrap(), None).unwrap();
        let witness = paths.profile.join("held.txt");
        let held = OpenOptions::new().write(true).create_new(true).share_mode(0).open(&witness).unwrap();
        let mut attempts = 0;
        assert!(retire_after_verified_drain(|| {
            attempts += 1;
            Profiles::retire(&paths)
        }, |_| {}).is_err());
        assert_eq!(attempts, 4);
        assert!(witness.is_file());
        drop(held);
        Profiles::retire(&paths).unwrap();
        let mut refused = 0;
        assert!(retire_after_verified_drain(|| {
            refused += 1;
            Err("BROWSER_REPARSE_POINT_REFUSED".into())
        }, |_| {}).is_err());
        assert_eq!(refused, 1);
        drop(profiles);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn owned_profile_names_cannot_address_a_personal_or_device_path() {
        for value in ["../Default", "C:/Users", "a/b", "CON", "nul.txt", "-bad", "a."] { assert!(profile_id(value).is_err(), "{value}"); }
        profile_id("gemini-research.1").unwrap();
        let id = opaque_id().unwrap(); assert_eq!(id.len(), 36); assert_eq!(&id[14..15], "4");
    }
}
