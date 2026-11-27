//! Physical, read-only qualification shared by the two native providers.
use crate::runtime::RuntimeError;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry { path: String, size: u64, sha256: String }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest { schema: u32, platform: String, protocol: u32,
    winapp_version: String, vda_commit: String,
    files: BTreeMap<String, Entry>, notices: BTreeMap<String, Entry> }

pub(crate) struct Resources {
    pub root: PathBuf,
    pub native: PathBuf,
    pub winapp: PathBuf,
    winapp_sha256: String,
    _pins: Vec<File>,
}

pub(super) fn relative(value: &str) -> Result<PathBuf, RuntimeError> {
    if value.is_empty() || value.contains('\\') || value.chars().any(|c| c.is_control() || "<>:\"|?*".contains(c)) {
        return Err("NATIVE_RESOURCE_PATH_INVALID".into());
    }
    for part in value.split('/') {
        let stem = part.split('.').next().unwrap_or_default().to_ascii_lowercase();
        if part.is_empty() || part == "." || part == ".." || part.ends_with('.') || part.ends_with(' ')
            || matches!(stem.as_str(), "con" | "prn" | "aux" | "nul")
            || (stem.len() == 4 && (stem.starts_with("com") || stem.starts_with("lpt"))
                && matches!(stem.as_bytes()[3], b'1'..=b'9')) { return Err("NATIVE_RESOURCE_PATH_INVALID".into()); }
    }
    let path = PathBuf::from(value);
    if path.components().any(|component| !matches!(component, Component::Normal(_))) { return Err("NATIVE_RESOURCE_PATH_INVALID".into()); }
    Ok(path)
}
fn physical(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() { return false; }
    #[cfg(windows)] {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 { return false; }
    }
    true
}
pub(crate) fn check_physical(path: &Path) -> Result<(), RuntimeError> {
    if !path.is_absolute() { return Err("NATIVE_PATH_NOT_ABSOLUTE".into()); }
    let mut prefix = PathBuf::new();
    for component in path.components() {
        if matches!(component, Component::ParentDir | Component::CurDir) { return Err("NATIVE_PATH_INVALID".into()); }
        prefix.push(component);
        if matches!(component, Component::Prefix(_) | Component::RootDir) { continue; }
        if !physical(&fs::symlink_metadata(&prefix)?) { return Err("NATIVE_REPARSE_POINT_REFUSED".into()); }
    }
    Ok(())
}
pub(crate) fn pin(path: &Path, directory: bool) -> Result<File, RuntimeError> {
    pin_with_directory_sharing(path, directory, false)
}

fn pin_with_directory_sharing(path: &Path, directory: bool, mutable_directory: bool) -> Result<File, RuntimeError> {
    check_physical(path)?;
    let mut options = OpenOptions::new(); options.read(true);
    #[cfg(windows)] {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};
        // State directory ancestors must permit child-file mutations by the
        // normal account. Withhold FILE_SHARE_DELETE to prevent replacement
        // of the pinned directory; immutable bundle pins still share read only.
        let share=FILE_SHARE_READ | if directory && mutable_directory { FILE_SHARE_WRITE } else { 0 };
        options.share_mode(share).custom_flags(0x00200000 | if directory { 0x02000000 } else { 0 });
    }
    #[cfg(not(windows))]
    let _ = mutable_directory;
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !physical(&metadata) || metadata.is_dir() != directory || (!directory && !metadata.is_file()) {
        return Err("NATIVE_RESOURCE_TYPE_INVALID".into());
    }
    Ok(file)
}
pub(crate) fn ordinary(path: &Path) -> Result<PathBuf, RuntimeError> {
    check_physical(path)?;
    let canonical = path.canonicalize()?;
    #[cfg(windows)] {
        let text = canonical.to_str().ok_or("NATIVE_PATH_ENCODING")?;
        let result = if let Some(rest) = text.strip_prefix("\\\\?\\UNC\\") { PathBuf::from(format!("\\\\{rest}")) }
            else if let Some(rest) = text.strip_prefix("\\\\?\\") { PathBuf::from(rest) }
            else { canonical.clone() };
        check_physical(&result)?;
        if result.canonicalize()? != canonical { return Err("NATIVE_PATH_IDENTITY_CHANGED".into()); }
        Ok(result)
    }
    #[cfg(not(windows))] { Ok(canonical) }
}
pub(crate) fn private_directory(path: &Path) -> Result<(PathBuf, Vec<File>), RuntimeError> {
    if !path.is_absolute() { return Err("NATIVE_PRIVATE_PATH_NOT_ABSOLUTE".into()); }
    let mut prefix = PathBuf::new(); let mut pins = Vec::new();
    for component in path.components() {
        if matches!(component, Component::CurDir | Component::ParentDir) { return Err("NATIVE_PRIVATE_PATH_INVALID".into()); }
        prefix.push(component);
        if matches!(component, Component::Prefix(_) | Component::RootDir) { continue; }
        if !prefix.exists() { fs::create_dir(&prefix)?; }
        pins.push(pin_with_directory_sharing(&prefix, true, true)?);
    }
    Ok((ordinary(path)?, pins))
}
fn digest(file: &mut File, maximum: u64) -> Result<(u64, String), RuntimeError> {
    let mut hash = Sha256::new(); let mut buffer = [0u8; 65536]; let mut bytes = 0u64;
    loop {
        let count = file.read(&mut buffer)?; if count == 0 { break; }
        bytes = bytes.checked_add(count as u64).filter(|size| *size <= maximum).ok_or("NATIVE_RESOURCE_SIZE_LIMIT")?;
        hash.update(&buffer[..count]);
    }
    Ok((bytes, hash.finalize().iter().map(|b| format!("{b:02x}")).collect()))
}
// No exact-passive NativeAOT image has yet been independently packaged,
// reviewed and pinned. Never infer support from command-line parsing or a
// mutable manifest field. Keep the previously pinned bundle usable only for
// the other native operations.
const EXACT_PASSIVE_WINAPP_SHA256: Option<&str> = None;
impl Resources {
    pub(super) fn exact_passive_capture_qualified(&self)->bool{
        EXACT_PASSIVE_WINAPP_SHA256.is_some_and(|pin|pin==self.winapp_sha256)
    }
    pub(crate) fn verify(root: &Path, seal: &str) -> Result<Self, RuntimeError> {
        if seal.len() != 64 || !seal.bytes().all(|c| c.is_ascii_hexdigit()) { return Err("NATIVE_MANIFEST_PIN_REQUIRED".into()); }
        let root = ordinary(root)?;
        let mut pins = vec![pin(&root, true)?];
        let manifest_path = root.join("manifest.json");
        let mut manifest_file = pin(&manifest_path, false)?;
        if manifest_file.metadata()?.len() > 65536 { return Err("NATIVE_MANIFEST_LIMIT".into()); }
        let mut bytes = Vec::new(); manifest_file.read_to_end(&mut bytes)?;
        if Sha256::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect::<String>() != seal.to_ascii_lowercase() { return Err("NATIVE_MANIFEST_CHANGED".into()); }
        let manifest: Manifest = serde_json::from_slice(&bytes)?;
        if manifest.schema != 1 || manifest.platform != "windows-x64" || manifest.protocol != 1
            || manifest.winapp_version != "0.5.0-agentbridge.2" || manifest.vda_commit != "8172097993b1194e3d5e2ff38421ebb06f867b6c" {
            return Err("NATIVE_DEPENDENCY_PIN_MISMATCH".into());
        }
        if manifest.files.len() != 4 || manifest.notices.is_empty() || manifest.notices.len() > 64 { return Err("NATIVE_MANIFEST_ENTRIES_INVALID".into()); }
        for (key, path, pin) in [
            ("native", "agent-bridge-native.exe", None),
            ("winapp", "winapp/winapp.exe", Some("2251c7a7a476b6cc527982bc5846e2433f524ff88796b6e9d16362918bdc3cc3")),
            ("skia", "winapp/libSkiaSharp.dll", Some("9a0d95e8caaa852c70d085af6a40a744242172ad9ea3fd6bc7599875a8a1dbcd")),
            ("vda", "VirtualDesktopAccessor.dll", Some("716c4ed3a38eaf3f318ae670949799f74d8030c7f79a117e903bcb73b14354b4")),
        ] {
            let entry = manifest.files.get(key).ok_or("NATIVE_RESOURCE_MISSING")?;
            if entry.path != path || pin.is_some_and(|expected| expected != entry.sha256) { return Err("NATIVE_DEPENDENCY_PIN_MISMATCH".into()); }
        }
        let mut expected = BTreeMap::new(); let mut aliases = BTreeSet::new(); let mut total = 0u64;
        for entry in manifest.files.values().chain(manifest.notices.values()) {
            let path = relative(&entry.path)?;
            if entry.path == "manifest.json" || !aliases.insert(entry.path.to_lowercase()) || entry.sha256.len() != 64
                || !entry.sha256.bytes().all(|c| c.is_ascii_hexdigit()) || entry.size == 0 {
                return Err("NATIVE_MANIFEST_ALIAS_OR_DIGEST".into());
            }
            total = total.checked_add(entry.size).filter(|size| *size <= 1024 * 1024 * 1024).ok_or("NATIVE_BUNDLE_SIZE_LIMIT")?;
            expected.insert(path, entry);
        }
        let mut pending = vec![root.clone()]; let mut seen = BTreeSet::new();
        while let Some(directory) = pending.pop() {
            for item in fs::read_dir(directory)? {
                let path = item?.path(); let metadata = fs::symlink_metadata(&path)?;
                if !physical(&metadata) { return Err("NATIVE_RESOURCE_LINK_REFUSED".into()); }
                if metadata.is_dir() { pins.push(pin(&path, true)?); pending.push(path); continue; }
                if path == manifest_path { continue; }
                let relative = path.strip_prefix(&root)?;
                let entry = expected.get(relative).ok_or("NATIVE_UNLISTED_RESOURCE")?;
                let mut file = pin(&path, false)?;
                if file.metadata()?.len() != entry.size { return Err("NATIVE_RESOURCE_SIZE_MISMATCH".into()); }
                let (size, hash) = digest(&mut file, entry.size)?;
                if size != entry.size || hash != entry.sha256.to_ascii_lowercase() { return Err("NATIVE_RESOURCE_CHANGED".into()); }
                seen.insert(relative.to_path_buf()); pins.push(file);
            }
        }
        if seen.len() != expected.len() { return Err("NATIVE_RESOURCE_MISSING".into()); }
        pins.push(manifest_file);
        let winapp_sha256=manifest.files.get("winapp").ok_or("NATIVE_RESOURCE_MISSING")?.sha256.clone();
        Ok(Self { native: root.join("agent-bridge-native.exe"), winapp: root.join("winapp/winapp.exe"),
            winapp_sha256, root, _pins: pins })
    }
}

pub(crate) fn uuid() -> Result<String, RuntimeError> {
    let mut bytes = [0u8; 16]; getrandom::fill(&mut bytes).map_err(|_| "NATIVE_RANDOM_UNAVAILABLE")?;
    bytes[6] = bytes[6] & 15 | 64; bytes[8] = bytes[8] & 63 | 128;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(format!("{}-{}-{}-{}-{}", &hex[..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..]))
}
pub(crate) fn valid_uuid(value: &str) -> bool {
    value.len() == 36 && value != "00000000-0000-0000-0000-000000000000" && value.bytes().enumerate().all(|(index, c)|
        if matches!(index, 8 | 13 | 18 | 23) { c == b'-' } else { c.is_ascii_hexdigit() })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(windows)]
    #[test]
    fn private_directory_pins_allow_sibling_mutation_but_prevent_replacement() {
        let base=std::env::temp_dir().join(format!("ab-private-directory-pin-{}",uuid().unwrap()));
        let state=base.join("private").join("state");
        fs::create_dir_all(&state).unwrap();
        let target=base.join("outside.txt");
        let staged=base.join("staged.txt");
        fs::write(&target,b"old").unwrap();
        fs::write(&staged,b"new").unwrap();
        let (_path,pins)=private_directory(&state).unwrap();
        // The provider pins the common ancestor of the mutable file and its
        // private state. A live provider must not deny a sibling file rename.
        let replaced=fs::rename(&staged,&target);
        let bytes=fs::read(&target).unwrap();
        let directory_rename=fs::rename(&state,base.join("moved"));
        drop(pins);
        fs::remove_dir_all(&base).unwrap();
        assert!(replaced.is_ok(),"native state pins interfered with sibling replace: {replaced:?}");
        assert_eq!(bytes,b"new");
        assert!(directory_rename.is_err(),"a pinned state directory must not be replaceable");
    }

    #[test] fn paths_and_ids_do_not_accept_aliases() {
        for invalid in ["../native.exe", "C:/native.exe", "a\\b", "a//b", "CON.txt", "a/NUL", "x. "] { assert!(relative(invalid).is_err()); }
        assert!(valid_uuid(&uuid().unwrap())); assert!(!valid_uuid("00000000-0000-0000-0000-000000000000"));
    }
}
