use crate::runtime::RuntimeError;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry { path: String, bytes: u64, sha256: String }
#[derive(Deserialize)]
struct Node { version: String, path: String, sha256: String }
#[derive(Deserialize)]
struct Playwright { version: String, sri: String }
#[derive(Deserialize)]
struct Browser { version: String, revision: String, executable: String }
#[derive(Deserialize)]
struct Manifest { schema_version: u32, protocol_version: u32, worker: String,
    node: Node, playwright: Playwright, browser: Browser, files: Vec<Entry> }

pub(super) struct Resources {
    #[cfg(windows)]
    pub root: PathBuf,
    #[cfg(windows)]
    pub node: PathBuf,
    #[cfg(windows)]
    pub worker: PathBuf,
    #[cfg(windows)]
    pub chromium: PathBuf,
    _pins: Vec<File>,
}

pub(super) fn relative(value: &str) -> Result<PathBuf, RuntimeError> {
    if value.is_empty() || value.contains('\\') || value.chars().any(|c| c.is_control() || "<>:\"|?*".contains(c)) {
        return Err("BROWSER_RESOURCE_PATH_INVALID".into());
    }
    for part in value.split('/') {
        let stem = part.split('.').next().unwrap_or_default().to_ascii_lowercase();
        if part.is_empty() || part == "." || part == ".." || part.ends_with('.') || part.ends_with(' ')
            || matches!(stem.as_str(), "con" | "prn" | "aux" | "nul")
            || (stem.len() == 4 && (stem.starts_with("com") || stem.starts_with("lpt"))
                && matches!(stem.as_bytes()[3], b'1'..=b'9')) {
            return Err("BROWSER_RESOURCE_PATH_INVALID".into());
        }
    }
    let path = PathBuf::from(value);
    if path.components().any(|component| !matches!(component, Component::Normal(_))) { return Err("BROWSER_RESOURCE_PATH_INVALID".into()); }
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
pub(super) fn check_physical(path: &Path) -> Result<(), RuntimeError> {
    if !path.is_absolute() { return Err("BROWSER_PRIVATE_PATH_NOT_ABSOLUTE".into()); }
    let mut prefix = PathBuf::new();
    for component in path.components() {
        if matches!(component, Component::ParentDir | Component::CurDir) { return Err("BROWSER_PRIVATE_PATH_INVALID".into()); }
        prefix.push(component);
        if matches!(component, Component::Prefix(_) | Component::RootDir) { continue; }
        if !physical(&fs::symlink_metadata(&prefix)?) { return Err("BROWSER_REPARSE_POINT_REFUSED".into()); }
    }
    Ok(())
}

#[cfg(windows)]
pub(super) fn node_path(path: &Path) -> Result<PathBuf, RuntimeError> {
    let canonical = path.canonicalize()?;
    // Node's main-module resolver rejects a verbatim drive-path argument.
    // Remove that presentation prefix only when it resolves to the same
    // already-qualified physical path; never normalize an authority alias.
    let text = canonical.to_str().ok_or("BROWSER_NODE_PATH_ENCODING")?;
    let ordinary = if let Some(rest) = text.strip_prefix("\\\\?\\UNC\\") { PathBuf::from(format!("\\\\{rest}")) }
        else if let Some(rest) = text.strip_prefix("\\\\?\\") { PathBuf::from(rest) }
        else { canonical.clone() };
    check_physical(&ordinary)?;
    if ordinary.canonicalize()? != canonical { return Err("BROWSER_NODE_PATH_IDENTITY_CHANGED".into()); }
    Ok(ordinary)
}

pub(super) fn pin(path: &Path, directory: bool) -> Result<File, RuntimeError> {
    check_physical(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)] {
        use std::os::windows::fs::OpenOptionsExt;
        // Deny writes/deletes while this exact resource is qualified and in use.
        options.share_mode(1).custom_flags(0x00200000 | if directory { 0x02000000 } else { 0 });
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !physical(&metadata) || metadata.is_dir() != directory || (!directory && !metadata.is_file()) {
        return Err("BROWSER_RESOURCE_TYPE_INVALID".into());
    }
    Ok(file)
}

pub(super) fn digest(file: &mut File, maximum: u64) -> Result<(u64, String), RuntimeError> {
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut bytes = 0u64;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 { break; }
        bytes = bytes.checked_add(count as u64).ok_or("BROWSER_RESOURCE_SIZE_OVERFLOW")?;
        if bytes > maximum { return Err("BROWSER_RESOURCE_SIZE_MISMATCH".into()); }
        hash.update(&buffer[..count]);
    }
    Ok((bytes, hash.finalize().iter().map(|b| format!("{b:02x}")).collect()))
}

fn validate_diagnostic_guard(expected: &BTreeMap<PathBuf, Entry>, executable: &Path) -> Result<(), RuntimeError> {
    let guard = executable.parent().ok_or("BROWSER_RESOURCE_PATH_INVALID")?.join("debug.log");
    let entry = expected.get(&guard).ok_or("BROWSER_DIAGNOSTIC_GUARD_MISSING")?;
    if entry.bytes != 0 || !entry.sha256.eq_ignore_ascii_case("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") {
        return Err("BROWSER_DIAGNOSTIC_GUARD_INVALID".into());
    }
    Ok(())
}

impl Resources {
    pub(super) fn verify(root: &Path, expected_manifest: &str) -> Result<Self, RuntimeError> {
        if expected_manifest.len() != 64 || !expected_manifest.bytes().all(|c| c.is_ascii_hexdigit()) { return Err("BROWSER_MANIFEST_PIN_REQUIRED".into()); }
        check_physical(root)?;
        let root = root.canonicalize()?;
        let mut pins = vec![pin(&root, true)?];
        let manifest_path = root.join("manifest.json");
        let mut manifest_file = pin(&manifest_path, false)?;
        if manifest_file.metadata()?.len() > 8 * 1024 * 1024 { return Err("BROWSER_MANIFEST_LIMIT".into()); }
        let mut bytes = Vec::new(); manifest_file.read_to_end(&mut bytes)?;
        if Sha256::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect::<String>() != expected_manifest.to_ascii_lowercase() { return Err("BROWSER_MANIFEST_CHANGED".into()); }
        let manifest: Manifest = serde_json::from_slice(&bytes)?;
        if manifest.schema_version != 1 || manifest.protocol_version != 2 || manifest.node.version != "24.14.0"
            || manifest.node.sha256 != "63c259c81e5d472b5f11c8d506070130cb04a1ecf84b80377a34ed6ec9048088"
            || manifest.playwright.version != "1.63.0"
            || manifest.playwright.sri != "sha512-rYCsBF/M5HjUch52bbtVONEFjv6Xu8sm8h72dNlR5bzIE1fvC/bxgspzkjSfU+MweEMmPM8KJebG6nnyxo5mCg=="
            || manifest.browser.version != "153.0.8010.12" || manifest.browser.revision != "1243" {
            return Err("BROWSER_DEPENDENCY_PIN_MISMATCH".into());
        }
        if manifest.files.is_empty() || manifest.files.len() > 50_000 { return Err("BROWSER_MANIFEST_ENTRY_LIMIT".into()); }
        let mut expected = BTreeMap::new();
        let mut names = BTreeSet::new();
        let mut total = 0u64;
        for entry in manifest.files {
            let path = relative(&entry.path)?;
            if entry.path == "manifest.json" || !names.insert(entry.path.to_lowercase())
                || entry.sha256.len() != 64 || !entry.sha256.bytes().all(|c| c.is_ascii_hexdigit()) {
                return Err("BROWSER_MANIFEST_ALIAS_OR_DIGEST".into());
            }
            total = total.checked_add(entry.bytes).filter(|size| *size <= 4 * 1024 * 1024 * 1024u64).ok_or("BROWSER_BUNDLE_SIZE_LIMIT")?;
            expected.insert(path, entry);
        }
        let node_relative = relative(&manifest.node.path)?;
        let worker_relative = relative(&manifest.worker)?;
        let chrome_relative = relative(&manifest.browser.executable)?;
        for required in [&node_relative, &worker_relative, &chrome_relative] {
            if !expected.contains_key(required) { return Err("BROWSER_REQUIRED_RESOURCE_UNPINNED".into()); }
        }
        if expected[&node_relative].sha256 != manifest.node.sha256 { return Err("BROWSER_NODE_EXECUTABLE_MISMATCH".into()); }
        validate_diagnostic_guard(&expected, &chrome_relative)?;
        let mut pending = vec![root.clone()];
        let mut seen = BTreeSet::new();
        while let Some(directory) = pending.pop() {
            for item in fs::read_dir(directory)? {
                let path = item?.path();
                let metadata = fs::symlink_metadata(&path)?;
                if !physical(&metadata) { return Err("BROWSER_RESOURCE_LINK_REFUSED".into()); }
                if metadata.is_dir() { pins.push(pin(&path, true)?); pending.push(path); continue; }
                if path == manifest_path { continue; }
                let relative = path.strip_prefix(&root)?;
                let entry = expected.get(relative).ok_or("BROWSER_UNLISTED_RESOURCE")?;
                let mut file = pin(&path, false)?;
                if file.metadata()?.len() != entry.bytes { return Err("BROWSER_RESOURCE_SIZE_MISMATCH".into()); }
                let (_, hash) = digest(&mut file, entry.bytes)?;
                if hash != entry.sha256.to_ascii_lowercase() { return Err("BROWSER_RESOURCE_CHANGED".into()); }
                seen.insert(relative.to_path_buf()); pins.push(file);
            }
        }
        if seen.len() != expected.len() { return Err("BROWSER_RESOURCE_MISSING".into()); }
        pins.push(manifest_file);
        Ok(Self {
            #[cfg(windows)]
            node:root.join(node_relative),
            #[cfg(windows)]
            worker:root.join(worker_relative),
            #[cfg(windows)]
            chromium:root.join(chrome_relative),
            #[cfg(windows)]
            root,
            _pins:pins,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn diagnostic_guard_must_be_the_exact_empty_manifest_member_beside_chromium() {
        let executable = Path::new("browser/chrome-win64/chrome.exe");
        let guard = executable.parent().unwrap().join("debug.log");
        let mut entries = BTreeMap::new();
        assert!(validate_diagnostic_guard(&entries, executable).is_err());
        entries.insert(guard.clone(), Entry {
            path: "browser/chrome-win64/debug.log".into(), bytes: 0,
            sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
        });
        assert!(validate_diagnostic_guard(&entries, executable).is_ok());
        entries.get_mut(&guard).unwrap().bytes = 1;
        assert!(validate_diagnostic_guard(&entries, executable).is_err());
        entries.get_mut(&guard).unwrap().bytes = 0;
        entries.get_mut(&guard).unwrap().sha256 = "0".repeat(64);
        assert!(validate_diagnostic_guard(&entries, executable).is_err());
    }
    #[test]
    fn resource_paths_exclude_windows_aliases_and_absolute_authority() {
        for invalid in ["../node.exe", "C:/node.exe", "a\\node.exe", "/worker.mjs", "a//b", "CON.txt", "a/NUL", "x. ", "a/../b"] {
            assert!(relative(invalid).is_err(), "{invalid}");
        }
        assert_eq!(relative("browser/chrome-win64/chrome.exe").unwrap(), PathBuf::from("browser/chrome-win64/chrome.exe"));
    }
}
