//! One-shot local operator import. The MCP dispatcher deliberately cannot
//! invoke these entry points or supply an external filesystem root.
use super::*;
use std::path::{Path, PathBuf};

const DISCOVERY_LIMIT: usize = 256;

fn refused(message: &'static str) -> SkillError {
    SkillError::new(SkillErrorCode::PathPolicyViolation, message)
}

fn root_spelling(path: &Path) -> Result<String, SkillError> {
    let normalized: PathBuf = path.components().collect();
    let text = normalized.to_str().ok_or_else(|| refused("Source root must be UTF-8"))?;
    if !path.is_absolute() || text.len() > 4096 || has_control_chars(text) {
        return Err(refused("Expected an explicit absolute source root"));
    }
    Ok(text.to_owned())
}

fn package_name(name: &str) -> Result<(), SkillError> {
    validate_path_segment(name)?;
    if name.starts_with('.') || name.len() > 255 {
        return Err(refused("Expected one named child skill directory"));
    }
    Ok(())
}

fn source_ref(root: &Path, package: &str) -> Result<String, SkillError> {
    // Do not expose a home directory or absolute path through the MCP
    // manifest. This is a fingerprint of the approved path spelling, not
    // a claim about the identity of a moving filesystem object.
    let spelling = root_spelling(root)?;
    Ok(format!("operator-root-sha256:{}/{}", sha256_hex(spelling.as_bytes()), package))
}

pub(super) fn valid_source_ref(value: &str) -> bool {
    value.strip_prefix("operator-root-sha256:")
        .and_then(|s| s.split_once('/'))
        .is_some_and(|(hash, package)| is_hex_64(hash)
            && hash.bytes().all(|b| !b.is_ascii_uppercase())
            && package_name(package).is_ok())
}

impl SkillManager {
    /// Bounded, non-recursive discovery. No package bytes are read; select
    /// one named child for a separate operator-approved import.
    pub fn discover_operator_root(
        root: &Path, confirm: impl FnOnce() -> bool,
    ) -> Result<Value, SkillError> {
        let spelling = root_spelling(root)?;
        if !confirm() { return Err(refused("Local operator approval required")); }
        let dir = super::super::open_workspace(root).map_err(skill_path_error)?;
        let mut candidates = Vec::new();
        let mut skipped = 0usize;
        let mut scanned = 0usize;
        for item in dir.entries().map_err(|e| SkillError::io("Read selected root", e))? {
            let item = item.map_err(|e| SkillError::io("Read selected root entry", e))?;
            if scanned == DISCOVERY_LIMIT {
                // No partially enumerated (and nondeterministically sorted)
                // candidate list is returned on an oversized root.
                return Err(SkillError::new(SkillErrorCode::LimitExceeded,
                    "Selected root exceeds 256 immediate entries; choose a narrower directory"));
            }
            scanned += 1;
            let os_name = item.file_name();
            let Some(name) = os_name.to_str() else { skipped += 1; continue; };
            if package_name(name).is_err() { skipped += 1; continue; }
            let Ok(child) = open_dir_nofollow(&dir, name) else { skipped += 1; continue; };
            // The existing no-follow + single-link check is applied even
            // during discovery. Opening this handle does not read its bytes.
            if open_file_nofollow(&child, SKILL_ENTRYPOINT).is_ok() {
                candidates.push(name.to_owned());
            } else {
                skipped += 1;
            }
        }
        candidates.sort();
        Ok(json!({"ok":true,"documentary_only":true,"execution_policy":"never_executed",
            "root_sha256":sha256_hex(spelling.as_bytes()),"candidates":candidates,
            "count":candidates.len(),"skipped":skipped,"scanned":scanned}))
    }

    /// Load exactly one approved package once. The operator sees metadata
    /// for these exact bytes and must accept them before publication.
    /// No root allowlist is retained and no remote provider is attached.
    pub fn import_operator_directory(
        private_store: &Path,
        root: &Path,
        package: &str,
        activate: bool,
        confirm_root: impl FnOnce() -> bool,
        confirm_snapshot: impl FnOnce(&Value) -> bool,
    ) -> Result<Value, SkillError> {
        package_name(package)?;
        let provenance = source_ref(root, package)?;
        if !confirm_root() { return Err(refused("Local operator source approval required")); }
        let workspace = super::super::open_workspace(root).map_err(skill_path_error)?;
        let store = super::super::open_workspace(private_store).map_err(skill_path_error)?;
        // No ambient canonicalization of a mutable source path. Compare
        // the existing path-policy identities of the qualified handles.
        use super::super::{path_policy, workspace_write};
        if workspace_write::dir_identity(&workspace).map_err(skill_path_error)?
            == workspace_write::dir_identity(&store).map_err(skill_path_error)? {
            return Err(refused("Source root and private store must be disjoint"));
        }
        #[cfg(windows)]
        let (source_path, store_path) = (
            path_policy::physical_directory_path(&workspace).map_err(skill_path_error)?,
            path_policy::physical_directory_path(&store).map_err(skill_path_error)?);
        #[cfg(not(windows))]
        let (source_path, store_path) = (
            path_policy::normalize_absolute(root).map_err(skill_path_error)?,
            path_policy::normalize_absolute(private_store).map_err(skill_path_error)?);
        if path_policy::contains_path(&source_path, &store_path)
            || path_policy::contains_path(&store_path, &source_path) {
            return Err(refused("Source root and private store must be disjoint"));
        }
        let manager = Self::new(store, workspace, SkillManagerConfig::for_operator("local"))?;
        let dir = open_dir_nofollow(&manager.workspace_dir, package)?;
        // Refuse a non-skill child before traversing its resources.
        let mut entrypoint = open_file_nofollow(&dir, SKILL_ENTRYPOINT)?;
        let bytes = read_file_bounded(&mut entrypoint,
            manager.config.limits.max_skill_md_bytes, SKILL_ENTRYPOINT)?;
        drop(entrypoint);
        if bytes.is_empty() || std::str::from_utf8(&bytes).is_err() {
            return Err(SkillError::new(SkillErrorCode::ValidationFailed,
                "SKILL.md must be nonempty UTF-8"));
        }
        let mut raw = Vec::new();
        let mut total = 0;
        let mut prefix = Vec::new();
        let mut remaining = directory_entry_budget(&manager.config.limits);
        collect_dir_files_recursive(&dir, &mut prefix, 0, &manager.config.limits,
            &mut total, &mut raw, &mut remaining, true)?;
        drop(dir);
        if !raw.iter().any(|file| file.relative_path == SKILL_ENTRYPOINT && file.bytes == bytes) {
            return Err(refused("SKILL.md changed during import"));
        }
        let mut loaded = assemble_and_validate_package(raw, None, Some(package),
            OPERATOR_SOURCE, &provenance, None, &manager.config.limits)?;
        if !loaded.frontmatter.get("license").is_some_and(|value| !value.trim().is_empty()) {
            loaded.warnings.push("No license declaration in SKILL.md; review any bundled license documents before approval".into());
        }
        let preview = loaded.to_manifest(0).to_json();
        if serde_json::to_vec_pretty(&preview).map_err(|_| refused("Invalid documentary manifest"))?.len() as u64
            > manager.config.limits.max_manifest_bytes {
            return Err(SkillError::new(SkillErrorCode::LimitExceeded, "Skill manifest exceeds its byte limit"));
        }
        if !confirm_snapshot(&preview) {
            return Err(refused("Local operator package approval required"));
        }
        // No read of the source occurs after consent. The immutable
        // revision and its provenance are committed through the old path.
        let mut receipt = manager.commit_loaded(loaded, activate)?;
        receipt["source_kind"] = json!(OPERATOR_SOURCE);
        receipt["source_ref"] = json!(provenance);
        receipt["license"] = preview["license"].clone();
        Ok(receipt)
    }

    /// A durable, local-only tombstone. All seven actions continue to use
    /// the same registry; no old revision can be read/activated/reimported.
    pub fn revoke_operator_import(
        private_store: &Path, name: &str, confirm: impl FnOnce() -> bool,
    ) -> Result<Value, SkillError> {
        validate_skill_name_str(name)?;
        if !confirm() { return Err(refused("Local operator revocation approval required")); }
        let store = super::super::open_workspace(private_store).map_err(skill_path_error)?;
        let workspace = store.try_clone().map_err(|e| SkillError::io("Clone private store", e))?;
        let manager = Self::new(store, workspace, SkillManagerConfig::for_operator("local"))?;
        let _in_proc = manager.in_process_lock.lock().map_err(|_| {
            SkillError::new(SkillErrorCode::LockTimeout, "Store mutex poisoned")
        })?;
        let _store_lock = manager.acquire_store_lock()?;
        let mut registry = manager.load_registry()?;
        let record = registry.skills.get_mut(name).filter(|rec| rec.import_source.is_some())
            .ok_or_else(|| SkillError::new(SkillErrorCode::NotFound, "Operator import not found"))?;
        let changed = !record.revoked;
        if changed {
            record.revoked = true;
            record.active_version = None;
            record.activation_history.clear();
            let now = now_epoch_s();
            record.updated_at_epoch_s = now;
            registry.updated_at_epoch_s = now;
            registry.schema_version = OPERATOR_REGISTRY_SCHEMA_VERSION;
            manager.save_registry_atomic(&registry)?;
        }
        Ok(json!({"ok":true,"name":name,"revoked":true,"changed":changed,
            "documentary_only":true,"active_version":null}))
    }
}
