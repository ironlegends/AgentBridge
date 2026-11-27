//! Documentary-only Agent Skills package manager for Agent Bridge.
//!
//! Design guarantees:
//! - Strictly documentary: bundled scripts/files are never executed and never granted execute bits.
//! - Capability-confined I/O: all filesystem operations run exclusively through operator-provided
//!   `cap_std::fs::Dir` handles (`store_dir` and `workspace_dir`), rejecting symlinks and traversal.
//! - Content-addressed immutable revisions (`sha256:<64-hex>`) with durable atomic writes and
//!   cross-process + in-process locking.
//! - No built-in network client or arbitrary download destination: `source_url` is gated behind
//!   Full/Unlock, canonical HTTPS origin allowlisting, SHA-256 verification, and an explicitly
//!   injected `ApprovedRemoteProvider`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{self, Read, Write};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{Dir, File, OpenOptions};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

mod zip_import;
mod operator_import;

pub const TOOL_NAME: &str = "desktop_skill_manage";
const REGISTRY_SCHEMA_VERSION: u64 = 1;
// V2 is published only after an explicit operator import. Old readers must
// refuse rather than silently ignore its source ownership or revocation.
const OPERATOR_REGISTRY_SCHEMA_VERSION: u64 = 2;
const OPERATOR_SOURCE: &str = "operator_approved_directory";
const REGISTRY_FILE_NAME: &str = "registry.json";
const LOCK_FILE_NAME: &str = ".skills.lock";
const STAGING_DIR_NAME: &str = "staging";
const SKILLS_DIR_NAME: &str = "skills";
const REVISIONS_DIR_NAME: &str = "revisions";
const FILES_DIR_NAME: &str = "files";
const MANIFEST_FILE_NAME: &str = "manifest.json";
const SKILL_ENTRYPOINT: &str = "SKILL.md";
const DEFAULT_MAX_CHARS: usize = 100_000;
const MIN_MAX_CHARS: usize = 1;
const MAX_MAX_CHARS: usize = 200_000;
const MAX_FRONTMATTER_LINES: usize = 128;

const WINDOWS_RESERVED_NAMES: &[&str] = &[
    "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
    "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
];

const SCRIPT_EXTENSIONS: &[&str] = &[
    "sh", "bash", "zsh", "fish", "ps1", "psm1", "psd1", "bat", "cmd", "py", "pyw", "js", "mjs",
    "cjs", "ts", "rb", "pl", "php", "lua", "exe", "dll", "so", "dylib", "vbs", "wsf",
];

/// Exact JSON Schema (`inputSchema`) matching the `desktop_skill_manage` contract.
pub fn input_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "properties": {
            "action": {
                "enum": ["list", "get", "read", "validate", "install", "activate", "rollback"],
                "type": "string"
            },
            "activate": {
                "default": true,
                "type": "boolean"
            },
            "expected_sha256": {
                "maxLength": 64,
                "minLength": 64,
                "type": "string"
            },
            "max_chars": {
                "default": 100000,
                "maximum": 200000,
                "minimum": 1,
                "type": "integer"
            },
            "name": {
                "maxLength": 64,
                "minLength": 1,
                "type": "string"
            },
            "resource_path": {
                "maxLength": 512,
                "minLength": 1,
                "type": "string"
            },
            "source_path": {
                "maxLength": 4096,
                "minLength": 1,
                "type": "string"
            },
            "source_url": {
                "format": "uri",
                "maxLength": 8192,
                "type": "string"
            },
            "version": {
                "maxLength": 256,
                "minLength": 1,
                "type": "string"
            }
        },
        "required": ["action"],
        "type": "object"
    })
}

/// Complete MCP tool definition for `desktop_skill_manage`.
pub fn tool_definition() -> Value {
    json!({
        "name": TOOL_NAME,
        "description": "Discover, validate, install, read, activate, and roll back versioned Agent Skills packages. Skills are model-readable instructions/resources, not hidden executors: bundled scripts are never auto-run by this subsystem. Local sources stay under agent-bridge path policy; remote ZIPs require Full/Unlock, HTTPS, and an expected SHA-256 digest.",
        "inputSchema": input_schema()
    })
}

/// Free-function dispatch helper for CLI routers.
pub fn dispatch_tool(manager: &SkillManager, args: &Value) -> Result<Value, SkillError> {
    manager.dispatch(args)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkillErrorCode {
    InvalidInput,
    PathPolicyViolation,
    LimitExceeded,
    ValidationFailed,
    NotFound,
    AmbiguousVersion,
    DigestMismatch,
    RemoteRequiresFullUnlock,
    RemoteOriginNotAllowed,
    ActionUnavailable,
    BinaryResourceNotReadable,
    NoRollbackTarget,
    LockTimeout,
    CorruptStore,
    IoError,
}

impl SkillErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidInput => "invalid_input",
            Self::PathPolicyViolation => "path_policy_violation",
            Self::LimitExceeded => "limit_exceeded",
            Self::ValidationFailed => "validation_failed",
            Self::NotFound => "not_found",
            Self::AmbiguousVersion => "ambiguous_version",
            Self::DigestMismatch => "digest_mismatch",
            Self::RemoteRequiresFullUnlock => "remote_requires_full_unlock",
            Self::RemoteOriginNotAllowed => "remote_origin_not_allowed",
            Self::ActionUnavailable => "action_unavailable",
            Self::BinaryResourceNotReadable => "binary_resource_not_readable",
            Self::NoRollbackTarget => "no_rollback_target",
            Self::LockTimeout => "lock_timeout",
            Self::CorruptStore => "corrupt_store",
            Self::IoError => "io_error",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SkillError {
    pub code: SkillErrorCode,
    pub message: String,
    pub details: Option<Value>,
}

impl SkillError {
    pub fn new(code: SkillErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            details: None,
        }
    }

    pub fn with_details(
        code: SkillErrorCode,
        message: impl Into<String>,
        details: Value,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            details: Some(details),
        }
    }

    fn io(context: impl Into<String>, err: io::Error) -> Self {
        Self::new(
            SkillErrorCode::IoError,
            format!("{}: {}", context.into(), err),
        )
    }

    pub fn to_json(&self) -> Value {
        let mut obj = Map::new();
        obj.insert("code".to_string(), Value::String(self.code.as_str().to_string()));
        obj.insert("message".to_string(), Value::String(self.message.clone()));
        if let Some(details) = &self.details {
            obj.insert("details".to_string(), details.clone());
        }
        Value::Object(obj)
    }
}

impl fmt::Display for SkillError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for SkillError {}

/// Hard resource bounds enforced during discovery, validation, install, and bounded reads.
#[derive(Debug, Clone)]
pub struct PackageLimits {
    pub max_files: usize,
    pub max_depth: usize,
    pub max_single_file_bytes: u64,
    pub max_skill_md_bytes: u64,
    pub max_total_bytes: u64,
    pub max_revisions_per_skill: usize,
    pub max_history_len: usize,
    pub max_registry_bytes: u64,
    pub max_manifest_bytes: u64,
}

impl Default for PackageLimits {
    fn default() -> Self {
        Self {
            max_files: 256,
            max_depth: 8,
            max_single_file_bytes: 2 * 1024 * 1024,
            max_skill_md_bytes: 512 * 1024,
            max_total_bytes: 16 * 1024 * 1024,
            max_revisions_per_skill: 64,
            max_history_len: 32,
            max_registry_bytes: 4 * 1024 * 1024,
            max_manifest_bytes: 1024 * 1024,
        }
    }
}

/// Local policy controlling whether remote HTTPS ZIP imports are permitted.
#[derive(Debug, Clone)]
pub struct RemoteSourcePolicy {
    /// Must be `true` (Full/Unlock mode) before any `source_url` request can proceed.
    pub full_unlock_enabled: bool,
    /// Explicitly allowlisted HTTPS origins (e.g. `https://skills.internal.example`).
    /// Empty by default; no remote origin is implicitly trusted.
    pub allowed_https_origins: Vec<String>,
    /// Maximum compressed ZIP archive size accepted from a remote provider.
    pub max_archive_bytes: usize,
}

impl Default for RemoteSourcePolicy {
    fn default() -> Self {
        Self {
            full_unlock_enabled: false,
            allowed_https_origins: Vec::new(),
            max_archive_bytes: 16 * 1024 * 1024,
        }
    }
}

/// Configuration for a private per-operator `SkillManager` instance.
#[derive(Debug, Clone)]
pub struct SkillManagerConfig {
    pub operator_id: String,
    pub limits: PackageLimits,
    pub remote_policy: RemoteSourcePolicy,
    pub lock_retry_attempts: usize,
    pub lock_retry_delay_ms: u64,
}

impl Default for SkillManagerConfig {
    fn default() -> Self {
        Self::for_operator("default")
    }
}

impl SkillManagerConfig {
    pub fn for_operator(operator_id: impl Into<String>) -> Self {
        Self {
            operator_id: operator_id.into(),
            limits: PackageLimits::default(),
            remote_policy: RemoteSourcePolicy::default(),
            lock_retry_attempts: 60,
            lock_retry_delay_ms: 25,
        }
    }
}

/// Raw file entry supplied by an `ApprovedRemoteProvider` after ZIP extraction.
#[derive(Debug, Clone)]
pub struct RawPackageFile {
    pub relative_path: String,
    pub bytes: Vec<u8>,
}

/// Optional host-supplied remote archive provider for allowlisted HTTPS ZIP sources.
///
/// Implementations MUST NOT follow redirects outside the allowlisted origin, MUST enforce
/// `max_bytes`, and MUST reject archive symlinks/special files during extraction.
/// Validates and extracts an in-memory documentary skill ZIP archive using
/// the same strict header, symlink, traversal, and size guards as local ZIPs.
pub fn decode_zip_bytes(
    zip_bytes: &[u8],
    limits: &PackageLimits,
) -> Result<Vec<RawPackageFile>, SkillError> {
    zip_import::decode(zip_bytes, limits).map(|decoded| decoded.files)
}

pub trait ApprovedRemoteProvider: Send + Sync {
    fn fetch_zip_bytes(&self, url: &str, max_bytes: usize) -> Result<Vec<u8>, SkillError>;
    fn extract_zip_entries(
        &self,
        zip_bytes: &[u8],
        limits: &PackageLimits,
    ) -> Result<Vec<RawPackageFile>, SkillError>;
}

/// Reusable documentary Agent Skills store backed by two `cap_std::fs::Dir` handles.
pub struct SkillManager {
    store_dir: Dir,
    workspace_dir: Dir,
    config: SkillManagerConfig,
    normalized_allowed_origins: BTreeSet<String>,
    remote_provider: Option<Box<dyn ApprovedRemoteProvider>>,
    in_process_lock: Mutex<()>,
}

impl SkillManager {
    /// Creates a `SkillManager` confined to `store_dir` (private operator store) and
    /// `workspace_dir` (local import boundary).
    pub fn new(
        store_dir: Dir,
        workspace_dir: Dir,
        config: SkillManagerConfig,
    ) -> Result<Self, SkillError> {
        let operator_id = config.operator_id.trim();
        if operator_id.is_empty() || operator_id.len() > 128 || has_control_chars(operator_id) {
            return Err(SkillError::new(
                SkillErrorCode::InvalidInput,
                "operator_id must be 1..=128 printable characters",
            ));
        }

        let mut normalized_allowed_origins = BTreeSet::new();
        for origin in &config.remote_policy.allowed_https_origins {
            let canonical = extract_https_origin(origin)?;
            normalized_allowed_origins.insert(canonical);
        }

        Ok(Self {
            store_dir,
            workspace_dir,
            config,
            normalized_allowed_origins,
            remote_provider: None,
            in_process_lock: Mutex::new(()),
        })
    }

    /// Attaches an optional host-approved remote ZIP provider.
    pub fn with_remote_provider(mut self, provider: Box<dyn ApprovedRemoteProvider>) -> Self {
        self.remote_provider = Some(provider);
        self
    }

    /// Dispatches a `desktop_skill_manage` request and returns either the action payload or a typed error.
    pub fn dispatch(&self, args: &Value) -> Result<Value, SkillError> {
        let obj = args.as_object().ok_or_else(|| {
            SkillError::new(SkillErrorCode::InvalidInput, "arguments must be a JSON object")
        })?;
        let action = require_string_field(obj, "action", 1, 32)?;

        match action.as_str() {
            "list" => self.action_list(obj),
            "get" => self.action_get(obj),
            "read" => self.action_read(obj),
            "validate" => self.action_validate(obj),
            "install" => self.action_install(obj),
            "activate" => self.action_activate(obj),
            "rollback" => self.action_rollback(obj),
            _ => Err(SkillError::new(
                SkillErrorCode::InvalidInput,
                format!(
                    "unsupported action '{}'; expected one of list, get, read, validate, install, activate, rollback",
                    action
                ),
            )),
        }
    }

    /// Dispatches and wraps errors into a consistent JSON response envelope for stdio/MCP handlers.
    pub fn dispatch_mcp_result(&self, args: &Value) -> Value {
        match self.dispatch(args) {
            Ok(payload) => payload,
            Err(err) => json!({
                "ok": false,
                "tool": TOOL_NAME,
                "documentary_only": true,
                "error": err.to_json()
            }),
        }
    }

    fn action_list(&self, obj: &Map<String, Value>) -> Result<Value, SkillError> {
        let filter_name = optional_skill_name(obj)?;
        let registry = self.load_registry()?;
        let mut skills_out = Vec::new();

        for (skill_name, record) in &registry.skills {
            if record.revoked { continue; }
            if let Some(target) = &filter_name {
                if skill_name != target {
                    continue;
                }
            }
            let active_desc = record
                .active_version
                .as_ref()
                .and_then(|v| record.revisions.get(v))
                .map(|r| r.description.clone())
                .or_else(|| {
                    record
                        .revisions
                        .values()
                        .next_back()
                        .map(|r| r.description.clone())
                })
                .unwrap_or_default();

            let revisions: Vec<Value> = record
                .revisions
                .values()
                .map(|rev| {
                    json!({
                        "version": rev.version,
                        "declared_version": rev.declared_version,
                        "installed_at_epoch_s": rev.installed_at_epoch_s,
                        "file_count": rev.file_count,
                        "total_bytes": rev.total_bytes,
                        "source_kind": rev.source_kind
                    })
                })
                .collect();

            skills_out.push(json!({
                "name": skill_name,
                "active_version": record.active_version,
                "previous_version": record.activation_history.last().cloned(),
                "history_depth": record.activation_history.len(),
                "revision_count": record.revisions.len(),
                "description": active_desc,
                "updated_at_epoch_s": record.updated_at_epoch_s,
                "revisions": revisions
            }));
        }

        Ok(json!({
            "ok": true,
            "action": "list",
            "operator_id": self.config.operator_id,
            "documentary_only": true,
            "execution_policy": "never_executed",
            "count": skills_out.len(),
            "skills": skills_out
        }))
    }

    fn action_get(&self, obj: &Map<String, Value>) -> Result<Value, SkillError> {
        let name = require_skill_name(obj)?;
        let requested_version = optional_version(obj)?;
        let registry = self.load_registry()?;
        let record = registry.skills.get(&name).filter(|record| !record.revoked).ok_or_else(|| {
            SkillError::new(
                SkillErrorCode::NotFound,
                format!("skill '{}' is not installed", name),
            )
        })?;

        if requested_version.is_none() && record.active_version.is_none() {
            return Ok(json!({
                "ok":true, "action":"get", "name":name, "active_version":null,
                "is_active":false, "documentary_only":true, "execution_policy":"never_executed",
                "revisions":record.revisions.keys().collect::<Vec<_>>()
            }));
        }
        let resolved_version = resolve_installed_version(record, requested_version.as_deref())?;
        let manifest = self.load_revision_manifest(&name, &resolved_version)?;

        Ok(json!({
            "ok": true,
            "action": "get",
            "documentary_only": true,
            "execution_policy": "never_executed",
            "name": name,
            "version": resolved_version,
            "is_active": record.active_version.as_deref() == Some(resolved_version.as_str()),
            "active_version": record.active_version,
            "previous_version": record.activation_history.last().cloned(),
            "history_depth": record.activation_history.len(),
            "manifest": manifest.to_json()
        }))
    }

    fn action_read(&self, obj: &Map<String, Value>) -> Result<Value, SkillError> {
        let name = require_skill_name(obj)?;
        let requested_version = optional_version(obj)?;
        let resource_raw = optional_string_field(obj, "resource_path", 1, 512)?;
        let max_chars = parse_max_chars(obj)?;

        let resource_segments = match resource_raw {
            Some(ref raw) => validate_relative_segments(raw, false, 512, "resource_path")?,
            None => vec![SKILL_ENTRYPOINT.to_string()],
        };
        let normalized_resource = resource_segments.join("/");

        let registry = self.load_registry()?;
        let record = registry.skills.get(&name).filter(|record| !record.revoked).ok_or_else(|| {
            SkillError::new(
                SkillErrorCode::NotFound,
                format!("skill '{}' is not installed", name),
            )
        })?;

        let resolved_version = resolve_installed_version(record, requested_version.as_deref())?;
        let manifest = self.load_revision_manifest(&name, &resolved_version)?;
        let manifest_file = manifest
            .files
            .iter()
            .find(|f| f.path == normalized_resource)
            .ok_or_else(|| {
                SkillError::new(
                    SkillErrorCode::NotFound,
                    format!(
                        "resource '{}' not found in skill '{}' version '{}'",
                        normalized_resource, name, resolved_version
                    ),
                )
            })?;

        let rev_dir = self.open_revision_dir(&name, &resolved_version)?;
        let files_dir = open_dir_nofollow(&rev_dir, FILES_DIR_NAME)?;
        let mut file = open_nested_file_nofollow(&files_dir, &resource_segments)?;
        let bytes = read_file_bounded(
            &mut file,
            self.config.limits.max_single_file_bytes,
            &normalized_resource,
        )?;

        let actual_sha = sha256_hex(&bytes);
        if !ct_eq(actual_sha.as_bytes(), manifest_file.sha256.as_bytes()) {
            return Err(SkillError::new(
                SkillErrorCode::CorruptStore,
                format!(
                    "integrity mismatch reading '{}' in skill '{}' version '{}'",
                    normalized_resource, name, resolved_version
                ),
            ));
        }

        let full_text = String::from_utf8(bytes).map_err(|_| {
            SkillError::new(
                SkillErrorCode::BinaryResourceNotReadable,
                format!(
                    "resource '{}' is not valid UTF-8 text and cannot be read as documentary text",
                    normalized_resource
                ),
            )
        })?;

        let total_chars = full_text.chars().count();
        let (content, truncated, returned_chars) = if total_chars > max_chars {
            let cut_idx = full_text
                .char_indices()
                .nth(max_chars)
                .map(|(idx, _)| idx)
                .unwrap_or(full_text.len());
            (full_text[..cut_idx].to_string(), true, max_chars)
        } else {
            (full_text, false, total_chars)
        };

        Ok(json!({
            "ok": true,
            "action": "read",
            "documentary_only": true,
            "execution_policy": "never_executed",
            "name": name,
            "version": resolved_version,
            "resource_path": normalized_resource,
            "sha256": actual_sha,
            "total_bytes": manifest_file.bytes,
            "total_chars": total_chars,
            "returned_chars": returned_chars,
            "max_chars": max_chars,
            "truncated": truncated,
            "is_script_document": manifest_file.is_script_document,
            "content": content
        }))
    }

    fn action_validate(&self, obj: &Map<String, Value>) -> Result<Value, SkillError> {
        let name_opt = optional_skill_name(obj)?;
        let version_opt = optional_version(obj)?;
        let source_path_opt = optional_string_field(obj, "source_path", 1, 4096)?;
        let source_url_opt = optional_string_field(obj, "source_url", 1, 8192)?;
        let expected_sha256 = optional_expected_sha256(obj)?;

        if source_path_opt.is_some() && source_url_opt.is_some() {
            return Err(SkillError::new(
                SkillErrorCode::InvalidInput,
                "specify either 'source_path' or 'source_url', not both",
            ));
        }

        if let Some(source_path) = source_path_opt {
            let loaded = self.load_local_package(&source_path, name_opt.as_deref(), expected_sha256.as_deref())?;
            return Ok(build_validation_response(&loaded.source_kind, &loaded));
        }

        if let Some(source_url) = source_url_opt {
            let loaded = self.load_remote_package(
                &source_url,
                expected_sha256.as_deref(),
                name_opt.as_deref(),
            )?;
            return Ok(build_validation_response("remote_https_zip", &loaded));
        }

        // Validate an already-installed revision on disk.
        let name = name_opt.ok_or_else(|| {
            SkillError::new(
                SkillErrorCode::InvalidInput,
                "validate requires 'source_path', 'source_url', or an installed skill 'name'",
            )
        })?;
        let registry = self.load_registry()?;
        let record = registry.skills.get(&name).filter(|record| !record.revoked).ok_or_else(|| {
            SkillError::new(
                SkillErrorCode::NotFound,
                format!("skill '{}' is not installed", name),
            )
        })?;
        let resolved_version = resolve_installed_version(record, version_opt.as_deref())?;
        let manifest = self.verify_installed_revision(&name, &resolved_version)?;

        if let Some(expected) = &expected_sha256 {
            let digest_hex = strip_sha256_prefix(&manifest.version).unwrap_or("");
            if !ct_eq(expected.as_bytes(), digest_hex.as_bytes()) {
                return Err(SkillError::with_details(
                    SkillErrorCode::DigestMismatch,
                    "installed revision SHA-256 digest does not match expected_sha256",
                    json!({
                        "expected_sha256": expected,
                        "actual_sha256": digest_hex
                    }),
                ));
            }
        }

        Ok(json!({
            "ok": true,
            "action": "validate",
            "target": "installed_revision",
            "valid": true,
            "documentary_only": true,
            "execution_policy": "never_executed",
            "name": name,
            "version": manifest.version,
            "declared_version": manifest.declared_version,
            "description": manifest.description,
            "file_count": manifest.file_count,
            "total_bytes": manifest.total_bytes,
            "bundled_scripts": manifest.bundled_scripts,
            "warnings": manifest.warnings,
            "errors": []
        }))
    }

    fn action_install(&self, obj: &Map<String, Value>) -> Result<Value, SkillError> {
        let name_opt = optional_skill_name(obj)?;
        let source_path_opt = optional_string_field(obj, "source_path", 1, 4096)?;
        let source_url_opt = optional_string_field(obj, "source_url", 1, 8192)?;
        let expected_sha256 = optional_expected_sha256(obj)?;
        let activate = optional_bool_field(obj, "activate")?.unwrap_or(true);

        if source_path_opt.is_some() && source_url_opt.is_some() {
            return Err(SkillError::new(
                SkillErrorCode::InvalidInput,
                "specify either 'source_path' or 'source_url', not both",
            ));
        }

        let loaded = match (source_path_opt, source_url_opt) {
            (Some(source_path), None) => {
                self.load_local_package(&source_path, name_opt.as_deref(), expected_sha256.as_deref())?
            }
            (None, Some(source_url)) => self.load_remote_package(
                &source_url,
                expected_sha256.as_deref(),
                name_opt.as_deref(),
            )?,
            _ => {
                return Err(SkillError::new(
                    SkillErrorCode::InvalidInput,
                    "install requires either 'source_path' or 'source_url'",
                ));
            }
        };

        self.commit_loaded(loaded, activate)
    }

    // Shared publication path: the local-only importer supplies a validated
    // in-memory package, never a second registry or an execution mechanism.
    fn commit_loaded(&self, loaded: LoadedPackage, activate: bool) -> Result<Value, SkillError> {
        let _in_proc = self.in_process_lock.lock().map_err(|_| {
            SkillError::new(SkillErrorCode::LockTimeout, "in-process store mutex poisoned")
        })?;
        let _store_lock = self.acquire_store_lock()?;

        let mut registry = self.load_registry()?;
        let now = now_epoch_s();
        let approved_source = (loaded.source_kind == OPERATOR_SOURCE).then_some(loaded.source_ref.clone());
        if let Some(record) = registry.skills.get(&loaded.name) {
            if record.revoked || record.import_source != approved_source {
                return Err(SkillError::new(SkillErrorCode::ValidationFailed,
                    "Skill name is revoked or belongs to a different import source"));
            }
        }
        if let Some(source) = &approved_source {
            if registry.skills.iter().any(|(name, record)| name != &loaded.name
                && record.import_source.as_ref() == Some(source)) {
                return Err(SkillError::new(SkillErrorCode::ValidationFailed,
                    "Approved import source already belongs to another skill name"));
            }
            registry.schema_version = OPERATOR_REGISTRY_SCHEMA_VERSION;
        }

        let already_in_registry = registry
            .skills
            .get(&loaded.name)
            .map(|rec| rec.revisions.contains_key(&loaded.version))
            .unwrap_or(false);

        if !already_in_registry {
            if let Some(rec) = registry.skills.get(&loaded.name) {
                if rec.revisions.len() >= self.config.limits.max_revisions_per_skill {
                    return Err(SkillError::new(
                        SkillErrorCode::LimitExceeded,
                        format!(
                            "skill '{}' reached maximum installed revisions ({})",
                            loaded.name, self.config.limits.max_revisions_per_skill
                        ),
                    ));
                }
            }
        }

        // Keep immutable provenance and the original installation timestamp
        // even for an idempotent reimport or an orphan recovered after a crash.
        let manifest = if already_in_registry ||
            self.open_revision_dir(&loaded.name, &loaded.version).is_ok() {
            let existing = self.verify_installed_revision(&loaded.name, &loaded.version)?;
            if (existing.source_kind == OPERATOR_SOURCE) != approved_source.is_some()
                || (approved_source.is_some() && existing.source_ref != loaded.source_ref) {
                return Err(SkillError::new(SkillErrorCode::ValidationFailed,
                    "Existing revision belongs to a different import source"));
            }
            existing
        } else {
            loaded.to_manifest(now)
        };

        let entry = registry
            .skills
            .entry(loaded.name.clone())
            .or_insert_with(|| SkillRecord {
                active_version: None,
                activation_history: Vec::new(),
                updated_at_epoch_s: now,
                revisions: BTreeMap::new(),
                import_source: approved_source,
                revoked: false,
            });

        // A replay of identical approved content is a no-op, not a new
        // revision or activation-history entry.
        if already_in_registry && (!activate || entry.active_version.as_deref() == Some(loaded.version.as_str())) {
            return Ok(json!({
                "ok":true,"action":"install","documentary_only":true,"execution_policy":"never_executed",
                "name":loaded.name,"version":loaded.version,"declared_version":manifest.declared_version,
                "already_installed":true,"activated":false,"active_version":entry.active_version,
                "previous_version":entry.active_version,"file_count":manifest.file_count,
                "total_bytes":manifest.total_bytes,"bundled_scripts":manifest.bundled_scripts,
                "warnings":manifest.warnings
            }));
        }

        entry.revisions.insert(
            loaded.version.clone(),
            RevisionSummary {
                version: loaded.version.clone(),
                declared_version: manifest.declared_version.clone(),
                description: manifest.description.clone(),
                installed_at_epoch_s: manifest.installed_at_epoch_s,
                file_count: manifest.file_count,
                total_bytes: manifest.total_bytes,
                source_kind: manifest.source_kind.clone(),
            },
        );
        entry.updated_at_epoch_s = now;

        let mut activated = false;
        let previous_version = entry.active_version.clone();
        if activate {
            if entry.active_version.as_deref() != Some(loaded.version.as_str()) {
                if let Some(prev) = entry.active_version.take() {
                    push_bounded_history(
                        &mut entry.activation_history,
                        prev,
                        self.config.limits.max_history_len,
                    );
                }
                entry.active_version = Some(loaded.version.clone());
                activated = true;
            }
        }

        let active_version = entry.active_version.clone();
        registry.updated_at_epoch_s = now;
        let registry_bytes = self.registry_bytes(&registry)?;
        let already_on_disk = self.persist_revision_atomic(&loaded, &manifest)?;
        atomic_write_bytes(&self.store_dir, REGISTRY_FILE_NAME, &registry_bytes)?;

        Ok(json!({
            "ok": true,
            "action": "install",
            "documentary_only": true,
            "execution_policy": "never_executed",
            "name": loaded.name,
            "version": loaded.version,
            "declared_version": manifest.declared_version,
            "already_installed": already_in_registry && already_on_disk,
            "activated": activated,
            "active_version": active_version,
            "previous_version": previous_version,
            "file_count": manifest.file_count,
            "total_bytes": manifest.total_bytes,
            "bundled_scripts": manifest.bundled_scripts,
            "warnings": manifest.warnings
        }))
    }

    fn action_activate(&self, obj: &Map<String, Value>) -> Result<Value, SkillError> {
        let name = require_skill_name(obj)?;
        let requested_version = require_string_field(obj, "version", 1, 256)?;

        let _in_proc = self.in_process_lock.lock().map_err(|_| {
            SkillError::new(SkillErrorCode::LockTimeout, "in-process store mutex poisoned")
        })?;
        let _store_lock = self.acquire_store_lock()?;

        let mut registry = self.load_registry()?;
        let record = registry.skills.get(&name).filter(|record| !record.revoked).ok_or_else(|| {
            SkillError::new(
                SkillErrorCode::NotFound,
                format!("skill '{}' is not installed", name),
            )
        })?;

        let target_version = resolve_installed_version(record, Some(requested_version.as_str()))?;
        self.verify_installed_revision(&name, &target_version)?;

        let record = registry.skills.get_mut(&name).ok_or_else(|| {
            SkillError::new(
                SkillErrorCode::NotFound,
                format!("skill '{}' is not installed", name),
            )
        })?;

        let previous_version = record.active_version.clone();
        let changed = previous_version.as_deref() != Some(target_version.as_str());
        if changed {
            if let Some(prev) = record.active_version.take() {
                push_bounded_history(
                    &mut record.activation_history,
                    prev,
                    self.config.limits.max_history_len,
                );
            }
            record.active_version = Some(target_version.clone());
            let now = now_epoch_s();
            record.updated_at_epoch_s = now;
            registry.updated_at_epoch_s = now;
            self.save_registry_atomic(&registry)?;
        }

        Ok(json!({
            "ok": true,
            "action": "activate",
            "documentary_only": true,
            "execution_policy": "never_executed",
            "name": name,
            "active_version": target_version,
            "previous_version": previous_version,
            "changed": changed
        }))
    }

    fn action_rollback(&self, obj: &Map<String, Value>) -> Result<Value, SkillError> {
        let name = require_skill_name(obj)?;
        let requested_version = optional_version(obj)?;

        let _in_proc = self.in_process_lock.lock().map_err(|_| {
            SkillError::new(SkillErrorCode::LockTimeout, "in-process store mutex poisoned")
        })?;
        let _store_lock = self.acquire_store_lock()?;

        let mut registry = self.load_registry()?;
        let (target_version, rolled_back_from, new_history) = {
            let record = registry.skills.get(&name).filter(|record| !record.revoked).ok_or_else(|| {
                SkillError::new(
                    SkillErrorCode::NotFound,
                    format!("skill '{}' is not installed", name),
                )
            })?;
            let current_active = record.active_version.clone();
            let mut history = record.activation_history.clone();

            let target = match requested_version.as_deref() {
                Some(ver) => resolve_installed_version(record, Some(ver))?,
                None => {
                    let mut chosen = None;
                    while let Some(candidate) = history.pop() {
                        if current_active.as_deref() != Some(candidate.as_str())
                            && record.revisions.contains_key(&candidate)
                        {
                            chosen = Some(candidate);
                            break;
                        }
                    }
                    chosen.ok_or_else(|| {
                        SkillError::new(
                            SkillErrorCode::NoRollbackTarget,
                            format!(
                                "skill '{}' has no previous installed revision in activation history",
                                name
                            ),
                        )
                    })?
                }
            };
            (target, current_active, history)
        };

        self.verify_installed_revision(&name, &target_version)?;

        let changed = rolled_back_from.as_deref() != Some(target_version.as_str());
        let remaining_history = {
            let record = registry.skills.get_mut(&name).ok_or_else(|| {
                SkillError::new(
                    SkillErrorCode::NotFound,
                    format!("skill '{}' is not installed", name),
                )
            })?;
            if changed {
                if requested_version.is_some() {
                    if let Some(prev) = &rolled_back_from {
                        push_bounded_history(
                            &mut record.activation_history,
                            prev.clone(),
                            self.config.limits.max_history_len,
                        );
                    }
                } else {
                    record.activation_history = new_history;
                }
                record.active_version = Some(target_version.clone());
                let now = now_epoch_s();
                record.updated_at_epoch_s = now;
                registry.updated_at_epoch_s = now;
            }
            record.activation_history.len()
        };

        if changed {
            self.save_registry_atomic(&registry)?;
        }

        Ok(json!({
            "ok": true,
            "action": "rollback",
            "documentary_only": true,
            "execution_policy": "never_executed",
            "name": name,
            "active_version": target_version,
            "rolled_back_from": rolled_back_from,
            "changed": changed,
            "remaining_history": remaining_history
        }))
    }

    fn load_local_package(
        &self,
        source_path: &str,
        explicit_name: Option<&str>,
        expected_digest: Option<&str>,
    ) -> Result<LoadedPackage, SkillError> {
        let segments = validate_relative_segments(source_path, true, 4096, "source_path")?;
        // A local ZIP is a regular file opened ONLY through the workspace
        // capability; all bytes remain in memory. No remote provider is used.
        if segments.last().is_some_and(|name| name.to_ascii_lowercase().ends_with(".zip")) {
            let mut file = open_nested_file_nofollow(&self.workspace_dir, &segments)?;
            let max_archive_bytes = self.config.limits.max_total_bytes.min(16 * 1024 * 1024);
            let archive_bytes = read_file_bounded(
                &mut file, max_archive_bytes, &segments.join("/"),
            )?;
            let archive_digest = sha256_hex(&archive_bytes);
            verify_source_digest(expected_digest, &archive_digest)?;
            let decoded = zip_import::decode(&archive_bytes, &self.config.limits)?;
            let zip_stem = segments.last().and_then(|name| name.get(..name.len() - 4));
            let inferred_name = decoded.enclosing_directory.as_deref().or(zip_stem);
            return assemble_and_validate_package(
                decoded.files,
                explicit_name,
                inferred_name,
                "local_workspace_zip",
                &segments.join("/"),
                Some(archive_digest),
                &self.config.limits,
            );
        }
        let mut current = self
            .workspace_dir
            .try_clone()
            .map_err(|e| SkillError::io("clone workspace_dir", e))?;
        for seg in &segments {
            current = open_dir_nofollow(&current, seg)?;
        }

        let mut raw_files = Vec::new();
        let mut total_bytes: u64 = 0;
        let mut prefix_segments = Vec::new();
        let mut remaining = directory_entry_budget(&self.config.limits);
        collect_dir_files_recursive(
            &current,
            &mut prefix_segments,
            0,
            &self.config.limits,
            &mut total_bytes,
            &mut raw_files,
            &mut remaining,
            false,
        )?;

        let inferred_basename = segments.last().map(String::as_str);
        let loaded = assemble_and_validate_package(
            raw_files,
            explicit_name,
            inferred_basename,
            "local_workspace",
            &segments.join("/"),
            None,
            &self.config.limits,
        )?;
        verify_source_digest(expected_digest, &loaded.digest_hex)?;
        Ok(loaded)
    }

    fn load_remote_package(
        &self,
        source_url: &str,
        expected_sha256: Option<&str>,
        explicit_name: Option<&str>,
    ) -> Result<LoadedPackage, SkillError> {
        if !self.config.remote_policy.full_unlock_enabled {
            return Err(SkillError::with_details(
                SkillErrorCode::RemoteRequiresFullUnlock,
                "remote source_url operations require Full/Unlock policy (RemoteSourcePolicy::full_unlock_enabled = true)",
                json!({
                    "required_policy": "RemoteSourcePolicy::full_unlock_enabled"
                }),
            ));
        }

        let expected_hex = expected_sha256.ok_or_else(|| {
            SkillError::new(
                SkillErrorCode::InvalidInput,
                "remote source_url requires 'expected_sha256' (64 hex characters)",
            )
        })?;

        let canonical_origin = extract_https_origin(source_url)?;
        if !self.normalized_allowed_origins.contains(&canonical_origin) {
            return Err(SkillError::with_details(
                SkillErrorCode::RemoteOriginNotAllowed,
                format!(
                    "source_url origin '{}' is not configured in local RemoteSourcePolicy::allowed_https_origins",
                    canonical_origin
                ),
                json!({
                    "missing_local_origin": canonical_origin,
                    "config_field": "RemoteSourcePolicy::allowed_https_origins",
                    "configured_origin_count": self.normalized_allowed_origins.len()
                }),
            ));
        }

        let provider = self.remote_provider.as_deref().ok_or_else(|| {
            SkillError::with_details(
                SkillErrorCode::ActionUnavailable,
                format!(
                    "remote source_url origin '{}' is allowlisted, but no ApprovedRemoteProvider is configured on SkillManager",
                    canonical_origin
                ),
                json!({
                    "approved_origin": canonical_origin,
                    "missing_component": "SkillManager::with_remote_provider(Box<dyn ApprovedRemoteProvider>)"
                }),
            )
        })?;

        let zip_bytes = provider.fetch_zip_bytes(
            source_url,
            self.config.remote_policy.max_archive_bytes,
        )?;
        if zip_bytes.len() > self.config.remote_policy.max_archive_bytes {
            return Err(SkillError::new(
                SkillErrorCode::LimitExceeded,
                format!(
                    "remote ZIP exceeds max_archive_bytes ({} > {})",
                    zip_bytes.len(),
                    self.config.remote_policy.max_archive_bytes
                ),
            ));
        }

        let actual_zip_sha = sha256_hex(&zip_bytes);
        if !ct_eq(actual_zip_sha.as_bytes(), expected_hex.as_bytes()) {
            return Err(SkillError::with_details(
                SkillErrorCode::DigestMismatch,
                "remote ZIP SHA-256 digest does not match expected_sha256",
                json!({
                    "expected_sha256": expected_hex,
                    "actual_sha256": actual_zip_sha
                }),
            ));
        }

        let raw_files = provider.extract_zip_entries(&zip_bytes, &self.config.limits)?;
        assemble_and_validate_package(
            raw_files,
            explicit_name,
            None,
            "remote_https_zip",
            source_url,
            Some(actual_zip_sha),
            &self.config.limits,
        )
    }

    fn persist_revision_atomic(
        &self,
        loaded: &LoadedPackage,
        manifest: &RevisionManifest,
    ) -> Result<bool, SkillError> {
        let skills_dir = ensure_dir_nofollow(&self.store_dir, SKILLS_DIR_NAME)?;
        let skill_dir = ensure_dir_nofollow(&skills_dir, &loaded.name)?;
        let revisions_dir = ensure_dir_nofollow(&skill_dir, REVISIONS_DIR_NAME)?;

        if revisions_dir.symlink_metadata(&loaded.digest_hex).is_ok() {
            self.verify_installed_revision(&loaded.name, &loaded.version)?;
            return Ok(true);
        }

        let staging_root = ensure_dir_nofollow(&self.store_dir, STAGING_DIR_NAME)?;
        let stage_id = format!("stage-{}", Uuid::new_v4().simple());
        let mut guard = StagingGuard::new(
            staging_root
                .try_clone()
                .map_err(|e| SkillError::io("clone staging_root", e))?,
            stage_id.clone(),
        );

        // Scope inner handles so every Dir/File handle inside stage_dir is closed before rename
        // (required on Windows to avoid sharing violations during directory rename).
        {
            staging_root
                .create_dir(&stage_id)
                .map_err(|e| SkillError::io("create staging directory", e))?;
            let stage_dir = open_dir_nofollow(&staging_root, &stage_id)?;
            stage_dir
                .create_dir(FILES_DIR_NAME)
                .map_err(|e| SkillError::io("create staging files directory", e))?;
            let files_dir = open_dir_nofollow(&stage_dir, FILES_DIR_NAME)?;

            for file in &loaded.files {
                let segments: Vec<&str> = file.path.split('/').collect();
                let (leaf, parents) = segments.split_last().ok_or_else(|| {
                    SkillError::new(SkillErrorCode::PathPolicyViolation, "empty file path")
                })?;

                let mut target_dir = files_dir
                    .try_clone()
                    .map_err(|e| SkillError::io("clone files_dir", e))?;
                for parent in parents {
                    target_dir = ensure_dir_nofollow(&target_dir, parent)?;
                }

                let mut opts = OpenOptions::new();
                opts.write(true).create_new(true);
                let mut out = target_dir
                    .open_with(leaf, &opts)
                    .map_err(|e| SkillError::io(format!("create staged '{}'", file.path), e))?;
                out.write_all(&file.bytes)
                    .map_err(|e| SkillError::io(format!("write staged '{}'", file.path), e))?;
                out.sync_all()
                    .map_err(|e| SkillError::io(format!("sync staged '{}'", file.path), e))?;
            }

            let manifest_bytes = serde_json::to_vec_pretty(&manifest.to_json())
                .map_err(|e| SkillError::new(SkillErrorCode::CorruptStore, e.to_string()))?;
            if manifest_bytes.len() as u64 > self.config.limits.max_manifest_bytes {
                return Err(SkillError::new(SkillErrorCode::LimitExceeded, "Skill manifest exceeds its byte limit"));
            }
            let mut m_opts = OpenOptions::new();
            m_opts.write(true).create_new(true);
            let mut manifest_file = stage_dir
                .open_with(MANIFEST_FILE_NAME, &m_opts)
                .map_err(|e| SkillError::io("create staged manifest.json", e))?;
            manifest_file
                .write_all(&manifest_bytes)
                .map_err(|e| SkillError::io("write staged manifest.json", e))?;
            manifest_file
                .sync_all()
                .map_err(|e| SkillError::io("sync staged manifest.json", e))?;
        }

        staging_root
            .rename(&stage_id, &revisions_dir, &loaded.digest_hex)
            .map_err(|e| SkillError::io("commit staged revision", e))?;
        guard.disarm();
        Ok(false)
    }

    fn open_revision_dir(&self, name: &str, canonical_version: &str) -> Result<Dir, SkillError> {
        let digest_hex = strip_sha256_prefix(canonical_version).ok_or_else(|| {
            SkillError::new(
                SkillErrorCode::CorruptStore,
                format!("invalid canonical revision version '{}'", canonical_version),
            )
        })?;
        let skills_dir = open_dir_nofollow(&self.store_dir, SKILLS_DIR_NAME)?;
        let skill_dir = open_dir_nofollow(&skills_dir, name)?;
        let revisions_dir = open_dir_nofollow(&skill_dir, REVISIONS_DIR_NAME)?;
        open_dir_nofollow(&revisions_dir, digest_hex)
    }

    fn load_revision_manifest(
        &self,
        name: &str,
        canonical_version: &str,
    ) -> Result<RevisionManifest, SkillError> {
        let rev_dir = self.open_revision_dir(name, canonical_version)?;
        let mut file = open_file_nofollow(&rev_dir, MANIFEST_FILE_NAME)?;
        let bytes = read_file_bounded(
            &mut file,
            self.config.limits.max_manifest_bytes,
            MANIFEST_FILE_NAME,
        )?;
        let value: Value = serde_json::from_slice(&bytes).map_err(|e| {
            SkillError::new(
                SkillErrorCode::CorruptStore,
                format!("corrupt manifest.json for '{}@{}': {}", name, canonical_version, e),
            )
        })?;
        let manifest = RevisionManifest::from_json(&value)?;
        if manifest.name != name || manifest.version != canonical_version {
            return Err(SkillError::new(
                SkillErrorCode::CorruptStore,
                format!(
                    "manifest identity mismatch for '{}@{}'",
                    name, canonical_version
                ),
            ));
        }
        Ok(manifest)
    }

    fn verify_installed_revision(
        &self,
        name: &str,
        canonical_version: &str,
    ) -> Result<RevisionManifest, SkillError> {
        let manifest = self.load_revision_manifest(name, canonical_version)?;
        let rev_dir = self.open_revision_dir(name, canonical_version)?;
        let files_dir = open_dir_nofollow(&rev_dir, FILES_DIR_NAME)?;

        let mut disk_entries = Vec::new();
        let mut total_bytes: u64 = 0;
        let mut prefix = Vec::new();
        let mut remaining = directory_entry_budget(&self.config.limits);
        collect_dir_files_recursive(
            &files_dir,
            &mut prefix,
            0,
            &self.config.limits,
            &mut total_bytes,
            &mut disk_entries,
            &mut remaining,
            false,
        )?;

        disk_entries.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
        if disk_entries.len() != manifest.files.len() {
            return Err(SkillError::new(
                SkillErrorCode::CorruptStore,
                format!(
                    "file count mismatch in installed revision '{}@{}'",
                    name, canonical_version
                ),
            ));
        }

        let mut digest_inputs = Vec::with_capacity(disk_entries.len());
        for (disk, expected) in disk_entries.iter().zip(manifest.files.iter()) {
            if disk.relative_path != expected.path {
                return Err(SkillError::new(
                    SkillErrorCode::CorruptStore,
                    format!(
                        "file list mismatch in '{}@{}': expected '{}', found '{}'",
                        name, canonical_version, expected.path, disk.relative_path
                    ),
                ));
            }
            let actual_sha = sha256_hex(&disk.bytes);
            if !ct_eq(actual_sha.as_bytes(), expected.sha256.as_bytes()) {
                return Err(SkillError::new(
                    SkillErrorCode::CorruptStore,
                    format!(
                        "file digest mismatch for '{}' in '{}@{}'",
                        expected.path, name, canonical_version
                    ),
                ));
            }
            digest_inputs.push((disk.relative_path.as_str(), disk.bytes.len() as u64, actual_sha));
        }

        let recomputed_hex = compute_canonical_package_digest(&digest_inputs);
        let expected_hex = strip_sha256_prefix(canonical_version).unwrap_or("");
        if !ct_eq(recomputed_hex.as_bytes(), expected_hex.as_bytes()) {
            return Err(SkillError::new(
                SkillErrorCode::CorruptStore,
                format!(
                    "canonical package digest mismatch for '{}@{}'",
                    name, canonical_version
                ),
            ));
        }

        Ok(manifest)
    }

    fn load_registry(&self) -> Result<Registry, SkillError> {
        match self.store_dir.symlink_metadata(REGISTRY_FILE_NAME) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Registry::empty(&self.config.operator_id)),
            Err(e) => Err(SkillError::io("stat registry.json", e)),
            Ok(_) => {
                let mut file = open_file_nofollow(&self.store_dir, REGISTRY_FILE_NAME)?;
                let bytes = read_file_bounded(
                    &mut file,
                    self.config.limits.max_registry_bytes,
                    REGISTRY_FILE_NAME,
                )?;
                let value: Value = serde_json::from_slice(&bytes).map_err(|e| {
                    SkillError::new(
                        SkillErrorCode::CorruptStore,
                        format!("corrupt registry.json: {}", e),
                    )
                })?;
                Registry::from_json(&value)
            }
        }
    }

    fn registry_bytes(&self, registry: &Registry) -> Result<Vec<u8>, SkillError> {
        let bytes = serde_json::to_vec_pretty(&registry.to_json())
            .map_err(|e| SkillError::new(SkillErrorCode::CorruptStore, e.to_string()))?;
        if bytes.len() as u64 > self.config.limits.max_registry_bytes {
            return Err(SkillError::new(SkillErrorCode::LimitExceeded, "Skill registry exceeds its byte limit"));
        }
        Ok(bytes)
    }

    fn save_registry_atomic(&self, registry: &Registry) -> Result<(), SkillError> {
        atomic_write_bytes(&self.store_dir, REGISTRY_FILE_NAME, &self.registry_bytes(registry)?)
    }

    fn acquire_store_lock(&self) -> Result<std::fs::File, SkillError> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).follow(FollowSymlinks::No);
        let file = self.store_dir.open_with(LOCK_FILE_NAME, &options)
            .map_err(|error| SkillError::io("open private skill store lock", error))?;
        super::workspace_write::ensure_single_hard_link(&file).map_err(skill_path_error)?;
        let file = file.into_std();
        // The OS releases the lock when the owning process or handle exits.
        let attempts = self.config.lock_retry_attempts.max(1);
        for attempt in 0..attempts {
            match file.try_lock() {
                Ok(()) => return Ok(file),
                Err(std::fs::TryLockError::WouldBlock) if attempt + 1 < attempts =>
                    thread::sleep(Duration::from_millis(self.config.lock_retry_delay_ms)),
                Err(std::fs::TryLockError::WouldBlock) => break,
                Err(std::fs::TryLockError::Error(error)) =>
                    return Err(SkillError::io("lock private skill store", error)),
            }
        }
        Err(SkillError::new(SkillErrorCode::LockTimeout, "Skill store is busy"))
    }
}

struct StagingGuard {
    staging_root: Dir,
    stage_id: String,
    armed: bool,
}

impl StagingGuard {
    fn new(staging_root: Dir, stage_id: String) -> Self {
        Self {
            staging_root,
            stage_id,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for StagingGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.staging_root.remove_dir_all(&self.stage_id);
        }
    }
}

struct LoadedFile {
    path: String,
    bytes: Vec<u8>,
    sha256: String,
    is_utf8: bool,
    is_script_document: bool,
}

struct LoadedPackage {
    name: String,
    version: String,
    digest_hex: String,
    declared_version: Option<String>,
    description: String,
    frontmatter: BTreeMap<String, String>,
    source_kind: String,
    source_ref: String,
    source_archive_sha256: Option<String>,
    total_bytes: u64,
    files: Vec<LoadedFile>,
    bundled_scripts: Vec<String>,
    warnings: Vec<String>,
}

impl LoadedPackage {
    fn to_manifest(&self, installed_at_epoch_s: u64) -> RevisionManifest {
        let files = self
            .files
            .iter()
            .map(|f| ManifestFileEntry {
                path: f.path.clone(),
                bytes: f.bytes.len() as u64,
                sha256: f.sha256.clone(),
                is_utf8: f.is_utf8,
                is_script_document: f.is_script_document,
            })
            .collect();

        RevisionManifest {
            schema_version: REGISTRY_SCHEMA_VERSION,
            name: self.name.clone(),
            version: self.version.clone(),
            declared_version: self.declared_version.clone(),
            description: self.description.clone(),
            frontmatter: self.frontmatter.clone(),
            source_kind: self.source_kind.clone(),
            source_ref: self.source_ref.clone(),
            source_archive_sha256: self.source_archive_sha256.clone(),
            installed_at_epoch_s,
            file_count: self.files.len(),
            total_bytes: self.total_bytes,
            bundled_scripts: self.bundled_scripts.clone(),
            warnings: self.warnings.clone(),
            files,
        }
    }
}

struct ManifestFileEntry {
    path: String,
    bytes: u64,
    sha256: String,
    is_utf8: bool,
    is_script_document: bool,
}

struct RevisionManifest {
    schema_version: u64,
    name: String,
    version: String,
    declared_version: Option<String>,
    description: String,
    frontmatter: BTreeMap<String, String>,
    source_kind: String,
    source_ref: String,
    source_archive_sha256: Option<String>,
    installed_at_epoch_s: u64,
    file_count: usize,
    total_bytes: u64,
    bundled_scripts: Vec<String>,
    warnings: Vec<String>,
    files: Vec<ManifestFileEntry>,
}

impl RevisionManifest {
    fn to_json(&self) -> Value {
        let mut fm = Map::new();
        for (k, v) in &self.frontmatter {
            fm.insert(k.clone(), Value::String(v.clone()));
        }
        let files: Vec<Value> = self
            .files
            .iter()
            .map(|f| {
                json!({
                    "path": f.path,
                    "bytes": f.bytes,
                    "sha256": f.sha256,
                    "is_utf8": f.is_utf8,
                    "is_script_document": f.is_script_document
                })
            })
            .collect();

        json!({
            "schema_version": self.schema_version,
            "documentary_only": true,
            "execution_policy": "never_executed",
            "name": self.name,
            "version": self.version,
            "declared_version": self.declared_version,
            "description": self.description,
            "frontmatter": Value::Object(fm),
            "license": self.frontmatter.get("license").filter(|value| !value.trim().is_empty()),
            "source_kind": self.source_kind,
            "source_ref": self.source_ref,
            "source_archive_sha256": self.source_archive_sha256,
            "installed_at_epoch_s": self.installed_at_epoch_s,
            "file_count": self.file_count,
            "total_bytes": self.total_bytes,
            "bundled_scripts": self.bundled_scripts,
            "warnings": self.warnings,
            "files": files
        })
    }

    fn from_json(v: &Value) -> Result<Self, SkillError> {
        let obj = v
            .as_object()
            .ok_or_else(|| SkillError::new(SkillErrorCode::CorruptStore, "manifest not object"))?;
        let schema_version = obj
            .get("schema_version")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                SkillError::new(SkillErrorCode::CorruptStore, "manifest missing schema_version")
            })?;
        if schema_version != REGISTRY_SCHEMA_VERSION {
            return Err(SkillError::new(
                SkillErrorCode::CorruptStore,
                format!("unsupported manifest schema_version {}", schema_version),
            ));
        }

        let name = json_req_str(obj, "name")?;
        let version = json_req_str(obj, "version")?;
        let declared_version = obj
            .get("declared_version")
            .and_then(Value::as_str)
            .map(ToString::to_string);
        let description = obj
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let source_kind = json_req_str(obj, "source_kind")?;
        let source_ref = json_req_str(obj, "source_ref")?;
        let source_archive_sha256 = obj
            .get("source_archive_sha256")
            .and_then(Value::as_str)
            .map(ToString::to_string);
        let installed_at_epoch_s = obj
            .get("installed_at_epoch_s")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let total_bytes = obj.get("total_bytes").and_then(Value::as_u64).unwrap_or(0);

        let mut frontmatter = BTreeMap::new();
        if let Some(fm) = obj.get("frontmatter").and_then(Value::as_object) {
            for (k, val) in fm {
                if let Some(s) = val.as_str() {
                    frontmatter.insert(k.clone(), s.to_string());
                }
            }
        }

        let bundled_scripts = json_str_vec(obj.get("bundled_scripts"));
        let warnings = json_str_vec(obj.get("warnings"));

        let files_arr = obj
            .get("files")
            .and_then(Value::as_array)
            .ok_or_else(|| SkillError::new(SkillErrorCode::CorruptStore, "manifest missing files"))?;
        let mut files = Vec::with_capacity(files_arr.len());
        for item in files_arr {
            let fobj = item.as_object().ok_or_else(|| {
                SkillError::new(SkillErrorCode::CorruptStore, "manifest file entry not object")
            })?;
            files.push(ManifestFileEntry {
                path: json_req_str(fobj, "path")?,
                bytes: fobj.get("bytes").and_then(Value::as_u64).unwrap_or(0),
                sha256: json_req_str(fobj, "sha256")?,
                is_utf8: fobj.get("is_utf8").and_then(Value::as_bool).unwrap_or(false),
                is_script_document: fobj
                    .get("is_script_document")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            });
        }
        files.sort_by(|a, b| a.path.cmp(&b.path));

        Ok(Self {
            schema_version,
            name,
            version,
            declared_version,
            description,
            frontmatter,
            source_kind,
            source_ref,
            source_archive_sha256,
            installed_at_epoch_s,
            file_count: files.len(),
            total_bytes,
            bundled_scripts,
            warnings,
            files,
        })
    }
}

struct RevisionSummary {
    version: String,
    declared_version: Option<String>,
    description: String,
    installed_at_epoch_s: u64,
    file_count: usize,
    total_bytes: u64,
    source_kind: String,
}

struct SkillRecord {
    // V2 registry-only authorization state. The package manifests remain
    // content-addressed V1 documents.
    import_source: Option<String>,
    revoked: bool,
    active_version: Option<String>,
    activation_history: Vec<String>,
    updated_at_epoch_s: u64,
    revisions: BTreeMap<String, RevisionSummary>,
}

struct Registry {
    schema_version: u64,
    operator_id: String,
    updated_at_epoch_s: u64,
    skills: BTreeMap<String, SkillRecord>,
}

impl Registry {
    fn empty(operator_id: &str) -> Self {
        Self {
            schema_version: REGISTRY_SCHEMA_VERSION,
            operator_id: operator_id.to_string(),
            updated_at_epoch_s: 0,
            skills: BTreeMap::new(),
        }
    }

    fn to_json(&self) -> Value {
        let mut skills_map = Map::new();
        for (name, rec) in &self.skills {
            let mut rev_map = Map::new();
            for (ver, rev) in &rec.revisions {
                rev_map.insert(
                    ver.clone(),
                    json!({
                        "version": rev.version,
                        "declared_version": rev.declared_version,
                        "description": rev.description,
                        "installed_at_epoch_s": rev.installed_at_epoch_s,
                        "file_count": rev.file_count,
                        "total_bytes": rev.total_bytes,
                        "source_kind": rev.source_kind
                    }),
                );
            }
            let mut record = json!({
                "active_version": rec.active_version,
                "activation_history": rec.activation_history,
                "updated_at_epoch_s": rec.updated_at_epoch_s,
                "revisions": Value::Object(rev_map)
            });
            if self.schema_version == OPERATOR_REGISTRY_SCHEMA_VERSION {
                record["import_source"] = json!(rec.import_source);
                record["revoked"] = json!(rec.revoked);
            }
            skills_map.insert(name.clone(), record);
        }

        json!({
            "schema_version": self.schema_version,
            "operator_id": self.operator_id,
            "documentary_only": true,
            "updated_at_epoch_s": self.updated_at_epoch_s,
            "skills": Value::Object(skills_map)
        })
    }

    fn from_json(v: &Value) -> Result<Self, SkillError> {
        let obj = v
            .as_object()
            .ok_or_else(|| SkillError::new(SkillErrorCode::CorruptStore, "registry not object"))?;
        let schema_version = obj
            .get("schema_version")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                SkillError::new(SkillErrorCode::CorruptStore, "registry missing schema_version")
            })?;
        if !matches!(schema_version, REGISTRY_SCHEMA_VERSION | OPERATOR_REGISTRY_SCHEMA_VERSION) {
            return Err(SkillError::new(
                SkillErrorCode::CorruptStore,
                format!("unsupported registry schema_version {}", schema_version),
            ));
        }

        let operator_id = obj
            .get("operator_id")
            .and_then(Value::as_str)
            .unwrap_or("default")
            .to_string();
        let updated_at_epoch_s = obj
            .get("updated_at_epoch_s")
            .and_then(Value::as_u64)
            .unwrap_or(0);

        let mut skills = BTreeMap::new();
        if let Some(skills_obj) = obj.get("skills").and_then(Value::as_object) {
            for (skill_name, skill_val) in skills_obj {
                validate_skill_name_str(skill_name)?;
                let sobj = skill_val.as_object().ok_or_else(|| {
                    SkillError::new(SkillErrorCode::CorruptStore, "skill record not object")
                })?;
                let active_version = sobj
                    .get("active_version")
                    .and_then(Value::as_str)
                    .map(ToString::to_string);
                let activation_history = json_str_vec(sobj.get("activation_history"));
                let rec_updated = sobj
                    .get("updated_at_epoch_s")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);

                let mut revisions = BTreeMap::new();
                if let Some(revs_obj) = sobj.get("revisions").and_then(Value::as_object) {
                    for (rev_key, rev_val) in revs_obj {
                        let robj = rev_val.as_object().ok_or_else(|| {
                            SkillError::new(
                                SkillErrorCode::CorruptStore,
                                "revision summary not object",
                            )
                        })?;
                        revisions.insert(
                            rev_key.clone(),
                            RevisionSummary {
                                version: json_req_str(robj, "version")?,
                                declared_version: robj
                                    .get("declared_version")
                                    .and_then(Value::as_str)
                                    .map(ToString::to_string),
                                description: robj
                                    .get("description")
                                    .and_then(Value::as_str)
                                    .unwrap_or_default()
                                    .to_string(),
                                installed_at_epoch_s: robj
                                    .get("installed_at_epoch_s")
                                    .and_then(Value::as_u64)
                                    .unwrap_or(0),
                                file_count: robj
                                    .get("file_count")
                                    .and_then(Value::as_u64)
                                    .unwrap_or(0) as usize,
                                total_bytes: robj
                                    .get("total_bytes")
                                    .and_then(Value::as_u64)
                                    .unwrap_or(0),
                                source_kind: robj
                                    .get("source_kind")
                                    .and_then(Value::as_str)
                                    .unwrap_or("unknown")
                                    .to_string(),
                            },
                        );
                    }
                }

                let (import_source, revoked) = if schema_version == OPERATOR_REGISTRY_SCHEMA_VERSION {
                    let source = match sobj.get("import_source") {
                        Some(Value::Null) => None,
                        Some(Value::String(value)) if operator_import::valid_source_ref(value) => Some(value.clone()),
                        _ => return Err(SkillError::new(SkillErrorCode::CorruptStore, "Invalid operator source")),
                    };
                    let revoked = sobj.get("revoked").and_then(Value::as_bool).ok_or_else(||
                        SkillError::new(SkillErrorCode::CorruptStore, "Missing revocation state"))?;
                    if (revoked && (source.is_none() || active_version.is_some() || !activation_history.is_empty()))
                        || revisions.values().any(|rev| (rev.source_kind == OPERATOR_SOURCE) != source.is_some()) {
                        return Err(SkillError::new(SkillErrorCode::CorruptStore, "Inconsistent operator import state"));
                    }
                    (source, revoked)
                } else {
                    if sobj.contains_key("import_source") || sobj.contains_key("revoked")
                        || revisions.values().any(|rev| rev.source_kind == OPERATOR_SOURCE) {
                        return Err(SkillError::new(SkillErrorCode::CorruptStore, "Operator imports require registry V2"));
                    }
                    (None, false)
                };
                skills.insert(
                    skill_name.clone(),
                    SkillRecord {
                        import_source, revoked,
                        active_version,
                        activation_history,
                        updated_at_epoch_s: rec_updated,
                        revisions,
                    },
                );
            }
        }

        Ok(Self {
            schema_version,
            operator_id,
            updated_at_epoch_s,
            skills,
        })
    }
}

fn build_validation_response(target: &str, loaded: &LoadedPackage) -> Value {
    json!({
        "ok": true,
        "action": "validate",
        "target": target,
        "valid": true,
        "documentary_only": true,
        "execution_policy": "never_executed",
        "name": loaded.name,
        "version": loaded.version,
        "declared_version": loaded.declared_version,
        "description": loaded.description,
        "file_count": loaded.files.len(),
        "total_bytes": loaded.total_bytes,
        "bundled_scripts": loaded.bundled_scripts,
        "warnings": loaded.warnings,
        "errors": []
    })
}

fn verify_source_digest(expected: Option<&str>, actual: &str) -> Result<(), SkillError> {
    if let Some(expected) = expected {
        if !ct_eq(expected.as_bytes(), actual.as_bytes()) {
            return Err(SkillError::with_details(SkillErrorCode::DigestMismatch,
                "Local source SHA-256 does not match expected_sha256",
                json!({"expected_sha256":expected,"actual_sha256":actual})));
        }
    }
    Ok(())
}

fn record_path_spelling(paths: &mut BTreeMap<String, String>, segments: &[String]) -> Result<(), SkillError> {
    let mut path = String::new();
    for segment in segments {
        if !path.is_empty() { path.push('/'); }
        path.push_str(segment);
        let spelling = paths.entry(path.to_lowercase()).or_insert_with(|| path.clone());
        if *spelling != path {
            return Err(SkillError::new(SkillErrorCode::PathPolicyViolation,
                "Inconsistent casing in package paths"));
        }
    }
    Ok(())
}

fn assemble_and_validate_package(
    raw_files: Vec<RawPackageFile>,
    explicit_name: Option<&str>,
    inferred_dir_name: Option<&str>,
    source_kind: &str,
    source_ref: &str,
    source_archive_sha256: Option<String>,
    limits: &PackageLimits,
) -> Result<LoadedPackage, SkillError> {
    if raw_files.is_empty() {
        return Err(SkillError::new(
            SkillErrorCode::ValidationFailed,
            "skill package contains no files",
        ));
    }
    if raw_files.len() > limits.max_files {
        return Err(SkillError::new(
            SkillErrorCode::LimitExceeded,
            format!(
                "package exceeds max_files limit ({} > {})",
                raw_files.len(),
                limits.max_files
            ),
        ));
    }

    let mut seen_paths = BTreeSet::new();
    let mut path_spellings = BTreeMap::new();
    let mut normalized_files = Vec::with_capacity(raw_files.len());
    let mut total_bytes: u64 = 0;

    for raw in raw_files {
        let segments = validate_relative_segments(&raw.relative_path, false, 512, "resource_path")?;
        record_path_spelling(&mut path_spellings, &segments)?;
        if segments.len().saturating_sub(1) > limits.max_depth {
            return Err(SkillError::new(
                SkillErrorCode::LimitExceeded,
                format!(
                    "package path '{}' exceeds max directory depth ({})",
                    raw.relative_path, limits.max_depth
                ),
            ));
        }
        let norm_path = segments.join("/");
        if !seen_paths.insert(norm_path.clone()) {
            return Err(SkillError::new(
                SkillErrorCode::ValidationFailed,
                format!("duplicate package path '{}'", norm_path),
            ));
        }

        let len = raw.bytes.len() as u64;
        if len > limits.max_single_file_bytes {
            return Err(SkillError::new(
                SkillErrorCode::LimitExceeded,
                format!(
                    "file '{}' exceeds max_single_file_bytes ({} > {})",
                    norm_path, len, limits.max_single_file_bytes
                ),
            ));
        }
        if norm_path == SKILL_ENTRYPOINT && len > limits.max_skill_md_bytes {
            return Err(SkillError::new(
                SkillErrorCode::LimitExceeded,
                format!(
                    "SKILL.md exceeds max_skill_md_bytes ({} > {})",
                    len, limits.max_skill_md_bytes
                ),
            ));
        }
        total_bytes = total_bytes.saturating_add(len);
        if total_bytes > limits.max_total_bytes {
            return Err(SkillError::new(
                SkillErrorCode::LimitExceeded,
                format!(
                    "package total size exceeds max_total_bytes ({} > {})",
                    total_bytes, limits.max_total_bytes
                ),
            ));
        }

        let sha256 = sha256_hex(&raw.bytes);
        let is_utf8 = std::str::from_utf8(&raw.bytes).is_ok();
        let is_script_document = is_script_path(&norm_path);
        normalized_files.push(LoadedFile {
            path: norm_path,
            bytes: raw.bytes,
            sha256,
            is_utf8,
            is_script_document,
        });
    }

    normalized_files.sort_by(|a, b| a.path.cmp(&b.path));

    let skill_md = normalized_files
        .iter()
        .find(|f| f.path == SKILL_ENTRYPOINT)
        .ok_or_else(|| {
            SkillError::new(
                SkillErrorCode::ValidationFailed,
                "required root document 'SKILL.md' is missing",
            )
        })?;
    let skill_md_text = std::str::from_utf8(&skill_md.bytes).map_err(|_| {
        SkillError::new(
            SkillErrorCode::ValidationFailed,
            "required root document 'SKILL.md' must be valid UTF-8",
        )
    })?;
    if skill_md_text.trim().is_empty() {
        return Err(SkillError::new(
            SkillErrorCode::ValidationFailed,
            "'SKILL.md' cannot be empty",
        ));
    }

    let parsed_fm = parse_skill_frontmatter(skill_md_text, source_kind == OPERATOR_SOURCE)?;
    let mut warnings = parsed_fm.warnings;

    let fm_name = parsed_fm.fields.get("name").map(|s| s.trim()).filter(|s| !s.is_empty());
    if let Some(n) = fm_name {
        validate_skill_name_str(n)?;
    }

    let resolved_name = match (explicit_name, fm_name, inferred_dir_name) {
        (Some(exp), Some(fm), _) => {
            if exp != fm {
                return Err(SkillError::new(
                    SkillErrorCode::ValidationFailed,
                    format!(
                        "provided name '{}' conflicts with SKILL.md frontmatter name '{}'",
                        exp, fm
                    ),
                ));
            }
            exp.to_string()
        }
        (Some(exp), None, _) => exp.to_string(),
        (None, Some(fm), _) => fm.to_string(),
        (None, None, Some(dir_name)) => {
            validate_skill_name_str(dir_name)?;
            warnings.push(
                "SKILL.md frontmatter lacks 'name'; inferred from source directory name"
                    .to_string(),
            );
            dir_name.to_string()
        }
        (None, None, None) => {
            return Err(SkillError::new(
                SkillErrorCode::ValidationFailed,
                "skill name could not be determined: declare 'name' in SKILL.md frontmatter or pass 'name'",
            ));
        }
    };

    let declared_version = parsed_fm
        .fields
        .get("version")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s.len() <= 256 && !has_control_chars(s));

    let description = parsed_fm
        .fields
        .get("description")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            warnings.push("SKILL.md frontmatter lacks 'description'".to_string());
            parsed_fm.fallback_description
        });

    let bundled_scripts: Vec<String> = normalized_files
        .iter()
        .filter(|f| f.is_script_document)
        .map(|f| f.path.clone())
        .collect();
    if !bundled_scripts.is_empty() {
        warnings.push(format!(
            "{} bundled script file(s) detected; stored strictly as inert documentary text and never executed",
            bundled_scripts.len()
        ));
    }

    let digest_inputs: Vec<(&str, u64, String)> = normalized_files
        .iter()
        .map(|f| (f.path.as_str(), f.bytes.len() as u64, f.sha256.clone()))
        .collect();
    let digest_hex = compute_canonical_package_digest(&digest_inputs);
    let version = format!("sha256:{}", digest_hex);

    Ok(LoadedPackage {
        name: resolved_name,
        version,
        digest_hex,
        declared_version,
        description,
        frontmatter: parsed_fm.fields,
        source_kind: source_kind.to_string(),
        source_ref: source_ref.to_string(),
        source_archive_sha256,
        total_bytes,
        files: normalized_files,
        bundled_scripts,
        warnings,
    })
}

struct ParsedFrontmatter {
    fields: BTreeMap<String, String>,
    fallback_description: String,
    warnings: Vec<String>,
}

fn parse_skill_frontmatter(content: &str, strict_import: bool) -> Result<ParsedFrontmatter, SkillError> {
    let mut fields = BTreeMap::new();
    let mut warnings = Vec::new();
    let mut lines = content.lines();
    let first = lines.next().unwrap_or("");
    let body_start_lines: Vec<&str>;

    if first.trim() == "---" {
        let mut closed = false;
        let mut count = 0usize;
        for line in lines.by_ref() {
            if line.trim() == "---" {
                closed = true;
                break;
            }
            count += 1;
            if count > MAX_FRONTMATTER_LINES {
                return Err(SkillError::new(
                    SkillErrorCode::ValidationFailed,
                    format!(
                        "SKILL.md frontmatter exceeds {} lines",
                        MAX_FRONTMATTER_LINES
                    ),
                ));
            }
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = trimmed.split_once(':') {
                let key = k.trim().to_ascii_lowercase();
                if !key.is_empty() && key.len() <= 64 {
                    let val = unquote_scalar(v.trim());
                    if fields.insert(key, val).is_some() && strict_import {
                        return Err(SkillError::new(SkillErrorCode::ValidationFailed,
                            "Duplicate SKILL.md frontmatter key"));
                    }
                }
            }
        }
        if !closed {
            return Err(SkillError::new(
                SkillErrorCode::ValidationFailed,
                "SKILL.md frontmatter starts with '---' but is never terminated",
            ));
        }
        body_start_lines = lines.collect();
    } else {
        warnings.push("SKILL.md does not start with YAML frontmatter ('---')".to_string());
        let mut all = vec![first];
        all.extend(lines);
        body_start_lines = all;
    }

    let fallback_description = body_start_lines
        .into_iter()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.chars().take(240).collect::<String>())
        .unwrap_or_default();

    Ok(ParsedFrontmatter {
        fields,
        fallback_description,
        warnings,
    })
}

fn unquote_scalar(s: &str) -> String {
    if s.len() >= 2 {
        let bytes = s.as_bytes();
        if (bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\'')
        {
            return s[1..s.len() - 1].to_string();
        }
    }
    s.to_string()
}

fn directory_entry_budget(limits: &PackageLimits) -> usize {
    limits.max_files.saturating_mul(limits.max_depth.saturating_add(1)).max(1)
}

fn collect_dir_files_recursive(
    dir: &Dir,
    prefix: &mut Vec<String>,
    depth: usize,
    limits: &PackageLimits,
    total_bytes: &mut u64,
    out: &mut Vec<RawPackageFile>,
    remaining_entries: &mut usize,
    operator_documentary: bool,
) -> Result<(), SkillError> {
    if depth > limits.max_depth {
        return Err(SkillError::new(
            SkillErrorCode::LimitExceeded,
            format!("directory nesting exceeds max_depth ({})", limits.max_depth),
        ));
    }

    let mut names = Vec::new();
    let entries = dir
        .entries()
        .map_err(|e| SkillError::io("read directory entries", e))?;
    for entry_res in entries {
        let entry = entry_res.map_err(|e| SkillError::io("iterate directory entry", e))?;
        let os_name = entry.file_name();
        let name = os_name.to_str().ok_or_else(|| {
            SkillError::new(
                SkillErrorCode::PathPolicyViolation,
                "non-UTF-8 filename rejected",
            )
        })?;
        // Bound empty directories as well as files. Never collect an
        // unbounded directory listing before enforcing package limits.
        *remaining_entries = remaining_entries.checked_sub(1).ok_or_else(||
            SkillError::new(SkillErrorCode::LimitExceeded, "Package directory entry limit exceeded"))?;
        names.push(name.to_string());
    }
    names.sort();

    for name in names {
        validate_path_segment(&name)?;
        if operator_documentary && (name.starts_with('.') ||
            matches!(name.to_ascii_lowercase().as_str(), "node_modules" | "__pycache__")) {
            return Err(SkillError::new(SkillErrorCode::PathPolicyViolation,
                "Hidden or generated package entries are not documentary imports"));
        }
        let meta = dir
            .symlink_metadata(&name)
            .map_err(|e| SkillError::io(format!("stat '{}'", name), e))?;
        let ft = meta.file_type();
        if ft.is_symlink() {
            return Err(SkillError::new(
                SkillErrorCode::PathPolicyViolation,
                format!("symlink '{}' rejected inside skill package", name),
            ));
        }

        if ft.is_dir() {
            let sub = open_dir_nofollow(dir, &name)?;
            prefix.push(name);
            let res = collect_dir_files_recursive(&sub, prefix, depth + 1, limits,
                total_bytes, out, remaining_entries, operator_documentary);
            prefix.pop();
            res?;
        } else if ft.is_file() {
            if out.len() >= limits.max_files {
                return Err(SkillError::new(
                    SkillErrorCode::LimitExceeded,
                    format!("package exceeds max_files ({})", limits.max_files),
                ));
            }
            let rel_path = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{}/{}", prefix.join("/"), name)
            };
            if operator_documentary && name.rsplit('.').next().is_some_and(|ext|
                matches!(ext.to_ascii_lowercase().as_str(), "exe"|"dll"|"so"|"dylib")) {
                return Err(SkillError::new(SkillErrorCode::BinaryResourceNotReadable,
                    "Executable images are not documentary import resources"));
            }
            let mut file = open_file_nofollow(dir, &name)?;
            let max_bytes = if rel_path == SKILL_ENTRYPOINT {
                limits.max_single_file_bytes.min(limits.max_skill_md_bytes)
            } else { limits.max_single_file_bytes };
            let bytes = read_file_bounded(&mut file, max_bytes, &rel_path)?;
            if operator_documentary && (bytes.contains(&0) || std::str::from_utf8(&bytes).is_err()) {
                return Err(SkillError::new(SkillErrorCode::BinaryResourceNotReadable,
                    "Operator directory imports require inert UTF-8 text resources"));
            }
            *total_bytes = total_bytes.saturating_add(bytes.len() as u64);
            if *total_bytes > limits.max_total_bytes {
                return Err(SkillError::new(
                    SkillErrorCode::LimitExceeded,
                    format!(
                        "package exceeds max_total_bytes ({} > {})",
                        *total_bytes, limits.max_total_bytes
                    ),
                ));
            }
            out.push(RawPackageFile {
                relative_path: rel_path,
                bytes,
            });
        } else {
            return Err(SkillError::new(
                SkillErrorCode::PathPolicyViolation,
                format!("non-regular filesystem entry '{}' rejected", name),
            ));
        }
    }

    Ok(())
}

fn resolve_installed_version(
    record: &SkillRecord,
    requested: Option<&str>,
) -> Result<String, SkillError> {
    let query = match requested {
        Some(v) => v.trim(),
        None => {
            return record.active_version.clone().ok_or_else(|| {
                SkillError::new(
                    SkillErrorCode::NotFound,
                    "skill has no active version; specify 'version' explicitly or activate one",
                )
            });
        }
    };

    if record.revisions.contains_key(query) {
        return Ok(query.to_string());
    }

    if is_hex_64(query) {
        let canonical = format!("sha256:{}", query.to_ascii_lowercase());
        if record.revisions.contains_key(&canonical) {
            return Ok(canonical);
        }
    }

    if let Some(hex_part) = strip_sha256_prefix(query) {
        if is_hex_64(hex_part) {
            let canonical = format!("sha256:{}", hex_part.to_ascii_lowercase());
            if record.revisions.contains_key(&canonical) {
                return Ok(canonical);
            }
        }
    }

    let mut matches: Vec<String> = record
        .revisions
        .iter()
        .filter_map(|(k, rev)| {
            if rev.declared_version.as_deref() == Some(query) {
                Some(k.clone())
            } else {
                None
            }
        })
        .collect();

    match matches.len() {
        1 => Ok(matches.remove(0)),
        0 => Err(SkillError::new(
            SkillErrorCode::NotFound,
            format!("version '{}' is not installed for this skill", query),
        )),
        _ => Err(SkillError::with_details(
            SkillErrorCode::AmbiguousVersion,
            format!(
                "declared version '{}' matches multiple installed digests; specify the canonical sha256:<hex> revision",
                query
            ),
            json!({ "matching_versions": matches }),
        )),
    }
}

fn skill_path_error(error: super::DesktopError) -> SkillError {
    SkillError::new(SkillErrorCode::PathPolicyViolation, error.to_string())
}

fn open_file_nofollow(dir: &Dir, name: &str) -> Result<File, SkillError> {
    let pre_meta = dir
        .symlink_metadata(name)
        .map_err(|e| SkillError::io(format!("stat '{}'", name), e))?;
    super::validate_segment(name).map_err(skill_path_error)?;
    super::ensure_regular(&pre_meta).map_err(skill_path_error)?;

    let mut opts = OpenOptions::new();
    opts.read(true).follow(FollowSymlinks::No);
    let file = dir
        .open_with(name, &opts)
        .map_err(|e| SkillError::io(format!("open '{}'", name), e))?;

    let opened_meta = file
        .metadata()
        .map_err(|e| SkillError::io(format!("fstat '{}'", name), e))?;
    super::ensure_regular(&opened_meta).map_err(skill_path_error)?;

    super::workspace_write::ensure_single_hard_link(&file).map_err(skill_path_error)?;

    Ok(file)
}

fn open_dir_nofollow(dir: &Dir, segment: &str) -> Result<Dir, SkillError> {
    super::open_child_dir(dir, segment).map_err(skill_path_error)
}

fn open_nested_file_nofollow(root: &Dir, segments: &[String]) -> Result<File, SkillError> {
    let (leaf, parents) = segments.split_last().ok_or_else(|| {
        SkillError::new(SkillErrorCode::PathPolicyViolation, "empty resource path")
    })?;
    let mut current = root
        .try_clone()
        .map_err(|e| SkillError::io("clone root dir", e))?;
    for seg in parents {
        current = open_dir_nofollow(&current, seg)?;
    }
    open_file_nofollow(&current, leaf)
}

fn ensure_dir_nofollow(parent: &Dir, segment: &str) -> Result<Dir, SkillError> {
    match parent.symlink_metadata(segment) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return Err(SkillError::new(
                    SkillErrorCode::PathPolicyViolation,
                    format!("store entry '{}' is not a regular directory", segment),
                ));
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            if let Err(create_err) = parent.create_dir(segment) {
                if create_err.kind() != io::ErrorKind::AlreadyExists {
                    return Err(SkillError::io(
                        format!("create dir '{}'", segment),
                        create_err,
                    ));
                }
            }
        }
        Err(e) => return Err(SkillError::io(format!("stat '{}'", segment), e)),
    }
    open_dir_nofollow(parent, segment)
}

fn atomic_write_bytes(dir: &Dir, filename: &str, bytes: &[u8]) -> Result<(), SkillError> {
    let tmp_name = format!(".{}.tmp-{}", filename, Uuid::new_v4().simple());
    let write_res: Result<(), SkillError> = (|| {
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        let mut file = dir
            .open_with(&tmp_name, &opts)
            .map_err(|e| SkillError::io(format!("create temp '{}'", tmp_name), e))?;
        file.write_all(bytes)
            .map_err(|e| SkillError::io(format!("write temp '{}'", tmp_name), e))?;
        file.sync_all()
            .map_err(|e| SkillError::io(format!("sync temp '{}'", tmp_name), e))?;
        drop(file);
        dir.rename(&tmp_name, dir, filename)
            .map_err(|e| SkillError::io(format!("rename '{}' -> '{}'", tmp_name, filename), e))?;
        Ok(())
    })();

    if write_res.is_err() {
        let _ = dir.remove_file(&tmp_name);
    }
    write_res
}

fn read_file_bounded(file: &mut File, max_bytes: u64, label: &str) -> Result<Vec<u8>, SkillError> {
    let meta_len = file
        .metadata()
        .map_err(|e| SkillError::io(format!("fstat '{}'", label), e))?
        .len();
    if meta_len > max_bytes {
        return Err(SkillError::new(
            SkillErrorCode::LimitExceeded,
            format!(
                "file '{}' exceeds max allowed size ({} > {} bytes)",
                label, meta_len, max_bytes
            ),
        ));
    }

    let initial_cap = usize::try_from(meta_len.min(64 * 1024)).unwrap_or(8192);
    let mut out = Vec::with_capacity(initial_cap);
    let mut buf = [0u8; 8192];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| SkillError::io(format!("read '{}'", label), e))?;
        if n == 0 {
            break;
        }
        let next_len = (out.len() as u64).saturating_add(n as u64);
        if next_len > max_bytes {
            return Err(SkillError::new(
                SkillErrorCode::LimitExceeded,
                format!(
                    "file '{}' exceeded max allowed size while reading ({} bytes)",
                    label, max_bytes
                ),
            ));
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

fn validate_relative_segments(
    raw: &str,
    allow_backslash: bool,
    max_len: usize,
    field: &str,
) -> Result<Vec<String>, SkillError> {
    let char_len = raw.chars().count();
    if char_len == 0 || char_len > max_len {
        return Err(SkillError::new(
            SkillErrorCode::InvalidInput,
            format!("'{}' length must be between 1 and {}", field, max_len),
        ));
    }
    if has_control_chars(raw) {
        return Err(SkillError::new(
            SkillErrorCode::PathPolicyViolation,
            format!("'{}' contains control characters", field),
        ));
    }
    if raw.starts_with('/') || raw.starts_with('\\') {
        return Err(SkillError::new(
            SkillErrorCode::PathPolicyViolation,
            format!("'{}' must be a relative path under policy root", field),
        ));
    }
    if !allow_backslash && raw.contains('\\') {
        return Err(SkillError::new(
            SkillErrorCode::PathPolicyViolation,
            format!("'{}' must use '/' separators", field),
        ));
    }
    let bytes = raw.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' {
        return Err(SkillError::new(
            SkillErrorCode::PathPolicyViolation,
            format!("'{}' must not include a drive prefix", field),
        ));
    }

    let trimmed = if allow_backslash {
        raw.trim_end_matches(|c| c == '/' || c == '\\')
    } else {
        raw
    };
    if trimmed.is_empty() {
        return Err(SkillError::new(
            SkillErrorCode::PathPolicyViolation,
            format!("'{}' cannot be empty or root", field),
        ));
    }

    let mut segments = Vec::new();
    let iter = if allow_backslash {
        trimmed.split(|c| c == '/' || c == '\\').collect::<Vec<_>>()
    } else {
        trimmed.split('/').collect::<Vec<_>>()
    };

    for seg in iter {
        validate_path_segment(seg)?;
        segments.push(seg.to_string());
    }
    if segments.is_empty() {
        return Err(SkillError::new(
            SkillErrorCode::PathPolicyViolation,
            format!("'{}' resolved to empty path", field),
        ));
    }
    Ok(segments)
}

fn validate_path_segment(seg: &str) -> Result<(), SkillError> {
    if seg.is_empty() || seg == "." || seg == ".." {
        return Err(SkillError::new(
            SkillErrorCode::PathPolicyViolation,
            format!("disallowed path segment '{}'", seg),
        ));
    }
    if has_control_chars(seg) {
        return Err(SkillError::new(
            SkillErrorCode::PathPolicyViolation,
            "path segment contains control characters",
        ));
    }
    if seg.ends_with('.') || seg.ends_with(' ') || seg.starts_with(' ') {
        return Err(SkillError::new(
            SkillErrorCode::PathPolicyViolation,
            format!("path segment '{}' has unsafe leading/trailing dot or space", seg),
        ));
    }
    if seg
        .chars()
        .any(|c| matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*' | '/' | '\\'))
    {
        return Err(SkillError::new(
            SkillErrorCode::PathPolicyViolation,
            format!("path segment '{}' contains illegal character", seg),
        ));
    }
    let stem = seg.split('.').next().unwrap_or("").to_ascii_lowercase();
    if WINDOWS_RESERVED_NAMES.contains(&stem.as_str()) {
        return Err(SkillError::new(
            SkillErrorCode::PathPolicyViolation,
            format!("path segment '{}' uses a Windows reserved device name", seg),
        ));
    }
    Ok(())
}

fn validate_skill_name_str(name: &str) -> Result<(), SkillError> {
    let char_len = name.chars().count();
    if char_len == 0 || char_len > 64 {
        return Err(SkillError::new(
            SkillErrorCode::InvalidInput,
            "skill 'name' must be 1..=64 characters",
        ));
    }
    validate_path_segment(name)?;
    let mut chars = name.chars();
    let first = chars.next().unwrap_or('\0');
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return Err(SkillError::new(
            SkillErrorCode::InvalidInput,
            format!(
                "skill name '{}' must start with lowercase ASCII letter or digit",
                name
            ),
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_' | '.'))
        || name.contains("..")
    {
        return Err(SkillError::new(
            SkillErrorCode::InvalidInput,
            format!(
                "skill name '{}' may only contain [a-z0-9._-] without '..'",
                name
            ),
        ));
    }
    Ok(())
}

fn extract_https_origin(raw_url: &str) -> Result<String, SkillError> {
    if raw_url.is_empty()
        || raw_url.chars().count() > 8192
        || has_control_chars(raw_url)
        || raw_url.chars().any(char::is_whitespace)
        || raw_url.contains('#')
    {
        return Err(SkillError::new(
            SkillErrorCode::InvalidInput,
            "source_url is malformed or contains disallowed characters/fragments",
        ));
    }
    if raw_url.len() < 9 || !raw_url.get(..8).is_some_and(|prefix| prefix.eq_ignore_ascii_case("https://")) {
        return Err(SkillError::new(
            SkillErrorCode::PathPolicyViolation,
            "source_url must use the https:// scheme",
        ));
    }

    let rest = &raw_url[8..];
    let authority_end = rest.find(|c| c == '/' || c == '?').unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty() || authority.contains('@') {
        return Err(SkillError::new(
            SkillErrorCode::PathPolicyViolation,
            "source_url authority is empty or contains disallowed userinfo",
        ));
    }

    let (host, port_opt) = if let Some(after_open) = authority.strip_prefix('[') {
        let close = after_open.find(']').ok_or_else(|| {
            SkillError::new(SkillErrorCode::InvalidInput, "unterminated IPv6 host in source_url")
        })?;
        let ipv6 = &after_open[..close];
        if ipv6.is_empty() || !ipv6.chars().all(|c| c.is_ascii_hexdigit() || c == ':') {
            return Err(SkillError::new(
                SkillErrorCode::InvalidInput,
                "invalid IPv6 literal in source_url",
            ));
        }
        let remainder = &after_open[close + 1..];
        let port = if remainder.is_empty() {
            None
        } else if let Some(p) = remainder.strip_prefix(':') {
            Some(parse_port(p)?)
        } else {
            return Err(SkillError::new(
                SkillErrorCode::InvalidInput,
                "invalid authority syntax after IPv6 literal",
            ));
        };
        (format!("[{}]", ipv6.to_ascii_lowercase()), port)
    } else {
        let (h, p) = match authority.split_once(':') {
            Some((h, p)) => {
                if p.contains(':') {
                    return Err(SkillError::new(
                        SkillErrorCode::InvalidInput,
                        "invalid port syntax in source_url",
                    ));
                }
                (h, Some(parse_port(p)?))
            }
            None => (authority, None),
        };
        if h.is_empty()
            || h.starts_with('.')
            || h.ends_with('.')
            || h.contains("..")
            || !h
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        {
            return Err(SkillError::new(
                SkillErrorCode::InvalidInput,
                "invalid hostname in source_url",
            ));
        }
        (h.to_ascii_lowercase(), p)
    };

    match port_opt {
        Some(port) if port != 443 => Ok(format!("https://{}:{}", host, port)),
        _ => Ok(format!("https://{}", host)),
    }
}

fn parse_port(raw: &str) -> Result<u16, SkillError> {
    let port: u16 = raw
        .parse()
        .map_err(|_| SkillError::new(SkillErrorCode::InvalidInput, "invalid TCP port in source_url"))?;
    if port == 0 {
        return Err(SkillError::new(
            SkillErrorCode::InvalidInput,
            "TCP port 0 is not allowed in source_url",
        ));
    }
    Ok(port)
}

fn compute_canonical_package_digest(entries: &[(&str, u64, String)]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"agent-bridge-skill-v1\n");
    for (path, len, file_sha) in entries {
        hasher.update(path.as_bytes());
        hasher.update(b"\0");
        hasher.update(len.to_string().as_bytes());
        hasher.update(b"\0");
        hasher.update(file_sha.as_bytes());
        hasher.update(b"\n");
    }
    encode_hex_lower(&hasher.finalize())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    encode_hex_lower(&hasher.finalize())
}

fn encode_hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn is_hex_64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn strip_sha256_prefix(s: &str) -> Option<&str> {
    s.strip_prefix("sha256:")
}

fn is_script_path(rel_path: &str) -> bool {
    if rel_path.starts_with("scripts/") {
        return true;
    }
    let filename = rel_path.rsplit('/').next().unwrap_or(rel_path);
    if let Some((_, ext)) = filename.rsplit_once('.') {
        let lower = ext.to_ascii_lowercase();
        return SCRIPT_EXTENSIONS.contains(&lower.as_str());
    }
    false
}

fn push_bounded_history(history: &mut Vec<String>, version: String, max_len: usize) {
    if max_len == 0 {
        history.clear();
        return;
    }
    if history.last().map(String::as_str) != Some(version.as_str()) {
        history.push(version);
    }
    if history.len() > max_len {
        let excess = history.len() - max_len;
        history.drain(0..excess);
    }
}

fn require_string_field(
    obj: &Map<String, Value>,
    key: &str,
    min_chars: usize,
    max_chars: usize,
) -> Result<String, SkillError> {
    optional_string_field(obj, key, min_chars, max_chars)?.ok_or_else(|| {
        SkillError::new(
            SkillErrorCode::InvalidInput,
            format!("missing required string field '{}'", key),
        )
    })
}

fn optional_string_field(
    obj: &Map<String, Value>,
    key: &str,
    min_chars: usize,
    max_chars: usize,
) -> Result<Option<String>, SkillError> {
    match obj.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => {
            let count = s.chars().count();
            if count < min_chars || count > max_chars {
                return Err(SkillError::new(
                    SkillErrorCode::InvalidInput,
                    format!(
                        "field '{}' length must be between {} and {} characters",
                        key, min_chars, max_chars
                    ),
                ));
            }
            Ok(Some(s.clone()))
        }
        Some(_) => Err(SkillError::new(
            SkillErrorCode::InvalidInput,
            format!("field '{}' must be a string", key),
        )),
    }
}

fn optional_bool_field(obj: &Map<String, Value>, key: &str) -> Result<Option<bool>, SkillError> {
    match obj.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(b)) => Ok(Some(*b)),
        Some(_) => Err(SkillError::new(
            SkillErrorCode::InvalidInput,
            format!("field '{}' must be a boolean", key),
        )),
    }
}

fn require_skill_name(obj: &Map<String, Value>) -> Result<String, SkillError> {
    optional_skill_name(obj)?.ok_or_else(|| {
        SkillError::new(SkillErrorCode::InvalidInput, "missing required field 'name'")
    })
}

fn optional_skill_name(obj: &Map<String, Value>) -> Result<Option<String>, SkillError> {
    match optional_string_field(obj, "name", 1, 64)? {
        Some(name) => {
            validate_skill_name_str(&name)?;
            Ok(Some(name))
        }
        None => Ok(None),
    }
}

fn optional_version(obj: &Map<String, Value>) -> Result<Option<String>, SkillError> {
    match optional_string_field(obj, "version", 1, 256)? {
        Some(v) => {
            if has_control_chars(&v) || v.contains('/') || v.contains('\\') {
                return Err(SkillError::new(
                    SkillErrorCode::InvalidInput,
                    "field 'version' contains disallowed characters",
                ));
            }
            Ok(Some(v))
        }
        None => Ok(None),
    }
}

fn optional_expected_sha256(obj: &Map<String, Value>) -> Result<Option<String>, SkillError> {
    match optional_string_field(obj, "expected_sha256", 64, 64)? {
        Some(hex) => {
            if !is_hex_64(&hex) {
                return Err(SkillError::new(
                    SkillErrorCode::InvalidInput,
                    "field 'expected_sha256' must be 64 hexadecimal characters",
                ));
            }
            Ok(Some(hex.to_ascii_lowercase()))
        }
        None => Ok(None),
    }
}

fn parse_max_chars(obj: &Map<String, Value>) -> Result<usize, SkillError> {
    match obj.get("max_chars") {
        None | Some(Value::Null) => Ok(DEFAULT_MAX_CHARS),
        Some(val) => {
            let n = val.as_i64().ok_or_else(|| {
                SkillError::new(
                    SkillErrorCode::InvalidInput,
                    "field 'max_chars' must be an integer",
                )
            })?;
            if !(MIN_MAX_CHARS as i64..=MAX_MAX_CHARS as i64).contains(&n) {
                return Err(SkillError::new(
                    SkillErrorCode::InvalidInput,
                    format!(
                        "field 'max_chars' must be between {} and {}",
                        MIN_MAX_CHARS, MAX_MAX_CHARS
                    ),
                ));
            }
            Ok(n as usize)
        }
    }
}

fn json_req_str(obj: &Map<String, Value>, key: &str) -> Result<String, SkillError> {
    obj.get(key)
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| {
            SkillError::new(
                SkillErrorCode::CorruptStore,
                format!("missing required string field '{}' in store metadata", key),
            )
        })
}

fn json_str_vec(val: Option<&Value>) -> Vec<String> {
    val.and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn has_control_chars(s: &str) -> bool {
    s.bytes().any(|b| b < 0x20 || b == 0x7f)
}

fn now_epoch_s() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
