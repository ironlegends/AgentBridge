//! Agent Bridge file-only workspace facade.
//! An original Rust implementation of a deliberately restricted subset of the
//! agent-bridge-desktop-v1 JSON tool contract; no provider code is incorporated.
//! All runtime filesystem access is relative to a directory capability.
//! Read-only by default; separate explicit create-only and workspace-write modes.

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, DirBuilder, File, Metadata, OpenOptions};
use regex::{Regex, RegexBuilder};
use serde::Serialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::ffi::OsString;
use std::fmt;
use std::io::{self, Read};
use std::sync::Mutex;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant, UNIX_EPOCH};
use uuid::Uuid;

mod artifacts;
pub mod skills;
mod workspace_write;
pub mod unified;
mod path_policy;
mod unified_transfer;
mod unified_artifacts;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const CONTRACT_VERSION: u32 = 1;

const MAX_PATH_BYTES: usize = 4096;
const MAX_FILE_BYTES: usize = 1_048_576;
const MAX_LINE_WINDOW: usize = 5_000;
const MAX_LIST_ENTRIES: usize = 200;
const MAX_LIST_DEPTH: usize = 4;
const MAX_SEARCH_RESULTS: usize = 100;
const MAX_SEARCH_DEPTH: usize = 6;
const MAX_SCANNED_ENTRIES: usize = 2_048;
const MAX_SEARCH_BYTES: usize = 8 * 1_048_576;
const MAX_PATTERN_CHARS: usize = 500;
const MAX_SEARCH_DURATION_MS: u64 = 10_000;
const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
const TEMP_PREFIX: &str = ".agent-bridge-tmp-";

pub type Result<T> = std::result::Result<T, DesktopError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopError {
    pub code: &'static str,
    pub message: String,
}

impl DesktopError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for DesktopError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for DesktopError {}

impl From<io::Error> for DesktopError {
    fn from(error: io::Error) -> Self {
        Self::new("FILESYSTEM_ERROR", error.to_string())
    }
}

/// Permission profile selected by the local operator for a workstation session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DesktopProfile {
    ReadOnly,
    WorkspaceWrite,
    FullControl,
    FullyUnlocked,
}

impl std::str::FromStr for DesktopProfile {
    type Err = DesktopError;

    fn from_str(raw: &str) -> Result<Self> {
        match raw {
            "read-only" => Ok(Self::ReadOnly),
            "workspace-write" => Ok(Self::WorkspaceWrite),
            "full-control" => Ok(Self::FullControl),
            "fully-unlocked" => Ok(Self::FullyUnlocked),
            _ => Err(DesktopError::new("INVALID_PROFILE", "Invalid AGENT_BRIDGE_DESKTOP_PROFILE")),
        }
    }
}

impl DesktopProfile {
    pub fn permits_processes(self) -> bool {
        matches!(self, Self::FullControl | Self::FullyUnlocked)
    }
}

#[derive(Debug, Clone)]
pub struct DesktopConfig {
    session_profile: Option<DesktopProfile>,
    workspace: PathBuf,
    create_only: bool,
    workspace_write: bool,
    web_project_read: bool,
}

impl DesktopConfig {
    /// The operator, not a tool caller, must choose an existing absolute root.
    pub fn new(workspace: impl Into<PathBuf>) -> Self {
        Self {
            session_profile: None,
            workspace: workspace.into(),
            create_only: false,
            workspace_write: false,
            web_project_read: false,
        }
    }

    pub fn with_session_profile(mut self, profile: DesktopProfile) -> Self {
        self.session_profile = Some(profile);
        self
    }

    /// Enable the create-only subset. Never enables rewrite, append, edit or move.
    pub fn allow_creation(mut self) -> Self {
        self.create_only = true;
        self
    }

    /// Explicit opt-in for bounded observed rewrites, appends, edits and moves.
    /// New-file creation and new-directory creation are included.
    pub fn allow_workspace_write(mut self) -> Self {
        self.create_only = true;
        self.workspace_write = true;
        self
    }

    /// Dedicated Web capability: refuse hidden/secret paths BEFORE opening
    /// entries, reading data, evaluating search patterns or charging quotas.
    /// Cannot enable artifacts, writes, a shell or broader local profiles.
    pub fn with_web_project_read_policy(mut self) -> Self {
        self.web_project_read = true;
        self.session_profile = Some(DesktopProfile::ReadOnly);
        self.create_only = false;
        self.workspace_write = false;
        self
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ToolSpec {
    pub name: &'static str,
    pub description: &'static str,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
}

/// An instance is bound to exactly one operator-selected directory handle.
/// There are no global or process-wide workspace settings.
pub struct DesktopFiles {
    session_profile: Option<DesktopProfile>,
    workspace: PathBuf,
    root: Dir,
    create_only: bool,
    workspace_write: bool,
    operations: Mutex<workspace_write::ObservationStore>,
    artifacts: Mutex<artifacts::ArtifactStore>,
    web_project_read: bool,
    protected: Option<std::sync::Arc<path_policy::ProtectedPaths>>,
}

impl DesktopFiles {
    /// Both handles originate from directories selected and qualified locally.
    pub fn documentary_skills(&self, private_store: &Path) -> Result<skills::SkillManager> {
        self.documentary_skills_with_policy(
            private_store,
            skills::RemoteSourcePolicy::default(),
            None,
        )
    }

    pub fn documentary_skills_with_policy(
        &self,
        private_store: &Path,
        remote_policy: skills::RemoteSourcePolicy,
        remote_provider: Option<Box<dyn skills::ApprovedRemoteProvider>>,
    ) -> Result<skills::SkillManager> {
        let store = open_workspace(private_store)?;
        let workspace = self.root.try_clone()?;
        let mut config = skills::SkillManagerConfig::for_operator("local");
        config.remote_policy = remote_policy;
        let manager = skills::SkillManager::new(store, workspace, config)
            .map_err(|error| DesktopError::new("SKILL_STORE_UNAVAILABLE", error.to_string()))?;
        Ok(match remote_provider {
            Some(provider) => manager.with_remote_provider(provider),
            None => manager,
        })
    }

    pub fn open(config: DesktopConfig) -> Result<Self> {
        let root = open_workspace(&config.workspace)?;
        Ok(Self::from_qualified_root(config, root))
    }

    fn from_qualified_root(config: DesktopConfig, root: Dir) -> Self {
        Self {
            session_profile: config.session_profile,
            workspace: config.workspace,
            root,
            create_only: !config.web_project_read && config.create_only
                && config.session_profile != Some(DesktopProfile::ReadOnly),
            workspace_write: !config.web_project_read && config.workspace_write
                && config.session_profile != Some(DesktopProfile::ReadOnly),
            operations: Mutex::new(workspace_write::ObservationStore::new()),
            artifacts: Mutex::new(artifacts::ArtifactStore::new()),
            protected: None,
            web_project_read: config.web_project_read,
        }
    }

    /// Clone the directory capability already owned by this facade. The
    /// selected path is only an identity witness; it never replaces the root.
    #[cfg(unix)]
    pub fn clone_workspace_root_handle(&self) -> Result<std::fs::File> {
        self.verify_workspace_root_identity()?;
        Ok(self.root.try_clone()?.into_std_file())
    }

    /// Adopt an already-owned Unix directory capability for the private
    /// metadata child. This constructor cannot enable any workspace writes.
    #[cfg(unix)]
    pub fn open_read_only_from_workspace_handle(
        workspace: impl Into<PathBuf>, handle: std::fs::File,
    ) -> Result<Self> {
        use std::os::fd::AsRawFd;
        let flags = unsafe { libc::fcntl(handle.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 { return Err(io::Error::last_os_error().into()); }
        if flags & libc::O_ACCMODE != libc::O_RDONLY || !handle.metadata()?.is_dir() {
            return Err(DesktopError::new("UNSAFE_WORKSPACE_HANDLE",
                "Workspace capability must be a read-only directory handle"));
        }
        let files = Self::from_qualified_root(
            DesktopConfig::new(workspace).with_session_profile(DesktopProfile::ReadOnly),
            Dir::from_std_file(handle),
        );
        files.verify_workspace_root_identity()?;
        Ok(files)
    }

    /// Refuse a renamed/replaced selection or any symlink in its path, while
    /// retaining the original root handle as the sole filesystem authority.
    #[cfg(unix)]
    pub fn verify_workspace_root_identity(&self) -> Result<()> {
        use cap_std::fs::MetadataExt;
        let held = self.root.dir_metadata()?;
        ensure_directory(&held)?;
        let selected = open_workspace(&self.workspace)?.dir_metadata()?;
        if held.dev() != selected.dev() || held.ino() != selected.ino() {
            return Err(DesktopError::new("WORKSPACE_ROOT_CHANGED",
                "Selected workspace no longer matches its owned directory handle"));
        }
        Ok(())
    }

    pub fn tool_catalog(&self) -> Vec<ToolSpec> {
        let path = json!({"type":"string","minLength":1,"maxLength":MAX_PATH_BYTES,
                          "description":"Workspace-relative path; use . for root"});
        let mut tools = vec![
            spec(
                "desktop_policy_status",
                "Inspect the selected workspace's file access, enabled tools and operation limits before choosing a file operation. This reads policy; it does not change permissions. For gateway version and health, use agent_bridge_status.",
                json!({}),
                &[],
            ),
            spec(
                "desktop_get_file_info",
                "Inspect one workspace entry without reading its contents. Returns its kind, file size when applicable, read-only flag and modification time when available. Use desktop_list_directory for children or desktop_read_file for text.",
                json!({"path":path}),
                &["path"],
            ),
            spec(
                "desktop_list_directory",
                "Browse children of a workspace directory. Returns entry metadata and a truncation flag when traversal reaches a limit. Use desktop_search to find names matching a pattern rather than enumerating a whole subtree.",
                json!({"path":path,"depth":{"description":"Number of directory levels to traverse. Use 1 for immediate children.","type":"integer","minimum":1,"maximum":4,"default":2}}),
                &["path"],
            ),
            spec(
                "desktop_read_file",
                "Read a window of lines from a UTF-8 file. Returns content, line counts, truncation, a SHA-256 digest and a five-minute observation ID for this instance. Reading leaves the file unchanged. Use desktop_get_file_info for metadata alone.",
                json!({"path":{"type":"string","minLength":1,"maxLength":MAX_PATH_BYTES,
                               "description":"Workspace-relative path to a regular UTF-8 file."},"offset":{"description":"Zero-based line index. A negative offset counts from the end of the file.","type":"integer","minimum":-MAX_SAFE_INTEGER,"maximum":MAX_SAFE_INTEGER,"default":0},
                       "length":{"description":"Maximum number of text lines to return.","type":"integer","minimum":1,"maximum":5000,"default":1000}}),
                &["path"],
            ),
            spec(
                "desktop_search",
                "Find matching filenames or UTF-8 text under a workspace directory in a single bounded search. Returns matches and a truncation flag. Narrow the path or filename filter for incomplete results; use desktop_read_file to inspect a match.",
                json!({"path":path,
                       "pattern":{"description":"Expression to match against a filename or a line of text. Interpreted as a regex unless literal_search is true.","type":"string","minLength":1,"maxLength":MAX_PATTERN_CHARS},
                       "search_type":{"description":"Match filenames with files, or text lines with content when the active profile permits it.","type":"string","enum":["files","content"],"default":"files"},
                       "file_pattern":{"description":"Optional filename glob restricting the files examined.","type":"string","minLength":1,"maxLength":256},
                       "ignore_case":{"description":"Match regardless of letter case when true.","type":"boolean","default":true},
                       "include_hidden":{"description":"Include hidden entries only when supported by the workspace policy.","type":"boolean","default":false},
                       "literal_search":{"description":"Treat pattern as literal text instead of a regular expression.","type":"boolean","default":false},
                       "max_results":{"description":"Stop collecting after this many matches.","type":"integer","minimum":1,"maximum":100,"default":50},
                       "timeout_ms":{"description":"Search time budget in milliseconds; a partial result can be truncated.","type":"integer","minimum":500,"maximum":10000,"default":5000}}),
                &["path", "pattern"],
            ),
            artifacts::tool_spec(),
        ];
        if self.web_project_read {
            tools.retain(|tool| WEB_PROJECT_READ_TOOLS.contains(&tool.name));
            for tool in &mut tools {
                match tool.name {
                    "desktop_list_directory" => {
                        tool.description = "List immediate children visible under a workspace directory. Returns the path, depth and entries. Use desktop_search to find visible filenames.";
                        tool.input_schema["properties"]["depth"] = json!({
                            "description":"This web profile lists immediate children only.","type":"integer","minimum":1,"maximum":1,"default":1
                        });
                    }
                    "desktop_search" => {
                        tool.input_schema["properties"]["search_type"] = json!({
                            "description":"This web profile searches filenames only.","type":"string","enum":["files"],"default":"files"
                        });
                        tool.input_schema["properties"]["include_hidden"] = json!({
                            "description":"Hidden entries are excluded in this web profile.","type":"boolean","const":false,"default":false
                        });
                    }
                    _ => {}
                }
            }
        }
        if self.create_only {
            tools.push(spec(
                "desktop_create_directory",
                "Create one absent directory under an existing safe parent.",
                json!({"path":path}),
                &["path"],
            ));
            let modes = if self.workspace_write {
                json!({"type":"string","enum":["rewrite","append"]})
            } else {
                json!({"type":"string","const":"rewrite"})
            };
            tools.push(spec(
                "desktop_write_file",
                "Create a new text file; existing-file rewrite/append requires explicit workspace-write mode and a fresh one-use observation_id.",
                json!({"path":path,
                       "content":{"type":"string","minLength":1,"maxLength":MAX_FILE_BYTES},
                       "mode":modes,
                       "observation_id":{"type":"string","format":"uuid"}}),
                &["path", "content", "mode"],
            ));
        }
        if self.workspace_write {
            tools.push(spec(
                "desktop_edit_file",
                "Replace exact text in an observed file. Single-use observation_id is mandatory.",
                json!({"path":path,
                       "old_string":{"type":"string","minLength":1,"maxLength":131072},
                       "new_string":{"type":"string","maxLength":131072},
                       "expected_replacements":{"type":"integer","minimum":1,"maximum":100,"default":1},
                       "observation_id":{"type":"string","format":"uuid"}}),
                &["path", "old_string", "new_string", "observation_id"],
            ));
            tools.push(spec(
                "desktop_move_file",
                "Move an observed regular file to a NEW name; source_observation_id mandatory. Non-atomic whole move; never overwrites destination.",
                json!({"source":path,"destination":path,
                       "source_observation_id":{"type":"string","format":"uuid"}}),
                &["source", "destination", "source_observation_id"],
            ));
        }
        tools
    }

    /// Dispatch a contract tool name with parsed JSON arguments. Return an MCP
    /// content envelope, with structured errors rather than a panic.
    pub fn dispatch(&self, name: &str, arguments: &Value) -> Value {
        // Fail closed *before* any metadata, walking, reads, quota charging,
        // pattern compilation or access to the observation/artifact stores.
        if self.web_project_read && !web_project_request_allowed(name, arguments) {
            return error_envelope(DesktopError::new(
                "PROJECT_READ_DENIED", "Project read request refused",
            ));
        }
        // One mutex serializes observation issuance/consumption and all file
        // operations made through this instance, including both move phases.
        // No OS-global lock or external compare-and-swap is implied.
        let result = match self.operations.lock() {
            Ok(mut state) => {
                state.prune();
                match name {
                    "desktop_policy_status" => self.policy(arguments),
                    "desktop_get_file_info" => self.file_info(arguments),
                    "desktop_list_directory" => self.list(arguments),
                    "desktop_read_file" => self.observed_read(arguments, &mut state),
                    "desktop_search" => self.search(arguments),
                    "desktop_artifact_manage" => self.manage_artifacts(arguments),
                    "desktop_create_directory" if self.create_only => self.create_dir(arguments),
                    "desktop_write_file" if self.create_only => self.observed_write(arguments, &mut state),
                    "desktop_edit_file" if self.workspace_write => self.observed_edit(arguments, &mut state),
                    "desktop_move_file" if self.workspace_write => self.observed_move(arguments, &mut state),
                    _ => Err(DesktopError::new(
                        "TOOL_NOT_IMPLEMENTED",
                        "Tool is unsupported or disabled in this file-only workspace instance",
                    )),
                }
            }
            Err(_) => Err(DesktopError::new(
                "LOCK_POISONED", "Workspace operations lock is poisoned; refusing access",
            )),
        };
        match result {
            Ok(value) => json!({"content":[{"type":"text","text":value.to_string()}]}),
            // Web responses must not reveal filesystem errors, internal paths, or
            // names that were never approved by the project-read policy.
            Err(_) if self.web_project_read => error_envelope(DesktopError::new(
                "PROJECT_READ_UNAVAILABLE", "Project read unavailable",
            )),
            Err(error) => error_envelope(error),
        }
    }

    /// JSON-string convenience entry point; no MCP or operating system runtime.
    pub fn dispatch_json(&self, name: &str, arguments_json: &str) -> String {
        let output = match serde_json::from_str::<Value>(arguments_json) {
            Ok(value) => self.dispatch(name, &value),
            Err(_) => error_envelope(DesktopError::new(
                "INVALID_JSON",
                "Arguments must be a JSON object",
            )),
        };
        output.to_string()
    }

    fn policy(&self, v: &Value) -> Result<Value> {
        object(v, &[])?;
        let tools = self
            .tool_catalog()
            .into_iter()
            .map(|spec| spec.name)
            .collect::<Vec<_>>();
        let file_access = if self.workspace_write { "workspace-write" }
            else if self.create_only { "create-only" } else { "read-only" };
        Ok(json!({
            "crate":"agent-bridge-desktop",
            "crate_version":VERSION,
            "contract_version":CONTRACT_VERSION,
            "workspace":self.workspace.to_string_lossy(),
            "profile":self.session_profile.map(|p| json!(p)).unwrap_or_else(|| json!(file_access)),
            "file_access":file_access,
            "paths":"workspace-relative only; no symlinks/reparse points",
            "tools":tools,
            "observation_capacity":64,
            "observation_ttl_seconds":300,
            "observation_scope":"this instance; consumed on use; never portable",
            "artifact_scope":"this instance; immutable checksum-verified temporary copies; never portable",
            "unsupported":if self.workspace_write {
                json!(["global_cross_process_compare_and_swap","atomic_whole_move"])
            } else {
                json!(["desktop_edit_file","desktop_move_file","existing_file_rewrite","append","artifact_publish","artifact_delete"])
            },
            "limits":{"file_bytes":MAX_FILE_BYTES,"read_lines":MAX_LINE_WINDOW,
                "listing_entries":MAX_LIST_ENTRIES,"listing_depth":MAX_LIST_DEPTH,
                "search_results":MAX_SEARCH_RESULTS,"search_depth":MAX_SEARCH_DEPTH,
                "scan_entries":MAX_SCANNED_ENTRIES,"search_bytes":MAX_SEARCH_BYTES,
                "artifact_max_count":artifacts::MAX_ARTIFACTS,
                "artifact_max_bytes":artifacts::MAX_ARTIFACT_BYTES,
                "artifact_max_total_bytes":artifacts::MAX_TOTAL_ARTIFACT_BYTES,
                "artifact_max_read_bytes":artifacts::MAX_ARTIFACT_READ_BYTES,
                "artifact_min_retention_seconds":artifacts::MIN_RETENTION_SECONDS,
                "artifact_max_retention_seconds":artifacts::MAX_RETENTION_SECONDS}
        }))
    }

    fn file_info(&self, v: &Value) -> Result<Value> {
        let a = object(v, &["path"])?;
        let path = required_string(a, "path", MAX_PATH_BYTES)?;
        let parts = relative_parts(path, true)?;
        let metadata = if parts.is_empty() {
            self.check_parts(&parts)?;
            self.root.dir_metadata()?
        } else {
            let (parent, name) = self.parent_and_name(&parts)?;
            let md = parent.symlink_metadata(&name)?;
            ensure_entry(&md)?;
            if md.is_dir() {
                if let Some(policy) = &self.protected {
                    policy.check_directory(&open_child_dir(&parent, &name)?)?;
                }
            }
            if md.is_file() {
                workspace_write::verify_regular_entry(&parent, &name)?;
            }
            md
        };
        Ok(metadata_json(&display_parts(&parts), &metadata))
    }

    fn list(&self, v: &Value) -> Result<Value> {
        let a = object(v, &["path", "depth"])?;
        let path = required_string(a, "path", MAX_PATH_BYTES)?;
        let depth = int_in(a, "depth", if self.web_project_read { 1 } else { 2 },
            1, if self.web_project_read { 1 } else { MAX_LIST_DEPTH as i64 })? as usize;
        let parts = relative_parts(path, true)?;
        let dir = self.open_dir_parts(&parts)?;
        let mut budget = WalkBudget::new(Duration::from_secs(10));
        let mut entries = Vec::new();
        walk_listing(&dir, &display_parts(&parts), 1, depth, &mut budget, &mut entries,
            self.web_project_read, self.protected.as_deref().map(|p| (p, self.workspace.as_path())))?;
        if self.web_project_read {
            // Scan counters and truncation/timing are not public evidence:
            // even enumerating a hidden directory entry can consume time.
            return Ok(json!({
                "path":display_parts(&parts),"depth":depth,"entries":entries
            }));
        }
        Ok(json!({
            "path":display_parts(&parts),"depth":depth,"entries":entries,
            "truncated":budget.truncated,"scanned":budget.scanned,
            "skipped_unsafe":budget.skipped_unsafe
        }))
    }

    fn search(&self, v: &Value) -> Result<Value> {
        let a = object(v, &[
            "path", "pattern", "search_type", "file_pattern", "ignore_case",
            "include_hidden", "literal_search", "max_results", "timeout_ms",
        ])?;
        let path = required_string(a, "path", MAX_PATH_BYTES)?;
        let pattern = required_string(a, "pattern", MAX_PATTERN_CHARS)?;
        let search_type = optional_string(a, "search_type", "files")?;
        if search_type != "files" && search_type != "content" {
            return Err(DesktopError::new("INVALID_ARGUMENT", "search_type must be files or content"));
        }
        let ignore_case = bool_in(a, "ignore_case", true)?;
        let include_hidden = bool_in(a, "include_hidden", false)?;
        let literal = bool_in(a, "literal_search", false)?;
        let maximum = int_in(a, "max_results", 50, 1, MAX_SEARCH_RESULTS as i64)? as usize;
        let timeout_ms = int_in(a, "timeout_ms", 5000, 500, MAX_SEARCH_DURATION_MS as i64)?;
        let expr = if literal { regex::escape(pattern) } else { pattern.to_owned() };
        let matcher = build_regex(&expr, ignore_case)?;
        let filename_matcher = match a.get("file_pattern") {
            None => None,
            Some(v) => {
                let name = v.as_str().ok_or_else(|| DesktopError::new(
                    "INVALID_ARGUMENT", "file_pattern must be a string"
                ))?;
                Some(build_regex(&glob_to_regex(name)?, ignore_case)?)
            }
        };
        let parts = relative_parts(path, true)?;
        let root = self.open_dir_parts(&parts)?;
        let mut budget = WalkBudget::new(Duration::from_millis(timeout_ms as u64));
        let mut queue = VecDeque::from([(root, display_parts(&parts), 0usize)]);
        let mut matches = Vec::new();

        'search: while let Some((dir, base, depth)) = queue.pop_front() {
            let protection = self.protected.as_deref().map(|p| (p, self.workspace.as_path()));
            let names = bounded_names(&dir, &mut budget, &base, self.web_project_read, protection)?;
            for name in names {
                if self.web_project_read && !web_project_child_allowed(&base, &name) {
                    continue;
                }
                if !budget.check_time() {
                    break 'search;
                }
                if !include_hidden && name.starts_with('.') {
                    continue;
                }
                let meta = dir.symlink_metadata(&name)?;
                if ensure_entry(&meta).is_err() {
                    budget.skipped_unsafe += 1;
                    continue;
                }
                let relative = join_relative(&base, &name);
                if meta.is_dir() {
                    if depth >= MAX_SEARCH_DEPTH && self.protected.is_none() {
                        budget.truncated = true;
                        continue;
                    }
                    let child = match open_child_dir(&dir, &name).and_then(|child| {
                        if let Some(policy) = &self.protected { policy.check_directory(&child)?; }
                        Ok(child)
                    }) {
                        Ok(child) => child,
                        Err(_) if self.protected.is_some() => { budget.skipped_unsafe += 1; continue; }
                        Err(error) => return Err(error),
                    };
                    if depth < MAX_SEARCH_DEPTH {
                        queue.push_back((child, relative, depth + 1));
                    } else {
                        budget.truncated = true;
                    }
                    continue;
                }
                if !meta.is_file() {
                    continue;
                }
                if workspace_write::verify_regular_entry(&dir, &name).is_err() {
                    budget.skipped_unsafe += 1;
                    continue;
                }
                let file_matches = filename_matcher
                    .as_ref()
                    .map_or(true, |glob| glob.is_match(&name));
                if !file_matches {
                    continue;
                }
                if search_type == "files" {
                    if matcher.is_match(&relative) {
                        if !push_match(&mut matches, maximum, json!({
                            "path":relative,"kind":"file","bytes":meta.len()
                        }), &mut budget) {
                            break 'search;
                        }
                    }
                    continue;
                }

                if meta.len() > MAX_FILE_BYTES as u64 {
                    budget.skipped_unsafe += 1;
                    continue;
                }
                if budget.bytes.saturating_add(meta.len() as usize) > MAX_SEARCH_BYTES {
                    budget.truncated = true;
                    break 'search;
                }
                budget.bytes += meta.len() as usize;
                let data = read_regular(&dir, &name)?;
                let Ok(text) = std::str::from_utf8(&data) else {
                    budget.skipped_unsafe += 1;
                    continue;
                };
                for (line_index, line) in text.lines().enumerate() {
                    if let Some(found) = matcher.find(line) {
                        if !push_match(&mut matches, maximum, json!({
                            "path":relative,"kind":"content","line":line_index + 1,
                            "excerpt":line.chars().take(240).collect::<String>(),
                            "match":found.as_str().chars().take(240).collect::<String>(),
                            "match_truncated":found.as_str().chars().nth(240).is_some()
                        }), &mut budget) {
                            break 'search;
                        }
                    }
                }
            }
        }
        // Keep the Rust-native response while supplying the legacy search
        // result keys used by desktop clients. All file paths stay under the
        // already pinned, operator-selected workspace.
        let mut result_bytes = 0;
        let mut results = Vec::new();
        let mut kept = 0;
        for entry in &matches {
            let relative = entry["path"].as_str().unwrap_or_default();
            let compat = if self.web_project_read {
                None
            } else {
                let file = self.workspace.join(relative).to_string_lossy().into_owned();
                Some(if search_type == "files" {
                    json!({"type":"file","file":file})
                } else {
                    json!({"type":"content","file":file,"line":entry["line"],"match":entry["match"]})
                })
            };
            // Tool content is JSON inside an MCP string. Leave room for both
            // escaping passes, the request ID, the workspace path and metadata.
            result_bytes += entry.to_string().len() + compat.as_ref().map_or(0, |v| v.to_string().len()) + 2;
            if result_bytes > 384 * 1024 {
                budget.truncated = true;
                break;
            }
            kept += 1;
            if let Some(value) = compat { results.push(value); }
        }
        matches.truncate(kept);
        if self.web_project_read {
            return Ok(json!({"path":display_parts(&parts),"search_type":search_type,
                "matches":matches,"truncated":budget.truncated}));
        }
        let result_count = results.len();
        Ok(json!({
            "path":display_parts(&parts),"search_type":search_type,
            "matches":matches,"truncated":budget.truncated,
            "scanned":budget.scanned,"bytes_scanned":budget.bytes,
            "skipped_unsafe":budget.skipped_unsafe,
            "results":results,"resultCount":result_count,
            "complete":!budget.timed_out,"timedOut":budget.timed_out
        }))
    }

    fn create_dir(&self, v: &Value) -> Result<Value> {
        let a = object(v, &["path"])?;
        let path = required_string(a, "path", MAX_PATH_BYTES)?;
        let parts = relative_parts(path, false)?;
        let (parent, name) = self.parent_and_name(&parts)?;
        #[cfg(unix)]
        let builder = {
            use cap_std::fs::DirBuilderExt;
            let mut builder = DirBuilder::new();
            builder.mode(0o700);
            builder
        };
        #[cfg(not(unix))]
        let builder = DirBuilder::new();
        parent.create_dir_with(&name, &builder)?;
        let opened = open_child_dir(&parent, &name)?;
        ensure_directory(&opened.dir_metadata()?)?;
        Ok(json!({"path":display_parts(&parts),"created":true}))
    }

    fn open_dir_parts(&self, parts: &[String]) -> Result<Dir> {
        self.check_parts(parts)?;
        let mut dir = self.root.try_clone()?;
        if let Some(policy) = &self.protected { policy.check_directory(&dir)?; }
        for component in parts {
            dir = open_child_dir(&dir, component)?;
            if let Some(policy) = &self.protected { policy.check_directory(&dir)?; }
        }
        Ok(dir)
    }

    fn check_parts(&self, parts: &[String]) -> Result<()> {
        if let Some(policy) = &self.protected {
            policy.check_relative(&self.workspace, &display_parts(parts))?;
        }
        Ok(())
    }

    fn parent_and_name(&self, parts: &[String]) -> Result<(Dir, String)> {
        self.check_parts(parts)?;
        let (name, parents) = parts
            .split_last()
            .ok_or_else(|| DesktopError::new("INVALID_PATH", "Root is not a regular file"))?;
        Ok((self.open_dir_parts(parents)?, name.clone()))
    }
}

fn spec(
    name: &'static str,
    description: &'static str,
    properties: Value,
    required: &[&str],
) -> ToolSpec {
    ToolSpec {
        name,
        description,
        input_schema: json!({
            "$schema":"https://json-schema.org/draft/2020-12/schema",
            "type":"object",
            "additionalProperties":false,
            "properties":properties,
            "required":required
        }),
    }
}

fn error_envelope(error: DesktopError) -> Value {
    json!({
        "isError":true,
        "content":[{"type":"text","text":json!({
            "code":error.code,"message":error.message
        }).to_string()}]
    })
}

fn object<'a>(value: &'a Value, allowed: &[&str]) -> Result<&'a Map<String, Value>> {
    let object = value
        .as_object()
        .ok_or_else(|| DesktopError::new("INVALID_ARGUMENT", "Arguments must be an object"))?;
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(DesktopError::new("INVALID_ARGUMENT", "Unexpected argument field"));
    }
    Ok(object)
}

fn required_string<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    maximum: usize,
) -> Result<&'a str> {
    let text = object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| DesktopError::new("INVALID_ARGUMENT", format!("{field} is required")))?;
    if text.is_empty() || text.len() > maximum {
        return Err(DesktopError::new(
            "INVALID_ARGUMENT",
            format!("{field} must be 1..={maximum} bytes"),
        ));
    }
    Ok(text)
}

fn optional_string<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    fallback: &'a str,
) -> Result<&'a str> {
    match object.get(field) {
        None => Ok(fallback),
        Some(Value::String(text)) => Ok(text),
        Some(_) => Err(DesktopError::new("INVALID_ARGUMENT",
            format!("{field} must be a string"))),
    }
}

fn int_in(
    object: &Map<String, Value>,
    field: &str,
    fallback: i64,
    minimum: i64,
    maximum: i64,
) -> Result<i64> {
    let number = match object.get(field) {
        None => fallback,
        Some(value) => value
            .as_i64()
            .ok_or_else(|| DesktopError::new("INVALID_ARGUMENT", format!("{field} must be an integer")))?,
    };
    if !(minimum..=maximum).contains(&number) {
        return Err(DesktopError::new("INVALID_ARGUMENT", format!("{field} out of range")));
    }
    Ok(number)
}

fn bool_in(object: &Map<String, Value>, field: &str, fallback: bool) -> Result<bool> {
    match object.get(field) {
        None => Ok(fallback),
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(DesktopError::new("INVALID_ARGUMENT", format!("{field} must be boolean"))),
    }
}

// This policy exists only for the authenticated Web project reader. The
// ordinary local DesktopFiles and the artifact provider retain their current
// catalogs, behavior and counters. A denied name is never stat'ed, opened,
// read, matched by regex, entered by a walker, or charged to a quota.
const WEB_PROJECT_READ_TOOLS: &[&str] = &[
    "desktop_get_file_info", "desktop_list_directory",
    "desktop_read_file", "desktop_search",
];

fn web_project_name_allowed(name: &str) -> bool {
    // ASCII-only components make Windows case-insensitivity and confusing
    // Unicode lookalikes fail closed. All tilde spellings are forbidden,
    // including DOS 8.3 aliases such as COMMAND~1.JSON and SETTIN~1.
    if !name.is_ascii() || name.starts_with('.') || name.contains('~')
        || name.ends_with(' ') || name.ends_with('.') {
        return false;
    }
    let lower = name.to_ascii_lowercase();
    if matches!(lower.as_str(),
        "commands.json" | "extensions.json" | "current.json"
        | "config.json" | "settings.json" | "local.json"
        | "oauth.json" | "oauth-workstation.json"
        | "credentials.json" | "secrets.json" | "session.json"
        | "tokens.json" | "token.json" | "enrollment.json"
        | "enrollment-workstation.json" | "running.lock"
        | "oauth-rust.lock" | "state.json" | "environment.json"
        | "id_rsa" | "id_ed25519" | "authorized_keys"
        | "known_hosts" | "web.config" | "appsettings.json"
        | "appsettings.development.json" | "appsettings.local.json"
    ) {
        return false;
    }
    if [".key", ".pem", ".p12", ".pfx", ".p8", ".jks",
        ".kdbx", ".sqlite", ".sqlite3", ".db", ".db-wal",
        ".db-shm", ".env", ".credentials", ".secret"]
        .iter().any(|suffix| lower.ends_with(suffix))
    {
        return false;
    }
    !lower.split(|c: char| !c.is_ascii_alphanumeric())
        .any(|token| matches!(token,
            "secret" | "secrets" | "private" | "credentials"
            | "credential" | "password" | "passwords"
            | "token" | "tokens" | "vault" | "vaults"
            | "keys" | "keyring" | "settings" | "lifecycle"
            | "session" | "sessions" | "enrollment" | "state"
            | "certificates" | "certs" | "ssh"))
}

fn web_project_path_allowed(parts: &[String]) -> bool {
    parts.iter().all(|part| web_project_name_allowed(part))
}
fn web_project_child_allowed(base: &str, child: &str) -> bool {
    // 'base' has already passed the same policy before directory opening.
    (base == "." || base.split('/').all(web_project_name_allowed))
        && web_project_name_allowed(child)
}
fn web_project_request_allowed(tool: &str, args: &Value) -> bool {
    if !WEB_PROJECT_READ_TOOLS.contains(&tool) { return false; }
    let Some(args) = args.as_object() else { return false; };
    let Some(path) = args.get("path").and_then(Value::as_str) else { return false; };
    let Ok(parts) = relative_parts(path, true) else { return false; };
    if !web_project_path_allowed(&parts) { return false; }
    match tool {
        "desktop_list_directory" =>
            args.get("depth").is_none_or(|v| v.as_i64() == Some(1)),
        "desktop_search" =>
            args.get("include_hidden").is_none_or(|v| v.as_bool() == Some(false))
                && args.get("search_type").is_none_or(|v| v.as_str() == Some("files")),
        "desktop_get_file_info" | "desktop_read_file" => true,
        _ => false,
    }
}

fn validate_segment(segment: &str) -> Result<()> {
    let invalid = segment.is_empty()
        || segment == "."
        || segment == ".."
        || segment.starts_with(TEMP_PREFIX)
        || segment.len() > 255
        || segment.ends_with(' ')
        || segment.ends_with('.')
        || segment.contains(':')
        || segment.contains('\\')
        || segment.contains('/')
        || segment.chars().any(|c| c.is_control());
    let first = segment.split('.').next().unwrap_or("").to_ascii_uppercase();
    let reserved_device = matches!(first.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$")
        || (first.len() == 4
            && (first.starts_with("COM") || first.starts_with("LPT"))
            && first.as_bytes()[3].is_ascii_digit()
            && first.as_bytes()[3] != b'0');
    if invalid || reserved_device {
        return Err(DesktopError::new("INVALID_PATH",
            "Unsafe, nonportable, reserved or empty path component"));
    }
    Ok(())
}

fn relative_parts(raw: &str, allow_root: bool) -> Result<Vec<String>> {
    if raw.is_empty() || raw.len() > MAX_PATH_BYTES || raw.contains('\\') || raw.contains('\0') {
        return Err(DesktopError::new("INVALID_PATH", "Invalid or oversized path"));
    }
    if raw == "." && allow_root {
        return Ok(Vec::new());
    }
    if Path::new(raw).is_absolute() || raw.starts_with('/') || raw.starts_with("//") {
        return Err(DesktopError::new("INVALID_PATH", "Absolute path is refused"));
    }
    let mut result = Vec::new();
    for component in raw.split('/') {
        validate_segment(component)?;
        result.push(component.to_owned());
    }
    if result.is_empty() && !allow_root {
        return Err(DesktopError::new("INVALID_PATH", "Root is not a file target"));
    }
    Ok(result)
}

fn open_workspace(path: &Path) -> Result<Dir> {
    open_filesystem_root(path, false)
}

fn open_filesystem_root(path: &Path, allow_volume: bool) -> Result<Dir> {
    // Open the platform root once using ambient authority, then step to the
    // operator-selected workspace ONLY via no-follow directory capabilities.
    // Even a replacement between metadata check and open cannot follow a link.
    if !path.is_absolute() {
        return Err(DesktopError::new("ABSOLUTE_WORKSPACE_REQUIRED",
            "Operator workspace must be an existing absolute directory"));
    }
    let mut platform_root = PathBuf::new();
    let mut segments: Vec<OsString> = Vec::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => {
                #[cfg(windows)]
                if !matches!(prefix.kind(), std::path::Prefix::Disk(_)) {
                    return Err(DesktopError::new("UNSAFE_WORKSPACE",
                        "Only ordinary local drive roots are allowed on Windows"));
                }
                platform_root.push(prefix.as_os_str());
            }
            Component::RootDir => platform_root.push(component.as_os_str()),
            Component::Normal(name) => {
                let text = name.to_str().ok_or_else(|| DesktopError::new(
                    "INVALID_PATH", "Workspace path must be valid UTF-8"))?;
                validate_segment(text)?;
                segments.push(name.to_os_string());
            }
            Component::CurDir | Component::ParentDir => return Err(DesktopError::new(
                "INVALID_PATH", "Workspace path must not use dot or parent components")),
        }
    }
    if (!allow_volume && segments.is_empty()) || !platform_root.is_absolute() {
        return Err(DesktopError::new("UNSAFE_WORKSPACE",
            "Filesystem volume root cannot be the workspace"));
    }
    let mut current = Dir::open_ambient_dir(&platform_root, ambient_authority())?;
    for name in segments {
        let md = current.symlink_metadata(&name)?;
        ensure_directory(&md)?;
        current = current.open_dir_nofollow(&name)?;
        ensure_directory(&current.dir_metadata()?)?;
    }
    Ok(current)
}

#[cfg(windows)]
fn is_reparse(metadata: &Metadata) -> bool {
    use cap_std::fs::MetadataExt;
    metadata.file_attributes() & 0x0000_0400 != 0
}

#[cfg(not(windows))]
fn is_reparse(_metadata: &Metadata) -> bool {
    false
}

fn ensure_directory(metadata: &Metadata) -> Result<()> {
    if metadata.is_dir() && !metadata.is_symlink() && !is_reparse(metadata) {
        Ok(())
    } else {
        Err(DesktopError::new("UNSAFE_DIRECTORY",
            "A directory component is linked, reparse, or not a directory"))
    }
}

fn ensure_regular(metadata: &Metadata) -> Result<()> {
    if !metadata.is_file() || metadata.is_symlink() || is_reparse(metadata) {
        return Err(DesktopError::new("UNSAFE_FILE",
            "File is linked, reparse, or not regular"));
    }
    #[cfg(unix)]
    {
        use cap_std::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err(DesktopError::new("UNSAFE_HARD_LINK",
                "Hard-linked files are not accessible"));
        }
    }
    Ok(())
}

fn ensure_entry(metadata: &Metadata) -> Result<()> {
    if metadata.is_dir() {
        ensure_directory(metadata)
    } else {
        ensure_regular(metadata)
    }
}

fn open_child_dir(parent: &Dir, name: &str) -> Result<Dir> {
    validate_segment(name)?;
    ensure_directory(&parent.symlink_metadata(name)?)?;
    let child = parent.open_dir_nofollow(name)?;
    ensure_directory(&child.dir_metadata()?)?;
    Ok(child)
}

fn same_file(before: &Metadata, after: &Metadata) -> bool {
    if before.len() != after.len() || before.modified().ok() != after.modified().ok() {
        return false;
    }
    #[cfg(unix)]
    {
        use cap_std::fs::MetadataExt;
        return before.dev() == after.dev() && before.ino() == after.ino();
    }
    #[cfg(windows)]
    {
        use cap_std::fs::MetadataExt;
        return before.creation_time() == after.creation_time()
            && before.file_attributes() == after.file_attributes();
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

fn read_regular(parent: &Dir, name: &str) -> Result<Vec<u8>> {
    workspace_write::verified_contents(parent, name)
}

fn hex_hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn display_parts(parts: &[String]) -> String {
    if parts.is_empty() {
        ".".to_owned()
    } else {
        parts.join("/")
    }
}

fn join_relative(base: &str, child: &str) -> String {
    if base == "." {
        child.to_owned()
    } else {
        format!("{base}/{child}")
    }
}

fn metadata_json(path: &str, metadata: &Metadata) -> Value {
    let modified_ms = metadata.modified().ok()
        .and_then(|time| time.into_std().duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_millis() as u64);
    json!({
        "path":path,
        "kind":if metadata.is_dir() {"directory"} else {"file"},
        "bytes":if metadata.is_file() {Some(metadata.len())} else {None},
        "modified_unix_ms":modified_ms,
        "read_only":metadata.permissions().readonly()
    })
}

struct WalkBudget {
    deadline: Instant,
    scanned: usize,
    bytes: usize,
    skipped_unsafe: usize,
    truncated: bool,
    timed_out: bool,
}

impl WalkBudget {
    fn new(duration: Duration) -> Self {
        Self {
            deadline: Instant::now() + duration,
            scanned: 0,
            bytes: 0,
            skipped_unsafe: 0,
            truncated: false,
            timed_out: false,
        }
    }

    fn charge_entry(&mut self) -> bool {
        if self.scanned >= MAX_SCANNED_ENTRIES || !self.check_time() {
            self.truncated = true;
            return false;
        }
        self.scanned += 1;
        true
    }

    fn check_time(&mut self) -> bool {
        if Instant::now() >= self.deadline {
            self.truncated = true;
            self.timed_out = true;
            false
        } else {
            true
        }
    }
}

fn bounded_names(
    dir: &Dir, budget: &mut WalkBudget, base: &str, web_read: bool,
    protection: Option<(&path_policy::ProtectedPaths, &Path)>,
) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in dir.entries()? {
        if web_read {
            if Instant::now() >= budget.deadline {
                return Err(DesktopError::new("READ_LIMIT", "Project read unavailable"));
            }
        } else if !budget.charge_entry() {
            break;
        }
        let item = entry?;
        let os_name = item.file_name();
        let Some(name) = os_name.to_str() else {
            if !web_read { budget.skipped_unsafe += 1; }
            continue;
        };
        if web_read && !web_project_child_allowed(base, name) {
            continue;
        }
        if protection.is_some_and(|(policy, root)| policy.check_relative(root, &join_relative(base, name)).is_err()) {
            continue;
        }
        if validate_segment(name).is_err() {
            if !web_read { budget.skipped_unsafe += 1; }
            continue;
        }
        if web_read && !budget.charge_entry() {
            break;
        }
        names.push(name.to_owned());
    }
    names.sort_unstable();
    Ok(names)
}

fn walk_listing(
    directory: &Dir,
    base: &str,
    depth: usize,
    maximum_depth: usize,
    budget: &mut WalkBudget,
    result: &mut Vec<Value>,
    web_read: bool,
    protection: Option<(&path_policy::ProtectedPaths, &Path)>,
) -> Result<()> {
    let names = bounded_names(directory, budget, base, web_read, protection)?;
    for name in names {
        if web_read && !web_project_child_allowed(base, &name) {
            continue;
        }
        if !budget.check_time() {
            return Ok(());
        }
        let metadata = directory.symlink_metadata(&name)?;
        if ensure_entry(&metadata).is_err() {
            budget.skipped_unsafe += 1;
            continue;
        }
        if metadata.is_file() &&
            workspace_write::verify_regular_entry(directory, &name).is_err()
        {
            budget.skipped_unsafe += 1;
            continue;
        }
        let opened = if metadata.is_dir() && (protection.is_some() || depth < maximum_depth) {
            match open_child_dir(directory, &name).and_then(|child| {
                if let Some((policy, _)) = protection { policy.check_directory(&child)?; }
                Ok(child)
            }) {
                Ok(child) => Some(child),
                Err(_) if protection.is_some() => { budget.skipped_unsafe += 1; continue; }
                Err(error) => return Err(error),
            }
        } else { None };
        if result.len() >= MAX_LIST_ENTRIES {
            budget.truncated = true;
            return Ok(());
        }
        let rel = join_relative(base, &name);
        result.push(metadata_json(&rel, &metadata));
        if metadata.is_dir() && depth < maximum_depth {
            let opened = opened.ok_or_else(|| DesktopError::new("DIRECTORY_UNAVAILABLE", "Directory capability unavailable"))?;
            walk_listing(&opened, &rel, depth + 1, maximum_depth, budget, result, web_read, protection)?;
            if budget.truncated {
                return Ok(());
            }
        }
    }
    Ok(())
}

fn push_match(
    out: &mut Vec<Value>,
    max: usize,
    entry: Value,
    budget: &mut WalkBudget,
) -> bool {
    if out.len() >= max {
        budget.truncated = true;
        false
    } else {
        out.push(entry);
        true
    }
}

fn build_regex(pattern: &str, ignore_case: bool) -> Result<Regex> {
    RegexBuilder::new(pattern)
        .case_insensitive(ignore_case)
        .size_limit(1 << 20)
        .dfa_size_limit(1 << 20)
        .build()
        .map_err(|_| DesktopError::new(
            "INVALID_PATTERN", "Pattern invalid or exceeds regex complexity budget"))
}

fn glob_to_regex(pattern: &str) -> Result<String> {
    if pattern.is_empty() || pattern.len() > 256
        || pattern.contains('/') || pattern.contains('\\') || pattern.contains('\0')
    {
        return Err(DesktopError::new("INVALID_PATTERN",
            "file_pattern must be a bounded basename glob"));
    }
    let mut out = String::from("^");
    for character in pattern.chars() {
        match character {
            '*' => out.push_str(".*"),
            '?' => out.push('.'),
            c => out.push_str(&regex::escape(&c.to_string())),
        }
    }
    out.push('$');
    Ok(out)
}
