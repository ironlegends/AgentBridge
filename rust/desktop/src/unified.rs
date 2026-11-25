//! Locally selected file authority for the complete workstation capability.
use super::*;
use path_policy::{contains_path, normalize_absolute, volume_and_relative, PinnedDirectory, ProtectedPaths};
use std::collections::HashMap;
use std::sync::{Arc, RwLock, RwLockReadGuard};
use unified_artifacts::StreamStore;
use unified_transfer::Source;

#[cfg(test)]
#[path = "unified_tests.rs"]
mod boundary_tests;

#[derive(Clone, Debug)]
pub enum FileScope { Workspace, AllowedRoots(Vec<PathBuf>), OsUser }

#[derive(Clone, Debug)]
pub struct UnifiedFileConfig {
    pub workspace: PathBuf,
    pub scope: FileScope,
    pub protected_roots: Vec<PathBuf>,
    pub private_root: PathBuf,
}

pub struct UnifiedFiles {
    workspace: PinnedDirectory,
    selected: Vec<PinnedDirectory>,
    scope: FileScope,
    protected: Arc<ProtectedPaths>,
    template: DesktopFiles,
    authorities: Mutex<HashMap<PathBuf, Arc<DesktopFiles>>>,
    file_operations: Mutex<()>,
    private: PinnedDirectory,
    artifacts: Mutex<Option<StreamStore>>,
    admission: RwLock<bool>,
    pending_uploads: Mutex<Vec<UploadCleanup>>,
}

struct ResolvedPath { path: PathBuf, relative: String, files: Arc<DesktopFiles> }

struct UploadCleanup { parent: Dir, directory: Dir, directory_name: String, file_name: String }
impl UploadCleanup {
    fn cleanup(&self) -> Result<()> {
        match self.directory.remove_file(&self.file_name) {
            Ok(()) => {},
            Err(error) if error.kind() == io::ErrorKind::NotFound => {},
            Err(error) => return Err(error.into()),
        }
        match self.parent.remove_dir(&self.directory_name) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

impl UnifiedFiles {
    pub fn open(mut config: UnifiedFileConfig) -> Result<Self> {
        config.protected_roots.push(config.private_root.clone());
        let protected = Arc::new(ProtectedPaths::open(&config.protected_roots)?);
        let workspace = PinnedDirectory::open(&config.workspace)?;
        protected.check_absolute(&workspace.path)?;
        protected.check_directory(&workspace.directory)?;
        let mut selected = Vec::new();
        if let FileScope::AllowedRoots(roots) = &config.scope {
            if roots.is_empty() || roots.len() > 32 {
                return Err(DesktopError::new("INVALID_FILE_POLICY", "Select 1..32 additional roots"));
            }
            for path in roots {
                let root = PinnedDirectory::open(path)?;
                protected.check_absolute(&root.path)?;
                protected.check_directory(&root.directory)?;
                selected.push(root);
            }
        }
        let mut template = DesktopFiles::from_qualified_root(DesktopConfig::new(&workspace.path)
            .with_session_profile(DesktopProfile::FullyUnlocked).allow_workspace_write(), workspace.directory.try_clone()?);
        template.protected = Some(Arc::clone(&protected));
        let private = PinnedDirectory::open(&config.private_root)?;
        unified_transfer::verify_private_directory(&private.directory)?;
        let store = StreamStore::open(&private.directory)?;
        Ok(Self { workspace, selected, scope: config.scope, protected, template,
            authorities: Mutex::new(HashMap::new()), file_operations:Mutex::new(()), private, artifacts:Mutex::new(Some(store)),
            admission:RwLock::new(true), pending_uploads:Mutex::new(Vec::new()) })
    }

    pub fn tool_catalog(&self) -> Vec<ToolSpec> {
        let mut catalog = self.template.tool_catalog();
        for tool in &mut catalog {
            if tool.name == "desktop_artifact_manage" {
                tool.description = "Publish an authorized local file up to 64MiB into a private temporary artifact; list, inspect, read verified chunks up to 256KiB, or delete. This instance permits at most 64 artifacts and 256MiB total. Private application sources remain excluded.";
            }
            for key in ["path", "source", "destination"] {
                if let Some(value) = tool.input_schema["properties"].get_mut(key) {
                    value["description"] = json!("Workspace-relative or explicitly permitted absolute local path; private application paths remain excluded");
                }
            }
        }
        catalog
    }

    pub fn dispatch(&self, profile: DesktopProfile, name: &str, args: &Value) -> Value {
        match self.open_guard().and_then(|_guard| {
            let _operation = self.file_operations.lock()
                .map_err(|_| DesktopError::new("LOCK_POISONED", "File operations unavailable"))?;
            self.dispatch_inner(profile, name, args)
        }) {
            Ok(value) => value,
            Err(error) => error_envelope(error),
        }
    }

    pub fn stage_uploads(&self, profile: DesktopProfile, paths: &[String], session_dir: &Path) -> Result<Vec<PathBuf>> {
        let _guard = self.open_guard()?;
        if !matches!(profile, DesktopProfile::FullControl | DesktopProfile::FullyUnlocked) {
            return Err(DesktopError::new("PROFILE_REQUIRED", "Browser uploads require Full Control or Fully Unlocked"));
        }
        if paths.is_empty() || paths.len() > 10 {
            return Err(DesktopError::new("INVALID_ARGUMENT", "Select 1..10 upload files"));
        }
        self.reconcile_uploads()?;
        let (session, session_path) = self.private_directory(session_dir)?;
        let session_id = workspace_write::dir_identity(&session)?;
        let mut sources = Vec::new();
        let mut total = 0usize;
        for raw in paths {
            let (source, path) = self.authorized_source(profile, raw)?;
            total = total.checked_add(source.len()).filter(|bytes| *bytes <= unified_artifacts::MAX_TOTAL_BYTES)
                .ok_or_else(|| DesktopError::new("TRANSFER_TOO_LARGE", "An upload batch is limited to256MiB"))?;
            let name = path.file_name().and_then(|name| name.to_str())
                .ok_or_else(|| DesktopError::new("INVALID_PATH", "Upload requires a regular filename"))?.to_owned();
            sources.push((source, name));
        }
        let mut staged = Vec::new();
        let mut cleanup = Vec::new();
        let copied = (|| -> Result<()> {
            for (mut source, name) in sources {
                let directory_name = format!("upload_{}", Uuid::new_v4().simple());
                let directory = unified_transfer::private_child_directory(&session, &directory_name)?;
                cleanup.push(UploadCleanup { parent:session.try_clone()?, directory:directory.try_clone()?,
                    directory_name:directory_name.clone(), file_name:name.clone() });
                let mut file = directory.open_with(&name, &unified_transfer::private_file_options())?;
                unified_transfer::verify_private_file(&file)?;
                source.copy_to(&mut file)?;
                drop(file);
                staged.push(session_path.join(directory_name).join(name));
            }
            let (current, _) = self.private_directory(&session_path)?;
            if workspace_write::dir_identity(&current)? != session_id {
                return Err(DesktopError::new("ROOT_IDENTITY_CHANGED", "Owned browser staging directory changed"));
            }
            Ok(())
        })();
        if let Err(error) = copied {
            self.pending_uploads.lock().map_err(|_| DesktopError::new("LOCK_POISONED", "Upload cleanup registry unavailable"))?.extend(cleanup);
            self.reconcile_uploads()?;
            return Err(error);
        }
        // The browser provider now owns the staging paths and removes its
        // complete private session tree after the worker has stopped.
        Ok(staged)
    }

    pub fn publish_download(&self, profile: DesktopProfile, private_file: &Path, suggested_name: &str) -> Result<Value> {
        let _guard = self.open_guard()?;
        if !matches!(profile, DesktopProfile::FullControl | DesktopProfile::FullyUnlocked) {
            return Err(DesktopError::new("PROFILE_REQUIRED", "Browser downloads require Full Control or Fully Unlocked"));
        }
        if suggested_name.is_empty() || suggested_name.len() > 256 || suggested_name.chars().any(|ch| ch.is_control() || matches!(ch, '/' | '\\')) {
            return Err(DesktopError::new("INVALID_ARGUMENT", "Download label must be a plain filename"));
        }
        let path = normalize_absolute(private_file)?;
        let parent = path.parent().ok_or_else(|| DesktopError::new("INVALID_PATH", "Download has no parent"))?;
        let directory = if parent == self.private.path {
            self.private.verify()?;
            unified_transfer::verify_private_directory(&self.private.directory)?;
            self.private.directory.try_clone()?
        } else { self.private_directory(parent)?.0 };
        if !contains_path(&self.private.path, &path) {
            return Err(DesktopError::new("PRIVATE_TRANSFER_SCOPE", "Download is outside the owned private state"));
        }
        let name = path.file_name().and_then(|name| name.to_str()).ok_or_else(|| DesktopError::new("INVALID_PATH", "Download has no filename"))?;
        let source = Source::open(directory, name.to_owned())?;
        let artifact = self.with_store(|store| store.insert(source, format!("browser-download:{suggested_name}"), artifacts::DEFAULT_RETENTION_SECONDS as u64))?;
        Ok(json!({"action":"publish","artifact":artifact}))
    }

    pub fn shutdown(&self) -> Result<()> {
        let mut admission = self.admission.write().map_err(|_| DesktopError::new("LOCK_POISONED", "File admission unavailable"))?;
        *admission = false;
        self.reconcile_uploads()?;
        let mut store = self.artifacts.lock().map_err(|_| DesktopError::new("LOCK_POISONED", "Artifact owner unavailable"))?;
        if let Some(store) = store.as_mut() { store.clear()?; }
        *store = None;
        Ok(())
    }

    fn open_guard(&self) -> Result<RwLockReadGuard<'_, bool>> {
        let guard = self.admission.read().map_err(|_| DesktopError::new("LOCK_POISONED", "File admission unavailable"))?;
        if !*guard { return Err(DesktopError::new("PROVIDER_CLOSED", "File provider has been shut down")); }
        Ok(guard)
    }

    fn with_store<T>(&self, operation: impl FnOnce(&mut StreamStore) -> Result<T>) -> Result<T> {
        let mut store = self.artifacts.lock().map_err(|_| DesktopError::new("LOCK_POISONED", "Artifact owner unavailable"))?;
        operation(store.as_mut().ok_or_else(|| DesktopError::new("PROVIDER_CLOSED", "Artifact provider has been shut down"))?)
    }

    fn reconcile_uploads(&self) -> Result<()> {
        let mut pending = self.pending_uploads.lock().map_err(|_| DesktopError::new("LOCK_POISONED", "Upload cleanup registry unavailable"))?;
        pending.retain(|item| item.cleanup().is_err());
        if pending.is_empty() { Ok(()) } else {
            Err(DesktopError::new("UPLOAD_CLEANUP_PENDING", "Private upload cleanup must complete before another batch"))
        }
    }

    fn private_directory(&self, path: &Path) -> Result<(Dir, PathBuf)> {
        let path = normalize_absolute(path)?;
        if !contains_path(&self.private.path, &path) || path.components().count() <= self.private.path.components().count() {
            return Err(DesktopError::new("PRIVATE_TRANSFER_SCOPE", "Session directory must be below the owned private root"));
        }
        if self.private.relative_authorized_path(&path)?.is_none() {
            return Err(DesktopError::new("PRIVATE_TRANSFER_SCOPE", "Private staging selection differs from its owned root"));
        }
        let mut directory = self.private.directory.try_clone()?;
        unified_transfer::verify_private_directory(&directory)?;
        for component in path.components().skip(self.private.path.components().count()) {
            let name = component.as_os_str().to_str().ok_or_else(|| DesktopError::new("INVALID_PATH", "Private path must be UTF-8"))?;
            directory = open_child_dir(&directory, name)?;
            unified_transfer::verify_private_directory(&directory)?;
        }
        Ok((directory, path))
    }

    fn authorized_source(&self, profile: DesktopProfile, raw: &str) -> Result<(Source, PathBuf)> {
        let resolved = self.resolve(profile, raw)?;
        #[cfg(test)] boundary_tests::after_resolve();
        let parts = relative_parts(&resolved.relative, false)?;
        let (parent, name) = resolved.files.parent_and_name(&parts)?;
        Ok((Source::open(parent, name)?, resolved.path))
    }

    fn dispatch_inner(&self, profile: DesktopProfile, name: &str, args: &Value) -> Result<Value> {
        if !self.tool_catalog().iter().any(|tool| tool.name == name) {
            return Err(DesktopError::new("TOOL_NOT_IMPLEMENTED", "Unknown desktop file tool"));
        }
        let mut arguments = args.as_object().ok_or_else(|| DesktopError::new("INVALID_ARGUMENT", "Arguments must be an object"))?.clone();
        let mutation = matches!(name, "desktop_write_file" | "desktop_edit_file" | "desktop_move_file" | "desktop_create_directory")
            || (name == "desktop_artifact_manage" && matches!(arguments.get("action").and_then(Value::as_str), Some("publish" | "delete")));
        if mutation && profile == DesktopProfile::ReadOnly {
            return Err(DesktopError::new("READ_ONLY", "The current profile does not permit file or artifact changes"));
        }
        if name == "desktop_policy_status" {
            object(args, &[])?;
            let mut policy = self.template.policy(args)?;
            policy["profile"] = json!(profile);
            policy["file_access"] = json!(if profile == DesktopProfile::ReadOnly { "read-only" } else { "authorized-write" });
            policy["paths"] = json!("Authorized local paths; physical directories, no symlinks/reparse points, private state excluded");
            policy["filesystem_scope"] = json!(match (&self.scope, profile) {
                (FileScope::OsUser, DesktopProfile::FullyUnlocked) => "os-user",
                (FileScope::AllowedRoots(_), _) => "allowed-roots",
                _ => "workspace",
            });
            policy["observation_guards"] = json!(true);
            policy["private_state_excluded"] = json!(true);
            policy["limits"]["artifact_max_bytes"] = json!(unified_artifacts::transfer_limit());
            policy["limits"]["artifact_total_bytes"] = json!(unified_artifacts::MAX_TOTAL_BYTES);
            policy["limits"]["artifact_max_total_bytes"] = json!(unified_artifacts::MAX_TOTAL_BYTES);
            return Ok(json!({"content":[{"type":"text","text":policy.to_string()}]}));
        }
        if name == "desktop_artifact_manage" {
            let value = if arguments.get("action").and_then(Value::as_str) == Some("publish") {
                let a = object(args, &["action", "path", "retention_seconds"])?;
                let raw = required_string(a, "path", MAX_PATH_BYTES)?;
                let retention = unified_artifacts::retention(a)?;
                let (source, path) = self.authorized_source(profile, raw)?;
                let artifact = self.with_store(|store| store.insert(source, path.to_string_lossy().into_owned(), retention))?;
                json!({"action":"publish","artifact":artifact})
            } else { self.with_store(|store| store.dispatch(args))? };
            return Ok(json!({"content":[{"type":"text","text":value.to_string()}]}));
        }
        if name == "desktop_move_file" {
            let source = self.resolve(profile, required_string(&arguments, "source", MAX_PATH_BYTES)?)?;
            #[cfg(test)] boundary_tests::after_resolve();
            let destination = self.resolve(profile, required_string(&arguments, "destination", MAX_PATH_BYTES)?)?;
            #[cfg(test)] boundary_tests::after_resolve();
            if !workspace_write::same_volume(&source.files.root, &destination.files.root)? {
                return Err(DesktopError::new("CROSS_VOLUME_MOVE", "Cross-volume moves require a separately verified copy and removal"));
            }
            arguments.insert("source".into(), json!(source.relative));
            arguments.insert("destination".into(), json!(destination.relative));
            let mut observations = source.files.operations.lock()
                .map_err(|_| DesktopError::new("LOCK_POISONED", "File observations unavailable"))?;
            let mut value = source.files.observed_move_to(&destination.files, &Value::Object(arguments), &mut observations)?;
            value["source"] = json!(source.path);
            value["destination"] = json!(destination.path);
            return Ok(json!({"content":[{"type":"text","text":value.to_string()}]}));
        }
        let resolved = self.resolve(profile, required_string(&arguments, "path", MAX_PATH_BYTES)?)?;
        #[cfg(test)] boundary_tests::after_resolve();
        arguments.insert("path".into(), json!(resolved.relative));
        let output = resolved.files.dispatch(name, &Value::Object(arguments));
        Ok(absolute_result_paths(output, &resolved.files.workspace))
    }

    fn resolve(&self, profile: DesktopProfile, raw: &str) -> Result<ResolvedPath> {
        let input = Path::new(raw);
        let path = if input.is_absolute() { normalize_absolute(input)? } else {
            let parts = relative_parts(raw, true)?;
            let mut path = self.workspace.path.clone();
            for part in parts { path.push(part); }
            normalize_absolute(&path)?
        };
        self.protected.check_absolute(&path)?;
        if let Some(relative) = self.workspace.relative_authorized_path(&path)? {
            return Ok(ResolvedPath { path, relative, files:self.files_for_pinned(&self.workspace)? });
        }
        match &self.scope {
            FileScope::OsUser if profile == DesktopProfile::FullyUnlocked => {
                let (volume, relative) = volume_and_relative(&path)?;
                Ok(ResolvedPath { path, relative, files:self.files_for_volume(&volume)? })
            }
            FileScope::AllowedRoots(_) => {
                for root in &self.selected {
                    if let Some(relative) = root.relative_authorized_path(&path)? {
                        return Ok(ResolvedPath { path, relative, files:self.files_for_pinned(root)? });
                    }
                }
                Err(DesktopError::new("PATH_OUTSIDE_SCOPE", "Path is outside the locally selected roots"))
            }
            _ => Err(DesktopError::new("PATH_OUTSIDE_SCOPE", "This profile permits only the selected workspace")),
        }
    }

    fn files_for_pinned(&self, root: &PinnedDirectory) -> Result<Arc<DesktopFiles>> {
        // The selected handle is the authority. A successful path recheck never
        // permits reopening the operation from a volume or an ambient name.
        self.files_for_directory(&root.path, root.directory.try_clone()?)
    }

    fn files_for_volume(&self, volume: &Path) -> Result<Arc<DesktopFiles>> {
        self.files_for_directory(volume, open_filesystem_root(volume, true)?)
    }

    fn files_for_directory(&self, path: &Path, directory: Dir) -> Result<Arc<DesktopFiles>> {
        self.protected.check_directory(&directory)?;
        let mut authorities = self.authorities.lock().map_err(|_| DesktopError::new("LOCK_POISONED", "File capability registry unavailable"))?;
        if let Some(files) = authorities.get(path) {
            if workspace_write::dir_identity(&directory)? != workspace_write::dir_identity(&files.root)? {
                return Err(DesktopError::new("ROOT_IDENTITY_CHANGED", "Filesystem volume changed"));
            }
            return Ok(Arc::clone(files));
        }
        if authorities.len() >= 64 { return Err(DesktopError::new("FILE_ROOT_LIMIT", "Too many filesystem authorities")); }
        let config = DesktopConfig::new(path).with_session_profile(DesktopProfile::FullyUnlocked).allow_workspace_write();
        let mut files = DesktopFiles::from_qualified_root(config, directory);
        files.protected = Some(Arc::clone(&self.protected));
        let files = Arc::new(files);
        authorities.insert(path.to_owned(), Arc::clone(&files));
        Ok(files)
    }
}

fn absolute_result_paths(mut envelope: Value, volume: &Path) -> Value {
    if envelope.get("isError").and_then(Value::as_bool) == Some(true) { return envelope; }
    let Some(text) = envelope["content"][0]["text"].as_str() else { return envelope; };
    let Ok(mut business) = serde_json::from_str::<Value>(text) else { return envelope; };
    fn visit(value: &mut Value, root: &Path) {
        match value {
            Value::Array(items) => { for item in items { visit(item, root); } }
            Value::Object(fields) => { for (key, value) in fields {
                if matches!(key.as_str(), "path" | "source" | "destination" | "source_path" | "file") {
                    if let Some(path) = value.as_str() {
                        if !Path::new(path).is_absolute() {
                            *value = json!(if path == "." { root.to_owned() } else { root.join(path) });
                        }
                    }
                } else { visit(value, root); }
            } }
            _ => {}
        }
    }
    visit(&mut business, volume);
    envelope["content"][0]["text"] = json!(business.to_string());
    envelope
}
