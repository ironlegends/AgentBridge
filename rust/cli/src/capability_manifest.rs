//! Immutable local selection for the complete native capability.
use crate::runtime::RuntimeError;
use agent_bridge_gateway::ToolDefinition;
use agent_bridge_oauth_server::CapabilityIdentity;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BundleSelection {
    pub bundle_root: PathBuf,
    pub manifest_sha256: String,
    pub state_root: PathBuf,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DesktopBinding {
    pub desktop_id: String,
    pub desktop_number: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DesktopSelection {
    pub bundle_root: PathBuf,
    pub manifest_sha256: String,
    pub state_root: PathBuf,
    pub desktops: Vec<DesktopBinding>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag="kind", rename_all="kebab-case", deny_unknown_fields)]
pub(crate) enum FileScopeSelection {
    Workspace {},
    AllowedRoots { roots: Vec<PathBuf> },
    OsUser {},
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UnifiedSelection {
    pub version: u32,
    pub policy_version: u32,
    pub catalogue_sha256: String,
    pub private_root: PathBuf,
    pub file_scope: FileScopeSelection,
    pub allow_import: bool,
    pub browser: BundleSelection,
    pub windows: BundleSelection,
    pub agent_desktop: DesktopSelection,
}

fn strict_hash(hash: &str) -> bool {
    hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn desktop_guid(guid: &str) -> bool {
    guid.len() == 36 && guid.bytes().enumerate().all(|(index, byte)|
        if [8,13,18,23].contains(&index) { byte == b'-' }
        else { byte.is_ascii_hexdigit() })
}
pub(crate) fn decode_selection(bytes: &[u8]) -> Result<UnifiedSelection, RuntimeError> {
    if bytes.len() > 128 * 1024 { return Err("Unified selection exceeds its private setting limit".into()); }
    let selected: UnifiedSelection = serde_json::from_slice(bytes)?;
    if selected.version != 1 || selected.policy_version != 1
        || !strict_hash(&selected.catalogue_sha256)
        || !strict_hash(&selected.browser.manifest_sha256)
        || !strict_hash(&selected.windows.manifest_sha256)
        || !strict_hash(&selected.agent_desktop.manifest_sha256)
    { return Err("Unsupported unified version or malformed resource/catalogue digest".into()); }
    if let FileScopeSelection::AllowedRoots { roots } = &selected.file_scope {
        if roots.is_empty() || roots.len() > 32 {
            return Err("Unified allowed-roots must select 1..32 physical directories".into());
        }
    }
    let mut ids = std::collections::BTreeSet::new();
    let mut numbers = std::collections::BTreeSet::new();
    if selected.agent_desktop.desktops.len() > 16 { return Err("Too many selected Agent Desktops".into()); }
    for desktop in &selected.agent_desktop.desktops {
        if desktop.desktop_number < 2 || !desktop_guid(&desktop.desktop_id)
            || !ids.insert(desktop.desktop_id.to_ascii_lowercase())
            || !numbers.insert(desktop.desktop_number)
        { return Err("Agent Desktop bindings must be unique real GUIDs outside desktop 1".into()); }
    }
    Ok(selected)
}
fn canonical_value(value: &Value) -> Value {
    match value {
        Value::Object(fields) => {
            let sorted: std::collections::BTreeMap<_, _> = fields.iter()
                .map(|(key, value)| (key.clone(), canonical_value(value))).collect();
            Value::Object(sorted.into_iter().collect())
        }
        Value::Array(values) => Value::Array(values.iter().map(canonical_value).collect()),
        other => other.clone(),
    }
}
pub(crate) fn canonical_digest(value: &Value) -> Result<String, RuntimeError> {
    use sha2::{Digest, Sha256};
    let bytes = serde_json::to_vec(&canonical_value(value))?;
    Ok(Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect())
}
pub(crate) fn catalogue_digest(catalogue: &[ToolDefinition]) -> Result<String, RuntimeError> {
    if catalogue.is_empty() || catalogue.len() > 96 {
        return Err("Empty or unbounded executable unified catalogue".into());
    }
    let mut sorted: Vec<_> = catalogue.iter().collect();
    sorted.sort_by(|left, right| left.name.cmp(&right.name));
    let mut last: Option<&str> = None;
    for definition in &sorted {
        if definition.name.is_empty() || definition.name.len() > 193
            || last == Some(definition.name.as_str()) || !definition.input_schema.is_object()
        { return Err("Invalid or duplicate executable unified tool definition".into()); }
        last = Some(&definition.name);
    }
    canonical_digest(&serde_json::to_value(sorted)?)
}

#[derive(Clone)]
pub(crate) struct ManifestContext {
    pub workspace: PathBuf,
    pub protected_roots: Vec<PathBuf>,
    pub legacy_authority: Value,
}
#[derive(Clone)]
pub(crate) struct QualifiedManifest {
    pub selection: UnifiedSelection,
    pub context: ManifestContext,
    settings: PathBuf,
    authority: Value,
    commands: std::sync::Arc<crate::command_catalogue::CommandCatalogueSnapshot>,
    database: std::sync::Arc<crate::database_binding::DatabaseBinding>,
}
impl QualifiedManifest {
    pub(crate) fn load(settings: &Path, context: ManifestContext) -> Result<Self, RuntimeError> {
        let bytes=agent_bridge_lifecycle::read_operator_setting(settings,"unified-v1.json")?;
        let selection=decode_selection(&bytes)?;
        let commands=std::sync::Arc::new(crate::command_catalogue::CommandCatalogueSnapshot::load(settings)?);
        let database=std::sync::Arc::new(crate::database_binding::DatabaseBinding::open(
            &context.legacy_authority["database_boundary"])?);
        let authority=physical_authority(&context,&selection,&commands,&database)?;
        Ok(Self {selection,context,settings:settings.to_owned(),authority,commands,database})
    }
    pub(crate) fn verify(&self) -> Result<(), RuntimeError> {
        self.database.verify()?;
        let current=Self::load(&self.settings,self.context.clone())?;
        if current.authority!=self.authority {
            return Err("UNIFIED_AUTHORITY_CHANGED: new local qualification and OAuth authorization required".into());
        }
        Ok(())
    }
    pub(crate) fn commands(&self)->std::sync::Arc<crate::command_catalogue::CommandCatalogueSnapshot> {
        std::sync::Arc::clone(&self.commands)
    }
    pub(crate) fn acquire_database(&self,path:&Path,owner:Option<crate::runtime::SharedCoreDatabase>)
        ->Result<crate::runtime::SharedCoreDatabase,RuntimeError>
    { self.database.acquire(path,owner) }
    pub(crate) fn verify_catalogue(&self, catalogue:&[ToolDefinition])->Result<(),RuntimeError> {
        let actual=catalogue_digest(catalogue)?;
        let names:std::collections::BTreeSet<_>=catalogue.iter().map(|tool|tool.name.as_str()).collect();
        let expected:std::collections::BTreeSet<_>=COMPLETE_TOOL_NAMES.iter().copied().collect();
        if catalogue.len()!=46 || names!=expected {
            return Err("UNIFIED_CATALOGUE_INCOMPLETE: all 46 real unique handlers are required".into());
        }
        if actual!=self.selection.catalogue_sha256 {
            return Err(format!("UNIFIED_CATALOGUE_CHANGED: expected {}, actual {actual}",
                self.selection.catalogue_sha256).into());
        }
        Ok(())
    }
    pub(crate) fn browser_config(&self)->crate::browser_owned::BrowserConfig {
        crate::browser_owned::BrowserConfig {
            bundle_root:self.selection.browser.bundle_root.clone(),
            manifest_sha256:self.selection.browser.manifest_sha256.clone(),
            state_root:self.selection.browser.state_root.clone(),
        }
    }
    pub(crate) fn windows_config(&self)->crate::windows_tools::WindowsToolsConfig {
        crate::windows_tools::WindowsToolsConfig {
            bundle_root:self.selection.windows.bundle_root.clone(),
            manifest_sha256:self.selection.windows.manifest_sha256.clone(),
            state_root:self.selection.windows.state_root.clone(),
        }
    }
    pub(crate) fn desktop_config(&self)->crate::agent_desktop::AgentDesktopConfig {
        crate::agent_desktop::AgentDesktopConfig {
            bundle_root:self.selection.agent_desktop.bundle_root.clone(),
            manifest_sha256:self.selection.agent_desktop.manifest_sha256.clone(),
            state_root:self.selection.agent_desktop.state_root.clone(),
            desktops:self.selection.agent_desktop.desktops.iter().map(|binding|
                crate::agent_desktop::DesktopBinding {
                    desktop_id:binding.desktop_id.clone(),desktop_number:binding.desktop_number,
                }).collect(),
        }
    }
    pub(crate) fn preflight_providers(&self)->Result<(),RuntimeError> {
        self.verify()?;
        crate::browser_owned::validate_bundle(&self.browser_config())?;
        crate::windows_tools::validate_bundle(&self.windows_config())?;
        crate::agent_desktop::validate_bundle(&self.desktop_config())?;
        Ok(())
    }
    pub(crate) fn file_config(&self)->agent_bridge_desktop::unified::UnifiedFileConfig {
        use agent_bridge_desktop::unified::{FileScope,UnifiedFileConfig};
        let mut protected=self.context.protected_roots.clone();
        for bundle in [&self.selection.browser.bundle_root,&self.selection.windows.bundle_root,
            &self.selection.agent_desktop.bundle_root] {
            if !protected.contains(bundle) { protected.push(bundle.clone()); }
        }
        UnifiedFileConfig {
            workspace:self.context.workspace.clone(),
            scope:match &self.selection.file_scope {
                FileScopeSelection::Workspace{}=>FileScope::Workspace,
                FileScopeSelection::AllowedRoots{roots}=>FileScope::AllowedRoots(roots.clone()),
                FileScopeSelection::OsUser{}=>FileScope::OsUser,
            },
            protected_roots:protected,private_root:self.selection.private_root.clone(),
        }
    }
    pub(crate) fn summary(&self)->Result<Value,RuntimeError> {
        Ok(serde_json::json!({
            "identity":self.identity()?,"total_tools":46,
            "families":{"desktop":27,"missions_including_status":16,"project_commands":1,"historical_utilities":2},
            "filesystem":self.selection.file_scope,"allow_import":self.selection.allow_import,
            "resources":{
                "browser_manifest_sha256":self.selection.browser.manifest_sha256,
                "windows_manifest_sha256":self.selection.windows.manifest_sha256,
                "desktop_manifest_sha256":self.selection.agent_desktop.manifest_sha256,
            },
            "components":{
                "files":{"implementation":"attached","qualification":"passed","availability":"checked-per-call"},
                "browser":{"implementation":"attached","qualification":"passed","availability":"checked-per-call"},
                "windows_ui":{"implementation":"attached","qualification":"passed","availability":"checked-per-call"},
                "agent_desktop":{"implementation":"attached","qualification":"passed","availability":"checked-per-call"},
                "missions":{"implementation":"attached","database":"shared-qualified-owner"},
                "terminal":{"implementation":"attached","availability":"live-profile-and-local-policy"},
                "extensions":{"implementation":"attached","availability":"exact-local-approval"},
                "skills":{"implementation":"attached","availability":"live-profile-and-local-policy"},
            }
        }))
    }
    pub(crate) fn identity(&self) -> Result<CapabilityIdentity, RuntimeError> {
        Ok(CapabilityIdentity::UnifiedV1 {
            manifest_sha256: canonical_digest(&self.authority)?,
            catalogue_sha256: self.selection.catalogue_sha256.clone(), policy_version: 1,
        })
    }
    pub(crate) fn authority_bytes(&self) -> Result<Vec<u8>, RuntimeError> {
        Ok(serde_json::to_vec(&canonical_value(&self.authority))?)
    }
}

pub(crate) const COMPLETE_TOOL_NAMES: &[&str] = &[
    "agent_bridge_context_create",
    "agent_bridge_mission_attach",
    "agent_bridge_mission_checkpoint",
    "agent_bridge_mission_checkpoints",
    "agent_bridge_mission_complete",
    "agent_bridge_mission_create",
    "agent_bridge_mission_get",
    "agent_bridge_mission_grant",
    "agent_bridge_mission_list",
    "agent_bridge_mission_observe",
    "agent_bridge_mission_subtask_assign",
    "agent_bridge_mission_subtask_create",
    "agent_bridge_mission_subtask_list",
    "agent_bridge_mission_subtask_update",
    "agent_bridge_mission_transfer",
    "agent_bridge_project_command",
    "agent_bridge_status",
    "agent_bridge_task_import",
    "desktop_agent_desktop",
    "desktop_artifact_manage",
    "desktop_browser_act",
    "desktop_browser_session",
    "desktop_browser_snapshot",
    "desktop_create_directory",
    "desktop_edit_file",
    "desktop_get_file_info",
    "desktop_interact_process",
    "desktop_list_allowed_commands",
    "desktop_list_directory",
    "desktop_mcp_manage",
    "desktop_mcp_tool_call",
    "desktop_mcp_tool_inspect",
    "desktop_mcp_tool_search",
    "desktop_move_file",
    "desktop_policy_status",
    "desktop_read_file",
    "desktop_read_process",
    "desktop_search",
    "desktop_skill_manage",
    "desktop_start_process",
    "desktop_task_manage",
    "desktop_terminate_process",
    "desktop_ui_action",
    "desktop_ui_snapshot",
    "desktop_ui_windows",
    "desktop_write_file",
];

fn path_key(path:&Path)->String {
    let value=path.to_string_lossy().trim_end_matches(['\\','/']).to_owned();
    if cfg!(windows) {value.replace('/',"\\").to_ascii_lowercase()} else {value}
}
fn within(path:&Path,root:&Path)->bool {
    let path=path_key(path); let root=path_key(root);
    path==root || path.starts_with(&(root+if cfg!(windows){"\\"}else{"/"}))
}
fn physical_directory(path:&Path)->Result<(PathBuf,Value),RuntimeError> {
    let identity=crate::gemini::scope_directory(path)?;
    Ok((std::fs::canonicalize(path)?,identity))
}
fn physical_authority(context:&ManifestContext,selection:&UnifiedSelection,
    commands:&crate::command_catalogue::CommandCatalogueSnapshot,
    database:&crate::database_binding::DatabaseBinding)
    ->Result<Value,RuntimeError>
{
    let (workspace,workspace_id)=physical_directory(&context.workspace)?;
    let mut protected=Vec::new(); let mut protected_ids=Vec::new();
    for root in &context.protected_roots {
        let (path,identity)=physical_directory(root)?;
        protected.push(path); protected_ids.push(identity);
    }
    let (private,private_id)=physical_directory(&selection.private_root)?;
    if within(&private,&workspace)||within(&workspace,&private)
        || protected.iter().any(|root|within(&private,root)||within(root,&private))
    {return Err("Unified private automation root must be disjoint from workspace and existing private authority".into());}
    let bundles=[&selection.browser.bundle_root,&selection.windows.bundle_root,
        &selection.agent_desktop.bundle_root];
    let states=[&selection.browser.state_root,&selection.windows.state_root,
        &selection.agent_desktop.state_root];
    let mut bundle_paths=Vec::new(); let mut bundle_ids=Vec::new();
    for bundle in bundles {
        let (path,identity)=physical_directory(bundle)?;
        if within(&path,&workspace)||within(&workspace,&path)
            || protected.iter().any(|root|within(&path,root)||within(root,&path))
        {return Err("Unified executable bundles overlap an existing authority root".into());}
        bundle_paths.push(path);bundle_ids.push(identity);
    }
    let mut state_paths:Vec<PathBuf>=Vec::new(); let mut state_ids=Vec::new();
    for state in states {
        let (path,identity)=physical_directory(state)?;
        if !within(&path,&private)||path_key(&path)==path_key(&private)
            || bundle_paths.iter().any(|bundle|within(&path,bundle)||within(bundle,&path))
            || state_paths.iter().any(|other|within(&path,other)||within(other,&path))
        {return Err("Unified provider state must be separate physical children of the common private root".into());}
        state_paths.push(path);state_ids.push(identity);
    }
    let mut root_ids=Vec::new();
    if let FileScopeSelection::AllowedRoots{roots}=&selection.file_scope {
        let mut seen=std::collections::BTreeSet::new();
        for root in roots {
            let (path,identity)=physical_directory(root)?;
            if within(&path,&private)||protected.iter().any(|excluded|within(&path,excluded))
                || bundle_paths.iter().any(|bundle|within(&path,bundle))
                || !seen.insert(path_key(&path))
            {return Err("An allowed file root is private, duplicated or an executable bundle".into());}
            root_ids.push(identity);
        }
    }
    let origins=std::env::var("AGENT_BRIDGE_SKILL_ALLOWED_HTTPS_ORIGINS").unwrap_or_default()
        .split(',').map(str::trim).filter(|part|!part.is_empty()).map(str::to_owned).collect::<Vec<_>>();
    Ok(serde_json::json!({
        "purpose":"agent-bridge.unified-v1.exact-authority","policy_version":1,
        "catalogue_sha256":selection.catalogue_sha256,
        "selection":selection,"legacy_physical_authority":context.legacy_authority,
        "physical_workspace":workspace_id,"physical_protected_roots":protected_ids,
        "physical_private_root":private_id,"physical_bundles":bundle_ids,
        "physical_provider_states":state_ids,"physical_allowed_roots":root_ids,
        "physical_database":database.authority(),
        "fixed_commands_sha256":commands.digest(),"skill_allowed_https_origins":origins,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn selection() -> Value {
        let common = json!({"bundle_root":"C:/qualified/bundle","manifest_sha256":"b".repeat(64),
            "state_root":"C:/qualified/private/browser"});
        json!({"version":1,"policy_version":1,"catalogue_sha256":"a".repeat(64),
            "private_root":"C:/qualified/private","file_scope":{"kind":"workspace"},
            "allow_import":true,"browser":common,"windows":common,
            "agent_desktop":{"bundle_root":"C:/qualified/bundle","manifest_sha256":"c".repeat(64),
                "state_root":"C:/qualified/private/desktops","desktops":[
                    {"desktop_id":"00000000-0000-0000-0000-000000000002","desktop_number":2}]}})
    }
    #[test]
    fn capability_manifest_selection_is_explicit_strict_and_versioned() {
        let valid = selection();
        let parsed = decode_selection(&serde_json::to_vec(&valid).unwrap())
            .expect("an explicit complete local selection must be accepted");
        assert!(parsed.allow_import);
        for (path, value) in [
            ("version",json!(2)),("policy_version",json!(2)),
            ("catalogue_sha256",json!("A".repeat(64))),("catalogue_sha256",json!("a".repeat(63))),
            ("remote_scope",json!("unified-v1")),
        ] {
            let mut bad = valid.clone(); bad[path] = value;
            assert!(decode_selection(&serde_json::to_vec(&bad).unwrap()).is_err(), "{path}");
        }
        let mut missing = valid.clone(); missing.as_object_mut().unwrap().remove("allow_import");
        assert!(decode_selection(&serde_json::to_vec(&missing).unwrap()).is_err());
        let mut broad = valid.clone(); broad["file_scope"] = json!({"kind":"workspace","roots":["C:/"]});
        assert!(decode_selection(&serde_json::to_vec(&broad).unwrap()).is_err());
        let mut user_desktop = valid.clone(); user_desktop["agent_desktop"]["desktops"][0]["desktop_number"]=json!(1);
        assert!(decode_selection(&serde_json::to_vec(&user_desktop).unwrap()).is_err());
        let duplicate = serde_json::to_string(&valid).unwrap().replacen(
            "\"version\":1", "\"version\":1,\"version\":1",1);
        assert!(decode_selection(duplicate.as_bytes()).is_err(), "duplicate selection fields are ambiguous");
    }
    #[test]
    fn capability_manifest_digest_is_canonical_and_covers_every_policy_field() {
        let original = selection();
        let first = canonical_digest(&original).unwrap();
        assert_eq!(first.len(),64);
        let same: Value = serde_json::from_str(&serde_json::to_string_pretty(&original).unwrap()).unwrap();
        assert_eq!(canonical_digest(&same).unwrap(),first);
        for name in ["allow_import","catalogue_sha256","file_scope","browser"] {
            let mut changed = original.clone(); changed[name]=json!(null);
            assert_ne!(canonical_digest(&changed).unwrap(),first,"{name} must change the seal");
        }
    }
    #[test]
    fn capability_catalogue_seal_covers_schemas_descriptions_and_unique_names() {
        let a = ToolDefinition::new("a",Some("first".into()),json!({"type":"object"}));
        let b = ToolDefinition::new("b",None,json!({"type":"object","properties":{"safe":{"type":"boolean"}}}));
        let first = catalogue_digest(&[a.clone(),b.clone()]).expect("real definitions must have a digest");
        assert_eq!(first,catalogue_digest(&[b.clone(),a.clone()]).unwrap());
        assert!(catalogue_digest(&[a.clone(),a.clone()]).is_err());
        assert!(catalogue_digest(&[]).is_err());
        let mut changed = b.clone(); changed.input_schema["additionalProperties"]=json!(true);
        assert_ne!(first,catalogue_digest(&[a.clone(),changed]).unwrap());
        let changed = ToolDefinition::new("b",Some("another description".into()),b.input_schema.clone());
        assert_ne!(first,catalogue_digest(&[a,changed]).unwrap());
    }
    struct PhysicalFixture {
        manifest: QualifiedManifest,
        root: PathBuf,
    }
    impl PhysicalFixture {
        fn new() -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let base=crate::test_state_base();
            let root=base.join(format!("manifest-{}-{}",std::process::id(),NEXT.fetch_add(1,Ordering::Relaxed)));
            std::fs::create_dir_all(&root).unwrap();
            for path in ["settings","oauth","lifecycle","db","private"] {
                agent_bridge_lifecycle::initialize_operator_settings(&root.join(path)).unwrap();
            }
            for path in ["workspace","browser-bundle","windows-bundle","private/browser","private/windows","private/desktops"] {
                std::fs::create_dir_all(root.join(path)).unwrap();
            }
            let mut selected=selection();
            selected["private_root"]=json!(root.join("private"));
            selected["browser"]["bundle_root"]=json!(root.join("browser-bundle"));
            selected["browser"]["state_root"]=json!(root.join("private/browser"));
            selected["windows"]["bundle_root"]=json!(root.join("windows-bundle"));
            selected["windows"]["state_root"]=json!(root.join("private/windows"));
            selected["agent_desktop"]["bundle_root"]=json!(root.join("windows-bundle"));
            selected["agent_desktop"]["state_root"]=json!(root.join("private/desktops"));
            crate::write_private(root.join("settings/unified-v1.json"),selected.to_string());
            drop(agent_bridge_core::CoreDatabase::initialize_new(root.join("db/core.sqlite")).unwrap());
            let context=ManifestContext {
                workspace:root.join("workspace"),
                protected_roots:["settings","oauth","lifecycle","db"].map(|p|root.join(p)).to_vec(),
                legacy_authority:json!({"purpose":"synthetic","resource":"https://synthetic.invalid/mcp",
                    "database_boundary":crate::gemini::scope_file(&root.join("db/core.sqlite")).unwrap()}),
            };
            let manifest=QualifiedManifest::load(&root.join("settings"),context)
                .expect("complete physical local selection must qualify without starting providers");
            Self {manifest,root}
        }
    }
    impl Drop for PhysicalFixture { fn drop(&mut self) { let _=std::fs::remove_dir_all(&self.root); } }

    #[test]
    fn capability_manifest_rechecks_private_selection_commands_and_physical_incarnation() {
        let fixture=PhysicalFixture::new();
        fixture.manifest.verify().unwrap();
        let settings=fixture.root.join("settings");
        let original=std::fs::read(settings.join("unified-v1.json")).unwrap();
        let mut changed:Value=serde_json::from_slice(&original).unwrap();
        changed["allow_import"]=json!(false);
        std::fs::write(settings.join("unified-v1.json"),changed.to_string()).unwrap();
        assert!(fixture.manifest.verify().is_err(),"selection drift invalidates unified authority");
        std::fs::write(settings.join("unified-v1.json"),original).unwrap();
        fixture.manifest.verify().unwrap();
        let commands=std::fs::read(settings.join("commands.json")).unwrap();
        std::fs::write(settings.join("commands.json"),b"{\"version\":1,\"programs\":{\"new\":{}}}").unwrap();
        assert!(fixture.manifest.verify().is_err(),"fixed commands are authority, not merely directory identity");
        std::fs::write(settings.join("commands.json"),commands).unwrap();
        fixture.manifest.verify().unwrap();
        std::fs::rename(fixture.root.join("private/browser"),fixture.root.join("private/old-browser")).unwrap();
        std::fs::create_dir(fixture.root.join("private/browser")).unwrap();
        assert!(fixture.manifest.verify().is_err(),"same path cannot authorize a replacement private state root");
    }

    #[test]
    fn capability_manifest_os_user_scope_requires_new_authority() {
        let fixture=PhysicalFixture::new();
        let settings=fixture.root.join("settings");
        let path=settings.join("unified-v1.json");
        let original=std::fs::read(&path).unwrap();
        let old_authority=fixture.manifest.authority_bytes().unwrap();
        let mut selected:Value=serde_json::from_slice(&original).unwrap();
        selected["file_scope"]=json!({"kind":"os-user"});
        std::fs::write(&path,selected.to_string()).unwrap();
        assert!(fixture.manifest.verify().is_err(),"an old workspace authorization cannot widen to OS-user");
        let widened=QualifiedManifest::load(&settings,fixture.manifest.context.clone()).unwrap();
        widened.verify().unwrap();
        assert_ne!(widened.authority_bytes().unwrap(),old_authority);
        assert!(matches!(widened.file_config().scope,agent_bridge_desktop::unified::FileScope::OsUser));
        std::fs::write(&path,original).unwrap();
        fixture.manifest.verify().unwrap();
        assert!(widened.verify().is_err(),"a stale widened manifest must also refuse policy drift");
    }

    #[test]
    fn capability_manifest_excludes_private_authority_roots_from_every_file_scope() {
        let fixture=PhysicalFixture::new();
        let settings=fixture.root.join("settings");
        let original=std::fs::read(settings.join("unified-v1.json")).unwrap();
        for (field,path) in [
            ("private_root",fixture.root.join("workspace")),
            ("browser.state_root",fixture.root.join("workspace")),
            ("browser.bundle_root",fixture.root.join("workspace")),
        ] {
            let mut bad:Value=serde_json::from_slice(&original).unwrap();
            if let Some((parent,child))=field.split_once('.') {bad[parent][child]=json!(path);}
            else {bad[field]=json!(path);}
            std::fs::write(settings.join("unified-v1.json"),bad.to_string()).unwrap();
            assert!(QualifiedManifest::load(&settings,fixture.manifest.context.clone()).is_err(),"{field}");
        }
        let mut bad:Value=serde_json::from_slice(&original).unwrap();
        bad["file_scope"]=json!({"kind":"allowed-roots","roots":[fixture.root.join("oauth")]});
        std::fs::write(settings.join("unified-v1.json"),bad.to_string()).unwrap();
        assert!(QualifiedManifest::load(&settings,fixture.manifest.context.clone()).is_err());
    }


    #[test]
    fn capability_fix_manifest_rechecks_database_incarnation() {
        let fixture=PhysicalFixture::new();
        let database=fixture.root.join("db/core.sqlite");
        drop(agent_bridge_core::CoreDatabase::initialize_new(fixture.root.join("db/replacement.sqlite")).unwrap());
        // A retained OS pin may prevent replacement altogether. Otherwise the
        // manifest must refuse the new incarnation at the original path.
        if std::fs::rename(&database,fixture.root.join("db/original.sqlite")).is_err() {
            fixture.manifest.verify().unwrap();
            return;
        }
        std::fs::rename(fixture.root.join("db/replacement.sqlite"),&database).unwrap();
        assert!(fixture.manifest.verify().is_err(),"the copied legacy DB value is not a fresh identity check");
    }

    #[test]
    fn capability_fix_unified_checks_the_actual_shared_core_owner() {
        use std::sync::{Arc,Mutex};
        let fixture=PhysicalFixture::new();
        let other=fixture.root.join("db/other.sqlite");
        drop(agent_bridge_core::CoreDatabase::initialize_new(&other).unwrap());
        for use_shared in [false,true] {
            let shared=if use_shared {
                Some(Arc::new(Mutex::new(agent_bridge_core::CoreDatabase::open_existing(&other).unwrap())))
            }else{None};
            let mut supervisors=Vec::new();let mut providers=Vec::new();
            let selected=if shared.is_some(){fixture.root.join("db/core.sqlite")}else{other.clone()};
            let result=crate::runtime::unified_router(&fixture.manifest,&selected,
                shared,&fixture.root.join("settings"),&json!({}),
                crate::session_profile::ProfileControl::new(agent_bridge_desktop::DesktopProfile::FullyUnlocked),
                &mut supervisors,&mut providers);
            let refused=result.err().expect("a different database must be rejected");
            assert!(refused.to_string().contains("DATABASE_AUTHORITY_CHANGED"),
                "database mismatch must be detected before any provider attachment, including legacy Core=None: {refused}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn capability_fix_actual_sqlite_handle_is_bound_and_pin_follows_core() {
        let mut fixture=PhysicalFixture::new();
        let other=PhysicalFixture::new();
        let path=fixture.root.join("db/core.sqlite");
        let owner=fixture.manifest.acquire_database(&path,None).unwrap();
        let different=std::fs::File::open(other.root.join("db/core.sqlite")).unwrap();
        assert!(owner.lock().unwrap().bind_authority_file(&different).is_err(),
            "a different open file must not bind even when its SQLite schema is identical");
        let manifest=std::mem::replace(&mut fixture.manifest,other.manifest.clone());
        drop(manifest);
        let renamed=fixture.root.join("db/closed.sqlite");
        assert!(std::fs::rename(&path,&renamed).is_err(),"the Core owner must retain the no-DELETE authority pin");
        drop(owner);
        std::fs::rename(&path,&renamed).unwrap();
    }

    #[cfg(not(windows))]
    #[test]
    fn capability_fix_unqualified_vfs_binding_is_explicitly_unavailable() {
        let fixture=PhysicalFixture::new();
        let path=fixture.root.join("db/core.sqlite");
        let error=fixture.manifest.acquire_database(&path,None).err().unwrap();
        assert!(error.to_string().contains("UNIFIED_DATABASE_HANDLE_IDENTITY_UNAVAILABLE"));
        assert!(agent_bridge_core::CoreDatabase::open_existing(&path).is_ok(),
            "the new unified boundary must not disable legacy Core opens");
    }

}
