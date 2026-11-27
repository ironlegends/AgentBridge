//! Operator-selected, immutable narrowing of an already qualified catalogue.
//! No name rewriting, synthetic tools, profile changes or remote selectors.
use agent_bridge_gateway::{GatewayConfig, ToolDefinition, ToolHandler, ToolMapHandler};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use crate::runtime::RuntimeError;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CatalogueSelection {
    #[default]
    Unified,
    Core,
    Code,
    Desktop,
    Automation,
    Extensions,
}

// Exact membership, not a prefix policy. New tools remain exclusive to the
// unified view until their placement in a specialized view is reviewed.
const CORE: &[&str] = &[
    "agent_bridge_context_create",
    "agent_bridge_mission_attach",
    "agent_bridge_mission_checkpoint",
    "agent_bridge_mission_checkpoints",
    "agent_bridge_mission_complete",
    "agent_bridge_mission_create",
    "agent_bridge_mission_get",
    "agent_bridge_mission_grant",
    "agent_bridge_mission_handoff",
    "agent_bridge_mission_list",
    "agent_bridge_mission_observe",
    "agent_bridge_mission_subtask_assign",
    "agent_bridge_mission_subtask_create",
    "agent_bridge_mission_subtask_list",
    "agent_bridge_mission_subtask_update",
    "agent_bridge_mission_transfer",
    "agent_bridge_mission_attempt",
    "agent_bridge_task_import",
    "desktop_task_manage",
];
const FILES: &[&str] = &[
    "desktop_artifact_manage",
    "desktop_create_directory",
    "desktop_edit_file",
    "desktop_get_file_info",
    "desktop_list_directory",
    "desktop_move_file",
    "desktop_read_file",
    "desktop_search",
    "desktop_write_file",
];
const COMMANDS: &[&str] = &["agent_bridge_project_command", "desktop_list_allowed_commands"];
const PROCESSES: &[&str] = &[
    "desktop_start_process", "desktop_read_process", "desktop_interact_process",
    "desktop_terminate_process",
];
const DESKTOP: &[&str] = &[
    "desktop_agent_desktop",
    "desktop_ui_windows", "desktop_ui_snapshot", "desktop_ui_action",
    "desktop_browser_session", "desktop_browser_snapshot", "desktop_browser_act",
];
const EXTENSIONS: &[&str] = &[
    "desktop_mcp_manage", "desktop_mcp_tool_inspect", "desktop_mcp_tool_search",
    "desktop_mcp_tool_call",
];
const COMMON: &[&str] = &["agent_bridge_status", "desktop_policy_status"];

impl CatalogueSelection {
    pub(crate) fn parse(name: &str) -> Result<Self, RuntimeError> {
        match name {
            "unified" => Ok(Self::Unified),
            "core" => Ok(Self::Core),
            "code" => Ok(Self::Code),
            "desktop" => Ok(Self::Desktop),
            "automation" => Ok(Self::Automation),
            "extensions" => Ok(Self::Extensions),
            _ => Err("CATALOGUE_SELECTION_UNKNOWN".into()),
        }
    }
    pub(crate) fn is_unified(&self) -> bool { *self == Self::Unified }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Unified => "unified",
            Self::Core => "core",
            Self::Code => "code",
            Self::Desktop => "desktop",
            Self::Automation => "automation",
            Self::Extensions => "extensions",
        }
    }

    pub(crate) fn allows(self, name: &str) -> bool {
        if COMMON.contains(&name) { return true; }
        match self {
            Self::Unified => true,
            Self::Core => CORE.contains(&name),
            Self::Code => FILES.contains(&name) || COMMANDS.contains(&name) ||
                PROCESSES.contains(&name) || matches!(name,"desktop_skill_manage"|"desktop_task_manage"),
            Self::Desktop => DESKTOP.contains(&name) || name == "desktop_artifact_manage",
            Self::Automation => DESKTOP.contains(&name) || PROCESSES.contains(&name) ||
                COMMANDS.contains(&name) || matches!(name,"desktop_task_manage"|"desktop_skill_manage"|"desktop_artifact_manage"),
            Self::Extensions => EXTENSIONS.contains(&name),
        }
    }

    /// Remove the excluded definitions and their dispatch entries together.
    /// This function neither creates nor substitutes a handler.
    pub(crate) fn restrict(self, tools: &mut Vec<ToolDefinition>, handlers: &mut ToolMapHandler) {
        if self.is_unified() { return; }
        tools.retain(|tool| {
            if self.allows(&tool.name) { true }
            else { handlers.remove(&tool.name); false }
        });
    }

    /// Stdio uses the subset of its actual local providers. Fail rather than
    /// advertise a status-only specialized connection with no relevant tool.
    pub(crate) fn require_available(self, tools: &[ToolDefinition], handlers: &ToolMapHandler)
        -> Result<(), RuntimeError>
    {
        if self.is_unified() { return Ok(()); }
        if !tools.iter().any(|tool| !COMMON.contains(&tool.name.as_str()) &&
            handlers.has_handler(&tool.name)) {
            return Err("CATALOGUE_SELECTION_UNAVAILABLE: no selected provider tools".into());
        }
        if tools.iter().any(|tool| tool.name != "agent_bridge_status" && !handlers.has_handler(&tool.name)) {
            return Err("CATALOGUE_SELECTION_INCOMPLETE".into());
        }
        Ok(())
    }

    /// Legacy clients get a distinct server name; modern discovery/list
    /// revisions also include the selection and exact local authority seal.
    /// The default name, TTL, definitions and revision remain unchanged.
    pub(crate) fn configure(self, mut config: GatewayConfig, seal: &str) -> GatewayConfig {
        if self.is_unified() { return config; }
        config.server_info.name = format!("{}-{}", config.server_info.name, self.name());
        config.with_catalog_partition(format!("{}:{seal}", self.name()))
    }
}

/// The existing family labels are retained for status and operator views.
pub(crate) fn family_counts<'a>(names: impl IntoIterator<Item = &'a str>) -> Value {
    let mut counts=json!({"desktop":0,"missions_including_status":0,"project_commands":0,
        "historical_utilities":0,"other":0});
    for name in names {
        let family=if matches!(name,"agent_bridge_task_import"|"desktop_list_allowed_commands") {
            "historical_utilities"
        } else if name=="agent_bridge_project_command" {"project_commands"}
        else if name.starts_with("desktop_") {"desktop"}
        else if name.starts_with("agent_bridge_mission_") ||
            matches!(name,"agent_bridge_context_create"|"agent_bridge_status") {"missions_including_status"}
        else {"other"};
        counts[family]=json!(counts[family].as_u64().unwrap_or(0)+1);
    }
    counts
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_bridge_gateway::{McpGateway, ToolCallResult, modern};
    use std::sync::{Arc,atomic::{AtomicUsize,Ordering}};
    const SPECIALIZED: [CatalogueSelection;5]=[CatalogueSelection::Core,CatalogueSelection::Code,
        CatalogueSelection::Desktop,CatalogueSelection::Automation,CatalogueSelection::Extensions];

    fn fixture(selection: CatalogueSelection)->(McpGateway<ToolMapHandler>,Arc<AtomicUsize>,Vec<ToolDefinition>){
        let calls=Arc::new(AtomicUsize::new(0));
        let mut handlers=ToolMapHandler::new();
        let original:Vec<_>=crate::capability_manifest::selected_tool_names(false)
            .map(|name|{
                let witness=calls.clone();
                handlers.register(name,move |_|{
                    witness.fetch_add(1,Ordering::Relaxed);
                    Ok(ToolCallResult::text("fixture"))
                });
                ToolDefinition::new(name,Some(format!("Existing {name}")),
                    json!({"type":"object","properties":{"witness":{"type":"string"}}}))
            }).collect();
        let mut selected=original.clone();
        selection.restrict(&mut selected,&mut handlers);
        for tool in &original {
            assert_eq!(handlers.has_handler(&tool.name),selection.allows(&tool.name));
        }
        let digest=crate::capability_manifest::catalogue_digest(&selected).unwrap();
        let config=selection.configure(GatewayConfig::new("fixture","1"),&digest);
        (McpGateway::new(config,selected,handlers),calls,original)
    }
    fn rpc(router:&McpGateway<ToolMapHandler>,method:&str,mut params:Value,modern_era:bool)->Value{
        if modern_era {
            params["_meta"]=json!({(modern::VERSION_KEY):modern::VERSION,(modern::CAPABILITIES_KEY):{}});
        }
        serde_json::from_str(&router.handle_str(&json!({"jsonrpc":"2.0","id":1,
            "method":method,"params":params}).to_string()).unwrap()).unwrap()
    }

    #[test]
    fn catalogue_selection_exact_sets_preserve_default_names_schemas_and_refuse_direct_calls() {
        use CatalogueSelection::*;
        let expected=[19,19,10,18,6]; // counts include both status tools
        for (selection,count) in SPECIALIZED.into_iter().zip(expected){
            let (router,calls,original)=fixture(selection);
            let expected:Vec<_>=original.iter().filter(|tool|selection.allows(&tool.name)).cloned().collect();
            assert_eq!(expected.len(),count,"{}",selection.name());
            assert!(!selection.allows("agent_bridge_mission_future"));
            assert_eq!(router.published_tools().into_iter().cloned().collect::<Vec<_>>(),expected);
            for era in [false,true]{
                let listed=rpc(&router,"tools/list",json!({}),era);
                let mut actual:Vec<ToolDefinition>=serde_json::from_value(listed["result"]["tools"].clone()).unwrap();
                let mut wanted=expected.clone();
                actual.sort_by(|a,b|a.name.cmp(&b.name));wanted.sort_by(|a,b|a.name.cmp(&b.name));
                assert_eq!(actual,wanted);
                let before=calls.load(Ordering::Relaxed);
                for tool in &original{
                    if !selection.allows(&tool.name){
                        let reply=rpc(&router,"tools/call",json!({"name":tool.name,"arguments":{}}),era);
                        assert!(reply["error"].is_object(),"{}: {reply}",tool.name);
                    }
                }
                assert_eq!(calls.load(Ordering::Relaxed),before);
                assert!(rpc(&router,"tools/call",json!({"name":"agent_bridge_status","arguments":{}}),era)["result"].is_object());
            }
        }
        let (default,_,original)=fixture(Unified);
        assert_eq!(original.len(),46);
        assert_eq!(default.published_tools().into_iter().cloned().collect::<Vec<_>>(),original);
    }

    #[test]
    fn identical_listing_has_distinct_cache_revision_when_the_local_partition_changes() {
        let descriptor=ToolDefinition::new("agent_bridge_status",None,json!({"type":"object"}));
        let make=|selection:CatalogueSelection,seal:&str|{
            let mut handlers=ToolMapHandler::new();
            handlers.register("agent_bridge_status",|_|Ok(ToolCallResult::text("ok")));
            McpGateway::new(selection.configure(GatewayConfig::new("fixture","1"),seal),
                vec![descriptor.clone()],handlers)
        };
        let revision=|router:&McpGateway<ToolMapHandler>|rpc(router,"tools/list",json!({}),true)
            ["result"]["_meta"][modern::CATALOG_REVISION_KEY].clone();
        let default=make(CatalogueSelection::Unified,"old");
        let listing=rpc(&default,"tools/list",json!({}),true);
        use sha2::{Digest,Sha256};
        let historical=hex::encode(Sha256::digest(listing["result"]["tools"].to_string().as_bytes()));
        assert_eq!(revision(&default),historical);
        let a=make(CatalogueSelection::Code,"seal-a");
        let b=make(CatalogueSelection::Core,"seal-a");
        let c=make(CatalogueSelection::Code,"seal-b");
        assert_ne!(revision(&a),revision(&b));
        assert_ne!(revision(&a),revision(&c));
        assert_ne!(revision(&a),revision(&default));
    }

    #[test]
    fn catalogue_selection_unknown_is_not_default_and_modern_cache_is_partitioned(){
        for bad in ["","Core","core ","all","unknown","desktop,code"] {
            assert!(CatalogueSelection::parse(bad).is_err());
        }
        let mut seen=std::collections::BTreeSet::new();
        for selection in [CatalogueSelection::Unified].into_iter().chain(SPECIALIZED){
            let (router,_,_)=fixture(selection);
            let listed=rpc(&router,"tools/list",json!({}),true);
            let discovered=rpc(&router,"server/discover",json!({}),true);
            let revision=&listed["result"]["_meta"][modern::CATALOG_REVISION_KEY];
            assert_eq!(revision,&discovered["result"]["_meta"][modern::CATALOG_REVISION_KEY]);
            assert_eq!(listed["result"]["cacheScope"],"private");
            assert!(seen.insert(revision.as_str().unwrap().to_owned()));
        }
    }
}
