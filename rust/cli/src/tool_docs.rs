//! Documentary metadata for the foreground server and explicitly selected workstation catalogues.
use super::{RuntimeError, ToolDefinition};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolDocs {
    description: Option<String>,
    annotations: Value,
    #[serde(default)]
    parameters: BTreeMap<String, String>,
}

type CatalogueDocs = BTreeMap<String, ToolDocs>;

fn apply(tools: &mut [ToolDefinition], docs: &CatalogueDocs) -> Result<(), RuntimeError> {
    for tool in tools {
        let Some(entry) = docs.get(&tool.name) else { continue };
        if let Some(description) = &entry.description {
            tool.description = Some(description.clone());
        }
        tool.annotations = Some(entry.annotations.clone());
        for (name, description) in &entry.parameters {
            let field = tool.input_schema["properties"].get_mut(name)
                .and_then(Value::as_object_mut)
                .ok_or("Documented parameter missing from the tool schema")?;
            field.insert("description".into(), Value::String(description.clone()));
        }
    }
    Ok(())
}

fn stdio_docs() -> Result<CatalogueDocs, RuntimeError> {
    Ok(serde_json::from_str(include_str!("../../../contracts/stdio-workspace-tool-docs.json"))?)
}

pub(super) fn document_stdio_workspace(tools: &mut [ToolDefinition]) -> Result<(), RuntimeError> {
    apply(tools, &stdio_docs()?)
}

pub(super) fn stdio_workspace_instructions(writable: bool) -> String {
    let files = if writable {
        "This workspace permits file writes. Check desktop_policy_status for limits."
    } else {
        "Project files are read-only in this workspace. Mission records can still change."
    };
    format!("{files} Use tools/list to see this session's capabilities. \
        desktop_artifact_manage works with temporary artifacts separate from project files. \
        After an invitation, use agent_bridge_mission_observe before agent_bridge_mission_attach. \
        To record progress use agent_bridge_mission_checkpoint. To read saved summaries use \
        agent_bridge_mission_checkpoints.")
}

// The operator selects an entire serialized catalogue by its existing digest mechanism.
// A legacy manifest must receive exactly its original definitions. Normal startup still
// checks handler membership and the complete digest before admitting an OAuth client.
pub(super) fn select_workstation_docs(
    tools: &mut Vec<ToolDefinition>, selected_digest: &str,
) -> Result<(), RuntimeError> {
    use crate::capability_manifest::catalogue_digest;
    if catalogue_digest(tools)? == selected_digest {
        return Ok(());
    }

    let mut docs = stdio_docs()?;
    docs.retain(|name, _| name.starts_with("agent_bridge_mission_") || name == "agent_bridge_context_create");
    let workstation: CatalogueDocs =
        serde_json::from_str(include_str!("../../../contracts/workstation-tool-docs.json"))?;
    docs.extend(workstation);
    let mut documented = tools.clone();
    apply(&mut documented, &docs)?;
    if catalogue_digest(&documented)? == selected_digest {
        *tools = documented;
    }
    Ok(())
}
