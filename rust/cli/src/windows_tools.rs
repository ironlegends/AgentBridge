//! The native UI provider owns WinApp directly; no DeskMCP process or endpoint.
pub(crate) mod bundle;
mod runner;
mod process_pin;
mod provider;
use crate::agent_desktop::AgentDesktopHandle;
use crate::provider_owner::ProviderOwner;
use crate::runtime::RuntimeError;
use crate::session_profile::ProfileControl;
use agent_bridge_gateway::{ToolDefinition, ToolMapHandler, ToolDispatchError};
use serde_json::{Map, Value};
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub(crate) struct WindowsToolsConfig {
    pub(crate) bundle_root: PathBuf,
    pub(crate) manifest_sha256: String,
    pub(crate) state_root: PathBuf,
}
pub(crate) fn definitions() -> Result<Vec<ToolDefinition>, RuntimeError> {
    Ok(serde_json::from_str(include_str!("../../../contracts/windows-tools-v1.json"))?)
}
pub(crate) fn validate_arguments(schema: &Value, mut args: Map<String,Value>) -> Result<Map<String,Value>,ToolDispatchError> {
    let invalid=||ToolDispatchError::invalid_params("NATIVE_ARGUMENT_SCHEMA_INVALID");
    let properties=schema["properties"].as_object().ok_or_else(invalid)?;
    if args.keys().any(|key|!properties.contains_key(key)) {return Err(invalid());}
    if let Some(required)=schema["required"].as_array() {
        if required.iter().any(|key|key.as_str().is_none_or(|key|!args.contains_key(key))) {return Err(invalid());}
    }
    for (key,value) in &mut args {
        let field=&properties[key];
        if let Some(choices)=field["enum"].as_array() {if !choices.contains(value){return Err(invalid());}}
        match field["type"].as_str() {
            Some("string")=>{
                let text=value.as_str().ok_or_else(invalid)?;let length=text.encode_utf16().count() as u64;
                if text.contains('\0') || field["minLength"].as_u64().is_some_and(|minimum|length<minimum)
                    || field["maxLength"].as_u64().is_some_and(|maximum|length>maximum) {return Err(invalid());}
                if field["format"]=="uuid" {if !bundle::valid_uuid(text){return Err(invalid());}*value=Value::String(text.to_ascii_lowercase());}
            }
            Some("boolean")=>{if !value.is_boolean(){return Err(invalid());}}
            Some("integer")=>{
                let number=value.as_f64().filter(|number|number.is_finite()&&number.fract()==0.0).ok_or_else(invalid)?;
                if number<i32::MIN as f64 || number>i32::MAX as f64 || field["minimum"].as_f64().is_some_and(|minimum|number<minimum)
                    || field["maximum"].as_f64().is_some_and(|maximum|number>maximum) {return Err(invalid());}
                *value=Value::from(number as i64);
            }
            _=>return Err(invalid()),
        }
    }
    Ok(args)
}
pub(crate) fn validate_bundle(config: &WindowsToolsConfig) -> Result<(), RuntimeError> {
    bundle::Resources::verify(&config.bundle_root, &config.manifest_sha256).map(|_| ())
}
pub(crate) fn attach(config: WindowsToolsConfig, profile: ProfileControl, desktops: AgentDesktopHandle,
    catalog: &mut Vec<ToolDefinition>, handlers: &mut ToolMapHandler) -> Result<ProviderOwner, RuntimeError> {
    provider::attach(config, profile, desktops, catalog, handlers)
}

#[cfg(all(test, windows))]
mod tests;
