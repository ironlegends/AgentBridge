//! Exact private command bytes captured by one unified grant identity.
use crate::runtime::RuntimeError;
use serde::Deserialize;
use serde_json::{json,Value};
use sha2::{Digest,Sha256};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

#[derive(Clone)]
pub(crate) struct CommandCatalogueSnapshot {
    bytes:Option<Arc<[u8]>>,
    digest:Option<String>,
}
impl CommandCatalogueSnapshot {
    pub(crate) fn load(settings:&Path)->Result<Self,RuntimeError> {
        let bytes=match agent_bridge_lifecycle::read_operator_setting(settings,"commands.json") {
            Ok(bytes)=>Some(bytes),
            Err(agent_bridge_lifecycle::LifecycleError::Io(error))
                if error.kind()==std::io::ErrorKind::NotFound=>None,
            Err(error)=>return Err(error.into()),
        };
        if bytes.as_ref().is_some_and(|bytes|bytes.len()>65_536) {
            return Err("COMMAND_CATALOGUE_TOO_LARGE".into());
        }
        let digest=bytes.as_ref().map(|bytes|Sha256::digest(bytes).iter()
            .map(|byte|format!("{byte:02x}")).collect());
        Ok(Self {bytes:bytes.map(Arc::from),digest})
    }
    pub(crate) fn digest(&self)->Option<&str> {self.digest.as_deref()}
    pub(crate) fn bytes(&self)->Result<&[u8],RuntimeError> {
        self.bytes.as_deref().ok_or_else(||"COMMAND_CATALOGUE_UNAVAILABLE".into())
    }
    pub(crate) fn names(&self)->Result<Value,RuntimeError> {
        let Some(bytes)=self.bytes.as_deref() else {
            return Ok(json!({"commands":[],"catalog_present":false}));
        };
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Names {version:u8,programs:BTreeMap<String,Value>}
        let names:Names=serde_json::from_slice(bytes)?;
        if names.version!=1 || names.programs.iter().any(|(name,value)|
            name.is_empty() || name.len()>256 || !value.is_object()) {
            return Err("INVALID_COMMAND_CATALOGUE".into());
        }
        Ok(json!({"commands":names.programs.keys().collect::<Vec<_>>(),"catalog_present":true}))
    }
}
