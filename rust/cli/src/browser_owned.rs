//! Isolated Playwright sessions owned by the native gateway.
mod profiles;
mod provider;
mod resources;
mod wire;
mod worker;
#[cfg(all(test, windows))]
mod tests;

use agent_bridge_desktop::DesktopProfile;
use agent_bridge_gateway::{ToolDefinition, ToolMapHandler};
use crate::agent_desktop::AgentDesktopHandle;
use crate::provider_owner::ProviderOwner;
use crate::runtime::RuntimeError;
use crate::session_profile::ProfileControl;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Clone, Debug)]
pub(crate) struct BrowserConfig {
    pub(crate) bundle_root: PathBuf,
    pub(crate) manifest_sha256: String,
    pub(crate) state_root: PathBuf,
}
pub(crate) type StageUploads = Arc<dyn Fn(DesktopProfile, &[String], &Path) -> Result<Vec<PathBuf>, RuntimeError> + Send + Sync>;
pub(crate) type PublishDownload = Arc<dyn Fn(DesktopProfile, &Path, &str) -> Result<Value, RuntimeError> + Send + Sync>;
#[derive(Clone)]
pub(crate) struct BrowserTransferCallbacks {
    pub(crate) stage_uploads: StageUploads,
    pub(crate) publish_download: PublishDownload,
}

pub(crate) fn validate_bundle(config: &BrowserConfig) -> Result<(), RuntimeError> {
    let _qualified = resources::Resources::verify(&config.bundle_root, &config.manifest_sha256)?;
    Ok(())
}

pub(crate) fn attach(
    config: BrowserConfig, profile: Arc<ProfileControl>, desktops: AgentDesktopHandle,
    transfers: BrowserTransferCallbacks, catalog: &mut Vec<ToolDefinition>, handlers: &mut ToolMapHandler,
) -> Result<ProviderOwner, RuntimeError> {
    provider::attach(config, profile, desktops, transfers, catalog, handlers)
}
