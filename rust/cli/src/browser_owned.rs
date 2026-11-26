//! Isolated Playwright sessions owned by the native gateway.
#[cfg(any(windows, test))]
mod profiles;
#[cfg(any(windows, test))]
mod provider;
mod resources;
#[cfg(any(windows, test))]
mod wire;
#[cfg(any(windows, test))]
mod worker;
#[cfg(all(test, windows, feature = "qualification"))]
mod tests;

#[cfg(windows)]
use agent_bridge_desktop::DesktopProfile;
use agent_bridge_gateway::{ToolDefinition, ToolMapHandler};
use crate::agent_desktop::AgentDesktopHandle;
use crate::provider_owner::ProviderOwner;
use crate::runtime::RuntimeError;
use crate::session_profile::ProfileControl;
#[cfg(windows)]
use serde_json::Value;
#[cfg(windows)]
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub(crate) struct BrowserConfig {
    pub(crate) bundle_root: PathBuf,
    pub(crate) manifest_sha256: String,
    #[cfg(windows)]
    pub(crate) state_root: PathBuf,
}
#[cfg(windows)]
pub(crate) type StageUploads = Arc<dyn Fn(DesktopProfile, &[String], &Path) -> Result<Vec<PathBuf>, RuntimeError> + Send + Sync>;
#[cfg(windows)]
pub(crate) type PublishDownload = Arc<dyn Fn(DesktopProfile, &Path, &str) -> Result<Value, RuntimeError> + Send + Sync>;
#[derive(Clone)]
pub(crate) struct BrowserTransferCallbacks {
    #[cfg(windows)]
    pub(crate) stage_uploads: StageUploads,
    #[cfg(windows)]
    pub(crate) publish_download: PublishDownload,
}

pub(crate) fn validate_bundle(config: &BrowserConfig) -> Result<(), RuntimeError> {
    let _qualified = resources::Resources::verify(&config.bundle_root, &config.manifest_sha256)?;
    Ok(())
}

#[cfg(windows)]
pub(crate) fn attach(
    config: BrowserConfig, profile: Arc<ProfileControl>, desktops: AgentDesktopHandle,
    transfers: BrowserTransferCallbacks, catalog: &mut Vec<ToolDefinition>, handlers: &mut ToolMapHandler,
) -> Result<ProviderOwner, RuntimeError> {
    provider::attach(config, profile, desktops, transfers, catalog, handlers)
}

#[cfg(not(windows))]
pub(crate) fn attach(
    _: BrowserConfig, _: Arc<ProfileControl>, _: AgentDesktopHandle,
    _: BrowserTransferCallbacks, _: &mut Vec<ToolDefinition>, _: &mut ToolMapHandler,
) -> Result<ProviderOwner, RuntimeError> {
    Err("BROWSER_PLATFORM_UNSUPPORTED: owned browser requires Windows".into())
}
