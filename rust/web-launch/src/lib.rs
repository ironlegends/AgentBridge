//! Operator-gated launch of first-party Agent Bridge Web conversation entry pages.
//!
//! # Public API
//!
//! 1. The trusted local CLI creates, privately secures and validates separate,
//!    persistent Bridge settings profiles:
//!    <Bridge settings>/browser-profiles/chatgpt and
//!    <Bridge settings>/browser-profiles/gemini. It then passes their absolute
//!    paths to LocalCliProfiles::from_local_cli(chatgpt, gemini). These paths
//!    MUST NOT be accepted from MCP or a conversation launch request.
//! 2. ChromeLauncher::discover(approved_collection_url, profiles)
//!    finds installed Chrome. The URL comes from approved local configuration.
//! 3. LaunchRequest::new(provider, mission_id, subtask_id) validates the
//!    first-party correlation IDs. launcher.prepare(&request) only describes
//!    the destination and model expectations, without opening anything.
//! 4. Only after an operator-triggered action call launcher.launch(
//!    &request, OperatorApproval::ExplicitlyRequested). This enum is a trusted
//!    caller assertion, not an independently verified consent token.
//! 5. LaunchOutcome.status distinguishes a spawned process from a post-spawn
//!    uncertainty. Neither state proves navigation, sign-in, model selection,
//!    transmission of a message or creation of a conversation. Never retry
//!    automatically after an uncertain result.
//!
//! Start pages are an approved Gemini notebook at
//! https://gemini.google.com/notebook/<uuid> or an approved ChatGPT project at
//! https://chatgpt.com/g/g-p-<32 lowercase hex>[-slug]/project.
//! Corresponds to gateway/src/web-conversation-launch.mjs launchTarget;
//! this crate intentionally does NOT implement its send/receipt contract.
//!
//! Chrome uses argv with a fixed --user-data-dir pointing to the EXISTING,
//! private Bridge-managed profile for that provider. No --guest, profile
//! creation/deletion, profile import, content inspection, CDP, injected script,
//! automated click or direct network operation exists in this crate. Each
//! provider uses a distinct persistent directory and never the user's regular
//! Chrome profile. Chrome itself accesses the network to render the official
//! HTTPS page; it owns the profile data it creates. On Windows, the local CLI
//! must separately verify the private owner/DACL because Rust's portable
//! filesystem metadata cannot prove ACL privacy; this crate additionally
//! rejects non-directory paths, symlinks, reparse points and wrong layout.
//! Filesystem validation is repeated before each spawn; a hostile external
//! process that races directory replacement is not covered by a global lock.
//!
//! A successful spawn is NOT evidence that Chrome honored all flags or opened
//! the URL. The user retains normal responsibility for sign-in and interaction.

#[cfg(any(windows, target_os = "macos"))]
use std::env;
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const CHATGPT_PREFIX: &str = "https://chatgpt.com/g/";
const GEMINI_NOTEBOOK_PREFIX: &str = "https://gemini.google.com/notebook/";
const MAX_PROJECT_URL_BYTES: usize = 512;

/// Only the two product providers have a launch entry.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Provider {
    ChatGpt,
    Gemini,
}

/// Pre-provisioned, private, persistent browser profiles supplied only by the
/// LOCAL CLI after it validates the Bridge settings and (on Windows) their ACLs.
/// The launch request cannot choose or override these paths.
#[derive(Clone)]
pub struct LocalCliProfiles {
    chatgpt: PathBuf,
    gemini: PathBuf,
}

impl fmt::Debug for LocalCliProfiles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LocalCliProfiles(<private Bridge settings paths>)")
    }
}

impl LocalCliProfiles {
    /// Existing paths only. Expected layout under the same Bridge settings:
    /// .../AgentBridge/browser-profiles/chatgpt and .../gemini (or
    /// .../agent-bridge/browser-profiles/... on Unix).
    ///
    /// This constructor belongs in the trusted *local CLI configuration
    /// layer*, never in an MCP tool handler. CLI must additionally have
    /// verified Windows ownership/DACL privacy before calling it.
    pub fn from_local_cli(
        chatgpt: impl Into<PathBuf>,
        gemini: impl Into<PathBuf>,
    ) -> Result<Self> {
        let profiles = Self {
            chatgpt: chatgpt.into(),
            gemini: gemini.into(),
        };
        profiles.validate()?;
        Ok(profiles)
    }

    fn for_provider(&self, provider: Provider) -> &Path {
        match provider {
            Provider::ChatGpt => &self.chatgpt,
            Provider::Gemini => &self.gemini,
        }
    }

    fn validate(&self) -> Result<()> {
        let first = &self.chatgpt;
        let second = &self.gemini;
        let first_parent = first.parent().ok_or_else(invalid_profile_layout)?;
        let second_parent = second.parent().ok_or_else(invalid_profile_layout)?;
        if first == second
            || first_parent != second_parent
            || !matches_basename(first, "chatgpt")
            || !matches_basename(second, "gemini")
            || !matches_basename(first_parent, "browser-profiles")
        {
            return Err(invalid_profile_layout());
        }
        let settings = first_parent.parent().ok_or_else(invalid_profile_layout)?;
        validate_profile_path(first, settings, first_parent)?;
        validate_profile_path(second, settings, first_parent)?;
        Ok(())
    }
}

fn invalid_profile_layout() -> LaunchError {
    LaunchError::new(
        "INVALID_BRIDGE_PROFILE_LAYOUT",
        "Profiles must be separate existing chatgpt/gemini directories under the same Bridge settings/browser-profiles",
    )
}

fn matches_basename(path: &Path, name: &str) -> bool {
    let Some(actual) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    #[cfg(windows)]
    { actual.eq_ignore_ascii_case(name) }
    #[cfg(not(windows))]
    { actual == name }
}

fn validate_profile_path(path: &Path, settings: &Path, profiles_parent: &Path) -> Result<()> {
    let value = path.to_str().ok_or_else(|| LaunchError::new(
        "INVALID_BRIDGE_PROFILE_PATH", "Non-UTF8 profile directory path"
    ))?;
    if !path.is_absolute() || value.len() > 4096
        || value.is_empty() || value.chars().any(char::is_control)
    {
        return Err(LaunchError::new(
            "INVALID_BRIDGE_PROFILE_PATH", "Expected safe absolute profile directory path",
        ));
    }

    // A walk based on lstat/symlink_metadata checks every ancestor, not only
    // the final directory. Never canonicalize through a junction or symlink.
    let mut prefix = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::Prefix(p) => {
                #[cfg(windows)]
                if !matches!(p.kind(), std::path::Prefix::Disk(_)) {
                    return Err(LaunchError::new(
                        "UNSAFE_BRIDGE_PROFILE_PATH",
                        "UNC, device and verbatim paths are refused",
                    ));
                }
                prefix.push(p.as_os_str());
            }
            std::path::Component::RootDir => prefix.push(component.as_os_str()),
            std::path::Component::Normal(name) => prefix.push(name),
            std::path::Component::CurDir | std::path::Component::ParentDir => {
                return Err(LaunchError::new(
                    "UNSAFE_BRIDGE_PROFILE_PATH",
                    "Dot components and parent traversal are refused",
                ))
            }
        }
        // On Windows, "C:" is drive-relative; wait for the following
        // RootDir component to form "C:\\" before inspecting metadata.
        if !prefix.is_absolute() {
            continue;
        }
        let info = fs::symlink_metadata(&prefix).map_err(|_| LaunchError::new(
            "BRIDGE_PROFILE_UNAVAILABLE",
            "An existing Bridge profile directory or ancestor is unavailable",
        ))?;
        if !info.is_dir() || info.file_type().is_symlink() || is_windows_reparse(&info) {
            return Err(LaunchError::new(
                "UNSAFE_BRIDGE_PROFILE_PATH",
                "A profile directory or ancestor is linked, reparse or not a directory",
            ));
        }
        if prefix == settings || prefix == profiles_parent || prefix == path {
            ensure_private_directory(&info)?;
        }
    }
    Ok(())
}

#[cfg(windows)]
fn is_windows_reparse(info: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    info.file_attributes() & 0x0000_0400 != 0
}

#[cfg(not(windows))]
fn is_windows_reparse(_info: &fs::Metadata) -> bool { false }

#[cfg(unix)]
fn ensure_private_directory(info: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    // SAFETY: geteuid has no arguments and does not modify filesystem state.
    let uid = unsafe { libc::geteuid() };
    let mode = info.permissions().mode();
    if uid == 0 || info.uid() != uid || mode & 0o077 != 0 || mode & 0o700 != 0o700 {
        return Err(LaunchError::new(
            "BRIDGE_PROFILE_NOT_PRIVATE",
            "Bridge settings and provider directories must be owned by the unprivileged CLI user and mode 0700",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn ensure_private_directory(_info: &fs::Metadata) -> Result<()> {
    // ACL privacy is a trusted local-CLI precondition, not inferred from
    // Windows read-only attributes (which do NOT imply a private DACL).
    // This launcher checks existence and reparse safety; no remote caller can
    // supply profile paths.
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn ensure_private_directory(_info: &fs::Metadata) -> Result<()> {
    Err(LaunchError::new("UNSUPPORTED_PLATFORM", "Unsupported profile platform"))
}

/// This must be supplied by a trusted operator-facing application only after
/// a *new, explicit* operator request; it does not attest consent by itself.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum OperatorApproval {
    ExplicitlyRequested,
    NotApproved,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LaunchError {
    pub code: &'static str,
    pub message: String,
}

impl LaunchError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }
}

impl fmt::Display for LaunchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}
impl Error for LaunchError {}

pub type Result<T> = std::result::Result<T, LaunchError>;

/// A typed request never carries an arbitrary destination, executable or flag.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LaunchRequest {
    provider: Provider,
    mission_id: String,
    subtask_id: String,
}

impl LaunchRequest {
    pub fn new(
        provider: Provider,
        mission_id: impl Into<String>,
        subtask_id: impl Into<String>,
    ) -> Result<Self> {
        let mission_id = mission_id.into();
        let subtask_id = subtask_id.into();
        if !valid_id(&mission_id, "mis_") || !valid_id(&subtask_id, "sub_") {
            return Err(LaunchError::new(
                "INVALID_LAUNCH_REQUEST",
                "Expected mis_ and sub_ identifiers with exactly 32 lowercase hex digits",
            ));
        }
        Ok(Self { provider, mission_id, subtask_id })
    }

    pub fn provider(&self) -> Provider { self.provider }
    pub fn mission_id(&self) -> &str { &self.mission_id }
    pub fn subtask_id(&self) -> &str { &self.subtask_id }
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ChatGptProject {
    id: String,
    canonical_url: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LaunchTarget {
    pub provider: Provider,
    pub mission_id: String,
    pub subtask_id: String,
    pub start_url: String,
    pub project_id: Option<String>,
    /// Product expectation only; this launcher does not select a model.
    pub selected_model: &'static str,
    /// Product expectation only; this launcher does not select thinking level.
    pub thinking_level: Option<&'static str>,
}

/// SpawnAcceptedUnverified is explicitly NOT a navigation receipt.
/// UncertainAfterSpawn cannot safely be retried without operator inspection.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum LaunchStatus {
    SpawnAcceptedUnverified,
    UncertainAfterSpawn,
}

#[derive(Debug)]
pub struct LaunchOutcome {
    pub status: LaunchStatus,
    pub target: LaunchTarget,
    /// PID of the immediate spawned process, not necessarily the eventual GUI.
    pub initial_process_id: u32,
    /// Status explanation; never includes local persistent profile paths.
    pub detail: String,
}

#[derive(Debug)]
pub struct ChromeLauncher {
    chrome: PathBuf,
    approved_project: Option<ChatGptProject>,
    approved_notebook: Option<String>,
    profiles: LocalCliProfiles,
}

impl ChromeLauncher {
    /// Discover local Chrome at fixed conventional installation locations.
    /// Does not start Chrome and does not open any profile data.
    pub fn discover(
        approved_collection_url: Option<&str>,
        profiles: LocalCliProfiles,
    ) -> Result<Self> {
        let (approved_project, approved_notebook) = match approved_collection_url {
            Some(raw) if raw.starts_with(GEMINI_NOTEBOOK_PREFIX) =>
                (None, Some(parse_approved_gemini_notebook(raw)?)),
            Some(raw) => (Some(parse_approved_chatgpt_project(raw)?), None),
            None => (None, None),
        };
        profiles.validate()?;
        let chrome = find_installed_chrome()?;
        Ok(Self { chrome, approved_project, approved_notebook, profiles })
    }

    pub fn chrome_executable(&self) -> &Path { &self.chrome }

    /// Pure destination selection, with no browser, filesystem write or network.
    pub fn prepare(&self, request: &LaunchRequest) -> Result<LaunchTarget> {
        let (start_url, project_id, selected_model, thinking_level) =
            match request.provider {
                Provider::ChatGpt => {
                    let project = self.approved_project.as_ref().ok_or_else(|| {
                        LaunchError::new(
                            "CHATGPT_PROJECT_CONFIGURATION_REQUIRED",
                            "An approved ChatGPT project URL is required",
                        )
                    })?;
                    (
                        project.canonical_url.clone(),
                        Some(project.id.clone()),
                        "Pro",
                        None,
                    )
                }
                Provider::Gemini => {
                    let id = self.approved_notebook.as_ref().ok_or_else(|| LaunchError::new(
                        "GEMINI_NOTEBOOK_CONFIGURATION_REQUIRED", "An approved Gemini notebook URL is required",
                    ))?;
                    (format!("{GEMINI_NOTEBOOK_PREFIX}{id}"), Some(id.clone()), "Neon", Some("High"))
                }
            };
        Ok(LaunchTarget {
            provider: request.provider,
            mission_id: request.mission_id.clone(),
            subtask_id: request.subtask_id.clone(),
            start_url,
            project_id,
            selected_model,
            thinking_level,
        })
    }

    /// The only method which starts Chrome. No hidden consent or automatic
    /// retries. Argument order is fixed and the URL is an internally validated
    /// LaunchTarget, not caller-provided text.
    pub fn launch(
        &self,
        request: &LaunchRequest,
        approval: OperatorApproval,
    ) -> Result<LaunchOutcome> {
        if approval != OperatorApproval::ExplicitlyRequested {
            return Err(LaunchError::new(
                "OPERATOR_APPROVAL_REQUIRED",
                "This launch requires an explicit new operator request",
            ));
        }
        let target = self.prepare(request)?;

        // Fail closed if the installed executable disappeared or changed type
        // after discovery. Never interpret a supplied path as a shell command.
        if !is_allowed_chrome_binary(&self.chrome) {
            return Err(LaunchError::new(
                "CHROME_INSTALLATION_CHANGED",
                "Installed Chrome binary is no longer an allowed regular executable",
            ));
        }

        // Revalidate the two already-created private Bridge profile directory
        // locations immediately before launch. The trusted LOCAL CLI is
        // responsible for provisioning and Windows owner/DACL verification.
        // This method never reads any profile file or directory entries.
        self.profiles.validate()?;
        let profile = self.profiles.for_provider(request.provider);
        let profile_arg = format!("--user-data-dir={}", path_as_argument(profile)?);
        let mut process = Command::new(&self.chrome);
        process
            .arg(profile_arg)
            .arg("--no-first-run")
            .arg("--no-default-browser-check")
            .arg("--new-window")
            .arg(&target.start_url)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // Don't permit inherited wrapper-specific Chrome extra flags.
        for name in [
            "CHROME_FLAGS",
            "CHROMIUM_FLAGS",
            "GOOGLE_CHROME_FLAGS",
            "CHROME_EXTRA_ARGS",
            "CHROME_USER_DATA_DIR",
        ] {
            process.env_remove(name);
        }

        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            // CREATE_NO_WINDOW: a GUI Chrome spawn must not open a console.
            // No cmd.exe, PowerShell, ShellExecute or shell quoting is used.
            process.creation_flags(0x0800_0000);
        }

        // Before spawn an error is definitive. After spawn NEVER automatically
        // retry: Chrome may have accepted or delegated the request.
        let mut child = process
            .spawn()
            .map_err(|e| LaunchError::new("CHROME_SPAWN_FAILED", e.to_string()))?;
        let initial_process_id = child.id();

        // Chrome owns its persistent Bridge profile; no create, cleanup,
        // content read or import is performed by this launcher.
        let (status, detail) = match child.try_wait() {
            Ok(None) => (
                LaunchStatus::SpawnAcceptedUnverified,
                "OS accepted creation of a Chrome process. Page, login, \
                 selected model and conversation are not observed."
                    .to_owned(),
            ),
            Ok(Some(code)) => (
                LaunchStatus::UncertainAfterSpawn,
                format!(
                    "Chrome's initial process exited immediately ({code}); \
                     it may have delegated to another process. Inspect before retrying."
                ),
            ),
            Err(error) => (
                LaunchStatus::UncertainAfterSpawn,
                format!(
                    "Chrome process was created but post-spawn observation failed: {error}; \
                     do not automatically retry."
                ),
            ),
        };

        Ok(LaunchOutcome {
            status,
            target,
            initial_process_id,
            detail,
        })
    }
}

fn valid_id(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|suffix| {
        suffix.len() == 32 &&
        suffix.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    })
}

fn parse_approved_gemini_notebook(raw: &str) -> Result<String> {
    let id = raw.strip_suffix('/').unwrap_or(raw).strip_prefix(GEMINI_NOTEBOOK_PREFIX);
    let valid = id.filter(|id| id.len() == 36 && id.bytes().enumerate().all(|(index, byte)| {
        if matches!(index, 8 | 13 | 18 | 23) { byte == b'-' }
        else { byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte) }
    }));
    valid.map(str::to_owned).ok_or_else(|| LaunchError::new(
        "INVALID_GEMINI_NOTEBOOK_URL", "Expected an official Gemini notebook URL with a lowercase UUID",
    ))
}

fn parse_approved_chatgpt_project(raw: &str) -> Result<ChatGptProject> {
    // Unlike a general URL parser, the first-party launch contract only
    // allows this exact official origin, canonical path shape and no extras.
    // Reject percent-encoding, query, fragment, credentials, port and slash
    // tricks rather than normalizing untrusted input into an allowed origin.
    if raw.len() > MAX_PROJECT_URL_BYTES || !raw.is_ascii() {
        return Err(LaunchError::new("INVALID_CHATGPT_PROJECT_URL",
            "Project URL exceeds limit or contains non-ASCII characters"));
    }
    let Some(rest) = raw.strip_prefix(CHATGPT_PREFIX) else {
        return Err(LaunchError::new(
            "INVALID_CHATGPT_PROJECT_URL",
            "Approved destination must use the official HTTPS ChatGPT project origin",
        ));
    };
    let path = rest.strip_suffix('/').unwrap_or(rest);
    let Some((project, terminal)) = path.split_once('/') else {
        return Err(LaunchError::new(
            "INVALID_CHATGPT_PROJECT_URL", "Expected /g/<project>/project path",
        ));
    };
    if terminal != "project" {
        return Err(LaunchError::new(
            "INVALID_CHATGPT_PROJECT_URL", "Unexpected path component or URL parameters",
        ));
    }
    let Some(after_prefix) = project.strip_prefix("g-p-") else {
        return Err(LaunchError::new("INVALID_CHATGPT_PROJECT_URL",
            "Expected g-p- project identifier"));
    };
    let Some(hex) = after_prefix.get(..32) else {
        return Err(LaunchError::new("INVALID_CHATGPT_PROJECT_URL",
            "Project ID must contain 32 lowercase hex digits"));
    };
    if !hex.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
        return Err(LaunchError::new("INVALID_CHATGPT_PROJECT_URL",
            "Project ID must contain 32 lowercase hex digits"));
    }
    let extra = &after_prefix[32..];
    if !extra.is_empty() {
        let Some(slug) = extra.strip_prefix('-') else {
            return Err(LaunchError::new("INVALID_CHATGPT_PROJECT_URL",
                "Unexpected project suffix"));
        };
        if slug.is_empty() || !slug.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-') {
            return Err(LaunchError::new("INVALID_CHATGPT_PROJECT_URL",
                "Project suffix contains invalid characters"));
        }
    }
    Ok(ChatGptProject {
        id: format!("g-p-{hex}"),
        canonical_url: format!("{CHATGPT_PREFIX}{project}/project"),
    })
}

fn path_as_argument(path: &Path) -> Result<String> {
    let text = path
        .to_str()
        .ok_or_else(|| LaunchError::new(
            "BRIDGE_PROFILE_UNAVAILABLE",
            "Chrome profile directory path is not valid UTF-8",
        ))?;
    if text.is_empty() || text.chars().any(char::is_control) {
        return Err(LaunchError::new(
            "BRIDGE_PROFILE_UNAVAILABLE",
            "Chrome profile directory path is not safe as a single argument",
        ));
    }
    Ok(text.to_owned())
}

/// Returns only known Chrome installation locations. Does not use PATH,
/// shell aliases, xdg-open, macOS open, or a browser supplied by a request.
fn chrome_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    #[cfg(windows)]
    {
        for root in ["PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"] {
            if let Some(dir) = env::var_os(root) {
                candidates.push(
                    PathBuf::from(dir).join("Google/Chrome/Application/chrome.exe")
                );
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        candidates.push(
            PathBuf::from("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
        );
        if let Some(home) = env::var_os("HOME") {
            candidates.push(
                PathBuf::from(home).join(
                    "Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
                )
            );
        }
    }

    #[cfg(target_os = "linux")]
    {
        candidates.push(PathBuf::from("/opt/google/chrome/chrome"));
        candidates.push(PathBuf::from("/usr/lib/google-chrome/chrome"));
        candidates.push(PathBuf::from("/usr/lib64/google-chrome/chrome"));
    }

    candidates
}

fn is_allowed_chrome_binary(path: &Path) -> bool {
    if !path.is_absolute() {
        return false;
    }
    let Some(filename) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    #[cfg(windows)]
    if !filename.eq_ignore_ascii_case("chrome.exe") {
        return false;
    }
    #[cfg(target_os = "macos")]
    if filename != "Google Chrome" {
        return false;
    }
    #[cfg(target_os = "linux")]
    if filename != "chrome" {
        return false;
    }

    let Ok(meta) = fs::symlink_metadata(path) else {
        return false;
    };
    if !meta.is_file() || meta.file_type().is_symlink() {
        return false;
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        // Reject final reparse-point executables as well as file symlinks.
        if meta.file_attributes() & 0x0000_0400 != 0 {
            return false;
        }
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o111 == 0 {
            return false;
        }
    }

    true
}

fn find_installed_chrome() -> Result<PathBuf> {
    for path in chrome_candidates() {
        if is_allowed_chrome_binary(&path) {
            return Ok(path);
        }
    }
    Err(LaunchError::new(
        "CHROME_UNAVAILABLE",
        "Installed Google Chrome was not found at supported local installation paths",
    ))
}
