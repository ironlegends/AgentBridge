// Copyright 2026 agent-bridge contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Local command decision core for `agent-bridge`.
//!
//! Policy model:
//! - Predefined approved commands supplied exclusively by the local operator
//!   (exact canonical executable path, pinned SHA-256 digest and file identity,
//!   exact literal argument array, exact canonical working directory within the
//!   canonical workspace).
//! - Any other valid command is queued for a single short-lived local operator
//!   confirmation bound to the exact displayed values, consumed atomically
//!   once, and never promoted to a permanent permission.
//! - Web callers can only submit requests, inspect their own request status,
//!   and cancel their own pending/unconsumed requests; local approval APIs live
//!   on a separate capability handle that is never exposed as an MCP tool.
//! - This crate never spawns processes, invokes shells, performs network I/O,
//!   or logs command contents.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, UNIX_EPOCH};

/// Hard upper bound on how long a pending confirmation may remain open.
pub const MAX_PENDING_TTL: Duration = Duration::from_secs(300);

/// Hard upper bound on how long an approved unconsumed request may wait.
pub const MAX_APPROVED_TTL: Duration = Duration::from_secs(120);

/// Default short TTL for local confirmation requests.
pub const DEFAULT_PENDING_TTL: Duration = Duration::from_secs(60);

/// Default short TTL for approved requests awaiting atomic consumption.
pub const DEFAULT_APPROVED_TTL: Duration = Duration::from_secs(30);

const READ_BUFFER_BYTES: usize = 64 * 1024;
const MAX_REQUESTER_ID_BYTES: usize = 128;
const MAX_RULE_ID_BYTES: usize = 128;
const MAX_REASON_CODE_BYTES: usize = 64;
const CONFIRMATION_DOMAIN_TAG: &[u8] = b"agent-bridge-commands:confirm:v1";

/// Shell interpreters accept a second command language as input. Their
/// per-request local confirmation may never be replaced by an approval of
/// the executable alone.
const SHELL_EXECUTABLES: &[&str] = &[
    "sh",
    "sh.exe",
    "bash",
    "bash.exe",
    "dash",
    "zsh",
    "fish",
    "ksh",
    "csh",
    "tcsh",
    "ash",
    "busybox",
    "busybox.exe",
    "cmd",
    "cmd.exe",
    "command.com",
    "powershell",
    "powershell.exe",
    "pwsh",
    "pwsh.exe",
    "wsl",
    "wsl.exe",
    "wscript",
    "wscript.exe",
    "cscript",
    "cscript.exe",
    "mshta",
    "mshta.exe",
];

/// Cryptographic SHA-256 digest serialized as 64 lowercase hexadecimal digits.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_hex(hex: &str) -> Result<Self, CommandError> {
        let bytes = hex.as_bytes();
        if bytes.len() != 64 {
            return Err(CommandError::InvalidDigest);
        }
        let mut out = [0u8; 32];
        for (i, chunk) in bytes.chunks_exact(2).enumerate() {
            let hi = decode_hex_nibble(chunk[0]).ok_or(CommandError::InvalidDigest)?;
            let lo = decode_hex_nibble(chunk[1]).ok_or(CommandError::InvalidDigest)?;
            out[i] = (hi << 4) | lo;
        }
        Ok(Self(out))
    }

    pub fn to_hex(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(64);
        for &b in &self.0 {
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0f) as usize] as char);
        }
        out
    }

    pub fn ct_eq(&self, other: &Self) -> bool {
        ct_eq_32(&self.0, &other.0)
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sha256Digest({})", self.to_hex())
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::from_hex(&s).map_err(|_| serde::de::Error::custom("invalid 64-char hex SHA-256"))
    }
}

/// Unpredictable 128-bit identifier for a single command decision request.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct RequestId(String);

impl RequestId {
    fn generate() -> Result<Self, CommandError> {
        let mut raw = [0u8; 16];
        getrandom::getrandom(&mut raw).map_err(|_| CommandError::EntropyUnavailable)?;
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(32);
        for b in raw {
            s.push(HEX[(b >> 4) as usize] as char);
            s.push(HEX[(b & 0x0f) as usize] as char);
        }
        Ok(Self(s))
    }

    pub fn parse(raw: &str) -> Result<Self, CommandError> {
        if raw.len() != 32 || !raw.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(CommandError::InvalidRequestId);
        }
        Ok(Self(raw.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RequestId({})", self.0)
    }
}

impl Serialize for RequestId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for RequestId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(|_| serde::de::Error::custom("invalid request id"))
    }
}

/// Isolated caller identity (for example, a Web session handle).
///
/// Requesters can only observe and cancel requests created with their own
/// `RequesterContext`.
#[derive(Clone, PartialEq, Eq, Hash, Serialize)]
pub struct RequesterContext {
    id: String,
}

impl RequesterContext {
    pub fn new(id: impl Into<String>) -> Result<Self, CommandError> {
        let id = id.into();
        if id.is_empty()
            || id.len() > MAX_REQUESTER_ID_BYTES
            || !id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b':' | b'.'))
        {
            return Err(CommandError::InvalidRequester);
        }
        Ok(Self { id })
    }

    pub fn as_str(&self) -> &str {
        &self.id
    }
}

impl fmt::Debug for RequesterContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RequesterContext(len={})", self.id.len())
    }
}

/// OS file identity attributes captured alongside the cryptographic digest to
/// detect executable replacement or metadata tampering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutableIdentity {
    pub file_len: u64,
    pub modified_unix_nanos: Option<u128>,
    pub unix_dev: Option<u64>,
    pub unix_ino: Option<u64>,
    pub windows_creation_time: Option<u64>,
    pub windows_last_write_time: Option<u64>,
    pub windows_file_attributes: Option<u32>,
}

/// Verified executable pinned by canonical path, SHA-256 digest, and OS identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedExecutable {
    pub canonical_path: PathBuf,
    pub sha256: Sha256Digest,
    pub identity: ExecutableIdentity,
}

/// Incoming command specification supplied by a caller.
///
/// Debug output intentionally redacts argument values to avoid leaking secrets.
#[derive(Clone, PartialEq, Eq, Deserialize)]
pub struct CommandRequest {
    pub executable: PathBuf,
    pub args: Vec<String>,
    pub cwd: PathBuf,
}

impl CommandRequest {
    pub fn new(executable: impl Into<PathBuf>, args: Vec<String>, cwd: impl Into<PathBuf>) -> Self {
        Self {
            executable: executable.into(),
            args,
            cwd: cwd.into(),
        }
    }
}

impl fmt::Debug for CommandRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommandRequest")
            .field("executable", &self.executable)
            .field("args_count", &self.args.len())
            .field("cwd", &self.cwd)
            .finish()
    }
}

/// Canonicalized and verified command bound to a pinned executable and
/// canonical working directory inside the workspace.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedCommand {
    pub executable: PinnedExecutable,
    pub args: Vec<String>,
    pub cwd: PathBuf,
}

impl fmt::Debug for VerifiedCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedCommand")
            .field("executable_path", &self.executable.canonical_path)
            .field("executable_sha256", &self.executable.sha256)
            .field("args_count", &self.args.len())
            .field("cwd", &self.cwd)
            .finish()
    }
}

/// Resource, concurrency, retention, and TTL bounds enforced by the engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineLimits {
    pub max_args: usize,
    pub max_arg_bytes: usize,
    pub max_total_args_bytes: usize,
    pub max_path_bytes: usize,
    pub max_pending_global: usize,
    pub max_pending_per_requester: usize,
    pub max_concurrent_executions: usize,
    pub max_retained_records: usize,
    pub max_result_summary_bytes: usize,
    pub pending_ttl: Duration,
    pub approved_ttl: Duration,
}

impl Default for EngineLimits {
    fn default() -> Self {
        Self {
            max_args: 64,
            max_arg_bytes: 4 * 1024,
            max_total_args_bytes: 32 * 1024,
            max_path_bytes: 4 * 1024,
            max_pending_global: 32,
            max_pending_per_requester: 8,
            max_concurrent_executions: 4,
            max_retained_records: 256,
            max_result_summary_bytes: 4 * 1024,
            pending_ttl: DEFAULT_PENDING_TTL,
            approved_ttl: DEFAULT_APPROVED_TTL,
        }
    }
}

impl EngineLimits {
    fn normalized(mut self) -> Self {
        self.max_args = self.max_args.max(1);
        self.max_arg_bytes = self.max_arg_bytes.max(1);
        self.max_total_args_bytes = self.max_total_args_bytes.max(self.max_arg_bytes);
        self.max_path_bytes = self.max_path_bytes.max(64);
        self.max_pending_global = self.max_pending_global.max(1);
        self.max_pending_per_requester = self
            .max_pending_per_requester
            .max(1)
            .min(self.max_pending_global);
        self.max_concurrent_executions = self.max_concurrent_executions.max(1);
        let min_retained = self
            .max_pending_global
            .saturating_add(self.max_concurrent_executions)
            .saturating_add(16);
        self.max_retained_records = self.max_retained_records.max(min_retained);
        self.max_result_summary_bytes = self.max_result_summary_bytes.max(64);
        self.pending_ttl = clamp_duration(self.pending_ttl, Duration::from_secs(1), MAX_PENDING_TTL);
        self.approved_ttl =
            clamp_duration(self.approved_ttl, Duration::from_secs(1), MAX_APPROVED_TTL);
        self
    }
}

/// Local filesystem/environment verifier used to pin executables and
/// canonicalize directories without executing commands.
pub trait EnvironmentVerifier: Send + Sync {
    fn verify_executable(&self, path: &Path) -> Result<PinnedExecutable, CommandError>;
    fn canonicalize_directory(&self, path: &Path) -> Result<PathBuf, CommandError>;
}

/// Default local filesystem verifier computing streaming SHA-256 digests and
/// OS file identity metadata.
#[derive(Debug, Default, Clone, Copy)]
pub struct FsEnvironmentVerifier;

impl EnvironmentVerifier for FsEnvironmentVerifier {
    fn verify_executable(&self, path: &Path) -> Result<PinnedExecutable, CommandError> {
        let canonical = fs::canonicalize(path).map_err(|_| CommandError::ExecutableNotFound)?;
        ensure_valid_utf8_path(&canonical)?;

        let meta_before = fs::metadata(&canonical).map_err(|_| CommandError::ExecutableNotFound)?;
        if !meta_before.is_file() {
            return Err(CommandError::ExecutableNotRegularFile);
        }
        const MAX_IMAGE_BYTES: u64 = 512 * 1024 * 1024;
        if meta_before.len() > MAX_IMAGE_BYTES { return Err(CommandError::ExecutableUnreadable); }
        let identity_before = capture_file_identity(&meta_before);

        let file = File::open(&canonical).map_err(|_| CommandError::ExecutableUnreadable)?;
        let handle_meta = file.metadata().map_err(|_| CommandError::ExecutableUnreadable)?;
        if !handle_meta.is_file() || capture_file_identity(&handle_meta) != identity_before {
            return Err(CommandError::ExecutablePinMismatch);
        }
        let mut file = file.take(MAX_IMAGE_BYTES + 1);
        let mut hasher = Sha256::new();
        let mut buf = [0u8; READ_BUFFER_BYTES];
        loop {
            let n = file
                .read(&mut buf)
                .map_err(|_| CommandError::ExecutableUnreadable)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }

        if file.limit() == 0 { return Err(CommandError::ExecutableUnreadable); }
        let meta_after = fs::metadata(&canonical).map_err(|_| CommandError::ExecutableUnreadable)?;
        if !meta_after.is_file() {
            return Err(CommandError::ExecutableNotRegularFile);
        }
        let identity_after = capture_file_identity(&meta_after);
        if identity_before != identity_after {
            return Err(CommandError::ExecutablePinMismatch);
        }

        let digest_bytes: [u8; 32] = hasher.finalize().into();
        Ok(PinnedExecutable {
            canonical_path: canonical,
            sha256: Sha256Digest::from_bytes(digest_bytes),
            identity: identity_after,
        })
    }

    fn canonicalize_directory(&self, path: &Path) -> Result<PathBuf, CommandError> {
        let canonical = fs::canonicalize(path).map_err(|_| CommandError::InvalidWorkingDirectory)?;
        ensure_valid_utf8_path(&canonical)?;
        let meta = fs::metadata(&canonical).map_err(|_| CommandError::InvalidWorkingDirectory)?;
        if !meta.is_dir() {
            return Err(CommandError::InvalidWorkingDirectory);
        }
        Ok(canonical)
    }
}

/// Operator-defined exact predefined rule. No partial matches or wildcards.
#[derive(Clone, PartialEq, Eq)]
pub struct PredefinedCommandRule {
    pub id: String,
    pub executable: PinnedExecutable,
    pub args: Vec<String>,
    pub cwd: PathBuf,
}

impl fmt::Debug for PredefinedCommandRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PredefinedCommandRule")
            .field("id", &self.id)
            .field("executable_path", &self.executable.canonical_path)
            .field("executable_sha256", &self.executable.sha256)
            .field("args_count", &self.args.len())
            .field("cwd", &self.cwd)
            .finish()
    }
}

/// Immutable policy authored exclusively by the local operator.
#[derive(Debug, Clone)]
pub struct OperatorPolicy {
    canonical_workspace_root: PathBuf,
    predefined_rules: Vec<PredefinedCommandRule>,
}

impl OperatorPolicy {
    pub fn builder(workspace_root: impl Into<PathBuf>) -> OperatorPolicyBuilder {
        OperatorPolicyBuilder {
            workspace_root: workspace_root.into(),
            rules: Vec::new(),
        }
    }

    pub fn workspace_root(&self) -> &Path {
        &self.canonical_workspace_root
    }

    pub fn predefined_rules(&self) -> &[PredefinedCommandRule] {
        &self.predefined_rules
    }

    fn check_executable_pin_integrity(&self, exe: &PinnedExecutable) -> Result<(), CommandError> {
        for rule in &self.predefined_rules {
            if rule.executable.canonical_path == exe.canonical_path
                && (!rule.executable.sha256.ct_eq(&exe.sha256)
                    || rule.executable.identity != exe.identity)
            {
                return Err(CommandError::ExecutablePinMismatch);
            }
        }
        Ok(())
    }

    fn match_predefined(&self, cmd: &VerifiedCommand) -> Option<&PredefinedCommandRule> {
        self.predefined_rules.iter().find(|rule| {
            rule.executable.canonical_path == cmd.executable.canonical_path
                && rule.executable.sha256.ct_eq(&cmd.executable.sha256)
                && rule.executable.identity == cmd.executable.identity
                && rule.cwd == cmd.cwd
                && rule.args == cmd.args
        })
    }
}

struct PendingRuleSpec {
    id: String,
    executable: PathBuf,
    expected_sha256: Sha256Digest,
    expected_identity: Option<ExecutableIdentity>,
    args: Vec<String>,
    cwd: PathBuf,
}

/// Local-operator builder for [`OperatorPolicy`].
pub struct OperatorPolicyBuilder {
    workspace_root: PathBuf,
    rules: Vec<PendingRuleSpec>,
}

impl OperatorPolicyBuilder {
    /// Adds a predefined rule whose executable will be verified against
    /// `expected_sha256` on disk and pinned with its current OS identity.
    pub fn add_predefined(
        mut self,
        id: impl Into<String>,
        executable: impl Into<PathBuf>,
        expected_sha256: Sha256Digest,
        args: Vec<String>,
        cwd: impl Into<PathBuf>,
    ) -> Self {
        self.rules.push(PendingRuleSpec {
            id: id.into(),
            executable: executable.into(),
            expected_sha256,
            expected_identity: None,
            args,
            cwd: cwd.into(),
        });
        self
    }

    /// Adds a predefined rule pinned with both an explicit SHA-256 digest and
    /// an explicit expected [`ExecutableIdentity`].
    pub fn add_predefined_with_identity(
        mut self,
        id: impl Into<String>,
        executable: impl Into<PathBuf>,
        expected_sha256: Sha256Digest,
        expected_identity: ExecutableIdentity,
        args: Vec<String>,
        cwd: impl Into<PathBuf>,
    ) -> Self {
        self.rules.push(PendingRuleSpec {
            id: id.into(),
            executable: executable.into(),
            expected_sha256,
            expected_identity: Some(expected_identity),
            args,
            cwd: cwd.into(),
        });
        self
    }

    /// Validates the workspace root and every predefined rule against
    /// `verifier` and `limits`, returning an immutable [`OperatorPolicy`].
    pub fn build(
        self,
        verifier: &dyn EnvironmentVerifier,
        limits: &EngineLimits,
    ) -> Result<OperatorPolicy, CommandError> {
        let limits = limits.clone().normalized();
        validate_raw_path(&self.workspace_root, limits.max_path_bytes)?;
        let canonical_workspace_root = verifier.canonicalize_directory(&self.workspace_root)?;

        let mut seen_ids = HashSet::with_capacity(self.rules.len());
        let mut pinned_by_path: HashMap<PathBuf, (Sha256Digest, ExecutableIdentity)> =
            HashMap::new();
        let mut predefined_rules = Vec::with_capacity(self.rules.len());

        for spec in self.rules {
            validate_rule_id(&spec.id)?;
            if !seen_ids.insert(spec.id.clone()) {
                return Err(CommandError::InvalidPolicy);
            }

            validate_raw_path(&spec.executable, limits.max_path_bytes)?;
            validate_not_shell_executable(&spec.executable)?;
            validate_raw_path(&spec.cwd, limits.max_path_bytes)?;
            validate_args(&spec.args, &limits)?;

            let pinned = verifier.verify_executable(&spec.executable)?;
            validate_not_shell_executable(&pinned.canonical_path)?;
            if !pinned.sha256.ct_eq(&spec.expected_sha256) {
                return Err(CommandError::ExecutablePinMismatch);
            }
            if let Some(expected_id) = spec.expected_identity {
                if pinned.identity != expected_id {
                    return Err(CommandError::ExecutablePinMismatch);
                }
            }

            let canonical_cwd = verifier.canonicalize_directory(&spec.cwd)?;
            if !canonical_cwd.starts_with(&canonical_workspace_root) {
                return Err(CommandError::WorkingDirectoryOutsideWorkspace);
            }

            if let Some((prev_sha, prev_id)) = pinned_by_path.get(&pinned.canonical_path) {
                if !prev_sha.ct_eq(&pinned.sha256) || prev_id != &pinned.identity {
                    return Err(CommandError::ExecutablePinMismatch);
                }
            } else {
                pinned_by_path.insert(
                    pinned.canonical_path.clone(),
                    (pinned.sha256, pinned.identity.clone()),
                );
            }

            predefined_rules.push(PredefinedCommandRule {
                id: spec.id,
                executable: pinned,
                args: spec.args,
                cwd: canonical_cwd,
            });
        }

        Ok(OperatorPolicy {
            canonical_workspace_root,
            predefined_rules,
        })
    }
}

/// Result returned to a requester after submitting a command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum SubmissionOutcome {
    /// Matched an exact operator-predefined rule; ready for single consumption.
    PredefinedApproved {
        request_id: RequestId,
        rule_id: String,
    },
    /// Queued for a single short-lived local operator confirmation.
    PendingLocalConfirmation {
        request_id: RequestId,
        expires_in_secs: u64,
    },
}

/// Exact command details displayed to the local operator for confirmation.
///
/// Approving requires echoing back `confirmation_digest`, which binds the
/// approval to every displayed field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PendingApprovalView {
    pub request_id: RequestId,
    pub requester_id: String,
    pub executable_path: String,
    pub executable_sha256: Sha256Digest,
    pub executable_identity: ExecutableIdentity,
    pub args: Vec<String>,
    pub cwd: String,
    pub expires_in_secs: u64,
    pub confirmation_digest: Sha256Digest,
}

/// Summary returned to the local operator upon approving a pending request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApprovedSummary {
    pub request_id: RequestId,
    pub confirmation_digest: Sha256Digest,
    pub expires_in_secs: u64,
}

/// Public status snapshot returned to a requester (for its own requests) or
/// to the local operator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RequestStatusView {
    PendingLocalConfirmation {
        request_id: RequestId,
        expires_in_secs: u64,
    },
    Approved {
        request_id: RequestId,
        origin: ApprovalOrigin,
        expires_in_secs: u64,
    },
    InFlight {
        request_id: RequestId,
    },
    Completed {
        request_id: RequestId,
        exit_code: i32,
        #[serde(skip_serializing_if = "Option::is_none")]
        summary: Option<String>,
    },
    FailedBeforeStart {
        request_id: RequestId,
        reason_code: String,
    },
    Uncertain {
        request_id: RequestId,
        reason_code: String,
        replay_forbidden: bool,
    },
    Denied {
        request_id: RequestId,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason_code: Option<String>,
    },
    Cancelled {
        request_id: RequestId,
    },
    Expired {
        request_id: RequestId,
    },
}

/// Provenance of a single-use approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ApprovalOrigin {
    Predefined { rule_id: String },
    LocalConfirmation { confirmation_digest: Sha256Digest },
}

/// Final outcome reported by the local executor after consuming an
/// [`ExecutionPermit`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionOutcome {
    /// Process ran and exited cleanly with a known exit code.
    Completed {
        exit_code: i32,
        summary: Option<String>,
    },
    /// Executor definitively failed before launching the process.
    FailedBeforeStart { reason_code: String },
    /// Execution state is uncertain (timeout, lost handle, crash, disconnect);
    /// permanently forbids replay.
    Uncertain { reason_code: String },
}

/// Non-Clone, single-use execution authorization returned by
/// [`ExecutionGate::consume`].
///
/// Dropping an [`ExecutionPermit`] without calling [`ExecutionGate::finish`]
/// automatically records the request as `Uncertain` with `replay_forbidden = true`
/// and releases its concurrency slot.
pub struct ExecutionPermit {
    request_id: RequestId,
    command: VerifiedCommand,
    inner: Arc<EngineInner>,
    finished: bool,
}

impl ExecutionPermit {
    pub fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    pub fn command(&self) -> &VerifiedCommand {
        &self.command
    }
}

impl fmt::Debug for ExecutionPermit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExecutionPermit")
            .field("request_id", &self.request_id)
            .field("command", &self.command)
            .finish()
    }
}

impl Drop for ExecutionPermit {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let mut state = lock_state(&self.inner.state);
        state.active_executions = state.active_executions.saturating_sub(1);
        if let Some(record) = state.records.get_mut(&self.request_id) {
            record.state = RecordState::Uncertain {
                reason_code: "execution_permit_dropped".to_string(),
            };
        }
    }
}

/// Non-leaking error codes emitted by the command decision core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandError {
    InvalidPolicy,
    InvalidRequester,
    InvalidRequestId,
    InvalidDigest,
    InvalidPath,
    PathNotAbsolute,
    PathTraversalNotAllowed,
    PathTooLong,
    ShellExecutableForbidden,
    ExecutableNotFound,
    ExecutableNotRegularFile,
    ExecutableUnreadable,
    ExecutablePinMismatch,
    InvalidWorkingDirectory,
    WorkingDirectoryOutsideWorkspace,
    TooManyArguments,
    ArgumentTooLarge,
    TotalArgumentsTooLarge,
    InvalidArgument,
    InvalidReasonCode,
    SummaryTooLarge,
    PendingLimitReached,
    ConcurrencyLimitReached,
    EntropyUnavailable,
    NotFound,
    NotPending,
    NotApproved,
    NotConsumable,
    NotCancellable,
    AlreadyInFlight,
    ConfirmationMismatch,
    Expired,
    ReplayForbidden,
}

impl fmt::Display for CommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::InvalidPolicy => "invalid operator command policy",
            Self::InvalidRequester => "invalid requester context identifier",
            Self::InvalidRequestId => "invalid command request identifier",
            Self::InvalidDigest => "invalid SHA-256 digest",
            Self::InvalidPath => "invalid path",
            Self::PathNotAbsolute => "path must be absolute",
            Self::PathTraversalNotAllowed => "path must not contain parent directory segments",
            Self::PathTooLong => "path exceeds maximum allowed byte length",
            Self::ShellExecutableForbidden => "a shell interpreter needs local per-request confirmation",
            Self::ExecutableNotFound => "executable path does not exist",
            Self::ExecutableNotRegularFile => "executable path is not a regular file",
            Self::ExecutableUnreadable => "executable could not be read for verification",
            Self::ExecutablePinMismatch => "executable digest or identity does not match pin",
            Self::InvalidWorkingDirectory => "working directory is invalid or inaccessible",
            Self::WorkingDirectoryOutsideWorkspace => {
                "canonical working directory is outside the workspace"
            }
            Self::TooManyArguments => "argument count exceeds limit",
            Self::ArgumentTooLarge => "argument exceeds maximum byte length",
            Self::TotalArgumentsTooLarge => "total argument size exceeds limit",
            Self::InvalidArgument => "argument contains forbidden NUL byte",
            Self::InvalidReasonCode => "invalid reason code format",
            Self::SummaryTooLarge => "execution summary exceeds maximum byte length",
            Self::PendingLimitReached => "maximum pending confirmation requests reached",
            Self::ConcurrencyLimitReached => "maximum concurrent command executions reached",
            Self::EntropyUnavailable => "operating system cryptographic RNG unavailable",
            Self::NotFound => "command request not found",
            Self::NotPending => "command request is not pending confirmation",
            Self::NotApproved => "command request has not been approved",
            Self::NotConsumable => "command request cannot be consumed",
            Self::NotCancellable => "command request cannot be cancelled in its current state",
            Self::AlreadyInFlight => "command request is already in flight",
            Self::ConfirmationMismatch => {
                "confirmation digest does not match exact displayed command values"
            }
            Self::Expired => "command request has expired",
            Self::ReplayForbidden => {
                "command request ended in an uncertain state; replay is permanently forbidden"
            }
        };
        f.write_str(msg)
    }
}

impl std::error::Error for CommandError {}

/// Central decision engine that mints capability-separated handles for the
/// Web/MCP layer, the local operator CLI, and the local execution coordinator.
#[derive(Clone)]
pub struct CommandDecisionEngine {
    inner: Arc<EngineInner>,
}

impl CommandDecisionEngine {
    pub fn new(
        policy: OperatorPolicy,
        limits: EngineLimits,
        verifier: Arc<dyn EnvironmentVerifier>,
    ) -> Self {
        let inner = Arc::new(EngineInner {
            policy,
            limits: limits.normalized(),
            verifier,
            state: Mutex::new(EngineState::new()),
        });
        Self { inner }
    }

    /// Creates a decision engine using the default local filesystem verifier.
    pub fn with_fs_verifier(policy: OperatorPolicy, limits: EngineLimits) -> Self {
        Self::new(policy, limits, Arc::new(FsEnvironmentVerifier))
    }

    /// Splits the engine into three distinct capability handles:
    /// - [`WebClient`]: safe for Web/MCP exposure (submit, own status, own cancel).
    /// - [`OperatorConsole`]: local-only CLI handle (inspect, approve, deny, cancel).
    /// - [`ExecutionGate`]: local-only single-use consumption & outcome recording.
    pub fn split(&self) -> (WebClient, OperatorConsole, ExecutionGate) {
        (
            self.web_client(),
            self.operator_console(),
            self.execution_gate(),
        )
    }

    pub fn web_client(&self) -> WebClient {
        WebClient {
            inner: Arc::clone(&self.inner),
        }
    }

    pub fn operator_console(&self) -> OperatorConsole {
        OperatorConsole {
            inner: Arc::clone(&self.inner),
        }
    }

    pub fn execution_gate(&self) -> ExecutionGate {
        ExecutionGate {
            inner: Arc::clone(&self.inner),
        }
    }
}

/// Web/MCP-facing capability handle.
///
/// Intentionally exposes NO approval, denial, global listing, policy mutation,
/// or execution consumption methods.
#[derive(Clone)]
pub struct WebClient {
    inner: Arc<EngineInner>,
}

impl WebClient {
    /// Evaluates `command` against the local operator policy.
    ///
    /// Exact predefined matches are marked ready for single consumption; any
    /// other valid command is queued for a single short-lived local confirmation.
    pub fn submit(
        &self,
        requester: &RequesterContext,
        command: CommandRequest,
    ) -> Result<SubmissionOutcome, CommandError> {
        let verified = verify_incoming_command(&self.inner, &command)?;
        self.inner
            .policy
            .check_executable_pin_integrity(&verified.executable)?;

        let predefined_rule_id = self
            .inner
            .policy
            .match_predefined(&verified)
            .map(|rule| rule.id.clone());

        let now = Instant::now();
        let mut state = lock_state(&self.inner.state);
        state.purge_expired(now);
        state.evict_terminal_if_needed(self.inner.limits.max_retained_records);

        if state.records.len() >= self.inner.limits.max_retained_records {
            return Err(CommandError::PendingLimitReached);
        }
        if predefined_rule_id.is_none() {
            let (global_pending, requester_pending) = state.count_pending(requester);
            if global_pending >= self.inner.limits.max_pending_global
                || requester_pending >= self.inner.limits.max_pending_per_requester
            {
                return Err(CommandError::PendingLimitReached);
            }
        }

        let request_id = state.next_unique_request_id()?;

        let (record_state, outcome) = match predefined_rule_id {
            Some(rule_id) => {
                let expires_at = now
                    .checked_add(self.inner.limits.approved_ttl)
                    .unwrap_or(now);
                (
                    RecordState::Approved {
                        origin: ApprovalOrigin::Predefined {
                            rule_id: rule_id.clone(),
                        },
                        expires_at,
                    },
                    SubmissionOutcome::PredefinedApproved {
                        request_id: request_id.clone(),
                        rule_id,
                    },
                )
            }
            None => {
                let confirmation_digest =
                    compute_confirmation_digest(&request_id, requester, &verified)?;
                let expires_at = now.checked_add(self.inner.limits.pending_ttl).unwrap_or(now);
                (
                    RecordState::PendingConfirmation {
                        confirmation_digest,
                        expires_at,
                    },
                    SubmissionOutcome::PendingLocalConfirmation {
                        request_id: request_id.clone(),
                        expires_in_secs: self.inner.limits.pending_ttl.as_secs(),
                    },
                )
            }
        };

        state.insert(
            request_id,
            RequestRecord {
                requester: requester.clone(),
                command: verified,
                state: record_state,
            },
        );

        Ok(outcome)
    }

    /// Returns the status of a request owned by `requester`.
    ///
    /// Requests belonging to another requester return [`CommandError::NotFound`].
    pub fn status(
        &self,
        requester: &RequesterContext,
        request_id: &RequestId,
    ) -> Result<RequestStatusView, CommandError> {
        let now = Instant::now();
        let mut state = lock_state(&self.inner.state);
        state.purge_expired(now);

        let record = state
            .records
            .get(request_id)
            .filter(|rec| &rec.requester == requester)
            .ok_or(CommandError::NotFound)?;

        Ok(record.to_status_view(request_id, now))
    }

    /// Cancels a pending or unconsumed approved request owned by `requester`.
    pub fn cancel(
        &self,
        requester: &RequesterContext,
        request_id: &RequestId,
    ) -> Result<(), CommandError> {
        let now = Instant::now();
        let mut state = lock_state(&self.inner.state);
        state.purge_expired(now);

        let record = state
            .records
            .get_mut(request_id)
            .filter(|rec| &rec.requester == requester)
            .ok_or(CommandError::NotFound)?;

        match record.state {
            RecordState::PendingConfirmation { .. } | RecordState::Approved { .. } => {
                record.state = RecordState::Cancelled;
                Ok(())
            }
            _ => Err(CommandError::NotCancellable),
        }
    }
}

/// Local-only operator capability handle for CLI confirmation workflows.
///
/// Must NEVER be registered or exposed as an MCP tool.
#[derive(Clone)]
pub struct OperatorConsole {
    inner: Arc<EngineInner>,
}

impl OperatorConsole {
    /// Lists all active pending confirmation requests with exact displayed
    /// values and confirmation digests, ordered oldest first.
    pub fn list_pending(&self) -> Vec<PendingApprovalView> {
        let now = Instant::now();
        let mut state = lock_state(&self.inner.state);
        state.purge_expired(now);

        let mut out = Vec::new();
        for id in &state.order {
            if let Some(record) = state.records.get(id) {
                if let Some(view) = record.to_pending_view(id, now) {
                    out.push(view);
                }
            }
        }
        out
    }

    /// Inspects a single pending confirmation request.
    pub fn inspect_pending(
        &self,
        request_id: &RequestId,
    ) -> Result<PendingApprovalView, CommandError> {
        let now = Instant::now();
        let mut state = lock_state(&self.inner.state);
        state.purge_expired(now);

        let record = state.records.get(request_id).ok_or(CommandError::NotFound)?;
        match &record.state {
            RecordState::PendingConfirmation { .. } => record
                .to_pending_view(request_id, now)
                .ok_or(CommandError::NotPending),
            RecordState::Expired => Err(CommandError::Expired),
            _ => Err(CommandError::NotPending),
        }
    }

    /// Approves a single pending request for one-time execution.
    ///
    /// Requires the exact `confirmation_digest` from [`PendingApprovalView`],
    /// re-verifies the pinned executable and workspace working directory on
    /// disk, and NEVER modifies the permanent operator policy.
    pub fn approve(
        &self,
        request_id: &RequestId,
        confirmation_digest: Sha256Digest,
    ) -> Result<ApprovedSummary, CommandError> {
        let command_snapshot = {
            let now = Instant::now();
            let mut state = lock_state(&self.inner.state);
            state.purge_expired(now);

            let record = state.records.get(request_id).ok_or(CommandError::NotFound)?;
            match &record.state {
                RecordState::PendingConfirmation {
                    confirmation_digest: expected,
                    ..
                } => {
                    if !expected.ct_eq(&confirmation_digest) {
                        return Err(CommandError::ConfirmationMismatch);
                    }
                    record.command.clone()
                }
                RecordState::Expired => return Err(CommandError::Expired),
                _ => return Err(CommandError::NotPending),
            }
        };

        reverify_pinned_command(&self.inner, &command_snapshot)?;

        let now = Instant::now();
        let mut state = lock_state(&self.inner.state);
        state.purge_expired(now);

        let record = state
            .records
            .get_mut(request_id)
            .ok_or(CommandError::NotFound)?;

        match &record.state {
            RecordState::PendingConfirmation {
                confirmation_digest: expected,
                ..
            } => {
                if !expected.ct_eq(&confirmation_digest) {
                    return Err(CommandError::ConfirmationMismatch);
                }
            }
            RecordState::Expired => return Err(CommandError::Expired),
            _ => return Err(CommandError::NotPending),
        }

        let expires_at = now
            .checked_add(self.inner.limits.approved_ttl)
            .unwrap_or(now);
        record.state = RecordState::Approved {
            origin: ApprovalOrigin::LocalConfirmation {
                confirmation_digest,
            },
            expires_at,
        };

        Ok(ApprovedSummary {
            request_id: request_id.clone(),
            confirmation_digest,
            expires_in_secs: self.inner.limits.approved_ttl.as_secs(),
        })
    }

    /// Denies a pending confirmation request.
    pub fn deny(
        &self,
        request_id: &RequestId,
        reason_code: Option<String>,
    ) -> Result<(), CommandError> {
        if let Some(code) = reason_code.as_deref() {
            validate_reason_code(code)?;
        }

        let now = Instant::now();
        let mut state = lock_state(&self.inner.state);
        state.purge_expired(now);

        let record = state
            .records
            .get_mut(request_id)
            .ok_or(CommandError::NotFound)?;

        match record.state {
            RecordState::PendingConfirmation { .. } => {
                record.state = RecordState::Denied { reason_code };
                Ok(())
            }
            RecordState::Expired => Err(CommandError::Expired),
            _ => Err(CommandError::NotPending),
        }
    }

    /// Cancels a pending or approved unconsumed request.
    pub fn cancel(&self, request_id: &RequestId) -> Result<(), CommandError> {
        let now = Instant::now();
        let mut state = lock_state(&self.inner.state);
        state.purge_expired(now);

        let record = state
            .records
            .get_mut(request_id)
            .ok_or(CommandError::NotFound)?;

        match record.state {
            RecordState::PendingConfirmation { .. } | RecordState::Approved { .. } => {
                record.state = RecordState::Cancelled;
                Ok(())
            }
            _ => Err(CommandError::NotCancellable),
        }
    }

    /// Inspects the current status of any request by ID.
    pub fn status(&self, request_id: &RequestId) -> Result<RequestStatusView, CommandError> {
        let now = Instant::now();
        let mut state = lock_state(&self.inner.state);
        state.purge_expired(now);

        let record = state.records.get(request_id).ok_or(CommandError::NotFound)?;
        Ok(record.to_status_view(request_id, now))
    }
}

/// Local-only single-use consumption and execution outcome coordinator.
///
/// This crate never spawns commands itself; a future local executor claims an
/// [`ExecutionPermit`] via [`ExecutionGate::consume`] and reports the outcome
/// via [`ExecutionGate::finish`].
#[derive(Clone)]
pub struct ExecutionGate {
    inner: Arc<EngineInner>,
}

impl ExecutionGate {
    /// Atomically consumes an approved request once, re-verifies the pinned
    /// executable and canonical workspace working directory, reserves a
    /// concurrency slot, and returns a single-use [`ExecutionPermit`].
    pub fn consume(&self, request_id: &RequestId) -> Result<ExecutionPermit, CommandError> {
        let command_snapshot = {
            let now = Instant::now();
            let mut state = lock_state(&self.inner.state);
            state.purge_expired(now);

            if state.active_executions >= self.inner.limits.max_concurrent_executions {
                return Err(CommandError::ConcurrencyLimitReached);
            }

            let record = state
                .records
                .get_mut(request_id)
                .ok_or(CommandError::NotFound)?;

            match &record.state {
                RecordState::Approved { .. } => {
                    record.state = RecordState::Verifying;
                    let command = record.command.clone();
                    state.active_executions += 1;
                    command
                }
                RecordState::PendingConfirmation { .. } => return Err(CommandError::NotApproved),
                RecordState::Verifying | RecordState::InFlight => {
                    return Err(CommandError::AlreadyInFlight);
                }
                RecordState::Uncertain { .. } => return Err(CommandError::ReplayForbidden),
                RecordState::Expired => return Err(CommandError::Expired),
                RecordState::Completed { .. }
                | RecordState::FailedBeforeStart { .. }
                | RecordState::Denied { .. }
                | RecordState::Cancelled => return Err(CommandError::NotConsumable),
            }
        };

        let mut guard = VerifyingGuard {
            inner: Arc::clone(&self.inner),
            request_id: request_id.clone(),
            disarmed: false,
        };

        let verify_result = reverify_pinned_command(&self.inner, &command_snapshot);

        match verify_result {
            Ok(()) => {
                let mut state = lock_state(&self.inner.state);
                guard.disarmed = true;
                if let Some(record) = state.records.get_mut(request_id) {
                    record.state = RecordState::InFlight;
                }
                Ok(ExecutionPermit {
                    request_id: request_id.clone(),
                    command: command_snapshot,
                    inner: Arc::clone(&self.inner),
                    finished: false,
                })
            }
            Err(err) => {
                let mut state = lock_state(&self.inner.state);
                guard.disarmed = true;
                state.active_executions = state.active_executions.saturating_sub(1);
                if let Some(record) = state.records.get_mut(request_id) {
                    record.state = RecordState::FailedBeforeStart {
                        reason_code: "pre_execution_verification_failed".to_string(),
                    };
                }
                Err(err)
            }
        }
    }

    /// Records the final outcome for a consumed [`ExecutionPermit`] and
    /// releases its concurrency slot.
    ///
    /// An [`ExecutionOutcome::Uncertain`] outcome permanently forbids replay.
    pub fn finish(
        &self,
        mut permit: ExecutionPermit,
        outcome: ExecutionOutcome,
    ) -> Result<(), CommandError> {
        if !Arc::ptr_eq(&self.inner, &permit.inner) {
            return Err(CommandError::NotConsumable);
        }
        let next_state = match outcome {
            ExecutionOutcome::Completed { exit_code, summary } => {
                if let Some(ref s) = summary {
                    if s.len() > self.inner.limits.max_result_summary_bytes
                        || s.as_bytes().contains(&0)
                    {
                        return Err(CommandError::SummaryTooLarge);
                    }
                }
                RecordState::Completed { exit_code, summary }
            }
            ExecutionOutcome::FailedBeforeStart { reason_code } => {
                validate_reason_code(&reason_code)?;
                RecordState::FailedBeforeStart { reason_code }
            }
            ExecutionOutcome::Uncertain { reason_code } => {
                validate_reason_code(&reason_code)?;
                RecordState::Uncertain { reason_code }
            }
        };

        permit.finished = true;
        let mut state = lock_state(&self.inner.state);
        state.active_executions = state.active_executions.saturating_sub(1);
        if let Some(record) = state.records.get_mut(&permit.request_id) {
            record.state = next_state;
        }
        Ok(())
    }
}

struct VerifyingGuard {
    inner: Arc<EngineInner>,
    request_id: RequestId,
    disarmed: bool,
}

impl Drop for VerifyingGuard {
    fn drop(&mut self) {
        if self.disarmed {
            return;
        }
        let mut state = lock_state(&self.inner.state);
        state.active_executions = state.active_executions.saturating_sub(1);
        if let Some(record) = state.records.get_mut(&self.request_id) {
            record.state = RecordState::Uncertain {
                reason_code: "verification_aborted".to_string(),
            };
        }
    }
}

struct EngineInner {
    policy: OperatorPolicy,
    limits: EngineLimits,
    verifier: Arc<dyn EnvironmentVerifier>,
    state: Mutex<EngineState>,
}

struct EngineState {
    records: HashMap<RequestId, RequestRecord>,
    order: VecDeque<RequestId>,
    active_executions: usize,
}

impl EngineState {
    fn new() -> Self {
        Self {
            records: HashMap::new(),
            order: VecDeque::new(),
            active_executions: 0,
        }
    }

    fn next_unique_request_id(&self) -> Result<RequestId, CommandError> {
        for _ in 0..8 {
            let candidate = RequestId::generate()?;
            if !self.records.contains_key(&candidate) {
                return Ok(candidate);
            }
        }
        Err(CommandError::EntropyUnavailable)
    }

    fn insert(&mut self, id: RequestId, record: RequestRecord) {
        self.records.insert(id.clone(), record);
        self.order.push_back(id);
    }

    fn purge_expired(&mut self, now: Instant) {
        for record in self.records.values_mut() {
            match record.state {
                RecordState::PendingConfirmation { expires_at, .. }
                | RecordState::Approved { expires_at, .. }
                    if now >= expires_at =>
                {
                    record.state = RecordState::Expired;
                }
                _ => {}
            }
        }
    }

    fn count_pending(&self, requester: &RequesterContext) -> (usize, usize) {
        let mut global = 0usize;
        let mut per_requester = 0usize;
        for record in self.records.values() {
            if matches!(record.state, RecordState::PendingConfirmation { .. }) {
                global += 1;
                if &record.requester == requester {
                    per_requester += 1;
                }
            }
        }
        (global, per_requester)
    }

    fn evict_terminal_if_needed(&mut self, max_retained: usize) {
        if self.records.len() < max_retained {
            return;
        }
        let mut retained_order = VecDeque::with_capacity(self.order.len());
        while let Some(id) = self.order.pop_front() {
            let should_evict = self.records.len() >= max_retained
                && self
                    .records
                    .get(&id)
                    .map(|r| r.state.is_terminal())
                    .unwrap_or(true);
            if should_evict {
                self.records.remove(&id);
            } else {
                retained_order.push_back(id);
            }
        }
        self.order = retained_order;
    }
}

struct RequestRecord {
    requester: RequesterContext,
    command: VerifiedCommand,
    state: RecordState,
}

impl RequestRecord {
    fn to_pending_view(&self, id: &RequestId, now: Instant) -> Option<PendingApprovalView> {
        let RecordState::PendingConfirmation {
            confirmation_digest,
            expires_at,
        } = &self.state
        else {
            return None;
        };

        let executable_path = self.command.executable.canonical_path.to_str()?.to_string();
        let cwd = self.command.cwd.to_str()?.to_string();

        Some(PendingApprovalView {
            request_id: id.clone(),
            requester_id: self.requester.as_str().to_string(),
            executable_path,
            executable_sha256: self.command.executable.sha256,
            executable_identity: self.command.executable.identity.clone(),
            args: self.command.args.clone(),
            cwd,
            expires_in_secs: expires_at.saturating_duration_since(now).as_secs(),
            confirmation_digest: *confirmation_digest,
        })
    }

    fn to_status_view(&self, id: &RequestId, now: Instant) -> RequestStatusView {
        match &self.state {
            RecordState::PendingConfirmation { expires_at, .. } => {
                RequestStatusView::PendingLocalConfirmation {
                    request_id: id.clone(),
                    expires_in_secs: expires_at.saturating_duration_since(now).as_secs(),
                }
            }
            RecordState::Approved { origin, expires_at } => RequestStatusView::Approved {
                request_id: id.clone(),
                origin: origin.clone(),
                expires_in_secs: expires_at.saturating_duration_since(now).as_secs(),
            },
            RecordState::Verifying | RecordState::InFlight => RequestStatusView::InFlight {
                request_id: id.clone(),
            },
            RecordState::Completed { exit_code, summary } => RequestStatusView::Completed {
                request_id: id.clone(),
                exit_code: *exit_code,
                summary: summary.clone(),
            },
            RecordState::FailedBeforeStart { reason_code } => {
                RequestStatusView::FailedBeforeStart {
                    request_id: id.clone(),
                    reason_code: reason_code.clone(),
                }
            }
            RecordState::Uncertain { reason_code } => RequestStatusView::Uncertain {
                request_id: id.clone(),
                reason_code: reason_code.clone(),
                replay_forbidden: true,
            },
            RecordState::Denied { reason_code } => RequestStatusView::Denied {
                request_id: id.clone(),
                reason_code: reason_code.clone(),
            },
            RecordState::Cancelled => RequestStatusView::Cancelled {
                request_id: id.clone(),
            },
            RecordState::Expired => RequestStatusView::Expired {
                request_id: id.clone(),
            },
        }
    }
}

enum RecordState {
    PendingConfirmation {
        confirmation_digest: Sha256Digest,
        expires_at: Instant,
    },
    Approved {
        origin: ApprovalOrigin,
        expires_at: Instant,
    },
    Verifying,
    InFlight,
    Completed {
        exit_code: i32,
        summary: Option<String>,
    },
    FailedBeforeStart {
        reason_code: String,
    },
    Uncertain {
        reason_code: String,
    },
    Denied {
        reason_code: Option<String>,
    },
    Cancelled,
    Expired,
}

impl RecordState {
    fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Completed { .. }
                | Self::FailedBeforeStart { .. }
                | Self::Uncertain { .. }
                | Self::Denied { .. }
                | Self::Cancelled
                | Self::Expired
        )
    }
}

fn lock_state(mutex: &Mutex<EngineState>) -> std::sync::MutexGuard<'_, EngineState> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn verify_incoming_command(
    inner: &EngineInner,
    command: &CommandRequest,
) -> Result<VerifiedCommand, CommandError> {
    validate_raw_path(&command.executable, inner.limits.max_path_bytes)?;
    validate_raw_path(&command.cwd, inner.limits.max_path_bytes)?;
    validate_args(&command.args, &inner.limits)?;

    let pinned = inner.verifier.verify_executable(&command.executable)?;
    // A dynamic command cannot use a shell image; preserve the shell
    // exclusion already enforced for locally predefined policies.
    validate_not_shell_executable(&pinned.canonical_path)?;
    ensure_path_within_limit(&pinned.canonical_path, inner.limits.max_path_bytes)?;

    let canonical_cwd = inner.verifier.canonicalize_directory(&command.cwd)?;
    ensure_path_within_limit(&canonical_cwd, inner.limits.max_path_bytes)?;
    if !canonical_cwd.starts_with(inner.policy.workspace_root()) {
        return Err(CommandError::WorkingDirectoryOutsideWorkspace);
    }

    Ok(VerifiedCommand {
        executable: pinned,
        args: command.args.clone(),
        cwd: canonical_cwd,
    })
}

fn reverify_pinned_command(
    inner: &EngineInner,
    expected: &VerifiedCommand,
) -> Result<(), CommandError> {
    let current_exe = inner
        .verifier
        .verify_executable(&expected.executable.canonical_path)?;

    if current_exe.canonical_path != expected.executable.canonical_path
        || !current_exe.sha256.ct_eq(&expected.executable.sha256)
        || current_exe.identity != expected.executable.identity
    {
        return Err(CommandError::ExecutablePinMismatch);
    }

    inner.policy.check_executable_pin_integrity(&current_exe)?;

    let current_cwd = inner.verifier.canonicalize_directory(&expected.cwd)?;
    if current_cwd != expected.cwd || !current_cwd.starts_with(inner.policy.workspace_root()) {
        return Err(CommandError::WorkingDirectoryOutsideWorkspace);
    }

    Ok(())
}

fn compute_confirmation_digest(
    request_id: &RequestId,
    requester: &RequesterContext,
    command: &VerifiedCommand,
) -> Result<Sha256Digest, CommandError> {
    let exe_str = ensure_valid_utf8_path(&command.executable.canonical_path)?;
    let cwd_str = ensure_valid_utf8_path(&command.cwd)?;

    let mut hasher = Sha256::new();
    update_len_prefixed(&mut hasher, CONFIRMATION_DOMAIN_TAG);
    update_len_prefixed(&mut hasher, request_id.as_str().as_bytes());
    update_len_prefixed(&mut hasher, requester.as_str().as_bytes());
    update_len_prefixed(&mut hasher, exe_str.as_bytes());
    hasher.update(command.executable.sha256.as_bytes());

    let id = &command.executable.identity;
    hasher.update(id.file_len.to_be_bytes());
    update_opt_u128(&mut hasher, id.modified_unix_nanos);
    update_opt_u64(&mut hasher, id.unix_dev);
    update_opt_u64(&mut hasher, id.unix_ino);
    update_opt_u64(&mut hasher, id.windows_creation_time);
    update_opt_u64(&mut hasher, id.windows_last_write_time);
    update_opt_u32(&mut hasher, id.windows_file_attributes);

    update_len_prefixed(&mut hasher, cwd_str.as_bytes());
    hasher.update((command.args.len() as u64).to_be_bytes());
    for arg in &command.args {
        update_len_prefixed(&mut hasher, arg.as_bytes());
    }

    let bytes: [u8; 32] = hasher.finalize().into();
    Ok(Sha256Digest::from_bytes(bytes))
}

fn validate_raw_path(path: &Path, max_bytes: usize) -> Result<(), CommandError> {
    let s = ensure_valid_utf8_path(path)?;
    if s.is_empty() {
        return Err(CommandError::InvalidPath);
    }
    if s.len() > max_bytes {
        return Err(CommandError::PathTooLong);
    }
    if s.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(CommandError::InvalidPath);
    }
    if !path.is_absolute() {
        return Err(CommandError::PathNotAbsolute);
    }
    #[cfg(windows)]
    if !matches!(path.components().next(), Some(Component::Prefix(p)) if matches!(p.kind(), std::path::Prefix::Disk(_))) {
        return Err(CommandError::InvalidPath);
    }
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(CommandError::PathTraversalNotAllowed);
    }
    Ok(())
}

fn ensure_path_within_limit(path: &Path, max_bytes: usize) -> Result<(), CommandError> {
    let s = ensure_valid_utf8_path(path)?;
    if s.len() > max_bytes {
        return Err(CommandError::PathTooLong);
    }
    Ok(())
}

fn ensure_valid_utf8_path(path: &Path) -> Result<&str, CommandError> {
    path.to_str().ok_or(CommandError::InvalidPath)
}

fn validate_not_shell_executable(path: &Path) -> Result<(), CommandError> {
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or(CommandError::InvalidPath)?;
    if SHELL_EXECUTABLES
        .iter()
        .any(|blocked| file_name.eq_ignore_ascii_case(blocked))
    {
        return Err(CommandError::ShellExecutableForbidden);
    }
    Ok(())
}

fn validate_args(args: &[String], limits: &EngineLimits) -> Result<(), CommandError> {
    if args.len() > limits.max_args {
        return Err(CommandError::TooManyArguments);
    }
    let mut total = 0usize;
    for arg in args {
        if arg.len() > limits.max_arg_bytes {
            return Err(CommandError::ArgumentTooLarge);
        }
        if arg.as_bytes().contains(&0) {
            return Err(CommandError::InvalidArgument);
        }
        total = total
            .checked_add(arg.len())
            .filter(|&sum| sum <= limits.max_total_args_bytes)
            .ok_or(CommandError::TotalArgumentsTooLarge)?;
    }
    Ok(())
}

fn validate_rule_id(id: &str) -> Result<(), CommandError> {
    if id.is_empty()
        || id.len() > MAX_RULE_ID_BYTES
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
    {
        return Err(CommandError::InvalidPolicy);
    }
    Ok(())
}

fn validate_reason_code(code: &str) -> Result<(), CommandError> {
    if code.is_empty()
        || code.len() > MAX_REASON_CODE_BYTES
        || !code
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err(CommandError::InvalidReasonCode);
    }
    Ok(())
}

fn capture_file_identity(meta: &fs::Metadata) -> ExecutableIdentity {
    let modified_unix_nanos = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_nanos());

    #[cfg(unix)]
    let (unix_dev, unix_ino) = {
        use std::os::unix::fs::MetadataExt;
        (Some(meta.dev()), Some(meta.ino()))
    };
    #[cfg(not(unix))]
    let (unix_dev, unix_ino) = (None, None);

    #[cfg(windows)]
    let (windows_creation_time, windows_last_write_time, windows_file_attributes) = {
        use std::os::windows::fs::MetadataExt;
        (
            Some(meta.creation_time()),
            Some(meta.last_write_time()),
            Some(meta.file_attributes()),
        )
    };
    #[cfg(not(windows))]
    let (windows_creation_time, windows_last_write_time, windows_file_attributes) =
        (None, None, None);

    ExecutableIdentity {
        file_len: meta.len(),
        modified_unix_nanos,
        unix_dev,
        unix_ino,
        windows_creation_time,
        windows_last_write_time,
        windows_file_attributes,
    }
}

fn update_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn update_opt_u128(hasher: &mut Sha256, value: Option<u128>) {
    match value {
        Some(v) => {
            hasher.update([1u8]);
            hasher.update(v.to_be_bytes());
        }
        None => hasher.update([0u8]),
    }
}

fn update_opt_u64(hasher: &mut Sha256, value: Option<u64>) {
    match value {
        Some(v) => {
            hasher.update([1u8]);
            hasher.update(v.to_be_bytes());
        }
        None => hasher.update([0u8]),
    }
}

fn update_opt_u32(hasher: &mut Sha256, value: Option<u32>) {
    match value {
        Some(v) => {
            hasher.update([1u8]);
            hasher.update(v.to_be_bytes());
        }
        None => hasher.update([0u8]),
    }
}

fn decode_hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

fn clamp_duration(value: Duration, min: Duration, max: Duration) -> Duration {
    if value < min {
        min
    } else if value > max {
        max
    } else {
        value
    }
}