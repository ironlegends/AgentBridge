//! Outbound OAuth 2.1 (PKCE S256) client and OS-protected token store for
//! locally approved Streamable HTTP MCP extensions.
//!
//! Security invariants:
//! - Registry metadata (`extensions.json` / `.extensions-admin.json`) NEVER
//!   stores access tokens, refresh tokens, PKCE verifiers, or client secrets.
//! - Outbound OAuth tokens are stored exclusively in a dedicated private file
//!   encrypted per-server with Windows DPAPI (`CryptProtectData` with
//!   `CRYPTPROTECT_UI_FORBIDDEN`).
//! - Remote endpoints must use HTTPS; loopback HTTP (`127.0.0.1` / `[::1]`)
//!   is permitted for local development/testing.
//! - No HTTP redirects, no proxies, bounded response sizes and timeouts.

use crate::{error, transport, Result};
use reqwest::blocking::Client;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const TOKEN_STORE_FILE: &str = ".extensions-oauth-tokens.json";
const MAX_STORE_BYTES: usize = 256 * 1024;
const MAX_METADATA_BYTES: usize = 64 * 1024;
const MAX_TOKEN_RESPONSE_BYTES: usize = 64 * 1024;
const CALLBACK_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientAuthMethod {
    ClientSecretBasic,
    ClientSecretPost,
    None,
}

/// Non-secret OAuth 2.1 configuration for one locally configured extension.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OAuthServerConfig {
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_auth_method: Option<ClientAuthMethod>,
    /// Name of a local process environment variable (`AGENT_BRIDGE_EXTENSION_*`)
    /// read only at token-exchange time. Never a secret value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret_env: Option<String>,
}

impl OAuthServerConfig {
    pub fn validate(&self) -> Result<()> {
        if let Some(scope) = &self.scope {
            if scope.is_empty() || scope.len() > 8192 || scope.chars().any(char::is_control) {
                return Err(error("Invalid OAuth scope"));
            }
        }
        if let Some(cid) = &self.client_id {
            if cid.is_empty() || cid.len() > 1024 || cid.chars().any(char::is_control) {
                return Err(error("Invalid OAuth client_id"));
            }
        }
        if let Some(env_name) = &self.client_secret_env {
            if !valid_secret_env_name(env_name) {
                return Err(error("Invalid OAuth client_secret_env reference"));
            }
        }
        if !self.enabled
            && (self.scope.is_some()
                || self.client_id.is_some()
                || self.client_auth_method.is_some()
                || self.client_secret_env.is_some())
        {
            return Err(error("Disabled OAuth config cannot carry client parameters"));
        }
        Ok(())
    }
}

pub fn valid_secret_env_name(key: &str) -> bool {
    key.starts_with("AGENT_BRIDGE_EXTENSION_")
        && key.len() <= 128
        && key
            .bytes()
            .all(|b| b == b'_' || b.is_ascii_uppercase() || b.is_ascii_digit())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredTokenRecord {
    pub access_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_unix_secs: Option<u64>,
    pub endpoint: String,
    pub obtained_at_unix_secs: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenStatusSummary {
    pub token_stored: bool,
    pub token_expired: bool,
    pub has_refresh_token: bool,
    pub expires_at_unix_secs: Option<u64>,
    pub granted_scope: Option<String>,
    pub storage_protection: &'static str,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreEnvelope {
    version: u8,
    protection: String,
    entries: BTreeMap<String, String>,
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn loopback_http_url(port: Option<u16>, path_and_query: &str) -> String {
    let scheme = "http";
    let host = "127.0.0.1";
    match port {
        Some(p) => format!("{scheme}://{host}:{p}{path_and_query}"),
        None => format!("{scheme}://{host}{path_and_query}"),
    }
}

pub fn storage_protection_label() -> &'static str {
    #[cfg(windows)]
    {
        "windows_dpapi"
    }
    #[cfg(target_os = "macos")]
    {
        "macos_keychain"
    }
    #[cfg(target_os = "linux")]
    {
        "linux_secret_service"
    }
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        "unsupported_platform"
    }
}

#[cfg(windows)]
mod os_protect {
    use super::*;
    use std::ffi::c_void;
    use std::ptr::{null, null_mut};

    const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;

    #[repr(C)]
    struct DataBlob {
        cb_data: u32,
        pb_data: *mut u8,
    }

    #[link(name = "Crypt32")]
    extern "system" {
        fn CryptProtectData(
            data_in: *const DataBlob,
            data_descr: *const u16,
            optional_entropy: *const DataBlob,
            reserved: *mut c_void,
            prompt_struct: *const c_void,
            flags: u32,
            data_out: *mut DataBlob,
        ) -> i32;
        fn CryptUnprotectData(
            data_in: *const DataBlob,
            data_descr: *mut *mut u16,
            optional_entropy: *const DataBlob,
            reserved: *mut c_void,
            prompt_struct: *const c_void,
            flags: u32,
            data_out: *mut DataBlob,
        ) -> i32;
    }

    #[link(name = "Kernel32")]
    extern "system" {
        fn LocalFree(mem: *mut c_void) -> *mut c_void;
    }

    #[link(name = "bcrypt")]
    extern "system" {
        fn BCryptGenRandom(algorithm: isize, buffer: *mut u8, size: u32, flags: u32) -> i32;
    }

    pub(super) fn random_bytes(buf: &mut [u8]) -> Result<()> {
        let len = u32::try_from(buf.len()).map_err(|_| error("Random buffer too large"))?;
        if unsafe { BCryptGenRandom(0, buf.as_mut_ptr(), len, 2) } < 0 {
            return Err(error("OS CSPRNG unavailable"));
        }
        Ok(())
    }

    pub(super) fn protect(server: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut entropy_bytes = format!("agent-bridge-ext-oauth-v1\0{server}").into_bytes();
        let mut plain_copy = plaintext.to_vec();
        let in_blob = DataBlob {
            cb_data: u32::try_from(plain_copy.len()).map_err(|_| error("Token record too large"))?,
            pb_data: plain_copy.as_mut_ptr(),
        };
        let entropy_blob = DataBlob {
            cb_data: u32::try_from(entropy_bytes.len())
                .map_err(|_| error("Server entropy too large"))?,
            pb_data: entropy_bytes.as_mut_ptr(),
        };
        let mut out_blob = DataBlob {
            cb_data: 0,
            pb_data: null_mut(),
        };
        let ok = unsafe {
            CryptProtectData(
                &in_blob,
                null(),
                &entropy_blob,
                null_mut(),
                null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out_blob,
            )
        };
        plain_copy.fill(0);
        if ok == 0 || out_blob.pb_data.is_null() {
            return Err(error("Windows DPAPI CryptProtectData failed"));
        }
        let protected = unsafe {
            std::slice::from_raw_parts(out_blob.pb_data, out_blob.cb_data as usize).to_vec()
        };
        unsafe {
            LocalFree(out_blob.pb_data.cast());
        }
        Ok(protected)
    }

    pub(super) fn unprotect(server: &str, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut entropy_bytes = format!("agent-bridge-ext-oauth-v1\0{server}").into_bytes();
        let mut cipher_copy = ciphertext.to_vec();
        let in_blob = DataBlob {
            cb_data: u32::try_from(cipher_copy.len())
                .map_err(|_| error("Ciphertext too large"))?,
            pb_data: cipher_copy.as_mut_ptr(),
        };
        let entropy_blob = DataBlob {
            cb_data: u32::try_from(entropy_bytes.len())
                .map_err(|_| error("Server entropy too large"))?,
            pb_data: entropy_bytes.as_mut_ptr(),
        };
        let mut out_blob = DataBlob {
            cb_data: 0,
            pb_data: null_mut(),
        };
        let ok = unsafe {
            CryptUnprotectData(
                &in_blob,
                null_mut(),
                &entropy_blob,
                null_mut(),
                null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out_blob,
            )
        };
        if ok == 0 || out_blob.pb_data.is_null() {
            return Err(error("Windows DPAPI CryptUnprotectData failed"));
        }
        let plain = unsafe {
            let slice = std::slice::from_raw_parts_mut(out_blob.pb_data, out_blob.cb_data as usize);
            let vec = slice.to_vec();
            slice.fill(0);
            vec
        };
        unsafe {
            LocalFree(out_blob.pb_data.cast());
        }
        Ok(plain)
    }
}

#[cfg(unix)]
mod os_protect {
    use super::*;
    use std::process::{Command, Stdio};

    pub(super) fn random_bytes(buf: &mut [u8]) -> Result<()> {
        let mut f = fs::File::open("/dev/urandom")
            .map_err(|_| error("OS CSPRNG (/dev/urandom) unavailable"))?;
        f.read_exact(buf)
            .map_err(|_| error("Failed to read OS CSPRNG bytes"))?;
        Ok(())
    }

    fn account_key(settings: &Path, server: &str) -> String {
        let base = settings.to_string_lossy();
        hex::encode(Sha256::digest(
            format!("agent-bridge-ext-oauth-v1 {base} {server}").as_bytes(),
        ))
    }

    #[cfg(target_os = "macos")]
    pub(super) fn store_secret(settings: &Path, server: &str, plaintext: &[u8]) -> Result<()> {
        let account = account_key(settings, server);
        let secret_hex = hex::encode(plaintext);
        let status = Command::new("/usr/bin/security")
            .args([
                "add-generic-password",
                "-U",
                "-s",
                "agent-bridge.extensions.oauth",
                "-a",
                &account,
                "-w",
                &secret_hex,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|_| error("macOS Keychain (/usr/bin/security) unavailable"))?;
        if !status.success() {
            return Err(error("macOS Keychain refused to store OAuth token"));
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    pub(super) fn load_secret(settings: &Path, server: &str) -> Result<Option<Vec<u8>>> {
        let account = account_key(settings, server);
        let out = Command::new("/usr/bin/security")
            .args([
                "find-generic-password",
                "-s",
                "agent-bridge.extensions.oauth",
                "-a",
                &account,
                "-w",
            ])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .map_err(|_| error("macOS Keychain (/usr/bin/security) unavailable"))?;
        if !out.status.success() {
            return Ok(None);
        }
        let hex_str = std::str::from_utf8(&out.stdout)
            .map_err(|_| error("Invalid macOS Keychain secret encoding"))?
            .trim();
        let bytes = hex::decode(hex_str).map_err(|_| error("Corrupt macOS Keychain token entry"))?;
        Ok(Some(bytes))
    }

    #[cfg(target_os = "macos")]
    pub(super) fn delete_secret(settings: &Path, server: &str) -> Result<bool> {
        let account = account_key(settings, server);
        let status = Command::new("/usr/bin/security")
            .args([
                "delete-generic-password",
                "-s",
                "agent-bridge.extensions.oauth",
                "-a",
                &account,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|_| error("macOS Keychain (/usr/bin/security) unavailable"))?;
        Ok(status.success())
    }

    #[cfg(target_os = "linux")]
    pub(super) fn store_secret(settings: &Path, server: &str, plaintext: &[u8]) -> Result<()> {
        let account = account_key(settings, server);
        let secret_hex = hex::encode(plaintext);
        let mut child = Command::new("/usr/bin/secret-tool")
            .args([
                "store",
                "--label=Agent Bridge Extension OAuth Token",
                "service",
                "agent-bridge-extensions-oauth",
                "account",
                &account,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| error("Linux Secret Service (/usr/bin/secret-tool) unavailable"))?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(secret_hex.as_bytes())?;
        }
        let status = child.wait()?;
        if !status.success() {
            return Err(error("Linux Secret Service refused to store OAuth token"));
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub(super) fn load_secret(settings: &Path, server: &str) -> Result<Option<Vec<u8>>> {
        let account = account_key(settings, server);
        let out = Command::new("/usr/bin/secret-tool")
            .args([
                "lookup",
                "service",
                "agent-bridge-extensions-oauth",
                "account",
                &account,
            ])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .map_err(|_| error("Linux Secret Service (/usr/bin/secret-tool) unavailable"))?;
        if !out.status.success() {
            return Ok(None);
        }
        let hex_str = std::str::from_utf8(&out.stdout)
            .map_err(|_| error("Invalid Linux Secret Service encoding"))?
            .trim();
        if hex_str.is_empty() {
            return Ok(None);
        }
        let bytes = hex::decode(hex_str).map_err(|_| error("Corrupt Linux Secret Service entry"))?;
        Ok(Some(bytes))
    }

    #[cfg(target_os = "linux")]
    pub(super) fn delete_secret(settings: &Path, server: &str) -> Result<bool> {
        let account = account_key(settings, server);
        let status = Command::new("/usr/bin/secret-tool")
            .args([
                "clear",
                "service",
                "agent-bridge-extensions-oauth",
                "account",
                &account,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|_| error("Linux Secret Service (/usr/bin/secret-tool) unavailable"))?;
        Ok(status.success())
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    pub(super) fn store_secret(_settings: &Path, _server: &str, _plaintext: &[u8]) -> Result<()> {
        Err(error("OS-protected outbound OAuth token store unavailable on this platform"))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    pub(super) fn load_secret(_settings: &Path, _server: &str) -> Result<Option<Vec<u8>>> {
        Err(error("OS-protected outbound OAuth token store unavailable on this platform"))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    pub(super) fn delete_secret(_settings: &Path, _server: &str) -> Result<bool> {
        Err(error("OS-protected outbound OAuth token store unavailable on this platform"))
    }
}

#[cfg(not(any(windows, unix)))]
mod os_protect {
    use super::*;
    pub(super) fn random_bytes(_buf: &mut [u8]) -> Result<()> {
        Err(error("OS CSPRNG unavailable on this platform"))
    }
}

pub struct OAuthTokenStore;

impl OAuthTokenStore {
    fn open_envelope(settings: &Path) -> Result<StoreEnvelope> {
        let path = settings.join(TOKEN_STORE_FILE);
        match fs::symlink_metadata(&path) {
            Ok(meta) => {
                if meta.file_type().is_symlink() || !meta.is_file() || meta.len() > MAX_STORE_BYTES as u64 {
                    return Err(error("Invalid OAuth token store file"));
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Ok(StoreEnvelope {
                    version: 1,
                    protection: storage_protection_label().to_owned(),
                    entries: BTreeMap::new(),
                });
            }
            Err(e) => return Err(e),
        }
        let mut opts = OpenOptions::new();
        opts.read(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            opts.custom_flags(0x0020_0000);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts.open(&path)?;
        let mut bytes = Vec::new();
        file.take((MAX_STORE_BYTES + 1) as u64).read_to_end(&mut bytes)?;
        if bytes.len() > MAX_STORE_BYTES {
            return Err(error("OAuth token store exceeds size limit"));
        }
        let env: StoreEnvelope =
            serde_json::from_slice(&bytes).map_err(|_| error("Invalid OAuth token store JSON"))?;
        if env.version != 1 || env.protection != storage_protection_label() {
            return Err(error("Unsupported OAuth token store version or protection"));
        }
        Ok(env)
    }

    fn write_envelope(settings: &Path, envelope: &StoreEnvelope) -> Result<()> {
        let bytes = serde_json::to_vec(envelope)
            .map_err(|_| error("Cannot encode OAuth token store"))?;
        if bytes.len() > MAX_STORE_BYTES {
            return Err(error("OAuth token store exceeds size limit"));
        }
        let target = settings.join(TOKEN_STORE_FILE);
        if let Ok(meta) = fs::symlink_metadata(&target) {
            if meta.file_type().is_symlink() || !meta.is_file() {
                return Err(error("Refusing symlinked OAuth token store"));
            }
        }
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let stage = settings.join(format!(
            "{TOKEN_STORE_FILE}.tmp-{}-{nonce}",
            std::process::id()
        ));
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            opts.custom_flags(0x0020_0000);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(&stage)?;
        let res = (|| {
            file.write_all(&bytes)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&stage, &target)
        })();
        if res.is_err() {
            let _ = fs::remove_file(&stage);
        }
        res
    }

    fn load_record(settings: &Path, server: &str) -> Result<Option<StoredTokenRecord>> {
        if !crate::valid_server_name(server) {
            return Err(error("Invalid server name"));
        }
        let env = Self::open_envelope(settings)?;
        let Some(entry_val) = env.entries.get(server) else {
            return Ok(None);
        };
        #[cfg(windows)]
        let mut plain = {
            let cipher = hex::decode(entry_val).map_err(|_| error("Corrupt OAuth token entry"))?;
            os_protect::unprotect(server, &cipher)?
        };
        #[cfg(unix)]
        let mut plain = {
            if entry_val != "os_keyring" {
                return Err(error("Corrupt OAuth keyring index entry"));
            }
            let Some(bytes) = os_protect::load_secret(settings, server)? else {
                return Ok(None);
            };
            bytes
        };
        #[cfg(not(any(windows, unix)))]
        let mut plain: Vec<u8> = {
            let _ = entry_val;
            return Err(error("OS-protected outbound OAuth token store unavailable"));
        };
        let parsed: Result<StoredTokenRecord> = serde_json::from_slice(&plain)
            .map_err(|_| error("Corrupt decrypted OAuth token record"));
        plain.fill(0);
        parsed.map(Some)
    }

    pub fn store_token(settings: &Path, server: &str, record: &StoredTokenRecord) -> Result<()> {
        if !crate::valid_server_name(server) || record.access_token.is_empty() {
            return Err(error("Invalid OAuth token record"));
        }
        let mut env = Self::open_envelope(settings)?;
        let mut plain = serde_json::to_vec(record)
            .map_err(|_| error("Cannot encode OAuth token record"))?;
        #[cfg(windows)]
        let stored_entry = {
            let cipher = os_protect::protect(server, &plain);
            plain.fill(0);
            hex::encode(cipher?)
        };
        #[cfg(unix)]
        let stored_entry = {
            let res = os_protect::store_secret(settings, server, &plain);
            plain.fill(0);
            res?;
            "os_keyring".to_owned()
        };
        #[cfg(not(any(windows, unix)))]
        let stored_entry: String = {
            plain.fill(0);
            return Err(error("OS-protected outbound OAuth token store unavailable"));
        };
        env.entries.insert(server.to_owned(), stored_entry);
        Self::write_envelope(settings, &env)
    }

    pub fn delete_token(settings: &Path, server: &str) -> Result<bool> {
        if !crate::valid_server_name(server) {
            return Err(error("Invalid server name"));
        }
        let mut env = Self::open_envelope(settings)?;
        let had_index = env.entries.remove(server).is_some();
        #[cfg(unix)]
        let had_keyring = os_protect::delete_secret(settings, server).unwrap_or(false);
        #[cfg(not(unix))]
        let had_keyring = false;
        if had_index {
            Self::write_envelope(settings, &env)?;
        }
        Ok(had_index || had_keyring)
    }

    /// Returns strictly non-secret token metadata (never returns any token string).
    pub fn load_status(settings: &Path, server: &str) -> Result<TokenStatusSummary> {
        let Some(rec) = Self::load_record(settings, server)? else {
            return Ok(TokenStatusSummary {
                token_stored: false,
                token_expired: false,
                has_refresh_token: false,
                expires_at_unix_secs: None,
                granted_scope: None,
                storage_protection: storage_protection_label(),
            });
        };
        let now = unix_now_secs();
        let expired = rec.expires_at_unix_secs.is_some_and(|exp| exp <= now);
        Ok(TokenStatusSummary {
            token_stored: true,
            token_expired: expired,
            has_refresh_token: rec.refresh_token.as_deref().is_some_and(|s| !s.is_empty()),
            expires_at_unix_secs: rec.expires_at_unix_secs,
            granted_scope: rec.scope,
            storage_protection: storage_protection_label(),
        })
    }

    pub fn load_access_token(
        settings: &Path,
        server: &str,
        expected_endpoint: &str,
    ) -> Result<Option<String>> {
        let Some(rec) = Self::load_record(settings, server)? else {
            return Ok(None);
        };
        if rec.endpoint != expected_endpoint {
            return Ok(None);
        }
        if rec
            .expires_at_unix_secs
            .is_some_and(|exp| exp <= unix_now_secs())
        {
            return Ok(None);
        }
        Ok(Some(rec.access_token))
    }
}

fn base64url_no_pad(input: &[u8]) -> String {
    const ALPHA: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    let mut chunks = input.chunks_exact(3);
    for c in &mut chunks {
        let n = (u32::from(c[0]) << 16) | (u32::from(c[1]) << 8) | u32::from(c[2]);
        out.push(ALPHA[((n >> 18) & 63) as usize] as char);
        out.push(ALPHA[((n >> 12) & 63) as usize] as char);
        out.push(ALPHA[((n >> 6) & 63) as usize] as char);
        out.push(ALPHA[(n & 63) as usize] as char);
    }
    match chunks.remainder() {
        [a] => {
            let n = u32::from(*a) << 16;
            out.push(ALPHA[((n >> 18) & 63) as usize] as char);
            out.push(ALPHA[((n >> 12) & 63) as usize] as char);
        }
        [a, b] => {
            let n = (u32::from(*a) << 16) | (u32::from(*b) << 8);
            out.push(ALPHA[((n >> 18) & 63) as usize] as char);
            out.push(ALPHA[((n >> 12) & 63) as usize] as char);
            out.push(ALPHA[((n >> 6) & 63) as usize] as char);
        }
        _ => {}
    }
    out
}

fn base64_std(input: &[u8]) -> String {
    const ALPHA: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    let mut chunks = input.chunks_exact(3);
    for c in &mut chunks {
        let n = (u32::from(c[0]) << 16) | (u32::from(c[1]) << 8) | u32::from(c[2]);
        out.push(ALPHA[((n >> 18) & 63) as usize] as char);
        out.push(ALPHA[((n >> 12) & 63) as usize] as char);
        out.push(ALPHA[((n >> 6) & 63) as usize] as char);
        out.push(ALPHA[(n & 63) as usize] as char);
    }
    match chunks.remainder() {
        [a] => {
            let n = u32::from(*a) << 16;
            out.push(ALPHA[((n >> 18) & 63) as usize] as char);
            out.push(ALPHA[((n >> 12) & 63) as usize] as char);
            out.push('=');
            out.push('=');
        }
        [a, b] => {
            let n = (u32::from(*a) << 16) | (u32::from(*b) << 8);
            out.push(ALPHA[((n >> 18) & 63) as usize] as char);
            out.push(ALPHA[((n >> 12) & 63) as usize] as char);
            out.push(ALPHA[((n >> 6) & 63) as usize] as char);
            out.push('=');
        }
        _ => {}
    }
    out
}

pub fn generate_pkce_s256() -> Result<(String, String)> {
    let mut raw = [0u8; 32];
    os_protect::random_bytes(&mut raw)?;
    let verifier = base64url_no_pad(&raw);
    let challenge = base64url_no_pad(&Sha256::digest(verifier.as_bytes()));
    Ok((verifier, challenge))
}

fn random_state_token() -> Result<String> {
    let mut raw = [0u8; 24];
    os_protect::random_bytes(&mut raw)?;
    Ok(base64url_no_pad(&raw))
}

fn ct_eq_str(a: &str, b: &str) -> bool {
    let (ab, bb) = (a.as_bytes(), b.as_bytes());
    if ab.len() != bb.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in ab.iter().zip(bb.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn oauth_http_client() -> Result<Client> {
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .no_proxy()
        .tls_backend_preconfigured(transport::https_tls()?)
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|_| error("Cannot initialize OAuth HTTP client"))
}

fn fetch_json_bounded(client: &Client, url: &Url, limit: usize) -> Result<Value> {
    let resp = client
        .get(url.clone())
        .header("Accept", "application/json")
        .send()
        .map_err(|_| error("OAuth metadata fetch failed"))?;
    if !resp.status().is_success() {
        return Err(error("OAuth metadata endpoint returned non-success status"));
    }
    let mut bytes = Vec::new();
    resp.take((limit as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| error("Incomplete OAuth metadata body"))?;
    if bytes.len() > limit {
        return Err(error("OAuth metadata exceeds byte limit"));
    }
    serde_json::from_slice(&bytes).map_err(|_| error("Invalid OAuth metadata JSON"))
}

#[derive(Clone, Debug)]
pub struct OAuthMetadata {
    pub authorization_endpoint: Url,
    pub token_endpoint: Url,
}

fn origin_url(endpoint: &Url, path: &str) -> Result<Url> {
    let mut base = endpoint.clone();
    base.set_path(path);
    base.set_query(None);
    base.set_fragment(None);
    Ok(base)
}

// A local development server may delegate to HTTPS. Cleartext is confined
// to the same already approved loopback origin at each discovery step.
fn discovered_endpoint(parent: &Url, raw: &str) -> Result<Url> {
    let endpoint = transport::endpoint(raw)?;
    if endpoint.scheme() == "http" && endpoint.origin() != parent.origin() {
        return Err(error("OAuth discovery requires HTTPS outside the approved loopback origin"));
    }
    Ok(endpoint)
}

pub fn discover_oauth_metadata(endpoint_str: &str) -> Result<OAuthMetadata> {
    let endpoint = transport::endpoint(endpoint_str)?;
    let client = oauth_http_client()?;

    // 1. Try RFC 9728 Protected Resource Metadata to locate authorization_servers[0]
    let mut auth_server_base = endpoint.clone();
    if let Ok(prm_url) = origin_url(&endpoint, "/.well-known/oauth-protected-resource") {
        if let Ok(prm) = fetch_json_bounded(&client, &prm_url, MAX_METADATA_BYTES) {
            if let Some(first) = prm
                .get("authorization_servers")
                .and_then(Value::as_array)
                .and_then(|arr| arr.first())
                .and_then(Value::as_str)
            {
                auth_server_base = discovered_endpoint(&endpoint, first)?;
            }
        }
    }

    // 2. Fetch RFC 8414 Authorization Server Metadata
    let meta_url = origin_url(&auth_server_base, "/.well-known/oauth-authorization-server")?;
    let meta = fetch_json_bounded(&client, &meta_url, MAX_METADATA_BYTES)?;

    if let Some(methods) = meta
        .get("code_challenge_methods_supported")
        .and_then(Value::as_array)
    {
        let supports_s256 = methods.iter().any(|v| v.as_str() == Some("S256"));
        if !supports_s256 {
            return Err(error("Authorization server does not support PKCE S256"));
        }
    }

    let auth_raw = meta
        .get("authorization_endpoint")
        .and_then(Value::as_str)
        .ok_or_else(|| error("Missing authorization_endpoint in OAuth metadata"))?;
    let token_raw = meta
        .get("token_endpoint")
        .and_then(Value::as_str)
        .ok_or_else(|| error("Missing token_endpoint in OAuth metadata"))?;

    let authorization_endpoint = discovered_endpoint(&auth_server_base, auth_raw)?;
    let token_endpoint = discovered_endpoint(&auth_server_base, token_raw)?;

    Ok(OAuthMetadata {
        authorization_endpoint,
        token_endpoint,
    })
}

fn form_encode(pairs: &[(&str, &str)]) -> Result<String> {
    let mut dummy = Url::parse(&loopback_http_url(None, "/"))
        .map_err(|_| error("Cannot initialize form encoder"))?;
    {
        let mut q = dummy.query_pairs_mut();
        for (k, v) in pairs {
            q.append_pair(k, v);
        }
    }
    Ok(dummy.query().unwrap_or("").to_owned())
}

fn wait_for_loopback_callback(
    listener: TcpListener,
    expected_state: &str,
    timeout: Duration,
) -> Result<String> {
    listener.set_nonblocking(true)?;
    let deadline = std::time::Instant::now() + timeout;
    let mut stream = loop {
        match listener.accept() {
            Ok((s, _)) => break s,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                if std::time::Instant::now() >= deadline {
                    return Err(error("Timed out waiting for OAuth loopback callback"));
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(e) => return Err(e),
        }
    };
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut buf = [0u8; 8192];
    let n = stream.read(&mut buf)?;
    let req_str = std::str::from_utf8(&buf[..n]).map_err(|_| error("Non-UTF8 OAuth callback"))?;
    let first_line = req_str
        .lines()
        .next()
        .ok_or_else(|| error("Empty OAuth callback request"))?;
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    if method != "GET" || !target.starts_with("/callback") {
        let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\nInvalid callback");
        return Err(error("Unexpected OAuth callback path or method"));
    }
    let parsed = Url::parse(&loopback_http_url(None, target))
        .map_err(|_| error("Invalid OAuth callback URL"))?;
    let mut code = None;
    let mut state = None;
    let mut oauth_err = None;
    for (k, v) in parsed.query_pairs() {
        match k.as_ref() {
            "code" => code = Some(v.into_owned()),
            "state" => state = Some(v.into_owned()),
            "error" => oauth_err = Some(v.into_owned()),
            _ => {}
        }
    }
    let _ = stream.write_all(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\n\r\n<!doctype html><html><body><p>Agent Bridge OAuth callback received. You may close this tab.</p></body></html>",
    );
    if oauth_err.is_some() {
        return Err(error("OAuth authorization was denied or returned an error"));
    }
    let got_state = state.ok_or_else(|| error("Missing OAuth state in callback"))?;
    if !ct_eq_str(&got_state, expected_state) {
        return Err(error("OAuth callback state mismatch"));
    }
    let code = code.ok_or_else(|| error("Missing authorization code in callback"))?;
    if code.is_empty() || code.len() > 2048 || code.chars().any(char::is_control) {
        return Err(error("Invalid authorization code"));
    }
    Ok(code)
}

fn exchange_code(
    token_endpoint: &Url,
    endpoint_str: &str,
    cfg: &OAuthServerConfig,
    code: &str,
    verifier: &str,
    redirect_uri: &str,
) -> Result<StoredTokenRecord> {
    let client_id = cfg
        .client_id
        .as_deref()
        .ok_or_else(|| error("OAuth client_id is required for token exchange"))?;
    let auth_method = cfg.client_auth_method.unwrap_or(ClientAuthMethod::None);
    let secret = match auth_method {
        ClientAuthMethod::None => None,
        ClientAuthMethod::ClientSecretBasic | ClientAuthMethod::ClientSecretPost => {
            let env_name = cfg
                .client_secret_env
                .as_deref()
                .ok_or_else(|| error("OAuth client_secret_env is required for confidential client"))?;
            if !valid_secret_env_name(env_name) {
                return Err(error("Invalid OAuth client_secret_env reference"));
            }
            let val = std::env::var(env_name)
                .map_err(|_| error("Configured OAuth client secret environment variable is unset"))?;
            if val.is_empty() {
                return Err(error("Configured OAuth client secret environment variable is empty"));
            }
            Some(val)
        }
    };

    let mut form_pairs: Vec<(&str, &str)> = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("code_verifier", verifier),
        ("resource", endpoint_str),
    ];

    let client = oauth_http_client()?;
    let mut req = client
        .post(token_endpoint.clone())
        .header("Accept", "application/json")
        .header("Content-Type", "application/x-www-form-urlencoded");

    match auth_method {
        ClientAuthMethod::ClientSecretBasic => {
            let basic_raw = format!("{client_id}:{}", secret.as_deref().unwrap_or(""));
            let encoded = base64_std(basic_raw.as_bytes());
            req = req.header("Authorization", format!("Basic {encoded}"));
        }
        ClientAuthMethod::ClientSecretPost => {
            form_pairs.push(("client_id", client_id));
            form_pairs.push(("client_secret", secret.as_deref().unwrap_or("")));
        }
        ClientAuthMethod::None => {
            form_pairs.push(("client_id", client_id));
        }
    }

    let body = form_encode(&form_pairs)?;
    let resp = req
        .body(body)
        .send()
        .map_err(|_| error("OAuth token exchange request failed"))?;
    if !resp.status().is_success() {
        return Err(error("OAuth token endpoint returned non-success status"));
    }
    let mut bytes = Vec::new();
    resp.take((MAX_TOKEN_RESPONSE_BYTES as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| error("Incomplete OAuth token response"))?;
    if bytes.len() > MAX_TOKEN_RESPONSE_BYTES {
        return Err(error("OAuth token response exceeds byte limit"));
    }
    let payload: Value =
        serde_json::from_slice(&bytes).map_err(|_| error("Invalid OAuth token JSON"))?;
    let access_token = payload
        .get("access_token")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 16384)
        .ok_or_else(|| error("OAuth token response missing access_token"))?
        .to_owned();
    let refresh_token = payload
        .get("refresh_token")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 16384)
        .map(str::to_owned);
    let token_type = payload
        .get("token_type")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let scope = payload
        .get("scope")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| cfg.scope.clone());
    let now = unix_now_secs();
    let expires_at_unix_secs = payload
        .get("expires_in")
        .and_then(Value::as_u64)
        .map(|ttl| now.saturating_add(ttl));

    Ok(StoredTokenRecord {
        access_token,
        refresh_token,
        token_type,
        scope,
        expires_at_unix_secs,
        endpoint: endpoint_str.to_owned(),
        obtained_at_unix_secs: now,
    })
}

/// Runs a complete OAuth 2.1 PKCE S256 authorization flow for one locally
/// approved server and stores the resulting token in the OS-protected store.
pub fn run_oauth_flow<F>(
    settings: &Path,
    server: &str,
    endpoint_str: &str,
    cfg: &OAuthServerConfig,
    force: bool,
    open_auth_url: F,
) -> Result<Value>
where
    F: FnOnce(&str) -> Result<()>,
{
    if !cfg.enabled {
        return Err(error("Outbound OAuth is not enabled for this extension server"));
    }
    // Enforce the same public-resource credential prohibition before token
    // reuse, metadata discovery, browser authorization or secret resolution.
    crate::validate_header_env(endpoint_str, &BTreeMap::new(), true)?;
    cfg.validate()?;
    let client_id = cfg
        .client_id
        .as_deref()
        .ok_or_else(|| error("OAuth client_id must be configured via set_oauth before auth_start"))?;

    if !force {
        let existing = OAuthTokenStore::load_status(settings, server)?;
        if existing.token_stored && !existing.token_expired {
            return Ok(json!({
                "server": server,
                "authorized": true,
                "already_authorized": true,
                "token_stored": true,
                "has_refresh_token": existing.has_refresh_token,
                "expires_at_unix_secs": existing.expires_at_unix_secs,
                "granted_scope": existing.granted_scope,
                "storage_protection": existing.storage_protection,
            }));
        }
    }

    let meta = discover_oauth_metadata(endpoint_str)?;
    let listener = TcpListener::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))?;
    let port = listener.local_addr()?.port();
    let redirect_uri = loopback_http_url(Some(port), "/callback");
    let (verifier, challenge) = generate_pkce_s256()?;
    let state = random_state_token()?;

    let mut auth_url = meta.authorization_endpoint.clone();
    {
        let mut q = auth_url.query_pairs_mut();
        q.append_pair("response_type", "code");
        q.append_pair("client_id", client_id);
        q.append_pair("redirect_uri", &redirect_uri);
        q.append_pair("code_challenge", &challenge);
        q.append_pair("code_challenge_method", "S256");
        q.append_pair("state", &state);
        q.append_pair("resource", endpoint_str);
        if let Some(scope) = &cfg.scope {
            q.append_pair("scope", scope);
        }
    }

    open_auth_url(auth_url.as_str())?;
    let code = wait_for_loopback_callback(listener, &state, CALLBACK_TIMEOUT)?;
    let record = exchange_code(
        &meta.token_endpoint,
        endpoint_str,
        cfg,
        &code,
        &verifier,
        &redirect_uri,
    )?;
    OAuthTokenStore::store_token(settings, server, &record)?;
    let summary = OAuthTokenStore::load_status(settings, server)?;
    Ok(json!({
        "server": server,
        "authorized": true,
        "already_authorized": false,
        "token_stored": summary.token_stored,
        "has_refresh_token": summary.has_refresh_token,
        "expires_at_unix_secs": summary.expires_at_unix_secs,
        "granted_scope": summary.granted_scope,
        "storage_protection": summary.storage_protection,
    }))
}

#[cfg(test)]
mod discovery_tests {
    use super::*;

    #[test]
    fn discovery_preserves_https_and_the_approved_loopback_origin() {
        let remote = Url::parse("https://resource.example").unwrap();
        let local = Url::parse("http://127.0.0.1:8080/mcp").unwrap();
        let local_token = "http://127.0.0.1:8080/token";
        let issuer = "https://identity.example/authorize";
        assert!(discovered_endpoint(&remote, issuer).is_ok());
        assert!(discovered_endpoint(&local, issuer).is_ok());
        assert!(discovered_endpoint(&local, local_token).is_ok());
        assert!(discovered_endpoint(&remote, local_token).is_err());
        assert!(discovered_endpoint(&local, "http://127.0.0.1:8081/token").is_err());
    }
}
