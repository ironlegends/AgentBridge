//! Instance-scoped, immutable, checksum-verified temporary artifact store.
//!
//! All workspace reads go strictly through the instance's `cap-std` directory
//! capability without following symlinks, Windows reparse points, or hard
//! links. Published copies live in private per-instance memory with
//! unpredictable IDs, strict count/size/chunk/TTL bounds, and zero writes to
//! the workspace or shared temporary directories.

use super::*;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;

pub(super) const MAX_ARTIFACTS: usize = 64;
pub(super) const MAX_ARTIFACT_BYTES: usize = 4 * 1_048_576;
pub(super) const MAX_TOTAL_ARTIFACT_BYTES: usize = 16 * 1_048_576;
pub(super) const MAX_ARTIFACT_READ_BYTES: usize = 262_144;
pub(super) const DEFAULT_ARTIFACT_READ_BYTES: usize = 65_536;
pub(super) const MIN_RETENTION_SECONDS: i64 = 60;
pub(super) const MAX_RETENTION_SECONDS: i64 = 604_800;
pub(super) const DEFAULT_RETENTION_SECONDS: i64 = 3_600;
const MAX_ARTIFACT_ID_BYTES: usize = 128;
const MAX_LIST_LIMIT: i64 = 200;
const DEFAULT_LIST_LIMIT: i64 = 50;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    volume: u64,
    number: u128,
}

struct ArtifactRecord {
    seq: u64,
    artifact_id: String,
    source_path: String,
    data: Arc<[u8]>,
    sha256: String,
    created_at_secs: u64,
    expires_at_secs: u64,
    retention_seconds: u64,
    expires_at: Instant,
}

impl ArtifactRecord {
    fn metadata_json(&self) -> Value {
        json!({
            "artifact_id": self.artifact_id,
            "source_path": self.source_path,
            "size_bytes": self.data.len(),
            "sha256": self.sha256,
            "created_at": format_unix_utc(self.created_at_secs),
            "expires_at": format_unix_utc(self.expires_at_secs),
            "retention_seconds": self.retention_seconds,
        })
    }
}

pub(super) struct ArtifactStore {
    records: HashMap<String, ArtifactRecord>,
    total_bytes: usize,
    next_seq: u64,
}

impl ArtifactStore {
    pub(super) fn new() -> Self {
        Self {
            records: HashMap::new(),
            total_bytes: 0,
            next_seq: 0,
        }
    }

    pub(super) fn prune(&mut self) {
        let now = Instant::now();
        let mut reclaimed = 0usize;
        self.records.retain(|_, record| {
            if record.expires_at <= now {
                reclaimed = reclaimed.saturating_add(record.data.len());
                false
            } else {
                true
            }
        });
        self.total_bytes = self.total_bytes.saturating_sub(reclaimed);
    }

    fn insert(
        &mut self,
        source_path: String,
        bytes: Vec<u8>,
        retention_seconds: u64,
    ) -> Result<Value> {
        self.prune();
        if self.records.len() >= MAX_ARTIFACTS {
            return Err(DesktopError::new(
                "ARTIFACT_LIMIT_EXCEEDED",
                format!("Active artifact limit ({MAX_ARTIFACTS}) reached; delete expired or unused artifacts first"),
            ));
        }
        let next_total = self
            .total_bytes
            .checked_add(bytes.len())
            .filter(|&sum| sum <= MAX_TOTAL_ARTIFACT_BYTES)
            .ok_or_else(|| {
                DesktopError::new(
                    "ARTIFACT_STORAGE_LIMIT_EXCEEDED",
                    format!("Total artifact storage limit ({MAX_TOTAL_ARTIFACT_BYTES} bytes) exceeded"),
                )
            })?;

        let data: Arc<[u8]> = Arc::from(bytes);
        let sha256 = hex_hash(&data);
        let artifact_id = self.next_unique_id()?;
        let now_instant = Instant::now();
        let expires_at = now_instant
            .checked_add(Duration::from_secs(retention_seconds))
            .ok_or_else(|| DesktopError::new("INVALID_ARGUMENT", "retention_seconds overflow"))?;
        let created_at_secs = unix_now_secs();
        let expires_at_secs = created_at_secs.saturating_add(retention_seconds);

        self.next_seq = self.next_seq.saturating_add(1);
        let record = ArtifactRecord {
            seq: self.next_seq,
            artifact_id: artifact_id.clone(),
            source_path,
            data,
            sha256,
            created_at_secs,
            expires_at_secs,
            retention_seconds,
            expires_at,
        };
        let meta = record.metadata_json();
        self.records.insert(artifact_id, record);
        self.total_bytes = next_total;
        Ok(meta)
    }

    fn next_unique_id(&self) -> Result<String> {
        for _ in 0..8 {
            let id = format!("art_{}", Uuid::new_v4().simple());
            if !self.records.contains_key(&id) {
                return Ok(id);
            }
        }
        Err(DesktopError::new(
            "ARTIFACT_ID_UNAVAILABLE",
            "Unable to allocate unique artifact identifier",
        ))
    }

    fn list(&mut self, limit: usize) -> Value {
        self.prune();
        let mut refs: Vec<&ArtifactRecord> = self.records.values().collect();
        refs.sort_unstable_by(|a, b| b.seq.cmp(&a.seq));
        let total = refs.len();
        let truncated = total > limit;
        let artifacts: Vec<Value> = refs
            .into_iter()
            .take(limit)
            .map(ArtifactRecord::metadata_json)
            .collect();
        json!({
            "action": "list",
            "artifacts": artifacts,
            "count": artifacts.len(),
            "total": total,
            "truncated": truncated,
        })
    }

    fn get(&mut self, artifact_id: &str) -> Result<Value> {
        self.prune();
        let record = self
            .records
            .get(artifact_id)
            .ok_or_else(artifact_not_found)?;
        Ok(json!({
            "action": "get",
            "artifact": record.metadata_json(),
        }))
    }

    fn read(
        &mut self,
        artifact_id: &str,
        offset: usize,
        length: usize,
        encoding: &str,
    ) -> Result<Value> {
        self.prune();
        let record = self
            .records
            .get(artifact_id)
            .ok_or_else(artifact_not_found)?;

        let data = &record.data;
        let total = data.len();
        if offset > total {
            return Err(DesktopError::new(
                "INVALID_OFFSET",
                format!("offset ({offset}) exceeds artifact size ({total} bytes)"),
            ));
        }

        if offset == total {
            return Ok(json!({
                "action": "read",
                "artifact_id": record.artifact_id,
                "encoding": encoding,
                "offset": offset,
                "bytes_read": 0,
                "next_offset": total,
                "total_bytes": total,
                "eof": true,
                "has_more": false,
                "sha256": record.sha256,
                "chunk_sha256": hex_hash(&[]),
                "content": "",
            }));
        }

        let raw_end = offset.saturating_add(length).min(total);
        let (chunk, content) = match encoding {
            "base64" => {
                let slice = &data[offset..raw_end];
                (slice, encode_base64(slice))
            }
            "utf8" => {
                let slice = &data[offset..raw_end];
                match std::str::from_utf8(slice) {
                    Ok(text) => (slice, text.to_owned()),
                    Err(err) if err.error_len().is_none() && raw_end < total => {
                        let valid_len = err.valid_up_to();
                        if valid_len > 0 {
                            let safe_slice = &slice[..valid_len];
                            let text = std::str::from_utf8(safe_slice).map_err(|_| {
                                DesktopError::new(
                                    "INVALID_UTF8",
                                    "Artifact chunk is not valid UTF-8; use encoding \"base64\"",
                                )
                            })?;
                            (safe_slice, text.to_owned())
                        } else {
                            let probe_end = offset.saturating_add(4).min(total);
                            if starts_with_valid_utf8_char(&data[offset..probe_end]) {
                                return Err(DesktopError::new(
                                    "INVALID_UTF8_BOUNDARY",
                                    "Requested length is too small for the UTF-8 character at offset; increase length or use encoding \"base64\"",
                                ));
                            }
                            return Err(DesktopError::new(
                                "INVALID_UTF8",
                                "Artifact chunk is not valid UTF-8; use encoding \"base64\"",
                            ));
                        }
                    }
                    Err(_) => {
                        return Err(DesktopError::new(
                            "INVALID_UTF8",
                            "Artifact chunk is not valid UTF-8; use encoding \"base64\"",
                        ));
                    }
                }
            }
            _ => {
                return Err(DesktopError::new(
                    "INVALID_ARGUMENT",
                    "encoding must be utf8 or base64",
                ));
            }
        };

        let bytes_read = chunk.len();
        let next_offset = offset + bytes_read;
        let eof = next_offset >= total;

        Ok(json!({
            "action": "read",
            "artifact_id": record.artifact_id,
            "encoding": encoding,
            "offset": offset,
            "bytes_read": bytes_read,
            "next_offset": next_offset,
            "total_bytes": total,
            "eof": eof,
            "has_more": !eof,
            "sha256": record.sha256,
            "chunk_sha256": hex_hash(chunk),
            "content": content,
        }))
    }

    fn delete(&mut self, artifact_id: &str) -> Result<Value> {
        self.prune();
        let removed = self
            .records
            .remove(artifact_id)
            .ok_or_else(artifact_not_found)?;
        self.total_bytes = self.total_bytes.saturating_sub(removed.data.len());
        Ok(json!({
            "action": "delete",
            "artifact_id": removed.artifact_id,
            "deleted": true,
        }))
    }
}

pub(super) fn tool_spec() -> ToolSpec {
    spec(
        "desktop_artifact_manage",
        "Keep a temporary, checksum-verified copy of a workspace file for chunked reads. Publish returns artifact metadata; list finds stored IDs, get returns metadata, read returns a chunk and next offset, and delete removes the stored copy. Publishing and deleting require a writable profile. The source file is unchanged.",
        json!({
            "action": {
                "description": "Operation to perform. Supply path for publish and artifact_id for get, read or delete; list accepts an optional limit.",
                "type": "string",
                "enum": ["publish", "list", "get", "read", "delete"]
            },
            "artifact_id": {
                "description": "Instance-local ID from publish or list. Required for get, read and delete.",
                "type": "string",
                "minLength": 1,
                "maxLength": MAX_ARTIFACT_ID_BYTES
            },
            "encoding": {
                "description": "Representation of a read chunk: utf8 for text or base64 for arbitrary bytes.",
                "type": "string",
                "enum": ["utf8", "base64"]
            },
            "length": {
                "description": "Maximum bytes to read in this chunk. Used only with read.",
                "type": "integer",
                "minimum": 1,
                "maximum": MAX_ARTIFACT_READ_BYTES
            },
            "limit": {
                "description": "Maximum number of artifacts to return for list.",
                "type": "integer",
                "minimum": 1,
                "maximum": MAX_LIST_LIMIT
            },
            "offset": {
                "description": "Zero-based byte offset for read. Use next_offset from the preceding chunk.",
                "type": "integer",
                "minimum": 0,
                "maximum": MAX_SAFE_INTEGER
            },
            "path": {
                "type": "string",
                "minLength": 1,
                "maxLength": MAX_PATH_BYTES,
                "description": "Workspace-relative path of a regular file"
            },
            "retention_seconds": {
                "description": "Lifetime of the stored copy from publication, in seconds. Used only with publish.",
                "type": "integer",
                "minimum": MIN_RETENTION_SECONDS,
                "maximum": MAX_RETENTION_SECONDS
            }
        }),
        &["action"],
    )
}

impl DesktopFiles {
    pub(super) fn manage_artifacts(&self, v: &Value) -> Result<Value> {
        let raw_obj = v
            .as_object()
            .ok_or_else(|| DesktopError::new("INVALID_ARGUMENT", "Arguments must be an object"))?;
        let action = required_string(raw_obj, "action", 32)?;

        match action {
            "publish" => {
                let a = object(v, &["action", "path", "retention_seconds"])?;
                if !self.workspace_write {
                    return Err(DesktopError::new(
                        "READ_ONLY",
                        "Artifact publishing requires a writable workspace profile",
                    ));
                }
                let path = required_string(a, "path", MAX_PATH_BYTES)?;
                let retention_seconds = int_in(
                    a,
                    "retention_seconds",
                    DEFAULT_RETENTION_SECONDS,
                    MIN_RETENTION_SECONDS,
                    MAX_RETENTION_SECONDS,
                )? as u64;
                let parts = relative_parts(path, false)?;
                let (parent, name) = self.parent_and_name(&parts)?;
                let data = read_verified_artifact_bytes(&parent, &name)?;
                let mut store = self.artifacts.lock().map_err(|_| {
                    DesktopError::new(
                        "LOCK_POISONED",
                        "Artifact store lock is poisoned; refusing access",
                    )
                })?;
                let artifact = store.insert(display_parts(&parts), data, retention_seconds)?;
                Ok(json!({
                    "action": "publish",
                    "artifact": artifact,
                }))
            }
            "list" => {
                let a = object(v, &["action", "limit"])?;
                let limit = int_in(a, "limit", DEFAULT_LIST_LIMIT, 1, MAX_LIST_LIMIT)? as usize;
                let mut store = self.artifacts.lock().map_err(|_| {
                    DesktopError::new(
                        "LOCK_POISONED",
                        "Artifact store lock is poisoned; refusing access",
                    )
                })?;
                Ok(store.list(limit))
            }
            "get" => {
                let a = object(v, &["action", "artifact_id"])?;
                let artifact_id = validate_artifact_id(a)?;
                let mut store = self.artifacts.lock().map_err(|_| {
                    DesktopError::new(
                        "LOCK_POISONED",
                        "Artifact store lock is poisoned; refusing access",
                    )
                })?;
                store.get(artifact_id)
            }
            "read" => {
                let a = object(v, &["action", "artifact_id", "offset", "length", "encoding"])?;
                let artifact_id = validate_artifact_id(a)?;
                let offset_i64 = int_in(a, "offset", 0, 0, MAX_SAFE_INTEGER)?;
                let offset = usize::try_from(offset_i64).map_err(|_| {
                    DesktopError::new("INVALID_OFFSET", "offset exceeds addressable range")
                })?;
                let length = int_in(
                    a,
                    "length",
                    DEFAULT_ARTIFACT_READ_BYTES as i64,
                    1,
                    MAX_ARTIFACT_READ_BYTES as i64,
                )? as usize;
                let encoding = optional_string(a, "encoding", "utf8")?;
                if encoding != "utf8" && encoding != "base64" {
                    return Err(DesktopError::new(
                        "INVALID_ARGUMENT",
                        "encoding must be utf8 or base64",
                    ));
                }
                let mut store = self.artifacts.lock().map_err(|_| {
                    DesktopError::new(
                        "LOCK_POISONED",
                        "Artifact store lock is poisoned; refusing access",
                    )
                })?;
                store.read(artifact_id, offset, length, encoding)
            }
            "delete" => {
                let a = object(v, &["action", "artifact_id"])?;
                if !self.workspace_write {
                    return Err(DesktopError::new(
                        "READ_ONLY",
                        "Artifact deletion requires a writable workspace profile",
                    ));
                }
                let artifact_id = validate_artifact_id(a)?;
                let mut store = self.artifacts.lock().map_err(|_| {
                    DesktopError::new(
                        "LOCK_POISONED",
                        "Artifact store lock is poisoned; refusing access",
                    )
                })?;
                store.delete(artifact_id)
            }
            _ => Err(DesktopError::new(
                "INVALID_ARGUMENT",
                "action must be one of publish, list, get, read, delete",
            )),
        }
    }
}

fn validate_artifact_id<'a>(a: &'a Map<String, Value>) -> Result<&'a str> {
    let id = required_string(a, "artifact_id", MAX_ARTIFACT_ID_BYTES)?;
    if id.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(DesktopError::new(
            "INVALID_ARGUMENT",
            "artifact_id must not contain whitespace or control characters",
        ));
    }
    Ok(id)
}

fn artifact_not_found() -> DesktopError {
    DesktopError::new(
        "ARTIFACT_NOT_FOUND",
        "Artifact unknown, expired, deleted, or belongs to another instance",
    )
}

fn read_verified_artifact_bytes(parent: &Dir, name: &str) -> Result<Vec<u8>> {
    validate_segment(name)?;
    let before = parent.symlink_metadata(name)?;
    ensure_regular(&before)?;
    if before.len() > MAX_ARTIFACT_BYTES as u64 {
        return Err(DesktopError::new(
            "ARTIFACT_TOO_LARGE",
            format!("File exceeds maximum artifact size ({MAX_ARTIFACT_BYTES} bytes)"),
        ));
    }

    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let mut file = parent.open_with(name, &options)?;
    let opened = file.metadata()?;
    ensure_regular(&opened)?;
    if !same_file(&before, &opened) {
        return Err(DesktopError::new(
            "STALE_FILE",
            "File changed while opening for artifact publication",
        ));
    }
    let file_key = file_identity(&file)?;

    let mut data = Vec::new();
    (&mut file)
        .take((MAX_ARTIFACT_BYTES + 1) as u64)
        .read_to_end(&mut data)?;
    if data.len() > MAX_ARTIFACT_BYTES {
        return Err(DesktopError::new(
            "ARTIFACT_TOO_LARGE",
            format!("File grew beyond maximum artifact size ({MAX_ARTIFACT_BYTES} bytes)"),
        ));
    }

    let after = file.metadata()?;
    ensure_regular(&after)?;
    if !same_file(&opened, &after) || after.len() != data.len() as u64 {
        return Err(DesktopError::new(
            "STALE_FILE",
            "File changed while reading for artifact publication",
        ));
    }

    let by_path = parent.symlink_metadata(name)?;
    ensure_regular(&by_path)?;
    if !same_file(&after, &by_path) {
        return Err(DesktopError::new(
            "STALE_FILE",
            "Path changed while reading for artifact publication",
        ));
    }

    let verified = parent.open_with(name, &options)?;
    if file_identity(&verified)? != file_key {
        return Err(DesktopError::new(
            "STALE_FILE",
            "Path identity changed during artifact publication",
        ));
    }

    Ok(data)
}

#[cfg(unix)]
fn file_identity(file: &File) -> Result<FileIdentity> {
    use cap_std::fs::MetadataExt;
    let md = file.metadata()?;
    if md.nlink() != 1 {
        return Err(DesktopError::new(
            "UNSAFE_HARD_LINK",
            "Hard-linked files cannot be published as artifacts",
        ));
    }
    Ok(FileIdentity {
        volume: md.dev(),
        number: u128::from(md.ino()),
    })
}

#[cfg(windows)]
fn file_identity(file: &File) -> Result<FileIdentity> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, GetFileInformationByHandleEx, BY_HANDLE_FILE_INFORMATION,
        FILE_ID_INFO, FileIdInfo,
    };
    let handle = file.as_raw_handle();
    let mut basic: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: borrowed live file HANDLE and initialized Win32 output struct.
    if unsafe { GetFileInformationByHandle(handle, &mut basic) } == 0 {
        return Err(DesktopError::new(
            "IDENTITY_UNAVAILABLE",
            io::Error::last_os_error().to_string(),
        ));
    }
    if basic.nNumberOfLinks != 1 {
        return Err(DesktopError::new(
            "UNSAFE_HARD_LINK",
            "Hard-linked files cannot be published as artifacts",
        ));
    }
    let mut extended: FILE_ID_INFO = unsafe { std::mem::zeroed() };
    // SAFETY: initialized output buffer with exact size for a live HANDLE.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileIdInfo,
            (&mut extended as *mut FILE_ID_INFO).cast(),
            std::mem::size_of::<FILE_ID_INFO>() as u32,
        )
    };
    if ok != 0 {
        let number = u128::from_le_bytes(extended.FileId.Identifier);
        if number == 0 {
            return Err(DesktopError::new("IDENTITY_UNAVAILABLE", "Zero file ID"));
        }
        return Ok(FileIdentity {
            volume: extended.VolumeSerialNumber,
            number,
        });
    }
    let failure = io::Error::last_os_error();
    if !matches!(failure.raw_os_error(), Some(50) | Some(87)) {
        return Err(DesktopError::new("IDENTITY_UNAVAILABLE", failure.to_string()));
    }
    let index = (u64::from(basic.nFileIndexHigh) << 32) | u64::from(basic.nFileIndexLow);
    if index == 0 {
        return Err(DesktopError::new(
            "IDENTITY_UNAVAILABLE",
            "Zero legacy file index",
        ));
    }
    Ok(FileIdentity {
        volume: u64::from(basic.dwVolumeSerialNumber),
        number: u128::from(index),
    })
}

#[cfg(not(any(unix, windows)))]
fn file_identity(_file: &File) -> Result<FileIdentity> {
    Err(DesktopError::new(
        "UNSUPPORTED_PLATFORM",
        "Windows/Unix only",
    ))
}

fn starts_with_valid_utf8_char(bytes: &[u8]) -> bool {
    match std::str::from_utf8(bytes) {
        Ok(s) => !s.is_empty(),
        Err(err) => err.valid_up_to() > 0,
    }
}

pub(super) fn encode_base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(input.len().div_ceil(3) * 4);
    let mut chunks = input.chunks_exact(3);
    for chunk in &mut chunks {
        let a = chunk[0];
        let b = chunk[1];
        let c = chunk[2];
        out.push(ALPHABET[(a >> 2) as usize]);
        out.push(ALPHABET[(((a & 0x03) << 4) | (b >> 4)) as usize]);
        out.push(ALPHABET[(((b & 0x0f) << 2) | (c >> 6)) as usize]);
        out.push(ALPHABET[(c & 0x3f) as usize]);
    }
    match chunks.remainder() {
        [a] => {
            out.push(ALPHABET[(a >> 2) as usize]);
            out.push(ALPHABET[((a & 0x03) << 4) as usize]);
            out.push(b'=');
            out.push(b'=');
        }
        [a, b] => {
            out.push(ALPHABET[(a >> 2) as usize]);
            out.push(ALPHABET[(((a & 0x03) << 4) | (b >> 4)) as usize]);
            out.push(ALPHABET[((b & 0x0f) << 2) as usize]);
            out.push(b'=');
        }
        _ => {}
    }
    // SAFETY: ALPHABET and '=' are pure ASCII bytes.
    unsafe { String::from_utf8_unchecked(out) }
}

pub(super) fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub(super) fn format_unix_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let sod = (secs % 86_400) as u32;
    let (year, month, day) = civil_from_days(days);
    let hour = sod / 3_600;
    let min = (sod % 3_600) / 60;
    let sec = sod % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}Z")
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    (year, m as u32, d as u32)
}
