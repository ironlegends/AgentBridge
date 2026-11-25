use super::*;
use artifacts::{encode_base64, format_unix_utc, unix_now_secs};
use std::collections::HashMap;
use std::io::{Seek, SeekFrom};
use unified_transfer::{anonymous_file, ownership_lock, private_child_directory, AnonymousFile, Source, BLOCK_BYTES, MAX_TRANSFER_BYTES};

pub(super) const MAX_TOTAL_BYTES: usize = 256 * 1024 * 1024;

struct Record {
    id: String,
    label: String,
    file: AnonymousFile,
    bytes: usize,
    sha256: String,
    blocks: Vec<[u8; 32]>,
    created: u64,
    expires: Instant,
    retention: u64,
    sequence: u64,
}
impl Record {
    fn metadata(&self) -> Value {
        json!({"artifact_id":self.id,"source_path":self.label,"size_bytes":self.bytes,
            "sha256":self.sha256,"created_at":format_unix_utc(self.created),
            "expires_at":format_unix_utc(self.created.saturating_add(self.retention)),"retention_seconds":self.retention})
    }

    fn chunk(&mut self, offset: usize, length: usize, encoding: &str) -> Result<Value> {
        if offset > self.bytes { return Err(DesktopError::new("INVALID_OFFSET", "Offset exceeds artifact size")); }
        let file = self.file.file.as_mut().ok_or_else(|| DesktopError::new("ARTIFACT_CLEANUP_PENDING", "Artifact is closing"))?;
        if file.metadata()?.len() != self.bytes as u64 {
            return Err(DesktopError::new("ARTIFACT_INTEGRITY_FAILED", "Stored artifact size changed"));
        }
        let end = offset.saturating_add(length).min(self.bytes);
        let aligned = offset / BLOCK_BYTES * BLOCK_BYTES;
        let mut selected = Vec::with_capacity(length.min(self.bytes.saturating_sub(offset)));
        if offset < end {
            file.seek(SeekFrom::Start(aligned as u64))?;
            let mut block = [0u8; BLOCK_BYTES];
            let mut position = aligned;
            while position < end {
                let size = BLOCK_BYTES.min(self.bytes - position);
                file.read_exact(&mut block[..size])?;
                let hash: [u8; 32] = Sha256::digest(&block[..size]).into();
                if self.blocks.get(position / BLOCK_BYTES) != Some(&hash) {
                    return Err(DesktopError::new("ARTIFACT_INTEGRITY_FAILED", "Stored artifact chunk changed"));
                }
                let begin = offset.saturating_sub(position);
                let stop = size.min(end - position);
                selected.extend_from_slice(&block[begin..stop]);
                position += size;
            }
        }
        let content = match encoding {
            "base64" => encode_base64(&selected),
            "utf8" => match std::str::from_utf8(&selected) {
                Ok(value) => value.to_owned(),
                Err(error) if error.error_len().is_none() && end < self.bytes && error.valid_up_to() > 0 => {
                    let valid = error.valid_up_to();
                    selected.truncate(valid);
                    std::str::from_utf8(&selected).map_err(|_| DesktopError::new("INVALID_UTF8", "Use base64 for binary data"))?.to_owned()
                }
                Err(error) if error.error_len().is_none() && end < self.bytes =>
                    return Err(DesktopError::new("INVALID_UTF8_BOUNDARY", "Increase length or use base64")),
                Err(_) => return Err(DesktopError::new("INVALID_UTF8", "Use base64 for binary data")),
            },
            _ => return Err(DesktopError::new("INVALID_ARGUMENT", "encoding must be utf8 or base64")),
        };
        let next = offset + selected.len();
        Ok(json!({"action":"read","artifact_id":self.id,"encoding":encoding,"offset":offset,
            "bytes_read":selected.len(),"next_offset":next,"total_bytes":self.bytes,
            "eof":next==self.bytes,"has_more":next<self.bytes,"sha256":self.sha256,
            "chunk_sha256":hex_hash(&selected),"content":content}))
    }
}

pub(super) struct StreamStore {
    directory: Dir,
    _lock: File,
    records: HashMap<String, Record>,
    total: usize,
    sequence: u64,
    pending: Vec<AnonymousFile>,
}

impl StreamStore {
    pub fn open(private_root: &Dir) -> Result<Self> {
        let directory = private_child_directory(private_root, "artifacts")?;
        let lock = ownership_lock(&directory)?;
        for entry in directory.entries()? {
            let entry = entry?;
            if entry.file_name() != "owner.lock" {
                return Err(DesktopError::new("ARTIFACT_RECONCILIATION_REQUIRED", "Private artifact files remain from another or uncertain owner"));
            }
        }
        Ok(Self { directory, _lock:lock, records:HashMap::new(), total:0, sequence:0, pending:Vec::new() })
    }

    fn reconcile(&mut self) -> Result<()> {
        let mut remaining = Vec::new();
        for mut file in self.pending.drain(..) {
            if file.close(&self.directory).is_err() { remaining.push(file); }
        }
        self.pending = remaining;
        if !self.pending.is_empty() {
            return Err(DesktopError::new("ARTIFACT_CLEANUP_PENDING", "Private artifact cleanup must complete before another transfer"));
        }
        Ok(())
    }

    fn prune(&mut self) -> Result<()> {
        let now = Instant::now();
        let expired = self.records.iter().filter(|(_, r)| r.expires <= now).map(|(id, _)| id.clone()).collect::<Vec<_>>();
        for id in expired {
            if let Some(record) = self.records.remove(&id) { self.pending.push(record.file); }
        }
        self.total = self.records.values().map(|r| r.bytes).sum();
        self.reconcile()
    }

    pub fn insert(&mut self, mut source: Source, label: String, retention: u64) -> Result<Value> {
        self.prune()?;
        if self.records.len() >= artifacts::MAX_ARTIFACTS || self.total.checked_add(source.len()).is_none_or(|n| n > MAX_TOTAL_BYTES) {
            return Err(DesktopError::new("ARTIFACT_STORAGE_LIMIT_EXCEEDED", "Artifact count or total byte budget reached"));
        }
        let mut file = anonymous_file(&self.directory)?;
        let copy = unified_transfer::verify_private_file(file.file.as_ref().expect("new artifact has a file"))
            .and_then(|()| file.unlink_early(&self.directory))
            .and_then(|()| source.copy_to(file.file.as_mut().expect("new artifact has a file")));
        let copied = match copy {
            Ok(value) => value,
            Err(error) => { self.pending.push(file); self.reconcile()?; return Err(error); }
        };
        let id = format!("art_{}", Uuid::new_v4().simple());
        if self.records.contains_key(&id) {
            self.pending.push(file); self.reconcile()?;
            return Err(DesktopError::new("ARTIFACT_ID_UNAVAILABLE", "Cannot allocate an artifact capability"));
        }
        self.sequence = self.sequence.saturating_add(1);
        let record = Record { id:id.clone(), label, file, bytes:copied.bytes,
            sha256:copied.sha256, blocks:copied.blocks, created:unix_now_secs(),
            expires:Instant::now()+Duration::from_secs(retention), retention, sequence:self.sequence };
        let metadata = record.metadata();
        self.total += record.bytes;
        self.records.insert(id, record);
        Ok(metadata)
    }

    pub fn dispatch(&mut self, args: &Value) -> Result<Value> {
        self.prune()?;
        let a = args.as_object().ok_or_else(|| DesktopError::new("INVALID_ARGUMENT", "Arguments must be an object"))?;
        let action = required_string(a, "action", 32)?;
        if action == "list" {
            let a = object(args, &["action", "limit"])?;
            let limit = int_in(a, "limit", 50, 1, 200)? as usize;
            let mut records = self.records.values().collect::<Vec<_>>();
            records.sort_unstable_by_key(|r| std::cmp::Reverse(r.sequence));
            let total = records.len();
            let entries = records.into_iter().take(limit).map(Record::metadata).collect::<Vec<_>>();
            return Ok(json!({"action":"list","count":entries.len(),"total":total,"truncated":total>limit,"artifacts":entries}));
        }
        let allowed: &[&str] = if action == "read" { &["action","artifact_id","offset","length","encoding"] } else { &["action","artifact_id"] };
        let a = object(args, allowed)?;
        let id = required_string(a, "artifact_id", 128)?;
        let record = self.records.get_mut(id).ok_or_else(|| DesktopError::new("ARTIFACT_NOT_FOUND", "Artifact is absent, expired, or belongs to another instance"))?;
        match action {
            "get" => Ok(json!({"action":"get","artifact":record.metadata()})),
            "read" => {
                let offset = usize::try_from(int_in(a, "offset", 0, 0, MAX_SAFE_INTEGER)?)
                    .map_err(|_| DesktopError::new("INVALID_OFFSET", "Offset exceeds addressable range"))?;
                let length = int_in(a, "length", 65536, 1, artifacts::MAX_ARTIFACT_READ_BYTES as i64)? as usize;
                let encoding = optional_string(a, "encoding", "utf8")?;
                record.chunk(offset, length, encoding)
            }
            "delete" => {
                let bytes = record.bytes;
                if let Some(record) = self.records.remove(id) { self.pending.push(record.file); }
                self.total -= bytes;
                self.reconcile()?;
                Ok(json!({"action":"delete","artifact_id":id,"deleted":true}))
            }
            _ => Err(DesktopError::new("INVALID_ARGUMENT", "Unknown artifact action")),
        }
    }

    pub fn clear(&mut self) -> Result<()> {
        self.pending.extend(self.records.drain().map(|(_, record)| record.file));
        self.total = 0;
        self.reconcile()
    }
}

pub(super) fn retention(args: &Map<String, Value>) -> Result<u64> {
    Ok(int_in(args, "retention_seconds", artifacts::DEFAULT_RETENTION_SECONDS,
        artifacts::MIN_RETENTION_SECONDS, artifacts::MAX_RETENTION_SECONDS)? as u64)
}

pub(super) fn transfer_limit() -> usize { MAX_TRANSFER_BYTES }
