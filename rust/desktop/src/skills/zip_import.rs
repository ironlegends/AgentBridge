//! Bounded, in-memory reader for ordinary, local Agent Skills ZIP archives.
//! This module never extracts a filesystem entry, follows a link, or executes
//! archive content. The caller supplies bytes read through its workspace Dir.
use super::{PackageLimits, RawPackageFile, SkillError, SkillErrorCode};
use std::collections::BTreeSet;
use std::io::{Cursor, Read};
use zip::{CompressionMethod, ZipArchive};

const MAX_ZIP_ENTRIES_MULTIPLIER: usize = 4;
const ZIP_LOCAL_HEADER: u32 = 0x0403_4b50;
const ZIP_CENTRAL_HEADER: u32 = 0x0201_4b50;
const ZIP_END_HEADER: u32 = 0x0605_4b50;
const ZIP_ENCRYPTION_BITS: u16 = 0x2041; // encrypted, strong encryption, central-dir encryption

pub(super) struct DecodedZip {
    pub files: Vec<RawPackageFile>,
    pub enclosing_directory: Option<String>,
}

struct Entry {
    path: String,
    is_directory: bool,
    size: u64,
}

fn malformed() -> SkillError {
    SkillError::new(SkillErrorCode::ValidationFailed, "Invalid or unsupported ordinary ZIP archive")
}
fn forbidden() -> SkillError {
    SkillError::new(SkillErrorCode::PathPolicyViolation, "ZIP contains a forbidden entry")
}
fn limit() -> SkillError {
    SkillError::new(SkillErrorCode::LimitExceeded, "ZIP exceeds documentary package limits")
}
fn get<'a>(bytes: &'a [u8], offset: usize, len: usize) -> Result<&'a [u8], SkillError> {
    let end = offset.checked_add(len).ok_or_else(malformed)?;
    bytes.get(offset..end).ok_or_else(malformed)
}
fn word(bytes: &[u8], at: usize) -> Result<u16, SkillError> {
    let part = get(bytes, at, 2)?;
    Ok(u16::from_le_bytes([part[0], part[1]]))
}
fn dword(bytes: &[u8], at: usize) -> Result<u32, SkillError> {
    let part = get(bytes, at, 4)?;
    Ok(u32::from_le_bytes([part[0], part[1], part[2], part[3]]))
}

/// Refuse multi-disk/ZIP64/self-extracting layouts and all encryption flags
/// *before* ZIP decoding. Check central AND local headers, including entries
/// that would otherwise be skipped (directories and metadata-only entries).
fn check_plain_headers(bytes: &[u8], entry_limit: usize) -> Result<usize, SkillError> {
    if bytes.len() < 22 { return Err(malformed()); }
    let earliest = bytes.len().saturating_sub(22 + 65_535);
    let latest = bytes.len() - 22;
    let mut ending = None;
    for at in (earliest..=latest).rev() {
        if dword(bytes, at)? == ZIP_END_HEADER
            && at + 22 + usize::from(word(bytes, at + 20)?) == bytes.len()
        {
            ending = Some(at);
            break;
        }
    }
    let end = ending.ok_or_else(malformed)?;
    if word(bytes, end + 4)? != 0 || word(bytes, end + 6)? != 0 {
        return Err(malformed());
    }
    let on_disk = usize::from(word(bytes, end + 8)?);
    let count = usize::from(word(bytes, end + 10)?);
    if count == 0 || count != on_disk || count > entry_limit || count == usize::from(u16::MAX) {
        return Err(limit());
    }
    let central_size = dword(bytes, end + 12)?;
    let central_start = dword(bytes, end + 16)?;
    if central_size == u32::MAX || central_start == u32::MAX {
        return Err(malformed());
    }
    let mut cursor = central_start as usize;
    if cursor.checked_add(central_size as usize) != Some(end) {
        return Err(malformed());
    }
    for _ in 0..count {
        if dword(bytes, cursor)? != ZIP_CENTRAL_HEADER {
            return Err(malformed());
        }
        let flags = word(bytes, cursor + 8)?;
        let method = word(bytes, cursor + 10)?;
        if flags & ZIP_ENCRYPTION_BITS != 0 || !matches!(method, 0 | 8) {
            return Err(forbidden());
        }
        if word(bytes, cursor + 34)? != 0 { return Err(malformed()); }
        let name_len = usize::from(word(bytes, cursor + 28)?);
        let extra_len = usize::from(word(bytes, cursor + 30)?);
        let comment_len = usize::from(word(bytes, cursor + 32)?);
        let compressed_size = dword(bytes, cursor + 20)?;
        let uncompressed_size = dword(bytes, cursor + 24)?;
        let local = dword(bytes, cursor + 42)?;
        if compressed_size == u32::MAX || uncompressed_size == u32::MAX || local == u32::MAX {
            return Err(malformed());
        }
        let central_name = get(bytes, cursor + 46, name_len)?;
        if dword(bytes, local as usize)? != ZIP_LOCAL_HEADER
            || word(bytes, local as usize + 6)? != flags
            || word(bytes, local as usize + 8)? != method
        {
            return Err(malformed());
        }
        let local_name_len = usize::from(word(bytes, local as usize + 26)?);
        let local_extra_len = usize::from(word(bytes, local as usize + 28)?);
        let local_name = get(bytes, local as usize + 30, local_name_len)?;
        if local_name != central_name { return Err(malformed()); }
        let data_start = (local as usize)
            .checked_add(30)
            .and_then(|n| n.checked_add(local_name_len))
            .and_then(|n| n.checked_add(local_extra_len))
            .ok_or_else(malformed)?;
        if data_start.checked_add(compressed_size as usize)
            .is_none_or(|n| n > central_start as usize)
        {
            return Err(malformed());
        }
        cursor = cursor.checked_add(46)
            .and_then(|n| n.checked_add(name_len))
            .and_then(|n| n.checked_add(extra_len))
            .and_then(|n| n.checked_add(comment_len))
            .ok_or_else(malformed)?;
        if cursor > end { return Err(malformed()); }
    }
    if cursor != end { return Err(malformed()); }
    Ok(count)
}

pub(super) fn decode(bytes: &[u8], limits: &PackageLimits) -> Result<DecodedZip, SkillError> {
    let entry_limit = limits.max_files.saturating_mul(MAX_ZIP_ENTRIES_MULTIPLIER);
    let expected_count = check_plain_headers(bytes, entry_limit)?;
    let mut archive = ZipArchive::new(Cursor::new(bytes)).map_err(|_| malformed())?;
    if archive.len() != expected_count { return Err(malformed()); }

    // Preflight every central directory entry before a single decompressed
    // byte is allocated. Directory and file names share the same namespace.
    let mut entries = Vec::with_capacity(expected_count);
    let mut seen_names = BTreeSet::new();
    let mut path_spellings = std::collections::BTreeMap::new();
    let mut file_names = BTreeSet::new();
    let mut declared_total = 0u64;
    let mut files_seen = 0usize;
    for i in 0..expected_count {
        // The ordinary non-password API refuses encrypted entries.
        let file = archive.by_index(i).map_err(|_| forbidden())?;
        if !matches!(file.compression(), CompressionMethod::Stored | CompressionMethod::Deflated) {
            return Err(forbidden());
        }
        let raw = std::str::from_utf8(file.name_raw()).map_err(|_| forbidden())?;
        let decoded_name = file.name().map_err(|_| forbidden())?;
        if raw != decoded_name.as_ref() { return Err(forbidden()); }
        let is_directory = file.is_dir();
        let name = if is_directory {
            raw.strip_suffix('/').ok_or_else(forbidden)?
        } else {
            raw
        };
        let segments = super::validate_relative_segments(name, false, 512, "ZIP resource_path")?;
        super::record_path_spelling(&mut path_spellings, &segments)?;
        if segments.len().saturating_sub(1) > limits.max_depth + 1 {
            return Err(limit());
        }
        let normalized = segments.join("/");
        let case_folded = normalized.to_lowercase();
        if !seen_names.insert(case_folded.clone()) { return Err(forbidden()); }

        if let Some(mode) = file.unix_mode() {
            // Missing Unix type bits are common for DOS/Windows ZIP files.
            let kind = mode & 0o170000;
            if !matches!(kind, 0)
                && !(kind == 0o040000 && is_directory)
                && !(kind == 0o100000 && !is_directory)
            {
                return Err(forbidden()); // symlink, device, socket, FIFO, etc.
            }
        }
        if is_directory {
            if file.size() != 0 { return Err(forbidden()); }
        } else {
            files_seen += 1;
            if files_seen > limits.max_files || file.size() > limits.max_single_file_bytes {
                return Err(limit());
            }
            declared_total = declared_total.checked_add(file.size()).ok_or_else(limit)?;
            if declared_total > limits.max_total_bytes { return Err(limit()); }
            file_names.insert(case_folded);
        }
        entries.push(Entry { path: normalized, is_directory, size: file.size() });
    }

    // A ZIP can contain one conventional enclosing directory; strip it only
    // when every entry belongs to that directory and it contains SKILL.md.
    // Otherwise the ZIP's root must directly contain SKILL.md.
    let has_root_skill = entries.iter().any(|e| !e.is_directory && e.path == "SKILL.md");
    let enclosing_directory = if has_root_skill {
        None
    } else {
        let first = entries.iter().find(|e| !e.is_directory)
            .and_then(|e| e.path.split('/').next()).ok_or_else(malformed)?;
        let required = format!("{first}/SKILL.md");
        if !entries.iter().any(|e| !e.is_directory && e.path == required)
            || !entries.iter().all(|e| e.path == first && e.is_directory
                || e.path.starts_with(&format!("{first}/")))
        {
            return Err(forbidden());
        }
        Some(first.to_string())
    };
    let prefix = enclosing_directory.as_deref().map(|v| format!("{v}/"));
    let stripped_file_names: BTreeSet<String> = entries.iter()
        .filter(|e| !e.is_directory)
        .map(|e| e.path.strip_prefix(prefix.as_deref().unwrap_or(""))
            .unwrap_or(&e.path).to_lowercase())
        .collect();

    // Reject file-as-directory conflicts, independent of entry ordering and
    // case. Explicit empty directories never create filesystem objects.
    for name in &stripped_file_names {
        let mut ancestor = String::new();
        for segment in name.split('/').take(name.split('/').count().saturating_sub(1)) {
            if !ancestor.is_empty() { ancestor.push('/'); }
            ancestor.push_str(segment);
            if stripped_file_names.contains(&ancestor) { return Err(forbidden()); }
        }
    }

    let mut result = Vec::with_capacity(files_seen);
    let mut actual_total = 0u64;
    for (index, meta) in entries.iter().enumerate() {
        if meta.is_directory { continue; }
        let mut file = archive.by_index(index).map_err(|_| forbidden())?;
        let path = meta.path.strip_prefix(prefix.as_deref().unwrap_or(""))
            .unwrap_or(&meta.path);
        let size_limit = if path == "SKILL.md" {
            limits.max_single_file_bytes.min(limits.max_skill_md_bytes)
        } else {
            limits.max_single_file_bytes
        };
        if meta.size > size_limit { return Err(limit()); }
        let capacity = usize::try_from(meta.size).map_err(|_| limit())?;
        let mut content = Vec::with_capacity(capacity);
        let mut buffer = [0u8; 8192];
        loop {
            let n = file.read(&mut buffer).map_err(|_| malformed())?;
            if n == 0 { break; }
            actual_total = actual_total.checked_add(n as u64).ok_or_else(limit)?;
            if actual_total > limits.max_total_bytes
                || content.len().checked_add(n).is_none_or(|len| len as u64 > size_limit)
            {
                return Err(limit());
            }
            content.extend_from_slice(&buffer[..n]);
        }
        if content.len() as u64 != meta.size { return Err(malformed()); }
        result.push(RawPackageFile { relative_path: path.to_owned(), bytes: content });
    }
    Ok(DecodedZip { files: result, enclosing_directory })
}
