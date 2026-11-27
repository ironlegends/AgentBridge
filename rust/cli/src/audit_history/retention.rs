//! Enforce physical age retention while the interprocess writer lock is held.

use super::*;

pub(super) struct SegmentAge {
    pub(super) oldest: u64,
    size: u64,
    modified: SystemTime,
}

impl SegmentAge {
    pub(super) fn from_file(file: &File, oldest: u64) -> Result<Self, AuditHistoryError> {
        let metadata = file.metadata()?;
        Ok(Self { oldest, size: metadata.len(), modified: metadata.modified()? })
    }
}

fn visit_records(
    segment: &SegmentInfo,
    mut visit: impl FnMut(u64, Option<PersistedAuditRecord>) -> Result<(), AuditHistoryError>,
) -> Result<(), AuditHistoryError> {
    let file = private_store::open_private_file(&segment.path, private_store::OpenMode::Read)?;
    read_bounded_lines(&mut BufReader::new(file), MAX_LINE_BYTES, |line| {
        let record = match line {
            LineRead::Line(s) if s.trim().is_empty() => return Ok(()),
            LineRead::Line(s) => serde_json::from_str::<PersistedAuditRecord>(s).ok()
                .filter(PersistedAuditRecord::validate_persisted_record),
            LineRead::Oversized | LineRead::InvalidUtf8 => None,
        };
        let stamp = record.as_ref().map_or(segment.stamp_ms, |r| r.timestamp_unix_ms);
        visit(stamp, record)
    })
}

fn remove_staging_if_present(path: &Path) -> Result<(), AuditHistoryError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => remove_verified_segment(path),
    }
}

pub(super) fn retain_segments(
    dir: &Path,
    segments: &mut Vec<SegmentInfo>,
    now_ms: u64,
    max_age_ms: u64,
    ages: &mut HashMap<String, SegmentAge>,
) -> Result<(), AuditHistoryError> {
    // Only the lock owner uses this private staging name. A crash before rename
    // leaves the original intact. A later owner safely discards the staged copy.
    let staging = dir.join("audit-retention.tmp");
    remove_staging_if_present(&staging)?;
    let mut kept = Vec::with_capacity(segments.len());
    for mut segment in segments.drain(..) {
        let modified = fs::symlink_metadata(&segment.path)?.modified()?;
        if ages.get(&segment.name).is_some_and(|age| age.size == segment.size
            && age.modified == modified && age.oldest.saturating_add(max_age_ms) > now_ms)
        {
            kept.push(segment);
            continue;
        }

        let mut oldest_retained = None::<u64>;
        let mut expired = false;
        visit_records(&segment, |stamp, _| {
            if stamp.saturating_add(max_age_ms) <= now_ms {
                expired = true;
            } else {
                oldest_retained = Some(oldest_retained.map_or(stamp, |old| old.min(stamp)));
            }
            Ok(())
        })?;
        let Some(oldest) = oldest_retained else {
            remove_verified_segment(&segment.path)?;
            continue;
        };
        let age = if expired {
            let rewritten = rewrite_retained(&segment, &staging, now_ms, max_age_ms, oldest);
            if rewritten.is_err() { remove_staging_if_present(&staging)?; }
            rewritten?
        } else {
            SegmentAge { oldest, size: segment.size, modified }
        };
        segment.size = age.size;
        ages.insert(segment.name.clone(), age);
        kept.push(segment);
    }
    ages.retain(|name, _| kept.iter().any(|s| &s.name == name));
    *segments = kept;
    Ok(())
}

fn rewrite_retained(
    segment: &SegmentInfo, staging: &Path, now_ms: u64, max_age_ms: u64, oldest: u64,
) -> Result<SegmentAge, AuditHistoryError> {
    let mut output = private_store::open_private_file(staging, private_store::OpenMode::CreateNew)?;
    visit_records(segment, |stamp, record| {
        if stamp.saturating_add(max_age_ms) > now_ms {
            // An invalid line remains countable until expiry without retaining its contents.
            serde_json::to_writer(&mut output, &record)?;
            output.write_all(b"\n")?;
        }
        Ok(())
    })?;
    output.sync_all()?;
    let age = SegmentAge::from_file(&output, oldest)?;
    drop(output);
    fs::rename(staging, &segment.path)?;
    Ok(age)
}
