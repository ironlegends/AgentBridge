use crate::audit_history::{default_history_dir, is_opaque_hex_id, read_history, AuditHistoryConfig, AuditHistoryFilter};
use crate::runtime::RuntimeError;
use std::ffi::OsString;
use std::path::Path;

pub(crate) const USAGE: &str = "agent-bridge audit recent <private-settings-directory> [--provider <name>] [--client-hash <sha256>] [--boot-id <id>] [--session-id <id>] [--context-id <ctx_id>] [--mission-id <mis_id>] [--method <name>] [--outcome <name>] [--since-ms <unix-ms>] [--until-ms <unix-ms>] [--limit <1-1000>]";
const INVALID_FILTER: &str = "Invalid audit filter. See agent-bridge audit --help.";

fn parse_filters(options: &[OsString]) -> Result<AuditHistoryFilter, RuntimeError> {
    let mut query = AuditHistoryFilter::default();
    for pair in options.chunks(2) {
        let [option, raw] = pair else { return Err(INVALID_FILTER.into()) };
        let value = raw.to_str().ok_or(INVALID_FILTER)?;
        let name = !value.is_empty() && value.len() <= 96 && value.bytes().all(|b|
            b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'/' | b'.'));
        match option.to_str() {
            Some("--boot-id") if query.boot_id.is_none() && is_opaque_hex_id(value, 32) => {
                query.boot_id = Some(value.into());
            }
            Some("--session-id") if query.session_id.is_none() && is_opaque_hex_id(value, 32) => {
                query.session_id = Some(value.into());
            }
            Some("--context-id") if query.context_id.is_none()
                && value.strip_prefix("ctx_").is_some_and(|id| is_opaque_hex_id(id, 32)) => {
                query.context_id = Some(value.into());
            }
            Some("--mission-id") if query.mission_id.is_none()
                && value.strip_prefix("mis_").is_some_and(|id| is_opaque_hex_id(id, 32)) => {
                query.mission_id = Some(value.into());
            }
            Some("--provider") if query.provider.is_none() && name => query.provider = Some(value.into()),
            Some("--method") if query.method.is_none() && name => query.method = Some(value.into()),
            Some("--outcome") if query.outcome.is_none() && name => query.outcome = Some(value.into()),
            Some("--client-hash") if query.client_id_sha256.is_none() && value.len() == 64
                && value.bytes().all(|b| b.is_ascii_hexdigit()) => query.client_id_sha256 = Some(value.to_ascii_lowercase()),
            Some("--since-ms") if query.since_unix_ms.is_none() => query.since_unix_ms = Some(value.parse().map_err(|_| INVALID_FILTER)?),
            Some("--until-ms") if query.until_unix_ms.is_none() => query.until_unix_ms = Some(value.parse().map_err(|_| INVALID_FILTER)?),
            Some("--limit") if query.limit.is_none() => {
                query.limit = Some(value.parse().ok().filter(|n| (1..=1000).contains(n)).ok_or(INVALID_FILTER)?);
            }
            _ => return Err(INVALID_FILTER.into()),
        }
    }
    if query.since_unix_ms.zip(query.until_unix_ms).is_some_and(|(first, last)| first > last) {
        return Err(INVALID_FILTER.into());
    }
    query.limit.get_or_insert(100);
    Ok(query)
}

pub(crate) fn run(options: &[OsString]) -> Result<(), RuntimeError> {
    if matches!(options, [help] if help == "--help" || help == "-h") {
        println!("{USAGE}");
        return Ok(());
    }
    let [action, directory, filters @ ..] = options else { return Err(USAGE.into()) };
    if action != "recent" { return Err(USAGE.into()); }
    let filter = parse_filters(filters)?;
    let dir = default_history_dir(Path::new(directory));
    let history = read_history(&dir, &filter, &AuditHistoryConfig::default())?;
    println!("{}", serde_json::json!({
        "available": history.available, "lost": history.lost, "corrupt_records": history.corrupt_lines,
        "truncated": history.truncated, "records": history.records,
    }));
    Ok(())
}
