//! Local operator `mcp.json` proposal importer.
//!
//! Reads a bounded, duplicate-key-free `mcp.json`, converts secret values into
//! `AGENT_BRIDGE_EXTENSION_*` environment references without persisting or
//! echoing any secret, URL or argument, and queues inert proposals in the
//! private administration journal for explicit local approval.

use super::{
    config_sha256, denied, effective_registry_bytes, enqueue_with, load_with,
    qualified_registry_with, valid_name, ExtBackend, Origin, ParsedRegistryView, RealBackend,
    ServerEntry,
};
use agent_bridge_extensions::oauth::valid_secret_env_name;
use agent_bridge_extensions::stdio::StdioSpec;
use agent_bridge_extensions::{
    public_docs_server, validate_header_env, validate_proposed_endpoint,
};
use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use serde_json::{json, Map, Number, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Component, Path};

const MAX_IMPORT_BYTES: usize = 256 * 1024;
const MAX_ARGS: usize = 64;
const MAX_ARG_BYTES: usize = 4096;
const MAX_TOTAL_ARG_BYTES: usize = 16 * 1024;
const MAX_ENV_ENTRIES: usize = 32;
const MAX_PATH_BYTES: usize = 1024;

struct NoDuplicateValue(Value);

impl<'de> Deserialize<'de> for NoDuplicateValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct UniqueVisitor;

        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = NoDuplicateValue;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("JSON with unique object keys")
            }

            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(NoDuplicateValue(Value::Null))
            }

            fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                self.visit_unit()
            }

            fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(NoDuplicateValue(Value::Bool(value)))
            }

            fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(NoDuplicateValue(Value::Number(value.into())))
            }

            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(NoDuplicateValue(Value::Number(value.into())))
            }

            fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
                Number::from_f64(value)
                    .map(Value::Number)
                    .map(NoDuplicateValue)
                    .ok_or_else(|| E::custom("non-finite JSON number"))
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(NoDuplicateValue(Value::String(value.to_owned())))
            }

            fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(NoDuplicateValue(Value::String(value)))
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut items = Vec::new();
                while let Some(NoDuplicateValue(item)) = seq.next_element()? {
                    items.push(item);
                }
                Ok(NoDuplicateValue(Value::Array(items)))
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut entries = Map::new();
                while let Some((key, NoDuplicateValue(val))) =
                    map.next_entry::<String, NoDuplicateValue>()?
                {
                    if entries.contains_key(&key) {
                        return Err(de::Error::custom("duplicate JSON object key"));
                    }
                    entries.insert(key, val);
                }
                Ok(NoDuplicateValue(Value::Object(entries)))
            }
        }

        deserializer.deserialize_any(UniqueVisitor)
    }
}

pub(super) fn is_allowed_child_env_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > 128 {
        return false;
    }
    if !(bytes[0].is_ascii_alphabetic() || bytes[0] == b'_')
        || !bytes.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_')
    {
        return false;
    }
    let upper = name.to_ascii_uppercase();
    if upper.starts_with("LD_") || upper.starts_with("DYLD_") {
        return false;
    }
    !matches!(
        upper.as_str(),
        "SYSTEMROOT"
            | "SYSTEMDRIVE"
            | "WINDIR"
            | "TEMP"
            | "TMP"
            | "USERPROFILE"
            | "APPDATA"
            | "LOCALAPPDATA"
            | "PROGRAMDATA"
            | "NUMBER_OF_PROCESSORS"
            | "PROCESSOR_ARCHITECTURE"
            | "OS"
            | "HOME"
            | "USER"
            | "LOGNAME"
            | "TMPDIR"
            | "LANG"
            | "LC_ALL"
            | "PATH"
            | "PATHEXT"
            | "COMSPEC"
            | "NODE_OPTIONS"
            | "NODE_PATH"
            | "PYTHONPATH"
            | "PYTHONHOME"
            | "PYTHONSTARTUP"
            | "PERL5OPT"
            | "PERL5LIB"
            | "RUBYOPT"
            | "RUBYLIB"
            | "JAVA_TOOL_OPTIONS"
            | "_JAVA_OPTIONS"
            | "JDK_JAVA_OPTIONS"
            | "CLASSPATH"
            | "BASH_ENV"
            | "ENV"
            | "ELECTRON_RUN_AS_NODE"
    )
}

fn sanitize_identifier_segment(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut last_underscore = true;
    for b in raw.bytes() {
        if b.is_ascii_alphanumeric() {
            out.push(char::from(b.to_ascii_uppercase()));
            last_underscore = false;
        } else if !last_underscore {
            out.push('_');
            last_underscore = true;
        }
    }
    while out.ends_with('_') {
        out.pop();
    }
    out
}

fn build_extension_env_ref(server: &str, raw_key: &str, collapse_key: bool) -> Option<String> {
    let server_seg = sanitize_identifier_segment(server);
    let key_seg = if collapse_key {
        sanitize_identifier_segment(raw_key)
    } else {
        raw_key.to_ascii_uppercase()
    };
    if server_seg.is_empty() || key_seg.is_empty() {
        return None;
    }
    let reference = format!("AGENT_BRIDGE_EXTENSION_{server_seg}_{key_seg}");
    valid_secret_env_name(&reference).then_some(reference)
}

fn contains_input_interpolation(value: &Value) -> bool {
    match value {
        Value::String(s) => s.contains("${input:"),
        Value::Array(items) => items.iter().any(contains_input_interpolation),
        Value::Object(map) => map
            .iter()
            .any(|(k, v)| k.contains("${input:") || contains_input_interpolation(v)),
        _ => false,
    }
}

fn has_known_token_prefix(token: &str) -> bool {
    const PREFIXES: &[&str] = &[
        // Split so repository secret scanning does not flag the detector.
        concat!("gh", "p_"),
        concat!("github", "_pat_"),
        "glpat-",
        "sk-",
        "xoxb-",
        "xoxp-",
        "AKIA",
        "AIza",
        "eyJ",
    ];
    PREFIXES.iter().any(|prefix| token.starts_with(prefix))
}

fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    let bytes = s.as_bytes();
    for &b in bytes {
        counts[usize::from(b)] += 1;
    }
    let len = bytes.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = (count as f64) / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn is_high_entropy_secret(candidate: &str) -> bool {
    if candidate.len() < 32 {
        return false;
    }
    if candidate.bytes().any(|b| b.is_ascii_whitespace()) {
        return false;
    }
    if Path::new(candidate).is_absolute()
        || candidate.contains('\\')
        || candidate.starts_with('/')
    {
        return false;
    }
    let entropy = shannon_entropy(candidate);
    if candidate.bytes().all(|b| b.is_ascii_hexdigit()) {
        return entropy >= 3.0;
    }
    let has_lower = candidate.bytes().any(|b| b.is_ascii_lowercase());
    let has_upper = candidate.bytes().any(|b| b.is_ascii_uppercase());
    let has_digit = candidate.bytes().any(|b| b.is_ascii_digit());
    let has_symbol = candidate
        .bytes()
        .any(|b| !b.is_ascii_alphanumeric() && b.is_ascii_graphic());
    let classes =
        usize::from(has_lower) + usize::from(has_upper) + usize::from(has_digit) + usize::from(has_symbol);
    classes >= 2 && entropy >= 3.5
}

fn is_secret_flag_name(raw_flag: &str) -> bool {
    let trimmed = raw_flag.trim_start_matches('-');
    if trimmed.is_empty() {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "key"
            | "apikey"
            | "api-key"
            | "api_key"
            | "token"
            | "secret"
            | "password"
            | "passwd"
            | "pwd"
            | "bearer"
            | "authorization"
            | "credential"
            | "credentials"
            | "passphrase"
            | "pat"
    ) || lower.ends_with("-key")
        || lower.ends_with("_key")
    {
        return true;
    }
    lower.split(['-', '_', '.']).any(|word| {
        matches!(
            word,
            "secret"
                | "token"
                | "apikey"
                | "password"
                | "passwd"
                | "pwd"
                | "bearer"
                | "credential"
                | "credentials"
                | "passphrase"
                | "authorization"
        )
    })
}

fn check_args_safety(args: &[String]) -> Result<(), &'static str> {
    if args.len() > MAX_ARGS {
        return Err("invalid_args");
    }
    let mut total_bytes = 0usize;
    for arg in args {
        if arg.len() > MAX_ARG_BYTES || arg.contains('\0') {
            return Err("invalid_args");
        }
        total_bytes = total_bytes.saturating_add(arg.len());
        if total_bytes > MAX_TOTAL_ARG_BYTES {
            return Err("invalid_args");
        }
        if arg.contains("${") {
            return Err("variable_interpolation_in_args");
        }
    }

    let mut index = 0usize;
    while index < args.len() {
        let arg = &args[index];
        if arg.starts_with('-') {
            if let Some((flag, value)) = arg.split_once('=') {
                if is_secret_flag_name(flag) {
                    return Err("literal_secret_in_args");
                }
                if has_known_token_prefix(value) || is_high_entropy_secret(value) {
                    return Err("literal_secret_in_args");
                }
            } else if is_secret_flag_name(arg) {
                match args.get(index + 1) {
                    Some(next) if Path::new(next).is_absolute() && !has_known_token_prefix(next) => {
                        index += 2;
                        continue;
                    }
                    _ => return Err("literal_secret_in_args"),
                }
            }
        }

        if !Path::new(arg).is_absolute() {
            if has_known_token_prefix(arg) {
                return Err("literal_secret_in_args");
            }
            for piece in arg.split(['=', ' ', ':']) {
                if has_known_token_prefix(piece) {
                    return Err("literal_secret_in_args");
                }
            }
            let is_plain_long_flag = arg.starts_with("--")
                && !arg.contains('=')
                && arg.bytes().all(|b| b.is_ascii_lowercase() || b == b'-');
            if !is_plain_long_flag && is_high_entropy_secret(arg) {
                return Err("literal_secret_in_args");
            }
        }
        index += 1;
    }
    Ok(())
}

fn parse_env_placeholder_hint(raw_value: &str) -> Option<&str> {
    let inner = raw_value
        .strip_prefix("${")
        .and_then(|rest| rest.strip_suffix('}'))?;
    let name = inner.strip_prefix("env:").unwrap_or(inner);
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > 128 {
        return None;
    }
    if !(bytes[0].is_ascii_alphabetic() || bytes[0] == b'_')
        || !bytes.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_')
    {
        return None;
    }
    if has_known_token_prefix(name) || is_high_entropy_secret(name) {
        return None;
    }
    Some(name)
}

fn valid_clean_absolute_path(raw: &str) -> bool {
    if raw.is_empty()
        || raw.len() > MAX_PATH_BYTES
        || raw.contains('\0')
        || raw.starts_with("\\\\")
    {
        return false;
    }
    let path = Path::new(raw);
    if !path.is_absolute() {
        return false;
    }
    !path
        .components()
        .any(|c| matches!(c, Component::CurDir | Component::ParentDir))
}

fn safe_report_name(raw: &str) -> String {
    if !raw.is_empty() && raw.len() <= 96 && !raw.chars().any(char::is_control) {
        raw.to_owned()
    } else {
        "<invalid>".to_owned()
    }
}

fn read_mcp_json_bytes(path: &Path) -> io::Result<Vec<u8>> {
    let before = fs::symlink_metadata(path)
        .map_err(|_| denied("Cannot inspect mcp.json import source"))?;
    if before.file_type().is_symlink() || !before.is_file() {
        return Err(denied("mcp.json import source must be a regular file"));
    }
    if before.len() > MAX_IMPORT_BYTES as u64 {
        return Err(denied("mcp.json exceeds 256 KiB import limit"));
    }
    let file = File::open(path).map_err(|_| denied("Cannot open mcp.json import source"))?;
    let meta = file
        .metadata()
        .map_err(|_| denied("Cannot read mcp.json metadata"))?;
    if !meta.is_file() {
        return Err(denied("mcp.json import source must be a regular file"));
    }
    let mut bytes = Vec::new();
    file.take((MAX_IMPORT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| denied("Cannot read mcp.json import source"))?;
    if bytes.len() > MAX_IMPORT_BYTES {
        return Err(denied("mcp.json exceeds 256 KiB import limit"));
    }
    Ok(bytes)
}

pub(super) fn run(settings: &Path, mcp_json_path: &Path, inherit_path: &BTreeSet<String>) -> io::Result<Value> {
    let report = import_with(&RealBackend, settings, mcp_json_path, inherit_path)?;
    let queued = report
        .get("proposals")
        .and_then(Value::as_array)
        .is_some_and(|items| !items.is_empty());
    if !queued {
        println!(
            "{}",
            serde_json::to_string_pretty(&report)
                .map_err(|_| denied("Cannot encode import report"))?
        );
        return Err(denied("No extension proposals queued from mcp.json"));
    }
    Ok(report)
}

/// Clients such as Claude Code write Windows paths as `C:/dir/tool.exe`.
/// The pinned spec keeps the native separator, so both spellings of the
/// same path import as the same server.
fn native_separators(path: &str) -> String {
    if cfg!(windows) { path.replace('/', "\\") } else { path.to_owned() }
}

/// The shape of an importable stdio entry. Refusals that depend on the
/// executable or the arguments still apply per server during the import.
fn stdio_entry(name: &str, entry: &Value) -> bool {
    let Some(entry) = entry.as_object() else { return false };
    valid_name(name) && !public_docs_server(name)
        && entry.get("command").is_some_and(Value::is_string)
        && !entry.contains_key("url") && !entry.contains_key("headers")
        && entry.get("type").is_none_or(|kind| kind.as_str() == Some("stdio"))
        && matches!(entry.get("disabled"), None | Some(Value::Bool(false)))
}

pub(super) fn import_with<B: ExtBackend>(
    backend: &B,
    settings: &Path,
    mcp_json_path: &Path,
    inherit_path: &BTreeSet<String>,
) -> io::Result<Value> {
    let base_bytes = qualified_registry_with(backend, settings)?;
    let file_bytes = read_mcp_json_bytes(mcp_json_path)?;
    let imported_file_sha256 = config_sha256(&file_bytes);

    let NoDuplicateValue(parsed) = serde_json::from_slice::<NoDuplicateValue>(&file_bytes)
        .map_err(|_| denied("Invalid or ambiguous JSON in mcp.json"))?;
    let root = parsed
        .as_object()
        .ok_or_else(|| denied("mcp.json root must be a JSON object"))?;
    if root.keys().any(|k| k != "mcpServers") {
        return Err(denied("mcp.json may only contain top-level mcpServers"));
    }
    let servers = root
        .get("mcpServers")
        .and_then(Value::as_object)
        .ok_or_else(|| denied("mcp.json requires an mcpServers object"))?;
    // Checked before anything is queued: each server named by the operator
    // must be an importable stdio entry of this file.
    if inherit_path.iter().any(|name| !servers.get(name).is_some_and(|entry| stdio_entry(name, entry))) {
        return Err(denied("--inherit-path must name a stdio server of mcp.json"));
    }

    let journal = load_with(backend, settings)?;
    let effective_bytes = effective_registry_bytes(&base_bytes, &journal)?;
    let current_registry = backend.parse_registry(&effective_bytes, Some(&journal.controls))?;

    let mut proposals = Vec::new();
    let mut refused = Vec::new();
    let mut skipped = Vec::new();

    for (raw_name, raw_entry) in servers {
        let report_name = safe_report_name(raw_name);
        if !valid_name(raw_name) {
            refused.push(json!({"name": report_name, "reason": "invalid_server_name"}));
            continue;
        }
        let Some(entry) = raw_entry.as_object() else {
            refused.push(json!({"name": raw_name, "reason": "invalid_server_entry"}));
            continue;
        };
        if contains_input_interpolation(raw_entry) {
            refused.push(json!({"name": raw_name, "reason": "input_interpolation_unsupported"}));
            continue;
        }
        match entry.get("disabled") {
            Some(Value::Bool(true)) => {
                skipped.push(json!({"name": raw_name, "reason": "disabled_in_source"}));
                continue;
            }
            Some(Value::Bool(false)) | None => {}
            Some(_) => {
                refused.push(json!({"name": raw_name, "reason": "invalid_server_entry"}));
                continue;
            }
        }

        if entry.keys().any(|field| {
            !matches!(
                field.as_str(),
                "command"
                    | "args"
                    | "env"
                    | "cwd"
                    | "url"
                    | "headers"
                    | "type"
                    | "disabled"
                    | "autoApprove"
                    | "alwaysAllow"
            )
        }) {
            refused.push(json!({"name": raw_name, "reason": "unsupported_server_field"}));
            continue;
        }

        let mut notes: Vec<&'static str> = Vec::new();
        if entry.contains_key("autoApprove") || entry.contains_key("alwaysAllow") {
            notes.push("auto_approve_ignored_no_tool_grants_imported");
        }

        let declared_type = match entry.get("type") {
            None => None,
            Some(Value::String(s)) => Some(s.as_str()),
            Some(_) => {
                refused.push(json!({"name": raw_name, "reason": "invalid_transport_type"}));
                continue;
            }
        };
        if declared_type.is_some_and(|t| t.eq_ignore_ascii_case("sse")) {
            refused.push(json!({"name": raw_name, "reason": "sse_transport_unsupported"}));
            continue;
        }

        let has_command = entry.contains_key("command");
        let has_url = entry.contains_key("url");
        if has_command && has_url {
            refused.push(json!({"name": raw_name, "reason": "conflicting_command_and_url"}));
            continue;
        }
        if !has_command && !has_url {
            refused.push(json!({"name": raw_name, "reason": "missing_transport_target"}));
            continue;
        }

        if has_command {
            if let Some(t) = declared_type {
                if t != "stdio" {
                    refused.push(json!({"name": raw_name, "reason": "unsupported_transport_type"}));
                    continue;
                }
            }
            if entry.contains_key("headers") {
                refused.push(json!({"name": raw_name, "reason": "invalid_stdio_entry"}));
                continue;
            }
            if public_docs_server(raw_name) {
                refused.push(json!({"name": raw_name, "reason": "reserved_server_name"}));
                continue;
            }
            let Some(command) = entry.get("command").and_then(Value::as_str) else {
                refused.push(json!({"name": raw_name, "reason": "invalid_command"}));
                continue;
            };
            let command = native_separators(command);
            let command = command.as_str();
            if command.contains("${") {
                refused.push(json!({"name": raw_name, "reason": "variable_interpolation_in_command"}));
                continue;
            }
            if !Path::new(command).is_absolute() {
                refused.push(json!({"name": raw_name, "reason": "command_not_absolute"}));
                continue;
            }
            if !valid_clean_absolute_path(command) {
                refused.push(json!({"name": raw_name, "reason": "invalid_executable_path"}));
                continue;
            }

            let cwd = match entry.get("cwd") {
                None => None,
                Some(Value::String(raw_cwd)) => {
                    let raw_cwd = &native_separators(raw_cwd);
                    if raw_cwd.contains("${") || !valid_clean_absolute_path(raw_cwd) {
                        refused.push(json!({"name": raw_name, "reason": "invalid_cwd"}));
                        continue;
                    }
                    Some(raw_cwd.clone())
                }
                Some(_) => {
                    refused.push(json!({"name": raw_name, "reason": "invalid_cwd"}));
                    continue;
                }
            };

            let args: Vec<String> = match entry.get("args") {
                None => Vec::new(),
                Some(Value::Array(items)) => {
                    let Some(parsed_args) = items
                        .iter()
                        .map(|v| v.as_str().map(str::to_owned))
                        .collect::<Option<Vec<_>>>()
                    else {
                        refused.push(json!({"name": raw_name, "reason": "invalid_args"}));
                        continue;
                    };
                    parsed_args
                }
                Some(_) => {
                    refused.push(json!({"name": raw_name, "reason": "invalid_args"}));
                    continue;
                }
            };
            if let Err(reason) = check_args_safety(&args) {
                refused.push(json!({"name": raw_name, "reason": reason}));
                continue;
            }

            let mut env_refs = BTreeMap::new();
            let mut operator_must_export = Vec::new();
            let mut source_env_hints = BTreeMap::new();
            let mut literal_value_dropped = false;
            if let Some(raw_env) = entry.get("env") {
                let Some(env_obj) = raw_env.as_object() else {
                    refused.push(json!({"name": raw_name, "reason": "invalid_env"}));
                    continue;
                };
                if env_obj.len() > MAX_ENV_ENTRIES {
                    refused.push(json!({"name": raw_name, "reason": "too_many_env_entries"}));
                    continue;
                }
                let mut seen_ci = BTreeSet::new();
                let mut env_error: Option<&'static str> = None;
                for (child_key, raw_val) in env_obj {
                    let Some(val_str) = raw_val.as_str() else {
                        env_error = Some("invalid_env");
                        break;
                    };
                    if !is_allowed_child_env_name(child_key)
                        || !backend.valid_child_env_name(child_key)
                    {
                        env_error = Some("denylisted_or_invalid_env_name");
                        break;
                    }
                    if !seen_ci.insert(child_key.to_ascii_uppercase()) {
                        env_error = Some("duplicate_env_name");
                        break;
                    }
                    let Some(reference) = build_extension_env_ref(raw_name, child_key, false) else {
                        env_error = Some("env_reference_too_long");
                        break;
                    };
                    if let Some(hint) = parse_env_placeholder_hint(val_str) {
                        source_env_hints.insert(reference.clone(), hint.to_owned());
                    } else if val_str.contains("${") {
                        env_error = Some("variable_interpolation_in_env");
                        break;
                    } else if !val_str.is_empty() {
                        literal_value_dropped = true;
                    }
                    operator_must_export.push(reference.clone());
                    env_refs.insert(child_key.clone(), reference);
                }
                if let Some(reason) = env_error {
                    refused.push(json!({"name": raw_name, "reason": reason}));
                    continue;
                }
            }

            let Ok(executable_sha256) = backend.observe_executable(Path::new(command)) else {
                refused.push(json!({"name": raw_name, "reason": "executable_unavailable"}));
                continue;
            };

            let spec = StdioSpec {
                executable: command.to_owned(),
                executable_sha256,
                args,
                env: env_refs,
                cwd,
                inherit_path: inherit_path.contains(raw_name),
            };
            if backend.validate_stdio_spec(&spec).is_err() {
                refused.push(json!({"name": raw_name, "reason": "invalid_stdio_spec"}));
                continue;
            }

            let identical_existing = current_registry.has_server(raw_name)
                && matches!(
                    journal.entries.get(raw_name),
                    Some(ServerEntry::AddedStdio { stdio, .. }) if stdio == &spec
                )
                && current_registry
                    .server_sha256(raw_name)?
                    .is_some_and(|sha| {
                        journal
                            .controls
                            .get(raw_name)
                            .is_some_and(|c| c.enabled && c.config_sha256 == sha)
                    });
            if identical_existing {
                skipped.push(json!({"name": raw_name, "reason": "identical_existing_server"}));
                continue;
            }

            let mut payload = Map::new();
            payload.insert("action".into(), json!("add_stdio"));
            payload.insert("name".into(), json!(raw_name));
            payload.insert("executable".into(), json!(spec.executable));
            payload.insert("executable_sha256".into(), json!(spec.executable_sha256));
            payload.insert("args".into(), json!(spec.args));
            if !spec.env.is_empty() {
                payload.insert("env".into(), json!(spec.env));
            }
            if let Some(cwd_val) = &spec.cwd {
                payload.insert("cwd".into(), json!(cwd_val));
            }
            if spec.inherit_path {
                payload.insert("inherit_path".into(), json!(true));
            }
            payload.insert("import_source_sha256".into(), json!(imported_file_sha256));

            let receipt = enqueue_with(backend, settings, &payload, Origin::LocalCli)?;
            operator_must_export.sort();
            let mut item = json!({
                "name": raw_name,
                "kind": "add_stdio",
                "request_id": receipt["request_id"],
                "submission": receipt["submission"],
                "support": receipt["support"],
                "literal_value_dropped": literal_value_dropped,
                "operator_must_export": operator_must_export,
            });
            if !source_env_hints.is_empty() {
                item["source_env_hints"] = json!(source_env_hints);
            }
            if !notes.is_empty() {
                item["notes"] = json!(notes);
            }
            proposals.push(item);
        } else {
            if let Some(t) = declared_type {
                if !matches!(t, "http" | "streamable-http") {
                    refused.push(json!({"name": raw_name, "reason": "unsupported_transport_type"}));
                    continue;
                }
            }
            if entry.contains_key("args") || entry.contains_key("env") || entry.contains_key("cwd")
            {
                refused.push(json!({"name": raw_name, "reason": "invalid_http_entry"}));
                continue;
            }
            let Some(url) = entry.get("url").and_then(Value::as_str) else {
                refused.push(json!({"name": raw_name, "reason": "invalid_endpoint"}));
                continue;
            };
            if url.len() > 4096 || url.contains("${") || validate_proposed_endpoint(url).is_err() {
                refused.push(json!({"name": raw_name, "reason": "invalid_endpoint"}));
                continue;
            }

            let mut header_env = BTreeMap::new();
            let mut operator_must_export = Vec::new();
            let mut source_env_hints = BTreeMap::new();
            let mut literal_value_dropped = false;
            if let Some(raw_headers) = entry.get("headers") {
                let Some(headers_obj) = raw_headers.as_object() else {
                    refused.push(json!({"name": raw_name, "reason": "invalid_headers"}));
                    continue;
                };
                let mut seen_refs = BTreeSet::new();
                let mut header_error: Option<&'static str> = None;
                for (header_name, raw_val) in headers_obj {
                    let Some(val_str) = raw_val.as_str() else {
                        header_error = Some("invalid_headers");
                        break;
                    };
                    let Some(reference) = build_extension_env_ref(raw_name, header_name, true)
                    else {
                        header_error = Some("invalid_header_reference");
                        break;
                    };
                    if !seen_refs.insert(reference.clone()) {
                        header_error = Some("duplicate_header_reference");
                        break;
                    }
                    if let Some(hint) = parse_env_placeholder_hint(val_str) {
                        source_env_hints.insert(reference.clone(), hint.to_owned());
                    } else if val_str.contains("${") {
                        header_error = Some("variable_interpolation_in_headers");
                        break;
                    } else if !val_str.is_empty() {
                        literal_value_dropped = true;
                    }
                    operator_must_export.push(reference.clone());
                    header_env.insert(header_name.clone(), reference);
                }
                if let Some(reason) = header_error {
                    refused.push(json!({"name": raw_name, "reason": reason}));
                    continue;
                }
            }
            if validate_header_env(url, &header_env, false).is_err() {
                refused.push(json!({"name": raw_name, "reason": "invalid_header_reference"}));
                continue;
            }

            let identical_existing = current_registry.has_server(raw_name)
                && match journal.entries.get(raw_name) {
                    Some(ServerEntry::Added {
                        endpoint,
                        header_env: existing_headers,
                        ..
                    }) => {
                        endpoint == url
                            && existing_headers == &header_env
                            && current_registry
                                .server_sha256(raw_name)?
                                .is_some_and(|sha| {
                                    journal
                                        .controls
                                        .get(raw_name)
                                        .is_some_and(|c| c.enabled && c.config_sha256 == sha)
                                })
                    }
                    None => {
                        current_registry.server_endpoint(raw_name) == Some(url)
                            && header_env.is_empty()
                            && journal.controls.get(raw_name).is_none_or(|c| c.enabled)
                    }
                    _ => false,
                };
            if identical_existing {
                skipped.push(json!({"name": raw_name, "reason": "identical_existing_server"}));
                continue;
            }

            let mut payload = Map::new();
            payload.insert("action".into(), json!("add"));
            payload.insert("name".into(), json!(raw_name));
            payload.insert("url".into(), json!(url));
            if !header_env.is_empty() {
                payload.insert("header_env".into(), json!(header_env));
            }

            let receipt = enqueue_with(backend, settings, &payload, Origin::LocalCli)?;
            operator_must_export.sort();
            let mut item = json!({
                "name": raw_name,
                "kind": "add",
                "request_id": receipt["request_id"],
                "submission": receipt["submission"],
                "support": receipt["support"],
                "literal_value_dropped": literal_value_dropped,
                "operator_must_export": operator_must_export,
            });
            if !source_env_hints.is_empty() {
                item["source_env_hints"] = json!(source_env_hints);
            }
            if !notes.is_empty() {
                item["notes"] = json!(notes);
            }
            proposals.push(item);
        }
    }

    let mut report = json!({
        "imported_file_sha256": imported_file_sha256,
        "proposals": proposals,
        "refused": refused,
        "configuration_changed": false,
        "operator_decision_required": true,
    });
    if !skipped.is_empty() {
        report["skipped"] = json!(skipped);
    }
    let queued: Vec<&Value> = report["proposals"].as_array().into_iter().flatten()
        .filter(|p| p["submission"] == "queued_for_local_decision")
        .map(|p| &p["request_id"]).collect();
    if queued.len() > 1 {
        report["approve_together"] = json!(queued);
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::super::stdio_admin_tests::{native_fixture_executable, TestBackend};
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static IMPORT_SEQ: AtomicU64 = AtomicU64::new(0);

    struct Sandbox(std::path::PathBuf);
    impl Sandbox {
        fn new(label: &str) -> Self {
            let n = IMPORT_SEQ.fetch_add(1, Ordering::Relaxed);
            let dir = crate::test_state_base().join(format!(
                "ab-import-{label}-{}-{n}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
            }
            Self(dir)
        }
        fn settings(&self) -> std::path::PathBuf {
            let s = self.0.join("settings");
            if !s.exists() {
                agent_bridge_lifecycle::initialize_operator_settings(&s).unwrap();
            }
            s
        }
    }
    impl Drop for Sandbox {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn import_drops_env_literals_and_never_persists_values() {
        let sb = Sandbox::new("env-drop");
        let settings = sb.settings();
        let exe = native_fixture_executable(&sb.0, "example-mcp");
        let secret_literal = "literal-secret-value-never-copy-887766";
        let mcp_path = sb.0.join("mcp.json");
        let mcp_doc = json!({
            "mcpServers": {
                "example-srv": {
                    "command": exe.to_str().unwrap(),
                    "args": ["stdio", "--read-only"],
                    "env": {
                        "EXAMPLE_TOKEN": secret_literal,
                        "PASSTHROUGH_VAR": "${HOST_TOKEN_SOURCE}",
                        "ENV_SCOPED_VAR": "${env:SECOND_TOKEN_SOURCE}"
                    },
                    "autoApprove": ["search_items"]
                }
            }
        });
        let raw_bytes = serde_json::to_vec_pretty(&mcp_doc).unwrap();
        fs::write(&mcp_path, &raw_bytes).unwrap();

        let backend = TestBackend::default();
        // `--inherit-path` must name a stdio server of the file, checked
        // before anything is queued.
        for name in ["absent-srv", "EXAMPLE-SRV"] {
            let only = BTreeSet::from([name.to_owned()]);
            assert!(import_with(&backend, &settings, &mcp_path, &only).is_err(), "{name}");
        }
        assert!(load_with(&backend, &settings).unwrap().requests.is_empty());
        let report = import_with(&backend, &settings, &mcp_path, &BTreeSet::new()).unwrap();
        let report_text = serde_json::to_string(&report).unwrap();
        assert!(!report_text.contains(secret_literal));
        assert!(!report_text.contains(exe.to_str().unwrap()));
        assert_eq!(report["imported_file_sha256"], config_sha256(&raw_bytes));
        assert_eq!(report["configuration_changed"], false);
        assert_eq!(report["operator_decision_required"], true);
        assert_eq!(report["refused"].as_array().unwrap().len(), 0);

        let proposals = report["proposals"].as_array().unwrap();
        assert_eq!(proposals.len(), 1);
        let p = &proposals[0];
        assert_eq!(p["name"], "example-srv");
        assert_eq!(p["kind"], "add_stdio");
        assert_eq!(p["submission"], "queued_for_local_decision");
        assert_eq!(p["support"], "local_stdio_registry_overlay_after_approval");
        assert_eq!(p["literal_value_dropped"], true);
        assert_eq!(
            p["operator_must_export"],
            json!([
                "AGENT_BRIDGE_EXTENSION_EXAMPLE_SRV_ENV_SCOPED_VAR",
                "AGENT_BRIDGE_EXTENSION_EXAMPLE_SRV_EXAMPLE_TOKEN",
                "AGENT_BRIDGE_EXTENSION_EXAMPLE_SRV_PASSTHROUGH_VAR"
            ])
        );
        assert_eq!(
            p["source_env_hints"],
            json!({
                "AGENT_BRIDGE_EXTENSION_EXAMPLE_SRV_PASSTHROUGH_VAR": "HOST_TOKEN_SOURCE",
                "AGENT_BRIDGE_EXTENSION_EXAMPLE_SRV_ENV_SCOPED_VAR": "SECOND_TOKEN_SOURCE"
            })
        );
        assert_eq!(
            p["notes"],
            json!(["auto_approve_ignored_no_tool_grants_imported"])
        );

        let journal_raw = fs::read_to_string(settings.join(super::super::JOURNAL)).unwrap();
        assert!(!journal_raw.contains(secret_literal));
        let ext_raw = fs::read_to_string(settings.join("extensions.json")).unwrap();
        assert!(!ext_raw.contains(secret_literal));

        let journal = load_with(&backend, &settings).unwrap();
        let id = p["request_id"].as_str().unwrap();
        let payload = &journal.requests[id].payload;
        assert_eq!(
            payload["env"]["EXAMPLE_TOKEN"],
            "AGENT_BRIDGE_EXTENSION_EXAMPLE_SRV_EXAMPLE_TOKEN"
        );
        assert_eq!(
            payload["import_source_sha256"],
            config_sha256(&raw_bytes)
        );
    }

    #[test]
    fn import_refuses_secret_args_relative_commands_scripts_sse_names_duplicates_oversize() {
        let sb = Sandbox::new("refusals");
        let settings = sb.settings();
        let exe = native_fixture_executable(&sb.0, "valid-mcp");
        let script = sb.0.join(if cfg!(windows) { "runner.cmd" } else { "runner.sh" });
        fs::write(&script, "#!/bin/sh\necho no\n").unwrap();

        let inline_secret = "super-secret-inline-arg-value";
        let flag_token = "flag-followed-secret-value";
        let classic_secret: &str = &format!("{}{}", "gh", "p_ExampleToken1234567890abcdef");
        let sk_secret: &str = &format!("{}{}", "sk", "-ExampleLiveKey1234567890abcdef");
        let jwt_secret = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload";
        let entropy_secret = "xK9mP2vL8nQ4wR7jT1yB6cF3hZ5dG0sA";
        let sse_url = "https://sse-secret-host.example.invalid/events";

        let mcp_path = sb.0.join("refusals.json");
        let doc = json!({
            "mcpServers": {
                "eq_secret": {
                    "command": exe.to_str().unwrap(),
                    "args": [format!("--api-key={inline_secret}")]
                },
                "flag_secret": {
                    "command": exe.to_str().unwrap(),
                    "args": ["--token", flag_token]
                },
                "prefix_ghp": {
                    "command": exe.to_str().unwrap(),
                    "args": [classic_secret]
                },
                "prefix_sk": {
                    "command": exe.to_str().unwrap(),
                    "args": [sk_secret]
                },
                "prefix_jwt": {
                    "command": exe.to_str().unwrap(),
                    "args": [jwt_secret]
                },
                "high_entropy": {
                    "command": exe.to_str().unwrap(),
                    "args": [entropy_secret]
                },
                "arg_interp": {
                    "command": exe.to_str().unwrap(),
                    "args": ["${DYNAMIC_SECRET}"]
                },
                "input_prompt": {
                    "command": exe.to_str().unwrap(),
                    "env": { "API_TOKEN": "${input:prompt_secret}" }
                },
                "relative_cmd": {
                    "command": "npx",
                    "args": ["-y", "example-mcp"]
                },
                "script_cmd": {
                    "command": script.to_str().unwrap()
                },
                "denylisted_env": {
                    "command": exe.to_str().unwrap(),
                    "env": { "NODE_OPTIONS": "anything" }
                },
                "sse_srv": {
                    "type": "sse",
                    "url": sse_url
                },
                "both_cmd_url": {
                    "command": exe.to_str().unwrap(),
                    "url": "https://example.invalid/mcp"
                },
                "bad/name": {
                    "command": exe.to_str().unwrap()
                }
            }
        });
        fs::write(&mcp_path, serde_json::to_vec(&doc).unwrap()).unwrap();

        let backend = TestBackend::default();
        let report = import_with(&backend, &settings, &mcp_path, &BTreeSet::new()).unwrap();
        assert!(report["proposals"].as_array().unwrap().is_empty());

        let report_text = serde_json::to_string(&report).unwrap();
        for forbidden in [
            inline_secret,
            flag_token,
            classic_secret,
            sk_secret,
            jwt_secret,
            entropy_secret,
            sse_url,
            "DYNAMIC_SECRET",
            "prompt_secret",
            "example.invalid",
        ] {
            assert!(
                !report_text.contains(forbidden),
                "import report contains a refused fixture value"
            );
        }

        let reasons: BTreeMap<String, String> = report["refused"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| {
                (
                    item["name"].as_str().unwrap().to_owned(),
                    item["reason"].as_str().unwrap().to_owned(),
                )
            })
            .collect();
        assert_eq!(reasons["eq_secret"], "literal_secret_in_args");
        assert_eq!(reasons["flag_secret"], "literal_secret_in_args");
        assert_eq!(reasons["prefix_ghp"], "literal_secret_in_args");
        assert_eq!(reasons["prefix_sk"], "literal_secret_in_args");
        assert_eq!(reasons["prefix_jwt"], "literal_secret_in_args");
        assert_eq!(reasons["high_entropy"], "literal_secret_in_args");
        assert_eq!(reasons["arg_interp"], "variable_interpolation_in_args");
        assert_eq!(reasons["input_prompt"], "input_interpolation_unsupported");
        assert_eq!(reasons["relative_cmd"], "command_not_absolute");
        assert_eq!(reasons["script_cmd"], "executable_unavailable");
        assert_eq!(reasons["denylisted_env"], "denylisted_or_invalid_env_name");
        assert_eq!(reasons["sse_srv"], "sse_transport_unsupported");
        assert_eq!(reasons["both_cmd_url"], "conflicting_command_and_url");
        assert_eq!(reasons["bad/name"], "invalid_server_name");

        // Production run fails (non-zero exit) when zero proposals were queued.
        assert!(run(&settings, &mcp_path, &BTreeSet::new()).is_err());

        // Duplicate keys refused at both top-level and nested object depth.
        let dup_path = sb.0.join("dup.json");
        fs::write(
            &dup_path,
            br#"{"mcpServers":{"a":{"url":"https://example.invalid/1"},"a":{"url":"https://example.invalid/2"}}}"#,
        )
        .unwrap();
        assert!(import_with(&RealBackend, &settings, &dup_path, &BTreeSet::new()).is_err());

        // Unknown top-level key refused.
        let extra_top = sb.0.join("extra_top.json");
        fs::write(&extra_top, br#"{"mcpServers":{},"extra":1}"#).unwrap();
        assert!(import_with(&RealBackend, &settings, &extra_top, &BTreeSet::new()).is_err());

        // Oversize (> 256 KiB) refused before parsing.
        let oversize = sb.0.join("oversize.json");
        let mut big = b"{\"mcpServers\":{\"x\":{\"url\":\"https://example.invalid/".to_vec();
        big.resize(MAX_IMPORT_BYTES + 16, b'a');
        fs::write(&oversize, &big).unwrap();
        assert!(import_with(&RealBackend, &settings, &oversize, &BTreeSet::new()).is_err());
    }

    #[test]
    fn import_url_entries_become_add_with_header_references() {
        let sb = Sandbox::new("http-url");
        let settings = sb.settings();
        let header_secret = "raw-header-bearer-secret-445566";
        let private_url = "https://remote-fixture.example.invalid/mcp";
        let mcp_path = sb.0.join("http.json");
        let doc = json!({
            "mcpServers": {
                "remote_http": {
                    "type": "streamable-http",
                    "url": private_url,
                    "headers": {
                        "X-Api-Key": header_secret,
                        "X-Org-Id": "${ORG_IDENTIFIER}"
                    }
                },
                "forbidden_host_header": {
                    "type": "http",
                    "url": "https://remote-fixture.example.invalid/mcp",
                    "headers": {
                        "Host": "evil.example.invalid"
                    }
                }
            }
        });
        fs::write(&mcp_path, serde_json::to_vec(&doc).unwrap()).unwrap();

        let report = import_with(&RealBackend, &settings, &mcp_path, &BTreeSet::new()).unwrap();
        let report_text = serde_json::to_string(&report).unwrap();
        assert!(!report_text.contains(header_secret));
        assert!(!report_text.contains(private_url));

        let proposals = report["proposals"].as_array().unwrap();
        assert_eq!(proposals.len(), 1);
        assert_eq!(proposals[0]["name"], "remote_http");
        assert_eq!(proposals[0]["kind"], "add");
        assert_eq!(proposals[0]["support"], "local_registry_overlay_after_approval");
        assert_eq!(proposals[0]["literal_value_dropped"], true);
        assert_eq!(
            proposals[0]["operator_must_export"],
            json!([
                "AGENT_BRIDGE_EXTENSION_REMOTE_HTTP_X_API_KEY",
                "AGENT_BRIDGE_EXTENSION_REMOTE_HTTP_X_ORG_ID"
            ])
        );
        assert_eq!(
            proposals[0]["source_env_hints"]["AGENT_BRIDGE_EXTENSION_REMOTE_HTTP_X_ORG_ID"],
            "ORG_IDENTIFIER"
        );
        assert_eq!(report["refused"][0]["name"], "forbidden_host_header");
        assert_eq!(report["refused"][0]["reason"], "invalid_header_reference");

        let journal_raw = fs::read_to_string(settings.join(super::super::JOURNAL)).unwrap();
        assert!(!journal_raw.contains(header_secret));
        let journal = load_with(&RealBackend, &settings).unwrap();
        let req_id = proposals[0]["request_id"].as_str().unwrap();
        assert_eq!(
            journal.requests[req_id].payload["header_env"]["X-Api-Key"],
            "AGENT_BRIDGE_EXTENSION_REMOTE_HTTP_X_API_KEY"
        );
    }

    #[test]
    fn import_creates_only_pending_proposals() {
        let sb = Sandbox::new("pending-only");
        let settings = sb.settings();
        let exe = native_fixture_executable(&sb.0, "stdio-pending");
        let before_ext = fs::read(settings.join("extensions.json")).unwrap();

        let mcp_path = sb.0.join("batch.json");
        let doc = json!({
            "mcpServers": {
                "alpha_stdio": {
                    // Claude Code writes Windows paths with forward slashes.
                    "command": exe.to_str().unwrap().replace('\\', "/"),
                    "args": ["--mode", "readonly"]
                },
                "beta_http": {
                    "url": "https://beta.example.invalid/mcp"
                },
                "gamma_disabled": {
                    "disabled": true,
                    "url": "https://gamma.example.invalid/mcp"
                }
            }
        });
        fs::write(&mcp_path, serde_json::to_vec(&doc).unwrap()).unwrap();

        let backend = TestBackend::default();
        let first = import_with(&backend, &settings, &mcp_path, &BTreeSet::new()).unwrap();
        assert_eq!(fs::read(settings.join("extensions.json")).unwrap(), before_ext);
        assert_eq!(first["proposals"].as_array().unwrap().len(), 2);
        assert_eq!(first["skipped"][0]["name"], "gamma_disabled");

        let journal = load_with(&backend, &settings).unwrap();
        assert!(journal.entries.is_empty());
        assert!(journal.controls.is_empty());
        assert_eq!(journal.requests.len(), 2);
        assert!(journal
            .requests
            .values()
            .all(|r| r.status == super::super::Decision::Pending));
        assert!(journal.requests.values()
            .any(|r| r.payload["executable"] == exe.to_str().unwrap()
                && r.payload.get("inherit_path").is_none()));

        // Re-running before any decision produces identical deterministic request IDs.
        let repeat = import_with(&backend, &settings, &mcp_path, &BTreeSet::new()).unwrap();
        assert_eq!(
            repeat["proposals"][0]["request_id"],
            first["proposals"][0]["request_id"]
        );
        assert_eq!(repeat["proposals"][0]["submission"], "previously_recorded");

        // Approve alpha_stdio; revision bumps, then re-import skips alpha_stdio and re-queues beta_http.
        let alpha_id = first["proposals"][0]["request_id"].as_str().unwrap();
        let decided = super::super::decide_inner_with(
            &backend,
            &settings,
            alpha_id,
            true,
            false,
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(decided["decision"], "approved");
        assert_eq!(decided["effect_now"], "added_stdio_without_tools");
        assert!(matches!(load_with(&backend, &settings).unwrap().entries.get("alpha_stdio"),
            Some(ServerEntry::AddedStdio { stdio, .. }) if !stdio.inherit_path));

        let after_one = import_with(&backend, &settings, &mcp_path, &BTreeSet::new()).unwrap();
        let after_proposals = after_one["proposals"].as_array().unwrap();
        assert_eq!(after_proposals.len(), 1);
        assert_eq!(after_proposals[0]["name"], "beta_http");
        assert_eq!(after_proposals[0]["submission"], "queued_for_local_decision");
        assert!(after_one["skipped"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["name"] == "alpha_stdio" && s["reason"] == "identical_existing_server"));
    }

    #[test]
    fn import_proposals_are_approved_together_in_one_decision() {
        let sb = Sandbox::new("batch");
        let settings = sb.settings();
        let exe = native_fixture_executable(&sb.0, "stdio-batch");
        let mcp_path = sb.0.join("batch.json");
        let doc = json!({"mcpServers": {
            "alpha_stdio": {"command": exe.to_str().unwrap()},
            "beta_http": {"url": "https://beta.example.invalid/mcp"},
            "gamma_http": {"url": "https://gamma.example.invalid/mcp"}
        }});
        fs::write(&mcp_path, serde_json::to_vec(&doc).unwrap()).unwrap();
        let backend = TestBackend::default();
        let batch = |ids: &[&str]| super::super::decide_batch_with(&backend, &settings, ids, false);

        let first = import_with(&backend, &settings, &mcp_path, &BTreeSet::new()).unwrap();
        let ids: Vec<String> = first["approve_together"].as_array().unwrap().iter()
            .map(|id| id.as_str().unwrap().to_owned()).collect();
        assert_eq!(ids.len(), 3);
        let id = |n: usize| ids[n].as_str();

        // One decision stales the other proposals of the same import, and a
        // batch holding a stale member changes nothing.
        let refused = super::super::decide_inner_with(&backend, &settings, id(2), false, false, |_| Ok(())).unwrap();
        assert_eq!(refused["decision"], "refused");
        let before = load_with(&backend, &settings).unwrap();
        assert!(batch(&[id(0), id(1)]).is_err());
        let after = load_with(&backend, &settings).unwrap();
        assert_eq!(after.revision, before.revision);
        assert!(after.entries.is_empty());
        assert!(after.requests.get(id(0)).is_some_and(|r| r.status == super::super::Decision::Pending));

        // A fresh import binds the current revision; the batch then applies
        // every member in one journal replacement.
        let second = import_with(&backend, &settings, &mcp_path, &BTreeSet::new()).unwrap();
        let fresh: Vec<String> = second["approve_together"].as_array().unwrap().iter()
            .map(|id| id.as_str().unwrap().to_owned()).collect();
        assert_eq!(fresh.len(), 3);
        let fresh: Vec<&str> = fresh.iter().map(String::as_str).collect();
        assert!(batch(&[fresh[0]]).is_err());
        assert!(batch(&[fresh[0], fresh[0]]).is_err());
        assert!(batch(&[fresh[0], "0".repeat(64).as_str()]).is_err());
        let revision = load_with(&backend, &settings).unwrap().revision;
        let decided = batch(&fresh).unwrap();
        let decisions = decided["decisions"].as_array().unwrap();
        assert_eq!(decisions.len(), 3);
        assert!(decisions.iter().all(|d| d["decision"] == "approved"));
        assert!(decisions.iter().all(|d| d["local_grant_handoff"]["tools_approved"] == 0));
        let journal = load_with(&backend, &settings).unwrap();
        assert_eq!(journal.revision, revision + 1);
        assert_eq!(journal.entries.len(), 3);
        assert_eq!(journal.controls.len(), 3);
        let nonces: BTreeSet<&str> = journal.entries.values().filter_map(|e| match e {
            ServerEntry::Added { grant_nonce, .. } | ServerEntry::AddedStdio { grant_nonce, .. } => Some(grant_nonce.as_str()),
            _ => None,
        }).collect();
        assert_eq!(nonces.len(), 3);
        // Decided members cannot be approved again.
        assert!(batch(&fresh).is_err());

        // Only pending add proposals can be grouped.
        let mut disable = Map::new();
        disable.insert("action".into(), json!("disable"));
        disable.insert("name".into(), json!("alpha_stdio"));
        let receipt = enqueue_with(&backend, &settings, &disable, Origin::LocalCli).unwrap();
        let doc = json!({"mcpServers": {"delta_http": {"url": "https://delta.example.invalid/mcp"}}});
        fs::write(&mcp_path, serde_json::to_vec(&doc).unwrap()).unwrap();
        let third = import_with(&backend, &settings, &mcp_path, &BTreeSet::new()).unwrap();
        let delta = third["proposals"][0]["request_id"].as_str().unwrap().to_owned();
        assert!(batch(&[delta.as_str(), receipt["request_id"].as_str().unwrap()]).is_err());
        assert!(load_with(&backend, &settings).unwrap().requests.get(&delta)
            .is_some_and(|r| r.status == super::super::Decision::Pending));

        // Two proposals for one server cannot be grouped.
        let first_url = json!({"mcpServers": {"eta_http": {"url": "https://eta.example.invalid/one"}}});
        fs::write(&mcp_path, serde_json::to_vec(&first_url).unwrap()).unwrap();
        let one = import_with(&backend, &settings, &mcp_path, &BTreeSet::new()).unwrap();
        let second_url = json!({"mcpServers": {"eta_http": {"url": "https://eta.example.invalid/two"}}});
        fs::write(&mcp_path, serde_json::to_vec(&second_url).unwrap()).unwrap();
        let two = import_with(&backend, &settings, &mcp_path, &BTreeSet::new()).unwrap();
        let eta = [one["proposals"][0]["request_id"].as_str().unwrap(), two["proposals"][0]["request_id"].as_str().unwrap()];
        assert_ne!(eta[0], eta[1]);
        assert!(batch(&eta).is_err());

        // A member that would not be approved records nothing for the others.
        let changing = native_fixture_executable(&sb.0, "stdio-changing");
        let doc = json!({"mcpServers": {
            "zeta_stdio": {"command": changing.to_str().unwrap()},
            "theta_http": {"url": "https://theta.example.invalid/mcp"}
        }});
        fs::write(&mcp_path, serde_json::to_vec(&doc).unwrap()).unwrap();
        let fourth = import_with(&backend, &settings, &mcp_path, &BTreeSet::new()).unwrap();
        let pair: Vec<String> = fourth["approve_together"].as_array().unwrap().iter()
            .map(|id| id.as_str().unwrap().to_owned()).collect();
        let mut bytes = fs::read(&changing).unwrap();
        bytes.push(0);
        fs::write(&changing, bytes).unwrap();
        let before = load_with(&backend, &settings).unwrap();
        let refused = batch(&[pair[0].as_str(), pair[1].as_str()]).unwrap_err();
        assert!(refused.to_string().contains("Batch not recorded"), "{refused}");
        let after = load_with(&backend, &settings).unwrap();
        assert_eq!(after.revision, before.revision);
        assert_eq!(after.entries.len(), before.entries.len());
        assert!(pair.iter().all(|id| after.requests.get(id)
            .is_some_and(|r| r.status == super::super::Decision::Pending)));
    }

    #[test]
    fn import_inherit_path_is_explicit_and_shown_to_the_operator() {
        let sb = Sandbox::new("inherit-path");
        let settings = sb.settings();
        let exe = native_fixture_executable(&sb.0, "stdio-inherit");
        let mcp_path = sb.0.join("inherit.json");
        let doc = json!({
            "mcpServers": {
                "alpha_stdio": {"command": exe.to_str().unwrap()},
                "beta_http": {"url": "https://beta.example.invalid/mcp"},
                "gamma_disabled": {"command": exe.to_str().unwrap(), "disabled": true},
                "delta_mixed": {"command": exe.to_str().unwrap(), "type": "http"}
            }
        });
        fs::write(&mcp_path, serde_json::to_vec(&doc).unwrap()).unwrap();
        let backend = TestBackend::default();

        // Only an importable stdio entry may inherit the PATH, and a refusal
        // happens before anything is queued.
        for name in ["beta_http", "gamma_disabled", "delta_mixed", "absent", "ALPHA_STDIO"] {
            let only = BTreeSet::from([name.to_owned()]);
            assert!(import_with(&backend, &settings, &mcp_path, &only).is_err(), "{name}");
        }
        assert!(load_with(&backend, &settings).unwrap().requests.is_empty());

        let inherit = BTreeSet::from(["alpha_stdio".to_owned()]);
        let first = import_with(&backend, &settings, &mcp_path, &inherit).unwrap();
        let journal = load_with(&backend, &settings).unwrap();
        let alpha = journal.requests.values().find(|r| r.payload["name"] == "alpha_stdio").unwrap();
        assert_eq!(alpha.payload["inherit_path"], true);
        assert!(journal.requests.values().any(|r| r.payload["name"] == "beta_http"
            && r.payload.get("inherit_path").is_none()));

        let alpha_id = first["proposals"].as_array().unwrap().iter()
            .find(|p| p["name"] == "alpha_stdio").unwrap()["request_id"].as_str().unwrap().to_owned();
        let decided = super::super::decide_inner_with(&backend, &settings, &alpha_id, true, false, |_| Ok(())).unwrap();
        assert_eq!(decided["decision"], "approved");
        assert!(matches!(load_with(&backend, &settings).unwrap().entries.get("alpha_stdio"),
            Some(ServerEntry::AddedStdio { stdio, .. }) if stdio.inherit_path));

        // The same flag re-imports as identical; dropping it is a new
        // proposal, never a silent change.
        let same = import_with(&backend, &settings, &mcp_path, &inherit).unwrap();
        assert!(same["skipped"].as_array().unwrap().iter()
            .any(|s| s["name"] == "alpha_stdio" && s["reason"] == "identical_existing_server"));
        let dropped = import_with(&backend, &settings, &mcp_path, &BTreeSet::new()).unwrap();
        let again = dropped["proposals"].as_array().unwrap().iter().find(|p| p["name"] == "alpha_stdio").unwrap();
        assert_eq!(again["submission"], "queued_for_local_decision");
        let journal = load_with(&backend, &settings).unwrap();
        assert!(journal.requests.get(again["request_id"].as_str().unwrap()).unwrap()
            .payload.get("inherit_path").is_none());
    }
}
