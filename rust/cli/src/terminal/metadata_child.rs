//! Private, fixed Agent Bridge child protocol. No MCP router, network, shell,
//! command execution, database, or inherited environment is needed here.
//! Each newline-delimited request is strictly {operation:"get_file_info",path}.

#[cfg(not(unix))]
use agent_bridge_desktop::DesktopConfig;
use agent_bridge_desktop::DesktopFiles;
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};
use std::path::Path;

const MAX_FRAME: usize = 8 * 1024;
const MAX_PATH: usize = 4096;
const MAX_QUERIES: usize = 32;

pub(super) fn valid_relative_path(path: &str) -> bool {
    if path.is_empty() || path.len() > MAX_PATH || path.starts_with('/')
        || path.contains('\\') || path.contains(':') || path.contains('\0')
        || path.chars().any(char::is_control)
    {
        return false;
    }
    path.split('/').all(|part| {
        !part.is_empty() && part != "." && part != ".."
            && part.len() <= 255 && !part.contains('~')
            && !part.ends_with(' ') && !part.ends_with('.')
    })
}

pub(super) fn bounded_line<R: BufRead>(reader: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut bytes = Vec::new();
    loop {
        let part = reader.fill_buf()?;
        if part.is_empty() {
            if bytes.is_empty() { return Ok(None); }
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "incomplete JSON frame"));
        }
        let n = part.iter().position(|&b| b == b'\n')
            .map_or(part.len(), |pos| pos + 1);
        if bytes.len().saturating_add(n) > MAX_FRAME {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "JSON frame too large"));
        }
        let is_end = part[..n].last() == Some(&b'\n');
        bytes.extend_from_slice(&part[..n]);
        reader.consume(n);
        if is_end {
            bytes.pop();
            return Ok(Some(bytes));
        }
    }
}

fn process(files: &DesktopFiles, frame: &[u8]) -> Value {
    let Ok(value) = serde_json::from_slice::<Value>(frame) else {
        return json!({"ok":false,"error":"INVALID_REQUEST"});
    };
    let Some(obj) = value.as_object() else {
        return json!({"ok":false,"error":"INVALID_REQUEST"});
    };
    if obj.len() != 2 || obj.get("operation").and_then(Value::as_str) != Some("get_file_info") {
        return json!({"ok":false,"error":"METHOD_DENIED"});
    }
    let Some(path) = obj.get("path").and_then(Value::as_str) else {
        return json!({"ok":false,"error":"INVALID_PATH"});
    };
    if !valid_relative_path(path) {
        return json!({"ok":false,"error":"INVALID_PATH"});
    }
    // This is the sole method reachable from the child protocol. DesktopFiles
    // stays in its default read-only mode and pins directory handles itself.
    let envelope = files.dispatch("desktop_get_file_info", &json!({"path":path}));
    if envelope["isError"] == true {
        return json!({"ok":false,"error":"METADATA_UNAVAILABLE"});
    }
    let Some(payload) = envelope["content"][0]["text"].as_str() else {
        return json!({"ok":false,"error":"METADATA_UNAVAILABLE"});
    };
    let Ok(metadata) = serde_json::from_str::<Value>(payload) else {
        return json!({"ok":false,"error":"METADATA_UNAVAILABLE"});
    };
    if metadata["kind"] != "file" {
        return json!({"ok":false,"error":"NOT_REGULAR_FILE"});
    }
    json!({"ok":true,"operation":"get_file_info","metadata":metadata})
}

pub(super) fn serve(root: &Path, expected_binding: &str) -> Result<(), crate::runtime::RuntimeError> {
    #[cfg(unix)]
    let files = {
        use std::os::fd::AsFd;
        // This private socket carries a newly owned FD from the parent's
        // actual DesktopFiles root, never a caller-supplied descriptor number.
        let input = io::stdin();
        let handle = agent_bridge_lifecycle::unix_project_handle::receive_project_directory(
            input.as_fd(), expected_binding,
        )?;
        DesktopFiles::open_read_only_from_workspace_handle(root, handle)
            .map_err(|_| io::Error::other("Unable to bind the received read-only workspace"))?
    };
    #[cfg(not(unix))]
    let files = {
        // The parent passes the operator-selected physical project identity in
        // fixed approved argv. Revalidate before opening the capability and
        // again before every metadata request.
        if expected_binding.is_empty()
            || super::metadata_project_binding(root)? != expected_binding
        {
            return Err("Metadata child workspace binding mismatch".into());
        }
        DesktopFiles::open(DesktopConfig::new(root))
            .map_err(|_| io::Error::other("Unable to open validated read-only workspace"))?
    };
    let input = io::stdin();
    let output = io::stdout();
    let mut reader = input.lock();
    let mut writer = output.lock();
    for _ in 0..MAX_QUERIES {
        let Some(frame) = bounded_line(&mut reader)? else { return Ok(()); };
        #[cfg(unix)]
        files.verify_workspace_root_identity()
            .map_err(|_| io::Error::other("Metadata child workspace changed"))?;
        #[cfg(not(unix))]
        if super::metadata_project_binding(root)? != expected_binding {
            return Err("Metadata child workspace changed".into());
        }
        let result = process(&files, &frame);
        let mut bytes = serde_json::to_vec(&result)?;
        if bytes.len() + 1 > MAX_FRAME {
            bytes = b"{\"ok\":false,\"error\":\"RESPONSE_LIMIT\"}".to_vec();
        }
        bytes.push(b'\n');
        writer.write_all(&bytes)?;
        writer.flush()?;
    }
    // Exiting closes stdin/stdout of this child; parent can verify EOF and
    // reap it. No hidden daemon or nested process remains.
    Ok(())
}
