//! Native operator commands for an attached workstation or separately managed local state.

use crate::state::{save_settings_to_disk, AppRuntime, PanelSettings};
use crate::native_runtime::NativeView;
use crate::supervisor::{self, Action, TaskState, Workstation};
use agent_bridge_runtime::backend::{OperatorRead, OperatorWrite};
use agent_bridge_core::{inspect_existing, CoreDatabase};
use agent_bridge_desktop::{DesktopConfig, DesktopFiles};
use agent_bridge_extensions::{OAuthTokenStore, Registry};
use agent_bridge_oauth_server::{Audience, LocalOwner, OAuthConfig};
use serde_json::{json, Map, Value};
use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};
use std::path::Path;
use std::time::Duration;

const LOOPBACK_IP: &str = "127.0.0.1";
const LOOPBACK_SCHEME: &str = "http";


fn operator_read(runtime: &AppRuntime, operation: OperatorRead) -> Result<Value, String> {
    if runtime.native_config.is_configured() {
        runtime.native_config.require()?;
        return runtime.native_runtime.read(operation);
    }
    let path = match operation {
        OperatorRead::Overview => "/api/overview", OperatorRead::Profile => "/api/profile",
        OperatorRead::Missions => "/api/missions", OperatorRead::OAuth => "/api/oauth",
        OperatorRead::Extensions => "/api/extensions", OperatorRead::Skills => "/api/skills",
        OperatorRead::Diagnostics => "/api/diagnostics",
        OperatorRead::Sessions => "/api/sessions",
    };
    runtime.operator.client()?.get(path)
}

fn operator_write(runtime: &AppRuntime, operation: OperatorWrite, payload: Value) -> Result<Value, String> {
    if runtime.native_config.is_configured() {
        runtime.native_config.require()?;
        return runtime.native_runtime.write(operation, payload);
    }
    let path = match operation {
        OperatorWrite::SetProfile => "/api/profile", OperatorWrite::OAuthEnroll => "/api/oauth/enroll",
        OperatorWrite::OAuthApprove => "/api/oauth/approve", OperatorWrite::ExtensionsDecide => "/api/extensions/decide",
        OperatorWrite::SkillsAction => "/api/skills/action",
    };
    runtime.operator.client()?.post(path, payload)
}

fn operator_profile(runtime: &AppRuntime) -> Result<Value, String> {
    crate::operator_connection::profile_snapshot(operator_read(runtime, OperatorRead::Profile)?)
}

fn parse_audience(raw: &str) -> Audience {
    if raw.eq_ignore_ascii_case("missions") {
        Audience::Missions
    } else {
        Audience::Workstation
    }
}

fn open_oauth_owner(settings: &PanelSettings) -> Option<Result<LocalOwner, String>> {
    if settings.oauth_state_dir.is_empty() || settings.oauth_origin.is_empty() {
        return None;
    }
    Some(
        LocalOwner::open(OAuthConfig {
            state_dir: settings.oauth_state_dir.clone().into(),
            public_origin: settings.oauth_origin.clone(),
            audience: parse_audience(&settings.oauth_audience),
        })
        .map_err(|e| e.to_string()),
    )
}

/// Fast non-blocking loopback probe for `GET /health` on `127.0.0.1:<port>`.
pub fn probe_loopback_health(port: u16) -> Value {
    let addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
    let Ok(mut stream) = TcpStream::connect_timeout(&addr.into(), Duration::from_millis(350)) else {
        return json!({ "reachable": false, "port": port });
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(350)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(350)));
    let req = format!(
        "GET /health HTTP/1.1\r\nHost: {LOOPBACK_IP}:{port}\r\nConnection: close\r\n\r\n"
    );
    if stream.write_all(req.as_bytes()).is_err() {
        return json!({ "reachable": false, "port": port });
    }
    let mut raw = String::new();
    let _ = stream.read_to_string(&mut raw);
    let ok = raw.starts_with("HTTP/1.1 200") || raw.starts_with("HTTP/1.0 200");
    let body = raw
        .split_once("\r\n\r\n")
        .and_then(|(_, b)| serde_json::from_str::<Value>(b.trim()).ok());
    json!({
        "reachable": ok,
        "port": port,
        "health": body,
    })
}


fn disconnected_profile(error: Option<&str>) -> Value {
    json!({
        "configured": true, "connected": false, "activeProfile": null,
        "maxProfile": null, "availableProfiles": [], "error": error,
    })
}

fn attached_controls(runtime: &AppRuntime, connected: bool) -> Value {
    let phase = runtime.lifecycle.phase().map(Action::phase);
    if runtime.native_config.is_configured() {
        let error = runtime.native_config.require().err();
        return runtime.native_runtime.controls(&runtime.native_runtime.snapshot(), error.is_none(), phase, error);
    }
    let mut can_start = false;
    let mut can_stop = false;
    let mut can_restart = false;
    let reason = match runtime.operator.client() {
        Err(error) => Some(error),
        Ok(client) => {
            can_stop = connected && client.supports_shutdown();
            match client.supervisor() {
                None => Some("Start this workstation through its external owner. No startup supervisor is configured.".to_owned()),
                Some(config) => match supervisor::connect(config).and_then(|mut owner| owner.state()) {
                    Err(error) => Some(error),
                    Ok(state) => {
                        let mut connection = client;
                        can_start = !connected && state == TaskState::Ready && connection.ports_closed(None);
                        can_restart = connected && can_stop && state == TaskState::Running;
                        if connected && !client.supports_shutdown() {
                            Some("The attached workstation does not advertise cooperative shutdown. Use its external owner.".to_owned())
                        } else if !connected && state != TaskState::Ready {
                            Some("The configured supervisor is active; waiting for an authenticated workstation session.".to_owned())
                        } else { None }
                    }
                },
            }
        }
    };
    json!({
        "canStart": phase.is_none() && can_start,
        "canStop": phase.is_none() && can_stop,
        "canRestart": phase.is_none() && can_restart,
        "phase": phase,
        "reason": reason,
    })
}

pub struct NativeStartup {
    pub panel: Result<Value, String>,
}

pub fn initialize_native_for_app(runtime: &AppRuntime) -> Result<NativeStartup, String> {
    perform_native_lifecycle(runtime, Action::Start)?;
    Ok(NativeStartup { panel: get_panel_state(runtime) })
}

fn perform_native_lifecycle(runtime: &AppRuntime, action: Action) -> Result<(), String> {
    let config = runtime.native_config.require()?;
    let _operation = runtime.lifecycle.begin(action)?;
    match action {
        Action::Start => runtime.native_runtime.start(config),
        Action::Stop => runtime.native_runtime.stop(),
        Action::Restart => {
            if !runtime.native_runtime.snapshot().running {
                Err("Restart requires the running native workstation.".into())
            } else {
                runtime.native_runtime.stop().and_then(|_| runtime.native_runtime.start(config))
            }
        }
    }
}

fn attached_lifecycle(runtime: &AppRuntime, action: Action) -> Result<Value, String> {
    if runtime.native_config.is_configured() {
        perform_native_lifecycle(runtime, action)?;
        return get_panel_state(runtime);
    }
    let mut connection = runtime.operator.client()?;
    let mut owner = match action {
        Action::Stop => None,
        Action::Start | Action::Restart => connection.supervisor().map(supervisor::connect).transpose()?,
    };
    let result = match owner.as_mut() {
        Some(owner) => runtime.lifecycle.perform(action, &mut connection, Some(owner.as_mut())),
        None => runtime.lifecycle.perform(action, &mut connection, None),
    };
    result?;
    get_panel_state(runtime)
}

fn attached_panel_state(
    runtime: &AppRuntime, settings: &PanelSettings, changed_profile: Option<Value>,
    captured_native: Option<NativeView>,
) -> Result<Value, String> {
    let native = runtime.native_config.is_configured();
    let mut native_view = captured_native.unwrap_or_else(|| runtime.native_runtime.snapshot());
    let configuration_error = if native { runtime.native_config.require().err() } else { None };
    let stopped = native && configuration_error.is_none() && !native_view.owned
        && !native_view.running && native_view.error.is_none();
    let port = if native {
        native_view.descriptor.as_ref().and_then(|d| d.listen_addr.parse::<std::net::SocketAddr>().ok())
            .map(|addr| addr.port())
            .or_else(|| runtime.native_config.require().ok().and_then(|c| c.arguments.get(5)?.parse().ok()))
            .unwrap_or(0)
    } else { runtime.operator.gateway_port().unwrap_or(0) };
    let mcp_url = if port != 0 { format!("{LOOPBACK_SCHEME}://{LOOPBACK_IP}:{port}/mcp") } else { String::new() };
    let mut effective = settings.clone();
    effective.workspace.clear();
    effective.database_path.clear();
    effective.settings_dir.clear();
    effective.lifecycle_dir.clear();
    effective.oauth_state_dir.clear();
    effective.oauth_origin.clear();
    effective.recent_workspaces.clear();
    effective.profile.clear();
    effective.gateway_port = port;
    effective.onboarding_completed = true;

    let read = |operation| if native { native_view.read(operation) } else { operator_read(runtime, operation) };
    let profile = if stopped {
        Ok(disconnected_profile(None))
    } else if let Some(error) = &configuration_error {
        Err(error.clone())
    } else {
        changed_profile.map(Ok).unwrap_or_else(|| {
            if native {
                if !native_view.running {
                    return Err(native_view.error.clone().unwrap_or_else(|| "The native workstation is not running.".into()));
                }
                crate::operator_connection::profile_snapshot(read(OperatorRead::Profile)?)
            } else { operator_profile(runtime) }
        })
    };
    let (live_profile, connected, connection_error) = match profile {
        Ok(profile) => {
            effective.profile = profile["activeProfile"].as_str().unwrap_or_default().to_owned();
            let connected = profile["connected"].as_bool().unwrap_or(false);
            (profile, connected, None)
        }
        Err(error) => (disconnected_profile(Some(&error)), false, Some(error)),
    };
    #[cfg(test)]
    runtime.checkpoint("after-panel-profile");
    let mut overview = Value::Null;
    let mut extensions = json!({ "configured": false, "exists": false, "servers": [], "requests": [] });
    if connected {
        overview = read(OperatorRead::Overview).unwrap_or_else(|error| json!({ "error": error }));
        extensions = read(OperatorRead::Extensions)
            .map(map_attached_extensions)
            .unwrap_or_else(|error| json!({ "configured": true, "exists": false, "error": error, "servers": [], "requests": [] }));
    }
    if native { native_view = runtime.native_runtime.revalidate_view(&native_view)?; }
    let controls = if native {
        runtime.native_runtime.controls(&native_view, configuration_error.is_none(),
            runtime.lifecycle.phase().map(Action::phase), configuration_error)
    } else { attached_controls(runtime, connected) };
    effective.workspace = overview.pointer("/project/path").and_then(Value::as_str).unwrap_or_default().to_owned();
    effective.database_path = overview.pointer("/database/path").and_then(Value::as_str).unwrap_or_default().to_owned();
    effective.settings_dir = overview.pointer("/extensions/settings_dir").and_then(Value::as_str).unwrap_or_default().to_owned();
    effective.oauth_state_dir = overview.pointer("/oauth/state_dir").and_then(Value::as_str).unwrap_or_default().to_owned();
    effective.oauth_origin = overview.pointer("/oauth/public_origin").and_then(Value::as_str).unwrap_or_default().to_owned();
    effective.oauth_audience = overview.pointer("/oauth/audience").and_then(Value::as_str).unwrap_or("workstation").to_ascii_lowercase();
    let oauth_pending = overview.pointer("/oauth/pending_count").and_then(Value::as_u64).unwrap_or(0);
    let extension_pending = overview.pointer("/extensions/pending_count").and_then(Value::as_u64).unwrap_or(0);

    Ok(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "os": overview.get("os").cloned().unwrap_or_else(|| json!(std::env::consts::OS)),
        "arch": overview.get("arch").cloned().unwrap_or_else(|| json!(std::env::consts::ARCH)),
        "settings": effective,
        "liveProfile": live_profile,
        "gateway": {
            "live": connected, "external": !native, "native": native,
            "ownedRunning": native && native_view.running, "reachable": connected,
            "stopped": stopped,
            "generation": native_view.descriptor.as_ref().map(|d| d.generation).unwrap_or(0),
            "port": port, "mcpUrl": mcp_url, "lastError": connection_error,
            "controls": controls,
            "health": { "service": "agent-bridge-workstation", "version": overview["version"] },
        },
        "database": {
            "configured": overview.pointer("/database/configured").and_then(Value::as_bool).unwrap_or(false),
            "exists": overview.pointer("/database/exists").and_then(Value::as_bool).unwrap_or(false),
            "path": overview.pointer("/database/path").cloned().unwrap_or(Value::Null),
            "schemaVersion": overview.pointer("/database/schema_version").cloned().unwrap_or(Value::Null),
            "pendingMigrations": overview.pointer("/database/pending_migrations").cloned().unwrap_or(Value::Null),
            "activeMissions": overview.pointer("/database/counts/missions/active").and_then(Value::as_u64).unwrap_or(0),
            "totalMissions": overview.pointer("/database/counts/missions/total").and_then(Value::as_u64).unwrap_or(0),
            "totalTaskRooms": overview.pointer("/database/counts/task_rooms").and_then(Value::as_u64).unwrap_or(0),
            "error": overview.pointer("/database/error").cloned().unwrap_or(Value::Null),
        },
        "oauth": {
            "configured": overview.pointer("/oauth/configured").and_then(Value::as_bool).unwrap_or(false),
            "origin": overview.pointer("/oauth/public_origin").cloned().unwrap_or(Value::Null),
            "audience": overview.pointer("/oauth/audience").cloned().unwrap_or(Value::Null),
            "pendingCount": oauth_pending,
            "error": overview.pointer("/oauth/error").cloned().unwrap_or(Value::Null),
        },
        "extensions": extensions,
        "skillsCount": overview.pointer("/skills/installed_count").and_then(Value::as_u64).unwrap_or(0),
        "pendingApprovalsTotal": oauth_pending + extension_pending,
        "operatorError": overview["error"],
        "tunnel": native_view.tunnel,
        "quickstart": {
            "mcpLoopbackUrl": mcp_url,
            "stdioReadOnly": overview.pointer("/quickstart_commands/stdio_read_only").and_then(Value::as_str).unwrap_or(""),
            "stdioWorkspaceWrite": overview.pointer("/quickstart_commands/stdio_workspace_write").and_then(Value::as_str).unwrap_or(""),
        },
    }))
}

fn map_attached_extensions(value: Value) -> Value {
    let requests = value["requests"].as_array().map(|rows| rows.iter().map(|row| json!({
        "requestId": row["request_id"],
        "action": row["action"],
        "name": row["name"],
        "status": row["decision"],
        "reason": row["reason"],
        "revision": row["revision"],
        "payload": row["payload"],
    })).collect::<Vec<_>>()).unwrap_or_default();
    let outbound = value["outbound_oauth"].as_object().map(|items| items.iter().map(|(name, metadata)| (
        name.clone(), json!({
            "enabled": metadata["enabled"], "scope": metadata["scope"],
            "clientId": metadata["client_id"], "tokenStatus": metadata["token_status"],
        })
    )).collect::<Map<String, Value>>()).unwrap_or_default();
    json!({
        "configured": value["configured"],
        "exists": value["configured"] == true,
        "settingsDir": value["settings_dir"],
        "canDecide": value["configured"] == true,
        "oauthOperation": value["oauth_operation"],
        "pendingCount": value["pending_count"],
        "serverCount": value["servers"].as_array().map(Vec::len).unwrap_or(0),
        "servers": value.get("servers").cloned().unwrap_or_else(|| json!([])),
        "approvedTools": value.get("approved_tools").cloned().unwrap_or_else(|| json!([])),
        "outboundOauth": outbound,
        "requests": requests,
    })
}

pub fn decide_extension_request(
    runtime: &AppRuntime,
    request_id: &str,
    approve: bool,
    reviewed: bool,
) -> Result<Value, String> {
    if request_id.len() != 64 || !request_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("Select an exact extension proposal before deciding it.".to_owned());
    }
    if approve && !reviewed {
        return Err("Review the exact extension endpoint and proposal before approving it.".to_owned());
    }
    operator_write(runtime, OperatorWrite::ExtensionsDecide, json!({
        "request_id": request_id,
        "approve": approve,
        "confirm": if approve { "APPROVE" } else { "REFUSE" },
    }))
}

fn map_attached_oauth(value: Value) -> Value {
    let pending = value["pending"].as_array().map(|rows| rows.iter().map(|row| json!({
        "id": row["id"], "clientId": row["client_id"], "provider": row["provider"],
        "redirectUri": row["redirect_uri"], "resource": row["resource"], "scope": row["scope"],
        "expiresEpochMs": row["expires_epoch_ms"], "audience": row["audience"],
        "capability": row.get("capability").cloned().unwrap_or_else(|| json!({"kind":"legacy"})),
    })).collect::<Vec<_>>()).unwrap_or_default();
    json!({
        "configured": value["configured"],
        "origin": value["public_origin"],
        "audience": value["audience"],
        "count": pending.len(),
        "pending": pending,
        "capabilitySelection": value["capability_selection"],
    })
}

fn map_attached_diagnostics(value: Value) -> Value {
    json!({
        "os": value["os"], "arch": value["arch"], "version": value["version"],
        "oauthKeystore": value.pointer("/capabilities/outbound_oauth_keystore").cloned().unwrap_or(Value::Null),
        "mcpBrowserProfiles": value.pointer("/browser_profiles/mcp_persistent_profiles").cloned().unwrap_or_else(|| json!([])),
        "workspaceAccess": value["workspace_inspection"],
        "capabilitySelection": value["capability_selection"],
        "providerCleanup": value["provider_cleanup"],
        "mcpRequestAudit": value["mcp_request_audit"],
        "capabilities": {
            "missionsAndTaskRooms": value.pointer("/capabilities/missions_and_task_rooms").cloned().unwrap_or(Value::Null),
            "workspaceFilesAndArtifacts": value.pointer("/capabilities/workspace_files_and_artifacts").cloned().unwrap_or(Value::Null),
            "documentarySkills": value.pointer("/capabilities/documentary_skills").cloned().unwrap_or(Value::Null),
            "inboundOAuth21": value.pointer("/capabilities/inbound_oauth_2_1").cloned().unwrap_or(Value::Null),
            "nativeChromeCdpPipe": value.pointer("/capabilities/native_chrome_cdp_pipe").cloned().unwrap_or(Value::Null),
            "nativeWindowInspection": value.pointer("/capabilities/native_window_inspection").cloned().unwrap_or(Value::Null),
            "confinedProcesses": value.pointer("/capabilities/confined_process_sessions").cloned().unwrap_or(Value::Null),
        },
    })
}

pub fn get_panel_state(runtime: &AppRuntime) -> Result<Value, String> {
    if runtime.native_config.is_configured() { runtime.native_runtime.observe_termination(); }
    let settings = runtime
        .settings
        .lock()
        .map_err(|_| "Settings lock poisoned".to_owned())?
        .clone();
    if runtime.is_live() {
        return attached_panel_state(runtime, &settings, None, None);
    }

    let (owned_running, owned_port, last_error) = {
        let mut gw = runtime
            .gateway
            .lock()
            .map_err(|_| "Gateway lock poisoned".to_owned())?;
        let running = gw.is_owned_running();
        let port = gw.port();
        let err = gw.last_error().map(str::to_owned);
        (running, port, err)
    };

    let probe_port = if owned_running {
        owned_port
    } else {
        settings.gateway_port
    };
    let probe = probe_loopback_health(probe_port);
    let live = probe["reachable"].as_bool().unwrap_or(false) || owned_running;

    let db_summary = inspect_database_summary(&settings.database_path);
    let oauth_summary = inspect_oauth_summary(&settings);
    let ext_summary = inspect_extensions_summary(&settings.settings_dir);
    let skills_count = inspect_skills_list(&settings.settings_dir, &settings.workspace)
        .ok()
        .and_then(|v| v.get("skills").and_then(Value::as_array).map(|a| a.len()))
        .unwrap_or(0);

    let pending_oauth = oauth_summary["pendingCount"].as_u64().unwrap_or(0);
    let pending_ext = ext_summary["pendingCount"].as_u64().unwrap_or(0);

    let mcp_url = format!("{LOOPBACK_SCHEME}://{LOOPBACK_IP}:{probe_port}/mcp");
    let ws_display = if settings.workspace.is_empty() {
        "<project-directory>".to_owned()
    } else {
        settings.workspace.clone()
    };
    let db_display = if settings.database_path.is_empty() {
        "<missions.sqlite>".to_owned()
    } else {
        settings.database_path.clone()
    };
    let set_display = if settings.settings_dir.is_empty() {
        "<private-settings-dir>".to_owned()
    } else {
        settings.settings_dir.clone()
    };

    Ok(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "settings": settings,
        "gateway": {
            "live": live,
            "ownedRunning": owned_running,
            "reachable": probe["reachable"],
            "port": probe_port,
            "mcpUrl": mcp_url,
            "lastError": last_error,
            "health": probe["health"],
        },
        "database": db_summary,
        "oauth": oauth_summary,
        "extensions": ext_summary,
        "skillsCount": skills_count,
        "pendingApprovalsTotal": pending_oauth + pending_ext,
        "quickstart": {
            "mcpLoopbackUrl": mcp_url,
            "stdioReadOnly": format!("agent-bridge stdio \"{db_display}\" --workspace \"{ws_display}\" --settings \"{set_display}\""),
            "stdioWorkspaceWrite": format!("agent-bridge stdio \"{db_display}\" --write-workspace \"{ws_display}\" --settings \"{set_display}\""),
        },
    }))
}

fn inspect_database_summary(db_path: &str) -> Value {
    if db_path.is_empty() {
        return json!({ "configured": false, "exists": false });
    }
    let path = Path::new(db_path);
    if !path.exists() {
        return json!({ "configured": true, "exists": false, "path": db_path });
    }
    match inspect_existing(path) {
        Ok(status) => {
            let mut active = 0i64;
            let mut total = 0i64;
            let mut task_rooms = 0i64;
            if status.pending_migrations == 0 {
                if let Ok(db) = CoreDatabase::open_existing(path) {
                    if let Ok(snap) =
                        agent_bridge_missions::operator::inspect_operator_snapshot(db.connection(), 1)
                    {
                        active = snap["mission_counts"]["active"].as_i64().unwrap_or(0);
                        total = snap["mission_counts"]["total"].as_i64().unwrap_or(0);
                        task_rooms = snap["total_task_rooms"].as_i64().unwrap_or(0);
                    }
                }
            }
            json!({
                "configured": true,
                "exists": true,
                "path": db_path,
                "schemaVersion": status.version,
                "pendingMigrations": status.pending_migrations,
                "activeMissions": active,
                "totalMissions": total,
                "totalTaskRooms": task_rooms,
            })
        }
        Err(err) => json!({
            "configured": true,
            "exists": true,
            "path": db_path,
            "error": err.to_string(),
        }),
    }
}

fn inspect_oauth_summary(settings: &PanelSettings) -> Value {
    match open_oauth_owner(settings) {
        None => json!({ "configured": false, "pendingCount": 0 }),
        Some(Ok(owner)) => match owner.pending_requests() {
            Ok(list) => json!({
                "configured": true,
                "origin": settings.oauth_origin,
                "audience": settings.oauth_audience,
                "pendingCount": list.len(),
            }),
            Err(err) => json!({
                "configured": true,
                "origin": settings.oauth_origin,
                "audience": settings.oauth_audience,
                "pendingCount": 0,
                "error": err.to_string(),
            }),
        },
        Some(Err(err)) => json!({
            "configured": true,
            "origin": settings.oauth_origin,
            "audience": settings.oauth_audience,
            "pendingCount": 0,
            "error": err,
        }),
    }
}

fn read_extension_journal_summary(settings_dir: &Path) -> (usize, Vec<Value>, Map<String, Value>) {
    let journal_path = settings_dir.join(".extensions-admin.json");
    let Ok(bytes) = fs::read(&journal_path) else {
        return (0, Vec::new(), Map::new());
    };
    let Ok(doc) = serde_json::from_slice::<Value>(&bytes) else {
        return (0, Vec::new(), Map::new());
    };
    let mut pending = 0usize;
    let mut requests = Vec::new();
    if let Some(map) = doc.get("requests").and_then(Value::as_object) {
        for (id, rec) in map {
            let status = rec
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            if status == "pending" {
                pending += 1;
            }
            requests.push(json!({
                "requestId": id,
                "action": rec.pointer("/payload/action").and_then(Value::as_str).unwrap_or(""),
                "name": rec.pointer("/payload/name").and_then(Value::as_str).unwrap_or(""),
                "status": status,
                "reason": rec.get("reason").cloned().unwrap_or(Value::Null),
                "revision": rec.get("revision").and_then(Value::as_i64).unwrap_or(0),
            }));
        }
    }
    let mut oauth_meta = Map::new();
    if let Some(ocfgs) = doc.get("oauth_configs").and_then(Value::as_object) {
        for (server, cfg) in ocfgs {
            let token_status = OAuthTokenStore::load_status(settings_dir, server).ok();
            oauth_meta.insert(
                server.clone(),
                json!({
                    "enabled": cfg.get("enabled").and_then(Value::as_bool).unwrap_or(false),
                    "scope": cfg.get("scope").cloned().unwrap_or(Value::Null),
                    "clientId": cfg.get("client_id").cloned().unwrap_or(Value::Null),
                    "tokenStatus": token_status,
                }),
            );
        }
    }
    (pending, requests, oauth_meta)
}

fn inspect_extensions_summary(settings_dir: &str) -> Value {
    if settings_dir.is_empty() {
        return json!({ "configured": false, "pendingCount": 0, "serverCount": 0 });
    }
    let dir = Path::new(settings_dir);
    if !dir.is_dir() {
        return json!({ "configured": true, "exists": false, "pendingCount": 0, "serverCount": 0 });
    }
    let (pending_count, requests, outbound_oauth) = read_extension_journal_summary(dir);
    let base = agent_bridge_lifecycle::read_operator_setting(dir, "extensions.json")
        .ok()
        .and_then(|bytes| Registry::parse(&bytes).ok());
    let servers = base
        .as_ref()
        .and_then(|reg| reg.servers(None).ok())
        .and_then(|v| v.get("servers").cloned())
        .unwrap_or_else(|| json!([]));
    let server_count = servers.as_array().map(|a| a.len()).unwrap_or(0);
    let approved_tools = base.as_ref().map(|r| r.list()).unwrap_or_default();

    json!({
        "configured": true,
        "exists": true,
        "settingsDir": settings_dir,
        "pendingCount": pending_count,
        "serverCount": server_count,
        "servers": servers,
        "approvedTools": approved_tools,
        "outboundOauth": outbound_oauth,
        "requests": requests,
    })
}

pub fn save_panel_settings(runtime: &AppRuntime, mut incoming: PanelSettings) -> Result<Value, String> {
    if runtime.is_live() {
        let current = runtime.settings.lock().map_err(|_| "Settings lock poisoned".to_owned())?.clone();
        let mut panel = attached_panel_state(runtime, &current, None, None)?;
        let expected: PanelSettings = serde_json::from_value(panel["settings"].clone())
            .map_err(|_| "Attached workstation settings are unavailable.")?;
        let mut compared = incoming.clone();
        compared.theme = expected.theme.clone();
        if compared != expected {
            return Err("Runtime settings belong to the attached workstation. Only the desktop theme can be changed here.".to_owned());
        }
        let mut updated = current;
        updated.theme = if matches!(incoming.theme.as_str(), "system" | "light" | "dark") {
            incoming.theme
        } else { "system".to_owned() };
        save_settings_to_disk(&runtime.config_root, &updated)?;
        *runtime.settings.lock().map_err(|_| "Settings lock poisoned".to_owned())? = updated.clone();
        panel["settings"]["theme"] = json!(updated.theme);
        return Ok(panel);
    }
    incoming.normalize();
    save_settings_to_disk(&runtime.config_root, &incoming)?;
    {
        let mut guard = runtime
            .settings
            .lock()
            .map_err(|_| "Settings lock poisoned".to_owned())?;
        *guard = incoming;
    }
    get_panel_state(runtime)
}

pub fn set_permission_profile(
    runtime: &AppRuntime,
    profile: &str,
    confirmed: bool,
) -> Result<Value, String> {
    if !matches!(
        profile,
        "read-only" | "workspace-write" | "full-control" | "fully-unlocked"
    ) {
        return Err("Unsupported permission profile.".to_owned());
    }
    if runtime.is_live() {
        if runtime.lifecycle.phase().is_some() {
            return Err("Wait for the workstation lifecycle action before changing its mode.".to_owned());
        }
        let captured = if runtime.native_config.is_configured() {
            runtime.native_config.require()?;
            Some(runtime.native_runtime.snapshot())
        } else { None };
        let reply = match &captured {
            Some(view) => view.write(OperatorWrite::SetProfile, json!({ "profile": profile })),
            None => operator_write(runtime, OperatorWrite::SetProfile, json!({ "profile": profile })),
        }?;
        let live_profile = crate::operator_connection::profile_snapshot(reply)?;
        #[cfg(test)]
        runtime.checkpoint("after-profile-write");
        let settings = runtime.settings.lock().map_err(|_| "Settings lock poisoned".to_owned())?.clone();
        return attached_panel_state(runtime, &settings, Some(live_profile), captured);
    }
    if matches!(profile, "full-control" | "fully-unlocked") && !confirmed {
        return Err("Explicit confirmation is required before enabling elevated profiles.".to_owned());
    }
    let mut updated = runtime
        .settings
        .lock()
        .map_err(|_| "Settings lock poisoned".to_owned())?
        .clone();
    updated.profile = profile.to_owned();
    updated.normalize();
    save_settings_to_disk(&runtime.config_root, &updated)?;
    {
        let mut guard = runtime
            .settings
            .lock()
            .map_err(|_| "Settings lock poisoned".to_owned())?;
        *guard = updated.clone();
    }
    get_panel_state(runtime)
}

pub fn initialize_local_state(runtime: &AppRuntime) -> Result<Value, String> {
    if runtime.native_config.is_configured() {
        runtime.native_config.require()?;
        return Err("The native workstation owns its runtime state. Initialize it through the configured installation.".into());
    }
    if runtime.is_live() {
        return Err("This desktop app is attached to an externally managed workstation. Its process and local state are controlled by the operator launcher.".to_owned());
    }
    let settings = runtime
        .settings
        .lock()
        .map_err(|_| "Settings lock poisoned".to_owned())?
        .clone();

    let mut actions = Vec::new();

    if !settings.database_path.is_empty() {
        let db_path = Path::new(&settings.database_path);
        if let Some(parent) = db_path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("Cannot create database folder: {e}"))?;
        }
        if !db_path.exists() {
            let _ = CoreDatabase::initialize_new(db_path)
                .map_err(|e| format!("Database initialization failed: {e}"))?;
            actions.push("database_initialized");
        } else {
            let status = inspect_existing(db_path)
                .map_err(|e| format!("Database inspection failed: {e}"))?;
            if status.pending_migrations > 0 {
                let _ = CoreDatabase::migrate_existing(db_path)
                    .map_err(|e| format!("Database migration failed: {e}"))?;
                actions.push("database_migrated");
            } else {
                actions.push("database_ready");
            }
        }
    }

    if !settings.settings_dir.is_empty() {
        let dir = Path::new(&settings.settings_dir);
        if !dir.join("extensions.json").exists() {
            agent_bridge_lifecycle::initialize_operator_settings(dir)
                .map_err(|e| format!("Settings initialization failed: {e}"))?;
            actions.push("settings_initialized");
        } else {
            actions.push("settings_ready");
        }
    }

    if !settings.lifecycle_dir.is_empty() {
        fs::create_dir_all(&settings.lifecycle_dir)
            .map_err(|e| format!("Cannot create lifecycle directory: {e}"))?;
        actions.push("lifecycle_ready");
    }

    Ok(json!({
        "ok": true,
        "actions": actions,
        "state": get_panel_state(runtime)?,
    }))
}

#[derive(Clone, Copy, Default, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GatewayIntent {
    #[default]
    Start,
    Restart,
}

pub fn start_or_restart_gateway(runtime: &AppRuntime, intent: GatewayIntent) -> Result<Value, String> {
    if runtime.is_live() {
        let action = match intent { GatewayIntent::Start => Action::Start, GatewayIntent::Restart => Action::Restart };
        return attached_lifecycle(runtime, action);
    }
    let settings = runtime
        .settings
        .lock()
        .map_err(|_| "Settings lock poisoned".to_owned())?
        .clone();
    #[cfg(test)]
    runtime.checkpoint("before-legacy-start-lock");
    {
        let mut gw = runtime
            .gateway
            .lock()
            .map_err(|_| "Gateway lock poisoned".to_owned())?;
        if runtime.native_runtime.is_closing() {
            return Err("Agent Bridge is quitting; the local gateway cannot start.".into());
        }
        gw.start(&settings)?;
    }
    std::thread::sleep(Duration::from_millis(250));
    get_panel_state(runtime)
}

pub fn stop_gateway(runtime: &AppRuntime) -> Result<Value, String> {
    if runtime.is_live() {
        return attached_lifecycle(runtime, Action::Stop);
    }
    {
        let mut gw = runtime
            .gateway
            .lock()
            .map_err(|_| "Gateway lock poisoned".to_owned())?;
        gw.stop()?;
    }
    get_panel_state(runtime)
}

pub fn get_missions_snapshot(runtime: &AppRuntime) -> Result<Value, String> {
    if runtime.is_live() {
        let mut snapshot = operator_read(runtime, OperatorRead::Missions)?;
        snapshot["exists"] = json!(snapshot["configured"] == true);
        snapshot["needsMigration"] = snapshot.get("needs_migration").cloned().unwrap_or(json!(false));
        return Ok(snapshot);
    }
    let settings = runtime
        .settings
        .lock()
        .map_err(|_| "Settings lock poisoned".to_owned())?
        .clone();
    if settings.database_path.is_empty() {
        return Ok(json!({ "configured": false }));
    }
    let path = Path::new(&settings.database_path);
    if !path.exists() {
        return Ok(json!({ "configured": true, "exists": false, "path": settings.database_path }));
    }
    let status = inspect_existing(path).map_err(|e| e.to_string())?;
    if status.pending_migrations > 0 {
        return Ok(json!({
            "configured": true,
            "exists": true,
            "needsMigration": true,
            "schemaVersion": status.version,
            "pendingMigrations": status.pending_migrations,
        }));
    }
    let db = CoreDatabase::open_existing(path).map_err(|e| e.to_string())?;
    let mut snap = agent_bridge_missions::operator::inspect_operator_snapshot(db.connection(), 100)
        .map_err(|e| e.message)?;
    snap["configured"] = json!(true);
    snap["exists"] = json!(true);
    snap["path"] = json!(settings.database_path);
    Ok(snap)
}

pub fn get_oauth_pending(runtime: &AppRuntime) -> Result<Value, String> {
    if runtime.is_live() {
        return operator_read(runtime, OperatorRead::OAuth).map(map_attached_oauth);
    }
    let settings = runtime
        .settings
        .lock()
        .map_err(|_| "Settings lock poisoned".to_owned())?
        .clone();
    match open_oauth_owner(&settings) {
        None => Ok(json!({ "configured": false, "pending": [] })),
        Some(Err(err)) => Err(err),
        Some(Ok(owner)) => {
            let list: Vec<Value> = owner
                .pending_requests()
                .map_err(|e| e.to_string())?
                .into_iter()
                .map(|req| {
                    json!({
                        "id": req.id,
                        "clientId": req.client_id,
                        "provider": if req.client_id.starts_with("chatgpt_") { "chatgpt" } else { "gemini" },
                        "redirectUri": req.redirect_uri,
                        "resource": req.resource,
                        "scope": req.scope,
                        "expiresEpochMs": req.expires_epoch_ms,
                        "audience": format!("{:?}", req.audience),
                        "capability": req.capability,
                    })
                })
                .collect();
            Ok(json!({
                "configured": true,
                "origin": settings.oauth_origin,
                "audience": settings.oauth_audience,
                "count": list.len(),
                "pending": list,
            }))
        }
    }
}

pub fn enable_oauth_enrollment(runtime: &AppRuntime) -> Result<Value, String> {
    if runtime.is_live() {
        let result = operator_write(runtime, OperatorWrite::OAuthEnroll, json!({ "confirm": "APPROVE" }))?;
        return Ok(json!({
            "enabled": result["local_oauth_enrollment"] == "enabled",
            "expiresEpochMs": result["expires_epoch_ms"],
            "durationMaxSeconds": result["duration_max_seconds"],
        }));
    }
    let settings = runtime
        .settings
        .lock()
        .map_err(|_| "Settings lock poisoned".to_owned())?
        .clone();
    let owner = match open_oauth_owner(&settings) {
        None => return Err("Configure OAuth State directory and HTTPS Origin in Settings first.".to_owned()),
        Some(res) => res?,
    };
    let expires = owner.enable_enrollment(|| true).map_err(|e| e.to_string())?;
    Ok(json!({
        "enabled": true,
        "expiresEpochMs": expires,
        "durationMaxSeconds": 600,
    }))
}

pub fn approve_oauth_request(
    runtime: &AppRuntime,
    request_id: &str,
    expected_callback: &str,
    expected_capability: Option<Value>,
) -> Result<Value, String> {
    let expected_capability = agent_bridge_oauth_server::CapabilityIdentity::from_marker(expected_capability.as_ref())
        .map_err(|_| "The reviewed capability is invalid. Refresh the request.".to_owned())?;
    if runtime.is_live() {
        let result = operator_write(runtime, OperatorWrite::OAuthApprove, json!({
            "request_id": request_id, "redirect_uri": expected_callback.trim(), "confirm": "APPROVE",
            "capability": expected_capability,
        }))?;
        return Ok(json!({ "approved": result["local_oauth_request"] == "approved", "id": result["id"] }));
    }
    let settings = runtime
        .settings
        .lock()
        .map_err(|_| "Settings lock poisoned".to_owned())?
        .clone();
    let owner = match open_oauth_owner(&settings) {
        None => return Err("OAuth owner state is not configured.".to_owned()),
        Some(res) => res?,
    };
    let expected = expected_callback.trim().to_owned();
    let mut mismatch = false;
    let mut capability_mismatch = false;
    let res = owner.approve_request(request_id, |req| {
        if req.redirect_uri != expected {
            mismatch = true;
            return false;
        }
        if req.capability != expected_capability {
            capability_mismatch = true;
            return false;
        }
        true
    });
    if mismatch {
        return Err("Callback URI mismatch: paste the exact callback shown in ChatGPT or Gemini.".to_owned());
    }
    if capability_mismatch {
        return Err("Capability changed: refresh and review the exact request before approving.".to_owned());
    }
    res.map_err(|e| e.to_string())?;
    Ok(json!({ "approved": true, "id": request_id }))
}

fn inspect_skills_list(settings_dir: &str, workspace: &str) -> Result<Value, String> {
    if settings_dir.is_empty() {
        return Ok(json!({ "configured": false, "skills": [] }));
    }
    let dir = Path::new(settings_dir);
    if !dir.is_dir() {
        return Ok(json!({ "configured": true, "exists": false, "skills": [] }));
    }
    let store_dir = agent_bridge_lifecycle::operator_skill_directory(dir).map_err(|e| e.to_string())?;
    let ws_path = if !workspace.is_empty() && Path::new(workspace).is_dir() {
        Path::new(workspace)
    } else {
        dir
    };
    let files = DesktopFiles::open(DesktopConfig::new(ws_path)).map_err(|e| e.to_string())?;
    let manager = files.documentary_skills(&store_dir).map_err(|e| e.to_string())?;
    let mut res = manager
        .dispatch(&json!({ "action": "list" }))
        .map_err(|e| e.to_string())?;
    res["configured"] = json!(true);
    Ok(res)
}

pub fn get_skills_overview(runtime: &AppRuntime) -> Result<Value, String> {
    if runtime.is_live() {
        return operator_read(runtime, OperatorRead::Skills);
    }
    let settings = runtime
        .settings
        .lock()
        .map_err(|_| "Settings lock poisoned".to_owned())?
        .clone();
    inspect_skills_list(&settings.settings_dir, &settings.workspace)
}

pub fn run_skill_action(
    runtime: &AppRuntime,
    action: &str,
    name: &str,
    version: Option<String>,
) -> Result<Value, String> {
    if !matches!(action, "get" | "activate" | "rollback") {
        return Err("Allowed desktop actions: get, activate, rollback.".to_owned());
    }
    if runtime.is_live() {
        return operator_write(runtime, OperatorWrite::SkillsAction, json!({
            "action": action, "name": name, "version": version,
        }));
    }
    let settings = runtime
        .settings
        .lock()
        .map_err(|_| "Settings lock poisoned".to_owned())?
        .clone();
    if settings.settings_dir.is_empty() {
        return Err("Settings directory is not configured.".to_owned());
    }
    let dir = Path::new(&settings.settings_dir);
    let store_dir = agent_bridge_lifecycle::operator_skill_directory(dir).map_err(|e| e.to_string())?;
    let ws_path = if !settings.workspace.is_empty() && Path::new(&settings.workspace).is_dir() {
        Path::new(&settings.workspace)
    } else {
        dir
    };
    let files = DesktopFiles::open(DesktopConfig::new(ws_path)).map_err(|e| e.to_string())?;
    let manager = files.documentary_skills(&store_dir).map_err(|e| e.to_string())?;
    let mut args = Map::new();
    args.insert("action".to_owned(), json!(action));
    args.insert("name".to_owned(), json!(name));
    if let Some(v) = version {
        args.insert("version".to_owned(), json!(v));
    }
    manager
        .dispatch(&Value::Object(args))
        .map_err(|e| e.to_string())
}

fn map_sessions(value: Value) -> Value {
    // The operator snapshot contains only schema-defined keys.
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(map_sessions).collect()),
        Value::Object(fields) => Value::Object(fields.into_iter().map(|(key, value)| {
            let mut words = key.split('_');
            let mut camel = words.next().unwrap_or_default().to_owned();
            for word in words {
                let mut chars = word.chars();
                if let Some(first) = chars.next() {
                    camel.push(first.to_ascii_uppercase());
                    camel.push_str(chars.as_str());
                }
            }
            (camel, map_sessions(value))
        }).collect()),
        value => value,
    }
}

pub fn get_sessions(runtime: &AppRuntime) -> Result<Value, String> {
    if runtime.is_live() {
        return Ok(match operator_read(runtime, OperatorRead::Sessions) {
            Ok(snapshot) if snapshot["available"] == true => map_sessions(snapshot),
            _ => json!({ "available": false, "reason": "The workstation session view is unavailable." }),
        });
    }
    let path = runtime.settings.lock().map_err(|_| "Settings lock poisoned".to_owned())?
        .database_path.clone();
    let mut snapshot = json!({ "available": false, "reason": "The workstation is not running." });
    if !path.is_empty() {
        if let Ok(db) = CoreDatabase::open_existing_read_only(Path::new(&path)) {
            if let Ok((_, earlier)) = agent_bridge_missions::operator::inspect_session_contexts(
                db.connection(), &[], Some(&Default::default()), 1_900_000,
            ) {
                snapshot["earlier"] = map_sessions(json!(earlier));
            }
        }
    }
    Ok(snapshot)
}

pub fn get_diagnostics(runtime: &AppRuntime) -> Result<Value, String> {
    if runtime.is_live() {
        return operator_read(runtime, OperatorRead::Diagnostics).map(map_attached_diagnostics);
    }
    let settings = runtime
        .settings
        .lock()
        .map_err(|_| "Settings lock poisoned".to_owned())?
        .clone();

    let mut mcp_profiles = Vec::new();
    if !settings.settings_dir.is_empty() {
        let root = Path::new(&settings.settings_dir).join("mcp-browser-profiles");
        if let Ok(entries) = fs::read_dir(&root) {
            for entry in entries.flatten() {
                if let Ok(meta) = fs::symlink_metadata(entry.path()) {
                    if meta.is_dir() && !meta.file_type().is_symlink() {
                        if let Some(name) = entry.file_name().to_str() {
                            mcp_profiles.push(name.to_owned());
                        }
                    }
                }
            }
        }
        mcp_profiles.sort();
    }

    let workspace_report = if !settings.workspace.is_empty() && Path::new(&settings.workspace).is_dir() {
        match agent_bridge_lifecycle::workspace_access::inspect_project_access(Path::new(&settings.workspace)) {
            Ok(access) => json!({ "ok": true, "access": access }),
            Err(err) => json!({ "ok": false, "error": err.to_string() }),
        }
    } else {
        Value::Null
    };

    let keystore = if cfg!(windows) {
        "Windows DPAPI (CurrentUser)"
    } else if cfg!(target_os = "macos") {
        "macOS Keychain"
    } else {
        "Linux Secret Service"
    };

    Ok(json!({
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "version": env!("CARGO_PKG_VERSION"),
        "oauthKeystore": keystore,
        "mcpBrowserProfiles": mcp_profiles,
        "workspaceAccess": workspace_report,
        "capabilities": {
            "missionsAndTaskRooms": true,
            "workspaceFilesAndArtifacts": true,
            "documentarySkills": true,
            "inboundOAuth21": true,
            "nativeChromeCdpPipe": cfg!(windows),
            "nativeWindowInspection": cfg!(windows),
            "confinedProcesses": cfg!(windows),
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);

    fn temp_dir(label: &str) -> std::path::PathBuf {
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        #[cfg(unix)]
        let base = {
            use std::os::unix::fs::PermissionsExt;
            let home = std::env::var_os("HOME")
                .map(std::path::PathBuf::from)
                .filter(|p| p.is_absolute())
                .unwrap_or_else(std::env::temp_dir);
            let root = home.join(".ab-tauri-tests");
            let _ = fs::create_dir_all(&root);
            let _ = fs::set_permissions(&root, fs::Permissions::from_mode(0o700));
            root
        };
        #[cfg(not(unix))]
        let base = {
            let t = std::env::temp_dir();
            let resolved = fs::canonicalize(&t).unwrap_or(t);
            if let Some(s) = resolved.to_str().and_then(|s| s.strip_prefix("\\\\?\\")) {
                std::path::PathBuf::from(s)
            } else {
                resolved
            }
        };
        let dir = base.join(format!("ab-tauri-{label}-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
        }
        dir
    }

    #[test]
    fn settings_persistence_profile_gate_and_state_init() {
        let root = temp_dir("backend");
        let runtime = AppRuntime::new(root.join("app-config"));

        let ws = root.join("workspace");
        fs::create_dir_all(&ws).unwrap();

        let mut s = PanelSettings::default();
        s.workspace = ws.display().to_string();
        s.database_path = root.join("db").join("missions.sqlite").display().to_string();
        s.settings_dir = root.join("settings").display().to_string();
        s.lifecycle_dir = root.join("lifecycle").display().to_string();
        s.theme = "dark".to_owned();
        s.onboarding_completed = true;

        let saved = save_panel_settings(&runtime, s).expect("save settings");
        assert_eq!(saved["settings"]["theme"], "dark");
        assert_eq!(saved["settings"]["recentWorkspaces"][0], ws.display().to_string());

        // Elevated profile requires explicit confirmation
        assert!(set_permission_profile(&runtime, "full-control", false).is_err());
        let elevated = set_permission_profile(&runtime, "full-control", true).expect("confirm full");
        assert_eq!(elevated["settings"]["profile"], "full-control");

        // Initialize SQLite v7 + private settings directory cleanly
        let init = initialize_local_state(&runtime).expect("initialize local state");
        assert_eq!(init["ok"], true);
        assert_eq!(init["state"]["database"]["exists"], true);
        assert_eq!(init["state"]["database"]["schemaVersion"], 7);

        // Missions snapshot must succeed and never expose handles
        let mut db = CoreDatabase::open_existing(root.join("db").join("missions.sqlite")).unwrap();
        let ctx = agent_bridge_missions::create_context(db.connection_mut()).unwrap();
        let _ = agent_bridge_missions::dispatch_tool(
            db.connection_mut(),
            "agent_bridge_mission_create",
            &json!({
                "actor_context_handle": ctx.context_handle,
                "goal": "Tauri desktop backend test",
                "idempotency_key": "tauri-test-1"
            }),
        )
        .unwrap();
        drop(db);

        let snap = get_missions_snapshot(&runtime).expect("missions snapshot");
        let snap_text = snap.to_string();
        assert!(!snap_text.contains(&ctx.context_handle));
        assert_eq!(snap["mission_counts"]["total"], 1);

        let diag = get_diagnostics(&runtime).expect("diagnostics");
        assert_eq!(diag["capabilities"]["missionsAndTaskRooms"], true);

        let _ = fs::remove_dir_all(&root);
    }
}
