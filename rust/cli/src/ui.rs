//! Local IPv4 loopback operator dashboard (`agent-bridge ui`).
//!
//! Security boundaries:
//! - Binds strictly to IPv4 loopback (`Ipv4Addr::LOCALHOST`).
//! - Every `/api/*` endpoint requires a per-process 256-bit session token
//!   (`X-Agent-Bridge-Token` or `Authorization: Bearer ...`), verified in
//!   constant time.
//! - Strict `Host`, `Origin`, and `Sec-Fetch-Site` validation blocks cross-site
//!   and DNS-rebinding access.
//! - Zero external CDN/font/script dependencies: all assets are embedded via
//!   `include_str!("ui_assets.html")`.
//! - Never exposes secret capability handles, OAuth tokens, or env secrets.

use crate::runtime::{RuntimeError, SharedCoreDatabase};
use crate::session_profile::ProfileControl;
use crate::operation_admission::OperationAdmission;
use agent_bridge_core::{inspect_existing, CoreDatabase};
use agent_bridge_desktop::{DesktopConfig, DesktopFiles, DesktopProfile};
use agent_bridge_oauth_server::{Audience, CapabilityIdentity, LocalOwner, OAuthConfig};
use axum::body::Body;
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;
use serde::Deserialize;
use serde_json::{json, Value};
use std::ffi::OsString;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tokio::sync::watch;

const UI_HTML: &str = include_str!("ui_assets.html");
const MAX_API_BODY_BYTES: usize = 64 * 1024;
const LOOPBACK_SCHEME: &str = "http";
const LOOPBACK_IP: &str = "127.0.0.1";

#[derive(Clone, Debug)]
pub struct UiConfig {
    pub port: u16,
    pub database: Option<PathBuf>,
    pub settings_dir: Option<PathBuf>,
    pub oauth_state: Option<PathBuf>,
    pub oauth_origin: Option<String>,
    pub oauth_audience: Option<Audience>,
    pub project: Option<PathBuf>,
    pub open_browser: bool,
    pub capability_selection: Option<Value>,
    pub(crate) request_audit: Option<Arc<crate::request_audit::RequestAudit>>,
}

#[derive(Clone)]
struct UiState {
    config: UiConfig,
    token: String,
    bound_port: u16,
    started_at_unix: u64,
    profile: Option<ProfileControl>,
    live_database: Option<SharedCoreDatabase>,
    shutdown_sender: Option<watch::Sender<bool>>,
    oauth_owner: crate::extensions::UiOAuthOwner,
    effects: OperationAdmission,
}

impl UiState {
    async fn blocking<F,T>(&self, action:F)->Result<T,RuntimeError>
    where F:FnOnce()->T+Send+'static,T:Send+'static {
        let effects=self.effects.clone();
        tokio::task::spawn_blocking(move || {
            // The permit lives in the real worker, never just in the task
            // awaiting its JoinHandle. Cancellation cannot release it early.
            let _effect=effects.begin()?;
            Ok::<T,RuntimeError>(action())
        }).await.map_err(|_| ->RuntimeError {"Native operator worker failed".into()})?
    }
}

pub fn run_cli(args: &[OsString]) -> Result<(), RuntimeError> {
    let config = parse_args(args)?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(serve(config))
}

fn parse_args(args: &[OsString]) -> Result<UiConfig, RuntimeError> {
    let mut port: u16 = 0;
    let mut database: Option<PathBuf> = None;
    let mut settings_dir: Option<PathBuf> = None;
    let mut oauth_state: Option<PathBuf> = None;
    let mut oauth_origin: Option<String> = None;
    let mut oauth_audience: Option<Audience> = None;
    let mut project: Option<PathBuf> = None;
    let mut open_browser = false;

    let mut iter = args.iter();
    while let Some(flag) = iter.next() {
        match flag.to_str() {
            Some("--port") => {
                let raw = iter
                    .next()
                    .and_then(|v| v.to_str())
                    .ok_or("Expected port number after --port")?;
                port = raw.parse::<u16>().map_err(|_| "Invalid --port number")?;
            }
            Some("--database" | "--db") if database.is_none() => {
                let val = iter.next().ok_or("Expected path after --database")?;
                database = Some(PathBuf::from(val));
            }
            Some("--settings-dir" | "--settings") if settings_dir.is_none() => {
                let val = iter.next().ok_or("Expected directory after --settings-dir")?;
                settings_dir = Some(PathBuf::from(val));
            }
            Some("--oauth-state") if oauth_state.is_none() => {
                let val = iter.next().ok_or("Expected directory after --oauth-state")?;
                oauth_state = Some(PathBuf::from(val));
            }
            Some("--oauth-origin") if oauth_origin.is_none() => {
                let val = iter
                    .next()
                    .and_then(|v| v.to_str())
                    .ok_or("Expected HTTPS origin after --oauth-origin")?;
                oauth_origin = Some(val.to_owned());
            }
            Some("--oauth-audience") if oauth_audience.is_none() => {
                let val = iter
                    .next()
                    .and_then(|v| v.to_str())
                    .ok_or("Expected missions or workstation after --oauth-audience")?;
                oauth_audience = Some(match val {
                    "missions" => Audience::Missions,
                    "workstation" => Audience::Workstation,
                    _ => return Err("--oauth-audience must be missions or workstation".into()),
                });
            }
            Some("--project") if project.is_none() => {
                let val = iter.next().ok_or("Expected directory after --project")?;
                project = Some(PathBuf::from(val));
            }
            Some("--open") => {
                open_browser = true;
            }
            _ => {
                return Err(
                    "Usage: agent-bridge ui [--port <number>] [--database <path>] [--settings-dir <dir>] [--oauth-state <dir> --oauth-origin <https-origin> --oauth-audience <missions|workstation>] [--project <dir>] [--open]"
                        .into(),
                );
            }
        }
    }

    let oauth_parts = usize::from(oauth_state.is_some())
        + usize::from(oauth_origin.is_some())
        + usize::from(oauth_audience.is_some());
    if oauth_parts != 0 && oauth_parts != 3 {
        return Err(
            "OAuth UI controls require all three flags: --oauth-state, --oauth-origin, and --oauth-audience"
                .into(),
        );
    }

    Ok(UiConfig {
        port,
        database,
        settings_dir,
        oauth_state,
        oauth_origin,
        oauth_audience,
        project,
        open_browser,
        capability_selection: None,
        request_audit: None,
    })
}

async fn serve(config: UiConfig) -> Result<(), RuntimeError> {
    serve_with_profile(config, None, None, None, None,OperationAdmission::default()).await
}

/// Shares the already authorized workstation's live profile controller. The
/// caller owns the MCP listener and joins this UI in the same process.
pub(crate) async fn serve_embedded(
    config: UiConfig,
    profile: ProfileControl,
    live_database: Option<SharedCoreDatabase>,
    shutdown: watch::Receiver<bool>,
    shutdown_sender: watch::Sender<bool>,
    effects: OperationAdmission,
) -> Result<(), RuntimeError> {
    serve_with_profile(config, Some(profile), live_database, Some(shutdown), Some(shutdown_sender),effects).await
}

async fn serve_with_profile(
    config: UiConfig,
    profile: Option<ProfileControl>,
    live_database: Option<SharedCoreDatabase>,
    shutdown: Option<watch::Receiver<bool>>,
    shutdown_sender: Option<watch::Sender<bool>>,
    effects: OperationAdmission,
) -> Result<(), RuntimeError> {
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, config.port));
    let listener = TcpListener::bind(addr).await?;
    let local_addr = listener.local_addr()?;
    let bound_port = local_addr.port();
    let token = agent_bridge_missions::operator::random_token_hex(32);
    let started_at_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let base_url = format!("{LOOPBACK_SCHEME}://{LOOPBACK_IP}:{bound_port}");
    let url = format!("{base_url}/?token={token}");
    let open_browser = config.open_browser;
    let live_profile_control = profile.is_some();
    let workstation_shutdown_control = shutdown_sender.is_some();

    let oauth_owner = crate::extensions::UiOAuthOwner::default();
    let state = Arc::new(UiState {
        oauth_owner: oauth_owner.clone(),
        config,
        token: token.clone(),
        bound_port,
        started_at_unix,
        profile,
        live_database,
        shutdown_sender,
        effects: effects.clone(),
    });

    let app = Router::new()
        .route("/", get(handle_index))
        .route("/health", get(handle_health))
        .route("/api/overview", get(handle_overview))
        .route("/api/profile", get(handle_profile).post(handle_set_profile))
        .route("/api/shutdown", post(handle_shutdown))
        .route("/api/missions", get(handle_missions))
        .route("/api/oauth", get(handle_oauth_list))
        .route("/api/oauth/enroll", post(handle_oauth_enroll))
        .route("/api/oauth/approve", post(handle_oauth_approve))
        .route("/api/extensions", get(handle_extensions_list))
        .route("/api/extensions/decide", post(handle_extensions_decide))
        .route("/api/skills", get(handle_skills_list))
        .route("/api/skills/action", post(handle_skills_action))
        .route("/api/diagnostics", get(handle_diagnostics))
        .with_state(state);

    println!(
        "{}",
        json!({
            "service": "agent-bridge-ui",
            "version": env!("CARGO_PKG_VERSION"),
            "listen": format!("{LOOPBACK_IP}:{bound_port}"),
            "ui_url": url,
            "token_required": true,
            "loopback_only": true,
            "live_profile_control": live_profile_control,
            "workstation_shutdown_control": workstation_shutdown_control,
        })
    );
    eprintln!("Agent Bridge Operator UI listening on {base_url}/ (Ctrl-C to stop)");

    if open_browser {
        open_in_default_browser(&url);
    }

    let stopping_owner = oauth_owner.clone();
    let stopping_effects=effects.clone();
    let served = axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            match shutdown {
                Some(receiver) => wait_for_shutdown(receiver).await,
                None => shutdown_signal().await,
            }
            stopping_owner.close_admission();
            stopping_effects.close();
        })
        .await;
    effects.close();
    effects.drain().await;
    oauth_owner.drain().await?;
    served?;
    Ok(())
}

pub(crate) async fn wait_for_shutdown(mut receiver: watch::Receiver<bool>) {
    loop {
        // Read the initial value as well as subsequent changes: the signal
        // may have arrived before either listener started waiting.
        if *receiver.borrow_and_update() {
            return;
        }
        if receiver.changed().await.is_err() {
            return;
        }
    }
}

pub(crate) async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}

fn open_in_default_browser(url: &str) {
    #[cfg(windows)]
    {
        #[link(name = "shell32")]
        extern "system" {
            fn ShellExecuteW(
                window: *mut std::ffi::c_void, verb: *const u16, file: *const u16,
                parameters: *const u16, directory: *const u16, show: i32,
            ) -> *mut std::ffi::c_void;
        }
        if url.contains('\0') { return; }
        let verb: Vec<u16> = "open".encode_utf16().chain(Some(0)).collect();
        let target: Vec<u16> = url.encode_utf16().chain(Some(0)).collect();
        // Only the explicit legacy --open/--ui-open path reaches this point.
        // Pass the URL directly to Windows, with no transient console shell.
        let result = unsafe {
            ShellExecuteW(std::ptr::null_mut(), verb.as_ptr(), target.as_ptr(),
                std::ptr::null(), std::ptr::null(), 1)
        } as isize;
        if result <= 32 {
            eprintln!("Agent Bridge: native browser opening failed (Windows code {result})");
        }
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(url).spawn();
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let _ = std::process::Command::new("xdg-open").arg(url).spawn();
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn json_response(status: StatusCode, body: Value) -> Response {
    let mut res = Response::new(Body::from(body.to_string()));
    *res.status_mut() = status;
    let headers = res.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    apply_security_headers(headers, false);
    res
}

fn html_response(body: &'static str) -> Response {
    let mut res = Response::new(Body::from(body));
    *res.status_mut() = StatusCode::OK;
    let headers = res.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    apply_security_headers(headers, true);
    res
}

fn apply_security_headers(headers: &mut HeaderMap, is_html: bool) {
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if is_html {
        headers.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(
                "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
            ),
        );
    }
}

fn validate_loopback_request(
    headers: &HeaderMap,
    state: &UiState,
    require_auth: bool,
) -> Result<(), Response> {
    let allowed_ip = format!("{LOOPBACK_IP}:{}", state.bound_port);
    let allowed_lh = format!("localhost:{}", state.bound_port);

    if let Some(host_val) = headers.get(header::HOST) {
        let host = host_val.to_str().unwrap_or("").trim().to_ascii_lowercase();
        if host != allowed_ip && host != allowed_lh {
            return Err(json_response(
                StatusCode::FORBIDDEN,
                json!({"error": "HOST_REJECTED", "message": "Only local loopback Host headers are permitted."}),
            ));
        }
    } else {
        return Err(json_response(
            StatusCode::BAD_REQUEST,
            json!({"error": "HOST_REQUIRED", "message": "Host header is required."}),
        ));
    }

    if let Some(origin_val) = headers.get(header::ORIGIN) {
        let origin = origin_val.to_str().unwrap_or("").trim().to_ascii_lowercase();
        let allowed_origin_ip = format!("{LOOPBACK_SCHEME}://{allowed_ip}");
        let allowed_origin_lh = format!("{LOOPBACK_SCHEME}://{allowed_lh}");
        if origin != allowed_origin_ip && origin != allowed_origin_lh {
            return Err(json_response(
                StatusCode::FORBIDDEN,
                json!({"error": "ORIGIN_REJECTED", "message": "Cross-origin requests are refused."}),
            ));
        }
    }

    if let Some(site_val) = headers.get("sec-fetch-site") {
        let site = site_val.to_str().unwrap_or("").trim().to_ascii_lowercase();
        if !matches!(site.as_str(), "same-origin" | "none") {
            return Err(json_response(
                StatusCode::FORBIDDEN,
                json!({"error": "FETCH_SITE_REJECTED", "message": "Cross-site fetch rejected."}),
            ));
        }
    }

    if require_auth {
        let provided = headers
            .get("x-agent-bridge-token")
            .and_then(|v| v.to_str().ok())
            .or_else(|| {
                headers
                    .get(header::AUTHORIZATION)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.strip_prefix("Bearer "))
            });
        let Some(candidate) = provided else {
            return Err(json_response(
                StatusCode::UNAUTHORIZED,
                json!({"error": "TOKEN_REQUIRED", "message": "Local operator session token is required."}),
            ));
        };
        if !constant_time_eq(candidate.as_bytes(), state.token.as_bytes()) {
            return Err(json_response(
                StatusCode::UNAUTHORIZED,
                json!({"error": "TOKEN_INVALID", "message": "Invalid operator session token."}),
            ));
        }
    }

    Ok(())
}

async fn read_json_body<T: for<'de> Deserialize<'de>>(body: Body) -> Result<T, Response> {
    let bytes = axum::body::to_bytes(body, MAX_API_BODY_BYTES)
        .await
        .map_err(|_| {
            json_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                json!({"error": "BODY_TOO_LARGE", "message": "Request payload exceeds limit."}),
            )
        })?;
    serde_json::from_slice(&bytes).map_err(|_| {
        json_response(
            StatusCode::BAD_REQUEST,
            json!({"error": "INVALID_JSON", "message": "Malformed JSON payload."}),
        )
    })
}

async fn handle_index(State(state): State<Arc<UiState>>, headers: HeaderMap) -> Response {
    if let Err(resp) = validate_loopback_request(&headers, &state, false) {
        return resp;
    }
    html_response(UI_HTML)
}

async fn handle_health(State(state): State<Arc<UiState>>, headers: HeaderMap) -> Response {
    if let Err(resp) = validate_loopback_request(&headers, &state, false) {
        return resp;
    }
    json_response(
        StatusCode::OK,
        json!({
            "ok": true,
            "service": "agent-bridge-ui",
            "version": env!("CARGO_PKG_VERSION"),
            "loopback_port": state.bound_port,
        }),
    )
}

async fn handle_shutdown(State(state): State<Arc<UiState>>, headers: HeaderMap) -> Response {
    if let Err(response) = validate_loopback_request(&headers, &state, true) {
        return response;
    }
    let Some(sender) = state.shutdown_sender.as_ref() else {
        return json_response(StatusCode::CONFLICT, json!({
            "error": "WORKSTATION_SHUTDOWN_UNAVAILABLE",
            "message": "This standalone console does not own a workstation shutdown channel.",
        }));
    };
    let response = json_response(StatusCode::ACCEPTED, json!({"status": "shutting_down"}));
    state.effects.close();
    if sender.send(true).is_err() {
        return json_response(StatusCode::SERVICE_UNAVAILABLE, json!({
            "error": "WORKSTATION_SHUTDOWN_UNAVAILABLE",
            "message": "The workstation shutdown channel is unavailable.",
        }));
    }
    response
}

fn profile_response(result: Result<Value, RuntimeError>) -> Response {
    match result {
        Ok(mut snapshot) => {
            snapshot["configured"] = json!(true);
            json_response(StatusCode::OK, snapshot)
        }
        Err(error) => json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error":"PROFILE_UNAVAILABLE", "message":error.to_string()}),
        ),
    }
}

async fn handle_profile(State(state): State<Arc<UiState>>, headers: HeaderMap) -> Response {
    if let Err(response) = validate_loopback_request(&headers, &state, true) {
        return response;
    }
    let Some(profile) = state.profile.clone() else {
        return json_response(StatusCode::OK, json!({
            "configured": false,
            "active_profile": null,
            "max_profile": null,
            "available_profiles": [],
            "message": "This standalone console is not attached to a live workstation. Start the workstation with --ui-port to control its session profile.",
        }));
    };
    let result = state.blocking(move || profile.snapshot()).await
        .unwrap_or_else(|_| Err("Profile status task failed".into()));
    profile_response(result)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetProfileBody {
    profile: String,
}

async fn handle_set_profile(
    State(state): State<Arc<UiState>>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if let Err(response) = validate_loopback_request(&headers, &state, true) {
        return response;
    }
    let request: SetProfileBody = match read_json_body(body).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    let requested = match request.profile.parse::<DesktopProfile>() {
        Ok(profile) => profile,
        Err(_) => return json_response(StatusCode::BAD_REQUEST, json!({
            "error": "INVALID_PROFILE",
            "message": "Expected read-only, workspace-write, full-control, or fully-unlocked.",
        })),
    };
    let Some(profile) = state.profile.clone() else {
        return json_response(StatusCode::CONFLICT, json!({
            "error":"LIVE_PROFILE_UNAVAILABLE",
            "message":"This standalone console has no live workstation profile to change.",
        }));
    };
    if !profile.allows(requested) {
        return json_response(StatusCode::FORBIDDEN, json!({
            "error":"PROFILE_ABOVE_STARTUP_LIMIT",
            "message":"This profile exceeds the authorization selected when the workstation started.",
            "max_profile":profile.startup_profile(),
        }));
    }
    let result = state.blocking(move || profile.set(requested)).await
        .unwrap_or_else(|_| Err("Profile change task failed".into()));
    profile_response(result)
}

async fn handle_overview(State(state): State<Arc<UiState>>, headers: HeaderMap) -> Response {
    if let Err(resp) = validate_loopback_request(&headers, &state, true) {
        return resp;
    }
    let cfg = state.config.clone();
    let started_at_unix = state.started_at_unix;
    let bound_port = state.bound_port;
    let live_database = state.live_database.clone();
    let oauth_owner = state.oauth_owner.clone();

    let payload =
        state.blocking(move || build_overview(&cfg, live_database.as_ref(), bound_port, started_at_unix, &oauth_owner))
            .await
            .unwrap_or_else(|_| json!({"error": "INTERNAL_ERROR"}));
    json_response(StatusCode::OK, payload)
}

/// Read the same qualified connection used by Task Rooms. No new SQLite open,
/// immutable inspection, recovery or checkpoint is permitted in this branch.
fn live_operator_snapshot(database: &SharedCoreDatabase, limit: i64) -> Result<Value, String> {
    let database = database.lock().map_err(|_| "Live Core database lock unavailable".to_owned())?;
    let mut snapshot = agent_bridge_missions::operator::inspect_operator_snapshot(
        database.connection(), limit,
    ).map_err(|error| error.message)?;
    snapshot["configured"] = json!(true);
    snapshot["path"] = json!(database.path().display().to_string());
    Ok(snapshot)
}

fn database_overview(cfg: &UiConfig, live_database: Option<&SharedCoreDatabase>) -> Value {
    if let Some(database) = live_database {
        return match live_operator_snapshot(database, 1) {
            Ok(snapshot) => json!({
                "configured": true,
                "path": snapshot["path"],
                "exists": true,
                "schema_version": snapshot["schema_version"],
                "pending_migrations": 0,
                "counts": {
                    "missions": snapshot["mission_counts"],
                    "task_rooms": snapshot["total_task_rooms"],
                },
            }),
            Err(error) => json!({
                "configured": true,
                "path": cfg.database.as_ref().map(|path| path.display().to_string()),
                "error": error,
            }),
        };
    }
    match &cfg.database {
        None => json!({"configured": false}),
        Some(path) => match inspect_existing(path) {
            Ok(status) => {
                let mut counts = Value::Null;
                if status.pending_migrations == 0 {
                    if let Ok(db) = CoreDatabase::open_existing(path) {
                        if let Ok(snap) =
                            agent_bridge_missions::operator::inspect_operator_snapshot(
                                db.connection(),
                                1,
                            )
                        {
                            counts = json!({
                                "missions": snap["mission_counts"],
                                "task_rooms": snap["total_task_rooms"],
                            });
                        }
                    }
                }
                json!({
                    "configured": true,
                    "path": path.display().to_string(),
                    "exists": true,
                    "schema_version": status.version,
                    "pending_migrations": status.pending_migrations,
                    "counts": counts,
                })
            }
            Err(err) => json!({
                "configured": true,
                "path": path.display().to_string(),
                "exists": path.exists(),
                "error": err.to_string(),
            }),
        },
    }
}

fn build_overview(
    cfg: &UiConfig,
    live_database: Option<&SharedCoreDatabase>,
    bound_port: u16,
    started_at_unix: u64,
    oauth_owner: &crate::extensions::UiOAuthOwner,
) -> Value {
    let db_info = database_overview(cfg, live_database);

    let oauth_info = match open_oauth_owner(cfg) {
        None => json!({"configured": false}),
        Some(Ok(owner)) => match owner.pending_requests() {
            Ok(list) => json!({
                "configured": true,
                "state_dir": cfg.oauth_state.as_ref().map(|p| p.display().to_string()),
                "public_origin": cfg.oauth_origin,
                "audience": cfg.oauth_audience.map(|a| format!("{a:?}")),
                "pending_count": list.len(),
            }),
            Err(err) => json!({
                "configured": true,
                "state_dir": cfg.oauth_state.as_ref().map(|p| p.display().to_string()),
                "error": err.to_string(),
            }),
        },
        Some(Err(err)) => json!({
            "configured": true,
            "state_dir": cfg.oauth_state.as_ref().map(|p| p.display().to_string()),
            "error": err,
        }),
    };

    let ext_info = match &cfg.settings_dir {
        None => json!({"configured": false}),
        Some(dir) => match crate::extensions::ui_overview(oauth_owner, dir) {
            Ok(overview) => json!({
                "configured": true,
                "settings_dir": dir.display().to_string(),
                "pending_count": overview["pending_count"],
                "total_requests": overview["total_requests"],
                "server_count": overview["servers"].as_array().map(|a| a.len()).unwrap_or(0),
                "approved_tool_count": overview["approved_tools"].as_array().map(|a| a.len()).unwrap_or(0),
            }),
            Err(err) => json!({
                "configured": true,
                "settings_dir": dir.display().to_string(),
                "error": err.to_string(),
            }),
        },
    };

    let skills_count = cfg
        .settings_dir
        .as_ref()
        .and_then(|dir| list_skills_summary(dir, cfg.project.as_deref()).ok())
        .and_then(|v| v.get("skills").and_then(Value::as_array).map(|a| a.len()));

    let db_placeholder = cfg
        .database
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "<missions.sqlite>".to_owned());
    let project_placeholder = cfg
        .project
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "<project-directory>".to_owned());
    let settings_placeholder = cfg
        .settings_dir
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "<private-settings-dir>".to_owned());

    json!({
        "version": env!("CARGO_PKG_VERSION"),
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "listen": format!("{LOOPBACK_IP}:{bound_port}"),
        "started_at_unix": started_at_unix,
        "database": db_info,
        "oauth": oauth_info,
        "extensions": ext_info,
        "skills": {
            "configured": cfg.settings_dir.is_some(),
            "installed_count": skills_count,
        },
        "project": {
            "configured": cfg.project.is_some(),
            "path": cfg.project.as_ref().map(|p| p.display().to_string()),
        },
        "quickstart_commands": {
            "stdio_read_only": format!(
                "agent-bridge stdio \"{db_placeholder}\" --workspace \"{project_placeholder}\" --settings \"{settings_placeholder}\""
            ),
            "stdio_workspace_write": format!(
                "agent-bridge stdio \"{db_placeholder}\" --write-workspace \"{project_placeholder}\" --settings \"{settings_placeholder}\""
            ),
            "http_missions": format!(
                "agent-bridge serve \"{db_placeholder}\" --port 18855"
            ),
            "db_init": format!("agent-bridge db init \"{db_placeholder}\""),
            "settings_init": format!("agent-bridge settings init \"{settings_placeholder}\""),
        },
    })
}

async fn handle_missions(State(state): State<Arc<UiState>>, headers: HeaderMap) -> Response {
    if let Err(resp) = validate_loopback_request(&headers, &state, true) {
        return resp;
    }
    let db_path = state.config.database.clone();
    let live_database = state.live_database.clone();
    let result = state.blocking(move || {
        if let Some(database) = live_database {
            return live_operator_snapshot(&database, 100);
        }
        match db_path {
            None => Ok(json!({
                "configured": false,
                "message": "Start agent-bridge ui with --database <missions.sqlite> to inspect durable missions and Task Rooms."
            })),
            Some(path) => {
                let status = inspect_existing(&path).map_err(|e| e.to_string())?;
                if status.pending_migrations > 0 {
                    return Ok(json!({
                        "configured": true,
                        "path": path.display().to_string(),
                        "needs_migration": true,
                        "schema_version": status.version,
                        "pending_migrations": status.pending_migrations,
                    }));
                }
                let db = CoreDatabase::open_existing(&path).map_err(|e| e.to_string())?;
                let mut snap =
                    agent_bridge_missions::operator::inspect_operator_snapshot(db.connection(), 100)
                        .map_err(|e| e.message)?;
                snap["configured"] = json!(true);
                snap["path"] = json!(path.display().to_string());
                Ok(snap)
            }
        }
    })
    .await
    .unwrap_or_else(|_| Err("Background task failed".to_owned()));

    match result {
        Ok(val) => json_response(StatusCode::OK, val),
        Err(msg) => json_response(
            StatusCode::BAD_REQUEST,
            json!({"error": "DATABASE_UNAVAILABLE", "message": msg}),
        ),
    }
}

fn open_oauth_owner(cfg: &UiConfig) -> Option<Result<LocalOwner, String>> {
    let state_dir = cfg.oauth_state.clone()?;
    let public_origin = cfg.oauth_origin.clone()?;
    let audience = cfg.oauth_audience?;
    Some(
        LocalOwner::open(OAuthConfig {
            state_dir,
            public_origin,
            audience,
        })
        .map_err(|e| e.to_string()),
    )
}

async fn handle_oauth_list(State(state): State<Arc<UiState>>, headers: HeaderMap) -> Response {
    if let Err(resp) = validate_loopback_request(&headers, &state, true) {
        return resp;
    }
    let cfg = state.config.clone();
    let result = state.blocking(move || match open_oauth_owner(&cfg) {
        None => Ok(json!({
            "configured": false,
            "message": "Start agent-bridge ui with --oauth-state <dir> --oauth-origin <https-origin> --oauth-audience <missions|workstation> to manage inbound OAuth 2.1 approvals."
        })),
        Some(Err(err)) => Err(err),
        Some(Ok(owner)) => {
            let pending = owner.pending_requests().map_err(|e| e.to_string())?;
            let list: Vec<Value> = pending
                .iter()
                .map(|req| {
                    json!({
                        "id": req.id,
                        "client_id": req.client_id,
                        "provider": if req.client_id.starts_with("chatgpt_") { "chatgpt" } else { "gemini" },
                        "redirect_uri": req.redirect_uri,
                        "resource": req.resource,
                        "scope": req.scope,
                        "expires_epoch_ms": req.expires_epoch_ms,
                        "audience": format!("{:?}", req.audience),
                        "capability": req.capability,
                    })
                })
                .collect();
            Ok(json!({
                "configured": true,
                "public_origin": cfg.oauth_origin,
                "audience": cfg.oauth_audience.map(|a| format!("{a:?}")),
                "count": list.len(),
                "pending": list,
                "capability_selection": cfg.capability_selection,
            }))
        }
    })
    .await
    .unwrap_or_else(|_| Err("Background task failed".to_owned()));

    match result {
        Ok(val) => json_response(StatusCode::OK, val),
        Err(msg) => json_response(
            StatusCode::BAD_REQUEST,
            json!({"error": "OAUTH_UNAVAILABLE", "message": msg}),
        ),
    }
}

#[derive(Deserialize)]
struct EnrollBody {
    confirm: String,
}

async fn handle_oauth_enroll(
    State(state): State<Arc<UiState>>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if let Err(resp) = validate_loopback_request(&headers, &state, true) {
        return resp;
    }
    let req: EnrollBody = match read_json_body(body).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    if req.confirm != "APPROVE" {
        return json_response(
            StatusCode::FORBIDDEN,
            json!({"error": "CONFIRMATION_REQUIRED", "message": "Explicit confirm='APPROVE' is required."}),
        );
    }
    let cfg = state.config.clone();
    let result = state.blocking(move || match open_oauth_owner(&cfg) {
        None => Err("OAuth owner state is not configured on this UI instance.".to_owned()),
        Some(Err(err)) => Err(err),
        Some(Ok(owner)) => {
            let expires = owner.enable_enrollment(|| true).map_err(|e| e.to_string())?;
            Ok(json!({
                "local_oauth_enrollment": "enabled",
                "expires_epoch_ms": expires,
                "duration_max_seconds": 600,
                "audience": cfg.oauth_audience.map(|a| format!("{a:?}")),
            }))
        }
    })
    .await
    .unwrap_or_else(|_| Err("Background task failed".to_owned()));

    match result {
        Ok(val) => json_response(StatusCode::OK, val),
        Err(msg) => json_response(
            StatusCode::BAD_REQUEST,
            json!({"error": "OAUTH_ENROLL_FAILED", "message": msg}),
        ),
    }
}

#[derive(Deserialize)]
struct ApproveOAuthBody {
    request_id: String,
    redirect_uri: String,
    confirm: String,
    #[serde(default)]
    capability: CapabilityIdentity,
}

async fn handle_oauth_approve(
    State(state): State<Arc<UiState>>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if let Err(resp) = validate_loopback_request(&headers, &state, true) {
        return resp;
    }
    let req: ApproveOAuthBody = match read_json_body(body).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    if req.confirm != "APPROVE" {
        return json_response(
            StatusCode::FORBIDDEN,
            json!({"error": "CONFIRMATION_REQUIRED", "message": "Explicit confirm='APPROVE' is required."}),
        );
    }
    let cfg = state.config.clone();
    let result = state.blocking(move || match open_oauth_owner(&cfg) {
        None => Err("OAuth owner state is not configured on this UI instance.".to_owned()),
        Some(Err(err)) => Err(err),
        Some(Ok(owner)) => {
            let expected = req.redirect_uri.trim().to_owned();
            let mut callback_mismatch = false;
            let mut capability_mismatch = false;
            let res = owner.approve_request(&req.request_id, |pending| {
                if pending.redirect_uri != expected {
                    callback_mismatch = true;
                    return false;
                }
                if pending.capability != req.capability {
                    capability_mismatch = true;
                    return false;
                }
                true
            });
            if callback_mismatch {
                return Err("LOCAL_OAUTH_CALLBACK_MISMATCH: exact callback URI from client UI does not match pending request.".to_owned());
            }
            if capability_mismatch {
                return Err("LOCAL_OAUTH_CAPABILITY_MISMATCH: refresh and review the exact contract before approving.".to_owned());
            }
            res.map_err(|e| e.to_string())?;
            Ok(json!({
                "local_oauth_request": "approved",
                "id": req.request_id,
                "permission": "one_exact_request_only",
            }))
        }
    })
    .await
    .unwrap_or_else(|_| Err("Background task failed".to_owned()));

    match result {
        Ok(val) => json_response(StatusCode::OK, val),
        Err(msg) => json_response(
            StatusCode::BAD_REQUEST,
            json!({"error": "OAUTH_APPROVE_FAILED", "message": msg}),
        ),
    }
}

async fn handle_extensions_list(State(state): State<Arc<UiState>>, headers: HeaderMap) -> Response {
    if let Err(resp) = validate_loopback_request(&headers, &state, true) {
        return resp;
    }
    let settings = state.config.settings_dir.clone();
    let oauth_owner = state.oauth_owner.clone();
    let result = state.blocking(move || match settings {
        None => Ok(json!({
            "configured": false,
            "message": "Start agent-bridge ui with --settings-dir <private-settings-dir> to manage MCP extensions and proposals."
        })),
        Some(dir) => {
            let mut data = crate::extensions::ui_overview(&oauth_owner, &dir).map_err(|e| e.to_string())?;
            data["configured"] = json!(true);
            data["settings_dir"] = json!(dir.display().to_string());
            Ok(data)
        }
    })
    .await
    .unwrap_or_else(|_| Err("Background task failed".to_owned()));

    match result {
        Ok(val) => json_response(StatusCode::OK, val),
        Err(msg) => json_response(
            StatusCode::BAD_REQUEST,
            json!({"error": "EXTENSIONS_UNAVAILABLE", "message": msg}),
        ),
    }
}

#[derive(Deserialize)]
struct DecideExtensionBody {
    request_id: String,
    approve: bool,
    confirm: String,
}

async fn handle_extensions_decide(
    State(state): State<Arc<UiState>>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if let Err(resp) = validate_loopback_request(&headers, &state, true) {
        return resp;
    }
    let req: DecideExtensionBody = match read_json_body(body).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let expected_verb = if req.approve { "APPROVE" } else { "REFUSE" };
    if req.confirm != expected_verb {
        return json_response(
            StatusCode::FORBIDDEN,
            json!({"error": "CONFIRMATION_REQUIRED", "message": format!("Explicit confirm='{expected_verb}' is required.")}),
        );
    }
    let settings = state.config.settings_dir.clone();
    let oauth_owner = state.oauth_owner.clone();
    let result = state.blocking(move || {
        let Some(dir) = settings else {
            return Err((StatusCode::BAD_REQUEST, "Settings directory is not configured on this UI instance.".to_owned()));
        };
        crate::extensions::decide_from_operator_ui(&oauth_owner, &dir, &req.request_id, req.approve)
            .map_err(|e| {
                let status = if e.downcast_ref::<std::io::Error>()
                    .is_some_and(|err| err.kind() == std::io::ErrorKind::WouldBlock)
                {
                    StatusCode::CONFLICT
                } else {
                    StatusCode::BAD_REQUEST
                };
                (status, e.to_string())
            })
    })
    .await
    .unwrap_or_else(|_| Err((StatusCode::INTERNAL_SERVER_ERROR, "Background task failed".to_owned())));

    match result {
        Ok(val) => {
            let active = val.get("oauth_operation")
                .and_then(|op| op.get("status"))
                .and_then(Value::as_str)
                .is_some_and(|status| matches!(status, "starting" | "awaiting_authorization"));
            json_response(if active { StatusCode::ACCEPTED } else { StatusCode::OK }, val)
        }
        Err((status, msg)) => json_response(
            status,
            json!({"error": "EXTENSION_DECISION_FAILED", "message": msg}),
        ),
    }
}

fn list_skills_summary(settings_dir: &Path, project: Option<&Path>) -> Result<Value, String> {
    let store_dir = agent_bridge_lifecycle::operator_skill_directory(settings_dir)
        .map_err(|e| e.to_string())?;
    let ws = project.unwrap_or(settings_dir);
    let files = DesktopFiles::open(DesktopConfig::new(ws)).map_err(|e| e.to_string())?;
    let manager = files
        .documentary_skills(&store_dir)
        .map_err(|e| e.to_string())?;
    manager
        .dispatch(&json!({"action": "list"}))
        .map_err(|e| e.to_string())
}

async fn handle_skills_list(State(state): State<Arc<UiState>>, headers: HeaderMap) -> Response {
    if let Err(resp) = validate_loopback_request(&headers, &state, true) {
        return resp;
    }
    let settings = state.config.settings_dir.clone();
    let project = state.config.project.clone();
    let result = state.blocking(move || match settings {
        None => Ok(json!({
            "configured": false,
            "message": "Start agent-bridge ui with --settings-dir <private-settings-dir> to inspect installed documentary skills."
        })),
        Some(dir) => {
            let mut val = list_skills_summary(&dir, project.as_deref())?;
            val["configured"] = json!(true);
            val["settings_dir"] = json!(dir.display().to_string());
            Ok(val)
        }
    })
    .await
    .unwrap_or_else(|_| Err("Background task failed".to_owned()));

    match result {
        Ok(val) => json_response(StatusCode::OK, val),
        Err(msg) => json_response(
            StatusCode::BAD_REQUEST,
            json!({"error": "SKILLS_UNAVAILABLE", "message": msg}),
        ),
    }
}

#[derive(Deserialize)]
struct SkillActionBody {
    action: String,
    name: String,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    resource_path: Option<String>,
}

async fn handle_skills_action(
    State(state): State<Arc<UiState>>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if let Err(resp) = validate_loopback_request(&headers, &state, true) {
        return resp;
    }
    let req: SkillActionBody = match read_json_body(body).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    if !matches!(
        req.action.as_str(),
        "get" | "read" | "activate" | "rollback"
    ) {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({"error": "UNSUPPORTED_SKILL_ACTION", "message": "Allowed UI skill actions: get, read, activate, rollback."}),
        );
    }
    let settings = state.config.settings_dir.clone();
    let project = state.config.project.clone();
    let result = state.blocking(move || {
        let Some(dir) = settings else {
            return Err("Settings directory is not configured on this UI instance.".to_owned());
        };
        let store_dir = agent_bridge_lifecycle::operator_skill_directory(&dir)
            .map_err(|e| e.to_string())?;
        let ws = project.as_deref().unwrap_or(dir.as_path());
        let files =
            DesktopFiles::open(DesktopConfig::new(ws)).map_err(|e| e.to_string())?;
        let manager = files
            .documentary_skills(&store_dir)
            .map_err(|e| e.to_string())?;
        let mut args = serde_json::Map::new();
        args.insert("action".to_owned(), json!(req.action));
        args.insert("name".to_owned(), json!(req.name));
        if let Some(v) = req.version {
            args.insert("version".to_owned(), json!(v));
        }
        if let Some(rp) = req.resource_path {
            args.insert("resource_path".to_owned(), json!(rp));
        }
        manager
            .dispatch(&Value::Object(args))
            .map_err(|e| e.to_string())
    })
    .await
    .unwrap_or_else(|_| Err("Background task failed".to_owned()));

    match result {
        Ok(val) => json_response(StatusCode::OK, val),
        Err(msg) => json_response(
            StatusCode::BAD_REQUEST,
            json!({"error": "SKILL_ACTION_FAILED", "message": msg}),
        ),
    }
}

async fn handle_diagnostics(State(state): State<Arc<UiState>>, headers: HeaderMap) -> Response {
    if let Err(resp) = validate_loopback_request(&headers, &state, true) {
        return resp;
    }
    let cfg = state.config.clone();
    let result = state.blocking(move || {
        let workspace_report = cfg.project.as_ref().map(|p| {
            match agent_bridge_lifecycle::workspace_access::inspect_project_access(p) {
                Ok(access) => json!({"ok": true, "access": access}),
                Err(err) => json!({"ok": false, "error": err.to_string()}),
            }
        });

        let mut mcp_profiles = Vec::new();
        let mut web_launch_profiles = Value::Null;
        if let Some(settings) = &cfg.settings_dir {
            let mcp_root = settings.join("mcp-browser-profiles");
            if let Ok(entries) = std::fs::read_dir(&mcp_root) {
                for entry in entries.flatten() {
                    if let Ok(meta) = std::fs::symlink_metadata(entry.path()) {
                        if meta.is_dir() && !meta.file_type().is_symlink() {
                            if let Some(name) = entry.file_name().to_str() {
                                mcp_profiles.push(name.to_owned());
                            }
                        }
                    }
                }
            }
            mcp_profiles.sort();

            if let Ok((chatgpt, gemini)) = agent_bridge_lifecycle::browser_profiles(settings) {
                web_launch_profiles = json!({
                    "chatgpt": { "path": chatgpt.display().to_string(), "exists": chatgpt.is_dir() },
                    "gemini": { "path": gemini.display().to_string(), "exists": gemini.is_dir() },
                });
            }
        }

        let oauth_keystore = if cfg!(windows) {
            "Windows DPAPI (CryptProtectData / CurrentUser)"
        } else if cfg!(target_os = "macos") {
            "macOS Keychain (security generic-password)"
        } else if cfg!(unix) {
            "Linux Secret Service (secret-tool)"
        } else {
            "Unavailable"
        };

        json!({
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "version": env!("CARGO_PKG_VERSION"),
            "capabilities": {
                "missions_and_task_rooms": true,
                "workspace_files_and_artifacts": true,
                "documentary_skills": true,
                "inbound_oauth_2_1": true,
                "outbound_oauth_keystore": oauth_keystore,
                "native_chrome_cdp_pipe": cfg!(windows),
                "native_window_inspection": cfg!(windows),
                "confined_process_sessions": cfg!(windows),
                "operator_loopback_ui": true,
            },
            "security_guards": {
                "loopback_only_bind": true,
                "per_session_256bit_token": true,
                "strict_host_and_origin_check": true,
                "csp_zero_external_assets": true,
                "secret_handles_redacted": true,
            },
            "browser_profiles": {
                "mcp_persistent_profiles": mcp_profiles,
                "web_launch_profiles": web_launch_profiles,
            },
            "workspace_inspection": workspace_report,
            "capability_selection": cfg.capability_selection,
            "mcp_request_audit": cfg.request_audit.as_ref().map(|audit| audit.snapshot()),
            "provider_cleanup": crate::provider_owner::ProviderOwner::rollback_status().map(|status|json!({
                "pending":status.pending,"omitted":status.omitted,
                "failures":status.failures.iter().map(|failure|json!({
                    "owner_id":failure.owner_id,"code":failure.code,"attempts":failure.attempts
                })).collect::<Vec<_>>()
            })).unwrap_or_else(|_|json!({"unavailable":true})),
        })
    })
    .await
    .unwrap_or_else(|_| json!({"error": "INTERNAL_ERROR"}));

    json_response(StatusCode::OK, result)
}

#[cfg(test)]
mod shutdown_tests {
    use super::wait_for_shutdown;
    use std::time::Duration;
    use tokio::sync::watch;

    #[tokio::test]
    async fn shared_shutdown_handles_initial_signal_later_signal_and_closed_channel() {
        let (_sender, receiver) = watch::channel(true);
        tokio::time::timeout(Duration::from_secs(1), wait_for_shutdown(receiver))
            .await.expect("an already signaled shutdown must not wait for a new change");

        let (sender, receiver) = watch::channel(false);
        let second_receiver = receiver.clone();
        let first = tokio::spawn(wait_for_shutdown(receiver));
        let second = tokio::spawn(wait_for_shutdown(second_receiver));
        sender.send(true).unwrap();
        for waiter in [first, second] {
            tokio::time::timeout(Duration::from_secs(1), waiter).await
                .expect("both listeners must receive the shared shutdown").unwrap();
        }

        let (sender, receiver) = watch::channel(false);
        drop(sender);
        tokio::time::timeout(Duration::from_secs(1), wait_for_shutdown(receiver))
            .await.expect("a closed signal channel must not leave a listener running");
    }
}
/// Rust-only adapter for native IPC. It reuses the HTTP handlers' business
/// validations without binding a socket, publishing a URL or exporting auth.
#[derive(Clone)]
pub(crate) struct NativeOperator { state: Arc<UiState> }

impl NativeOperator {
    #[cfg(test)]
    pub(crate) fn new(
        config: UiConfig,
        profile: ProfileControl,
        live_database: Option<SharedCoreDatabase>,
    ) -> Self {
        Self::with_admission(config,profile,live_database,OperationAdmission::default())
    }

    pub(crate) fn with_admission(
        mut config:UiConfig,profile:ProfileControl,live_database:Option<SharedCoreDatabase>,
        effects:OperationAdmission,
    )->Self {
        config.port = 0;
        config.open_browser = false;
        let state = Arc::new(UiState {
            config,
            token: agent_bridge_missions::operator::random_token_hex(32),
            bound_port: 0,
            started_at_unix: SystemTime::now().duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_secs()).unwrap_or(0),
            profile: Some(profile), live_database, shutdown_sender: None,
            oauth_owner: crate::extensions::UiOAuthOwner::default(),
            effects,
        });
        Self { state }
    }

    pub(crate) fn oauth_owner(&self) -> crate::extensions::UiOAuthOwner {
        self.state.oauth_owner.clone()
    }

    fn headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("127.0.0.1:0"));
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
        // Generated hexadecimal token has a fixed safe HTTP-header alphabet.
        headers.insert("X-Agent-Bridge-Token", HeaderValue::from_str(&self.state.token)
            .expect("generated operator token is a header value"));
        headers
    }

    pub(crate) async fn get(
        &self, operation: crate::backend::OperatorRead,
    ) -> Result<crate::backend::OperatorReply, RuntimeError> {
        use crate::backend::OperatorRead;
        let state = State(Arc::clone(&self.state));
        let headers = self.headers();
        let response = match operation {
            OperatorRead::Overview => handle_overview(state, headers).await,
            OperatorRead::Profile => handle_profile(state, headers).await,
            OperatorRead::Missions => handle_missions(state, headers).await,
            OperatorRead::OAuth => handle_oauth_list(state, headers).await,
            OperatorRead::Extensions => handle_extensions_list(state, headers).await,
            OperatorRead::Skills => handle_skills_list(state, headers).await,
            OperatorRead::Diagnostics => handle_diagnostics(state, headers).await,
        };
        let mut reply = self.reply(response).await?;
        if matches!(operation, OperatorRead::Overview) {
            reply.body["listen"] = Value::Null;
            reply.body["operator_transport"] = json!("native-ipc");
        }
        Ok(reply)
    }

    pub(crate) async fn post(
        &self, operation: crate::backend::OperatorWrite, payload: Value,
    ) -> Result<crate::backend::OperatorReply, RuntimeError> {
        use crate::backend::OperatorWrite;
        let mut bounded = BoundedNativeRequest(Vec::new());
        if serde_json::to_writer(&mut bounded, &payload).is_err() {
            return Ok(crate::backend::OperatorReply {
                status: 413, body: json!({"error":"BODY_TOO_LARGE",
                    "message":"Request payload exceeds limit."}),
            });
        }
        let state = State(Arc::clone(&self.state));
        let headers = self.headers();
        let body = Body::from(bounded.0);
        let response = match operation {
            OperatorWrite::SetProfile => handle_set_profile(state, headers, body).await,
            OperatorWrite::OAuthEnroll => handle_oauth_enroll(state, headers, body).await,
            OperatorWrite::OAuthApprove => handle_oauth_approve(state, headers, body).await,
            OperatorWrite::ExtensionsDecide => handle_extensions_decide(state, headers, body).await,
            OperatorWrite::SkillsAction => handle_skills_action(state, headers, body).await,
        };
        self.reply(response).await
    }

    async fn reply(&self, response: Response) -> Result<crate::backend::OperatorReply, RuntimeError> {
        let status = response.status().as_u16();
        let bytes = axum::body::to_bytes(response.into_body(), 2 * 1024 * 1024).await
            .map_err(|_| "Native operator response exceeds limit")?;
        let mut body: Value = serde_json::from_slice(&bytes)
            .map_err(|_| "Native operator returned invalid JSON")?;
        redact_native_token(&mut body, &self.state.token);
        Ok(crate::backend::OperatorReply { status, body })
    }
}

struct BoundedNativeRequest(Vec<u8>);
impl std::io::Write for BoundedNativeRequest {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > MAX_API_BODY_BYTES.saturating_sub(self.0.len()) {
            return Err(std::io::Error::other("Native operator request exceeds limit"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}

fn redact_native_token(value: &mut Value, token: &str) {
    match value {
        Value::String(text) => *text = text.replace(token, "[redacted]"),
        Value::Array(values) => values.iter_mut().for_each(|value| redact_native_token(value, token)),
        Value::Object(fields) => {
            let original = std::mem::take(fields);
            for (key, mut value) in original {
                redact_native_token(&mut value, token);
                fields.insert(key.replace(token, "[redacted]"), value);
            }
        }
        _ => {}
    }
}


#[cfg(test)]
mod native_operator_tests {
    use super::*;

    fn operator() -> NativeOperator {
        NativeOperator::new(UiConfig {
            port: 0, database: None, settings_dir: None, oauth_state: None,
            oauth_origin: None, oauth_audience: None, project: None, open_browser: false,
            capability_selection: None,
            request_audit: Some(Arc::new(crate::request_audit::RequestAudit::new().unwrap())),
        }, ProfileControl::new(DesktopProfile::ReadOnly), None)
    }

    #[tokio::test]
    async fn request_audit_requires_local_operator_diagnostics_authentication() {
        let operator = operator();
        let mut headers = operator.headers();
        headers.remove("X-Agent-Bridge-Token");
        let state = State(Arc::clone(&operator.state));
        let unauthenticated = operator.reply(handle_diagnostics(state, headers).await).await.unwrap();
        assert_eq!(unauthenticated.status, 401);
        assert!(unauthenticated.body.get("mcp_request_audit").is_none());

        let reply = operator.get(crate::backend::OperatorRead::Diagnostics).await.unwrap();
        assert_eq!(reply.status, 200);
        assert_eq!(reply.body["mcp_request_audit"]["boot_id"].as_str().unwrap().len(), 32);
        assert_eq!(reply.body["mcp_request_audit"]["evicted"], 0);
        assert_eq!(reply.body["mcp_request_audit"]["in_flight"], 0);
        assert_eq!(reply.body["mcp_request_audit"]["records"], json!([]));
    }

    #[tokio::test]
    async fn native_reply_redacts_private_auth_in_nested_values_and_object_keys() {
        let operator = operator();
        let token = operator.state.token.clone();
        let mut fields = serde_json::Map::new();
        fields.insert(format!("key-{token}"), json!([{"nested":format!("Bearer {token}")}]));
        let reply = operator.reply(json_response(StatusCode::OK, Value::Object(fields)))
            .await.unwrap();
        let serialized = serde_json::to_string(&reply).unwrap();
        assert!(!serialized.contains(&token));
        assert!(serialized.contains("[redacted]"));
    }

    #[tokio::test]
    async fn native_reply_rejects_oversize_body_before_returning_it_to_the_host() {
        let operator = operator();
        let response = json_response(StatusCode::OK, json!({"value":"x".repeat(2*1024*1024)}));
        assert!(operator.reply(response).await.is_err());
    }
}

#[cfg(test)]
#[path = "native_capability_tests.rs"]
mod native_capability_tests;
