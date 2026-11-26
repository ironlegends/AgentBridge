use crate::runtime::{self, Router as MissionRouter, RuntimeError, WebWorkstationCapabilities};
use crate::session_profile::ProfileControl;
use crate::operation_admission::OperationAdmission;
use crate::request_audit::{ErrorCode, RequestAudit, RequestDetails, RequestObservation};
use agent_bridge_desktop::DesktopProfile;
use agent_bridge_http::modern::{response_status, ResponseMetadata};
use agent_bridge_oauth_server::{
    Audience, AuthorizedIdentity, CapabilityIdentity, ConnectorClient, HttpAction, HttpRequest,
    OAuthConfig, OAuthServer,
};
use axum::body::{to_bytes, Body};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, Uri};
use axum::response::Response;
use serde_json::{json,Value};
use std::io::{Read, Write};
use std::path::{Path,PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Semaphore;

#[derive(Clone)]
struct ExtensionGuard {
    settings: PathBuf,
    // All effective local server grants and parameter/descriptor pins.
    // This is the authority of each separately authorized OAuth identity.
    authority: serde_json::Value,
}

struct UnifiedRoute {
    identity: CapabilityIdentity,
    router: Arc<MissionRouter>,
    extension_guard: Option<ExtensionGuard>,
    manifest_guard: Arc<dyn Fn() -> Result<(), RuntimeError> + Send + Sync>,
    response_permits: Arc<Semaphore>,
}

// Own the permit with the allocated bytes, including any transport clones.
// A client that has not consumed its response cannot free this budget early.
struct BudgetedResponse {
    text: String,
    _permit: tokio::sync::OwnedSemaphorePermit,
}
impl AsRef<[u8]> for BudgetedResponse {
    fn as_ref(&self)->&[u8] {self.text.as_bytes()}
}
fn response_body(text:String,permit:Option<tokio::sync::OwnedSemaphorePermit>)->Body {
    match permit {
        Some(permit)=>Body::from(axum::body::Bytes::from_owner(BudgetedResponse{text,_permit:permit})),
        None=>Body::from(text),
    }
}

#[derive(Clone)]
struct Gateway {
    oauth: Arc<Mutex<OAuthServer>>,
    router: Arc<MissionRouter>,
    legacy_catalogue_sha256: Arc<str>,
    request_audit: Arc<RequestAudit>,
    unified: Option<Arc<UnifiedRoute>>,
    audience: Audience,
    expected_resource: Option<String>,
    public_host: String,
    loopback_host: String,
    requests: Arc<Semaphore>,
    effects: OperationAdmission,
    extension_guard: Option<ExtensionGuard>,
}

impl Gateway {
    fn observe_identity(&self, audit: &RequestDetails, identity: &AuthorizedIdentity) {
        let digest = match &identity.capability {
            CapabilityIdentity::Legacy => Some(self.legacy_catalogue_sha256.as_ref()),
            CapabilityIdentity::UnifiedV1 { catalogue_sha256, .. } => self.unified.as_ref()
                .filter(|route| route.identity == identity.capability)
                .map(|_| catalogue_sha256.as_str()),
        };
        audit.observe_identity(identity, digest);
    }
}

fn router_catalogue_digest(router: &MissionRouter) -> Result<Arc<str>, RuntimeError> {
    let catalogue: Vec<_> = router.published_tools().into_iter().cloned().collect();
    Ok(crate::capability_manifest::catalogue_digest(&catalogue)?.into())
}

/// Request admission owns the gateway clone until all its resources have
/// been released. Rust drops struct fields in declaration order, so shutdown
/// cannot reacquire this permit before the gateway clone has been destroyed.
struct AdmittedRequest<T> {
    state: T,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

fn reply(status: StatusCode, text: &'static str) -> Response {
    Response::builder().status(status).header("cache-control", "no-store")
        .header("x-content-type-options","nosniff").body(Body::from(text)).expect("fixed HTTP response")
}

fn refuse(audit: &RequestDetails, status: StatusCode, code: &'static str, text: &'static str) -> Response {
    audit.refuse(ErrorCode::Named(code));
    reply(status, text)
}

fn oauth_refusal_code(body: &[u8]) -> &'static str {
    let body = serde_json::from_slice::<Value>(body).ok();
    match body.as_ref().and_then(|value| value.get("error")).and_then(Value::as_str) {
        Some("invalid_token") => "invalid_token",
        Some("request_limit") => "request_limit",
        Some("invalid_request") => "invalid_request",
        Some("origin_refused") => "origin_refused",
        Some("not_found") => "not_found",
        Some("connector_busy") => "connector_busy",
        Some("oauth_state_uncertain") => "oauth_state_uncertain",
        _ => "oauth_refused",
    }
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>, ()> {
    let mut values = headers.get_all(name).iter();
    let first = values.next().map(|v| v.to_str().map_err(|_| ())).transpose()?;
    if values.next().is_some() { return Err(()); }
    Ok(first)
}

fn adapt_chatgpt_file_read_result(frame: &str, routed: &str) -> Option<String> {
    let request: Value = serde_json::from_str(frame).ok()?;
    if request.get("method")?.as_str()? != "tools/call"
        || request.get("params")?.get("name")?.as_str()? != "desktop_read_file"
    {
        return None;
    }

    let mut response: Value = serde_json::from_str(routed).ok()?;
    if response.get("jsonrpc")?.as_str()? != "2.0"
        || response.get("id").is_none()
        || response.get("error").is_some()
    {
        return None;
    }
    let result = response.get_mut("result")?.as_object_mut()?;
    if !matches!(result.get("isError"), None | Some(Value::Bool(false))) {
        return None;
    }

    // Desktop file reads produce a single text block containing the business JSON.
    let [block] = result.get_mut("content")?.as_array_mut()?.as_mut_slice() else {
        return None;
    };
    if block.get("type")?.as_str()? != "text" {
        return None;
    }
    let text = block.get_mut("text")?;
    let mut business = serde_json::from_str::<serde_json::Map<String, Value>>(text.as_str()?).ok()?;
    if business.contains_key("file_content") || !business.get("content")?.is_string() {
        return None;
    }
    let content = business.remove("content")?;
    business.insert("file_content".to_owned(), content);
    *text = Value::String(serde_json::to_string(&business).ok()?);
    serde_json::to_string(&response).ok()
}

async fn handle(State(app): State<Gateway>, request: Request) -> Response {
    let is_mcp = request.uri().path() == "/mcp";
    let observation = RequestObservation::new(is_mcp.then(|| Arc::clone(&app.request_audit)));
    let response = handle_request(app, request, is_mcp, observation.details()).await;
    observation.complete(response.status());
    response
}

async fn handle_request(app: Gateway, request: Request, is_mcp: bool, audit: &RequestDetails) -> Response {
    let Ok(permit) = app.requests.clone().try_acquire_owned() else {
        return refuse(audit, StatusCode::SERVICE_UNAVAILABLE, "request_capacity_busy", "busy");
    };
    let admitted = AdmittedRequest { state: app, _permit: permit };
    let app = &admitted.state;
    let (parts, body) = request.into_parts();
    let target = parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    if parts.uri.authority().is_some() || parts.uri.scheme().is_some() ||
        !matches!(header(&parts.headers,"host"),Ok(Some(h)) if h.eq_ignore_ascii_case(&app.public_host) || h == app.loopback_host) {
        return refuse(audit, StatusCode::FORBIDDEN, "host_refused", "host refused");
    }
    let limit = if target == "/mcp" { 1024 * 1024 } else { 64 * 1024 };
    let bytes = match tokio::time::timeout(Duration::from_secs(10),to_bytes(body,limit)).await {
        Ok(Ok(b)) => b,
        Ok(Err(_)) => return refuse(audit, StatusCode::PAYLOAD_TOO_LARGE,
            "invalid_or_oversized_body", "invalid or oversized body"),
        Err(_) => return refuse(audit, StatusCode::REQUEST_TIMEOUT,
            "body_timeout", "body timed out"),
    };
    let worker_audit = audit.clone();
    tokio::task::spawn_blocking(move || {
        let admitted = admitted;
        let audit = &worker_audit;
        let app = &admitted.state;
        let Ok(_effect)=app.effects.begin() else {
            return refuse(audit, StatusCode::SERVICE_UNAVAILABLE, "workstation_stopping", "workstation is stopping");
        };
        audit.observe_frame(&bytes);
        let (Ok(auth),Ok(origin),Ok(content_type)) = (header(&parts.headers,"authorization"),
            header(&parts.headers,"origin"),header(&parts.headers,"content-type")) else {
            return refuse(audit, StatusCode::BAD_REQUEST, "invalid_http_headers", "invalid HTTP headers");
        };
        let Ok(mut oauth) = app.oauth.lock() else {
            return refuse(audit, StatusCode::SERVICE_UNAVAILABLE, "oauth_unavailable", "OAuth unavailable");
        };
        let target = parts.uri.path_and_query().map(|p|p.as_str()).unwrap_or("/");
        let action = oauth.handle_http(HttpRequest {method:parts.method.as_str(),target,authorization:auth,
            origin,content_type,body:&bytes});
        match action {
            HttpAction::Reply(output) => {
                if is_mcp {
                    let code = oauth_refusal_code(&output.body);
                    // The limiter can reject a valid client before returning McpAuthorized.
                    if output.status == 429 && code == "request_limit" {
                        if let Ok(identity) = oauth.authorize_mcp(auth) {
                            app.observe_identity(audit, &identity);
                        }
                    }
                    audit.refuse(ErrorCode::Named(code));
                }
                let mut response = Response::builder().status(output.status);
                for (name,value) in output.headers {
                    let (Ok(name),Ok(value)) = (HeaderName::try_from(name),HeaderValue::try_from(value)) else {
                        return refuse(audit, StatusCode::INTERNAL_SERVER_ERROR, "invalid_oauth_response", "invalid OAuth response");
                    };
                    response = response.header(name,value);
                }
                response.body(Body::from(output.body)).unwrap_or_else(|_|refuse(
                    audit, StatusCode::INTERNAL_SERVER_ERROR, "invalid_oauth_response", "invalid OAuth response"))
            }
            HttpAction::McpAuthorized(first) => {
                app.observe_identity(audit, &first);
                if parts.method != axum::http::Method::POST {
                    return refuse(audit, StatusCode::METHOD_NOT_ALLOWED, "post_required", "use POST for MCP requests");
                }
                if parts.headers.contains_key("last-event-id") || !content_type.is_some_and(|ct|
                    ct.split(';').next().is_some_and(|s|s.trim().eq_ignore_ascii_case("application/json"))) {
                    return refuse(audit, StatusCode::BAD_REQUEST, "invalid_mcp_content_or_replay", "invalid MCP content or replay request");
                }
                let Ok(frame) = std::str::from_utf8(&bytes) else {
                    return refuse(audit, StatusCode::BAD_REQUEST, "invalid_mcp_payload", "invalid MCP payload");
                };
                if first.audience != app.audience
                    || first.scope != "mcp"
                    || app.expected_resource.as_ref().is_some_and(|wanted| wanted != &first.resource)
                    || !oauth.authorize_mcp(auth).is_ok_and(|current|
                        current == first && current.audience == app.audience
                        && app.expected_resource.as_ref().is_none_or(|wanted| wanted == &current.resource))
                {
                    return refuse(audit, StatusCode::UNAUTHORIZED, "authorization_expired_or_revoked", "authorization expired or revoked");
                }
                // Select the complete immutable view while authorization is
                // still verified. A shared name never borrows another view's
                // schema or handler, and no remote parameter selects this view.
                let unified = if first.capability.is_legacy() { None } else {
                    let Some(selected) = app.unified.as_ref().filter(|selected|
                        app.audience == Audience::Workstation && selected.identity == first.capability)
                    else { return refuse(audit, StatusCode::UNAUTHORIZED, "capability_unavailable", "capability unavailable"); };
                    Some(Arc::clone(selected))
                };
                // Authorization applies to this admitted request. No slow
                // filesystem, browser or UI handler holds the global OAuth lock.
                drop(oauth);
                let (router, extension_guard, response_limit, response_permit) =
                    if let Some(selected) = unified.as_ref() {
                        let Ok(permit) = selected.response_permits.clone().try_acquire_owned()
                        else { return refuse(audit, StatusCode::SERVICE_UNAVAILABLE, "response_capacity_busy", "unified response capacity busy"); };
                        if (selected.manifest_guard)().is_err() {
                            return refuse(audit, StatusCode::FORBIDDEN, "capability_authority_changed", "unified capability authority changed");
                        }
                        (&selected.router, &selected.extension_guard, 48 * 1024 * 1024, Some(permit))
                    } else {
                        (&app.router, &app.extension_guard, 1024 * 1024, None)
                    };
                // The selected view retains its own exact extension authority.
                // Effectful extension calls also compare and execute through
                // the SAME loaded registry, after their live-profile check.
                if let Some(guard)=extension_guard {
                    if app.audience!=Audience::Workstation
                        || !runtime::workstation_extension_authority(&guard.settings)
                            .is_ok_and(|current|current==guard.authority)
                    {
                        return refuse(audit, StatusCode::FORBIDDEN, "extension_authority_changed", "workstation extension authority changed");
                    }
                }
                // Modern routing headers must agree with the authorized body
                // before dispatch. Legacy requests keep their behavior.
                let modern = match agent_bridge_http::modern::preflight(&parts.headers, frame) {
                    agent_bridge_http::modern::Preflight::Legacy => false,
                    agent_bridge_http::modern::Preflight::Modern => true,
                    agent_bridge_http::modern::Preflight::Reject(status, body) => {
                        let code = ResponseMetadata::read(&body).error_code.map(ErrorCode::Rpc)
                            .unwrap_or(ErrorCode::Named("mcp_preflight_refused"));
                        audit.refuse(code);
                        return Response::builder()
                            .status(status).header("content-type","application/json").header("cache-control","no-store")
                            .body(Body::from(body)).expect("fixed MCP refusal");
                    }
                };
                let routed = router.handle_str(frame);
                let routed = if app.audience == Audience::Workstation
                    && first.provider == ConnectorClient::ChatGpt
                {
                    routed.map(|result| {
                        adapt_chatgpt_file_read_result(frame, &result).unwrap_or(result)
                    })
                } else {
                    routed
                };
                match routed {
                    Some(result) if result.len() <= response_limit => {
                        let metadata = ResponseMetadata::read(&result);
                        let status = if modern { response_status(&result) } else { StatusCode::OK };
                        let response = Response::builder().status(status)
                            .header("content-type","application/json").header("cache-control","no-store")
                            .body(response_body(result,response_permit)).expect("fixed MCP response");
                        audit.routed(metadata);
                        response
                    }
                    Some(_) => refuse(audit, StatusCode::INTERNAL_SERVER_ERROR, "response_exceeds_limit", "MCP response exceeds limit"),
                    None => {
                        audit.routed(ResponseMetadata::default());
                        reply(StatusCode::ACCEPTED,"")
                    }
                }
            }
        }
    }).await.unwrap_or_else(|_|refuse(audit, StatusCode::INTERNAL_SERVER_ERROR,
        "request_interrupted", "request interrupted"))
}

pub fn serve(database: &Path, state: &Path, origin: &str, port: u16) -> Result<(),RuntimeError> {
    runtime::check_port(port)?;
    let public_host = origin.parse::<Uri>()?.authority().ok_or("public origin needs an authority")?.as_str().to_owned();
    let event_loop = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build()?;
    event_loop.block_on(async move {
        let listener = agent_bridge_http::bind_loopback(port).await?;
        let oauth = OAuthServer::open(OAuthConfig {state_dir:state.to_owned(),public_origin:origin.to_owned(),audience:Audience::Missions})?;
        let missions = runtime::missions(database)?;
        // This listener's audit ring is reserved for local diagnostics in issue #160.
        let request_audit = Arc::new(RequestAudit::new()?);
        let legacy_catalogue_sha256 = router_catalogue_digest(&missions)?;
        let app = Gateway { oauth:Arc::new(Mutex::new(oauth)),router:Arc::new(missions),
            legacy_catalogue_sha256, request_audit,
            audience:Audience::Missions,expected_resource:None,
            public_host,loopback_host:format!("127.0.0.1:{port}"),requests:Arc::new(Semaphore::new(32)),
            effects:OperationAdmission::default(),
            extension_guard:None, unified:None };
        let router = axum::Router::new().fallback(handle).with_state(app);
        axum::serve(listener,router).with_graceful_shutdown(async { let _ = tokio::signal::ctrl_c().await; }).await?;
        Ok(())
    })
}


/// Require two independently named HTTPS OAuth origins. The OAuth library
/// requires an origin with path "/" and derives its *own* resource as
/// <origin>/mcp. Canonical comparison prevents using the same resource for
/// the existing Missions and explicitly selected Workstation services.
pub(crate) fn canonical_web_origin(origin: &str) -> Result<String, RuntimeError> {
    if !origin.is_ascii() || origin.len() > 4096
        || !origin.starts_with("https://")
        || origin.bytes().any(|byte| matches!(byte, b'@' | b'?' | b'#' | b'%' | b'\\'))
    {
        return Err("An explicit canonical HTTPS DNS origin is required".into());
    }
    let supplied = origin.strip_suffix('/').unwrap_or(origin);
    let uri: Uri = origin.parse()?;
    if uri.scheme_str() != Some("https") || uri.query().is_some()
        || uri.path() != "/"
    {
        return Err("OAuth origin cannot contain a path, query or fragment".into());
    }
    let authority = uri.authority().ok_or("OAuth origin has no authority")?;
    if supplied != format!("https://{}", authority.as_str()) {
        return Err("OAuth origin must be an unambiguous HTTPS authority".into());
    }
    let hostname = uri.host().ok_or("OAuth origin has no hostname")?;
    if hostname.is_empty() || hostname.len() > 253 || !hostname.is_ascii()
        || hostname.split('.').any(|label| {
            label.is_empty() || label.len() > 63 || label.starts_with('-')
                || label.ends_with('-')
                || !label.bytes().all(|ch| ch.is_ascii_alphanumeric() || ch == b'-')
        })
    {
        return Err("OAuth origin requires an ordinary DNS hostname".into());
    }
    let port = uri.port_u16().unwrap_or(443);
    if port == 0 {
        return Err("OAuth origin has an invalid port".into());
    }
    Ok(if port == 443 {
        format!("https://{}", hostname.to_ascii_lowercase())
    } else {
        format!("https://{}:{port}", hostname.to_ascii_lowercase())
    })
}

fn require_distinct_oauth_states(workstation: &Path, missions: &Path) -> Result<(), RuntimeError> {
    // Metadata/path qualification only; do not open or read the contents of
    // the existing Missions OAuth store. The Workstation store later verifies
    // its own owner-only ACL and historical audience during OAuthServer::open.
    let selected = std::fs::canonicalize(workstation)?;
    let existing = std::fs::canonicalize(missions)?;
    let components = |path: &Path| path.components()
        .map(|part| part.as_os_str().to_string_lossy().to_lowercase())
        .collect::<Vec<_>>();
    let a = components(&selected);
    let b = components(&existing);
    if a.starts_with(&b) || b.starts_with(&a) {
        return Err("Workstation and Missions OAuth state directories must be disjoint".into());
    }
    Ok(())
}

/// Local opt-in: a separate HTTPS OAuth origin + owner-private Workstation
/// state, a distinct explicitly reported Missions state/origin, and an
/// independently qualified read-only project. The database path is only an
/// EXCLUSION BOUNDARY for workspace qualification; it is never opened.
/// Nothing is attached to the normal mission router or its agent contexts.
pub fn serve_project_reads(
    database_boundary: &Path,
    workstation_state: &Path,
    workstation_origin: &str,
    port: u16,
    project: &Path,
    missions_state: &Path,
    missions_origin: &str,
    settings_dir: &Path,
    lifecycle_dir: &Path,
) -> Result<(), RuntimeError> {
    runtime::check_port(port)?;
    let workstation_origin=canonical_web_origin(workstation_origin)?;
    let missions_origin=canonical_web_origin(missions_origin)?;
    if workstation_origin==missions_origin {
        return Err("Workstation and Missions OAuth resources must have distinct HTTPS origins".into());
    }
    require_distinct_oauth_states(workstation_state,missions_state)?;
    require_disjoint_workstation_state(workstation_state,missions_state,
        settings_dir,lifecycle_dir,database_boundary)?;
    // Physically qualify the selected project against ALL private boundaries
    // before opening OAuth or registering the four existing read-only tools.
    let qualified=runtime::qualify_web_workstation_project(
        project,database_boundary,workstation_state,
        missions_state,settings_dir,lifecycle_dir,
    )?;
    #[cfg(windows)]
    let _selected_project=agent_bridge_lifecycle::workspace_access::PinnedProjectDirectory::open(&qualified)?;
    let was_empty=initial_workstation_state_empty(workstation_state)?;
    let resource=format!("{workstation_origin}/mcp");
    let host=workstation_origin.parse::<Uri>()?
        .authority().ok_or("Workstation origin needs an authority")?
        .as_str().to_owned();
    let event_loop=tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2).enable_all().build()?;
    event_loop.block_on(async move {
        let oauth=OAuthServer::open(OAuthConfig{
            state_dir:workstation_state.to_owned(),
            public_origin:workstation_origin,
            audience:Audience::Workstation,
        })?;
        let genuinely_fresh=if was_empty {
            freshly_empty_under_oauth_lock(workstation_state)?
        }else{false};
        if was_empty && !genuinely_fresh {
            return Err("Project-read OAuth state changed during startup; new state required".into());
        }
        let reader=runtime::project_read_router(
            &qualified,database_boundary,workstation_state,missions_state,
            settings_dir,lifecycle_dir,
        )?;
        // No readable old-state fallback. The profile's exact four schemas,
        // project FILE ID, private boundaries and OAuth resource are sealed.
        // A legacy four-tool token without this physical binding is rejected.
        let scope=serde_json::json!({
            "schema":2,
            "purpose":"agent-bridge.web.project-read.physical-binding.v1",
            "oauth_resource":resource,
            "port":port,
            "missions_origin":missions_origin,
            "physical_project":scope_directory(&qualified)?,
            "workstation_oauth_state":scope_directory(workstation_state)?,
            "missions_oauth_state":scope_directory(missions_state)?,
            "private_settings":scope_directory(settings_dir)?,
            "private_lifecycle":scope_directory(lifecycle_dir)?,
            "database_boundary":scope_file(database_boundary)?,
            "profile":"read-only",
            "executable_catalog":reader.published_tools(),
        });
        bind_workstation_scope(workstation_state,genuinely_fresh,&scope)?;
        // Legacy endpoint, original four tools, original OAuth URLs.
        // Only the authorization boundary is strengthened; never bind a
        // public network adapter or advertise anonymous workspace tools.
        let listener=agent_bridge_http::bind_loopback(port).await?;
        // This listener's audit ring is reserved for local diagnostics in issue #160.
        let request_audit = Arc::new(RequestAudit::new()?);
        let legacy_catalogue_sha256 = router_catalogue_digest(&reader)?;
        let app=Gateway{
            oauth:Arc::new(Mutex::new(oauth)),
            router:Arc::new(reader),
            legacy_catalogue_sha256, request_audit,
            audience:Audience::Workstation,
            expected_resource:Some(resource),
            public_host:host,
            loopback_host:format!("127.0.0.1:{port}"),
            requests:Arc::new(Semaphore::new(32)),
            effects:OperationAdmission::default(),
            extension_guard:None, unified:None,
        };
        let router=axum::Router::new().fallback(handle).with_state(app);
        axum::serve(listener,router)
            .with_graceful_shutdown(async{let _=tokio::signal::ctrl_c().await;})
            .await?;
        Ok(())
    })
}

/// The ONLY way to enable a richer Web workstation surface is this explicit
/// local CLI startup choice. The old project-read entry and old Workstation
/// OAuth state are not reused. Nothing in an MCP payload can set these flags.
pub struct WorkstationStart<'a> {
    pub database_boundary: &'a Path,
    pub workstation_state: &'a Path,
    pub workstation_origin: &'a str,
    pub port: u16,
    pub project: &'a Path,
    pub missions_state: &'a Path,
    pub missions_origin: &'a str,
    pub settings_dir: &'a Path,
    pub lifecycle_dir: &'a Path,
    pub permitted: WebWorkstationCapabilities,
    pub local_window: Option<crate::window_inspection::DedicatedWindow>,
    pub local_doc_pages: Vec<String>,
    pub local_learn_url: Option<String>,
    pub local_chrome_pages: Vec<String>,
    pub local_chrome_origins: Vec<String>,
    pub ui_port: Option<u16>,
    pub ui_open: bool,
    pub unified_v1: bool,
}

const WORKSTATION_SCOPE_FILE: &str = ".agent-bridge-workstation-scope-v2.json";
const MAX_SCOPE_BYTES: usize = 256 * 1024;

/// The marker is an immutable, exact authorization binding for this LOCAL
/// startup: not merely a mutable profile label. A changed project identity,
/// private directory, OAuth resource, window selection, document set or tool
/// input schema requires a fresh owner-private OAuth state and new tokens.
/// Old project-read stores lack this v2 seal and cannot be promoted.
/// Nothing in MCP can create, modify or select this marker.
pub(crate) fn scope_directory(path: &Path) -> Result<serde_json::Value, RuntimeError> {
    if !path.is_absolute() {
        return Err("A workstation scope directory must be absolute".into());
    }
    let md=std::fs::symlink_metadata(path)?;
    if !md.is_dir() || md.file_type().is_symlink() {
        return Err("A workstation authority directory is not physical".into());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if md.file_attributes() & 0x400 != 0 {
            return Err("A workstation authority directory is a Windows reparse point".into());
        }
        // This existing lifecycle primitive pins the physical directory and
        // all its ancestors by handles, then incorporates the real path AND
        // volume/file identity into a stable namespaced SID. Metadata only;
        // no settings, bearer token or database contents are inspected.
        let id=agent_bridge_lifecycle::workspace_access::project_read_sid(path)?;
        let canonical=std::fs::canonicalize(path)?;
        return Ok(serde_json::json!({"physical_path":canonical,"identity":id}));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let canonical=std::fs::canonicalize(path)?;
        if canonical != path {return Err("A workstation scope directory has an alias".into());}
        return Ok(serde_json::json!({
            "physical_path":canonical,"device":md.dev(),"inode":md.ino()
        }));
    }
    #[cfg(not(any(windows,unix)))]
    {
        Err("No physical directory identity support on this platform".into())
    }
}

pub(crate) fn scope_file(path: &Path) -> Result<serde_json::Value,RuntimeError> {
    if !path.is_absolute() {
        return Err("A workstation authority file must be absolute".into());
    }
    let parent=path.parent().ok_or("A workstation authority file needs a parent")?;
    let parent_identity=scope_directory(parent)?;
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind()==std::io::ErrorKind::NotFound => Ok(serde_json::json!({
            "selected_path":path,"present":false,"parent":parent_identity
        })),
        Err(error)=>Err(error.into()),
        Ok(md)=>{
            if !md.is_file() || md.file_type().is_symlink() {
                return Err("A workstation authority file is not physical".into());
            }
            #[cfg(windows)]
            let stamp={
                use std::os::windows::fs::MetadataExt;
                if md.file_attributes() & 0x400 != 0 {
                    return Err("A workstation authority file is a reparse point".into());
                }
                // Creation time is a metadata-only file incarnation witness;
                // never open/read the contents of the SQLite or private file.
                serde_json::json!({"created_windows_filetime":md.creation_time()})
            };
            #[cfg(unix)]
            let stamp={
                use std::os::unix::fs::MetadataExt;
                serde_json::json!({"device":md.dev(),"inode":md.ino()})
            };
            #[cfg(not(any(unix,windows)))]
            let stamp=serde_json::json!({"unavailable":true});
            let resolved=std::fs::canonicalize(path)?;
            Ok(serde_json::json!({
                "selected_path":path,"physical_path":resolved,
                "present":true,"parent":parent_identity,"file_identity":stamp
            }))
        }
    }
}

fn selected_window_scope(
    window: &crate::window_inspection::DedicatedWindow,
) -> Result<serde_json::Value,RuntimeError> {
    Ok(serde_json::json!({
        "desktop":window.desktop_name,
        "image":scope_file(&window.executable)?,
        "class":window.class_name,
        "title":window.title,
        // A confirmed HWND/process incarnation is deliberately NOT reused
        // across startups. See fresh-state admission in serve_workstation.
        "selection_is_one_incarnation":true
    }))
}

/// The base identity is checked under the OAuth store lock before attaching
/// extensions, accessing SQLite or opening any workstation tool. It includes
/// ALL authority-changing operator selections except the not-yet-assembled
/// catalogue, which is compared in full before network binding.
fn workstation_scope_base(
    request: &WorkstationStart<'_>,
    resource: &str,
    missions_origin: &str,
    selected_project: &Path,
    selected_window: Option<&serde_json::Value>,
    exact_pages: &[String],
    public_learn_url: Option<&str>,
    native_chrome_pages: &[String],
    native_chrome_origins: &[String],
    extensions: Option<&serde_json::Value>,
) -> Result<serde_json::Value,RuntimeError> {
    let database=scope_file(request.database_boundary)?;
    Ok(serde_json::json!({
        "schema":2,
        "purpose":"agent-bridge.web.workstation.exact-authority.v2",
        "oauth_resource":resource,
        "local_port":request.port,
        "missions_origin":missions_origin,
        "physical_project":scope_directory(selected_project)?,
        "workstation_oauth_state":scope_directory(request.workstation_state)?,
        "missions_oauth_state":scope_directory(request.missions_state)?,
        "private_settings":scope_directory(request.settings_dir)?,
        "private_lifecycle":scope_directory(request.lifecycle_dir)?,
        "database_boundary":database,
        "profile":request.permitted.profile,
        "task_rooms":request.permitted.task_rooms,
        "settings_tools":request.permitted.settings_tools,
        "processes":request.permitted.processes,
        "exact_window":selected_window,
        "exact_document_pages":exact_pages,
        // The local operator's ONE public starting URL is part of the
        // bearer authority, just like a page list or a window incarnation.
        "public_learn_home_url":public_learn_url,
        // Native Chrome has a distinct source boundary. Only these
        // operator-selected local pages and exact allowed public origins
        // can be reached through its private, unauthenticated CDP stdio pipe.
        "native_chrome_pages":native_chrome_pages,
        "native_chrome_origins":native_chrome_origins,
        "effective_extension_authority":extensions
    }))
}

fn legacy_base_for_unified(
    state:&Path,initial_empty:bool,current:&Value,
)->Result<Value,RuntimeError> {
    if initial_empty {return Ok(current.clone());}
    let bytes=read_workstation_scope(state)?.ok_or("Legacy workstation marker is required")?;
    let historical:Value=serde_json::from_slice(&bytes)?;
    // The original writer uses this exact compact representation. Reject
    // duplicate/ambiguous keys, missing fields and altered encoding as before.
    if serde_json::to_vec(&historical)?!=bytes || !historical.is_object()
        || !historical.get("executable_catalog").and_then(Value::as_array)
            .is_some_and(|catalogue|!catalogue.is_empty()&&catalogue.len()<=96)
    {return Err("Invalid historical workstation authority marker".into());}
    let authority=historical.get("effective_extension_authority")
        .ok_or("Historical extension authority is missing")?;
    let settings=current.get("settings_tools").and_then(Value::as_bool).ok_or("Invalid local workstation selection")?;
    if settings&&!authority.is_object() || !settings&&!authority.is_null() {
        return Err("Historical extension authority shape does not match its legacy selection".into());
    }
    let mut selected=current.clone();
    selected["effective_extension_authority"]=authority.clone();
    preflight_workstation_scope(state,false,&selected)?;
    Ok(selected)
}

fn workstation_scope(
    base: &serde_json::Value,
    published: &MissionRouter,
) -> Result<serde_json::Value,RuntimeError> {
    let definitions=published.published_tools();
    if definitions.is_empty() || definitions.len()>96 {
        return Err("Empty or unbounded Web workstation executable catalog".into());
    }
    let mut bound=base.clone();
    // Seal every actually implemented tool and its exact schema. A new tool,
    // removal or broader argument contract requires new OAuth state/tokens.
    bound["executable_catalog"]=serde_json::json!(definitions);
    Ok(bound)
}

// Read only the binding that this Rust server created in a pre-existing,
// owner-private OAuth directory. Reject link/reparse substitution at BOTH
// path metadata and opened-handle layers. Never read bearer/token data here.
fn read_workstation_scope(state_dir:&Path)->Result<Option<Vec<u8>>,RuntimeError>{
    let path=state_dir.join(WORKSTATION_SCOPE_FILE);
    let metadata=match std::fs::symlink_metadata(&path){
        Err(e) if e.kind()==std::io::ErrorKind::NotFound=>return Ok(None),
        Err(e)=>return Err(e.into()),
        Ok(meta)=>meta,
    };
    if !metadata.is_file() || metadata.file_type().is_symlink()
        || metadata.len()>MAX_SCOPE_BYTES as u64
    {
        return Err("Invalid workstation scope marker type, alias or size".into());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err("Reparse workstation scope marker refused".into());
        }
    }
    let mut options=std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(0x20000); // O_NOFOLLOW on supported Linux
    }
    let file=options.open(&path)?;
    let opened=file.metadata()?;
    if !opened.is_file() || opened.len()>MAX_SCOPE_BYTES as u64 {
        return Err("Workstation scope marker changed or exceeded limit".into());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if opened.file_attributes() & 0x400 != 0
            || metadata.creation_time()!=opened.creation_time()
        {
            return Err("Workstation scope marker reparse/identity changed".into());
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if opened.dev()!=metadata.dev() || opened.ino()!=metadata.ino() {
            return Err("Workstation scope marker identity changed".into());
        }
    }
    let mut bytes=Vec::new();
    file.take((MAX_SCOPE_BYTES+1) as u64).read_to_end(&mut bytes)?;
    if bytes.len()>MAX_SCOPE_BYTES {return Err("Workstation scope marker exceeds its limit".into());}
    Ok(Some(bytes))
}

/// Compare all operator choices and private physical path identities BEFORE
/// creating any workstation handlers or opening the selected Core database.
/// Only the executable-tool schema comparison waits for runtime assembly.
fn preflight_workstation_scope(
    state_dir:&Path,
    initial_empty:bool,
    selected_base:&serde_json::Value,
)->Result<(),RuntimeError>{
    if initial_empty {
        if read_workstation_scope(state_dir)?.is_some() {
            return Err("An old OAuth authority unexpectedly appeared during fresh startup".into());
        }
        return Ok(());
    }
    let bytes=read_workstation_scope(state_dir)?
        .ok_or("Existing read-only or unrelated OAuth state has no exact workstation scope; a NEW state is required")?;
    let mut stored:serde_json::Value=serde_json::from_slice(&bytes)?;
    let fields=stored.as_object_mut().ok_or("Invalid workstation scope marker object")?;
    let _catalog=fields.remove("executable_catalog")
        .ok_or("Existing workstation OAuth scope has no executable catalog binding")?;
    if &stored!=selected_base {
        return Err("Workstation authority changed (project, settings, DB, window, docs, profile or origin); use a NEW owner-private OAuth state".into());
    }
    Ok(())
}

/// Called only after OAuthServer::open holds the exclusive state lock.
/// The earlier empty-directory observation is advisory; reject any token
/// state that appeared between that check and lock acquisition. Known
/// bootstrap lock/request paths are the ONLY allowed newly created entries.
fn freshly_empty_under_oauth_lock(state_dir:&Path)->Result<bool,RuntimeError>{
    let mut entries=0usize;
    for entry in std::fs::read_dir(state_dir)?{
        let entry=entry?;
        entries+=1;
        if entries>16 {return Ok(false);}
        let name=entry.file_name();
        let Some(name)=name.to_str() else {return Ok(false)};
        let md=std::fs::symlink_metadata(entry.path())?;
        match name{
            "oauth-rust.lock"|"running.lock" if md.is_file()
                && !md.file_type().is_symlink()=>{},
            "requests-workstation" if md.is_dir()
                && !md.file_type().is_symlink()=>{
                // No already-pending approval belongs to a fresh OAuth state.
                if std::fs::read_dir(entry.path())?.next().is_some(){return Ok(false);}
            },
            _=>return Ok(false),
        }
    }
    Ok(true)
}

fn bind_workstation_scope(
    state_dir:&Path,
    initial_empty:bool,
    scope:&serde_json::Value,
)->Result<(),RuntimeError>{
    let expected=serde_json::to_vec(scope)?;
    if expected.len()>MAX_SCOPE_BYTES {
        return Err("The exact workstation executable catalog/authority exceeds its binding limit".into());
    }
    match read_workstation_scope(state_dir)? {
        Some(bytes) if !initial_empty && bytes==expected=>Ok(()),
        Some(_) if initial_empty=>Err("OAuth scope appeared during a fresh workstation startup".into()),
        Some(_)=>Err("Workstation tool schemas or local authority changed; select a NEW OAuth state and obtain new tokens".into()),
        None if !initial_empty=>Err("Existing OAuth state lacks a bound workstation catalog; reuse refused".into()),
        None=>{
            let path=state_dir.join(WORKSTATION_SCOPE_FILE);
            let mut options=std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt;
                options.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600).custom_flags(0x20000); // O_NOFOLLOW on supported Linux
            }
            let mut file=options.open(&path)?;
            file.write_all(&expected)?;
            file.sync_all()?;
            Ok(())
        }
    }
}

fn initial_workstation_state_empty(state_dir:&Path)->Result<bool,RuntimeError>{
    // This is local metadata inspection only, never a public route. OAuth
    // checks the directory's owner-only permissions before accepting use.
    let mut count=0usize;
    for entry in std::fs::read_dir(state_dir)? {
        let _=entry?;
        count+=1;
        if count>256 {return Err("Workstation OAuth state contains too many entries".into());}
    }
    Ok(count==0)
}

fn require_disjoint_workstation_state(
    workstation:&Path, missions:&Path, settings:&Path,
    lifecycle:&Path, database:&Path,
)->Result<(),RuntimeError>{
    // The selected OAuth state must not be inside, or contain, the
    // operator's private settings, lifecycle, Missions state or SQLite
    // directory. Project disjointness is checked separately by runtime.
    let db_dir=database.parent().ok_or("SQLite boundary has no parent")?;
    let owner=std::fs::canonicalize(workstation)?;
    let key=|p:&Path| p.components().map(|c|
        c.as_os_str().to_string_lossy().to_lowercase()).collect::<Vec<_>>();
    let a=key(&owner);
    for root in [missions,settings,lifecycle,db_dir] {
        let other=key(&std::fs::canonicalize(root)?);
        if a.starts_with(&other) || other.starts_with(&a){
            return Err("Workstation OAuth state overlaps private settings, lifecycle, database or Missions state".into());
        }
    }
    Ok(())
}

/// A distinct OAuth-protected listener for a NEW, locally bound Workstation
/// resource. Existing "gemini serve", "serve --port" and "gemini
/// project-read" are not modified and cannot inherit these privileges.
/// Binds IPv4 loopback only; public HTTPS forwarding is operator-managed.
// The store is acquired before effectful handlers are assembled. Startup
// failure must drain any supervisors before releasing that exclusive gate.
struct StartupSupervisors {
    items: Vec<crate::terminal::SessionSupervisor>,
    providers: Vec<crate::provider_owner::ProviderOwner>,
    oauth: Arc<Mutex<OAuthServer>>,
}
fn cleanup_resources(
    supervisors:&mut [crate::terminal::SessionSupervisor],
    providers:&mut [crate::provider_owner::ProviderOwner],
)->Result<(),RuntimeError> {
    for supervisor in supervisors {supervisor.shutdown()?;}
    // Providers are attached in dependency order: files, desktops, UI,
    // browser. On uncertainty, retain lower dependencies and the OAuth gate.
    for owner in providers.iter_mut().rev() {owner.shutdown()?;}
    Ok(())
}
impl Drop for StartupSupervisors {
    fn drop(&mut self) {
        let retained=Arc::new(Mutex::new((
            std::mem::take(&mut self.items),std::mem::take(&mut self.providers),Arc::clone(&self.oauth),
        )));
        let cleanup:crate::provider_owner::Cleanup=Arc::new(move || {
            let mut resources=retained.lock().unwrap_or_else(|poisoned|poisoned.into_inner());
            let (items,providers,_oauth)=&mut *resources;
            cleanup_resources(items,providers)
        });
        let mut owner=crate::provider_owner::ProviderOwner::new(Arc::new(||Ok(())),cleanup);
        if owner.shutdown().is_err() {owner.defer();}
    }
}

pub(crate) struct PreparedWorkstation {
    pub(crate) listener: Option<tokio::net::TcpListener>,
    pub(crate) requests: Arc<Semaphore>,
    pub(crate) effects: OperationAdmission,
    pub(crate) service: axum::Router,
    pub(crate) profile: ProfileControl,
    pub(crate) database: Option<runtime::SharedCoreDatabase>,
    pub(crate) ui_config: crate::ui::UiConfig,
    // Keep OAuth ownership and the physical project pin until explicit cleanup,
    // even after the HTTP future has returned and released its router clone.
    pub(crate) _oauth: Arc<Mutex<OAuthServer>>,
    pub(crate) supervisors: Vec<crate::terminal::SessionSupervisor>,
    pub(crate) providers: Vec<crate::provider_owner::ProviderOwner>,
    cleanup_complete: bool,
    #[cfg(windows)]
    pub(crate) _project_pin: Option<agent_bridge_lifecycle::workspace_access::PinnedProjectDirectory>,
}
impl PreparedWorkstation {
    pub(crate) fn drain_requests(&self)
        -> impl std::future::Future<Output = Result<(), RuntimeError>> + Send + 'static
    {
        let requests = Arc::clone(&self.requests);
        let effects=self.effects.clone();
        effects.close();
        async move {
            // HTTP disconnection can abandon spawn_blocking without cancelling it.
            // After the listener has stopped, owning every permit proves that all
            // admitted gateway closures have returned, including detached ones.
            let _drained = requests.acquire_many(32).await
                .map_err(|_| "Gateway request admission closed unexpectedly")?;
            effects.drain().await;
            Ok(())
        }
    }
    pub(crate) fn cleanup(&mut self) -> Result<(), RuntimeError> {
        self.effects.close();
        if self.requests.available_permits()!=32 || !self.effects.is_drained() {
            return Err("WORKSTATION_EFFECT_DRAIN_PENDING".into());
        }
        cleanup_resources(&mut self.supervisors,&mut self.providers)?;
        self.cleanup_complete=true;
        Ok(())
    }
}

// Compatibility-host errors and cancellation retain the same collective
// authority as native abandonment. No failed cleanup may drop OAuth first.
struct RetainedPrepared {
    requests: Arc<Semaphore>,
    effects: OperationAdmission,
    supervisors: Vec<crate::terminal::SessionSupervisor>,
    providers: Vec<crate::provider_owner::ProviderOwner>,
    _service: axum::Router,
    _database: Option<runtime::SharedCoreDatabase>,
    _profile: ProfileControl,
    _oauth: Arc<Mutex<OAuthServer>>,
    #[cfg(windows)]
    _project_pin: Option<agent_bridge_lifecycle::workspace_access::PinnedProjectDirectory>,
}
impl Drop for PreparedWorkstation {
    fn drop(&mut self) {
        if self.cleanup_complete {return;}
        self.effects.close();
        self.listener.take();
        let retained=Arc::new(Mutex::new(Some(RetainedPrepared {
            requests:Arc::clone(&self.requests),effects:self.effects.clone(),
            supervisors:std::mem::take(&mut self.supervisors),
            providers:std::mem::take(&mut self.providers),
            _service:std::mem::take(&mut self.service),_database:self.database.take(),
            _profile:self.profile.clone(),_oauth:Arc::clone(&self._oauth),
            #[cfg(windows)]
            _project_pin:self._project_pin.take(),
        })));
        let cleanup:crate::provider_owner::Cleanup=Arc::new(move || {
            let mut slot=retained.lock().unwrap_or_else(|error|error.into_inner());
            let Some(owner)=slot.as_mut() else {return Ok(());};
            if owner.requests.available_permits()!=32 || !owner.effects.is_drained() {
                return Err("WORKSTATION_EFFECT_DRAIN_PENDING".into());
            }
            cleanup_resources(&mut owner.supervisors,&mut owner.providers)?;
            slot.take();
            Ok(())
        });
        crate::provider_owner::ProviderOwner::new(Arc::new(||Ok(())),cleanup).defer();
    }
}

pub(crate) async fn prepare_workstation(mut request: WorkstationStart<'_>) -> Result<PreparedWorkstation, RuntimeError> {
    static PREPARATION:tokio::sync::Mutex<()>=tokio::sync::Mutex::const_new(());
    let _preparation=PREPARATION.lock().await;
    crate::provider_owner::ProviderOwner::reconcile_rollbacks()?;
    runtime::check_port(request.port)?;
    if request.ui_open && request.ui_port.is_none() {
        return Err("--ui-open requires --ui-port".into());
    }
    if request.ui_port == Some(request.port) {
        return Err("The operator UI and MCP require distinct loopback ports".into());
    }
    let read_only=request.permitted.profile==DesktopProfile::ReadOnly;
    if read_only && (request.permitted.task_rooms || request.permitted.settings_tools
        || request.permitted.processes)
    {
        return Err("Read-only Web cannot grant settings, Task Rooms or process execution".into());
    }
    if request.permitted.processes
        && !request.permitted.profile.permits_processes()
    {
        return Err("Web process tools require explicit local full-control or fully-unlocked".into());
    }
    let browser_providers=usize::from(!request.local_doc_pages.is_empty())
        +usize::from(request.local_learn_url.is_some())
        +usize::from(!request.local_chrome_pages.is_empty());
    if browser_providers>1
        || (!request.local_chrome_origins.is_empty() && request.local_chrome_pages.is_empty())
        || request.local_chrome_pages.len()>8
        || request.local_chrome_origins.len()>4
        || request.local_doc_pages.len()>crate::browser_docs::MAX_APPROVED_PAGES
    {
        return Err("Select exactly one bounded browser provider with local project scope".into());
    }
    // A window requires its own local native consent; its tool names do not
    // overlap the browser or extension handlers, so other families need not
    // be disabled when their exact local authority is also selected.

    let workstation_origin=canonical_web_origin(request.workstation_origin)?;
    let missions_origin=canonical_web_origin(request.missions_origin)?;
    if workstation_origin==missions_origin {
        return Err("Missions and Workstation require separate HTTPS OAuth resources".into());
    }
    require_distinct_oauth_states(request.workstation_state,request.missions_state)?;
    require_disjoint_workstation_state(
        request.workstation_state,request.missions_state,request.settings_dir,
        request.lifecycle_dir,request.database_boundary,
    )?;
    // Qualify all root exclusions before opening OAuth, Core or any workstation
    // tool. No other route ever receives this richer profile.
    let qualified=runtime::qualify_web_workstation_project(
        request.project,request.database_boundary,request.workstation_state,
        request.missions_state,request.settings_dir,request.lifecycle_dir,
    )?;
    #[cfg(windows)]
    let project_pin=agent_bridge_lifecycle::workspace_access::PinnedProjectDirectory::open(&qualified)?;

    // A selected native window + process incarnation is ephemeral. Even if the name,
    // executable, title and desktop are unchanged, an earlier OAuth token may
    // not be reused to inspect a NEW window: require fresh OAuth state for
    // every startup selecting a window.
    let state_was_empty=initial_workstation_state_empty(request.workstation_state)?;
    if request.local_window.is_some() && !state_was_empty {
        return Err("A locally selected window requires a NEW, empty workstation OAuth state; old bearer tokens cannot follow a new HWND".into());
    }
    // Bind the *exact* operator-chosen target before it is moved into its
    // one-incarnation local approval. No MCP field may select an application.
    let window_scope=request.local_window.as_ref()
        .map(selected_window_scope).transpose()?;
    let selected_pages=request.local_doc_pages.clone();
    let selected_learn_url=request.local_learn_url.clone();
    let selected_chrome_pages=request.local_chrome_pages.clone();
    let selected_chrome_origins=request.local_chrome_origins.clone();

    let local_approval=match request.local_window.take() {
        Some(window)=>Some(crate::window_inspection::confirm_local_selection(window)?),
        None=>None,
    };
    let docs_approval=if selected_pages.is_empty() {
        None
    } else {
        // Reuse the existing strict reader: exact locally chosen page names,
        // pre-open private-path filtering, installed Chrome qualification and
        // bounded one-shot isolated rendering. Never a general browser.
        Some(crate::browser_docs::approve_from_local_cli(
            crate::browser_docs::LocalDocsRequest{
                workspace:qualified.clone(),pages:selected_pages.clone(),
            },
        )?)
    };
    let learn_approval = match selected_learn_url.as_ref() {
        Some(url) => Some(crate::browser_docs::learn::approve_local(
            crate::browser_docs::learn::LocalLearnSelection {
                home_url:url.to_owned(),
            },
        )?),
        None => None,
    };
    #[cfg(any(windows, unix))]
    let native_chrome_approval=if selected_chrome_pages.is_empty() {
        None
    } else {
        // The local argv and already qualified physical project are the
        // only source of Chrome's editable DOM scope; not MCP arguments.
        Some(crate::browser_docs::interactive::approve_local(
            crate::browser_docs::interactive::LocalInteractiveSelection{
                workspace:qualified.clone(),
                pages:selected_chrome_pages.clone(),
                allowed_origins:selected_chrome_origins.clone(),
            },
        )?)
    };
    #[cfg(not(any(windows, unix)))]
    if !selected_chrome_pages.is_empty() || !selected_chrome_origins.is_empty() {
        return Err("Native interactive Chrome is unavailable on this platform".into());
    }
    let resource=format!("{workstation_origin}/mcp");
    // The complete preflight includes effective extension grants and is
    // evaluated after the OAuth state lock but before any effectful tool.
    let public_host=workstation_origin.parse::<Uri>()?.authority()
        .ok_or("Workstation origin has no hostname")?.as_str().to_owned();

    let active_profile = ProfileControl::new(request.permitted.profile);
    // Read the locally selected manifest and qualify all required resources
    // before acquiring OAuth or binding a listener. Missing components cannot
    // turn --unified-v1 into a silent legacy fallback.
    let unified_manifest=if request.unified_v1 {
        let authority=runtime::workstation_extension_authority(request.settings_dir)?;
        let legacy_extensions=if request.permitted.settings_tools {Some(&authority)} else {None};
        let mut base=workstation_scope_base(&request,&resource,&missions_origin,&qualified,
            window_scope.as_ref(),&selected_pages,selected_learn_url.as_deref(),
            &selected_chrome_pages,&selected_chrome_origins,legacy_extensions)?;
        // Unified always composes extensions, even if the retained legacy
        // selection did not include them. Its authority is sealed separately.
        base["effective_extension_authority"]=authority;
        let context=crate::capability_manifest::ManifestContext {
            workspace:qualified.clone(),
            protected_roots:vec![
                request.workstation_state.to_owned(),request.missions_state.to_owned(),
                request.settings_dir.to_owned(),request.lifecycle_dir.to_owned(),
                request.database_boundary.parent().ok_or("Database parent unavailable")?.to_owned(),
            ],
            legacy_authority:base,
        };
        let manifest=crate::capability_manifest::QualifiedManifest::load(request.settings_dir,context)?;
        manifest.preflight_providers()?;
        Some(Arc::new(manifest))
    } else {None};
    let options=OAuthConfig {
        state_dir:request.workstation_state.to_owned(),
        public_origin:workstation_origin.clone(),audience:Audience::Workstation,
    };
    let oauth_owner=match unified_manifest.as_ref() {
        Some(manifest)=>OAuthServer::open_with_capability(options,manifest.identity()?)?,
        None=>OAuthServer::open(options)?,
    };
    let oauth=Arc::new(Mutex::new(oauth_owner));
    let mut supervisors = StartupSupervisors { items: Vec::new(), providers: Vec::new(), oauth: Arc::clone(&oauth) };

    // The initial empty-state observation was outside the OAuth lock.
    // Recheck now under exclusive ownership: another OAuth grant/state
    // must not have appeared in the interim. Never promote old bearer
    // tokens, even if a local project/profile selection is broader.
    let genuinely_fresh=if state_was_empty {
        freshly_empty_under_oauth_lock(request.workstation_state)?
    } else {false};
    if state_was_empty && !genuinely_fresh {
        return Err("Workstation OAuth state was populated during startup; select a NEW empty state".into());
    }
    // Snapshot the EFFECTIVE, locally approved extension registry: not
    // just the four published generic extension MCP tool schemas.
    // The registry combines the private journal, server generation,
    // individual tool pins, parameter constraints and enable controls.
    let current_extension_scope=if request.permitted.settings_tools || unified_manifest.is_some() {
        Some(runtime::workstation_extension_authority(request.settings_dir)?)
    }else{None};
    let unified_extension_scope=if let Some(manifest)=unified_manifest.as_ref() {
        if current_extension_scope.as_ref()!=Some(&manifest.context.legacy_authority["effective_extension_authority"]) {
            return Err("Unified extension authority changed during preparation".into());
        }
        current_extension_scope.clone()
    }else{None};
    let current_legacy_extensions=if request.permitted.settings_tools {
        current_extension_scope.as_ref()
    }else{None};
    // Check client-independent sealed authority BEFORE opening the Core
    // database or attaching any private, effectful workstation handler.
    let expected_base=workstation_scope_base(
        &request,&resource,&missions_origin,&qualified,
        window_scope.as_ref(),&selected_pages,
        selected_learn_url.as_deref(),&selected_chrome_pages,
        &selected_chrome_origins,current_legacy_extensions,
    )?;
    if let Some(manifest)=unified_manifest.as_ref() {
        let mut current=expected_base.clone();
        current["effective_extension_authority"]=unified_extension_scope.clone()
            .ok_or("Unified extension authority unavailable")?;
        if current!=manifest.context.legacy_authority {
            return Err("UNIFIED_AUTHORITY_CHANGED: physical startup authority changed before Core acquisition".into());
        }
        manifest.verify()?;
    }
    let expected_base=if unified_manifest.is_some() {
        legacy_base_for_unified(request.workstation_state,genuinely_fresh,&expected_base)?
    }else{expected_base};
    let extension_scope=if request.permitted.settings_tools {
        Some(expected_base["effective_extension_authority"].clone())
    }else{None};
    preflight_workstation_scope(request.workstation_state,
        genuinely_fresh,&expected_base)?;

    // Assemble ONLY authorized, executable tools, then seal the EXACT
    // published catalog (names + schemas) before binding the listener.
    let runtime::WorkstationRuntime { router: tools, database }=runtime::workstation_router(
        &qualified,request.database_boundary,request.workstation_state,
        request.missions_state,request.settings_dir,request.lifecycle_dir,
        request.permitted,local_approval,docs_approval,learn_approval,
        #[cfg(any(windows, unix))] native_chrome_approval,
        &mut supervisors.items,extension_scope.as_ref(),active_profile.clone(),
    )?;
    let scope=workstation_scope(&expected_base,&tools)?;
    bind_workstation_scope(request.workstation_state,genuinely_fresh,&scope)?;
    let legacy_count=tools.published_tools().len();
    let mut database=database;
    let mut capability_selection=json!({
        "identity":CapabilityIdentity::Legacy,"total_tools":legacy_count,
        "components":{"legacy_workstation":{"implementation":"attached","availability":"legacy-profile-and-local-policy"}}
    });
    let unified=if let Some(manifest)=unified_manifest {
        let authority=unified_extension_scope.ok_or("Unified extension authority unavailable")?;
        let assembled=runtime::unified_router(&manifest,request.database_boundary,
            database.clone(),request.settings_dir,&authority,active_profile.clone(),
            &mut supervisors.items,&mut supervisors.providers)?;
        let definitions=assembled.router.published_tools().into_iter().cloned().collect::<Vec<_>>();
        manifest.verify_catalogue(&definitions)?;
        manifest.verify()?;
        if runtime::workstation_extension_authority(request.settings_dir)?!=authority {
            return Err("Unified extension authority changed before bind".into());
        }
        oauth.lock().map_err(|_|"OAuth owner unavailable")?
            .bind_capability_manifest(&manifest.authority_bytes()?)?;
        capability_selection=manifest.summary()?;
        database=assembled.database;
        let identity=manifest.identity()?;
        let guard=Arc::clone(&manifest);
        Some(Arc::new(UnifiedRoute {
            identity,router:Arc::new(assembled.router),
            extension_guard:Some(ExtensionGuard {settings:request.settings_dir.to_owned(),authority}),
            manifest_guard:Arc::new(move ||guard.verify()),
            response_permits:Arc::new(Semaphore::new(2)),
        }))
    }else{None};

    // Same existing, authenticated OAuth /mcp transport, strictly loopback
    // and distinct from the mission-only and four-tool project-read paths.
    let listener=agent_bridge_http::bind_loopback(request.port).await?;
    let requests = Arc::new(Semaphore::new(32));
    let effects=OperationAdmission::default();
    let request_audit = Arc::new(RequestAudit::new()?);
    let legacy_catalogue_sha256 = router_catalogue_digest(&tools)?;
    let app=Gateway{
        oauth:Arc::clone(&oauth),router:Arc::new(tools), unified,
        legacy_catalogue_sha256, request_audit: Arc::clone(&request_audit),
        audience:Audience::Workstation,expected_resource:Some(resource),
        public_host,loopback_host:format!("127.0.0.1:{}",request.port),
        requests:Arc::clone(&requests),
        effects:effects.clone(),
        extension_guard:extension_scope.map(|authority|ExtensionGuard{
            settings:request.settings_dir.to_owned(),authority,
        }),
    };
    let service=axum::Router::new().fallback(handle).with_state(app);
    let ui_config = crate::ui::UiConfig {
        port: request.ui_port.unwrap_or(0),
        database: Some(request.database_boundary.to_owned()),
        settings_dir: Some(request.settings_dir.to_owned()),
        oauth_state: Some(request.workstation_state.to_owned()),
        oauth_origin: Some(workstation_origin),
        oauth_audience: Some(Audience::Workstation),
        project: Some(qualified),
        open_browser: request.ui_open,
        capability_selection: Some(capability_selection),
        request_audit: Some(request_audit),
    };
    Ok(PreparedWorkstation {
        listener: Some(listener), requests, effects, service, profile: active_profile, database,
        ui_config, _oauth: oauth, supervisors: std::mem::take(&mut supervisors.items),
        providers: std::mem::take(&mut supervisors.providers),
        cleanup_complete:false,
        #[cfg(windows)]
        _project_pin: Some(project_pin),
    })
}

/// Compatibility host for the existing explicit headless CLI. The native host
/// uses the same preparation, without creating either a runtime or a UI socket.
pub fn serve_workstation(request: WorkstationStart<'_>) -> Result<(), RuntimeError> {
    let ui_port = request.ui_port;
    let event_loop = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2).enable_all().build()?;
    event_loop.block_on(async {
        let mut prepared = prepare_workstation(request).await?;
        let (signal_sender, signal_receiver) = tokio::sync::watch::channel(false);
        let process_signal = signal_sender.clone();
        let signal_effects=prepared.effects.clone();
        let signal_task = tokio::spawn(async move {
            crate::ui::shutdown_signal().await;
            signal_effects.close();
            let _ = process_signal.send(true);
        });
        let listener = prepared.listener.take().ok_or("Workstation listener unavailable")?;
        let service = prepared.service.clone();
        let mcp_shutdown = signal_receiver.clone();
        let closing_effects=prepared.effects.clone();
        let serve_mcp = async move {
            axum::serve(listener, service)
                .with_graceful_shutdown(async move {
                    crate::ui::wait_for_shutdown(mcp_shutdown).await;
                    closing_effects.close();
                })
                .await?;
            Ok::<(), RuntimeError>(())
        };
        let served = if ui_port.is_some() {
            tokio::try_join!(serve_mcp, crate::ui::serve_embedded(
                prepared.ui_config.clone(), prepared.profile.clone(),
                prepared.database.clone(), signal_receiver, signal_sender,prepared.effects.clone(),
            )).map(|_| ())
        } else {
            serve_mcp.await
        };
        signal_task.abort();
        prepared.drain_requests().await?;
        prepared.cleanup()?;
        served
    })
}

#[cfg(test)]
mod tests {
    use super::{adapt_chatgpt_file_read_result, AdmittedRequest};

    #[tokio::test]
    async fn admitted_owner_drops_before_request_permit_returns() {
        use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
        use tokio::sync::Semaphore;
        struct DropWitness {
            semaphore: Arc<Semaphore>,
            permits_during_drop: Arc<AtomicUsize>,
        }
        impl Drop for DropWitness {
            fn drop(&mut self) {
                self.permits_during_drop.store(
                    self.semaphore.available_permits(), Ordering::SeqCst);
            }
        }

        for blocking in [false, true] {
            let semaphore = Arc::new(Semaphore::new(1));
            let observed = Arc::new(AtomicUsize::new(usize::MAX));
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let admitted = AdmittedRequest {
                state: DropWitness {
                    semaphore: semaphore.clone(),
                    permits_during_drop: observed.clone(),
                },
                _permit: permit,
            };
            if blocking {
                tokio::task::spawn_blocking(move || drop(admitted)).await.unwrap();
            } else {
                drop(admitted);
            }
            assert_eq!(observed.load(Ordering::SeqCst), 0,
                "shutdown must not observe drained permits before owner destruction");
            assert_eq!(semaphore.available_permits(), 1);
        }
    }
    use serde_json::json;

    const FILE_READ: &str =
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"desktop_read_file"}}"#;

    #[test]
    fn file_read_adapter_preserves_malformed_and_colliding_business_payloads() {
        for text in [
            "not JSON",
            r#"["file text"]"#,
            r#"{"offset":0}"#,
            r#"{"content":["file text"]}"#,
            r#"{"content":"source","file_content":"existing"}"#,
            r#"{"content":"source","file_content":null}"#,
        ] {
            let response = json!({
                "jsonrpc":"2.0", "id":1,
                "result":{"content":[{"type":"text","text":text}]}
            });
            assert!(adapt_chatgpt_file_read_result(FILE_READ, &response.to_string()).is_none());
        }
    }

    #[test]
    fn file_read_adapter_preserves_errors_and_unexpected_mcp_envelopes() {
        let block = json!({"type":"text","text":r#"{"content":"file text"}"#});
        for result in [
            json!({"isError":true,"content":[block]}),
            json!({"isError":null,"content":[block]}),
            json!({"content":block}),
            json!({"content":[block,block]}),
            json!({"content":[{"type":"image","text":block["text"]}]}),
            json!({"content":[{"type":"text","text":42}]}),
        ] {
            let response = json!({"jsonrpc":"2.0","id":1,"result":result});
            assert!(adapt_chatgpt_file_read_result(FILE_READ, &response.to_string()).is_none());
        }
        for response in [
            "not JSON",
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"Internal error"}}"#,
        ] {
            assert!(adapt_chatgpt_file_read_result(FILE_READ, response).is_none());
        }
    }

    #[test]
    fn file_read_adapter_ignores_other_methods_and_tools() {
        let response = json!({
            "jsonrpc":"2.0","id":1,
            "result":{"content":[{"type":"text","text":r#"{"content":"business text"}"#}]}
        }).to_string();
        for frame in [
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"name":"desktop_read_file"}}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"desktop_policy_status"}}"#,
        ] {
            assert!(adapt_chatgpt_file_read_result(frame, &response).is_none());
        }
    }
}

#[cfg(test)]
#[path = "capability_route_tests.rs"]
mod capability_route_tests;
#[cfg(all(test, windows, feature = "qualification"))]
pub(crate) use capability_route_tests::assert_audited_unified_status;
