//! Historical Gemini OAuth shapes, origin/callback validation and cryptography.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, time::{SystemTime, UNIX_EPOCH}};
use subtle::ConstantTimeEq;
use url::Url;

use crate::{Audience, CapabilityIdentity, OAuthError, Result};

pub(crate) const SCOPE: &str = "mcp";
pub(crate) const CLIENT_MAX: usize = 16;
pub(crate) const PROVISIONAL_MAX: usize = 64;
pub(crate) const PENDING_MAX: usize = 32;
pub(crate) const ACCESS_TTL_MS: i64 = 3_600_000;
pub(crate) const GRANT_TTL_MS: i64 = 30 * 86_400_000;
pub(crate) const APPROVAL_TTL_MS: i64 = 600_000;
pub(crate) const CODE_TTL_MS: i64 = 60_000;
pub(crate) const MAX_SAFE_JS_INTEGER: i64 = 9_007_199_254_740_991;

#[derive(Debug, Clone)]
pub(crate) struct Policy {
    pub base: String,
    pub resource: String,
    pub audience: Audience,
}

impl Policy {
    pub fn new(origin: &str, audience: Audience) -> Result<Self> {
        let parsed = Url::parse(origin).map_err(|_| OAuthError::Invalid("invalid_public_origin"))?;
        if parsed.scheme() != "https" || parsed.cannot_be_a_base()
            || parsed.host_str().is_none() || parsed.username() != ""
            || parsed.password().is_some() || parsed.path() != "/"
            || parsed.query().is_some() || parsed.fragment().is_some()
        {
            return Err(OAuthError::Invalid("invalid_public_origin"));
        }
        // URL.origin in the historical sidecar normalizes the original input.
        let base = parsed.origin().ascii_serialization();
        if base == "null" || base.len() > 8096 {
            return Err(OAuthError::Invalid("invalid_public_origin"));
        }
        Ok(Self { resource: format!("{base}/mcp"), base, audience })
    }
    pub fn audience_str(&self) -> &'static str {
        match self.audience { Audience::Missions => "missions", Audience::Workstation => "workstation" }
    }
    pub fn audience_valid(&self, value: Option<&Value>) -> bool {
        match (self.audience, value) {
            (Audience::Missions, None) => true,
            (Audience::Missions, Some(Value::String(s))) if s == "missions" => true,
            (Audience::Workstation, Some(Value::String(s))) if s == "workstation" => true,
            _ => false,
        }
    }
    pub fn authorization_server_metadata(&self) -> Value {
        json!({
            "issuer":self.base,
            "authorization_endpoint":format!("{}/oauth/authorize",self.base),
            "token_endpoint":format!("{}/oauth/token",self.base),
            "registration_endpoint":format!("{}/oauth/register",self.base),
            "revocation_endpoint":format!("{}/oauth/revoke",self.base),
            "response_types_supported":["code"],
            "grant_types_supported":["authorization_code","refresh_token"],
            "code_challenge_methods_supported":["S256"],
            "authorization_response_iss_parameter_supported":true,
            "token_endpoint_auth_methods_supported":["client_secret_post","client_secret_basic"],
            "scopes_supported":[SCOPE]
        })
    }
    pub fn protected_resource_metadata(&self) -> Value {
        json!({
            "resource":self.resource,
            "authorization_servers":[self.base],
            "scopes_supported":[SCOPE],
            "bearer_methods_supported":["header"],
            "resource_name":"Agent Bridge"
        })
    }
}

pub(crate) fn now_ms() -> Result<i64> {
    let ms = SystemTime::now().duration_since(UNIX_EPOCH)
        .map_err(|_| OAuthError::Invalid("system_clock_invalid"))?.as_millis();
    let ms = i64::try_from(ms).map_err(|_| OAuthError::Invalid("system_clock_invalid"))?;
    if ms > MAX_SAFE_JS_INTEGER {
        return Err(OAuthError::Invalid("system_clock_invalid"));
    }
    Ok(ms)
}

pub(crate) fn expiry_ms(now: i64, duration: i64) -> Result<i64> {
    now.checked_add(duration)
        .filter(|n| (0..=MAX_SAFE_JS_INTEGER).contains(n))
        .ok_or(OAuthError::Invalid("expiration_overflow"))
}

pub(crate) fn random_token() -> Result<String> {
    let mut secret = [0u8; 32];
    getrandom::fill(&mut secret)
        .map_err(|_| OAuthError::Uncertain("random_generator_unavailable"))?;
    Ok(URL_SAFE_NO_PAD.encode(secret))
}

pub(crate) fn digest(input: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(input.as_bytes()))
}

pub(crate) fn equal(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.as_bytes().ct_eq(b.as_bytes()).unwrap_u8() == 1
}

pub(crate) fn token_shape(s: &str) -> bool {
    s.len() == 43 && s.bytes().all(|b|
        b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Only the two official MCP-hosted connector callback families are
/// admissible. Registered redirect URIs are subsequently bound EXACTLY to
/// one generated confidential client, its PKCE code and its owner approval.
/// The host-pattern check by itself is NEVER authorization.
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub enum ConnectorClient { Gemini, ChatGpt }
impl ConnectorClient {
    pub(crate) fn name(self) -> &'static str {
        match self { Self::Gemini => "gemini", Self::ChatGpt => "chatgpt" }
    }
    pub(crate) fn id_prefix(self) -> &'static str {
        match self { Self::Gemini => "gemini_", Self::ChatGpt => "chatgpt_" }
    }
    pub(crate) fn callback(self,redirect:&str,registration:bool)->bool {
        match self {
            Self::Gemini => google_callback(redirect,registration),
            Self::ChatGpt => chatgpt_callback(redirect),
        }
    }
    pub(crate) fn matches_id(self,client_id:&str)->bool {
        client_id.starts_with(self.id_prefix())
            && token_shape(&client_id[self.id_prefix().len()..])
    }
}

/// Official ChatGPT MCP callbacks. The stable URI is valid
/// because we advertise RFC 9207 issuer identification AND return exact iss
/// on code/error redirects; callback-ID-specific paths are accepted only
/// when they exactly match the URI supplied by ChatGPT's MCP manager.
/// Never treat an arbitrary chatgpt.com route as a callback.
pub(crate) fn chatgpt_callback(raw:&str)->bool {
    let Ok(url)=Url::parse(raw)else{return false};
    if url.scheme()!="https"||url.host_str()!=Some("chatgpt.com")
        ||url.port().is_some()||!url.username().is_empty()
        ||url.password().is_some()||url.query().is_some()
        ||url.fragment().is_some()||url.path()!=raw.strip_prefix("https://chatgpt.com").unwrap_or("")
    {return false}
    if url.path()=="/connector_platform_oauth_redirect" {return true}
    let Some(id)=url.path().strip_prefix("/connector/oauth/")else{return false};
    !id.is_empty()&&id.len()<=128&&id.bytes().all(|b|
        b.is_ascii_alphanumeric()||b==b'_'||b==b'-')
}
pub(crate) fn callback_family(raw:&str,registration:bool)->Option<ConnectorClient>{
    if ConnectorClient::Gemini.callback(raw,registration){Some(ConnectorClient::Gemini)}
    else if ConnectorClient::ChatGpt.callback(raw,registration){Some(ConnectorClient::ChatGpt)}
    else{None}
}

pub(crate) fn verifier_shape(s: &str) -> bool {
    (43..=128).contains(&s.len()) && s.bytes().all(|b|
        b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
            || b == b'.' || b == b'~')
}

/// Google registered callbacks permit three Google hostnames, but actual
/// authorization is deliberately production-only. No other domain/URL is admitted.
pub(crate) fn google_callback(input: &str, registration: bool) -> bool {
    let Ok(url) = Url::parse(input) else { return false };
    let Some(host) = url.host_str() else { return false };
    if url.scheme() != "https" || url.port().is_some()
        || !url.username().is_empty() || url.password().is_some()
        || url.query().is_some() || url.fragment().is_some()
        || !match host {
            "oauth-redirect.googleusercontent.com" => true,
            "oauth-redirect-sandbox.googleusercontent.com"
            | "oauth-redirect-test.googleusercontent.com" => registration,
            _ => false,
        }
    {
        return false;
    }
    let mut segments = url.path().split('/');
    if segments.next() != Some("") || !matches!(segments.next(), Some("a" | "r")) {
        return false;
    }
    let Some(last) = segments.next() else { return false };
    !last.is_empty() && segments.next().is_none()
        && last.bytes().all(|b| b.is_ascii_alphanumeric()
            || matches!(b, b'.' | b'_' | b'~' | b'-'))
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub(crate) struct Binding {
    pub client_id: String,
    pub redirect: String,
    pub challenge: String,
    pub state: String,
    pub resource: String,
    pub scope: String,
    #[serde(default, skip_serializing_if = "CapabilityIdentity::is_legacy")]
    pub capability: CapabilityIdentity,
}
impl Binding {
    pub fn hash(&self) -> Result<String> { Ok(digest(&serde_json::to_string(self)?)) }
}

#[derive(Clone)]
pub(crate) struct Pending {
    pub binding: Binding,
    pub id: String,
    pub expires: i64,
}
#[derive(Clone)]
pub(crate) struct Code {
    pub binding: Binding,
    pub expires: i64,
}

#[derive(Clone)]
pub(crate) struct Client {
    pub redirects: Vec<String>,
    pub provider: ConnectorClient,
    pub method: String,
    pub secret_hash: String,
    pub created: i64,
    pub expires: i64,
}
impl Client {
    pub fn from_json(value: &Value) -> Option<Self> {
        if revoked_extension(value) { return None }
        let obj = value.as_object()?;
        let redirects: Vec<_> = obj.get("redirects")?.as_array()?.iter()
            .map(|x| x.as_str().map(str::to_owned)).collect::<Option<_>>()?;
        let provider=match obj.get("provider").and_then(Value::as_str) {
            Some("gemini")=>ConnectorClient::Gemini,
            Some("chatgpt")=>ConnectorClient::ChatGpt,
            None if redirects.iter().all(|url|google_callback(url,true))=>
                ConnectorClient::Gemini, // existing Gemini-only state
            _=>return None,
        };
        if redirects.is_empty()||redirects.len()>6
            || !redirects.iter().all(|url|provider.callback(url,true))
        {return None}
        let method = obj.get("method")?.as_str()?.to_owned();
        if !matches!(method.as_str(),"client_secret_basic" | "client_secret_post") { return None }
        let secret_hash=obj.get("secretHash")?.as_str()?.to_owned();
        if !token_shape(&secret_hash) { return None }
        // Historic persistent client expires is its provisional TTL, not a
        // revocation flag. The C# compatibility inspector accepts omission.
        let created = obj.get("created").and_then(Value::as_i64).unwrap_or(0);
        let expires = obj.get("expires").and_then(Value::as_i64).unwrap_or(0);
        Some(Self{redirects,provider,method,secret_hash,created,expires})
    }
    pub fn json(&self) -> Value {
        json!({
            "redirects":self.redirects, "provider":self.provider.name(), "method":self.method,
            "secretHash":self.secret_hash, "created":self.created, "expires":self.expires
        })
    }
}

pub(crate) fn revoked_extension(value: &Value) -> bool {
    let Some(o) = value.as_object() else {return true};
    const REVOCATION: [&str;10] = [
        "revoked", "revokedAt", "revoked_at", "revocation", "revocations",
        "revoked_on", "revokedUntil", "disabled", "tombstones", "revokedGrants"
    ];
    REVOCATION.iter().any(|k| o.contains_key(*k))
        || o.get("state").is_some_and(|v| v.as_str()!=Some("active"))
        || o.get("status").is_some_and(|v| v.as_str()!=Some("active"))
}

pub(crate) fn params(raw: &str, max_len: usize) -> Result<BTreeMap<String,String>> {
    if raw.len()>max_len {return Err(OAuthError::bad("request_too_large",413))}
    let mut out=BTreeMap::new();
    for (key,value) in url::form_urlencoded::parse(raw.as_bytes()) {
        if out.insert(key.into_owned(),value.into_owned()).is_some() {
            return Err(OAuthError::bad("duplicate_parameter",400));
        }
    }
    Ok(out)
}

pub(crate) fn request_json(input: &[u8]) -> Result<Value> {
    if input.len()>16_384 {return Err(OAuthError::bad("request_too_large",413))}
    let snapshot = agent_bridge_oauth_compat::HistoricalSnapshot::from_json_bytes(input)
        .map_err(|_| OAuthError::bad("invalid_request",400))?;
    Ok(snapshot.into_preserved_value())
}

pub(crate) fn basic_client(header: &str) -> Option<(String,String)> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let body = header.strip_prefix("Basic ")?;
    if body.len()>4096 {return None}
    let bytes=STANDARD.decode(body).ok()?;
    let plain=std::str::from_utf8(&bytes).ok()?;
    let (user,secret)=plain.split_once(':')?;
    if user.is_empty() {return None}
    Some((url_decode_component(user)?,url_decode_component(secret)?))
}
fn url_decode_component(s:&str)->Option<String> {
    let mut decoded=Vec::with_capacity(s.len());
    let mut bytes=s.as_bytes().iter().copied();
    while let Some(b)=bytes.next() {
        if b==b'%' {
            let a=(bytes.next()? as char).to_digit(16)?;
            let b=(bytes.next()? as char).to_digit(16)?;
            decoded.push(((a<<4)|b) as u8);
        } else {decoded.push(b);}
    }
    String::from_utf8(decoded).ok()
}
