//! Synthetic-state OAuth boundary checks. No installed state or tokens are read.
use super::*;
use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
const ORIGIN: &str = "https://capability-test.example.invalid";
const RESOURCE: &str = "https://capability-test.example.invalid/mcp";

struct TemporaryState(PathBuf);
impl TemporaryState {
    fn new() -> Self {
        let base = fs::canonicalize(std::env::temp_dir()).unwrap();
        let base = base.to_str().and_then(|path| path.strip_prefix(r"\\?\"))
            .map(PathBuf::from).unwrap_or(base);
        let root = base.join(format!("oauth-capability-test-{}-{}",
            std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        assert!(!root.exists(), "synthetic state must be fresh");
        platform::create_requests(&root).unwrap();
        Self(root)
    }
}
impl Drop for TemporaryState {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}

struct Fixture {
    // Server ownership is dropped before the temporary state directory.
    server: OAuthServer,
    _root: TemporaryState,
    client: String,
    secret: String,
    access: String,
    refresh: String,
    grant: String,
}
impl Fixture {
    fn legacy() -> Self { Self::with_capability(CapabilityIdentity::Legacy) }

    fn with_capability(capability: CapabilityIdentity) -> Self {
        let root = TemporaryState::new();
        let mut server = OAuthServer::open_with_capability(OAuthConfig {
            state_dir: root.0.clone(),
            public_origin: ORIGIN.into(),
            audience: Audience::Workstation,
        }, capability).unwrap();
        let client = format!("gemini_{}", "C".repeat(43));
        let secret = "S".repeat(43);
        let access = "A".repeat(43);
        let refresh = "R".repeat(43);
        let grant = "G".repeat(43);
        let now = now_ms().unwrap();
        server.persist(|data| {
            collection_mut(data, "clients")?.insert(client.clone(), json!({
                "redirects": ["https://oauth-redirect.googleusercontent.com/r/capability-test"],
                "provider": "gemini",
                "method": "client_secret_post",
                "secretHash": digest(&secret),
                "created": now,
                "expires": now + APPROVAL_TTL_MS
            }));
            collection_mut(data, "grants")?.insert(grant.clone(), json!({
                "clientId": client,
                "resource": RESOURCE,
                "scope": "mcp",
                "audience": "workstation",
                "refreshHash": digest(&refresh),
                "expires": now + GRANT_TTL_MS
            }));
            collection_mut(data, "access")?.insert(digest(&access), json!({
                "grant": grant,
                "expires": now + ACCESS_TTL_MS
            }));
            Ok(())
        }).unwrap();
        Self { server, _root: root, client, secret, access, refresh, grant }
    }

    fn access_action(&mut self, access: &str) -> HttpAction {
        let authorization = format!("Bearer {access}");
        self.server.handle_http(HttpRequest {
            method: "POST", target: "/mcp", origin: None,
            authorization: Some(&authorization),
            content_type: Some("application/json"),
            body: br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
        })
    }

    fn refresh_reply(&mut self) -> HttpResponse {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "refresh_token")
            .append_pair("client_id", &self.client)
            .append_pair("client_secret", &self.secret)
            .append_pair("refresh_token", &self.refresh)
            .finish();
        match self.server.handle_http(HttpRequest {
            method: "POST", target: "/oauth/token", origin: None,
            authorization: None,
            content_type: Some("application/x-www-form-urlencoded"),
            body: body.as_bytes(),
        }) {
            HttpAction::Reply(reply) => reply,
            HttpAction::McpAuthorized(_) => panic!("token route must not dispatch MCP"),
        }
    }

    fn set_grant_capability(&mut self, capability: Value) {
        let id = self.grant.clone();
        self.server.persist(|data| {
            collection_mut(data, "grants")?.get_mut(&id).unwrap()
                .as_object_mut().unwrap().insert("capability".into(), capability);
            Ok(())
        }).unwrap();
    }
}

fn invalid_capabilities() -> Vec<Value> {
    vec![
        Value::Null,
        json!({}),
        json!({"kind":"future-v2"}),
        json!({"kind":"unified-v1","manifest_sha256":"ab".repeat(32),
            "catalogue_sha256":"cd".repeat(32),"policy_version":1}),
        json!({"kind":"unified-v1","manifest_sha256":"bad",
            "catalogue_sha256":"00".repeat(32),"policy_version":1}),
        json!({"kind":"unified-v1","manifest_sha256":"ab".repeat(32),
            "catalogue_sha256":"cd".repeat(32),"policy_version":2}),
        json!({"kind":"legacy","unexpected":true}),
    ]
}

#[test]
fn capability_http_rejects_present_unknown_or_malformed_access_identity() {
    for (case, capability) in invalid_capabilities().into_iter().enumerate() {
        let mut fixture = Fixture::legacy();
        let access = fixture.access.clone();
        assert!(matches!(fixture.access_action(&access), HttpAction::McpAuthorized(_)),
            "synthetic legacy control must authenticate");
        fixture.set_grant_capability(capability);
        match fixture.access_action(&access) {
            HttpAction::Reply(reply) => assert_eq!(reply.status, 401),
            HttpAction::McpAuthorized(_) =>
                panic!("present malformed capability must not fall back to legacy authority: case {case}"),
        }
    }
}

#[test]
fn capability_http_rejects_present_unknown_or_malformed_refresh_identity() {
    for (case, capability) in invalid_capabilities().into_iter().enumerate() {
        let mut fixture = Fixture::legacy();
        fixture.set_grant_capability(capability);
        let reply = fixture.refresh_reply();
        assert_eq!(reply.status, 400,
            "refresh must reject malformed capability before issuing any token: case {case}");
        let body: Value = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(body["error"], "invalid_grant");
    }
}

#[test]
fn capability_http_legacy_refresh_keeps_historical_record_and_token_behavior() {
    let mut fixture = Fixture::legacy();
    let old_access = fixture.access.clone();
    let reply = fixture.refresh_reply();
    assert_eq!(reply.status, 200);
    let body: Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(body["refresh_token"].as_str(), Some(fixture.refresh.as_str()),
        "legacy refresh tokens retain their nonrotating protocol");
    assert_eq!(body["scope"], "mcp");
    let new_access = body["access_token"].as_str().unwrap();
    assert!(matches!(fixture.access_action(new_access), HttpAction::McpAuthorized(_)));
    assert!(matches!(fixture.access_action(&old_access), HttpAction::McpAuthorized(_)));
    assert!(fixture.server.data["grants"][&fixture.grant].get("capability").is_none(),
        "refresh must not silently add or promote a legacy capability marker");
}

fn unified_identity() -> CapabilityIdentity {
    CapabilityIdentity::UnifiedV1 {
        manifest_sha256: "ab".repeat(32),
        catalogue_sha256: "cd".repeat(32),
        policy_version: 1,
    }
}

impl Fixture {
    fn owner(&self) -> LocalOwner {
        LocalOwner::open(OAuthConfig { state_dir: self._root.0.clone(),
            public_origin: ORIGIN.into(), audience: Audience::Workstation }).unwrap()
    }

    fn authorize_reply(&mut self) -> HttpResponse {
        let challenge = digest(&"V".repeat(43));
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.client)
            .append_pair("redirect_uri", "https://oauth-redirect.googleusercontent.com/r/capability-test")
            .append_pair("code_challenge_method", "S256")
            .append_pair("code_challenge", &challenge)
            .append_pair("state", "synthetic-state")
            .append_pair("scope", "mcp")
            .append_pair("resource", RESOURCE)
            // A remote client cannot choose the internal contract.
            .append_pair("capability", "unified-v1")
            .finish();
        let target = format!("/oauth/authorize?{query}");
        match self.server.handle_http(HttpRequest {
            method: "GET", target: &target, origin: None, authorization: None,
            content_type: None, body: b"",
        }) {
            HttpAction::Reply(reply) => reply,
            HttpAction::McpAuthorized(_) => panic!("authorize route must not dispatch MCP"),
        }
    }

    fn exchange_code_reply(&mut self, code: &str) -> HttpResponse {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "authorization_code")
            .append_pair("client_id", &self.client)
            .append_pair("client_secret", &self.secret)
            .append_pair("redirect_uri", "https://oauth-redirect.googleusercontent.com/r/capability-test")
            .append_pair("code", code)
            .append_pair("code_verifier", &"V".repeat(43)).finish();
        match self.server.handle_http(HttpRequest {
            method: "POST", target: "/oauth/token", origin: None, authorization: None,
            content_type: Some("application/x-www-form-urlencoded"), body: body.as_bytes(),
        }) {
            HttpAction::Reply(reply) => reply,
            HttpAction::McpAuthorized(_) => panic!("token route must not dispatch MCP"),
        }
    }

    fn approved_code(&mut self) -> String {
        let request = self.owner().pending_requests().unwrap().pop().unwrap();
        self.owner().approve_request(&request.id, |_| true).unwrap();
        let reply = self.authorize_reply();
        assert_eq!(reply.status, 302);
        let location = reply.headers.iter().find(|(name, _)| name == "location").unwrap();
        let url = url::Url::parse(&location.1).unwrap();
        assert_eq!(url.host_str(), Some("oauth-redirect.googleusercontent.com"));
        assert!(url.query_pairs().any(|(key,value)| key == "iss" && value == ORIGIN));
        url.query_pairs().find(|(key, _)| key == "code").unwrap().1.into_owned()
    }
}

#[test]
fn capability_http_new_authorization_binds_exact_local_identity_through_refresh() {
    let identity = unified_identity();
    let marker = serde_json::to_value(&identity).unwrap();
    let mut fixture = Fixture::with_capability(identity.clone());
    let reply = fixture.authorize_reply();
    assert_eq!(reply.status, 200);
    let pending = fixture.server.pending.values().next().unwrap();
    let request_path = fixture._root.0.join("requests-workstation").join(format!("{}.json", pending.id));
    let request: Value = serde_json::from_slice(&fs::read(request_path).unwrap()).unwrap();
    assert_eq!(request.get("capability"), Some(&marker),
        "owner review must bind the locally selected contract, not a client parameter");
    let code = fixture.approved_code();
    let reply = fixture.exchange_code_reply(&code);
    assert_eq!(reply.status, 200);
    let tokens: Value = serde_json::from_slice(&reply.body).unwrap();
    let access = tokens["access_token"].as_str().unwrap();
    match fixture.access_action(access) {
        HttpAction::McpAuthorized(identity_after) => assert_eq!(identity_after.capability, identity),
        _ => panic!("approved unified token must authenticate to its exact contract"),
    }
    let grant_id = fixture.server.data["access"][digest(access)]["grant"].as_str().unwrap().to_owned();
    assert_eq!(fixture.server.data["grants"][&grant_id]["capability"], marker);
    fixture.refresh = tokens["refresh_token"].as_str().unwrap().to_owned();
    let refreshed = fixture.refresh_reply();
    assert_eq!(refreshed.status, 200);
    assert_eq!(fixture.server.data["grants"][&grant_id]["capability"], marker,
        "refresh must preserve the contract identity byte-for-value");
    assert!(fixture.server.data["grants"][&fixture.grant].get("capability").is_none(),
        "new unified consent must not rewrite the existing legacy grant");
}

#[test]
fn capability_http_active_unified_does_not_promote_legacy_refresh() {
    let mut fixture = Fixture::with_capability(unified_identity());
    let reply = fixture.refresh_reply();
    assert_eq!(reply.status, 200);
    let tokens: Value = serde_json::from_slice(&reply.body).unwrap();
    match fixture.access_action(tokens["access_token"].as_str().unwrap()) {
        HttpAction::McpAuthorized(identity) => assert_eq!(identity.capability, CapabilityIdentity::Legacy),
        _ => panic!("legacy refresh remains valid while unified is selected"),
    }
    assert!(fixture.server.data["grants"][&fixture.grant].get("capability").is_none());
}

#[test]
fn capability_http_remote_selection_cannot_elevate_legacy_authorization() {
    let mut fixture = Fixture::legacy();
    assert_eq!(fixture.authorize_reply().status, 200);
    let pending = fixture.server.pending.values().next().unwrap();
    let expected_binding = json!({
        "clientId": fixture.client,
        "redirect": "https://oauth-redirect.googleusercontent.com/r/capability-test",
        "challenge": digest(&"V".repeat(43)), "state": "synthetic-state",
        "resource": RESOURCE, "scope": "mcp"
    });
    assert_eq!(pending.binding.hash().unwrap(), digest(&expected_binding.to_string()),
        "legacy binding serialization must remain exact");
    let code = fixture.approved_code();
    let reply = fixture.exchange_code_reply(&code);
    assert_eq!(reply.status, 200);
    let tokens: Value = serde_json::from_slice(&reply.body).unwrap();
    match fixture.access_action(tokens["access_token"].as_str().unwrap()) {
        HttpAction::McpAuthorized(identity) => assert_eq!(identity.capability, CapabilityIdentity::Legacy),
        _ => panic!("legacy approval must issue a legacy token"),
    }
}

impl Fixture {
    fn reopen(self, capability: CapabilityIdentity) -> Self {
        let Self { server, _root, client, secret, access, refresh, grant } = self;
        drop(server);
        let server = OAuthServer::open_with_capability(OAuthConfig {
            state_dir: _root.0.clone(), public_origin: ORIGIN.into(), audience: Audience::Workstation,
        }, capability).unwrap();
        Self { server, _root, client, secret, access, refresh, grant }
    }
}

#[test]
fn capability_owner_review_rechecks_exact_identity_before_approving() {
    let mut fixture = Fixture::with_capability(unified_identity());
    assert_eq!(fixture.authorize_reply().status, 200);
    let request = fixture.owner().pending_requests().unwrap().pop().unwrap();
    assert_eq!(request.capability, unified_identity());
    let request_path = fixture._root.0.join("requests-workstation").join(format!("{}.json", request.id));
    let owner = fixture.owner();
    let result = owner.approve_request(&request.id, |reviewed| {
        assert_eq!(reviewed.capability, unified_identity());
        let mut changed: Value = serde_json::from_slice(&fs::read(&request_path).unwrap()).unwrap();
        changed["capability"]["catalogue_sha256"] = json!("ef".repeat(32));
        fs::write(&request_path, serde_json::to_vec(&changed).unwrap()).unwrap();
        true
    });
    assert!(result.is_err(), "raced contract replacement must not receive approval");
    assert!(fixture.server.codes.is_empty());
}

#[test]
fn capability_http_rejects_changed_approval_without_spending_a_code() {
    let mut fixture = Fixture::with_capability(unified_identity());
    assert_eq!(fixture.authorize_reply().status, 200);
    let request = fixture.owner().pending_requests().unwrap().pop().unwrap();
    fixture.owner().approve_request(&request.id, |_| true).unwrap();
    let approval_path = fixture._root.0.join("requests-workstation").join(format!("{}.approved", request.id));
    let mut approval: Value = serde_json::from_slice(&fs::read(&approval_path).unwrap()).unwrap();
    approval["capability"]["manifest_sha256"] = json!("ef".repeat(32));
    fs::write(&approval_path, serde_json::to_vec(&approval).unwrap()).unwrap();
    assert_eq!(fixture.authorize_reply().status, 403);
    assert!(fixture.server.codes.is_empty());
    assert_eq!(fixture.server.data["grants"].as_object().unwrap().len(), 1);
}

#[test]
fn capability_http_restart_preserves_grant_identity_and_refuses_other_contract() {
    let mut fixture = Fixture::with_capability(unified_identity());
    assert_eq!(fixture.authorize_reply().status, 200);
    let code = fixture.approved_code();
    let reply = fixture.exchange_code_reply(&code);
    let tokens: Value = serde_json::from_slice(&reply.body).unwrap();
    let access = tokens["access_token"].as_str().unwrap().to_owned();
    fixture.refresh = tokens["refresh_token"].as_str().unwrap().to_owned();
    let mut fixture = fixture.reopen(unified_identity());
    assert!(matches!(fixture.access_action(&access), HttpAction::McpAuthorized(_)));
    assert_eq!(fixture.refresh_reply().status, 200);
    let changed = CapabilityIdentity::UnifiedV1 {
        manifest_sha256: "ef".repeat(32), catalogue_sha256: "cd".repeat(32), policy_version: 1,
    };
    let mut fixture = fixture.reopen(changed);
    assert!(matches!(fixture.access_action(&access), HttpAction::Reply(HttpResponse { status: 401, .. })));
    assert_eq!(fixture.refresh_reply().status, 400);
    let legacy_access = fixture.access.clone();
    assert!(matches!(fixture.access_action(&legacy_access), HttpAction::McpAuthorized(_)),
        "unsupported unified identity must not invalidate independent legacy grants");
}

#[test]
fn capability_http_old_pending_approval_cannot_promote_after_restart() {
    let mut fixture = Fixture::legacy();
    assert_eq!(fixture.authorize_reply().status, 200);
    let old_request = fixture.owner().pending_requests().unwrap().pop().unwrap();
    assert_eq!(old_request.capability, CapabilityIdentity::Legacy);
    let mut fixture = fixture.reopen(unified_identity());
    fixture.owner().approve_request(&old_request.id, |_| true).unwrap();
    assert_eq!(fixture.authorize_reply().status, 200,
        "an old approval cannot complete a newly selected contract");
    let pending = fixture.server.pending.values().next().unwrap();
    assert_ne!(pending.id, old_request.id);
    assert_eq!(pending.binding.capability, unified_identity());
    assert!(fixture.server.codes.is_empty());
}


#[test]
fn capability_owner_refuses_ambiguous_nested_identity_keys() {
    let mut fixture = Fixture::with_capability(unified_identity());
    assert_eq!(fixture.authorize_reply().status, 200);
    let request = fixture.owner().pending_requests().unwrap().pop().unwrap();
    let path = fixture._root.0.join("requests-workstation").join(format!("{}.json", request.id));
    let source = fs::read_to_string(&path).unwrap();
    let ambiguous = source.replace("\"kind\":\"unified-v1\"", "\"kind\":\"legacy\",\"kind\":\"unified-v1\"");
    assert_ne!(source, ambiguous);
    fs::write(path, ambiguous).unwrap();
    assert!(fixture.owner().pending_requests().is_err(),
        "duplicate nested identity keys must not produce an approvable request");
}

#[test]
fn capability_manifest_seal_is_separate_immutable_private_and_matches_selected_identity() {
    use sha2::{Digest, Sha256};
    let root=TemporaryState::new();
    let config=OAuthConfig{state_dir:root.0.clone(),public_origin:ORIGIN.into(),audience:Audience::Workstation};
    let legacy=OAuthServer::open(config.clone()).unwrap();
    let bytes=format!(r#"{{"catalogue_sha256":"{}","policy_version":1,"selection":"fixture"}}"#,"a".repeat(64)).into_bytes();
    assert!(legacy.bind_capability_manifest(&bytes).is_err());
    drop(legacy);
    let hash:String=Sha256::digest(&bytes).iter().map(|byte|format!("{byte:02x}")).collect();
    let identity=CapabilityIdentity::UnifiedV1{manifest_sha256:hash.clone(),
        catalogue_sha256:"a".repeat(64),policy_version:1};
    let server=OAuthServer::open_with_capability(config,identity).unwrap();
    let legacy_marker=root.0.join(".agent-bridge-workstation-scope-v2.json");
    fs::write(&legacy_marker,b"synthetic unchanged legacy marker").unwrap();
    server.bind_capability_manifest(&bytes).expect("a matching local seal must be persisted separately");
    server.bind_capability_manifest(&bytes).unwrap();
    assert_eq!(fs::read(&legacy_marker).unwrap(),b"synthetic unchanged legacy marker");
    let seal=root.0.join(format!("unified-v1-{hash}.json"));
    assert_eq!(fs::read(&seal).unwrap(),bytes);
    assert!(server.bind_capability_manifest(b"changed").is_err());
    fs::write(&seal,b"tampered").unwrap();
    assert!(server.bind_capability_manifest(&bytes).is_err(),"an existing seal is never replaced");
    assert_eq!(fs::read(&seal).unwrap(),b"tampered");
}
