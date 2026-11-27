use agent_bridge_extensions::oauth::{ClientAuthMethod, OAuthServerConfig};
#[cfg(windows)]
use agent_bridge_extensions::oauth::{run_oauth_flow, OAuthTokenStore};
use agent_bridge_extensions::{
    config_sha256, fetch_https_bytes, validate_proposed_endpoint, valid_server_name, Registry,
    ServerControl, ToolScope,
};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

fn canonical_descriptor_hash(v: &Value) -> String {
    let mut c = v.clone();
    c.sort_all_objects();
    hex::encode(Sha256::digest(c.to_string().as_bytes()))
}

fn sample_mcp_docs_registry() -> Vec<u8> {
    let descriptor = json!({
        "name": "search_model_context_protocol",
        "description": "Search the public MCP documentation",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": { "type": "string" }
            }
        }
    });
    let hash = canonical_descriptor_hash(&descriptor);
    serde_json::to_vec(&json!({
        "version": 1,
        "servers": {
            "mcp_docs": {
                "endpoint": "https://modelcontextprotocol.io/mcp",
                "tools": {
                    "search_model_context_protocol": {
                        "descriptor_sha256": hash,
                        "descriptor": descriptor,
                        "parameters": {
                            "query": { "type": "search_terms" }
                        }
                    }
                }
            }
        }
    }))
    .unwrap()
}

#[test]
fn registry_parse_allowlist_and_tamper_regressions() {
    let raw = sample_mcp_docs_registry();
    let reg = Registry::parse(&raw).expect("valid mcp_docs registry");
    assert!(reg.has_server("mcp_docs"));
    assert_eq!(reg.list(), vec!["mcp_docs:search_model_context_protocol"]);
    assert_eq!(config_sha256(&raw).len(), 64);

    let searched = reg.search_cached("docs", None, 10).expect("search_cached");
    assert!(!searched["tools"].as_array().unwrap().is_empty());
    let inspected = reg
        .inspect_cached("mcp_docs:search_model_context_protocol")
        .expect("inspect_cached");
    assert_eq!(inspected["name"], "mcp_docs:search_model_context_protocol");

    // Regression: public MCP documentation forbids bearer credentials
    let with_bearer = serde_json::to_vec(&json!({
        "version": 1,
        "servers": {
            "mcp_docs": {
                "endpoint": "https://modelcontextprotocol.io/mcp",
                "bearer_env": "AGENT_BRIDGE_EXTENSION_TOKEN",
                "tools": {}
            }
        }
    }))
    .unwrap();
    assert!(Registry::parse(&with_bearer).is_err());

    // Regression: unallowlisted tool (e.g. get_model_context_protocol_page) rejected at parse time
    let unallowlisted = serde_json::to_vec(&json!({
        "version": 1,
        "servers": {
            "mcp_docs": {
                "endpoint": "https://modelcontextprotocol.io/mcp",
                "tools": {
                    "get_model_context_protocol_page": {
                        "descriptor_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "parameters": { "url": { "type": "search_terms" } }
                    }
                }
            }
        }
    }))
    .unwrap();
    assert!(Registry::parse(&unallowlisted).is_err());

    // Regression: tampered descriptor_sha256 rejected at parse time
    let tampered = serde_json::to_vec(&json!({
        "version": 1,
        "servers": {
            "mcp_docs": {
                "endpoint": "https://modelcontextprotocol.io/mcp",
                "tools": {
                    "search_model_context_protocol": {
                        "descriptor_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
                        "descriptor": { "name": "search_model_context_protocol", "inputSchema": { "type": "object", "properties": {} } },
                        "parameters": { "query": { "type": "search_terms" } }
                    }
                }
            }
        }
    }))
    .unwrap();
    assert!(Registry::parse(&tampered).is_err());

    // Microsoft Learn: the same public, tokenless, one-query search adapter.
    let learn_descriptor = json!({"name": "microsoft_docs_search",
        "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}}});
    let learn = |tool: &str, descriptor: Value, bearer: bool| {
        let mut server = json!({"endpoint": "https://learn.microsoft.com/api/mcp", "tools": {tool: {
            "descriptor_sha256": canonical_descriptor_hash(&descriptor), "descriptor": descriptor,
            "parameters": {"query": {"type": "search_terms"}}}}});
        if bearer { server["bearer_env"] = json!("AGENT_BRIDGE_EXTENSION_TOKEN"); }
        serde_json::to_vec(&json!({"version": 1, "servers": {"microsoft_learn": server}})).unwrap()
    };
    let reg = Registry::parse(&learn("microsoft_docs_search", learn_descriptor.clone(), false))
        .expect("valid microsoft_learn registry");
    assert_eq!(reg.list(), vec!["microsoft_learn:microsoft_docs_search"]);
    assert!(Registry::parse(&learn("microsoft_docs_search", learn_descriptor, true)).is_err());
    let fetch = json!({"name": "microsoft_docs_fetch",
        "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}}});
    assert!(Registry::parse(&learn("microsoft_docs_fetch", fetch, false)).is_err());
    let mut widened: Value = serde_json::from_slice(&learn("microsoft_docs_search",
        json!({"name": "microsoft_docs_search"}), false)).unwrap();
    widened["servers"]["microsoft_learn"]["tools"]["microsoft_docs_search"]["parameters"]["language"] =
        json!({"type": "search_terms"});
    assert!(Registry::parse(&serde_json::to_vec(&widened).unwrap()).is_err(),
        "Learn search must keep exactly one bounded query");
    let mut tampered: Value = serde_json::from_slice(&learn("microsoft_docs_search",
        json!({"name": "microsoft_docs_search"}), false)).unwrap();
    tampered["servers"]["microsoft_learn"]["tools"]["microsoft_docs_search"]["descriptor_sha256"] = json!("0".repeat(64));
    assert!(Registry::parse(&serde_json::to_vec(&tampered).unwrap()).is_err());
    assert!(agent_bridge_extensions::public_docs_server("microsoft_learn"));
    assert!(!agent_bridge_extensions::public_docs_server("other_server"));
}

#[test]
fn auth_status_truthful_outbound_oauth_gap_and_controls_regressions() {
    let raw = sample_mcp_docs_registry();
    let reg = Registry::parse(&raw).expect("parse");
    let fp = reg
        .server_sha256("mcp_docs")
        .unwrap()
        .expect("server sha256");

    assert!(reg.auth_status("absent_server", None).unwrap().is_none());

    // 1. No local decision -> truthful local-only status, outbound_oauth=not_implemented, remote=unknown
    let s_none = reg
        .auth_status("mcp_docs", None)
        .unwrap()
        .expect("status");
    assert_eq!(s_none["local_control"], "no_local_decision");
    assert_eq!(s_none["outbound_oauth"], "not_implemented");
    assert_eq!(s_none["remote_oauth_state"], "unknown");
    assert_eq!(s_none["bearer_reference_configured"], false);

    // 2. Changed fingerprint -> configuration_changed
    let stale_ctrl = ServerControl {
        enabled: true,
        config_sha256: "f".repeat(64),
    };
    let s_changed = reg
        .auth_status("mcp_docs", Some(&stale_ctrl))
        .unwrap()
        .unwrap();
    assert_eq!(s_changed["local_control"], "configuration_changed");
    assert_eq!(s_changed["outbound_oauth"], "not_implemented");
    assert_eq!(s_changed["remote_oauth_state"], "unknown");

    // 3. Disabled server -> disabled, and with_controls blocks inspect_cached & call
    let dis_ctrl = ServerControl {
        enabled: false,
        config_sha256: fp.clone(),
    };
    let mut map = BTreeMap::new();
    map.insert("mcp_docs".to_owned(), dis_ctrl.clone());
    let disabled_reg = Registry::parse(&raw)
        .unwrap()
        .with_controls(&map)
        .unwrap();
    let s_dis = disabled_reg
        .auth_status("mcp_docs", Some(&dis_ctrl))
        .unwrap()
        .unwrap();
    assert_eq!(s_dis["local_control"], "disabled");
    assert!(disabled_reg
        .inspect_cached("mcp_docs:search_model_context_protocol")
        .is_err());
    assert!(disabled_reg
        .call("mcp_docs:search_model_context_protocol", &Map::new(), ToolScope::DataOperations)
        .is_err());

    // 4. Enabled server with exact fingerprint
    let en_ctrl = ServerControl {
        enabled: true,
        config_sha256: fp,
    };
    let mut en_map = BTreeMap::new();
    en_map.insert("mcp_docs".to_owned(), en_ctrl.clone());
    let enabled_reg = Registry::parse(&raw)
        .unwrap()
        .with_controls(&en_map)
        .unwrap();
    let s_en = enabled_reg
        .auth_status("mcp_docs", Some(&en_ctrl))
        .unwrap()
        .unwrap();
    assert_eq!(s_en["local_control"], "enabled");
    assert_eq!(s_en["outbound_oauth"], "not_implemented");
    assert_eq!(s_en["remote_oauth_state"], "unknown");
}

#[test]
fn endpoint_validation_and_refresh_scope_gap_regressions() {
    assert!(valid_server_name("mcp_docs"));
    assert!(!valid_server_name("../bad"));
    assert!(!valid_server_name(""));

    // Remote HTTP rejected; remote HTTPS & loopback HTTP accepted
    let remote_http = format!("{}://example.com/mcp", "http");
    let loopback_http = format!("{}://{}:8080/mcp", "http", "127.0.0.1");
    assert!(validate_proposed_endpoint(&remote_http).is_err());
    assert!(validate_proposed_endpoint("https://modelcontextprotocol.io/mcp").is_ok());
    assert!(validate_proposed_endpoint(&loopback_http).is_ok());

    // Gap: remote refresh is strictly limited to mcp_docs
    let reg = Registry::parse(&sample_mcp_docs_registry()).unwrap();
    let err = reg
        .refresh_public_docs("other_server")
        .expect_err("non-mcp_docs refresh must be refused");
    assert!(
        err.to_string().contains("not supported"),
        "unexpected error: {err}"
    );
}

#[test]
fn fetch_https_bytes_fail_closed_regressions() {
    let insecure = format!("{}://example.invalid/skill.zip", "http");
    assert!(fetch_https_bytes(&insecure, 1024).is_err());
    assert!(fetch_https_bytes("https://user:pass@example.invalid/skill.zip", 1024).is_err());
    assert!(fetch_https_bytes("https://example.invalid/skill.zip#frag", 1024).is_err());
    assert!(fetch_https_bytes("https://example.invalid/skill.zip", 0).is_err());
}

#[cfg(windows)]
#[test]
fn outbound_oauth_pkce_s256_dpapi_store_and_disconnect_regressions() {
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
    use std::sync::{Arc, Mutex};
    use std::thread;

    let dir = { let t = std::env::temp_dir(); if cfg!(unix) { std::fs::canonicalize(&t).unwrap_or(t) } else { t } }.join(format!("ab-ext-oauth-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // Start a real local loopback OAuth 2.1 mock authorization & token server
    let listener = TcpListener::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
        .expect("bind mock oauth server");
    let port = listener.local_addr().unwrap().port();
    let base = format!("{}://{}:{port}", "http", "127.0.0.1");
    let endpoint = format!("{base}/mcp");

    let captured_challenge = Arc::new(Mutex::new(String::new()));
    let captured_challenge_srv = Arc::clone(&captured_challenge);
    let base_srv = base.clone();

    let server_thread = thread::spawn(move || {
        // Handle 3 requests: /.well-known/oauth-protected-resource (optional 404),
        // /.well-known/oauth-authorization-server, /token
        for _ in 0..4 {
            let Ok((mut stream, _)) = listener.accept() else { break };
            let mut buf = [0u8; 8192];
            let Ok(n) = stream.read(&mut buf) else { continue };
            let req = String::from_utf8_lossy(&buf[..n]).into_owned();
            let first = req.lines().next().unwrap_or("");
            let path = first.split_whitespace().nth(1).unwrap_or("");

            if path == "/.well-known/oauth-protected-resource" {
                let body = json!({"authorization_servers": [base_srv]}).to_string();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
            } else if path == "/.well-known/oauth-authorization-server" {
                let body = json!({
                    "issuer": base_srv,
                    "authorization_endpoint": format!("{base_srv}/authorize"),
                    "token_endpoint": format!("{base_srv}/token"),
                    "code_challenge_methods_supported": ["S256"]
                })
                .to_string();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
            } else if path == "/token" {
                let body_part = req.split("\r\n\r\n").nth(1).unwrap_or("");
                let mut verifier = String::new();
                let mut code = String::new();
                for pair in body_part.split('&') {
                    if let Some((k, v)) = pair.split_once('=') {
                        if k == "code_verifier" { verifier = v.to_owned(); }
                        if k == "code" { code = v.to_owned(); }
                    }
                }
                assert_eq!(code, "auth_code_12345");
                // Verify Basic Auth header for confidential client
                assert!(
                    req.lines().any(|l| l.to_ascii_lowercase().starts_with("authorization: basic ")),
                    "expected Basic auth header: {req}"
                );
                // Verify PKCE S256 matches challenge captured during /authorize
                let digest = Sha256::digest(verifier.as_bytes());
                const ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
                let mut b64 = String::new();
                let mut chunks = digest.chunks_exact(3);
                for c in &mut chunks {
                    let v = (u32::from(c[0]) << 16) | (u32::from(c[1]) << 8) | u32::from(c[2]);
                    b64.push(ALPHA[((v >> 18) & 63) as usize] as char);
                    b64.push(ALPHA[((v >> 12) & 63) as usize] as char);
                    b64.push(ALPHA[((v >> 6) & 63) as usize] as char);
                    b64.push(ALPHA[(v & 63) as usize] as char);
                }
                if let [a, b] = chunks.remainder() {
                    let v = (u32::from(*a) << 16) | (u32::from(*b) << 8);
                    b64.push(ALPHA[((v >> 18) & 63) as usize] as char);
                    b64.push(ALPHA[((v >> 12) & 63) as usize] as char);
                    b64.push(ALPHA[((v >> 6) & 63) as usize] as char);
                }
                assert_eq!(b64, *captured_challenge_srv.lock().unwrap());

                let tok = json!({
                    "access_token": "secret_access_token_xyz_999",
                    "refresh_token": "secret_refresh_token_abc_888",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "scope": "mcp:read"
                })
                .to_string();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{tok}",
                    tok.len()
                );
                let _ = stream.write_all(resp.as_bytes());
                break;
            }
        }
    });

    std::env::set_var("AGENT_BRIDGE_EXTENSION_TEST_OAUTH_SECRET", "top_secret_client_pw");
    let cfg = OAuthServerConfig {
        enabled: true,
        scope: Some("mcp:read".into()),
        client_id: Some("bridge-client-1".into()),
        client_auth_method: Some(ClientAuthMethod::ClientSecretBasic),
        client_secret_env: Some("AGENT_BRIDGE_EXTENSION_TEST_OAUTH_SECRET".into()),
    };

    let ch_clone = Arc::clone(&captured_challenge);
    let receipt = run_oauth_flow(&dir, "demo_oauth", &endpoint, &cfg, false, move |auth_url| {
        // Parse authorization URL, verify PKCE S256, and simulate browser redirect to loopback callback
        let query = auth_url.split_once('?').unwrap().1;
        let mut redirect_uri = String::new();
        let mut state = String::new();
        let mut challenge = String::new();
        let mut method = String::new();
        for pair in query.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                let dec = v.replace("%3A", ":").replace("%2F", "/");
                match k {
                    "redirect_uri" => redirect_uri = dec,
                    "state" => state = dec,
                    "code_challenge" => challenge = dec,
                    "code_challenge_method" => method = dec,
                    _ => {}
                }
            }
        }
        assert_eq!(method, "S256");
        *ch_clone.lock().unwrap() = challenge;

        // Extract callback port from redirect_uri and send GET /callback?code=...&state=...
        let host_port = redirect_uri.split("://").nth(1).unwrap().split('/').next().unwrap();
        let cb_port: u16 = host_port.split(':').nth(1).unwrap().parse().unwrap();
        thread::spawn(move || {
            let mut s = TcpStream::connect((Ipv4Addr::LOCALHOST, cb_port)).unwrap();
            let req = format!(
                "GET /callback?code=auth_code_12345&state={state} HTTP/1.1\r\nHost: 127.0.0.1:{cb_port}\r\nConnection: close\r\n\r\n"
            );
            s.write_all(req.as_bytes()).unwrap();
            let mut sink = [0u8; 512];
            let _ = s.read(&mut sink);
        });
        Ok(())
    })
    .expect("run_oauth_flow succeeded");

    let _ = server_thread.join();

    assert_eq!(receipt["authorized"], true);
    assert_eq!(receipt["token_stored"], true);
    assert_eq!(receipt["has_refresh_token"], true);
    assert_eq!(receipt["storage_protection"], "windows_dpapi");

    // 1. Verify raw file on disk does NOT contain plaintext access_token or refresh_token (DPAPI encrypted!)
    let raw_store = std::fs::read_to_string(dir.join(".extensions-oauth-tokens.json")).unwrap();
    assert!(!raw_store.contains("secret_access_token_xyz_999"), "access token leaked in plaintext!");
    assert!(!raw_store.contains("secret_refresh_token_abc_888"), "refresh token leaked in plaintext!");
    assert!(raw_store.contains("windows_dpapi"));

    // 2. Verify load_status returns non-secret metadata
    let status = OAuthTokenStore::load_status(&dir, "demo_oauth").unwrap();
    assert!(status.token_stored);
    assert!(!status.token_expired);
    assert!(status.has_refresh_token);
    assert_eq!(status.storage_protection, "windows_dpapi");

    // 3. Verify load_access_token decrypts exact token for matching endpoint & rejects mismatched endpoint
    let decrypted = OAuthTokenStore::load_access_token(&dir, "demo_oauth", &endpoint).unwrap();
    assert_eq!(decrypted.as_deref(), Some("secret_access_token_xyz_999"));
    assert_eq!(
        OAuthTokenStore::load_access_token(&dir, "demo_oauth", "https://wrong.invalid/mcp").unwrap(),
        None
    );

    // 4. Re-running run_oauth_flow with force=false returns already_authorized without hitting network
    let cached = run_oauth_flow(&dir, "demo_oauth", &endpoint, &cfg, false, |_| {
        panic!("should not reopen auth URL when unexpired token is stored and force=false");
    })
    .expect("cached auth_start");
    assert_eq!(cached["already_authorized"], true);

    // 5. Verify Registry::auth_status_with_oauth reports truthful combined status
    let reg = Registry::parse(&sample_mcp_docs_registry()).unwrap();
    let combined = reg
        .auth_status_with_oauth("mcp_docs", None, Some(&cfg), Some(&status))
        .unwrap()
        .unwrap();
    assert_eq!(combined["oauth_configured"], true);
    assert_eq!(combined["outbound_oauth"], "configured");
    assert_eq!(combined["token_stored"], true);
    assert_eq!(combined["has_refresh_token"], true);
    assert_eq!(combined["oauth_client_secret_env_configured"], true);
    assert_eq!(combined["storage_protection"], "windows_dpapi");
    assert_eq!(combined["remote_oauth_state"], "unknown");

    // 6. Verify delete_token removes token idempotently
    assert_eq!(OAuthTokenStore::delete_token(&dir, "demo_oauth").unwrap(), true);
    assert_eq!(OAuthTokenStore::delete_token(&dir, "demo_oauth").unwrap(), false);
    let after_del = OAuthTokenStore::load_status(&dir, "demo_oauth").unwrap();
    assert!(!after_del.token_stored);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn outbound_oauth_pkce_s256_and_config_validation_cross_platform() {
    use agent_bridge_extensions::oauth::{
        generate_pkce_s256, storage_protection_label, valid_secret_env_name,
    };

    // 1. PKCE S256 generation works on Windows, macOS, and Linux
    let (v1, c1) = generate_pkce_s256().expect("pkce 1");
    let (v2, c2) = generate_pkce_s256().expect("pkce 2");
    assert_ne!(v1, v2);
    assert_ne!(c1, c2);
    assert!(v1.len() >= 43 && c1.len() >= 43);

    // 2. Secret env var allowlist enforcement
    assert!(valid_secret_env_name("AGENT_BRIDGE_EXTENSION_CLIENT_SECRET"));
    assert!(!valid_secret_env_name("RAW_SECRET"));
    assert!(!valid_secret_env_name("AGENT_BRIDGE_EXTENSION_lowercase"));

    // 3. OAuthServerConfig validation (disabled config cannot hold client_id)
    let bad = OAuthServerConfig {
        enabled: false,
        scope: None,
        client_id: Some("cid".into()),
        client_auth_method: None,
        client_secret_env: None,
    };
    assert!(bad.validate().is_err());

    let good = OAuthServerConfig {
        enabled: true,
        scope: Some("mcp:read".into()),
        client_id: Some("cid".into()),
        client_auth_method: Some(ClientAuthMethod::None),
        client_secret_env: None,
    };
    assert!(good.validate().is_ok());

    // 4. Platform-accurate storage protection label reported in auth_status_with_oauth
    let reg = Registry::parse(&sample_mcp_docs_registry()).unwrap();
    let st = reg
        .auth_status_with_oauth("mcp_docs", None, Some(&good), None)
        .unwrap()
        .unwrap();
    assert_eq!(st["oauth_configured"], true);
    assert_eq!(st["storage_protection"], storage_protection_label());
    assert_eq!(st["token_stored"], false);
    assert_eq!(st["remote_oauth_state"], "unknown");
}

/// The stdio schema change must not alter any HTTP server fingerprint: the
/// literals below were computed before `endpoint` became optional. A
/// changed value would silently revoke every sealed local enable.
#[test]
fn http_server_fingerprint_and_overview_unchanged() {
    let raw = serde_json::to_vec(&json!({
        "version": 1,
        "servers": {
            "example": {
                "endpoint": "https://example.com/mcp",
                "bearer_env": "AGENT_BRIDGE_EXTENSION_EXAMPLE_TOKEN",
                "header_env": {"X-Api-Key": "AGENT_BRIDGE_EXTENSION_EXAMPLE_KEY"},
                "tools": {}
            },
            "plain": {"endpoint": "https://example.org/mcp", "tools": {}}
        }
    }))
    .unwrap();
    let docs = Registry::parse(&sample_mcp_docs_registry()).unwrap();
    let reg = Registry::parse(&raw).unwrap();
    let observed = [
        docs.server_sha256("mcp_docs").unwrap().unwrap(),
        reg.server_sha256("example").unwrap().unwrap(),
        reg.server_sha256("plain").unwrap().unwrap(),
    ];
    assert_eq!(observed, [
        "9687340862751690b926097f773b34c0b671915f63feb180e4f062db8dca7c87",
        "da89ad287edea2bd3a93c426ef39b499f0bac6c34eb62b562702fac1baa4b11c",
        "3e1d8c34e063242e0ff100c1dce57b99ed8cb5bdd90479e29568f888471e4491",
    ]);
    assert_eq!(reg.server_endpoint("example"), Some("https://example.com/mcp"));
    assert!(!reg.header_authorization_configured("example"));
    assert_eq!(reg.servers(None).unwrap(), json!({"action": "list", "count": 2, "servers": [
        {"id": "example", "enabled": true, "tools": []},
        {"id": "plain", "enabled": true, "tools": []}]}));
    assert_eq!(docs.servers(Some("mcp_docs")).unwrap(), json!({"action": "inspect", "server":
        {"id": "mcp_docs", "enabled": true, "tools": ["search_model_context_protocol"]}}));
    // An exact control keeps an HTTP server enabled; a stale one disables it.
    let controls = BTreeMap::from([("plain".to_owned(), ServerControl { enabled: true, config_sha256: observed[2].clone() }),
        ("example".to_owned(), ServerControl { enabled: true, config_sha256: "0".repeat(64) })]);
    let controlled = Registry::parse(&raw).unwrap().with_controls(&controls).unwrap();
    assert_eq!(controlled.servers(None).unwrap()["servers"], json!([
        {"id": "example", "enabled": false, "tools": []},
        {"id": "plain", "enabled": true, "tools": []}]));
}

#[test]
fn connection_test_http_covers_success_handshake_failure_and_unapproved_refusal() {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{Ipv4Addr, TcpListener};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;

    let calls_seen = Arc::new(AtomicUsize::new(0));
    let calls_seen_srv = Arc::clone(&calls_seen);

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let endpoint = format!("http://127.0.0.1:{port}/mcp");
    let srv = thread::spawn(move || {
        for _ in 0..2 {
            let Ok((mut stream, _)) = listener.accept() else { break };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut len = 0usize;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
                if let Some((k, v)) = line.split_once(':') {
                    if k.eq_ignore_ascii_case("content-length") {
                        len = v.trim().parse().unwrap_or(0);
                    }
                }
            }
            let mut body = vec![0u8; len];
            reader.read_exact(&mut body).unwrap();
            let req: Value = serde_json::from_slice(&body).unwrap();
            let id = req["id"].clone();
            let method = req["method"].as_str().unwrap_or("");
            if method == "tools/call" {
                calls_seen_srv.fetch_add(1, Ordering::SeqCst);
            }
            let resp = match method {
                "server/discover" => json!({
                    "jsonrpc": "2.0", "id": id,
                    "result": {
                        "resultType": "complete",
                        "supportedVersions": ["2026-07-28"],
                        "capabilities": {"tools": {}},
                        "ttlMs": 0, "cacheScope": "private"
                    }
                }),
                "tools/list" => json!({
                    "jsonrpc": "2.0", "id": id,
                    "result": {
                        "resultType": "complete", "ttlMs": 0, "cacheScope": "private",
                        "tools": [{"name": "list_items", "inputSchema": {"type": "object"}}]
                    }
                }),
                _ => json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": "unexpected"}}),
            };
            let text = resp.to_string();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
                text.len()
            )
            .unwrap();
        }
    });

    let raw = serde_json::to_vec(&json!({
        "version": 1,
        "servers": {
            "approved_http": { "endpoint": endpoint, "tools": {} },
            "disabled_http": { "endpoint": "http://127.0.0.1:1/mcp", "tools": {} }
        }
    }))
    .unwrap();
    let parsed = Registry::parse(&raw).unwrap();
    let dis_fp = parsed.server_sha256("disabled_http").unwrap().unwrap();
    let controls = BTreeMap::from([(
        "disabled_http".to_owned(),
        ServerControl { enabled: false, config_sha256: dis_fp },
    )]);
    let reg = Registry::parse(&raw).unwrap().with_controls(&controls).unwrap();

    // Unapproved / unknown and disabled servers refuse before any network probe.
    assert!(reg.test_connection("unknown_server").is_err());
    assert!(reg.test_connection("disabled_http").is_err());

    // Approved HTTP server succeeds without granting or calling tools.
    let ok = reg.test_connection("approved_http").unwrap();
    srv.join().unwrap();
    assert_eq!(ok["ok"], true);
    assert_eq!(ok["status"], "ok");
    assert_eq!(ok["transport"], "http");
    assert_eq!(ok["protocol_version"], "2026-07-28");
    assert_eq!(ok["live_tool_count"], 1);
    assert_eq!(ok["approved_tool_count"], 0);
    assert_eq!(ok["approved_grants_changed"], false);
    assert_eq!(ok["registry_changed"], false);
    assert_eq!(ok["tool_invoked"], false);
    assert!(ok["latency_ms"].as_u64().is_some());
    assert!(ok["error_class"].is_null());
    assert_eq!(calls_seen.load(Ordering::SeqCst), 0);

    // Handshake failure reports structured error_class and latency_ms without tool call.
    let bad_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let bad_port = bad_listener.local_addr().unwrap().port();
    let bad_srv = thread::spawn(move || {
        let (mut stream, _) = bad_listener.accept().unwrap();
        let mut sink = [0u8; 2048];
        let _ = stream.read(&mut sink);
        let body = b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let _ = stream.write_all(body);
    });
    let bad_raw = serde_json::to_vec(&json!({
        "version": 1,
        "servers": {
            "bad_http": { "endpoint": format!("http://127.0.0.1:{bad_port}/mcp"), "tools": {} }
        }
    }))
    .unwrap();
    let bad_reg = Registry::parse(&bad_raw).unwrap();
    let failed = bad_reg.test_connection("bad_http").unwrap();
    bad_srv.join().unwrap();
    assert_eq!(failed["ok"], false);
    assert_eq!(failed["status"], "error");
    assert_eq!(failed["error_class"], "handshake_failed");
    assert_eq!(failed["tool_invoked"], false);
    assert_eq!(failed["approved_grants_changed"], false);
    assert!(failed["latency_ms"].as_u64().is_some());
}

#[test]
fn http_probe_admit_and_cancel_on_revocation_during_handshake_and_list() {
    use agent_bridge_extensions::{LiveExtensionRegistry, StatusTracker};
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{Ipv4Addr, TcpListener};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    for stall_on_list in [false, true] {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let entered = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let calls_seen = Arc::new(AtomicUsize::new(0));
        let entered_srv = Arc::clone(&entered);
        let stop_srv = Arc::clone(&stop);
        let calls_srv = Arc::clone(&calls_seen);

        let srv = thread::spawn(move || {
            let _ = listener.set_nonblocking(false);
            let mut held = Vec::new();
            for _ in 0..4 {
                if stop_srv.load(Ordering::Acquire) {
                    break;
                }
                let Ok((mut stream, _)) = listener.accept() else { break };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut len = 0usize;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    if let Some((k, v)) = line.split_once(':') {
                        if k.eq_ignore_ascii_case("content-length") {
                            len = v.trim().parse().unwrap_or(0);
                        }
                    }
                }
                if len == 0 {
                    continue;
                }
                let mut body = vec![0u8; len];
                if reader.read_exact(&mut body).is_err() {
                    continue;
                }
                let req: Value = serde_json::from_slice(&body).unwrap();
                let id = req["id"].clone();
                let method = req["method"].as_str().unwrap_or("");
                if method == "tools/call" {
                    calls_srv.fetch_add(1, Ordering::SeqCst);
                }
                if (!stall_on_list && method == "server/discover") || (stall_on_list && method == "tools/list") {
                    entered_srv.store(true, Ordering::Release);
                    held.push((stream, reader));
                    while !stop_srv.load(Ordering::Acquire) {
                        thread::sleep(Duration::from_millis(20));
                    }
                    break;
                }
                if method == "server/discover" {
                    let text = json!({
                        "jsonrpc": "2.0", "id": id,
                        "result": {
                            "resultType": "complete",
                            "supportedVersions": ["2026-07-28"],
                            "capabilities": {"tools": {}},
                            "ttlMs": 0, "cacheScope": "private"
                        }
                    })
                    .to_string();
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
                        text.len()
                    );
                } else {
                    break;
                }
            }
            drop(held);
        });

        let raw = serde_json::to_vec(&json!({
            "version": 1,
            "servers": {
                "http_srv": { "endpoint": format!("http://127.0.0.1:{port}/mcp"), "tools": {} }
            }
        }))
        .unwrap();
        let initial = Registry::parse(&raw).unwrap();
        let pool = agent_bridge_extensions::SessionPool::new();
        let status = StatusTracker::new();
        let live = LiveExtensionRegistry::new(initial, pool.clone(), status.clone());

        let admitted = live.admit_probe("http_srv").unwrap();
        let started = Instant::now();
        let err = thread::scope(|scope| {
            let probe = scope.spawn(|| admitted.execute());
            let deadline = Instant::now() + Duration::from_secs(5);
            while !entered.load(Ordering::Acquire) {
                assert!(Instant::now() < deadline, "HTTP probe did not reach stall point");
                thread::sleep(Duration::from_millis(10));
            }
            let revoked = live.revoke_server("http_srv").unwrap();
            assert_eq!(revoked.removed_or_disabled, 1);
            assert_eq!(revoked.cancelled_in_flight, 1);
            probe.join().unwrap().unwrap_err()
        });
        assert!(started.elapsed() < Duration::from_secs(3), "HTTP probe cancellation took {:?}", started.elapsed());
        assert!(err.to_string().contains("cancelled due to revocation"), "{err}");
        assert_eq!(calls_seen.load(Ordering::SeqCst), 0);
        let snap = status.snapshot_for_registry(&live.current(), Some(&pool), Some(live.generation()));
        assert_eq!(snap["servers"][0]["state"], "disabled");

        stop.store(true, Ordering::Release);
        srv.join().unwrap();
    }
}
