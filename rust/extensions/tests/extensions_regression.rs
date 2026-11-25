use agent_bridge_extensions::oauth::{ClientAuthMethod, OAuthServerConfig};
#[cfg(windows)]
use agent_bridge_extensions::oauth::{run_oauth_flow, OAuthTokenStore};
use agent_bridge_extensions::{
    config_sha256, fetch_https_bytes, validate_proposed_endpoint, valid_server_name, Registry,
    ServerControl,
};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

fn canonical_descriptor_hash(v: &Value) -> String {
    let mut c = v.clone();
    c.sort_all_objects();
    hex::encode(Sha256::digest(c.to_string().as_bytes()))
}

fn sample_ms_learn_registry() -> Vec<u8> {
    let descriptor = json!({
        "name": "microsoft_docs_search",
        "description": "Search Microsoft Learn public docs",
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
            "microsoft_learn": {
                "endpoint": "https://learn.microsoft.com/api/mcp",
                "tools": {
                    "microsoft_docs_search": {
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
    let raw = sample_ms_learn_registry();
    let reg = Registry::parse(&raw).expect("valid microsoft_learn registry");
    assert!(reg.has_server("microsoft_learn"));
    assert_eq!(reg.list(), vec!["microsoft_learn:microsoft_docs_search"]);
    assert_eq!(config_sha256(&raw).len(), 64);

    let searched = reg.search_cached("docs", None, 10).expect("search_cached");
    assert!(!searched["tools"].as_array().unwrap().is_empty());
    let inspected = reg
        .inspect_cached("microsoft_learn:microsoft_docs_search")
        .expect("inspect_cached");
    assert_eq!(inspected["name"], "microsoft_learn:microsoft_docs_search");

    // Regression: public Microsoft Learn forbids bearer credentials
    let with_bearer = serde_json::to_vec(&json!({
        "version": 1,
        "servers": {
            "microsoft_learn": {
                "endpoint": "https://learn.microsoft.com/api/mcp",
                "bearer_env": "AGENT_BRIDGE_EXTENSION_TOKEN",
                "tools": {}
            }
        }
    }))
    .unwrap();
    assert!(Registry::parse(&with_bearer).is_err());

    // Regression: unallowlisted tool (e.g. microsoft_docs_fetch) rejected at parse time
    let unallowlisted = serde_json::to_vec(&json!({
        "version": 1,
        "servers": {
            "microsoft_learn": {
                "endpoint": "https://learn.microsoft.com/api/mcp",
                "tools": {
                    "microsoft_docs_fetch": {
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
            "microsoft_learn": {
                "endpoint": "https://learn.microsoft.com/api/mcp",
                "tools": {
                    "microsoft_docs_search": {
                        "descriptor_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
                        "descriptor": { "name": "microsoft_docs_search", "inputSchema": { "type": "object", "properties": {} } },
                        "parameters": { "query": { "type": "search_terms" } }
                    }
                }
            }
        }
    }))
    .unwrap();
    assert!(Registry::parse(&tampered).is_err());
}

#[test]
fn auth_status_truthful_outbound_oauth_gap_and_controls_regressions() {
    let raw = sample_ms_learn_registry();
    let reg = Registry::parse(&raw).expect("parse");
    let fp = reg
        .server_sha256("microsoft_learn")
        .unwrap()
        .expect("server sha256");

    assert!(reg.auth_status("absent_server", None).unwrap().is_none());

    // 1. No local decision -> truthful local-only status, outbound_oauth=not_implemented, remote=unknown
    let s_none = reg
        .auth_status("microsoft_learn", None)
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
        .auth_status("microsoft_learn", Some(&stale_ctrl))
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
    map.insert("microsoft_learn".to_owned(), dis_ctrl.clone());
    let disabled_reg = Registry::parse(&raw)
        .unwrap()
        .with_controls(&map)
        .unwrap();
    let s_dis = disabled_reg
        .auth_status("microsoft_learn", Some(&dis_ctrl))
        .unwrap()
        .unwrap();
    assert_eq!(s_dis["local_control"], "disabled");
    assert!(disabled_reg
        .inspect_cached("microsoft_learn:microsoft_docs_search")
        .is_err());
    assert!(disabled_reg
        .call("microsoft_learn:microsoft_docs_search", &Map::new())
        .is_err());

    // 4. Enabled server with exact fingerprint
    let en_ctrl = ServerControl {
        enabled: true,
        config_sha256: fp,
    };
    let mut en_map = BTreeMap::new();
    en_map.insert("microsoft_learn".to_owned(), en_ctrl.clone());
    let enabled_reg = Registry::parse(&raw)
        .unwrap()
        .with_controls(&en_map)
        .unwrap();
    let s_en = enabled_reg
        .auth_status("microsoft_learn", Some(&en_ctrl))
        .unwrap()
        .unwrap();
    assert_eq!(s_en["local_control"], "enabled");
    assert_eq!(s_en["outbound_oauth"], "not_implemented");
    assert_eq!(s_en["remote_oauth_state"], "unknown");
}

#[test]
fn endpoint_validation_and_refresh_scope_gap_regressions() {
    assert!(valid_server_name("microsoft_learn"));
    assert!(!valid_server_name("../bad"));
    assert!(!valid_server_name(""));

    // Remote HTTP rejected; remote HTTPS & loopback HTTP accepted
    let remote_http = format!("{}://example.com/mcp", "http");
    let loopback_http = format!("{}://{}:8080/mcp", "http", "127.0.0.1");
    assert!(validate_proposed_endpoint(&remote_http).is_err());
    assert!(validate_proposed_endpoint("https://learn.microsoft.com/api/mcp").is_ok());
    assert!(validate_proposed_endpoint(&loopback_http).is_ok());

    // Gap: remote refresh is strictly limited to microsoft_learn
    let reg = Registry::parse(&sample_ms_learn_registry()).unwrap();
    let err = reg
        .refresh_microsoft_learn("other_server")
        .expect_err("non-microsoft_learn refresh must be refused");
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
    let reg = Registry::parse(&sample_ms_learn_registry()).unwrap();
    let combined = reg
        .auth_status_with_oauth("microsoft_learn", None, Some(&cfg), Some(&status))
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
    let reg = Registry::parse(&sample_ms_learn_registry()).unwrap();
    let st = reg
        .auth_status_with_oauth("microsoft_learn", None, Some(&good), None)
        .unwrap()
        .unwrap();
    assert_eq!(st["oauth_configured"], true);
    assert_eq!(st["storage_protection"], storage_protection_label());
    assert_eq!(st["token_stored"], false);
    assert_eq!(st["remote_oauth_state"], "unknown");
}
