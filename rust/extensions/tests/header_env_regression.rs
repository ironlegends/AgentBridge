use agent_bridge_extensions::{Registry, ServerControl};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

fn config(endpoint: &str, headers: Value) -> Vec<u8> {
    let mut server = json!({"endpoint":endpoint,"tools":{}});
    if !headers.is_null() { server["header_env"] = headers; }
    serde_json::to_vec(&json!({"version":1,"servers":{"sample":server}})).unwrap()
}

#[test]
fn header_env_is_inert_until_approved_and_binds_exact_references() {
    let old = Registry::parse(&config("https://example.invalid/mcp", Value::Null)).unwrap();
    let mut old_shape = json!({"endpoint":"https://example.invalid/mcp","bearer_env":null,"tools":{}});
    old_shape.sort_all_objects();
    let old_hash = hex::encode(Sha256::digest(old_shape.to_string().as_bytes()));
    assert_eq!(old.server_sha256("sample").unwrap().unwrap(), old_hash,
        "absent new field must preserve historical fingerprints");
    let a = Registry::parse(&config("https://example.invalid/mcp",
        json!({"X-Api-Key":"AGENT_BRIDGE_EXTENSION_HEADER_A"}))).expect("inert references are supported");
    let a_hash = a.server_sha256("sample").unwrap().unwrap();
    assert_ne!(a_hash, old_hash);
    let b = Registry::parse(&config("https://example.invalid/mcp",
        json!({"X-Api-Key":"AGENT_BRIDGE_EXTENSION_HEADER_B"}))).unwrap();
    assert_ne!(a_hash, b.server_sha256("sample").unwrap().unwrap());
    let controls = BTreeMap::from([("sample".to_owned(), ServerControl { enabled:true, config_sha256:a_hash })]);
    let changed = b.with_controls(&controls).unwrap();
    assert_eq!(changed.auth_status("sample", controls.get("sample")).unwrap().unwrap()["local_control"], "configuration_changed");
    let public = a.servers(None).unwrap().to_string();
    assert!(!public.contains("AGENT_BRIDGE_EXTENSION_HEADER_A"), "inspection must not reveal private credential references");
}

#[test]
fn header_env_refuses_transport_overrides_secret_literals_and_insecure_destinations() {
    for headers in [
        json!({"Host":"AGENT_BRIDGE_EXTENSION_A"}),
        json!({"Content-Length":"AGENT_BRIDGE_EXTENSION_A"}),
        json!({"Mcp-Session-Id":"AGENT_BRIDGE_EXTENSION_A"}),
        json!({"MCP-Protocol-Version":"AGENT_BRIDGE_EXTENSION_A"}),
        json!({"Connection":"AGENT_BRIDGE_EXTENSION_A"}),
        json!({"X-Api-Key":"literal-secret"}),
        json!({"X-Api-Key":"HOME"}),
        json!({"X-Api-Key\r\nInjected":"AGENT_BRIDGE_EXTENSION_A"}),
        json!({"X-Api-Key":"AGENT_BRIDGE_EXTENSION_A","x-api-key":"AGENT_BRIDGE_EXTENSION_B"}),
    ] {
        assert!(Registry::parse(&config("https://example.invalid/mcp", headers.clone())).is_err(), "{headers}");
    }
    let allowed = json!({"Authorization":"AGENT_BRIDGE_EXTENSION_AUTH"});
    assert!(Registry::parse(&config("http://127.0.0.1:39123/mcp", allowed.clone())).is_err());
    assert!(Registry::parse(&config("https://modelcontextprotocol.io/mcp", allowed.clone())).is_err());
    let mut duplicate: Value = serde_json::from_slice(&config("https://example.invalid/mcp", allowed)).unwrap();
    duplicate["servers"]["sample"]["bearer_env"] = json!("AGENT_BRIDGE_EXTENSION_BEARER");
    assert!(Registry::parse(&serde_json::to_vec(&duplicate).unwrap()).is_err(), "two Authorization sources must be refused");
}

#[test]
fn task5_normalized_public_destination_never_accepts_private_header_references() {
    for endpoint in [
        "https://MODELCONTEXTPROTOCOL.io/mcp",
        "https://modelcontextprotocol.io:443/mcp",
        "HTTPS://MODELCONTEXTPROTOCOL.IO:443/mcp",
        "https://modelcontextprotocol.io/./mcp",
        "https://modelcontextprotocol.io./mcp",
        "https://MODELCONTEXTPROTOCOL.IO.:443/mcp",
        "https://modelcontextprotocol.io./%6Dcp",
        "https://modelcontextprotocol.io./other",
        "https://modelcontextprotocol.io.:8443/mcp",
        "https://LEARN.microsoft.com/api/mcp",
        "https://learn.microsoft.com:443/api/mcp",
        "https://learn.microsoft.com/./api/mcp",
        "https://learn.microsoft.com./api/mcp",
        "https://learn.microsoft.com./api/%6Dcp",
        "https://learn.microsoft.com./other",
        "https://learn.microsoft.com.:8443/api/mcp",
    ] {
        let references = BTreeMap::from([("X-Api-Key".into(), "AGENT_BRIDGE_EXTENSION_SYNTHETIC".into())]);
        assert!(agent_bridge_extensions::validate_header_env(endpoint, &references, false).is_err(),
            "an equivalent public endpoint accepted a private header proposal: {endpoint}");
        assert!(agent_bridge_extensions::validate_header_env(endpoint, &BTreeMap::new(), true).is_err());
        assert!(Registry::parse(&config(endpoint,
            json!({"X-Api-Key":"AGENT_BRIDGE_EXTENSION_SYNTHETIC"}))).is_err());
        let mut bearer: Value = serde_json::from_slice(&config(endpoint, Value::Null)).unwrap();
        bearer["servers"]["sample"]["bearer_env"] = json!("AGENT_BRIDGE_EXTENSION_SYNTHETIC");
        assert!(Registry::parse(&serde_json::to_vec(&bearer).unwrap()).is_err(),
            "normalization must also preserve the public no-bearer invariant");
    }
}

#[test]
fn public_credential_guard_does_not_rewrite_endpoints_or_reject_unrelated_hosts() {
    let references = BTreeMap::from([("X-Api-Key".into(), "AGENT_BRIDGE_EXTENSION_SYNTHETIC".into())]);
    for endpoint in ["https://modelcontextprotocol.io.evil.invalid/api/mcp", "https://private.example.invalid./api/mcp"] {
        assert!(agent_bridge_extensions::validate_header_env(endpoint, &references, false).is_ok());
        assert!(agent_bridge_extensions::validate_header_env(endpoint, &BTreeMap::new(), true).is_ok());
    }
    let alias = "https://modelcontextprotocol.io./mcp";
    let registry = Registry::parse(&config(alias, Value::Null)).unwrap();
    assert_eq!(registry.server_endpoint("sample"), Some(alias));
    let mut unapproved: Value = serde_json::from_slice(&config(alias, Value::Null)).unwrap();
    unapproved["servers"]["sample"]["tools"]["search_model_context_protocol"] = json!({
        "descriptor_sha256": "0".repeat(64), "parameters": {"query":{"type":"search_terms"}}
    });
    assert!(Registry::parse(&serde_json::to_vec(&unapproved).unwrap()).is_err(),
        "the exact operation allowlist must not be widened by host normalization");
}

#[test]
fn public_docs_oauth_flow_is_denied_before_config_storage_or_network() {
    use agent_bridge_extensions::oauth::{run_oauth_flow, OAuthServerConfig};
    // Deliberately no client_id: on the old path this returns before network
    // discovery, so even RED is entirely offline and touches no token store.
    let cfg = OAuthServerConfig { enabled: true, scope: None, client_id: None,
        client_auth_method: None, client_secret_env: None };
    for endpoint in ["https://modelcontextprotocol.io/mcp", "https://MODELCONTEXTPROTOCOL.IO.:443/mcp",
        "https://learn.microsoft.com/api/mcp", "https://LEARN.microsoft.com.:443/api/mcp"] {
        let error = run_oauth_flow(std::path::Path::new("unused-offline-test-setting"), "public_docs", endpoint,
            &cfg, false, |_| panic!("public OAuth must not present an authorization URL")).unwrap_err();
        assert_eq!(error.to_string(), "Public documentation search forbids credentials");
    }
}
