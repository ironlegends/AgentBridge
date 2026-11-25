use serde_json::Value;

fn open_url_permission() -> Value {
    let capability: Value =
        serde_json::from_str(include_str!("../capabilities/default.json")).unwrap();
    let permissions = capability["permissions"].as_array().unwrap();
    assert!(
        !permissions.iter().any(|permission| {
            permission.as_str().is_some_and(|name| {
                matches!(name, "opener:default" | "opener:allow-default-urls")
            })
        }),
        "Provider links must not inherit the unrestricted default URL set"
    );
    permissions
        .iter()
        .find(|permission| permission["identifier"] == "opener:allow-open-url")
        .expect("Opening provider links requires an explicit URL scope")
        .clone()
}

fn is_url_allowed(permission: &Value, url: &str) -> bool {
    permission["allow"]
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| {
            glob::Pattern::new(entry["url"].as_str().unwrap())
                .unwrap()
                .matches(url)
        })
}

#[test]
fn provider_url_scope_allows_https_and_literal_loopback_http() {
    let permission = open_url_permission();
    for url in [
        "https://auth.example.invalid/authorize?state=fixture",
        "https://auth.example.invalid:8443/oauth/authorize",
        "http://127.0.0.1/authorize",
        "http://127.0.0.1:1/authorize",
        "http://127.0.0.1:80/authorize",
        "http://127.0.0.1:888/authorize",
        "http://127.0.0.1:8080/authorize",
        "http://127.0.0.1:65535/authorize?state=fixture",
        "http://[::1]/authorize",
        "http://[::1]:1/authorize",
        "http://[::1]:80/authorize",
        "http://[::1]:888/authorize",
        "http://[::1]:8080/authorize",
        "http://[::1]:65535/authorize?state=fixture",
    ] {
        assert!(is_url_allowed(&permission, url), "URL was denied: {url}");
    }
}

#[test]
fn provider_url_scope_rejects_other_protocols_and_non_loopback_http() {
    let permission = open_url_permission();
    for url in [
        "file:///C:/Windows/System32/cmd.exe",
        "javascript:alert(1)",
        "data:text/html,fixture",
        "mailto:fixture@example.invalid",
        "tel:12345",
        "ftp://auth.example.invalid/authorize",
        "http://auth.example.invalid/authorize",
        "http://localhost/authorize",
        "http://127.0.0.2/authorize",
        "http://127.1/authorize",
        "http://2130706433/authorize",
        "http://127.0.0.1.evil.invalid/authorize",
        "http://127.0.0.1:80@evil.invalid/authorize",
        "http://127.0.0.1:80x/authorize",
        "http://127.0.0.1:123456/authorize",
        "http://[::1].evil.invalid/authorize",
        "http://[::1]:80@evil.invalid/authorize",
        "http://[::2]/authorize",
    ] {
        assert!(!is_url_allowed(&permission, url), "URL was allowed: {url}");
    }
}

#[test]
fn provider_url_scope_grants_no_file_path_or_custom_application() {
    let permission = open_url_permission();
    let entries = permission["allow"].as_array().unwrap();
    assert!(!entries.is_empty());
    for entry in entries {
        let object = entry.as_object().unwrap();
        assert_eq!(object.len(), 1, "Only URL patterns belong in this scope");
        assert!(entry["url"].is_string());
    }
}
