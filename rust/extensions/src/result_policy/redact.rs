use serde_json::Value;

pub(super) const REDACTED: &str = "[REDACTED]";

pub(super) fn redact(value: &mut Value) {
    match value {
        Value::Object(map) => {
            map.retain(|key, _| redact_string(key) == *key);
            for (key, val) in map.iter_mut() {
                if is_sensitive_key(key) && !is_non_sensitive_bool_flag(key, val) {
                    *val = Value::String(REDACTED.to_string());
                } else {
                    redact(val);
                }
            }
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                redact(item);
            }
        }
        Value::String(text) => {
            *text = redact_string(text);
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn is_non_sensitive_bool_flag(key: &str, value: &Value) -> bool {
    if !value.is_boolean() {
        return false;
    }
    let tokens = split_key_tokens(key);
    let first = tokens.first().map(String::as_str);
    let last = tokens.last().map(String::as_str);
    matches!(
        first,
        Some("has" | "is" | "use" | "uses" | "allow" | "allows" | "enable" | "enabled" | "require" | "requires" | "supports" | "with")
    ) || matches!(
        last,
        Some("enabled" | "present" | "configured" | "required" | "set" | "valid" | "active" | "verified")
    )
}

fn is_sensitive_key(key: &str) -> bool {
    let tokens = split_key_tokens(key);
    if tokens.is_empty() {
        return false;
    }

    if tokens.iter().any(|t| {
        matches!(
            t.as_str(),
            "password"
                | "passwords"
                | "passwd"
                | "pwd"
                | "passphrase"
                | "motdepasse"
                | "mdp"
                | "token"
                | "tokens"
                | "apikey"
                | "apikeys"
                | "apisecret"
                | "apitoken"
                | "secret"
                | "secrets"
                | "bearer"
                | "authorization"
                | "cookie"
                | "cookies"
                | "credential"
                | "credentials"
                | "privatekey"
                | "jwt"
        )
    }) {
        return true;
    }

    let has_api = tokens.iter().any(|t| t == "api");
    let has_key_like = tokens.iter().any(|t| {
        matches!(
            t.as_str(),
            "key" | "keys" | "auth" | "pass" | "secret" | "token" | "credential"
        )
    });
    if has_api && has_key_like {
        return true;
    }

    if tokens
        .windows(3)
        .any(|w| w[0] == "mot" && w[1] == "de" && w[2] == "passe")
    {
        return true;
    }

    tokens.windows(2).any(|w| {
        matches!(
            (w[0].as_str(), w[1].as_str()),
            ("private", "key") | ("access", "key") | ("signing", "key") | ("client", "key")
        )
    })
}

fn split_key_tokens(key: &str) -> Vec<String> {
    let chars: Vec<char> = key.chars().collect();
    let mut tokens = Vec::new();
    let mut current = String::new();

    for (idx, &ch) in chars.iter().enumerate() {
        if !ch.is_alphanumeric() {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
            continue;
        }
        if ch.is_uppercase() && !current.is_empty() {
            let prev = chars[idx - 1];
            let next_is_lower = chars.get(idx + 1).is_some_and(|c| c.is_lowercase());
            if prev.is_lowercase()
                || prev.is_ascii_digit()
                || (prev.is_uppercase() && next_is_lower)
            {
                tokens.push(std::mem::take(&mut current));
            }
        }
        for lower in ch.to_lowercase() {
            current.push(lower);
        }
    }

    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

fn redact_string(input: &str) -> String {
    // A free-form assignment can quote or wrap a value across whitespace.
    // Suppress the whole field when its boundary cannot be inferred safely.
    for (offset, _) in input.match_indices(['=', ':']) {
        let prefix = input[..offset].trim_end_matches(|c: char| c.is_whitespace() || c == '"' || c == '\'');
        let key = prefix.rsplit(|c: char| !(c.is_alphanumeric() || c == '_' || c == '-')).next().unwrap_or("");
        if is_sensitive_key(key) {
            let rest = input[offset + 1..].trim_start();
            if key.eq_ignore_ascii_case("authorization") && match_bearer(rest).is_some() { continue; }
            return REDACTED.to_owned();
        }
    }
    let mut out = String::with_capacity(input.len());
    let mut i = 0;

    while i < input.len() {
        if is_boundary_before(input, i) {
            let rest = &input[i..];
            if let Some(len) = match_bearer(rest)
                .or_else(|| match_openai(rest))
                .or_else(|| match_github(rest))
            {
                out.push_str(REDACTED);
                i += len;
                continue;
            }
        }

        let ch = input[i..].chars().next().expect("valid UTF-8 boundary");
        out.push(ch);
        i += ch.len_utf8();
    }

    out
}

fn is_boundary_before(input: &str, idx: usize) -> bool {
    if idx == 0 {
        return true;
    }
    match input[..idx].chars().next_back() {
        Some(ch) => !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '-'),
        None => true,
    }
}

fn match_bearer(rest: &str) -> Option<usize> {
    let bytes = rest.as_bytes();
    if bytes.len() < 8 || !bytes[..6].eq_ignore_ascii_case(b"bearer") {
        return None;
    }
    let mut pos = 6;
    while pos < bytes.len() && matches!(bytes[pos], b' ' | b'\t') {
        pos += 1;
    }
    if pos == 6 {
        return None;
    }
    let token_start = pos;
    while pos < bytes.len() && is_bearer_token_byte(bytes[pos]) {
        pos += 1;
    }
    let token = &bytes[token_start..pos];
    if token.is_empty() {
        return None;
    }
    let looks_like_secret = token.len() >= 6
        || token
            .iter()
            .any(|b| b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'_' | b'/' | b'+' | b'='));
    if !looks_like_secret {
        return None;
    }
    Some(pos)
}

fn is_bearer_token_byte(b: u8) -> bool {
    b.is_ascii_graphic() && !matches!(b, b'"' | b'\'' | b',' | b';' | b')' | b']' | b'}' | b'>')
}

fn match_openai(rest: &str) -> Option<usize> {
    if !rest.starts_with("sk-") {
        return None;
    }
    let bytes = rest.as_bytes();
    let mut pos = 3;
    while pos < bytes.len()
        && (bytes[pos].is_ascii_alphanumeric() || matches!(bytes[pos], b'_' | b'-'))
    {
        pos += 1;
    }
    if pos - 3 < 8 {
        return None;
    }
    Some(pos)
}

fn match_github(rest: &str) -> Option<usize> {
    let (kind, body) = rest.split_once('_')?;
    let token = match kind {
        "github" => body.strip_prefix("pat_")?,
        "ghp" | "gho" | "ghu" | "ghs" | "ghr" => body,
        _ => return None,
    };
    let bytes = rest.as_bytes();
    let start = bytes.len() - token.len();
    let mut pos = start;
    while pos < bytes.len() && (bytes[pos].is_ascii_alphanumeric() || bytes[pos] == b'_') {
        pos += 1;
    }
    if pos - start < 6 {
        return None;
    }
    Some(pos)
}

#[cfg(test)]
mod tests {
    use super::{redact, REDACTED};
    use serde_json::json;

    #[test]
    fn redacts_sensitive_fields_recursively_in_objects_and_arrays() {
        let mut payload = json!({
            "password": "my-secret-password-99",
            "mot_de_passe": "secret-fr-42",
            "nested": {
                "access_token": "tok_live_987654321",
                "apiKey": "plain-api-key-value",
                "X-API-Key": "header-api-key-value",
                "items": [
                    { "refreshToken": "ref_0011223344", "label": "ok" },
                    { "motDePasse": "autre-secret-88" }
                ]
            }
        });

        redact(&mut payload);

        assert_eq!(payload["password"], REDACTED);
        assert_eq!(payload["mot_de_passe"], REDACTED);
        assert_eq!(payload["nested"]["access_token"], REDACTED);
        assert_eq!(payload["nested"]["apiKey"], REDACTED);
        assert_eq!(payload["nested"]["X-API-Key"], REDACTED);
        assert_eq!(payload["nested"]["items"][0]["refreshToken"], REDACTED);
        assert_eq!(payload["nested"]["items"][0]["label"], "ok");
        assert_eq!(payload["nested"]["items"][1]["motDePasse"], REDACTED);

        let serialized = payload.to_string();
        for leaked in [
            "my-secret-password-99",
            "secret-fr-42",
            "tok_live_987654321",
            "plain-api-key-value",
            "header-api-key-value",
            "ref_0011223344",
            "autre-secret-88",
        ] {
            assert!(!serialized.contains(leaked), "leaked secret: {leaked}");
        }
    }

    #[test]
    fn redacts_bearer_openai_and_github_values_without_leaking_fragments() {
        let mut payload = json!({
            "headers": [
                "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload99.sig77",
                "openai=sk-proj-AbCdEf1234567890ZyXw",
                "classic=sk-9988776655"
            ],
            "notes": format!("tokens {}_SuperSecretGitHub98765 and {}_pat_11ABCDEF_9988776655 end", "ghp", "github")
        });

        redact(&mut payload);

        assert_eq!(payload["headers"][0], "Authorization: [REDACTED]");
        assert_eq!(payload["headers"][1], "openai=[REDACTED]");
        assert_eq!(payload["headers"][2], "classic=[REDACTED]");
        assert_eq!(payload["notes"], "tokens [REDACTED] and [REDACTED] end");

        let serialized = payload.to_string();
        for fragment in [
            "eyJhbGci",
            "payload99",
            "sig77",
            "sk-proj-",
            "AbCdEf1234567890ZyXw",
            "sk-99887766",
            "SuperSecretGitHub98765",
            "11ABCDEF",
            "9988776655",
        ] {
            assert!(!serialized.contains(fragment), "leaked fragment: {fragment}");
        }
    }

    #[test]
    fn preserves_non_sensitive_booleans_and_metadata() {
        let mut payload = json!({
            "enabled": true,
            "read_only": false,
            "has_token": true,
            "api_key_configured": false,
            "flags": [true, false, 42, null],
            "api": {
                "version": "2.2.0",
                "available": true,
                "token": format!("{}_MustBeMasked123456", "gho")
            }
        });

        redact(&mut payload);

        assert_eq!(payload["enabled"], json!(true));
        assert_eq!(payload["read_only"], json!(false));
        assert_eq!(payload["has_token"], json!(true));
        assert_eq!(payload["api_key_configured"], json!(false));
        assert_eq!(payload["flags"], json!([true, false, 42, null]));
        assert_eq!(payload["api"]["version"], json!("2.2.0"));
        assert_eq!(payload["api"]["available"], json!(true));
        assert_eq!(payload["api"]["token"], REDACTED);
        assert!(!payload.to_string().contains("MustBeMasked123456"));
    }
}
