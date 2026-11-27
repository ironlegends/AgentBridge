//! Operator-selected result limits apply at the upstream boundary, before a reply or a cache entry.
mod redact;

use crate::{error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct ResultPolicy {
    #[serde(skip_serializing_if = "Option::is_none")]
    allow: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    deny: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_bytes: Option<usize>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    mask_literals: Vec<String>,
}

#[derive(Default)]
struct PointerNode {
    selected: bool,
    children: BTreeMap<String, PointerNode>,
}

impl PointerNode {
    fn compile(pointers: &[String]) -> Result<Self> {
        if pointers.is_empty() || pointers.len() > 64 {
            return Err(error("Extension result policy requires 1 to 64 pointers"));
        }
        let mut root = Self::default();
        for pointer in pointers {
            if pointer.len() > 512 || (!pointer.is_empty() && !pointer.starts_with('/')) {
                return Err(error("Invalid extension result pointer"));
            }
            let mut node = &mut root;
            if let Some(path) = pointer.strip_prefix('/') {
                for (depth, segment) in path.split('/').enumerate() {
                    if depth >= 16 { return Err(error("Extension result pointer exceeds depth limit")); }
                    let mut token = String::new();
                    let mut chars = segment.chars();
                    while let Some(ch) = chars.next() {
                        token.push(match ch {
                            '~' => match chars.next() {
                                Some('0') => '~', Some('1') => '/',
                                _ => return Err(error("Invalid extension result pointer escape")),
                            },
                            other => other,
                        });
                    }
                    node = node.children.entry(token).or_default();
                }
            }
            node.selected = true;
        }
        Ok(root)
    }

    fn project(&self, value: Value, allow: bool) -> Option<Value> {
        if self.selected { return allow.then_some(value); }
        let keep = |key: &str, value: Value| match self.children.get(key) {
            Some(child) => child.project(value, allow),
            None => (!allow).then_some(value),
        };
        match value {
            Value::Object(input) => {
                let object: Map<_, _> = input.into_iter()
                    .filter_map(|(key, value)| keep(&key, value).map(|result| (key, result))).collect();
                (!allow || !object.is_empty()).then_some(Value::Object(object))
            }
            Value::Array(input) => {
                let array: Vec<_> = input.into_iter().enumerate()
                    .filter_map(|(index, value)| keep(&index.to_string(), value)).collect();
                (!allow || !array.is_empty()).then_some(Value::Array(array))
            }
            scalar => (!allow).then_some(scalar),
        }
    }
}

impl ResultPolicy {
    fn pointers(&self) -> Result<Option<(PointerNode, bool)>> {
        match (&self.allow, &self.deny) {
            (None, None) => Ok(None),
            (Some(paths), None) => Ok(Some((PointerNode::compile(paths)?, true))),
            (None, Some(paths)) => Ok(Some((PointerNode::compile(paths)?, false))),
            _ => Err(error("Extension result allow and deny policies are mutually exclusive")),
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.pointers()?;
        if self.max_bytes.is_some_and(|size| !(16..=1024 * 1024).contains(&size))
            || self.mask_literals.len() > 16
            || self.mask_literals.iter().any(|s| s.is_empty() || s.len() > 128) {
            return Err(error("Invalid extension result byte cap or mask"));
        }
        Ok(())
    }

    fn mask_literals(&self, value: &mut Value) {
        match value {
            Value::String(text) if self.mask_literals.iter().any(|s| text.contains(s)) => {
                *text = redact::REDACTED.to_owned();
            }
            Value::Object(fields) => {
                fields.retain(|key, _| !self.mask_literals.iter().any(|pattern| key.contains(pattern)));
                fields.values_mut().for_each(|item| self.mask_literals(item));
            }
            Value::Array(items) => items.iter_mut().for_each(|item| self.mask_literals(item)),
            _ => {}
        }
    }

    fn redact_payload(&self, data: &mut Value) {
        redact::redact(data);
        if !self.mask_literals.is_empty() { self.mask_literals(data); }
    }

    pub(crate) fn apply(&self, mut value: Value) -> Result<Value> {
        let result = value.as_object_mut().ok_or_else(|| error("Invalid extension tool result"))?;
        if !result.get("content").is_some_and(Value::is_array)
            || result.get("isError").is_some_and(|flag| !flag.is_boolean()) {
            return Err(error("Invalid extension tool result envelope"));
        }
        if let Some((pointers, allow)) = self.pointers()? {
            let original = result.remove("structuredContent")
                .ok_or_else(|| error("Extension result filter requires structuredContent"))?;
            let projected = pointers.project(original, allow);
            result.retain(|key, item| key == "isError" || key == "content"
                || (key == "resultType" && item.as_str() == Some("complete")));
            result.insert("content".into(), Value::Array(Vec::new()));
            if let Some(data) = projected { result.insert("structuredContent".into(), data); }
        }
        let structured_changed = result.get_mut("structuredContent").is_some_and(|data| {
            let original = data.clone();
            self.redact_payload(data);
            original != *data
        });
        if let Some(meta) = result.get_mut("_meta") { self.redact_payload(meta); }
        let blocks = result.get_mut("content").and_then(Value::as_array_mut)
            .ok_or_else(|| error("Invalid extension tool content"))?;
        if structured_changed {
            // Text or binary mirrors may repeat a masked value without a label.
            blocks.clear();
        } else {
            blocks.retain_mut(|block| {
                if block.get("type").and_then(Value::as_str) != Some("text") {
                    let original = block.clone();
                    self.redact_payload(block);
                    return original == *block;
                }
                let Some(fields) = block.as_object_mut() else { return false };
                let Some(text) = fields.get_mut("text") else { return false };
                let Some(source) = text.as_str() else { return false };
                if let Ok(mut embedded @ (Value::Object(_) | Value::Array(_))) = serde_json::from_str::<Value>(source) {
                    let original = embedded.clone();
                    self.redact_payload(&mut embedded);
                    if original != embedded { *text = Value::String(embedded.to_string()); }
                } else {
                    self.redact_payload(text);
                }
                for (key, field) in fields.iter_mut() {
                    if key != "type" && key != "text" { self.redact_payload(field); }
                }
                true
            });
        }
        // The MCP discriminants and error bit describe the operation, independently of its payload.
        result.retain(|key, _| matches!(key.as_str(), "content" | "structuredContent" | "_meta" | "isError" | "resultType"));
        if let Some(cap) = self.max_bytes {
            if serde_json::to_vec(&value).map_err(|_| error("Invalid extension result encoding"))?.len() > cap {
                return Err(error("Extension result exceeds its approved byte cap"));
            }
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn policy(config: Value) -> Result<ResultPolicy> {
        let policy: ResultPolicy = serde_json::from_value(config).map_err(|_| error("bad policy"))?;
        policy.validate()?;
        Ok(policy)
    }

    #[test]
    fn allow_projects_escaped_keys_and_original_array_indices_without_raw_text_or_metadata() {
        let config = policy(json!({"allow":["/meta/a~1b","/meta/~01","/items/2/name","/items/0/name"]})).unwrap();
        let input = json!({"content":[{"type":"text","text":"unfiltered"}],"isError":false,"_meta":{"private":"unfiltered"},
            "structuredContent":{"meta":{"a/b":1,"~1":2,"/":3},"items":[{"name":"a","x":"unfiltered"},{},{"name":"b"}]}});
        assert_eq!(config.apply(input).unwrap(), json!({"content":[],"isError":false,
            "structuredContent":{"meta":{"a/b":1,"~1":2},"items":[{"name":"a"},{"name":"b"}]}}));
    }

    #[test]
    fn deny_preserves_array_order_and_requires_structured_content() {
        let config = policy(json!({"deny":["/rows/1","/rows/3","/credential"]})).unwrap();
        let input = json!({"content":[],"isError":true,"structuredContent":{"rows":[0,1,2,3],"credential":"private"}});
        assert_eq!(config.apply(input).unwrap(),json!({"isError":true,"content":[],"structuredContent":{"rows":[0,2]}}));
        assert!(config.apply(json!({"content":[{"type":"text","text":"unfiltered"}]})).is_err());
        for invalid in [json!({"allow":[],"deny":[""]}), json!({"deny":["/~2"]}), json!({"allow":["invalid"]}),
                        json!({"mask_literals":[""]}), json!({"max_bytes":0})] {
            assert!(policy(invalid).is_err());
        }
    }

    #[test]
    fn configured_literals_never_change_mcp_error_or_content_discriminants() {
        let input = json!({"isError":true,"resultType":"complete","content":[{"type":"text","text":"operator-value"}]});
        let p = policy(json!({"mask_literals":["isError","content","type","text","complete","operator-value"]})).unwrap();
        assert_eq!(p.apply(input).unwrap(), json!({"isError":true,"resultType":"complete",
            "content":[{"type":"text","text":"[REDACTED]"}]}));
    }

    #[test]
    fn plaintext_credentials_and_unlabelled_mirrors_do_not_survive_redaction() {
        let p = ResultPolicy::default();
        for data in ["account password=sample-credential", "Authorization: Basic c3ludGhldGlj",
            "api_key: multiple words containing confidential data", "accessToken = example-data"] {
            let out = p.apply(json!({"content":[{"type":"text","text":data}]})).unwrap();
            assert_eq!(out["content"][0]["text"], "[REDACTED]");
        }
        let input = json!({"structuredContent":{"password":"ordinary-value-without-a-prefix","name":"safe"},
            "content":[{"type":"text","text":"Your value is ordinary-value-without-a-prefix."}]});
        let out = p.apply(input).unwrap();
        assert!(!out.to_string().contains("ordinary-value-without-a-prefix"));
        assert_eq!(out["structuredContent"]["name"], "safe");
    }

    #[test]
    fn limits_measure_utf8_and_masks_apply_to_mcp_text_and_structured_content() {
        let data = json!({"content":[{"type":"text","text":"{\"password\":\"example-value\"}"}],
                          "structuredContent":{"user":"contains private-fragment here","key-private-fragment":2,
                            (format!("{}_ExampleFixtureToken", "ghp")):"key secret","ok":"éÉ"}});
        let result = policy(json!({"mask_literals":["private-fragment"]})).unwrap().apply(data.clone()).unwrap();
        assert!(!result.to_string().contains("private-fragment"));
        assert!(!result.to_string().contains("example-value"));
        assert!(!result.to_string().contains("ExampleFixtureToken"));
        let length = result.to_string().len();
        assert!(policy(json!({"mask_literals":["private-fragment"], "max_bytes":length})).unwrap().apply(data.clone()).is_ok());
        assert!(policy(json!({"mask_literals":["private-fragment"], "max_bytes":length-1})).unwrap().apply(data).is_err());
    }
}
