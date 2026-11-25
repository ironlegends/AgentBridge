//! Versioned public contract identity. This contains digests, never bearer secrets.
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum CapabilityIdentity {
    #[default]
    Legacy,
    UnifiedV1 {
        manifest_sha256: String,
        catalogue_sha256: String,
        policy_version: u32,
    },
}

impl CapabilityIdentity {
    pub fn is_legacy(&self) -> bool { matches!(self, Self::Legacy) }

    pub fn validate(&self) -> bool {
        match self {
            Self::Legacy => true,
            Self::UnifiedV1 { manifest_sha256, catalogue_sha256, policy_version } =>
                *policy_version == 1 && sha256_hex(manifest_sha256) && sha256_hex(catalogue_sha256),
        }
    }

    /// Absence is the historical format. Present values must be fully known
    /// and well-formed; null/partial/future values never become Legacy.
    pub fn from_marker(marker: Option<&Value>) -> Result<Self, &'static str> {
        let Some(value) = marker else { return Ok(Self::Legacy); };
        let invalid = "invalid_capability_identity";
        let record = value.as_object().ok_or(invalid)?;
        let identity = match record.get("kind").and_then(Value::as_str) {
            Some("legacy") if record.len() == 1 => Self::Legacy,
            Some("unified-v1") if record.len() == 4 => Self::UnifiedV1 {
                manifest_sha256: record.get("manifest_sha256").and_then(Value::as_str)
                    .ok_or(invalid)?.to_owned(),
                catalogue_sha256: record.get("catalogue_sha256").and_then(Value::as_str)
                    .ok_or(invalid)?.to_owned(),
                policy_version: record.get("policy_version").and_then(Value::as_u64)
                    .and_then(|value| u32::try_from(value).ok()).ok_or(invalid)?,
            },
            _ => return Err(invalid),
        };
        if !identity.validate() { return Err(invalid); }
        Ok(identity)
    }
}

impl<'de> Deserialize<'de> for CapabilityIdentity {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct IdentityVisitor;
        impl<'de> serde::de::Visitor<'de> for IdentityVisitor {
            type Value = CapabilityIdentity;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("one unambiguous capability identity")
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(self, mut input: M) -> Result<Self::Value, M::Error> {
                let mut fields = serde_json::Map::new();
                while let Some((key, value)) = input.next_entry::<String, Value>()? {
                    if fields.insert(key, value).is_some() {
                        return Err(serde::de::Error::custom("duplicate_capability_field"));
                    }
                    if fields.len() > 4 {
                        return Err(serde::de::Error::custom("invalid_capability_identity"));
                    }
                }
                CapabilityIdentity::from_marker(Some(&Value::Object(fields)))
                    .map_err(serde::de::Error::custom)
            }
        }
        deserializer.deserialize_map(IdentityVisitor)
    }
}

fn sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
