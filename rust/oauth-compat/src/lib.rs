//! Read-only compatibility inspection for the historical Agent Bridge Gemini
//! OAuth sidecar's persistent JSON schema 1. No authentication happens here.
//!
//! Historical Agent Bridge schema and behavior:
//!   gateway/src/gemini-access.mjs:
//!     oauthPaths / startGeminiAccess (the two separate OAuth JSON audiences);
//!     default data and schema checks (schema 1, clients, grants, access);
//!     prune / validGrant / /oauth/revoke (expiration, missing grants, revocation);
//!     registration / authorization-code / refresh-token branches (record fields).
//!   docs/operations.md ("Gemini Web personnel" and Unix workstation connection)
//!   docs/architecture.md ("Personal Gemini access").
//!
//! The public metadata contract has scope "mcp" and an HTTPS resource ending
//! in "/mcp". Workstation OAuth is a distinct audience; neither its top-level
//! state nor its grants are interchangeable with the legacy mission audience.
//!
//! This crate has no filesystem/network/configuration/identity access, token
//! generation, verification endpoint or transport. Only caller-supplied bytes
//! and an independently supplied comparison policy are inspected. Never use a
//! compatibility report as an authorization decision. Revocation can happen
//! AFTER any offline snapshot, and the caller must never infer a new grant
//! from an orphaned access record, a cached hash, or an unknown extension.
//!
//! Parsed JSON fields (including unknown fields, legacy integer timestamps,
//! fingerprints provided BY THE CALLER, and expired/tombstoned rows) are
//! retained without pruning or migration. JSON whitespace/number spellings
//! are not byte-preserved, and ambiguous duplicate keys are rejected.
//! Diagnostics contain only fixed codes and aggregate counts: never keys,
//! token digests, URLs or secret values.

mod capability;
pub use capability::CapabilityIdentity;

use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use serde_json::{Map, Number, Value};
use std::collections::{BTreeMap, HashMap};
use std::fmt;

pub const LEGACY_SCHEMA: i64 = 1;
pub const PUBLIC_SCOPE: &str = "mcp";
pub const MAX_INPUT_BYTES: usize = 8 * 1024 * 1024;
const JS_MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadError {
    /// The supplied byte slice is too large; no I/O was attempted.
    InputTooLarge,
    /// Invalid JSON, including any duplicate object key at any depth.
    InvalidJson,
    /// The historical state is a JSON object, not an array or scalar.
    NonObjectRoot,
    /// A policy must supply a timestamp and independently trusted resource.
    InvalidInspectionPolicy,
}

impl fmt::Display for ReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InputTooLarge => "input_exceeds_limit",
            Self::InvalidJson => "invalid_or_ambiguous_json",
            Self::NonObjectRoot => "oauth_state_must_be_object",
            Self::InvalidInspectionPolicy => "invalid_inspection_policy",
        };
        formatter.write_str(message)
    }
}
impl std::error::Error for ReadError {}

/// The two disjoint storage audiences from gemini-access.mjs.
/// The original mission store typically OMITTED an audience marker entirely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Audience {
    Missions,
    Workstation,
}

/// Expectations MUST be provided independently of the untrusted document.
/// The resource is a public comparison value, not a URL to contact.
#[derive(Clone, Copy)]
pub struct InspectionPolicy<'a> {
    pub audience: Audience,
    pub resource: &'a str,
    /// A caller-supplied UTC Unix timestamp in INTEGER MILLISECONDS.
    pub at_epoch_ms: i64,
}

impl fmt::Debug for InspectionPolicy<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never echo a supplied resource URL in diagnostic output.
        f.debug_struct("InspectionPolicy")
            .field("audience", &self.audience)
            .field("resource", &"[redacted]")
            .field("at_epoch_ms", &self.at_epoch_ms)
            .finish()
    }
}

/// A fixed, value-free compatibility/integrity diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DiagnosticCode {
    UnsupportedSchema,
    AudienceMismatch,
    MissingOrInvalidClients,
    MissingOrInvalidGrants,
    MissingOrInvalidAccess,
    MalformedClientRecord,
    MalformedGrantRecord,
    MalformedAccessRecord,
    HistoricalClientTtlElapsed,
    ExpiredGrant,
    ExpiredAccess,
    OrphanedAccess,
    MissingClientForGrant,
    GrantResourceMismatch,
    GrantScopeMismatch,
    GrantAudienceMismatch,
    AccessReferencesIneligibleGrant,
    RevocationExtensionPresent,
}

/// A diagnostic has no user-controlled string fields or record identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Diagnostic {
    pub code: DiagnosticCode,
    pub count: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RecordCounts {
    pub clients: usize,
    pub grants: usize,
    pub access: usize,
}

/// An offline *format* assessment, NOT a security token, permission or grant.
#[derive(Debug, Clone)]
pub struct CompatibilityReport {
    /// True only if schema, audience, collections, and known record shapes
    /// conform to the inspected legacy format; expiration is NOT a migration.
    pub format_compatible: bool,
    pub records: RecordCounts,
    pub diagnostics: Vec<Diagnostic>,
}

impl CompatibilityReport {
    /// True means a structural or reference-integrity issue merits review.
    /// Expired rows are not repaired or removed regardless of this value.
    pub fn has_diagnostics(&self) -> bool {
        !self.diagnostics.is_empty()
    }
}

/// Opaque in-memory snapshot preserving all source fields, including unknown
/// properties in every nested object. No Debug, Display, logging, or automatic
/// serialization of sensitive material is exposed.
pub struct HistoricalSnapshot {
    original: Value,
}
impl fmt::Debug for HistoricalSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HistoricalSnapshot([sensitive data withheld])")
    }
}
impl HistoricalSnapshot {
    /// Parse only supplied bytes, with size/depth limits enforced by
    /// serde_json. Duplicate JSON keys are rejected rather than silently
    /// overwriting an existing revocation or grant object.
    pub fn from_json_bytes(input: &[u8]) -> Result<Self, ReadError> {
        if input.len() > MAX_INPUT_BYTES {
            return Err(ReadError::InputTooLarge);
        }
        let NoDuplicateValue(original) =
            serde_json::from_slice::<NoDuplicateValue>(input)
                .map_err(|_| ReadError::InvalidJson)?;
        if !original.is_object() {
            return Err(ReadError::NonObjectRoot);
        }
        Ok(Self { original })
    }

    pub fn from_json_str(input: &str) -> Result<Self, ReadError> {
        Self::from_json_bytes(input.as_bytes())
    }

    /// Caller-controlled, explicit lossless preservation of parsed JSON
    /// fields. This returns the caller's sensitive data as-is. It does NOT
    /// authorize its use, refresh it, or write it anywhere.
    pub fn into_preserved_value(self) -> Value {
        self.original
    }

    /// Inspect only metadata types, epoch millisecond deadlines, references
    /// and audience/resource equality. No token, hash or secret is decoded.
    /// No stored expiration or unknown field is changed.
    pub fn inspect(&self, policy: InspectionPolicy<'_>) -> Result<CompatibilityReport, ReadError> {
        if !valid_policy(policy) {
            return Err(ReadError::InvalidInspectionPolicy);
        }
        let root = self.original.as_object().ok_or(ReadError::NonObjectRoot)?;
        let mut issues = IssueAccumulator::default();
        let mut structural = true;

        if root.get("schema").and_then(Value::as_i64) != Some(LEGACY_SCHEMA) {
            issues.add(DiagnosticCode::UnsupportedSchema);
            structural = false;
        }
        if !audience_matches(root.get("audience"), policy.audience) {
            issues.add(DiagnosticCode::AudienceMismatch);
            structural = false;
        }

        let clients = root.get("clients").and_then(Value::as_object);
        let grants = root.get("grants").and_then(Value::as_object);
        let access = root.get("access").and_then(Value::as_object);
        if clients.is_none() {
            issues.add(DiagnosticCode::MissingOrInvalidClients);
            structural = false;
        }
        if grants.is_none() {
            issues.add(DiagnosticCode::MissingOrInvalidGrants);
            structural = false;
        }
        if access.is_none() {
            issues.add(DiagnosticCode::MissingOrInvalidAccess);
            structural = false;
        }
        let records = RecordCounts {
            clients: clients.map_or(0, Map::len),
            grants: grants.map_or(0, Map::len),
            access: access.map_or(0, Map::len),
        };

        // The source's /oauth/revoke deletes the GRANT. It does not emit a new
        // grant or tombstone. Never reconstruct a removed grant from access.
        // Unknown revocation extensions are preserved and explicitly flagged;
        // any such marker disqualifies the associated record from evaluation.
        let global_revocation_unknown = contains_revocation_extension(root);
        if global_revocation_unknown {
            issues.add(DiagnosticCode::RevocationExtensionPresent);
        }

        let mut valid_clients = HashMap::<&str, bool>::new();
        if let Some(clients) = clients {
            for (id, value) in clients {
                let Some(record) = value.as_object() else {
                    issues.add(DiagnosticCode::MalformedClientRecord);
                    structural = false;
                    valid_clients.insert(id.as_str(), false);
                    continue;
                };
                // Stored after an exact owner-approved authorization:
                // redirects, method, secretHash, created and provisional
                // expires. The stored provisional TTL is NOT the grant TTL;
                // the original sidecar does not use client.expires for
                // authorization after the client becomes persistent.
                let redirects_valid = record.get("redirects")
                    .and_then(Value::as_array)
                    .is_some_and(|redirects| !redirects.is_empty()
                        && redirects.len() <= 6
                        && redirects.iter().all(|value| value.as_str()
                            .is_some_and(|text| !text.is_empty())));
                let method_valid = matches!(
                    record.get("method").and_then(Value::as_str),
                    Some("client_secret_basic" | "client_secret_post")
                );
                // Check ONLY type/presence, not the sensitive hash contents.
                let hash_present = record.get("secretHash").is_some_and(Value::is_string);
                let created_valid = optional_epoch_ms(record, "created");
                let expiry_valid = optional_epoch_ms(record, "expires");
                let valid = redirects_valid && method_valid && hash_present
                    && created_valid && expiry_valid;
                if !valid {
                    issues.add(DiagnosticCode::MalformedClientRecord);
                    structural = false;
                }
                if let Some(expires) = record.get("expires").and_then(epoch_ms) {
                    if expires <= policy.at_epoch_ms {
                        issues.add(DiagnosticCode::HistoricalClientTtlElapsed);
                    }
                }
                let revoked = contains_revocation_extension(record);
                if revoked {
                    issues.add(DiagnosticCode::RevocationExtensionPresent);
                }
                valid_clients.insert(id.as_str(), valid && !revoked);
            }
        }

        let mut current_grants = HashMap::<&str, bool>::new();
        if let Some(grants) = grants {
            for (id, value) in grants {
                let Some(record) = value.as_object() else {
                    issues.add(DiagnosticCode::MalformedGrantRecord);
                    structural = false;
                    current_grants.insert(id.as_str(), false);
                    continue;
                };
                let client_id = record.get("clientId").and_then(Value::as_str);
                let resource = record.get("resource").and_then(Value::as_str);
                let scope = record.get("scope").and_then(Value::as_str);
                // Presence/type only: never read or reproduce refreshHash.
                let refresh_hash_present =
                    record.get("refreshHash").is_some_and(Value::is_string);
                let expiry = record.get("expires").and_then(epoch_ms);
                let shape_valid = client_id.is_some() && resource.is_some()
                    && scope.is_some() && refresh_hash_present && expiry.is_some()
                    && CapabilityIdentity::from_marker(record.get("capability")).is_ok();
                if !shape_valid {
                    issues.add(DiagnosticCode::MalformedGrantRecord);
                    structural = false;
                }

                let client_valid = client_id
                    .and_then(|client| valid_clients.get(client).copied())
                    .unwrap_or(false);
                if client_id.is_some() && !client_valid {
                    issues.add(DiagnosticCode::MissingClientForGrant);
                    structural = false;
                }
                let same_resource = resource == Some(policy.resource);
                if resource.is_some() && !same_resource {
                    issues.add(DiagnosticCode::GrantResourceMismatch);
                    structural = false;
                }
                let same_scope = scope == Some(PUBLIC_SCOPE);
                if scope.is_some() && !same_scope {
                    issues.add(DiagnosticCode::GrantScopeMismatch);
                    structural = false;
                }
                let same_audience = audience_matches(record.get("audience"), policy.audience);
                if !same_audience {
                    issues.add(DiagnosticCode::GrantAudienceMismatch);
                    structural = false;
                }
                let not_expired = expiry.is_some_and(|until| until > policy.at_epoch_ms);
                if expiry.is_some() && !not_expired {
                    issues.add(DiagnosticCode::ExpiredGrant);
                }
                let revoked = contains_revocation_extension(record);
                if revoked {
                    issues.add(DiagnosticCode::RevocationExtensionPresent);
                }

                // Private, transient metadata for orphan-reference diagnostics.
                // NEVER exported as a grant decision. An offline copy cannot
                // know of a revocation that happened after capture.
                current_grants.insert(
                    id.as_str(),
                    shape_valid && client_valid && same_resource && same_scope
                        && same_audience && not_expired && !revoked
                        && !global_revocation_unknown && structural_root(root, policy.audience),
                );
            }
        }

        if let Some(access) = access {
            for (_digest_key, value) in access {
                let Some(record) = value.as_object() else {
                    issues.add(DiagnosticCode::MalformedAccessRecord);
                    structural = false;
                    continue;
                };
                let grant_id = record.get("grant").and_then(Value::as_str);
                let expiry = record.get("expires").and_then(epoch_ms);
                if grant_id.is_none() || expiry.is_none() {
                    issues.add(DiagnosticCode::MalformedAccessRecord);
                    structural = false;
                }
                let not_expired = expiry.is_some_and(|until| until > policy.at_epoch_ms);
                if expiry.is_some() && !not_expired {
                    issues.add(DiagnosticCode::ExpiredAccess);
                }
                if let Some(grant_id) = grant_id {
                    match current_grants.get(grant_id).copied() {
                        None => {
                            // The source's prune() removes such records.
                            // Preserve them in the returned document, but
                            // never treat the dangling hash as permission.
                            issues.add(DiagnosticCode::OrphanedAccess);
                        }
                        Some(false) => {
                            issues.add(DiagnosticCode::AccessReferencesIneligibleGrant);
                        }
                        Some(true) => {}
                    }
                }
                if contains_revocation_extension(record) {
                    issues.add(DiagnosticCode::RevocationExtensionPresent);
                }
                // Even a structurally consistent access remains untrusted:
                // no authentication, bearer comparison or entitlement here.
            }
        }

        Ok(CompatibilityReport {
            format_compatible: structural,
            records,
            diagnostics: issues.into_diagnostics(),
        })
    }
}

/// Shorthand: parse and inspect provided bytes without any external lookups.
/// For a preserving round-trip, keep HistoricalSnapshot rather than this report.
pub fn inspect_provided_json(
    input: &[u8],
    policy: InspectionPolicy<'_>,
) -> Result<CompatibilityReport, ReadError> {
    HistoricalSnapshot::from_json_bytes(input)?.inspect(policy)
}

fn valid_policy(policy: InspectionPolicy<'_>) -> bool {
    policy.at_epoch_ms >= 0
        && policy.at_epoch_ms <= JS_MAX_SAFE_INTEGER
        && policy.resource.starts_with("https://")
        && policy.resource.ends_with("/mcp")
        && !policy.resource.chars().any(|ch| {
            matches!(ch, '?' | '#' | '@') || ch.is_whitespace()
        })
        && policy.resource.len() <= 8192
}
fn structural_root(root: &Map<String, Value>, audience: Audience) -> bool {
    root.get("schema").and_then(Value::as_i64) == Some(LEGACY_SCHEMA)
        && audience_matches(root.get("audience"), audience)
}
fn audience_matches(stored: Option<&Value>, expected: Audience) -> bool {
    match (expected, stored) {
        (Audience::Missions, None) => true, // the actual historical default
        (Audience::Missions, Some(Value::String(value))) if value == "missions" => true,
        (Audience::Workstation, Some(Value::String(value))) if value == "workstation" => true,
        _ => false,
    }
}
fn epoch_ms(value: &Value) -> Option<i64> {
    let millis = value.as_i64()?;
    (0..=JS_MAX_SAFE_INTEGER).contains(&millis).then_some(millis)
}
fn optional_epoch_ms(record: &Map<String, Value>, key: &str) -> bool {
    record.get(key).map_or(true, |value| epoch_ms(value).is_some())
}
fn contains_revocation_extension(record: &Map<String, Value>) -> bool {
    // Legacy schema 1 has NO persistent tombstone field. Preserve all
    // unknown fields; an extension implying revoked/disabled status must
    // never be silently interpreted as approval or normalized away.
    const REVOCATION_FIELDS: [&str; 10] = [
        "revoked", "revokedAt", "revoked_at", "revocation",
        "revocations", "revoked_on", "revokedUntil", "disabled",
        "tombstones", "revokedGrants",
    ];
    REVOCATION_FIELDS.iter().any(|field| record.contains_key(*field))
        || record.get("state").is_some_and(|value| value.as_str() != Some("active"))
        || record.get("status").is_some_and(|value| value.as_str() != Some("active"))
}

#[derive(Default)]
struct IssueAccumulator(BTreeMap<DiagnosticCode, usize>);
impl IssueAccumulator {
    fn add(&mut self, code: DiagnosticCode) {
        *self.0.entry(code).or_default() += 1;
    }
    fn into_diagnostics(self) -> Vec<Diagnostic> {
        self.0.into_iter()
            .map(|(code, count)| Diagnostic { code, count })
            .collect()
    }
}

/// A recursive JSON visitor that refuses duplicate keys at ANY nesting depth.
/// Serde's normal Value parser would silently use the last duplicate. That
/// could conceal a deleted grant, revocation marker or expiration field.
struct NoDuplicateValue(Value);
impl<'de> Deserialize<'de> for NoDuplicateValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct UniqueVisitor;
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = NoDuplicateValue;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("JSON with unique object keys")
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(NoDuplicateValue(Value::Null))
            }
            fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                self.visit_unit()
            }
            fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(NoDuplicateValue(Value::Bool(value)))
            }
            fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(NoDuplicateValue(Value::Number(value.into())))
            }
            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(NoDuplicateValue(Value::Number(value.into())))
            }
            fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
                Number::from_f64(value)
                    .map(Value::Number)
                    .map(NoDuplicateValue)
                    .ok_or_else(|| E::custom("non-finite JSON number"))
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(NoDuplicateValue(Value::String(value.to_owned())))
            }
            fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(NoDuplicateValue(Value::String(value)))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(NoDuplicateValue(value)) = sequence.next_element()? {
                    values.push(value);
                }
                Ok(NoDuplicateValue(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut values = Map::new();
                while let Some((key, NoDuplicateValue(value))) =
                    map.next_entry::<String, NoDuplicateValue>()?
                {
                    if values.contains_key(&key) {
                        return Err(de::Error::custom("duplicate JSON object key"));
                    }
                    values.insert(key, value);
                }
                Ok(NoDuplicateValue(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(UniqueVisitor)
    }
}
