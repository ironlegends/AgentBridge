use agent_bridge_oauth_compat::{
    Audience, DiagnosticCode, HistoricalSnapshot, InspectionPolicy, ReadError,
};
use serde_json::json;

#[test]
fn oauth_compat_inspection_duplicate_keys_redaction_and_revocation_gap_regressions() {
    let policy = InspectionPolicy {
        audience: Audience::Missions,
        resource: "https://bridge.example.invalid/mcp",
        at_epoch_ms: 1_760_000_000_000,
    };

    // Debug redacts sensitive fields
    let policy_dbg = format!("{policy:?}");
    assert!(!policy_dbg.contains("bridge.example.invalid"));

    // Duplicate JSON keys rejected rather than silently overwriting
    let dup = br#"{"schema":1,"schema":1,"clients":{},"grants":{},"access":{}}"#;
    assert_eq!(
        HistoricalSnapshot::from_json_bytes(dup).unwrap_err(),
        ReadError::InvalidJson
    );

    // Non-object root rejected
    assert_eq!(
        HistoricalSnapshot::from_json_str("[]").unwrap_err(),
        ReadError::NonObjectRoot
    );

    // Valid empty missions snapshot passes cleanly and preserves unknown fields losslessly
    let valid_doc = json!({
        "schema": 1,
        "clients": {},
        "grants": {},
        "access": {},
        "custom_preserved_marker": "keep-me"
    });
    let snap = HistoricalSnapshot::from_json_str(&valid_doc.to_string()).expect("parse valid");
    assert!(format!("{snap:?}").contains("sensitive data withheld"));
    let report = snap.inspect(policy).expect("inspect valid");
    assert!(!report.has_diagnostics(), "unexpected diagnostics: {report:?}");
    let preserved = snap.into_preserved_value();
    assert_eq!(preserved["custom_preserved_marker"], "keep-me");

    // Unsupported schema, audience mismatch, and unknown revocation extension are all flagged
    let bad_doc = json!({
        "schema": 99,
        "audience": "workstation",
        "revoked": true,
        "clients": {},
        "grants": {},
        "access": {}
    });
    let bad_snap = HistoricalSnapshot::from_json_str(&bad_doc.to_string()).expect("parse bad");
    let bad_report = bad_snap.inspect(policy).expect("inspect bad");
    assert!(bad_report.has_diagnostics());
    let codes: Vec<DiagnosticCode> = bad_report.diagnostics.iter().map(|d| d.code).collect();
    assert!(codes.contains(&DiagnosticCode::UnsupportedSchema));
    assert!(codes.contains(&DiagnosticCode::AudienceMismatch));
    assert!(codes.contains(&DiagnosticCode::RevocationExtensionPresent));
}
