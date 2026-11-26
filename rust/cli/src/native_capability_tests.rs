use super::*;
use crate::backend::{OperatorRead, OperatorWrite};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
const ORIGIN: &str = "https://native-capability.example.invalid";
const CALLBACK: &str = "https://oauth-redirect.googleusercontent.com/r/native-capability";
struct Fixture { operator: NativeOperator, root: PathBuf, id: String, marker: Value }
impl Fixture {
    fn new() -> Self {
        let base = crate::test_state_base();
        let root = base.join(format!("native-capability-{}-{}", std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)));
        agent_bridge_lifecycle::initialize_operator_settings(&root).unwrap();
        for entry in std::fs::read_dir(&root).unwrap() {
            let path = entry.unwrap().path();
            if path.is_file() { std::fs::remove_file(path).unwrap(); }
        }
        LocalOwner::open(OAuthConfig { state_dir: root.clone(), public_origin: ORIGIN.into(),
            audience: Audience::Workstation }).unwrap();
        let id = "I".repeat(43);
        let marker = json!({"kind":"unified-v1","manifest_sha256":"ab".repeat(32),
            "catalogue_sha256":"cd".repeat(32),"policy_version":1});
        let expires = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64 + 60_000;
        crate::write_private(root.join("requests-workstation").join(format!("{id}.json")),
            serde_json::to_vec(&json!({"id":id,"clientId":format!("gemini_{}", "C".repeat(43)),
                "redirect":CALLBACK,"scope":"mcp","resource":format!("{ORIGIN}/mcp"),
                "expires":expires,"bindingHash":"B".repeat(43),"audience":"workstation",
                "capability":marker})).unwrap());
        let operator = NativeOperator::new(UiConfig { port: 0, database: None, settings_dir: None,
            oauth_state: Some(root.clone()), oauth_origin: Some(ORIGIN.into()),
            oauth_audience: Some(Audience::Workstation), project: None, open_browser: false,
            capability_selection: Some(json!({"identity":marker,"total_tools":46,"filesystem":{"kind":"workspace"}})),
            request_audit: None,
        }, ProfileControl::new(DesktopProfile::FullyUnlocked), None);
        Self { operator, root, id, marker }
    }
}
impl Drop for Fixture { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.root); } }

#[tokio::test]
async fn native_capability_review_returns_exact_grant_contract() {
    let fixture = Fixture::new();
    let reply = fixture.operator.get(OperatorRead::OAuth).await.unwrap();
    assert_eq!(reply.status, 200);
    assert_eq!(reply.body["pending"][0]["capability"], fixture.marker,
        "native owner must see the full exact contract before granting it");
}

#[tokio::test]
async fn native_capability_approval_requires_reviewed_contract_and_callback() {
    let fixture = Fixture::new();
    for payload in [
        json!({"request_id":fixture.id,"redirect_uri":CALLBACK,"confirm":"APPROVE"}),
        json!({"request_id":fixture.id,"redirect_uri":CALLBACK,"confirm":"APPROVE",
            "capability":{"kind":"legacy"}}),
        json!({"request_id":fixture.id,"redirect_uri":"https://oauth-redirect.googleusercontent.com/r/other",
            "confirm":"APPROVE","capability":fixture.marker}),
    ] {
        let reply = fixture.operator.post(OperatorWrite::OAuthApprove, payload).await.unwrap();
        assert_ne!(reply.status, 200, "a stale/missing contract or mismatched callback cannot approve");
        assert!(!fixture.root.join("requests-workstation").join(format!("{}.approved",fixture.id)).exists());
    }
    let reply = fixture.operator.post(OperatorWrite::OAuthApprove,
        json!({"request_id":fixture.id,"redirect_uri":CALLBACK,"confirm":"APPROVE",
            "capability":fixture.marker})).await.unwrap();
    assert_eq!(reply.status, 200);
    let approved: Value = serde_json::from_slice(&std::fs::read(
        fixture.root.join("requests-workstation").join(format!("{}.approved",fixture.id))).unwrap()).unwrap();
    assert_eq!(approved["capability"], fixture.marker);
}

#[tokio::test]
async fn native_capability_selection_is_visible_in_diagnostics_and_request_review() {
    let fixture = Fixture::new();
    for operation in [OperatorRead::Diagnostics,OperatorRead::OAuth] {
        let reply = fixture.operator.get(operation).await.unwrap();
        assert_eq!(reply.status,200);
        assert_eq!(reply.body["capability_selection"]["identity"],fixture.marker);
        assert_eq!(reply.body["capability_selection"]["total_tools"],46);
        assert_eq!(reply.body["capability_selection"]["filesystem"]["kind"],"workspace");
    }
}
