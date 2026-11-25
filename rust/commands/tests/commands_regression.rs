use agent_bridge_commands::{
    CommandDecisionEngine, CommandError, CommandRequest, EngineLimits, EnvironmentVerifier,
    ExecutionOutcome, FsEnvironmentVerifier, OperatorPolicy, RequestStatusView, RequesterContext,
    Sha256Digest, SubmissionOutcome,
};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static SEQ: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);
impl TempDir {
    fn new(label: &str) -> Self {
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = { let t = std::env::temp_dir(); if cfg!(unix) { std::fs::canonicalize(&t).unwrap_or(t) } else { t } }.join(format!("ab-cmd-test-{label}-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp dir");
        Self(dir)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn predefined_approval_one_use_permit_and_tamper_regressions() {
    let tmp = TempDir::new("cmd");
    let ws = tmp.0.join("ws");
    let tools = tmp.0.join("tools");
    fs::create_dir_all(&ws).unwrap();
    fs::create_dir_all(&tools).unwrap();

    let exe = tools.join("tool.exe");
    fs::write(&exe, b"pinned-binary-v1").unwrap();

    let verifier = FsEnvironmentVerifier;
    let pin = verifier.verify_executable(&exe).expect("verify exe");
    let limits = EngineLimits::default();

    let policy = OperatorPolicy::builder(&ws)
        .add_predefined("safe-tool", &exe, pin.sha256, vec!["--version".into()], &ws)
        .build(&verifier, &limits)
        .expect("build policy");

    let engine = CommandDecisionEngine::with_fs_verifier(policy, limits);
    let (web, operator, gate) = engine.split();
    let who = RequesterContext::new("web-test").unwrap();

    // 1. Exact predefined command gets PredefinedApproved and one-use permit
    let out = web
        .submit(&who, CommandRequest::new(&exe, vec!["--version".into()], &ws))
        .expect("submit predefined");
    let req_id = match out {
        SubmissionOutcome::PredefinedApproved { request_id, .. } => request_id,
        other => panic!("expected PredefinedApproved, got {other:?}"),
    };

    let permit = gate.consume(&req_id).expect("first consume");
    // Double consume MUST fail closed
    assert!(gate.consume(&req_id).is_err(), "double consume must fail");
    gate.finish(
        permit,
        ExecutionOutcome::Completed {
            exit_code: 0,
            summary: Some("ok".into()),
        },
    )
    .expect("finish");

    // 2. Different argument MUST require PendingLocalConfirmation (never auto-approved)
    let out2 = web
        .submit(&who, CommandRequest::new(&exe, vec!["--other".into()], &ws))
        .expect("submit non-predefined");
    let req2 = match out2 {
        SubmissionOutcome::PendingLocalConfirmation { request_id, .. } => request_id,
        other => panic!("expected PendingLocalConfirmation, got {other:?}"),
    };

    // Gate refuses unapproved request
    assert!(gate.consume(&req2).is_err());

    // Wrong confirmation digest rejected
    let view = operator.inspect_pending(&req2).expect("inspect pending");
    let bad_digest = Sha256Digest::from_hex(&"0".repeat(64)).unwrap();
    assert!(matches!(
        operator.approve(&req2, bad_digest),
        Err(CommandError::ConfirmationMismatch)
    ));

    // Exact digest approves; then tampering binary before consume fails closed
    operator
        .approve(&req2, view.confirmation_digest)
        .expect("approve with exact digest");
    assert!(matches!(
        operator.status(&req2).unwrap(),
        RequestStatusView::Approved { .. }
    ));

    fs::write(&exe, b"tampered-binary-v2").unwrap();
    assert!(
        gate.consume(&req2).is_err(),
        "binary modified after approval must fail closed at consume"
    );

    // 3. Working directory outside workspace must be rejected
    let outside = tmp.0.join("outside");
    fs::create_dir_all(&outside).unwrap();
    assert!(
        web.submit(&who, CommandRequest::new(&exe, vec![], &outside))
            .is_err(),
        "cwd outside workspace must be refused"
    );
}
