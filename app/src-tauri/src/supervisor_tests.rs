use super::*;
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::rc::Rc;

fn safe_policy() -> TaskPolicy {
    TaskPolicy { enabled: true, on_demand: true, current_user: true, least_privilege: true, ignore_new: true }
}

#[test]
fn task_policy_rejects_each_authority_or_ownership_mismatch() {
    assert!(safe_policy().validate().is_ok());
    for index in 0..5 {
        let mut policy = safe_policy();
        match index {
            0 => policy.enabled = false,
            1 => policy.on_demand = false,
            2 => policy.current_user = false,
            3 => policy.least_privilege = false,
            _ => policy.ignore_new = false,
        }
        assert!(policy.validate().is_err(), "unsafe policy accepted at {index}");
    }
}

#[test]
fn supervisor_configuration_accepts_only_a_literal_local_task_name() {
    let valid: SupervisorConfig = serde_json::from_str(
        r#"{"kind":"windows-task","taskName":"\\AgentBridge-Rust-Workstation"}"#,
    ).unwrap();
    assert!(valid.validate().is_ok());
    for name in ["", " task ", "\\", "task*", "task?", "task\nother", "task\0other", "\\\\remote\\task"] {
        let value = serde_json::json!({"kind":"windows-task", "taskName":name});
        let config: SupervisorConfig = serde_json::from_value(value).unwrap();
        assert!(config.validate().is_err(), "accepted {name:?}");
    }
    for value in [
        serde_json::json!({"kind":"shell", "command":"anything"}),
        serde_json::json!({"kind":"windows-task", "taskName":"Task", "command":"anything"}),
    ] {
        assert!(serde_json::from_value::<SupervisorConfig>(value).is_err());
    }
}

type Events = Rc<RefCell<Vec<&'static str>>>;
struct FakeOwner { events: Events, remaining: usize, runs: usize, reject_run: bool }
impl TaskOwner for FakeOwner {
    fn state(&mut self) -> Result<TaskState, String> {
        if self.runs > 0 { return Ok(TaskState::Running); }
        if self.remaining > 0 {
            self.remaining -= 1;
            self.events.borrow_mut().push("owner-running");
            Ok(TaskState::Running)
        } else {
            self.events.borrow_mut().push("owner-ready");
            Ok(TaskState::Ready)
        }
    }
    fn run(&mut self) -> Result<(), String> {
        self.events.borrow_mut().push("run");
        if self.reject_run { return Err("owner refused".into()); }
        self.runs += 1;
        Ok(())
    }
}
struct FakeWorkstation {
    events: Events, sessions: VecDeque<Result<SessionMarker, String>>,
    closed: VecDeque<bool>, reject_shutdown: bool,
    probe_elapsed: Option<(Rc<Cell<u64>>, u64)>,
    readiness_elapsed: Option<(Rc<Cell<u64>>, u64)>,
}
impl Workstation for FakeWorkstation {
    fn session(&mut self) -> Result<SessionMarker, String> {
        self.events.borrow_mut().push("authenticate");
        self.sessions.pop_front().unwrap_or_else(|| Err("not ready".into()))
    }
    fn ready_session(&mut self) -> Result<SessionMarker, String> {
        if let Some((elapsed, cost)) = &self.readiness_elapsed { elapsed.set(elapsed.get() + cost); }
        self.session()
    }
    fn shutdown(&mut self) -> Result<(), String> {
        self.events.borrow_mut().push("shutdown");
        if self.reject_shutdown { Err("authentication refused".into()) } else { Ok(()) }
    }
    fn ports_closed(&mut self, _deadline: Option<Instant>) -> bool {
        self.events.borrow_mut().push("ports");
        if let Some((elapsed, cost)) = &self.probe_elapsed {
            elapsed.set(elapsed.get() + cost);
        }
        self.closed.pop_front().unwrap_or(true)
    }
}
struct FakeClock {
    epoch: Instant,
    elapsed: Rc<Cell<u64>>,
}

impl Default for FakeClock {
    fn default() -> Self {
        Self { epoch: Instant::now(), elapsed: Rc::default() }
    }
}

impl Clock for FakeClock {
    fn now(&self) -> Instant { self.epoch + Duration::from_millis(self.elapsed.get()) }

    fn pause(&mut self, deadline: Instant) {
        if self.now() < deadline {
            self.elapsed.set(self.elapsed.get() + 1);
        }
    }
}
fn fixture() -> (Events, FakeOwner, FakeWorkstation) {
    let events = Rc::new(RefCell::new(Vec::new()));
    let owner = FakeOwner { events: events.clone(), remaining: 1, runs: 0, reject_run: false };
    let workstation = FakeWorkstation {
        events: events.clone(),
        sessions: [Ok(SessionMarker::new("old".into())), Ok(SessionMarker::new("new".into()))].into(),
        closed: [false, true].into(), reject_shutdown: false, probe_elapsed: None, readiness_elapsed: None,
    };
    (events, owner, workstation)
}
fn limits() -> Limits {
    Limits { stop: Duration::from_millis(4), start: Duration::from_millis(4) }
}

#[test]
fn restart_waits_for_owner_and_ports_before_starting_and_authenticates_a_new_session() {
    let (events, mut owner, mut workstation) = fixture();
    execute(Action::Restart, &mut workstation, Some(&mut owner), &mut FakeClock::default(), limits()).unwrap();
    let events = events.borrow();
    let shutdown = events.iter().position(|event| *event == "shutdown").unwrap();
    let ready = events.iter().position(|event| *event == "owner-ready").unwrap();
    let run = events.iter().position(|event| *event == "run").unwrap();
    assert!(shutdown < ready && ready < run);
    assert_eq!(owner.runs, 1);
    assert_eq!(events.last(), Some(&"authenticate"));
}

#[test]
fn accepted_shutdown_does_not_restart_when_owner_never_finishes() {
    let (_, mut owner, mut workstation) = fixture();
    owner.remaining = 100;
    let result = execute(Action::Restart, &mut workstation, Some(&mut owner), &mut FakeClock::default(), limits());
    assert!(result.unwrap_err().contains("timed out"));
    assert_eq!(owner.runs, 0);
}

#[test]
fn closure_at_the_stop_deadline_cannot_start_a_replacement() {
    let (events, mut owner, mut workstation) = fixture();
    let mut clock = FakeClock::default();
    workstation.closed = [true].into();
    workstation.probe_elapsed = Some((clock.elapsed.clone(), 4));

    let result = execute(Action::Restart, &mut workstation, Some(&mut owner), &mut clock, limits());

    assert!(result.unwrap_err().contains("timed out"));
    assert_eq!(clock.elapsed.get(), 4);
    assert_eq!(owner.runs, 0);
    assert_eq!(events.borrow().as_slice(), ["authenticate", "owner-running", "shutdown", "owner-ready", "ports"]);
}

#[test]
fn refused_shutdown_never_runs_the_owner() {
    let (_, mut owner, mut workstation) = fixture();
    workstation.reject_shutdown = true;
    assert!(execute(Action::Restart, &mut workstation, Some(&mut owner), &mut FakeClock::default(), limits()).is_err());
    assert_eq!(owner.runs, 0);
}

#[test]
fn replacement_with_a_stale_authenticated_session_is_not_ready() {
    let (_, mut owner, mut workstation) = fixture();
    workstation.sessions = std::iter::repeat_with(|| Ok(SessionMarker::new("old".into()))).take(20).collect();
    let result = execute(Action::Restart, &mut workstation, Some(&mut owner), &mut FakeClock::default(), limits());
    assert!(result.unwrap_err().contains("timed out"));
    assert_eq!(owner.runs, 1);
}

#[test]
fn attachment_without_supervisor_can_stop_but_cannot_start_or_restart() {
    let (events, _, mut workstation) = fixture();
    execute(Action::Stop, &mut workstation, None, &mut FakeClock::default(), limits()).unwrap();
    assert!(events.borrow().contains(&"shutdown"));
    for action in [Action::Start, Action::Restart] {
        let (events, _, mut workstation) = fixture();
        assert!(execute(action, &mut workstation, None, &mut FakeClock::default(), limits()).is_err());
        assert!(!events.borrow().contains(&"shutdown"));
    }
}

#[test]
fn start_refuses_occupied_ports_without_touching_the_owner() {
    let (_, mut owner, mut workstation) = fixture();
    owner.remaining = 0;
    let result = execute(Action::Start, &mut workstation, Some(&mut owner), &mut FakeClock::default(), limits());
    assert!(result.is_err());
    assert_eq!(owner.runs, 0);
}

#[test]
fn task_start_error_does_not_claim_success() {
    let (_, mut owner, mut workstation) = fixture();
    owner.remaining = 0;
    owner.reject_run = true;
    workstation.closed = [true].into();
    let result = execute(Action::Start, &mut workstation, Some(&mut owner), &mut FakeClock::default(), limits());
    assert_eq!(result.unwrap_err(), "owner refused");
    assert_eq!(owner.runs, 0);
}

#[test]
fn lifecycle_guard_serializes_native_actions_and_releases_after_errors() {
    let controller = LifecycleController::default();
    let guard = controller.begin(Action::Restart).unwrap();
    assert!(controller.begin(Action::Stop).is_err());
    assert_eq!(controller.phase(), Some(Action::Restart));
    drop(guard);
    assert_eq!(controller.phase(), None);
    assert!(controller.begin(Action::Start).is_ok());
}

#[test]
fn restart_refuses_ready_or_queued_owner_before_shutdown() {
    struct InactiveOwner(TaskState);
    impl TaskOwner for InactiveOwner {
        fn state(&mut self) -> Result<TaskState, String> { Ok(self.0) }
        fn run(&mut self) -> Result<(), String> { panic!("inactive owner must not be started"); }
    }
    for initial in [TaskState::Ready, TaskState::Queued] {
        let (events, _, mut workstation) = fixture();
        let mut owner = InactiveOwner(initial);
        let result = execute(Action::Restart, &mut workstation, Some(&mut owner), &mut FakeClock::default(), limits());
        assert!(!events.borrow().contains(&"shutdown"));
        assert!(result.is_err());
    }
}

#[test]
fn stale_start_never_shuts_down_or_runs_an_active_owner() {
    let (events, mut owner, mut workstation) = fixture();
    assert!(execute(Action::Start, &mut workstation, Some(&mut owner), &mut FakeClock::default(), limits()).is_err());
    assert!(!events.borrow().contains(&"shutdown"));
    assert_eq!(owner.runs, 0);
}

#[test]
fn startup_ready_at_or_after_deadline_is_not_accepted() {
    for cost in [4, 5] {
        let (_, mut owner, mut workstation) = fixture();
        let mut clock = FakeClock::default();
        workstation.readiness_elapsed = Some((clock.elapsed.clone(), cost));
        owner.remaining = 0;
        workstation.closed = [true].into();
        let result = execute(Action::Start, &mut workstation, Some(&mut owner), &mut clock, limits());
        assert!(result.unwrap_err().contains("timed out"));
        assert_eq!(owner.runs, 1);
    }
}
