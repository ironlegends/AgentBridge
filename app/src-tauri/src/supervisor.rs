use serde::Deserialize;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SupervisorConfig {
    WindowsTask { #[serde(rename = "taskName")] task_name: String },
}

impl SupervisorConfig {
    pub fn validate(&self) -> Result<(), String> {
        let Self::WindowsTask { task_name } = self;
        let name = task_name.strip_prefix('\\').unwrap_or(task_name);
        if name.is_empty() || task_name.trim() != task_name
            || task_name.encode_utf16().count() > 512
            || name.split('\\').any(|part| part.is_empty() || part == "." || part == "..")
            || name.chars().any(|c| c.is_control() || matches!(c, '*' | '?' | '/' | ':'))
        {
            return Err("The supervisor must name one existing local scheduled task.".into());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Action { Start, Stop, Restart }

impl Action {
    pub fn phase(self) -> &'static str {
        match self { Self::Start => "starting", Self::Stop => "stopping", Self::Restart => "restarting" }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TaskState { Ready, Running, Queued }

struct TaskPolicy {
    enabled: bool,
    on_demand: bool,
    current_user: bool,
    least_privilege: bool,
    ignore_new: bool,
}

impl TaskPolicy {
    fn validate(&self) -> Result<(), String> {
        if !self.enabled { return Err("The configured supervisor task is disabled.".into()); }
        if !self.on_demand { return Err("The configured supervisor task does not allow on-demand starts.".into()); }
        if !self.current_user { return Err("The configured supervisor task must belong to the current user.".into()); }
        if !self.least_privilege { return Err("The configured supervisor task must use least privilege.".into()); }
        if !self.ignore_new { return Err("The configured supervisor task must ignore duplicate starts.".into()); }
        Ok(())
    }
}

// This private generation marker may contain the local session token.
#[derive(PartialEq, Eq)]
pub struct SessionMarker(String);

impl SessionMarker {
    pub fn new(value: String) -> Self { Self(value) }
}

pub trait Workstation {
    fn session(&mut self) -> Result<SessionMarker, String>;
    fn ready_session(&mut self) -> Result<SessionMarker, String>;
    fn shutdown(&mut self) -> Result<(), String>;
    fn ports_closed(&mut self, deadline: Option<Instant>) -> bool;
}

pub trait TaskOwner {
    fn state(&mut self) -> Result<TaskState, String>;
    fn run(&mut self) -> Result<(), String>;
}

trait Clock {
    fn now(&self) -> Instant;
    fn pause(&mut self, deadline: Instant);
}

struct RealClock;

impl Clock for RealClock {
    fn now(&self) -> Instant { Instant::now() }

    fn pause(&mut self, deadline: Instant) {
        let remaining = deadline.saturating_duration_since(self.now());
        std::thread::sleep(remaining.min(Duration::from_millis(100)));
    }
}

struct Limits { stop: Duration, start: Duration }

#[derive(Default)]
pub struct LifecycleController { phase: Mutex<Option<Action>> }

pub struct LifecycleGuard<'a> { controller: &'a LifecycleController }

impl LifecycleController {
    pub fn begin(&self, action: Action) -> Result<LifecycleGuard<'_>, String> {
        let mut phase = self.phase.lock().map_err(|_| "The lifecycle controller is unavailable.")?;
        if phase.is_some() { return Err("Another workstation lifecycle action is in progress.".into()); }
        *phase = Some(action);
        Ok(LifecycleGuard { controller: self })
    }

    pub fn phase(&self) -> Option<Action> {
        *self.phase.lock().unwrap_or_else(|error| error.into_inner())
    }

    pub fn perform(
        &self, action: Action, workstation: &mut dyn Workstation, owner: Option<&mut dyn TaskOwner>,
    ) -> Result<(), String> {
        let _operation = self.begin(action)?;
        execute(action, workstation, owner, &mut RealClock,
            Limits { stop: Duration::from_secs(45), start: Duration::from_secs(30) })
    }
}

impl Drop for LifecycleGuard<'_> {
    fn drop(&mut self) {
        *self.controller.phase.lock().unwrap_or_else(|error| error.into_inner()) = None;
    }
}

fn execute(
    action: Action, workstation: &mut dyn Workstation, mut owner: Option<&mut dyn TaskOwner>,
    clock: &mut dyn Clock, limits: Limits,
) -> Result<(), String> {
    if action != Action::Stop && owner.is_none() {
        return Err("Start and restart require an explicitly configured supported supervisor. Use the external owner to start this workstation.".into());
    }
    let previous = if action != Action::Start { Some(workstation.session()?) } else { None };
    const STOP_TIMEOUT: &str =
        "Workstation shutdown timed out. Cleanup may still be running; no replacement was started.";
    let stop_deadline = if action != Action::Start {
        if action == Action::Restart && owner.as_mut().expect("restart requires an owner").state()? != TaskState::Running {
            return Err("Restart requires the configured supervisor to be running. Refresh the workstation state.".into());
        }
        workstation.shutdown()?;
        let deadline = clock.now() + limits.stop;
        loop {
            if clock.now() >= deadline { return Err(STOP_TIMEOUT.into()); }
            let ready = match owner.as_mut() {
                Some(owner) => owner.state()? == TaskState::Ready,
                None => true,
            };
            if ready && clock.now() < deadline && workstation.ports_closed(Some(deadline))
                && clock.now() < deadline
            {
                break;
            }
            clock.pause(deadline);
        }
        if action == Action::Stop { return Ok(()); }
        Some(deadline)
    } else {
        None
    };

    let owner = owner.as_mut().expect("non-stop actions require an owner");
    if action == Action::Start {
        if owner.state()? != TaskState::Ready {
            return Err("The configured supervisor is still active. Wait for its workstation to become available.".into());
        }
        if !workstation.ports_closed(None) {
            return Err("A workstation port is still occupied. The supervisor was not started.".into());
        }
    }
    if stop_deadline.is_some_and(|deadline| clock.now() >= deadline) {
        return Err(STOP_TIMEOUT.into());
    }
    owner.run()?;
    let deadline = clock.now() + limits.start;
    while clock.now() < deadline {
        let running = owner.state()? == TaskState::Running;
        if running && clock.now() < deadline {
            if let Ok(current) = workstation.ready_session() {
                if clock.now() < deadline && previous.as_ref().is_none_or(|previous| *previous != current) {
                    return Ok(());
                }
            }
        }
        clock.pause(deadline);
    }
    Err("Workstation startup timed out before a new authenticated session became ready. Check the existing supervisor; it has not been stopped.".into())
}

pub fn connect(config: &SupervisorConfig) -> Result<Box<dyn TaskOwner>, String> {
    config.validate()?;
    #[cfg(windows)]
    {
        let SupervisorConfig::WindowsTask { task_name } = config;
        Ok(Box::new(windows_task::ScheduledTask::open(task_name)?))
    }
    #[cfg(not(windows))]
    {
        Err("The configured Windows task supervisor is unavailable on this platform. Start the workstation through its local external owner.".into())
    }
}

#[cfg(windows)]
mod windows_task {
    use super::{TaskOwner, TaskPolicy, TaskState};
    use windows::core::{BSTR, PCWSTR, PWSTR};
    use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree, VARIANT_BOOL};
    use windows::Win32::Security::{
        EqualSid, GetTokenInformation, LookupAccountNameW, PSID, SID_NAME_USE, TOKEN_QUERY,
        TOKEN_USER, TokenUser,
    };
    use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
    use windows::Win32::System::Com::{
        CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize,
    };
    use windows::Win32::System::TaskScheduler::{
        IRegisteredTask, ITaskService, TASK_INSTANCES_IGNORE_NEW, TASK_INSTANCES_POLICY,
        TASK_RUNLEVEL_LUA, TASK_RUNLEVEL_TYPE, TASK_STATE_QUEUED, TASK_STATE_READY,
        TASK_STATE_RUNNING, TaskScheduler,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows::Win32::System::Variant::VARIANT;

    struct Apartment;
    impl Drop for Apartment {
        fn drop(&mut self) { unsafe { CoUninitialize(); } }
    }
    struct Token(HANDLE);
    impl Drop for Token {
        fn drop(&mut self) { unsafe { let _ = CloseHandle(self.0); } }
    }
    struct LocalSid(PSID);
    impl Drop for LocalSid {
        fn drop(&mut self) { unsafe { let _ = LocalFree(Some(HLOCAL(self.0.0))); } }
    }

    pub(super) struct ScheduledTask {
        task: IRegisteredTask,
        _apartment: Apartment,
    }

    fn unavailable() -> String { "The configured local supervisor task is unavailable or access was refused.".into() }

    fn current_user_matches(user: &BSTR) -> Result<bool, String> {
        if user.is_empty() { return Ok(false); }
        unsafe {
            let mut handle = HANDLE::default();
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle).map_err(|_| unavailable())?;
            let token = Token(handle);
            let mut required = 0;
            let _ = GetTokenInformation(token.0, TokenUser, None, 0, &mut required);
            if required == 0 || required > 65536 { return Err(unavailable()); }
            let mut bytes = vec![0usize; (required as usize).div_ceil(std::mem::size_of::<usize>())];
            GetTokenInformation(token.0, TokenUser, Some(bytes.as_mut_ptr().cast()),
                required, &mut required).map_err(|_| unavailable())?;
            let current = (*(bytes.as_ptr().cast::<TOKEN_USER>())).User.Sid;
            if user.to_string().to_ascii_uppercase().starts_with("S-") {
                let mut sid = PSID::default();
                ConvertStringSidToSidW(PCWSTR(user.as_ptr()), &mut sid).map_err(|_| unavailable())?;
                let sid = LocalSid(sid);
                return Ok(EqualSid(current, sid.0).is_ok());
            }
            let (mut sid_size, mut domain_size, mut usage) = (0, 0, SID_NAME_USE::default());
            let _ = LookupAccountNameW(PCWSTR::null(), PCWSTR(user.as_ptr()), None, &mut sid_size,
                None, &mut domain_size, &mut usage);
            if sid_size == 0 || sid_size > 65536 || domain_size > 32768 { return Err(unavailable()); }
            let mut sid = vec![0usize; (sid_size as usize).div_ceil(std::mem::size_of::<usize>())];
            let mut domain = vec![0u16; (domain_size as usize).max(1)];
            let account = PSID(sid.as_mut_ptr().cast());
            LookupAccountNameW(PCWSTR::null(), PCWSTR(user.as_ptr()), Some(account), &mut sid_size,
                Some(PWSTR(domain.as_mut_ptr())), &mut domain_size, &mut usage).map_err(|_| unavailable())?;
            Ok(EqualSid(current, account).is_ok())
        }
    }

    impl ScheduledTask {
        pub(super) fn open(name: &str) -> Result<Self, String> {
            unsafe {
                CoInitializeEx(None, COINIT_MULTITHREADED).ok().map_err(|_| unavailable())?;
                let apartment = Apartment;
                let service: ITaskService = CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER)
                    .map_err(|_| unavailable())?;
                let empty = VARIANT::default();
                service.Connect(&empty, &empty, &empty, &empty).map_err(|_| unavailable())?;
                let root = service.GetFolder(&BSTR::from("\\")).map_err(|_| unavailable())?;
                let task = root.GetTask(&BSTR::from(name)).map_err(|_| unavailable())?;
                let result = Self { task, _apartment: apartment };
                result.validate()?;
                Ok(result)
            }
        }

        fn validate(&self) -> Result<(), String> {
            unsafe {
                let definition = self.task.Definition().map_err(|_| unavailable())?;
                let settings = definition.Settings().map_err(|_| unavailable())?;
                let principal = definition.Principal().map_err(|_| unavailable())?;
                let mut user = BSTR::default();
                let mut group = BSTR::default();
                principal.UserId(&mut user).map_err(|_| unavailable())?;
                principal.GroupId(&mut group).map_err(|_| unavailable())?;
                let mut level = TASK_RUNLEVEL_TYPE::default();
                principal.RunLevel(&mut level).map_err(|_| unavailable())?;
                let mut demand = VARIANT_BOOL::default();
                settings.AllowDemandStart(&mut demand).map_err(|_| unavailable())?;
                let mut instances = TASK_INSTANCES_POLICY::default();
                settings.MultipleInstances(&mut instances).map_err(|_| unavailable())?;
                TaskPolicy {
                    enabled: self.task.Enabled().map_err(|_| unavailable())?.0 != 0,
                    on_demand: demand.0 != 0,
                    current_user: group.is_empty() && current_user_matches(&user)?,
                    least_privilege: level == TASK_RUNLEVEL_LUA,
                    ignore_new: instances == TASK_INSTANCES_IGNORE_NEW,
                }.validate()
            }
        }
    }

    impl TaskOwner for ScheduledTask {
        fn state(&mut self) -> Result<TaskState, String> {
            self.validate()?;
            match unsafe { self.task.State() }.map_err(|_| unavailable())? {
                TASK_STATE_READY => Ok(TaskState::Ready),
                TASK_STATE_RUNNING => Ok(TaskState::Running),
                TASK_STATE_QUEUED => Ok(TaskState::Queued),
                _ => Err("The configured supervisor is not ready or running.".into()),
            }
        }

        fn run(&mut self) -> Result<(), String> {
            if self.state()? != TaskState::Ready {
                return Err("The configured supervisor is already active.".into());
            }
            unsafe { self.task.Run(&VARIANT::default()) }.map_err(|_| unavailable())?;
            Ok(())
        }
    }
}

#[cfg(test)]
#[path = "supervisor_tests.rs"]
mod tests;
