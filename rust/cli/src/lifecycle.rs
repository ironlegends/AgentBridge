use crate::runtime::{self, RuntimeError};
use agent_bridge_http::{HealthStatus, HttpServerConfig, ServiceActivity};
use agent_bridge_lifecycle::{
    launch, stop, HostResult, HostRuntime, LaunchOptions, StopApproval, StopOptions, StopOutcome,
    DEFAULT_TIMEOUT,
};
use std::ffi::{OsStr, OsString};
use std::io;
use std::path::{Path, PathBuf};
use tokio::runtime::{Builder, Runtime};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

fn package_directory() -> Result<PathBuf, RuntimeError> {
    let executable = std::env::current_exe()?;
    let parent = executable.parent().ok_or("executable has no parent directory")?;
    #[cfg(windows)]
    if let Some(std::path::Component::Prefix(prefix)) = parent.components().next() {
        if matches!(prefix.kind(), std::path::Prefix::VerbatimDisk(_)) {
            let value = parent.to_str().ok_or("unsupported package path")?;
            return Ok(PathBuf::from(value.strip_prefix(r"\\?\").ok_or("unsupported package path")?));
        }
    }
    Ok(parent.to_owned())
}

pub fn control(command: &OsStr, args: &[OsString]) -> Result<(), RuntimeError> {
    let starting = command == "start";
    let mut state = None;
    let mut database = None;
    let mut port = None;
    let mut args = args.iter();
    while let Some(flag) = args.next() {
        let value = args.next().ok_or("missing option value")?;
        match flag.to_str() {
            Some("--state-dir") if state.is_none() => state = Some(PathBuf::from(value)),
            Some("--database") if starting && database.is_none() => database = Some(PathBuf::from(value)),
            Some("--port") if starting && port.is_none() => {
                port = Some(value.to_str().ok_or("invalid port")?.parse::<u16>()?);
            }
            _ => return Err("unrecognized or repeated lifecycle option".into()),
        }
    }
    let package = package_directory()?;
    let state_dir = state.unwrap_or_else(|| package.join("rust-session"));
    if starting {
        let database = database.unwrap_or_else(|| package.join("data/core/agent-bridge.sqlite"));
        let port = port.unwrap_or(18855);
        runtime::check_port(port)?;
        // A missing, live or incompatible history must be reported before a
        // launch record is published. Only db init/migrate may change schema.
        if agent_bridge_core::inspect_existing(&database)?.pending_migrations != 0 {
            return Err("offline database migration required before startup".into());
        }
        let session = launch(LaunchOptions {
            state_dir,
            host_args: vec![database.into_os_string(), port.to_string().into()],
            timeout: DEFAULT_TIMEOUT,
        })?;
        println!("{}", serde_json::json!({"status":"started","session_id":session.id,"port":port}));
    } else {
        match stop(StopOptions { state_dir, timeout: DEFAULT_TIMEOUT })? {
            StopOutcome::Stopped => println!(r#"{{"status":"stopped"}}"#),
            StopOutcome::Busy => return Err("the host is processing a request".into()),
        }
    }
    Ok(())
}

struct RunningHost {
    runtime: Runtime,
    activity: ServiceActivity,
    shutdown: oneshot::Sender<()>,
    server: JoinHandle<io::Result<()>>,
}

#[derive(Default)]
pub struct MissionHost {
    running: Option<RunningHost>,
}

impl HostRuntime for MissionHost {
    fn start(&mut self, args: &[OsString]) -> HostResult {
        let [database, port] = args else { return Err("invalid host arguments".into()); };
        let port = port.to_str().ok_or("invalid host port")?.parse::<u16>()?;
        runtime::check_port(port)?;
        let event_loop = Builder::new_multi_thread().worker_threads(2).enable_all().build()?;
        let listener = event_loop.block_on(agent_bridge_http::bind_loopback(port))?;
        let router = runtime::missions(Path::new(database))?;
        let activity = ServiceActivity::default();
        let (shutdown, received) = oneshot::channel();
        let server = event_loop.spawn(agent_bridge_http::serve_managed(
            listener,
            HttpServerConfig::default(),
            activity.clone(),
            move |frame| router.handle_str(frame),
            HealthStatus::ok,
            async { let _ = received.await; },
        ));
        self.running = Some(RunningHost { runtime: event_loop, activity, shutdown, server });
        Ok(())
    }

    fn approve_stop(&mut self) -> StopApproval {
        match &self.running {
            Some(host) if !host.server.is_finished() && host.activity.is_idle() => StopApproval::Approved,
            Some(host) if !host.server.is_finished() => StopApproval::Busy,
            _ => StopApproval::Uncertain,
        }
    }

    fn cooperative_stop(&mut self) -> HostResult {
        let host = self.running.take().ok_or("host not running")?;
        host.shutdown.send(()).map_err(|_| "shutdown receiver closed")?;
        host.runtime.block_on(host.server)??;
        Ok(())
    }
}
