use crate::native_config::TunnelConfig;
use serde::Serialize;
use std::time::{Duration, Instant};

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelView {
    pub configured: bool,
    pub child_running: bool,
    pub pid: Option<u32>,
    pub state: &'static str,
    pub remote_ready: Option<bool>,
    pub last_exit_code: Option<u32>,
    pub retry_after_seconds: Option<u64>,
    pub error: Option<String>,
}

impl Default for TunnelView {
    fn default() -> Self {
        Self { configured: false, child_running: false, pid: None, state: "disabled",
            remote_ready: None, last_exit_code: None, retry_after_seconds: None, error: None }
    }
}

#[cfg(not(windows))]
struct TunnelChild;
#[cfg(not(windows))]
impl TunnelChild {
    fn spawn(_: &TunnelConfig, _: &mut Option<String>) -> Result<Self, String> { Err("The managed tunnel requires Windows.".into()) }
    fn pid(&self) -> u32 { 0 }
    fn exited(&self) -> Result<Option<u32>, String> { Ok(None) }
    fn stop(&mut self) -> Result<(), String> { Ok(()) }
}
#[cfg(windows)]
use crate::native_windows::TunnelChild;
#[cfg(windows)]
impl TunnelChild {
    fn pid(&self) -> u32 { self.process.pid }
    fn exited(&self) -> Result<Option<u32>, String> { self.process.exited() }
    fn stop(&mut self) -> Result<(), String> { self.process.stop() }
}

pub struct ManagedTunnel {
    config: TunnelConfig,
    child: Option<TunnelChild>,
    identity: Option<String>,
    desired: bool,
    retry_at: Option<Instant>,
    failures: u32,
    view: TunnelView,
}
impl ManagedTunnel {
    pub fn new(config: TunnelConfig) -> Self {
        Self { config, child: None, identity: None, desired: true, retry_at: None, failures: 0,
            view: TunnelView { configured: true, state: "stopped", ..Default::default() } }
    }
    pub fn snapshot(&self) -> TunnelView { self.view.clone() }
    pub fn start(&mut self) {
        match TunnelChild::spawn(&self.config, &mut self.identity) {
            Ok(child) => {
                self.view.child_running = true;
                self.view.pid = Some(child.pid());
                self.view.state = "running";
                self.view.error = None;
                self.view.retry_after_seconds = None;
                self.retry_at = None;
                self.child = Some(child);
            }
            Err(error) => {
                self.desired = false;
                self.view.child_running = false;
                self.view.pid = None;
                self.view.state = "configuration-error";
                self.view.error = Some(error);
                self.view.retry_after_seconds = None;
                self.retry_at = None;
            }
        }
    }
    pub fn tick(&mut self) -> bool {
        if !self.desired { return false; }
        if let Some(child) = self.child.as_mut() {
            match child.exited() {
                Ok(None) => return false,
                Ok(Some(code)) => {
                    self.view.last_exit_code = Some(code);
                    self.view.child_running = false;
                    self.view.pid = None;
                    if let Err(error) = child.stop() { self.failed_cleanup(error); return true; }
                    self.child = None;
                    self.failures = self.failures.saturating_add(1);
                    let delay = retry_delay(self.failures);
                    self.retry_at = Some(Instant::now() + delay);
                    self.view.child_running = false;
                    self.view.pid = None;
                    self.view.state = "backoff";
                    self.view.retry_after_seconds = Some(delay.as_secs());
                    self.view.error = Some(format!("The tunnel exited with code {code}; a silent retry is scheduled."));
                    return true;
                }
                Err(error) => { self.failed_cleanup(error); return true; }
            }
        }
        if self.retry_at.is_some_and(|time| Instant::now() >= time) {
            self.start();
            return true;
        }
        false
    }
    fn failed_cleanup(&mut self, error: String) {
        self.desired = false;
        self.retry_at = None;
        self.view.state = "cleanup-failed";
        self.view.error = Some(error);
        self.view.retry_after_seconds = None;
    }
    pub fn stop(&mut self) -> Result<(), String> {
        self.desired = false;
        self.retry_at = None;
        if let Some(child) = self.child.as_mut() {
            if let Ok(Some(code)) = child.exited() {
                self.view.last_exit_code = Some(code);
                self.view.child_running = false;
                self.view.pid = None;
            }
            if let Err(error) = child.stop() {
                self.failed_cleanup(error.clone());
                return Err(error);
            }
            if let Ok(Some(code)) = child.exited() {
                self.view.last_exit_code = Some(code);
                self.view.child_running = false;
                self.view.pid = None;
            }
        }
        self.child = None;
        self.view.child_running = false;
        self.view.pid = None;
        self.view.state = "stopped";
        self.view.retry_after_seconds = None;
        self.view.error = None;
        Ok(())
    }
}
fn retry_delay(failures: u32) -> Duration {
    Duration::from_secs(match failures { 0 | 1 => 1, 2 => 2, 3 => 5, 4 => 10, _ => 30 })
}
