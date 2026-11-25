use crate::native_config::AppConfig;
use crate::native_tunnel::{ManagedTunnel, TunnelView};
use agent_bridge_runtime::backend::{
    self, BackendDescriptor, OperatorControl, OperatorRead, OperatorWrite, RunningWorkstation,
};
use serde_json::{json, Value};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

#[derive(Clone, Default)]
pub struct NativeView {
    pub descriptor: Option<BackendDescriptor>,
    pub operator: Option<OperatorControl>,
    pub owned: bool,
    pub running: bool,
    pub cleanup_failed: bool,
    pub error: Option<String>,
    pub tunnel: TunnelView,
}
impl NativeView {
    fn operator(&self) -> Result<&OperatorControl, String> {
        if !self.running { return Err("The native workstation is not running.".into()); }
        self.operator.as_ref().ok_or_else(|| "The native workstation is not running.".into())
    }
    pub fn read(&self, operation: OperatorRead) -> Result<Value, String> {
        let reply = tauri::async_runtime::block_on(self.operator()?.get(operation))
            .map_err(|e| e.to_string())?;
        reply_body(reply)
    }
    pub fn write(&self, operation: OperatorWrite, payload: Value) -> Result<Value, String> {
        let reply = tauri::async_runtime::block_on(self.operator()?.post(operation, payload))
            .map_err(|e| e.to_string())?;
        reply_body(reply)
    }
}
#[derive(Default)]
struct OwnedNative {
    backend: Option<RunningWorkstation>,
    tunnel: Option<ManagedTunnel>,
}
#[derive(Default)]
pub struct NativeRuntime {
    owned: Mutex<OwnedNative>,
    view: Mutex<NativeView>,
    closing: AtomicBool,
}
impl NativeRuntime {
    #[cfg(test)]
    pub fn with_ownership_lock(&self, action: impl FnOnce()) {
        let _owned = self.owned.lock().unwrap();
        action();
    }
    pub fn snapshot(&self) -> NativeView {
        self.view.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
    pub fn set_closing(&self, closing: bool) { self.closing.store(closing, Ordering::Release); }
    pub fn is_closing(&self) -> bool { self.closing.load(Ordering::Acquire) }

    pub fn revalidate_view(&self, captured: &NativeView) -> Result<NativeView, String> {
        let changed = "The native workstation changed while its state was being read. Refresh its current state.";
        let owned = self.owned.try_lock().map_err(|error| match error {
            std::sync::TryLockError::WouldBlock => "Native state is temporarily busy. Refresh its current state.".to_owned(),
            std::sync::TryLockError::Poisoned(_) => "Native ownership is unavailable.".to_owned(),
        })?;
        let current = self.snapshot();
        let generation = |view: &NativeView| view.descriptor.as_ref().map(|d| d.generation);
        if generation(&current) != generation(captured)
            || current.running != captured.running || current.owned != captured.owned
            || current.cleanup_failed != captured.cleanup_failed || current.error != captured.error
        {
            return Err(changed.into());
        }
        if current.running && !owned.backend.as_ref().is_some_and(|running|
            Some(running.descriptor().generation) == generation(captured) && !running.is_finished())
        {
            return Err(changed.into());
        }
        Ok(current)
    }

    pub fn start(&self, config: &AppConfig) -> Result<(), String> {
        let mut owned = self.owned.lock().map_err(|_| "Native ownership is unavailable.")?;
        if self.closing.load(Ordering::Acquire) {
            return Err("Agent Bridge is quitting; a new generation cannot start.".into());
        }
        if owned.backend.is_some() || owned.tunnel.is_some() {
            return Err("The native workstation still owns its previous generation. Stop it before starting another.".into());
        }
        let runtime_config = backend::WorkstationConfig::from_cli_args(&config.arguments)
            .map_err(|e| e.to_string())?;
        match tauri::async_runtime::block_on(backend::start_backend(runtime_config)) {
            Ok(running) => {
                let descriptor = running.descriptor().clone();
                let operator = running.operator();
                owned.backend = Some(running);
                *self.view.lock().unwrap_or_else(|e| e.into_inner()) = NativeView {
                    descriptor: Some(descriptor), operator: Some(operator), owned: true,
                    running: true, cleanup_failed: false, error: None, tunnel: TunnelView::default(),
                };
                if let Some(config) = &config.tunnel {
                    let mut tunnel = ManagedTunnel::new(config.clone());
                    tunnel.start();
                    self.view.lock().unwrap_or_else(|e| e.into_inner()).tunnel = tunnel.snapshot();
                    owned.tunnel = Some(tunnel);
                    self.log_tunnel();
                }
                Ok(())
            }
            Err(error) => {
                let message = format!("Native workstation startup failed: {error}");
                self.view.lock().unwrap_or_else(|e| e.into_inner()).error = Some(message.clone());
                eprintln!("{message}");
                Err(message)
            }
        }
    }
    fn log_tunnel(&self) {
        let view = self.snapshot();
        eprintln!("native-tunnel generation={} state={} exit={:?} error={}",
            view.descriptor.as_ref().map(|d| d.generation).unwrap_or(0),
            view.tunnel.state, view.tunnel.last_exit_code,
            view.tunnel.error.as_deref().unwrap_or("none"));
    }
    fn mark_stopping(&self) {
        let mut view = self.view.lock().unwrap_or_else(|e| e.into_inner());
        view.running = false;
        view.operator = None;
    }
    fn cleanup_error(&self, message: String) -> String {
        let mut view = self.view.lock().unwrap_or_else(|e| e.into_inner());
        view.cleanup_failed = true;
        view.error = Some(message.clone());
        eprintln!("{message}");
        message
    }
    fn stop_tunnel(&self, owned: &mut OwnedNative) -> Result<(), String> {
        if let Some(tunnel) = owned.tunnel.as_mut() {
            let result = tunnel.stop();
            self.view.lock().unwrap_or_else(|e| e.into_inner()).tunnel = tunnel.snapshot();
            self.log_tunnel();
            result.map_err(|error| self.cleanup_error(error))?;
            owned.tunnel = None;
        }
        Ok(())
    }
    pub fn stop(&self) -> Result<(), String> { self.stop_with_timeout(Duration::from_secs(45)) }

    pub(crate) fn stop_with_timeout(&self, timeout: Duration) -> Result<(), String> {
        let mut owned = self.owned.lock().map_err(|_| "Native ownership is unavailable.")?;
        self.mark_stopping();
        if let Some(running) = owned.backend.as_ref() {
            running.request_shutdown().map_err(|e| self.cleanup_error(e.to_string()))?;
        }
        self.stop_tunnel(&mut owned)?;
        let Some(running) = owned.backend.as_mut() else { return Ok(()); };
        let result = tauri::async_runtime::block_on(async {
            tokio::time::timeout(timeout, running.shutdown()).await
        });
        match result {
            Ok(Ok(report)) if report.clean => {
                owned.backend = None;
                let mut view = self.view.lock().unwrap_or_else(|e| e.into_inner());
                view.owned = false;
                view.cleanup_failed = false;
                view.error = None;
                Ok(())
            }
            result => {
                let message = match result {
                    Err(_) => "Native cleanup timed out. Ownership is retained; no replacement was started.".to_owned(),
                    Ok(Err(error)) => format!("Native cleanup is incomplete: {error}"),
                    _ => "Native cleanup was not confirmed. Ownership is retained.".to_owned(),
                };
                Err(self.cleanup_error(message))
            }
        }
    }

    pub fn observe_termination(&self) -> bool {
        let Ok(mut owned) = self.owned.try_lock() else { return false; };
        let Some(running) = owned.backend.as_ref() else { return false; };
        if self.snapshot().cleanup_failed { return false; }
        if !running.is_finished() {
            if self.closing.load(Ordering::Acquire) { return false; }
            let changed = owned.tunnel.as_mut().is_some_and(ManagedTunnel::tick);
            if changed {
                self.view.lock().unwrap_or_else(|e| e.into_inner()).tunnel =
                    owned.tunnel.as_ref().unwrap().snapshot();
                self.log_tunnel();
            }
            return changed;
        }
        self.mark_stopping();
        if let Err(error) = running.request_shutdown() {
            self.cleanup_error(error.to_string());
            return true;
        }
        if self.stop_tunnel(&mut owned).is_err() { return true; }
        let running = owned.backend.as_mut().unwrap();
        let result = tauri::async_runtime::block_on(async {
            tokio::time::timeout(Duration::from_secs(45), running.join()).await
        });
        let clean = matches!(result, Ok(Ok(ref report)) if report.clean);
        if clean { owned.backend = None; }
        let mut view = self.view.lock().unwrap_or_else(|e| e.into_inner());
        view.owned = !clean;
        view.cleanup_failed = !clean;
        view.error = Some(if clean {
            "The native workstation ended. Start it again when its configuration is ready."
        } else {
            "The native workstation ended, but cleanup is incomplete. Ownership is retained."
        }.to_owned());
        true
    }
    pub fn read(&self, operation: OperatorRead) -> Result<Value, String> {
        self.snapshot().read(operation)
    }
    pub fn write(&self, operation: OperatorWrite, payload: Value) -> Result<Value, String> {
        self.snapshot().write(operation, payload)
    }
    pub fn controls(&self, view: &NativeView, valid: bool, phase: Option<&str>, configuration_error: Option<String>) -> Value {
        let closing = self.closing.load(Ordering::Acquire);
        json!({
            "canStart": valid && !view.owned && phase.is_none() && !closing,
            "canStop": view.owned && phase.is_none(),
            "canRestart": valid && view.running && !view.cleanup_failed && phase.is_none() && !closing,
            "phase": phase,
            "reason": configuration_error.or_else(|| view.error.clone()),
        })
    }
}
fn reply_body(reply: backend::OperatorReply) -> Result<Value, String> {
    if (200..300).contains(&reply.status) { Ok(reply.body) }
    else { Err(crate::operator_connection::response_error(reply.status, reply.body["error"].as_str())) }
}
