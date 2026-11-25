//! Close admission before draining; the actual worker owns its effect permit.
use crate::runtime::RuntimeError;
use std::sync::{Arc, Mutex};

struct Counts { open: bool, active: usize }
struct Inner { counts: Mutex<Counts>, changed: tokio::sync::Notify }

#[derive(Clone)]
pub(crate) struct OperationAdmission { inner: Arc<Inner> }
impl Default for OperationAdmission {
    fn default() -> Self {
        Self { inner: Arc::new(Inner {
            counts: Mutex::new(Counts { open: true, active: 0 }),
            changed: tokio::sync::Notify::new(),
        }) }
    }
}
impl OperationAdmission {
    pub(crate) fn begin(&self) -> Result<OperationPermit, RuntimeError> {
        let mut counts=self.inner.counts.lock().unwrap_or_else(|error|error.into_inner());
        if !counts.open {return Err("WORKSTATION_EFFECT_ADMISSION_CLOSED".into());}
        counts.active=counts.active.checked_add(1).ok_or("WORKSTATION_EFFECT_CAPACITY")?;
        Ok(OperationPermit { inner: Arc::clone(&self.inner) })
    }
    pub(crate) fn close(&self) {
        self.inner.counts.lock().unwrap_or_else(|error|error.into_inner()).open=false;
        self.inner.changed.notify_waiters();
    }
    pub(crate) fn is_drained(&self) -> bool {
        self.inner.counts.lock().unwrap_or_else(|error|error.into_inner()).active==0
    }
    pub(crate) async fn drain(&self) {
        loop {
            let changed=self.inner.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.is_drained() {return;}
            changed.await;
        }
    }
}

pub(crate) struct OperationPermit { inner: Arc<Inner> }
impl Drop for OperationPermit {
    fn drop(&mut self) {
        let mut counts=self.inner.counts.lock().unwrap_or_else(|error|error.into_inner());
        counts.active-=1;
        drop(counts);
        self.inner.changed.notify_waiters();
    }
}
