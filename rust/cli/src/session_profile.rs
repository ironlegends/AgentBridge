use agent_bridge_desktop::DesktopProfile;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex, RwLock, RwLockReadGuard};
use crate::runtime::RuntimeError;

pub(crate) type Revoker = Arc<dyn Fn() -> Result<(), RuntimeError> + Send + Sync>;

#[derive(Clone)]
pub(crate) struct ProfileControl {
    startup: DesktopProfile,
    active: Arc<RwLock<DesktopProfile>>,
    revokers: Arc<Mutex<Vec<(DesktopProfile, Revoker)>>>,
}

pub(crate) fn rank(profile: DesktopProfile) -> u8 {
    match profile {
        DesktopProfile::ReadOnly => 0,
        DesktopProfile::WorkspaceWrite => 1,
        DesktopProfile::FullControl => 2,
        DesktopProfile::FullyUnlocked => 3,
    }
}

impl ProfileControl {
    pub(crate) fn new(startup: DesktopProfile) -> Self {
        Self {
            startup,
            active: Arc::new(RwLock::new(startup)),
            revokers: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub(crate) fn startup_profile(&self) -> DesktopProfile { self.startup }
    pub(crate) fn shared(&self) -> Arc<RwLock<DesktopProfile>> { Arc::clone(&self.active) }
    pub(crate) fn allows(&self, profile: DesktopProfile) -> bool {
        rank(profile) <= rank(self.startup)
    }
    pub(crate) fn read(&self) -> Result<RwLockReadGuard<'_, DesktopProfile>, RuntimeError> {
        self.active.read().map_err(|_| "PROFILE_STATE_UNAVAILABLE".into())
    }
    fn snapshot_at(&self, active: DesktopProfile) -> Value {
        let available: Vec<_> = [
            DesktopProfile::ReadOnly, DesktopProfile::WorkspaceWrite,
            DesktopProfile::FullControl, DesktopProfile::FullyUnlocked,
        ].into_iter().filter(|profile| self.allows(*profile)).collect();
        json!({"active_profile":active, "max_profile":self.startup,
            "available_profiles":available})
    }
    pub(crate) fn snapshot(&self) -> Result<Value, RuntimeError> {
        Ok(self.snapshot_at(*self.read()?))
    }
    pub(crate) fn register_revoker(&self, minimum: DesktopProfile, revoke: Revoker)
        -> Result<(), RuntimeError>
    {
        self.revokers.lock().map_err(|_| "PROFILE_REVOCATION_UNAVAILABLE")?
            .push((minimum, revoke));
        Ok(())
    }
    pub(crate) fn set(&self, requested: DesktopProfile) -> Result<Value, RuntimeError> {
        if !self.allows(requested) {
            return Err("PROFILE_CEILING_EXCEEDED: restart locally with the required maximum profile".into());
        }
        let mut active = self.active.write().map_err(|_| "PROFILE_STATE_UNAVAILABLE")?;
        if requested == *active {
            return Ok(self.snapshot_at(*active));
        }
        if rank(requested) < rank(*active) {
            // Exclude all admitted effects until owned processes have stopped.
            // Revokers must not acquire this profile lock themselves.
            let revokers = self.revokers.lock().map_err(|_| "PROFILE_REVOCATION_UNAVAILABLE")?;
            for (minimum, revoke) in revokers.iter() {
                if rank(*active) >= rank(*minimum) && rank(requested) < rank(*minimum) {
                    revoke().map_err(|_| "PROFILE_REVOCATION_FAILED: the previous mode remains active")?;
                }
            }
        }
        *active = requested;
        Ok(self.snapshot_at(requested))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const PROFILES: [DesktopProfile; 4] = [
        DesktopProfile::ReadOnly,
        DesktopProfile::WorkspaceWrite,
        DesktopProfile::FullControl,
        DesktopProfile::FullyUnlocked,
    ];

    #[test]
    fn every_startup_ceiling_bounds_all_live_transitions() {
        for (ceiling_index, ceiling) in PROFILES.into_iter().enumerate() {
            let control = ProfileControl::new(ceiling);
            for (requested_index, requested) in PROFILES.into_iter().enumerate() {
                let before = control.snapshot().unwrap();
                let result = control.set(requested);
                if requested_index > ceiling_index {
                    assert!(result.is_err(), "{ceiling:?} must not admit {requested:?}");
                    assert_eq!(control.snapshot().unwrap(), before);
                } else {
                    assert_eq!(result.unwrap()["active_profile"], json!(requested));
                    assert_eq!(*control.shared().read().unwrap(), requested);
                }
                assert_eq!(control.startup_profile(), ceiling);
            }
        }
    }

    #[test]
    fn revoke_on_downgrade_then_allow_a_new_unlocked_session() {
        let control = ProfileControl::new(DesktopProfile::FullyUnlocked);
        let revoked = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&revoked);
        control.register_revoker(DesktopProfile::FullyUnlocked, Arc::new(move || {
            count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })).unwrap();
        control.set(DesktopProfile::FullControl).unwrap();
        assert_eq!(revoked.load(Ordering::SeqCst), 1);
        control.set(DesktopProfile::ReadOnly).unwrap();
        assert_eq!(revoked.load(Ordering::SeqCst), 1);
        control.set(DesktopProfile::FullyUnlocked).unwrap();
        control.set(DesktopProfile::WorkspaceWrite).unwrap();
        assert_eq!(revoked.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn failed_process_cleanup_never_reports_a_successful_downgrade() {
        let control = ProfileControl::new(DesktopProfile::FullyUnlocked);
        control.register_revoker(DesktopProfile::FullyUnlocked, Arc::new(|| {
            Err("owned child is still running".into())
        })).unwrap();
        assert!(control.set(DesktopProfile::ReadOnly).is_err());
        assert_eq!(control.snapshot().unwrap()["active_profile"], "fully-unlocked");
    }

    #[test]
    fn poisoned_profile_state_fails_closed() {
        let control = ProfileControl::new(DesktopProfile::FullyUnlocked);
        let shared = control.shared();
        let _ = std::thread::spawn(move || {
            let _guard = shared.write().unwrap();
            panic!("synthetic poisoned profile lock");
        }).join();
        assert!(control.snapshot().is_err());
        assert!(control.set(DesktopProfile::ReadOnly).is_err());
        assert!(control.read().is_err());
    }
}
