use super::*;
use najwa_ffi::desktop::LocalPreferences;

impl Owner {
    pub(super) fn reset_transport(&self) -> Result<()> {
        drop(self.client.prepare_wipe().map_err(|_| Failure::new("lock_failed"))?);
        DesktopClient::init(&self.directory).map_err(|_| Failure::new("lock_failed"))?;
        self.transport_reset.store(false, Ordering::SeqCst);
        Ok(())
    }
    pub fn idle_expired(&self) -> bool {
        self.activity.lock().unwrap().elapsed().as_secs()
            >= u64::from(self.lock_timeout_seconds.load(Ordering::SeqCst))
    }

    pub fn preferences(&self) -> Result<LocalPreferences> {
        let snapshot = self.status();
        self.validate(&snapshot.session, snapshot.generation, true)?;
        let prefs = self.client.local_preferences().map_err(|e| Failure::new(e.code))?;
        self.validate(&snapshot.session, snapshot.generation, true)?;
        Ok(prefs)
    }

    pub fn save_preferences(&self, session: &str, generation: u64, prefs: LocalPreferences) -> Result<Value> {
        self.identity_busy.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| Failure::new("busy"))?;
        let _busy = BusyGuard(&self.identity_busy);
        let mut profile = self.profile.lock().unwrap();
        self.validate(session, generation, true)?;
        let previous = self.client.local_preferences().map_err(|e| Failure::new(e.code))?;
        let mut view = self.view.write().unwrap();
        if view.session != session || view.generation != generation || view.phase != "unlocked" {
            return Err(Failure::new("stale_operation"));
        }
        let prefs = self.client.save_local_preferences(prefs).map_err(|e| Failure::new(e.code))?;
        self.lock_timeout_seconds.store(prefs.lock_timeout_seconds, Ordering::SeqCst);
        view.lock_timeout_seconds = prefs.lock_timeout_seconds;
        *self.activity.lock().unwrap() = Instant::now();
        if prefs.bridges == previous.bridges {
            return Ok(json!({"preferences":prefs,"identity":view.clone()}));
        }
        // Stop the old Tor client before the new routing policy can take effect.
        // A normal lock keeps its cover connection; this change must destroy it.
        view.generation += 1;
        view.phase = "locking";
        view.busy = true;
        view.recovery_pending = false;
        self.transport_reset.store(true, Ordering::SeqCst);
        let epoch = view.generation;
        drop(view);
        self.client.cancel();
        let result = self.client.lock().and_then(|_| {
            profile.manager.lock();
            profile.words = None;
            self.reset_transport().map_err(|_| najwa_ffi::desktop::DesktopError { code: "lock_failed" })
        });
        let mut view = self.view.write().unwrap();
        if view.generation == epoch {
            view.phase = if result.is_ok() { "locked" } else { "error" };
            view.busy = false;
        }
        result.map_err(|_| Failure::new("lock_failed"))?;
        Ok(json!({"preferences":prefs,"identity":view.clone()}))
    }
}
