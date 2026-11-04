//! Durable, profile-scoped erasure. Mailbox deactivation is bounded best effort;
//! local erasure never waits on its outcome.
use super::*;
use najwa_privacy::lifecycle::emergency;

/// Tor bootstrap, every deactivation request and shutdown (S13 §10.1).
const DEACTIVATION_BUDGET: std::time::Duration = std::time::Duration::from_secs(20);

impl Owner {
    pub fn erase(&self, session: &str, generation: u64, confirmed: bool, confirmation: &str) -> Result<Value> {
        if !confirmed || confirmation != "ERASE" { return Err(Failure::new("invalid_confirmation")); }
        self.identity_busy.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| Failure::new("busy"))?;
        let _busy = BusyGuard(&self.identity_busy);
        let mut profile = self.profile.lock().unwrap();
        let mut view = self.view.write().unwrap();
        if view.session != session || view.generation != generation || view.busy
            || !matches!(view.phase, "unlocked" | "locked" | "absent" | "wiping" | "error") {
            return Err(Failure::new("stale_operation"));
        }
        // Persist intent before removing any key or byte. Restart can only retry.
        emergency::begin(&self.directory).map_err(|_| Failure::new("wipe_incomplete"))?;
        view.generation += 1;
        view.phase = "wiping";
        view.busy = true;
        view.recovery_pending = false;
        drop(view);
        profile.manager.lock();
        profile.words = None;
        let result = self.client.prepare_wipe().map_err(|_| Failure::new("wipe_incomplete"))
            .and_then(|targets| {
                // Unlocked: ask mailboxes to stop accepting deposits while the files,
                // Tor state included, still exist. Locked: no targets, no network.
                let mailboxes = targets.deactivate_best_effort(DEACTIVATION_BUDGET);
                emergency::erase(&self.directory).map(|_| mailboxes)
                    .map_err(|_| Failure::new("wipe_incomplete"))
            });
        let mut view = self.view.write().unwrap();
        view.busy = false;
        if result.is_err() {
            view.unavailable_reason = Some("wipe_incomplete");
        } else {
            view.phase = "erased";
            view.fingerprint = None;
            view.recovery_available = false;
            view.unavailable_reason = None;
            self.shutdown.notify_one();
        }
        result.map(|mailboxes| {
            let mut value = json!(view.clone());
            value["mailboxes"] = json!(mailboxes);
            value
        })
    }
}
