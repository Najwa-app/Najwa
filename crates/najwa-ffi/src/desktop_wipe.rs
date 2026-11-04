//! Native-only wipe coordinator. Only `WipeReport` (mailbox onions, which the UI
//! already shows) is serializable; capabilities never leave this module.
use crate::{
    desktop::{preferences, DesktopClient, DesktopError, Result},
    state::{self, state_cell},
};
use najwa_protocol::mailbox::http::HttpMailboxClient;
use najwa_transport::{config::TorConfig, tor::TorTransport};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

struct Target {
    onion: String,
    fetch: Zeroizing<[u8; 32]>,
}
#[derive(Default)]
pub struct WipeTargets {
    targets: Vec<Target>,
    /// Saved Tor settings, bridges included. `None` when locked or unreadable:
    /// a bad setting is never consent to connect directly.
    pub(crate) tor: Option<TorConfig>,
}
/// Mailboxes (`<onion>.onion`) by outcome. A mailbox is deactivated only when
/// every collected capability on it was.
#[derive(Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct WipeReport {
    pub deactivated: Vec<String>,
    pub unreachable: Vec<String>,
}
impl WipeTargets {
    fn add(&mut self, onion: &str, fetch: &[u8]) {
        if onion.len() != 56
            || !onion
                .bytes()
                .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
        {
            return;
        }
        let Ok(fetch) = <[u8; 32]>::try_from(fetch).map(Zeroizing::new) else {
            return;
        };
        if !self
            .targets
            .iter()
            .any(|t| t.onion == onion && *t.fetch == *fetch)
        {
            self.targets.push(Target {
                onion: onion.into(),
                fetch,
            });
        }
    }

    /// One attempt per capability over a fresh Tor client with the saved
    /// bridges. `budget` bounds bootstrap, requests and runtime shutdown; this
    /// never fails, so the caller's local erasure always proceeds. Without
    /// targets (locked profile) it returns at once and starts no Tor client.
    pub fn deactivate_best_effort(mut self, budget: Duration) -> WipeReport {
        let started = Instant::now();
        let (Some(config), false) = (self.tor.take(), self.targets.is_empty()) else {
            return self.report(&[]);
        };
        let Ok(runtime) = tokio::runtime::Runtime::new() else {
            return self.report(&[]);
        };
        // The last 2 s of the budget are for runtime shutdown.
        let deadline = tokio::time::Instant::from_std(
            started + budget.saturating_sub(Duration::from_secs(2)),
        );
        let report = runtime.block_on(async {
            let mut tor = TorTransport::new(config);
            match tokio::time::timeout_at(deadline, tor.bootstrap()).await {
                Ok(Ok(())) => {
                    self.deactivate(HttpMailboxClient::new(Arc::new(tor)), deadline)
                        .await
                }
                _ => self.report(&[]),
            }
        });
        runtime.shutdown_timeout((started + budget).saturating_duration_since(Instant::now()));
        report
    }

    /// All attempts run at once, so one dead mailbox cannot use up the budget.
    pub(crate) async fn deactivate(
        &self,
        client: HttpMailboxClient,
        deadline: tokio::time::Instant,
    ) -> WipeReport {
        let client = Arc::new(client);
        let mut attempts = tokio::task::JoinSet::new();
        for (index, target) in self.targets.iter().enumerate() {
            let (client, onion, fetch) = (client.clone(), target.onion.clone(), target.fetch.clone());
            attempts.spawn(async move {
                let sent = tokio::time::timeout_at(deadline, client.deactivate_emergency(&onion, &fetch)).await;
                (index, matches!(sent, Ok(Ok(()))))
            });
        }
        let mut done = vec![false; self.targets.len()];
        while let Some(joined) = attempts.join_next().await {
            if let Ok((index, true)) = joined {
                done[index] = true;
            }
        }
        self.report(&done)
    }

    // ponytail: quadratic over a profile's capabilities (tens); fine at that size.
    fn report(&self, done: &[bool]) -> WipeReport {
        let mut report = WipeReport::default();
        for target in &self.targets {
            let all = self.targets.iter().enumerate()
                .all(|(i, other)| other.onion != target.onion || done.get(i) == Some(&true));
            let list = if all { &mut report.deactivated } else { &mut report.unreachable };
            let onion = format!("{}.onion", target.onion);
            if !list.contains(&onion) {
                list.push(onion);
            }
        }
        report
    }
}

impl DesktopClient {
    /// Drain and destroy the complete messaging runtime without persisting keys.
    /// The native owner is responsible for its own keys and filesystem erasure.
    pub fn prepare_wipe(&self) -> Result<WipeTargets> {
        let _lifecycle = state::LIFECYCLE.lock().unwrap();
        if !state::cancel_operations(state::LOCK_DRAIN_DEADLINE_MS) {
            return Err(DesktopError {
                code: "wipe_incomplete",
            });
        }
        crate::callback::quiesce_callbacks();
        let Some(mut app) = state_cell().write().unwrap().take() else {
            return Ok(WipeTargets::default());
        };
        let mut targets = WipeTargets::default();
        if let Some(db) = &app.storage {
            targets.tor = preferences::read(db)
                .and_then(|prefs| preferences::tor_config(&app.data_dir, &prefs))
                .ok();
            let mut mailboxes = db.list_mailboxes().unwrap_or_default();
            for mailbox in &mailboxes {
                targets.add(&mailbox.onion_address, &mailbox.fetch_capability);
                if let Some(fetch) = &mailbox.cover_fetch_capability {
                    targets.add(&mailbox.onion_address, fetch);
                }
                for mut dummy in db.list_dummy_capabilities(mailbox.id).unwrap_or_default() {
                    targets.add(&mailbox.onion_address, &dummy.fetch_capability);
                    dummy.fetch_capability.zeroize();
                    dummy.deposit_capability.zeroize();
                }
                for mut cap in db
                    .get_active_ephemeral_handshake_caps_for_mailbox(
                        mailbox.id,
                        najwa_crypto::time::now() as i64,
                    )
                    .unwrap_or_default()
                {
                    targets.add(&mailbox.onion_address, &cap.fetch_capability);
                    cap.fetch_capability.zeroize();
                    cap.deposit_capability.zeroize();
                    cap.envelope_secret.zeroize();
                }
            }
            for contact in db.list_contacts().unwrap_or_default() {
                for mut cap in db.get_contact_capabilities(contact.id).unwrap_or_default() {
                    if let (Some(mailbox), Some(fetch)) = (
                        mailboxes.iter().find(|m| m.id == cap.mailbox_id),
                        &cap.fetch_capability,
                    ) {
                        targets.add(&mailbox.onion_address, fetch);
                    }
                    cap.deposit_capability.zeroize();
                    cap.fetch_capability.zeroize();
                    cap.their_deposit_capability.zeroize();
                    cap.their_envelope_secret.zeroize();
                    cap.envelope_secret.zeroize();
                }
            }
            for mailbox in &mut mailboxes {
                mailbox.fetch_capability.zeroize();
                mailbox.deposit_capability.zeroize();
                mailbox.envelope_secret.zeroize();
                mailbox.cover_fetch_capability.zeroize();
                mailbox.cover_deposit_capability.zeroize();
                mailbox.cover_envelope_secret.zeroize();
            }
        }
        if let Some(cleaner) = app.disappearing_cleanup.take() {
            cleaner.abort();
            let _ = app.runtime.block_on(cleaner);
        }
        app.cover = None;
        *app.service.lock().unwrap() = None;
        app.disappearing_keys.zeroize_all();
        app.identity = None;
        app.db_key = None;
        app.storage = None;
        if let Some(mut manager) = app.identity_manager.take() {
            manager.lock();
        }
        // Outside the global state lock, bound shutdown of remaining transport
        // workers. The cleaner/key owners are gone; any still-held cache file
        // makes the caller's local erase fail safely with its retry marker.
        app.runtime.shutdown_timeout(Duration::from_secs(2));
        Ok(targets)
    }
}
