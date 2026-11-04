//! Typed desktop boundary. Credentials stay in the native identity owner.
//! This shares the ABI's cancellation, SQLCipher, disappearing keys and cover
//! runtime; it adds no C exports and must be called from a blocking worker.
pub use crate::desktop_wipe::{WipeReport, WipeTargets};
pub use transfers::{UploadManifest,TransferView,DownloadInfo};
pub use preferences::LocalPreferences;
#[path = "desktop_preferences.rs"]
pub(crate) mod preferences;
#[path = "desktop_contacts.rs"]
mod contact_actions;
#[path = "desktop_history.rs"]
mod history;
#[path = "desktop_files.rs"]
mod attachments;
#[path = "desktop_transfers.rs"]
mod transfers;
#[cfg(test)]
#[path = "desktop_browser_tests.rs"]
mod browser_tests;
#[cfg(test)]
#[path = "desktop_history_tests.rs"]
mod history_tests;
use crate::{
    error::FfiErrorCode,
    state::{self, state_cell, OperationGuard},
};
use najwa_core::{
    cover::{AbsorptionPriority, SlotSource},
    types::MessageContent,
};
use najwa_crypto::{keys::Ed25519KeyPair, random::random_bytes, time::now};
use najwa_identity::record::Identity;
use najwa_protocol::{
    contact::{
        accept::accept_contact, capability_lifecycle::EPHEMERAL_CAP_TTL_SECS,
        types::HandshakePayload,
    },
    mailbox::{
        error::MailboxError,
        http::HttpMailboxClient,
        types::{CapabilitySettings, MailboxConfig},
    },
    message::{control::ControlMessage, types::ContentType},
};
use najwa_storage::{
    database::SqliteStorage,
    types::{NewEphemeralHandshakeCap, NewMailbox},
};
use serde::Serialize;
use std::{
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use zeroize::Zeroizing;

pub type Result<T> = std::result::Result<T, DesktopError>;
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct DesktopError {
    pub code: &'static str,
}
impl DesktopError {
    fn new(code: &'static str) -> Self {
        Self { code }
    }
}
impl From<FfiErrorCode> for DesktopError {
    fn from(code: FfiErrorCode) -> Self {
        Self::new(match code {
            FfiErrorCode::IdentityError => "locked",
            FfiErrorCode::TransportError => "not_connected",
            FfiErrorCode::StorageError => "storage_unavailable",
            _ => "operation_failed",
        })
    }
}
fn storage<T>(value: najwa_storage::error::Result<T>) -> Result<T> {
    value.map_err(|_| DesktopError::new("storage_unavailable"))
}
fn messaging<T>(value: najwa_core::error::Result<T>) -> Result<T> {
    value.map_err(|e| {
        tracing::debug!(error = %e, "desktop messaging operation failed");
        DesktopError::new(match e {
            najwa_core::error::MessagingError::ContactBlocked => "contact_blocked",
            najwa_core::error::MessagingError::ContactNotFound => "contact_missing",
            najwa_core::error::MessagingError::NoMailboxCapability => "mailbox_unavailable",
            _ => "sync_failed",
        })
    })
}

/// Mean gap between receive polls (S08 §10.1). Gaps are exponential like cover
/// slots (S10 §3), so the poll times carry no fixed period or unlock phase.
const RECEIVE_POLL_MEAN: Duration = Duration::from_secs(3);

fn next_poll_gap() -> Duration {
    najwa_core::cover::scheduler::jittered_duration(RECEIVE_POLL_MEAN, 25)
}

/// One poll of the receive worker that unlock generation `generation` starts.
/// Unlocked, it runs `sync`. Through the lock that follows it keeps the same
/// schedule and selection from the in-memory fetch plan, fetch-only (S13 §8.3).
/// Returns false once a later unlock owns polling or the profile is erased.
async fn receive_tick(generation: u64) -> bool {
    let locked = {
        let cell = state_cell().read().unwrap();
        let Some(s) = cell
            .as_ref()
            .filter(|s| s.lifecycle_generation <= generation + 1)
        else {
            return false;
        };
        (s.identity.is_none() || s.lifecycle_generation != generation)
            .then(|| s.cover.as_ref().map(|c| (c.fetch_plan.clone(), c.client.clone())))
    };
    match locked {
        None => {
            let _ = tokio::task::spawn_blocking(|| {
                let client = DesktopClient;
                if client.status().connection == "offline" {
                    client.reconnect();
                }
                let _ = client.sync();
            })
            .await;
        }
        Some(Some((plan, client))) => plan.poll_locked(&*client).await,
        // Locked before Tor ever connected: there is nothing to poll with.
        Some(None) => {}
    }
    true
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkStatus {
    pub unlocked: bool,
    pub connection: &'static str,
    pub cover_running: bool,
    pub mailboxes: Vec<String>,
    pub paused_mailboxes: Vec<String>,
    pub retrying_mailboxes: Vec<String>,
    pub mailbox_details: Vec<MailboxStatus>,
    pub delivery_mode: &'static str,
    pub pending_deposits: Option<u64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MailboxStatus {
    pub onion: String,
    pub registered: bool,
    pub primary: bool,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Contact {
    pub id: String,
    pub name: String,
    pub verified: bool,
    pub blocked: bool,
    pub unread: u32,
    pub ready: bool,
    pub setup_state: &'static str,
    pub setup_expires_at: Option<u64>,
    pub safety_number: String,
    pub timer_seconds: u32,
    pub timer_pending: bool,
    pub preview: Option<String>,
    pub last_message_at: Option<u64>,
    pub repair_status: Option<&'static str>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Message {
    pub id: String,
    pub msg_id: String,
    pub text: String,
    pub outgoing: bool,
    pub timestamp: u64,
    pub status: &'static str,
    pub expires_at: Option<u64>,
    pub reply_to: Option<String>,
    pub attachment: Option<attachments::Attachment>,
}
/// S17 §5.6.2: message text is plaintext; wipe it when the caller drops it.
impl Drop for Message {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.text);
    }
}

/// One messaging owner per process, matching the existing ABI lifecycle.
pub struct DesktopClient;
static NETWORK_BUSY: AtomicBool = AtomicBool::new(false);
static OUTBOX_BUSY: AtomicBool = AtomicBool::new(false);
struct NetworkAdmission;
impl Drop for NetworkAdmission {
    fn drop(&mut self) {
        NETWORK_BUSY.store(false, Ordering::SeqCst);
    }
}
struct OutboxAdmission;
impl Drop for OutboxAdmission {
    fn drop(&mut self) {
        OUTBOX_BUSY.store(false, Ordering::SeqCst);
    }
}
impl DesktopClient {
    pub fn init(directory: &Path) -> Result<Self> {
        let _lifecycle = state::LIFECYCLE.lock().unwrap();
        let mut cell = state_cell().write().unwrap();
        if cell.is_some() {
            return Err(DesktopError::new("already_initialized"));
        }
        najwa_crypto::initialize()
            .map_err(|_| DesktopError::new("security_initialization_failed"))?;
        *cell = Some(state::AppState::new(directory.into())?);
        Ok(Self)
    }

    pub fn attach_identity(&self, identity: &Identity) -> Result<()> {
        let _lifecycle = state::LIFECYCLE.lock().unwrap();
        if !state::cancel_operations(state::LOCK_DRAIN_DEADLINE_MS) {
            return Err(DesktopError::new("lock_failed"));
        }
        let mut cell = state_cell().write().unwrap();
        let s = cell
            .as_mut()
            .ok_or_else(|| DesktopError::new("unavailable"))?;
        if s.identity.is_some() {
            return Err(DesktopError::new("already_unlocked"));
        }
        let key =
            crate::derive_sqlcipher_key(&Zeroizing::new(identity.keypair.private().to_bytes()));
        let db = state::open_storage(&s.data_dir, &key)?;
        storage(db.resume_legacy_delivery_pauses())?;
        // Desktop/web UX defaults to immediate sends. The C ABI keeps its own
        // policy; absence of this desktop-only preference still means paced.
        if storage(db.get_setting::<bool>("desktop:responsive"))?.is_none() {
            storage(db.set_setting("desktop:responsive", &true))?;
        }
        s.prepare_disappearing(&db, &key)?;
        s.identity = Some(Identity {
            // Shares the caller's key; a guarded key stays the one copy (S01 §6.2).
            keypair: identity.keypair.clone(),
            created_at: identity.created_at,
            version: identity.version,
        });
        s.db_key = Some(key);
        s.storage = Some(db);
        s.lifecycle_generation += 1;
        let generation = s.lifecycle_generation;
        let runtime = s.runtime.handle().clone();
        drop(cell);
        if !state::allow_operations() {
            return Err(DesktopError::new("lock_failed"));
        }
        crate::callback::unquiesce();
        crate::bootstrap_transport_in_background();
        runtime.spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                if !state_cell()
                    .read()
                    .unwrap()
                    .as_ref()
                    .is_some_and(|s| s.identity.is_some() && s.lifecycle_generation == generation)
                {
                    break;
                }
                let _ = tokio::task::spawn_blocking(|| {
                    let _ = DesktopClient.prepare_read_receipts();
                    let _ = DesktopClient.prepare_stream_transfers();
                    let _ = DesktopClient.prepare_attachments();
                    let _ = DesktopClient.request_missing_parts();
                })
                .await;
            }
        });
        runtime.spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                let current =
                    state_cell().read().unwrap().as_ref().is_some_and(|s| {
                        s.identity.is_some() && s.lifecycle_generation == generation
                    });
                if !current {
                    break;
                }
                let _ = tokio::task::spawn_blocking(|| {
                    let _ = DesktopClient.flush_outbox();
                })
                .await;
            }
        });
        runtime.spawn(async move {
            loop {
                tokio::time::sleep(next_poll_gap()).await;
                if !receive_tick(generation).await {
                    break;
                }
            }
        });
        Ok(())
    }

    /// A failed lock deliberately retains keys and must never be reported locked.
    pub fn lock(&self) -> Result<()> {
        if crate::najwa_lock() != 0 {
            return Err(DesktopError::new("lock_failed"));
        }
        Ok(())
    }
    pub fn cancel(&self) {
        state::cancel_operations(0);
    }
    pub fn reconnect(&self) {
        crate::bootstrap_transport_in_background();
    }
    pub fn status(&self) -> NetworkStatus {
        let cell = state_cell().read().unwrap();
        let s = cell.as_ref();
        let unlocked = s.is_some_and(|s| s.identity.is_some());
        let db = s.and_then(|s| s.storage.as_ref());
        let configured = db
            .and_then(|db| db.list_mailboxes().ok())
            .unwrap_or_default();
        let primary = db
            .and_then(|db| db.get_setting::<String>("desktop:primary").ok())
            .flatten();
        let selected = primary
            .as_deref()
            .filter(|onion| {
                configured
                    .iter()
                    .any(|m| m.enabled && m.onion_address == *onion)
            })
            .or_else(|| {
                configured
                    .iter()
                    .find(|m| m.enabled)
                    .map(|m| m.onion_address.as_str())
            });
        let mailbox_details = configured
            .iter()
            .map(|m| MailboxStatus {
                onion: format!("{}.onion", m.onion_address),
                registered: m.enabled
                    && db
                        .and_then(|db| {
                            db.get_setting::<bool>(&format!("desktop:mailbox:{}", m.id))
                                .ok()
                        })
                        .flatten()
                        == Some(true),
                primary: selected == Some(m.onion_address.as_str()),
            })
            .collect();
        NetworkStatus {
            unlocked,
            connection: if !unlocked {
                "locked"
            } else if s.is_some_and(|s| s.bootstrapping) {
                "connecting"
            } else if s.is_some_and(|s| s.service.lock().unwrap().is_some()) {
                "connected"
            } else {
                "offline"
            },
            cover_running: s
                .and_then(|s| s.cover.as_ref())
                .is_some_and(|c| c.scheduler.is_running()),
            mailboxes: s
                .and_then(|s| s.storage.as_ref())
                .and_then(|db| db.list_mailboxes().ok())
                .unwrap_or_default()
                .into_iter()
                .map(|m| format!("{}.onion", m.onion_address))
                .collect(),
            paused_mailboxes: s
                .and_then(|s| s.storage.as_ref())
                .and_then(|db| db.paused_remote_mailboxes().ok())
                .unwrap_or_default()
                .into_iter()
                .map(|onion| format!("{onion}.onion"))
                .collect(),
            retrying_mailboxes: db
                .and_then(|db| db.retrying_mailboxes().ok())
                .unwrap_or_default()
                .into_iter()
                .map(|onion| format!("{onion}.onion"))
                .collect(),
            mailbox_details,
            pending_deposits: db.and_then(|db| pending_deposits(db).ok()),
            delivery_mode: if db
                .and_then(|db| db.get_setting::<bool>("desktop:responsive").ok())
                .flatten()
                == Some(true)
            {
                "responsive"
            } else {
                "privacy"
            },
        }
    }
    /// S02 §13.2: the recovery marker outlives publication; the encrypted store
    /// records the completed generation (`prekeys:complete`, najwa-core prekeys).
    pub fn prekey_recovery_pending(&self) -> Result<bool> {
        let cell = state_cell().read().unwrap();
        let s = cell.as_ref().ok_or_else(|| DesktopError::new("unavailable"))?;
        let (Some(identity), Some(db)) = (&s.identity, &s.storage) else {
            return Err(DesktopError::new("locked"));
        };
        let marker = najwa_identity::prekey_recovery::generation(
            db.data_dir(),
            &identity.keypair.public().to_bytes(),
        )
        .map_err(|_| DesktopError::new("storage_unavailable"))?;
        Ok(match marker {
            Some(generation) => {
                storage(db.get_setting_raw("prekeys:complete"))?.as_deref()
                    != Some(generation.as_slice())
            }
            None => false,
        })
    }

    pub fn set_delivery_mode(&self, mode: &str) -> Result<()> {
        if !matches!(mode, "responsive" | "privacy") {
            return Err(DesktopError::new("invalid_request"));
        }
        let _operation = OperationGuard::acquire().ok_or_else(|| DesktopError::new("locked"))?;
        let cell = state_cell().read().unwrap();
        let app = cell
            .as_ref()
            .filter(|s| s.identity.is_some())
            .ok_or_else(|| DesktopError::new("locked"))?;
        let db = app
            .storage
            .as_ref()
            .ok_or_else(|| DesktopError::new("locked"))?;
        storage(db.set_setting("desktop:responsive", &(mode == "responsive")))?;
        if let Some(cover) = &app.cover {
            cover
                .scheduler
                .slot_source()
                .set_bypass(mode == "responsive");
        }
        Ok(())
    }

    pub fn select_mailbox(&self, onion: &str) -> Result<()> {
        let onion = checked_onion(onion)?;
        let _operation = OperationGuard::acquire().ok_or_else(|| DesktopError::new("locked"))?;
        let cell = state_cell().read().unwrap();
        let app = cell
            .as_ref()
            .filter(|s| s.identity.is_some())
            .ok_or_else(|| DesktopError::new("locked"))?;
        let db = app
            .storage
            .as_ref()
            .ok_or_else(|| DesktopError::new("locked"))?;
        let mailbox = storage(db.list_mailboxes())?
            .into_iter()
            .find(|m| m.enabled && m.onion_address == onion)
            .ok_or_else(|| DesktopError::new("mailbox_required"))?;
        if storage(db.get_setting::<bool>(&format!("desktop:mailbox:{}", mailbox.id)))?
            != Some(true)
        {
            return Err(DesktopError::new("mailbox_unregistered"));
        }
        for contact in storage(db.list_contacts())? {
            storage(db.delete_setting(&format!("desktop:announced:{}", contact.id)))?;
        }
        storage(db.set_setting("desktop:primary", &onion))
    }

    /// Forget unused incomplete setup without retiring any active receive path.
    pub fn forget_mailbox(&self, onion: &str) -> Result<()> {
        let onion = checked_onion(onion)?;
        NETWORK_BUSY
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| DesktopError::new("busy"))?;
        let _admission = NetworkAdmission;
        let _operation = OperationGuard::acquire().ok_or_else(|| DesktopError::new("locked"))?;
        let mut cell = state_cell().write().unwrap();
        let app = cell
            .as_mut()
            .filter(|s| s.identity.is_some())
            .ok_or_else(|| DesktopError::new("locked"))?;
        let db = app
            .storage
            .clone()
            .ok_or_else(|| DesktopError::new("locked"))?;
        let mailbox = storage(db.list_mailboxes())?
            .into_iter()
            .find(|m| m.onion_address == onion)
            .ok_or_else(|| DesktopError::new("mailbox_required"))?;
        if mailbox.enabled
            || storage(db.get_setting::<bool>(&format!("desktop:mailbox:{}", mailbox.id)))?
                == Some(true)
            || !storage(db.get_capabilities_for_mailbox(mailbox.id))?.is_empty()
            || !storage(db.get_active_ephemeral_handshake_caps_for_mailbox(mailbox.id, 0))?
                .is_empty()
        {
            return Err(DesktopError::new("mailbox_in_use"));
        }
        storage(db.delete_mailbox(mailbox.id))?;
        if let Some(cover) = &mut app.cover {
            cover.refresh(&db);
        }
        Ok(())
    }

    /// Manual recovery only; automatic reconnect never resets mailbox pauses.
    pub fn retry_mailbox(&self, onion: &str) -> Result<()> {
        let onion = checked_onion(onion)?;
        let _guard = OperationGuard::acquire().ok_or_else(|| DesktopError::new("locked"))?;
        let cell = state_cell().read().unwrap();
        let app = cell
            .as_ref()
            .ok_or_else(|| DesktopError::new("unavailable"))?;
        if app.identity.is_none() {
            return Err(DesktopError::new("locked"));
        }
        let db = app
            .storage
            .as_ref()
            .ok_or_else(|| DesktopError::new("locked"))?;
        if !storage(db.paused_remote_mailboxes())?.contains(&onion) {
            return Err(DesktopError::new("mailbox_not_paused"));
        }
        storage(db.enable_remote_mailbox(&onion))
    }

    pub fn contacts(&self) -> Result<Vec<Contact>> {
        let _guard = OperationGuard::acquire().ok_or_else(|| DesktopError::new("locked"))?;
        let cell = state_cell().read().unwrap();
        let s = cell
            .as_ref()
            .ok_or_else(|| DesktopError::new("unavailable"))?;
        let db = s
            .storage
            .as_ref()
            .ok_or_else(|| DesktopError::new("locked"))?;
        let public = s
            .identity
            .as_ref()
            .ok_or_else(|| DesktopError::new("locked"))?
            .keypair
            .public()
            .to_bytes();
        let service = s.service.lock().unwrap().clone();
        storage(db.list_contacts_with_preview())?
            .into_iter()
            .map(|(c, preview, unread)| {
                let ready = contact_ready(db, c.id)?;
                let setup = contact_setup(db, c.id, ready, now())?;
                Ok(Contact {
                    id: c.id.to_string(),
                    name: c.display_name.unwrap_or_else(|| "Contact".into()),
                    verified: c.verified,
                    blocked: c.blocked,
                    unread,
                    ready,
                    setup_state: setup.state,
                    setup_expires_at: setup.expires_at,
                    safety_number: najwa_protocol::contact::fingerprint::safety_number(
                        &public,
                        &c.their_ik_pub,
                    ),
                    timer_seconds: storage(db.get_conversation_timer(c.id))?.unwrap_or(0),
                    timer_pending: storage(db.timer_change_pending(c.id))?,
                    preview: preview.map(|text| text.chars().take(160).collect()),
                    last_message_at: c.last_message_at.map(|at| at.max(0) as u64),
                    repair_status: service.as_ref().and_then(|svc| svc.get_repair_state(c.id as u64)).map(|state| match state.phase {
                        najwa_core::service::RepairPhase::InProgress => "repairing",
                        najwa_core::service::RepairPhase::Failed => "failed",
                    }),
                })
            })
            .collect()
    }
    pub fn messages(&self, contact: &str) -> Result<Vec<Message>> {
        let id = positive_id(contact)?;
        let _guard = OperationGuard::acquire().ok_or_else(|| DesktopError::new("locked"))?;
        let cell = state_cell().read().unwrap();
        let s = cell
            .as_ref()
            .ok_or_else(|| DesktopError::new("unavailable"))?;
        let db = s
            .storage
            .as_ref()
            .ok_or_else(|| DesktopError::new("locked"))?;
        attachments::visible_rows(db, &s.disappearing_keys, id)?
            .into_iter()
            .map(|mut m| {
                // The row's plaintext is copied into `text`; wipe the row.
                let content = attachments::message_content(db, &m);
                zeroize::Zeroize::zeroize(&mut m.content);
                let (text, reply_to, attachment) = content?;
                Ok(Message {
                    id: m.id.to_string(),
                    msg_id: crate::hex_encode(&m.msg_id),
                    text,
                    reply_to,
                    attachment,
                    outgoing: m.direction == najwa_storage::types::MessageDirection::Sent,
                    timestamp: m.timestamp.max(0) as u64,
                    status: status_name(m.status),
                    expires_at: m.disappear_at.map(|v| v.max(0) as u64),
                })
            })
            .collect()
    }
    pub fn displayed(&self, contact: &str, ids: &[String]) -> Result<()> {
        let cid = positive_id(contact)?;
        if ids.len() > 200 {
            return Err(DesktopError::new("invalid_request"));
        }
        let ids = ids
            .iter()
            .map(|id| positive_id(id))
            .collect::<Result<Vec<_>>>()?;
        let _guard = OperationGuard::acquire().ok_or_else(|| DesktopError::new("locked"))?;
        crate::with_storage(|db| {
            db.mark_displayed_with_receipts(cid, &ids)
                .map_err(|_| FfiErrorCode::StorageError)
        })?;
        Ok(())
    }
    pub fn verify(
        &self,
        contact: &str,
        expected_safety_number: &str,
        verified: bool,
    ) -> Result<()> {
        let cid = positive_id(contact)?;
        let _guard = OperationGuard::acquire().ok_or_else(|| DesktopError::new("locked"))?;
        let cell = state_cell().read().unwrap();
        let s = cell
            .as_ref()
            .ok_or_else(|| DesktopError::new("unavailable"))?;
        let db = s
            .storage
            .as_ref()
            .ok_or_else(|| DesktopError::new("locked"))?;
        let public = s
            .identity
            .as_ref()
            .ok_or_else(|| DesktopError::new("locked"))?
            .keypair
            .public()
            .to_bytes();
        let contact =
            storage(db.get_contact(cid))?.ok_or_else(|| DesktopError::new("contact_missing"))?;
        if najwa_protocol::contact::fingerprint::safety_number(&public, &contact.their_ik_pub)
            != expected_safety_number
        {
            return Err(DesktopError::new("stale_operation"));
        }
        storage(db.verify_contact_identity(cid, &contact.their_ik_pub, verified))
    }

    /// Persist exact pairs before network work. Lost responses retry the same pair.
    pub fn add_mailbox(&self, onion: &str) -> Result<()> {
        let onion = checked_onion(onion)?;
        self.run(|session| async move {
            let existing = storage(session.db.list_mailboxes())?
                .into_iter()
                .find(|m| m.onion_address == onion);
            let id = match existing {
                Some(m) => m.id,
                None => {
                    if storage(session.db.list_mailboxes())?.len() >= 8 {
                        return Err(DesktopError::new("mailbox_limit"));
                    }
                    let id = storage(session.db.save_mailbox(&NewMailbox::with_cover_caps(
                        onion,
                        random_bytes::<32>().to_vec(),
                        random_bytes::<32>().to_vec(),
                        0,
                        now() as i64,
                    )))?;
                    // An unreachable new mailbox must not stall polling and
                    // prekey maintenance for already-working conversations.
                    storage(session.db.disable_mailbox(id))?;
                    id
                }
            };
            provision_primary(&session, id).await?;
            storage(session.db.enable_mailbox(id))?;
            messaging(session.service.maintain_prekeys().await)?;
            extend_contact_mailboxes(&session.db)
        })
    }
    pub fn invitation(&self, name: &str) -> Result<String> {
        checked_name(name)?;
        let name = name.to_string();
        self.run(|session| async move {
            let mut mailboxes = Vec::new();
            for mailbox in storage(session.db.list_mailboxes())?
                .into_iter()
                .filter(|m| m.enabled)
            {
                if storage(
                    session
                        .db
                        .get_setting::<bool>(&format!("desktop:mailbox:{}", mailbox.id)),
                )? == Some(true)
                {
                    mailboxes.push(mailbox);
                }
            }
            if mailboxes.is_empty() {
                return Err(DesktopError::new("mailbox_required"));
            }
            let primary = storage(session.db.get_setting::<String>("desktop:primary"))?;
            mailboxes.sort_by_key(|m| primary.as_deref() != Some(m.onion_address.as_str()));
            let mut configs = Vec::new();
            let mut retry_pointers = Vec::new();
            let mut expiry = u64::MAX;
            for mailbox in mailboxes {
                provision_primary(&session, mailbox.id).await?;
                // Reuse only a slot whose earlier attempt failed or was cancelled
                // before export. Every exported invitation keeps its own queue.
                let setting = format!("desktop:invite:{}", mailbox.id);
                let previous = storage(session.db.get_setting::<i64>(&setting))?
                    .map(|id| storage(session.db.get_ephemeral_handshake_cap(id)))
                    .transpose()?
                    .flatten()
                    .filter(|cap| {
                        cap.accepted_at.is_none()
                            && cap.deactivated_at.is_none()
                            && reusable_invitation_window(
                                cap.created_at,
                                cap.expires_at,
                                now() as i64,
                            )
                    });
                // Earlier development builds omitted the wire type. A new request
                // cannot upgrade that server pair, so never reuse those invitations.
                let previous = match previous {
                    Some(cap)
                        if storage(
                            session
                                .db
                                .get_setting::<u8>(&format!("desktop:invite-wire:{}", cap.id)),
                        )? == Some(1) =>
                    {
                        Some(cap)
                    }
                    _ => None,
                };
                let id = match previous {
                    Some(cap) => cap.id,
                    None => {
                        let created_at = now() as i64;
                        let id = storage(session.db.save_ephemeral_handshake_cap(
                            &NewEphemeralHandshakeCap {
                                mailbox_id: mailbox.id,
                                deposit_capability: random_bytes::<32>().to_vec(),
                                fetch_capability: random_bytes::<32>().to_vec(),
                                envelope_secret: random_bytes::<32>().to_vec(),
                                capability_type: 1,
                                created_at,
                                expires_at: created_at + EPHEMERAL_CAP_TTL_SECS as i64,
                            },
                        ))?;
                        storage(session.db.set_setting(&setting, &id))?;
                        storage(
                            session
                                .db
                                .set_setting(&format!("desktop:invite-wire:{id}"), &1u8),
                        )?;
                        id
                    }
                };
                let cap = storage(session.db.get_ephemeral_handshake_cap(id))?
                    .ok_or_else(|| DesktopError::new("storage_unavailable"))?;
                let config = coordinates(
                    &mailbox.onion_address,
                    &cap.fetch_capability,
                    &cap.deposit_capability,
                    &cap.envelope_secret,
                )?;
                if cap.registered_at.is_none() {
                    register_ephemeral(&session, &config, cap.expires_at as u64).await?;
                    storage(
                        session
                            .db
                            .mark_ephemeral_handshake_cap_registered(id, now() as i64),
                    )?;
                }
                messaging(session.service.maintain_prekeys().await)?;
                // Setup can spend minutes on Tor. Never export an expired or nearly
                // expired saved invitation after a retry; the next call mints a new one.
                if !reusable_invitation_window(cap.created_at, cap.expires_at, now() as i64) {
                    return Err(DesktopError::new("invitation_expiring"));
                }
                expiry = expiry.min(cap.expires_at as u64);
                configs.push(config);
                retry_pointers.push(setting);
                retry_pointers.push(format!("desktop:invite-wire:{id}"));
            }
            if expiry <= now().saturating_add(600) {
                return Err(DesktopError::new("invitation_expiring"));
            }
            let mut payload = HandshakePayload::create(
                &session.identity,
                &configs,
                &name,
                EPHEMERAL_CAP_TTL_SECS / 3600,
            )
            .map_err(|_| DesktopError::new("invalid_invitation"))?;
            payload.expires_at = expiry;
            payload.signature = session.identity.sign(&payload.signable_bytes()).to_bytes();
            let uri = payload
                .to_uri()
                .map_err(|_| DesktopError::new("invalid_invitation"))?;
            // S05 §5.2: a queue accepts one Initial. Once exported it belongs to
            // this invitation alone, so the next request mints fresh queues.
            for key in retry_pointers {
                storage(session.db.delete_setting(&key))?;
            }
            Ok(uri)
        })
    }
    /// `confirmed` is the user's explicit consent to add a contact after
    /// `DAILY_CONTACT_LIMIT` additions in 24 hours (S05 §8.1).
    pub fn accept_invitation(&self, invitation: &str, name: &str, confirmed: bool) -> Result<String> {
        checked_name(name)?;
        if invitation.len() > 4096 {
            return Err(DesktopError::new("invalid_invitation"));
        }
        let payload = if invitation.starts_with("NAJWA:") {
            HandshakePayload::from_qr_string(invitation)
        } else {
            HandshakePayload::from_uri(invitation)
        }
        .map_err(|_| DesktopError::new("invalid_invitation"))?;
        payload
            .verify()
            .map_err(|_| DesktopError::new("invalid_invitation"))?;
        for entry in &payload.mailbox_entries {
            checked_onion(
                std::str::from_utf8(&entry.onion_address)
                    .map_err(|_| DesktopError::new("invalid_invitation"))?,
            )?;
        }
        let name = name.to_string();
        // Accepting a signed invitation only needs the unlocked local store.
        // The normal sync worker registers routes and sends the introduction.
        let mut operation = OperationGuard::acquire().ok_or_else(|| DesktopError::new("locked"))?;
        let (runtime, db, identity) = {
            let cell = state_cell().read().unwrap();
            let app = cell
                .as_ref()
                .ok_or_else(|| DesktopError::new("unavailable"))?;
            let identity = app
                .identity
                .as_ref()
                .ok_or_else(|| DesktopError::new("locked"))?;
            (
                app.runtime.handle().clone(),
                app.storage
                    .clone()
                    .ok_or_else(|| DesktopError::new("locked"))?,
                identity.keypair.clone(),
            )
        };
        runtime.block_on(operation.cancellable(async move {
            if payload.ik_pub == identity.public().to_bytes() {
                return Err(DesktopError::new("self_contact"));
            }
            let existing = storage(db.get_contact_by_ik(&payload.ik_pub))?;
            let cid = if let Some(contact) = existing {
                // Retry only the exact signed invitation that established this contact.
                let saved =
                    storage(db.get_setting_raw(&format!("contact_handshake:{}", contact.id)))?;
                if saved.as_deref() != Some(payload.to_bytes().as_slice()) {
                    return Err(DesktopError::new("contact_exists"));
                }
                contact.id
            } else {
                // Counts every contact added, including those from own invitations.
                let added = storage(db.list_contacts())?.into_iter().map(|c| c.created_at);
                if !confirmed
                    && najwa_core::contact_rate_limit::confirmation_required(added, now() as i64)
                {
                    return Err(DesktopError::new("contact_limit_confirm"));
                }
                let accepted = accept_contact(&identity, &*db, &payload)
                    .await
                    .map_err(|_| DesktopError::new("invalid_invitation"))?;
                accepted.contact_id.0 as i64
            };
            // Durable obligation survives cancellation/restart before the Initial.
            if storage(db.get_ratchet_state(cid))?.is_none() {
                storage(db.set_setting(&format!("desktop:reciprocal:{cid}"), &name))?;
            }
            Ok(cid.to_string())
        }))?
    }
    pub fn sync(&self) -> Result<()> {
        self.run(|session| async move {
            // Receive from established routes before optional setup can fail.
            // The core poll retains the mandatory prekey-recovery gate and
            // tolerates ordinary maintenance failures on another mailbox.
            messaging(session.service.poll_messages().await)?;
            for m in storage(session.db.list_mailboxes())?
                .into_iter()
                .filter(|m| m.enabled)
            {
                provision_primary(&session, m.id).await?;
            }
            prepare_contacts(&session).await
        })
    }
    pub fn send(&self, contact: &str, text: &str) -> Result<String> {
        self.send_reply(contact, text, None)
    }
    pub fn send_reply(&self, contact: &str, text: &str, reply_to: Option<&str>) -> Result<String> {
        let cid = positive_id(contact)?;
        if text.trim().is_empty() || text.len() > 16_000 || text.contains('\0') {
            return Err(DesktopError::new("invalid_message"));
        }
        let text = text.to_string();
        let reply_to = reply_to.map(attachments::decode_id).transpose()?;
        // Queueing an established conversation must not contend with the slow
        // network admission guard. Lock still cancels and drains this operation.
        let mut operation = OperationGuard::acquire().ok_or_else(|| DesktopError::new("locked"))?;
        let (runtime, db, service) = {
            let cell = state_cell().read().unwrap();
            let app = cell
                .as_ref()
                .ok_or_else(|| DesktopError::new("unavailable"))?;
            let db = app
                .storage
                .clone()
                .ok_or_else(|| DesktopError::new("locked"))?;
            let service = app
                .service
                .lock()
                .unwrap()
                .clone()
                .ok_or_else(|| DesktopError::new("not_connected"))?;
            (app.runtime.handle().clone(), db, service)
        };
        if !contact_ready(&db, cid)? {
            return Err(DesktopError::new("contact_pending"));
        }
        if storage(db.timer_change_pending(cid))? {
            return Err(DesktopError::new("timer_pending"));
        }
        runtime.block_on(operation.cancellable(async {
            let message = messaging(
                tokio::time::timeout(
                    Duration::from_secs(15),
                    service.enqueue_message_with_flags(
                        cid as u64,
                        match reply_to {
                            Some(reply_to) => MessageContent::TextReply { text, reply_to },
                            None => MessageContent::Text(text),
                        },
                        najwa_protocol::message::payload_flags::READ_RECEIPT_REQUESTED,
                    ),
                )
                .await
                .map_err(|_| DesktopError::new("timeout"))?,
            )?;
            Ok(crate::hex_encode(&message.msg_id))
        }))?
    }

    /// Change only future messages; setting and encrypted peer notification are atomic.
    pub fn set_timer(&self, contact: &str, seconds: u32) -> Result<()> {
        let cid = positive_id(contact)?;
        if (1..30).contains(&seconds) {
            return Err(DesktopError::new("invalid_timer"));
        }
        let mut operation = OperationGuard::acquire().ok_or_else(|| DesktopError::new("locked"))?;
        let (runtime, db, service) = {
            let cell = state_cell().read().unwrap();
            let app = cell
                .as_ref()
                .ok_or_else(|| DesktopError::new("unavailable"))?;
            let db = app
                .storage
                .clone()
                .ok_or_else(|| DesktopError::new("locked"))?;
            let service = app
                .service
                .lock()
                .unwrap()
                .clone()
                .ok_or_else(|| DesktopError::new("not_connected"))?;
            (app.runtime.handle().clone(), db, service)
        };
        if !contact_ready(&db, cid)? {
            return Err(DesktopError::new("contact_pending"));
        }
        if seconds > 0 && (storage(db.transfers(Some(cid)))?.iter().any(|t|t.state<3) || storage(db.attachment_jobs())?.iter().any(|key| key.starts_with(&format!("desktop:attachment-job:{cid}:")))) {
            return Err(DesktopError::new("file_preparing"));
        }
        if storage(db.timer_change_pending(cid))? {
            return Err(DesktopError::new("timer_pending"));
        }
        runtime.block_on(operation.cancellable(async {
            messaging(
                tokio::time::timeout(
                    Duration::from_secs(15),
                    service.enqueue_timer_change(cid as u64, (seconds > 0).then_some(seconds)),
                )
                .await
                .map_err(|_| DesktopError::new("timeout"))?,
            )
        }))?
    }

    /// Independent delivery keeps queued text from waiting behind a slow poll.
    /// Core frame claims prevent overlapping retries from duplicating deposits.
    fn prepare_read_receipts(&self) -> Result<()> {
        let mut operation = OperationGuard::acquire().ok_or_else(|| DesktopError::new("locked"))?;
        let (runtime, service) = {
            let cell = state_cell().read().unwrap();
            let app = cell.as_ref().ok_or_else(|| DesktopError::new("unavailable"))?;
            let service = app.service.lock().unwrap().clone()
                .ok_or_else(|| DesktopError::new("not_connected"))?;
            (app.runtime.handle().clone(), service)
        };
        runtime.block_on(operation.cancellable(async {
            messaging(service.enqueue_read_receipts().await)
        }))?
    }

    fn flush_outbox(&self) -> Result<()> {
        OUTBOX_BUSY
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| DesktopError::new("busy"))?;
        let _admission = OutboxAdmission;
        let mut operation = OperationGuard::acquire().ok_or_else(|| DesktopError::new("locked"))?;
        let (runtime, service) = {
            let cell = state_cell().read().unwrap();
            let app = cell
                .as_ref()
                .ok_or_else(|| DesktopError::new("unavailable"))?;
            let service = app
                .service
                .lock()
                .unwrap()
                .clone()
                .ok_or_else(|| DesktopError::new("not_connected"))?;
            (app.runtime.handle().clone(), service)
        };
        runtime.block_on(operation.cancellable(async {
            messaging(
                tokio::time::timeout(Duration::from_secs(600), service.drive_outgoing())
                    .await
                    .map_err(|_| DesktopError::new("timeout"))?,
            )
        }))?
    }

    fn run<T, F, Fut>(&self, f: F) -> Result<T>
    where
        F: FnOnce(Session) -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        NETWORK_BUSY
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| DesktopError::new("busy"))?;
        let _admission = NetworkAdmission;
        let mut operation = OperationGuard::acquire().ok_or_else(|| DesktopError::new("locked"))?;
        let (runtime, session) = {
            let cell = state_cell().read().unwrap();
            let s = cell
                .as_ref()
                .ok_or_else(|| DesktopError::new("unavailable"))?;
            let service = s
                .service
                .lock()
                .unwrap()
                .clone()
                .ok_or_else(|| DesktopError::new("not_connected"))?;
            let cover = s
                .cover
                .as_ref()
                .ok_or_else(|| DesktopError::new("not_connected"))?;
            let identity = s
                .identity
                .as_ref()
                .ok_or_else(|| DesktopError::new("locked"))?;
            (
                s.runtime.handle().clone(),
                Session {
                    db: s
                        .storage
                        .clone()
                        .ok_or_else(|| DesktopError::new("locked"))?,
                    service,
                    client: cover.client.clone(),
                    slots: cover.scheduler.slot_source(),
                    identity: identity.keypair.clone(),
                },
            )
        };
        runtime.block_on(operation.cancellable(async {
            tokio::time::timeout(Duration::from_secs(600), f(session))
                .await
                .map_err(|_| DesktopError::new("timeout"))?
        }))?
    }
}

struct Session {
    db: Arc<SqliteStorage>,
    service: Arc<state::FfiService>,
    client: Arc<HttpMailboxClient>,
    slots: Arc<SlotSource>,
    identity: Ed25519KeyPair,
}
fn reusable_invitation_window(created_at: i64, expires_at: i64, current: i64) -> bool {
    // Migrate the mistakenly issued 15-minute QR slots to the S05 URI lifetime.
    // Reserve at least one full desktop-operation timeout for acceptance.
    expires_at.saturating_sub(created_at) == EPHEMERAL_CAP_TTL_SECS as i64
        && expires_at.saturating_sub(current) > 600
}
fn registration_error(phase: &'static str, error: MailboxError) -> DesktopError {
    let code = match &error {
        MailboxError::TransportError(_) => "registration_transport",
        MailboxError::PowTimeout | MailboxError::PowExhausted => "registration_pow",
        MailboxError::RateLimited | MailboxError::PowRequired(_) => "registration_limited",
        MailboxError::ServerError(409) => "registration_conflict",
        MailboxError::ServerError(500..=599) | MailboxError::QuotaExceeded => "registration_server",
        MailboxError::ServerError(400..=499)
        | MailboxError::CapabilityNotFound
        | MailboxError::MessageTooLarge => "registration_rejected",
        _ => "registration_failed",
    };
    let http_status = match error {
        MailboxError::ServerError(status) => Some(status),
        _ => None,
    };
    // Log only stable classifications, never capabilities, PoW tokens or responses.
    tracing::warn!(phase, code, http_status, "mailbox registration failed");
    DesktopError::new(code)
}
async fn register(session: &Session, config: &MailboxConfig) -> Result<()> {
    let pow = session
        .client
        .prepare_registration_pow(config)
        .await
        .map_err(|error| registration_error("primary_challenge", error))?;
    loop {
        let permit = session
            .slots
            .await_slot(&config.onion_address, AbsorptionPriority::Control, None)
            .await;
        if permit.begin() {
            break;
        }
    }
    session
        .client
        .register_cover_once(config, &CapabilitySettings::default(), pow)
        .await
        .map_err(|error| registration_error("primary_submission", error))
}
async fn register_ephemeral(
    session: &Session,
    config: &MailboxConfig,
    expires_at: u64,
) -> Result<()> {
    let pow = session
        .client
        .prepare_registration_pow(config)
        .await
        .map_err(|error| registration_error("invitation_challenge", error))?;
    loop {
        let permit = session
            .slots
            .await_slot(&config.onion_address, AbsorptionPriority::Control, None)
            .await;
        if permit.begin() {
            break;
        }
    }
    session
        .client
        .register_ephemeral_once(config, &CapabilitySettings::default(), pow, expires_at)
        .await
        .map_err(|error| registration_error("invitation_submission", error))
}
async fn provision_primary(session: &Session, id: i64) -> Result<()> {
    let marker = format!("desktop:mailbox:{id}");
    if storage(session.db.get_setting::<bool>(&marker))? == Some(true) {
        return Ok(());
    }
    let m = storage(session.db.get_mailbox(id))?
        .ok_or_else(|| DesktopError::new("mailbox_required"))?;
    register(
        session,
        &coordinates(
            &m.onion_address,
            &m.fetch_capability,
            &m.deposit_capability,
            &m.envelope_secret,
        )?,
    )
    .await?;
    storage(session.db.set_setting(&marker, &true))
}
async fn prepare_contacts(session: &Session) -> Result<()> {
    extend_contact_mailboxes(&session.db)?;
    let mut contacts = Vec::new();
    for contact in storage(session.db.list_contacts())? {
        if contact.blocked {
            continue;
        }
        let setup = contact_setup(
            &session.db,
            contact.id,
            contact_ready(&session.db, contact.id)?,
            now(),
        )?;
        if retire_expired_setup(&session.db, contact.id, &setup)? {
            continue;
        }
        if setup.state != "failed" {
            contacts.push(contact);
        }
    }
    for c in &contacts {
        if c.blocked {
            continue;
        }
        for cap in storage(session.db.get_contact_capabilities(c.id))? {
            if cap.revoked_at.is_some() || cap.registered_at.is_some() {
                continue;
            }
            let m = storage(session.db.get_mailbox(cap.mailbox_id))?
                .ok_or_else(|| DesktopError::new("mailbox_required"))?;
            let config = coordinates(
                &m.onion_address,
                cap.fetch_capability.as_deref().unwrap_or_default(),
                &cap.deposit_capability,
                cap.envelope_secret.as_deref().unwrap_or_default(),
            )?;
            register(session, &config).await?;
            storage(
                session
                    .db
                    .mark_contact_capability_registered(cap.id, now() as i64),
            )?;
        }
    }
    messaging(session.service.maintain_prekeys().await)?;
    for c in contacts {
        if c.blocked {
            continue;
        }
        let key = format!("desktop:reciprocal:{}", c.id);
        let pending = storage(session.db.get_setting::<String>(&key))?;
        let entries = local_configs(&session.db, c.id)?;
        let payload = signed_long_term(
            &session.identity,
            &entries,
            pending.as_deref().unwrap_or(""),
        )?;
        // Completion belongs to this exact ordered set. A primary change can
        // happen while the network await is in flight; finishing the old update
        // must not suppress the newer mailbox order on the next sync.
        let marker = announcement_marker(c.id, &entries);
        if pending.is_some() {
            // A committed Initial includes the ratchet and durable outbox atomically.
            // Never generate a second Initial when cancellation lost its return value.
            if storage(session.db.get_ratchet_state(c.id))?.is_none() {
                messaging(
                    session
                        .service
                        .send_message(
                            c.id as u64,
                            MessageContent::Raw {
                                content_type: ContentType::ReciprocalHandshake as u8,
                                bytes: payload.to_bytes(),
                                reply_to: None,
                            },
                        )
                        .await,
                )?;
                complete_announcement(&session.db, c.id, &marker)?;
            }
            // If an earlier Initial committed but its result was lost, we do
            // not know which coordinates it advertised. Send an update below.
            storage(session.db.delete_setting(&key))?;
        }
        if storage(session.db.get_ratchet_state(c.id))?.is_some()
            && !announcement_is_current(&session.db, c.id, &marker)?
        {
            messaging(
                session
                    .service
                    .send_control_message(
                        c.id as u64,
                        &ControlMessage::MailboxUpdate {
                            mailboxes: payload.mailbox_entries,
                        },
                    )
                    .await,
            )?;
            complete_announcement(&session.db, c.id, &marker)?;
        }
    }
    Ok(())
}
fn announcement_marker(contact: i64, mailboxes: &[MailboxConfig]) -> String {
    let mut bytes = Zeroizing::new(Vec::new());
    bytes.extend_from_slice(b"najwa.desktop.mailbox-announcement.v2");
    for mailbox in mailboxes {
        bytes.extend_from_slice(&(mailbox.onion_address.len() as u64).to_be_bytes());
        bytes.extend_from_slice(mailbox.onion_address.as_bytes());
        bytes.extend_from_slice(&mailbox.fetch_capability);
        bytes.extend_from_slice(&mailbox.deposit_capability);
        bytes.extend_from_slice(&mailbox.envelope_secret);
    }
    let digest: String = najwa_crypto::hash::sha256(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("desktop:announced-v2:{contact}:{digest}")
}
fn announcement_is_current(db: &SqliteStorage, contact: i64, marker: &str) -> Result<bool> {
    Ok(
        storage(db.get_setting::<String>(&format!("desktop:announced-current:{contact}")))?
            .as_deref()
            == Some(marker),
    )
}
fn complete_announcement(db: &SqliteStorage, contact: i64, marker: &str) -> Result<()> {
    // Store the last completion, not every set ever sent. A -> B -> A must
    // announce A again. A late completion for A cannot make B look current.
    storage(db.set_contact_setting(
        contact,
        &format!("desktop:announced-current:{contact}"),
        &marker,
    ))
}
/// New mailboxes become registered per-contact receive paths through the normal
/// setup worker. Never advertise a capability before the server accepts it.
fn extend_contact_mailboxes(db: &SqliteStorage) -> Result<()> {
    let mailboxes = storage(db.list_mailboxes())?;
    for contact in storage(db.list_contacts())?
        .into_iter()
        .filter(|c| !c.blocked)
    {
        let existing = storage(db.get_contact_capabilities(contact.id))?;
        for mailbox in mailboxes.iter().filter(|m| m.enabled) {
            if storage(db.get_setting::<bool>(&format!("desktop:mailbox:{}", mailbox.id)))?
                != Some(true)
                || existing.iter().any(|c| c.mailbox_id == mailbox.id)
            {
                continue;
            }
            storage(db.delete_setting(&format!("desktop:announced:{}", contact.id)))?;
            storage(
                db.save_contact_capability(&najwa_storage::types::NewContactMailboxCap {
                    contact_id: contact.id,
                    mailbox_id: mailbox.id,
                    deposit_capability: random_bytes::<32>().to_vec(),
                    fetch_capability: Some(random_bytes::<32>().to_vec()),
                    envelope_secret: Some(random_bytes::<32>().to_vec()),
                    their_deposit_capability: existing
                        .first()
                        .and_then(|c| c.their_deposit_capability.clone()),
                    their_envelope_secret: existing
                        .first()
                        .and_then(|c| c.their_envelope_secret.clone()),
                    capability_type: 2,
                    expires_at: None,
                    registered_at: None,
                    created_at: now() as i64,
                }),
            )?;
        }
    }
    Ok(())
}
fn local_configs(db: &SqliteStorage, cid: i64) -> Result<Vec<MailboxConfig>> {
    let mut configs: Vec<MailboxConfig> = storage(db.get_contact_capabilities(cid))?
        .into_iter()
        .filter(|c| c.registered_at.is_some() && c.revoked_at.is_none())
        .map(|c| {
            let m = storage(db.get_mailbox(c.mailbox_id))?
                .ok_or_else(|| DesktopError::new("mailbox_required"))?;
            coordinates(
                &m.onion_address,
                c.fetch_capability.as_deref().unwrap_or_default(),
                &c.deposit_capability,
                c.envelope_secret.as_deref().unwrap_or_default(),
            )
        })
        .collect::<Result<_>>()?;
    let primary = storage(db.get_setting::<String>("desktop:primary"))?;
    configs.sort_by_key(|config| primary.as_deref() != Some(config.onion_address.as_str()));
    Ok(configs)
}
fn signed_long_term(
    identity: &Ed25519KeyPair,
    configs: &[MailboxConfig],
    name: &str,
) -> Result<HandshakePayload> {
    // S05 §8.2: live at least as long as the invitation queue the Initial is
    // deposited to. That queue was created before acceptance and lives one TTL.
    let mut p = HandshakePayload::create(identity, configs, name, EPHEMERAL_CAP_TTL_SECS / 3600)
        .map_err(|_| DesktopError::new("mailbox_required"))?;
    for entry in &mut p.mailbox_entries {
        entry.capability_type = 2;
    }
    p.signature = identity.sign(&p.signable_bytes()).to_bytes();
    Ok(p)
}
struct ContactSetup {
    state: &'static str,
    expires_at: Option<u64>,
    message_id: Option<i64>,
}

fn retire_expired_setup(db: &SqliteStorage, cid: i64, setup: &ContactSetup) -> Result<bool> {
    if setup.state != "expired" {
        return Ok(false);
    }
    if let Some(message) = setup.message_id {
        if !storage(db.retire_undeposited_contact_setup(message))? {
            return Ok(false);
        }
    }
    storage(db.delete_setting(&format!("desktop:reciprocal:{cid}")))?;
    Ok(true)
}

fn pending_deposits(db: &SqliteStorage) -> Result<u64> {
    // Inspect preparation first: its atomic replacement by an Initial frame can
    // briefly overcount, but must never report zero before that frame deposits.
    let mut preparing = storage(db.attachment_jobs())?.len() as u64 + storage(db.transfers(None))?.iter().filter(|t|t.state<3).count() as u64;
    for cid in storage(db.pending_contact_preparations())? {
        let setup = contact_setup(db, cid, false, now())?;
        if setup.state == "queued" && setup.message_id.is_none() {
            preparing += 1;
        }
    }
    // Receiving an introduction establishes a ratchet before our reply's
    // receive paths have been registered and announced. Count that preparation
    // too: local readiness is not proof that the remote peer can finish setup.
    let mailboxes = storage(db.list_mailboxes())?;
    for contact in storage(db.list_contacts())?.into_iter().filter(|c| !c.blocked) {
        if storage(db.get_ratchet_state(contact.id))?.is_none() {
            continue;
        }
        let setup = contact_setup(db, contact.id, contact_ready(db, contact.id)?, now())?;
        if matches!(setup.state, "expired" | "failed") {
            continue;
        }
        let caps = storage(db.get_contact_capabilities(contact.id))?;
        let missing_path = mailboxes.iter().filter(|m| m.enabled).any(|m| {
            !caps.iter().any(|cap| cap.mailbox_id == m.id
                && cap.revoked_at.is_none() && cap.registered_at.is_some())
        });
        let configs = local_configs(db, contact.id)?;
        if missing_path || configs.is_empty()
            || !announcement_is_current(db, contact.id, &announcement_marker(contact.id, &configs))?
        {
            preparing += 1;
        }
    }
    Ok(preparing + storage(db.pending_deposit_count())?)
}

fn contact_setup(db: &SqliteStorage, cid: i64, ready: bool, current: u64) -> Result<ContactSetup> {
    if ready {
        return Ok(ContactSetup {
            state: "ready",
            expires_at: None,
            message_id: None,
        });
    }
    if let Some(message) = storage(db.contact_setup_message(cid))? {
        let expires_at = HandshakePayload::from_bytes(&message.content)
            .ok()
            .map(|payload| payload.expires_at);
        let deposited = matches!(
            message.status,
            najwa_storage::types::MessageStatus::Sent
                | najwa_storage::types::MessageStatus::Delivered
                | najwa_storage::types::MessageStatus::Read
        );
        let elapsed = expires_at.is_some_and(|expiry| current >= expiry);
        let state = if deposited {
            if elapsed {
                "unconfirmed"
            } else {
                "waiting"
            }
        } else if elapsed {
            "expired"
        } else if message.status == najwa_storage::types::MessageStatus::PermanentlyFailed {
            "failed"
        } else {
            "queued"
        };
        return Ok(ContactSetup {
            state,
            expires_at,
            message_id: Some(message.id),
        });
    }
    let expires_at = storage(db.get_setting_raw(&format!("contact_handshake:{cid}")))?
        .and_then(|bytes| HandshakePayload::from_bytes(&bytes).ok())
        .map(|payload| payload.expires_at);
    Ok(ContactSetup {
        state: if expires_at.is_some_and(|expiry| current >= expiry) {
            "expired"
        } else {
            "queued"
        },
        expires_at,
        message_id: None,
    })
}

fn contact_ready(db: &SqliteStorage, cid: i64) -> Result<bool> {
    if storage(db.get_ratchet_state(cid))?.is_none() {
        return Ok(false);
    }
    let targets = storage(
        db.get_setting::<Vec<najwa_storage::contact_establishment::ContactTarget>>(&format!(
            "contact_targets:{cid}"
        )),
    )?;
    Ok(targets.is_some_and(|targets| {
        targets.iter().any(|t| {
            najwa_protocol::contact::mailbox_key::MailboxEntry::from_bytes(&t.mailbox_entry)
                .is_ok_and(|e| e.capability_type == 2)
        })
    }))
}
fn coordinates(
    onion: &str,
    fetch: &[u8],
    deposit: &[u8],
    envelope: &[u8],
) -> Result<MailboxConfig> {
    let array = |v: &[u8]| {
        v.try_into()
            .map_err(|_| DesktopError::new("storage_unavailable"))
    };
    let mut config = MailboxConfig::new(checked_onion(onion)?, array(fetch)?, array(deposit)?);
    config.envelope_secret = array(envelope)?;
    Ok(config)
}
fn checked_onion(value: &str) -> Result<String> {
    let label = value.strip_suffix(".onion").unwrap_or(value);
    if label.len() != 56
        || !label
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7'))
    {
        return Err(DesktopError::new("invalid_mailbox"));
    }
    Ok(label.into())
}
fn checked_name(name: &str) -> Result<()> {
    if name.trim().is_empty() || name.len() > 128 || name.chars().any(char::is_control) {
        return Err(DesktopError::new("invalid_name"));
    }
    Ok(())
}
fn positive_id(value: &str) -> Result<i64> {
    if value.len() > 19 || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(DesktopError::new("invalid_request"));
    }
    value
        .parse::<i64>()
        .ok()
        .filter(|id| *id > 0)
        .ok_or_else(|| DesktopError::new("invalid_request"))
}
fn status_name(value: najwa_storage::types::MessageStatus) -> &'static str {
    use najwa_storage::types::MessageStatus::*;
    match value {
        Pending => "queued",
        Sent => "deposited",
        Delivered => "delivered",
        Read => "read",
        Failed => "retrying",
        PermanentlyFailed => "failed",
    }
}

#[cfg(test)]
#[path = "desktop_tests.rs"]
mod tests;
