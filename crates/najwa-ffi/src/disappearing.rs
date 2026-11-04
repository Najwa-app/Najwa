//! Desktop S12 lifecycle. The cleaner runs independently of Tor availability.
use crate::error::FfiErrorCode;
use najwa_core::disappearing::{
    DisappearingCleanupTask, DisappearingMessageManager, VolatileKeyCache,
};
use najwa_storage::database::SqliteStorage;
use std::sync::Arc;
use std::time::Duration;

pub(crate) async fn cleanup(
    storage: Arc<SqliteStorage>,
    cache: VolatileKeyCache,
) -> Result<(), FfiErrorCode> {
    DisappearingCleanupTask::with_default_interval(
        Arc::new(DisappearingMessageManager::new(storage)),
        cache,
    )
    .run_once()
    .await
    .map_err(|_| FfiErrorCode::StorageError)
}

/// Period of the storage retention pass (S03 §6.4) run by the cleaner.
pub(crate) const RETENTION_INTERVAL: Duration = Duration::from_secs(3600);

/// The cleaner lives only between unlock and lock, so the retention pass that
/// rides on it (first tick after unlock, then every `retention`) does too.
pub(crate) fn start_cleanup(
    runtime: &tokio::runtime::Runtime,
    storage: &Arc<SqliteStorage>,
    cache: VolatileKeyCache,
    interval: Duration,
    retention: Duration,
) -> tokio::task::JoinHandle<()> {
    let storage = Arc::downgrade(storage);
    runtime.spawn(async move {
        let mut retained: Option<std::time::Instant> = None;
        loop {
            tokio::time::sleep(interval).await;
            let Some(storage) = storage.upgrade() else {
                break;
            };
            if let Err(error) = cleanup(storage.clone(), cache.clone()).await {
                tracing::error!(?error, "disappearing cleanup failed");
            }
            if retained.is_none_or(|at| at.elapsed() >= retention) {
                retained = Some(std::time::Instant::now());
                if let Err(error) = storage.run_retention_cleanup() {
                    tracing::error!(?error, "storage retention cleanup failed");
                }
            }
        }
    })
}

/// Produce the same messages the ABI renders; only successfully opened rows
/// count as displayed. An expired row cannot be revived between cleanup ticks.
pub(crate) fn displayed_messages(
    storage: &SqliteStorage,
    cache: &VolatileKeyCache,
    contact_id: i64,
) -> Result<Vec<najwa_storage::types::Message>, FfiErrorCode> {
    let displayed = fetched_messages(storage, cache, contact_id)?;
    storage
        .mark_displayed_messages(
            contact_id,
            &displayed.iter().map(|m| m.id).collect::<Vec<_>>(),
        )
        .map_err(|_| FfiErrorCode::StorageError)?;
    Ok(displayed)
}

/// Open a page without marking it read or starting timers. The desktop must
/// acknowledge only the specific rows that became visible after rendering.
/// Expiry remains enforced even between background cleanup ticks.
pub(crate) fn fetched_messages(
    storage: &SqliteStorage,
    cache: &VolatileKeyCache,
    contact_id: i64,
) -> Result<Vec<najwa_storage::types::Message>, FfiErrorCode> {
    use najwa_core::disappearing::{open_sealed_content, Opened};
    let messages = storage
        .list_messages(contact_id, 200, None)
        .map_err(|_| FfiErrorCode::StorageError)?;
    let mut displayed = Vec::new();
    for mut message in messages {
        let now = najwa_crypto::time::now_ms();
        if message.disappear_at.is_some_and(|at| at <= now) {
            cache.remove_key(&message.msg_id);
            continue;
        }
        if message.disappear_timer.is_some() {
            match open_sealed_content(cache, &message.msg_id, &message.content)
                .map_err(|_| FfiErrorCode::CryptoError)?
            {
                Opened::Plaintext(content) => message.content = content,
                Opened::Expired => continue,
            }
        }
        displayed.push(message);
    }
    Ok(displayed)
}
