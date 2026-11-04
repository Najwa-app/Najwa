//! Thin global application state (S17 §4.1 lifecycle backing).
//!
//! Deliberately small: the thin ABI's lifecycle is init → (create | unlock) →
//! operate → lock/cancel. Every key-holding field is `Option` and taken
//! (zeroized or dropped) on lock, AFTER the §4.1 drain: reject entry →
//! cancel in-flight (deadline ≥ 2 s) → quiesce callbacks → zeroize.

use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex, OnceLock, RwLock};

use najwa_crypto::memory::GuardedMemory;
use najwa_identity::manager::IdentityManager;
use najwa_identity::record::Identity;
use najwa_storage::database::SqliteStorage;

use crate::error::FfiErrorCode;

/// The database key in locked memory (S01 §6.2). Storage handles share it.
pub(crate) type DbKey = Arc<GuardedMemory<[u8; 32]>>;

/// The concrete service the thin ABI drives (generic-free by design — the C
/// ABI has no generics to hide).
pub(crate) type FfiService = najwa_core::service::MessagingService<
    SqliteStorage,
    najwa_protocol::mailbox::http::HttpMailboxClient,
>;

pub(crate) struct AppState {
    pub data_dir: PathBuf,
    /// The multi-thread runtime all async core work runs on (§5.5: core work
    /// never happens on the callback thread).
    pub runtime: tokio::runtime::Runtime,
    pub identity_manager: Option<IdentityManager>,
    /// Unlocked identity keys — TAKEN on lock. Shares the identity manager's
    /// guarded key (S01 §6.2).
    pub identity: Option<Identity>,
    /// Database key, the one copy every storage handle shares — TAKEN on lock.
    pub db_key: Option<DbKey>,
    pub storage: Option<Arc<SqliteStorage>>,
    /// Present once the transport bootstrap has succeeded; `send`/`poll`
    /// return the not-connected error while absent.
    pub service: Arc<Mutex<Option<Arc<FfiService>>>>,
    /// A transport bootstrap is in flight (no double-spawn on re-unlock).
    pub bootstrapping: bool,
    pub lifecycle_generation: u64,
    pub cover: Option<crate::cover::CoverRuntime>,
    /// Available immediately on unlock, including while Tor is offline.
    pub disappearing_keys: najwa_core::disappearing::VolatileKeyCache,
    pub disappearing_cleanup: Option<tokio::task::JoinHandle<()>>,
    /// Battery level reported by `najwa_update_battery` (S17 §4.3). The value
    /// is stored; no feature reads it.
    pub battery_level: i32,
    pub battery_charging: bool,
}

impl AppState {
    pub fn new(data_dir: PathBuf) -> Result<Self, FfiErrorCode> {
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|_| FfiErrorCode::InternalError)?;
        Ok(Self {
            data_dir,
            runtime,
            identity_manager: None,
            identity: None,
            db_key: None,
            storage: None,
            service: Arc::new(Mutex::new(None)),
            bootstrapping: false,
            lifecycle_generation: 0,
            cover: None,
            disappearing_keys: Default::default(),
            disappearing_cleanup: None,
            battery_level: 100,
            battery_charging: true,
        })
    }

    /// Called only after the operation drain and callback quiescence. Cover
    /// retains only its transport and cover coordinates, never these keys.
    pub fn clear_unlocked(&mut self) -> Result<(), FfiErrorCode> {
        self.stop_disappearing_cleanup();
        if let (Some(storage), Some(db_key)) = (&self.storage, &self.db_key) {
            // The operation drain already stopped send/receive; also join the
            // cleaner before taking the snapshot so no key can race persistence.
            let persisted = (|| {
                self.runtime.block_on(crate::disappearing::cleanup(
                    storage.clone(), self.disappearing_keys.clone(),
                ))?;
                storage.replace_volatile_keys(
                    &self.disappearing_keys.persist_all(db_key), najwa_crypto::time::now_ms(),
                ).map_err(|_| FfiErrorCode::StorageError)?;
                storage.wal_checkpoint().map_err(|_| FfiErrorCode::StorageError)
            })();
            if let Err(error) = persisted {
                // A failed lock retains live keys for retry, but expiry must
                // keep running even while key-using ABI operations are gated.
                self.disappearing_cleanup = Some(crate::disappearing::start_cleanup(
                    &self.runtime, storage, self.disappearing_keys.clone(),
                    std::time::Duration::from_secs(najwa_core::disappearing::DEFAULT_CLEANUP_INTERVAL_SECS),
                    crate::disappearing::RETENTION_INTERVAL,
                ));
                return Err(error);
            }
        }
        self.disappearing_keys.zeroize_all();
        if let (Some(cover), Some(storage)) = (&mut self.cover, &self.storage) {
            cover.refresh(storage);
        }
        self.lifecycle_generation += 1;
        self.db_key = None;
        self.identity = None;
        self.storage = None;
        *self.service.lock().unwrap() = None;
        self.bootstrapping = false;
        if let Some(mut manager) = self.identity_manager.take() {
            manager.lock();
        }
        Ok(())
    }

    /// Restore and clean before publishing storage, rendering, or bootstrap.
    pub fn prepare_disappearing(&mut self, storage: &Arc<SqliteStorage>, db_key: &[u8; 32]) -> Result<(), FfiErrorCode> {
        self.stop_disappearing_cleanup();
        let entries = storage.take_live_volatile_keys(najwa_crypto::time::now_ms())
            .map_err(|_| FfiErrorCode::StorageError)?;
        self.disappearing_keys.restore_all(db_key, &entries);
        self.runtime.block_on(crate::disappearing::cleanup(storage.clone(), self.disappearing_keys.clone()))?;
        self.disappearing_cleanup = Some(crate::disappearing::start_cleanup(
            &self.runtime, storage, self.disappearing_keys.clone(),
            std::time::Duration::from_secs(najwa_core::disappearing::DEFAULT_CLEANUP_INTERVAL_SECS),
            crate::disappearing::RETENTION_INTERVAL,
        ));
        Ok(())
    }

    fn stop_disappearing_cleanup(&mut self) {
        if let Some(task) = self.disappearing_cleanup.take() {
            task.abort();
            let _ = self.runtime.block_on(task);
        }
    }

    pub fn identity_path(&self) -> PathBuf {
        self.data_dir.join("identity.najwa")
    }
}

static STATE: OnceLock<RwLock<Option<AppState>>> = OnceLock::new();

pub(crate) fn state_cell() -> &'static RwLock<Option<AppState>> {
    STATE.get_or_init(|| RwLock::new(None))
}

// ---------------------------------------------------------------------------
// §4.1 operation gating: `najwa_lock` MUST reject entry, drain, then zeroize.
// ---------------------------------------------------------------------------

pub(crate) static LIFECYCLE: Mutex<()> = Mutex::new(());

struct Operations {
    allowed: bool,
    in_flight: usize,
    cancel: tokio::sync::watch::Sender<bool>,
}

struct OperationGate {
    operations: Mutex<Operations>,
    drained: Condvar,
}

impl OperationGate {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            operations: Mutex::new(Operations {
                allowed: true,
                in_flight: 0,
                cancel: tokio::sync::watch::channel(false).0,
            }),
            drained: Condvar::new(),
        })
    }

    fn acquire(self: &Arc<Self>) -> Option<OperationGuard> {
        let mut operations = self.operations.lock().unwrap();
        if !operations.allowed {
            return None;
        }
        operations.in_flight += 1;
        Some(OperationGuard {
            gate: self.clone(),
            cancelled: operations.cancel.subscribe(),
        })
    }

    fn cancel(&self, deadline_ms: i32) -> bool {
        let mut operations = self.operations.lock().unwrap();
        // Admission and the drain snapshot share the same lock: there is no
        // window in which a caller can enter after we observe zero operations.
        operations.allowed = false;
        operations.cancel.send_replace(true);
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_millis(deadline_ms.max(0) as u64);
        while operations.in_flight != 0 {
            let Some(remaining) = deadline.checked_duration_since(std::time::Instant::now()) else {
                return false;
            };
            operations = self.drained.wait_timeout(operations, remaining).unwrap().0;
        }
        true
    }

    fn allow(&self) -> bool {
        let mut operations = self.operations.lock().unwrap();
        if operations.in_flight != 0 {
            return false;
        }
        operations.cancel = tokio::sync::watch::channel(false).0;
        operations.allowed = true;
        true
    }
}

fn operation_gate() -> &'static Arc<OperationGate> {
    static GATE: OnceLock<Arc<OperationGate>> = OnceLock::new();
    GATE.get_or_init(OperationGate::new)
}

/// Acquire permission for one key-using operation. Fails once
/// `najwa_lock`/`najwa_cancel_operations` has begun draining.
pub(crate) struct OperationGuard {
    gate: Arc<OperationGate>,
    cancelled: tokio::sync::watch::Receiver<bool>,
}

impl OperationGuard {
    pub(crate) fn is_cancelled(&self)->bool {*self.cancelled.borrow()}
    pub(crate) fn acquire() -> Option<Self> {
        operation_gate().acquire()
    }

    pub(crate) async fn cancellable<F: std::future::Future>(
        &mut self,
        operation: F,
    ) -> Result<F::Output, FfiErrorCode> {
        tokio::select! {
            biased;
            _ = self.cancelled.wait_for(|cancelled| *cancelled) => Err(FfiErrorCode::InternalError),
            result = operation => Ok(result),
        }
    }
}

impl Drop for OperationGuard {
    fn drop(&mut self) {
        let mut operations = self.gate.operations.lock().unwrap();
        operations.in_flight -= 1;
        self.gate.drained.notify_all();
    }
}

/// `najwa_cancel_operations`: refuse new operations, wait for in-flight ones
/// to drain (bounded by the deadline). Returns true when drained.
pub(crate) fn cancel_operations(deadline_ms: i32) -> bool {
    operation_gate().cancel(deadline_ms)
}

/// Re-allow operations (unlock path).
pub(crate) fn allow_operations() -> bool {
    operation_gate().allow()
}

/// S17 §4.1 `najwa_lock` step 1: drain with the implementation-chosen deadline
/// of 5 s (spec floor: ≥ 2 s).
pub(crate) const LOCK_DRAIN_DEADLINE_MS: i32 = 5_000;

/// Open (or create) the encrypted database for the unlocked identity.
pub(crate) fn open_storage(
    data_dir: &std::path::Path,
    db_key: &DbKey,
) -> Result<Arc<SqliteStorage>, FfiErrorCode> {
    let storage =
        SqliteStorage::open_shared(&data_dir.join("najwa.db"), db_key.clone())
            .map_err(|_| FfiErrorCode::StorageError)?;
    Ok(Arc::new(storage))
}

/// A test database key in its own locked region.
#[cfg(test)]
pub(crate) fn test_key(byte: u8) -> DbKey {
    Arc::new(GuardedMemory::new([byte; 32]))
}

#[cfg(test)]
mod row14_tests {
    use super::*;

    #[test]
    fn cancellation_wakes_pending_async_operation_and_reopens_cleanly() {
        let gate = OperationGate::new();
        let mut guard = gate.acquire().unwrap();
        let cancelled = gate.clone();
        let worker = std::thread::spawn(move || cancelled.cancel(2000));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        assert!(runtime
            .block_on(guard.cancellable(std::future::pending::<()>()))
            .is_err());
        assert!(!gate.allow(), "cannot reopen with a live guard");
        assert!(gate.acquire().is_none());
        drop(guard);
        assert!(worker.join().unwrap());
        assert!(gate.allow());
        let mut next = gate.acquire().unwrap();
        assert_eq!(
            runtime.block_on(next.cancellable(async { 42 })).unwrap(),
            42
        );
    }

    #[test]
    fn deadline_does_not_claim_live_operations_have_stopped() {
        let gate = OperationGate::new();
        let guard = gate.acquire().unwrap();
        assert!(!gate.cancel(0));
        assert!(!gate.allow());
        assert!(gate.acquire().is_none());
        drop(guard);
        assert!(gate.cancel(0));
    }

    #[test]
    fn admission_and_drain_are_atomic_under_contention() {
        for _ in 0..100 {
            let gate = OperationGate::new();
            let barrier = Arc::new(std::sync::Barrier::new(9));
            let workers: Vec<_> = (0..8)
                .map(|_| {
                    let gate = gate.clone();
                    let barrier = barrier.clone();
                    std::thread::spawn(move || {
                        barrier.wait();
                        drop(gate.acquire());
                    })
                })
                .collect();
            barrier.wait();
            assert!(gate.cancel(2000));
            assert!(gate.acquire().is_none());
            assert_eq!(gate.operations.lock().unwrap().in_flight, 0);
            for worker in workers {
                worker.join().unwrap();
            }
        }
    }
}
