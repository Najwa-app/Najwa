//! Database layer — SQLite storage engine for the mailbox server.

pub mod models;
pub mod schema;

use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use self::models::*;
use crate::config::Config;

/// Thread-safe database handle.
///
/// SQLite in WAL mode allows concurrent reads, but writes are serialized.
/// We wrap the connection in a `Mutex` for write safety; a production deployment
/// could use a connection pool (e.g. `r2d2`) for read scaling.
pub struct Database {
    conn: Mutex<Connection>,
}

/// Outcome of an atomic quota-checked deposit ([`Database::deposit_message_checked`]).
pub enum DepositOutcome {
    Stored(String),
    Dropped,
    BlobTooLarge,
    MessageQuotaExceeded,
    StorageQuotaExceeded,
}

#[derive(Debug, thiserror::Error)]
pub enum PrekeyUploadError {
    #[error("prekey ID reused with different key material")]
    Conflict,
    #[error("OPK quota exceeded")]
    Quota,
    #[error("capability is inactive")]
    Inactive,
    #[error(transparent)]
    Database(#[from] rusqlite::Error),
}

/// Cached type-1 prekey-fetch result (S16 §3.7), stored JSON-encoded in
/// `capabilities.prekey_fetch_cache` so repeat fetches on an ephemeral capability
/// return byte-identically and consume no further OPK.
#[derive(serde::Serialize, serde::Deserialize)]
struct PrekeyFetchCacheEntry {
    bundle_json: String,
    opk: Option<(u32, [u8; 32])>,
}

impl Database {
    /// Open (or create) the database and run migrations.
    pub fn open(config: &Config) -> anyhow::Result<Self> {
        let conn = Connection::open(&config.server.database_path)?;
        Self::apply_pragmas(&conn)?;
        schema::ensure(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Open an in-memory database (tests and harnesses).
    pub fn open_in_memory() -> anyhow::Result<Self> {
        let conn = Connection::open_in_memory()?;
        Self::apply_pragmas(&conn)?;
        schema::ensure(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Per-connection PRAGMAs. `synchronous`, `temp_store`, and `foreign_keys` are
    /// PER-CONNECTION and reset to SQLite defaults on every `open`, so they MUST be
    /// re-asserted here — `initialize()` only runs on a fresh DB, so on a normal
    /// restart the live connection would otherwise silently fall back to defaults:
    /// `synchronous=NORMAL` under WAL breaks the §3.3/§12 deposit-durability promise
    /// (no fsync per commit), `foreign_keys=OFF` drops referential integrity, and
    /// `temp_store=FILE` leaks temp data to disk. `journal_mode=WAL`/`secure_delete`
    /// persist in the DB header but re-assert cheaply. (S16 §12.)
    fn apply_pragmas(conn: &Connection) -> rusqlite::Result<()> {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             PRAGMA secure_delete = ON;
             PRAGMA temp_store = MEMORY;
             PRAGMA foreign_keys = ON;",
        )
    }

    // -----------------------------------------------------------------------
    // Capabilities
    // -----------------------------------------------------------------------

    /// Register a new capability pair.
    /// Returns `Ok(RegisterResult::Created)` on success,
    /// `Ok(RegisterResult::AlreadyExists)` for idempotent re-registration (S16 §3.1),
    /// `Ok(RegisterResult::Conflict)` if tokens are already used in a different mapping.
    // The registration tuple (both caps, settings, type, expiry, clamp, now)
    // is one coherent unit; a params struct would add indirection with a
    // single caller.
    #[allow(clippy::too_many_arguments)]
    pub fn register_capability(
        &self,
        fetch_cap: &[u8; 32],
        deposit_cap: &[u8; 32],
        settings: &CapabilitySettings,
        capability_type: u8,
        expires_at: Option<i64>,
        ephemeral_max_lifetime_secs: i64,
        now: i64,
    ) -> rusqlite::Result<RegisterResult> {
        let mut guard = self.conn.lock().unwrap();
        let conn = guard.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let settings_json = serde_json::to_string(settings).unwrap();

        // Check if fetch_cap already exists
        let fetch_exists: bool = conn
            .query_row(
                "SELECT 1 FROM capabilities WHERE fetch_cap = ?1",
                params![fetch_cap.as_slice()],
                |_| Ok(true),
            )
            .optional()?
            .unwrap_or(false);

        // Check if deposit_cap already exists
        let deposit_linked_fetch: Option<Vec<u8>> = conn
            .query_row(
                "SELECT fetch_cap FROM deposit_caps WHERE deposit_cap = ?1",
                params![deposit_cap.as_slice()],
                |row| row.get(0),
            )
            .optional()?;

        // Idempotent re-registration (S16 §3.1): if exact same pair already registered, return OK
        if fetch_exists {
            if let Some(ref linked) = deposit_linked_fetch {
                if linked.as_slice() == fetch_cap.as_slice() {
                    return Ok(RegisterResult::AlreadyExists);
                }
            }
            // fetch_cap exists but deposit_cap maps to different fetch, or deposit not linked
            return Ok(RegisterResult::Conflict);
        }

        if deposit_linked_fetch.is_some() {
            // deposit_cap is already linked to a different fetch_cap
            return Ok(RegisterResult::Conflict);
        }

        // S16 §3.1 expiry clamp: type-1 (ephemeral handshake / rendezvous) caps ALWAYS
        // have a bounded lifetime — clamp expires_at to created_at +
        // `[capability_expiry].ephemeral_max_lifetime_hours` (spec default 48 h) and
        // default-assign it when omitted, closing the photographed-QR window. Type-2
        // (long-term) expires_at is optional and unclamped (relies on the 30-day
        // inactivity expiry otherwise).
        let effective_expires_at: Option<i64> = if capability_type == 1 {
            let cap = now + ephemeral_max_lifetime_secs;
            Some(expires_at.map(|e| e.min(cap)).unwrap_or(cap))
        } else {
            expires_at
        };

        conn.execute(
            "INSERT INTO capabilities (fetch_cap, settings_json, created_at, last_active_at, capability_type, expires_at) VALUES (?1, ?2, ?3, ?3, ?4, ?5)",
            params![fetch_cap.as_slice(), settings_json, now, capability_type as i64, effective_expires_at],
        )?;
        conn.execute(
            "INSERT INTO deposit_caps (deposit_cap, fetch_cap, created_at) VALUES (?1, ?2, ?3)",
            params![deposit_cap.as_slice(), fetch_cap.as_slice(), now],
        )?;
        conn.commit()?;
        Ok(RegisterResult::Created)
    }

    /// Look up the fetch_cap associated with a deposit_cap (active capabilities only).
    #[allow(dead_code)] // callers now prefer lookup_deposit_cap_state for 404/410 distinction
    pub fn lookup_fetch_cap(&self, deposit_cap: &[u8; 32]) -> rusqlite::Result<Option<[u8; 32]>> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT d.fetch_cap FROM deposit_caps d
             JOIN capabilities c ON c.fetch_cap = d.fetch_cap
             WHERE d.deposit_cap = ?1 AND c.deactivated = 0",
            params![deposit_cap.as_slice()],
            |row| {
                let blob: Vec<u8> = row.get(0)?;
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&blob);
                Ok(arr)
            },
        )
        .optional()
    }

    /// Look up a deposit_cap. Prekey endpoints use the result to answer 404/410;
    /// the deposit path silently discards on inactive or unknown (S16 §3.3).
    /// Returns `(fetch_cap, inactive, capability_type)` for a deposit cap.
    /// `inactive` folds deactivated + expired (S16 §3.1) so the deposit path can
    /// silent-drop; `capability_type` (1=ephemeral, 2=long-term) selects the
    /// reduced quota (§9) and the always-on PoW floor (§7.2) on the deposit path.
    pub fn lookup_deposit_cap_state(
        &self,
        deposit_cap: &[u8; 32],
    ) -> rusqlite::Result<Option<([u8; 32], bool, u8)>> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().timestamp();
        conn.query_row(
            "SELECT d.fetch_cap, c.deactivated, c.expires_at, c.capability_type FROM deposit_caps d
             JOIN capabilities c ON c.fetch_cap = d.fetch_cap
             WHERE d.deposit_cap = ?1",
            params![deposit_cap.as_slice()],
            |row| {
                let blob: Vec<u8> = row.get(0)?;
                let deactivated: i64 = row.get(1)?;
                let expires_at: Option<i64> = row.get(2)?;
                let capability_type: i64 = row.get(3)?;
                // Expired caps count as inactive (S16 §3.1) → deposit silent-drops.
                let expired = expires_at.map(|e| e <= now).unwrap_or(false);
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&blob);
                Ok((arr, deactivated != 0 || expired, capability_type as u8))
            },
        )
        .optional()
    }

    /// Check if a capability is deactivated.
    #[allow(dead_code)] // callers now prefer capability_state for 404/410 distinction
    pub fn is_deactivated(&self, fetch_cap: &[u8; 32]) -> rusqlite::Result<bool> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT deactivated FROM capabilities WHERE fetch_cap = ?1",
            params![fetch_cap.as_slice()],
            |row| {
                let val: i64 = row.get(0)?;
                Ok(val != 0)
            },
        )
        .optional()
        .map(|opt| opt.unwrap_or(true)) // not found = treat as deactivated
    }

    /// Check the state of a capability: exists + active, exists + deactivated, or not found.
    pub fn capability_state(&self, fetch_cap: &[u8; 32]) -> rusqlite::Result<CapabilityState> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().timestamp();
        let row: Option<(i64, Option<i64>)> = conn
            .query_row(
                "SELECT deactivated, expires_at FROM capabilities WHERE fetch_cap = ?1",
                params![fetch_cap.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        match row {
            Some((0, expires_at)) => {
                // S16 §3.1: an expired capability is treated like a deactivated one on
                // owner-facing endpoints (→ 410).
                if expires_at.map(|e| e <= now).unwrap_or(false) {
                    Ok(CapabilityState::Deactivated)
                } else {
                    Ok(CapabilityState::Active)
                }
            }
            Some(_) => Ok(CapabilityState::Deactivated),
            None => Ok(CapabilityState::NotFound),
        }
    }

    /// Read a capability's `(capability_type, expires_at)` — test/harness
    /// accessor for the §3.1 registration clamps.
    pub fn capability_type_and_expiry(
        &self,
        fetch_cap: &[u8; 32],
    ) -> rusqlite::Result<Option<(u8, Option<i64>)>> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT capability_type, expires_at FROM capabilities WHERE fetch_cap = ?1",
            params![fetch_cap.as_slice()],
            |row| {
                let t: i64 = row.get(0)?;
                Ok((t as u8, row.get(1)?))
            },
        )
        .optional()
    }

    /// Deactivate a capability (irreversible, S16 §3.9). Deletes messages, the prekey bundle and available OPKs.
    /// Returns the number of messages deleted, or None if the capability was not found/already deactivated.
    pub fn deactivate_capability(&self, fetch_cap: &[u8; 32]) -> rusqlite::Result<Option<u64>> {
        let mut guard = self.conn.lock().unwrap();
        let conn = guard.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = chrono::Utc::now().timestamp();
        // Stamp deactivated_at so the 24h grace sweep (S16 §10) is measured from
        // deactivation, not registration.
        let updated = conn.execute(
            "UPDATE capabilities SET deactivated = 1, deactivated_at = ?2 WHERE fetch_cap = ?1 AND deactivated = 0",
            params![fetch_cap.as_slice(), now],
        )?;
        if updated == 0 {
            // Distinguish not-found from already-deactivated: S16 §3.9 deactivation
            // is IDEMPOTENT — re-deactivating an already-deactivated cap returns
            // `200 {messages_deleted:0}`, not 404. Only a truly unknown cap is None.
            let exists: bool = conn
                .query_row(
                    "SELECT 1 FROM capabilities WHERE fetch_cap = ?1",
                    params![fetch_cap.as_slice()],
                    |_| Ok(true),
                )
                .optional()?
                .unwrap_or(false);
            return Ok(if exists { Some(0) } else { None });
        }
        let messages_deleted = conn.execute(
            "DELETE FROM messages WHERE fetch_cap = ?1",
            params![fetch_cap.as_slice()],
        )? as u64;
        conn.execute(
            "DELETE FROM prekey_bundles WHERE fetch_cap = ?1",
            params![fetch_cap.as_slice()],
        )?;
        conn.execute(
            "DELETE FROM one_time_prekeys WHERE fetch_cap = ?1",
            params![fetch_cap.as_slice()],
        )?;
        conn.commit()?;
        Ok(Some(messages_deleted))
    }

    /// Get capability status (message count, storage, prekey count).
    pub fn capability_status(
        &self,
        fetch_cap: &[u8; 32],
    ) -> rusqlite::Result<Option<CapabilityStatus>> {
        let conn = self.conn.lock().unwrap();

        let exists: bool = conn
            .query_row(
                "SELECT 1 FROM capabilities WHERE fetch_cap = ?1 AND deactivated = 0 AND (expires_at IS NULL OR expires_at > unixepoch())",
                params![fetch_cap.as_slice()],
                |_| Ok(true),
            )
            .optional()?
            .unwrap_or(false);

        if !exists {
            return Ok(None);
        }

        let message_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM messages WHERE fetch_cap = ?1",
            params![fetch_cap.as_slice()],
            |row| row.get(0),
        )?;

        let _storage_bytes: i64 = conn.query_row(
            "SELECT COALESCE(SUM(size), 0) FROM messages WHERE fetch_cap = ?1",
            params![fetch_cap.as_slice()],
            |row| row.get(0),
        )?;

        let prekey_ids = conn
            .prepare(
                "SELECT prekey_id FROM one_time_prekeys WHERE fetch_cap = ?1 ORDER BY prekey_id",
            )?
            .query_map(params![fetch_cap.as_slice()], |row| row.get::<_, u32>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let prekey_count = prekey_ids.len() as u32;

        let oldest_message_age: i64 = conn.query_row(
            "SELECT COALESCE(MIN(deposited_at), 0) FROM messages WHERE fetch_cap = ?1",
            params![fetch_cap.as_slice()],
            |row| row.get(0),
        )?;

        let now = chrono::Utc::now().timestamp();
        let oldest_age_secs = if oldest_message_age > 0 {
            (now - oldest_message_age).max(0) as u64
        } else {
            0
        };

        // Read quota from settings
        let (settings_json, capability_type): (String, u8) = conn.query_row(
            "SELECT settings_json, capability_type FROM capabilities WHERE fetch_cap = ?1",
            params![fetch_cap.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let settings: CapabilitySettings =
            serde_json::from_str(&settings_json).unwrap_or(CapabilitySettings {
                retention_days: 14,
                max_message_size: 262_144,
            });

        Ok(Some(CapabilityStatus {
            messages_stored: message_count as u64,
            quota_remaining: 1000u64.saturating_sub(message_count as u64), // will be overridden by caller with actual config
            oldest_message_age: oldest_age_secs,
            prekey_count,
            prekey_ids,
            retention_days: settings.retention_days,
            capability_type,
        }))
    }

    // -----------------------------------------------------------------------
    // Messages
    // -----------------------------------------------------------------------

    /// Deposit a message blob with its computed release time (S16 §6).
    /// `deposit_cap` is stored for cap_hint computation in fetch responses.
    /// Returns the assigned message ID.
    pub fn deposit_message(
        &self,
        fetch_cap: &[u8; 32],
        deposit_cap: &[u8; 32],
        blob: &[u8],
        now: i64,
        batching_config: &crate::config::BatchingConfig,
    ) -> rusqlite::Result<String> {
        let mut guard = self.conn.lock().unwrap();
        let conn = guard.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let id = Self::do_deposit(&conn, fetch_cap, deposit_cap, blob, now, batching_config)?;
        conn.commit()?;
        Ok(id)
    }

    /// Atomic quota-checked deposit. The message-count and storage-byte quotas are
    /// evaluated and the row inserted in one IMMEDIATE transaction, so concurrent
    /// deposits at the ceiling can no longer each observe room and all insert (the
    /// former `deposit.rs` check-then-insert TOCTOU). A deduplicated re-deposit is
    /// never rejected — it stores nothing new, so it is quota-exempt (checked first).
    // The deposit composite (dedup key + quotas + insert parameters) is one
    // coherent operation; splitting it into a params struct adds indirection
    // without a second caller.
    #[allow(clippy::too_many_arguments)]
    pub fn deposit_message_checked(
        &self,
        fetch_cap: &[u8; 32],
        deposit_cap: &[u8; 32],
        blob: &[u8],
        now: i64,
        batching_config: &crate::config::BatchingConfig,
        max_messages: u64,
        max_storage_bytes: u64,
    ) -> rusqlite::Result<DepositOutcome> {
        let mut guard = self.conn.lock().unwrap();
        let conn = guard.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let row: Option<(String, bool)> = conn.query_row(
            "SELECT c.settings_json, c.deactivated=0 AND (c.expires_at IS NULL OR c.expires_at>?3)
             FROM capabilities c JOIN deposit_caps d ON c.fetch_cap=d.fetch_cap
             WHERE c.fetch_cap=?1 AND d.deposit_cap=?2",
            params![fetch_cap.as_slice(), deposit_cap.as_slice(), now],
            |r| Ok((r.get(0)?, r.get(1)?)),
        ).optional()?;
        let Some((settings, active)) = row else {
            return Ok(DepositOutcome::Dropped);
        };
        let settings: CapabilitySettings = serde_json::from_str(&settings)
            .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
        // S16 §3.3 step 4: the registered size limit applies to a deactivated or
        // expired row too (its settings are still stored), so an oversized blob
        // gets the same 413 whether or not the queue is live.
        if blob.len() > settings.max_message_size {
            return Ok(DepositOutcome::BlobTooLarge);
        }

        // Dedup FIRST (S16 §3.3 step 4): a duplicate returns the original id and
        // stores nothing, so it must bypass the quota (it never grows the mailbox).
        // It runs before the inactive drop, so a blob deposited while the queue
        // was live keeps its id after deactivation, exactly as a live queue would.
        let blob_hash: [u8; 32] = {
            use sha2::{Digest, Sha256};
            Sha256::digest(blob).into()
        };
        if let Some(existing_id) = conn
            .query_row(
                "SELECT message_id FROM deposit_dedup
                 WHERE deposit_cap = ?1 AND blob_hash = ?2 AND expires_at > ?3",
                params![deposit_cap.as_slice(), blob_hash.as_slice(), now],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            return Ok(DepositOutcome::Stored(existing_id));
        }
        if !active {
            return Ok(DepositOutcome::Dropped);
        }

        // S16 §3.3 step 5 — quotas, under the same lock as the insert below.
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM messages WHERE fetch_cap = ?1",
            params![fetch_cap.as_slice()],
            |row| row.get(0),
        )?;
        if count as u64 >= max_messages {
            return Ok(DepositOutcome::MessageQuotaExceeded);
        }
        let used: i64 = conn.query_row(
            "SELECT COALESCE(SUM(size), 0) FROM messages WHERE fetch_cap = ?1",
            params![fetch_cap.as_slice()],
            |row| row.get(0),
        )?;
        if used as u64 + blob.len() as u64 > max_storage_bytes {
            return Ok(DepositOutcome::StorageQuotaExceeded);
        }

        let id = Self::do_deposit(&conn, fetch_cap, deposit_cap, blob, now, batching_config)?;
        conn.commit()?;
        Ok(DepositOutcome::Stored(id))
    }

    /// Dedup + insert, run against an already-held connection so callers can compose
    /// it atomically with quota checks. (The dedup SELECT here is redundant when
    /// called from `deposit_message_checked`, which already checked — one cheap
    /// indexed lookup under the same lock — but keeps `deposit_message` a one-liner.)
    fn do_deposit(
        conn: &Connection,
        fetch_cap: &[u8; 32],
        deposit_cap: &[u8; 32],
        blob: &[u8],
        now: i64,
        batching_config: &crate::config::BatchingConfig,
    ) -> rusqlite::Result<String> {
        // S16 §3.3 step 4 — deposit dedup. If this exact (deposit_cap, blob) was
        // deposited within the hold window, return the ORIGINAL message_id without
        // storing again or double-counting quota. Absorbs S08 §5 same-blob transport
        // retries and closes replay-based quota amplification (a duplicate never
        // increases messages_stored).
        let blob_hash: [u8; 32] = {
            use sha2::{Digest, Sha256};
            Sha256::digest(blob).into()
        };
        if let Some(existing_id) = conn
            .query_row(
                "SELECT message_id FROM deposit_dedup
                 WHERE deposit_cap = ?1 AND blob_hash = ?2 AND expires_at > ?3",
                params![deposit_cap.as_slice(), blob_hash.as_slice(), now],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            return Ok(existing_id);
        }

        let msg_id = format!("msg-{}", uuid::Uuid::new_v4());
        let size = blob.len() as i64;

        // Release timing (S16 §6):
        // release_at = deposited_at + random(min_hold, max_hold) + random(0, jitter)
        let hold = if batching_config.max_hold_secs > batching_config.min_hold_secs {
            use rand::Rng;
            let mut rng = rand::thread_rng();
            rng.gen_range(batching_config.min_hold_secs..=batching_config.max_hold_secs)
        } else {
            batching_config.min_hold_secs
        };
        let jitter = if batching_config.jitter_secs > 0 {
            use rand::Rng;
            rand::thread_rng().gen_range(0..=batching_config.jitter_secs)
        } else {
            0
        };
        let release_at = now + hold as i64 + jitter as i64;

        conn.execute(
            "INSERT INTO messages (id, fetch_cap, blob, deposited_at, size, release_at, deposit_cap) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![msg_id, fetch_cap.as_slice(), blob, now, size, release_at, deposit_cap.as_slice()],
        )?;

        // Keep retry idempotency independent of release timing. Immediate
        // delivery must still collapse a retry after a lost HTTP response.
        // REPLACE allows an expired entry to be renewed.
        let dedup_expires = now
            + (batching_config.max_hold_secs as i64 + batching_config.jitter_secs as i64).max(600);
        conn.execute(
            "INSERT OR REPLACE INTO deposit_dedup (deposit_cap, blob_hash, message_id, expires_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                deposit_cap.as_slice(),
                blob_hash.as_slice(),
                msg_id,
                dedup_expires
            ],
        )?;

        // Keep the capability alive so the 30-day inactivity sweep (§10) doesn't reap
        // an actively-used capability.
        conn.execute(
            "UPDATE capabilities SET last_active_at = ?1 WHERE fetch_cap = ?2",
            params![now, fetch_cap.as_slice()],
        )?;

        Ok(msg_id)
    }

    /// Fetch released messages for a capability (S16 §3.4).
    /// Only returns messages where `release_at <= now`. Ordered by release_at ascending.
    /// Each message includes `cap_hint = SHA256(deposit_cap)[0:8]`.
    pub fn fetch_messages(
        &self,
        fetch_cap: &[u8; 32],
        limit: u32,
        now: i64,
    ) -> rusqlite::Result<Vec<MessageRow>> {
        let mut guard = self.conn.lock().unwrap();
        let conn = guard.transaction_with_behavior(TransactionBehavior::Immediate)?;

        // S16 §3.4: NO fetch cursor. Return ALL released (release_at <= now),
        // unacknowledged messages up to `limit`, ordered by release_at. `since_id`
        // is removed — a monotonic cursor over randomized release_at silently skips
        // late-released messages (ratchet desync); /v1/acknowledge is the only cursor.
        let mut stmt = conn.prepare(
            "SELECT id, fetch_cap, blob, deposited_at, size, deposit_cap FROM messages
             WHERE fetch_cap = ?1
               AND (release_at IS NULL OR release_at <= ?2)
             ORDER BY COALESCE(release_at, deposited_at) ASC
             LIMIT ?3",
        )?;

        let rows = stmt.query_map(params![fetch_cap.as_slice(), now, limit], |row| {
            let fetch_blob: Vec<u8> = row.get(1)?;
            let mut fc = [0u8; 32];
            fc.copy_from_slice(&fetch_blob);
            let dep_cap: Option<Vec<u8>> = row.get(5)?;
            let cap_hint = dep_cap.and_then(|dc| {
                if dc.len() >= 32 {
                    use sha2::{Digest, Sha256};
                    let hash = Sha256::digest(&dc);
                    let mut hint = [0u8; 8];
                    hint.copy_from_slice(&hash[..8]);
                    Some(hint)
                } else {
                    None
                }
            });
            Ok(MessageRow {
                id: row.get(0)?,
                fetch_cap: fc,
                blob: row.get(2)?,
                deposited_at: row.get(3)?,
                size: row.get(4)?,
                cap_hint,
            })
        })?;

        // Collect first so the prepared statement's borrow of `conn` is released
        // before the UPDATE below.
        let collected: Vec<MessageRow> = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        drop(stmt);

        // S16 §3.4 step 5 / §9: mark each returned message fetched — this starts the
        // retention_days clock for fetched-but-unacked messages (unfetched messages
        // stay exempt up to the 90-day hard cap). Idempotent: fetched_at is set once,
        // on first return.
        for r in &collected {
            conn.execute(
                "UPDATE messages SET fetched_at = ?1 WHERE id = ?2 AND fetched_at IS NULL",
                params![now, r.id],
            )?;
        }

        // Keep the capability alive (§10 inactivity sweep) on read activity too.
        conn.execute(
            "UPDATE capabilities SET last_active_at = ?1 WHERE fetch_cap = ?2",
            params![now, fetch_cap.as_slice()],
        )?;

        conn.commit()?;
        Ok(collected)
    }

    /// Acknowledge (delete) messages by ID.
    pub fn acknowledge_messages(
        &self,
        fetch_cap: &[u8; 32],
        message_ids: &[String],
    ) -> rusqlite::Result<u32> {
        let mut guard = self.conn.lock().unwrap();
        let conn = guard.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut deleted = 0u32;
        for id in message_ids {
            deleted += conn.execute(
                "DELETE FROM messages WHERE id = ?1 AND fetch_cap = ?2",
                params![id, fetch_cap.as_slice()],
            )? as u32;
        }
        conn.commit()?;
        Ok(deleted)
    }

    /// Count messages for a capability (for quota checks).
    pub fn message_count(&self, fetch_cap: &[u8; 32]) -> rusqlite::Result<u64> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM messages WHERE fetch_cap = ?1",
            params![fetch_cap.as_slice()],
            |row| row.get(0),
        )?;
        Ok(count as u64)
    }

    /// Total storage bytes for a capability.
    pub fn storage_bytes(&self, fetch_cap: &[u8; 32]) -> rusqlite::Result<u64> {
        let conn = self.conn.lock().unwrap();
        let val: i64 = conn.query_row(
            "SELECT COALESCE(SUM(size), 0) FROM messages WHERE fetch_cap = ?1",
            params![fetch_cap.as_slice()],
            |row| row.get(0),
        )?;
        Ok(val as u64)
    }

    // -----------------------------------------------------------------------
    // Prekeys
    // -----------------------------------------------------------------------

    /// Count OPKs currently in pool for a capability.
    pub fn opk_count(&self, fetch_cap: &[u8; 32]) -> rusqlite::Result<u32> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT COUNT(*) FROM one_time_prekeys WHERE fetch_cap = ?1",
            params![fetch_cap.as_slice()],
            |row| row.get(0),
        )
    }

    /// Upload/update a prekey bundle. Replaces signed prekey; appends OPKs (S16 §3.6).
    /// Duplicate IDs are idempotent, including after consumption; different key material is rejected.
    pub fn upload_prekey_bundle(
        &self,
        fetch_cap: &[u8; 32],
        bundle_json: &str,
        opks: &[(u32, [u8; 32])],
        max_opks: u32,
        now: i64,
    ) -> Result<u32, PrekeyUploadError> {
        self.write_prekey_bundle(fetch_cap, bundle_json, opks, max_opks, now, false)
    }

    pub fn replace_prekey_bundle(
        &self,
        fetch_cap: &[u8; 32],
        bundle_json: &str,
        opks: &[(u32, [u8; 32])],
        max_opks: u32,
        now: i64,
    ) -> Result<u32, PrekeyUploadError> {
        self.write_prekey_bundle(fetch_cap, bundle_json, opks, max_opks, now, true)
    }

    fn write_prekey_bundle(
        &self,
        fetch_cap: &[u8; 32],
        bundle_json: &str,
        opks: &[(u32, [u8; 32])],
        max_opks: u32,
        now: i64,
        replace: bool,
    ) -> Result<u32, PrekeyUploadError> {
        let mut guard = self.conn.lock().unwrap();
        let conn = guard.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let active: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM capabilities WHERE fetch_cap=?1 AND deactivated=0
             AND (expires_at IS NULL OR expires_at>?2))",
            params![fetch_cap.as_slice(), now],
            |r| r.get(0),
        )?;
        if !active {
            return Err(PrekeyUploadError::Inactive);
        }
        if replace {
            let kind: u8 = conn.query_row(
                "SELECT capability_type FROM capabilities WHERE fetch_cap=?1",
                [fetch_cap.as_slice()],
                |r| r.get(0),
            )?;
            if kind == 1 {
                return Err(PrekeyUploadError::Inactive);
            }
            // Keep entries repeated in a recovery retry, but remove pre-restore keys.
            // Historical IDs still prevent a consumed key from being resurrected.
            let keep: std::collections::HashSet<u32> = opks.iter().map(|(id, _)| *id).collect();
            let old: Vec<u32> = {
                let mut stmt =
                    conn.prepare("SELECT prekey_id FROM one_time_prekeys WHERE fetch_cap=?1")?;
                let rows = stmt.query_map([fetch_cap.as_slice()], |r| r.get(0))?;
                rows.collect::<rusqlite::Result<_>>()?
            };
            for id in old.into_iter().filter(|id| !keep.contains(id)) {
                conn.execute(
                    "DELETE FROM one_time_prekeys WHERE fetch_cap=?1 AND prekey_id=?2",
                    params![fetch_cap.as_slice(), id],
                )?;
            }
        }
        let mut ids: std::collections::HashSet<u32> = {
            let mut stmt =
                conn.prepare("SELECT prekey_id FROM one_time_prekeys WHERE fetch_cap=?1")?;
            let rows = stmt.query_map(params![fetch_cap.as_slice()], |r| r.get(0))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        let mut fresh = std::collections::BTreeMap::new();
        for (id, key) in opks {
            let previous: Option<Vec<u8>> = conn
                .query_row(
                    "SELECT key_bytes FROM prekey_upload_ids WHERE fetch_cap=?1 AND prekey_id=?2",
                    params![fetch_cap.as_slice(), id],
                    |r| r.get(0),
                )
                .optional()?;
            if let Some(previous) = previous {
                if previous != key.as_slice() {
                    return Err(PrekeyUploadError::Conflict);
                }
            } else if fresh.insert(*id, *key).is_some_and(|prior| prior != *key) {
                return Err(PrekeyUploadError::Conflict);
            }
        }
        ids.extend(fresh.keys());
        if ids.len() > max_opks as usize {
            return Err(PrekeyUploadError::Quota);
        }
        conn.execute(
            "INSERT OR REPLACE INTO prekey_bundles (fetch_cap, bundle_json, updated_at) VALUES (?1, ?2, ?3)",
            params![fetch_cap.as_slice(), bundle_json, now],
        )?;
        for (id, key) in fresh {
            conn.execute(
                "INSERT INTO prekey_upload_ids(fetch_cap,prekey_id,key_bytes) VALUES (?1,?2,?3)",
                params![fetch_cap.as_slice(), id, key.as_slice()],
            )?;
            conn.execute("INSERT INTO one_time_prekeys (fetch_cap, prekey_id, key_bytes, created_at) VALUES (?1,?2,?3,?4)",
                params![fetch_cap.as_slice(), id, key.as_slice(), now])?;
        }
        conn.commit()?;
        Ok(ids.len() as u32)
    }

    /// Fetch a prekey bundle by fetch_cap. Consumes one OPK while more than one remains (S16 §3.7).
    #[allow(clippy::type_complexity)]
    pub fn fetch_prekey_bundle(
        &self,
        fetch_cap: &[u8; 32],
        capability_type: u8,
    ) -> rusqlite::Result<Option<(String, Option<(u32, [u8; 32])>)>> {
        let mut guard = self.conn.lock().unwrap();
        let conn = guard.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let active: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM capabilities WHERE fetch_cap=?1 AND deactivated=0)",
            params![fetch_cap.as_slice()],
            |r| r.get(0),
        )?;
        if !active {
            return Ok(None);
        }

        // S16 §3.7 type-1 idempotency: after the first fetch on an ephemeral
        // capability, return the cached (bundle, consumed OPK) byte-identically and
        // consume NOTHING. Held under the same lock as the consume+cache below, so
        // concurrent first-fetches cannot both consume.
        if capability_type == 1 {
            let cached: Option<Option<String>> = conn
                .query_row(
                    "SELECT prekey_fetch_cache FROM capabilities WHERE fetch_cap = ?1",
                    params![fetch_cap.as_slice()],
                    |row| row.get::<_, Option<String>>(0),
                )
                .optional()?;
            if let Some(Some(json)) = cached {
                if let Ok(entry) = serde_json::from_str::<PrekeyFetchCacheEntry>(&json) {
                    return Ok(Some((entry.bundle_json, entry.opk)));
                }
            }
        }

        let bundle_json: Option<String> = conn
            .query_row(
                "SELECT bundle_json FROM prekey_bundles WHERE fetch_cap = ?1",
                params![fetch_cap.as_slice()],
                |row| row.get(0),
            )
            .optional()?;

        let bundle_json = match bundle_json {
            Some(b) => b,
            None => return Ok(None),
        };

        // S16 §3.7 "refuse last OPK": the server MUST NEVER serve the final OPK.
        // Only consume when at least 2 remain, so a fetch can never drain the pool to
        // zero — forcing a 3-DH fallback (the initiator verifies the signed manifest
        // to confirm the fallback is legitimate). This bounds OPK drain and prevents
        // an attacker from exhausting the pool to strip one-time-prekey forward
        // secrecy. When 0 or 1 remain, no OPK is served (3-DH fallback).
        let opk_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM one_time_prekeys WHERE fetch_cap = ?1",
            params![fetch_cap.as_slice()],
            |row| row.get(0),
        )?;

        let consumed_opk = if opk_count > 1 {
            let (row_id, prekey_id, key_blob): (i64, u32, Vec<u8>) = conn.query_row(
                "SELECT id, prekey_id, key_bytes FROM one_time_prekeys WHERE fetch_cap = ?1 ORDER BY id ASC LIMIT 1",
                params![fetch_cap.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?;
            conn.execute(
                "DELETE FROM one_time_prekeys WHERE id = ?1",
                params![row_id],
            )?;
            let mut key = [0u8; 32];
            key.copy_from_slice(&key_blob);
            Some((prekey_id, key))
        } else {
            None // 0 or 1 OPK remaining → force 3-DH fallback, never serve the last
        };

        // S16 §3.7: cache this exact result for type-1 caps so every subsequent
        // fetch is idempotent (returns it, consumes nothing).
        if capability_type == 1 {
            let entry = PrekeyFetchCacheEntry {
                bundle_json: bundle_json.clone(),
                opk: consumed_opk,
            };
            if let Ok(json) = serde_json::to_string(&entry) {
                conn.execute(
                    "UPDATE capabilities SET prekey_fetch_cache = ?2 WHERE fetch_cap = ?1",
                    params![fetch_cap.as_slice(), json],
                )?;
            }
        }

        conn.commit()?;
        Ok(Some((bundle_json, consumed_opk)))
    }

    // PoW challenges live in memory (`pow::ChallengeStore`, S16 §3.2).

    // The server has no push-relay registration.

    // -----------------------------------------------------------------------
    // Retention Cleanup
    // -----------------------------------------------------------------------

    /// Delete expired messages, challenges, and deactivated capabilities.
    pub fn cleanup(
        &self,
        now: i64,
        retention_secs: i64,
        vacuum_threshold_percent: u32,
    ) -> rusqlite::Result<CleanupStats> {
        let mut guard = self.conn.lock().unwrap();
        let conn = guard.transaction_with_behavior(TransactionBehavior::Immediate)?;

        // S16 §9/§10: retention split. `retention_days` applies ONLY to messages
        // that have been fetched at least once (fetched_at set) but never acked;
        // UNFETCHED messages are EXEMPT and retained up to the 90-day hard cap
        // (§10.1) — a recipient offline for weeks has, by definition, never fetched,
        // and deleting their mail at retention_days would silently strand them
        // (guaranteed ratchet desync). Acked messages are deleted immediately by
        // /v1/acknowledge and never reach here.
        const HARD_RETENTION_CAP_SECS: i64 = 90 * 86_400;
        let hard_cutoff = now - HARD_RETENTION_CAP_SECS;

        // 1. Fetched-but-unacknowledged messages past retention_days.
        let fetched_deleted = conn.execute(
            "DELETE FROM messages WHERE fetched_at IS NOT NULL AND deposited_at < ?1 -
             MIN(?3, COALESCE((SELECT json_extract(settings_json, '$.retention_days') * 86400
                 FROM capabilities WHERE capabilities.fetch_cap=messages.fetch_cap), ?2))",
            params![now, retention_secs, HARD_RETENTION_CAP_SECS],
        )? as u64;
        // 2. Everything past the 90-day hard cap (this is what catches UNFETCHED mail).
        let hard_deleted = conn.execute(
            "DELETE FROM messages WHERE deposited_at < ?1",
            params![hard_cutoff],
        )? as u64;
        let messages_deleted = fetched_deleted + hard_deleted;

        // Only rows written by servers that stored challenges on disk; the
        // current server keeps them in memory (S16 §3.2).
        let challenges_deleted = conn.execute(
            "DELETE FROM pow_challenges WHERE expires_at < ?1",
            params![now],
        )? as u64;

        // S16 §10 step 5: delete expired deposit-dedup rows (past their hold window).
        conn.execute(
            "DELETE FROM deposit_dedup WHERE expires_at < ?1",
            params![now],
        )?;

        // S16 §10 steps 6+7+8: delete capabilities that are past `expires_at`,
        // deactivated >24h ago, or inactive >30d — cascading child-first to all
        // dependent rows. foreign_keys is ON and none of the FKs declare ON DELETE
        // CASCADE, so we cascade explicitly (else the parent DELETE fails and orphan
        // messages/prekeys/deposit_caps/dedup accumulate indefinitely).
        let deactivated_cutoff = now - 86_400;
        let inactive_cutoff = now - 30 * 86_400;
        let doomed: Vec<Vec<u8>> = {
            let mut stmt = conn.prepare(
                "SELECT fetch_cap FROM capabilities WHERE
                    (deactivated = 1 AND deactivated_at IS NOT NULL AND deactivated_at < ?1)
                 OR (deactivated = 0 AND last_active_at IS NOT NULL AND last_active_at < ?2)
                 OR (expires_at IS NOT NULL AND expires_at < ?3)",
            )?;
            let rows = stmt.query_map(params![deactivated_cutoff, inactive_cutoff, now], |r| {
                r.get::<_, Vec<u8>>(0)
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        let caps_deleted = doomed.len() as u64;
        for fc in &doomed {
            conn.execute(
                "DELETE FROM deposit_dedup WHERE deposit_cap IN (SELECT deposit_cap FROM deposit_caps WHERE fetch_cap = ?1)",
                params![fc.as_slice()],
            )?;
            conn.execute(
                "DELETE FROM messages WHERE fetch_cap = ?1",
                params![fc.as_slice()],
            )?;
            conn.execute(
                "DELETE FROM one_time_prekeys WHERE fetch_cap = ?1",
                params![fc.as_slice()],
            )?;
            conn.execute(
                "DELETE FROM prekey_bundles WHERE fetch_cap = ?1",
                params![fc.as_slice()],
            )?;
            conn.execute(
                "DELETE FROM deposit_caps WHERE fetch_cap = ?1",
                params![fc.as_slice()],
            )?;
            conn.execute(
                "DELETE FROM capabilities WHERE fetch_cap = ?1",
                params![fc.as_slice()],
            )?;
        }

        conn.commit()?;
        let conn = &*guard;

        // Vacuum if needed (S16 §10 step 9)
        let page_count: i64 = conn
            .query_row("PRAGMA page_count", [], |row| row.get(0))
            .unwrap_or(0);
        let freelist_count: i64 = conn
            .query_row("PRAGMA freelist_count", [], |row| row.get(0))
            .unwrap_or(0);
        let vacuumed = if page_count > 0
            && (freelist_count * 100 / page_count) as u32 >= vacuum_threshold_percent
        {
            conn.execute_batch("VACUUM").ok();
            true
        } else {
            false
        };

        Ok(CleanupStats {
            messages_deleted,
            challenges_deleted,
            caps_deleted,
            vacuumed,
        })
    }

    /// Count total active capabilities (for health endpoint).
    pub fn active_capability_count(&self) -> rusqlite::Result<u64> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM capabilities WHERE deactivated = 0",
            [],
            |row| row.get(0),
        )?;
        Ok(count as u64)
    }

    /// Count total stored messages (for health endpoint).
    pub fn total_message_count(&self) -> rusqlite::Result<u64> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM messages", [], |row| row.get(0))?;
        Ok(count as u64)
    }
}

/// Result of a registration attempt.
#[derive(Debug, Clone, PartialEq)]
pub enum RegisterResult {
    /// New capability pair created.
    Created,
    /// Exact same fetch+deposit pair already exists (idempotent re-registration, S16 §3.1).
    AlreadyExists,
    /// One or both tokens conflict with an existing different mapping.
    Conflict,
}

/// The state of a capability.
#[derive(Debug, Clone, PartialEq)]
pub enum CapabilityState {
    Active,
    Deactivated,
    NotFound,
}

/// Stats returned by cleanup operations.
#[derive(Debug, Clone)]
pub struct CleanupStats {
    pub messages_deleted: u64,
    pub challenges_deleted: u64,
    pub caps_deleted: u64,
    pub vacuumed: bool,
}

/// Capability status for the /v1/status endpoint.
#[derive(Debug, Clone)]
pub struct CapabilityStatus {
    pub capability_type: u8,
    pub retention_days: u32,
    pub messages_stored: u64,
    pub quota_remaining: u64,
    pub oldest_message_age: u64,
    pub prekey_count: u32,
    pub prekey_ids: Vec<u32>,
}

#[cfg(test)]
mod row6_prekey_tests {
    use super::*;
    #[test]
    fn recovery_replaces_pool_without_reactivating_consumed_ids() {
        let db = Database::open_in_memory().unwrap();
        db.register_capability(
            &[1; 32],
            &[2; 32],
            &CapabilitySettings::default(),
            2,
            None,
            3600,
            10,
        )
        .unwrap();
        db.upload_prekey_bundle(
            &[1; 32],
            "old",
            &[(1, [1; 32]), (2, [2; 32]), (3, [3; 32])],
            3,
            10,
        )
        .unwrap();
        let fresh = [(4, [4; 32]), (5, [5; 32]), (6, [6; 32])];
        assert_eq!(
            db.replace_prekey_bundle(&[1; 32], "fresh", &fresh, 3, 11)
                .unwrap(),
            3
        );
        let first = db.fetch_prekey_bundle(&[1; 32], 2).unwrap().unwrap();
        assert_eq!(first.0, "fresh");
        assert!(first.1.unwrap().0 >= 4);
        assert_eq!(
            db.replace_prekey_bundle(&[1; 32], "fresh", &fresh, 3, 12)
                .unwrap(),
            2
        );
        assert!(
            db.fetch_prekey_bundle(&[1; 32], 2)
                .unwrap()
                .unwrap()
                .1
                .unwrap()
                .0
                >= 4
        );
    }

    #[test]
    fn retried_upload_cannot_restore_consumed_opk_or_replace_its_key() {
        let db = Database::open_in_memory().unwrap();
        db.register_capability(
            &[1; 32],
            &[2; 32],
            &CapabilitySettings::default(),
            2,
            None,
            3600,
            10,
        )
        .unwrap();
        let keys = [(1, [11; 32]), (2, [12; 32]), (3, [13; 32])];
        db.upload_prekey_bundle(&[1; 32], "{}", &keys, 3, 10)
            .unwrap();
        let first = db
            .fetch_prekey_bundle(&[1; 32], 2)
            .unwrap()
            .unwrap()
            .1
            .unwrap();
        assert_eq!(db.opk_count(&[1; 32]).unwrap(), 2);
        assert_eq!(
            db.upload_prekey_bundle(&[1; 32], "{}", &keys, 3, 11)
                .unwrap(),
            2
        );
        let second = db
            .fetch_prekey_bundle(&[1; 32], 2)
            .unwrap()
            .unwrap()
            .1
            .unwrap();
        assert_ne!(first.0, second.0);
        assert!(matches!(
            db.upload_prekey_bundle(&[1; 32], "{}", &[(first.0, [99; 32])], 3, 12),
            Err(PrekeyUploadError::Conflict)
        ));
    }
}
