//! Database schema — created fresh, in full, at the final shape (S16 §4).
//!
//! Consolidated schema policy (same as the client storage crate): the
//! v1 nine-step migration chain is deleted pre-launch. A fresh database is
//! created at the final layout in one shot; there is no in-place upgrade path
//! from a v1 mailbox database (different binary, different guarantees — an
//! operator migrating starts from an empty store, which is the S16 §13
//! retirement posture anyway).
//!
//! There are no channel-feed tables (`feeds`, `feed_messages`).

use rusqlite::{Connection, OptionalExtension};

/// Schema version written on creation. the current schema line: the layout below equals
/// the v1 final shape (post-migration-9) minus the cut feed tables.
pub const SCHEMA_VERSION: i64 = 2;

/// Create the full schema if the database is empty; refuse a database written
/// by another schema version rather than silently misreading it.
pub fn ensure(conn: &Connection) -> rusqlite::Result<()> {
    let table_exists: bool = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_version'",
            [],
            |_| Ok(true),
        )
        .optional()?
        .unwrap_or(false);
    let current: Option<i64> = if table_exists {
        Some(conn.query_row(
            "SELECT version FROM schema_version LIMIT 1",
            [],
            |row| row.get(0),
        )?)
    } else {
        None
    };

    match current {
        None => initialize(conn),
        Some(v) if v == SCHEMA_VERSION => Ok(()),
        Some(v) => Err(rusqlite::Error::InvalidParameterName(format!(
            "mailbox database schema version {v} is not supported (this build creates version {SCHEMA_VERSION}); \
             start from an empty database"
        ))),
    }
}

/// Create the complete final schema.
pub fn initialize(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        -- Schema version tracking
        CREATE TABLE schema_version (
            version     INTEGER NOT NULL
        );

        -- Capability registrations (S16 §4)
        CREATE TABLE capabilities (
            fetch_cap           BLOB(32) PRIMARY KEY,
            settings_json       TEXT NOT NULL,
            created_at          INTEGER NOT NULL,
            last_active_at      INTEGER,
            deactivated         INTEGER NOT NULL DEFAULT 0,
            deactivated_at      INTEGER, -- NULL while active; 24h grace keyed on deactivation (S16 §10)
            capability_type     INTEGER NOT NULL DEFAULT 2, -- 1 = ephemeral handshake, 2 = long-term (§3.1)
            expires_at          INTEGER, -- NULL = inactivity expiry only; type 1 ALWAYS set (§3.1)
            prekey_fetch_cache  TEXT     -- type-1 idempotent prekey-fetch snapshot (§3.7)
        );

        -- Deposit -> Fetch capability mapping (many-to-one)
        CREATE TABLE deposit_caps (
            deposit_cap     BLOB(32) PRIMARY KEY,
            fetch_cap       BLOB(32) NOT NULL REFERENCES capabilities(fetch_cap),
            created_at      INTEGER NOT NULL
        );
        CREATE INDEX idx_deposit_fetch ON deposit_caps(fetch_cap);

        -- Stored messages
        CREATE TABLE messages (
            id              TEXT PRIMARY KEY,
            fetch_cap       BLOB(32) NOT NULL REFERENCES capabilities(fetch_cap),
            blob            BLOB NOT NULL,
            deposited_at    INTEGER NOT NULL,
            size            INTEGER NOT NULL,
            release_at      INTEGER, -- mandatory batched release (§6)
            deposit_cap     BLOB,    -- cap_hint derivation (SHA256(deposit_cap)[0:8])
            fetched_at      INTEGER  -- NULL until first fetch; drives the §9 retention split
        );
        CREATE INDEX idx_messages_fetch ON messages(fetch_cap, deposited_at);
        CREATE INDEX idx_messages_release ON messages(fetch_cap, release_at);

        -- Deposit dedup within the hold window (§3.3 step 4)
        CREATE TABLE deposit_dedup (
            deposit_cap  BLOB(32) NOT NULL,
            blob_hash    BLOB(32) NOT NULL, -- SHA256(blob)
            message_id   TEXT NOT NULL,     -- original message_id returned on the first deposit
            expires_at   INTEGER NOT NULL,  -- deposited_at + max_hold_secs + jitter_secs
            PRIMARY KEY (deposit_cap, blob_hash)
        );

        -- Prekey bundles (one per capability)
        CREATE TABLE prekey_bundles (
            fetch_cap       BLOB(32) PRIMARY KEY REFERENCES capabilities(fetch_cap),
            bundle_json     TEXT NOT NULL,
            updated_at      INTEGER NOT NULL
        );

        -- One-time prekeys (consume-once)
        CREATE TABLE one_time_prekeys (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            fetch_cap       BLOB(32) NOT NULL REFERENCES capabilities(fetch_cap),
            prekey_id       INTEGER NOT NULL,
            key_bytes       BLOB(32) NOT NULL,
            created_at      INTEGER NOT NULL
        );
        CREATE INDEX idx_opk_fetch ON one_time_prekeys(fetch_cap);

        CREATE TABLE prekey_upload_ids (
            fetch_cap BLOB(32) NOT NULL REFERENCES capabilities(fetch_cap) ON DELETE CASCADE,
            prekey_id INTEGER NOT NULL,
            key_bytes BLOB(32) NOT NULL,
            PRIMARY KEY(fetch_cap, prekey_id)
        );

        -- Unused: PoW challenges now live in memory (S16 §3.2). Kept so every
        -- version-2 database has the same tables; cleanup drains old rows.
        CREATE TABLE pow_challenges (
            challenge       BLOB(32) PRIMARY KEY,
            difficulty      INTEGER NOT NULL,
            expires_at      INTEGER NOT NULL,
            used            INTEGER NOT NULL DEFAULT 0
        );

        INSERT INTO schema_version (rowid, version) VALUES (1, 2);
        ",
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    #[test]
    fn fresh_db_is_created_at_version_2() {
        let conn = Connection::open_in_memory().unwrap();
        ensure(&conn).unwrap();
        let version: i64 = conn
            .query_row("SELECT version FROM schema_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        // Re-running on a current database is a no-op.
        ensure(&conn).unwrap();
    }

    #[test]
    fn foreign_schema_version_is_refused_not_silently_reused() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE schema_version (version INTEGER NOT NULL);")
            .unwrap();
        conn.execute("INSERT INTO schema_version (rowid, version) VALUES (1, 9)", [])
            .unwrap();
        // A v1 mailbox database (final v1 schema version 9) must NOT be opened
        // by this server — refuse with a clear error instead of misreading it.
        let err = ensure(&conn).unwrap_err();
        assert!(err.to_string().contains("not supported"));
    }

    #[test]
    fn final_schema_has_no_feed_tables_and_has_every_v9_column() {
        let conn = Connection::open_in_memory().unwrap();
        ensure(&conn).unwrap();
        let tables: Vec<String> = {
            let mut stmt = conn
                .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
                .unwrap();
            stmt.query_map([], |r| r.get::<_, String>(0))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
        };
        assert!(
            !tables.iter().any(|t| t.starts_with("feed")),
            "S09 feed tables must not exist: {tables:?}"
        );
        for required in [
            "schema_version",
            "capabilities",
            "deposit_caps",
            "messages",
            "deposit_dedup",
            "prekey_bundles",
            "one_time_prekeys",
            "pow_challenges",
        ] {
            assert!(tables.contains(&required.to_string()), "missing {required}");
        }
        // Every late v1 migration column exists from day one.
        for (table, column) in [
            ("capabilities", "last_active_at"),
            ("capabilities", "deactivated_at"),
            ("capabilities", "capability_type"),
            ("capabilities", "expires_at"),
            ("capabilities", "prekey_fetch_cache"),
            ("messages", "release_at"),
            ("messages", "deposit_cap"),
            ("messages", "fetched_at"),
        ] {
            let ok: bool = conn
                .query_row(
                    "SELECT COUNT(*) FROM pragma_table_info(?1) WHERE name = ?2",
                    rusqlite::params![table, column],
                    |r| r.get(0),
                )
                .unwrap();
            assert!(ok, "{table}.{column} missing");
        }
    }
}
