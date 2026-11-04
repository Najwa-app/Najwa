-- Najwa consolidated database schema (S03).
-- There are no group, channel or linked-device tables.
-- Schema version 2 and supported additive updates are managed by init_schema.
-- See docs/specs/03-encrypted-storage.md.

-- table: db_meta
CREATE TABLE IF NOT EXISTS db_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- table: ratchet_sessions
CREATE TABLE IF NOT EXISTS ratchet_sessions (
    contact_id INTEGER PRIMARY KEY,
    -- DH Ratchet keys
    dhs_private BLOB,
    dhs_public BLOB,
    dhr BLOB,
    -- Root and chain keys
    rk BLOB,
    cks BLOB,
    ckr BLOB,
    -- Message counters
    ns INTEGER DEFAULT 0,
    nr INTEGER DEFAULT 0,
    pn INTEGER DEFAULT 0,
    -- Session metadata
    established_at INTEGER NOT NULL,
    last_activity INTEGER NOT NULL,
    -- Previous sending-epoch public key, sent as epoch_link (S06 §3.10)
    prev_dhs_pub BLOB,
    FOREIGN KEY (contact_id) REFERENCES contacts(id) ON DELETE CASCADE
);

-- table: skipped_keys
CREATE TABLE IF NOT EXISTS skipped_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    contact_id INTEGER NOT NULL,
    -- Key identifier
    dh_pub BLOB NOT NULL,
    message_number INTEGER NOT NULL,
    -- The actual message key
    message_key BLOB NOT NULL,
    -- Expiration
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    FOREIGN KEY (contact_id) REFERENCES contacts(id) ON DELETE CASCADE,
    UNIQUE (contact_id, dh_pub, message_number)
);

-- index: idx_skipped_expires
CREATE INDEX IF NOT EXISTS idx_skipped_expires ON skipped_keys(expires_at);

-- table: messages
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    contact_id INTEGER NOT NULL,
    -- Message identity
    msg_id BLOB NOT NULL UNIQUE,
    -- Direction and type
    direction INTEGER NOT NULL,
    content_type INTEGER NOT NULL,
    flags INTEGER DEFAULT 0,
    -- Content
    content BLOB NOT NULL,
    file_path TEXT,
    -- Timestamps
    timestamp INTEGER NOT NULL,
    received_at INTEGER,
    read_at INTEGER,
    -- Status (for sent messages)
    status INTEGER DEFAULT 0,
    retry_count INTEGER DEFAULT 0,
    last_retry_at INTEGER,
    -- Threading
    reply_to_msg_id BLOB,
    -- Disappearing messages (S03 §5.6, S12)
    disappear_timer INTEGER,
    disappear_at INTEGER, encrypted_blob BLOB, group_id BLOB, sender_display_name TEXT, origin_timestamp_ms INTEGER, retry_wire_blob BLOB,
    FOREIGN KEY (contact_id) REFERENCES contacts(id) ON DELETE CASCADE
);

-- index: idx_messages_contact
CREATE INDEX IF NOT EXISTS idx_messages_contact ON messages(contact_id, timestamp DESC);

-- index: idx_messages_status
CREATE INDEX IF NOT EXISTS idx_messages_status ON messages(status) WHERE status < 2;

-- index: idx_messages_msg_id
CREATE INDEX IF NOT EXISTS idx_messages_msg_id ON messages(msg_id);

-- S07 ACK lookup survives pruning of the plaintext repair-history buffer.
CREATE TABLE IF NOT EXISTS outbound_message_positions (
    contact_id INTEGER NOT NULL,
    dh_pub BLOB NOT NULL CHECK(length(dh_pub) = 32),
    message_number INTEGER NOT NULL,
    msg_id BLOB NOT NULL,
    PRIMARY KEY (contact_id, dh_pub, message_number),
    FOREIGN KEY (contact_id) REFERENCES contacts(id) ON DELETE CASCADE,
    FOREIGN KEY (msg_id) REFERENCES messages(msg_id) ON DELETE CASCADE
);

-- index: idx_messages_disappear
CREATE INDEX IF NOT EXISTS idx_messages_disappear ON messages(disappear_at) WHERE disappear_at IS NOT NULL;

-- table: prekeys
CREATE TABLE IF NOT EXISTS prekeys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    -- Key identification
    key_id BLOB NOT NULL UNIQUE CHECK(length(key_id) = 4),
    key_type INTEGER NOT NULL,
    -- Key material
    private_key BLOB NOT NULL,
    public_key BLOB NOT NULL,
    signature BLOB,
    -- Lifecycle
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    used INTEGER DEFAULT 0,
    used_at INTEGER,
    -- Which mailbox this was uploaded to
    mailbox_id INTEGER,
    fetch_scope BLOB,
    FOREIGN KEY (mailbox_id) REFERENCES mailboxes(id)
);

-- index: idx_prekeys_type
CREATE INDEX IF NOT EXISTS idx_prekeys_type ON prekeys(key_type, used);

-- index: idx_prekeys_mailbox
CREATE INDEX IF NOT EXISTS idx_prekeys_mailbox ON prekeys(mailbox_id);

-- table: contact_mailbox_caps
CREATE TABLE IF NOT EXISTS contact_mailbox_caps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    contact_id INTEGER NOT NULL,
    mailbox_id INTEGER NOT NULL,
    -- Capability they use to send to us (per-contact for revocation)
    deposit_capability BLOB NOT NULL,
    -- Their capabilities for us to send to them
    their_deposit_capability BLOB,
    created_at INTEGER NOT NULL,
    revoked_at INTEGER, fetch_capability BLOB, their_envelope_secret BLOB, envelope_secret BLOB, capability_type INTEGER NOT NULL DEFAULT 2, expires_at INTEGER, registered_at INTEGER,
    FOREIGN KEY (contact_id) REFERENCES contacts(id) ON DELETE CASCADE,
    FOREIGN KEY (mailbox_id) REFERENCES mailboxes(id),
    UNIQUE (contact_id, mailbox_id, deposit_capability)
);

-- table: settings
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL,
    updated_at INTEGER NOT NULL
);

-- table: onion_pins
CREATE TABLE IF NOT EXISTS onion_pins (
    onion_address TEXT PRIMARY KEY,
    expected_key_hash BLOB NOT NULL,
    first_seen INTEGER NOT NULL,
    last_verified INTEGER NOT NULL,
    pin_count INTEGER DEFAULT 1
);

-- index: idx_ratchet_sessions_dhr
CREATE INDEX IF NOT EXISTS idx_ratchet_sessions_dhr ON ratchet_sessions(dhr);

-- table: volatile_keys
CREATE TABLE IF NOT EXISTS volatile_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    msg_id BLOB NOT NULL UNIQUE,
    encrypted_key BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER
);

-- index: idx_volatile_keys_expires
CREATE INDEX IF NOT EXISTS idx_volatile_keys_expires ON volatile_keys(expires_at)
    WHERE expires_at IS NOT NULL;

-- table: mailboxes
CREATE TABLE IF NOT EXISTS "mailboxes" (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    onion_address TEXT NOT NULL UNIQUE,
    fetch_capability BLOB NOT NULL,
    deposit_capability BLOB NOT NULL,
    cover_deposit_capability BLOB,
    cover_fetch_capability BLOB,
    priority INTEGER DEFAULT 1,
    last_success INTEGER,
    last_failure INTEGER,
    failure_count INTEGER DEFAULT 0,
    messages_stored INTEGER DEFAULT 0,
    quota_limit INTEGER,
    enabled INTEGER DEFAULT 1,
    created_at INTEGER NOT NULL,
    last_seen_id TEXT
, envelope_secret BLOB, cover_envelope_secret BLOB, cover_registered_at INTEGER);

-- table: pending_introductions
CREATE TABLE IF NOT EXISTS pending_introductions (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    introducer_contact_id   INTEGER NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    introduced_ik_pub       BLOB    NOT NULL CHECK(length(introduced_ik_pub) = 32),
    introduced_display_name TEXT    NOT NULL,
    introducer_ik_pub       BLOB    NOT NULL CHECK(length(introducer_ik_pub) = 32),
    payload_blob            BLOB    NOT NULL,
    is_anonymous            INTEGER NOT NULL DEFAULT 0,
    status                  INTEGER NOT NULL DEFAULT 0,
    created_at              INTEGER NOT NULL,
    expires_at              INTEGER NOT NULL,
    resolved_at             INTEGER
);

-- index: idx_pending_intro_status
CREATE INDEX IF NOT EXISTS idx_pending_intro_status
    ON pending_introductions(status);

-- index: idx_pending_intro_introducer
CREATE INDEX IF NOT EXISTS idx_pending_intro_introducer
    ON pending_introductions(introducer_contact_id);

-- index: idx_messages_group
CREATE INDEX IF NOT EXISTS idx_messages_group ON messages(group_id, timestamp DESC)
    WHERE group_id IS NOT NULL;

-- table: epoch_quarantine
CREATE TABLE IF NOT EXISTS epoch_quarantine (
    blob_hash      BLOB PRIMARY KEY,
    blob           BLOB NOT NULL,
    quarantined_at INTEGER NOT NULL
);

-- table: msg_id_cache_transport
CREATE TABLE IF NOT EXISTS msg_id_cache_transport (
    msg_id     BLOB    PRIMARY KEY,      -- 16 bytes: transport msg_id
    contact_id INTEGER NOT NULL,
    seen_at    INTEGER NOT NULL,
    FOREIGN KEY (contact_id) REFERENCES contacts(id) ON DELETE CASCADE
);

-- index: idx_msg_cache_transport_seen
CREATE INDEX IF NOT EXISTS idx_msg_cache_transport_seen ON msg_id_cache_transport(seen_at);

-- table: msg_id_cache_logical
CREATE TABLE IF NOT EXISTS msg_id_cache_logical (
    contact_id     INTEGER NOT NULL,
    logical_msg_id BLOB    NOT NULL,      -- 16 bytes: content-derived logical message ID
    seen_at        INTEGER NOT NULL,
    PRIMARY KEY (contact_id, logical_msg_id),
    FOREIGN KEY (contact_id) REFERENCES contacts(id) ON DELETE CASCADE
);

-- index: idx_msg_cache_logical_seen
CREATE INDEX IF NOT EXISTS idx_msg_cache_logical_seen ON msg_id_cache_logical(seen_at);

-- table: identity_history
CREATE TABLE IF NOT EXISTS identity_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    contact_id  INTEGER NOT NULL,
    old_ik_pub  BLOB NOT NULL,
    new_ik_pub  BLOB NOT NULL,
    rotated_at  INTEGER NOT NULL,
    reason      TEXT,
    FOREIGN KEY (contact_id) REFERENCES contacts(id) ON DELETE CASCADE
);

-- index: idx_identity_history_contact
CREATE INDEX IF NOT EXISTS idx_identity_history_contact ON identity_history(contact_id);

-- table: contacts
CREATE TABLE IF NOT EXISTS "contacts" (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pseudonym BLOB NOT NULL,            -- their pairwise pseudonym for us (NON-unique: shared across devices)
    their_ik_pub BLOB NOT NULL,         -- their master identity public key
    their_device_pub BLOB NOT NULL,     -- their device signing public key (DK_n_pub); = their_ik_pub for single-device
    our_pseudonym BLOB NOT NULL,
    display_name TEXT,
    avatar_hash BLOB,
    created_at INTEGER NOT NULL,
    last_message_at INTEGER,
    verified INTEGER DEFAULT 0,
    blocked INTEGER DEFAULT 0,
    next_outbound_seq INTEGER NOT NULL DEFAULT 0, -- from migration 017
    UNIQUE(their_ik_pub, their_device_pub)
);

-- index: idx_contacts_pseudonym
CREATE INDEX IF NOT EXISTS idx_contacts_pseudonym ON contacts(pseudonym);

-- index: idx_contacts_ik
CREATE INDEX IF NOT EXISTS idx_contacts_ik ON contacts(their_ik_pub);

-- index: idx_contacts_last_message
CREATE INDEX IF NOT EXISTS idx_contacts_last_message ON contacts(last_message_at DESC);

-- table: outbound_repair_records
CREATE TABLE IF NOT EXISTS outbound_repair_records (
    contact_id       INTEGER NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    dh_pub           BLOB    NOT NULL CHECK(length(dh_pub) = 32),
    message_number   INTEGER NOT NULL,
    msg_id           BLOB    NOT NULL CHECK(length(msg_id) = 16),
    timestamp        INTEGER NOT NULL,
    logical_seq      INTEGER NOT NULL,
    content_type     INTEGER NOT NULL,
    flags            INTEGER NOT NULL,
    content          BLOB    NOT NULL,
    content_sealed   INTEGER NOT NULL DEFAULT 0,
    created_at       INTEGER NOT NULL,
    PRIMARY KEY (contact_id, dh_pub, message_number)
);

-- index: idx_outbound_repair_created
CREATE INDEX IF NOT EXISTS idx_outbound_repair_created
    ON outbound_repair_records (contact_id, created_at DESC);

-- table: ephemeral_handshake_caps
CREATE TABLE IF NOT EXISTS ephemeral_handshake_caps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mailbox_id INTEGER NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    deposit_capability BLOB NOT NULL UNIQUE CHECK(length(deposit_capability) = 32),
    fetch_capability BLOB NOT NULL UNIQUE CHECK(length(fetch_capability) = 32),
    envelope_secret BLOB NOT NULL UNIQUE CHECK(length(envelope_secret) = 32),
    capability_type INTEGER NOT NULL DEFAULT 1 CHECK(capability_type = 1),
    expires_at INTEGER NOT NULL,
    registered_at INTEGER,
    accepted_at INTEGER,
    deactivated_at INTEGER,
    created_at INTEGER NOT NULL,
    CHECK(expires_at > created_at)
);

-- index: idx_ephemeral_handshake_caps_active
CREATE INDEX IF NOT EXISTS idx_ephemeral_handshake_caps_active
    ON ephemeral_handshake_caps(mailbox_id, expires_at)
    WHERE registered_at IS NOT NULL AND deactivated_at IS NULL;

-- table: dummy_capabilities (S08 §6.1.1 poll padding, S10 §5.1)
CREATE TABLE IF NOT EXISTS dummy_capabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mailbox_id INTEGER NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    fetch_capability BLOB NOT NULL UNIQUE CHECK(length(fetch_capability) = 32),
    deposit_capability BLOB NOT NULL UNIQUE CHECK(length(deposit_capability) = 32),
    registered_at INTEGER
);


-- Keep persisted ephemeral keys on the authoritative message deadline.
CREATE TRIGGER IF NOT EXISTS message_key_deadline AFTER UPDATE OF disappear_at ON messages
BEGIN
    UPDATE volatile_keys SET expires_at=NEW.disappear_at WHERE msg_id=NEW.msg_id;
END;
CREATE TRIGGER IF NOT EXISTS message_secrets_deleted AFTER DELETE ON messages
BEGIN
    DELETE FROM volatile_keys WHERE msg_id=OLD.msg_id;
    DELETE FROM outbound_repair_records WHERE msg_id=OLD.msg_id;
END;
-- Overwrite is the first step of secure deletion: remove repair copies then too.
CREATE TRIGGER IF NOT EXISTS message_repair_overwritten AFTER UPDATE OF content ON messages
BEGIN
    DELETE FROM outbound_repair_records WHERE msg_id=OLD.msg_id;
END;

-- S08: atomically queued ciphertext, including controls retained until ACK.
CREATE TABLE IF NOT EXISTS outgoing_frames (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    contact_id INTEGER NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    message_id INTEGER REFERENCES messages(id) ON DELETE CASCADE,
    wire BLOB NOT NULL,
    dh_pub BLOB NOT NULL CHECK(length(dh_pub)=32),
    n INTEGER NOT NULL,
    requires_ack INTEGER NOT NULL,
    is_replay INTEGER NOT NULL DEFAULT 0,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt INTEGER NOT NULL DEFAULT 0,
    deposited_at INTEGER,
    UNIQUE(contact_id,dh_pub,n)
);
-- S08 §7.1: a deleted contact's RevocationNotice and its deposit routes. It
-- outlives the contact row until its first deposit, or 90 days.
CREATE TABLE IF NOT EXISTS revocation_frames (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    wire BLOB NOT NULL,
    targets BLOB NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS received_frames (
    header_id BLOB PRIMARY KEY CHECK(length(header_id)=16),
    contact_id INTEGER NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    dh_pub BLOB NOT NULL CHECK(length(dh_pub)=32),
    n INTEGER NOT NULL,
    ack_required INTEGER NOT NULL,
    ack_pending INTEGER NOT NULL,
    received_at INTEGER NOT NULL,
    UNIQUE(contact_id,dh_pub,n)
);
CREATE TABLE IF NOT EXISTS inbound_work (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    contact_id INTEGER NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    body BLOB NOT NULL,
    cursor INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS outbound_history (
    message_id INTEGER PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,
    contact_id INTEGER NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    logical_id BLOB NOT NULL CHECK(length(logical_id)=16),
    logical_seq INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_outbound_history_logical ON outbound_history(contact_id,logical_id);
CREATE TABLE IF NOT EXISTS remote_mailbox_health (
    onion TEXT PRIMARY KEY,
    failures INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1
);

-- A wiped local message must have no surviving resend source or queued copy.
CREATE TRIGGER IF NOT EXISTS message_outbox_overwritten AFTER UPDATE OF content ON messages
BEGIN
    DELETE FROM outgoing_frames WHERE message_id=NEW.id;
    DELETE FROM outbound_history WHERE message_id=NEW.id;
END;

-- IDs survive key cleanup and recovery, preventing reactivation of retired keys.
CREATE TABLE IF NOT EXISTS prekey_used_ids (
    key_id BLOB PRIMARY KEY CHECK(length(key_id)=4)
);

-- Resumable browser transfers. All source/prepared bytes stay inside SQLCipher;
-- no plaintext staging paths or browser credentials are persisted.
CREATE TABLE IF NOT EXISTS browser_transfers (
    id TEXT PRIMARY KEY CHECK(length(id)=32),
    contact_id INTEGER NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32),
    manifest BLOB NOT NULL,
    size INTEGER NOT NULL CHECK(size BETWEEN 1 AND 268435456),
    received INTEGER NOT NULL DEFAULT 0,
    state INTEGER NOT NULL DEFAULT 0,
    cursor INTEGER NOT NULL DEFAULT 0,
    metadata BLOB,
    error TEXT,
    created_at INTEGER NOT NULL,
    UNIQUE(contact_id,fingerprint)
);
CREATE TABLE IF NOT EXISTS browser_transfer_parts (
    transfer_id TEXT NOT NULL REFERENCES browser_transfers(id) ON DELETE CASCADE,
    kind INTEGER NOT NULL CHECK(kind IN (0,1)),
    part INTEGER NOT NULL CHECK(part>=0),
    data BLOB NOT NULL CHECK(length(data)<=1048576),
    PRIMARY KEY(transfer_id,kind,part)
);
CREATE TABLE IF NOT EXISTS browser_download_grants (
    digest BLOB PRIMARY KEY CHECK(length(digest)=32),
    contact_id INTEGER NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_browser_file_progress
ON messages(contact_id,direction,substr(content,1,16),substr(content,17,4),status)
WHERE content_type=11 AND disappear_timer IS NULL;
-- Each received part looks up its metadata by session (S11 §4.3 orphan bound).
CREATE INDEX IF NOT EXISTS idx_browser_file_metadata
ON messages(contact_id,direction,substr(content,1,16))
WHERE content_type=10 AND disappear_timer IS NULL;
-- Replace the preview index once; progress must not walk file-body overflow
-- pages merely to read a status column stored after the content blob.
DROP INDEX IF EXISTS idx_browser_file_parts;
