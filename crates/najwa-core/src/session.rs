//! Session management for active ratchet sessions (S08 §4).
//!
//! Handles X3DH session initiation, acceptance, and DH-key-based lookup
//! for efficient decryption routing.

use najwa_crypto::keys::ed25519::{Ed25519Public, Ed25519Signature};
use najwa_crypto::keys::x25519::{X25519KeyPair, X25519Public};
use najwa_protocol::mailbox::client::MailboxClient;
use najwa_protocol::message::types::ContentType;
use najwa_protocol::pseudonym::derive_pairwise_pseudonyms;
use najwa_protocol::ratchet::decrypt::ratchet_decrypt;
use najwa_protocol::ratchet::error::RatchetError;
use najwa_protocol::ratchet::header::RatchetHeader;
use najwa_protocol::ratchet::init::{init_alice, init_bob};
use najwa_protocol::ratchet::state::{RatchetState, SkippedKey};
use najwa_protocol::x3dh::initiator::x3dh_initiate;
use najwa_protocol::x3dh::responder::x3dh_respond;
use najwa_protocol::x3dh::types::{X3DHHeader, X3DHPrekeyBundle};

use crate::error::{MessagingError, Result};
use crate::service::MessagingService;
use crate::storage::CoreStorage;
use crate::types::{Contact, ContactId};

/// A fully-decrypted, guard-passed Initial (or SessionRepairInit) from
/// [`MessagingService::accept_session`] that the caller MUST commit atomically
/// via `commit_initial_received` — nothing is persisted inside accept_session, so
/// a replayed/duplicate Initial cannot clobber an advanced session before the
/// dedup mark records it (S08 §4.3 / S06 §3.11 I3/I4).
pub(crate) struct AcceptedInitial {
    pub contact: Contact,
    pub plaintext: Vec<u8>,
    /// Candidate responder ratchet state (already advanced by the first decrypt).
    pub state: RatchetState,
    /// X3DH associated data for the (re)established session.
    pub ad: Vec<u8>,
    /// One-time-prekey id to consume in the commit; `None` if the Initial used none.
    pub opk_id: Option<[u8; 4]>,
}

// ---------------------------------------------------------------------------
// X3DH header wire serialization (for Initial messages)
// ---------------------------------------------------------------------------

/// Serialize an X3DHHeader to bytes for embedding in Initial messages (S06 §2.4).
///
/// Layout: `ik_pub(32) || ek_pub(32) || device_pub(32) || spk_id(4) ||
/// opk_flag(1) || [opk_id(4)]` = 101 bytes (no OPK) or 105 bytes (with OPK).
pub fn serialize_x3dh_header(header: &X3DHHeader) -> Vec<u8> {
    let mut out = Vec::with_capacity(105);
    out.extend_from_slice(&header.identity_key.to_bytes());
    out.extend_from_slice(&header.ephemeral_key.to_bytes());
    out.extend_from_slice(&header.device_key.to_bytes());
    out.extend_from_slice(&header.signed_prekey_id);
    match header.used_one_time_prekey_id {
        Some(opk_id) => {
            out.push(0x01);
            out.extend_from_slice(&opk_id);
        }
        None => {
            out.push(0x00);
        }
    }
    out
}

/// Deserialize an X3DHHeader from bytes (S06 §2.4: 101/105-byte layout).
pub fn deserialize_x3dh_header(data: &[u8]) -> Result<(X3DHHeader, usize)> {
    if data.len() < 101 {
        return Err(MessagingError::SerializationError(
            "x3dh header too short".into(),
        ));
    }
    let mut ik_bytes = [0u8; 32];
    ik_bytes.copy_from_slice(&data[0..32]);
    let mut ek_bytes = [0u8; 32];
    ek_bytes.copy_from_slice(&data[32..64]);
    let mut device_bytes = [0u8; 32];
    device_bytes.copy_from_slice(&data[64..96]);
    let mut spk_id = [0u8; 4];
    spk_id.copy_from_slice(&data[96..100]);
    let opk_flag = data[100];
    if opk_flag > 1 || data.len() != if opk_flag == 1 { 105 } else { 101 } {
        return Err(MessagingError::SerializationError("invalid x3dh header layout".into()));
    }

    let (opk_id, consumed) = if opk_flag == 0x01 {
        if data.len() < 105 {
            return Err(MessagingError::SerializationError(
                "x3dh header truncated (opk)".into(),
            ));
        }
        let mut id = [0u8; 4];
        id.copy_from_slice(&data[101..105]);
        (Some(id), 105)
    } else {
        (None, 101)
    };

    let ik = Ed25519Public::from_bytes(&ik_bytes)
        .map_err(|e| MessagingError::SerializationError(e.to_string()))?;
    let device_key = Ed25519Public::from_bytes(&device_bytes)
        .map_err(|e| MessagingError::SerializationError(e.to_string()))?;

    Ok((
        X3DHHeader {
            identity_key: ik,
            ephemeral_key: X25519Public::from_bytes(ek_bytes),
            device_key,
            signed_prekey_id: spk_id,
            used_one_time_prekey_id: opk_id,
        },
        consumed,
    ))
}

// ---------------------------------------------------------------------------
// Clone ratchet state for trial decryption (S08 §4.4)
// ---------------------------------------------------------------------------

/// Clone a RatchetState by reconstructing key pairs from raw bytes.
///
/// This is needed because `X25519KeyPair` doesn't implement `Clone`
/// (the underlying `StaticSecret` from x25519-dalek doesn't).
pub(crate) fn clone_ratchet_state(state: &RatchetState) -> RatchetState {
    RatchetState {
        dhs: X25519KeyPair::from_seed(state.dhs.private().to_bytes()),
        dhr: state.dhr.clone(),
        rk: state.rk,
        cks: state.cks,
        ckr: state.ckr,
        ns: state.ns,
        nr: state.nr,
        pn: state.pn,
        prev_dhs_pub: state.prev_dhs_pub,
        skipped: state
            .skipped
            .iter()
            .map(|(k, v)| {
                (
                    *k,
                    SkippedKey {
                        message_key: v.message_key,
                        created_at: v.created_at,
                    },
                )
            })
            .collect(),
    }
}

// ---------------------------------------------------------------------------
// PrekeyBundle → X3DHPrekeyBundle conversion
// ---------------------------------------------------------------------------

/// Convert a mailbox wire-format PrekeyBundle to X3DHPrekeyBundle for X3DH.
fn mailbox_bundle_to_x3dh(
    bundle: &najwa_protocol::mailbox::types::PrekeyBundle,
    contact_ik: &[u8; 32], signing_key: &[u8; 32],
) -> Result<X3DHPrekeyBundle> {
    if &bundle.identity_key != signing_key {
        return Err(najwa_protocol::x3dh::error::X3DHError::InvalidSignature.into());
    }
    let signing_key = Ed25519Public::from_bytes(signing_key)
        .map_err(|e| MessagingError::SerializationError(e.to_string()))?;
    najwa_protocol::x3dh::initiator::check_bundle_manifest(bundle, &signing_key)?;
    let ik = Ed25519Public::from_bytes(contact_ik)
        .map_err(|e| MessagingError::SerializationError(e.to_string()))?;

    let sig = Ed25519Signature::from_bytes(
        &bundle
            .signed_prekey_signature
            .as_slice()
            .try_into()
            .map_err(|_| MessagingError::SerializationError("bad sig length".into()))?,
    )
    .map_err(|e| MessagingError::SerializationError(e.to_string()))?;

    let spk_id = bundle.signed_prekey_id.to_be_bytes();

    let (opk, opk_id) = if let Some(first) = bundle.one_time_prekeys.first() {
        (
            Some(X25519Public::from_bytes(first.key)),
            Some(first.id.to_be_bytes()),
        )
    } else {
        (None, None)
    };

    Ok(X3DHPrekeyBundle {
        identity_key: ik,
        mailbox_ik_pub: Some(signing_key),
        signed_prekey: X25519Public::from_bytes(bundle.signed_prekey),
        signed_prekey_id: spk_id,
        signed_prekey_timestamp: bundle.signed_prekey_timestamp,
        signed_prekey_signature: sig,
        one_time_prekey: opk,
        one_time_prekey_id: opk_id,
    })
}

// ---------------------------------------------------------------------------
// MessagingService session methods
// ---------------------------------------------------------------------------

impl<S: CoreStorage, M: MailboxClient> MessagingService<S, M> {
    /// Get existing ratchet session or initiate a new one via X3DH (S08 §4.2).
    ///
    /// Returns `(RatchetState, AD, is_initial)` where `is_initial` is true
    /// if this is a brand-new session that needs an Initial message type.
    pub(crate) async fn get_or_create_session(
        &self,
        contact: &Contact,
    ) -> Result<(RatchetState, Vec<u8>, bool)> {
        // Check for existing session
        if let Some(state) = self
            .storage
            .get_ratchet_state(contact.id)
            .await
            .map_err(MessagingError::StorageError)?
        {
            let ad = self
                .storage
                .get_session_ad(contact.id)
                .await
                .map_err(MessagingError::StorageError)?
                .unwrap_or_else(|| self.build_ad_as_initiator(contact));
            return Ok((state, ad, false));
        }

        self.create_session_candidate(contact).await
    }

    pub(crate) async fn create_session_candidate(
        &self,
        contact: &Contact,
    ) -> Result<(RatchetState, Vec<u8>, bool)> {
        // No durable state changes until the caller commits a complete frame.
        let caps = self
            .storage
            .get_contact_capabilities(contact.id)
            .await
            .map_err(MessagingError::StorageError)?;
        let mut candidate = None;
        let mut last_error = MessagingError::NoMailboxCapability;
        'mailboxes: for cap in &caps {
            let Some(their_dep_cap) = cap.their_deposit_capability else { continue; };
            let mailbox = cap.mailbox_config();
            let signing_key = self.storage.get_contact_mailbox_signing_key(
                contact.id, &mailbox.onion_address).await
                .map_err(MessagingError::StorageError)?.unwrap_or(contact.their_ik_pub);
            // Retry a stale/bad SPK once on this mailbox; withholding switches mailbox.
            for attempt in 0..2 {
                let wire_bundle = match self.mailbox_client.fetch_prekey_bundle(
                    &mailbox, &their_dep_cap, &contact.their_pseudonym).await {
                    Ok(bundle) => bundle,
                    Err(error) => { last_error = error.into(); continue 'mailboxes; }
                };
                let result = mailbox_bundle_to_x3dh(&wire_bundle, &contact.their_ik_pub, &signing_key)
                    .and_then(|bundle| x3dh_initiate(&self.identity_key, &bundle)
                        .map(|result| (bundle, result)).map_err(Into::into));
                match result {
                    Ok(value) => { candidate = Some(value); break 'mailboxes; }
                    Err(error) => {
                        let retry = matches!(&error, MessagingError::X3DHError(
                            najwa_protocol::x3dh::error::X3DHError::InvalidSignature));
                        if retry && attempt == 1 { return Err(error); }
                        last_error = error;
                        if !retry { continue 'mailboxes; }
                    }
                }
            }
        }
        let (x3dh_bundle, x3dh_result) = candidate.ok_or(last_error)?;

        // Initialize Double Ratchet as Alice (initiator). S06 §3.2: the first
        // sending-ratchet DH key is the authenticated X3DH ephemeral EK_A, not a
        // fresh unrelated key — binding the ratchet to the X3DH handshake.
        let state = init_alice(
            &x3dh_result.shared_secret,
            &x3dh_bundle.signed_prekey,
            &x3dh_result.ephemeral_seed,
        )?;

        // Store the X3DH header bytes for embedding in the first message
        let x3dh_header_bytes = serialize_x3dh_header(&x3dh_result.header);

        // Candidate only: persist it with the first valid frame and its outbox
        // entry. A rejected first payload must leave the contact sessionless.
        let ad = x3dh_result.associated_data.clone();
        let mut combined = x3dh_header_bytes;
        combined.extend_from_slice(&ad);

        Ok((state, combined, true))
    }

    /// Accept (or re-establish) a session from an Initial / SessionRepairInit,
    /// returning a candidate the caller commits atomically (S08 §4.3, S06 §3.11).
    ///
    /// NOTHING is persisted here. The existing-session GUARD runs AFTER decrypt
    /// because the repair-vs-duplicate discriminator (control subtype `0x31`) lives
    /// in the ciphertext — a pre-decrypt guard (the previous design) could not see
    /// it and so permanently rejected every re-establishment/repair Initial to a
    /// peer that still held a session. The anti-clobber property is preserved by
    /// not-persisting + the caller's dedup mark, which records the msg_id in the
    /// same transaction as the (over)write, gating a replay.
    pub(crate) async fn accept_session(
        &self,
        x3dh_header: &X3DHHeader,
        ratchet_header: &RatchetHeader,
        encrypted_payload: &[u8],
        wire_prefix: &[u8],
        via_invitation_queue: bool,
    ) -> Result<AcceptedInitial> {
        self.require_prekey_recovery_complete()?;
        // Look up the sender's contact by the cleartext X3DH-header IK — used only
        // to IDENTITY-BIND the decrypted pseudonym below. The keep/adopt/
        // re-establish/drop decision reads the session of the contact the commit
        // will actually overwrite (the pseudonym-resolved one), looked up AFTER the
        // payload authenticates. Nothing is written here.
        let sender_ik = x3dh_header.identity_key.to_bytes();
        let sender_device = x3dh_header.device_key.to_bytes();
        let ik_contact = self
            .storage
            .get_contact_by_ik_device(&sender_ik, &sender_device)
            .await
            .map_err(MessagingError::StorageError)?;

        // 1. Our SPK.
        let our_spk = self
            .storage
            .get_spk_keypair(&x3dh_header.signed_prekey_id)
            .await
            .map_err(MessagingError::StorageError)?
            .ok_or(MessagingError::NoSignedPrekey)?;

        // 2. OPK — looked up but NOT consumed (the atomic commit consumes it). If
        //    the header names an OPK we don't hold, fail fast: x3dh_respond would
        //    otherwise silently fall back to 3-DH and the AEAD would fail anyway.
        let opk_id = x3dh_header.used_one_time_prekey_id;
        let our_opk = match opk_id {
            Some(id) => Some(
                self.storage
                    .get_opk_keypair(&id)
                    .await
                    .map_err(MessagingError::StorageError)?
                    .ok_or(MessagingError::NoSignedPrekey)?,
            ),
            None => None,
        };

        // 3. X3DH responder + 4. candidate ratchet + 5. decrypt. A FORGED Initial
        //    cannot produce a valid AEAD and fails here, before any guard/state.
        let x3dh_result =
            x3dh_respond(&self.identity_key, &our_spk, our_opk.as_ref(), x3dh_header)?;
        let mut session = init_bob(&x3dh_result.shared_secret, our_spk);
        let ad = x3dh_result.associated_data.clone();
        let plaintext = ratchet_decrypt(
            &mut session,
            ratchet_header,
            encrypted_payload,
            &ad,
            wire_prefix,
        )?;

        // 6. Parse the inner payload → sender pseudonym + is_repair. A repair is a
        //    `SessionRepairInit` control message (subtype 0x31) inside the padded
        //    payload — the ONLY reliable repair discriminator (S06 §3.7.1 / S07).
        let temp_payload = match najwa_protocol::message::types::Payload::from_bytes(&plaintext) {
            Ok(payload) => Some(payload),
            Err(najwa_protocol::message::MessageError::UnknownContentType(_)) => None,
            Err(error) => return Err(error.into()),
        };
        let sender_pseudonym: [u8; 32] = plaintext
            .get(..32)
            .ok_or_else(|| MessagingError::SerializationError("truncated Initial payload".into()))?
            .try_into()
            .unwrap();
        let is_repair = temp_payload.as_ref().is_some_and(|temp_payload| {
            temp_payload.content_type == najwa_protocol::message::types::ContentType::Control
                && matches!(
                    najwa_protocol::message::control::ControlMessage::from_bytes(
                        &temp_payload.content
                    ),
                    Ok(najwa_protocol::message::control::ControlMessage::SessionRepairInit { .. })
                )
        });

        // 7. Resolve the contact by pseudonym, and IDENTITY-BIND it to the IK. A
        // reciprocal handshake is the sole exception to the usual pre-existing
        // contact requirement: one scan gives the QR creator enough private
        // prekey material to decrypt this Initial, while the signed reciprocal
        // payload supplies the acceptor's missing mailbox coordinates (S05
        // §8.2). Validate every handshake field before creating anything.
        let pseudonym_contact = self
            .storage
            .get_contact_by_pseudonym(&sender_pseudonym)
            .await
            .map_err(MessagingError::StorageError)?;
        let contact = match pseudonym_contact {
            Some(contact) => {
                // The pseudonym only names the contact; the X3DH-header IK must be
                // that contact's stored IK. Otherwise anyone who learns a contact's
                // pseudonym could bind their own IK to that contact (S08 §4.3).
                if contact.their_ik_pub != sender_ik
                    || ik_contact.as_ref().is_some_and(|ik_c| ik_c.id != contact.id)
                {
                    tracing::warn!(
                        "Initial: X3DH-header IK does not match the contact named by the payload pseudonym — rejecting"
                    );
                    return Err(MessagingError::PseudonymMismatch);
                }
                contact
            }
            None if temp_payload
                .as_ref()
                .is_some_and(|p| p.content_type == ContentType::ReciprocalHandshake) =>
            {
                let temp_payload = temp_payload.as_ref().unwrap();
                // A new contact may only come from one of our invitation queues.
                // Any other queue is reachable by existing contacts, who must not
                // be able to add contacts (S05 §8.2).
                if !via_invitation_queue {
                    return Err(MessagingError::UnknownPseudonym);
                }
                if ik_contact.is_some() {
                    // Same identity under a different pseudonym is not a new
                    // contact. Mailbox-update UX is a separate, explicit flow;
                    // never silently create or replace here.
                    return Err(MessagingError::PseudonymMismatch);
                }
                let reciprocal =
                    najwa_protocol::contact::HandshakePayload::from_bytes(&temp_payload.content)
                        .map_err(|e| {
                            MessagingError::SerializationError(format!(
                                "invalid reciprocal handshake: {e}"
                            ))
                        })?;
                // Reject a valid payload prefix with appended bytes: S05 §8.2
                // requires the content to be exactly one HandshakePayload.
                if reciprocal.to_bytes() != temp_payload.content {
                    return Err(MessagingError::SerializationError(
                        "reciprocal handshake has trailing data".into(),
                    ));
                }
                // Includes outer signature, payload expiry, every mailbox cert
                // signature, and the reconstructed cert expires_at check.
                reciprocal.verify().map_err(|e| {
                    MessagingError::SerializationError(format!(
                        "reciprocal handshake verification failed: {e}"
                    ))
                })?;
                let mut usable_reciprocal = reciprocal.clone();
                usable_reciprocal.mailbox_entries.retain(|entry| {
                    let supported = entry.capability_type
                        == najwa_protocol::contact::mailbox_key::CAP_TYPE_EPHEMERAL
                        || entry.capability_type
                            == najwa_protocol::contact::mailbox_key::CAP_TYPE_LONG_TERM;
                    if !supported {
                        tracing::warn!(
                            capability_type = entry.capability_type,
                            "skipping unsupported reciprocal mailbox capability"
                        );
                    }
                    supported
                });
                if usable_reciprocal.mailbox_entries.is_empty() {
                    // No contact is created because this client has no usable
                    // deposit route. A newer client or a new payload with a
                    // supported capability lets the legitimate user retry.
                    return Err(MessagingError::SerializationError(
                        "reciprocal handshake has no supported mailbox capability".into(),
                    ));
                }
                if reciprocal.ik_pub != sender_ik {
                    return Err(MessagingError::PseudonymMismatch);
                }
                let reciprocal_ik = Ed25519Public::from_bytes(&reciprocal.ik_pub)
                    .map_err(|e| MessagingError::SerializationError(e.to_string()))?;
                let (our_pseudonym, their_pseudonym) =
                    derive_pairwise_pseudonyms(&self.identity_key, &reciprocal_ik)
                        .map_err(|e| MessagingError::InternalError(e.to_string()))?;
                if temp_payload.sender_pseudonym != their_pseudonym.0 {
                    return Err(MessagingError::PseudonymMismatch);
                }
                self.storage
                    .create_reciprocal_contact(
                        &usable_reciprocal,
                        &our_pseudonym.0,
                        &their_pseudonym.0,
                    )
                    .await
                    .map_err(MessagingError::StorageError)?
            }
            None => return Err(MessagingError::UnknownPseudonym),
        };

        // 8. GUARD (S08 §4.3 I4 + crossing tiebreak). Read the session of the
        //    contact the commit will OVERWRITE (the pseudonym-resolved one), so the
        //    guard and the overwrite target the same session even when the sender's
        //    IK is not (yet) mapped to a contact.
        let existing_state = self
            .storage
            .get_ratchet_state(contact.id)
            .await
            .map_err(MessagingError::StorageError)?;
        if let Some(state) = &existing_state {
            if state.ckr.is_none() {
                // We hold an UN-ANSWERED outbound Initial (no receiving chain yet;
                // `dhs` is our EK_A). This is a crossing Initial — resolve by the
                // larger-EK_pub tiebreak REGARDLESS of is_repair (a "repair always
                // wins" rule would let simultaneous repairs cross again). If ours is
                // larger, keep our session (peer adopts ours); else adopt theirs
                // (the commit overwrites ours).
                if state.dhs.public().to_bytes() > x3dh_header.ephemeral_key.to_bytes() {
                    tracing::info!(
                        "crossing Initial: our EK_pub larger — keeping local session (S08 §4.3)"
                    );
                    return Err(MessagingError::KeepLocalSession);
                }
                tracing::info!(
                    "crossing Initial: peer EK_pub larger — adopting incoming session (S08 §4.3)"
                );
            } else if is_repair {
                // Advanced session + a genuine SessionRepairInit → re-establish (the
                // commit overwrites the desynced session). This is the case the old
                // pre-decrypt guard permanently (and wrongly) rejected.
                tracing::info!(
                    contact_id = contact.id,
                    "accepting SessionRepairInit — re-establishing session (S08 §4.3)"
                );
            } else {
                // Advanced session + a plain Initial → duplicate / replay / redundant
                // multi-path copy. Drop WITHOUT clobbering (nothing persisted here).
                tracing::debug!(
                    contact_id = contact.id,
                    "ignoring Initial for an advanced session (S08 §4.3 I4): duplicate/replay"
                );
                return Err(MessagingError::DuplicateMessage);
            }
        }

        Ok(AcceptedInitial {
            contact,
            plaintext,
            state: session,
            ad,
            opk_id,
        })
    }

    /// Try to decrypt with an existing ratchet session (S08 §4.4).
    ///
    /// Uses DH ratchet public key from the header as a lookup hint for O(1)
    /// session identification. Falls back to trial decryption if hint misses.
    /// Trial-decrypt against existing sessions. On success returns the contact,
    /// the plaintext, the contact id, and the **advanced ratchet state** — but
    /// does NOT persist it. The caller commits the advanced state atomically
    /// together with the message and dedup mark (S06 §3.11 I3) via
    /// `commit_received`, so a crash mid-receive cannot advance the ratchet
    /// without durably storing the message. (A message that is ultimately
    /// rejected — e.g. pseudonym mismatch — is never committed, so the ratchet
    /// advance is correctly discarded rather than applied to a forged frame.)
    pub(crate) async fn decrypt_with_existing_session(
        &self,
        ratchet_header: &RatchetHeader,
        encrypted_payload: &[u8],
        wire_prefix: &[u8],
    ) -> Result<(Contact, Vec<u8>, ContactId, RatchetState)> {
        let dh_pub_bytes = ratchet_header.dh_pub.to_bytes();
        // A `TooManySkipped` counts only from the session the header names:
        // same epoch (`dh_pub == DHr`) or the next (non-zero `epoch_link == DHr`).
        // Every other session also fails on a frame that is not its own, and a
        // `MissedEpochBoundary` names no session at all, so neither is surfaced
        // (S06 §3.7.1). Anything else stays `NoMatchingSession` (quarantine).
        let names = |state: &RatchetState| {
            let dhr = state.dhr.as_ref().map(|k| k.to_bytes());
            dhr == Some(dh_pub_bytes)
                || (ratchet_header.epoch_link != [0u8; 32] && dhr == Some(ratchet_header.epoch_link))
        };
        let mut desync = None;

        // Fast path: look up session by DH public key from header (S08 §4.4)
        if let Some((contact_id, session)) = self
            .storage
            .get_ratchet_state_by_dh_pub(&dh_pub_bytes)
            .await
            .map_err(MessagingError::StorageError)?
        {
            let contact = self
                .storage
                .get_contact(contact_id)
                .await
                .map_err(MessagingError::StorageError)?
                .ok_or(MessagingError::ContactNotFound)?;

            let ad = self
                .storage
                .get_session_ad(contact_id)
                .await
                .map_err(MessagingError::StorageError)?
                .unwrap_or_default();

            // Clone before trial decrypt (S08 §4.4)
            let mut trial_session = clone_ratchet_state(&session);
            match ratchet_decrypt(
                &mut trial_session,
                ratchet_header,
                encrypted_payload,
                &ad,
                wire_prefix,
            ) {
                // Do NOT persist here — the caller commits the advanced state
                // atomically with the message + dedup (I3).
                Ok(plaintext) => return Ok((contact, plaintext, contact_id, trial_session)),
                Err(e @ RatchetError::TooManySkipped { .. })
                    if !contact.blocked && names(&session) =>
                {
                    desync = Some(e)
                }
                Err(_) => {}
            }
        }

        // Slow path: trial decryption across all contacts
        let contacts = self
            .storage
            .list_contacts()
            .await
            .map_err(MessagingError::StorageError)?;

        for contact in &contacts {
            if contact.blocked {
                continue; // Skip blocked contacts (S08 §7.1)
            }
            if let Some(session) = self
                .storage
                .get_ratchet_state(contact.id)
                .await
                .map_err(MessagingError::StorageError)?
            {
                let ad = self
                    .storage
                    .get_session_ad(contact.id)
                    .await
                    .map_err(MessagingError::StorageError)?
                    .unwrap_or_default();

                // CRITICAL: Clone before trial to prevent state corruption (S08 §4.4)
                let mut trial_session = clone_ratchet_state(&session);
                match ratchet_decrypt(
                    &mut trial_session,
                    ratchet_header,
                    encrypted_payload,
                    &ad,
                    wire_prefix,
                ) {
                    // Deferred persistence — committed atomically by the caller (I3).
                    Ok(plaintext) => {
                        return Ok((contact.clone(), plaintext, contact.id, trial_session))
                    }
                    Err(e @ RatchetError::TooManySkipped { .. }) if names(&session) => {
                        desync = Some(e)
                    }
                    Err(_) => {}
                }
            }
        }

        Err(desync.map_or(MessagingError::NoMatchingSession, Into::into))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x3dh_header_roundtrip_with_opk() {
        let ik = najwa_crypto::keys::ed25519::Ed25519KeyPair::from_seed(&[0x01; 32]);
        let ek = X25519KeyPair::generate(&mut rand::thread_rng());
        let header = X3DHHeader {
            identity_key: ik.public().clone(),
            ephemeral_key: ek.public().clone(),
            device_key: ik.public().clone(),
            signed_prekey_id: [0xAA, 0xBB, 0xCC, 0xDD],
            used_one_time_prekey_id: Some([0x11, 0x22, 0x33, 0x44]),
        };

        let bytes = serialize_x3dh_header(&header);
        assert_eq!(bytes.len(), 105); // S06 §2.4: 105 bytes with OPK

        let (parsed, consumed) = deserialize_x3dh_header(&bytes).unwrap();
        assert_eq!(consumed, 105);
        assert_eq!(parsed.identity_key.to_bytes(), ik.public().to_bytes());
        assert_eq!(parsed.ephemeral_key.to_bytes(), ek.public().to_bytes());
        assert_eq!(parsed.device_key.to_bytes(), ik.public().to_bytes());
        assert_eq!(parsed.signed_prekey_id, [0xAA, 0xBB, 0xCC, 0xDD]);
        assert_eq!(
            parsed.used_one_time_prekey_id,
            Some([0x11, 0x22, 0x33, 0x44])
        );
    }

    #[test]
    fn x3dh_header_roundtrip_without_opk() {
        let ik = najwa_crypto::keys::ed25519::Ed25519KeyPair::from_seed(&[0x02; 32]);
        let ek = X25519KeyPair::generate(&mut rand::thread_rng());
        let header = X3DHHeader {
            identity_key: ik.public().clone(),
            ephemeral_key: ek.public().clone(),
            device_key: ik.public().clone(),
            signed_prekey_id: [0, 0, 0, 1],
            used_one_time_prekey_id: None,
        };

        let bytes = serialize_x3dh_header(&header);
        assert_eq!(bytes.len(), 101); // S06 §2.4: 101 bytes without OPK

        let (parsed, consumed) = deserialize_x3dh_header(&bytes).unwrap();
        assert_eq!(consumed, 101);
        assert_eq!(parsed.device_key.to_bytes(), ik.public().to_bytes());
        assert!(parsed.used_one_time_prekey_id.is_none());
    }

    #[test]
    fn x3dh_header_too_short_rejected() {
        assert!(deserialize_x3dh_header(&[0u8; 100]).is_err());
    }
    #[test]
    fn mailbox_signer_is_separate_from_authenticated_dh_identity() {
        use najwa_crypto::keys::ed25519::Ed25519KeyPair;
        let alice = Ed25519KeyPair::from_seed(&[1;32]);
        let bob = Ed25519KeyPair::from_seed(&[2;32]);
        let signer = Ed25519KeyPair::from_seed(&[3;32]);
        let spk = X25519KeyPair::from_seed([4;32]);
        let bundle = najwa_protocol::mailbox::types::PrekeyBundle {
            identity_key: signer.public().to_bytes(), signed_prekey: spk.public().to_bytes(),
            signed_prekey_id: 5, signed_prekey_timestamp: 100,
            signed_prekey_signature: signer.sign(&najwa_protocol::x3dh::types::spk_signature_message(
                &spk.public().to_bytes(), &5u32.to_be_bytes(),100)).to_bytes().to_vec(),
            one_time_prekeys: vec![], manifest: Some(najwa_protocol::x3dh::types::build_wire_manifest(
                &signer, &5u32.to_be_bytes(), &[],100)),
        };
        let converted = mailbox_bundle_to_x3dh(&bundle,&bob.public().to_bytes(),&signer.public().to_bytes()).unwrap();
        let result = x3dh_initiate(&alice,&converted).unwrap();
        let response = x3dh_respond(&bob,&spk,None,&result.header).unwrap();
        assert_eq!(result.shared_secret,response.shared_secret);
    }

    #[test]
    fn exhausted_bundle_served_without_opk_field_takes_signed_3dh_fallback() {
        // S06 §2.2 1b: the server omits `one_time_prekeys` when it serves none
        // (S16 §3.7). With a signed opk_count = 0 that is the 3-DH fallback.
        use najwa_crypto::keys::ed25519::Ed25519KeyPair;
        let alice = Ed25519KeyPair::from_seed(&[11; 32]);
        let bob = Ed25519KeyPair::from_seed(&[12; 32]);
        let signer = Ed25519KeyPair::from_seed(&[13; 32]);
        let spk = X25519KeyPair::from_seed([14; 32]);
        let signed = najwa_protocol::mailbox::types::PrekeyBundle {
            identity_key: signer.public().to_bytes(), signed_prekey: spk.public().to_bytes(),
            signed_prekey_id: 5, signed_prekey_timestamp: 100,
            signed_prekey_signature: signer.sign(&najwa_protocol::x3dh::types::spk_signature_message(
                &spk.public().to_bytes(), &5u32.to_be_bytes(), 100)).to_bytes().to_vec(),
            one_time_prekeys: vec![], manifest: Some(najwa_protocol::x3dh::types::build_wire_manifest(
                &signer, &5u32.to_be_bytes(), &[], 100)),
        };
        let mut served = serde_json::to_value(&signed).unwrap();
        served.as_object_mut().unwrap().remove("one_time_prekeys");
        let bundle: najwa_protocol::mailbox::types::PrekeyBundle =
            serde_json::from_value(served).expect("server bundle without OPKs must parse");
        let converted = mailbox_bundle_to_x3dh(&bundle, &bob.public().to_bytes(), &signer.public().to_bytes()).unwrap();
        assert!(converted.one_time_prekey.is_none());
        let result = x3dh_initiate(&alice, &converted).unwrap();
        assert!(result.header.used_one_time_prekey_id.is_none(), "3-DH header carries no OPK id");
        let response = x3dh_respond(&bob, &spk, None, &result.header).unwrap();
        assert_eq!(result.shared_secret, response.shared_secret);
    }

}
