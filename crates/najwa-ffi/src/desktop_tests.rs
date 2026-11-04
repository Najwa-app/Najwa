use crate::{
    callback,
    desktop::*,
    state::{self, state_cell, AppState},
};
use najwa_crypto::keys::Ed25519KeyPair;
use najwa_identity::record::Identity;

#[test]
fn pending_deposits_includes_the_received_introductions_unprepared_reply() {
    use najwa_storage::types::{NewContact, NewContactMailboxCap, RatchetState};
    let dir = tempfile::tempdir().unwrap();
    let db = state::open_storage(dir.path(), &crate::state::test_key(14)).unwrap();
    let cid = db.create_contact(&NewContact {
        pseudonym: [1; 32], their_ik_pub: [2; 32], their_device_pub: [2; 32],
        our_pseudonym: [3; 32], display_name: Some("Incoming introduction".into()),
    }).unwrap();
    let mid = db.save_mailbox(&NewMailbox::with_cover_caps(
        "a".repeat(56), vec![1; 32], vec![2; 32], 0, now() as i64,
    )).unwrap();
    db.set_setting(&format!("desktop:mailbox:{mid}"), &true).unwrap();
    db.save_ratchet_state(cid, &RatchetState {
        dhs_private: Some(vec![1; 32]), dhs_public: Some(vec![2; 32]),
        dhr: Some(vec![3; 32]), rk: Some(vec![4; 32]), cks: Some(vec![5; 32]),
        ckr: Some(vec![6; 32]), ns: 0, nr: 0, pn: 0,
        prev_dhs_pub: None,
        established_at: 1, last_activity: 1,
    }).unwrap();
    assert_eq!(db.pending_deposit_count().unwrap(), 0);
    assert_eq!(pending_deposits(&db).unwrap(), 1, "reply preparation must count before any frame or local receive path exists");
    db.save_contact_capability(&NewContactMailboxCap {
        contact_id: cid, mailbox_id: mid, deposit_capability: vec![7; 32],
        fetch_capability: Some(vec![8; 32]), envelope_secret: Some(vec![9; 32]),
        their_deposit_capability: None, their_envelope_secret: None,
        capability_type: 2, expires_at: None, registered_at: None, created_at: 1,
    }).unwrap();
    let cap = db.get_contact_capabilities(cid).unwrap()[0].id;
    assert_eq!(pending_deposits(&db).unwrap(), 1, "an unregistered receive path is still preparing");
    db.mark_contact_capability_registered(cap, now() as i64).unwrap();
    assert_eq!(pending_deposits(&db).unwrap(), 1, "registering a path does not announce it to the other person");
    let marker = announcement_marker(cid, &local_configs(&db, cid).unwrap());
    complete_announcement(&db, cid, &marker).unwrap();
    assert_eq!(pending_deposits(&db).unwrap(), 0);
    db.set_contact_blocked(cid, true).unwrap();
    db.delete_setting(&format!("desktop:announced-current:{cid}")).unwrap();
    assert_eq!(pending_deposits(&db).unwrap(), 0, "blocked contacts do not prepare replies");
    db.set_contact_blocked(cid, false).unwrap();
    assert_eq!(pending_deposits(&db).unwrap(), 1, "unblocking restores the unannounced reply obligation");
}

#[test]
fn invitation_acceptance_is_durable_while_offline_and_network_admission_is_busy() {
    let _serial = callback::tests::test_lock().lock().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let db = state::open_storage(directory.path(), &crate::state::test_key(14)).unwrap();
    db.save_mailbox(&NewMailbox::with_cover_caps(
        "a".repeat(56),
        vec![1; 32],
        vec![2; 32],
        0,
        now() as i64,
    ))
    .unwrap();
    let mut app = AppState::new(directory.path().into()).unwrap();
    app.identity = Some(Identity {
        keypair: Ed25519KeyPair::from_seed(&[7; 32]),
        created_at: 1,
        version: 2,
    });
    app.db_key = Some(crate::state::test_key(14));
    app.storage = Some(db.clone());
    *state_cell().write().unwrap() = Some(app);
    assert!(state::allow_operations());
    assert!(!NETWORK_BUSY.swap(true, Ordering::SeqCst));
    let _admission = NetworkAdmission;
    let peer = Ed25519KeyPair::from_seed(&[8; 32]);
    let payload = HandshakePayload::create(
        &peer,
        &[MailboxConfig::new("b".repeat(56), [3; 32], [4; 32])],
        "Offline peer",
        24,
    )
    .unwrap();
    let invitation = payload.to_uri().unwrap();
    let started = std::time::Instant::now();
    let accepted = DesktopClient.accept_invitation(&invitation, "Local person", false);
    assert!(accepted.is_ok(), "offline acceptance must save locally instead of waiting for network admission: {accepted:?}");
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
    let contact = accepted.unwrap().parse::<i64>().unwrap();
    assert_eq!(
        db.get_setting::<String>(&format!("desktop:reciprocal:{contact}"))
            .unwrap()
            .as_deref(),
        Some("Local person")
    );
    assert!(db.get_ratchet_state(contact).unwrap().is_none());
    assert_eq!(
        DesktopClient.status().pending_deposits,
        Some(1),
        "saved introductions count as work before an Initial frame exists"
    );
    assert_eq!(
        DesktopClient
            .accept_invitation(&invitation, "Local person", false)
            .unwrap(),
        contact.to_string()
    );
    assert_eq!(db.list_contacts().unwrap().len(), 1);
    DesktopClient.lock().unwrap();
    assert_eq!(
        DesktopClient
            .accept_invitation(&invitation, "Local person", false)
            .unwrap_err()
            .code,
        "locked"
    );
    drop(state_cell().write().unwrap().take());
    drop(db);
    let reopened = state::open_storage(directory.path(), &crate::state::test_key(14)).unwrap();
    assert_eq!(
        reopened
            .get_setting::<String>(&format!("desktop:reciprocal:{contact}"))
            .unwrap()
            .as_deref(),
        Some("Local person")
    );
    assert_eq!(reopened.list_contacts().unwrap().len(), 1);
}

fn unlocked_test_state(directory: &std::path::Path) -> std::sync::Arc<najwa_storage::database::SqliteStorage> {
    let db = state::open_storage(directory, &crate::state::test_key(14)).unwrap();
    let mut app = AppState::new(directory.into()).unwrap();
    app.identity = Some(Identity { keypair: Ed25519KeyPair::from_seed(&[7; 32]), created_at: 1, version: 2 });
    app.db_key = Some(crate::state::test_key(14));
    app.storage = Some(db.clone());
    *state_cell().write().unwrap() = Some(app);
    assert!(state::allow_operations());
    db
}

#[test]
fn an_eleventh_contact_within_a_day_needs_explicit_confirmation() {
    use najwa_storage::types::NewContact;
    let _serial = callback::tests::test_lock().lock().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let db = unlocked_test_state(directory.path());
    db.save_mailbox(&NewMailbox::with_cover_caps("a".repeat(56), vec![1; 32], vec![2; 32], 0, now() as i64))
        .unwrap();
    for i in 0..10u8 {
        db.create_contact(&NewContact {
            pseudonym: [i; 32], their_ik_pub: [100 + i; 32], their_device_pub: [100 + i; 32],
            our_pseudonym: [50 + i; 32], display_name: None,
        }).unwrap();
    }
    let payload = HandshakePayload::create(
        &Ed25519KeyPair::from_seed(&[8; 32]),
        &[MailboxConfig::new("b".repeat(56), [3; 32], [4; 32])],
        "Eleventh peer",
        24,
    )
    .unwrap();
    let invitation = payload.to_uri().unwrap();
    let refused = DesktopClient.accept_invitation(&invitation, "Local person", false);
    assert_eq!(refused.unwrap_err().code, "contact_limit_confirm");
    assert_eq!(db.list_contacts().unwrap().len(), 10, "an unconfirmed attempt adds nothing");
    DesktopClient.accept_invitation(&invitation, "Local person", true).unwrap();
    assert_eq!(db.list_contacts().unwrap().len(), 11);
    // Retrying the same accepted invitation adds no contact and needs no confirmation.
    DesktopClient.accept_invitation(&invitation, "Local person", false).unwrap();
    DesktopClient.lock().unwrap();
    drop(state_cell().write().unwrap().take());
}

#[test]
fn recovery_prekey_obligation_ends_when_the_store_records_publication() {
    let _serial = callback::tests::test_lock().lock().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let db = unlocked_test_state(directory.path());
    assert!(!DesktopClient.prekey_recovery_pending().unwrap());
    let key: String = Ed25519KeyPair::from_seed(&[7; 32]).public().to_bytes().iter().map(|b| format!("{b:02x}")).collect();
    najwa_identity::atomic::atomic_write(&directory.path().join(format!("prekey-recovery-{key}")), &[5; 32]).unwrap();
    assert!(DesktopClient.prekey_recovery_pending().unwrap());
    // najwa-core records the completed generation; the marker file stays.
    db.set_setting_raw("prekeys:complete", &[5; 32]).unwrap();
    assert!(!DesktopClient.prekey_recovery_pending().unwrap());
    drop(state_cell().write().unwrap().take());
    assert_eq!(DesktopClient.prekey_recovery_pending().unwrap_err().code, "unavailable");
}

#[test]
fn contact_setup_distinguishes_unsent_expiry_from_an_unanswered_deposited_request() {
    use najwa_storage::types::{
        ContentType as StoredType, MessageDirection, MessageStatus, NewContact, NewMessage,
    };
    let directory = tempfile::tempdir().unwrap();
    let db = state::open_storage(directory.path(), &crate::state::test_key(14)).unwrap();
    let cid = db
        .create_contact(&NewContact {
            pseudonym: [1; 32],
            their_ik_pub: [2; 32],
            their_device_pub: [2; 32],
            our_pseudonym: [3; 32],
            display_name: Some("Pending peer".into()),
        })
        .unwrap();
    let peer = Ed25519KeyPair::from_seed(&[8; 32]);
    let payload = HandshakePayload::create(
        &peer,
        &[MailboxConfig::new("b".repeat(56), [3; 32], [4; 32])],
        "Pending peer",
        24,
    )
    .unwrap();
    db.set_setting_raw(&format!("contact_handshake:{cid}"), &payload.to_bytes())
        .unwrap();
    db.set_setting(&format!("desktop:reciprocal:{cid}"), &"Local person")
        .unwrap();
    assert_eq!(
        contact_setup(&db, cid, false, payload.created_at)
            .unwrap()
            .state,
        "queued"
    );
    assert_eq!(
        contact_setup(&db, cid, false, payload.expires_at)
            .unwrap()
            .state,
        "expired"
    );
    let mid = db
        .save_message(&NewMessage {
            contact_id: cid,
            msg_id: [9; 16],
            direction: MessageDirection::Sent,
            content_type: StoredType::ReciprocalHandshake,
            flags: 0,
            content: payload.to_bytes(),
            file_path: None,
            timestamp: payload.created_at as i64,
            received_at: None,
            status: MessageStatus::Pending,
            reply_to_msg_id: None,
            disappear_timer: None,
            encrypted_blob: None,
            group_id: None,
            sender_display_name: None,
            origin_timestamp_ms: None,
            retry_wire_blob: None,
        })
        .unwrap();
    let expired = contact_setup(&db, cid, false, payload.expires_at).unwrap();
    assert_eq!(expired.state, "expired");
    assert_eq!(expired.expires_at, Some(payload.expires_at));
    assert_eq!(
        db.get_message(mid).unwrap().unwrap().status,
        MessageStatus::Pending,
        "reading progress must not mutate the queue"
    );
    assert!(retire_expired_setup(&db, cid, &expired).unwrap());
    assert_eq!(
        db.get_message(mid).unwrap().unwrap().status,
        MessageStatus::PermanentlyFailed
    );
    assert!(db
        .get_setting::<String>(&format!("desktop:reciprocal:{cid}"))
        .unwrap()
        .is_none());
    db.update_message_status(mid, MessageStatus::Sent).unwrap();
    assert!(
        !retire_expired_setup(&db, cid, &expired).unwrap(),
        "a concurrent successful deposit must win over an older expiry snapshot"
    );
    assert_eq!(
        contact_setup(&db, cid, false, payload.created_at)
            .unwrap()
            .state,
        "waiting"
    );
    let unanswered = contact_setup(&db, cid, false, payload.expires_at).unwrap();
    assert_eq!(unanswered.state, "unconfirmed");
    assert!(
        !retire_expired_setup(&db, cid, &unanswered).unwrap(),
        "a collected introduction can still receive a late valid confirmation"
    );
    assert_eq!(
        contact_setup(&db, cid, true, payload.expires_at)
            .unwrap()
            .state,
        "ready"
    );
    assert_eq!(
        db.list_contacts().unwrap().len(),
        1,
        "expiry must preserve the contact and its cryptographic state"
    );
}

#[test]
fn late_mailbox_announcement_completion_does_not_hide_a_new_primary_or_capability() {
    let dir = tempfile::tempdir().unwrap();
    let db = state::open_storage(dir.path(), &crate::state::test_key(14)).unwrap();
    db.create_contact(&najwa_storage::types::NewContact {
        pseudonym: [1; 32],
        their_ik_pub: [2; 32],
        their_device_pub: [2; 32],
        our_pseudonym: [3; 32],
        display_name: Some("Announcement fixture".into()),
    })
    .unwrap();
    let first = MailboxConfig::new("a".repeat(56), [1; 32], [2; 32]);
    let second = MailboxConfig::new("b".repeat(56), [3; 32], [4; 32]);
    let old_order = vec![first.clone(), second.clone()];
    let new_order = vec![second.clone(), first.clone()];
    let in_flight = announcement_marker(1, &old_order);
    let current = announcement_marker(1, &new_order);
    // The old network request completes AFTER the user changed their primary.
    complete_announcement(&db, 1, &in_flight).unwrap();
    assert!(
        !announcement_is_current(&db, 1, &current).unwrap(),
        "the next sync must advertise the new primary"
    );
    complete_announcement(&db, 1, &current).unwrap();
    assert!(announcement_is_current(&db, 1, &current).unwrap());
    assert!(
        !announcement_is_current(&db, 1, &in_flight).unwrap(),
        "returning to the previous primary must advertise it again"
    );
    complete_announcement(&db, 1, &in_flight).unwrap();
    assert!(announcement_is_current(&db, 1, &in_flight).unwrap());
    assert!(
        !announcement_is_current(&db, 1, &current).unwrap(),
        "a late old completion cannot hide the current primary"
    );
    assert_eq!(
        announcement_marker(1, &old_order),
        in_flight,
        "retries of the exact set reuse completion"
    );
    let mut rotated = new_order;
    rotated[0].deposit_capability = [8; 32];
    assert!(
        !announcement_is_current(&db, 1, &announcement_marker(1, &rotated)).unwrap(),
        "capability rotation cannot reuse an older completion"
    );
    assert!(
        !announcement_is_current(&db, 2, &in_flight).unwrap(),
        "another contact has its own completion"
    );
    assert_ne!(
        announcement_marker(1, std::slice::from_ref(&first)),
        in_flight,
        "adding a mailbox requires an updated advertisement"
    );
    assert_ne!(
        announcement_marker(2, &old_order),
        in_flight,
        "completion is contact-scoped"
    );
}

#[test]
fn invitations_include_registered_mailboxes_in_selected_order_and_reuse_saved_pairs() {
    let _serial = callback::tests::test_lock().lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let db = state::open_storage(dir.path(), &crate::state::test_key(14)).unwrap();
    let timestamp = now();
    let mut saved = Vec::new();
    for (offset, letter) in [(0, 'a'), (1, 'b')] {
        let id = db
            .save_mailbox(&NewMailbox::with_cover_caps(
                letter.to_string().repeat(56),
                random_bytes::<32>().to_vec(),
                random_bytes::<32>().to_vec(),
                0,
                timestamp as i64 + offset,
            ))
            .unwrap();
        db.set_setting(&format!("desktop:mailbox:{id}"), &true)
            .unwrap();
        db.mark_cover_capabilities_registered(id, timestamp as i64)
            .unwrap();
        let fetch = random_bytes::<32>();
        let deposit = random_bytes::<32>();
        let expiry = timestamp + EPHEMERAL_CAP_TTL_SECS - offset as u64 * 60;
        let cap = db
            .save_ephemeral_handshake_cap(&NewEphemeralHandshakeCap {
                mailbox_id: id,
                deposit_capability: deposit.to_vec(),
                fetch_capability: fetch.to_vec(),
                envelope_secret: random_bytes::<32>().to_vec(),
                capability_type: 1,
                created_at: timestamp as i64 - offset * 60,
                expires_at: expiry as i64,
            })
            .unwrap();
        db.mark_ephemeral_handshake_cap_registered(cap, timestamp as i64)
            .unwrap();
        db.set_setting(&format!("desktop:invite:{id}"), &cap)
            .unwrap();
        db.set_setting(&format!("desktop:invite-wire:{cap}"), &1u8)
            .unwrap();
        let primary: [u8; 32] = db
            .get_mailbox(id)
            .unwrap()
            .unwrap()
            .fetch_capability
            .try_into()
            .unwrap();
        for scope in [primary, fetch] {
            db.set_setting(
                &najwa_storage::prekey_lifecycle::prekey_scope_setting("last", &scope),
                &timestamp,
            )
            .unwrap();
        }
        saved.push((id, deposit, expiry));
    }
    let pending = db
        .save_mailbox(&NewMailbox::with_cover_caps(
            "c".repeat(56),
            vec![1; 32],
            vec![2; 32],
            0,
            timestamp as i64,
        ))
        .unwrap();
    db.disable_mailbox(pending).unwrap();
    db.set_setting("desktop:primary", &"b".repeat(56)).unwrap();
    db.set_setting("desktop:responsive", &true).unwrap();
    let mut app = AppState::new(dir.path().into()).unwrap();
    app.identity = Some(Identity {
        keypair: Ed25519KeyPair::from_seed(&[7; 32]),
        created_at: 1,
        version: 2,
    });
    app.db_key = Some(crate::state::test_key(14));
    app.storage = Some(db);
    let handle = app.runtime.handle().clone();
    {
        let _entered = handle.enter();
        crate::install_connected_service(
            &mut app,
            Arc::new(HttpMailboxClient::new(Arc::new(NoNetwork))),
        )
        .unwrap();
    }
    *state_cell().write().unwrap() = Some(app);
    assert!(state::allow_operations());
    let uri = DesktopClient.invitation("Test Alice").unwrap();
    let payload = HandshakePayload::from_uri(&uri).unwrap();
    payload.verify().unwrap();
    assert_eq!(
        payload.mailbox_entries.len(),
        2,
        "incomplete setup is excluded"
    );
    assert_eq!(
        payload.mailbox_entries[0].onion_address,
        "b".repeat(56).as_bytes()
    );
    assert_eq!(
        payload.expires_at, saved[1].2,
        "earliest capability deadline bounds the entire invitation"
    );
    assert_eq!(payload.mailbox_entries[0].deposit_capability, saved[1].1);
    assert_eq!(payload.mailbox_entries[1].deposit_capability, saved[0].1);
    let db = state_cell().read().unwrap().as_ref().unwrap().storage.clone().unwrap();
    for (id, _, _) in &saved {
        assert!(
            db.get_setting::<i64>(&format!("desktop:invite:{id}")).unwrap().is_none(),
            "an exported queue is never handed to a later invitation"
        );
    }
    DesktopClient.lock().unwrap();
    drop(state_cell().write().unwrap().take());
}

#[test]
fn delivery_preference_is_live_and_survives_service_reinstallation() {
    let _serial = callback::tests::test_lock().lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let db = state::open_storage(dir.path(), &crate::state::test_key(14)).unwrap();
    let mut app = AppState::new(dir.path().into()).unwrap();
    app.identity = Some(Identity {
        keypair: Ed25519KeyPair::from_seed(&[7; 32]),
        created_at: 1,
        version: 2,
    });
    app.db_key = Some(crate::state::test_key(14));
    app.storage = Some(db.clone());
    let client = Arc::new(HttpMailboxClient::new(Arc::new(NoNetwork)));
    let handle = app.runtime.handle().clone();
    {
        let _entered = handle.enter();
        crate::install_connected_service(&mut app, client.clone()).unwrap();
    }
    assert!(
        !app.cover.as_ref().unwrap().scheduler.slot_source().bypass(),
        "non-desktop ABI policy remains paced"
    );
    *state_cell().write().unwrap() = Some(app);
    assert!(state::allow_operations());
    DesktopClient.set_delivery_mode("responsive").unwrap();
    assert_eq!(DesktopClient.status().delivery_mode, "responsive");
    assert_eq!(
        db.get_setting::<bool>("desktop:responsive").unwrap(),
        Some(true)
    );
    {
        let mut cell = state_cell().write().unwrap();
        let app = cell.as_mut().unwrap();
        let _entered = handle.enter();
        crate::install_connected_service(app, client).unwrap();
        assert!(app.cover.as_ref().unwrap().scheduler.slot_source().bypass());
    }
    DesktopClient.set_delivery_mode("privacy").unwrap();
    assert_eq!(DesktopClient.status().delivery_mode, "privacy");
    assert!(!state_cell()
        .read()
        .unwrap()
        .as_ref()
        .unwrap()
        .cover
        .as_ref()
        .unwrap()
        .scheduler
        .slot_source()
        .bypass());
    assert_eq!(
        DesktopClient.set_delivery_mode("unknown").unwrap_err().code,
        "invalid_request"
    );
    DesktopClient.lock().unwrap();
    assert_eq!(
        DesktopClient
            .set_delivery_mode("responsive")
            .unwrap_err()
            .code,
        "locked"
    );
    let app = state_cell().write().unwrap().take();
    drop(app);
}

#[test]
fn mailbox_selection_and_backfill_keep_unregistered_coordinates_private() {
    let _serial = callback::tests::test_lock().lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let db = state::open_storage(dir.path(), &crate::state::test_key(14)).unwrap();
    let contact = db
        .create_contact(&najwa_storage::types::NewContact {
            pseudonym: [1; 32],
            their_ik_pub: [2; 32],
            their_device_pub: [3; 32],
            our_pseudonym: [4; 32],
            display_name: Some("Test peer".into()),
        })
        .unwrap();
    let first = db
        .save_mailbox(&NewMailbox::with_cover_caps(
            "a".repeat(56),
            vec![1; 32],
            vec![2; 32],
            0,
            1,
        ))
        .unwrap();
    let second = db
        .save_mailbox(&NewMailbox::with_cover_caps(
            "b".repeat(56),
            vec![3; 32],
            vec![4; 32],
            0,
            2,
        ))
        .unwrap();
    db.set_setting(&format!("desktop:mailbox:{first}"), &true)
        .unwrap();
    extend_contact_mailboxes(&db).unwrap();
    let original = db.get_contact_capabilities(contact).unwrap();
    assert_eq!(original.len(), 1);
    assert!(original[0].registered_at.is_none());
    assert!(
        local_configs(&db, contact).unwrap().is_empty(),
        "never advertise an unregistered pair"
    );
    extend_contact_mailboxes(&db).unwrap();
    assert_eq!(
        db.get_contact_capabilities(contact).unwrap()[0].deposit_capability,
        original[0].deposit_capability,
        "retries reuse exact coordinates"
    );
    db.set_setting(&format!("desktop:mailbox:{second}"), &true)
        .unwrap();
    extend_contact_mailboxes(&db).unwrap();
    let caps = db.get_contact_capabilities(contact).unwrap();
    assert_eq!(caps.len(), 2);
    for cap in &caps {
        db.mark_contact_capability_registered(cap.id, 1).unwrap();
    }
    db.set_setting(&format!("desktop:announced:{contact}"), &true)
        .unwrap();
    let mut app = AppState::new(dir.path().into()).unwrap();
    app.identity = Some(Identity {
        keypair: Ed25519KeyPair::from_seed(&[7; 32]),
        created_at: 1,
        version: 2,
    });
    app.storage = Some(db.clone());
    *state_cell().write().unwrap() = Some(app);
    assert!(state::allow_operations());
    DesktopClient
        .select_mailbox(&format!("{}.onion", "b".repeat(56)))
        .unwrap();
    assert!(DesktopClient.status().mailbox_details[1].primary);
    assert_eq!(
        local_configs(&db, contact).unwrap()[0].onion_address,
        "b".repeat(56)
    );
    assert_eq!(
        db.get_setting::<bool>(&format!("desktop:announced:{contact}"))
            .unwrap(),
        None,
        "selection schedules authenticated mailbox updates"
    );
    assert_eq!(
        DesktopClient
            .select_mailbox(&format!("{}.onion", "c".repeat(56)))
            .unwrap_err()
            .code,
        "mailbox_required"
    );
    db.disable_mailbox(first).unwrap();
    assert_eq!(
        DesktopClient.status().mailbox_details.len(),
        2,
        "incomplete setup remains visible for retry"
    );
    assert_eq!(
        DesktopClient
            .forget_mailbox(&format!("{}.onion", "a".repeat(56)))
            .unwrap_err()
            .code,
        "mailbox_in_use"
    );
    let incomplete = db
        .save_mailbox(&NewMailbox::with_cover_caps(
            "c".repeat(56),
            vec![5; 32],
            vec![6; 32],
            0,
            3,
        ))
        .unwrap();
    db.disable_mailbox(incomplete).unwrap();
    DesktopClient
        .forget_mailbox(&format!("{}.onion", "c".repeat(56)))
        .unwrap();
    assert!(db.get_mailbox(incomplete).unwrap().is_none());
    assert_eq!(DesktopClient.status().mailbox_details.len(), 2);
    drop(state_cell().write().unwrap().take());
}

#[test]
fn uri_invitation_retries_reject_legacy_and_nearly_expired_slots() {
    let created_at = 1_700_000_000;
    let uri_expiry = created_at + EPHEMERAL_CAP_TTL_SECS as i64;
    assert_eq!(uri_expiry - created_at, 48 * 3600);
    assert!(reusable_invitation_window(
        created_at, uri_expiry, created_at
    ));
    assert!(reusable_invitation_window(
        created_at,
        uri_expiry,
        uri_expiry - 601
    ));
    assert!(!reusable_invitation_window(
        created_at,
        uri_expiry,
        uri_expiry - 600
    ));
    assert!(!reusable_invitation_window(
        created_at,
        uri_expiry,
        uri_expiry - 42
    ));
    assert!(!reusable_invitation_window(
        created_at, uri_expiry, uri_expiry
    ));
    assert!(!reusable_invitation_window(
        created_at,
        created_at + 900,
        created_at
    ));
}

#[test]
fn registration_errors_distinguish_retryable_conditions_and_rejections() {
    use najwa_transport::error::TransportError;
    let cases = [
        (
            MailboxError::TransportError(TransportError::CircuitFailed("test timeout".into())),
            "registration_transport",
        ),
        (MailboxError::PowTimeout, "registration_pow"),
        (MailboxError::RateLimited, "registration_limited"),
        (MailboxError::ServerError(409), "registration_conflict"),
        (MailboxError::ServerError(503), "registration_server"),
        (MailboxError::ServerError(400), "registration_rejected"),
    ];
    for (error, code) in cases {
        let public = registration_error("invitation_submission", error);
        assert_eq!(public.code, code);
        let encoded = serde_json::to_string(&public).unwrap();
        assert!(!encoded.contains("test timeout"));
        assert!(!encoded.contains("invitation_submission"));
    }
}

struct NoNetwork;

struct MaintenanceFailure {
    healthy_fetches: std::sync::atomic::AtomicUsize,
}
#[async_trait::async_trait]
impl najwa_protocol::mailbox::client::Transport for MaintenanceFailure {
    async fn get_circuit(
        &self,
        isolation: najwa_transport::circuit::CircuitIsolation,
    ) -> std::result::Result<
        najwa_transport::circuit::CircuitHandle,
        najwa_transport::error::TransportError,
    > {
        Ok(najwa_transport::circuit::CircuitHandle::new(isolation))
    }
    async fn post(
        &self,
        _: &najwa_transport::circuit::CircuitHandle,
        url: &str,
        _: &[u8],
        _: &str,
    ) -> std::result::Result<
        najwa_transport::http::HttpResponse,
        najwa_transport::error::TransportError,
    > {
        let healthy_fetch = url.ends_with("/v1/fetch") && url.contains(&"a".repeat(56));
        if healthy_fetch {
            self.healthy_fetches.fetch_add(1, Ordering::SeqCst);
        }
        Ok(najwa_transport::http::HttpResponse {
            status: if healthy_fetch { 200 } else { 404 },
            headers: std::collections::HashMap::new(),
            body: if healthy_fetch {
                br#"{"messages":[],"has_more":false}"#.to_vec()
            } else {
                b"{}".to_vec()
            },
        })
    }
    async fn get(
        &self,
        circuit: &najwa_transport::circuit::CircuitHandle,
        url: &str,
    ) -> std::result::Result<
        najwa_transport::http::HttpResponse,
        najwa_transport::error::TransportError,
    > {
        self.post(circuit, url, &[], "application/json").await
    }
}

#[test]
fn failed_mailbox_maintenance_does_not_starve_healthy_receive_routes() {
    let _serial = callback::tests::test_lock().lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let db = state::open_storage(dir.path(), &crate::state::test_key(14)).unwrap();
    for (index, letter) in ['a', 'b'].into_iter().enumerate() {
        let id = db
            .save_mailbox(&NewMailbox::with_cover_caps(
                letter.to_string().repeat(56),
                random_bytes::<32>().to_vec(),
                random_bytes::<32>().to_vec(),
                0,
                index as i64,
            ))
            .unwrap();
        db.set_setting(&format!("desktop:mailbox:{id}"), &true)
            .unwrap();
        db.mark_cover_capabilities_registered(id, now() as i64)
            .unwrap();
    }
    db.set_setting("desktop:responsive", &true).unwrap();
    let transport = Arc::new(MaintenanceFailure {
        healthy_fetches: std::sync::atomic::AtomicUsize::new(0),
    });
    let mut app = AppState::new(dir.path().into()).unwrap();
    app.identity = Some(Identity {
        keypair: Ed25519KeyPair::from_seed(&[7; 32]),
        created_at: 1,
        version: 2,
    });
    app.db_key = Some(crate::state::test_key(14));
    app.storage = Some(db);
    let handle = app.runtime.handle().clone();
    {
        let _entered = handle.enter();
        crate::install_connected_service(
            &mut app,
            Arc::new(HttpMailboxClient::new(transport.clone())),
        )
        .unwrap();
    }
    *state_cell().write().unwrap() = Some(app);
    assert!(state::allow_operations());
    assert_eq!(
        DesktopClient.sync().unwrap_err().code,
        "sync_failed",
        "setup errors must remain visible"
    );
    assert!(
        transport.healthy_fetches.load(Ordering::SeqCst) > 0,
        "read healthy routes even when prekey maintenance fails"
    );
    DesktopClient.lock().unwrap();
    drop(state_cell().write().unwrap().take());
}

#[async_trait::async_trait]
impl najwa_protocol::mailbox::client::Transport for NoNetwork {
    async fn get_circuit(
        &self,
        _: najwa_transport::circuit::CircuitIsolation,
    ) -> std::result::Result<
        najwa_transport::circuit::CircuitHandle,
        najwa_transport::error::TransportError,
    > {
        panic!("local outbox operation attempted network work")
    }
    async fn post(
        &self,
        _: &najwa_transport::circuit::CircuitHandle,
        _: &str,
        _: &[u8],
        _: &str,
    ) -> std::result::Result<
        najwa_transport::http::HttpResponse,
        najwa_transport::error::TransportError,
    > {
        panic!("local outbox operation attempted network work")
    }
    async fn get(
        &self,
        _: &najwa_transport::circuit::CircuitHandle,
        _: &str,
    ) -> std::result::Result<
        najwa_transport::http::HttpResponse,
        najwa_transport::error::TransportError,
    > {
        panic!("local outbox operation attempted network work")
    }
}

struct PausedNetwork(std::sync::mpsc::Sender<()>);
#[async_trait::async_trait]
impl najwa_protocol::mailbox::client::Transport for PausedNetwork {
    async fn get_circuit(
        &self,
        _: najwa_transport::circuit::CircuitIsolation,
    ) -> std::result::Result<
        najwa_transport::circuit::CircuitHandle,
        najwa_transport::error::TransportError,
    > {
        self.0.send(()).unwrap();
        std::future::pending().await
    }
    async fn post(
        &self,
        _: &najwa_transport::circuit::CircuitHandle,
        _: &str,
        _: &[u8],
        _: &str,
    ) -> std::result::Result<
        najwa_transport::http::HttpResponse,
        najwa_transport::error::TransportError,
    > {
        unreachable!()
    }
    async fn get(
        &self,
        _: &najwa_transport::circuit::CircuitHandle,
        _: &str,
    ) -> std::result::Result<
        najwa_transport::http::HttpResponse,
        najwa_transport::error::TransportError,
    > {
        unreachable!()
    }
}

#[test]
fn prepare_wipe_destroys_unlocked_owners_and_cover_without_persisting_keys() {
    use std::sync::Arc;
    let _serial = callback::tests::test_lock().lock().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let mut app = AppState::new(directory.path().into()).unwrap();
    let db = state::open_storage(directory.path(), &crate::state::test_key(14)).unwrap();
    let weak_db = Arc::downgrade(&db);
    let cache = app.disappearing_keys.clone();
    cache.insert_key(&[1; 16], [2; 32]);
    let client = Arc::new(HttpMailboxClient::new(Arc::new(NoNetwork)));
    let weak_client = Arc::downgrade(&client);
    {
        let _entered = app.runtime.enter();
        app.cover = Some(crate::cover::CoverRuntime::start(
            client,
            Default::default(),
        ));
    }
    assert!(app.cover.as_ref().unwrap().scheduler.is_running());
    let mut service = state::FfiService::new(
        Ed25519KeyPair::from_seed(&[7; 32]),
        najwa_storage::database::SqliteStorage::open(&directory.path().join("najwa.db"), &[14; 32])
            .unwrap(),
        HttpMailboxClient::new(Arc::new(NoNetwork)),
    );
    service.set_volatile_cache(cache.clone());
    let service = Arc::new(service);
    let weak_service = Arc::downgrade(&service);
    *app.service.lock().unwrap() = Some(service);
    app.identity = Some(Identity {
        keypair: Ed25519KeyPair::from_seed(&[7; 32]),
        created_at: 1,
        version: 2,
    });
    app.db_key = Some(crate::state::test_key(14));
    app.storage = Some(db);
    *state_cell().write().unwrap() = Some(app);
    assert!(state::allow_operations());
    let targets = DesktopClient.prepare_wipe().unwrap();
    assert!(state_cell().read().unwrap().is_none());
    assert!(cache.is_empty());
    assert!(weak_db.upgrade().is_none());
    assert!(weak_service.upgrade().is_none());
    assert!(weak_client.upgrade().is_none());
    assert!(state::OperationGuard::acquire().is_none());
    let reopened = state::open_storage(directory.path(), &crate::state::test_key(14)).unwrap();
    assert!(reopened.get_all_volatile_keys().unwrap().is_empty());
    drop(targets);
    drop(reopened);
}

/// Records every deactivation as (onion, base64 fetch); mailbox `down` answers 503.
struct DeactivationNetwork {
    seen: std::sync::Mutex<Vec<(String, String)>>,
    down: String,
}
#[async_trait::async_trait]
impl najwa_protocol::mailbox::client::Transport for DeactivationNetwork {
    async fn get_circuit(
        &self,
        isolation: najwa_transport::circuit::CircuitIsolation,
    ) -> std::result::Result<
        najwa_transport::circuit::CircuitHandle,
        najwa_transport::error::TransportError,
    > {
        Ok(najwa_transport::circuit::CircuitHandle::new(isolation))
    }
    async fn post(
        &self,
        _: &najwa_transport::circuit::CircuitHandle,
        url: &str,
        body: &[u8],
        _: &str,
    ) -> std::result::Result<
        najwa_transport::http::HttpResponse,
        najwa_transport::error::TransportError,
    > {
        assert!(url.ends_with(".onion/v1/capability/deactivate"), "{url}");
        let onion = url.trim_start_matches("http://")[..56].to_owned();
        let body: serde_json::Value = serde_json::from_slice(body).unwrap();
        let fetch = body["fetch_capability"].as_str().unwrap().to_owned();
        self.seen.lock().unwrap().push((onion.clone(), fetch));
        Ok(najwa_transport::http::HttpResponse {
            status: if onion == self.down { 503 } else { 200 },
            headers: std::collections::HashMap::new(),
            body: br#"{"status":"deactivated","messages_deleted":0}"#.to_vec(),
        })
    }
    async fn get(
        &self,
        _: &najwa_transport::circuit::CircuitHandle,
        _: &str,
    ) -> std::result::Result<
        najwa_transport::http::HttpResponse,
        najwa_transport::error::TransportError,
    > {
        unreachable!()
    }
}

#[test]
fn unlocked_wipe_deactivates_every_capability_and_reports_the_failed_mailbox() {
    use base64::Engine;
    use najwa_storage::types::{NewContact, NewContactMailboxCap};
    let _serial = callback::tests::test_lock().lock().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let mut app = AppState::new(directory.path().into()).unwrap();
    let db = state::open_storage(directory.path(), &crate::state::test_key(14)).unwrap();
    let (a, b) = ("a".repeat(56), "b".repeat(56));
    let a_id = db.save_mailbox(&NewMailbox::with_cover_caps(a.clone(), vec![1; 32], vec![2; 32], 0, now() as i64)).unwrap();
    let invitation = db.save_ephemeral_handshake_cap(&NewEphemeralHandshakeCap {
        mailbox_id: a_id, deposit_capability: vec![3; 32], fetch_capability: vec![4; 32],
        envelope_secret: vec![0; 32], capability_type: 1,
        created_at: now() as i64, expires_at: now() as i64 + 3600,
    }).unwrap();
    db.mark_ephemeral_handshake_cap_registered(invitation, now() as i64).unwrap();
    let b_id = db.save_mailbox(&NewMailbox::with_cover_caps(b.clone(), vec![5; 32], vec![6; 32], 1, now() as i64)).unwrap();
    let contact = db.create_contact(&NewContact {
        pseudonym: [1; 32], their_ik_pub: [2; 32], their_device_pub: [2; 32],
        our_pseudonym: [3; 32], display_name: Some("Contact".into()),
    }).unwrap();
    db.save_contact_capability(&NewContactMailboxCap {
        contact_id: contact, mailbox_id: b_id, deposit_capability: vec![7; 32],
        fetch_capability: Some(vec![8; 32]), envelope_secret: Some(vec![9; 32]),
        their_deposit_capability: None, their_envelope_secret: None,
        capability_type: 2, expires_at: None, registered_at: None, created_at: 1,
    }).unwrap();
    let bridge = "127.0.0.1:1 0123456789ABCDEF0123456789ABCDEF01234567";
    db.set_setting("desktop:local-preferences", &LocalPreferences { bridges: vec![bridge.into()], ..Default::default() }).unwrap();
    let encode = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
    let mut expected = vec![(a.clone(), encode(&[1; 32])), (a.clone(), encode(&[4; 32])),
        (b.clone(), encode(&[5; 32])), (b.clone(), encode(&[8; 32]))];
    for mailbox in db.list_mailboxes().unwrap() {
        expected.push((mailbox.onion_address.clone(), encode(mailbox.cover_fetch_capability.as_ref().unwrap())));
    }
    app.identity = Some(Identity { keypair: Ed25519KeyPair::from_seed(&[7; 32]), created_at: 1, version: 2 });
    app.db_key = Some(crate::state::test_key(14));
    app.storage = Some(db);
    *state_cell().write().unwrap() = Some(app);
    assert!(state::allow_operations());
    let targets = DesktopClient.prepare_wipe().unwrap();
    assert_eq!(targets.tor.as_ref().unwrap().bridges.len(), 1, "saved bridges, never direct Tor");
    let network = std::sync::Arc::new(DeactivationNetwork { seen: Default::default(), down: b.clone() });
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let report = tokio::runtime::Runtime::new().unwrap()
        .block_on(targets.deactivate(HttpMailboxClient::new(network.clone()), deadline));
    let mut seen = network.seen.lock().unwrap().clone();
    seen.sort();
    expected.sort();
    assert_eq!(seen, expected, "primary, cover, invitation and per-contact queues");
    assert_eq!(report, WipeReport { deactivated: vec![format!("{a}.onion")], unreachable: vec![format!("{b}.onion")] });
}

#[test]
fn locked_wipe_starts_no_tor_client() {
    let _serial = callback::tests::test_lock().lock().unwrap();
    let directory = tempfile::tempdir().unwrap();
    // Capabilities exist on disk, but a locked owner holds no storage handle.
    let db = state::open_storage(directory.path(), &crate::state::test_key(14)).unwrap();
    db.save_mailbox(&NewMailbox::with_cover_caps("a".repeat(56), vec![1; 32], vec![2; 32], 0, now() as i64)).unwrap();
    drop(db);
    *state_cell().write().unwrap() = Some(AppState::new(directory.path().into()).unwrap());
    assert!(state::allow_operations());
    let targets = DesktopClient.prepare_wipe().unwrap();
    let started = std::time::Instant::now();
    assert_eq!(targets.deactivate_best_effort(Duration::from_secs(20)), WipeReport::default());
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(!directory.path().join("tor").exists(), "no Tor client was started");
}

#[test]
fn typed_desktop_send_queues_during_network_work_and_rejects_after_lock() {
    use najwa_core::storage::CoreStorage;
    let _serial = callback::tests::test_lock().lock().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let mut app = AppState::new(directory.path().into()).unwrap();
    let db = state::open_storage(directory.path(), &crate::state::test_key(14)).unwrap();
    db.save_mailbox(&najwa_storage::types::NewMailbox {
        onion_address: "a".repeat(56),
        fetch_capability: vec![1; 32],
        deposit_capability: vec![2; 32],
        envelope_secret: vec![3; 32],
        cover_deposit_capability: None,
        cover_fetch_capability: None,
        cover_envelope_secret: None,
        priority: 0,
        created_at: now() as i64,
    })
    .unwrap();
    let identity = Identity {
        keypair: Ed25519KeyPair::from_seed(&[7; 32]),
        created_at: 1,
        version: 2,
    };
    let remote = Ed25519KeyPair::from_seed(&[8; 32]);
    let mut config = MailboxConfig::new("a".repeat(56), [4; 32], [5; 32]);
    config.envelope_secret = [6; 32];
    let payload = signed_long_term(&remote, &[config], "Synthetic peer").unwrap();
    let contact = app
        .runtime
        .block_on(accept_contact(&identity.keypair, &*db, &payload))
        .unwrap()
        .contact_id
        .0;
    let spk = najwa_crypto::keys::X25519KeyPair::from_seed([9; 32]);
    let ratchet =
        najwa_protocol::ratchet::init::init_alice(&[10; 32], spk.public(), &[11; 32]).unwrap();
    app.runtime
        .block_on(CoreStorage::save_ratchet_state(&*db, contact, &ratchet))
        .unwrap();
    app.runtime
        .block_on(CoreStorage::save_session_ad(
            &*db,
            contact,
            b"synthetic session AD",
        ))
        .unwrap();
    let service_db =
        std::sync::Arc::try_unwrap(state::open_storage(directory.path(), &crate::state::test_key(14)).unwrap())
            .ok()
            .unwrap();
    let mut service = state::FfiService::new(
        Ed25519KeyPair::from_seed(&[7; 32]),
        service_db,
        najwa_protocol::mailbox::http::HttpMailboxClient::new(std::sync::Arc::new(NoNetwork)),
    );
    service.set_volatile_cache(app.disappearing_keys.clone());
    *app.service.lock().unwrap() = Some(std::sync::Arc::new(service));
    app.identity = Some(identity);
    app.db_key = Some(crate::state::test_key(14));
    app.storage = Some(db.clone());
    *state_cell().write().unwrap() = Some(app);
    assert!(state::allow_operations());
    NETWORK_BUSY.store(true, Ordering::SeqCst);
    let network_admission = NetworkAdmission;
    let client = DesktopClient;
    let id = client
        .send(&contact.to_string(), "queued during sync")
        .unwrap();
    let rows = client.messages(&contact.to_string()).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].msg_id, id);
    assert_eq!(rows[0].status, "queued");
    assert_eq!(db.get_message(rows[0].id.parse().unwrap()).unwrap().unwrap().flags & 4, 4);
    assert_eq!(db.outgoing_frames().unwrap().len(), 1);
    assert_eq!(client.sync().unwrap_err().code, "busy");
    assert_eq!(
        client.set_timer(&contact.to_string(), 29).unwrap_err().code,
        "invalid_timer"
    );
    assert_eq!(db.get_conversation_timer(contact as i64).unwrap(), None);
    for _ in 0..5 {
        db.record_remote_mailbox(&"a".repeat(56), false).unwrap();
    }
    for _ in 0..5 {
        db.record_remote_mailbox(&"b".repeat(56), false).unwrap();
    }
    assert_eq!(
        client.status().retrying_mailboxes,
        vec![
            format!("{}.onion", "a".repeat(56)),
            format!("{}.onion", "b".repeat(56))
        ]
    );
    assert!(client.status().paused_mailboxes.is_empty());
    assert!(db.remote_mailbox_enabled(&"a".repeat(56)).unwrap());
    assert_eq!(
        db.outgoing_frames().unwrap().len(),
        1,
        "transport failures preserve the existing durable frame"
    );
    assert_eq!(
        client
            .retry_mailbox(&format!("{}.onion", "a".repeat(56)))
            .unwrap_err()
            .code,
        "mailbox_not_paused"
    );
    assert_eq!(client.status().retrying_mailboxes.len(), 2);
    assert!(
        db.remote_mailbox_enabled(&"b".repeat(56)).unwrap(),
        "temporary failures never disable delivery routes"
    );
    client.set_timer(&contact.to_string(), 30).unwrap();
    let first_timer = db
        .get_conversation_timer_setting(contact as i64)
        .unwrap()
        .unwrap();
    assert_eq!(first_timer.0, Some(30));
    assert_eq!(
        first_timer.2,
        Ed25519KeyPair::from_seed(&[7; 32]).public().to_bytes()
    );
    assert_eq!(client.contacts().unwrap()[0].timer_seconds, 30);
    assert!(client.contacts().unwrap()[0].timer_pending);
    assert_eq!(
        client
            .send(&contact.to_string(), "too early")
            .unwrap_err()
            .code,
        "timer_pending"
    );
    assert_eq!(
        client.set_timer(&contact.to_string(), 0).unwrap_err().code,
        "timer_pending"
    );
    let timer_frame = db.outgoing_frames().unwrap().last().unwrap().clone();
    {
        let cell = state_cell().read().unwrap();
        let runtime = &cell.as_ref().unwrap().runtime;
        let state = runtime
            .block_on(CoreStorage::get_ratchet_state(&*db, contact as u64))
            .unwrap()
            .unwrap();
        runtime
            .block_on(CoreStorage::commit_confirmation(
                &*db,
                contact as u64,
                &state,
                &[99; 16],
                &najwa_core::types::DeliveryConfirmation::Ack(vec![(
                    timer_frame.dh_pub,
                    timer_frame.n,
                    timer_frame.n,
                )]),
            ))
            .unwrap();
    }
    assert!(!client.contacts().unwrap()[0].timer_pending);
    client
        .send(&contact.to_string(), "timed after peer ACK")
        .unwrap();
    assert_eq!(
        db.get_message(2).unwrap().unwrap().disappear_timer,
        Some(30)
    );
    client.set_timer(&contact.to_string(), 0).unwrap();
    let off_timer = db
        .get_conversation_timer_setting(contact as i64)
        .unwrap()
        .unwrap();
    assert_eq!(off_timer.0, None);
    assert!(
        off_timer.1 > first_timer.1,
        "same-second changes carry increasing merge timestamps"
    );
    assert_eq!(
        client.messages(&contact.to_string()).unwrap().len(),
        2,
        "controls add no chat rows"
    );
    assert_eq!(
        db.get_message(rows[0].id.parse().unwrap())
            .unwrap()
            .unwrap()
            .disappear_timer,
        None,
        "existing messages keep their original timer"
    );
    assert_eq!(db.outgoing_frames().unwrap().len(), 3);
    let (entered, waiting) = std::sync::mpsc::channel();
    let service_db =
        std::sync::Arc::try_unwrap(state::open_storage(directory.path(), &crate::state::test_key(14)).unwrap())
            .ok()
            .unwrap();
    *state_cell()
        .read()
        .unwrap()
        .as_ref()
        .unwrap()
        .service
        .lock()
        .unwrap() = Some(std::sync::Arc::new(state::FfiService::new(
        Ed25519KeyPair::from_seed(&[7; 32]),
        service_db,
        najwa_protocol::mailbox::http::HttpMailboxClient::new(std::sync::Arc::new(PausedNetwork(
            entered,
        ))),
    )));
    let service_owner = {
        let cell = state_cell().read().unwrap();
        let service = cell.as_ref().unwrap().service.lock().unwrap();
        std::sync::Arc::downgrade(service.as_ref().unwrap())
    };
    let delivery = std::thread::spawn(|| DesktopClient.flush_outbox());
    waiting.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(client.flush_outbox().unwrap_err().code, "busy");
    client.lock().unwrap();
    assert!(delivery.join().unwrap().is_err());
    assert!(
        service_owner.upgrade().is_none(),
        "lock drops the worker's unlocked service owner"
    );
    assert!(!OUTBOX_BUSY.load(Ordering::SeqCst));
    assert_eq!(
        db.outgoing_frames().unwrap().len(),
        3,
        "cancellation retains the durable frame"
    );
    drop(network_admission);
    assert_eq!(
        client
            .retry_mailbox(&format!("{}.onion", "a".repeat(56)))
            .unwrap_err()
            .code,
        "locked"
    );
    assert_eq!(
        client
            .send(&contact.to_string(), "after lock")
            .unwrap_err()
            .code,
        "locked"
    );
    drop(state_cell().write().unwrap().take());
}

#[test]
fn typed_desktop_fetch_is_side_effect_free_and_lock_cancels_admission() {
    let _serial = callback::tests::test_lock().lock().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let mut app = AppState::new(directory.path().into()).unwrap();
    let db = state::open_storage(directory.path(), &crate::state::test_key(14)).unwrap();
    let timestamp = najwa_crypto::time::now();
    let contact = db
        .create_contact(&najwa_storage::types::NewContact {
            pseudonym: [1; 32],
            their_ik_pub: Ed25519KeyPair::from_seed(&[2; 32]).public().to_bytes(),
            their_device_pub: [2; 32],
            our_pseudonym: [3; 32],
            display_name: Some("fixture".into()),
        })
        .unwrap();
    let id = db
        .save_message(&najwa_storage::types::NewMessage {
            contact_id: contact,
            msg_id: [4; 16],
            direction: najwa_storage::types::MessageDirection::Received,
            content_type: najwa_storage::types::ContentType::Text,
            flags: 0,
            content: b"synthetic message".to_vec(),
            timestamp: timestamp as i64,
            status: najwa_storage::types::MessageStatus::Delivered,
            file_path: None,
            received_at: None,
            reply_to_msg_id: None,
            disappear_timer: None,
            encrypted_blob: None,
            group_id: None,
            sender_display_name: None,
            origin_timestamp_ms: None,
            retry_wire_blob: None,
        })
        .unwrap();
    app.identity = Some(Identity {
        keypair: Ed25519KeyPair::from_seed(&[7; 32]),
        created_at: 1,
        version: 2,
    });
    app.db_key = Some(crate::state::test_key(14));
    app.storage = Some(db.clone());
    *state_cell().write().unwrap() = Some(app);
    assert!(state::allow_operations());
    let client = DesktopClient;
    assert_eq!(
        client.messages(&contact.to_string()).unwrap()[0].timestamp,
        timestamp
    );
    assert_eq!(client.contacts().unwrap()[0].unread, 1);
    assert_eq!(
        client.messages(&contact.to_string()).unwrap()[0].text,
        "synthetic message"
    );
    assert_eq!(db.get_message(id).unwrap().unwrap().read_at, None);
    client
        .displayed(&contact.to_string(), &[id.to_string()])
        .unwrap();
    assert!(db.get_message(id).unwrap().unwrap().read_at.is_some());
    let number = client.contacts().unwrap()[0].safety_number.clone();
    assert!(client.verify(&contact.to_string(), "wrong", true).is_err());
    client.verify(&contact.to_string(), &number, true).unwrap();
    assert!(client.contacts().unwrap()[0].verified);
    for invalid in ["0", "-1", "9223372036854775808", "1x"] {
        assert!(client.messages(invalid).is_err());
    }
    assert!(client.displayed("1", &vec!["1".into(); 201]).is_err());
    client.lock().unwrap();
    assert!(!client.status().unlocked);
    assert_eq!(client.contacts().unwrap_err().code, "locked");
    assert_eq!(
        client.messages(&contact.to_string()).unwrap_err().code,
        "locked"
    );
    drop(state_cell().write().unwrap().take());
}

#[test]
fn reciprocal_stays_valid_until_the_invitation_queue_it_answers_expires() {
    // S05 §8.2: the invitation queue predates acceptance and lives one TTL, so a
    // creator who first fetches the Initial just before that expiry accepts it.
    let peer = Ed25519KeyPair::from_seed(&[8; 32]);
    let payload = signed_long_term(
        &peer,
        &[MailboxConfig::new("a".repeat(56), [4; 32], [5; 32])],
        "Late peer",
    )
    .unwrap();
    payload
        .verify_at(payload.created_at + EPHEMERAL_CAP_TTL_SECS)
        .unwrap();
}

/// One in-memory mailbox shared by every profile: S16 §3 shapes, no PoW, no
/// release delay. Unknown queues read as empty and swallow deposits.
#[derive(Default)]
struct MemoryMailbox(std::sync::Mutex<MemoryQueues>);
#[derive(Default)]
struct MemoryQueues {
    owners: std::collections::HashMap<[u8; 32], [u8; 32]>,
    bundles: std::collections::HashMap<[u8; 32], najwa_protocol::mailbox::types::PrekeyBundle>,
    blobs: std::collections::HashMap<[u8; 32], Vec<najwa_protocol::mailbox::types::MailboxMessage>>,
    next: u64,
}
#[async_trait::async_trait]
impl najwa_protocol::mailbox::client::Transport for MemoryMailbox {
    async fn get_circuit(
        &self,
        isolation: najwa_transport::circuit::CircuitIsolation,
    ) -> std::result::Result<
        najwa_transport::circuit::CircuitHandle,
        najwa_transport::error::TransportError,
    > {
        Ok(najwa_transport::circuit::CircuitHandle::new(isolation))
    }
    async fn post(
        &self,
        _: &najwa_transport::circuit::CircuitHandle,
        url: &str,
        body: &[u8],
        _: &str,
    ) -> std::result::Result<
        najwa_transport::http::HttpResponse,
        najwa_transport::error::TransportError,
    > {
        use najwa_protocol::mailbox::types::*;
        use serde_json::{from_slice, json, to_vec};
        let mut q = self.0.lock().unwrap();
        let reply = match &url[url.find("/v1/").unwrap_or(0)..] {
            "/v1/challenge" => to_vec(&PowChallenge {
                challenge: vec![0; 32],
                difficulty: 0,
                algorithm: "sha256-leading-zeros".into(),
                expires_at: u64::MAX,
            }).ok(),
            "/v1/capability/register" => {
                let r: RegisterCapabilityRequest = from_slice(body).unwrap();
                q.owners.insert(r.deposit_capability, r.fetch_capability);
                to_vec(&json!({"status": "ok"})).ok()
            }
            "/v1/prekey/upload" => {
                let r: UploadPrekeyRequest = from_slice(body).unwrap();
                q.bundles.insert(r.deposit_capability, r.bundle);
                to_vec(&json!({"status": "ok"})).ok()
            }
            "/v1/prekey/fetch" => {
                let r: FetchPrekeyRequest = from_slice(body).unwrap();
                q.bundles.get(&r.deposit_capability).cloned().map(|mut bundle| {
                    // A type-1 queue serves the same cached OPK to every fetch.
                    bundle.one_time_prekeys.truncate(1);
                    to_vec(&bundle).unwrap()
                })
            }
            "/v1/status" => {
                let r: StatusRequest = from_slice(body).unwrap();
                let ids: Vec<u32> = q
                    .owners
                    .iter()
                    .find(|(_, fetch)| **fetch == r.fetch_capability)
                    .and_then(|(deposit, _)| q.bundles.get(deposit))
                    .map(|b| b.one_time_prekeys.iter().map(|k| k.id).collect())
                    .unwrap_or_default();
                to_vec(&CapabilityStatus {
                    messages_stored: 0,
                    quota_remaining: 0,
                    oldest_message_age: 0,
                    prekey_count: ids.len() as u32,
                    prekey_ids: ids,
                }).ok()
            }
            "/v1/deposit" => {
                let r: DepositRequest = from_slice(body).unwrap();
                q.next += 1;
                let id = q.next.to_string();
                if let Some(fetch) = q.owners.get(&r.deposit_capability).copied() {
                    q.blobs.entry(fetch).or_default().push(MailboxMessage {
                        id: id.clone(),
                        size: r.blob.len() as u32,
                        blob: r.blob,
                        deposited_at: now(),
                        cap_hint: None,
                    });
                }
                to_vec(&DepositResult { accepted: true, message_id: Some(id) }).ok()
            }
            "/v1/fetch" => {
                let r: FetchRequest = from_slice(body).unwrap();
                let messages = q.blobs.get(&r.fetch_capability).cloned().unwrap_or_default();
                to_vec(&FetchResponse { messages, has_more: false }).ok()
            }
            "/v1/acknowledge" => {
                let r: AcknowledgeRequest = from_slice(body).unwrap();
                if let Some(blobs) = q.blobs.get_mut(&r.fetch_capability) {
                    blobs.retain(|m| !r.message_ids.contains(&m.id));
                }
                to_vec(&json!({"status": "ok"})).ok()
            }
            "/v1/capability/deactivate" => {
                let r: DeactivateRequest = from_slice(body).unwrap();
                q.blobs.remove(&r.fetch_capability);
                q.owners.retain(|_, fetch| *fetch != r.fetch_capability);
                to_vec(&json!({"messages_deleted": 0})).ok()
            }
            _ => None,
        };
        Ok(najwa_transport::http::HttpResponse {
            status: if reply.is_some() { 200 } else { 404 },
            headers: Default::default(),
            body: reply.unwrap_or_else(|| b"{}".to_vec()),
        })
    }
    async fn get(
        &self,
        circuit: &najwa_transport::circuit::CircuitHandle,
        url: &str,
    ) -> std::result::Result<
        najwa_transport::http::HttpResponse,
        najwa_transport::error::TransportError,
    > {
        self.post(circuit, url, &[], "application/json").await
    }
}

/// An unlocked, connected profile whose primary mailbox is already set up.
fn memory_profile(
    directory: &std::path::Path,
    seed: u8,
    onion: char,
    network: &Arc<MemoryMailbox>,
) -> AppState {
    let db = state::open_storage(directory, &crate::state::test_key(14)).unwrap();
    let id = db
        .save_mailbox(&NewMailbox::with_cover_caps(
            onion.to_string().repeat(56),
            random_bytes::<32>().to_vec(),
            random_bytes::<32>().to_vec(),
            0,
            now() as i64,
        ))
        .unwrap();
    db.set_setting(&format!("desktop:mailbox:{id}"), &true).unwrap();
    db.mark_cover_capabilities_registered(id, now() as i64).unwrap();
    db.set_setting("desktop:responsive", &true).unwrap();
    let mut app = AppState::new(directory.into()).unwrap();
    app.identity = Some(Identity {
        keypair: Ed25519KeyPair::from_seed(&[seed; 32]),
        created_at: 1,
        version: 2,
    });
    app.db_key = Some(crate::state::test_key(14));
    app.storage = Some(db);
    let handle = app.runtime.handle().clone();
    {
        let _entered = handle.enter();
        crate::install_connected_service(
            &mut app,
            Arc::new(HttpMailboxClient::new(network.clone())),
        )
        .unwrap();
    }
    app
}

#[test]
fn two_outstanding_invitations_each_complete_their_own_contact() {
    let _serial = callback::tests::test_lock().lock().unwrap();
    let network = Arc::new(MemoryMailbox::default());
    let directories: Vec<_> = (0..3).map(|_| tempfile::tempdir().unwrap()).collect();
    let creator = memory_profile(directories[0].path(), 21, 'c', &network);
    let creator_db = creator.storage.clone().unwrap();
    *state_cell().write().unwrap() = Some(creator);
    assert!(state::allow_operations());
    // Both invitations are outstanding before either person answers.
    let invitations = [
        DesktopClient.invitation("Creator").unwrap(),
        DesktopClient.invitation("Creator").unwrap(),
    ];
    let creator = state_cell().write().unwrap().take().unwrap();
    let mut acceptors = Vec::new();
    for (index, invitation) in invitations.iter().enumerate() {
        let acceptor = memory_profile(
            directories[index + 1].path(),
            22 + index as u8,
            ['d', 'e'][index],
            &network,
        );
        *state_cell().write().unwrap() = Some(acceptor);
        DesktopClient
            .accept_invitation(invitation, ["First friend", "Second friend"][index], false)
            .unwrap();
        // Registers the reply route and deposits the reciprocal Initial.
        DesktopClient.sync().unwrap();
        acceptors.push(state_cell().write().unwrap().take().unwrap());
    }
    *state_cell().write().unwrap() = Some(creator);
    DesktopClient.sync().unwrap();
    let mut names: Vec<_> = creator_db
        .list_contacts()
        .unwrap()
        .into_iter()
        .filter_map(|contact| contact.display_name)
        .collect();
    names.sort();
    assert_eq!(
        names,
        ["First friend", "Second friend"],
        "each outstanding invitation completes its own contact"
    );
    DesktopClient.lock().unwrap();
    drop(state_cell().write().unwrap().take());
    drop(acceptors);
}

#[test]
fn receive_poll_gaps_are_exponential_not_a_fixed_period() {
    use std::time::Duration;
    let gaps: Vec<Duration> = (0..200).map(|_| next_poll_gap()).collect();
    let distinct: std::collections::HashSet<_> = gaps.iter().collect();
    assert!(distinct.len() > 100, "poll gaps repeat a fixed period");
    assert!(gaps.iter().all(|gap| *gap >= Duration::from_secs(1)));
    let mean = gaps.iter().sum::<Duration>() / 200;
    assert!(mean > Duration::from_secs(2) && mean < Duration::from_millis(4500), "mean {mean:?}");
}

/// Records the circuit of every fetch and counts acknowledgements.
#[derive(Default)]
struct LockedFetches {
    fetches: std::sync::Mutex<Vec<najwa_transport::circuit::CircuitIsolation>>,
    acks: std::sync::atomic::AtomicUsize,
}
#[async_trait::async_trait]
impl najwa_protocol::mailbox::client::Transport for LockedFetches {
    async fn get_circuit(
        &self,
        isolation: najwa_transport::circuit::CircuitIsolation,
    ) -> std::result::Result<najwa_transport::circuit::CircuitHandle, najwa_transport::error::TransportError> {
        Ok(najwa_transport::circuit::CircuitHandle::new(isolation))
    }
    async fn post(
        &self,
        circuit: &najwa_transport::circuit::CircuitHandle,
        url: &str,
        _: &[u8],
        _: &str,
    ) -> std::result::Result<najwa_transport::http::HttpResponse, najwa_transport::error::TransportError> {
        if url.ends_with("/v1/fetch") {
            self.fetches.lock().unwrap().push(circuit.isolation.clone());
        } else if url.ends_with("/v1/acknowledge") {
            self.acks.fetch_add(1, Ordering::SeqCst);
        }
        Ok(najwa_transport::http::HttpResponse {
            status: 200,
            headers: Default::default(),
            body: br#"{"messages":[],"has_more":false}"#.to_vec(),
        })
    }
    async fn get(
        &self,
        _: &najwa_transport::circuit::CircuitHandle,
        _: &str,
    ) -> std::result::Result<najwa_transport::http::HttpResponse, najwa_transport::error::TransportError> {
        unreachable!()
    }
}

#[test]
fn locked_receive_worker_keeps_polling_its_selection_without_keys_or_storage() {
    use najwa_transport::circuit::CircuitIsolation;
    use std::sync::Arc;
    let _serial = callback::tests::test_lock().lock().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let mut app = AppState::new(directory.path().into()).unwrap();
    let db = state::open_storage(directory.path(), &crate::state::test_key(15)).unwrap();
    let onion = "b".repeat(56);
    let id = db
        .save_mailbox(&NewMailbox::with_cover_caps(onion.clone(), vec![1; 32], vec![2; 32], 0, 1))
        .unwrap();
    db.mark_cover_capabilities_registered(id, 1).unwrap();
    for n in 0..najwa_core::fetch_plan::DUMMY_CAPS_PER_MAILBOX as u8 {
        let row = db.save_dummy_capability(id, &[0x80 + n; 32], &[0x90 + n; 32]).unwrap();
        db.mark_dummy_capability_registered(row, 1).unwrap();
    }
    let network = Arc::new(LockedFetches::default());
    {
        let _entered = app.runtime.enter();
        app.cover = Some(crate::cover::CoverRuntime::start(
            Arc::new(HttpMailboxClient::new(network.clone())),
            najwa_core::cover::CoverTrafficConfig { enabled: false, ..Default::default() },
        ));
    }
    // The last refresh before the database closes, then the lock itself: the
    // unlock that started this worker was generation 7, the lock made it 8.
    app.cover.as_mut().unwrap().refresh(&db);
    drop(db);
    app.lifecycle_generation = 8;
    *state_cell().write().unwrap() = Some(app);
    let runtime = tokio::runtime::Runtime::new().unwrap();
    for _ in 0..3 {
        assert!(runtime.block_on(receive_tick(7)), "polling continues while locked");
        let fetches = std::mem::take(&mut *network.fetches.lock().unwrap());
        assert!((4..=10).contains(&fetches.len()), "{} fetches", fetches.len());
        assert!(fetches.iter().all(|c| matches!(c, CircuitIsolation::ByMailbox(o) if *o == onion)));
    }
    assert_eq!(network.acks.load(Ordering::SeqCst), 0, "a locked poll acknowledges nothing");
    // The next unlock starts its own worker; this one stops.
    state_cell().write().unwrap().as_mut().unwrap().lifecycle_generation = 9;
    assert!(!runtime.block_on(receive_tick(7)));
    drop(state_cell().write().unwrap().take());
}
