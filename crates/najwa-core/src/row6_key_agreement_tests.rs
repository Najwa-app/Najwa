#[tokio::test]
async fn row6_mailbox_cannot_replace_known_contact_identity() {
    let service = service_ready_to_send();
    let attacker = Ed25519KeyPair::from_seed(&[88; 32]);
    let spk = X25519KeyPair::from_seed([89; 32]);
    let opk = X25519KeyPair::from_seed([90; 32]);
    service
        .mailbox_client
        .set_prekey_bundle(make_prekey_bundle(&attacker, &spk, &opk, [1; 4], [2; 4]));
    let contact = service.storage.get_contact(1).await.unwrap().unwrap();
    assert!(service.create_session_candidate(&contact).await.is_err());
    assert!(service
        .storage
        .get_ratchet_state(1)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn row6_core_rejects_forged_manifest_before_session_creation() {
    let service = service_ready_to_send();
    let mut bundle = service
        .mailbox_client
        .prekey_bundle
        .lock()
        .unwrap()
        .clone()
        .unwrap();
    bundle.manifest = Some(najwa_protocol::x3dh::types::build_wire_manifest(
        &Ed25519KeyPair::from_seed(&[88; 32]),
        &bundle.signed_prekey_id.to_be_bytes(),
        &[bundle.one_time_prekeys[0].id],
        0,
    ));
    service.mailbox_client.set_prekey_bundle(bundle);
    let contact = service.storage.get_contact(1).await.unwrap().unwrap();
    assert!(service.create_session_candidate(&contact).await.is_err());
    assert!(service
        .storage
        .get_ratchet_state(1)
        .await
        .unwrap()
        .is_none());
}

#[test]
fn row6_x3dh_header_rejects_noncanonical_flag_and_trailing_data() {
    let ik = Ed25519KeyPair::from_seed(&[41; 32]);
    let header = najwa_protocol::x3dh::types::X3DHHeader {
        identity_key: ik.public().clone(),
        device_key: ik.public().clone(),
        ephemeral_key: X25519KeyPair::from_seed([42; 32]).public().clone(),
        signed_prekey_id: [1; 4],
        used_one_time_prekey_id: None,
    };
    let mut bytes = crate::session::serialize_x3dh_header(&header);
    bytes[100] = 2;
    assert!(crate::session::deserialize_x3dh_header(&bytes).is_err());
    bytes[100] = 0;
    bytes.push(0);
    assert!(crate::session::deserialize_x3dh_header(&bytes).is_err());
}

#[tokio::test]
async fn row6_storage_rejects_wrong_type_expired_and_consumed_prekeys() {
    let db = najwa_storage::database::SqliteStorage::open_in_memory(&[14; 32]).unwrap();
    let mut key = najwa_storage::types::Prekey {
        key_id: [1; 4],
        key_type: najwa_storage::types::PrekeyType::Opk,
        private_key: vec![2; 32],
        public_key: vec![3; 32],
        signature: None,
        created_at: 0,
        expires_at: None,
        used: false,
        used_at: None,
        mailbox_id: None,
    };
    db.save_prekey(&key).unwrap();
    assert!(CoreStorage::get_spk_keypair(&db, &key.key_id)
        .await
        .unwrap()
        .is_none());
    assert!(CoreStorage::get_opk_keypair(&db, &key.key_id)
        .await
        .unwrap()
        .is_some());
    key.key_type = najwa_storage::types::PrekeyType::Spk;
    db.save_prekey(&key).unwrap();
    assert!(CoreStorage::get_opk_keypair(&db, &key.key_id)
        .await
        .unwrap()
        .is_none());
    assert!(CoreStorage::get_spk_keypair(&db, &key.key_id)
        .await
        .unwrap()
        .is_some());
    key.expires_at = Some(1);
    db.save_prekey(&key).unwrap();
    assert!(CoreStorage::get_spk_keypair(&db, &key.key_id)
        .await
        .unwrap()
        .is_none());
    assert!(db.get_current_spk().unwrap().is_none());
    key.expires_at = None;
    key.used = true;
    db.save_prekey(&key).unwrap();
    assert!(CoreStorage::get_spk_keypair(&db, &key.key_id)
        .await
        .unwrap()
        .is_none());
}
