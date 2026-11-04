use najwa_protocol::mailbox::types::PrekeyBundle;

#[test]
fn bundle_emits_spec_signer_name_and_accepts_previous_name() {
    let bundle = PrekeyBundle {
        identity_key: [1; 32],
        signed_prekey: [2; 32],
        signed_prekey_id: 3,
        signed_prekey_signature: vec![4; 64],
        signed_prekey_timestamp: 5,
        one_time_prekeys: vec![],
        manifest: None,
    };
    let mut value = serde_json::to_value(&bundle).unwrap();
    assert!(value.get("mailbox_ik_pub").is_some());
    assert!(value.get("identity_key").is_none());
    let public = value
        .as_object_mut()
        .unwrap()
        .remove("mailbox_ik_pub")
        .unwrap();
    value["identity_key"] = public;
    assert_eq!(
        serde_json::from_value::<PrekeyBundle>(value)
            .unwrap()
            .identity_key,
        [1; 32]
    );
}
