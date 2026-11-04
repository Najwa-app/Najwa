use najwa_storage::types::{Prekey, PrekeyType, RatchetState, SkippedKey};

#[test]
fn persisted_key_records_never_format_secret_bytes() {
    let ratchet = RatchetState {
        dhs_private: Some(vec![211; 32]),
        dhs_public: None,
        dhr: None,
        rk: Some(vec![211; 32]),
        cks: Some(vec![211; 32]),
        ckr: Some(vec![211; 32]),
        ns: 0,
        nr: 0,
        pn: 0,
        prev_dhs_pub: None,
        established_at: 0,
        last_activity: 0,
    };
    let skipped = SkippedKey {
        dh_pub: [0; 32],
        message_number: 0,
        message_key: [211; 32],
        created_at: 0,
        expires_at: 0,
    };
    let prekey = Prekey {
        key_id: [0; 4],
        key_type: PrekeyType::Opk,
        private_key: vec![211; 32],
        public_key: vec![0; 32],
        signature: None,
        created_at: 0,
        expires_at: None,
        used: false,
        used_at: None,
        mailbox_id: None,
    };
    for output in [
        format!("{ratchet:?}"),
        format!("{skipped:?}"),
        format!("{prekey:?}"),
    ] {
        assert!(!output.contains("211"), "secret key escaped into Debug");
    }
}
