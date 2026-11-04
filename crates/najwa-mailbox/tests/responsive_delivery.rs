use najwa_mailbox::{
    config::BatchingConfig,
    db::{models::CapabilitySettings, Database},
};

#[test]
fn default_and_partial_config_release_immediately_and_preserve_retry_idempotency() {
    for config in [
        BatchingConfig::default(),
        toml::from_str::<BatchingConfig>("min_hold_secs = 0").unwrap(),
    ] {
        let db = Database::open_in_memory().unwrap();
        db.register_capability(
            &[1; 32],
            &[2; 32],
            &CapabilitySettings::default(),
            2,
            None,
            172800,
            1000,
        )
        .unwrap();
        let first = db
            .deposit_message(&[1; 32], &[2; 32], b"encrypted test message", 1000, &config)
            .unwrap();
        let messages = db.fetch_messages(&[1; 32], 100, 1000).unwrap();
        assert_eq!(messages.len(), 1, "default policy adds no server hold");
        let retry = db
            .deposit_message(&[1; 32], &[2; 32], b"encrypted test message", 1001, &config)
            .unwrap();
        assert_eq!(
            first, retry,
            "lost-response retry reuses the deposited message"
        );
        assert_eq!(db.fetch_messages(&[1; 32], 100, 1001).unwrap().len(), 1);
    }
}

#[test]
fn explicit_timing_privacy_profile_retains_hold_and_jitter_bounds() {
    let config: BatchingConfig =
        toml::from_str("min_hold_secs = 30\nmax_hold_secs = 300\njitter_secs = 60").unwrap();
    let db = Database::open_in_memory().unwrap();
    db.register_capability(
        &[1; 32],
        &[2; 32],
        &CapabilitySettings::default(),
        2,
        None,
        172800,
        1000,
    )
    .unwrap();
    db.deposit_message(&[1; 32], &[2; 32], b"encrypted test message", 1000, &config)
        .unwrap();
    assert!(db.fetch_messages(&[1; 32], 100, 1029).unwrap().is_empty());
    assert_eq!(db.fetch_messages(&[1; 32], 100, 1360).unwrap().len(), 1);
}
