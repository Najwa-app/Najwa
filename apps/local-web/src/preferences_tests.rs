use super::*;

#[test]
fn saved_timeout_drives_the_idle_deadline_and_lock_cannot_clear_wipe_state() {
    let _owner = TEST_OWNER.lock().unwrap_or_else(|p| p.into_inner());
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("index.html"), "Najwa").unwrap();
    let assets = crate::assets::Assets::resolve(Some(dir.path().into())).unwrap();
    let owner = Owner::open(&dir.path().join("profile"), assets, 1429).unwrap();
    owner.lock_timeout_seconds.store(60, Ordering::SeqCst);
    *owner.activity.lock().unwrap() = Instant::now() - std::time::Duration::from_secs(59);
    assert!(!owner.idle_expired());
    *owner.activity.lock().unwrap() = Instant::now() - std::time::Duration::from_secs(61);
    assert!(owner.idle_expired());
    owner.lock_timeout_seconds.store(900, Ordering::SeqCst);
    assert!(!owner.idle_expired());
    najwa_privacy::lifecycle::emergency::begin(&owner.directory).unwrap();
    owner.view.write().unwrap().phase = "wiping";
    let epoch = owner.begin_lock();
    assert_eq!(owner.finish_lock(epoch).map(|view| view.phase).unwrap_or("failed"), "wiping");
    assert!(owner.identity(&owner.status().session, epoch, IdentityOperation::Unlock { password: Secret(Zeroizing::new("synthetic".into())) }).is_err());
    drop(owner.client.prepare_wipe().unwrap());
}
