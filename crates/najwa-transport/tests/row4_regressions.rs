use najwa_transport::{
    circuit::{CircuitHandle, CircuitIsolation},
    version::{DistributionChannel, UpdateChecker},
};
use std::collections::{hash_map::DefaultHasher, HashSet};
use std::hash::{Hash, Hasher};

fn hash(value: &CircuitIsolation) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

#[test]
fn isolation_equality_and_hash_are_stable_when_handles_are_allocated() {
    for isolation in [
        CircuitIsolation::OneShot,
        CircuitIsolation::ByMailbox("a".into()),
        CircuitIsolation::CoverTraffic("a".into()),
        CircuitIsolation::ByContact([1; 32]),
    ] {
        assert_eq!(isolation, isolation.clone());
        let before = hash(&isolation);
        let mut set = HashSet::new();
        set.insert(isolation.clone());
        for _ in 0..20 {
            CircuitHandle::new(CircuitIsolation::OneShot);
        }
        assert_eq!(before, hash(&isolation));
        assert!(set.contains(&isolation));
    }
    assert_ne!(
        CircuitIsolation::ByMailbox("a".into()),
        CircuitIsolation::CoverTraffic("a".into())
    );
}

#[test]
fn direct_updates_require_a_configured_onion_endpoint() {
    let unconfigured = UpdateChecker::new(DistributionChannel::Direct);
    assert!(!unconfigured.needs_update_check());
    assert!(unconfigured.update_check_url().is_none());
    for url in [
        "http://updates.najwa.onion/v1/latest",
        "https://example.com/latest",
        "http://localhost/latest",
    ] {
        assert!(UpdateChecker::with_update_url(DistributionChannel::Direct, url.into()).is_err());
    }
    let url = format!("http://{}.onion:8080/v1/latest", "a".repeat(56));
    let direct = UpdateChecker::with_update_url(DistributionChannel::Direct, url.clone()).unwrap();
    assert!(direct.needs_update_check());
    assert_eq!(direct.update_check_url(), Some(url.as_str()));
    for distribution in [DistributionChannel::AppStore, DistributionChannel::FDroid] {
        let checker = UpdateChecker::with_update_url(distribution, url.clone()).unwrap();
        assert!(!checker.needs_update_check());
        assert!(checker.update_check_url().is_none());
    }
}
