use std::{path::PathBuf, process::Command};
struct Profiles(Vec<PathBuf>);
impl Drop for Profiles {
    fn drop(&mut self) {
        for path in &self.0 {
            if let Ok(bytes) = std::fs::read(path.join("identity.najwa")) {
                if let Ok(record) = najwa_identity::IdentityRecordStandard::from_bytes(&bytes) {
                    let _ = najwa_identity::platform::delete_record_dkm(&record);
                }
            }
        }
    }
}
#[test]
#[ignore = "requires a live onion mailbox, built bundled UI and an installed browser"]
fn browser_to_browser_over_public_tor_with_persistent_restart() {
    let onion = std::env::var("NAJWA_MAILBOX_ONION").expect("public development mailbox hostname");
    let executable = std::env::var_os("NAJWA_WEB_TEST_EXE").expect("bundled native executable");
    let directory = tempfile::tempdir().unwrap();
    let profiles = Profiles(vec![
        directory.path().join("alice"),
        directory.path().join("bob"),
    ]);
    let project = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../desktop");
    let output = std::env::var_os("NAJWA_LIVE_REPORT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/live-release-check")
        });
    let status = Command::new("node")
        .current_dir(project)
        .arg("local-web/live-messaging.mjs")
        .arg(executable)
        .arg(onion)
        .arg(&profiles.0[0])
        .arg(&profiles.0[1])
        .arg(output)
        .status()
        .unwrap();
    assert!(
        status.success(),
        "see live-release-check/result.json for the failed stage"
    );
}
