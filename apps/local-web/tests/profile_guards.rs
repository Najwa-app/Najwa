use fs2::FileExt;
use std::{
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

fn launch(profile: &Path, assets: &Path, test_override: bool) -> Child {
    let executable = std::env::var_os("NAJWA_WEB_TEST_EXE")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_najwa-web").into());
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let mut command = Command::new(executable);
    command
        .args([
            "--no-browser",
            "--profile",
            profile.to_str().unwrap(),
            "--assets",
            assets.to_str().unwrap(),
            "--port",
            &port.to_string(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if test_override {
        command.env("NAJWA_DKM_FILE", profile.join("forbidden-test-key"));
    }
    command.spawn().unwrap()
}
fn rejected(mut child: Child) {
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(!status.success());
            return;
        }
        if Instant::now() >= until {
            let _ = child.kill();
            let _ = child.wait();
            panic!("unsafe profile startup must be refused");
        }
        std::thread::sleep(Duration::from_millis(30));
    }
}
#[test]
fn startup_obeys_the_shared_profile_lease_erasure_marker_and_real_keystore_policy() {
    let temp = tempfile::tempdir().unwrap();
    let profile = temp.path().join("profile");
    let assets = temp.path().join("ui");
    std::fs::create_dir(&profile).unwrap();
    std::fs::create_dir(&assets).unwrap();
    std::fs::write(assets.join("index.html"), "<html>test</html>").unwrap();
    let lease = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(profile.join("owner.lock"))
        .unwrap();
    lease.try_lock_exclusive().unwrap();
    rejected(launch(&profile, &assets, false));
    drop(lease);
    std::fs::write(profile.join("wipe.pending"), b"synthetic pending erasure").unwrap();
    rejected(launch(&profile, &assets, false));
    std::fs::remove_file(profile.join("wipe.pending")).unwrap();
    rejected(launch(&profile, &assets, true));
    assert!(!profile.join("identity.najwa").exists());
    assert!(!profile.join("forbidden-test-key").exists());
}
