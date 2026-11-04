use std::io::Write;
use std::process::{Command, Output, Stdio};

fn run(dir: &std::path::Path, command: &[&str], password: Option<&str>) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_najwa-cli"));
    child
        .args(command)
        .arg(dir)
        .env("NAJWA_DKM_FILE", dir.join("test-dkm.hex"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if password.is_some() {
        child.arg("--password-stdin");
    }
    let mut child = child.spawn().unwrap();
    if let Some(password) = password {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(password.as_bytes())
            .unwrap();
    }
    child.wait_with_output().unwrap()
}

#[test]
fn process_restart_create_unlock_database_and_wrong_password() {
    let dir = tempfile::tempdir().unwrap();
    let weak = run(dir.path(), &["identity", "create"], Some("aaaaaaaaaaaa\n"));
    assert!(!weak.status.success());
    assert!(String::from_utf8_lossy(&weak.stderr).contains("too easy to guess"));
    assert!(!dir.path().join("identity.najwa").exists());
    for command in [
        ["identity", "create"],
        ["identity", "unlock"],
        ["db", "open"],
    ] {
        let output = run(dir.path(), &command, Some("harbor violet canyon thimble\n"));
        assert!(
            output.status.success(),
            "{:?}: {}",
            command,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert!(dir.path().join("najwa.db").exists());
    let exists = run(dir.path(), &["identity", "exists"], None);
    assert!(exists.status.success());
    assert_eq!(String::from_utf8(exists.stdout).unwrap().trim(), "true");
    let wrong = run(
        dir.path(),
        &["identity", "unlock"],
        Some("wrong password\n"),
    );
    assert!(!wrong.status.success());
    assert!(!String::from_utf8_lossy(&wrong.stderr).contains("wrong password"));
}
