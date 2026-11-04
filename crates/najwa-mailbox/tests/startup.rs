//! Process-level startup and shutdown of the real `najwa-mailbox` binary
//! (S16 §5 configuration file, §12 signals).

use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_najwa-mailbox");

fn wait_for_exit(child: &mut Child, limit: Duration) -> Option<ExitStatus> {
    let start = Instant::now();
    while start.elapsed() < limit {
        if let Some(status) = child.try_wait().unwrap() {
            return Some(status);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

/// A missing config file is an error. The server must not start on built-in
/// defaults with a `mailbox.db` in its working directory.
#[test]
fn missing_config_file_refuses_to_start() {
    let dir = tempfile::tempdir().unwrap();
    let mut child = Command::new(BIN)
        .arg("absent.toml")
        .current_dir(dir.path())
        .env_remove("RUST_LOG")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let Some(status) = wait_for_exit(&mut child, Duration::from_secs(30)) else {
        child.kill().ok();
        panic!("server kept running without its config file");
    };
    let mut stderr = String::new();
    std::io::Read::read_to_string(&mut child.stderr.take().unwrap(), &mut stderr).unwrap();
    assert!(!status.success());
    assert!(
        stderr.contains("absent.toml"),
        "error must name the file: {stderr}"
    );
    assert!(!dir.path().join("mailbox.db").exists());
}

/// `docker stop` and `systemctl stop` send SIGTERM. The server must drain and
/// exit 0 through the graceful path, not die from the signal.
#[cfg(unix)]
#[test]
fn sigterm_shuts_down_gracefully() {
    use std::io::BufRead;

    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("mailbox.toml");
    std::fs::write(
        &config,
        format!(
            "[server]\nlisten_port = 0\nhealth_port = 0\ndatabase_path = {:?}\n\
             [quotas]\n[pow]\n[rate_limits]\n[cleanup]\n\
             [logging]\nlevel = \"info\"\nformat = \"text\"\n",
            dir.path().join("mailbox.db")
        ),
    )
    .unwrap();
    let mut child = Command::new(BIN)
        .arg(&config)
        .env_remove("RUST_LOG")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let (lines_tx, lines) = std::sync::mpsc::channel();
    let stdout = child.stdout.take().unwrap();
    std::thread::spawn(move || {
        for line in std::io::BufReader::new(stdout).lines() {
            if lines_tx.send(line.unwrap()).is_err() {
                break;
            }
        }
    });
    let mut log = Vec::new();
    while !log
        .iter()
        .any(|l: &String| l.contains("API server listening"))
    {
        match lines.recv_timeout(Duration::from_secs(30)) {
            Ok(line) => log.push(line),
            Err(_) => {
                child.kill().ok();
                panic!("server did not start: {log:?}");
            }
        }
    }

    let sent = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(sent.success());
    let Some(status) = wait_for_exit(&mut child, Duration::from_secs(10)) else {
        child.kill().ok();
        panic!("server ignored SIGTERM");
    };
    log.extend(lines.iter()); // ends at EOF, now that the process is gone
    assert!(status.success(), "killed instead of shut down: {status:?}");
    assert!(
        log.iter()
            .any(|l| l.contains("server shut down gracefully")),
        "{log:?}"
    );
}
