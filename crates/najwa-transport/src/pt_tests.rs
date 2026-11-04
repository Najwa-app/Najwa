use super::*;

#[tokio::test]
async fn handshake_requires_version_requested_method_and_done() {
    for output in [
        "",
        "VERSION 1\nCMETHOD obfs4 socks5 127.0.0.1:1234\n",
        "CMETHOD obfs4 socks5 127.0.0.1:1234\nCMETHODS DONE\n",
        "VERSION 1\nCMETHODS DONE\n",
        "VERSION 2\n",
        "VERSION 1\nCMETHOD obfs4 socks4 127.0.0.1:1234\n",
        "VERSION 1\nCMETHOD meek socks5 127.0.0.1:1234\n",
        "VERSION 1\nCMETHOD obfs4 socks5 8.8.8.8:1234\n",
        "VERSION 1\nCMETHOD obfs4 socks5 127.0.0.1:0\n",
        "VERSION 1\nCMETHOD-ERROR obfs4 failed\n",
    ] {
        assert!(
            handshake(&mut output.as_bytes(), "obfs4").await.is_err(),
            "{output:?}"
        );
    }
    let output = b"VERSION 1\r\nLOG SEVERITY=notice MESSAGE=starting\nCMETHOD obfs4 socks5 127.0.0.1:1234\nCMETHODS DONE\n";
    assert_eq!(
        handshake(&mut output.as_slice(), "obfs4").await.unwrap(),
        "127.0.0.1:1234".parse().unwrap()
    );
}

#[tokio::test]
async fn handshake_output_is_bounded() {
    let long = format!("LOG {}\n", "a".repeat(4096));
    assert!(handshake(&mut long.as_bytes(), "obfs4").await.is_err());
    let many = "LOG abcdefghijklmnopqrstuvwxyz\n".repeat(4096);
    assert!(handshake(&mut many.as_bytes(), "obfs4").await.is_err());
}

#[cfg(unix)]
mod subprocess {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        dir: PathBuf,
        binary: PathBuf,
    }
    impl Fixture {
        fn new(script: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "najwa-pt-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let binary = dir.join("fake-pt");
            std::fs::write(&binary, format!("#!/bin/sh\n{script}\n")).unwrap();
            std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self { dir, binary }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[tokio::test]
    async fn incomplete_subprocess_handshake_is_not_success() {
        let f = Fixture::new("printf 'VERSION 1\nCMETHOD obfs4 socks5 127.0.0.1:1234\n'");
        assert!(PtProcess::spawn_obfs4(&f.binary, &f.dir).await.is_err());
    }

    #[tokio::test]
    async fn meek_forwards_endpoint_and_keeps_control_pipe_alive() {
        let f = Fixture::new(
            r#"
test "$TOR_PT_MANAGED_TRANSPORT_VER" = 1 || exit 1
test "$TOR_PT_EXIT_ON_STDIN_CLOSE" = 1 || exit 2
test "$1" = '-url' && test "$2" = 'https://reflector.invalid/' || exit 3
test "$3" = '-front' && test "$4" = 'front.invalid' || exit 4
printf 'VERSION 1\nCMETHOD meek socks5 127.0.0.1:1234\nCMETHODS DONE\n'
i=0
while test "$i" -lt 12000; do printf 'LOG SEVERITY=notice MESSAGE=still-running\n' || exit 5; i=$((i+1)); done
printf ready > "$TOR_PT_STATE_LOCATION/ready"
read ignored
"#,
        );
        let mut process = PtProcess::spawn_meek(
            &f.binary,
            &f.dir,
            "front.invalid",
            "https://reflector.invalid/",
        )
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while !f.dir.join("ready").exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert!(process.is_running());
        process.kill().await.unwrap();
        assert!(!process.is_running());
    }

    #[tokio::test]
    async fn initialization_timeout_kills_child() {
        let f = Fixture::new("echo $$ > \"$TOR_PT_STATE_LOCATION/pid\"\nexec sleep 30");
        let result =
            PtProcess::spawn(&f.binary, &f.dir, "obfs4", &[], Duration::from_millis(100)).await;
        assert!(
            matches!(result, Err(TransportError::ConnectionFailed(ref message)) if message.contains("initialization timeout"))
        );
        // The deadline may fire before the child is scheduled. In that case
        // there is no PID marker to inspect. Drop/cancellation tests below wait
        // for initialization before asserting process cleanup independently.
        if let Ok(pid) = std::fs::read_to_string(f.dir.join("pid")) {
            if let Ok(pid) = pid.trim().parse::<u32>() {
                tokio::time::timeout(Duration::from_secs(3), async {
                    while Path::new(&format!("/proc/{pid}")).exists() {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                })
                .await
                .unwrap();
            }
        }
    }

    #[tokio::test]
    async fn dropping_initialized_process_kills_child() {
        let f = Fixture::new("echo $$ > \"$TOR_PT_STATE_LOCATION/pid\"\nprintf 'VERSION 1\nCMETHOD obfs4 socks5 127.0.0.1:1234\nCMETHODS DONE\n'\nread ignored");
        let process = PtProcess::spawn_obfs4(&f.binary, &f.dir).await.unwrap();
        let pid = std::fs::read_to_string(f.dir.join("pid")).unwrap();
        drop(process);
        tokio::time::timeout(Duration::from_secs(3), async {
            while Path::new(&format!("/proc/{}", pid.trim())).exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn cancelling_initialization_kills_child() {
        let f = Fixture::new("echo $$ > \"$TOR_PT_STATE_LOCATION/pid\"\nexec sleep 30");
        let binary = f.binary.clone();
        let dir = f.dir.clone();
        let task = tokio::spawn(async move { PtProcess::spawn_obfs4(&binary, &dir).await });
        tokio::time::timeout(Duration::from_secs(3), async {
            while !f.dir.join("pid").exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        task.abort();
        assert!(matches!(task.await, Err(error) if error.is_cancelled()));
        let pid = std::fs::read_to_string(f.dir.join("pid")).unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            while Path::new(&format!("/proc/{}", pid.trim())).exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }
}
