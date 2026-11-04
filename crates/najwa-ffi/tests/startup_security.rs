#![cfg(target_os = "linux")]

#[test]
fn init_disables_process_dumps_before_accepting_work() {
    const CHILD: &str = "NAJWA_TEST_FFI_STARTUP";
    if std::env::var_os(CHILD).is_some() {
        // Set an observable insecure baseline in an isolated child.
        assert_eq!(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0) }, 0);
        let dir = tempfile::tempdir().unwrap();
        let path = std::ffi::CString::new(dir.path().to_str().unwrap()).unwrap();
        assert_eq!(najwa_ffi::najwa_init(path.as_ptr()), 0);
        assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) }, 0);
        let mut limit = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 1,
        };
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) }, 0);
        assert_eq!((limit.rlim_cur, limit.rlim_max), (0, 0));
        assert_eq!(najwa_ffi::najwa_identity_exists(), 0);
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "init_disables_process_dumps_before_accepting_work",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
