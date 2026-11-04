#![cfg(target_os = "windows")]

#[test]
fn initialize_suppresses_windows_crash_reports() {
    use windows_sys::Win32::System::Diagnostics::Debug::{
        GetErrorMode, SetErrorMode, SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX,
    };
    use windows_sys::Win32::System::ErrorReporting::WerRemoveExcludedApplication;
    const CHILD: &str = "NAJWA_TEST_WINDOWS_STARTUP";
    if std::env::var_os(CHILD).is_some() {
        // This checks the actual OS state in a child, not just a helper's return.
        unsafe { SetErrorMode(0) };
        najwa_crypto::initialize().unwrap();
        najwa_crypto::memory::exclude_from_error_reporting().unwrap();
        let flags = SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX;
        assert_eq!(unsafe { GetErrorMode() } & flags, flags);
        return;
    }
    let exe = std::env::current_exe().unwrap();
    let name = exe.file_name().unwrap().to_str().unwrap().to_owned();
    let wide: Vec<u16> = name.encode_utf16().chain([0]).collect();
    // S01 §6.3: start without an exclusion, so only the child's
    // exclude_from_error_reporting() can create the per-user WER exclusion.
    unsafe { WerRemoveExcludedApplication(wide.as_ptr(), 0) };
    let output = std::process::Command::new(&exe)
        .args([
            "--exact",
            "initialize_suppresses_windows_crash_reports",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .output()
        .unwrap();
    let excluded = std::process::Command::new("reg")
        .args([
            "query",
            r"HKCU\Software\Microsoft\Windows\Windows Error Reporting\ExcludedApplications",
            "/v",
            &name,
        ])
        .output()
        .unwrap()
        .status
        .success();
    // Leave no registry entry behind for this test binary.
    unsafe { WerRemoveExcludedApplication(wide.as_ptr(), 0) };
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        excluded,
        "exclude_from_error_reporting() must exclude {name} from Windows Error Reporting"
    );
}
