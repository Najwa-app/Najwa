//! Continue a deliberately interrupted maximum-size test without reuploading.
use std::{path::PathBuf, process::Command};
struct Profiles {
    paths: Vec<PathBuf>,
    cleanup: bool,
}
impl Drop for Profiles {
    fn drop(&mut self) {
        if !self.cleanup {
            return;
        }
        for path in &self.paths {
            if let Ok(bytes) = std::fs::read(path.join("identity.najwa")) {
                if let Ok(record) = najwa_identity::IdentityRecordStandard::from_bytes(&bytes) {
                    let _ = najwa_identity::platform::delete_record_dkm(&record);
                }
            }
        }
    }
}
#[test]
#[ignore = "requires the generated synthetic profiles from an interrupted 256 MiB public-Tor test"]
fn maximum_file_continues_from_persistent_test_profiles() {
    let project = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = project.join("../../target/large-files-stable-profiles");
    let fresh = std::env::var("NAJWA_LARGE_FRESH").as_deref() == Ok("1");
    if fresh {
        assert!(!root.exists(), "never overwrite an existing test identity");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("synthetic-test-owner.txt"),
            "najwa-generated-256MiB-resume-test\n",
        )
        .unwrap();
    }
    assert_eq!(
        std::fs::read_to_string(root.join("synthetic-test-owner.txt")).unwrap(),
        "najwa-generated-256MiB-resume-test\n"
    );
    let mut profiles = Profiles {
        paths: vec![root.join("alice"), root.join("bob")],
        cleanup: false,
    };
    let output = project.join("../../target/large-files-final-live");
    let status = Command::new("node")
        .current_dir(project.join("../desktop"))
        .arg(if fresh {
            "local-web/live-messaging.mjs"
        } else {
            "local-web/resume-large-files.mjs"
        })
        .env("NAJWA_LARGE_FILES", "1")
        .arg(std::env::var_os("NAJWA_WEB_TEST_EXE").expect("final native package"))
        .arg(std::env::var("NAJWA_MAILBOX_ONION").expect("development onion mailbox"))
        .arg(&profiles.paths[0])
        .arg(&profiles.paths[1])
        .arg(output)
        .status()
        .unwrap();
    profiles.cleanup = status.success();
    assert!(status.success(), "see target/large-files-final-live/result.json; failed synthetic profiles are kept for continuation");
}
