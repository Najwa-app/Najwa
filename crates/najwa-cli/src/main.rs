//! Najwa development command-line interface.
//!
//! Drives the Rust crates directly (identity + storage). It has no network
//! commands and is not part of the packaged app. Subcommands:
//!
//!   najwa-cli identity create <data-dir> [--password-stdin]
//!   najwa-cli identity unlock <data-dir> [--password-stdin]   (verifies + reports key state)
//!   najwa-cli identity exists <data-dir>
//!   najwa-cli db open        <data-dir> [--password-stdin]   (opens + integrity-checks the DB)

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use najwa_identity::manager::IdentityManager;
use najwa_identity::IdentityError;
use zeroize::Zeroizing;

const USAGE: &str = "usage:
  najwa-cli identity create <data-dir> [--password-stdin]
  najwa-cli identity unlock <data-dir> [--password-stdin]
  najwa-cli identity exists <data-dir>
  najwa-cli db open         <data-dir> [--password-stdin]";

fn main() -> ExitCode {
    if let Err(error) = najwa_crypto::initialize() {
        eprintln!("security initialization failed: {error}");
        return ExitCode::FAILURE;
    }
    let args = Zeroizing::new(std::env::args().skip(1).collect::<Vec<String>>());
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            eprintln!("{USAGE}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    match argv.as_slice() {
        ["identity", "exists", dir] => exists(Path::new(dir)),
        [kind, action, dir, rest @ ..]
            if matches!(
                (*kind, *action),
                ("identity", "create" | "unlock") | ("db", "open")
            ) =>
        {
            let password = match rest {
                [] => Zeroizing::new(
                    rpassword::prompt_password("Password: ")
                        .map_err(|e| format!("read password: {e}"))?,
                ),
                ["--password-stdin"] => read_stdin_password(std::io::stdin().lock())?,
                _ => return Err("passwords must use the hidden prompt or --password-stdin".into()),
            };
            if password.is_empty() || password.len() > 4096 {
                return Err("password must contain 1 to 4096 bytes".into());
            }
            match (*kind, *action) {
                ("identity", "create") => identity_create(PathBuf::from(dir), &password),
                ("identity", "unlock") => identity_unlock(PathBuf::from(dir), &password),
                ("db", "open") => db_open(PathBuf::from(dir), &password),
                _ => unreachable!(),
            }
        }
        _ => Err("invalid command arguments".into()),
    }
}

fn read_stdin_password(reader: impl std::io::Read) -> Result<Zeroizing<String>, String> {
    use std::io::Read;
    let mut password = Zeroizing::new(String::new());
    reader
        .take(4099)
        .read_to_string(&mut password)
        .map_err(|e| format!("read password: {e}"))?;
    if password.ends_with('\n') {
        password.pop();
        if password.ends_with('\r') {
            password.pop();
        }
    }
    if password.is_empty() || password.len() > 4096 || password.contains(['\n', '\r', '\0']) {
        return Err("password input must be one nonempty line of at most 4096 bytes".into());
    }
    Ok(password)
}

fn identity_create(data_dir: PathBuf, password: &str) -> Result<(), String> {
    std::fs::create_dir_all(&data_dir).map_err(|e| format!("create dir: {e}"))?;
    let password = Zeroizing::new(password.to_string());
    let mut manager = IdentityManager::new(data_dir.join("identity.najwa"))
        .map_err(|e| format!("open identity: {e}"))?;
    manager
        .create(&password)
        .map_err(|e| match &e {
            // S02 §11.1: zxcvbn's warning, if any, never contains the input.
            IdentityError::WeakPassphrase { hint: Some(hint) } => {
                format!("create identity: {e} ({hint})")
            }
            _ => format!("create identity: {e}"),
        })?;
    println!(
        "identity created at {}",
        data_dir.join("identity.najwa").display()
    );
    Ok(())
}

fn identity_unlock(data_dir: PathBuf, password: &str) -> Result<(), String> {
    let password = Zeroizing::new(password.to_string());
    let identity = IdentityManager::unlock_once(&data_dir.join("identity.najwa"), &password)
        .map_err(|e| format!("unlock failed: {e}"))?;
    println!(
        "unlocked; IK public = {}",
        hex(&identity.keypair.public().to_bytes())
    );
    Ok(())
}

fn exists(data_dir: &Path) -> Result<(), String> {
    println!("{}", data_dir.join("identity.najwa").exists());
    Ok(())
}

fn db_open(data_dir: PathBuf, password: &str) -> Result<(), String> {
    let password = Zeroizing::new(password.to_string());
    let identity = IdentityManager::unlock_once(&data_dir.join("identity.najwa"), &password)
        .map_err(|e| format!("unlock failed: {e}"))?;
    let db_key = Zeroizing::new(derive_sqlcipher_key(&Zeroizing::new(
        identity.keypair.private().to_bytes(),
    )));
    let db_path = data_dir.join("najwa.db");
    let _db = najwa_storage::database::SqliteStorage::open(&db_path, &db_key)
        .map_err(|e| format!("open database: {e}"))?;
    println!("database opened ({})", db_path.display());
    Ok(())
}

/// Same derivation the FFI uses (v1-compatible HKDF over the identity seed).
fn derive_sqlcipher_key(identity_seed: &[u8; 32]) -> [u8; 32] {
    let derived = Zeroizing::new(
        najwa_crypto::kdf::hkdf_sha256(
            identity_seed,
            b"najwa-sqlcipher-key",
            b"najwa/v1/sqlcipher-key",
            32,
        )
        .expect("HKDF-SHA256 should not fail for 32-byte output"),
    );
    let mut key = [0u8; 32];
    key.copy_from_slice(&derived);
    key
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(all(test, target_os = "linux"))]
mod startup_tests {
    #[test]
    fn cli_disables_process_dumps_before_dispatch() {
        const CHILD: &str = "NAJWA_TEST_CLI_STARTUP";
        if std::env::var_os(CHILD).is_some() {
            assert_eq!(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0) }, 0);
            // The test runner's arguments are invalid CLI arguments, so main
            // returns without doing identity/storage work, after initialization.
            let _ = super::main();
            assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) }, 0);
            let mut limit = libc::rlimit {
                rlim_cur: 1,
                rlim_max: 1,
            };
            assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) }, 0);
            assert_eq!((limit.rlim_cur, limit.rlim_max), (0, 0));
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "startup_tests::cli_disables_process_dumps_before_dispatch",
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
}

#[cfg(test)]
mod row14_tests {
    use super::*;
    #[test]
    fn passwords_are_not_accepted_as_arguments() {
        let args = ["identity", "create", "unused", "secret"].map(str::to_string);
        assert!(run(&args).unwrap_err().contains("hidden prompt"));
    }
    #[test]
    fn stdin_password_is_bounded_and_preserves_spaces() {
        assert_eq!(
            &**read_stdin_password(&b"  secret  \r\n"[..]).unwrap(),
            "  secret  "
        );
        for invalid in ["", "\n", "one\ntwo", "nul\0", &"a".repeat(4097)] {
            assert!(read_stdin_password(invalid.as_bytes()).is_err());
        }
    }
}
