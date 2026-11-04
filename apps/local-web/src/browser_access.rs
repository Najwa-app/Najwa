//! Remembers permission to reach a locked profile, never an unlocked identity.
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const LIFETIME_SECS: u64 = 30 * 24 * 60 * 60;

#[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct Grant {
    token: String,
    expires_at: u64,
}

pub struct BrowserAccess {
    path: PathBuf,
    grant: Mutex<Grant>,
}

impl BrowserAccess {
    /// A partial wipe may have damaged the remembered grant. A fresh launch can
    /// access only the erasure screen; never parse or overwrite damaged files.
    pub fn for_erasure(directory: &Path) -> Self {
        Self {
            path: directory.join("browser-access.json"),
            grant: Mutex::new(Grant {
                token: crate::profile::random_hex::<32>(),
                expires_at: now().saturating_add(LIFETIME_SECS),
            }),
        }
    }
    // The profile owner holds its exclusive lease before opening this file.
    pub fn open(directory: &Path) -> Result<Self, &'static str> {
        let path = directory.join("browser-access.json");
        let grant = match std::fs::metadata(&path) {
            Ok(metadata) if metadata.len() <= 512 => {
                let bytes = Zeroizing::new(
                    std::fs::read(&path).map_err(|_| "cannot read browser permission")?,
                );
                let grant: Grant =
                    serde_json::from_slice(&bytes).map_err(|_| "cannot read browser permission")?;
                if grant.token.len() != 64
                    || !grant.token.bytes().all(|byte| byte.is_ascii_hexdigit())
                {
                    return Err("invalid browser permission");
                }
                grant
            }
            Ok(_) => return Err("invalid browser permission"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let grant = Grant {
                    token: crate::profile::random_hex::<32>(),
                    expires_at: now().saturating_add(LIFETIME_SECS),
                };
                save(&path, &grant)?;
                grant
            }
            Err(_) => return Err("cannot read browser permission"),
        };
        Ok(Self {
            path,
            grant: Mutex::new(grant),
        })
    }

    pub fn accepts(&self, value: &str) -> bool {
        let grant = self.grant.lock().unwrap();
        grant.expires_at > now()
            && najwa_crypto::hash::constant_time_eq(value.as_bytes(), grant.token.as_bytes())
    }

    pub fn cookie(&self) -> Result<(String, u64), &'static str> {
        let mut grant = self.grant.lock().unwrap();
        let current_time = now();
        if grant.expires_at <= current_time {
            let replacement = Grant {
                token: crate::profile::random_hex::<32>(),
                expires_at: current_time.saturating_add(LIFETIME_SECS),
            };
            save(&self.path, &replacement)?;
            *grant = replacement;
        }
        Ok((grant.token.clone(), grant.expires_at - current_time))
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn save(path: &Path, grant: &Grant) -> Result<(), &'static str> {
    let bytes =
        Zeroizing::new(serde_json::to_vec(grant).map_err(|_| "cannot save browser permission")?);
    najwa_identity::atomic::atomic_write(path, &bytes)
        .map_err(|_| "cannot save browser permission")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|_| "cannot protect browser permission")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_survives_restart_but_is_separate_for_each_profile() {
        let directory = tempfile::tempdir().unwrap();
        let access = BrowserAccess::open(directory.path()).unwrap();
        let (cookie, age) = access.cookie().unwrap();
        assert!(age > 0 && age <= LIFETIME_SECS);
        drop(access);
        assert!(BrowserAccess::open(directory.path())
            .unwrap()
            .accepts(&cookie));
        let other = tempfile::tempdir().unwrap();
        assert!(!BrowserAccess::open(other.path()).unwrap().accepts(&cookie));
    }

    #[test]
    fn permission_check_rejects_a_wrong_grant_of_any_length() {
        let directory = tempfile::tempdir().unwrap();
        let access = BrowserAccess::open(directory.path()).unwrap();
        let (cookie, _) = access.cookie().unwrap();
        let mut wrong = cookie.clone().into_bytes();
        wrong[63] = if wrong[63] == b'0' { b'1' } else { b'0' };
        assert!(access.accepts(&cookie));
        assert!(!access.accepts(std::str::from_utf8(&wrong).unwrap()));
        assert!(!access.accepts(&cookie[..63]));
        assert!(!access.accepts(&format!("{cookie}0")));
    }

    #[test]
    fn an_expired_permission_is_rejected_and_replaced_on_fresh_launch() {
        let directory = tempfile::tempdir().unwrap();
        let expired = Grant {
            token: "a".repeat(64),
            expires_at: now() - 1,
        };
        save(&directory.path().join("browser-access.json"), &expired).unwrap();
        let access = BrowserAccess::open(directory.path()).unwrap();
        assert!(!access.accepts(&expired.token));
        let (replacement, _) = access.cookie().unwrap();
        assert_ne!(replacement, expired.token);
        assert!(access.accepts(&replacement));
        assert!(BrowserAccess::open(directory.path())
            .unwrap()
            .accepts(&replacement));
        assert!(!access.accepts(&expired.token));
    }
}
