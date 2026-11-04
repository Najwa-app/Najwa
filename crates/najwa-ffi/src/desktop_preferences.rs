//! Encrypted per-profile preferences. Browser input never selects an executable.
use super::{storage, DesktopClient, DesktopError, Result};
use crate::state::{state_cell, OperationGuard};
use najwa_storage::database::SqliteStorage;
use najwa_transport::{config::{BridgeConfig, BridgeType, PluggableTransportConfig, TorConfig}, tor::TorTransport};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{io::Read, path::{Path, PathBuf}};

const SETTING: &str = "desktop:local-preferences";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalPreferences {
    pub lock_timeout_seconds: u32,
    pub bridges: Vec<String>,
}
impl Default for LocalPreferences {
    fn default() -> Self { Self { lock_timeout_seconds: 300, bridges: Vec::new() } }
}
impl LocalPreferences {
    pub fn normalized(mut self) -> Result<Self> {
        if !(60..=3600).contains(&self.lock_timeout_seconds)
            || self.bridges.len() > 8
            || self.bridges.iter().map(String::len).sum::<usize>() > 16_384 {
            return Err(DesktopError::new("invalid_preferences"));
        }
        for line in &mut self.bridges {
            if line.len() > 4096 || line.contains(['\r', '\n', '\0']) {
                return Err(DesktopError::new("invalid_bridges"));
            }
            *line = line.split_whitespace().collect::<Vec<_>>().join(" ");
            bridge_type(line)?;
        }
        Ok(self)
    }
}

fn bridge_type(line: &str) -> Result<BridgeType> {
    let line = line.strip_prefix("Bridge ").unwrap_or(line);
    match line.split_whitespace().next() {
        Some("obfs4") => Ok(BridgeType::Obfs4),
        Some("snowflake") => Ok(BridgeType::Snowflake),
        Some(word) if word.parse::<std::net::SocketAddr>().is_ok() => Ok(BridgeType::Plain),
        _ => Err(DesktopError::new("invalid_bridges")),
    }
}

pub(crate) fn read(db: &SqliteStorage) -> Result<LocalPreferences> {
    // A malformed stored setting is an error, never consent to use direct Tor.
    storage(db.get_setting::<LocalPreferences>(SETTING))?.unwrap_or_default().normalized()
}

fn bundled_helper() -> Result<PathBuf> {
    let executable = std::env::current_exe().map_err(|_| DesktopError::new("bridge_helper_unavailable"))?;
    let directory = executable.parent().ok_or_else(|| DesktopError::new("bridge_helper_unavailable"))?;
    #[cfg(target_os = "macos")]
    let directory = if directory.file_name().is_some_and(|name| name == "MacOS") {
        directory.parent().unwrap().join("Resources")
    } else { directory.to_path_buf() };
    #[cfg(not(target_os = "macos"))]
    let directory = directory.to_path_buf();
    let path = directory.join("transports").join(if cfg!(windows) { "lyrebird.exe" } else { "lyrebird" });
    verify_helper(&path)?;
    Ok(path)
}

fn verify_helper(path: &Path) -> Result<()> {
    let unavailable = || DesktopError::new("bridge_helper_unavailable");
    let manifest: serde_json::Value = serde_json::from_str(include_str!("../../../tor-transports.json"))
        .map_err(|_| unavailable())?;
    let key = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
    let expected = manifest["platforms"][&key]["binarySha256"].as_str().ok_or_else(unavailable)?;
    let mut file = std::fs::File::open(path).map_err(|_| unavailable())?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 65_536];
    loop {
        let count = file.read(&mut buffer).map_err(|_| unavailable())?;
        if count == 0 { break; }
        digest.update(&buffer[..count]);
    }
    let actual: String = digest.finalize().iter().map(|byte| format!("{byte:02x}")).collect();
    if actual != expected { return Err(unavailable()); }
    Ok(())
}

pub(crate) fn tor_config(directory: &Path, preferences: &LocalPreferences) -> Result<TorConfig> {
    let preferences = preferences.clone().normalized()?;
    let mut config = TorConfig { data_dir: directory.join("tor"), ..Default::default() };
    for line in preferences.bridges {
        let kind = bridge_type(&line)?;
        if kind != BridgeType::Plain && !config.transports.iter().any(|pt| pt.bridge_type == kind) {
            config.transports.push(PluggableTransportConfig {
                bridge_type: kind, executable: bundled_helper()?, arguments: Vec::new(),
            });
        }
        config.bridges.push(BridgeConfig { bridge_type: kind, address: line, fingerprint: None });
    }
    TorTransport::validate_config(config.clone()).map_err(|_| DesktopError::new("invalid_bridges"))?;
    Ok(config)
}

impl DesktopClient {
    pub fn local_preferences(&self) -> Result<LocalPreferences> {
        let _operation = OperationGuard::acquire().ok_or_else(|| DesktopError::new("locked"))?;
        let cell = state_cell().read().unwrap();
        let db = cell.as_ref().filter(|s| s.identity.is_some()).and_then(|s| s.storage.as_ref())
            .ok_or_else(|| DesktopError::new("locked"))?;
        read(db)
    }
    pub fn save_local_preferences(&self, preferences: LocalPreferences) -> Result<LocalPreferences> {
        let preferences = preferences.normalized()?;
        let _operation = OperationGuard::acquire().ok_or_else(|| DesktopError::new("locked"))?;
        let cell = state_cell().read().unwrap();
        let app = cell.as_ref().filter(|s| s.identity.is_some()).ok_or_else(|| DesktopError::new("locked"))?;
        // Check the complete Arti configuration and pinned helper before committing.
        tor_config(&app.data_dir, &preferences)?;
        storage(app.storage.as_ref().ok_or_else(|| DesktopError::new("locked"))?.set_setting(SETTING, &preferences))?;
        Ok(preferences)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounds_and_bridge_validation_never_turn_errors_into_direct_routing() {
        let dir = tempfile::tempdir().unwrap();
        for seconds in [0, 59, 3601, u32::MAX] {
            assert!(LocalPreferences { lock_timeout_seconds: seconds, ..Default::default() }.normalized().is_err());
        }
        for line in ["", "meek 1.2.3.4:1", "127.0.0.1:1\n127.0.0.2:2", "../program.exe", "obfs4 invalid"] {
            let prefs = LocalPreferences { bridges: vec![line.into()], ..Default::default() };
            assert!(tor_config(dir.path(), &prefs).is_err(), "{line}");
        }
        let plain = LocalPreferences { bridges: vec!["Bridge 127.0.0.1:1 0123456789ABCDEF0123456789ABCDEF01234567".into()], ..Default::default() };
        let config = tor_config(dir.path(), &plain).unwrap();
        assert_eq!(config.bridges.len(), 1);
        assert!(config.transports.is_empty());
        assert!(tor_config(dir.path(), &LocalPreferences::default()).unwrap().bridges.is_empty());
    }
    #[test]
    fn preferences_persist_in_encrypted_storage_and_corruption_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let db = SqliteStorage::open(&dir.path().join("prefs.db"), &[41;32]).unwrap();
        assert_eq!(read(&db).unwrap(), LocalPreferences::default());
        let prefs = LocalPreferences { lock_timeout_seconds: 900, ..Default::default() };
        db.set_setting(SETTING, &prefs).unwrap();
        drop(db);
        let db = SqliteStorage::open(&dir.path().join("prefs.db"), &[41;32]).unwrap();
        assert_eq!(read(&db).unwrap(), prefs);
        db.set_setting(SETTING, &serde_json::json!({"bridges":["bad"]})).unwrap();
        assert!(read(&db).is_err());
    }
    #[test]
    fn tampered_transport_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lyrebird");
        std::fs::write(&path, b"not the packaged transport").unwrap();
        assert!(verify_helper(&path).is_err());
    }
}
