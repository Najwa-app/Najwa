use std::path::{Path, PathBuf};
include!(concat!(env!("OUT_DIR"), "/web_assets.rs"));

/// The packer checks the exact embedded UI, including names and boundaries.
pub fn bundled_digest() -> String {
    let mut bytes = Vec::new();
    for (name, data) in BUNDLED {
        bytes.extend_from_slice(name.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&(data.len() as u64).to_le_bytes());
        bytes.extend_from_slice(data);
    }
    najwa_crypto::hash::sha256(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub enum Assets {
    Directory(PathBuf),
    Bundled,
}
impl Assets {
    pub fn resolve(explicit: Option<PathBuf>) -> Result<Self, &'static str> {
        if let Some(path) = explicit {
            return Self::directory(&path);
        }
        if !BUNDLED.is_empty() {
            return Ok(Self::Bundled);
        }
        let executable = std::env::current_exe().map_err(|_| "cannot locate application")?;
        Self::directory(
            &executable
                .parent()
                .ok_or("cannot locate application folder")?
                .join("web-ui"),
        )
    }
    fn directory(path: &Path) -> Result<Self, &'static str> {
        let path = path
            .canonicalize()
            .map_err(|_| "web UI is missing; use a bundled application or --assets DIRECTORY")?;
        if !path.join("index.html").is_file() {
            return Err("web UI has no index.html");
        }
        Ok(Self::Directory(path))
    }
    pub async fn read(&self, name: &str) -> Option<Vec<u8>> {
        match self {
            Self::Bundled => BUNDLED
                .iter()
                .find(|(path, _)| *path == name)
                .map(|(_, bytes)| bytes.to_vec()),
            Self::Directory(root) => {
                let file = root.join(name).canonicalize().ok()?;
                if !file.starts_with(root) {
                    return None;
                }
                tokio::fs::read(file)
                    .await
                    .ok()
                    .filter(|bytes| bytes.len() <= 4_194_304)
            }
        }
    }
}
