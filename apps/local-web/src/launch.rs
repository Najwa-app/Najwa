//! Native launch and discovery. No interpreter, shell command or Docker dependency.
use crate::profile::Owner;
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};
use zeroize::Zeroizing;

pub const INSTANCE_FILE: &str = "web-instance.json";
/// Unix redirect page that carries the tokenized URL to the browser (see `open`).
pub const LAUNCH_FILE: &str = "web-launch.html";
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Instance {
    port: u16,
    session: String,
    token: String,
}
pub struct Registration(PathBuf);
impl Registration {
    pub fn publish(
        directory: &Path,
        owner: &Owner,
        port: u16,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let path = directory.join(INSTANCE_FILE);
        let bytes = Zeroizing::new(serde_json::to_vec(&Instance {
            port,
            session: owner.status().session,
            token: owner.token.clone(),
        })?);
        najwa_identity::atomic::atomic_write(&path, &bytes)?;
        Ok(Self(path))
    }
}
impl Drop for Registration {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        let _ = std::fs::remove_file(self.0.with_file_name(LAUNCH_FILE));
    }
}
pub fn existing(directory: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let path = directory.join(INSTANCE_FILE);
    if std::fs::metadata(&path)?.len() > 1024 {
        return Err("invalid local instance record".into());
    }
    let bytes = Zeroizing::new(std::fs::read(path)?);
    let instance: Instance = serde_json::from_slice(&bytes)?;
    if instance.token.len() != 64
        || !instance.token.bytes().all(|v| v.is_ascii_hexdigit())
        || instance.session.len() != 32
        || !instance.session.bytes().all(|v| v.is_ascii_hexdigit())
    {
        return Err("invalid local instance record".into());
    }
    let mut stream = std::net::TcpStream::connect_timeout(
        &format!("127.0.0.1:{}", instance.port).parse()?,
        Duration::from_secs(2),
    )?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    write!(stream,"GET /api/bootstrap HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-Najwa-Launch: {}\r\nConnection: close\r\n\r\n",instance.port,instance.token)?;
    let mut response = String::new();
    stream.take(8192).read_to_string(&mut response)?;
    let (head, body) = response
        .split_once("\r\n\r\n")
        .ok_or("local app did not respond")?;
    let value: serde_json::Value = serde_json::from_str(body)?;
    if !head.starts_with("HTTP/1.1 200")
        || value["session"] != instance.session
        || value["token"] != instance.token
    {
        return Err("could not verify the running local app".into());
    }
    Ok(format!(
        "http://127.0.0.1:{}/#{}",
        instance.port, instance.token
    ))
}
// ShellExecute hands the URL to the browser, whose command line other
// non-admin users cannot read: the default process DACL admits only the
// user, SYSTEM and Administrators.
#[cfg(windows)]
pub fn open(_directory: &Path, url: &str) -> Result<(), Box<dyn std::error::Error>> {
    use windows_sys::Win32::UI::{Shell::ShellExecuteW, WindowsAndMessaging::SW_SHOWNORMAL};
    let url: Vec<u16> = url.encode_utf16().chain(Some(0)).collect();
    let operation: Vec<u16> = "open".encode_utf16().chain(Some(0)).collect();
    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            operation.as_ptr(),
            url.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    if result as isize <= 32 {
        Err(
            "could not open the default browser; check your browser setting and reopen Najwa"
                .into(),
        )
    } else {
        Ok(())
    }
}
#[cfg(not(windows))]
pub fn open(directory: &Path, url: &str) -> Result<(), Box<dyn std::error::Error>> {
    use std::process::Stdio;
    let mut child = opener(directory, url)?
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}
/// Other local users can read process arguments (`/proc/<pid>/cmdline`, `ps`),
/// so the opener gets only the path of a redirect page. The page is created
/// 0600 in the 0700 profile directory, replaced on every launch and removed
/// when the owning service exits (`Registration`).
#[cfg(not(windows))]
fn opener(directory: &Path, url: &str) -> std::io::Result<std::process::Command> {
    use std::os::unix::fs::OpenOptionsExt;
    let path = directory.join(LAUNCH_FILE);
    match std::fs::remove_file(&path) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error),
        _ => {}
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    write!(file, "<!doctype html><meta charset=\"utf-8\"><title>Najwa</title><meta http-equiv=\"refresh\" content=\"0;url={url}\"><a href=\"{url}\">Open Najwa</a>")?;
    let mut command =
        std::process::Command::new(if cfg!(target_os = "macos") { "open" } else { "xdg-open" });
    command.arg(path);
    Ok(command)
}
pub fn report(error: &str, interactive: bool) {
    eprintln!("Najwa: {error}");
    #[cfg(windows)]
    if interactive {
        use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK};
        let message: Vec<u16> = error.encode_utf16().chain(Some(0)).collect();
        let title: Vec<u16> = "Najwa could not open"
            .encode_utf16()
            .chain(Some(0))
            .collect();
        unsafe {
            MessageBoxW(
                std::ptr::null_mut(),
                message.as_ptr(),
                title.as_ptr(),
                MB_OK | MB_ICONERROR,
            );
        }
    }
    #[cfg(not(windows))]
    let _ = interactive;
}

#[cfg(all(test, unix))]
mod tests {
    #[test]
    fn opener_gets_an_owner_only_redirect_path_never_the_token() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let token = "ab".repeat(32);
        let url = format!("http://127.0.0.1:1421/#{token}");
        let command = super::opener(directory.path(), &url).unwrap();
        let args: Vec<_> = command.get_args().collect();
        assert_eq!(args, [directory.path().join(super::LAUNCH_FILE).as_os_str()]);
        assert!(!args[0].to_string_lossy().contains(&token));
        let metadata = std::fs::metadata(args[0]).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert!(std::fs::read_to_string(args[0]).unwrap().contains(&url));
    }
}
