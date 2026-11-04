//! Managed pluggable-transport subprocesses. Arti's production bridge path uses
//! its own PT manager; these helpers are available to external integrations.

use crate::error::{Result, TransportError};
use std::net::SocketAddr;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::task::JoinHandle;

pub struct PtProcess {
    child: Child,
    stdout_task: JoinHandle<()>,
    pub socks_addr: SocketAddr,
    pub transport_name: String,
}

fn pt_error(message: &str) -> TransportError {
    TransportError::ConnectionFailed(format!("PT: {message}"))
}

async fn control_line<R: AsyncBufRead + Unpin>(reader: &mut R) -> Result<String> {
    let mut bytes = Vec::new();
    reader.take(4097).read_until(b'\n', &mut bytes).await?;
    if bytes.len() > 4096 || !bytes.ends_with(b"\n") {
        return Err(pt_error("oversized line or unexpected EOF"));
    }
    bytes.pop();
    if bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
    String::from_utf8(bytes).map_err(|_| pt_error("invalid control encoding"))
}

async fn handshake<R: AsyncBufRead + Unpin>(reader: &mut R, name: &str) -> Result<SocketAddr> {
    let mut version = false;
    let mut address = None;
    let mut total = 0;
    loop {
        let line = control_line(reader).await?;
        total += line.len() + 1;
        if total > 64 * 1024 {
            return Err(pt_error("initialization output limit"));
        }
        let words: Vec<_> = line.split_whitespace().collect();
        match words.as_slice() {
            ["VERSION", "1"] if !version => version = true,
            ["CMETHOD", transport, "socks5", addr, ..]
                if version && *transport == name && address.is_none() =>
            {
                let addr: SocketAddr = addr
                    .parse()
                    .map_err(|_| pt_error("invalid SOCKS address"))?;
                if !addr.ip().is_loopback() || addr.port() == 0 {
                    return Err(pt_error("SOCKS listener must be local"));
                }
                address = Some(addr);
            }
            ["CMETHODS", "DONE"] if version => {
                return address.ok_or_else(|| pt_error("missing requested transport"))
            }
            ["LOG" | "STATUS", ..] => {}
            _ => return Err(pt_error("invalid or failed initialization")),
        }
    }
}

impl PtProcess {
    async fn spawn(
        binary: &Path,
        state_dir: &Path,
        name: &str,
        args: &[&str],
        timeout: Duration,
    ) -> Result<Self> {
        tokio::fs::create_dir_all(state_dir)
            .await
            .map_err(|e| pt_error(&format!("state directory: {e}")))?;
        let mut command = Command::new(binary);
        command
            .args(args)
            .env("TOR_PT_MANAGED_TRANSPORT_VER", "1")
            .env("TOR_PT_CLIENT_TRANSPORTS", name)
            .env("TOR_PT_STATE_LOCATION", state_dir)
            .env("TOR_PT_EXIT_ON_STDIN_CLOSE", "1")
            .env_remove("TOR_PT_PROXY")
            .env_remove("TOR_PT_SERVER_TRANSPORTS")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        #[cfg(windows)]
        command.creation_flags(0x08000000); // CREATE_NO_WINDOW
        let mut child = command
            .spawn()
            .map_err(|e| pt_error(&format!("spawn: {e}")))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| pt_error("missing stdout"))?;
        let mut reader = BufReader::new(stdout);
        let socks_addr = tokio::time::timeout(timeout, handshake(&mut reader, name))
            .await
            .map_err(|_| pt_error("initialization timeout"))??;
        if child.try_wait()?.is_some() {
            return Err(pt_error("exited during initialization"));
        }
        // Retain and drain stdout for the entire child lifetime. Never log
        // transport output: it can contain bridge addresses or reflector URLs.
        let stdout_task =
            tokio::spawn(async move { while control_line(&mut reader).await.is_ok() {} });
        Ok(Self {
            child,
            stdout_task,
            socks_addr,
            transport_name: name.to_owned(),
        })
    }

    pub async fn spawn_obfs4(pt_binary: &Path, state_dir: &Path) -> Result<Self> {
        Self::spawn(pt_binary, state_dir, "obfs4", &[], Duration::from_secs(30)).await
    }

    pub async fn spawn_meek(
        pt_binary: &Path,
        state_dir: &Path,
        front_domain: &str,
        url: &str,
    ) -> Result<Self> {
        if front_domain.is_empty() || url.is_empty() {
            return Err(pt_error("missing meek endpoint"));
        }
        Self::spawn(
            pt_binary,
            state_dir,
            "meek",
            &["-url", url, "-front", front_domain],
            Duration::from_secs(30),
        )
        .await
    }

    pub async fn spawn_snowflake(
        pt_binary: &Path,
        state_dir: &Path,
        broker_url: &str,
        front_domain: &str,
    ) -> Result<Self> {
        if front_domain.is_empty() || broker_url.is_empty() {
            return Err(pt_error("missing snowflake endpoint"));
        }
        Self::spawn(
            pt_binary,
            state_dir,
            "snowflake",
            &[
                "-url",
                broker_url,
                "-front",
                front_domain,
                "-ice",
                "stun:stun.l.google.com:19302",
            ],
            Duration::from_secs(60),
        )
        .await
    }

    pub fn is_running(&mut self) -> bool {
        if self.stdout_task.is_finished() {
            let _ = self.child.start_kill();
            return false;
        }
        matches!(self.child.try_wait(), Ok(None))
    }

    pub async fn kill(&mut self) -> Result<()> {
        self.stdout_task.abort();
        self.child
            .kill()
            .await
            .map_err(|e| pt_error(&format!("kill: {e}")))
    }
}

impl Drop for PtProcess {
    fn drop(&mut self) {
        self.stdout_task.abort();
        let _ = self.child.start_kill();
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn pt_process_struct_exists() {
        let _name = "obfs4".to_string();
    }
}

#[cfg(test)]
#[path = "pt_tests.rs"]
mod regression_tests;
