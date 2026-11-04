//! Disposable browser-demo peer. Keys stay in Rust; this is never a release entry point.
use najwa_ffi::desktop::DesktopClient;
use serde::Deserialize;
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Operation {
    Status,
    Contacts,
    Messages {
        contact: String,
    },
    Displayed {
        contact: String,
        ids: Vec<String>,
    },
    Send {
        contact: String,
        text: String,
    },
    SetTimer {
        contact: String,
        seconds: u32,
    },
    AddMailbox {
        onion: String,
    },
    SelectMailbox {
        onion: String,
    },
    ForgetMailbox {
        onion: String,
    },
    SetDeliveryMode {
        mode: String,
    },
    RetryMailbox {
        onion: String,
    },
    Invitation {
        name: String,
    },
    AcceptInvitation {
        invitation: String,
        name: String,
        #[serde(default)]
        confirmed: bool,
    },
    Verify {
        contact: String,
        safety: String,
        verified: bool,
    },
    Sync,
    Reconnect,
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("najwa_ffi=debug,najwa_core=warn,najwa_protocol=warn,najwa_transport=warn")
        .with_writer(io::stderr)
        .with_ansi(false)
        .init();
    let directory =
        std::path::PathBuf::from(std::env::args_os().nth(1).expect("fresh test directory"));
    // Refuse reuse: this peer intentionally has no persistent identity record.
    std::fs::create_dir(&directory).expect("demo profile must be fresh");
    let identity = najwa_identity::record::Identity {
        keypair: najwa_crypto::keys::Ed25519KeyPair::from_seed(&zeroize::Zeroizing::new(
            najwa_crypto::random::random_bytes(),
        )),
        created_at: najwa_crypto::time::now(),
        version: 2,
    };
    let fingerprint: String = identity
        .keypair
        .public()
        .to_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let client = DesktopClient::init(&directory).unwrap();
    client.attach_identity(&identity).unwrap();
    println!("{}", json!({"ok":{"fingerprint":fingerprint}}));
    io::stdout().flush().unwrap();
    for line in io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        let result = match serde_json::from_str::<Operation>(&line) {
            Ok(operation) => execute(&client, operation),
            Err(_) => Err(najwa_ffi::desktop::DesktopError {
                code: "invalid_request",
            }),
        };
        println!(
            "{}",
            match result {
                Ok(value) => json!({"ok":value}),
                Err(error) => json!({"error":error.code}),
            }
        );
        if io::stdout().flush().is_err() {
            break;
        }
    }
    let _ = client.prepare_wipe();
}

fn execute(
    client: &DesktopClient,
    operation: Operation,
) -> Result<Value, najwa_ffi::desktop::DesktopError> {
    match operation {
        Operation::Status => Ok(serde_json::to_value(client.status()).unwrap()),
        Operation::Contacts => client.contacts().map(|v| serde_json::to_value(v).unwrap()),
        Operation::Messages { contact } => client
            .messages(&contact)
            .map(|v| serde_json::to_value(v).unwrap()),
        Operation::Displayed { contact, ids } => {
            client.displayed(&contact, &ids).map(|_| Value::Null)
        }
        Operation::Send { contact, text } => client.send(&contact, &text).map(Value::String),
        Operation::SetTimer { contact, seconds } => {
            client.set_timer(&contact, seconds).map(|_| Value::Null)
        }
        Operation::AddMailbox { onion } => client.add_mailbox(&onion).map(|_| Value::Null),
        Operation::SelectMailbox { onion } => client.select_mailbox(&onion).map(|_| Value::Null),
        Operation::ForgetMailbox { onion } => client.forget_mailbox(&onion).map(|_| Value::Null),
        Operation::SetDeliveryMode { mode } => client.set_delivery_mode(&mode).map(|_| Value::Null),
        Operation::RetryMailbox { onion } => client.retry_mailbox(&onion).map(|_| Value::Null),
        Operation::Invitation { name } => client.invitation(&name).map(Value::String),
        Operation::AcceptInvitation { invitation, name, confirmed } => client
            .accept_invitation(&invitation, &name, confirmed)
            .map(Value::String),
        Operation::Verify {
            contact,
            safety,
            verified,
        } => client
            .verify(&contact, &safety, verified)
            .map(|_| Value::Null),
        Operation::Sync => client.sync().map(|_| Value::Null),
        Operation::Reconnect => {
            client.reconnect();
            Ok(Value::Null)
        }
    }
}
