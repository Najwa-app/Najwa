//! Synthetic peer for testing the same typed boundary used by the desktop.
//! No credentials, software identity record or private key export is involved.
use najwa_ffi::desktop::DesktopClient;
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("najwa_ffi=debug,najwa_core=warn,najwa_core::receive=debug,najwa_core::pipeline=debug,najwa_protocol=warn,najwa_transport=warn")
        .with_writer(io::stderr)
        .with_ansi(false)
        .init();
    let directory = std::env::args_os()
        .nth(1)
        .expect("synthetic test directory");
    std::fs::create_dir_all(&directory).unwrap();
    let directory = std::path::PathBuf::from(directory).canonicalize().unwrap();
    let identity = najwa_identity::record::Identity {
        keypair: najwa_crypto::keys::Ed25519KeyPair::from_seed(&zeroize::Zeroizing::new(
            najwa_crypto::random::random_bytes(),
        )),
        created_at: najwa_crypto::time::now(),
        version: 2,
    };
    let client = DesktopClient::init(&directory).unwrap();
    client.attach_identity(&identity).unwrap();
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let input: Value = serde_json::from_str(&line).unwrap();
        let text = |key: &str| input[key].as_str().unwrap_or("");
        let result = match text("kind") {
            "status" => Ok(serde_json::to_value(client.status()).unwrap()),
            "mailbox" => client.add_mailbox(text("onion")).map(|_| Value::Null),
            "invite" => client.invitation(text("name")).map(Value::String),
            "accept" => client
                .accept_invitation(text("invitation"), text("name"), input["confirmed"] == true)
                .map(Value::String),
            "contacts" => client.contacts().map(|v| serde_json::to_value(v).unwrap()),
            "messages" => client
                .messages(text("contact"))
                .map(|v| serde_json::to_value(v).unwrap()),
            "send" => client
                .send(text("contact"), text("text"))
                .map(Value::String),
            "sync" => client.sync().map(|_| Value::Null),
            "lock" => client.lock().map(|_| Value::Null),
            "unlock" => client.attach_identity(&identity).map(|_| Value::Null),
            "displayed" => client
                .displayed(
                    text("contact"),
                    &input["ids"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| v.as_str().unwrap().to_owned())
                        .collect::<Vec<_>>(),
                )
                .map(|_| Value::Null),
            "quit" => {
                client.lock().unwrap();
                break;
            }
            _ => panic!("unknown fixture command"),
        };
        println!(
            "{}",
            match result {
                Ok(value) => json!({"ok":value}),
                Err(error) => json!({"error":error.code}),
            }
        );
        io::stdout().flush().unwrap();
    }
}
