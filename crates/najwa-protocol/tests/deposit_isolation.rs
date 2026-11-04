use async_trait::async_trait;
use najwa_protocol::mailbox::prelude::{
    HttpMailboxClient, MailboxClient, MailboxConfig, RetryConfig, Transport,
};
use najwa_transport::{
    circuit::{CircuitHandle, CircuitIsolation},
    error::TransportError,
    http::HttpResponse,
};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

#[derive(Default)]
struct RecordingTransport {
    selected: Mutex<Vec<(u64, CircuitIsolation)>>,
    failures_left: AtomicUsize,
}

#[async_trait]
impl Transport for RecordingTransport {
    async fn get_circuit(
        &self,
        isolation: CircuitIsolation,
    ) -> Result<CircuitHandle, TransportError> {
        let handle = CircuitHandle::new(isolation.clone());
        self.selected.lock().unwrap().push((handle.id, isolation));
        Ok(handle)
    }
    async fn post(
        &self,
        _circuit: &CircuitHandle,
        url: &str,
        _body: &[u8],
        _content_type: &str,
    ) -> Result<HttpResponse, TransportError> {
        if self
            .failures_left
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            return Err(TransportError::Timeout);
        }
        let body = if url.ends_with("/v1/deposit") {
            br#"{"accepted":true,"message_id":"stored"}"#.to_vec()
        } else {
            br#"{"messages":[],"has_more":false}"#.to_vec()
        };
        Ok(HttpResponse {
            status: 200,
            headers: HashMap::new(),
            body,
        })
    }
    async fn get(&self, _: &CircuitHandle, _: &str) -> Result<HttpResponse, TransportError> {
        unreachable!()
    }
}

#[tokio::test]
async fn real_deposit_api_uses_one_shot_for_every_target_and_retry() {
    let transport = Arc::new(RecordingTransport::default());
    let client = HttpMailboxClient::with_retry(
        transport.clone(),
        RetryConfig {
            max_retries: 1,
            base_delay_ms: 0,
            ..RetryConfig::default()
        },
    );
    let a = MailboxConfig::new("a".repeat(56), [1; 32], [2; 32]);
    let b = MailboxConfig::new("b".repeat(56), [3; 32], [4; 32]);
    transport.failures_left.store(1, Ordering::SeqCst);
    client
        .deposit(&a, &a.deposit_capability, b"encrypted-a", None)
        .await
        .unwrap();
    client
        .deposit(&b, &b.deposit_capability, b"encrypted-b", None)
        .await
        .unwrap();
    client
        .deposit(&a, &a.deposit_capability, b"encrypted-a2", None)
        .await
        .unwrap();
    let selected = transport.selected.lock().unwrap();
    assert_eq!(selected.len(), 4); // initial attempt + retry + two deposits
    assert!(selected
        .iter()
        .all(|(_, x)| matches!(x, CircuitIsolation::OneShot)));
    let ids: std::collections::HashSet<_> = selected.iter().map(|(id, _)| id).collect();
    assert_eq!(ids.len(), selected.len());
}

#[tokio::test]
async fn polling_retains_per_mailbox_isolation() {
    let transport = Arc::new(RecordingTransport::default());
    let client = HttpMailboxClient::new(transport.clone());
    let mailbox = MailboxConfig::new("a".repeat(56), [1; 32], [2; 32]);
    client
        .fetch(&mailbox, &mailbox.fetch_capability, None, 10)
        .await
        .unwrap();
    assert!(
        matches!(&transport.selected.lock().unwrap()[0].1, CircuitIsolation::ByMailbox(host) if host == &mailbox.onion_address)
    );
}

#[tokio::test]
async fn responsive_file_attempts_use_only_the_explicit_attachment_isolation() {
    let transport=Arc::new(RecordingTransport::default());
    let client=HttpMailboxClient::new(transport.clone());
    let mailbox=MailboxConfig::new("a".repeat(56),[1;32],[2;32]);
    for key in [[7;32],[7;32],[8;32]] {
        client.deposit_file_once(&mailbox,&mailbox.deposit_capability,b"part",None,key).await.unwrap();
    }
    client.deposit_once(&mailbox,&mailbox.deposit_capability,b"ordinary",None).await.unwrap();
    let selected=transport.selected.lock().unwrap();
    assert_eq!(selected.iter().map(|(_,key)|key.clone()).collect::<Vec<_>>(),vec![
        CircuitIsolation::FileTransfer([7;32]),CircuitIsolation::FileTransfer([7;32]),
        CircuitIsolation::FileTransfer([8;32]),CircuitIsolation::OneShot,
    ]);
}
