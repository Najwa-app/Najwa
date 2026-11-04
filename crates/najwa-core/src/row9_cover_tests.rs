use super::*;
use crate::cover::{
    AbsorptionPriority, BurstMode, CoverMailboxSnapshot, CoverTrafficConfig, CoverTrafficScheduler,
    PendingQueues, SlotGrant, SlotSource,
};
use najwa_protocol::mailbox::{client::Transport, error::RetryConfig, http::HttpMailboxClient};
use najwa_transport::{
    circuit::{CircuitHandle, CircuitIsolation},
    error::TransportError,
    http::HttpResponse,
};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn row9_cover_poll_acknowledges_stored_blobs() {
    let mailbox = Arc::new(MockMailbox::new());
    mailbox.inject_fetched(vec![MailboxMessage {
        id: "stored-cover-1".into(),
        blob: vec![9; 256],
        deposited_at: 1,
        size: 256,
        cap_hint: None,
    }]);
    let mut scheduler = CoverTrafficScheduler::new(CoverTrafficConfig {
        poll_interval: Duration::ZERO,
        deposit_interval: Duration::from_secs(86400),
        jitter_percent: 0,
        burst_mode: BurstMode::PrivacyPriority,
        ..CoverTrafficConfig::default()
    });
    scheduler.replace_mailboxes(vec![snapshot()]);
    scheduler.start(mailbox.clone());
    tokio::time::timeout(Duration::from_secs(3), async {
        while scheduler.snapshot().cover_polls < 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(mailbox.acked_ids(), vec!["stored-cover-1"]);
}

fn snapshot() -> CoverMailboxSnapshot {
    CoverMailboxSnapshot {
        onion_address: "cover.onion".into(),
        cover_deposit_capability: [1; 32],
        cover_fetch_capability: [2; 32],
        cover_envelope_secret: [3; 32],
        dummy_deposit_capabilities: Vec::new(),
    }
}

fn fast_config() -> CoverTrafficConfig {
    CoverTrafficConfig {
        poll_interval: Duration::from_secs(86400),
        deposit_interval: Duration::ZERO,
        jitter_percent: 0,
        burst_mode: BurstMode::PrivacyPriority,
        ..CoverTrafficConfig::default()
    }
}

#[tokio::test]
async fn row9_dropped_grant_immediately_emits_replacement_cover() {
    let mailbox = Arc::new(MockMailbox::new());
    let mut scheduler = CoverTrafficScheduler::new(fast_config());
    scheduler.replace_mailboxes(vec![snapshot()]);
    scheduler.start(mailbox.clone());
    let permit = scheduler
        .slot_source()
        .await_slot("peer", AbsorptionPriority::Control, None)
        .await;
    drop(permit);
    tokio::time::timeout(Duration::from_millis(200), async {
        while scheduler.snapshot().cover_deposits == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(scheduler.snapshot().real_sends_absorbed, 0);
    assert_eq!(mailbox.take_deposited().len(), 1);
}

// Regression coverage for the row 9 review findings.
#[tokio::test]
async fn row9_restart_survives_old_task_exit() {
    let mut scheduler = CoverTrafficScheduler::new(CoverTrafficConfig::default());
    let mailbox = Arc::new(MockMailbox::new());
    scheduler.start(mailbox.clone());
    tokio::task::yield_now().await; // install the old task's exit guard
    assert!(scheduler.is_running());
    scheduler.stop();
    scheduler.start(mailbox);
    assert!(scheduler.is_running());
    for _ in 0..5 {
        tokio::task::yield_now().await;
    }
    assert!(
        scheduler.is_running(),
        "old guard must not overwrite the new run flag"
    );
}

#[tokio::test]
async fn row9_stop_during_enqueue_releases_waiter() {
    let running = Arc::new(AtomicBool::new(true));
    let queues = Arc::new(PendingQueues::new());
    let hook_running = running.clone();
    let hook_queues = queues.clone();
    let slots = SlotSource::with_boost(
        queues.clone(),
        running.clone(),
        Arc::new(move || {
            // Deterministic interleaving of stop() after the running check.
            hook_running.store(false, Ordering::SeqCst);
            hook_queues.wake_all();
        }),
    );
    let result = tokio::time::timeout(
        Duration::from_millis(50),
        slots.await_slot("peer", AbsorptionPriority::RealMessage, None),
    )
    .await;
    assert_eq!(result.unwrap(), SlotGrant::SchedulerStopped);
    assert!(!running.load(Ordering::SeqCst));
    assert!(queues.is_empty());
}

struct ProbeTransport {
    calls: AtomicUsize,
    hang: bool,
    fail_first: bool,
    accepted: bool,
}
#[async_trait]
impl Transport for ProbeTransport {
    async fn get_circuit(
        &self,
        isolation: CircuitIsolation,
    ) -> std::result::Result<CircuitHandle, TransportError> {
        Ok(CircuitHandle::new(isolation))
    }
    async fn post(
        &self,
        _: &CircuitHandle,
        url: &str,
        _: &[u8],
        _: &str,
    ) -> std::result::Result<HttpResponse, TransportError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        if self.hang {
            return std::future::pending().await;
        }
        if self.fail_first && call == 0 {
            return Err(TransportError::ConnectionFailed("response lost".into()));
        }
        let body = if url.ends_with("/fetch") {
            br#"{"messages":[],"has_more":false}"#.to_vec()
        } else {
            format!(r#"{{"accepted":{},"message_id":null}}"#, self.accepted).into_bytes()
        };
        Ok(HttpResponse {
            status: 200,
            headers: Default::default(),
            body,
        })
    }
    async fn get(
        &self,
        _: &CircuitHandle,
        _: &str,
    ) -> std::result::Result<HttpResponse, TransportError> {
        unreachable!()
    }
}

#[tokio::test]
async fn row9_slow_cover_does_not_block_slots() {
    let transport = Arc::new(ProbeTransport {
        calls: AtomicUsize::new(0),
        hang: true,
        fail_first: false,
        accepted: true,
    });
    let client = Arc::new(HttpMailboxClient::new(transport.clone()));
    let mut scheduler = CoverTrafficScheduler::new(fast_config());
    scheduler.replace_mailboxes(vec![snapshot()]);
    scheduler.start(client);
    tokio::time::timeout(Duration::from_secs(3), async {
        while transport.calls.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let result = tokio::time::timeout(
        Duration::from_millis(2200),
        scheduler
            .slot_source()
            .await_slot("peer", AbsorptionPriority::RealMessage, None),
    )
    .await;
    let permit = result.expect("healthy sender must receive a slot despite stalled cover");
    assert!(permit.was_paced());
    assert!(permit.begin());
    assert!(scheduler.is_running());
    assert_eq!(scheduler.pending_queues().len(), 0);
    assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn row9_cover_call_performs_one_network_attempt() {
    let transport = Arc::new(ProbeTransport {
        calls: AtomicUsize::new(0),
        hang: false,
        fail_first: true,
        accepted: true,
    });
    let client = HttpMailboxClient::with_retry(
        transport.clone(),
        RetryConfig {
            base_delay_ms: 0,
            ..RetryConfig::default()
        },
    );
    let mb = MailboxConfig {
        onion_address: "cover.onion".into(),
        fetch_capability: [1; 32],
        deposit_capability: [2; 32],
        envelope_secret: [3; 32],
        cover_deposit_capability: None,
        cover_fetch_capability: None,
        cover_envelope_secret: None,
    };
    assert!(client
        .deposit_cover(&mb, &[2; 32], &[9; 256])
        .await
        .is_err());
    assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn row9_user_message_outranks_parked_typing() {
    let mut service = service_ready_to_send();
    let queues = Arc::new(PendingQueues::new());
    service.set_slot_source(Arc::new(SlotSource::new(
        queues.clone(),
        Arc::new(AtomicBool::new(true)),
    )));
    let control = service.send_control_message(
        1,
        &najwa_protocol::message::control::ControlMessage::TypingIndicator,
    );
    tokio::pin!(control);
    assert!(
        tokio::time::timeout(Duration::from_millis(40), &mut control)
            .await
            .is_err()
    );
    let user = service.send_message(1, MessageContent::Text("priority one".into()));
    tokio::pin!(user);
    assert!(tokio::time::timeout(Duration::from_millis(40), &mut user)
        .await
        .is_err());
    assert_eq!(queues.len(), 2);
    let item = queues.pop_highest("bobmailbox").unwrap();
    assert_eq!(item.priority, AbsorptionPriority::RealMessage);
    if let crate::cover::PendingPayload::Slot(tx) = item.payload {
        tx.send(crate::cover::SlotPermit::unpaced(SlotGrant::Granted))
            .unwrap();
    } else {
        panic!("expected permit");
    }
    user.await.unwrap();
    assert_eq!(service.mailbox_client.take_deposited().len(), 1);
    assert_eq!(
        queues.pop_highest("bobmailbox").unwrap().priority,
        AbsorptionPriority::TypingIndicator
    );
}

#[tokio::test]
async fn row9_blocked_send_replaces_grant_with_cover() {
    let mut service = service_ready_to_send();
    let mailbox = service.mailbox_client.clone();
    let mut scheduler = CoverTrafficScheduler::new(fast_config());
    scheduler.replace_mailboxes(vec![snapshot()]);
    service.set_slot_source(scheduler.slot_source());
    scheduler.start(Arc::new(mailbox.clone()));
    let send = service.send_message(1, MessageContent::Text("cancel before grant".into()));
    tokio::pin!(send);
    assert!(tokio::time::timeout(Duration::from_millis(40), &mut send)
        .await
        .is_err());
    assert_eq!(scheduler.pending_queues().len(), 1);
    service.block_contact(1).await.unwrap();
    tokio::time::timeout(Duration::from_secs(3), &mut send)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while scheduler.snapshot().cover_deposits == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(scheduler.snapshot().real_sends_absorbed, 0);
    let deposits = mailbox.take_deposited();
    assert!(!deposits.is_empty());
    assert!(deposits.iter().all(|(onion, _)| onion == "cover.onion"));
}

#[tokio::test]
async fn row9_duplicate_dispatch_cannot_release_another_frames_claim() {
    let mut service = service_ready_to_send();
    let queues = Arc::new(PendingQueues::new());
    service.set_slot_source(Arc::new(SlotSource::new(
        queues.clone(),
        Arc::new(AtomicBool::new(true)),
    )));
    let send = service.send_message(1, MessageContent::Text("one durable frame".into()));
    tokio::pin!(send);
    assert!(tokio::time::timeout(Duration::from_millis(40), &mut send)
        .await
        .is_err());
    for _ in 0..2 {
        tokio::time::timeout(Duration::from_millis(100), service.retry_outgoing())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(queues.len(), 1);
    }
    if let crate::cover::PendingPayload::Slot(tx) =
        queues.pop_highest("bobmailbox").unwrap().payload
    {
        tx.send(crate::cover::SlotPermit::unpaced(SlotGrant::Granted))
            .unwrap();
    }
    send.await.unwrap();
    assert_eq!(service.mailbox_client.take_deposited().len(), 1);
}

#[tokio::test]
async fn row9_expired_permit_cannot_emit_after_fallback_cover() {
    let mailbox = Arc::new(MockMailbox::new());
    let mut scheduler = CoverTrafficScheduler::new(fast_config());
    scheduler.replace_mailboxes(vec![snapshot()]);
    scheduler.start(mailbox.clone());
    let permit = scheduler
        .slot_source()
        .await_slot("peer", AbsorptionPriority::Control, None)
        .await;
    assert!(permit.was_paced());
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(!permit.begin());
    assert!(scheduler.snapshot().cover_deposits >= 1);
    assert_eq!(scheduler.snapshot().real_sends_absorbed, 0);
}

struct PowTransport {
    deposits: AtomicUsize,
    requests: std::sync::Mutex<Vec<(CircuitIsolation, String, serde_json::Value)>>,
}

#[tokio::test]
async fn row9_stale_retry_batch_cannot_resend_completed_attempt() {
    let mut service = service_ready_to_send();
    let queues = Arc::new(PendingQueues::new());
    service.set_slot_source(Arc::new(SlotSource::new(
        queues.clone(),
        Arc::new(AtomicBool::new(true)),
    )));
    let send = service.send_message(1, MessageContent::Text("one attempt".into()));
    tokio::pin!(send);
    assert!(tokio::time::timeout(Duration::from_millis(40), &mut send)
        .await
        .is_err());
    let stale = service.storage.outgoing_frames().await.unwrap().remove(0);
    if let crate::cover::PendingPayload::Slot(tx) =
        queues.pop_highest("bobmailbox").unwrap().payload
    {
        tx.send(crate::cover::SlotPermit::unpaced(SlotGrant::Granted))
            .unwrap();
    }
    send.await.unwrap();
    tokio::time::timeout(
        Duration::from_millis(100),
        service.retry_frame(&stale, AbsorptionPriority::RealMessage),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(queues.is_empty());
    assert_eq!(service.mailbox_client.take_deposited().len(), 1);
}
#[async_trait]
impl Transport for PowTransport {
    async fn get_circuit(
        &self,
        isolation: CircuitIsolation,
    ) -> std::result::Result<CircuitHandle, TransportError> {
        Ok(CircuitHandle::new(isolation))
    }
    async fn post(
        &self,
        circuit: &CircuitHandle,
        url: &str,
        body: &[u8],
        _: &str,
    ) -> std::result::Result<HttpResponse, TransportError> {
        self.requests.lock().unwrap().push((
            circuit.isolation.clone(),
            url.into(),
            serde_json::from_slice(body).unwrap(),
        ));
        let (status, body) = if url.ends_with("/deposit") {
            if self.deposits.fetch_add(1, Ordering::SeqCst) == 0 {
                (429, vec![])
            } else {
                (200, br#"{"accepted":true,"message_id":null}"#.to_vec())
            }
        } else if url.ends_with("/challenge") {
            (
                200,
                serde_json::to_vec(&PowChallenge {
                    challenge: vec![1; 32],
                    difficulty: 0,
                    algorithm: "sha256-leading-zeros".into(),
                    expires_at: najwa_crypto::time::now() + 300,
                })
                .unwrap(),
            )
        } else {
            (200, b"{}".to_vec())
        };
        Ok(HttpResponse {
            status,
            headers: Default::default(),
            body,
        })
    }
    async fn get(
        &self,
        _: &CircuitHandle,
        _: &str,
    ) -> std::result::Result<HttpResponse, TransportError> {
        unreachable!()
    }
}

#[tokio::test]
async fn row9_pow_retry_waits_for_a_second_slot() {
    let warm = service_ready_to_send();
    warm.send_message(1, MessageContent::Text("establish session".into()))
        .await
        .unwrap();
    let transport = Arc::new(PowTransport {
        deposits: AtomicUsize::new(0),
        requests: Default::default(),
    });
    let mut service = MessagingService::new(
        warm.identity_key,
        warm.storage,
        HttpMailboxClient::new(transport.clone()),
    );
    let queues = Arc::new(PendingQueues::new());
    service.set_slot_source(Arc::new(SlotSource::new(
        queues.clone(),
        Arc::new(AtomicBool::new(true)),
    )));
    let send = service.send_message(1, MessageContent::Text("paced PoW".into()));
    tokio::pin!(send);
    assert!(tokio::time::timeout(Duration::from_millis(40), &mut send)
        .await
        .is_err());
    assert_eq!(transport.deposits.load(Ordering::SeqCst), 0);
    for expected in [1, 2] {
        assert_eq!(queues.len(), 1);
        if let crate::cover::PendingPayload::Slot(tx) =
            queues.pop_highest("bobmailbox").unwrap().payload
        {
            tx.send(crate::cover::SlotPermit::unpaced(SlotGrant::Granted))
                .unwrap();
        }
        if expected == 1 {
            assert!(tokio::time::timeout(Duration::from_millis(200), &mut send)
                .await
                .is_err());
            assert_eq!(
                transport.deposits.load(Ordering::SeqCst),
                1,
                "PoW must not redeposit on the first grant"
            );
        }
    }
    send.await.unwrap();
    assert_eq!(transport.deposits.load(Ordering::SeqCst), 2);
    let requests = transport.requests.lock().unwrap();
    let deposits: Vec<_> = requests
        .iter()
        .filter(|(_, url, _)| url.ends_with("/deposit"))
        .collect();
    assert!(deposits[0].2.get("pow_solution").is_none());
    assert!(deposits[1].2.get("pow_solution").is_some());
}

#[tokio::test]
async fn row9_cover_ack_uses_cover_circuit_and_fetch_capability() {
    let transport = Arc::new(PowTransport {
        deposits: AtomicUsize::new(0),
        requests: Default::default(),
    });
    let client = HttpMailboxClient::new(transport.clone());
    let mailbox = MailboxConfig {
        onion_address: "cover.onion".into(),
        fetch_capability: [1; 32],
        deposit_capability: [2; 32],
        envelope_secret: [3; 32],
        cover_deposit_capability: None,
        cover_fetch_capability: None,
        cover_envelope_secret: None,
    };
    client
        .acknowledge_cover(&mailbox, &[4; 32], &["old-cover".into()])
        .await
        .unwrap();
    let requests = transport.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].0,
        CircuitIsolation::CoverTraffic("cover.onion".into())
    );
    let ack: najwa_protocol::mailbox::types::AcknowledgeRequest =
        serde_json::from_value(requests[0].2.clone()).unwrap();
    assert_eq!(ack.fetch_capability, [4; 32]);
    assert_eq!(ack.message_ids, vec!["old-cover"]);
}
