//! A slot is consumed only when its owner begins the network operation.
use super::absorption::SlotGrant;
use std::sync::{
    atomic::{AtomicU8, Ordering},
    Arc,
};
use tokio::sync::oneshot;

#[derive(Debug)]
#[must_use = "call begin immediately before the network operation; dropping emits replacement cover"]
pub struct SlotPermit {
    grant: SlotGrant,
    state: Option<Arc<AtomicU8>>,
    completion: Option<oneshot::Sender<()>>,
    deadline: Option<tokio::time::Instant>,
}

impl SlotPermit {
    pub fn unpaced(grant: SlotGrant) -> Self {
        Self {
            grant,
            state: None,
            completion: None,
            deadline: None,
        }
    }

    pub(crate) fn tracked() -> (Self, Arc<AtomicU8>, oneshot::Receiver<()>) {
        let state = Arc::new(AtomicU8::new(0));
        let (tx, rx) = oneshot::channel();
        (
            Self {
                grant: SlotGrant::Granted,
                state: Some(state.clone()),
                completion: Some(tx),
                deadline: Some(tokio::time::Instant::now() + std::time::Duration::from_secs(1)),
            },
            state,
            rx,
        )
    }

    pub fn was_paced(&self) -> bool {
        self.grant.was_paced()
    }

    /// False means the lease expired: the scheduler emitted cover, so the
    /// caller must acquire a fresh slot. No await may separate this from send.
    pub fn begin(mut self) -> bool {
        if self
            .deadline
            .is_some_and(|deadline| tokio::time::Instant::now() >= deadline)
        {
            return false;
        }
        if let Some(state) = &self.state {
            if state
                .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_err()
            {
                return false;
            }
        }
        if let Some(tx) = self.completion.take() {
            let _ = tx.send(());
        }
        true
    }
}

impl PartialEq<SlotGrant> for SlotPermit {
    fn eq(&self, other: &SlotGrant) -> bool {
        self.grant == *other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn expired_permit_cannot_begin_before_scheduler_resumes() {
        let (permit, state, completion) = SlotPermit::tracked();
        tokio::time::sleep(std::time::Duration::from_millis(1050)).await;
        assert!(!permit.begin());
        assert_eq!(state.load(Ordering::SeqCst), 0);
        assert!(completion.await.is_err());
    }
}
