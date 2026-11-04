use super::*;

impl DesktopClient {
    pub fn manage_contact(&self, contact: &str, action: &str, name: &str) -> Result<()> {
        let cid = positive_id(contact)?;
        if !matches!(action, "block" | "unblock" | "delete" | "rename") {
            return Err(DesktopError::new("invalid_request"));
        }
        if action == "rename" {
            checked_name(name)?;
        }
        let mut guard = OperationGuard::acquire().ok_or_else(|| DesktopError::new("locked"))?;
        let (runtime, service) = {
            let cell = state_cell().read().unwrap();
            let app = cell
                .as_ref()
                .ok_or_else(|| DesktopError::new("unavailable"))?;
            let (Some(_), Some(identity), Some(key)) = (&app.storage, &app.identity, &app.db_key)
            else {
                return Err(DesktopError::new("locked"));
            };
            let connected = app.service.lock().unwrap().clone();
            let service = match connected {
                Some(service) => service,
                // Before Tor connects, a service on a never-started transport
                // still seals Delete's RevocationNotice into the outbox (S08
                // §7.1) without any request; delivery starts once connected.
                None => {
                    let mut offline = state::FfiService::new(
                        identity.keypair.clone(),
                        storage(SqliteStorage::open_shared(&app.data_dir.join("najwa.db"), key.clone()))?,
                        HttpMailboxClient::new(Arc::new(najwa_transport::tor::TorTransport::new(
                            Default::default(),
                        ))),
                    );
                    offline.set_volatile_cache(app.disappearing_keys.clone());
                    Arc::new(offline)
                }
            };
            (app.runtime.handle().clone(), service)
        };
        runtime.block_on(guard.cancellable(async {
            messaging(service.manage_local_contact(cid as u64, action, name).await)
        }))??;
        Ok(())
    }

    pub fn invitation_details(&self, invitation: &str) -> Result<serde_json::Value> {
        if invitation.len() > 4096 {
            return Err(DesktopError::new("invalid_invitation"));
        }
        let payload = HandshakePayload::from_uri(invitation)
            .map_err(|_| DesktopError::new("invalid_invitation"))?;
        payload
            .verify()
            .map_err(|_| DesktopError::new("invalid_invitation"))?;
        let qr = payload
            .to_qr_string()
            .map_err(|_| DesktopError::new("qr_too_large"))?;
        let svg =
            najwa_protocol::contact::qr_card::generate_printable_card(&qr, &Default::default());
        let svg = String::from_utf8(svg).map_err(|_| DesktopError::new("invalid_invitation"))?;
        if svg.contains("QR data too large") {
            return Err(DesktopError::new("qr_too_large"));
        }
        Ok(serde_json::json!({"qrText":qr,"qrSvg":svg,"expiresAt":payload.expires_at}))
    }
}
