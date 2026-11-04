//! Read-only history/search adapters for the existing browser message view.
use super::*;

impl DesktopClient {
    pub fn message_history(
        &self,
        contact: &str,
        before: Option<(i64, String)>,
        query: Option<&str>,
    ) -> Result<Vec<Message>> {
        let cid = positive_id(contact)?;
        let before = before
            .map(|(timestamp, id)| {
                if timestamp < 0 {
                    return Err(DesktopError::new("invalid_request"));
                }
                Ok((timestamp, positive_id(&id)?))
            })
            .transpose()?;
        if query.is_some_and(|q| q.trim().is_empty() || q.len() > 512) {
            return Err(DesktopError::new("invalid_request"));
        }
        let _guard = OperationGuard::acquire().ok_or_else(|| DesktopError::new("locked"))?;
        let cell = state_cell().read().unwrap();
        let app = cell.as_ref().ok_or_else(|| DesktopError::new("unavailable"))?;
        let db = app.storage.as_ref().ok_or_else(|| DesktopError::new("locked"))?;
        if storage(db.get_contact(cid))?.is_none() {
            return Err(DesktopError::new("contact_missing"));
        }
        let mut result = Vec::new();
        for mut row in storage(db.browser_history(cid, before, query))? {
            if row.disappear_timer.is_some() {
                use najwa_core::disappearing::{open_sealed_content, Opened};
                match open_sealed_content(&app.disappearing_keys, &row.msg_id, &row.content)
                    .map_err(|_| DesktopError::new("storage_unavailable"))?
                {
                    Opened::Plaintext(bytes) => row.content = bytes,
                    Opened::Expired => continue,
                }
            }
            // The row's plaintext is copied into `text`; wipe the row.
            let content = attachments::message_content(db, &row);
            zeroize::Zeroize::zeroize(&mut row.content);
            let (text, reply_to, attachment) = content?;
            result.push(Message {
                id: row.id.to_string(), msg_id: crate::hex_encode(&row.msg_id), text,
                reply_to, attachment,
                outgoing: row.direction == najwa_storage::types::MessageDirection::Sent,
                timestamp: row.timestamp.max(0) as u64, status: status_name(row.status),
                expires_at: row.disappear_at.map(|at| at.max(0) as u64),
            });
        }
        Ok(result)
    }
}
