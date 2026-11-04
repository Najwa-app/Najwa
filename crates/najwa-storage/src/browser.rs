//! Queries for the browser's text/reply/file view. Chunk rows never consume the
//! visible page limit, and large file bytes are fetched only for a download.
use crate::{
    database::SqliteStorage,
    error::{Result, StorageError},
    messages::row_to_message,
    types::Message,
};
use rusqlite::params;

const COLUMNS: &str = "id,contact_id,msg_id,direction,content_type,flags,content,file_path,timestamp,received_at,read_at,status,retry_count,last_retry_at,reply_to_msg_id,disappear_timer,disappear_at,encrypted_blob,group_id,sender_display_name,origin_timestamp_ms,retry_wire_blob";
pub(crate) const ATTACHMENT_PROGRESS_SQL: &str = "SELECT COUNT(DISTINCT hex(substr(content,17,4))), COUNT(DISTINCT CASE WHEN status IN (1,2,3) THEN hex(substr(content,17,4)) END) FROM messages WHERE contact_id=?1 AND content_type=11 AND direction=?2 AND disappear_timer IS NULL AND substr(content,1,16)=?3";
impl SqliteStorage {
    /// Cursor pages contain only UI messages. Search reuses the durable-message
    /// exclusion policy and never scans file-chunk bodies or sealed content.
    pub fn browser_history(
        &self, cid: i64, before: Option<(i64, i64)>, query: Option<&str>,
    ) -> Result<Vec<Message>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!(
            "SELECT {COLUMNS} FROM messages
             WHERE contact_id=?1 AND content_type IN (0,8,10)
               AND (disappear_at IS NULL OR disappear_at>?2)
               AND (?3 IS NULL OR timestamp<?3 OR (timestamp=?3 AND id<?4))
               AND (?5 IS NULL OR (
                   content_type IN (0,8) AND (flags & 1)=0
                   AND disappear_timer IS NULL AND disappear_at IS NULL
                   AND instr(lower(CAST(CASE WHEN content_type=8 THEN substr(content,19) ELSE content END AS TEXT)),lower(?5))>0))
             ORDER BY timestamp DESC,id DESC LIMIT 200"
        ))?;
        let rows = stmt.query_map(params![cid, najwa_crypto::time::now_ms(), before.map(|v| v.0), before.map(|v| v.1), query], |row| Ok(row_to_message(row)))?;
        rows.map(|row| row.map_err(StorageError::from)?).collect()
    }
    pub fn browser_messages(&self, cid: i64) -> Result<Vec<Message>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!("SELECT {COLUMNS} FROM messages WHERE contact_id=?1 AND content_type IN (0,8,10) AND (disappear_at IS NULL OR disappear_at>?2) ORDER BY timestamp DESC,id DESC LIMIT 200"))?;
        let rows = stmt.query_map(params![cid, najwa_crypto::time::now_ms()], |r| {
            Ok(row_to_message(r))
        })?;
        rows.map(|r| r.map_err(StorageError::from)?).collect()
    }
    pub fn attachment_rows(
        &self,
        cid: i64,
        session: &[u8; 16],
        outgoing: bool,
    ) -> Result<Vec<Message>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!("SELECT {COLUMNS} FROM messages WHERE contact_id=?1 AND content_type=11 AND direction=?2 AND disappear_timer IS NULL AND substr(content,1,16)=?3 ORDER BY id LIMIT 2048"))?;
        let rows = stmt.query_map(params![cid, i32::from(outgoing), session.as_slice()], |r| {
            Ok(row_to_message(r))
        })?;
        rows.map(|r| r.map_err(StorageError::from)?).collect()
    }
    pub fn attachment_metadata_exists(&self, cid: i64, session: &[u8; 16]) -> Result<bool> {
        Ok(self.conn().query_row("SELECT EXISTS(SELECT 1 FROM messages WHERE contact_id=?1 AND content_type=10 AND direction=1 AND disappear_timer IS NULL AND substr(content,1,16)=?2)", params![cid,session.as_slice()], |r| r.get(0))?)
    }
    pub fn attachment_progress(
        &self,
        cid: i64,
        session: &[u8; 16],
        outgoing: bool,
    ) -> Result<(u32, u32)> {
        Ok(self.conn().query_row(ATTACHMENT_PROGRESS_SQL, params![cid,i32::from(outgoing),session.as_slice()], |r| Ok((r.get(0)?,r.get(1)?)))?)
    }
    pub fn set_contact_setting<T: serde::Serialize>(
        &self,
        cid: i64,
        key: &str,
        value: &T,
    ) -> Result<()> {
        self.conn().execute("INSERT OR REPLACE INTO settings(key,value,updated_at) SELECT ?1,?2,?3 WHERE EXISTS(SELECT 1 FROM contacts WHERE id=?4)",params![key,serde_json::to_vec(value)?,najwa_crypto::time::now() as i64,cid])?;
        Ok(())
    }
    pub fn attachment_jobs(&self) -> Result<Vec<String>> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT key FROM settings WHERE key GLOB 'desktop:attachment-job:*' ORDER BY updated_at,key LIMIT 8")?;
        let rows = stmt.query_map([], |r| r.get(0))?;
        rows.map(|r| r.map_err(StorageError::from)).collect()
    }
    pub fn stage_attachment(&self, cid: i64, key: &str, value: &[u8]) -> Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let count: i64 = tx.query_row(
            "SELECT COUNT(*) FROM settings WHERE key GLOB 'desktop:attachment-job:*'",
            [],
            |r| r.get(0),
        )?;
        if count >= 4 {
            return Err(StorageError::InvalidData("attachment queue full".into()));
        }
        let changed = tx.execute("INSERT INTO settings(key,value,updated_at) SELECT ?1,?2,?3 WHERE EXISTS(SELECT 1 FROM contacts WHERE id=?4 AND blocked=0)", params![key,value,najwa_crypto::time::now() as i64,cid])?;
        if changed == 0 {
            return Err(StorageError::NotFound);
        }
        tx.commit()?;
        Ok(())
    }
    pub fn advance_attachment(&self, key: &str, cursor: u32) -> Result<()> {
        // Replace only the cursor prefix. Never recreate a job after deletion.
        self.conn().execute(
            "UPDATE settings SET value=CAST(?2 || substr(value,5) AS BLOB) WHERE key=?1",
            params![key, cursor.to_be_bytes().as_slice()],
        )?;
        Ok(())
    }
}
