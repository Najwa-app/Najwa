//! Bounded SQLCipher-backed upload and preparation parts, independent of HTTP.
use crate::{
    database::SqliteStorage,
    error::{Result, StorageError},
    types::MessageId,
};
use rusqlite::{params, OptionalExtension};

pub const UPLOAD_PART: usize = 1024 * 1024;
pub const MAX_TRANSFER: u64 = 256 * 1024 * 1024;
#[derive(Debug, Clone)]
pub struct Transfer {
    pub id: String,
    pub contact: i64,
    pub manifest: Vec<u8>,
    pub size: u64,
    pub received: u64,
    pub state: u32,
    pub cursor: u32,
    pub metadata: Option<Vec<u8>>,
    pub error: Option<String>,
}

fn transfer(r: &rusqlite::Row<'_>) -> rusqlite::Result<Transfer> {
    Ok(Transfer {
        id: r.get(0)?,
        contact: r.get(1)?,
        manifest: r.get(2)?,
        size: r.get::<_, i64>(3)? as u64,
        received: r.get::<_, i64>(4)? as u64,
        state: r.get(5)?,
        cursor: r.get(6)?,
        metadata: r.get(7)?,
        error: r.get(8)?,
    })
}
const TRANSFER_COLUMNS: &str = "id,contact_id,manifest,size,received,state,cursor,metadata,error";
/// S11 §4.1: a received file whose quiet period has elapsed.
#[derive(Debug, Clone)]
pub struct FileNackDue {
    /// The received `FileMetadata` message row.
    pub metadata_id: MessageId,
    pub contact_id: i64,
    /// Encoded `FileMetadata`.
    pub metadata: Vec<u8>,
    /// FileChunkNacks already sent for the file.
    pub attempts: u32,
    /// Distinct stored part indices, ascending.
    pub stored: Vec<u32>,
}
fn invalid() -> StorageError {
    StorageError::InvalidData("invalid transfer".into())
}
/// S11 §4.3: stored received part bodies per contact whose `FileMetadata` has
/// not arrived — the 1,093 part bodies of one 256 MiB file.
pub const ORPHAN_PART_BYTES: i64 = MAX_TRANSFER as i64 + 1_093 * 24;
/// S11 §4.3: age after which a received part without metadata is deleted.
pub const ORPHAN_PART_SECS: i64 = 7 * 86_400;
const ORPHANS: &str = "FROM messages WHERE contact_id=?1 AND direction=0 AND content_type=11 AND disappear_timer IS NULL AND substr(content,1,16) NOT IN (SELECT substr(content,1,16) FROM messages WHERE contact_id=?1 AND direction=0 AND content_type=10 AND disappear_timer IS NULL)";
/// Called in the receive transaction before a message row is inserted. For an
/// unsealed received part, deletes the contact's expired orphan parts, then
/// refuses the part if it has no metadata yet and would exceed the cap.
/// ponytail: expired orphans go when the contact's next part arrives; add a
/// periodic sweep if orphans left by a contact that stops sending matter.
pub(crate) fn orphan_part_refused(
    tx: &rusqlite::Transaction<'_>,
    msg: &crate::types::NewMessage,
    disappearing: Option<(u32, u64)>,
) -> Result<bool> {
    use crate::types::{ContentType, MessageDirection};
    if msg.direction != MessageDirection::Received
        || msg.content_type != ContentType::FileChunk
        || msg.disappear_timer.is_some()
        || disappearing.is_some()
    {
        return Ok(false);
    }
    let cutoff = najwa_crypto::time::now() as i64 - ORPHAN_PART_SECS;
    tx.execute(
        &format!("DELETE {ORPHANS} AND received_at<?2"),
        params![msg.contact_id, cutoff],
    )?;
    let session = &msg.content[..msg.content.len().min(16)];
    // A part of a file whose metadata arrived restarts that file's quiet
    // period (S11 §4.1): `last_retry_at` of a received metadata row is the
    // time of its last part or FileChunkNack.
    let has_metadata = tx.execute("UPDATE messages SET last_retry_at=?3 WHERE contact_id=?1 AND direction=0 AND content_type=10 AND disappear_timer IS NULL AND substr(content,1,16)=?2", params![msg.contact_id, session, najwa_crypto::time::now() as i64])? > 0;
    if has_metadata {
        return Ok(false);
    }
    let stored: i64 = tx.query_row(
        &format!("SELECT COALESCE(SUM(length(content)),0) {ORPHANS}"),
        params![msg.contact_id],
        |r| r.get(0),
    )?;
    Ok(stored + msg.content.len() as i64 > ORPHAN_PART_BYTES)
}
impl SqliteStorage {
    pub fn outgoing_file_session(&self, id: i64) -> Result<Option<[u8; 16]>> {
        let bytes: Option<Vec<u8>> = self.conn().query_row(
            "SELECT substr(m.content,1,16) FROM outgoing_frames f JOIN messages m ON m.id=f.message_id AND m.contact_id=f.contact_id WHERE f.id=?1 AND m.direction=1 AND m.content_type IN (10,11) AND m.disappear_timer IS NULL AND length(m.content)>=16",
            params![id], |r| r.get(0),
        ).optional()?;
        bytes.map(|v| v.try_into().map_err(|_| invalid())).transpose()
    }

    pub fn outgoing_frame_ids(&self) -> Result<Vec<i64>> {
        let conn = self.conn();
        let mut s=conn.prepare("SELECT f.id FROM outgoing_frames f LEFT JOIN messages m ON m.id=f.message_id WHERE f.next_attempt<=?1 AND (f.message_id IS NULL OR ((f.is_replay=1 OR m.status NOT IN (2,3,5)) AND (m.disappear_at IS NULL OR m.disappear_at>?2))) ORDER BY f.id")?;
        let result = s
            .query_map(
                params![
                    najwa_crypto::time::now() as i64,
                    najwa_crypto::time::now_ms()
                ],
                |r| r.get(0),
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(result)
    }
    pub fn outgoing_frame_page(
        &self,
        id: Option<i64>,
        limit: u32,
    ) -> Result<Vec<crate::messaging::OutgoingFrame>> {
        let conn = self.conn();
        let mut s=conn.prepare("SELECT f.id,f.contact_id,f.message_id,f.wire,f.dh_pub,f.n,f.requires_ack,f.attempts,f.next_attempt,f.deposited_at FROM outgoing_frames f LEFT JOIN messages m ON m.id=f.message_id WHERE (?1 IS NULL OR f.id=?1) AND (f.message_id IS NULL OR ((f.is_replay=1 OR m.status NOT IN (2,3,5)) AND (m.disappear_at IS NULL OR m.disappear_at>?2))) AND (?1 IS NOT NULL OR f.next_attempt<=?3) ORDER BY CASE WHEN m.content_type IN (10,11) THEN 1 ELSE 0 END,f.id LIMIT ?4")?;
        let result = s
            .query_map(
                params![
                    id,
                    najwa_crypto::time::now_ms(),
                    najwa_crypto::time::now() as i64,
                    limit.min(64)
                ],
                |r| {
                    let dh: Vec<u8> = r.get(4)?;
                    Ok(crate::messaging::OutgoingFrame {
                        id: r.get(0)?,
                        contact_id: r.get(1)?,
                        message_id: r.get(2)?,
                        wire: r.get(3)?,
                        dh_pub: dh.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?,
                        n: r.get(5)?,
                        requires_ack: r.get(6)?,
                        attempts: r.get(7)?,
                        next_attempt: r.get::<_, i64>(8)?.max(0) as u64,
                        deposited_at: r.get::<_, Option<i64>>(9)?.map(|v| v.max(0) as u64),
                    })
                },
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(result)
    }
    pub fn begin_transfer(
        &self,
        id: &str,
        cid: i64,
        fingerprint: &[u8; 32],
        manifest: &[u8],
        size: u64,
    ) -> Result<Transfer> {
        if id.len() != 32
            || !id.bytes().all(|b| b.is_ascii_hexdigit())
            || manifest.len() > 32768
            || size == 0
            || size > MAX_TRANSFER
        {
            return Err(invalid());
        }
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let contact: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM contacts WHERE id=?1 AND blocked=0)",
            params![cid],
            |r| r.get(0),
        )?;
        if !contact {
            return Err(StorageError::NotFound);
        }
        if let Some(existing)=tx.query_row(&format!("SELECT {TRANSFER_COLUMNS} FROM browser_transfers WHERE contact_id=?1 AND fingerprint=?2"),params![cid,fingerprint.as_slice()],transfer).optional()? {
            if existing.state<3 {return Ok(existing)}
            tx.execute("DELETE FROM browser_transfers WHERE id=?1",params![existing.id])?;
        }
        let count:i64=tx.query_row("SELECT (SELECT COUNT(*) FROM browser_transfers WHERE state<3)+(SELECT COUNT(*) FROM settings WHERE key GLOB 'desktop:attachment-job:*')",[],|r|r.get(0))?;
        if count >= 4 {
            return Err(StorageError::InvalidData("attachment queue full".into()));
        }
        tx.execute("INSERT INTO browser_transfers(id,contact_id,fingerprint,manifest,size,created_at) VALUES(?1,?2,?3,?4,?5,?6)",params![id,cid,fingerprint.as_slice(),manifest,size as i64,najwa_crypto::time::now() as i64])?;
        let value = tx.query_row(
            &format!("SELECT {TRANSFER_COLUMNS} FROM browser_transfers WHERE id=?1"),
            params![id],
            transfer,
        )?;
        tx.commit()?;
        Ok(value)
    }
    pub fn transfer(&self, id: &str) -> Result<Option<Transfer>> {
        Ok(self
            .conn()
            .query_row(
                &format!("SELECT {TRANSFER_COLUMNS} FROM browser_transfers WHERE id=?1"),
                params![id],
                transfer,
            )
            .optional()?)
    }
    pub fn transfers(&self, cid: Option<i64>) -> Result<Vec<Transfer>> {
        let conn = self.conn();
        let mut s=conn.prepare(&format!("SELECT {TRANSFER_COLUMNS} FROM browser_transfers WHERE state!=3 AND (?1 IS NULL OR contact_id=?1) ORDER BY (state=4),created_at,id LIMIT 8"))?;
        let result = s
            .query_map(params![cid], transfer)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(result)
    }
    pub fn put_upload_part(&self, id: &str, part: u32, bytes: &[u8]) -> Result<()> {
        if bytes.is_empty() || bytes.len() > UPLOAD_PART {
            return Err(invalid());
        }
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let (size,state):(i64,u32)=tx.query_row("SELECT size,state FROM browser_transfers WHERE id=?1 AND EXISTS(SELECT 1 FROM contacts WHERE contacts.id=contact_id AND blocked=0)",params![id],|r|Ok((r.get(0)?,r.get(1)?)))?;
        let size = size as u64;
        let start = part as u64 * UPLOAD_PART as u64;
        if state != 0
            || start >= size
            || bytes.len() as u64 != (size - start).min(UPLOAD_PART as u64)
        {
            return Err(invalid());
        }
        let old:Option<Vec<u8>>=tx.query_row("SELECT data FROM browser_transfer_parts WHERE transfer_id=?1 AND kind=0 AND part=?2",params![id,part],|r|r.get(0)).optional()?;
        if let Some(old) = old {
            if old != bytes {
                return Err(invalid());
            }
            return Ok(());
        }
        tx.execute(
            "INSERT INTO browser_transfer_parts VALUES(?1,0,?2,?3)",
            params![id, part, bytes],
        )?;
        tx.execute(
            "UPDATE browser_transfers SET received=received+?2 WHERE id=?1",
            params![id, bytes.len() as i64],
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn transfer_part(&self, id: &str, kind: u32, part: u32) -> Result<Option<Vec<u8>>> {
        Ok(self.conn().query_row("SELECT data FROM browser_transfer_parts WHERE transfer_id=?1 AND kind=?2 AND part=?3",params![id,kind,part],|r|r.get(0)).optional()?)
    }
    pub fn uploaded_parts(&self, id: &str) -> Result<Vec<u32>> {
        let conn = self.conn();
        let mut s = conn.prepare(
            "SELECT part FROM browser_transfer_parts WHERE transfer_id=?1 AND kind=0 ORDER BY part",
        )?;
        let result = s
            .query_map(params![id], |r| r.get(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(result)
    }
    pub fn seal_upload(&self, id: &str) -> Result<()> {
        let n = self.conn().execute(
            "UPDATE browser_transfers SET state=1 WHERE id=?1 AND state=0 AND received=size",
            params![id],
        )?;
        if n != 1 {
            let t = self.transfer(id)?.ok_or(StorageError::NotFound)?;
            if t.state == 0 {
                return Err(invalid());
            }
        }
        Ok(())
    }
    pub fn reset_transfer_output(&self, id: &str) -> Result<()> {
        self.conn().execute("DELETE FROM browser_transfer_parts WHERE transfer_id=?1 AND kind=1 AND EXISTS(SELECT 1 FROM browser_transfers WHERE id=?1 AND state=1)",params![id])?;
        Ok(())
    }
    pub fn put_transfer_output(&self, id: &str, part: u32, bytes: &[u8]) -> Result<()> {
        if bytes.len() > UPLOAD_PART {
            return Err(invalid());
        }
        let changed=self.conn().execute("INSERT INTO browser_transfer_parts SELECT ?1,1,?2,?3 WHERE EXISTS(SELECT 1 FROM browser_transfers t JOIN contacts c ON c.id=t.contact_id WHERE t.id=?1 AND t.state=1 AND c.blocked=0) ON CONFLICT(transfer_id,kind,part) DO UPDATE SET data=excluded.data",params![id,part,bytes])?;
        if changed != 1 {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }
    pub fn finish_transfer_output(&self, id: &str, metadata: &[u8]) -> Result<()> {
        if metadata.len() > 4096 {
            return Err(invalid());
        }
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        if tx.execute(
            "UPDATE browser_transfers SET state=2,metadata=?2,cursor=0 WHERE id=?1 AND state=1",
            params![id, metadata],
        )? != 1
        {
            return Err(StorageError::NotFound);
        }
        tx.execute(
            "DELETE FROM browser_transfer_parts WHERE transfer_id=?1 AND kind=0",
            params![id],
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn advance_transfer(&self, id: &str, cursor: u32, done: bool) -> Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        tx.execute("UPDATE browser_transfers SET cursor=?2,state=CASE WHEN ?3 THEN 3 ELSE state END WHERE id=?1 AND state=2",params![id,cursor,done])?;
        if done {
            tx.execute(
                "DELETE FROM browser_transfer_parts WHERE transfer_id=?1",
                params![id],
            )?;
        }
        tx.commit()?;
        Ok(())
    }
    pub fn fail_transfer(&self, id: &str, error: &str) -> Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        tx.execute(
            "UPDATE browser_transfers SET state=4,error=?2 WHERE id=?1",
            params![id, error],
        )?;
        tx.execute(
            "DELETE FROM browser_transfer_parts WHERE transfer_id=?1",
            params![id],
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn cancel_transfer(&self, id: &str, cid: i64) -> Result<()> {
        let n = self.conn().execute(
            "DELETE FROM browser_transfers WHERE id=?1 AND contact_id=?2 AND state IN (0,4)",
            params![id, cid],
        )?;
        if n != 1 {
            return Err(StorageError::InvalidData(
                "transfer already preparing".into(),
            ));
        }
        Ok(())
    }
    pub fn attachment_part(
        &self,
        cid: i64,
        session: &[u8; 16],
        outgoing: bool,
        index: u32,
    ) -> Result<Option<Vec<u8>>> {
        let conn = self.conn();
        let mut s=conn.prepare("SELECT content FROM messages WHERE contact_id=?1 AND direction=?2 AND content_type=11 AND disappear_timer IS NULL AND substr(content,1,16)=?3 AND substr(content,17,4)=?4 ORDER BY id")?;
        let mut rows = s.query(params![
            cid,
            i32::from(outgoing),
            session.as_slice(),
            index.to_be_bytes().as_slice()
        ])?;
        let mut result: Option<Vec<u8>> = None;
        while let Some(r) = rows.next()? {
            let data: Vec<u8> = r.get(0)?;
            if data.len() > 245_760 + 24 || result.as_ref().is_some_and(|old| old != &data) {
                return Err(invalid());
            }
            result = Some(data);
        }
        Ok(result)
    }
    /// S11 §4.1: received, unsealed files of unblocked contacts with at most
    /// `max_attempts` NACKs sent whose last part, NACK or metadata is at least
    /// `interval << attempts` seconds old.
    pub fn file_nacks_due(
        &self,
        now: i64,
        interval: i64,
        max_attempts: u32,
    ) -> Result<Vec<FileNackDue>> {
        let conn = self.conn();
        let mut s = conn.prepare("SELECT m.id,m.contact_id,m.content,COALESCE(m.retry_count,0) FROM contacts c JOIN messages m ON m.contact_id=c.id AND m.direction=0 AND m.content_type=10 AND m.disappear_timer IS NULL WHERE c.blocked=0 AND COALESCE(m.retry_count,0)<=?3 AND COALESCE(m.last_retry_at,m.received_at,0)+(?2<<COALESCE(m.retry_count,0))<=?1 ORDER BY m.id")?;
        let rows = s
            .query_map(params![now, interval, max_attempts], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, Vec<u8>>(2)?, r.get::<_, u32>(3)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut parts = conn.prepare("SELECT DISTINCT substr(content,17,4) FROM messages WHERE contact_id=?1 AND direction=0 AND content_type=11 AND disappear_timer IS NULL AND substr(content,1,16)=?2 ORDER BY 1")?;
        let mut due = Vec::with_capacity(rows.len());
        for (metadata_id, contact_id, metadata, attempts) in rows {
            let session = &metadata[..metadata.len().min(16)];
            let stored = parts
                .query_map(params![contact_id, session], |r| r.get::<_, Vec<u8>>(0))?
                .filter_map(|v| v.ok()?.try_into().ok().map(u32::from_be_bytes))
                .collect();
            due.push(FileNackDue { metadata_id, contact_id, metadata, attempts, stored });
        }
        Ok(due)
    }
    /// S11 §4.1: record `attempts` and restart the quiet period of a received
    /// file. `max_attempts + 1` ends the watch.
    pub fn record_file_nack(&self, metadata_id: MessageId, attempts: u32, now: i64) -> Result<()> {
        self.conn().execute(
            "UPDATE messages SET retry_count=?2,last_retry_at=?3 WHERE id=?1 AND direction=0 AND content_type=10",
            params![metadata_id, attempts, now],
        )?;
        Ok(())
    }
    /// S11 §4.1: the sender's stored copy of part `index` of file `session`
    /// sent to `cid`, with its logical sequence, for a FileChunkNack answer.
    pub fn outgoing_file_part(
        &self,
        cid: i64,
        session: &[u8; 16],
        index: u32,
    ) -> Result<Option<crate::messaging::HistoryMessage>> {
        let row: Option<(i64, i64, Vec<u8>)> = self.conn().query_row("SELECT m.id,h.logical_seq,h.logical_id FROM messages m JOIN outbound_history h ON h.message_id=m.id WHERE m.contact_id=?1 AND m.direction=1 AND m.content_type=11 AND m.disappear_timer IS NULL AND substr(m.content,1,16)=?2 AND substr(m.content,17,4)=?3 AND (m.disappear_at IS NULL OR m.disappear_at>?4) ORDER BY m.id LIMIT 1", params![cid, session.as_slice(), index.to_be_bytes().as_slice(), najwa_crypto::time::now_ms()], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).optional()?;
        let Some((id, seq, logical)) = row else {
            return Ok(None);
        };
        Ok(self.get_message(id)?.map(|message| crate::messaging::HistoryMessage {
            message,
            logical_seq: seq as u32,
            logical_msg_id: logical.try_into().unwrap_or_default(),
        }))
    }
    pub fn create_download_grant(
        &self,
        digest: &[u8; 32],
        cid: i64,
        message: MessageId,
    ) -> Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        tx.execute(
            "DELETE FROM browser_download_grants WHERE expires_at<=?1",
            params![najwa_crypto::time::now() as i64],
        )?;
        tx.execute("INSERT INTO browser_download_grants SELECT ?1,?2,?3,?4 WHERE EXISTS(SELECT 1 FROM messages WHERE id=?3 AND contact_id=?2)",params![digest.as_slice(),cid,message,najwa_crypto::time::now() as i64+3600])?;
        tx.commit()?;
        Ok(())
    }
    pub fn download_grant(&self, digest: &[u8; 32]) -> Result<Option<(i64, MessageId)>> {
        Ok(self.conn().query_row("SELECT contact_id,message_id FROM browser_download_grants WHERE digest=?1 AND expires_at>?2",params![digest.as_slice(),najwa_crypto::time::now() as i64],|r|Ok((r.get(0)?,r.get(1)?))).optional()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::NewContact;
    #[test]
    fn progress_index_upgrades_old_profiles_and_never_reads_file_body_records() {
        let dir=tempfile::tempdir().unwrap();let path=dir.path().join("index-upgrade.db");
        let db=SqliteStorage::open(&path,&[45;32]).unwrap();let cid=contact(&db,1);
        let session=[8u8;16];
        for index in 0..2u32 {
            let mut content=session.to_vec();content.extend(index.to_be_bytes());content.extend(vec![7;245760]);
            db.conn().execute("INSERT INTO messages(contact_id,msg_id,direction,content_type,flags,content,timestamp,status) VALUES(?1,?2,1,11,0,?3,1,?4)",params![cid,index.to_be_bytes().repeat(4),content,index]).unwrap();
        }
        db.conn().execute_batch("DROP INDEX idx_browser_file_progress; CREATE INDEX idx_browser_file_parts ON messages(contact_id,direction,substr(content,1,16),substr(content,17,4)) WHERE content_type=11 AND disappear_timer IS NULL;").unwrap();
        {
            let conn=db.conn();
            let mut statement=conn.prepare(&format!("EXPLAIN {}",crate::browser::ATTACHMENT_PROGRESS_SQL)).unwrap();
            let old_reads=statement.query_map(params![cid,1,session.as_slice()],|r|Ok((r.get::<_,String>(1)?,r.get::<_,i64>(2)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
            assert!(old_reads.iter().any(|(op,cursor)|op=="Column" && *cursor==0),"old preview index must demonstrate the body-record read");
        }
        drop(db);
        let db=SqliteStorage::open(&path,&[45;32]).unwrap();
        assert_eq!(db.attachment_progress(cid,&session,true).unwrap(),(2,1));
        let conn=db.conn();
        assert!(!conn.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='idx_browser_file_parts')",[],|r|r.get::<_,bool>(0)).unwrap());
        let root:i64=conn.query_row("SELECT rootpage FROM sqlite_master WHERE name='messages'",[],|r|r.get(0)).unwrap();
        let mut statement=conn.prepare(&format!("EXPLAIN {}",crate::browser::ATTACHMENT_PROGRESS_SQL)).unwrap();
        let ops=statement.query_map(params![cid,1,session.as_slice()],|r|Ok((r.get::<_,String>(1)?,r.get::<_,i64>(2)?,r.get::<_,i64>(3)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        let table_cursors:Vec<_>=ops.iter().filter(|(op,_,p2)|op=="OpenRead" && *p2==root).map(|(_,p1,_)|*p1).collect();
        assert!(!ops.iter().any(|(op,p1,_)|op=="Column" && table_cursors.contains(p1)),"progress must read index values instead of traversing file-body records: {ops:?}");
        drop(statement);drop(conn);
        db.conn().execute("UPDATE messages SET status=2 WHERE contact_id=?1",params![cid]).unwrap();
        assert_eq!(db.attachment_progress(cid,&session,true).unwrap(),(2,2));
    }
    fn contact(db: &SqliteStorage, tag: u8) -> i64 {
        db.create_contact(&NewContact {
            pseudonym: [tag; 32],
            their_ik_pub: [tag; 32],
            their_device_pub: [tag; 32],
            our_pseudonym: [tag + 1; 32],
            display_name: None,
        })
        .unwrap()
    }
    #[test]
    fn upload_parts_resume_exactly_after_restart_and_reject_conflicting_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("transfer.db");
        let key = [45; 32];
        let db = SqliteStorage::open(&path, &key).unwrap();
        let cid = contact(&db, 1);
        let id = "a".repeat(32);
        db.begin_transfer(&id, cid, &[2; 32], b"manifest", (UPLOAD_PART + 7) as u64)
            .unwrap();
        let part = vec![3; UPLOAD_PART];
        db.put_upload_part(&id, 0, &part).unwrap();
        db.put_upload_part(&id, 0, &part).unwrap();
        assert_eq!(
            db.transfer(&id).unwrap().unwrap().received,
            UPLOAD_PART as u64
        );
        assert!(db.put_upload_part(&id, 0, &vec![4; UPLOAD_PART]).is_err());
        assert!(db.seal_upload(&id).is_err());
        drop(db);
        let db = SqliteStorage::open(&path, &key).unwrap();
        let resumed = db
            .begin_transfer(
                &"b".repeat(32),
                cid,
                &[2; 32],
                b"manifest",
                (UPLOAD_PART + 7) as u64,
            )
            .unwrap();
        assert_eq!(resumed.id, id);
        assert_eq!(db.uploaded_parts(&id).unwrap(), vec![0]);
        db.put_upload_part(&id, 1, &[9; 7]).unwrap();
        db.seal_upload(&id).unwrap();
        assert_eq!(db.transfer(&id).unwrap().unwrap().state, 1);
        db.put_transfer_output(&id, 0, b"sanitized first try")
            .unwrap();
        db.reset_transfer_output(&id).unwrap();
        assert!(db.transfer_part(&id, 1, 0).unwrap().is_none());
        assert!(db.transfer_part(&id, 0, 0).unwrap().is_some());
        db.put_transfer_output(&id, 0, b"sanitized").unwrap();
        db.finish_transfer_output(&id, b"metadata").unwrap();
        assert!(db.transfer_part(&id, 0, 0).unwrap().is_none());
        db.advance_transfer(&id, 1, true).unwrap();
        assert!(db.transfer_part(&id, 1, 0).unwrap().is_none());
    }
    #[test]
    fn transfer_bounds_blocking_quota_and_contact_deletion_apply_to_staged_bytes() {
        let db = SqliteStorage::open_in_memory(&[45; 32]).unwrap();
        let cid = contact(&db, 1);
        let id = "a".repeat(32);
        db.begin_transfer(&id, cid, &[2; 32], b"manifest", MAX_TRANSFER)
            .unwrap();
        assert!(db
            .begin_transfer(
                &"b".repeat(32),
                cid,
                &[3; 32],
                b"manifest",
                MAX_TRANSFER + 1
            )
            .is_err());
        assert!(db.put_upload_part(&id, 256, &[1]).is_err());
        assert!(db
            .put_upload_part(&id, 0, &vec![1; UPLOAD_PART + 1])
            .is_err());
        db.conn()
            .execute("UPDATE contacts SET blocked=1 WHERE id=?1", params![cid])
            .unwrap();
        assert!(db.put_upload_part(&id, 0, &vec![1; UPLOAD_PART]).is_err());
        db.conn()
            .execute("UPDATE contacts SET blocked=0 WHERE id=?1", params![cid])
            .unwrap();
        db.put_upload_part(&id, 0, &vec![1; UPLOAD_PART]).unwrap();
        db.delete_contact(cid).unwrap();
        assert!(db.transfer(&id).unwrap().is_none());
        assert!(db.transfer_part(&id, 0, 0).unwrap().is_none());
    }
    #[test]
    fn delivery_pages_bound_ciphertext_and_prioritize_chat_over_file_parts() {
        let db = SqliteStorage::open_in_memory(&[45; 32]).unwrap();
        let cid = contact(&db, 1);
        let wire = vec![7u8; 262144];
        for n in 0..130u32 {
            let mid=db.conn().query_row("INSERT INTO messages(contact_id,msg_id,direction,content_type,flags,content,timestamp,status) VALUES(?1,?2,1,?3,0,X'00',1,0) RETURNING id",params![cid,n.to_be_bytes().repeat(4),if n==129{0}else{11}],|r|r.get::<_,i64>(0)).unwrap();
            db.conn().execute("INSERT INTO outgoing_frames(contact_id,message_id,wire,dh_pub,n,requires_ack,is_replay,attempts,next_attempt) VALUES(?1,?2,?3,?4,?5,0,0,0,0)",params![cid,mid,&wire,[1u8;32].as_slice(),n]).unwrap();
        }
        let page = db.outgoing_frame_page(None, 1000).unwrap();
        assert_eq!(page.len(), 64);
        assert_eq!(page[0].n, 129);
        assert_eq!(
            page.iter().map(|f| f.wire.len()).sum::<usize>(),
            64 * 262144
        );
        assert_eq!(db.outgoing_frame_ids().unwrap().len(), 130);
        let exact = db.outgoing_frame_page(Some(page[63].id), 1).unwrap();
        assert_eq!(exact.len(), 1);
        assert_eq!(exact[0].id, page[63].id);
    }
}
