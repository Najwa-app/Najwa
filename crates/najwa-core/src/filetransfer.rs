//! File transfer: chunking, reassembly, session management, and progress tracking.
//!
//! Provides:
//! - File chunking for mailbox transport (<256KB per message, S11 §2.3)
//! - Chunk reassembly with hash verification
//! - Transfer session management with unique IDs
//! - Progress tracking for send/receive
//! - Pause, resume and cancel of in-memory sends
//!
//! The desktop app uses only the send side (`FileTransferManager::start_send`
//! and `next_chunk`) for the single-request path (S11 §9.7). The receive side
//! (`start_receive`, `add_chunk`, the in-memory early-chunk buffer,
//! `complete_receive`, progress and cleanup) is an in-memory implementation the
//! app does not call: the app stores received parts as message rows
//! (S11 §4.3) and assembles them from storage (S11 §2.4).

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

use najwa_sanitize::{sanitize_file, FileType, SanitizationSettings};

// ---------------------------------------------------------------------------
// Constants (S11 §2.1)
// ---------------------------------------------------------------------------

/// Maximum chunk size in bytes (~240KB, leaves room for encryption overhead).
pub use najwa_protocol::message::file_transfer::MAX_CHUNK_SIZE;

/// Hard cap on total file size (S11 §2.1): 256 MiB, enforced on both send and
/// receive sides so a hostile `FileMetadata` cannot force an unbounded
/// allocation (`Vec::with_capacity(total_size)`) or unbounded chunk state.
pub const MAX_FILE_SIZE: u64 = 268_435_456;

/// Bound on the in-memory orphan-chunk buffer (receive side, not used by the
/// app; S11 §4.3 requires the bound): 64 MiB across all transfers
/// whose `FileMetadata` has not yet arrived. Chunks routinely arrive before
/// their metadata over the reordering mailbox transport; buffering them (rather
/// than dropping them with `SessionNotFound`, which loses the consumed ratchet
/// key) prevents common-path unrecoverable loss — but the buffer MUST be bounded
/// so a sender cannot force unbounded allocation for a transfer it never opens.
pub const MAX_ORPHAN_BYTES: usize = 67_108_864;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Errors during file transfer operations.
#[derive(Debug, thiserror::Error)]
pub enum FileTransferError {
    /// The requested operation is not valid for this transfer state.
    #[error("transfer is not active")]
    InactiveTransfer,

    /// Received bytes disagree with the declared file size.
    #[error("file size mismatch: expected {expected}, received {received}")]
    SizeMismatch { expected: u64, received: u64 },
    /// Not all chunks have been received.
    #[error("missing chunks: expected {expected}, got {received}")]
    MissingChunks { expected: u32, received: u32 },

    /// Reassembled file hash does not match expected hash.
    #[error("hash mismatch: file corrupted or tampered")]
    HashMismatch,

    /// Duplicate chunk received.
    #[error("duplicate chunk index {0}")]
    DuplicateChunk(u32),

    /// A different chunk was received for an already-stored index (S11 §4.4) —
    /// corruption or tampering; the transfer must be failed.
    #[error("conflicting chunk at index {0}")]
    ChunkConflict(u32),

    /// Chunk index out of range.
    #[error("chunk index {index} out of range (total: {total})")]
    ChunkOutOfRange { index: u32, total: u32 },

    /// Transfer session not found.
    #[error("transfer session not found: {0:?}")]
    SessionNotFound([u8; 16]),

    /// Sanitization failed.
    #[error("sanitization failed: {0}")]
    SanitizationFailed(String),

    /// Declared total size exceeds `MAX_FILE_SIZE` (S11 §2.1).
    #[error("file too large: {size} bytes (max {MAX_FILE_SIZE})")]
    FileTooLarge { size: u64 },

    /// `total_chunks` is inconsistent with `total_size` (S11 §2.2.1).
    #[error("invalid chunk count: expected {expected}, declared {declared}")]
    InvalidChunkCount { expected: u32, declared: u32 },

    /// A received chunk exceeds `MAX_CHUNK_SIZE`, or cumulative received bytes
    /// would exceed the declared `total_size` (S11 §4.4).
    #[error("chunk size overflow: {0}")]
    ChunkSizeOverflow(String),
}

/// A file transfer session descriptor.
#[derive(Debug, Clone)]
pub struct FileTransferSession {
    /// Unique random transfer ID.
    pub transfer_id: [u8; 16],
    /// Original file name (sanitized of path info).
    pub file_name: String,
    /// Detected file type.
    pub file_type: FileType,
    /// Total size of the sanitized file in bytes.
    pub total_size: u64,
    /// Total number of chunks.
    pub total_chunks: u32,
    /// Size of each chunk (last chunk may be smaller).
    pub chunk_size: usize,
    /// SHA-256 hash of the complete sanitized file.
    pub sha256_hash: [u8; 32],
}

/// A single file chunk for transport.
#[derive(Debug, Clone)]
pub struct FileChunk {
    /// Transfer ID this chunk belongs to.
    pub transfer_id: [u8; 16],
    /// Zero-based chunk index.
    pub chunk_index: u32,
    /// Chunk data bytes.
    pub data: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Chunking (S11 §2.3)
// ---------------------------------------------------------------------------

/// Compute SHA-256 hash of data.
fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Generate 16 random bytes for a transfer ID (OS CSPRNG, S01 §5.1).
fn random_transfer_id() -> [u8; 16] {
    najwa_crypto::random::random_bytes()
}

/// Split sanitized bytes into chunks for transport (S11 §2.3).
///
/// Returns a session descriptor and the list of chunks.
///
/// Crate-internal primitive: the bytes MUST already have been through the
/// S11 §5.1 pipeline. External senders cannot reach this —
/// [`FileTransferManager::start_send`] sanitizes at the boundary
/// (S11 §5.1).
pub(crate) fn chunk_file(
    sanitized: &[u8],
    file_name: &str,
    file_type: FileType,
) -> Result<(FileTransferSession, Vec<FileChunk>), FileTransferError> {
    // S11 §2.1: reject oversized input at the send chokepoint.
    if sanitized.len() as u64 > MAX_FILE_SIZE {
        return Err(FileTransferError::FileTooLarge {
            size: sanitized.len() as u64,
        });
    }
    let transfer_id = random_transfer_id();
    let total_chunks = sanitized.len().div_ceil(MAX_CHUNK_SIZE) as u32;
    let file_hash = sha256(sanitized);

    let session = FileTransferSession {
        transfer_id,
        file_name: sanitize_filename(file_name),
        file_type,
        total_size: sanitized.len() as u64,
        total_chunks,
        chunk_size: MAX_CHUNK_SIZE,
        sha256_hash: file_hash,
    };

    let chunks: Vec<FileChunk> = sanitized
        .chunks(MAX_CHUNK_SIZE)
        .enumerate()
        .map(|(i, chunk)| FileChunk {
            transfer_id,
            chunk_index: i as u32,
            data: chunk.to_vec(),
        })
        .collect();

    Ok((session, chunks))
}

/// Sanitize a file name (S11 §2.5): strip path components, control chars, and
/// Unicode bidi/format overrides (RTL spoofing); trim trailing `.`/` `; map
/// empty/`.`/`..` to `unnamed`; prefix Windows reserved device names; and
/// UTF-8-truncate on a char boundary to 255 bytes (never panics on a multibyte
/// filename).
fn sanitize_filename(name: &str) -> String {
    // Keep the leaf only (strip any path components).
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);

    // Drop control chars (Cc) and Unicode bidi/zero-width format controls (Cf)
    // that enable filename spoofing.
    let cleaned: String = base
        .chars()
        .filter(|c| {
            !c.is_control()
                && !matches!(
                    *c,
                    '\u{200E}' | '\u{200F}'                 // LRM / RLM
                        | '\u{202A}'..='\u{202E}'           // LRE/RLE/PDF/LRO/RLO
                        | '\u{2066}'..='\u{2069}'           // LRI/RLI/FSI/PDI
                        | '\u{061C}'                        // Arabic letter mark
                        | '\u{200B}'..='\u{200D}'           // zero-width space/(non)joiner
                        | '\u{FEFF}'                        // zero-width no-break space / BOM
                )
        })
        .collect();

    // Trim trailing dots/spaces (Windows silently strips them → spoofing).
    let trimmed = cleaned.trim_end_matches(['.', ' ']).trim_start();

    // Empty / "." / ".." → a safe placeholder (no traversal, no empty name).
    let base_name = match trimmed {
        "" | "." | ".." => "unnamed",
        other => other,
    };

    // Prefix Windows reserved device names (case-insensitive, with or without an
    // extension): CON, PRN, AUX, NUL, COM1-9, LPT1-9.
    let stem = base_name.split('.').next().unwrap_or(base_name);
    let up = stem.to_ascii_uppercase();
    let is_reserved = matches!(up.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (up.len() == 4
            && (up.starts_with("COM") || up.starts_with("LPT"))
            && matches!(up.as_bytes()[3], b'1'..=b'9'));
    let safe = if is_reserved {
        format!("_{base_name}")
    } else {
        base_name.to_string()
    };

    // UTF-8-safe truncation to 255 bytes — back off to a char boundary so a
    // multibyte filename can never panic on a byte slice.
    if safe.len() <= 255 {
        safe
    } else {
        let mut end = 255;
        while end > 0 && !safe.is_char_boundary(end) {
            end -= 1;
        }
        safe[..end].to_string()
    }
}

// ---------------------------------------------------------------------------
// Reassembly (in memory; the app assembles from storage, S11 §2.4)
// ---------------------------------------------------------------------------

/// Reassemble chunks into a complete file.
///
/// Verifies all chunks are present and the final hash matches.
pub fn reassemble_file(
    session: &FileTransferSession,
    chunks: &[FileChunk],
) -> Result<Vec<u8>, FileTransferError> {
    // Verify all chunks present
    if chunks.len() != session.total_chunks as usize {
        return Err(FileTransferError::MissingChunks {
            expected: session.total_chunks,
            received: chunks.len() as u32,
        });
    }

    // Sort by chunk index
    let mut sorted = chunks.to_vec();
    sorted.sort_by_key(|c| c.chunk_index);

    // Verify no gaps or duplicates
    for (i, chunk) in sorted.iter().enumerate() {
        if chunk.chunk_index != i as u32 {
            return Err(FileTransferError::MissingChunks {
                expected: session.total_chunks,
                received: chunks.len() as u32,
            });
        }
    }

    // Reassemble. Size from the actual chunk bytes in hand — never trust
    // `session.total_size`, which may be a crafted header.
    let capacity: usize = sorted.iter().map(|c| c.data.len()).sum();
    if capacity as u64 != session.total_size || capacity as u64 > MAX_FILE_SIZE {
        return Err(FileTransferError::SizeMismatch {
            expected: session.total_size,
            received: capacity as u64,
        });
    }
    let mut assembled = Vec::with_capacity(capacity);
    for chunk in &sorted {
        assembled.extend_from_slice(&chunk.data);
    }

    // Verify hash
    if sha256(&assembled) != session.sha256_hash {
        return Err(FileTransferError::HashMismatch);
    }

    Ok(assembled)
}

// ---------------------------------------------------------------------------
// Transfer session management
// ---------------------------------------------------------------------------

/// Transfer direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferDirection {
    Send,
    Receive,
}

/// Transfer state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferState {
    /// Transfer is in progress.
    InProgress,
    /// Transfer completed successfully.
    Completed,
    /// Transfer failed.
    Failed,
    /// Transfer was cancelled.
    Cancelled,
    /// Transfer is paused and can be resumed.
    Paused,
}

/// In-memory progress information for a file transfer. The app reports
/// persisted progress instead (S11 §3).
#[derive(Debug, Clone)]
pub struct TransferProgress {
    /// Transfer session descriptor.
    pub session: FileTransferSession,
    /// Transfer direction.
    pub direction: TransferDirection,
    /// Current state.
    pub state: TransferState,
    /// Number of chunks transferred so far.
    pub chunks_transferred: u32,
    /// Bytes transferred so far.
    pub bytes_transferred: u64,
}

impl TransferProgress {
    /// Progress as a fraction (0.0 to 1.0).
    pub fn progress_fraction(&self) -> f64 {
        if self.session.total_chunks == 0 {
            return 1.0;
        }
        self.chunks_transferred as f64 / self.session.total_chunks as f64
    }

    /// Progress as a percentage (0 to 100).
    pub fn progress_percent(&self) -> u32 {
        (self.progress_fraction() * 100.0) as u32
    }
}

/// Manages active file transfer sessions in memory.
///
/// Tracks in-progress sends and receives, progress, and supports pause and
/// resume of sends. The app uses `start_send` and `next_chunk` for the
/// single-request path (S11 §9.7); the receive methods are not called by the
/// app.
pub struct FileTransferManager {
    /// Active send sessions: transfer_id → (session, chunks remaining)
    sends: Mutex<HashMap<[u8; 16], SendSession>>,
    /// Active receive sessions: transfer_id → receive buffer
    receives: Mutex<HashMap<[u8; 16], ReceiveSession>>,
    /// Chunks received BEFORE their `FileMetadata` (S11 §4.3): transfer_id →
    /// buffered chunks, drained into the session by `start_receive`. Bounded by
    /// [`MAX_ORPHAN_BYTES`].
    orphans: Mutex<HashMap<[u8; 16], Vec<FileChunk>>>,
}

/// Internal state for an outgoing transfer.
struct SendSession {
    session: FileTransferSession,
    chunks: Vec<FileChunk>,
    next_chunk: AtomicU32,
    state: TransferState,
}

/// Internal state for an incoming transfer.
struct ReceiveSession {
    session: FileTransferSession,
    chunks: HashMap<u32, FileChunk>,
    state: TransferState,
}

/// Validate and insert a chunk into a receive session (S11 §4.4). Shared by
/// `add_chunk` and the `start_receive` orphan drain; operates on an already-held
/// `&mut ReceiveSession` so neither caller re-locks the receives map.
fn insert_chunk(recv: &mut ReceiveSession, chunk: FileChunk) -> Result<(), FileTransferError> {
    if recv.state != TransferState::InProgress {
        return Err(FileTransferError::InactiveTransfer);
    }
    if chunk.chunk_index >= recv.session.total_chunks {
        return Err(FileTransferError::ChunkOutOfRange {
            index: chunk.chunk_index,
            total: recv.session.total_chunks,
        });
    }

    // S11 §4.4: a re-received index is idempotent iff the bytes match (a
    // legitimate re-send); a DIFFERING chunk at the same index
    // is a conflict (corruption/tamper) that fails the transfer.
    if let Some(existing) = recv.chunks.get(&chunk.chunk_index) {
        if existing.data == chunk.data {
            return Ok(());
        }
        recv.state = TransferState::Failed;
        return Err(FileTransferError::ChunkConflict(chunk.chunk_index));
    }

    // S11 §4.4: every non-final chunk MUST be exactly `chunk_size`; the final
    // chunk is the declared remainder. This exact check subsumes the
    // MAX_CHUNK_SIZE cap and rejects a truncated/padded chunk.
    let expected_len = if chunk.chunk_index + 1 == recv.session.total_chunks {
        recv.session
            .total_size
            .saturating_sub((recv.session.total_chunks as u64 - 1) * recv.session.chunk_size as u64)
            as usize
    } else {
        recv.session.chunk_size
    };
    if chunk.data.len() != expected_len {
        return Err(FileTransferError::ChunkSizeOverflow(format!(
            "chunk {} is {} bytes, expected {expected_len}",
            chunk.chunk_index,
            chunk.data.len()
        )));
    }
    let received: u64 = recv.chunks.values().map(|c| c.data.len() as u64).sum();
    if received + chunk.data.len() as u64 > recv.session.total_size {
        return Err(FileTransferError::ChunkSizeOverflow(format!(
            "cumulative received bytes would exceed declared total_size {}",
            recv.session.total_size
        )));
    }

    recv.chunks.insert(chunk.chunk_index, chunk);
    Ok(())
}

impl FileTransferManager {
    /// Create a new transfer manager.
    pub fn new() -> Self {
        Self {
            sends: Mutex::new(HashMap::new()),
            receives: Mutex::new(HashMap::new()),
            orphans: Mutex::new(HashMap::new()),
        }
    }

    /// Start a new outgoing file transfer (S11 §5.1).
    ///
    /// Sanitization is enforced HERE, not delegated to the caller: raw bytes
    /// go through the S11 §5.1 pipeline before anything is chunked — decodable
    /// images are structurally converted to WebP, unknown or unsupported
    /// formats are refused — so unsanitized data can never enter the chunk
    /// pipeline. The wire metadata describes the sanitized output type
    /// (images are `WebP` on the wire).
    pub fn start_send(
        &self,
        data: &[u8],
        file_name: &str,
    ) -> Result<FileTransferSession, FileTransferError> {
        let sanitized = sanitize_file(data, &SanitizationSettings::default())
            .map_err(|e| FileTransferError::SanitizationFailed(e.to_string()))?;
        let (session, chunks) =
            chunk_file(&sanitized.sanitized_bytes, file_name, sanitized.output_type)?;
        let transfer_id = session.transfer_id;

        let send = SendSession {
            session: session.clone(),
            chunks,
            next_chunk: AtomicU32::new(0),
            state: TransferState::InProgress,
        };

        self.sends.lock().unwrap().insert(transfer_id, send);
        Ok(session)
    }

    /// Get the next chunk to send for a transfer.
    ///
    /// Returns `None` when all chunks have been sent.
    pub fn next_chunk(&self, transfer_id: &[u8; 16]) -> Option<FileChunk> {
        let sends = self.sends.lock().unwrap();
        if let Some(send) = sends.get(transfer_id) {
            if send.state == TransferState::InProgress {
                let idx = send.next_chunk.load(Ordering::SeqCst);
                if let Some(chunk) = send.chunks.get(idx as usize) {
                    send.next_chunk.store(idx + 1, Ordering::SeqCst);
                    return Some(chunk.clone());
                }
            }
        }
        None
    }

    /// Register an incoming file transfer session (bounds of S11 §2.2.1).
    ///
    /// Validates the sender-declared `total_size` and `total_chunks` and
    /// re-sanitizes the file name before buffering, so a hostile `FileMetadata`
    /// cannot force an unbounded allocation or unbounded chunk state. Rejects
    /// `total_size > MAX_FILE_SIZE` and any `total_chunks` inconsistent with
    /// `total_size`.
    pub fn start_receive(&self, mut session: FileTransferSession) -> Result<(), FileTransferError> {
        if session.total_size > MAX_FILE_SIZE {
            return Err(FileTransferError::FileTooLarge {
                size: session.total_size,
            });
        }
        let expected = (session.total_size as usize).div_ceil(MAX_CHUNK_SIZE) as u32;
        if session.total_chunks != expected {
            return Err(FileTransferError::InvalidChunkCount {
                expected,
                declared: session.total_chunks,
            });
        }
        // Chunk size is a protocol constant, never a sender-controlled parameter.
        session.chunk_size = MAX_CHUNK_SIZE;
        // S11 §2.5: re-sanitize regardless of what the sender claims.
        session.file_name = sanitize_filename(&session.file_name);
        let transfer_id = session.transfer_id;
        let mut recv = ReceiveSession {
            session,
            chunks: HashMap::new(),
            state: TransferState::InProgress,
        };
        // S11 §4.3: drain any chunks that arrived before this metadata. A bad
        // orphan (out-of-range / wrong size / cumulative overflow) is dropped +
        // logged, never fatal to the transfer.
        if let Some(orphans) = self.orphans.lock().unwrap().remove(&transfer_id) {
            for chunk in orphans {
                if let Err(e) = insert_chunk(&mut recv, chunk) {
                    tracing::warn!(?transfer_id, error = %e, "dropping invalid buffered orphan chunk");
                }
            }
        }
        self.receives.lock().unwrap().insert(transfer_id, recv);
        Ok(())
    }

    /// Add a received chunk to the buffer.
    ///
    /// If the chunk arrives BEFORE its `FileMetadata` (no session registered
    /// yet), it is retained in the bounded orphan buffer (S11 §4.3) and drained
    /// by `start_receive`, rather than dropped with `SessionNotFound` — which
    /// would lose the already-consumed ratchet key, an unrecoverable common-path
    /// loss over the reordering mailbox transport.
    pub fn add_chunk(&self, chunk: FileChunk) -> Result<(), FileTransferError> {
        let mut receives = self.receives.lock().unwrap();
        match receives.get_mut(&chunk.transfer_id) {
            Some(recv) => insert_chunk(recv, chunk),
            None => {
                drop(receives);
                self.buffer_orphan(chunk)
            }
        }
    }

    /// Buffer a chunk whose session has not been registered yet (S11 §4.3),
    /// bounded by [`MAX_ORPHAN_BYTES`] across all pending transfers so a sender
    /// cannot force unbounded allocation for a transfer it never opens.
    fn buffer_orphan(&self, chunk: FileChunk) -> Result<(), FileTransferError> {
        if chunk.data.len() > MAX_CHUNK_SIZE {
            return Err(FileTransferError::ChunkSizeOverflow(format!(
                "orphan chunk {} bytes exceeds MAX_CHUNK_SIZE",
                chunk.data.len()
            )));
        }
        let mut orphans = self.orphans.lock().unwrap();
        let buffered: usize = orphans.values().flatten().map(|c| c.data.len()).sum();
        if buffered + chunk.data.len() > MAX_ORPHAN_BYTES {
            return Err(FileTransferError::ChunkSizeOverflow(
                "orphan-chunk buffer full (S11 §4.3)".into(),
            ));
        }
        orphans.entry(chunk.transfer_id).or_default().push(chunk);
        Ok(())
    }

    /// Check if all chunks have been received for a transfer.
    pub fn is_receive_complete(&self, transfer_id: &[u8; 16]) -> bool {
        let receives = self.receives.lock().unwrap();
        if let Some(recv) = receives.get(transfer_id) {
            recv.chunks.len() == recv.session.total_chunks as usize
        } else {
            false
        }
    }

    /// Attempt to reassemble a completed receive transfer.
    pub fn complete_receive(&self, transfer_id: &[u8; 16]) -> Result<Vec<u8>, FileTransferError> {
        let mut receives = self.receives.lock().unwrap();
        let recv = receives
            .get_mut(transfer_id)
            .ok_or(FileTransferError::SessionNotFound(*transfer_id))?;

        if !matches!(
            recv.state,
            TransferState::InProgress | TransferState::Completed
        ) {
            return Err(FileTransferError::InactiveTransfer);
        }

        let chunks: Vec<FileChunk> = recv.chunks.values().cloned().collect();
        let result = match reassemble_file(&recv.session, &chunks) {
            Ok(result) => result,
            Err(error) => {
                if !matches!(error, FileTransferError::MissingChunks { .. }) {
                    recv.state = TransferState::Failed;
                }
                return Err(error);
            }
        };

        recv.state = TransferState::Completed;
        Ok(result)
    }

    /// Get progress for a send transfer.
    pub fn send_progress(&self, transfer_id: &[u8; 16]) -> Option<TransferProgress> {
        let sends = self.sends.lock().unwrap();
        sends.get(transfer_id).map(|send| {
            let chunks_sent = send.next_chunk.load(Ordering::SeqCst);
            TransferProgress {
                session: send.session.clone(),
                direction: TransferDirection::Send,
                state: send.state,
                chunks_transferred: chunks_sent,
                bytes_transferred: send
                    .chunks
                    .iter()
                    .take(chunks_sent as usize)
                    .map(|chunk| chunk.data.len() as u64)
                    .sum(),
            }
        })
    }

    /// Get progress for a receive transfer.
    pub fn receive_progress(&self, transfer_id: &[u8; 16]) -> Option<TransferProgress> {
        let receives = self.receives.lock().unwrap();
        receives.get(transfer_id).map(|recv| {
            let chunks_received = recv.chunks.len() as u32;
            let bytes: u64 = recv.chunks.values().map(|c| c.data.len() as u64).sum();
            TransferProgress {
                session: recv.session.clone(),
                direction: TransferDirection::Receive,
                state: recv.state,
                chunks_transferred: chunks_received,
                bytes_transferred: bytes,
            }
        })
    }

    /// Cancel a send transfer.
    pub fn cancel_send(&self, transfer_id: &[u8; 16]) {
        if let Some(send) = self.sends.lock().unwrap().get_mut(transfer_id) {
            send.state = TransferState::Cancelled;
        }
    }

    /// Cancel a receive transfer.
    pub fn cancel_receive(&self, transfer_id: &[u8; 16]) {
        if let Some(recv) = self.receives.lock().unwrap().get_mut(transfer_id) {
            recv.state = TransferState::Cancelled;
        }
    }

    /// Pause a send transfer for later resume.
    pub fn pause_send(&self, transfer_id: &[u8; 16]) {
        if let Some(send) = self.sends.lock().unwrap().get_mut(transfer_id) {
            send.state = TransferState::Paused;
        }
    }

    /// Resume a paused send transfer.
    pub fn resume_send(&self, transfer_id: &[u8; 16]) {
        if let Some(send) = self.sends.lock().unwrap().get_mut(transfer_id) {
            if send.state == TransferState::Paused {
                send.state = TransferState::InProgress;
            }
        }
    }

    /// Get list of chunk indices still needed for a receive.
    pub fn missing_chunks(&self, transfer_id: &[u8; 16]) -> Option<Vec<u32>> {
        let receives = self.receives.lock().unwrap();
        receives.get(transfer_id).map(|recv| {
            (0..recv.session.total_chunks)
                .filter(|i| !recv.chunks.contains_key(i))
                .collect()
        })
    }

    /// Clean up completed/cancelled transfers.
    pub fn cleanup(&self) {
        self.sends.lock().unwrap().retain(|_, s| {
            s.state == TransferState::InProgress || s.state == TransferState::Paused
        });
        self.receives.lock().unwrap().retain(|_, r| {
            r.state == TransferState::InProgress || r.state == TransferState::Paused
        });
    }
}

impl Default for FileTransferManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // S11 §2.3: chunk_file produces correct session and chunks
    #[test]
    fn chunk_small_file() {
        let data = vec![0x42u8; 1000];
        let (session, chunks) = chunk_file(&data, "test.bin", FileType::Unknown).unwrap();

        assert_eq!(session.total_size, 1000);
        assert_eq!(session.total_chunks, 1);
        assert_eq!(session.chunk_size, MAX_CHUNK_SIZE);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].data.len(), 1000);
        assert_eq!(chunks[0].chunk_index, 0);
        assert_eq!(chunks[0].transfer_id, session.transfer_id);
    }

    // S11 §2.3: large file splits into multiple chunks
    #[test]
    fn chunk_large_file() {
        let data = vec![0x42u8; MAX_CHUNK_SIZE * 3 + 100];
        let (session, chunks) = chunk_file(&data, "big.bin", FileType::Unknown).unwrap();

        assert_eq!(session.total_chunks, 4);
        assert_eq!(chunks.len(), 4);
        assert_eq!(chunks[0].data.len(), MAX_CHUNK_SIZE);
        assert_eq!(chunks[1].data.len(), MAX_CHUNK_SIZE);
        assert_eq!(chunks[2].data.len(), MAX_CHUNK_SIZE);
        assert_eq!(chunks[3].data.len(), 100);
    }

    // S11 §2.1: zero-byte files have div_ceil(0, MAX_CHUNK_SIZE) = 0 chunks.
    #[test]
    fn chunk_empty_file() {
        let data = vec![];
        let (session, chunks) = chunk_file(&data, "empty", FileType::Unknown).unwrap();

        assert_eq!(session.total_size, 0);
        assert_eq!(session.total_chunks, 0);
        assert!(chunks.is_empty());
    }

    // reassemble_file roundtrip
    #[test]
    fn chunk_and_reassemble_roundtrip() {
        let original = vec![0xAB; 500_000];
        let (session, chunks) = chunk_file(&original, "data.bin", FileType::Unknown).unwrap();

        let reassembled = reassemble_file(&session, &chunks).unwrap();
        assert_eq!(reassembled, original);
    }

    // reassemble detects missing chunks
    #[test]
    fn reassemble_missing_chunks() {
        let data = vec![0x42u8; MAX_CHUNK_SIZE * 2];
        let (session, chunks) = chunk_file(&data, "test.bin", FileType::Unknown).unwrap();

        // Only provide first chunk
        let result = reassemble_file(&session, &chunks[..1]);
        assert!(matches!(
            result,
            Err(FileTransferError::MissingChunks { .. })
        ));
    }

    // reassemble detects corruption (hash mismatch)
    #[test]
    fn reassemble_detects_corruption() {
        let data = vec![0x42u8; 1000];
        let (session, mut chunks) = chunk_file(&data, "test.bin", FileType::Unknown).unwrap();

        // Corrupt a byte
        chunks[0].data[0] = 0x00;

        let result = reassemble_file(&session, &chunks);
        assert!(matches!(result, Err(FileTransferError::HashMismatch)));
    }

    // reassemble works with out-of-order chunks
    #[test]
    fn reassemble_out_of_order() {
        let data = vec![0xAB; MAX_CHUNK_SIZE * 3 + 50];
        let (session, mut chunks) = chunk_file(&data, "test.bin", FileType::Unknown).unwrap();

        // Reverse chunk order
        chunks.reverse();

        let reassembled = reassemble_file(&session, &chunks).unwrap();
        assert_eq!(reassembled, data);
    }

    // S11 §2.5: filename sanitization
    #[test]
    fn sanitize_filename_strips_path() {
        assert_eq!(sanitize_filename("/home/user/photo.jpg"), "photo.jpg");
        assert_eq!(sanitize_filename("C:\\Users\\test\\doc.pdf"), "doc.pdf");
        assert_eq!(sanitize_filename("simple.txt"), "simple.txt");
    }

    #[test]
    fn sanitize_filename_hardening() {
        // S11 §2.5: dot-segments and empties → placeholder (no traversal).
        assert_eq!(sanitize_filename(".."), "unnamed");
        assert_eq!(sanitize_filename("."), "unnamed");
        assert_eq!(sanitize_filename(""), "unnamed");
        // Bidi override (RTL spoofing) + control chars stripped.
        assert_eq!(sanitize_filename("photo\u{202E}gpj.exe"), "photogpj.exe");
        assert_eq!(sanitize_filename("a\u{0000}b\tc.txt"), "abc.txt");
        // Trailing dots/spaces trimmed (Windows silently strips them).
        assert_eq!(sanitize_filename("report.txt. ."), "report.txt");
        // Windows reserved device names prefixed.
        assert_eq!(sanitize_filename("CON"), "_CON");
        assert_eq!(sanitize_filename("nul.txt"), "_nul.txt");
        assert_eq!(sanitize_filename("COM1"), "_COM1");
        // A normal name that merely contains a reserved substring is left alone.
        assert_eq!(sanitize_filename("console.log"), "console.log");
    }

    #[test]
    fn sanitize_filename_multibyte_no_panic() {
        // A long multibyte filename must UTF-8-truncate on a char boundary, never
        // panic on a byte slice at 255 (the former base[..255] bug).
        let name = "é".repeat(200); // 400 bytes, 200 chars
        let out = sanitize_filename(&name);
        assert!(out.len() <= 255);
        assert!(out.is_char_boundary(out.len()));
        // Also a name whose 255th byte lands mid-codepoint.
        let name2 = format!("{}é", "a".repeat(254));
        let out2 = sanitize_filename(&name2);
        assert!(out2.len() <= 255 && out2.is_char_boundary(out2.len()));
    }

    /// A clean minimal WebP (RIFF/WEBP + one VP8 chunk) of exactly `total`
    /// bytes. The S11 §5.1 pipeline passes it through unchanged (nothing to strip,
    /// verifier clean), so send-path tests get size-stable sanitized bytes.
    fn clean_webp(total: usize) -> Vec<u8> {
        assert!(total >= 20, "too small for a WebP header + VP8 chunk");
        let vp8_payload = total - 20;
        let mut data = Vec::with_capacity(total);
        data.extend_from_slice(b"RIFF");
        data.extend_from_slice(&((4 + 8 + vp8_payload) as u32).to_le_bytes());
        data.extend_from_slice(b"WEBP");
        data.extend_from_slice(b"VP8 ");
        data.extend_from_slice(&(vp8_payload as u32).to_le_bytes());
        data.resize(total, 0);
        data
    }

    // FileTransferManager send flow
    #[test]
    fn transfer_manager_send_flow() {
        let mgr = FileTransferManager::new();
        let data = clean_webp(1000);

        let session = mgr.start_send(&data, "photo.webp").unwrap();
        assert_eq!(session.total_chunks, 1);

        // Get first chunk
        let chunk = mgr.next_chunk(&session.transfer_id);
        assert!(chunk.is_some());
        assert_eq!(chunk.unwrap().chunk_index, 0);

        // No more chunks
        let chunk = mgr.next_chunk(&session.transfer_id);
        assert!(chunk.is_none());
    }

    // FileTransferManager receive flow
    #[test]
    fn transfer_manager_receive_flow() {
        let mgr = FileTransferManager::new();
        let data = vec![0x42u8; 1000];
        let (session, chunks) = chunk_file(&data, "file.bin", FileType::Unknown).unwrap();

        mgr.start_receive(session.clone()).unwrap();
        assert!(!mgr.is_receive_complete(&session.transfer_id));

        // Add all chunks
        for chunk in chunks {
            mgr.add_chunk(chunk).unwrap();
        }

        assert!(mgr.is_receive_complete(&session.transfer_id));

        // Complete and verify
        let result = mgr.complete_receive(&session.transfer_id).unwrap();
        assert_eq!(result, data);
    }

    // progress tracking
    #[test]
    fn progress_tracking() {
        let mgr = FileTransferManager::new();
        let data = clean_webp(MAX_CHUNK_SIZE * 2 + 100);

        let session = mgr.start_send(&data, "photo.webp").unwrap();
        assert_eq!(session.total_chunks, 3);

        // Initial progress
        let progress = mgr.send_progress(&session.transfer_id).unwrap();
        assert_eq!(progress.chunks_transferred, 0);
        assert_eq!(progress.progress_percent(), 0);

        // Send one chunk
        mgr.next_chunk(&session.transfer_id);
        let progress = mgr.send_progress(&session.transfer_id).unwrap();
        assert_eq!(progress.chunks_transferred, 1);
        assert_eq!(progress.progress_percent(), 33);
    }

    // missing chunks of a partial receive
    #[test]
    fn resume_missing_chunks() {
        let mgr = FileTransferManager::new();
        let data = vec![0x42u8; MAX_CHUNK_SIZE * 3];
        let (session, chunks) = chunk_file(&data, "file.bin", FileType::Unknown).unwrap();

        mgr.start_receive(session.clone()).unwrap();

        // Add only first and third chunks (skip index 1)
        mgr.add_chunk(chunks[0].clone()).unwrap();
        mgr.add_chunk(chunks[2].clone()).unwrap();

        let missing = mgr.missing_chunks(&session.transfer_id).unwrap();
        assert_eq!(missing, vec![1]);
    }

    // S11 §4.4: an identical re-received chunk is idempotent (Ok);
    // a DIFFERING chunk at the same index is a ChunkConflict.
    #[test]
    fn duplicate_chunk_idempotent_conflict_rejected() {
        let mgr = FileTransferManager::new();
        let data = vec![0x42u8; 1000];
        let (session, chunks) = chunk_file(&data, "file.bin", FileType::Unknown).unwrap();
        let tid = session.transfer_id;

        mgr.start_receive(session).unwrap();
        mgr.add_chunk(chunks[0].clone()).unwrap();

        // Re-adding the SAME bytes at index 0 is idempotent (Nack/retransmit).
        assert!(mgr.add_chunk(chunks[0].clone()).is_ok());

        // A DIFFERENT chunk at index 0 is a conflict.
        let conflicting = FileChunk {
            transfer_id: tid,
            chunk_index: 0,
            data: vec![0x99u8; 1000],
        };
        assert!(matches!(
            mgr.add_chunk(conflicting),
            Err(FileTransferError::ChunkConflict(0))
        ));
    }

    // pause and resume
    #[test]
    fn pause_and_resume_send() {
        let mgr = FileTransferManager::new();
        let data = clean_webp(MAX_CHUNK_SIZE * 3);

        let session = mgr.start_send(&data, "photo.webp").unwrap();

        // Send one chunk
        mgr.next_chunk(&session.transfer_id);

        // Pause
        mgr.pause_send(&session.transfer_id);
        let progress = mgr.send_progress(&session.transfer_id).unwrap();
        assert_eq!(progress.state, TransferState::Paused);

        // Resume
        mgr.resume_send(&session.transfer_id);
        let progress = mgr.send_progress(&session.transfer_id).unwrap();
        assert_eq!(progress.state, TransferState::InProgress);
    }

    // cancel transfer
    #[test]
    fn cancel_transfer() {
        let mgr = FileTransferManager::new();
        let data = clean_webp(1000);

        let session = mgr.start_send(&data, "photo.webp").unwrap();
        mgr.cancel_send(&session.transfer_id);

        let progress = mgr.send_progress(&session.transfer_id).unwrap();
        assert_eq!(progress.state, TransferState::Cancelled);
    }

    // Cleanup removes completed/cancelled transfers
    #[test]
    fn cleanup_removes_finished() {
        let mgr = FileTransferManager::new();
        let data = clean_webp(1000);

        let session = mgr.start_send(&data, "photo.webp").unwrap();
        mgr.cancel_send(&session.transfer_id);

        mgr.cleanup();
        assert!(mgr.send_progress(&session.transfer_id).is_none());
    }

    // S11 §5.1: the send boundary refuses bytes that cannot be
    // sanitized — raw data can never enter the chunk pipeline.
    #[test]
    fn start_send_refuses_unsanitizable_data() {
        let mgr = FileTransferManager::new();
        let err = mgr.start_send(&[0x42u8; 100], "blob.bin").unwrap_err();
        assert!(matches!(err, FileTransferError::SanitizationFailed(_)));
    }

    // S11 §5.1: the manager runs the sanitization pipeline itself — a dirty
    // WebP is cleaned before chunking, and the wire metadata stays WebP.
    #[test]
    fn start_send_sanitizes_webp_at_the_boundary() {
        let mgr = FileTransferManager::new();
        let mut body = Vec::new();
        body.extend_from_slice(b"VP8X");
        body.extend_from_slice(&10u32.to_le_bytes());
        body.push(0x08); // EXIF presence flag set
        body.extend_from_slice(&[0u8; 9]); // reserved(3) + canvas(6)
        let exif = b"Exif\x00\x00GPS_COORDINATES_LEAK";
        body.extend_from_slice(b"EXIF");
        body.extend_from_slice(&(exif.len() as u32).to_le_bytes());
        body.extend_from_slice(exif);
        body.extend_from_slice(b"VP8 ");
        body.extend_from_slice(&4u32.to_le_bytes());
        body.extend_from_slice(&[0, 0, 0, 0]);
        let mut dirty = b"RIFF".to_vec();
        dirty.extend_from_slice(&((4 + body.len()) as u32).to_le_bytes());
        dirty.extend_from_slice(b"WEBP");
        dirty.extend_from_slice(&body);

        let session = mgr.start_send(&dirty, "photo.webp").unwrap();
        assert_eq!(session.file_type, FileType::WebP);
        let chunk = mgr.next_chunk(&session.transfer_id).unwrap();
        assert!(
            !chunk.data.windows(4).any(|w| w == b"EXIF"),
            "EXIF chunk survived the send boundary"
        );
    }

    // Chunk index out of range
    #[test]
    fn chunk_out_of_range() {
        let mgr = FileTransferManager::new();
        let data = vec![0x42u8; 1000];
        let (session, _) = chunk_file(&data, "file.bin", FileType::Unknown).unwrap();

        mgr.start_receive(session.clone()).unwrap();

        let bad_chunk = FileChunk {
            transfer_id: session.transfer_id,
            chunk_index: 999,
            data: vec![0x00],
        };

        let result = mgr.add_chunk(bad_chunk);
        assert!(matches!(
            result,
            Err(FileTransferError::ChunkOutOfRange { .. })
        ));
    }

    // S11 §4.3: a chunk for an unregistered transfer is BUFFERED (not dropped
    // with SessionNotFound) and drained once its FileMetadata arrives — the
    // ratchet key is already consumed, so dropping it is unrecoverable loss.
    #[test]
    fn early_chunk_is_buffered_and_drained_not_dropped() {
        let mgr = FileTransferManager::new();
        let tid = [7u8; 16]; // crafted_session's transfer_id
        let chunk0 = FileChunk {
            transfer_id: tid,
            chunk_index: 0,
            data: vec![0xAB; MAX_CHUNK_SIZE],
        };
        let chunk1 = FileChunk {
            transfer_id: tid,
            chunk_index: 1,
            data: vec![0xCD; 100],
        };

        // Chunk 1 arrives BEFORE the metadata → buffered, not SessionNotFound.
        assert!(
            mgr.add_chunk(chunk1).is_ok(),
            "early chunk must be buffered, not dropped"
        );
        assert!(!mgr.is_receive_complete(&tid));

        // FileMetadata (start_receive) arrives and drains the orphan.
        mgr.start_receive(crafted_session(MAX_CHUNK_SIZE as u64 + 100, 2))
            .unwrap();
        // Only chunk 0 remains to arrive normally.
        mgr.add_chunk(chunk0).unwrap();
        assert!(
            mgr.is_receive_complete(&tid),
            "both chunks present after the orphan drain"
        );
    }

    // S11 §4.3: the orphan buffer is bounded — a sender flooding chunks for a
    // transfer whose metadata never arrives is eventually rejected.
    #[test]
    fn orphan_buffer_is_bounded() {
        let mgr = FileTransferManager::new();
        let tid = [9u8; 16];
        let mut rejected = false;
        for idx in 0..((MAX_ORPHAN_BYTES / MAX_CHUNK_SIZE) as u32 + 5) {
            let c = FileChunk {
                transfer_id: tid,
                chunk_index: idx,
                data: vec![0u8; MAX_CHUNK_SIZE],
            };
            if mgr.add_chunk(c).is_err() {
                rejected = true;
                break;
            }
        }
        assert!(
            rejected,
            "orphan buffer must reject beyond MAX_ORPHAN_BYTES"
        );
    }

    // S11 §2.1 / §2.2.1: receiver-side bounds on a hostile FileMetadata.
    fn crafted_session(total_size: u64, total_chunks: u32) -> FileTransferSession {
        FileTransferSession {
            transfer_id: [7u8; 16],
            file_name: "x.bin".to_string(),
            file_type: FileType::Unknown,
            total_size,
            total_chunks,
            chunk_size: MAX_CHUNK_SIZE,
            sha256_hash: [0u8; 32],
        }
    }

    #[test]
    fn start_receive_rejects_oversize() {
        let mgr = FileTransferManager::new();
        let session = crafted_session(MAX_FILE_SIZE + 1, 1);
        assert!(matches!(
            mgr.start_receive(session),
            Err(FileTransferError::FileTooLarge { .. })
        ));
    }

    #[test]
    fn start_receive_rejects_bad_chunk_count() {
        let mgr = FileTransferManager::new();
        // 100 bytes → div_ceil == 1 chunk; declaring 5 is hostile.
        assert!(matches!(
            mgr.start_receive(crafted_session(100, 5)),
            Err(FileTransferError::InvalidChunkCount {
                expected: 1,
                declared: 5
            })
        ));
        // The consistent count is accepted.
        assert!(mgr.start_receive(crafted_session(100, 1)).is_ok());
    }

    #[test]
    fn add_chunk_rejects_oversize_chunk() {
        let mgr = FileTransferManager::new();
        let session = crafted_session(MAX_CHUNK_SIZE as u64 * 2, 2);
        let tid = session.transfer_id;
        mgr.start_receive(session).unwrap();
        let oversize = FileChunk {
            transfer_id: tid,
            chunk_index: 0,
            data: vec![0u8; MAX_CHUNK_SIZE + 1],
        };
        assert!(matches!(
            mgr.add_chunk(oversize),
            Err(FileTransferError::ChunkSizeOverflow(_))
        ));
    }

    #[test]
    fn add_chunk_rejects_cumulative_overflow() {
        let mgr = FileTransferManager::new();
        let session = crafted_session(100, 1); // one chunk expected
        let tid = session.transfer_id;
        mgr.start_receive(session).unwrap();
        // A single chunk claiming 200 bytes exceeds the declared total_size 100.
        let chunk = FileChunk {
            transfer_id: tid,
            chunk_index: 0,
            data: vec![0u8; 200],
        };
        assert!(matches!(
            mgr.add_chunk(chunk),
            Err(FileTransferError::ChunkSizeOverflow(_))
        ));
    }
}
