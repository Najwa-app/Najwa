//! S11 §2.2.1 byte-exact wire codecs for file-transfer payloads and the
//! §2.1/§4.1 FileChunkNack control body.
//!
//! All integers big-endian; strings UTF-8 with a u16-BE byte-length prefix
//! (§2.2.1 is authoritative). Receivers MUST reject the hostile-input cases
//! listed in §2.2.1 — implemented here as parse-time validation so callers
//! cannot skip them.

use super::error::MessageError;
use crate::message::control::ControlMessage;

/// S11 §2.1: maximum file size accepted by chunk/start/add paths.
pub const MAX_FILE_SIZE: u64 = 262_144 * 1024; // 256 MiB
/// S11 §2.1: per-chunk data cap.
pub const MAX_CHUNK_SIZE: usize = 245_760;
/// S11 §4.1: quiet period before a receiver's first FileChunkNack for a file;
/// attempt `k` (0-based) waits `NACK_MIN_INTERVAL_SECS << k`. A sender answers
/// at most one NACK per file and contact per this interval.
pub const NACK_MIN_INTERVAL_SECS: u64 = 600;
/// S11 §4.1: FileChunkNacks a receiver sends for one file before it reports the
/// file as failed.
pub const NACK_MAX_ATTEMPTS: u32 = 4;
/// S11 §2.1: max missing indices per FileChunkNack.
pub const NACK_MAX_INDICES: usize = 256;

/// S11 §2.2.1 `FileMetadata` — Payload `content_type = 0x10`
/// (registry: docs/reference/message-types.md).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMetadata {
    pub session_id: [u8; 16],
    /// Display hint, never a path (S11 §2.5).
    pub filename: String,
    pub total_size: u64,
    pub mime_type: String,
    pub chunk_count: u32,
    /// SHA-256 of the entire sanitized file.
    pub sha256_hash: [u8; 32],
}

impl FileMetadata {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            16 + 2 + self.filename.len() + 8 + 2 + self.mime_type.len() + 4 + 32,
        );
        out.extend_from_slice(&self.session_id);
        out.extend_from_slice(&(self.filename.len() as u16).to_be_bytes());
        out.extend_from_slice(self.filename.as_bytes());
        out.extend_from_slice(&self.total_size.to_be_bytes());
        out.extend_from_slice(&(self.mime_type.len() as u16).to_be_bytes());
        out.extend_from_slice(self.mime_type.as_bytes());
        out.extend_from_slice(&self.chunk_count.to_be_bytes());
        out.extend_from_slice(&self.sha256_hash);
        out
    }

    /// Parse with every §2.2.1 receiver MUST-reject rule:
    /// `total_size > MAX_FILE_SIZE`, `chunk_count != div_ceil(total_size,
    /// MAX_CHUNK_SIZE)`, `filename_len > 255`, `mime_type_len > 127`, or
    /// trailing bytes after `sha256_hash`.
    pub fn from_bytes(data: &[u8]) -> Result<Self, MessageError> {
        let err = |m: &str| Err(MessageError::InvalidHeader(format!("FileMetadata: {m}")));
        if data.len() < 16 + 2 + 8 + 2 + 4 + 32 {
            return err("truncated");
        }
        let mut pos = 0usize;
        let mut session_id = [0u8; 16];
        session_id.copy_from_slice(&data[..16]);
        pos += 16;

        let filename_len = u16::from_be_bytes(data[pos..pos + 2].try_into().unwrap()) as usize;
        pos += 2;
        if filename_len > 255 {
            return err("filename_len > 255");
        }
        if pos + filename_len + 8 + 2 + 4 + 32 > data.len() {
            return err("truncated filename/fields");
        }
        let filename = std::str::from_utf8(&data[pos..pos + filename_len])
            .map_err(|_| MessageError::InvalidHeader("FileMetadata: filename not UTF-8".into()))?;
        if filename.is_empty() {
            return err("empty filename");
        }
        pos += filename_len;

        let total_size = u64::from_be_bytes(data[pos..pos + 8].try_into().unwrap());
        pos += 8;
        if total_size > MAX_FILE_SIZE {
            return err("total_size > MAX_FILE_SIZE");
        }

        let mime_len = u16::from_be_bytes(data[pos..pos + 2].try_into().unwrap()) as usize;
        pos += 2;
        if mime_len > 127 {
            return err("mime_type_len > 127");
        }
        if pos + mime_len + 4 + 32 > data.len() {
            return err("truncated mime/hash");
        }
        let mime_type = std::str::from_utf8(&data[pos..pos + mime_len])
            .map_err(|_| MessageError::InvalidHeader("FileMetadata: mime not UTF-8".into()))?
            .to_string();
        pos += mime_len;

        let chunk_count = u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;

        // §2.1: chunk_count MUST equal div_ceil(total_size, MAX_CHUNK_SIZE).
        let expected = total_size.div_ceil(MAX_CHUNK_SIZE as u64) as u32;
        if chunk_count != expected {
            return err("chunk_count != div_ceil(total_size, MAX_CHUNK_SIZE)");
        }

        if pos + 32 != data.len() {
            return err("trailing bytes after sha256_hash");
        }
        let mut sha256_hash = [0u8; 32];
        sha256_hash.copy_from_slice(&data[pos..pos + 32]);

        Ok(Self {
            session_id,
            filename: filename.to_string(),
            total_size,
            mime_type,
            chunk_count,
            sha256_hash,
        })
    }
}

/// S11 §2.2.1 `FileChunk` — Payload `content_type = 0x11`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileChunkWire {
    pub session_id: [u8; 16],
    /// 0-based chunk index.
    pub index: u32,
    /// Up to MAX_CHUNK_SIZE bytes.
    pub data: Vec<u8>,
}

impl FileChunkWire {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + 4 + 4 + self.data.len());
        out.extend_from_slice(&self.session_id);
        out.extend_from_slice(&self.index.to_be_bytes());
        out.extend_from_slice(&(self.data.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.data);
        out
    }

    /// Parse with the §2.2.1 receiver MUST-reject rules: `data_len >
    /// MAX_CHUNK_SIZE` or `data_len != data.len`.
    pub fn from_bytes(data: &[u8]) -> Result<Self, MessageError> {
        if data.len() < 16 + 4 + 4 {
            return Err(MessageError::InvalidHeader("FileChunk: truncated".into()));
        }
        let mut session_id = [0u8; 16];
        session_id.copy_from_slice(&data[..16]);
        let index = u32::from_be_bytes(data[16..20].try_into().unwrap());
        let data_len = u32::from_be_bytes(data[20..24].try_into().unwrap()) as usize;
        if data_len > MAX_CHUNK_SIZE {
            return Err(MessageError::InvalidHeader(
                "FileChunk: data_len > MAX_CHUNK_SIZE".into(),
            ));
        }
        if data.len() != 24 + data_len {
            return Err(MessageError::InvalidHeader(
                "FileChunk: data_len != data.len".into(),
            ));
        }
        Ok(Self {
            session_id,
            index,
            data: data[24..].to_vec(),
        })
    }
}

/// S11 §2.2.1 `FileChunkNack` — control subtype `0x3C` (first byte of a
/// `content_type = 0x20` Control body): `session_id[16] ‖ missing_count(u16
/// BE) ‖ missing_index_N(u32 BE)`. Indices strictly ascending, each <
/// chunk_count, count ≤ [`NACK_MAX_INDICES`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileChunkNack {
    pub session_id: [u8; 16],
    /// Strictly ascending 0-based missing chunk indices.
    pub missing_indices: Vec<u32>,
}

impl FileChunkNack {
    pub fn to_bytes(&self) -> Result<Vec<u8>, MessageError> {
        if self.missing_indices.is_empty() || self.missing_indices.len() > NACK_MAX_INDICES {
            return Err(MessageError::InvalidHeader(
                "FileChunkNack: missing_count out of 1..=256".into(),
            ));
        }
        let mut prev: Option<u32> = None;
        for idx in &self.missing_indices {
            if let Some(p) = prev {
                if *idx <= p {
                    return Err(MessageError::InvalidHeader(
                        "FileChunkNack: indices not strictly ascending".into(),
                    ));
                }
            }
            prev = Some(*idx);
        }
        let mut out = Vec::with_capacity(1 + 16 + 2 + 4 * self.missing_indices.len());
        out.push(0x3C);
        out.extend_from_slice(&self.session_id);
        out.extend_from_slice(&(self.missing_indices.len() as u16).to_be_bytes());
        for idx in &self.missing_indices {
            out.extend_from_slice(&idx.to_be_bytes());
        }
        Ok(out)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, MessageError> {
        if data.len() < 1 + 16 + 2 || data[0] != 0x3C {
            return Err(MessageError::InvalidHeader(
                "FileChunkNack: bad header".into(),
            ));
        }
        let count = u16::from_be_bytes(data[17..19].try_into().unwrap()) as usize;
        if count == 0 || count > NACK_MAX_INDICES || data.len() != 19 + 4 * count {
            return Err(MessageError::InvalidHeader(
                "FileChunkNack: bad length/count".into(),
            ));
        }
        let mut missing_indices = Vec::with_capacity(count);
        for i in 0..count {
            let off = 19 + 4 * i;
            let index = u32::from_be_bytes(data[off..off + 4].try_into().unwrap());
            if missing_indices
                .last()
                .is_some_and(|previous| *previous >= index)
            {
                return Err(MessageError::InvalidHeader(
                    "FileChunkNack: indices not strictly ascending".into(),
                ));
            }
            missing_indices.push(index);
        }
        Ok(Self {
            session_id: data[1..17].try_into().unwrap(),
            missing_indices,
        })
    }
}

/// Convenience: wrap a FileChunkNack as a Control payload for the wire
/// (content_type 0x20, control subtype 0x3C).
impl FileChunkNack {
    pub fn to_control_message(self) -> Result<ControlMessage, MessageError> {
        self.to_bytes()?;
        Ok(ControlMessage::FileChunkNack {
            session_id: self.session_id,
            missing_indices: self.missing_indices,
        })
    }
}
