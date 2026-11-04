//! Minimal deterministic ZIP reader/writer for DOCX/ODT sanitization
//! (S11 §5.4 / §7.5–7.6).
//!
//! Reading: iterates the central directory (the authoritative entry record),
//! locates each entry's data via its local header, and inflates DEFLATE
//! entries. Rejects encrypted, Zip64, and unknown-method entries — fail closed
//! rather than pass through bytes we cannot inspect.
//!
//! Writing: the S11 §5.4 determinism mandate — every entry rewritten *stored*
//! (uncompressed), original entry order preserved, DOS date/time zeroed, no
//! extra fields, no comments. This closes the ZIP entry-mtime leak (per-entry
//! modification times are document metadata) and removes compressor-version
//! nondeterminism.

use std::io::Read;

use crate::SanitizeError;

/// Local file header signature `PK\x03\x04`.
const LFH_SIG: u32 = 0x0403_4b50;
/// Central directory record signature `PK\x01\x02`.
const CDR_SIG: u32 = 0x0201_4b50;
/// End-of-central-directory signature `PK\x05\x06`.
const EOCD_SIG: u32 = 0x0605_4b50;

/// Cap on the total decompressed size of an archive (zip-bomb guard). Documents
/// shared through Najwa are bounded far below this by MAX_CONTENT_SIZE anyway.
const MAX_TOTAL_UNCOMPRESSED: u64 = 512 * 1024 * 1024;

/// One parsed archive entry, decompressed, plus the header metadata the
/// verifier inspects (the writer ignores it and emits S11 §5.4 constants).
pub struct ZipEntry {
    /// Entry name, byte-for-byte from the central directory.
    pub name: String,
    /// Decompressed entry data.
    pub data: Vec<u8>,
    /// Original compression method (0 = stored, 8 = DEFLATE).
    pub method: u16,
    /// Original DOS mod time (central directory) — MUST be 0 post-sanitize.
    pub dos_time: u16,
    /// Original DOS mod date (central directory) — MUST be 0 post-sanitize.
    pub dos_date: u16,
    /// Combined central + local extra-field length — MUST be 0 post-sanitize.
    pub extra_len: usize,
}

fn rd_u16(d: &[u8], off: usize) -> Option<u16> {
    d.get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn rd_u32(d: &[u8], off: usize) -> Option<u32> {
    d.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn zerr(m: impl std::fmt::Display) -> SanitizeError {
    SanitizeError::InvalidFormat(format!("ZIP: {m}"))
}

/// Parse a ZIP archive into decompressed entries in central-directory order.
pub fn parse_zip(data: &[u8]) -> Result<Vec<ZipEntry>, SanitizeError> {
    if data.len() < 22 {
        return Err(zerr("too short"));
    }

    // Find the EOCD: scan backwards over the trailing comment window
    // (EOCD is 22 bytes + up to 65535 comment bytes from the end).
    let scan_floor = data.len().saturating_sub(22 + 65_535);
    let mut eocd = None;
    let mut i = data.len() - 22;
    loop {
        if rd_u32(data, i) == Some(EOCD_SIG) {
            eocd = Some(i);
            break;
        }
        if i == scan_floor {
            break;
        }
        i -= 1;
    }
    let eocd = eocd.ok_or_else(|| zerr("no end-of-central-directory"))?;
    let total_entries = rd_u16(data, eocd + 10).ok_or_else(|| zerr("truncated EOCD"))? as usize;
    let cd_offset = rd_u32(data, eocd + 16).ok_or_else(|| zerr("truncated EOCD"))? as usize;

    let mut entries = Vec::with_capacity(total_entries);
    let mut pos = cd_offset;
    let mut total_out: u64 = 0;

    for _ in 0..total_entries {
        if rd_u32(data, pos) != Some(CDR_SIG) {
            return Err(zerr("bad central-directory record"));
        }
        let t = || zerr("truncated central directory");
        let flags = rd_u16(data, pos + 8).ok_or_else(t)?;
        let method = rd_u16(data, pos + 10).ok_or_else(t)?;
        let dos_time = rd_u16(data, pos + 12).ok_or_else(t)?;
        let dos_date = rd_u16(data, pos + 14).ok_or_else(t)?;
        let csize = rd_u32(data, pos + 20).ok_or_else(t)? as usize;
        let usize_decl = rd_u32(data, pos + 24).ok_or_else(t)? as usize;
        let name_len = rd_u16(data, pos + 28).ok_or_else(t)? as usize;
        let extra_len = rd_u16(data, pos + 30).ok_or_else(t)? as usize;
        let comment_len = rd_u16(data, pos + 32).ok_or_else(t)? as usize;
        let lfh_off = rd_u32(data, pos + 42).ok_or_else(t)? as usize;
        let name_bytes = data.get(pos + 46..pos + 46 + name_len).ok_or_else(t)?;
        let name = String::from_utf8_lossy(name_bytes).into_owned();

        if flags & 0x0001 != 0 {
            return Err(zerr(format!("encrypted entry '{name}'")));
        }
        if csize == 0xFFFF_FFFF || usize_decl == 0xFFFF_FFFF {
            return Err(zerr("Zip64 archives are not supported"));
        }
        total_out += usize_decl as u64;
        if total_out > MAX_TOTAL_UNCOMPRESSED {
            return Err(zerr("decompressed size cap exceeded"));
        }

        // Locate the data through the LOCAL header — its name/extra lengths can
        // legitimately differ from the central directory's.
        if rd_u32(data, lfh_off) != Some(LFH_SIG) {
            return Err(zerr(format!("bad local header for '{name}'")));
        }
        let lt = || zerr("truncated local header");
        let l_name = rd_u16(data, lfh_off + 26).ok_or_else(lt)? as usize;
        let l_extra = rd_u16(data, lfh_off + 28).ok_or_else(lt)? as usize;
        let data_start = lfh_off + 30 + l_name + l_extra;
        let raw = data
            .get(data_start..data_start + csize)
            .ok_or_else(|| zerr(format!("truncated data for '{name}'")))?;

        let out = match method {
            0 => {
                if csize != usize_decl {
                    return Err(zerr(format!("stored size mismatch in '{name}'")));
                }
                raw.to_vec()
            }
            8 => {
                let mut v = Vec::with_capacity(usize_decl.min(1 << 20));
                let mut dec = flate2::read::DeflateDecoder::new(raw);
                // Read at most declared+1 bytes so an overrun is detectable
                // without unbounded allocation.
                dec.by_ref()
                    .take(usize_decl as u64 + 1)
                    .read_to_end(&mut v)
                    .map_err(|e| zerr(format!("inflate failed in '{name}': {e}")))?;
                if v.len() != usize_decl {
                    return Err(zerr(format!("decompressed size mismatch in '{name}'")));
                }
                v
            }
            m => {
                return Err(zerr(format!(
                    "unsupported compression method {m} in '{name}'"
                )))
            }
        };

        entries.push(ZipEntry {
            name,
            data: out,
            method,
            dos_time,
            dos_date,
            extra_len: extra_len + l_extra,
        });
        pos += 46 + name_len + extra_len + comment_len;
    }

    Ok(entries)
}

/// IEEE CRC-32 over `data` (ZIP entry checksum), via flate2's implementation.
fn crc32(data: &[u8]) -> u32 {
    let mut c = flate2::Crc::new();
    c.update(data);
    c.sum()
}

/// Serialize entries as a deterministic all-stored ZIP (S11 §5.4): original
/// order, method 0, DOS date/time = 0, no extra fields, no comments, fixed
/// version fields. Identical entries always produce identical bytes.
pub fn write_zip_stored(entries: &[ZipEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    let mut count: u16 = 0;

    for e in entries {
        let offset = out.len() as u32;
        let crc = crc32(&e.data);
        let size = e.data.len() as u32;
        let name = e.name.as_bytes();

        // Local file header.
        out.extend_from_slice(&LFH_SIG.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed: 2.0
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&0u16.to_le_bytes()); // method: stored
        out.extend_from_slice(&0u16.to_le_bytes()); // mod time = 0 (S11 §5.4)
        out.extend_from_slice(&0u16.to_le_bytes()); // mod date = 0 (S11 §5.4)
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes()); // compressed size
        out.extend_from_slice(&size.to_le_bytes()); // uncompressed size
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra len = 0 (S11 §5.4)
        out.extend_from_slice(name);
        out.extend_from_slice(&e.data);

        // Matching central directory record.
        central.extend_from_slice(&CDR_SIG.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes()); // version made by
        central.extend_from_slice(&20u16.to_le_bytes()); // version needed
        central.extend_from_slice(&0u16.to_le_bytes()); // flags
        central.extend_from_slice(&0u16.to_le_bytes()); // method: stored
        central.extend_from_slice(&0u16.to_le_bytes()); // mod time = 0
        central.extend_from_slice(&0u16.to_le_bytes()); // mod date = 0
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&(name.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes()); // extra len = 0
        central.extend_from_slice(&0u16.to_le_bytes()); // comment len = 0
        central.extend_from_slice(&0u16.to_le_bytes()); // disk number
        central.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        central.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name);

        count += 1;
    }

    let cd_offset = out.len() as u32;
    let cd_size = central.len() as u32;
    out.extend_from_slice(&central);

    // End of central directory.
    out.extend_from_slice(&EOCD_SIG.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // disk number
    out.extend_from_slice(&0u16.to_le_bytes()); // cd start disk
    out.extend_from_slice(&count.to_le_bytes()); // entries on disk
    out.extend_from_slice(&count.to_le_bytes()); // total entries
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment len = 0

    out
}

/// Test-only: build a ZIP with DEFLATE entries, nonzero timestamps, and an
/// extra field — the "dirty" shape a real document generator produces. Shared
/// by the zip and document test modules.
#[cfg(test)]
pub(crate) fn build_dirty_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    use std::io::Write;
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, data) in entries {
        let offset = out.len() as u32;
        let crc = crc32(data);
        let mut enc =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(data).unwrap();
        let compressed = enc.finish().unwrap();
        let extra: &[u8] = &[0x55, 0x54, 0x05, 0x00, 0x03, 0x11, 0x22, 0x33, 0x44]; // UT extended-timestamp
        let n = name.as_bytes();

        out.extend_from_slice(&LFH_SIG.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&8u16.to_le_bytes()); // DEFLATE
        out.extend_from_slice(&0x6A2Bu16.to_le_bytes()); // nonzero mtime
        out.extend_from_slice(&0x58E5u16.to_le_bytes()); // nonzero mdate
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(n.len() as u16).to_le_bytes());
        out.extend_from_slice(&(extra.len() as u16).to_le_bytes());
        out.extend_from_slice(n);
        out.extend_from_slice(extra);
        out.extend_from_slice(&compressed);

        central.extend_from_slice(&CDR_SIG.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&8u16.to_le_bytes());
        central.extend_from_slice(&0x6A2Bu16.to_le_bytes());
        central.extend_from_slice(&0x58E5u16.to_le_bytes());
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(n.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(n);
    }
    let cd_offset = out.len() as u32;
    let cd_size = central.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(&EOCD_SIG.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_inflates_deflated_entries() {
        let zip = build_dirty_zip(&[("a.xml", b"<x>hello</x>"), ("b/c.txt", b"payload")]);
        let entries = parse_zip(&zip).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "a.xml");
        assert_eq!(entries[0].data, b"<x>hello</x>");
        assert_eq!(entries[0].method, 8);
        assert_ne!(entries[0].dos_time, 0);
        assert!(entries[0].extra_len > 0);
        assert_eq!(entries[1].data, b"payload");
    }

    #[test]
    fn stored_rewrite_is_deterministic_and_clean() {
        let zip = build_dirty_zip(&[("mimetype", b"application/x"), ("content.xml", b"<d/>")]);
        let entries = parse_zip(&zip).unwrap();
        let out1 = write_zip_stored(&entries);
        let out2 = write_zip_stored(&parse_zip(&zip).unwrap());
        assert_eq!(
            out1, out2,
            "rewrite must be byte-level deterministic (§5.4)"
        );

        // The rewritten archive parses back with all S11 §5.4 invariants.
        let reparsed = parse_zip(&out1).unwrap();
        assert_eq!(reparsed.len(), 2);
        assert_eq!(reparsed[0].name, "mimetype"); // original order preserved
        for e in &reparsed {
            assert_eq!(e.method, 0, "all entries stored");
            assert_eq!(e.dos_time, 0, "entry mtime zeroed");
            assert_eq!(e.dos_date, 0, "entry mdate zeroed");
            assert_eq!(e.extra_len, 0, "no extra fields");
        }
        assert_eq!(reparsed[1].data, b"<d/>");

        // Idempotent: rewriting the rewrite changes nothing.
        assert_eq!(write_zip_stored(&reparsed), out1);
    }

    #[test]
    fn rejects_encrypted_and_truncated() {
        let mut zip = build_dirty_zip(&[("a.xml", b"<x/>")]);
        // Flip the encryption flag bit in the central directory record.
        let cd_offset = {
            let eocd = zip.len() - 22;
            u32::from_le_bytes(zip[eocd + 16..eocd + 20].try_into().unwrap()) as usize
        };
        zip[cd_offset + 8] |= 0x01;
        assert!(parse_zip(&zip).is_err(), "encrypted entry must be rejected");

        assert!(parse_zip(&[0u8; 10]).is_err(), "too-short input rejected");
        assert!(parse_zip(&[0u8; 100]).is_err(), "missing EOCD rejected");
    }
}
