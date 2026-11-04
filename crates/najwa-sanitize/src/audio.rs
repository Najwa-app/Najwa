//! ID3/Vorbis tag metadata stripping (S11 §7.7–7.9).
//!
//! Strips identifying metadata from audio files:
//! - MP3: stacked ID3v2/ID3v1, appended ID3v2.4, and APEv2 tags
//! - OGG: Vorbis comment packets
//! - FLAC: VORBIS_COMMENT and PICTURE metadata blocks

use std::collections::{HashMap, HashSet};

use crate::SanitizeError;

// ---------------------------------------------------------------------------
// MP3 ID3 stripping
// ---------------------------------------------------------------------------

/// Strip ID3 tags from an MP3 file.
///
/// Removes:
/// - Stacked ID3v2 tags at the beginning of the file
/// - ID3v1 tag at the end of the file (last 128 bytes starting with "TAG")
/// - Appended ID3v2.4 and APEv2 tags at the end
pub fn strip_mp3_metadata(data: &[u8]) -> Result<(Vec<u8>, Vec<String>), SanitizeError> {
    let mut removed = Vec::new();
    let mut start = 0;
    let mut end = data.len();

    // Iterate stacked ID3v2 tags at the start (some files carry more than one).
    while data.len() >= start + 10 && &data[start..start + 3] == b"ID3" {
        let flags = data[start + 5];
        let size = decode_syncsafe_u32(&data[start + 6..start + 10]) as usize;
        // A set footer-present flag (bit 4) appends a 10-byte footer to the tag.
        let footer = if flags & 0x10 != 0 { 10 } else { 0 };
        let total = 10 + size + footer;
        if start + total > data.len() {
            break;
        }
        start += total;
        removed.push("ID3v2".into());
    }

    // Strip trailing tags — ID3v1, APEv2, and an appended ID3v2.4 ("3DI" footer)
    // — in any order until none remain.
    loop {
        let mut changed = false;
        if end >= start + 128 && &data[end - 128..end - 125] == b"TAG" {
            end -= 128;
            removed.push("ID3v1".into());
            changed = true;
        }
        if end >= start + 32 && &data[end - 32..end - 24] == b"APETAGEX" {
            // Footer: APETAGEX(8) | version(4) | tag_size(4) | items(4) | flags(4) | reserved(8)
            let tag_size =
                u32::from_le_bytes(data[end - 20..end - 16].try_into().unwrap()) as usize;
            let flags = u32::from_le_bytes(data[end - 12..end - 8].try_into().unwrap());
            // tag_size covers items + footer; bit 31 of flags means a header precedes.
            let total = tag_size + if flags & 0x8000_0000 != 0 { 32 } else { 0 };
            if total >= 32 && end >= start + total {
                end -= total;
                removed.push("APEv2".into());
                changed = true;
            }
        }
        if end >= start + 20 && &data[end - 10..end - 7] == b"3DI" {
            let size = decode_syncsafe_u32(&data[end - 4..end]) as usize;
            let total = 20 + size;
            if end >= start + total && &data[end - total..end - total + 3] == b"ID3" {
                end -= total;
                removed.push("ID3v2.4-footer".into());
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    if start > end {
        return Err(SanitizeError::InvalidFormat(
            "ID3 tags overlap entire file".into(),
        ));
    }

    Ok((data[start..end].to_vec(), removed))
}

/// Decode a 4-byte syncsafe integer (used in ID3v2 headers).
/// Each byte uses only the lower 7 bits.
fn decode_syncsafe_u32(data: &[u8]) -> u32 {
    ((data[0] as u32) << 21) | ((data[1] as u32) << 14) | ((data[2] as u32) << 7) | (data[3] as u32)
}

// ---------------------------------------------------------------------------
// OGG Vorbis comment stripping
// ---------------------------------------------------------------------------

/// Strip Vorbis comments from an OGG file.
///
/// OGG files contain Vorbis comment packets that can include artist, title,
/// and other identifying metadata. We strip these by replacing the comment
/// packet with an empty comment packet while preserving the OGG page structure.
///
#[derive(Debug)]
struct OggPage {
    start: usize,
    end: usize,
    body_start: usize,
    serial: u32,
    segments: Vec<u8>,
}

#[derive(Default)]
struct OggPacket {
    bytes: Vec<u8>,
    ranges: Vec<(usize, usize, usize)>, // output offset, length, page start
}

fn parse_ogg_pages(data: &[u8]) -> Result<Vec<OggPage>, SanitizeError> {
    let mut pages = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        if data.len() - pos < 27 || &data[pos..pos + 4] != b"OggS" || data[pos + 4] != 0 {
            return Err(SanitizeError::InvalidFormat(
                "malformed OGG page header".into(),
            ));
        }
        let segment_count = data[pos + 26] as usize;
        let header_end = pos
            .checked_add(27 + segment_count)
            .filter(|&end| end <= data.len())
            .ok_or_else(|| SanitizeError::InvalidFormat("truncated OGG segment table".into()))?;
        let body_len = data[pos + 27..header_end]
            .iter()
            .try_fold(0usize, |sum, &length| sum.checked_add(length as usize))
            .ok_or_else(|| SanitizeError::InvalidFormat("OGG page size overflow".into()))?;
        let end = header_end
            .checked_add(body_len)
            .filter(|&end| end <= data.len())
            .ok_or_else(|| SanitizeError::InvalidFormat("truncated OGG page body".into()))?;
        pages.push(OggPage {
            start: pos,
            end,
            body_start: header_end,
            serial: u32::from_le_bytes(data[pos + 14..pos + 18].try_into().unwrap()),
            segments: data[pos + 27..header_end].to_vec(),
        });
        pos = end;
    }
    if pages.is_empty() {
        return Err(SanitizeError::InvalidFormat(
            "OGG stream has no pages".into(),
        ));
    }
    Ok(pages)
}

fn empty_ogg_comment(packet: &[u8]) -> Result<Option<(&'static str, Vec<u8>)>, SanitizeError> {
    let (kind, signature_len, framing) = if packet.starts_with(b"\x03vorbis") {
        ("Vorbis Comments", 7, true)
    } else if packet.starts_with(b"OpusTags") {
        ("Opus Tags", 8, false)
    } else {
        return Ok(None);
    };

    let mut pos = signature_len;
    let vendor_len = read_comment_len(packet, &mut pos)?;
    pos = pos
        .checked_add(vendor_len)
        .filter(|&end| end <= packet.len())
        .ok_or_else(|| SanitizeError::InvalidFormat("truncated OGG comment vendor".into()))?;
    let comment_count = read_comment_len(packet, &mut pos)?;
    for _ in 0..comment_count {
        let length = read_comment_len(packet, &mut pos)?;
        pos = pos
            .checked_add(length)
            .filter(|&end| end <= packet.len())
            .ok_or_else(|| SanitizeError::InvalidFormat("truncated OGG user comment".into()))?;
    }
    if framing && packet.get(pos).is_none_or(|byte| byte & 1 == 0) {
        return Err(SanitizeError::InvalidFormat(
            "Vorbis comment packet has no framing bit".into(),
        ));
    }

    let already_empty = vendor_len == 0 && comment_count == 0;
    let mut minimal = packet[..signature_len].to_vec();
    minimal.extend_from_slice(&0u32.to_le_bytes());
    minimal.extend_from_slice(&0u32.to_le_bytes());
    if framing {
        minimal.push(1);
    }
    if minimal.len() > packet.len() {
        return Err(SanitizeError::InvalidFormat(
            "truncated OGG comment packet".into(),
        ));
    }
    Ok((!already_empty).then_some((kind, minimal)))
}

fn read_comment_len(packet: &[u8], pos: &mut usize) -> Result<usize, SanitizeError> {
    let end = pos
        .checked_add(4)
        .filter(|&end| end <= packet.len())
        .ok_or_else(|| SanitizeError::InvalidFormat("truncated OGG comment length".into()))?;
    let length = u32::from_le_bytes(packet[*pos..end].try_into().unwrap()) as usize;
    *pos = end;
    Ok(length)
}

fn rewrite_packet(
    output: &mut [u8],
    packet: &OggPacket,
    replacement: &[u8],
    touched_pages: &mut HashSet<usize>,
) {
    let mut replacement_pos = 0usize;
    for &(offset, length, page_start) in &packet.ranges {
        let take = length.min(replacement.len().saturating_sub(replacement_pos));
        if take != 0 {
            output[offset..offset + take]
                .copy_from_slice(&replacement[replacement_pos..replacement_pos + take]);
            replacement_pos += take;
        }
        output[offset + take..offset + length].fill(0);
        touched_pages.insert(page_start);
    }
}

/// Ogg's non-reflected CRC-32 (polynomial 0x04C11DB7, initial value zero).
fn ogg_crc(page: &[u8]) -> u32 {
    let mut crc = 0u32;
    for &byte in page {
        crc ^= (byte as u32) << 24;
        for _ in 0..8 {
            crc = if crc & 0x8000_0000 != 0 {
                (crc << 1) ^ 0x04C1_1DB7
            } else {
                crc << 1
            };
        }
    }
    crc
}

pub fn strip_ogg_metadata(data: &[u8]) -> Result<(Vec<u8>, Vec<String>), SanitizeError> {
    let pages = parse_ogg_pages(data)?;
    let mut output = data.to_vec();
    let mut removed = Vec::new();
    let mut touched_pages = HashSet::new();
    let mut packets: HashMap<u32, OggPacket> = HashMap::new();

    for page in &pages {
        let packet = packets.entry(page.serial).or_default();
        let mut body_pos = page.body_start;
        for &segment_len in &page.segments {
            let segment_len = segment_len as usize;
            packet
                .bytes
                .extend_from_slice(&data[body_pos..body_pos + segment_len]);
            packet.ranges.push((body_pos, segment_len, page.start));
            body_pos += segment_len;
            if segment_len < 255 {
                if let Some((kind, minimal)) = empty_ogg_comment(&packet.bytes)? {
                    rewrite_packet(&mut output, packet, &minimal, &mut touched_pages);
                    removed.push(kind.into());
                }
                packet.bytes.clear();
                packet.ranges.clear();
            }
        }
    }
    if packets.values().any(|packet| !packet.bytes.is_empty()) {
        return Err(SanitizeError::InvalidFormat(
            "truncated continued OGG packet".into(),
        ));
    }

    for page in pages
        .iter()
        .filter(|page| touched_pages.contains(&page.start))
    {
        output[page.start + 22..page.start + 26].fill(0);
        let crc = ogg_crc(&output[page.start..page.end]);
        output[page.start + 22..page.start + 26].copy_from_slice(&crc.to_le_bytes());
    }

    Ok((output, removed))
}

/// Return residual OGG comment findings, or an error if the page/packet stream
/// cannot be parsed well enough to make a metadata-free determination.
pub(crate) fn verify_ogg_comments(data: &[u8]) -> Result<Vec<String>, SanitizeError> {
    let pages = parse_ogg_pages(data)?;
    let mut packets: HashMap<u32, Vec<u8>> = HashMap::new();
    let mut findings = Vec::new();
    for page in &pages {
        let packet = packets.entry(page.serial).or_default();
        let mut body_pos = page.body_start;
        for &segment_len in &page.segments {
            let segment_len = segment_len as usize;
            packet.extend_from_slice(&data[body_pos..body_pos + segment_len]);
            body_pos += segment_len;
            if segment_len < 255 {
                if let Some((kind, _)) = empty_ogg_comment(packet)? {
                    findings.push(format!("residual OGG {kind}"));
                }
                packet.clear();
            }
        }
    }
    if packets.values().any(|packet| !packet.is_empty()) {
        return Err(SanitizeError::InvalidFormat(
            "truncated continued OGG packet".into(),
        ));
    }
    Ok(findings)
}

// ---------------------------------------------------------------------------
// FLAC metadata stripping
// ---------------------------------------------------------------------------

/// FLAC metadata block types to strip.
const FLAC_STRIP_BLOCK_TYPES: &[u8] = &[
    4, // VORBIS_COMMENT
    6, // PICTURE
];

/// Strip metadata blocks from a FLAC file.
///
/// Removes VORBIS_COMMENT and PICTURE metadata blocks while
/// preserving STREAMINFO and other essential blocks.
pub fn strip_flac_metadata(data: &[u8]) -> Result<(Vec<u8>, Vec<String>), SanitizeError> {
    if data.len() < 8 || &data[..4] != b"fLaC" {
        return Err(SanitizeError::InvalidFormat("not a valid FLAC file".into()));
    }

    let mut output = Vec::new();
    let mut removed = Vec::new();

    // Write FLAC signature
    output.extend_from_slice(b"fLaC");

    let mut pos = 4;
    let mut last_kept_header_pos: Option<usize> = None;

    while pos + 4 <= data.len() {
        let header_byte = data[pos];
        let is_last = (header_byte & 0x80) != 0;
        let block_type = header_byte & 0x7F;
        let block_size = ((data[pos + 1] as usize) << 16)
            | ((data[pos + 2] as usize) << 8)
            | (data[pos + 3] as usize);

        let block_end = pos + 4 + block_size;
        if block_end > data.len() {
            return Err(SanitizeError::InvalidFormat(
                "truncated FLAC metadata block".into(),
            ));
        }

        if FLAC_STRIP_BLOCK_TYPES.contains(&block_type) {
            match block_type {
                4 => removed.push("FLAC:VORBIS_COMMENT".into()),
                6 => removed.push("FLAC:PICTURE".into()),
                _ => removed.push(format!("FLAC:block_{block_type}")),
            }
        } else {
            // Write block header (clear the is_last flag for now; we'll fix it later)
            last_kept_header_pos = Some(output.len());
            output.push(block_type); // is_last = 0 for now
            output.extend_from_slice(&data[pos + 1..pos + 4]); // size
            output.extend_from_slice(&data[pos + 4..block_end]); // data
        }

        pos = block_end;

        if is_last {
            break;
        }
    }

    // Fix the is_last flag on the last kept block
    if let Some(header_pos) = last_kept_header_pos {
        output[header_pos] |= 0x80;
    }

    // Append audio frames (everything after metadata blocks)
    if pos < data.len() {
        output.extend_from_slice(&data[pos..]);
    }

    Ok((output, removed))
}

// ---------------------------------------------------------------------------
// WAV metadata stripping (S11 §7.15) — RIFF container
// ---------------------------------------------------------------------------

/// Closed keep-list from S11 §7.15. Unknown chunks are metadata-capable and
/// therefore removed rather than guessed safe.
pub(crate) const WAV_KEEP_CHUNKS: &[[u8; 4]] =
    &[*b"fmt ", *b"data", *b"fact", *b"cue ", *b"plst", *b"smpl"];

#[derive(Debug)]
pub(crate) struct WavChunk {
    pub fourcc: [u8; 4],
    pub start: usize,
    pub end: usize,
}

pub(crate) fn parse_wav_chunks(data: &[u8]) -> Result<(Vec<WavChunk>, usize), SanitizeError> {
    if data.len() < 12 || &data[0..4] != b"RIFF" || &data[8..12] != b"WAVE" {
        return Err(SanitizeError::InvalidFormat("not a valid WAV".into()));
    }
    let riff_size = u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize;
    let riff_end = 8usize
        .checked_add(riff_size)
        .filter(|&end| riff_size >= 4 && end <= data.len())
        .ok_or_else(|| SanitizeError::InvalidFormat("invalid WAV RIFF size".into()))?;

    let mut chunks = Vec::new();
    let mut pos = 12usize;
    while pos < riff_end {
        if riff_end - pos < 8 {
            return Err(SanitizeError::InvalidFormat(
                "truncated WAV chunk header".into(),
            ));
        }
        let fourcc = data[pos..pos + 4].try_into().unwrap();
        let size = u32::from_le_bytes(data[pos + 4..pos + 8].try_into().unwrap()) as usize;
        let payload_start = pos + 8;
        let payload_end = payload_start
            .checked_add(size)
            .filter(|&end| end <= riff_end)
            .ok_or_else(|| SanitizeError::InvalidFormat("truncated WAV chunk".into()))?;
        let end = payload_end
            .checked_add(size & 1)
            .filter(|&end| end <= riff_end)
            .ok_or_else(|| SanitizeError::InvalidFormat("truncated WAV chunk padding".into()))?;
        chunks.push(WavChunk {
            fourcc,
            start: pos,
            end,
        });
        pos = end;
    }
    Ok((chunks, riff_end))
}

/// Strip metadata chunks from a WAV (RIFF) file (S11 §7.15). Kept chunks are
/// copied byte-for-byte in original order; audio is never decoded.
pub fn strip_wav_metadata(data: &[u8]) -> Result<(Vec<u8>, Vec<String>), SanitizeError> {
    let (chunks, riff_end) = parse_wav_chunks(data)?;
    let mut removed = Vec::new();
    let mut body = Vec::new();
    for chunk in chunks {
        if WAV_KEEP_CHUNKS.contains(&chunk.fourcc) {
            body.extend_from_slice(&data[chunk.start..chunk.end]);
        } else {
            removed.push(format!(
                "WAV:{}",
                String::from_utf8_lossy(&chunk.fourcc).trim_end()
            ));
        }
    }
    if riff_end < data.len() {
        removed.push("WAV:trailing-data".into());
    }

    let mut output = Vec::with_capacity(12 + body.len());
    output.extend_from_slice(b"RIFF");
    let output_size = u32::try_from(4 + body.len())
        .map_err(|_| SanitizeError::InvalidFormat("WAV output exceeds RIFF size limit".into()))?;
    output.extend_from_slice(&output_size.to_le_bytes());
    output.extend_from_slice(b"WAVE");
    output.extend_from_slice(&body);
    Ok((output, removed))
}

/// Strip audio metadata, dispatching by file type (S11 §7.7–7.9, §7.15).
pub fn strip_audio_metadata(
    data: &[u8],
    file_type: &crate::detect::FileType,
) -> Result<(Vec<u8>, Vec<String>), SanitizeError> {
    match file_type {
        crate::detect::FileType::Mp3 => strip_mp3_metadata(data),
        crate::detect::FileType::Wav => strip_wav_metadata(data),
        crate::detect::FileType::Flac => strip_flac_metadata(data),
        crate::detect::FileType::Ogg => strip_ogg_metadata(data),
        _ => Ok((data.to_vec(), vec![])),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ogg_segmented_page(
        serial: u32,
        sequence: u32,
        header_type: u8,
        segments: &[u8],
        body: &[u8],
    ) -> Vec<u8> {
        assert_eq!(
            segments
                .iter()
                .map(|&length| length as usize)
                .sum::<usize>(),
            body.len()
        );
        let mut page = b"OggS".to_vec();
        page.push(0); // stream-structure version
        page.push(header_type);
        page.extend_from_slice(&0u64.to_le_bytes()); // granule position
        page.extend_from_slice(&serial.to_le_bytes());
        page.extend_from_slice(&sequence.to_le_bytes());
        page.extend_from_slice(&0u32.to_le_bytes()); // checksum placeholder
        page.push(segments.len() as u8);
        page.extend_from_slice(segments);
        page.extend_from_slice(body);
        let crc = ogg_crc(&page);
        page[22..26].copy_from_slice(&crc.to_le_bytes());
        page
    }

    fn ogg_page(serial: u32, sequence: u32, header_type: u8, packet: &[u8]) -> Vec<u8> {
        assert!(packet.len() < 255);
        ogg_segmented_page(serial, sequence, header_type, &[packet.len() as u8], packet)
    }

    fn assert_ogg_checksums(data: &[u8]) {
        for page in parse_ogg_pages(data).unwrap() {
            let expected =
                u32::from_le_bytes(data[page.start + 22..page.start + 26].try_into().unwrap());
            let mut bytes = data[page.start..page.end].to_vec();
            bytes[22..26].fill(0);
            assert_eq!(ogg_crc(&bytes), expected);
        }
    }

    #[test]
    fn syncsafe_decode() {
        // 0x00 0x00 0x02 0x01 = 0*2^21 + 0*2^14 + 2*2^7 + 1 = 257
        assert_eq!(decode_syncsafe_u32(&[0x00, 0x00, 0x02, 0x01]), 257);
    }

    #[test]
    fn mp3_strips_id3v2() {
        let mut mp3 = Vec::new();
        // ID3v2 header
        mp3.extend_from_slice(b"ID3");
        mp3.extend_from_slice(&[0x04, 0x00]); // version 2.4.0
        mp3.push(0x00); // flags
                        // Size = 100 in syncsafe (0x00 0x00 0x00 0x64)
        mp3.extend_from_slice(&[0x00, 0x00, 0x00, 0x64]);
        // 100 bytes of tag data
        mp3.extend_from_slice(&[0u8; 100]);
        // Fake audio frame sync
        mp3.extend_from_slice(&[0xFF, 0xFB, 0x90, 0x00]);
        mp3.extend_from_slice(&[0u8; 50]); // audio data

        let (stripped, removed) = strip_mp3_metadata(&mp3).unwrap();
        assert!(removed.contains(&"ID3v2".to_string()));
        // Stripped should start with the sync bytes
        assert_eq!(stripped[0], 0xFF);
        assert_eq!(stripped[1], 0xFB);
    }

    #[test]
    fn mp3_strips_id3v1() {
        let mut mp3 = Vec::new();
        // Some audio data
        mp3.extend_from_slice(&[0xFF, 0xFB, 0x90, 0x00]);
        mp3.extend_from_slice(&[0u8; 50]);
        // ID3v1 tag (128 bytes starting with "TAG")
        mp3.extend_from_slice(b"TAG");
        mp3.extend_from_slice(&[0u8; 125]);

        let (stripped, removed) = strip_mp3_metadata(&mp3).unwrap();
        assert!(removed.contains(&"ID3v1".to_string()));
        assert_eq!(stripped.len(), 54); // 4 + 50 bytes of audio data
    }

    #[test]
    fn mp3_strips_both_id3v2_and_v1() {
        let mut mp3 = Vec::new();
        // ID3v2 header (size = 20)
        mp3.extend_from_slice(b"ID3\x04\x00\x00");
        mp3.extend_from_slice(&[0x00, 0x00, 0x00, 0x14]); // syncsafe 20
        mp3.extend_from_slice(&[0u8; 20]); // tag data
                                           // Audio data
        mp3.extend_from_slice(&[0xFF, 0xFB]);
        mp3.extend_from_slice(&[0u8; 200]);
        // ID3v1 at end
        mp3.extend_from_slice(b"TAG");
        mp3.extend_from_slice(&[0u8; 125]);

        let (stripped, removed) = strip_mp3_metadata(&mp3).unwrap();
        assert!(removed.contains(&"ID3v2".to_string()));
        assert!(removed.contains(&"ID3v1".to_string()));
        assert_eq!(stripped.len(), 202); // 2 + 200
    }

    #[test]
    fn flac_strips_vorbis_comment() {
        let mut flac = Vec::new();
        flac.extend_from_slice(b"fLaC");

        // STREAMINFO block (type 0, size = 34, not last)
        flac.push(0x00); // type=0, is_last=0
        flac.extend_from_slice(&[0x00, 0x00, 0x22]); // size=34
        flac.extend_from_slice(&[0u8; 34]);

        // VORBIS_COMMENT block (type 4, size = 20, not last)
        flac.push(0x04); // type=4, is_last=0
        flac.extend_from_slice(&[0x00, 0x00, 0x14]); // size=20
        flac.extend_from_slice(&[0u8; 20]);

        // PADDING block (type 1, size = 10, is_last)
        flac.push(0x81); // type=1, is_last=1
        flac.extend_from_slice(&[0x00, 0x00, 0x0A]); // size=10
        flac.extend_from_slice(&[0u8; 10]);

        // Audio frames
        flac.extend_from_slice(&[0xFF, 0xF8, 0x00, 0x00]);

        let (stripped, removed) = strip_flac_metadata(&flac).unwrap();
        assert!(removed.iter().any(|r| r.contains("VORBIS_COMMENT")));
        assert!(stripped.len() < flac.len());
        // Should still start with fLaC
        assert_eq!(&stripped[..4], b"fLaC");
    }

    #[test]
    fn flac_preserves_streaminfo() {
        let mut flac = Vec::new();
        flac.extend_from_slice(b"fLaC");

        // STREAMINFO (type 0, 34 bytes, is_last)
        flac.push(0x80); // type=0, is_last=1
        flac.extend_from_slice(&[0x00, 0x00, 0x22]); // size=34
        flac.extend_from_slice(&[0x42u8; 34]);

        let (stripped, removed) = strip_flac_metadata(&flac).unwrap();
        assert!(removed.is_empty());
        assert_eq!(stripped, flac);
    }

    #[test]
    fn ogg_strips_vorbis_comments_and_preserves_audio_page() {
        let serial = 7;
        let identification = ogg_page(serial, 0, 0x02, b"\x01vorbisidentification");
        let mut comment = b"\x03vorbis".to_vec();
        comment.extend_from_slice(&6u32.to_le_bytes());
        comment.extend_from_slice(b"Najwa!");
        comment.extend_from_slice(&1u32.to_le_bytes());
        comment.extend_from_slice(&11u32.to_le_bytes());
        comment.extend_from_slice(b"ARTIST=Alice");
        comment.push(1);
        let comment_page = ogg_page(serial, 1, 0, &comment);
        let audio_page = ogg_page(serial, 2, 0x04, b"\xAA\xBBaudio-payload\xCC");
        let audio_offset = identification.len() + comment_page.len();
        let mut ogg = identification;
        ogg.extend_from_slice(&comment_page);
        ogg.extend_from_slice(&audio_page);

        let (stripped, removed) = strip_ogg_metadata(&ogg).unwrap();
        assert!(removed.iter().any(|r| r.contains("Vorbis")));
        assert!(verify_ogg_comments(&stripped).unwrap().is_empty());
        assert_eq!(&stripped[audio_offset..], &audio_page);
        assert_ogg_checksums(&stripped);
    }

    #[test]
    fn ogg_strips_opus_tags() {
        let mut tags = b"OpusTags".to_vec();
        tags.extend_from_slice(&6u32.to_le_bytes());
        tags.extend_from_slice(b"vendor");
        tags.extend_from_slice(&1u32.to_le_bytes());
        tags.extend_from_slice(&9u32.to_le_bytes());
        tags.extend_from_slice(b"TITLE=One");
        let ogg = ogg_page(9, 1, 0, &tags);

        let (stripped, removed) = strip_ogg_metadata(&ogg).unwrap();
        assert!(removed.iter().any(|r| r.contains("Opus")));
        assert!(verify_ogg_comments(&stripped).unwrap().is_empty());
        assert_ogg_checksums(&stripped);
    }

    #[test]
    fn ogg_strips_comment_packet_continued_across_pages() {
        let mut tags = b"OpusTags".to_vec();
        tags.extend_from_slice(&260u32.to_le_bytes());
        tags.extend_from_slice(&[b'V'; 260]);
        tags.extend_from_slice(&0u32.to_le_bytes());
        let first = ogg_segmented_page(11, 0, 0x02, &[255], &tags[..255]);
        let second = ogg_segmented_page(11, 1, 0x01, &[(tags.len() - 255) as u8], &tags[255..]);
        let audio = ogg_page(11, 2, 0x04, b"audio");
        let audio_offset = first.len() + second.len();
        let mut ogg = first;
        ogg.extend_from_slice(&second);
        ogg.extend_from_slice(&audio);

        let (stripped, removed) = strip_ogg_metadata(&ogg).unwrap();
        assert!(removed.iter().any(|r| r.contains("Opus")));
        assert!(verify_ogg_comments(&stripped).unwrap().is_empty());
        assert_eq!(&stripped[audio_offset..], &audio);
        assert_ogg_checksums(&stripped);
    }

    #[test]
    fn flac_invalid_returns_error() {
        let result = strip_flac_metadata(&[0x00, 0x01]);
        assert!(result.is_err());
    }

    #[test]
    fn mp3_strips_stacked_id3v2_and_apev2() {
        let mut mp3 = Vec::new();
        // Two stacked ID3v2 tags (10-byte header + 4-byte body each).
        for _ in 0..2 {
            mp3.extend_from_slice(b"ID3\x04\x00\x00");
            mp3.extend_from_slice(&[0x00, 0x00, 0x00, 0x04]); // syncsafe 4
            mp3.extend_from_slice(&[0u8; 4]);
        }
        mp3.extend_from_slice(&[0xFF, 0xFB, 0x90, 0x00]); // audio frame
                                                          // APEv2 footer only (tag_size = 32, no header flag).
        mp3.extend_from_slice(b"APETAGEX");
        mp3.extend_from_slice(&2000u32.to_le_bytes());
        mp3.extend_from_slice(&32u32.to_le_bytes());
        mp3.extend_from_slice(&0u32.to_le_bytes());
        mp3.extend_from_slice(&0u32.to_le_bytes());
        mp3.extend_from_slice(&[0u8; 8]);

        let (out, removed) = strip_mp3_metadata(&mp3).unwrap();
        assert_eq!(removed.iter().filter(|r| *r == "ID3v2").count(), 2);
        assert!(removed.iter().any(|r| r == "APEv2"));
        assert_eq!(out, vec![0xFF, 0xFB, 0x90, 0x00]);
    }

    #[test]
    fn mp3_strips_apev2_header_and_footer_form() {
        let audio = [0xFF, 0xFB, 0x90, 0x00];
        let mut mp3 = audio.to_vec();
        for flags in [0xA000_0000u32, 0x8000_0000] {
            mp3.extend_from_slice(b"APETAGEX");
            mp3.extend_from_slice(&2000u32.to_le_bytes());
            mp3.extend_from_slice(&32u32.to_le_bytes());
            mp3.extend_from_slice(&0u32.to_le_bytes());
            mp3.extend_from_slice(&flags.to_le_bytes());
            mp3.extend_from_slice(&[0u8; 8]);
        }

        let (out, removed) = strip_mp3_metadata(&mp3).unwrap();
        assert_eq!(out, audio);
        assert!(removed.iter().any(|r| r == "APEv2"));
    }

    #[test]
    fn mp3_strips_appended_id3v24_header_body_and_footer() {
        let audio = [0xFF, 0xFB, 0x90, 0x00, 1, 2, 3, 4];
        let mut mp3 = audio.to_vec();
        mp3.extend_from_slice(b"ID3\x04\x00\x10");
        mp3.extend_from_slice(&[0, 0, 0, 4]);
        mp3.extend_from_slice(b"TIT2");
        mp3.extend_from_slice(b"3DI\x04\x00\x10");
        mp3.extend_from_slice(&[0, 0, 0, 4]);

        let (out, removed) = strip_mp3_metadata(&mp3).unwrap();
        assert_eq!(out, audio);
        assert!(removed.iter().any(|r| r == "ID3v2.4-footer"));
    }

    #[test]
    fn wav_closed_keep_list_strips_metadata_and_preserves_audio() {
        let mut body = b"WAVE".to_vec();
        body.extend_from_slice(b"fmt ");
        body.extend_from_slice(&4u32.to_le_bytes());
        body.extend_from_slice(&[0, 0, 0, 0]);
        body.extend_from_slice(b"LIST");
        let list = b"INFOISFTsoftware0000"; // even length (20) → no padding
        body.extend_from_slice(&(list.len() as u32).to_le_bytes());
        body.extend_from_slice(list);
        body.extend_from_slice(b"JUNK"); // unknown chunks are removed too
        body.extend_from_slice(&4u32.to_le_bytes());
        body.extend_from_slice(b"meta");
        body.extend_from_slice(b"data");
        body.extend_from_slice(&4u32.to_le_bytes());
        body.extend_from_slice(&[1, 2, 3, 4]);
        let mut wav = b"RIFF".to_vec();
        wav.extend_from_slice(&(body.len() as u32).to_le_bytes());
        wav.extend_from_slice(&body);

        let (out, removed) = strip_wav_metadata(&wav).unwrap();
        assert!(removed.iter().any(|r| r.contains("LIST")));
        assert!(removed.iter().any(|r| r.contains("JUNK")));
        assert!(!out.windows(4).any(|w| w == b"LIST"));
        let (chunks, _) = parse_wav_chunks(&out).unwrap();
        assert_eq!(
            chunks.iter().map(|chunk| chunk.fourcc).collect::<Vec<_>>(),
            [*b"fmt ", *b"data"]
        );
        let data_chunk = chunks
            .iter()
            .find(|chunk| chunk.fourcc == *b"data")
            .unwrap();
        let payload_start = data_chunk.start + 8;
        let payload_size =
            u32::from_le_bytes(out[data_chunk.start + 4..payload_start].try_into().unwrap())
                as usize;
        assert_eq!(
            &out[payload_start..payload_start + payload_size],
            &[1, 2, 3, 4]
        );
    }
}
