//! Post-strip verification to confirm no residual metadata (S11 §8).
//!
//! After stripping, we re-scan the output to verify that no identifying
//! metadata fields remain. This is a defense-in-depth measure.

use crate::detect::FileType;
use crate::SanitizeError;

/// Result of post-strip verification.
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Whether the verification passed (no residual metadata found).
    pub passed: bool,
    /// Any residual metadata patterns found (should be empty if passed).
    pub residual_findings: Vec<String>,
}

/// Verify that no residual metadata remains after stripping (S11 §8).
///
/// Re-scans the stripped data for known metadata signatures.
/// Returns an error if residual metadata is detected.
pub fn verify_no_metadata(
    data: &[u8],
    file_type: &FileType,
) -> Result<VerificationResult, SanitizeError> {
    let mut findings = Vec::new();

    match file_type {
        FileType::Jpeg => verify_jpeg(data, &mut findings),
        FileType::Png => verify_png(data, &mut findings),
        FileType::Mp4 | FileType::Mov => verify_mp4(data, &mut findings),
        FileType::Pdf => verify_pdf(data, &mut findings),
        FileType::Mp3 => verify_mp3(data, &mut findings),
        FileType::Ogg => verify_ogg(data, &mut findings),
        FileType::Flac => verify_flac(data, &mut findings),
        FileType::WebP => verify_webp(data, &mut findings),
        FileType::Bmp => verify_bmp(data, &mut findings),
        FileType::Wav => verify_wav(data, &mut findings),
        FileType::Gif => verify_gif(data, &mut findings),
        FileType::Docx => verify_zip_document(
            data,
            crate::document::DOCX_METADATA_FILES,
            crate::document::DOCX_METADATA_TAGS,
            &mut findings,
        ),
        FileType::Odt => verify_zip_document(
            data,
            crate::document::ODT_METADATA_FILES,
            crate::document::ODT_METADATA_TAGS,
            &mut findings,
        ),
        // TIFF and HEIC have no verifier and always fail closed. Sanitized
        // output is never TIFF (converted to WebP, S11 §7.13) or HEIC
        // (refused, S11 §7.14).
        FileType::Tiff | FileType::Heic => findings.push(format!(
            "no metadata verifier for {file_type}; cannot confirm clean"
        )),
        FileType::Unknown => findings.push("cannot verify unknown file type".into()),
    }

    Ok(VerificationResult {
        passed: findings.is_empty(),
        residual_findings: findings,
    })
}

/// Verify JPEG has no residual metadata segments.
fn verify_jpeg(data: &[u8], findings: &mut Vec<String>) {
    // Scan for APP1 (EXIF/XMP) markers
    for i in 0..data.len().saturating_sub(1) {
        if data[i] == 0xFF {
            match data[i + 1] {
                0xE1 => findings.push("residual APP1 (EXIF/XMP) segment".into()),
                0xE2 => findings.push("residual APP2 (ICC) segment".into()),
                0xED => findings.push("residual APP13 (IPTC) segment".into()),
                0xE3..=0xEC | 0xEE..=0xEF => {
                    findings.push("residual JPEG application metadata segment".into())
                }
                0xFE => findings.push("residual COM (Comment) segment".into()),
                _ => {}
            }
        }
    }

    // Check for EXIF signature in data
    if data.windows(6).any(|w| w.starts_with(b"Exif\x00")) {
        findings.push("residual EXIF data found".into());
    }
}

/// Verify PNG has no residual metadata chunks.
fn verify_png(data: &[u8], findings: &mut Vec<String>) {
    let metadata_chunks: &[&[u8; 4]] = &[b"tEXt", b"iTXt", b"zTXt", b"eXIf", b"iCCP", b"tIME"];
    for chunk_type in metadata_chunks {
        if data.windows(4).any(|w| w == *chunk_type) {
            let name = std::str::from_utf8(*chunk_type).unwrap_or("unknown");
            findings.push(format!("residual PNG {name} chunk"));
        }
    }
}

/// Verify MP4/MOV has no residual metadata atoms.
fn verify_mp4(data: &[u8], findings: &mut Vec<String>) {
    match crate::video::strip_video_metadata(data) {
        Ok((_, residual)) => findings.extend(residual),
        Err(error) => findings.push(format!("unverifiable video: {error}")),
    }
}

/// Verify parsed PDF Info dictionaries and XMP stream references.
fn verify_pdf(data: &[u8], findings: &mut Vec<String>) {
    match crate::pdf::verify(data) {
        Ok(residual) => findings.extend(residual),
        Err(error) => findings.push(format!("unverifiable PDF: {error}")),
    }
}

/// Verify MP3 has no residual ID3 tags.
fn verify_mp3(data: &[u8], findings: &mut Vec<String>) {
    if data.len() >= 3 && &data[..3] == b"ID3" {
        findings.push("residual ID3v2 tag at start".into());
    }
    if data.len() >= 128 && &data[data.len() - 128..data.len() - 125] == b"TAG" {
        findings.push("residual ID3v1 tag at end".into());
    }
    if data.windows(8).any(|w| w == b"APETAGEX") {
        findings.push("residual APEv2 tag".into());
    }
    let trailing = &data[data.len().saturating_sub(160)..];
    if trailing.windows(3).any(|w| w == b"3DI") {
        findings.push("residual appended ID3v2.4 tag".into());
    }
}

/// Verify OGG comment packets are structurally parseable and contain neither a
/// vendor string nor user comments. Signature bytes inside audio are ignored.
fn verify_ogg(data: &[u8], findings: &mut Vec<String>) {
    match crate::audio::verify_ogg_comments(data) {
        Ok(residual) => findings.extend(residual),
        Err(error) => findings.push(format!("unverifiable OGG stream: {error}")),
    }
}

/// Verify a WAV has no residual metadata chunks (chunk-walk so a FourCC-like
/// byte run inside audio samples can't false-positive).
fn verify_wav(data: &[u8], findings: &mut Vec<String>) {
    let (chunks, riff_end) = match crate::audio::parse_wav_chunks(data) {
        Ok(parsed) => parsed,
        Err(error) => {
            findings.push(format!("unverifiable WAV stream: {error}"));
            return;
        }
    };
    for chunk in chunks {
        if !crate::audio::WAV_KEEP_CHUNKS.contains(&chunk.fourcc) {
            findings.push(format!(
                "residual WAV {} chunk",
                String::from_utf8_lossy(&chunk.fourcc).trim_end()
            ));
        }
    }
    if riff_end != data.len() {
        findings.push("residual WAV data outside RIFF boundary".into());
    }
}

/// Verify FLAC has no residual VORBIS_COMMENT blocks.
fn verify_flac(data: &[u8], findings: &mut Vec<String>) {
    if data.len() < 8 || &data[..4] != b"fLaC" {
        return;
    }

    let mut pos = 4;
    while pos + 4 <= data.len() {
        let header_byte = data[pos];
        let is_last = (header_byte & 0x80) != 0;
        let block_type = header_byte & 0x7F;
        let block_size = ((data[pos + 1] as usize) << 16)
            | ((data[pos + 2] as usize) << 8)
            | (data[pos + 3] as usize);

        if block_type == 4 {
            findings.push("residual FLAC VORBIS_COMMENT block".into());
        }
        if block_type == 6 {
            findings.push("residual FLAC PICTURE block".into());
        }

        pos += 4 + block_size;
        if is_last || pos > data.len() {
            break;
        }
    }
}

/// Verify a WebP has no residual EXIF/XMP chunks (walk the RIFF chunk list so a
/// FourCC-like byte sequence inside pixel data can't cause a false positive).
fn verify_webp(data: &[u8], findings: &mut Vec<String>) {
    if data.len() < 12 || &data[0..4] != b"RIFF" || &data[8..12] != b"WEBP" {
        findings.push("unverifiable WebP header".into());
        return;
    }
    let riff_size = u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize;
    let Some(riff_end) = 8usize
        .checked_add(riff_size)
        .filter(|&end| end <= data.len())
    else {
        findings.push("unverifiable WebP RIFF size".into());
        return;
    };
    let mut pos = 12;
    while pos < riff_end {
        if riff_end - pos < 8 {
            findings.push("unverifiable WebP chunk header".into());
            return;
        }
        let fourcc = &data[pos..pos + 4];
        let size = u32::from_le_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]])
            as usize;
        let Some(chunk_end) = (pos + 8)
            .checked_add(size)
            .and_then(|end| end.checked_add(size & 1))
            .filter(|&end| end <= riff_end)
        else {
            findings.push("unverifiable WebP chunk size".into());
            return;
        };
        match fourcc {
            b"EXIF" => findings.push("residual WebP EXIF chunk".into()),
            b"XMP " => findings.push("residual WebP XMP chunk".into()),
            b"ICCP" => findings.push("residual WebP ICC chunk".into()),
            b"VP8X" if size >= 1 && data[pos + 8] & 0x2C != 0 => {
                findings.push("residual WebP VP8X metadata flags".into())
            }
            _ => {}
        }
        pos = chunk_end;
    }
    if riff_end != data.len() {
        findings.push("residual WebP data outside RIFF boundary".into());
    }
}

/// Verify a BMP has no smuggled trailing data, embedded EXIF, or V5 ICC profile.
fn verify_bmp(data: &[u8], findings: &mut Vec<String>) {
    if data.len() < 14 || &data[0..2] != b"BM" {
        findings.push("unverifiable BMP header".into());
        return;
    }
    let declared = u32::from_le_bytes([data[2], data[3], data[4], data[5]]) as usize;
    if declared != data.len() {
        findings.push("BMP byte length does not match declared file size".into());
    }
    if data.windows(5).any(|w| w == b"Exif\x00") {
        findings.push("residual BMP embedded EXIF".into());
    }
    if data.len() >= 138 && u32::from_le_bytes(data[14..18].try_into().unwrap()) >= 124 {
        let color_space = u32::from_le_bytes(data[70..74].try_into().unwrap());
        if matches!(color_space, 0x4C49_4E4B | 0x4D42_4544)
            || data[126..134].iter().any(|&byte| byte != 0)
        {
            findings.push("residual BMP V5 ICC profile reference".into());
        }
    }
}

/// GIF sub-block skipper (used by verify_gif to walk extension blocks).
fn gif_skip_subblocks(data: &[u8], mut p: usize) -> Option<usize> {
    while p < data.len() {
        let len = data[p] as usize;
        p += 1;
        if len == 0 {
            return Some(p);
        }
        p = p.checked_add(len)?;
        if p > data.len() {
            return None;
        }
    }
    None
}

/// Verify a GIF has no residual comment or non-animation application extensions
/// (walks the block structure so image LZW data can't false-positive).
fn verify_gif(data: &[u8], findings: &mut Vec<String>) {
    if data.len() < 13 || (&data[0..6] != b"GIF87a" && &data[0..6] != b"GIF89a") {
        findings.push("unverifiable GIF header".into());
        return;
    }
    let mut pos = 13;
    if data[10] & 0x80 != 0 {
        pos += 3 * (1usize << ((data[10] & 0x07) + 1));
        if pos > data.len() {
            findings.push("unverifiable GIF global color table".into());
            return;
        }
    }
    let mut saw_trailer = false;
    while pos < data.len() {
        match data[pos] {
            0x3B => {
                saw_trailer = true;
                if pos + 1 != data.len() {
                    findings.push("residual GIF data after trailer".into());
                }
                break;
            }
            0x21 => {
                if pos + 2 > data.len() {
                    findings.push("unverifiable GIF extension".into());
                    return;
                }
                let label = data[pos + 1];
                let sub_start = pos + 2;
                let is_animation = label == 0xFF && sub_start < data.len() && {
                    let idlen = data[sub_start] as usize;
                    let id = &data[sub_start + 1..(sub_start + 1 + idlen).min(data.len())];
                    id.starts_with(b"NETSCAPE") || id.starts_with(b"ANIMEXTS")
                };
                match label {
                    0xFE => findings.push("residual GIF comment extension".into()),
                    0x01 => findings.push("residual GIF plain-text extension".into()),
                    0xFF if !is_animation => {
                        findings.push("residual GIF application extension".into())
                    }
                    _ => {}
                }
                match gif_skip_subblocks(data, sub_start) {
                    Some(e) => pos = e,
                    None => {
                        findings.push("unverifiable GIF extension sub-blocks".into());
                        return;
                    }
                }
            }
            0x2C => {
                if pos + 10 > data.len() {
                    findings.push("unverifiable GIF image descriptor".into());
                    return;
                }
                let packed = data[pos + 9];
                let mut p = pos + 10;
                if packed & 0x80 != 0 {
                    p += 3 * (1usize << ((packed & 0x07) + 1));
                }
                if p >= data.len() {
                    findings.push("unverifiable GIF image data".into());
                    return;
                }
                p += 1;
                match gif_skip_subblocks(data, p) {
                    Some(e) => pos = e,
                    None => {
                        findings.push("unverifiable GIF image sub-blocks".into());
                        return;
                    }
                }
            }
            _ => {
                findings.push("unverifiable GIF block type".into());
                return;
            }
        }
    }
    if !saw_trailer {
        findings.push("unverifiable GIF missing trailer".into());
    }
}

/// Verify a ZIP-based document (DOCX/ODT) is fully sanitized (S11 §5.4 + §8):
/// every entry stored with zeroed timestamps and no extra fields (the
/// entry-mtime leak), and the normative metadata tags in the target XML
/// members carry no content. An unparseable archive is itself a finding —
/// fail closed rather than affirm what we cannot inspect.
fn verify_zip_document(
    data: &[u8],
    target_files: &[&str],
    tags: &[&str],
    findings: &mut Vec<String>,
) {
    let entries = match crate::zip::parse_zip(data) {
        Ok(e) => e,
        Err(e) => {
            findings.push(format!("unverifiable ZIP archive: {e}"));
            return;
        }
    };
    for entry in &entries {
        if entry.method != 0 {
            findings.push(format!(
                "entry '{}' not stored (method {}) — §5.4 requires stored entries",
                entry.name, entry.method
            ));
        }
        if entry.dos_time != 0 || entry.dos_date != 0 {
            findings.push(format!(
                "entry '{}' carries a modification timestamp (entry-mtime leak)",
                entry.name
            ));
        }
        if entry.extra_len != 0 {
            findings.push(format!("entry '{}' carries extra fields", entry.name));
        }
        if target_files.contains(&entry.name.as_str()) {
            for tag in tags {
                match crate::document::empty_xml_tag_contents(&entry.data, tag) {
                    Ok((_, true)) => {
                        findings.push(format!("residual metadata in '{}': <{tag}>", entry.name))
                    }
                    Ok((_, false)) => {}
                    Err(error) => findings.push(format!("unverifiable metadata XML: {error}")),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ogg_packet(packet: &[u8]) -> Vec<u8> {
        assert!(packet.len() < 255);
        let mut page = b"OggS".to_vec();
        page.extend_from_slice(&[0, 0]); // version, header type
        page.extend_from_slice(&0u64.to_le_bytes());
        page.extend_from_slice(&1u32.to_le_bytes()); // serial
        page.extend_from_slice(&0u32.to_le_bytes()); // sequence
        page.extend_from_slice(&0u32.to_le_bytes()); // CRC (not checked by verifier)
        page.extend_from_slice(&[1, packet.len() as u8]);
        page.extend_from_slice(packet);
        page
    }

    fn wav_with_chunks(chunks: &[(&[u8; 4], &[u8])]) -> Vec<u8> {
        let mut body = b"WAVE".to_vec();
        for (fourcc, payload) in chunks {
            body.extend_from_slice(*fourcc);
            body.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            body.extend_from_slice(payload);
            if payload.len() & 1 != 0 {
                body.push(0);
            }
        }
        let mut wav = b"RIFF".to_vec();
        wav.extend_from_slice(&(body.len() as u32).to_le_bytes());
        wav.extend_from_slice(&body);
        wav
    }

    #[test]
    fn clean_jpeg_passes_verification() {
        // Minimal JPEG without metadata
        let jpeg = [0xFF, 0xD8, 0xFF, 0xDB, 0x00, 0x02, 0xFF, 0xD9];
        let result = verify_no_metadata(&jpeg, &FileType::Jpeg).unwrap();
        assert!(result.passed);
        assert!(result.residual_findings.is_empty());
    }

    #[test]
    fn jpeg_with_exif_fails_verification() {
        // JPEG with APP1 segment
        let jpeg = [0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x02, 0xFF, 0xD9];
        let result = verify_no_metadata(&jpeg, &FileType::Jpeg).unwrap();
        assert!(!result.passed);
        assert!(result.residual_findings.iter().any(|f| f.contains("APP1")));
    }

    #[test]
    fn clean_mp3_passes_verification() {
        let mp3 = [0xFF, 0xFB, 0x90, 0x00, 0x00, 0x00];
        let result = verify_no_metadata(&mp3, &FileType::Mp3).unwrap();
        assert!(result.passed);
    }

    #[test]
    fn mp3_with_id3v2_fails_verification() {
        let mut mp3 = b"ID3\x04\x00\x00".to_vec();
        mp3.extend_from_slice(&[0u8; 50]);
        let result = verify_no_metadata(&mp3, &FileType::Mp3).unwrap();
        assert!(!result.passed);
    }

    #[test]
    fn mp3_verifier_catches_apev2_header_and_appended_id3_footer() {
        let mut mp3 = vec![0xFF, 0xFB, 0x90, 0x00];
        mp3.extend_from_slice(b"APETAGEX");
        mp3.extend_from_slice(&[0u8; 24]);
        mp3.extend_from_slice(&[0u8; 192]); // APE header form, away from the tail
        mp3.extend_from_slice(b"3DI\x04\x00\x10\x00\x00\x00\x00");
        let result = verify_no_metadata(&mp3, &FileType::Mp3).unwrap();
        assert!(!result.passed);
        assert!(result.residual_findings.iter().any(|f| f.contains("APEv2")));
        assert!(result
            .residual_findings
            .iter()
            .any(|f| f.contains("appended ID3")));
    }

    #[test]
    fn ogg_verifier_catches_nonempty_comment_packet() {
        let mut comment = b"OpusTags".to_vec();
        comment.extend_from_slice(&6u32.to_le_bytes());
        comment.extend_from_slice(b"vendor");
        comment.extend_from_slice(&0u32.to_le_bytes());
        let result = verify_no_metadata(&ogg_packet(&comment), &FileType::Ogg).unwrap();
        assert!(!result.passed);
        assert!(result.residual_findings.iter().any(|f| f.contains("Opus")));
    }

    #[test]
    fn wav_verifier_catches_metadata_and_unknown_chunks() {
        let wav = wav_with_chunks(&[
            (b"fmt ", &[0, 0, 0, 0]),
            (b"bext", b"author"),
            (b"JUNK", b"unknown"),
            (b"data", &[1, 2, 3, 4]),
        ]);
        let result = verify_no_metadata(&wav, &FileType::Wav).unwrap();
        assert!(!result.passed);
        assert!(result.residual_findings.iter().any(|f| f.contains("bext")));
        assert!(result.residual_findings.iter().any(|f| f.contains("JUNK")));
    }

    #[test]
    fn weak_image_format_verifiers_catch_spec_metadata_surfaces() {
        let mut gif = b"GIF89a".to_vec();
        gif.extend_from_slice(&[1, 0, 1, 0, 0, 0, 0]);
        gif.extend_from_slice(&[0x21, 0x01, 0x03]);
        gif.extend_from_slice(b"PII");
        gif.extend_from_slice(&[0, 0x3B]);
        assert!(!verify_no_metadata(&gif, &FileType::Gif).unwrap().passed);

        let mut webp_body = b"WEBPVP8X".to_vec();
        webp_body.extend_from_slice(&10u32.to_le_bytes());
        webp_body.push(0x20); // ICC flag
        webp_body.extend_from_slice(&[0u8; 9]);
        webp_body.extend_from_slice(b"ICCP");
        webp_body.extend_from_slice(&4u32.to_le_bytes());
        webp_body.extend_from_slice(b"prof");
        let mut webp = b"RIFF".to_vec();
        webp.extend_from_slice(&(webp_body.len() as u32).to_le_bytes());
        webp.extend_from_slice(&webp_body);
        assert!(!verify_no_metadata(&webp, &FileType::WebP).unwrap().passed);

        let mut bmp = vec![0u8; 138];
        bmp[0..2].copy_from_slice(b"BM");
        bmp[2..6].copy_from_slice(&138u32.to_le_bytes());
        bmp[14..18].copy_from_slice(&124u32.to_le_bytes());
        bmp[70..74].copy_from_slice(&0x4D42_4544u32.to_le_bytes());
        bmp[126..130].copy_from_slice(&124u32.to_le_bytes());
        bmp[130..134].copy_from_slice(&4u32.to_le_bytes());
        assert!(!verify_no_metadata(&bmp, &FileType::Bmp).unwrap().passed);
    }

    #[test]
    fn unverifiable_type_fails_closed() {
        // A type with no verifier cannot be confirmed clean, so it MUST NOT pass
        // (S11 §5.1/§8) — otherwise unstripped TIFF/HEIC would ship.
        let data = [0x00, 0x01, 0x02, 0x03];
        let result = verify_no_metadata(&data, &FileType::Tiff).unwrap();
        assert!(!result.passed);
        assert!(result
            .residual_findings
            .iter()
            .any(|f| f.contains("no metadata verifier")));
    }
}
