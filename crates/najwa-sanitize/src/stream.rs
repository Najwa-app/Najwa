//! File-backed processing for large media. Media payloads are copied through a
//! 64 KiB buffer, and the streamed output is verified (S11 §8) by walking it
//! with bounded reads. Structural document/image codecs retain their existing
//! parser bounds and mandatory verification; they run one file at a time.
use crate::{FileType, SanitizationSettings, SanitizeError, VerificationResult};
use std::io::{Read, Seek, SeekFrom, Write};
use zeroize::Zeroizing;
fn bad() -> SanitizeError {
    SanitizeError::InvalidFormat("invalid streamed media container".into())
}
fn io(e: std::io::Error) -> SanitizeError {
    // A read that ends before the structure the file declares is a truncated
    // file, not a storage fault: retrying cannot fix it (S11 §5.3).
    if e.kind() == std::io::ErrorKind::UnexpectedEof {
        return bad();
    }
    SanitizeError::Other(e.to_string())
}
fn copy<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    mut size: u64,
    zero: bool,
) -> Result<(), SanitizeError> {
    let mut buffer = Zeroizing::new(vec![0; 65536]);
    while size > 0 {
        let n = size.min(buffer.len() as u64) as usize;
        if !zero {
            input.read_exact(&mut buffer[..n]).map_err(io)?;
        }
        output.write_all(&buffer[..n]).map_err(io)?;
        size -= n as u64;
    }
    Ok(())
}
pub fn sanitize_seekable<R: Read + Seek, W: Read + Write + Seek>(
    input: &mut R,
    output: &mut W,
) -> Result<FileType, SanitizeError> {
    let size = input.seek(SeekFrom::End(0)).map_err(io)?;
    if size == 0 || size > 268_435_456 {
        return Err(bad());
    }
    input.rewind().map_err(io)?;
    let mut prefix = [0; 64];
    let n = input.read(&mut prefix).map_err(io)?;
    input.rewind().map_err(io)?;
    let kind = crate::detect_file_type(&prefix[..n]);
    match kind {
        FileType::Unknown | FileType::Heic => {
            return Err(SanitizeError::UnsupportedType(
                "no safe sanitizer for this file type".into(),
            ))
        }
        FileType::Wav => wav(input, output, size)?,
        FileType::WebP => riff(input, output, size, true)?,
        FileType::Mp3 => mp3(input, output, size)?,
        FileType::Flac => flac(input, output, size)?,
        FileType::Mp4 | FileType::Mov => video(input, output, size, 0)?,
        _ => {
            let mut source = Zeroizing::new(Vec::with_capacity(size as usize));
            input.read_to_end(&mut source).map_err(io)?;
            let result = crate::sanitize_file(&source, &SanitizationSettings::default())?;
            let bytes = Zeroizing::new(result.sanitized_bytes);
            if bytes.len() > 268_435_456 {
                return Err(bad());
            }
            output.write_all(&bytes).map_err(io)?;
            return Ok(result.output_type);
        }
    }
    output.flush().map_err(io)?;
    // The streamed cleaners skip `sanitize_file`, so their output gets the
    // same mandatory verification pass here (S11 §8).
    let verification = verify_seekable(output, &kind)?;
    if !verification.passed {
        return Err(SanitizeError::VerificationFailed {
            residual_count: verification.residual_findings.len(),
            findings: verification.residual_findings,
        });
    }
    Ok(kind)
}

/// Verify a file-backed file as `kind` (S11 §8). WAV, WebP, MP3, FLAC, MP4 and
/// MOV are walked with reads of at most 64 KiB, applying the `verify_no_metadata`
/// rules; a structure the walk cannot follow is itself a finding. Other types
/// need the whole file, so they are read into memory (at most 256 MiB, §5.6).
pub fn verify_seekable<R: Read + Seek>(
    input: &mut R,
    kind: &FileType,
) -> Result<VerificationResult, SanitizeError> {
    let size = input.seek(SeekFrom::End(0)).map_err(io)?;
    input.rewind().map_err(io)?;
    let mut findings = Vec::new();
    let walked = match kind {
        FileType::Wav => verify_riff(input, size, false, &mut findings),
        FileType::WebP => verify_riff(input, size, true, &mut findings),
        FileType::Mp3 => verify_mp3(input, size, &mut findings),
        FileType::Flac => verify_flac(input, size, &mut findings),
        FileType::Mp4 | FileType::Mov => verify_video(input, size, 0, &mut findings),
        // No verifier: always a finding, without reading the file.
        FileType::Tiff | FileType::Heic | FileType::Unknown => {
            return crate::verify::verify_no_metadata(&[], kind)
        }
        _ => {
            if size > 268_435_456 {
                return Err(bad());
            }
            let mut data = Zeroizing::new(Vec::with_capacity(size as usize));
            input.read_to_end(&mut data).map_err(io)?;
            return crate::verify::verify_no_metadata(&data, kind);
        }
    };
    match walked {
        Err(SanitizeError::InvalidFormat(e)) => findings.push(format!("unverifiable {kind}: {e}")),
        other => other?,
    }
    Ok(VerificationResult {
        passed: findings.is_empty(),
        residual_findings: findings,
    })
}
fn verify_riff<R: Read + Seek>(
    input: &mut R,
    size: u64,
    webp: bool,
    findings: &mut Vec<String>,
) -> Result<(), SanitizeError> {
    let header = read_at(input, 0, 12)?;
    let end = u32::from_le_bytes(header[4..8].try_into().unwrap()) as u64 + 8;
    if &header[..4] != b"RIFF"
        || &header[8..] != if webp { b"WEBP" } else { b"WAVE" }
        || end < 12
        || end > size
    {
        return Err(bad());
    }
    let mut pos = 12;
    while pos < end {
        if end - pos < 8 {
            return Err(bad());
        }
        let h = read_at(input, pos, 8)?;
        let len = u32::from_le_bytes(h[4..].try_into().unwrap()) as u64;
        let padded = len + (len & 1);
        if pos + 8 + padded > end {
            return Err(bad());
        }
        let name = String::from_utf8_lossy(&h[..4]).trim_end().to_string();
        if webp {
            let flags =
                &h[..4] == b"VP8X" && len >= 1 && read_at(input, pos + 8, 1)?[0] & 0x2c != 0;
            if matches!(&h[..4], b"EXIF" | b"XMP " | b"ICCP") || flags {
                findings.push(format!("residual WebP {name} metadata"));
            }
        } else if !crate::audio::WAV_KEEP_CHUNKS
            .iter()
            .any(|v| v.as_slice() == &h[..4])
        {
            findings.push(format!("residual WAV {name} chunk"));
        }
        pos += 8 + padded;
    }
    if end != size {
        findings.push("residual data outside RIFF boundary".into());
    }
    Ok(())
}
fn verify_mp3<R: Read + Seek>(
    input: &mut R,
    size: u64,
    findings: &mut Vec<String>,
) -> Result<(), SanitizeError> {
    if size >= 3 && read_at(input, 0, 3)? == b"ID3" {
        findings.push("residual ID3v2 tag at start".into());
    }
    if size >= 128 && read_at(input, size - 128, 3)? == b"TAG" {
        findings.push("residual ID3v1 tag at end".into());
    }
    let tail = size.min(160);
    if read_at(input, size - tail, tail as usize)?
        .windows(3)
        .any(|v| v == b"3DI")
    {
        findings.push("residual appended ID3v2.4 tag".into());
    }
    // APETAGEX anywhere: scan 64 KiB blocks, carrying 7 bytes across blocks.
    input.rewind().map_err(io)?;
    let mut buffer = Zeroizing::new(vec![0; 65536 + 7]);
    let (mut carried, mut left) = (0, size);
    while left > 0 {
        let n = left.min(65536) as usize;
        input
            .read_exact(&mut buffer[carried..carried + n])
            .map_err(io)?;
        let filled = carried + n;
        if buffer[..filled].windows(8).any(|v| v == b"APETAGEX") {
            findings.push("residual APEv2 tag".into());
            break;
        }
        carried = filled.min(7);
        buffer.copy_within(filled - carried..filled, 0);
        left -= n as u64;
    }
    Ok(())
}
fn verify_flac<R: Read + Seek>(
    input: &mut R,
    size: u64,
    findings: &mut Vec<String>,
) -> Result<(), SanitizeError> {
    if size < 8 || read_at(input, 0, 4)? != b"fLaC" {
        return Err(bad());
    }
    let mut pos = 4;
    while pos + 4 <= size {
        let h = read_at(input, pos, 4)?;
        match h[0] & 127 {
            4 => findings.push("residual FLAC VORBIS_COMMENT block".into()),
            6 => findings.push("residual FLAC PICTURE block".into()),
            _ => {}
        }
        pos += 4 + u32::from_be_bytes([0, h[1], h[2], h[3]]) as u64;
        if h[0] & 128 != 0 {
            break;
        }
    }
    Ok(())
}
// The rules of the in-memory video verifier, without its chunk-offset check:
// offsets carry no metadata, and the streamed cleaner never moves media.
fn verify_video<R: Read + Seek>(
    input: &mut R,
    end: u64,
    depth: u32,
    findings: &mut Vec<String>,
) -> Result<(), SanitizeError> {
    if depth >= 64 {
        return Err(bad());
    }
    while input.stream_position().map_err(io)? < end {
        let (start, len, h) = box_header(input, end)?;
        let kind: [u8; 4] = h[4..8].try_into().unwrap();
        let name = String::from_utf8_lossy(&kind).to_string();
        if matches!(&kind, b"moof" | b"mfra" | b"mvex") {
            return Err(bad());
        } else if crate::video::STRIP_ATOMS.contains(&&kind) {
            findings.push(format!("residual MP4 {name} box"));
        } else if crate::video::is_container_atom(&kind) {
            verify_video(input, start + len, depth + 1, findings)?;
        } else if matches!(&kind, b"mvhd" | b"tkhd" | b"mdhd") {
            let at = start + h.len() as u64;
            let dates = match read_at(input, at, 4)?[0] {
                0 => 8,
                1 => 16,
                _ => return Err(bad()),
            };
            if len < h.len() as u64 + 4 + dates {
                return Err(bad());
            }
            if read_at(input, at + 4, dates as usize)?
                .iter()
                .any(|v| *v != 0)
            {
                findings.push(format!("residual MP4 {name} dates"));
            }
        }
        input.seek(SeekFrom::Start(start + len)).map_err(io)?;
    }
    Ok(())
}

fn wav<R: Read + Seek, W: Write + Seek>(
    input: &mut R,
    output: &mut W,
    size: u64,
) -> Result<(), SanitizeError> {
    riff(input, output, size, false)
}
fn riff<R: Read + Seek, W: Write + Seek>(
    input: &mut R,
    output: &mut W,
    size: u64,
    webp: bool,
) -> Result<(), SanitizeError> {
    let mut header = [0; 12];
    input.read_exact(&mut header).map_err(io)?;
    let end = u32::from_le_bytes(header[4..8].try_into().unwrap()) as u64 + 8;
    if &header[..4] != b"RIFF"
        || &header[8..] != if webp { b"WEBP" } else { b"WAVE" }
        || end < 12
        || end > size
    {
        return Err(bad());
    }
    output.write_all(&header).map_err(io)?;
    let mut pos = 12;
    while pos < end {
        if end - pos < 8 {
            return Err(bad());
        }
        let mut h = [0; 8];
        input.read_exact(&mut h).map_err(io)?;
        let len = u32::from_le_bytes(h[4..].try_into().unwrap()) as u64;
        let padded = len + (len & 1);
        if pos + 8 + padded > end {
            return Err(bad());
        }
        let keep = if webp {
            matches!(
                &h[..4],
                b"VP8 " | b"VP8L" | b"VP8X" | b"ALPH" | b"ANIM" | b"ANMF"
            )
        } else {
            crate::audio::WAV_KEEP_CHUNKS
                .iter()
                .any(|v| v.as_slice() == &h[..4])
        };
        if keep {
            output.write_all(&h).map_err(io)?;
            if webp && &h[..4] == b"VP8X" {
                if len < 10 {
                    return Err(bad());
                }
                let mut flags = [0];
                input.read_exact(&mut flags).map_err(io)?;
                flags[0] &= !0x2c;
                output.write_all(&flags).map_err(io)?;
                copy(input, output, padded - 1, false)?;
            } else {
                copy(input, output, padded, false)?;
            }
        } else {
            input.seek(SeekFrom::Current(padded as i64)).map_err(io)?;
        }
        pos += 8 + padded;
    }
    let output_end = output.stream_position().map_err(io)?;
    output.seek(SeekFrom::Start(4)).map_err(io)?;
    output
        .write_all(&((output_end - 8) as u32).to_le_bytes())
        .map_err(io)?;
    output.seek(SeekFrom::Start(output_end)).map_err(io)?;
    Ok(())
}
fn read_at<R: Read + Seek>(r: &mut R, pos: u64, n: usize) -> Result<Vec<u8>, SanitizeError> {
    r.seek(SeekFrom::Start(pos)).map_err(io)?;
    let mut b = vec![0; n];
    r.read_exact(&mut b).map_err(io)?;
    Ok(b)
}
fn syncsafe(b: &[u8]) -> Result<u64, SanitizeError> {
    if b.len() != 4 || b.iter().any(|v| v & 128 != 0) {
        return Err(bad());
    }
    Ok(b.iter().fold(0, |n, v| (n << 7) | *v as u64))
}
fn mp3<R: Read + Seek, W: Write + Seek>(
    input: &mut R,
    output: &mut W,
    size: u64,
) -> Result<(), SanitizeError> {
    let mut start = 0;
    let mut end = size;
    while end - start >= 10 {
        let h = read_at(input, start, 10)?;
        if &h[..3] != b"ID3" {
            break;
        }
        let total = 10 + syncsafe(&h[6..10])? + if h[5] & 16 != 0 { 10 } else { 0 };
        if total > end - start {
            return Err(bad());
        }
        start += total;
    }
    loop {
        let before = end;
        if end - start >= 128 && read_at(input, end - 128, 3)? == b"TAG" {
            end -= 128;
        }
        if end - start >= 32 {
            let footer = read_at(input, end - 32, 32)?;
            if &footer[..8] == b"APETAGEX" {
                let len = u32::from_le_bytes(footer[12..16].try_into().unwrap()) as u64;
                let flags = u32::from_le_bytes(footer[20..24].try_into().unwrap());
                let total = len + if flags & 0x8000_0000 != 0 { 32 } else { 0 };
                if total < 32 || total > end - start {
                    return Err(bad());
                }
                end -= total;
            }
        }
        if end - start >= 20 {
            let footer = read_at(input, end - 10, 10)?;
            if &footer[..3] == b"3DI" {
                let total = 20 + syncsafe(&footer[6..10])?;
                if total > end - start || read_at(input, end - total, 3)? != b"ID3" {
                    return Err(bad());
                }
                end -= total;
            }
        }
        if before == end {
            break;
        }
    }
    if start >= end {
        return Err(bad());
    }
    input.seek(SeekFrom::Start(start)).map_err(io)?;
    let mut buffer = Zeroizing::new(vec![0; 65536]);
    let mut overlap = Vec::new();
    let mut tail = Vec::new();
    let mut left = end - start;
    while left > 0 {
        let n = left.min(buffer.len() as u64) as usize;
        input.read_exact(&mut buffer[..n]).map_err(io)?;
        let mut scan = Zeroizing::new(overlap.clone());
        scan.extend_from_slice(&buffer[..n]);
        if scan.windows(8).any(|v| v == b"APETAGEX") {
            return Err(bad());
        }
        overlap = scan[scan.len().saturating_sub(7)..].to_vec();
        tail.extend_from_slice(&buffer[..n]);
        if tail.len() > 160 {
            tail = tail[tail.len() - 160..].to_vec()
        }
        output.write_all(&buffer[..n]).map_err(io)?;
        left -= n as u64;
    }
    if tail.windows(3).any(|v| v == b"3DI") {
        return Err(bad());
    }
    Ok(())
}
fn flac<R: Read + Seek, W: Write + Seek>(
    input: &mut R,
    output: &mut W,
    size: u64,
) -> Result<(), SanitizeError> {
    if read_at(input, 0, 4)? != b"fLaC" {
        return Err(bad());
    }
    output.write_all(b"fLaC").map_err(io)?;
    let mut pos = 4;
    let mut last = None;
    loop {
        if size - pos < 4 {
            return Err(bad());
        }
        let mut h = [0; 4];
        input.read_exact(&mut h).map_err(io)?;
        let terminal = h[0] & 128 != 0;
        let kind = h[0] & 127;
        let len = u32::from_be_bytes([0, h[1], h[2], h[3]]) as u64;
        if len > size - pos - 4 {
            return Err(bad());
        }
        if matches!(kind, 4 | 6) {
            input.seek(SeekFrom::Current(len as i64)).map_err(io)?;
        } else {
            let p = output.stream_position().map_err(io)?;
            last = Some((p, kind));
            h[0] = kind;
            output.write_all(&h).map_err(io)?;
            copy(input, output, len, false)?;
        }
        pos += 4 + len;
        if terminal {
            break;
        }
    }
    let Some((where_, kind)) = last else {
        return Err(bad());
    };
    let out_end = output.stream_position().map_err(io)?;
    output.seek(SeekFrom::Start(where_)).map_err(io)?;
    output.write_all(&[kind | 128]).map_err(io)?;
    output.seek(SeekFrom::Start(out_end)).map_err(io)?;
    copy(input, output, size - pos, false)
}
/// Read the box header at the current position: (start, total length, header).
fn box_header<R: Read + Seek>(
    input: &mut R,
    end: u64,
) -> Result<(u64, u64, Vec<u8>), SanitizeError> {
    let start = input.stream_position().map_err(io)?;
    if end - start < 8 {
        return Err(bad());
    }
    let mut h = vec![0; 8];
    input.read_exact(&mut h).map_err(io)?;
    let len = match u32::from_be_bytes(h[..4].try_into().unwrap()) {
        0 => end - start,
        1 => {
            h.resize(16, 0);
            input.read_exact(&mut h[8..]).map_err(io)?;
            u64::from_be_bytes(h[8..].try_into().unwrap())
        }
        v => v as u64,
    };
    if len < h.len() as u64 || len > end - start {
        return Err(bad());
    }
    Ok((start, len, h))
}
// Replace metadata/free payloads by zero-filled free boxes of the same length.
// All mdat positions and absolute stco/co64 offsets therefore remain unchanged.
fn video<R: Read + Seek, W: Write + Seek>(
    input: &mut R,
    output: &mut W,
    end: u64,
    depth: u32,
) -> Result<(), SanitizeError> {
    if depth >= 64 {
        return Err(bad());
    }
    while input.stream_position().map_err(io)? < end {
        let (start, len, mut h) = box_header(input, end)?;
        let kind: [u8; 4] = h[4..8].try_into().unwrap();
        let payload = len - h.len() as u64;
        if matches!(&kind, b"moof" | b"mfra" | b"mvex") {
            return Err(bad());
        }
        if matches!(
            &kind,
            b"udta" | b"meta" | b"uuid" | b"XMP_" | b"CTIM" | b"free" | b"skip"
        ) {
            h[4..8].copy_from_slice(b"free");
            output.write_all(&h).map_err(io)?;
            copy(input, output, payload, true)?;
            input.seek(SeekFrom::Start(start + len)).map_err(io)?;
        } else {
            output.write_all(&h).map_err(io)?;
            if matches!(
                &kind,
                b"moov" | b"trak" | b"mdia" | b"minf" | b"stbl" | b"edts" | b"dinf"
            ) {
                video(input, output, start + len, depth + 1)?;
            } else if matches!(&kind, b"mvhd" | b"tkhd" | b"mdhd") {
                let mut version = [0; 4];
                input.read_exact(&mut version).map_err(io)?;
                let dates = match version[0] {
                    0 => 8,
                    1 => 16,
                    _ => return Err(bad()),
                };
                if payload < 4 + dates {
                    return Err(bad());
                }
                output.write_all(&version).map_err(io)?;
                copy(input, output, dates, true)?;
                input.seek(SeekFrom::Current(dates as i64)).map_err(io)?;
                copy(input, output, payload - 4 - dates, false)?;
            } else {
                copy(input, output, payload, false)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    fn wav(payload: usize) -> Vec<u8> {
        let mut b = b"RIFF\0\0\0\0WAVEfmt \x10\0\0\0".to_vec();
        b.extend_from_slice(&[1, 0, 1, 0, 0x44, 0xac, 0, 0, 0x88, 0x58, 1, 0, 2, 0, 16, 0]);
        b.extend_from_slice(b"LIST\x0c\0\0\0INFOAuthor!!");
        b.extend_from_slice(b"data");
        b.extend_from_slice(&(payload as u32).to_le_bytes());
        b.resize(b.len() + payload, 0x42);
        let size = b.len() as u32 - 8;
        b[4..8].copy_from_slice(&size.to_le_bytes());
        b.extend_from_slice(b"private trailing data");
        b
    }
    #[test]
    fn streamed_wav_matches_verified_sanitizer_and_removes_trailing_metadata() {
        let source = wav(3 * 1024 * 1024);
        let expected = crate::sanitize_file(&source, &SanitizationSettings::default()).unwrap();
        let mut out = Cursor::new(Vec::new());
        assert_eq!(
            sanitize_seekable(&mut Cursor::new(source), &mut out).unwrap(),
            FileType::Wav
        );
        assert_eq!(out.into_inner(), expected.sanitized_bytes);
    }
    struct BoundedReader {
        inner: Cursor<Vec<u8>>,
        largest: usize,
    }
    impl Read for BoundedReader {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            self.largest = self.largest.max(b.len());
            assert!(b.len() <= 65536);
            self.inner.read(b)
        }
    }
    impl Seek for BoundedReader {
        fn seek(&mut self, s: SeekFrom) -> std::io::Result<u64> {
            self.inner.seek(s)
        }
    }
    #[test]
    fn large_media_is_never_requested_as_one_buffer() {
        let mut input = BoundedReader {
            inner: Cursor::new(wav(8 * 1024 * 1024)),
            largest: 0,
        };
        let mut out = Cursor::new(Vec::new());
        sanitize_seekable(&mut input, &mut out).unwrap();
        assert_eq!(input.largest, 65536);
    }
    fn atom(kind: &[u8; 4], body: &[u8]) -> Vec<u8> {
        let mut b = ((body.len() + 8) as u32).to_be_bytes().to_vec();
        b.extend_from_slice(kind);
        b.extend_from_slice(body);
        b
    }
    fn tagged_video() -> Vec<u8> {
        let ftyp = atom(b"ftyp", b"isom\0\0\0\0isom");
        let mut timing = vec![0; 20];
        timing[4..12].fill(3);
        let moov = atom(
            b"moov",
            &[atom(b"mvhd", &timing), atom(b"udta", b"private author")].concat(),
        );
        let mdat = atom(b"mdat", &vec![0x35; 1024 * 1024]);
        [ftyp, moov, mdat].concat()
    }
    fn tagged_mp3_flac_webp() -> [Vec<u8>; 3] {
        let mut mp3 = b"ID3\x04\0\0\0\0\0\x04tags\xff\xfb\x90\0audio frames".to_vec();
        let mut tag = vec![0; 128];
        tag[..3].copy_from_slice(b"TAG");
        mp3.extend(tag);
        let mut flac = b"fLaC\0\0\0\x22".to_vec();
        flac.extend([0; 34]);
        flac.extend(b"\x84\0\0\x04tagsaudio frames");
        let mut body =
            b"VP8X\x0a\0\0\0\x2c\0\0\0\0\0\0\0\0\0EXIF\x04\0\0\0tagsVP8 \x04\0\0\0data".to_vec();
        let mut webp = b"RIFF".to_vec();
        webp.extend_from_slice(&((body.len() + 4) as u32).to_le_bytes());
        webp.extend(b"WEBP");
        webp.append(&mut body);
        [mp3, flac, webp]
    }
    #[test]
    fn streamed_video_erases_metadata_and_dates_without_moving_media() {
        let source = tagged_video();
        let position = source.windows(4).position(|v| v == b"mdat").unwrap();
        let mut out = Cursor::new(Vec::new());
        sanitize_seekable(&mut Cursor::new(source.clone()), &mut out).unwrap();
        let bytes = out.into_inner();
        assert_eq!(bytes.len(), source.len());
        assert_eq!(&bytes[position..], &source[position..]);
        assert!(!bytes.windows(7).any(|v| v == b"private"));
        assert!(
            crate::verify::verify_no_metadata(&bytes, &FileType::Mp4)
                .unwrap()
                .passed
        );
    }
    #[test]
    fn streamed_containers_fail_closed_on_malformed_sizes_and_fragmentation() {
        let mut bad_wav = wav(10);
        bad_wav[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(
            sanitize_seekable(&mut Cursor::new(bad_wav), &mut Cursor::new(Vec::new())).is_err()
        );
        let fragmented = [
            atom(b"ftyp", b"isom\0\0\0\0isom"),
            atom(b"moof", b"fragment"),
        ]
        .concat();
        assert!(
            sanitize_seekable(&mut Cursor::new(fragmented), &mut Cursor::new(Vec::new())).is_err()
        );
    }
    #[test]
    fn streamed_mp3_flac_and_webp_match_verified_metadata_removal() {
        for source in tagged_mp3_flac_webp() {
            let expected = crate::sanitize_file(&source, &SanitizationSettings::default()).unwrap();
            let mut output = Cursor::new(Vec::new());
            let kind = sanitize_seekable(&mut Cursor::new(source), &mut output).unwrap();
            assert_eq!(kind, expected.output_type);
            assert_eq!(output.into_inner(), expected.sanitized_bytes);
        }
    }
    /// An output that undoes the cleaner's `udta` → `free` rename, as a
    /// cleaner bug would.
    struct Unrenamed(Cursor<Vec<u8>>);
    impl Write for Unrenamed {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            if b.len() >= 8 && &b[4..8] == b"free" {
                return self.0.write(&[&b[..4], b"udta", &b[8..]].concat());
            }
            self.0.write(b)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl Read for Unrenamed {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            self.0.read(b)
        }
    }
    impl Seek for Unrenamed {
        fn seek(&mut self, s: SeekFrom) -> std::io::Result<u64> {
            self.0.seek(s)
        }
    }
    #[test]
    fn streamed_output_with_leftover_metadata_fails_verification() {
        let mut leaky = Unrenamed(Cursor::new(Vec::new()));
        assert!(matches!(
            sanitize_seekable(&mut Cursor::new(tagged_video()), &mut leaky),
            Err(SanitizeError::VerificationFailed { .. })
        ));
        // Each streamed walker reports what the in-memory verifier reports.
        let [mp3, flac, webp] = tagged_mp3_flac_webp();
        for (source, kind) in [
            (wav(16), FileType::Wav),
            (webp, FileType::WebP),
            (mp3, FileType::Mp3),
            (flac, FileType::Flac),
            (tagged_video(), FileType::Mp4),
        ] {
            assert!(
                !crate::verify::verify_no_metadata(&source, &kind)
                    .unwrap()
                    .passed
            );
            let streamed = verify_seekable(&mut Cursor::new(source), &kind).unwrap();
            assert!(!streamed.passed, "{kind}");
        }
    }
}
