//! MP4/MOV/M4A atom metadata stripping (S11 §7.3).
//!
//! Strips identifying metadata from ISO Base Media File Format containers
//! (MP4, MOV, M4A). Removes `udta` (user data), `meta` (metadata), and other
//! atoms that may contain GPS coordinates, device info, or creation dates.
//!
//! After stripping, all `stco` (32-bit) and `co64` (64-bit) chunk offset
//! tables are adjusted to account for the size change inside `moov`, ensuring
//! the file remains playable.

use crate::SanitizeError;

/// Atom types to strip from MP4/MOV files.
/// These contain user/device metadata that can identify the sender.
pub(crate) const STRIP_ATOMS: &[&[u8; 4]] = &[
    b"udta", // User data box (contains GPS, device info)
    b"meta", // Metadata box (handler-based metadata)
    b"uuid", // Extended (UUID) metadata box
    b"XMP_", // XMP metadata
    b"CTIM", // Creation time
];

/// Read a 32-bit big-endian value from a byte slice.
fn read_u32_be(data: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

/// Write a 32-bit big-endian value into a byte slice.
fn write_u32_be(data: &mut [u8], offset: usize, value: u32) {
    let bytes = value.to_be_bytes();
    data[offset..offset + 4].copy_from_slice(&bytes);
}

/// Read a 64-bit big-endian value from a byte slice.
fn read_u64_be(data: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ])
}

/// Write a 64-bit big-endian value into a byte slice.
fn write_u64_be(data: &mut [u8], offset: usize, value: u64) {
    let bytes = value.to_be_bytes();
    data[offset..offset + 8].copy_from_slice(&bytes);
}

/// Strip metadata with checked atom boundaries and per-mdat relocation.
pub fn strip_video_metadata(data: &[u8]) -> Result<(Vec<u8>, Vec<String>), SanitizeError> {
    if data.len() < 8 {
        return Err(video_error("file too small"));
    }
    let mut output = Vec::new();
    let mut removed = Vec::new();
    let mut media = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let size = atom_actual_size(data, pos)?;
        let atom = &data[pos..pos + size];
        let kind: [u8; 4] = atom[4..8].try_into().unwrap();
        if matches!(&kind, b"moof" | b"mfra") {
            return Err(video_error("fragmented video is not supported safely"));
        }
        if STRIP_ATOMS.contains(&&kind) {
            removed.push(format!("MP4:{}", String::from_utf8_lossy(&kind)));
        } else if is_container_atom(&kind) {
            output.extend(strip_moov_children(atom, &mut removed, 0)?);
        } else {
            if &kind == b"mdat" {
                let header = atom_header_size(atom);
                media.push((pos + header, pos + size, output.len() + header));
            }
            output.extend_from_slice(atom);
        }
        pos += size;
    }
    adjust_chunk_offsets(&mut output, &media, 0)?;
    Ok((output, removed))
}

fn video_error(message: &str) -> SanitizeError {
    SanitizeError::InvalidFormat(format!("MP4/MOV: {message}"))
}

fn atom_header_size(data: &[u8]) -> usize {
    if read_u32_be(data, 0) == 1 {
        16
    } else {
        8
    }
}

/// Validate extended sizes before loops advance or slices are formed.
fn atom_actual_size(data: &[u8], pos: usize) -> Result<usize, SanitizeError> {
    let remaining = data
        .len()
        .checked_sub(pos)
        .ok_or_else(|| video_error("invalid atom offset"))?;
    if remaining < 8 {
        return Err(video_error("truncated atom header"));
    }
    let size32 = read_u32_be(data, pos);
    let (size, header) = match size32 {
        0 => (remaining, 8),
        1 => {
            if remaining < 16 {
                return Err(video_error("truncated extended atom header"));
            }
            (
                usize::try_from(read_u64_be(data, pos + 8))
                    .map_err(|_| video_error("atom size overflow"))?,
                16,
            )
        }
        size => (size as usize, 8),
    };
    if size < header || size > remaining {
        return Err(video_error("invalid or truncated atom size"));
    }
    Ok(size)
}

fn strip_moov_children(
    container: &[u8],
    removed: &mut Vec<String>,
    depth: usize,
) -> Result<Vec<u8>, SanitizeError> {
    if depth >= 64 {
        return Err(video_error("atom nesting exceeds 64"));
    }
    let mut output = vec![0; 8];
    output[4..8].copy_from_slice(&container[4..8]);
    let mut pos = atom_header_size(container);
    while pos < container.len() {
        let size = atom_actual_size(container, pos)?;
        let child = &container[pos..pos + size];
        let kind: [u8; 4] = child[4..8].try_into().unwrap();
        if STRIP_ATOMS.contains(&&kind) {
            removed.push(format!("MP4:{}", String::from_utf8_lossy(&kind)));
        } else if &kind == b"mvex" {
            return Err(video_error("fragmented video is not supported safely"));
        } else if is_container_atom(&kind) {
            output.extend(strip_moov_children(child, removed, depth + 1)?);
        } else {
            let mut cleaned = child.to_vec();
            if matches!(&kind, b"mvhd" | b"tkhd" | b"mdhd") {
                let header = atom_header_size(child);
                let version = *child
                    .get(header)
                    .ok_or_else(|| video_error("truncated timing box"))?;
                let date_len = match version {
                    0 => 8,
                    1 => 16,
                    _ => return Err(video_error("unknown timing box version")),
                };
                let dates = cleaned
                    .get_mut(header + 4..header + 4 + date_len)
                    .ok_or_else(|| video_error("truncated timing box dates"))?;
                if dates.iter().any(|&byte| byte != 0) {
                    dates.fill(0);
                    removed.push(format!("MP4:{} dates", String::from_utf8_lossy(&kind)));
                }
            }
            output.extend(cleaned);
        }
        pos += size;
    }
    let size = u32::try_from(output.len()).map_err(|_| video_error("container too large"))?;
    write_u32_be(&mut output, 0, size);
    Ok(output)
}

pub(crate) fn is_container_atom(atom_type: &[u8; 4]) -> bool {
    matches!(
        atom_type,
        b"moov" | b"trak" | b"mdia" | b"minf" | b"stbl" | b"edts" | b"dinf"
    )
}

/// Map each absolute offset through the media extent it originally referenced.
/// This handles top-level removals, extended headers, and multiple mdat boxes.
fn adjust_chunk_offsets(
    output: &mut [u8],
    media: &[(usize, usize, usize)],
    depth: usize,
) -> Result<(), SanitizeError> {
    if depth >= 64 {
        return Err(video_error("atom nesting exceeds 64"));
    }
    let mut pos = 0;
    while pos < output.len() {
        let size = atom_actual_size(output, pos)?;
        let atom = &mut output[pos..pos + size];
        let header = atom_header_size(atom);
        let kind: [u8; 4] = atom[4..8].try_into().unwrap();
        if matches!(&kind, b"stco" | b"co64") {
            if atom.len() < header + 8 || atom[header..header + 4] != [0; 4] {
                return Err(video_error("invalid chunk-offset header"));
            }
            let count = read_u32_be(atom, header + 4) as usize;
            let width = if &kind == b"stco" { 4 } else { 8 };
            let expected = count
                .checked_mul(width)
                .and_then(|n| n.checked_add(header + 8))
                .ok_or_else(|| video_error("offset table overflow"))?;
            if expected != size {
                return Err(video_error("truncated chunk-offset table"));
            }
            for i in 0..count {
                let p = header + 8 + i * width;
                let old = if width == 4 {
                    read_u32_be(atom, p) as u64
                } else {
                    read_u64_be(atom, p)
                };
                let &(start, _, new_start) = media
                    .iter()
                    .find(|&&(start, end, _)| old >= start as u64 && old < end as u64)
                    .ok_or_else(|| video_error("chunk offset outside local media data"))?;
                let new = old - start as u64 + new_start as u64;
                if width == 4 {
                    write_u32_be(
                        atom,
                        p,
                        u32::try_from(new)
                            .map_err(|_| video_error("32-bit chunk offset overflow"))?,
                    );
                } else {
                    write_u64_be(atom, p, new);
                }
            }
        } else if is_container_atom(&kind) {
            adjust_chunk_offsets(&mut atom[header..], media, depth + 1)?;
        }
        pos += size;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal MP4 with ftyp, moov (containing udta + trak with stco), and mdat.
    fn build_mp4_with_udta_and_stco() -> Vec<u8> {
        let mut mp4 = Vec::new();

        // ftyp atom (20 bytes)
        let ftyp_size: u32 = 20;
        mp4.extend_from_slice(&ftyp_size.to_be_bytes());
        mp4.extend_from_slice(b"ftyp");
        mp4.extend_from_slice(b"isom");
        mp4.extend_from_slice(&0u32.to_be_bytes());
        mp4.extend_from_slice(b"isom");

        // Build stco with one entry pointing into mdat
        // stco: size(4) + "stco"(4) + version/flags(4) + count(4) + offset(4) = 20 bytes
        let mdat_payload = b"Hello audio data here!";
        // mdat will start right after moov. We need to compute the offset.
        // ftyp = 20, moov = ?, mdat header = 8, data starts at ftyp + moov + 8
        // We'll compute moov size first, then fill in the offset.

        // udta child (16 bytes)
        let udta_data = b"GPScoord";
        let udta_size: u32 = 8 + udta_data.len() as u32;
        let mut udta = Vec::new();
        udta.extend_from_slice(&udta_size.to_be_bytes());
        udta.extend_from_slice(b"udta");
        udta.extend_from_slice(udta_data);

        // stco atom (20 bytes): 1 entry
        let stco_size: u32 = 20;
        let mut stco = Vec::new();
        stco.extend_from_slice(&stco_size.to_be_bytes());
        stco.extend_from_slice(b"stco");
        stco.extend_from_slice(&[0u8; 4]); // version + flags
        stco.extend_from_slice(&1u32.to_be_bytes()); // entry_count = 1
                                                     // offset placeholder — will be filled below
        stco.extend_from_slice(&0u32.to_be_bytes());

        // stbl containing stco (size = 8 + stco_size)
        let stbl_size: u32 = 8 + stco_size;
        let mut stbl = Vec::new();
        stbl.extend_from_slice(&stbl_size.to_be_bytes());
        stbl.extend_from_slice(b"stbl");
        stbl.extend_from_slice(&stco);

        // minf containing stbl
        let minf_size: u32 = 8 + stbl_size;
        let mut minf = Vec::new();
        minf.extend_from_slice(&minf_size.to_be_bytes());
        minf.extend_from_slice(b"minf");
        minf.extend_from_slice(&stbl);

        // mdia containing minf
        let mdia_size: u32 = 8 + minf_size;
        let mut mdia = Vec::new();
        mdia.extend_from_slice(&mdia_size.to_be_bytes());
        mdia.extend_from_slice(b"mdia");
        mdia.extend_from_slice(&minf);

        // trak containing mdia
        let trak_size: u32 = 8 + mdia_size;
        let mut trak = Vec::new();
        trak.extend_from_slice(&trak_size.to_be_bytes());
        trak.extend_from_slice(b"trak");
        trak.extend_from_slice(&mdia);

        // moov containing trak + udta
        let moov_size: u32 = 8 + trak_size + udta_size;
        let moov_offset_in_file = 20usize; // after ftyp
        let mdat_start = moov_offset_in_file + moov_size as usize;
        let mdat_data_start = mdat_start + 8; // mdat header is 8 bytes

        // Now patch stco entry to point at mdat_data_start
        let stco_entry_offset = trak.len() - 4; // last 4 bytes of trak are the stco entry
        let offset_bytes = (mdat_data_start as u32).to_be_bytes();
        trak[stco_entry_offset..stco_entry_offset + 4].copy_from_slice(&offset_bytes);

        mp4.extend_from_slice(&moov_size.to_be_bytes());
        mp4.extend_from_slice(b"moov");
        mp4.extend_from_slice(&trak);
        mp4.extend_from_slice(&udta);

        // mdat atom
        let mdat_size: u32 = 8 + mdat_payload.len() as u32;
        mp4.extend_from_slice(&mdat_size.to_be_bytes());
        mp4.extend_from_slice(b"mdat");
        mp4.extend_from_slice(mdat_payload);

        mp4
    }

    #[test]
    fn mp4_strips_udta_and_adjusts_offsets() {
        let mp4 = build_mp4_with_udta_and_stco();
        let original_len = mp4.len();

        let (stripped, removed) = strip_video_metadata(&mp4).unwrap();

        // udta was removed
        assert!(removed.iter().any(|r| r.contains("udta")));
        assert!(stripped.len() < original_len);

        // Find stco in the stripped output and verify the offset was adjusted.
        // stco layout: size(4) | "stco"(4) | version_flags(4) | entry_count(4) | offsets(4 each)
        // windows(4) finds "stco" at the type field, so the atom starts 4 bytes before.
        let stco_type_pos = stripped
            .windows(4)
            .position(|w| w == *b"stco")
            .expect("stco should exist");
        let stco_atom_start = stco_type_pos - 4;
        // version/flags at +8, entry_count at +12, first offset at +16
        let entry_count = read_u32_be(&stripped, stco_atom_start + 12) as usize;
        assert_eq!(entry_count, 1);

        let offset = read_u32_be(&stripped, stco_atom_start + 16);

        // Find mdat in stripped output. "mdat" type is at +4 into the atom.
        let mdat_type_pos = stripped
            .windows(4)
            .position(|w| w == *b"mdat")
            .expect("mdat should exist");
        let mdat_atom_start = mdat_type_pos - 4;
        let mdat_data_start = mdat_atom_start + 8; // skip size(4) + type(4)

        assert_eq!(
            offset as usize, mdat_data_start,
            "stco offset should point to mdat data after adjustment"
        );
    }

    #[test]
    fn mp4_preserves_ftyp_mdat() {
        let mp4 = build_mp4_with_udta_and_stco();
        let (stripped, _) = strip_video_metadata(&mp4).unwrap();

        assert_eq!(&stripped[4..8], b"ftyp");
        assert!(stripped.windows(4).any(|w| w == *b"mdat"));
    }

    #[test]
    fn mp4_preserves_moov_structure() {
        let mp4 = build_mp4_with_udta_and_stco();
        let (stripped, _) = strip_video_metadata(&mp4).unwrap();

        assert!(stripped.windows(4).any(|w| w == *b"moov"));
        assert!(stripped.windows(4).any(|w| w == *b"trak"));
        assert!(stripped.windows(4).any(|w| w == *b"stco"));
        // udta should NOT be present
        assert!(!stripped.windows(4).any(|w| w == *b"udta"));
    }

    #[test]
    fn mp4_no_metadata_passthrough() {
        // MP4 with no strippable atoms — should pass through unchanged
        let mut mp4 = Vec::new();

        let ftyp_size: u32 = 20;
        mp4.extend_from_slice(&ftyp_size.to_be_bytes());
        mp4.extend_from_slice(b"ftyp");
        mp4.extend_from_slice(b"isom");
        mp4.extend_from_slice(&0u32.to_be_bytes());
        mp4.extend_from_slice(b"isom");

        let moov_size: u32 = 8;
        mp4.extend_from_slice(&moov_size.to_be_bytes());
        mp4.extend_from_slice(b"moov");

        let mdat_size: u32 = 16;
        mp4.extend_from_slice(&mdat_size.to_be_bytes());
        mp4.extend_from_slice(b"mdat");
        mp4.extend_from_slice(b"testdata");

        let (stripped, removed) = strip_video_metadata(&mp4).unwrap();
        assert!(removed.is_empty());
        assert_eq!(stripped, mp4);
    }

    #[test]
    fn mp4_too_small_returns_error() {
        let result = strip_video_metadata(&[0x00, 0x01]);
        assert!(result.is_err());
    }
}
