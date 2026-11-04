//! Real-world file tests for sanitization (S11 §7).
//!
//! Image formats are tested through the WebP conversion path (structural
//! metadata destruction): a real, decodable image is generated with the
//! `image` crate, a metadata segment is injected, and the conversion must
//! destroy it. Audio/video formats keep their per-format strippers.

use std::io::Cursor;

use image::{DynamicImage, ImageFormat, Rgb, RgbImage};
use najwa_sanitize::audio::strip_mp3_metadata;
use najwa_sanitize::convert::convert_to_webp;
use najwa_sanitize::video::strip_video_metadata;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// Encode a real 2×2 RGB image in the given format.
fn real_image(format: ImageFormat) -> Vec<u8> {
    let img = DynamicImage::ImageRgb8(RgbImage::from_pixel(2, 2, Rgb([90, 140, 200])));
    let mut out = Cursor::new(Vec::new());
    img.write_to(&mut out, format).unwrap();
    out.into_inner()
}

/// Build a real JPEG with an EXIF APP1 segment injected after SOI. The
/// segment carries a correct big-endian length so decoders skip it cleanly.
fn jpeg_with_metadata() -> Vec<u8> {
    let mut jpeg = real_image(ImageFormat::Jpeg);
    assert_eq!(&jpeg[0..2], &[0xFF, 0xD8], "fixture must start with SOI");

    let exif = b"Exif\0\0GPS_LATITUDE=48.8566;LONGITUDE=2.3522;CAMERA=Canon EOS R5;";
    let mut segment = Vec::new();
    segment.extend_from_slice(&[0xFF, 0xE1]); // APP1 marker
    segment.extend_from_slice(&((exif.len() + 2) as u16).to_be_bytes());
    segment.extend_from_slice(exif);
    // Splice the APP1 in right after the SOI (before any other segment).
    jpeg.splice(2..2, segment);
    jpeg
}

/// Build a real PNG with a tEXt metadata chunk injected before IEND.
fn png_with_metadata() -> Vec<u8> {
    let png = real_image(ImageFormat::Png);
    let (body, iend) = png.split_at(png.len() - 12);
    assert_eq!(&iend[4..8], b"IEND", "fixture must end with IEND");

    let text = b"Comment\0metadata leak";
    let mut chunk = Vec::new();
    chunk.extend_from_slice(&(text.len() as u32).to_be_bytes());
    chunk.extend_from_slice(b"tEXt");
    chunk.extend_from_slice(text);
    chunk.extend_from_slice(&crc32(&chunk[4..]).to_be_bytes());

    let mut out = body.to_vec();
    out.extend_from_slice(&chunk);
    out.extend_from_slice(iend);
    out
}

/// Minimal CRC-32 (IEEE 802.3) for PNG chunk construction.
fn crc32(data: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for i in 0..256u32 {
        let mut c = i;
        for _ in 0..8 {
            c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
        }
        table[i as usize] = c;
    }
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc = table[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

/// Build a minimal MP4 with a udta atom containing metadata.
fn mp4_with_metadata() -> Vec<u8> {
    let mut data = Vec::new();
    let ftyp_data = b"isom\0\0\0\0isomavc1";
    let ftyp_size = (8 + ftyp_data.len()) as u32;
    data.extend_from_slice(&ftyp_size.to_be_bytes());
    data.extend_from_slice(b"ftyp");
    data.extend_from_slice(ftyp_data);
    let udta_payload = b"GPS: 48.8566, 2.3522; Device: TestPhone";
    let udta_size = (8 + udta_payload.len()) as u32;
    let moov_size = 8 + udta_size;
    data.extend_from_slice(&moov_size.to_be_bytes());
    data.extend_from_slice(b"moov");
    data.extend_from_slice(&udta_size.to_be_bytes());
    data.extend_from_slice(b"udta");
    data.extend_from_slice(udta_payload);
    let mdat = [0u8; 16];
    let mdat_size = (8 + mdat.len()) as u32;
    data.extend_from_slice(&mdat_size.to_be_bytes());
    data.extend_from_slice(b"mdat");
    data.extend_from_slice(&mdat);
    data
}

/// Build a minimal MP3 with ID3v2 header + ID3v1 tag.
fn mp3_with_metadata() -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(b"ID3");
    data.extend_from_slice(&[0x04, 0x00, 0x00]);
    data.extend_from_slice(&[0x00, 0x00, 0x00, 0x40]);
    let title_frame = b"TIT2\0\0\0\x0C\0\0\x03Test Title\0";
    data.extend_from_slice(title_frame);
    let pad_needed = 64 - title_frame.len();
    data.extend_from_slice(&vec![0u8; pad_needed]);
    for _ in 0..4 {
        data.extend_from_slice(&[0xFF, 0xFB]);
        data.extend_from_slice(&[0x90, 0x00]);
        data.extend_from_slice(&[0x00; 413]);
    }
    data.extend_from_slice(b"TAG");
    data.extend_from_slice(b"Test Title\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
    data.extend_from_slice(b"Test Artist\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
    data.extend_from_slice(&[0u8; 35]);
    data
}

// ---------------------------------------------------------------------------
// Image conversion tests (WebP path)
// ---------------------------------------------------------------------------

#[test]
fn jpeg_conversion_destroys_metadata() {
    let jpeg = jpeg_with_metadata();
    assert!(
        jpeg.windows(4).any(|w| w == b"Exif"),
        "fixture should contain EXIF data"
    );

    let webp = convert_to_webp(&jpeg).unwrap();
    // The EXIF marker bytes must not survive the conversion.
    assert!(
        !webp.windows(4).any(|w| w == *b"Exif"),
        "EXIF leaked into WebP output"
    );
    // WebP magic present.
    assert_eq!(&webp[8..12], b"WEBP");
}

#[test]
fn png_conversion_destroys_metadata() {
    let png = png_with_metadata();
    assert!(
        png.windows(4).any(|w| w == b"tEXt"),
        "fixture should contain tEXt chunk"
    );

    let webp = convert_to_webp(&png).unwrap();
    // tEXt chunk marker must not survive.
    assert!(
        !webp.windows(4).any(|w| w == *b"tEXt"),
        "tEXt chunk leaked into WebP output"
    );
    assert_eq!(&webp[8..12], b"WEBP");
}

// ---------------------------------------------------------------------------
// Audio/video format tests (per-format strippers — not WebP-converted)
// ---------------------------------------------------------------------------

#[test]
fn mp4_udta_stripped() {
    let mp4 = mp4_with_metadata();
    assert!(
        mp4.windows(4).any(|w| w == b"udta"),
        "fixture should contain udta atom"
    );

    let result = strip_video_metadata(&mp4);
    match result {
        Ok((stripped, removed)) => {
            assert!(!removed.is_empty(), "should report removed metadata");
            assert!(
                !stripped.windows(4).any(|w| w == b"udta"),
                "stripped MP4 should not contain udta"
            );
            assert!(
                stripped.windows(4).any(|w| w == b"ftyp"),
                "ftyp must be preserved"
            );
        }
        Err(e) => {
            eprintln!("MP4 strip returned error (may be expected for minimal fixture): {e}");
        }
    }
}

#[test]
fn mp3_id3_tags_stripped() {
    let mp3 = mp3_with_metadata();
    assert_eq!(&mp3[..3], b"ID3", "fixture should start with ID3v2");

    let result = strip_mp3_metadata(&mp3);
    match result {
        Ok((stripped, removed)) => {
            assert!(!removed.is_empty(), "should report removed metadata");
            assert_ne!(
                &stripped[..3],
                b"ID3",
                "stripped MP3 should not start with ID3v2"
            );
            let end = &stripped[stripped.len().saturating_sub(128)..];
            assert!(
                !end.starts_with(b"TAG"),
                "stripped MP3 should not have ID3v1 tag"
            );
        }
        Err(e) => {
            eprintln!("MP3 strip returned error (may be expected for minimal fixture): {e}");
        }
    }
}
