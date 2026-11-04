//! Criterion benchmarks for najwa-sanitize media sanitization.
//!
//! Image benches run the image pipeline: structural conversion to WebP (the
//! retired per-format strippers are gone), the in-place WebP chunk strip, and
//! the full `sanitize_file` path with its post-strip verification.

use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;
use std::io::Cursor;

use image::{DynamicImage, ImageFormat, Rgb, RgbImage};
use najwa_sanitize::audio::{strip_flac_metadata, strip_mp3_metadata};
use najwa_sanitize::convert::convert_to_webp;
use najwa_sanitize::image::strip_webp_metadata;
use najwa_sanitize::video::strip_video_metadata;
use najwa_sanitize::{sanitize_file, SanitizationSettings};

/// Encode a real 64×64 RGB image in the given format (pixel-decodable —
/// required for the conversion benches, which run the actual decoder).
fn real_image(format: ImageFormat) -> Vec<u8> {
    let img = DynamicImage::ImageRgb8(RgbImage::from_pixel(64, 64, Rgb([200, 30, 30])));
    let mut out = Cursor::new(Vec::new());
    img.write_to(&mut out, format).unwrap();
    out.into_inner()
}

fn bench_jpeg_to_webp(c: &mut Criterion) {
    let jpeg = real_image(ImageFormat::Jpeg);
    c.bench_function("convert_jpeg_to_webp", |b| {
        b.iter(|| {
            let _ = convert_to_webp(black_box(&jpeg));
        })
    });
}

fn bench_png_to_webp(c: &mut Criterion) {
    let png = real_image(ImageFormat::Png);
    c.bench_function("convert_png_to_webp", |b| {
        b.iter(|| {
            let _ = convert_to_webp(black_box(&png));
        })
    });
}

fn bench_webp_strip(c: &mut Criterion) {
    let webp = real_image(ImageFormat::WebP);
    c.bench_function("strip_webp_metadata", |b| {
        b.iter(|| {
            let _ = strip_webp_metadata(black_box(&webp));
        })
    });
}

fn bench_sanitize_file_image(c: &mut Criterion) {
    // End to end: detect → convert → verify against the WebP output.
    let jpeg = real_image(ImageFormat::Jpeg);
    c.bench_function("sanitize_file_jpeg", |b| {
        b.iter(|| {
            let _ = sanitize_file(black_box(&jpeg), &SanitizationSettings::default());
        })
    });
}

fn bench_video_strip(c: &mut Criterion) {
    // Minimal MP4: ftyp + moov with udta child
    let mut data = Vec::new();
    // ftyp atom (20 bytes)
    data.extend_from_slice(&20u32.to_be_bytes());
    data.extend_from_slice(b"ftyp");
    data.extend_from_slice(b"isom");
    data.extend_from_slice(&[0u8; 8]);
    // moov atom containing a udta child (to strip)
    let udta_size: u32 = 16;
    let moov_size: u32 = 8 + udta_size;
    data.extend_from_slice(&moov_size.to_be_bytes());
    data.extend_from_slice(b"moov");
    data.extend_from_slice(&udta_size.to_be_bytes());
    data.extend_from_slice(b"udta");
    data.extend_from_slice(&[0u8; 8]); // udta payload

    c.bench_function("strip_video_metadata", |b| {
        b.iter(|| {
            let _ = strip_video_metadata(black_box(&data));
        })
    });
}

fn bench_mp3_strip(c: &mut Criterion) {
    // Minimal MP3 with ID3v2 header + fake audio + ID3v1 tag
    let mut data = Vec::new();
    // ID3v2 header (10 bytes header + 128 bytes payload)
    data.extend_from_slice(b"ID3");
    data.extend_from_slice(&[0x04, 0x00, 0x00]); // version 2.4, no flags
                                                 // Syncsafe size: 128 = 0x00 0x00 0x01 0x00
    data.extend_from_slice(&[0x00, 0x00, 0x01, 0x00]);
    data.extend_from_slice(&[0u8; 128]); // ID3v2 payload
                                         // Fake audio frames
    data.extend_from_slice(&[0xFF; 256]);
    // ID3v1 tag (128 bytes at end)
    data.extend_from_slice(b"TAG");
    data.extend_from_slice(&[0u8; 125]);

    c.bench_function("strip_mp3_metadata", |b| {
        b.iter(|| {
            let _ = strip_mp3_metadata(black_box(&data));
        })
    });
}

fn bench_flac_strip(c: &mut Criterion) {
    // Minimal FLAC: magic + STREAMINFO block + VORBIS_COMMENT block
    let mut data = Vec::new();
    data.extend_from_slice(b"fLaC");
    // STREAMINFO block (type 0, not last, 34 bytes)
    data.push(0x00); // type=0 (STREAMINFO), not last
    data.extend_from_slice(&[0x00, 0x00, 0x22]); // length = 34
    data.extend_from_slice(&[0u8; 34]); // STREAMINFO payload
                                        // VORBIS_COMMENT block (type 4, last)
    data.push(0x84); // type=4 (VORBIS_COMMENT), is last
    let comment = [0u8; 32];
    data.extend_from_slice(&[0x00, 0x00, 0x20]); // length = 32
    data.extend_from_slice(&comment);

    c.bench_function("strip_flac_metadata", |b| {
        b.iter(|| {
            let _ = strip_flac_metadata(black_box(&data));
        })
    });
}

criterion_group!(
    benches,
    bench_jpeg_to_webp,
    bench_png_to_webp,
    bench_webp_strip,
    bench_sanitize_file_image,
    bench_video_strip,
    bench_mp3_strip,
    bench_flac_strip,
);
criterion_main!(benches);
