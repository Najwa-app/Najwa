use najwa_core::filetransfer::{
    reassemble_file, FileChunk, FileTransferManager, FileTransferSession, TransferState,
    MAX_CHUNK_SIZE,
};
use najwa_protocol::message::file_transfer::{FileChunkWire, FileMetadata};
use najwa_sanitize::zip::{write_zip_stored, ZipEntry};
use najwa_sanitize::{sanitize_file, FileType, SanitizationSettings};
use sha2::{Digest, Sha256};
use std::io::Write;

#[test]
fn nack_control_uses_exactly_one_subtype_byte() {
    use najwa_protocol::message::{file_transfer::FileChunkNack, ControlMessage};
    let nack = FileChunkNack {
        session_id: [0x21; 16],
        missing_indices: vec![1, 3],
    };
    let wire = nack.to_bytes().unwrap();
    assert_eq!(nack.to_control_message().unwrap().to_bytes(), wire);
    assert!(ControlMessage::from_bytes(&wire).is_ok());
}

#[test]
fn nack_wire_parser_rejects_unsorted_indices() {
    use najwa_protocol::message::file_transfer::FileChunkNack;
    let mut wire = vec![0x3c];
    wire.extend_from_slice(&[0x21; 16]);
    wire.extend_from_slice(&2u16.to_be_bytes());
    wire.extend_from_slice(&3u32.to_be_bytes());
    wire.extend_from_slice(&1u32.to_be_bytes());
    assert!(FileChunkNack::from_bytes(&wire).is_err());
}

fn clean(data: &[u8]) -> Vec<u8> {
    sanitize_file(data, &SanitizationSettings::default())
        .unwrap()
        .sanitized_bytes
}

fn wav(size: usize) -> Vec<u8> {
    let mut out = b"RIFF".to_vec();
    out.extend_from_slice(&((36 + size) as u32).to_le_bytes());
    out.extend_from_slice(b"WAVEfmt ");
    out.extend_from_slice(&16u32.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes()); // PCM
    out.extend_from_slice(&1u16.to_le_bytes()); // mono
    out.extend_from_slice(&8000u32.to_le_bytes());
    out.extend_from_slice(&8000u32.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&8u16.to_le_bytes());
    out.extend_from_slice(b"data");
    out.extend_from_slice(&(size as u32).to_le_bytes());
    out.resize(44 + size, 128);
    out
}

fn session(data: &[u8]) -> FileTransferSession {
    FileTransferSession {
        transfer_id: [1; 16],
        file_name: "test.wav".into(),
        file_type: FileType::Wav,
        total_size: data.len() as u64,
        total_chunks: data.len().div_ceil(MAX_CHUNK_SIZE) as u32,
        chunk_size: MAX_CHUNK_SIZE,
        sha256_hash: Sha256::digest(data).into(),
    }
}

#[test]
fn manager_metadata_is_accepted_by_wire_codec() {
    let manager = FileTransferManager::new();
    let s = manager.start_send(&wav(100_000), "audio.wav").unwrap();
    let meta = FileMetadata {
        session_id: s.transfer_id,
        filename: s.file_name,
        total_size: s.total_size,
        mime_type: "audio/wav".into(),
        chunk_count: s.total_chunks,
        sha256_hash: s.sha256_hash,
    };
    assert!(
        FileMetadata::from_bytes(&meta.to_bytes()).is_ok(),
        "manager metadata rejected by codec"
    );
}

#[test]
fn manager_chunk_is_accepted_by_wire_codec() {
    let manager = FileTransferManager::new();
    let s = manager.start_send(&wav(100_000), "audio.wav").unwrap();
    let c = manager.next_chunk(&s.transfer_id).unwrap();
    let wire = FileChunkWire {
        session_id: c.transfer_id,
        index: c.chunk_index,
        data: c.data,
    };
    assert!(
        FileChunkWire::from_bytes(&wire.to_bytes()).is_ok(),
        "manager chunk rejected by codec"
    );
}

#[test]
fn paused_send_yields_no_more_chunks() {
    let manager = FileTransferManager::new();
    let s = manager.start_send(&wav(100), "audio.wav").unwrap();
    manager.pause_send(&s.transfer_id);
    assert!(manager.next_chunk(&s.transfer_id).is_none());
}

#[test]
fn cancelled_send_yields_no_more_chunks() {
    let manager = FileTransferManager::new();
    let s = manager.start_send(&wav(100), "audio.wav").unwrap();
    manager.cancel_send(&s.transfer_id);
    assert!(manager.next_chunk(&s.transfer_id).is_none());
}

#[test]
fn chunk_conflict_permanently_fails_receive() {
    let manager = FileTransferManager::new();
    let data = wav(100);
    let s = session(&data);
    manager.start_receive(s.clone()).unwrap();
    manager
        .add_chunk(FileChunk {
            transfer_id: s.transfer_id,
            chunk_index: 0,
            data: data.clone(),
        })
        .unwrap();
    let mut bad = data;
    bad[0] ^= 1;
    assert!(manager
        .add_chunk(FileChunk {
            transfer_id: s.transfer_id,
            chunk_index: 0,
            data: bad
        })
        .is_err());
    assert_eq!(
        manager.receive_progress(&s.transfer_id).unwrap().state,
        TransferState::Failed
    );
    assert!(manager.complete_receive(&s.transfer_id).is_err());
}

#[test]
fn progress_stops_at_real_byte_and_chunk_totals() {
    let manager = FileTransferManager::new();
    let s = manager.start_send(&wav(100), "audio.wav").unwrap();
    while manager.next_chunk(&s.transfer_id).is_some() {}
    let p = manager.send_progress(&s.transfer_id).unwrap();
    assert_eq!(p.chunks_transferred, s.total_chunks);
    assert_eq!(p.bytes_transferred, s.total_size);
}

#[test]
fn reassembly_rejects_declared_size_mismatch() {
    let data = wav(100);
    let mut s = session(&data);
    s.total_size += 1;
    let chunk = FileChunk {
        transfer_id: s.transfer_id,
        chunk_index: 0,
        data,
    };
    assert!(reassemble_file(&s, &[chunk]).is_err());
}

fn pdf(objects: &[Vec<u8>]) -> Vec<u8> {
    let mut out = b"%PDF-1.4\n".to_vec();
    let mut offsets = Vec::new();
    for (i, body) in objects.iter().enumerate() {
        offsets.push(out.len());
        writeln!(&mut out, "{} 0 obj", i + 1).unwrap();
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendobj\n");
    }
    let xref = out.len();
    write!(
        &mut out,
        "xref\n0 {}\n0000000000 65535 f \n",
        objects.len() + 1
    )
    .unwrap();
    for offset in offsets {
        writeln!(&mut out, "{offset:010} 00000 n ").unwrap();
    }
    write!(
        &mut out,
        "trailer\n<< /Size {} /Root 1 0 R /Info 3 0 R >>\nstartxref\n{xref}\n%%EOF\n",
        objects.len() + 1
    )
    .unwrap();
    out
}

fn pdf_with_info(info: &[u8]) -> Vec<u8> {
    pdf(&[
        b"<< /Type /Catalog /Pages 2 0 R >>".to_vec(),
        b"<< /Type /Pages /Kids [] /Count 0 >>".to_vec(),
        info.to_vec(),
    ])
}

#[test]
fn pdf_escaped_author_is_removed_or_refused() {
    let input = pdf_with_info(b"<< /Au#74hor (Alice Private) >>");
    if let Ok(result) = sanitize_file(&input, &SanitizationSettings::default()) {
        assert!(!result
            .sanitized_bytes
            .windows(13)
            .any(|s| s == b"Alice Private"));
    }
}

#[test]
fn pdf_xmp_is_removed_or_refused_when_compressed() {
    let xml = b"<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><rdf:Description xmlns:dc=\"http://purl.org/dc/elements/1.1/\" dc:creator=\"Alice Private\"/></rdf:RDF></x:xmpmeta>";
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(xml).unwrap();
    let compressed = encoder.finish().unwrap();
    let mut stream = format!(
        "<< /Type /Metadata /Subtype /XML /Filter /FlateDecode /Length {} >>\nstream\n",
        compressed.len()
    )
    .into_bytes();
    stream.extend_from_slice(&compressed);
    stream.extend_from_slice(b"\nendstream");
    let input = pdf(&[
        b"<< /Type /Catalog /Pages 2 0 R /Metadata 4 0 R >>".to_vec(),
        b"<< /Type /Pages /Kids [] /Count 0 >>".to_vec(),
        b"<< >>".to_vec(),
        stream,
    ]);
    if let Ok(result) = sanitize_file(&input, &SanitizationSettings::default()) {
        assert!(!result
            .sanitized_bytes
            .windows(compressed.len())
            .any(|s| s == compressed));
    }
}

#[test]
fn pdf_xref_offsets_survive_sanitization() {
    let out = clean(&pdf_with_info(b"<< /Author (Alice Private) >>"));
    let marker = out.windows(10).position(|w| w == b"startxref\n").unwrap();
    let declared: usize = std::str::from_utf8(&out[marker + 10..])
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(
        declared,
        out.windows(5).position(|w| w == b"xref\n").unwrap()
    );
}

fn entry(name: &str, data: &[u8]) -> ZipEntry {
    ZipEntry {
        name: name.into(),
        data: data.to_vec(),
        method: 0,
        dos_time: 0,
        dos_date: 0,
        extra_len: 0,
    }
}

#[test]
fn docx_newline_before_attribute_does_not_leak_author() {
    let xml = b"<cp:coreProperties xmlns:cp=\"http://schemas.openxmlformats.org/package/2006/metadata/core-properties\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\"><dc:creator\n xml:lang=\"en\">Alice Private</dc:creator></cp:coreProperties>";
    let zip = write_zip_stored(&[
        entry("[Content_Types].xml", b"<Types/>"),
        entry("docProps/core.xml", xml),
    ]);
    if let Ok(result) = sanitize_file(&zip, &SanitizationSettings::default()) {
        assert!(!result
            .sanitized_bytes
            .windows(13)
            .any(|s| s == b"Alice Private"));
    }
}

fn atom(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut out = ((data.len() + 8) as u32).to_be_bytes().to_vec();
    out.extend_from_slice(kind);
    out.extend_from_slice(data);
    out
}

#[test]
fn video_creation_and_modification_dates_are_zeroed() {
    let mut mvhd = vec![0; 100];
    mvhd[4..8].copy_from_slice(&3_900_000_000u32.to_be_bytes());
    mvhd[8..12].copy_from_slice(&3_900_000_100u32.to_be_bytes());
    let mut input = atom(b"ftyp", b"isom\0\0\0\0");
    input.extend(atom(b"moov", &atom(b"mvhd", &mvhd)));
    let out = clean(&input);
    let pos = out.windows(4).position(|x| x == b"mvhd").unwrap();
    assert_eq!(&out[pos + 8..pos + 16], &[0; 8]);
}

#[test]
fn video_offsets_account_for_top_level_metadata_removal() {
    let mut stco = vec![0; 4];
    stco.extend_from_slice(&1u32.to_be_bytes());
    stco.extend_from_slice(&0u32.to_be_bytes());
    let moov = atom(
        b"moov",
        &atom(
            b"trak",
            &atom(
                b"mdia",
                &atom(b"minf", &atom(b"stbl", &atom(b"stco", &stco))),
            ),
        ),
    );
    let mut input = atom(b"ftyp", b"isom\0\0\0\0");
    input.extend(atom(b"uuid", &[42; 16]));
    input.extend(moov);
    let mdat_payload_offset = input.len() as u32 + 8;
    input.extend(atom(b"mdat", &[100; 16]));
    let p = input.windows(4).position(|x| x == b"stco").unwrap();
    input[p + 12..p + 16].copy_from_slice(&mdat_payload_offset.to_be_bytes());
    let out = clean(&input);
    let p = out.windows(4).position(|x| x == b"stco").unwrap();
    let pointer = u32::from_be_bytes(out[p + 12..p + 16].try_into().unwrap()) as usize;
    let actual = out.windows(4).position(|x| x == b"mdat").unwrap() + 4;
    assert_eq!(pointer, actual);
}

#[test]
fn malformed_extended_atom_is_refused_without_hanging() {
    let mut video = atom(b"ftyp", b"isom\0\0\0\0");
    video.extend_from_slice(&1u32.to_be_bytes());
    video.extend_from_slice(b"free");
    video.extend_from_slice(&0u64.to_be_bytes());
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(sanitize_file(&video, &SanitizationSettings::default()));
    });
    assert!(rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .expect("sanitizer hung")
        .is_err());
}

#[test]
fn metadata_xml_aliases_cdata_and_invalid_encodings_are_handled() {
    for xml in [
        b"<root xmlns:alias=\"http://purl.org/dc/elements/1.1/\"><alias:creator><![CDATA[Alice Private]]></alias:creator></root>".as_slice(),
        b"<root><dc:creator attribute=\">\">Alice Private</dc:creator></root>",
    ] {
        let zip = write_zip_stored(&[entry("[Content_Types].xml", b"<Types/>"), entry("docProps/core.xml", xml)]);
        let out = clean(&zip);
        assert!(!out.windows(13).any(|w| w == b"Alice Private"));
    }
    for xml in [
        b"<root><dc:creator>Unclosed".as_slice(),
        b"<!DOCTYPE root [<!ENTITY author 'Alice'>]><root/>",
        b"\xff\xfe<\0r\0o\0o\0t\0/\0>\0",
    ] {
        let zip = write_zip_stored(&[
            entry("[Content_Types].xml", b"<Types/>"),
            entry("docProps/core.xml", xml),
        ]);
        assert!(sanitize_file(&zip, &SanitizationSettings::default()).is_err());
    }
}
