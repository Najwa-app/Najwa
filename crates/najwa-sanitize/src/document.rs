//! PDF/DOCX author and metadata stripping (S11 §7.4–7.6).
//!
//! Strips identifying metadata from document files:
//! - PDF: /Author, /Creator, /Producer, /Title, /Subject, /Keywords, /CreationDate, /ModDate
//! - DOCX: core.xml properties (author, lastModifiedBy, revision)
//! - ODT: meta.xml properties

use crate::SanitizeError;

// ---------------------------------------------------------------------------
// PDF metadata stripping
// ---------------------------------------------------------------------------

/// Strip parsed Info entries and all XMP streams, then rebuild the PDF.
pub fn strip_pdf_metadata(data: &[u8]) -> Result<(Vec<u8>, Vec<String>), SanitizeError> {
    crate::pdf::strip(data)
}

// ---------------------------------------------------------------------------
// DOCX / ODT metadata stripping (S11 §7.5–7.6 + §5.4 deterministic ZIP rewrite)
// ---------------------------------------------------------------------------

/// Normative DOCX metadata tags (S11 §7.5) — contents emptied in
/// `docProps/core.xml` and `docProps/app.xml`. Closed list per S11 §5.4.
pub(crate) const DOCX_METADATA_TAGS: &[&str] = &[
    "dc:creator",
    "dc:title",
    "dc:subject",
    "dc:description",
    "cp:lastModifiedBy",
    "cp:revision",
    "dcterms:created",
    "dcterms:modified",
];

/// DOCX archive members scanned for metadata (S11 §7.5).
pub(crate) const DOCX_METADATA_FILES: &[&str] = &["docProps/core.xml", "docProps/app.xml"];

/// Normative ODT metadata tags (S11 §7.6) — contents emptied in `meta.xml`.
pub(crate) const ODT_METADATA_TAGS: &[&str] = &[
    "meta:initial-creator",
    "dc:creator",
    "meta:creation-date",
    "dc:date",
    "meta:editing-cycles",
    "meta:editing-duration",
    "meta:generator",
];

/// ODT archive members scanned for metadata (S11 §7.6).
pub(crate) const ODT_METADATA_FILES: &[&str] = &["meta.xml"];

/// Empty the target metadata element using XML events, refusing unparseable XML.
pub(crate) fn empty_xml_tag_contents(
    xml: &[u8],
    tag: &str,
) -> Result<(Vec<u8>, bool), SanitizeError> {
    crate::xml::empty_tag(xml, tag)
}

/// Shared DOCX/ODT implementation: parse the ZIP, empty the normative metadata
/// tags in the target XML members, and rewrite the archive deterministically
/// (stored entries, original order, zeroed timestamps, no extra fields —
/// S11 §5.4). The rewrite happens unconditionally: even a document with no
/// matching tags carries entry mtimes, which are metadata and must not survive.
fn strip_zip_document(
    data: &[u8],
    target_files: &[&str],
    tags: &[&str],
    label: &str,
) -> Result<(Vec<u8>, Vec<String>), SanitizeError> {
    let mut entries = crate::zip::parse_zip(data)?;
    let mut removed = Vec::new();

    for entry in entries.iter_mut() {
        if !target_files.contains(&entry.name.as_str()) {
            continue;
        }
        for tag in tags {
            let (rewritten, changed) = empty_xml_tag_contents(&entry.data, tag)?;
            if changed {
                removed.push(format!("{label}:{tag}"));
            }
            entry.data = rewritten;
        }
    }

    Ok((crate::zip::write_zip_stored(&entries), removed))
}

/// Strip metadata from a DOCX file (S11 §7.5).
///
/// Empties the normative metadata tag contents in `docProps/core.xml` and
/// `docProps/app.xml`, then rewrites the ZIP deterministically per S11 §5.4
/// (closing the entry-mtime leak).
pub fn strip_docx_metadata(data: &[u8]) -> Result<(Vec<u8>, Vec<String>), SanitizeError> {
    strip_zip_document(data, DOCX_METADATA_FILES, DOCX_METADATA_TAGS, "DOCX")
}

/// Strip metadata from an ODT file (S11 §7.6).
///
/// Empties the normative metadata tag contents in `meta.xml`, then rewrites
/// the ZIP deterministically per S11 §5.4. All entries are rewritten *stored*, in
/// original order — which also keeps the ODF `mimetype`-first-and-uncompressed
/// convention intact.
pub fn strip_odt_metadata(data: &[u8]) -> Result<(Vec<u8>, Vec<String>), SanitizeError> {
    strip_zip_document(data, ODT_METADATA_FILES, ODT_METADATA_TAGS, "ODT")
}

/// Strip document metadata, dispatching by file type (S11 §7.4–7.6).
pub fn strip_document_metadata(
    data: &[u8],
    file_type: &crate::detect::FileType,
) -> Result<(Vec<u8>, Vec<String>), SanitizeError> {
    match file_type {
        crate::detect::FileType::Pdf => strip_pdf_metadata(data),
        crate::detect::FileType::Docx => strip_docx_metadata(data),
        crate::detect::FileType::Odt => strip_odt_metadata(data),
        _ => Ok((data.to_vec(), vec![])),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pdf_strips_author() {
        let pdf = crate::pdf::fixture(lopdf::dictionary! {
            "Author" => lopdf::Object::string_literal("John Doe"),
            "Creator" => lopdf::Object::string_literal("TestApp"),
            "Producer" => lopdf::Object::string_literal("LibPDF")
        });
        let (stripped, removed) = strip_pdf_metadata(&pdf).unwrap();
        for key in ["Author", "Creator", "Producer"] {
            assert!(removed.iter().any(|field| field.ends_with(key)));
        }
        let doc = lopdf::Document::load_mem(&stripped).unwrap();
        let (_, info) = doc.dereference(doc.trailer.get(b"Info").unwrap()).unwrap();
        assert_eq!(
            info.as_dict()
                .unwrap()
                .get(b"Author")
                .unwrap()
                .as_str()
                .unwrap(),
            b""
        );
        assert!(!stripped.windows(8).any(|w| w == b"John Doe"));
    }

    #[test]
    fn pdf_preserves_structure() {
        let pdf = crate::pdf::fixture(lopdf::Dictionary::new());
        let (stripped, removed) = strip_pdf_metadata(&pdf).unwrap();
        assert!(removed.is_empty());
        lopdf::Document::load_mem(&stripped)
            .unwrap()
            .catalog()
            .unwrap();
        assert_eq!(stripped, strip_pdf_metadata(&stripped).unwrap().0);
    }

    #[test]
    fn pdf_invalid_returns_error() {
        let result = strip_pdf_metadata(b"not a pdf");
        assert!(result.is_err());
    }

    #[test]
    fn pdf_strips_hex_string_values() {
        let pdf = crate::pdf::fixture(lopdf::dictionary! {
            "Author" => lopdf::Object::String(b"John".to_vec(), lopdf::StringFormat::Hexadecimal),
            "Title" => lopdf::Object::string_literal("Test")
        });
        let (_, removed) = strip_pdf_metadata(&pdf).unwrap();
        assert!(removed.iter().any(|r| r.contains("Author")));
        assert!(removed.iter().any(|r| r.contains("Title")));
    }

    #[test]
    fn docx_strips_and_rewrites_deterministically() {
        // A realistic DOCX shape: deflated entries, nonzero mtimes, extra fields.
        let core = b"<cp:coreProperties><dc:creator>John Doe</dc:creator>\
            <cp:lastModifiedBy>Jane</cp:lastModifiedBy>\
            <dcterms:created xsi:type=\"dcterms:W3CDTF\">2024-01-01T00:00:00Z</dcterms:created>\
            <dc:title>Secret Plan</dc:title></cp:coreProperties>";
        let doc = b"<w:document><w:body>hello</w:body></w:document>";
        let zip = crate::zip::build_dirty_zip(&[
            ("[Content_Types].xml", b"<Types/>"),
            ("docProps/core.xml", core),
            ("word/document.xml", doc),
        ]);

        let (out, removed) = strip_docx_metadata(&zip).unwrap();
        assert!(removed.iter().any(|r| r == "DOCX:dc:creator"));
        assert!(removed.iter().any(|r| r == "DOCX:cp:lastModifiedBy"));
        assert!(removed.iter().any(|r| r == "DOCX:dcterms:created"));
        assert!(removed.iter().any(|r| r == "DOCX:dc:title"));

        // Content survives; metadata content is gone; tags remain (empty).
        let entries = crate::zip::parse_zip(&out).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].name, "[Content_Types].xml"); // order preserved
        fn contains(hay: &[u8], needle: &[u8]) -> bool {
            hay.windows(needle.len()).any(|w| w == needle)
        }
        let core_out = &entries[1];
        assert!(!contains(&core_out.data, b"John Doe"));
        assert!(!contains(&core_out.data, b"Secret Plan"));
        // Tags remain, now empty; attributed tags keep their attributes.
        assert!(contains(&core_out.data, b"<dc:creator></dc:creator>"));
        assert!(contains(
            &core_out.data,
            b"<dcterms:created xsi:type=\"dcterms:W3CDTF\"></dcterms:created>"
        ));
        assert_eq!(entries[2].data.as_slice(), doc.as_slice());

        // S11 §5.4 invariants on every entry.
        for e in &entries {
            assert_eq!(e.method, 0);
            assert_eq!(e.dos_time, 0);
            assert_eq!(e.dos_date, 0);
            assert_eq!(e.extra_len, 0);
        }

        // Deterministic + idempotent (fixed point, S18 §17).
        let (out2, _) = strip_docx_metadata(&zip).unwrap();
        assert_eq!(out, out2);
        let (out3, removed3) = strip_docx_metadata(&out).unwrap();
        assert_eq!(out, out3, "stripping a stripped file is a fixed point");
        assert!(removed3.is_empty(), "no residual findings on second pass");
    }

    #[test]
    fn odt_strips_meta_xml_and_keeps_mimetype_first() {
        let meta = b"<office:meta><meta:initial-creator>Bob</meta:initial-creator>\
            <meta:generator>LibreOffice/7.6</meta:generator>\
            <meta:editing-cycles>42</meta:editing-cycles>\
            <dc:date>2024-06-01T10:00:00</dc:date></office:meta>";
        let zip = crate::zip::build_dirty_zip(&[
            ("mimetype", b"application/vnd.oasis.opendocument.text"),
            ("meta.xml", meta),
            ("content.xml", b"<office:text>hi</office:text>"),
        ]);

        let (out, removed) = strip_odt_metadata(&zip).unwrap();
        assert!(removed.iter().any(|r| r == "ODT:meta:initial-creator"));
        assert!(removed.iter().any(|r| r == "ODT:meta:generator"));
        assert!(removed.iter().any(|r| r == "ODT:meta:editing-cycles"));
        assert!(removed.iter().any(|r| r == "ODT:dc:date"));

        let entries = crate::zip::parse_zip(&out).unwrap();
        // ODF convention preserved: mimetype first, stored.
        assert_eq!(entries[0].name, "mimetype");
        assert_eq!(entries[0].method, 0);
        let meta_out = &entries[1];
        assert!(!meta_out.data.windows(3).any(|w| w == b"Bob"));
        assert!(!meta_out.data.windows(11).any(|w| w == b"LibreOffice"));
        assert_eq!(entries[2].data.as_slice(), b"<office:text>hi</office:text>");
        for e in &entries {
            assert_eq!(e.dos_time, 0);
            assert_eq!(e.dos_date, 0);
        }
    }

    #[test]
    fn empty_xml_tag_contents_handles_variants() {
        // Plain, attributed, self-closing, and repeated occurrences.
        let xml = b"<a><dc:creator>X</dc:creator><dc:creator/>\
            <dc:creator id=\"1\">Y</dc:creator><dc:creatorx>Z</dc:creatorx></a>";
        let (out, changed) = empty_xml_tag_contents(xml, "dc:creator").unwrap();
        assert!(changed);
        let s = String::from_utf8(out).unwrap();
        assert_eq!(
            s,
            "<a><dc:creator></dc:creator><dc:creator/>\
             <dc:creator id=\"1\"></dc:creator><dc:creatorx>Z</dc:creatorx></a>"
        );
        // Already-empty content → unchanged.
        let (out2, changed2) = empty_xml_tag_contents(s.as_bytes(), "dc:creator").unwrap();
        assert!(!changed2);
        assert_eq!(out2, s.as_bytes());
    }

    #[test]
    fn pdf_strips_xmp_packet_preserving_length() {
        let base = crate::pdf::fixture(lopdf::Dictionary::new());
        let mut doc = lopdf::Document::load_mem(&base).unwrap();
        let xmp = b"<x:xmpmeta><rdf:Description dc:creator=\"Alice\"/></x:xmpmeta>";
        let stream = lopdf::Stream::new(
            lopdf::dictionary! {"Type" => "Metadata", "Subtype" => "XML"},
            xmp.to_vec(),
        );
        let metadata = doc.add_object(stream);
        doc.catalog_mut().unwrap().set("Metadata", metadata);
        let mut input = Vec::new();
        doc.save_to(&mut input).unwrap();
        let (out, removed) = strip_pdf_metadata(&input).unwrap();
        assert!(removed.iter().any(|r| r.contains("XMP")));
        assert!(!out.windows(5).any(|w| w == b"Alice"));
        // A structural rewrite rebuilds offsets instead of preserving length.
        let parsed = lopdf::Document::load_mem(&out).unwrap();
        assert!(!parsed.catalog().unwrap().has(b"Metadata"));
        assert_eq!(out, strip_pdf_metadata(&out).unwrap().0);
    }
}
