//! Structural PDF sanitization. Rewriting objects rebuilds xref offsets and
//! discards incremental history, unreachable objects, and compressed XMP.

use crate::SanitizeError;
use lopdf::{Dictionary, Document, Object, StringFormat};

const INFO_KEYS: &[&[u8]] = &[
    b"Author",
    b"Creator",
    b"Producer",
    b"Title",
    b"Subject",
    b"Keywords",
    b"CreationDate",
    b"ModDate",
];

fn error(error: impl std::fmt::Display) -> SanitizeError {
    SanitizeError::InvalidFormat(format!("PDF: {error}"))
}

fn load(data: &[u8]) -> Result<Document, SanitizeError> {
    let doc = Document::load_mem(data).map_err(error)?;
    if doc.is_encrypted() {
        return Err(error("encrypted documents cannot be sanitized"));
    }
    doc.catalog().map_err(error)?;
    Ok(doc)
}

fn clean_object(
    object: &mut Object,
    fields: &mut Vec<String>,
    depth: usize,
) -> Result<(), SanitizeError> {
    if depth > 128 {
        return Err(error("object nesting exceeds 128"));
    }
    match object {
        Object::Stream(stream)
            if stream.dict.get(b"Type").and_then(Object::as_name).ok() == Some(b"Metadata") =>
        {
            *object = Object::Null;
            fields.push("PDF:XMP".into());
        }
        Object::Stream(stream) => clean_dictionary(&mut stream.dict, fields, depth + 1)?,
        Object::Dictionary(dict) => clean_dictionary(dict, fields, depth + 1)?,
        Object::Array(items) => {
            for item in items {
                clean_object(item, fields, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn clean_dictionary(
    dict: &mut Dictionary,
    fields: &mut Vec<String>,
    depth: usize,
) -> Result<(), SanitizeError> {
    if dict.remove(b"Metadata").is_some() {
        fields.push("PDF:XMP".into());
    }
    for (_, value) in dict.iter_mut() {
        clean_object(value, fields, depth)?;
    }
    Ok(())
}

pub(crate) fn strip(data: &[u8]) -> Result<(Vec<u8>, Vec<String>), SanitizeError> {
    let mut doc = load(data)?;
    let mut fields = Vec::new();
    if let Ok(info) = doc.trailer.get(b"Info") {
        let (original_id, info) = doc.dereference(info).map_err(error)?;
        let info = info.as_dict().map_err(error)?;
        let mut clean_info = Dictionary::new();
        for (key, value) in info.iter() {
            if INFO_KEYS.contains(&key.as_slice()) {
                clean_info.set(
                    key.clone(),
                    Object::String(Vec::new(), StringFormat::Literal),
                );
            }
            let (_, value) = doc.dereference(value).map_err(error)?;
            if !matches!(value, Object::String(bytes, _) if bytes.is_empty()) {
                fields.push(format!("PDF:{}", String::from_utf8_lossy(key)));
            }
        }
        // A fresh Info object disconnects all original indirect values. They
        // are pruned before writing, rather than merely hidden from readers.
        let id = if let Some(id) = original_id {
            doc.objects.insert(id, Object::Dictionary(clean_info));
            id
        } else {
            doc.add_object(clean_info)
        };
        doc.trailer.set("Info", id);
    }
    for object in doc.objects.values_mut() {
        clean_object(object, &mut fields, 0)?;
    }
    for key in [
        b"Prev".as_slice(),
        b"XRefStm",
        b"ID",
        b"Type",
        b"W",
        b"Index",
        b"Length",
        b"Filter",
        b"DecodeParms",
    ] {
        doc.trailer.remove(key);
    }
    doc.prune_objects();
    doc.max_id = doc.objects.keys().map(|id| id.0).max().unwrap_or(0);
    doc.reference_table.cross_reference_type = lopdf::xref::XrefType::CrossReferenceTable;
    let mut output = Vec::new();
    doc.save_to(&mut output).map_err(error)?;
    Ok((output, fields))
}

pub(crate) fn verify(data: &[u8]) -> Result<Vec<String>, SanitizeError> {
    let doc = load(data)?;
    let mut findings = Vec::new();
    if let Ok(info) = doc.trailer.get(b"Info") {
        let (_, info) = doc.dereference(info).map_err(error)?;
        for (key, value) in info.as_dict().map_err(error)?.iter() {
            let (_, value) = doc.dereference(value).map_err(error)?;
            if !INFO_KEYS.contains(&key.as_slice())
                || !matches!(value, Object::String(bytes, _) if bytes.is_empty())
            {
                findings.push(format!(
                    "residual PDF Info {}",
                    String::from_utf8_lossy(key)
                ));
            }
        }
    }
    for object in doc.objects.values() {
        // Walk parsed dictionaries, including stream dictionaries; compressed
        // metadata is recognized by structure without scanning compressed bytes.
        let mut clone = object.clone();
        clean_object(&mut clone, &mut findings, 0)?;
    }
    Ok(findings)
}

#[cfg(test)]
pub(crate) fn fixture(info: Dictionary) -> Vec<u8> {
    let mut doc = Document::with_version("1.4");
    let pages = doc.add_object(
        lopdf::dictionary! {"Type" => "Pages", "Kids" => Object::Array(vec![]), "Count" => 0},
    );
    let root = doc.add_object(lopdf::dictionary! {"Type" => "Catalog", "Pages" => pages});
    let info = doc.add_object(info);
    doc.trailer.set("Root", root);
    doc.trailer.set("Info", info);
    let mut data = Vec::new();
    doc.save_to(&mut data).unwrap();
    data
}

#[test]
fn deeply_nested_pdf_objects_are_refused_without_aborting() {
    // RUSTSEC-2026-0187: build the input as bytes so constructing or dropping
    // the fixture does not itself recurse through thousands of Rust objects.
    let mut data = b"%PDF-1.4\n".to_vec();
    let catalog = data.len();
    data.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R /X ");
    data.resize(data.len() + 10_380, b'[');
    data.push(b'0');
    data.resize(data.len() + 10_380, b']');
    data.extend_from_slice(b" >>\nendobj\n");
    let pages = data.len();
    data.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n");
    let xref = data.len();
    data.extend_from_slice(
        format!(
            "xref\n0 3\n0000000000 65535 f \n{catalog:010} 00000 n \n{pages:010} 00000 n \ntrailer\n<< /Root 1 0 R /Size 3 >>\nstartxref\n{xref}\n%%EOF\n"
        )
        .as_bytes(),
    );
    assert!(strip(&data).is_err());
    assert!(verify(&data).is_err());
}
