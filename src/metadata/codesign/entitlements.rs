use crate::metadata::codesign::types::{
    BlobType, CSMAGIC_ENTITLEMENTS, CSMAGIC_ENTITLEMENTS_DER, SignatureBlob,
};

/// Extract XML entitlements from the signature blobs.
pub fn extract_entitlements_xml<'data>(blobs: &[SignatureBlob<'data>]) -> Option<&'data str> {
    for blob in blobs {
        if blob.blob_type == BlobType::Entitlements && blob.magic == CSMAGIC_ENTITLEMENTS {
            // Entitlements blob: 8-byte header (magic + length) + XML data
            if blob.data.len() > 8 {
                let xml_data = &blob.data[8..];
                return std::str::from_utf8(xml_data).ok();
            }
        }
    }
    None
}

/// Extract DER-encoded entitlements from the signature blobs.
pub fn extract_entitlements_der<'data>(blobs: &[SignatureBlob<'data>]) -> Option<&'data [u8]> {
    for blob in blobs {
        if blob.blob_type == BlobType::DerEntitlements
            && blob.magic == CSMAGIC_ENTITLEMENTS_DER
            && blob.data.len() > 8
        {
            return Some(&blob.data[8..]);
        }
    }
    None
}
