#![deny(missing_docs)]
//! Code-directory, superblob, entitlement, and signature parsing.
//!
//! Depend on this crate directly for signature inspection without the `macho`
//! façade: [`parse_code_signature`] on a [`macho_core::MachoFile`], or
//! [`superblob::parse_super_blob`] on raw blob bytes.

extern crate self as codesign;

pub use macho_core::model;

/// The error module.
pub mod error;
pub(crate) use error::Error;
pub use error::{CodesignError, CodesignErrorKind, Result};

/// The codedir module.
pub mod codedir;
/// The entitlements module.
pub mod entitlements;
/// Code-requirement set parsing.
pub mod requirements;
/// The superblob module.
pub mod superblob;
/// The types module.
pub mod types;

pub use types::{BlobType, CodeDirectory, HashType, SignatureBlob};

use crate::model::addr::ThinFileOffset;
use crate::model::ext::MachoExt;
use crate::model::load_command::LoadCommand;
use crate::model::macho_file::MachoFile;

/// Parsed code signature from LC_CODE_SIGNATURE.
#[derive(Debug)]
pub struct CodeSignature<'data> {
    blobs: Vec<SignatureBlob<'data>>,
    code_directories: Vec<CodeDirectory<'data>>,
    entitlements_xml: Option<&'data str>,
    entitlements_der: Option<&'data [u8]>,
    designated_requirement: Option<&'data [u8]>,
}

impl<'data> MachoExt<'data> for CodeSignature<'data> {
    type Error = CodesignError;

    fn parse<'mf>(macho: &'mf MachoFile<'data>) -> Result<Self>
    where
        'data: 'mf,
    {
        parse_code_signature(macho)
    }
}

/// Performs parse_code_signature.
pub fn parse_code_signature<'data>(macho: &MachoFile<'data>) -> Result<CodeSignature<'data>> {
    let linkedit = macho
        .find_load_command(|lc| matches!(lc, LoadCommand::CodeSignature(_)))
        .and_then(|lc| lc.kind().as_linkedit_data())
        .ok_or_else(|| Error::format("no LC_CODE_SIGNATURE"))?;

    let sig_data = macho.read_bytes_at(
        ThinFileOffset(linkedit.data_offset as u64),
        linkedit.data_size as usize,
    )?;

    let blobs = superblob::parse_super_blob(sig_data)?;

    // Parse CodeDirectories
    let mut code_directories = Vec::new();
    for blob in &blobs {
        match blob.blob_type {
            BlobType::CodeDirectory | BlobType::AlternateCodeDirectory(_) => {
                if let Ok(cd) = codedir::parse_code_directory(blob.data) {
                    code_directories.push(cd);
                }
            }
            _ => {}
        }
    }

    let entitlements_xml = entitlements::extract_entitlements_xml(&blobs);
    let entitlements_der = entitlements::extract_entitlements_der(&blobs);
    let designated_requirement = requirements::extract_designated_requirement(&blobs)?;

    Ok(CodeSignature {
        blobs,
        code_directories,
        entitlements_xml,
        entitlements_der,
        designated_requirement,
    })
}

impl<'data> CodeSignature<'data> {
    /// Performs blobs.
    pub fn blobs(&self) -> &[SignatureBlob<'data>] {
        &self.blobs
    }

    /// Performs code_directories.
    pub fn code_directories(&self) -> &[CodeDirectory<'data>] {
        &self.code_directories
    }

    /// Performs entitlements_xml.
    pub fn entitlements_xml(&self) -> Option<&'data str> {
        self.entitlements_xml
    }

    /// Performs entitlements_der.
    pub fn entitlements_der(&self) -> Option<&'data [u8]> {
        self.entitlements_der
    }

    /// Return the complete canonical designated-requirement blob.
    ///
    /// The returned slice includes the `CSMAGIC_REQUIREMENT` magic and length
    /// header. `None` means the signature has no designated requirement.
    pub fn designated_requirement(&self) -> Option<&'data [u8]> {
        self.designated_requirement
    }

    /// Performs identifier.
    pub fn identifier(&self) -> Option<&'data str> {
        self.code_directories.first().and_then(|cd| cd.identifier)
    }

    /// Performs team_id.
    pub fn team_id(&self) -> Option<&'data str> {
        self.code_directories.first().and_then(|cd| cd.team_id)
    }

    /// Whether the signature contains non-empty CMS payload data.
    ///
    /// Ad-hoc signatures conventionally carry an empty eight-byte BlobWrapper
    /// header. That placeholder is not a cryptographic CMS signature.
    pub fn cms_signature_present(&self) -> bool {
        self.blobs.iter().any(|blob| {
            blob.blob_type == BlobType::Signature
                && blob
                    .data
                    .get(8..)
                    .is_some_and(|payload| !payload.is_empty())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::CSMAGIC_BLOBWRAPPER;

    #[test]
    fn empty_adhoc_blob_wrapper_is_not_cms() {
        let data = [CSMAGIC_BLOBWRAPPER.to_be_bytes(), 8u32.to_be_bytes()].concat();
        let signature = CodeSignature {
            blobs: vec![SignatureBlob {
                blob_type: BlobType::Signature,
                magic: CSMAGIC_BLOBWRAPPER,
                offset: 0,
                size: data.len() as u32,
                data: &data,
            }],
            code_directories: Vec::new(),
            entitlements_xml: None,
            entitlements_der: None,
            designated_requirement: None,
        };

        assert!(!signature.cms_signature_present());
    }
}
