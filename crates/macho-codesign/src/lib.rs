#![deny(missing_docs)]
//! Code-directory, superblob, entitlement, and signature parsing.

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

    Ok(CodeSignature {
        blobs,
        code_directories,
        entitlements_xml,
        entitlements_der,
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

    /// Performs identifier.
    pub fn identifier(&self) -> Option<&'data str> {
        self.code_directories.first().and_then(|cd| cd.identifier)
    }

    /// Performs team_id.
    pub fn team_id(&self) -> Option<&'data str> {
        self.code_directories.first().and_then(|cd| cd.team_id)
    }

    /// Performs cms_signature_present.
    pub fn cms_signature_present(&self) -> bool {
        self.blobs
            .iter()
            .any(|b| b.blob_type == BlobType::Signature)
    }
}
