pub mod codedir;
pub mod entitlements;
pub mod superblob;
pub mod types;

pub use types::{BlobType, CodeDirectory, HashType, SignatureBlob};

use crate::addr::ThinFileOffset;
use crate::error::{Error, Result};
use crate::ext::MachExt;
use crate::model::load_command::LoadCommand;
use crate::model::mach::MachFile;

/// Parsed code signature from LC_CODE_SIGNATURE.
#[derive(Debug)]
pub struct CodeSignature<'data> {
    blobs: Vec<SignatureBlob<'data>>,
    code_directories: Vec<CodeDirectory<'data>>,
    entitlements_xml: Option<&'data str>,
    entitlements_der: Option<&'data [u8]>,
}

impl<'data> MachExt<'data> for CodeSignature<'data> {
    fn parse<'mf>(mach: &'mf MachFile<'data>) -> Result<Self>
    where
        'data: 'mf,
    {
        parse_code_signature(mach)
    }
}

pub fn parse_code_signature<'data>(mach: &MachFile<'data>) -> Result<CodeSignature<'data>> {
    let linkedit = mach
        .find_load_command(|lc| matches!(lc, LoadCommand::CodeSignature(_)))
        .and_then(|lc| lc.kind.as_linkedit_data())
        .ok_or_else(|| Error::Format("no LC_CODE_SIGNATURE".into()))?;

    let sig_data = mach.read_bytes_at(
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
    pub fn blobs(&self) -> &[SignatureBlob<'data>] {
        &self.blobs
    }

    pub fn code_directories(&self) -> &[CodeDirectory<'data>] {
        &self.code_directories
    }

    pub fn entitlements_xml(&self) -> Option<&'data str> {
        self.entitlements_xml
    }

    pub fn entitlements_der(&self) -> Option<&'data [u8]> {
        self.entitlements_der
    }

    pub fn identifier(&self) -> Option<&'data str> {
        self.code_directories.first().and_then(|cd| cd.identifier)
    }

    pub fn team_id(&self) -> Option<&'data str> {
        self.code_directories.first().and_then(|cd| cd.team_id)
    }

    pub fn cms_signature_present(&self) -> bool {
        self.blobs
            .iter()
            .any(|b| b.blob_type == BlobType::Signature)
    }
}
