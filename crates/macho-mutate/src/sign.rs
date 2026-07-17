//! Pure-Rust ad-hoc code signing for Mach-O binaries.
//!
//! After patching a Mach-O binary, its code signature is invalid. On macOS,
//! unsigned binaries may not load. This module programmatically computes an
//! ad-hoc signature (no identity, no notarization) that satisfies the kernel's
//! basic code-integrity checks.
//!
//! # Algorithm
//!
//! 1. Parse the input binary to extract existing identifier and entitlements.
//! 2. Strip the existing `LC_CODE_SIGNATURE` and its data.
//! 3. Compute SHA-256 hashes for each page-sized chunk of the binary.
//! 4. Build a CodeDirectory blob with those hashes.
//! 5. Wrap it in a SuperBlob (with optional entitlements).
//! 6. Append the SuperBlob to `__LINKEDIT` and add `LC_CODE_SIGNATURE`.
//! 7. Rebuild the binary via `MachoEditor`.

use sha2::{Digest, Sha256};

use crate::model::load_command::LoadCommand;
use crate::model::macho_file::MachoFile;
use crate::{MachoEditor, Result};

use crate::format::parse_macho_file;
use macho_codesign::types::{
    CS_HASHTYPE_SHA256, CS_SLOT_CODEDIRECTORY, CS_SLOT_ENTITLEMENTS, CSMAGIC_CODEDIRECTORY,
    CSMAGIC_EMBEDDED_SIGNATURE, CSMAGIC_ENTITLEMENTS,
};

/// Request passed to an injected signing capability.
#[derive(Debug, Clone, Default)]
pub struct SignatureRequest {
    /// Optional signing identity. `None` requests an ad-hoc signature.
    pub identity: Option<String>,
    /// Optional bundle identifier override.
    pub identifier: Option<String>,
    /// Optional entitlements XML.
    pub entitlements_xml: Option<String>,
}

/// Typed host-signing capability failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SignatureProviderError {
    /// The configured signing capability is unavailable.
    #[error("signing capability unavailable: {0}")]
    Unavailable(String),
    /// Signing rejected the candidate bytes.
    #[error("signing failed: {0}")]
    Failed(String),
}

/// Injectable signing provider. Implementations never choose output paths.
pub trait SignatureProvider: Send + Sync {
    /// Return a signed replacement buffer without modifying the input.
    fn sign(
        &self,
        bytes: &[u8],
        request: &SignatureRequest,
    ) -> std::result::Result<Vec<u8>, SignatureProviderError>;
}

/// Pure in-process ad-hoc signing provider.
#[derive(Debug, Default, Clone, Copy)]
pub struct AdhocSignatureProvider;

impl SignatureProvider for AdhocSignatureProvider {
    fn sign(
        &self,
        bytes: &[u8],
        request: &SignatureRequest,
    ) -> std::result::Result<Vec<u8>, SignatureProviderError> {
        adhoc_sign(
            bytes,
            &AdhocSignOptions {
                identifier: request.identifier.clone(),
                entitlements_xml: request.entitlements_xml.clone(),
                preserve_existing: true,
                ..AdhocSignOptions::default()
            },
        )
        .map_err(|error| SignatureProviderError::Failed(error.to_string()))
    }
}

/// Options for ad-hoc signing.
#[derive(Debug, Clone, Default)]
pub struct AdhocSignOptions {
    /// Bundle identifier to embed. If `None` and `preserve_existing` is true,
    /// the existing identifier is reused. Otherwise defaults to a placeholder.
    pub identifier: Option<String>,
    /// XML entitlements to embed. If `None` and `preserve_existing` is true,
    /// existing entitlements are reused.
    pub entitlements_xml: Option<String>,
    /// Page size override. Defaults to 4096 for x86_64 and 16384 for arm64.
    pub page_size: Option<u32>,
    /// Whether to extract identifier and entitlements from the existing
    /// signature before stripping it.
    pub preserve_existing: bool,
}

/// Result of a successful ad-hoc signing operation.
#[derive(Debug, Clone)]
pub struct AdhocSignResult {
    /// The identifier embedded in the signature.
    pub identifier: String,
    /// The code limit (bytes of binary content covered by hashes).
    pub code_limit: u32,
    /// Number of page hashes computed.
    pub page_count: u32,
    /// Total size of the signature SuperBlob.
    pub signature_size: u32,
}

/// CS_ADHOC flag — indicates the binary is ad-hoc signed (no real identity).
const CS_ADHOC: u32 = 0x0000_0002;

/// CodeDirectory version 0x20400 (supports exec segment info).
const CD_VERSION: u32 = 0x0002_0400;

/// SHA-256 hash output size.
const SHA256_SIZE: u8 = 32;

/// Ad-hoc sign a Mach-O binary. Returns the new signed binary bytes.
pub fn adhoc_sign(binary: &[u8], options: &AdhocSignOptions) -> Result<Vec<u8>> {
    // --- 1. Parse the binary to extract existing signature info ---
    let mach = parse_macho_file(binary)?;

    let mut identifier = options.identifier.clone();
    let mut entitlements_xml = options.entitlements_xml.clone();

    if options.preserve_existing {
        if let Ok(sig) = mach.ext::<macho_codesign::CodeSignature<'_>>() {
            if identifier.is_none() {
                identifier = sig.identifier().map(|s| s.to_string());
            }
            if entitlements_xml.is_none() {
                entitlements_xml = sig.entitlements_xml().map(|s| s.to_string());
            }
        }
    }

    let identifier = identifier.unwrap_or_else(|| "adhoc-signed".to_string());

    // --- 2. Determine page size ---
    let page_size = options.page_size.unwrap_or_else(|| {
        // arm64/arm64e use 16K pages, x86_64 uses 4K.
        if mach.header().cpu_type().0 == macho_core::format::constants::CPU_TYPE_ARM64 {
            16384
        } else {
            4096
        }
    });
    let page_size_log2 = page_size.trailing_zeros() as u8;

    // --- 3. Strip existing LC_CODE_SIGNATURE ---
    let stripped = strip_code_signature(binary, &mach)?;
    let code_limit = stripped.len() as u32;

    // --- 4. Find __TEXT segment for exec segment info ---
    let (exec_seg_base, exec_seg_limit) = find_text_segment(&mach);

    // --- 5. Compute page hashes ---
    // n_code_slots = ceil(code_limit / page_size). Guard against page_size == 0
    // (caller could override it) to keep the division well-defined.
    if page_size == 0 {
        return Err(crate::Error::validation("page_size must be nonzero"));
    }
    let n_code_slots = (code_limit as u64).div_ceil(page_size as u64);
    let mut code_hashes = Vec::with_capacity(n_code_slots as usize);

    for i in 0..n_code_slots {
        let start = (i * page_size as u64) as usize;
        let end = (start + page_size as usize).min(stripped.len());
        let hash = sha256(&stripped[start..end]);
        code_hashes.push(hash);
    }

    // Invariant enforced as a hard contract on the CodeDirectory we're about
    // to build: the number of emitted hashes must match the declared slot
    // count. A mismatch here produces a binary that fails kernel validation
    // with no indication of why, so surface it eagerly.
    if code_hashes.len() as u64 != n_code_slots {
        return Err(crate::Error::validation(format!(
            "code hash count {} does not match declared slot count {}",
            code_hashes.len(),
            n_code_slots
        )));
    }

    // --- 6. Build special slot hashes ---
    let entitlements_blob = entitlements_xml.as_deref().map(build_entitlements_blob);

    // Special slot -5 = entitlements hash.
    let entitlements_hash = entitlements_blob
        .as_ref()
        .map(|blob| sha256(blob))
        .unwrap_or([0u8; 32]);

    // Slots -1 through -5 (info, requirements, resource, application, entitlements).
    // We only populate entitlements (-5); rest are zero.
    let n_special_slots: u32 = if entitlements_blob.is_some() { 5 } else { 2 };
    let mut special_hashes = vec![[0u8; 32]; n_special_slots as usize];
    if entitlements_blob.is_some() {
        special_hashes[4] = entitlements_hash; // slot -5 (index 4 in reverse order)
    }

    // --- 7. Build CodeDirectory ---
    let cd_blob = build_code_directory(CodeDirectoryInput {
        identifier: &identifier,
        code_limit,
        page_size_log2,
        n_code_slots: n_code_slots as u32,
        n_special_slots,
        special_hashes: &special_hashes,
        code_hashes: &code_hashes,
        exec_seg_base,
        exec_seg_limit,
    })?;

    // --- 8. Build SuperBlob ---
    let super_blob = build_super_blob(&cd_blob, entitlements_blob.as_deref());
    let signature_size = super_blob.len() as u32;

    // --- 9. Append signature and rebuild binary ---
    let mut signed = stripped;
    // Align to 16 bytes.
    while signed.len() % 16 != 0 {
        signed.push(0);
    }
    let sig_offset = signed.len() as u32;
    signed.extend_from_slice(&super_blob);

    // Now re-parse and use MachoEditor to add LC_CODE_SIGNATURE.
    let mach2 = parse_macho_file(&signed)?;
    let mut editor = MachoEditor::new(&mach2);

    // Remove any leftover LC_CODE_SIGNATURE (shouldn't exist after strip, but be safe).
    editor.remove_code_signature();

    // Add new LC_CODE_SIGNATURE pointing to our SuperBlob.
    editor.add_command(LoadCommand::CodeSignature(
        macho_core::model::load_command::LinkeditData {
            data_offset: sig_offset,
            data_size: signature_size,
        },
    ));

    let result_binary = editor.build()?;

    Ok(result_binary)
}

// ───────────────────────────── strip existing sig ─────────────────────────

fn strip_code_signature(binary: &[u8], mach: &MachoFile<'_>) -> Result<Vec<u8>> {
    let sig_lc = mach
        .find_load_command(|lc| matches!(lc, LoadCommand::CodeSignature(_)))
        .and_then(|lc| lc.kind().as_linkedit_data());

    let Some(sig) = sig_lc else {
        // No existing signature; return as-is.
        return Ok(binary.to_vec());
    };

    let sig_offset = sig.data_offset as usize;

    // Truncate at the signature offset.
    if sig_offset > binary.len() {
        return Ok(binary.to_vec());
    }

    let stripped = binary[..sig_offset].to_vec();

    // Remove the LC_CODE_SIGNATURE load command by rebuilding via editor.
    let mach2 = parse_macho_file(&stripped)?;
    let mut editor = MachoEditor::new(&mach2);
    editor.remove_code_signature();
    editor.build()
}

// ───────────────────────────── CodeDirectory ─────────────────────────────

struct CodeDirectoryInput<'a> {
    identifier: &'a str,
    code_limit: u32,
    page_size_log2: u8,
    n_code_slots: u32,
    n_special_slots: u32,
    special_hashes: &'a [[u8; 32]],
    code_hashes: &'a [[u8; 32]],
    exec_seg_base: u64,
    exec_seg_limit: u64,
}

fn build_code_directory(input: CodeDirectoryInput<'_>) -> Result<Vec<u8>> {
    let CodeDirectoryInput {
        identifier,
        code_limit,
        page_size_log2,
        n_code_slots,
        n_special_slots,
        special_hashes,
        code_hashes,
        exec_seg_base,
        exec_seg_limit,
    } = input;
    // Contract: the caller must supply exactly one hash per declared slot.
    // A mismatch would silently truncate or over-read the buffer.
    if code_hashes.len() != n_code_slots as usize {
        return Err(crate::Error::validation(format!(
            "build_code_directory: code_hashes.len()={} != n_code_slots={}",
            code_hashes.len(),
            n_code_slots
        )));
    }
    if special_hashes.len() != n_special_slots as usize {
        return Err(crate::Error::validation(format!(
            "build_code_directory: special_hashes.len()={} != n_special_slots={}",
            special_hashes.len(),
            n_special_slots
        )));
    }
    let ident_bytes = identifier.as_bytes();
    let ident_len = ident_bytes.len() + 1; // +1 for null terminator

    // CodeDirectory layout (version 0x20400):
    //   0: magic (4)
    //   4: length (4)
    //   8: version (4)
    //  12: flags (4)
    //  16: hashOffset (4)
    //  20: identOffset (4)
    //  24: nSpecialSlots (4)
    //  28: nCodeSlots (4)
    //  32: codeLimit (4)
    //  36: hashSize (1)
    //  37: hashType (1)
    //  38: platform (1)
    //  39: pageSize (1)
    //  40: spare2 (4)
    //  44: scatterOffset (4)  [v0x20100]
    //  48: teamOffset (4)     [v0x20200]
    //  52: spare3 (4)         [v0x20300]
    //  56: codeLimit64 (8)    [v0x20300]
    //  64: execSegBase (8)    [v0x20400]
    //  72: execSegLimit (8)   [v0x20400]
    //  80: execSegFlags (8)   [v0x20400]
    //  88: <end of fixed header>
    // Then: special hashes, identifier string, code hashes.

    let header_size: usize = 88;
    let special_hashes_size = n_special_slots as usize * SHA256_SIZE as usize;
    let ident_offset = header_size + special_hashes_size;
    let hash_offset = ident_offset + ident_len;
    let code_hashes_size = n_code_slots as usize * SHA256_SIZE as usize;
    let total_len = hash_offset + code_hashes_size;

    let mut buf = vec![0u8; total_len];

    // Header
    write_be_u32(&mut buf, 0, CSMAGIC_CODEDIRECTORY);
    write_be_u32(&mut buf, 4, total_len as u32);
    write_be_u32(&mut buf, 8, CD_VERSION);
    write_be_u32(&mut buf, 12, CS_ADHOC);
    write_be_u32(&mut buf, 16, hash_offset as u32);
    write_be_u32(&mut buf, 20, ident_offset as u32);
    write_be_u32(&mut buf, 24, n_special_slots);
    write_be_u32(&mut buf, 28, n_code_slots);
    write_be_u32(&mut buf, 32, code_limit);
    buf[36] = SHA256_SIZE;
    buf[37] = CS_HASHTYPE_SHA256;
    buf[38] = 0; // platform
    buf[39] = page_size_log2;
    // spare2, scatterOffset, teamOffset, spare3 = 0
    write_be_u64(&mut buf, 56, code_limit as u64); // codeLimit64
    write_be_u64(&mut buf, 64, exec_seg_base);
    write_be_u64(&mut buf, 72, exec_seg_limit);
    write_be_u64(&mut buf, 80, 0); // execSegFlags

    // Special hashes (written in reverse order: slot -n first, slot -1 last).
    for (i, hash) in special_hashes.iter().rev().enumerate() {
        let offset = header_size + i * SHA256_SIZE as usize;
        buf[offset..offset + 32].copy_from_slice(hash);
    }

    // Identifier string (null-terminated).
    buf[ident_offset..ident_offset + ident_bytes.len()].copy_from_slice(ident_bytes);
    buf[ident_offset + ident_bytes.len()] = 0;

    // Code hashes.
    for (i, hash) in code_hashes.iter().enumerate() {
        let offset = hash_offset + i * SHA256_SIZE as usize;
        buf[offset..offset + 32].copy_from_slice(hash);
    }

    Ok(buf)
}

// ───────────────────────────── entitlements blob ─────────────────────────

fn build_entitlements_blob(xml: &str) -> Vec<u8> {
    let xml_bytes = xml.as_bytes();
    let total_len = 8 + xml_bytes.len(); // magic + length + data
    let mut buf = vec![0u8; total_len];
    write_be_u32(&mut buf, 0, CSMAGIC_ENTITLEMENTS);
    write_be_u32(&mut buf, 4, total_len as u32);
    buf[8..].copy_from_slice(xml_bytes);
    buf
}

// ───────────────────────────── SuperBlob ─────────────────────────────

fn build_super_blob(cd_blob: &[u8], entitlements_blob: Option<&[u8]>) -> Vec<u8> {
    let blob_count: u32 = if entitlements_blob.is_some() { 2 } else { 1 };

    // SuperBlob layout:
    //   0: magic (4)
    //   4: length (4)
    //   8: count (4)
    //  12: BlobIndex[0] { type(4), offset(4) }
    //  20: BlobIndex[1] { type(4), offset(4) }  (if entitlements)
    //  Then: blob data

    let index_size = 12 + blob_count as usize * 8;
    let cd_offset = index_size;
    let ent_offset = cd_offset + cd_blob.len();
    let total_len = ent_offset + entitlements_blob.map_or(0, |b| b.len());

    let mut buf = vec![0u8; total_len];

    // SuperBlob header.
    write_be_u32(&mut buf, 0, CSMAGIC_EMBEDDED_SIGNATURE);
    write_be_u32(&mut buf, 4, total_len as u32);
    write_be_u32(&mut buf, 8, blob_count);

    // BlobIndex[0]: CodeDirectory.
    write_be_u32(&mut buf, 12, CS_SLOT_CODEDIRECTORY);
    write_be_u32(&mut buf, 16, cd_offset as u32);

    // BlobIndex[1]: Entitlements (if present).
    if let Some(ent_blob) = entitlements_blob {
        write_be_u32(&mut buf, 20, CS_SLOT_ENTITLEMENTS);
        write_be_u32(&mut buf, 24, ent_offset as u32);
        buf[ent_offset..ent_offset + ent_blob.len()].copy_from_slice(ent_blob);
    }

    // CodeDirectory data.
    buf[cd_offset..cd_offset + cd_blob.len()].copy_from_slice(cd_blob);

    buf
}

// ───────────────────────────── helpers ─────────────────────────────

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn find_text_segment(mach: &MachoFile<'_>) -> (u64, u64) {
    for seg in mach.segments() {
        if seg.name() == "__TEXT" {
            return (seg.file_offset().0, seg.file_size());
        }
    }
    (0, 0)
}

fn write_be_u32(buf: &mut [u8], offset: usize, val: u32) {
    buf[offset..offset + 4].copy_from_slice(&val.to_be_bytes());
}

fn write_be_u64(buf: &mut [u8], offset: usize, val: u64) {
    buf[offset..offset + 8].copy_from_slice(&val.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entitlements_blob_format() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict/></plist>"#;
        let blob = build_entitlements_blob(xml);
        assert_eq!(
            u32::from_be_bytes(blob[0..4].try_into().unwrap()),
            CSMAGIC_ENTITLEMENTS
        );
        let len = u32::from_be_bytes(blob[4..8].try_into().unwrap()) as usize;
        assert_eq!(len, blob.len());
        assert_eq!(&blob[8..], xml.as_bytes());
    }

    #[test]
    fn super_blob_format() {
        let code_hashes = [sha256(b"hello")];
        let cd = build_code_directory(CodeDirectoryInput {
            identifier: "test",
            code_limit: 4096,
            page_size_log2: 12,
            n_code_slots: 1,
            n_special_slots: 0,
            special_hashes: &[],
            code_hashes: &code_hashes,
            exec_seg_base: 0,
            exec_seg_limit: 0,
        })
        .expect("valid inputs");
        let sb = build_super_blob(&cd, None);

        // Check magic.
        assert_eq!(
            u32::from_be_bytes(sb[0..4].try_into().unwrap()),
            CSMAGIC_EMBEDDED_SIGNATURE
        );
        // Check count.
        assert_eq!(u32::from_be_bytes(sb[8..12].try_into().unwrap()), 1);
    }

    #[test]
    fn code_directory_format() {
        let hashes = vec![sha256(b"page0"), sha256(b"page1")];
        let cd = build_code_directory(CodeDirectoryInput {
            identifier: "com.test.app",
            code_limit: 8192,
            page_size_log2: 12,
            n_code_slots: 2,
            n_special_slots: 0,
            special_hashes: &[],
            code_hashes: &hashes,
            exec_seg_base: 0,
            exec_seg_limit: 4096,
        })
        .expect("valid inputs");

        // Magic.
        assert_eq!(
            u32::from_be_bytes(cd[0..4].try_into().unwrap()),
            CSMAGIC_CODEDIRECTORY
        );
        // Version.
        assert_eq!(
            u32::from_be_bytes(cd[8..12].try_into().unwrap()),
            CD_VERSION
        );
        // Flags = CS_ADHOC.
        assert_eq!(u32::from_be_bytes(cd[12..16].try_into().unwrap()), CS_ADHOC);
        // nCodeSlots.
        assert_eq!(u32::from_be_bytes(cd[28..32].try_into().unwrap()), 2);
        // codeLimit.
        assert_eq!(u32::from_be_bytes(cd[32..36].try_into().unwrap()), 8192);
        // hashSize.
        assert_eq!(cd[36], 32);
        // hashType.
        assert_eq!(cd[37], CS_HASHTYPE_SHA256);
        // pageSize (log2(4096) = 12).
        assert_eq!(cd[39], 12);
    }

    #[test]
    fn sha256_deterministic() {
        let h1 = sha256(b"hello world");
        let h2 = sha256(b"hello world");
        assert_eq!(h1, h2);
        assert_ne!(h1, [0u8; 32]);
    }
}
