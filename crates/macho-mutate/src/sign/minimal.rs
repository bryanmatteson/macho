//! Feature-minimal Mach-O signing used by external credential providers.

use macho_core::format::io::Endian;
use macho_core::model::container::MachoContainer;
use macho_core::model::header::Bitness;
use macho_core::model::load_command::LoadCommand;
use macho_core::model::macho_file::MachoFile;
use sha2::{Digest, Sha256, Sha384};

use super::{ExternalDigestSigner, SignatureKind, SignatureProviderError, SignatureRequest};

const PAGE_SIZE: usize = 4096;
const CODE_DIRECTORY_HEADER_SIZE: usize = 64;
const ENTITLEMENTS_SLOT: usize = 5;

pub(super) fn sign_adhoc(
    bytes: &[u8],
    request: &SignatureRequest,
) -> Result<Vec<u8>, SignatureProviderError> {
    sign_container(bytes, |thin| {
        let metadata = signing_metadata(thin, request, "adhoc-signed")?;
        let clean = strip_existing_signature(thin)?;
        finalize_signature(&clean, &metadata, |_| Ok(Vec::new()))
    })
}

pub(super) fn sign_external(
    bytes: &[u8],
    request: &SignatureRequest,
    signer: &dyn ExternalDigestSigner,
) -> Result<Vec<u8>, SignatureProviderError> {
    let certificates = signer.certificate_chain();
    let leaf = certificates.first().ok_or_else(|| {
        SignatureProviderError::InvalidCredentials(
            "external signer returned an empty certificate chain".to_string(),
        )
    })?;
    let (issuer, serial) = certificate_issuer_and_serial(leaf)?;
    let algorithm = ["ecdsa-p256-sha256", "rsa-pkcs1-sha256", "ecdsa-p384-sha384"]
        .into_iter()
        .find(|candidate| signer.algorithms().iter().any(|value| value == candidate))
        .ok_or_else(|| {
            SignatureProviderError::Unavailable(
                "external signer has no supported Mach-O CMS algorithm".to_string(),
            )
        })?;
    let identity = Sha256::digest(signer.public_identity().as_bytes());
    let fallback = format!(
        "external.{}",
        identity[..12]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    sign_container(bytes, |thin| {
        let metadata = signing_metadata(thin, request, &fallback)?;
        let clean = strip_existing_signature(thin)?;
        finalize_signature(&clean, &metadata, |code_directory| {
            cms_signature(
                code_directory,
                algorithm,
                &certificates,
                &issuer,
                &serial,
                signer,
            )
        })
    })
}

fn sign_container(
    bytes: &[u8],
    mut sign_thin: impl FnMut(&[u8]) -> Result<Vec<u8>, SignatureProviderError>,
) -> Result<Vec<u8>, SignatureProviderError> {
    let parsed = macho_core::parse(bytes).map_err(failed)?;
    match &parsed {
        MachoContainer::Thin(macho) => sign_thin(macho.bytes()),
        MachoContainer::Fat(fat) => {
            let replacements = fat
                .arches()
                .iter()
                .enumerate()
                .map(|(index, arch)| sign_thin(arch.macho().bytes()).map(|bytes| (index, bytes)))
                .collect::<Result<Vec<_>, _>>()?;
            let mut output = crate::owned::OwnedFatBinary::from_fat(fat, bytes);
            for (index, replacement) in replacements {
                output.replace_arch(index, replacement).map_err(failed)?;
            }
            output.try_into_bytes().map_err(failed)
        }
    }
}

struct SigningMetadata {
    identifier: String,
    entitlements_xml: Option<String>,
}

fn signing_metadata(
    bytes: &[u8],
    request: &SignatureRequest,
    fallback_identifier: &str,
) -> Result<SigningMetadata, SignatureProviderError> {
    let macho = macho_core::format::parse_macho_file(bytes).map_err(failed)?;
    let prior = macho.ext::<macho_codesign::CodeSignature<'_>>().ok();
    let identifier = request
        .identifier()
        .map(str::to_owned)
        .or_else(|| {
            prior
                .as_ref()
                .and_then(|value| value.identifier().map(str::to_owned))
        })
        .unwrap_or_else(|| fallback_identifier.to_string());
    if identifier.is_empty() || identifier.contains('\0') {
        return Err(SignatureProviderError::Failed(
            "binary identifier must be nonempty and NUL-free".to_string(),
        ));
    }
    let entitlements_xml = request.entitlements_xml().map(str::to_owned).or_else(|| {
        prior
            .as_ref()
            .and_then(|value| value.entitlements_xml().map(str::to_owned))
    });
    Ok(SigningMetadata {
        identifier,
        entitlements_xml,
    })
}

fn finalize_signature(
    bytes: &[u8],
    metadata: &SigningMetadata,
    mut cms: impl FnMut(&[u8]) -> Result<Vec<u8>, SignatureProviderError>,
) -> Result<Vec<u8>, SignatureProviderError> {
    let entitlements = metadata.entitlements_xml.as_deref().map(entitlements_blob);
    let mut reserved_size = 4096usize;
    for _ in 0..8 {
        let (mut prepared, signature_offset) = prepare_signature_slot(bytes, reserved_size)?;
        let code_directory = code_directory(
            &prepared[..signature_offset],
            &metadata.identifier,
            entitlements.as_deref(),
        )?;
        let cms = cms(&code_directory)?;
        let superblob = signature_superblob(&code_directory, entitlements.as_deref(), &cms)?;
        let required = align_usize(superblob.len(), 16)?;
        if required != reserved_size {
            reserved_size = required;
            continue;
        }
        prepared[signature_offset..signature_offset + superblob.len()].copy_from_slice(&superblob);
        prepared[signature_offset + superblob.len()..].fill(0);
        macho_core::format::parse_macho_file(&prepared).map_err(failed)?;
        verify_code_slots(&prepared)?;
        return Ok(prepared);
    }
    Err(SignatureProviderError::Failed(
        "Mach-O signature size did not stabilize during finalization".to_string(),
    ))
}

fn strip_existing_signature(bytes: &[u8]) -> Result<Vec<u8>, SignatureProviderError> {
    let macho = macho_core::format::parse_macho_file(bytes).map_err(failed)?;
    let signatures = macho
        .load_commands()
        .iter()
        .filter_map(|command| match command.kind() {
            LoadCommand::CodeSignature(data) => Some(data),
            _ => None,
        })
        .collect::<Vec<_>>();
    let Some(signature) = signatures.first() else {
        return Ok(bytes.to_vec());
    };
    if signatures.len() != 1 {
        return Err(SignatureProviderError::Failed(
            "duplicate LC_CODE_SIGNATURE commands are unsupported".to_string(),
        ));
    }
    let start = signature.data_offset as usize;
    let end = start
        .checked_add(signature.data_size as usize)
        .ok_or_else(|| failed("existing signature range overflows"))?;
    if end > bytes.len() || bytes[end..].iter().any(|byte| *byte != 0) {
        return Err(SignatureProviderError::Failed(
            "existing signature is not the terminal file payload".to_string(),
        ));
    }
    let mut transaction = crate::PatchTransaction::new(&macho);
    transaction.remove_code_signature();
    let mut output = transaction.commit().map_err(failed)?;
    resize_terminal_segment(&mut output, bytes.len(), start)?;
    output.truncate(start);
    macho_core::format::parse_macho_file(&output).map_err(failed)?;
    Ok(output)
}

fn prepare_signature_slot(
    bytes: &[u8],
    signature_size: usize,
) -> Result<(Vec<u8>, usize), SignatureProviderError> {
    let macho = macho_core::format::parse_macho_file(bytes).map_err(failed)?;
    let commands_end = macho
        .bitness()
        .header_size()
        .checked_add(macho.header().load_commands_size() as usize)
        .ok_or_else(|| failed("load-command range overflows"))?;
    let first_content = first_file_content(&macho, commands_end);
    let new_commands_end = commands_end
        .checked_add(16)
        .ok_or_else(|| failed("signature command range overflows"))?;
    if new_commands_end > first_content
        || bytes
            .get(commands_end..new_commands_end)
            .is_none_or(|slack| slack.iter().any(|byte| *byte != 0))
    {
        return Err(SignatureProviderError::Failed(
            "Mach-O header has insufficient zero-filled signature-command slack".to_string(),
        ));
    }
    let signature_offset = align_usize(bytes.len(), 16)?;
    let final_size = signature_offset
        .checked_add(signature_size)
        .ok_or_else(|| failed("signature range overflows"))?;
    let mut output = bytes.to_vec();
    output.resize(final_size, 0);
    let endian = macho.endian();
    write_u32(&mut output, commands_end, endian, 0x1d)?;
    write_u32(&mut output, commands_end + 4, endian, 16)?;
    write_u32(
        &mut output,
        commands_end + 8,
        endian,
        u32::try_from(signature_offset).map_err(failed)?,
    )?;
    write_u32(
        &mut output,
        commands_end + 12,
        endian,
        u32::try_from(signature_size).map_err(failed)?,
    )?;
    write_u32(
        &mut output,
        16,
        endian,
        macho
            .header()
            .load_command_count()
            .checked_add(1)
            .ok_or_else(|| failed("load-command count overflows"))?,
    )?;
    write_u32(
        &mut output,
        20,
        endian,
        macho
            .header()
            .load_commands_size()
            .checked_add(16)
            .ok_or_else(|| failed("load-command bytes overflow"))?,
    )?;
    resize_terminal_segment(&mut output, bytes.len(), final_size)?;
    Ok((output, signature_offset))
}

fn first_file_content(macho: &MachoFile<'_>, commands_end: usize) -> usize {
    macho
        .segments()
        .iter()
        .flat_map(|segment| segment.sections())
        .filter(|section| !section.section_type().is_zerofill() && section.size() > 0)
        .filter_map(|section| usize::try_from(section.offset().0).ok())
        .filter(|offset| *offset >= commands_end)
        .min()
        .unwrap_or_else(|| macho.bytes().len())
}

fn resize_terminal_segment(
    output: &mut [u8],
    old_end: usize,
    new_end: usize,
) -> Result<(), SignatureProviderError> {
    let snapshot = output.to_vec();
    let macho = macho_core::format::parse_macho_file(&snapshot).map_err(failed)?;
    let mut match_offset = None;
    for command in macho.load_commands() {
        let Some(segment_data) = command.kind().as_segment() else {
            continue;
        };
        let segment = &macho.segments()[segment_data.segment_index];
        if segment.file_offset().0.checked_add(segment.file_size()) == Some(old_end as u64) {
            if match_offset.is_some() {
                return Err(failed("multiple segments own the terminal file byte"));
            }
            match_offset = Some((command.file_offset().as_usize(), macho.bitness(), segment));
        }
    }
    let Some((offset, bitness, segment)) = match_offset else {
        return Err(failed(
            "Mach-O has no terminal file-backed segment for its signature",
        ));
    };
    let file_size = (new_end as u64)
        .checked_sub(segment.file_offset().0)
        .ok_or_else(|| failed("terminal segment resize underflows"))?;
    let required_vm_size = align_u64(file_size, 0x1000)?;
    let vm_size = segment.vm_size().max(required_vm_size);
    let endian = macho.endian();
    match bitness {
        Bitness::Bits64 => {
            write_u64(output, offset + 48, endian, file_size)?;
            write_u64(output, offset + 32, endian, vm_size)?;
        }
        Bitness::Bits32 => {
            write_u32(
                output,
                offset + 36,
                endian,
                u32::try_from(file_size).map_err(failed)?,
            )?;
            write_u32(
                output,
                offset + 28,
                endian,
                u32::try_from(vm_size).map_err(failed)?,
            )?;
        }
    }
    Ok(())
}

fn code_directory(
    code: &[u8],
    identifier: &str,
    entitlements: Option<&[u8]>,
) -> Result<Vec<u8>, SignatureProviderError> {
    if code.len() > u32::MAX as usize {
        return Err(failed("Mach-O CodeDirectory input exceeds UInt32"));
    }
    let special_slots = usize::from(entitlements.is_some()) * ENTITLEMENTS_SLOT;
    let identifier_offset = CODE_DIRECTORY_HEADER_SIZE;
    let special_offset = identifier_offset
        .checked_add(identifier.len() + 1)
        .ok_or_else(|| failed("CodeDirectory identifier overflows"))?;
    let hash_offset = special_offset
        .checked_add(special_slots * 32)
        .ok_or_else(|| failed("CodeDirectory special slots overflow"))?;
    let slots = code.len().div_ceil(PAGE_SIZE);
    let total = hash_offset
        .checked_add(slots * 32)
        .ok_or_else(|| failed("CodeDirectory hashes overflow"))?;
    let mut output = Vec::with_capacity(total);
    for value in [
        0xfade0c02u32,
        u32::try_from(total).map_err(failed)?,
        0x0002_0300,
        0,
        u32::try_from(hash_offset).map_err(failed)?,
        u32::try_from(identifier_offset).map_err(failed)?,
        u32::try_from(special_slots).map_err(failed)?,
        u32::try_from(slots).map_err(failed)?,
        code.len() as u32,
    ] {
        output.extend_from_slice(&value.to_be_bytes());
    }
    output.extend_from_slice(&[32, 2, 0, 12]);
    output.extend_from_slice(&0u32.to_be_bytes());
    output.extend_from_slice(&0u32.to_be_bytes());
    output.extend_from_slice(&0u32.to_be_bytes());
    output.extend_from_slice(&0u32.to_be_bytes());
    output.extend_from_slice(&(code.len() as u64).to_be_bytes());
    output.extend_from_slice(identifier.as_bytes());
    output.push(0);
    if let Some(entitlements) = entitlements {
        output.extend_from_slice(&Sha256::digest(entitlements));
        output.resize(special_offset + ENTITLEMENTS_SLOT * 32, 0);
    }
    for page in code.chunks(PAGE_SIZE) {
        output.extend_from_slice(&Sha256::digest(page));
    }
    Ok(output)
}

fn entitlements_blob(xml: &str) -> Vec<u8> {
    let mut output = Vec::with_capacity(xml.len() + 8);
    output.extend_from_slice(&0xfade7171u32.to_be_bytes());
    output.extend_from_slice(&((xml.len() + 8) as u32).to_be_bytes());
    output.extend_from_slice(xml.as_bytes());
    output
}

fn signature_superblob(
    code_directory: &[u8],
    entitlements: Option<&[u8]>,
    cms: &[u8],
) -> Result<Vec<u8>, SignatureProviderError> {
    let mut cms_blob = Vec::with_capacity(cms.len() + 8);
    cms_blob.extend_from_slice(&0xfade0b01u32.to_be_bytes());
    cms_blob.extend_from_slice(&u32::try_from(cms.len() + 8).map_err(failed)?.to_be_bytes());
    cms_blob.extend_from_slice(cms);
    let count = if entitlements.is_some() {
        3usize
    } else {
        2usize
    };
    let index_end = 12 + count * 8;
    let code_offset = index_end;
    let entitlements_offset = code_offset + code_directory.len();
    let cms_offset = entitlements_offset + entitlements.map_or(0, <[u8]>::len);
    let total = cms_offset
        .checked_add(cms_blob.len())
        .ok_or_else(|| failed("signature superblob overflows"))?;
    let mut output = Vec::with_capacity(total);
    output.extend_from_slice(&0xfade0cc0u32.to_be_bytes());
    output.extend_from_slice(&u32::try_from(total).map_err(failed)?.to_be_bytes());
    output.extend_from_slice(&u32::try_from(count).map_err(failed)?.to_be_bytes());
    output.extend_from_slice(&0u32.to_be_bytes());
    output.extend_from_slice(&u32::try_from(code_offset).map_err(failed)?.to_be_bytes());
    if entitlements.is_some() {
        output.extend_from_slice(&5u32.to_be_bytes());
        output.extend_from_slice(
            &u32::try_from(entitlements_offset)
                .map_err(failed)?
                .to_be_bytes(),
        );
    }
    output.extend_from_slice(&0x0001_0000u32.to_be_bytes());
    output.extend_from_slice(&u32::try_from(cms_offset).map_err(failed)?.to_be_bytes());
    output.extend_from_slice(code_directory);
    if let Some(entitlements) = entitlements {
        output.extend_from_slice(entitlements);
    }
    output.extend_from_slice(&cms_blob);
    Ok(output)
}

fn cms_signature(
    code_directory: &[u8],
    algorithm: &str,
    certificates: &[Vec<u8>],
    issuer: &[u8],
    serial: &[u8],
    signer: &dyn ExternalDigestSigner,
) -> Result<Vec<u8>, SignatureProviderError> {
    let (digest_algorithm, signature_algorithm, message_digest, use_sha384) = match algorithm {
        "ecdsa-p256-sha256" => (
            der_algorithm(
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
                true,
            ),
            der_algorithm(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02], false),
            Sha256::digest(code_directory).to_vec(),
            false,
        ),
        "rsa-pkcs1-sha256" => (
            der_algorithm(
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
                true,
            ),
            der_algorithm(
                &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01],
                true,
            ),
            Sha256::digest(code_directory).to_vec(),
            false,
        ),
        "ecdsa-p384-sha384" => (
            der_algorithm(
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02],
                true,
            ),
            der_algorithm(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03], false),
            Sha384::digest(code_directory).to_vec(),
            true,
        ),
        _ => return Err(failed("unsupported code-signing algorithm")),
    };
    let content_type_attribute = der_sequence(&[
        der_oid(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03]),
        der_set(&[der_oid(&[
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01,
        ])]),
    ]);
    let message_digest_attribute = der_sequence(&[
        der_oid(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04]),
        der_set(&[der(0x04, &message_digest)]),
    ]);
    let mut attributes = [content_type_attribute, message_digest_attribute];
    attributes.sort();
    let attribute_contents = attributes.concat();
    let signed_attributes = der(0x31, &attribute_contents);
    let digest = if use_sha384 {
        Sha384::digest(&signed_attributes).to_vec()
    } else {
        Sha256::digest(&signed_attributes).to_vec()
    };
    let signature = signer.sign_digest(algorithm, &digest)?;
    if signature.is_empty() {
        return Err(failed("external signer returned an empty signature"));
    }
    let signer_info = der_sequence(&[
        der_integer(1),
        der_sequence(&[issuer.to_vec(), serial.to_vec()]),
        digest_algorithm.clone(),
        der(0xa0, &attribute_contents),
        signature_algorithm,
        der(0x04, &signature),
    ]);
    let signed_data = der_sequence(&[
        der_integer(1),
        der_set(&[digest_algorithm]),
        der_sequence(&[der_oid(&[
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01,
        ])]),
        der(0xa0, &certificates.concat()),
        der_set(&[signer_info]),
    ]);
    Ok(der_sequence(&[
        der_oid(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02]),
        der(0xa0, &signed_data),
    ]))
}

pub(super) fn verify_signed_binary(
    bytes: &[u8],
    kind: SignatureKind,
) -> Result<(), SignatureProviderError> {
    if kind == SignatureKind::Opaque {
        return Err(SignatureProviderError::Unavailable(
            "opaque signatures must be verified by their signing provider".to_string(),
        ));
    }
    let parsed = macho_core::parse(bytes).map_err(verification)?;
    match &parsed {
        MachoContainer::Thin(macho) => verify_signature_kind(macho.bytes(), kind),
        MachoContainer::Fat(fat) => {
            for arch in fat.arches() {
                verify_signature_kind(arch.macho().bytes(), kind)?;
            }
            Ok(())
        }
    }
}

fn verify_signature_kind(bytes: &[u8], kind: SignatureKind) -> Result<(), SignatureProviderError> {
    let signature = verify_code_slots(bytes)?;
    let cms_present = signature.cms_signature_present();
    match kind {
        SignatureKind::AdHoc if cms_present => {
            Err(verification("ad-hoc signature contains CMS data"))
        }
        SignatureKind::Certificate if !cms_present => {
            Err(verification("certificate signature has no CMS data"))
        }
        _ => Ok(()),
    }
}

fn verify_code_slots(
    bytes: &[u8],
) -> Result<macho_codesign::CodeSignature<'_>, SignatureProviderError> {
    let macho = macho_core::format::parse_macho_file(bytes).map_err(verification)?;
    let signature = macho
        .ext::<macho_codesign::CodeSignature<'_>>()
        .map_err(verification)?;
    let code_blob = signature
        .blobs()
        .iter()
        .find(|blob| blob.blob_type == macho_codesign::BlobType::CodeDirectory)
        .ok_or_else(|| verification("signature has no CodeDirectory"))?;
    let directory = code_blob.data;
    let hash_offset = read_be_u32(directory, 16)? as usize;
    let special_slots = read_be_u32(directory, 24)? as usize;
    let code_slots = read_be_u32(directory, 28)? as usize;
    let code_limit = read_be_u32(directory, 32)? as usize;
    let hash_size = *directory
        .get(36)
        .ok_or_else(|| verification("truncated CodeDirectory"))? as usize;
    let hash_type = *directory
        .get(37)
        .ok_or_else(|| verification("truncated CodeDirectory"))?;
    let page_exponent = *directory
        .get(39)
        .ok_or_else(|| verification("truncated CodeDirectory"))?;
    if hash_size != 32 || hash_type != 2 || page_exponent != 12 || code_limit > bytes.len() {
        return Err(verification(
            "unsupported or invalid CodeDirectory parameters",
        ));
    }
    if code_slots != code_limit.div_ceil(PAGE_SIZE) {
        return Err(verification(
            "CodeDirectory code-slot count is inconsistent",
        ));
    }
    for (index, page) in bytes[..code_limit].chunks(PAGE_SIZE).enumerate() {
        let start = hash_offset + index * hash_size;
        let end = start + hash_size;
        if directory.get(start..end) != Some(Sha256::digest(page).as_slice()) {
            return Err(verification(format!(
                "code digest mismatch in CodeDirectory page {index}"
            )));
        }
    }
    if let Some(entitlements) = signature
        .blobs()
        .iter()
        .find(|blob| blob.blob_type == macho_codesign::BlobType::Entitlements)
    {
        if special_slots < ENTITLEMENTS_SLOT || hash_offset < ENTITLEMENTS_SLOT * hash_size {
            return Err(verification(
                "CodeDirectory omits the entitlements special slot",
            ));
        }
        let start = hash_offset - ENTITLEMENTS_SLOT * hash_size;
        if directory.get(start..start + hash_size)
            != Some(Sha256::digest(entitlements.data).as_slice())
        {
            return Err(verification("CodeDirectory entitlements hash differs"));
        }
    }
    Ok(signature)
}

fn certificate_issuer_and_serial(
    certificate: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), SignatureProviderError> {
    let mut outer_cursor = 0usize;
    let (outer_tag, certificate_content, _) = der_take(certificate, &mut outer_cursor)?;
    if outer_tag != 0x30 || outer_cursor != certificate.len() {
        return Err(invalid_credentials("certificate is not one DER sequence"));
    }
    let mut certificate_cursor = 0usize;
    let (tag, tbs, _) = der_take(certificate_content, &mut certificate_cursor)?;
    if tag != 0x30 {
        return Err(invalid_credentials(
            "certificate TBS value is not a sequence",
        ));
    }
    let mut cursor = 0usize;
    let (first_tag, _, first_full) = der_take(tbs, &mut cursor)?;
    let serial = if first_tag == 0xa0 {
        let (tag, _, full) = der_take(tbs, &mut cursor)?;
        if tag != 0x02 {
            return Err(invalid_credentials("certificate serial number is absent"));
        }
        full.to_vec()
    } else if first_tag == 0x02 {
        first_full.to_vec()
    } else {
        return Err(invalid_credentials("certificate serial number is absent"));
    };
    let (signature_tag, _, _) = der_take(tbs, &mut cursor)?;
    if signature_tag != 0x30 {
        return Err(invalid_credentials(
            "certificate signature algorithm is malformed",
        ));
    }
    let (issuer_tag, _, issuer) = der_take(tbs, &mut cursor)?;
    if issuer_tag != 0x30 {
        return Err(invalid_credentials("certificate issuer is malformed"));
    }
    Ok((issuer.to_vec(), serial))
}

fn der_take<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
) -> Result<(u8, &'a [u8], &'a [u8]), SignatureProviderError> {
    let start = *cursor;
    let tag = *bytes
        .get(*cursor)
        .ok_or_else(|| invalid_credentials("truncated DER value"))?;
    *cursor += 1;
    let first = *bytes
        .get(*cursor)
        .ok_or_else(|| invalid_credentials("truncated DER length"))?;
    *cursor += 1;
    let length = if first & 0x80 == 0 {
        usize::from(first)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > std::mem::size_of::<usize>() {
            return Err(invalid_credentials("unsupported DER length"));
        }
        let mut length = 0usize;
        for _ in 0..count {
            let byte = *bytes
                .get(*cursor)
                .ok_or_else(|| invalid_credentials("truncated DER length"))?;
            *cursor += 1;
            length = length
                .checked_mul(256)
                .and_then(|value| value.checked_add(usize::from(byte)))
                .ok_or_else(|| invalid_credentials("DER length overflows"))?;
        }
        length
    };
    let end = cursor
        .checked_add(length)
        .ok_or_else(|| invalid_credentials("DER value overflows"))?;
    let content = bytes
        .get(*cursor..end)
        .ok_or_else(|| invalid_credentials("truncated DER value"))?;
    *cursor = end;
    Ok((tag, content, &bytes[start..end]))
}

fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut output = vec![tag];
    if content.len() < 128 {
        output.push(content.len() as u8);
    } else {
        let bytes = content.len().to_be_bytes();
        let first = bytes
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(bytes.len() - 1);
        output.push(0x80 | (bytes.len() - first) as u8);
        output.extend_from_slice(&bytes[first..]);
    }
    output.extend_from_slice(content);
    output
}

fn der_sequence(values: &[Vec<u8>]) -> Vec<u8> {
    der(0x30, &values.concat())
}

fn der_set(values: &[Vec<u8>]) -> Vec<u8> {
    let mut values = values.to_vec();
    values.sort();
    der(0x31, &values.concat())
}

fn der_oid(value: &[u8]) -> Vec<u8> {
    der(0x06, value)
}

fn der_integer(value: u8) -> Vec<u8> {
    der(0x02, &[value])
}

fn der_algorithm(oid: &[u8], null_parameter: bool) -> Vec<u8> {
    let mut values = vec![der_oid(oid)];
    if null_parameter {
        values.push(der(0x05, &[]));
    }
    der_sequence(&values)
}

fn read_be_u32(bytes: &[u8], offset: usize) -> Result<u32, SignatureProviderError> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| verification("truncated CodeDirectory integer"))?;
    Ok(u32::from_be_bytes(
        value.try_into().expect("four-byte range"),
    ))
}

fn write_u32(
    bytes: &mut [u8],
    offset: usize,
    endian: Endian,
    value: u32,
) -> Result<(), SignatureProviderError> {
    let encoded = match endian {
        Endian::Little => value.to_le_bytes(),
        Endian::Big => value.to_be_bytes(),
    };
    bytes
        .get_mut(offset..offset + 4)
        .ok_or_else(|| failed("Mach-O u32 write exceeds output"))?
        .copy_from_slice(&encoded);
    Ok(())
}

fn write_u64(
    bytes: &mut [u8],
    offset: usize,
    endian: Endian,
    value: u64,
) -> Result<(), SignatureProviderError> {
    let encoded = match endian {
        Endian::Little => value.to_le_bytes(),
        Endian::Big => value.to_be_bytes(),
    };
    bytes
        .get_mut(offset..offset + 8)
        .ok_or_else(|| failed("Mach-O u64 write exceeds output"))?
        .copy_from_slice(&encoded);
    Ok(())
}

fn align_usize(value: usize, alignment: usize) -> Result<usize, SignatureProviderError> {
    value
        .checked_add(alignment - 1)
        .map(|value| value & !(alignment - 1))
        .ok_or_else(|| failed("aligned Mach-O size overflows"))
}

fn align_u64(value: u64, alignment: u64) -> Result<u64, SignatureProviderError> {
    value
        .checked_add(alignment - 1)
        .map(|value| value & !(alignment - 1))
        .ok_or_else(|| failed("aligned Mach-O VM size overflows"))
}

fn failed(error: impl std::fmt::Display) -> SignatureProviderError {
    SignatureProviderError::Failed(error.to_string())
}

fn verification(error: impl std::fmt::Display) -> SignatureProviderError {
    SignatureProviderError::VerificationFailed(error.to_string())
}

fn invalid_credentials(error: impl std::fmt::Display) -> SignatureProviderError {
    SignatureProviderError::InvalidCredentials(error.to_string())
}
