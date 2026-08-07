//! Bounded arm64e pointer-authentication inventory and patch assessment.

use crate::core::format::constants::{CPU_TYPE_ARM64, SectionAttributes};
use crate::core::model::addr::Va;
use crate::core::model::macho_file::MachoFile;
use crate::insn::{
    Arch, Disassembler, Insn, InsnKind, Operand, RegClass, ValueEffect,
    decode_one as decode_instruction, disassemble_one,
};
use crate::metadata::dyld::resolve::{
    InventoryPointerTarget, LegacyBindStream, PointerEncoding, PointerInventory, PointerResolver,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Version of the serialized PAC report vocabulary.
pub const PAC_REPORT_SCHEMA_VERSION: u32 = 1;

/// Explicit bounds for one PAC analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacAnalysisLimits {
    /// Maximum dyld-managed pointer records retained.
    pub max_pointers: u64,
    /// Maximum executable-section bytes decoded for PAC sites.
    pub max_code_bytes: usize,
}

impl Default for PacAnalysisLimits {
    fn default() -> Self {
        Self {
            max_pointers: 1_000_000,
            max_code_bytes: 64 * 1024 * 1024,
        }
    }
}

impl PacAnalysisLimits {
    fn validate(self) -> Result<Self, PacAnalysisError> {
        if self.max_pointers == 0 || self.max_code_bytes == 0 {
            return Err(PacAnalysisError::InvalidLimits);
        }
        Ok(self)
    }
}

/// Failure preventing PAC analysis from producing a report.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PacAnalysisError {
    /// A configured bound was zero.
    #[error("PAC analysis limits must be non-zero")]
    InvalidLimits,
    /// The selected architecture cannot contain AArch64 PAC instructions.
    #[error("PAC analysis requires an arm64 or arm64e image, got {0}")]
    UnsupportedArchitecture(String),
    /// Dyld pointer evidence could not be recovered.
    #[error("PAC pointer inventory failed: {0}")]
    PointerInventory(String),
}

/// Architectural pointer-authentication key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PacKey {
    /// Instruction A key.
    Ia,
    /// Instruction B key.
    Ib,
    /// Data A key.
    Da,
    /// Data B key.
    Db,
    /// Unrecognized format key selector.
    Unknown(u8),
}

impl From<u8> for PacKey {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Ia,
            1 => Self::Ib,
            2 => Self::Da,
            3 => Self::Db,
            other => Self::Unknown(other),
        }
    }
}

/// On-disk pointer encoding projected into the PAC report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PacPointerEncoding {
    /// Chained rebase pointer.
    ChainedRebase,
    /// Chained bind pointer.
    ChainedBind,
    /// Legacy rebase pointer.
    LegacyRebase,
    /// Legacy bind pointer.
    LegacyBind,
    /// Direct pointer bytes.
    Direct,
}

impl From<PointerEncoding> for PacPointerEncoding {
    fn from(value: PointerEncoding) -> Self {
        match value {
            PointerEncoding::ChainedRebase => Self::ChainedRebase,
            PointerEncoding::ChainedBind => Self::ChainedBind,
            PointerEncoding::LegacyRebase => Self::LegacyRebase,
            PointerEncoding::LegacyBind => Self::LegacyBind,
            PointerEncoding::Direct => Self::Direct,
        }
    }
}

/// Proven authentication state of one dyld-managed pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum PacPointerAuthentication {
    /// The pointer is encoded without authentication.
    Plain,
    /// The chained pointer asks dyld to authenticate the runtime value.
    Authenticated {
        /// Selected PAC key.
        key: PacKey,
        /// Encoded constant diversity.
        diversity: u16,
        /// Whether the storage address participates in the modifier.
        address_diversity: bool,
    },
}

/// Semantic pointer destination retained in a PAC map.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PacPointerTarget {
    /// Null pointer.
    Null,
    /// Address inside the selected image.
    Internal {
        /// Unslid destination virtual address.
        address: u64,
    },
    /// Imported symbol.
    Import {
        /// Chained-import table ordinal, when applicable.
        import_ordinal: Option<u32>,
        /// Raw imported symbol name.
        name: String,
        /// Dynamic-library ordinal when uniquely represented by all evidence.
        library_ordinal: Option<i32>,
        /// Weak-import state when uniquely represented by all evidence.
        weak: Option<bool>,
        /// Addend carried by the chained import table.
        import_addend: i64,
        /// Addend carried by the pointer or legacy bind opcode.
        pointer_addend: i64,
    },
}

/// Legacy dyld bind stream retained for pointer provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PacLegacyBindStream {
    /// Regular bind stream.
    Regular,
    /// Weak bind stream.
    Weak,
    /// Lazy bind stream.
    Lazy,
}

/// One exact legacy-bind occurrence retained by a pointer record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacLegacyBindOccurrence {
    /// Source opcode stream.
    pub stream: PacLegacyBindStream,
    /// Dyld bind type.
    pub bind_type: u8,
    /// Dynamic-library ordinal.
    pub library_ordinal: i32,
    /// Weak-import flag.
    pub weak: bool,
    /// Raw symbol flags.
    pub symbol_flags: u8,
    /// Bind addend.
    pub addend: i64,
}

/// One pointer-bearing dyld record in the PAC map.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacPointerRecord {
    /// Slice-relative file offset of the pointer field.
    pub file_offset: u64,
    /// Unslid virtual address of the pointer field.
    pub address: u64,
    /// Containing segment, when one was recovered.
    pub segment: Option<String>,
    /// Containing section, when one was recovered.
    pub section: Option<String>,
    /// Pointer width in bytes.
    pub width: u8,
    /// Exact encoded bytes stored in the image.
    pub stored_bytes: Vec<u8>,
    /// On-disk pointer encoding.
    pub encoding: PacPointerEncoding,
    /// Chained pointer format selector, when applicable.
    pub chained_pointer_format: Option<u16>,
    /// Exact legacy bind occurrences, empty for non-legacy pointers.
    pub legacy_bind_occurrences: Vec<PacLegacyBindOccurrence>,
    /// Whether a legacy rebase stream also covers this pointer field.
    pub legacy_rebase: bool,
    /// Proven authentication state.
    pub authentication: PacPointerAuthentication,
    /// Semantic destination.
    pub target: PacPointerTarget,
}

/// Modifier form used by a PAC instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PacModifier {
    /// Implicit stack-pointer modifier.
    StackPointer,
    /// Implicit zero modifier.
    Zero,
    /// Explicit general-purpose register modifier.
    Register {
        /// AArch64 register number.
        number: u8,
    },
    /// The decoder did not retain a modifier.
    Unknown,
}

/// Semantic class of one PAC-related instruction site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PacCodeSiteKind {
    /// Sign a pointer.
    Sign,
    /// Authenticate a pointer.
    Authenticate,
    /// Strip authentication bits.
    Strip,
    /// Fused authenticated register branch.
    AuthenticatedBranch,
    /// Fused authenticated register call.
    AuthenticatedCall,
    /// Authenticated return.
    AuthenticatedReturn,
}

/// Evidence authority for a recovered PAC code site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PacCodeEvidence {
    /// Four-byte aligned decode in a section marked as instructions. This
    /// establishes the instruction bytes but does not, by itself, claim the
    /// address is reachable.
    ExecutableSectionDecode,
    /// A straight-line authenticate instruction established the target
    /// register and only decoded NOPs intervened before an ordinary transfer.
    AuthenticateThenTransfer,
}

/// One PAC/authentication instruction recovered from executable bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacCodeSite {
    /// Instruction virtual address.
    pub address: u64,
    /// Slice-relative instruction file offset.
    pub file_offset: u64,
    /// Containing segment.
    pub segment: String,
    /// Containing section.
    pub section: String,
    /// Semantic PAC operation.
    pub kind: PacCodeSiteKind,
    /// Selected key, when the operation uses one.
    pub key: Option<PacKey>,
    /// Target or pointer register, when decoded.
    pub target_register: Option<u8>,
    /// Authentication modifier.
    pub modifier: PacModifier,
    /// Canonical disassembly text.
    pub instruction: String,
    /// Recovery authority.
    pub evidence: PacCodeEvidence,
    /// Address of a separate authenticate instruction paired with this
    /// transfer, when the gadget is not fused.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication_address: Option<u64>,
}

/// Named key count used by deterministic JSON output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacKeyCount {
    /// PAC key.
    pub key: PacKey,
    /// Number of authenticated pointers using the key.
    pub count: u64,
}

/// Count for one exact authenticated-pointer discriminator form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacDiversityCount {
    /// PAC key paired with the discriminator.
    pub key: PacKey,
    /// Encoded constant diversity.
    pub diversity: u16,
    /// Whether the pointer storage address also participates in the modifier.
    pub address_diversity: bool,
    /// Number of pointers using this exact form.
    pub count: u64,
}

/// Aggregate PAC report counts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacSummary {
    /// Authenticated pointer count.
    pub authenticated_pointers: u64,
    /// Proven plain pointer count.
    pub plain_pointers: u64,
    /// Authenticated pointers using their storage address as diversity.
    pub address_diverse_pointers: u64,
    /// Pointer counts by key.
    pub pointer_keys: Vec<PacKeyCount>,
    /// Pointer counts by exact key, diversity, and address-diversity form.
    pub pointer_diversities: Vec<PacDiversityCount>,
    /// PAC instruction-site counts by architectural key.
    pub code_keys: Vec<PacKeyCount>,
    /// Recovered signing instruction sites.
    pub sign_sites: u64,
    /// Recovered authentication instruction sites.
    pub authenticate_sites: u64,
    /// Recovered authentication-stripping sites.
    pub strip_sites: u64,
    /// Recovered fused authenticated branches.
    pub authenticated_branches: u64,
    /// Recovered fused authenticated calls.
    pub authenticated_calls: u64,
    /// Recovered authenticated returns.
    pub authenticated_returns: u64,
}

/// Pointer inventory completion state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PacPointerInventoryStatus {
    /// No dyld pointer metadata was present.
    Absent,
    /// Every admitted pointer was retained.
    Complete,
    /// A bounded prefix was retained.
    Truncated,
}

/// Completeness receipt for one PAC report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacCompleteness {
    /// Pointer inventory status.
    pub pointer_status: PacPointerInventoryStatus,
    /// Total available dyld pointer count when known.
    pub available_pointers: u64,
    /// Retained pointer count.
    pub retained_pointers: u64,
    /// Executable bytes admitted for decoding.
    pub decoded_code_bytes: u64,
    /// Whether the executable-byte budget truncated scanning.
    pub code_truncated: bool,
    /// First executable address omitted by the byte budget.
    pub next_code_address: Option<u64>,
    /// Number of aligned instruction words that failed to decode.
    pub decode_gaps: u64,
}

/// Bounded PAC inventory for one selected Mach-O image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacIndex {
    /// Wire schema version.
    pub schema_version: u32,
    /// Qualified selected architecture name.
    pub architecture: String,
    /// Whether the selected CPU subtype is arm64e.
    pub arm64e: bool,
    /// Applied recovery limits.
    pub limits: PacAnalysisLimits,
    /// Aggregate counts.
    pub summary: PacSummary,
    /// Pointer map sorted by source address.
    pub pointers: Vec<PacPointerRecord>,
    /// PAC code sites sorted by instruction address.
    pub code_sites: Vec<PacCodeSite>,
    /// Completeness receipt.
    pub completeness: PacCompleteness,
}

impl PacIndex {
    /// Recover pointer and executable-code PAC evidence for one image.
    pub fn recover(
        macho: &MachoFile<'_>,
        limits: PacAnalysisLimits,
    ) -> Result<Self, PacAnalysisError> {
        let limits = limits.validate()?;
        if macho.header().cpu_type().0 != CPU_TYPE_ARM64 {
            return Err(PacAnalysisError::UnsupportedArchitecture(
                macho.header().arch_spec().name(),
            ));
        }

        let resolver = PointerResolver::new(macho)
            .map_err(|error| PacAnalysisError::PointerInventory(error.to_string()))?;
        let inventory = resolver
            .inventory(limits.max_pointers)
            .map_err(|error| PacAnalysisError::PointerInventory(error.to_string()))?;
        let (raw_pointers, pointer_status, available_pointers) = match inventory {
            PointerInventory::Absent => (Vec::new(), PacPointerInventoryStatus::Absent, 0),
            PointerInventory::Complete(pointers) => {
                let available = pointers.len() as u64;
                (pointers, PacPointerInventoryStatus::Complete, available)
            }
            PointerInventory::Truncated {
                pointers,
                available,
                ..
            } => (pointers, PacPointerInventoryStatus::Truncated, available),
        };
        let mut pointers = raw_pointers
            .into_iter()
            .map(|pointer| -> Result<_, PacAnalysisError> {
                let (segment, section) = location_names(macho, pointer.source_va.0);
                let stored_bytes = macho
                    .read_bytes_at(pointer.file_offset, usize::from(pointer.width))
                    .map_err(|error| PacAnalysisError::PointerInventory(error.to_string()))?
                    .to_vec();
                Ok(PacPointerRecord {
                    file_offset: pointer.file_offset.0,
                    address: pointer.source_va.0,
                    segment,
                    section,
                    width: pointer.width,
                    stored_bytes,
                    encoding: pointer.encoding.into(),
                    chained_pointer_format: pointer.chained_pointer_format,
                    legacy_bind_occurrences: pointer
                        .legacy_bind_occurrences
                        .into_iter()
                        .map(|occurrence| PacLegacyBindOccurrence {
                            stream: match occurrence.stream {
                                LegacyBindStream::Regular => PacLegacyBindStream::Regular,
                                LegacyBindStream::Weak => PacLegacyBindStream::Weak,
                                LegacyBindStream::Lazy => PacLegacyBindStream::Lazy,
                            },
                            bind_type: occurrence.bind_type,
                            library_ordinal: occurrence.library_ordinal,
                            weak: occurrence.weak,
                            symbol_flags: occurrence.symbol_flags,
                            addend: occurrence.addend,
                        })
                        .collect(),
                    legacy_rebase: pointer.legacy_rebase,
                    authentication: pointer.authentication.map_or(
                        PacPointerAuthentication::Plain,
                        |authentication| PacPointerAuthentication::Authenticated {
                            key: authentication.key.into(),
                            diversity: authentication.diversity,
                            address_diversity: authentication.address_diversity,
                        },
                    ),
                    target: project_target(pointer.target),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        pointers.sort_by_key(|pointer| pointer.address);

        let (mut code_sites, decoded_code_bytes, code_truncated, next_code_address, decode_gaps) =
            recover_code_sites(macho, limits.max_code_bytes);
        code_sites.sort_by_key(|site| site.address);
        let summary = summarize(&pointers, &code_sites);
        Ok(Self {
            schema_version: PAC_REPORT_SCHEMA_VERSION,
            architecture: macho.header().arch_spec().name(),
            arm64e: macho.header().arch_spec().is_arm64e(),
            limits,
            summary,
            completeness: PacCompleteness {
                pointer_status,
                available_pointers,
                retained_pointers: pointers.len() as u64,
                decoded_code_bytes,
                code_truncated,
                next_code_address,
                decode_gaps,
            },
            pointers,
            code_sites,
        })
    }
}

fn project_target(target: InventoryPointerTarget) -> PacPointerTarget {
    match target {
        InventoryPointerTarget::Null => PacPointerTarget::Null,
        InventoryPointerTarget::Address(address) => {
            PacPointerTarget::Internal { address: address.0 }
        }
        InventoryPointerTarget::Import {
            import_ordinal,
            name,
            library_ordinal,
            weak,
            import_addend,
            pointer_addend,
        } => PacPointerTarget::Import {
            import_ordinal,
            name,
            library_ordinal,
            weak,
            import_addend,
            pointer_addend,
        },
    }
}

fn location_names(macho: &MachoFile<'_>, address: u64) -> (Option<String>, Option<String>) {
    if let Some(section) = macho.all_sections().find(|section| {
        section.addr().0 <= address && address < section.addr().0.saturating_add(section.size())
    }) {
        return (
            Some(section.segment_name().to_string()),
            Some(section.section_name().to_string()),
        );
    }
    let segment = macho.segments().iter().find(|segment| {
        segment.vm_addr().0 <= address
            && address < segment.vm_addr().0.saturating_add(segment.vm_size())
    });
    (segment.map(|segment| segment.name().to_string()), None)
}

fn recover_code_sites(
    macho: &MachoFile<'_>,
    max_code_bytes: usize,
) -> (Vec<PacCodeSite>, u64, bool, Option<u64>, u64) {
    let mut sites = Vec::new();
    let mut remaining = max_code_bytes;
    let mut decoded = 0_u64;
    let mut truncated = false;
    let mut next_address = None;
    let mut gaps = 0_u64;
    for section in macho.all_sections().filter(|section| {
        section
            .attributes()
            .intersects(SectionAttributes::PURE_INSTRUCTIONS | SectionAttributes::SOME_INSTRUCTIONS)
    }) {
        let mut authenticated_registers = [None; 32];
        if remaining == 0 {
            truncated = true;
            next_address = Some(section.addr().0);
            break;
        }
        let admitted = usize::try_from(section.size())
            .unwrap_or(usize::MAX)
            .min(remaining);
        let admitted = admitted - admitted % 4;
        if admitted == 0 {
            if section.size() != 0 {
                truncated = true;
                next_address = Some(section.addr().0);
            }
            break;
        }
        let Ok(bytes) = macho.read_bytes_at(section.offset(), admitted) else {
            gaps = gaps.saturating_add((admitted / 4) as u64);
            remaining = remaining.saturating_sub(admitted);
            decoded = decoded.saturating_add(admitted as u64);
            continue;
        };
        for offset in (0..admitted).step_by(4) {
            let address = section.addr().0.saturating_add(offset as u64);
            let instruction_bytes = &bytes[offset..offset + 4];
            let word =
                u32::from_le_bytes(instruction_bytes.try_into().expect("four-byte instruction"));
            if word == 0xD503_201F {
                continue;
            }
            if !is_pac_scan_candidate(word) {
                authenticated_registers.fill(None);
                continue;
            }
            match decode_instruction(instruction_bytes, address, Arch::Arm64e) {
                Ok(instruction) => {
                    let classified = classify_site(word, &instruction);
                    if let Some((kind, key, target_register, modifier)) = classified {
                        sites.push(PacCodeSite {
                            address,
                            file_offset: section.offset().0.saturating_add(offset as u64),
                            segment: section.segment_name().to_string(),
                            section: section.section_name().to_string(),
                            kind,
                            key,
                            target_register,
                            modifier,
                            instruction: disassemble_one(instruction_bytes, address, Arch::Arm64e)
                                .unwrap_or_else(|_| format!(".inst 0x{word:08x}")),
                            evidence: PacCodeEvidence::ExecutableSectionDecode,
                            authentication_address: None,
                        });
                        if kind == PacCodeSiteKind::Authenticate
                            && let (Some(register), Some(key)) = (target_register, key)
                        {
                            authenticated_registers[usize::from(register)] =
                                Some((key, modifier, address));
                        }
                    } else if let Some(register) = transfer_register(&instruction)
                        && let Some((key, modifier, authentication_address)) =
                            authenticated_registers[usize::from(register)]
                    {
                        let kind = match instruction.kind {
                            InsnKind::Branch(_) => PacCodeSiteKind::AuthenticatedBranch,
                            InsnKind::Call(_) => PacCodeSiteKind::AuthenticatedCall,
                            InsnKind::Return => PacCodeSiteKind::AuthenticatedReturn,
                            _ => unreachable!("transfer_register admitted non-transfer"),
                        };
                        sites.push(PacCodeSite {
                            address,
                            file_offset: section.offset().0.saturating_add(offset as u64),
                            segment: section.segment_name().to_string(),
                            section: section.section_name().to_string(),
                            kind,
                            key: Some(key),
                            target_register: Some(register),
                            modifier,
                            instruction: disassemble_one(instruction_bytes, address, Arch::Arm64e)
                                .unwrap_or_else(|_| format!(".inst 0x{word:08x}")),
                            evidence: PacCodeEvidence::AuthenticateThenTransfer,
                            authentication_address: Some(authentication_address),
                        });
                    }

                    let control_flow_boundary = matches!(
                        instruction.kind,
                        InsnKind::Branch(_)
                            | InsnKind::Call(_)
                            | InsnKind::CondBranch(_)
                            | InsnKind::Return
                    );
                    let authentication =
                        matches!(classified, Some((PacCodeSiteKind::Authenticate, _, _, _)));
                    if control_flow_boundary
                        || (!authentication && instruction.kind != InsnKind::Nop)
                    {
                        // The compact instruction model exposes only the first
                        // written register. Clear every candidate across any
                        // non-NOP instruction so this evidence never assumes
                        // that an unrepresented secondary write was harmless.
                        authenticated_registers.fill(None);
                    }
                }
                Err(_) => {
                    gaps = gaps.saturating_add(1);
                    // A decode gap cannot prove that the authenticated value
                    // survived, so it is an evidence boundary.
                    authenticated_registers.fill(None);
                }
            }
        }
        remaining = remaining.saturating_sub(admitted);
        decoded = decoded.saturating_add(admitted as u64);
        if (admitted as u64) < section.size() {
            truncated = true;
            next_address = Some(section.addr().0.saturating_add(admitted as u64));
            break;
        }
    }
    (sites, decoded, truncated, next_address, gaps)
}

fn is_pac_scan_candidate(word: u32) -> bool {
    // All branch-register encodings (ordinary and authenticated), including
    // RET. Ordinary transfers are needed only to close a preceding AUT chain.
    if word & 0xFE00_0000 == 0xD600_0000 {
        return true;
    }
    if matches!(word, 0xD503_233F | 0xD503_237F | 0xD503_23BF | 0xD503_23FF) {
        return true;
    }
    if matches!(
        word & 0xFFFF_FC00,
        0xDAC1_0000
            | 0xDAC1_0400
            | 0xDAC1_0800
            | 0xDAC1_0C00
            | 0xDAC1_1000
            | 0xDAC1_1400
            | 0xDAC1_1800
            | 0xDAC1_1C00
    ) {
        return true;
    }
    matches!(
        word & 0xFFFF_FFE0,
        0xDAC1_23E0
            | 0xDAC1_27E0
            | 0xDAC1_2BE0
            | 0xDAC1_2FE0
            | 0xDAC1_33E0
            | 0xDAC1_37E0
            | 0xDAC1_3BE0
            | 0xDAC1_3FE0
            | 0xDAC1_43E0
            | 0xDAC1_47E0
    )
}

fn transfer_register(instruction: &Insn) -> Option<u8> {
    match instruction.kind {
        InsnKind::Branch(_) | InsnKind::Call(_) => {
            instruction.operands().first().and_then(operand_gpr)
        }
        InsnKind::Return => Some(30),
        _ => None,
    }
}

fn classify_site(
    word: u32,
    instruction: &Insn,
) -> Option<(PacCodeSiteKind, Option<PacKey>, Option<u8>, PacModifier)> {
    if word == 0xD65F_0BFF || word == 0xD65F_0FFF {
        return Some((
            PacCodeSiteKind::AuthenticatedReturn,
            Some(if word == 0xD65F_0BFF {
                PacKey::Ia
            } else {
                PacKey::Ib
            }),
            Some(30),
            PacModifier::StackPointer,
        ));
    }

    let authenticated_register_transfer = word & 0xFE00_0000 == 0xD600_0000
        && word & 0xFFFF_FC1F != 0xD61F_0000
        && word & 0xFFFF_FC1F != 0xD63F_0000;
    if authenticated_register_transfer {
        let kind = match instruction.kind {
            InsnKind::Branch(_) => PacCodeSiteKind::AuthenticatedBranch,
            InsnKind::Call(_) => PacCodeSiteKind::AuthenticatedCall,
            _ => return None,
        };
        let zero_modifier = word & 0x0100_0000 == 0;
        return Some((
            kind,
            Some(if ((word >> 10) & 1) == 0 {
                PacKey::Ia
            } else {
                PacKey::Ib
            }),
            instruction.operands().first().and_then(operand_gpr),
            if zero_modifier {
                PacModifier::Zero
            } else {
                instruction
                    .operands()
                    .get(1)
                    .and_then(operand_gpr)
                    .map_or(PacModifier::Unknown, |number| PacModifier::Register {
                        number,
                    })
            },
        ));
    }

    let (kind, key) = match instruction.value_effect {
        ValueEffect::SignPointerIa => (PacCodeSiteKind::Sign, Some(PacKey::Ia)),
        ValueEffect::SignPointerIb => (PacCodeSiteKind::Sign, Some(PacKey::Ib)),
        ValueEffect::SignPointerDa => (PacCodeSiteKind::Sign, Some(PacKey::Da)),
        ValueEffect::SignPointerDb => (PacCodeSiteKind::Sign, Some(PacKey::Db)),
        ValueEffect::AuthenticatePointerIa => (PacCodeSiteKind::Authenticate, Some(PacKey::Ia)),
        ValueEffect::AuthenticatePointerIb => (PacCodeSiteKind::Authenticate, Some(PacKey::Ib)),
        ValueEffect::AuthenticatePointerDa => (PacCodeSiteKind::Authenticate, Some(PacKey::Da)),
        ValueEffect::AuthenticatePointerDb => (PacCodeSiteKind::Authenticate, Some(PacKey::Db)),
        ValueEffect::StripPointerAuthentication => (PacCodeSiteKind::Strip, None),
        _ => return None,
    };
    let implicit_sp = matches!(word, 0xD503_233F | 0xD503_237F | 0xD503_23BF | 0xD503_23FF);
    let modifier = if kind == PacCodeSiteKind::Strip {
        PacModifier::Unknown
    } else if implicit_sp {
        PacModifier::StackPointer
    } else if is_zero_modifier_pac(word) {
        PacModifier::Zero
    } else {
        instruction
            .operands()
            .get(2)
            .and_then(operand_gpr)
            .map_or(PacModifier::Unknown, |number| PacModifier::Register {
                number,
            })
    };
    let target_register = if implicit_sp {
        Some(30)
    } else {
        instruction.operands().first().and_then(operand_gpr)
    };
    Some((kind, key, target_register, modifier))
}

fn is_zero_modifier_pac(word: u32) -> bool {
    matches!(
        word & 0xFFFF_FFE0,
        0xDAC1_23E0
            | 0xDAC1_27E0
            | 0xDAC1_2BE0
            | 0xDAC1_2FE0
            | 0xDAC1_33E0
            | 0xDAC1_37E0
            | 0xDAC1_3BE0
            | 0xDAC1_3FE0
    )
}

fn operand_gpr(operand: &Operand) -> Option<u8> {
    match operand {
        Operand::Reg(register) if register.class == RegClass::Gpr => Some(register.num),
        _ => None,
    }
}

fn summarize(pointers: &[PacPointerRecord], sites: &[PacCodeSite]) -> PacSummary {
    let authenticated_pointers = pointers
        .iter()
        .filter(|pointer| {
            matches!(
                pointer.authentication,
                PacPointerAuthentication::Authenticated { .. }
            )
        })
        .count() as u64;
    let plain_pointers = pointers.len() as u64 - authenticated_pointers;
    let address_diverse_pointers = pointers
        .iter()
        .filter(|pointer| {
            matches!(
                pointer.authentication,
                PacPointerAuthentication::Authenticated {
                    address_diversity: true,
                    ..
                }
            )
        })
        .count() as u64;
    let mut key_counts = std::collections::BTreeMap::<PacKey, u64>::new();
    let mut diversity_counts = std::collections::BTreeMap::<(PacKey, u16, bool), u64>::new();
    for pointer in pointers {
        if let PacPointerAuthentication::Authenticated {
            key,
            diversity,
            address_diversity,
        } = pointer.authentication
        {
            *key_counts.entry(key).or_default() += 1;
            *diversity_counts
                .entry((key, diversity, address_diversity))
                .or_default() += 1;
        }
    }
    let count_sites = |kind| sites.iter().filter(|site| site.kind == kind).count() as u64;
    let mut code_key_counts = std::collections::BTreeMap::<PacKey, u64>::new();
    for site in sites {
        if let Some(key) = site.key {
            *code_key_counts.entry(key).or_default() += 1;
        }
    }
    PacSummary {
        authenticated_pointers,
        plain_pointers,
        address_diverse_pointers,
        pointer_keys: key_counts
            .into_iter()
            .map(|(key, count)| PacKeyCount { key, count })
            .collect(),
        pointer_diversities: diversity_counts
            .into_iter()
            .map(
                |((key, diversity, address_diversity), count)| PacDiversityCount {
                    key,
                    diversity,
                    address_diversity,
                    count,
                },
            )
            .collect(),
        code_keys: code_key_counts
            .into_iter()
            .map(|(key, count)| PacKeyCount { key, count })
            .collect(),
        sign_sites: count_sites(PacCodeSiteKind::Sign),
        authenticate_sites: count_sites(PacCodeSiteKind::Authenticate),
        strip_sites: count_sites(PacCodeSiteKind::Strip),
        authenticated_branches: count_sites(PacCodeSiteKind::AuthenticatedBranch),
        authenticated_calls: count_sites(PacCodeSiteKind::AuthenticatedCall),
        authenticated_returns: count_sites(PacCodeSiteKind::AuthenticatedReturn),
    }
}

/// Jump form selected by a function-entry detour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PacDetourEncoding {
    /// A direct AArch64 `B` immediate.
    DirectBranch,
    /// A raw literal load followed by ordinary register `BR`.
    PlainIndirectLiteral,
    /// An address assembled exclusively from instruction immediates before
    /// ordinary register `BR`.
    MaterializedAddress,
}

/// Branch Target Identification landing-pad class at a function entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PacBtiKind {
    /// Generic BTI landing pad.
    Generic,
    /// Call-compatible landing pad.
    Call,
    /// Jump-compatible landing pad.
    Jump,
    /// Call- and jump-compatible landing pad.
    CallOrJump,
}

/// Bounded entry contract used by detour compatibility analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacEntryContract {
    /// Entry address inspected.
    pub address: u64,
    /// BTI landing-pad class, when present as the first instruction.
    pub bti: Option<PacBtiKind>,
    /// Key used to sign the return address with SP in the inspected prologue.
    pub return_address_key: Option<PacKey>,
    /// Number of complete entry instructions inspected.
    pub examined_instructions: u8,
    /// Whether every instruction in the bounded entry window was readable and
    /// decodable.
    pub complete: bool,
}

/// Exact transfer mechanism selected by the executable patch planner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacDetourMechanism {
    /// Branch encoding used after any preserved landing pad.
    pub encoding: PacDetourEncoding,
    /// Whether an existing entry BTI instruction remains the first instruction.
    pub preserves_entry_bti: bool,
}

/// Explicit evidence bounds for PAC patch assessment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacPatchLimits {
    /// Maximum dyld-managed pointers inspected for references to the entry.
    pub max_pointers: u64,
}

impl Default for PacPatchLimits {
    fn default() -> Self {
        Self {
            max_pointers: 16_000_000,
        }
    }
}

/// Overall PAC compatibility of one detour plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PacPatchVerdict {
    /// The observed patch mechanism is PAC-neutral.
    Compatible,
    /// The patch is expected to execute but weakens authenticated control flow.
    DegradesProtection,
    /// Recovered evidence proves the patch is PAC-incompatible.
    Incompatible,
    /// Available evidence is insufficient for a compatibility claim.
    Indeterminate,
}

/// Severity of one PAC patch finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PacFindingSeverity {
    /// Context that does not change the verdict.
    Info,
    /// Security protection is weakened or evidence is incomplete.
    Warning,
    /// Recovered evidence proves incompatibility.
    Error,
}

/// One stable PAC patch-planning diagnostic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacPatchFinding {
    /// Stable machine-readable finding code.
    pub code: String,
    /// Finding severity.
    pub severity: PacFindingSeverity,
    /// Human-readable explanation.
    pub message: String,
    /// Address supplying the evidence, when applicable.
    pub evidence_address: Option<u64>,
}

/// PAC assessment attached to one arm64e detour preview.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacDetourAssessment {
    /// Overall compatibility verdict.
    pub verdict: PacPatchVerdict,
    /// Recovered source-entry contract.
    pub source_contract: PacEntryContract,
    /// Recovered destination-entry contract.
    pub destination_contract: PacEntryContract,
    /// Planner mechanism being assessed.
    pub mechanism: PacDetourMechanism,
    /// Evidence bounds applied to this assessment.
    pub limits: PacPatchLimits,
    /// Stable evidence-backed findings.
    pub findings: Vec<PacPatchFinding>,
}

impl PacDetourAssessment {
    /// Whether strict PAC policy should admit this detour.
    pub const fn is_compatible(&self) -> bool {
        matches!(self.verdict, PacPatchVerdict::Compatible)
    }
}

/// Assess the PAC consequences of one already-encoded arm64e entry detour.
pub fn assess_detour(
    macho: &MachoFile<'_>,
    entry_va: u64,
    destination_va: u64,
    overwrite_len: usize,
    mechanism: PacDetourMechanism,
    limits: PacPatchLimits,
) -> PacDetourAssessment {
    let mut verdict = PacPatchVerdict::Compatible;
    let mut findings = Vec::new();
    let source_contract = recover_entry_contract(macho, entry_va);
    let destination_contract = recover_entry_contract(macho, destination_va);

    if source_contract.bti.is_some() && !mechanism.preserves_entry_bti {
        elevate_verdict(&mut verdict, PacPatchVerdict::Incompatible);
        findings.push(PacPatchFinding {
            code: "pac.detour.entry_bti_removed".into(),
            severity: PacFindingSeverity::Error,
            message: "detour removes the function's indirect-branch landing pad".into(),
            evidence_address: Some(entry_va),
        });
    }

    if mechanism.encoding == PacDetourEncoding::PlainIndirectLiteral {
        elevate_verdict(&mut verdict, PacPatchVerdict::DegradesProtection);
        findings.push(PacPatchFinding {
            code: "pac.detour.unsigned_indirect_veneer".into(),
            severity: PacFindingSeverity::Warning,
            message: format!(
                "far detour to {destination_va:#x} loads a raw code address and transfers with unauthenticated BR"
            ),
            evidence_address: Some(entry_va),
        });
    }
    if mechanism.encoding == PacDetourEncoding::MaterializedAddress {
        findings.push(PacPatchFinding {
            code: "pac.detour.address_materialized_from_immediates".into(),
            severity: PacFindingSeverity::Info,
            message: "far detour materializes its destination from instruction immediates instead of introducing a plain pointer literal".into(),
            evidence_address: Some(entry_va),
        });
    }

    if matches!(
        mechanism.encoding,
        PacDetourEncoding::PlainIndirectLiteral | PacDetourEncoding::MaterializedAddress
    ) && !matches!(
        destination_contract.bti,
        Some(PacBtiKind::Jump | PacBtiKind::CallOrJump)
    ) {
        elevate_verdict(&mut verdict, PacPatchVerdict::Indeterminate);
        findings.push(PacPatchFinding {
            code: "pac.detour.indirect_destination_bti_unproven".into(),
            severity: PacFindingSeverity::Warning,
            message: "far detour ends in an indirect branch, but the destination does not expose a jump-compatible BTI landing pad".into(),
            evidence_address: Some(destination_va),
        });
    }

    if source_contract.return_address_key.is_some()
        && destination_contract.return_address_key.is_none()
    {
        let finding = if destination_contract.complete {
            (
                PacPatchVerdict::DegradesProtection,
                PacFindingSeverity::Warning,
            )
        } else {
            (PacPatchVerdict::Indeterminate, PacFindingSeverity::Warning)
        };
        elevate_verdict(&mut verdict, finding.0);
        findings.push(PacPatchFinding {
            code: "pac.detour.return_address_contract_not_preserved".into(),
            severity: finding.1,
            message: "source prologue signs the return address with SP, but no equivalent destination prologue contract was recovered".into(),
            evidence_address: Some(destination_va),
        });
    }

    if let Ok(bytes) = macho.read_bytes_at_va(Va(entry_va), overwrite_len) {
        let mut disassembler = Disassembler::new(Arch::Arm64e);
        for offset in (0..bytes.len().saturating_sub(3)).step_by(4) {
            let address = entry_va.saturating_add(offset as u64);
            let word = u32::from_le_bytes(
                bytes[offset..offset + 4]
                    .try_into()
                    .expect("four-byte instruction"),
            );
            if let Ok(decoded) = disassembler.decode_one(&bytes[offset..], address)
                && classify_site(word, &decoded.instruction).is_some()
            {
                findings.push(PacPatchFinding {
                    code: "pac.detour.entry_contract_replaced".into(),
                    severity: PacFindingSeverity::Info,
                    message: format!(
                        "detour replaces PAC-related entry instruction `{}`",
                        decoded.text
                    ),
                    evidence_address: Some(address),
                });
            }
        }
    }

    match PointerResolver::new(macho).and_then(|resolver| resolver.inventory(limits.max_pointers)) {
        Ok(inventory) => {
            let (pointers, truncated) = match inventory {
                PointerInventory::Absent => (Vec::new(), false),
                PointerInventory::Complete(pointers) => (pointers, false),
                PointerInventory::Truncated { pointers, .. } => (pointers, true),
            };
            for pointer in pointers {
                let targets_entry = matches!(
                    pointer.target,
                    InventoryPointerTarget::Address(address) if address.0 == entry_va
                );
                if targets_entry && pointer.authentication.is_some() {
                    findings.push(PacPatchFinding {
                        code: "pac.detour.authenticated_entry_redirected".into(),
                        severity: PacFindingSeverity::Info,
                        message: "an authenticated pointer continues to validate the original entry before the preserved code entry redirects control".into(),
                        evidence_address: Some(pointer.source_va.0),
                    });
                }
            }
            if truncated {
                elevate_verdict(&mut verdict, PacPatchVerdict::Indeterminate);
                findings.push(PacPatchFinding {
                    code: "pac.detour.pointer_inventory_truncated".into(),
                    severity: PacFindingSeverity::Warning,
                    message: "authenticated-pointer inventory was truncated before every entry reference could be checked".into(),
                    evidence_address: None,
                });
            }
        }
        Err(error) => {
            elevate_verdict(&mut verdict, PacPatchVerdict::Indeterminate);
            findings.push(PacPatchFinding {
                code: "pac.detour.pointer_inventory_failed".into(),
                severity: PacFindingSeverity::Warning,
                message: format!("authenticated-pointer inventory failed: {error}"),
                evidence_address: None,
            });
        }
    }

    findings.sort_by_key(|finding| (finding.evidence_address, finding.code.clone()));
    PacDetourAssessment {
        verdict,
        source_contract,
        destination_contract,
        mechanism,
        limits,
        findings,
    }
}

fn elevate_verdict(verdict: &mut PacPatchVerdict, candidate: PacPatchVerdict) {
    let rank = |value| match value {
        PacPatchVerdict::Compatible => 0,
        PacPatchVerdict::DegradesProtection => 1,
        PacPatchVerdict::Indeterminate => 2,
        PacPatchVerdict::Incompatible => 3,
    };
    if rank(candidate) > rank(*verdict) {
        *verdict = candidate;
    }
}

fn recover_entry_contract(macho: &MachoFile<'_>, address: u64) -> PacEntryContract {
    const MAX_INSTRUCTIONS: u8 = 4;
    let mut contract = PacEntryContract {
        address,
        bti: None,
        return_address_key: None,
        examined_instructions: 0,
        complete: true,
    };
    let mut disassembler = Disassembler::new(Arch::Arm64e);
    for index in 0..MAX_INSTRUCTIONS {
        let instruction_address = address.saturating_add(u64::from(index) * 4);
        let Ok(bytes) = macho.read_bytes_at_va(Va(instruction_address), 4) else {
            contract.complete = false;
            break;
        };
        let word = u32::from_le_bytes(bytes.try_into().expect("four-byte instruction"));
        let Ok(decoded) = disassembler.decode_one(bytes, instruction_address) else {
            contract.complete = false;
            break;
        };
        contract.examined_instructions += 1;
        if index == 0 {
            contract.bti = match word {
                0xD503_241F => Some(PacBtiKind::Generic),
                0xD503_245F => Some(PacBtiKind::Call),
                0xD503_249F => Some(PacBtiKind::Jump),
                0xD503_24DF => Some(PacBtiKind::CallOrJump),
                _ => None,
            };
        }
        if let Some((PacCodeSiteKind::Sign, key, _, PacModifier::StackPointer)) =
            classify_site(word, &decoded.instruction)
        {
            contract.return_address_key = key;
        }
        if !matches!(decoded.instruction.kind, InsnKind::Other | InsnKind::Nop) {
            break;
        }
    }
    contract
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovers_sign_authenticated_call_and_return_sites() {
        let mut bytes = macho_test_support::disassembly_arm64e();
        bytes[0x100..0x104].copy_from_slice(&0xD503_233Fu32.to_le_bytes());
        bytes[0x104..0x108].copy_from_slice(&0xD73F_0B21u32.to_le_bytes());
        bytes[0x108..0x10c].copy_from_slice(&0xD65F_0BFFu32.to_le_bytes());
        let container = crate::core::parse(&bytes).unwrap();
        let report = PacIndex::recover(
            container.first_macho().unwrap(),
            PacAnalysisLimits::default(),
        )
        .unwrap();
        assert_eq!(report.summary.sign_sites, 1);
        assert_eq!(report.summary.authenticated_calls, 1);
        assert_eq!(report.summary.authenticated_returns, 1);
        assert_eq!(
            report.completeness.pointer_status,
            PacPointerInventoryStatus::Absent
        );
    }

    #[test]
    fn recovers_separate_authenticate_then_branch_gadget() {
        let mut bytes = macho_test_support::disassembly_arm64e();
        bytes[0x100..0x104].copy_from_slice(&0xDAC1_10A4_u32.to_le_bytes()); // autia x4, x5
        bytes[0x104..0x108].copy_from_slice(&0xD503_201F_u32.to_le_bytes()); // nop
        bytes[0x108..0x10c].copy_from_slice(&0xD61F_0080_u32.to_le_bytes()); // br x4
        let container = crate::core::parse(&bytes).unwrap();
        let report = PacIndex::recover(
            container.first_macho().unwrap(),
            PacAnalysisLimits::default(),
        )
        .unwrap();
        assert_eq!(report.summary.authenticate_sites, 1);
        assert_eq!(report.summary.authenticated_branches, 1);
        let transfer = report
            .code_sites
            .iter()
            .find(|site| site.kind == PacCodeSiteKind::AuthenticatedBranch)
            .unwrap();
        assert_eq!(transfer.key, Some(PacKey::Ia));
        assert_eq!(transfer.target_register, Some(4));
        assert_eq!(transfer.modifier, PacModifier::Register { number: 5 });
        assert_eq!(transfer.authentication_address, Some(0x1_0000_0100));
        assert_eq!(transfer.evidence, PacCodeEvidence::AuthenticateThenTransfer);
    }

    #[test]
    fn separate_authentication_evidence_stops_at_non_nop_instructions() {
        let mut bytes = macho_test_support::disassembly_arm64e();
        bytes[0x100..0x104].copy_from_slice(&0xDAC1_10A4_u32.to_le_bytes()); // autia x4, x5
        bytes[0x104..0x108].copy_from_slice(&0xD280_0000_u32.to_le_bytes()); // movz x0, #0
        bytes[0x108..0x10c].copy_from_slice(&0xD61F_0080_u32.to_le_bytes()); // br x4
        let container = crate::core::parse(&bytes).unwrap();
        let report = PacIndex::recover(
            container.first_macho().unwrap(),
            PacAnalysisLimits::default(),
        )
        .unwrap();
        assert_eq!(report.summary.authenticate_sites, 1);
        assert_eq!(report.summary.authenticated_branches, 0);
    }

    #[test]
    fn recognizes_every_zero_modifier_pac_key_form() {
        for word in [
            0xDAC1_23E4_u32,
            0xDAC1_27E4,
            0xDAC1_2BE4,
            0xDAC1_2FE4,
            0xDAC1_33E4,
            0xDAC1_37E4,
            0xDAC1_3BE4,
            0xDAC1_3FE4,
        ] {
            let decoded = crate::insn::decode_one(&word.to_le_bytes(), 0x1000, Arch::Arm64e)
                .expect("PAC zero-modifier instruction");
            let (_, _, target, modifier) =
                classify_site(word, &decoded).expect("classified PAC instruction");
            assert_eq!(target, Some(4), "word {word:#010x}");
            assert_eq!(modifier, PacModifier::Zero, "word {word:#010x}");
        }
    }

    #[test]
    fn scan_prefilter_admits_pac_and_register_transfer_families() {
        for word in [
            0xD503_233F_u32, // paciasp
            0xD503_23FF,     // autibsp
            0xDAC1_0020,     // pacia x0, x1
            0xDAC1_1F7A,     // autdb x26, x27
            0xDAC1_23E4,     // paciza x4
            0xDAC1_47E4,     // xpaci x4
            0xD61F_0080,     // br x4
            0xD63F_0080,     // blr x4
            0xD71F_0880,     // braa x4, x8
            0xD73F_0880,     // blraa x4, x8
            0xD65F_03C0,     // ret
            0xD65F_0BFF,     // retaa
        ] {
            assert!(is_pac_scan_candidate(word), "word {word:#010x}");
        }
        for word in [
            0xD503_201F_u32, // nop has its own fast path
            0xD280_0000,     // movz x0, #0
            0x1400_0001,     // b +4
        ] {
            assert!(!is_pac_scan_candidate(word), "word {word:#010x}");
        }
    }

    #[test]
    fn plain_indirect_detour_is_reported_as_degrading() {
        let mut bytes = macho_test_support::disassembly_arm64e();
        bytes[0x104..0x108].copy_from_slice(&0xD503_249F_u32.to_le_bytes());
        let container = crate::core::parse(&bytes).unwrap();
        let assessment = assess_detour(
            container.first_macho().unwrap(),
            0x1_0000_0100,
            0x1_0000_0104,
            4,
            PacDetourMechanism {
                encoding: PacDetourEncoding::PlainIndirectLiteral,
                preserves_entry_bti: false,
            },
            PacPatchLimits::default(),
        );
        assert_eq!(assessment.verdict, PacPatchVerdict::DegradesProtection);
        assert!(
            assessment
                .findings
                .iter()
                .any(|finding| { finding.code == "pac.detour.unsigned_indirect_veneer" })
        );
    }

    #[test]
    fn summarizes_exact_key_and_diversity_forms() {
        let pointer = |address, authentication| PacPointerRecord {
            file_offset: address,
            address,
            segment: Some("__DATA_CONST".into()),
            section: None,
            width: 8,
            stored_bytes: vec![0; 8],
            encoding: PacPointerEncoding::ChainedRebase,
            chained_pointer_format: Some(1),
            legacy_bind_occurrences: Vec::new(),
            legacy_rebase: false,
            authentication,
            target: PacPointerTarget::Null,
        };
        let authentication = PacPointerAuthentication::Authenticated {
            key: PacKey::Da,
            diversity: 0x1234,
            address_diversity: true,
        };
        let summary = summarize(
            &[
                pointer(0x1000, authentication),
                pointer(0x1008, authentication),
                pointer(0x1010, PacPointerAuthentication::Plain),
            ],
            &[],
        );
        assert_eq!(
            summary.pointer_keys,
            vec![PacKeyCount {
                key: PacKey::Da,
                count: 2
            }]
        );
        assert_eq!(
            summary.pointer_diversities,
            vec![PacDiversityCount {
                key: PacKey::Da,
                diversity: 0x1234,
                address_diversity: true,
                count: 2,
            }]
        );
    }
}
