//! Fail-closed pointer resolution with retained encoding provenance.

use std::collections::BTreeMap;

use macho_core::MachoFile;
use macho_core::model::addr::{ThinFileOffset, Va};
use macho_core::model::load_command::LoadCommand;

use crate::error::{Error, Result};
use crate::types::FixupKind;

/// On-disk mechanism that supplies a pointer target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PointerEncoding {
    /// Ordinary pointer bytes with no dyld record.
    Direct,
    /// Chained-fixup rebase.
    ChainedRebase,
    /// Chained-fixup bind.
    ChainedBind,
    /// Legacy rebase opcode.
    LegacyRebase,
    /// Legacy bind opcode.
    LegacyBind,
}

/// Authentication metadata retained from an authenticated chained pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PointerAuthentication {
    /// Pointer-auth diversity value.
    pub diversity: u16,
    /// Pointer-auth key selector.
    pub key: u8,
    /// Whether the pointer address participates in diversity.
    pub address_diversity: bool,
}

/// Semantic target of a pointer-valued field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PointerTarget {
    /// Null pointer.
    Null,
    /// Address within the selected image.
    Address(Va),
    /// Imported symbol.
    Import {
        /// Symbol name.
        name: String,
        /// Dynamic-library ordinal when represented by the encoding.
        library_ordinal: Option<i32>,
    },
}

/// One resolved pointer with exact source bytes and provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PointerObservation {
    /// Thin-file offset of the pointer field.
    pub file_offset: ThinFileOffset,
    /// Virtual address of the pointer field.
    pub source_va: Va,
    /// Raw bytes exactly as stored in the image.
    pub raw: Vec<u8>,
    /// Endian-correct unsigned value represented by the stored pointer bytes.
    pub stored_value: u64,
    /// On-disk pointer mechanism.
    pub encoding: PointerEncoding,
    /// Authentication metadata, when present.
    pub authentication: Option<PointerAuthentication>,
    /// Resolved semantic target.
    pub target: PointerTarget,
}

#[derive(Debug, Clone)]
struct FixupEvidence {
    encoding: PointerEncoding,
    authentication: Option<PointerAuthentication>,
    target: PointerTarget,
}

/// Fail-closed resolver shared by language metadata decoders.
pub struct PointerResolver<'image, 'data> {
    image: &'image MachoFile<'data>,
    fixups: BTreeMap<u64, FixupEvidence>,
}

impl<'image, 'data> PointerResolver<'image, 'data> {
    /// Build the complete pointer-evidence map for one selected image.
    pub fn new(image: &'image MachoFile<'data>) -> Result<Self> {
        let has_chained = image
            .find_load_command(|command| matches!(command, LoadCommand::DyldChainedFixups(_)))
            .is_some();
        let has_legacy = image
            .find_load_command(|command| {
                matches!(
                    command,
                    LoadCommand::DyldInfo(_) | LoadCommand::DyldInfoOnly(_)
                )
            })
            .is_some();
        let fixups = if has_chained {
            chained_evidence(image)?
        } else if has_legacy {
            legacy_evidence(image)?
        } else {
            BTreeMap::new()
        };
        Ok(Self { image, fixups })
    }

    /// Resolve a pointer field identified by virtual address.
    pub fn observe_at_va(&self, source_va: Va) -> Result<PointerObservation> {
        let file_offset = self.image.address_map().va_to_thin_offset(source_va)?;
        self.observe(file_offset, source_va)
    }

    /// Resolve a pointer field identified by thin-file offset.
    pub fn observe_at_offset(&self, file_offset: ThinFileOffset) -> Result<PointerObservation> {
        let source_va = self.image.address_map().thin_offset_to_va(file_offset)?;
        self.observe(file_offset, source_va)
    }

    fn observe(&self, file_offset: ThinFileOffset, source_va: Va) -> Result<PointerObservation> {
        let width = if self.image.is_64bit() { 8 } else { 4 };
        let raw = self.image.read_bytes_at(file_offset, width)?.to_vec();
        let stored_value = stored_pointer_value(self.image, &raw);
        if let Some(evidence) = self.fixups.get(&file_offset.0) {
            let target = match (&evidence.encoding, &evidence.target) {
                (PointerEncoding::LegacyRebase, PointerTarget::Address(_)) => {
                    direct_target(self.image, &raw)
                }
                _ => evidence.target.clone(),
            };
            return Ok(PointerObservation {
                file_offset,
                source_va,
                raw,
                stored_value,
                encoding: evidence.encoding,
                authentication: evidence.authentication,
                target,
            });
        }
        Ok(PointerObservation {
            file_offset,
            source_va,
            target: direct_target(self.image, &raw),
            raw,
            stored_value,
            encoding: PointerEncoding::Direct,
            authentication: None,
        })
    }
}

fn direct_target(image: &MachoFile<'_>, raw: &[u8]) -> PointerTarget {
    let value = stored_pointer_value(image, raw);
    if value == 0 {
        PointerTarget::Null
    } else {
        PointerTarget::Address(Va(value))
    }
}

fn stored_pointer_value(image: &MachoFile<'_>, raw: &[u8]) -> u64 {
    if image.is_64bit() {
        image
            .endian()
            .read_u64(raw.try_into().expect("validated pointer width"))
    } else {
        u64::from(
            image
                .endian()
                .read_u32(raw.try_into().expect("validated pointer width")),
        )
    }
}

fn chained_evidence(image: &MachoFile<'_>) -> Result<BTreeMap<u64, FixupEvidence>> {
    let decoded = crate::chained::parse_chained_fixups(image)?;
    let mut evidence = BTreeMap::new();
    for fixup in decoded.fixups {
        let segment = image.segments().get(fixup.segment_index).ok_or_else(|| {
            Error::format(format!(
                "chained fixup references absent segment {}",
                fixup.segment_index
            ))
        })?;
        let file_offset = segment
            .file_offset()
            .0
            .checked_add(fixup.segment_offset)
            .ok_or_else(|| Error::address("chained-fixup file offset overflows"))?;
        let item = match fixup.kind {
            FixupKind::Rebase { target } => FixupEvidence {
                encoding: PointerEncoding::ChainedRebase,
                authentication: None,
                target: rebased_target(image, target)?,
            },
            FixupKind::AuthRebase {
                target,
                diversity,
                key,
                addr_div,
            } => FixupEvidence {
                encoding: PointerEncoding::ChainedRebase,
                authentication: Some(PointerAuthentication {
                    diversity,
                    key,
                    address_diversity: addr_div,
                }),
                target: rebased_target(image, target)?,
            },
            FixupKind::Bind { import_index, .. } => FixupEvidence {
                encoding: PointerEncoding::ChainedBind,
                authentication: None,
                target: chained_import(&decoded.imports, import_index)?,
            },
            FixupKind::AuthBind {
                import_index,
                diversity,
                key,
                addr_div,
            } => FixupEvidence {
                encoding: PointerEncoding::ChainedBind,
                authentication: Some(PointerAuthentication {
                    diversity,
                    key,
                    address_diversity: addr_div,
                }),
                target: chained_import(&decoded.imports, import_index)?,
            },
        };
        if evidence.insert(file_offset, item).is_some() {
            return Err(Error::format("duplicate chained-fixup file offset"));
        }
    }
    Ok(evidence)
}

fn rebased_target(image: &MachoFile<'_>, target: u64) -> Result<PointerTarget> {
    image
        .image_base()
        .0
        .checked_add(target)
        .map(Va)
        .map(PointerTarget::Address)
        .ok_or_else(|| Error::address("chained rebase target overflows"))
}

fn chained_import(
    imports: &[crate::types::ChainedImport<'_>],
    index: u32,
) -> Result<PointerTarget> {
    let import = imports
        .get(index as usize)
        .ok_or_else(|| Error::format(format!("chained bind references absent import {index}")))?;
    Ok(PointerTarget::Import {
        name: import.name.to_string(),
        library_ordinal: Some(import.lib_ordinal),
    })
}

fn legacy_evidence(image: &MachoFile<'_>) -> Result<BTreeMap<u64, FixupEvidence>> {
    let mut evidence = BTreeMap::new();
    let (regular, weak, lazy) = crate::bind::parse_bind_entries(image)?;
    for bind in regular.iter().chain(weak.iter()).chain(lazy.iter()) {
        let segment = image.segments().get(bind.segment_index).ok_or_else(|| {
            Error::format(format!(
                "legacy bind references absent segment {}",
                bind.segment_index
            ))
        })?;
        let file_offset = segment
            .file_offset()
            .0
            .checked_add(bind.segment_offset)
            .ok_or_else(|| Error::address("legacy bind file offset overflows"))?;
        let ordinal = i32::try_from(bind.lib_ordinal).ok();
        if evidence
            .insert(
                file_offset,
                FixupEvidence {
                    encoding: PointerEncoding::LegacyBind,
                    authentication: None,
                    target: PointerTarget::Import {
                        name: bind.symbol_name.to_string(),
                        library_ordinal: ordinal,
                    },
                },
            )
            .is_some()
        {
            return Err(Error::format("duplicate legacy bind file offset"));
        }
    }
    for rebase in crate::rebase::parse_rebase_entries(image)? {
        let segment = image.segments().get(rebase.segment_index).ok_or_else(|| {
            Error::format(format!(
                "legacy rebase references absent segment {}",
                rebase.segment_index
            ))
        })?;
        let file_offset = segment
            .file_offset()
            .0
            .checked_add(rebase.segment_offset)
            .ok_or_else(|| Error::address("legacy rebase file offset overflows"))?;
        evidence.entry(file_offset).or_insert(FixupEvidence {
            encoding: PointerEncoding::LegacyRebase,
            authentication: None,
            target: PointerTarget::Address(Va(0)),
        });
    }
    Ok(evidence)
}
