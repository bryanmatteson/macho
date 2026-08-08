//! Fail-closed pointer resolution with retained encoding provenance.

use std::collections::BTreeMap;

use crate::core::MachoFile;
use crate::core::model::addr::{ThinFileOffset, Va};
use crate::core::model::load_command::LoadCommand;

use crate::metadata::dyld::error::{Error, Result};
use crate::metadata::dyld::types::FixupKind;

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

/// Legacy dyld opcode stream that supplied a bind occurrence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LegacyBindStream {
    /// Regular bind stream.
    Regular,
    /// Weak bind stream.
    Weak,
    /// Lazy bind stream.
    Lazy,
}

/// One retained legacy-bind occurrence for a pointer field.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct LegacyBindOccurrence {
    /// Source opcode stream.
    pub stream: LegacyBindStream,
    /// Dyld bind type.
    pub bind_type: u8,
    /// Dynamic-library ordinal carried by this stream.
    pub library_ordinal: i32,
    /// Whether this occurrence carries the weak-import flag.
    pub weak: bool,
    /// Raw symbol flags carried by this occurrence.
    pub symbol_flags: u8,
    /// Bind addend.
    pub addend: i64,
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

/// Lossless semantic target in a dyld-managed pointer inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InventoryPointerTarget {
    /// Null pointer.
    Null,
    /// Address within the selected image.
    Address(Va),
    /// Imported symbol with both table and pointer-level addends retained.
    Import {
        /// Chained-import ordinal; absent for legacy binds.
        import_ordinal: Option<u32>,
        /// Imported symbol name.
        name: String,
        /// Unique dynamic-library ordinal, or `None` when compatible legacy
        /// streams disagree and the occurrences retain their exact values.
        library_ordinal: Option<i32>,
        /// Unique weak flag, or `None` when compatible legacy occurrences differ.
        weak: Option<bool>,
        /// Addend encoded in the chained import table.
        import_addend: i64,
        /// Addend encoded in the pointer or legacy bind stream.
        pointer_addend: i64,
    },
}

/// One complete dyld-managed pointer fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DyldPointer {
    /// Thin-file offset of the pointer field.
    pub file_offset: ThinFileOffset,
    /// Unslid virtual address of the pointer field.
    pub source_va: Va,
    /// Pointer width in bytes.
    pub width: u8,
    /// On-disk pointer mechanism.
    pub encoding: PointerEncoding,
    /// Raw chained-pointer format, when applicable.
    pub chained_pointer_format: Option<u16>,
    /// Authentication metadata, when applicable.
    pub authentication: Option<PointerAuthentication>,
    /// Exact regular/weak/lazy bind occurrences, empty for non-legacy pointers.
    pub legacy_bind_occurrences: Vec<LegacyBindOccurrence>,
    /// Whether the legacy rebase stream also covers this pointer field.
    ///
    /// Lazy symbol pointers and internal weak definitions can legitimately
    /// carry both a rebase and a bind at the same file offset. In that case
    /// [`Self::encoding`] remains [`PointerEncoding::LegacyBind`] while this
    /// flag retains the rebase occurrence.
    pub legacy_rebase: bool,
    /// Semantic pointer target.
    pub target: InventoryPointerTarget,
}

/// Continuation coordinate for a bounded pointer inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PointerInventoryContinuation {
    /// Thin-file offset of the first omitted pointer.
    pub next_file_offset: ThinFileOffset,
    /// Virtual address of the first omitted pointer.
    pub next_source_va: Va,
}

/// Explicit state of a bounded dyld-managed pointer inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PointerInventory {
    /// No chained-fixup or legacy dyld metadata is present.
    Absent,
    /// Every admitted pointer was retained.
    Complete(Vec<DyldPointer>),
    /// A deterministic file-offset-ordered prefix was retained.
    Truncated {
        /// Retained prefix.
        pointers: Vec<DyldPointer>,
        /// Total admitted pointer count.
        available: u64,
        /// Exact first omitted coordinate.
        continuation: PointerInventoryContinuation,
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct FixupEvidence {
    encoding: PointerEncoding,
    chained_pointer_format: Option<u16>,
    authentication: Option<PointerAuthentication>,
    target: InventoryPointerTarget,
    legacy_bind_occurrences: Vec<LegacyBindOccurrence>,
    legacy_rebase_type: Option<u8>,
}

/// Fail-closed resolver shared by language metadata decoders.
pub struct PointerResolver<'image, 'data> {
    image: &'image MachoFile<'data>,
    fixups: BTreeMap<u64, FixupEvidence>,
    has_dyld_metadata: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PointerInventorySelection {
    All,
    LegacyBinds,
    LegacyRebases,
}

impl<'image, 'data> PointerResolver<'image, 'data> {
    /// Build the complete pointer-evidence map for one selected image.
    pub fn new(image: &'image MachoFile<'data>) -> Result<Self> {
        let chained_commands = image
            .load_commands()
            .iter()
            .filter(|command| matches!(command.kind(), LoadCommand::DyldChainedFixups(_)))
            .count();
        let legacy_commands = image
            .load_commands()
            .iter()
            .filter(|command| {
                matches!(
                    command.kind(),
                    LoadCommand::DyldInfo(_) | LoadCommand::DyldInfoOnly(_)
                )
            })
            .count();
        if chained_commands > 1 {
            return Err(Error::format("duplicate LC_DYLD_CHAINED_FIXUPS commands"));
        }
        if legacy_commands > 1 {
            return Err(Error::format("duplicate LC_DYLD_INFO commands"));
        }
        let has_chained = chained_commands == 1;
        let has_legacy = legacy_commands == 1;
        let fixups = if has_chained {
            chained_evidence(image)?
        } else if has_legacy {
            legacy_evidence(image)?
        } else {
            BTreeMap::new()
        };
        Ok(Self {
            image,
            fixups,
            has_dyld_metadata: has_chained || has_legacy,
        })
    }

    /// Return every dyld-managed pointer as a bounded, deterministic inventory.
    pub fn inventory(&self, limit: u64) -> Result<PointerInventory> {
        self.inventory_matching(limit, PointerInventorySelection::All)
    }

    /// Return legacy-bound pointer fields as a bounded, deterministic inventory.
    ///
    /// Pure legacy rebases do not consume this limit. Bind fields retain every
    /// compatible regular, weak, and lazy occurrence in
    /// [`DyldPointer::legacy_bind_occurrences`].
    pub fn legacy_bind_inventory(&self, limit: u64) -> Result<PointerInventory> {
        self.inventory_matching(limit, PointerInventorySelection::LegacyBinds)
    }

    /// Return legacy-rebased pointer fields as a bounded, deterministic inventory.
    ///
    /// Bind-only fields do not consume this limit. A field covered by both a
    /// legacy bind and rebase is projected as the rebase occurrence with the
    /// target read from its stored pointer bytes.
    pub fn legacy_rebase_inventory(&self, limit: u64) -> Result<PointerInventory> {
        self.inventory_matching(limit, PointerInventorySelection::LegacyRebases)
    }

    fn inventory_matching(
        &self,
        limit: u64,
        selection: PointerInventorySelection,
    ) -> Result<PointerInventory> {
        if limit == 0 {
            return Err(Error::format("pointer inventory limit must be positive"));
        }
        if !self.has_dyld_metadata {
            return Ok(PointerInventory::Absent);
        }
        let width = if self.image.is_64bit() { 8 } else { 4 };
        let available = u64::try_from(
            self.fixups
                .values()
                .filter(|evidence| selection.matches(evidence))
                .count(),
        )
        .unwrap_or(u64::MAX);
        let mut pointers = Vec::with_capacity(
            usize::try_from(available)
                .unwrap_or(usize::MAX)
                .min(usize::try_from(limit).unwrap_or(usize::MAX)),
        );
        let mut continuation = None;
        for (&offset, evidence) in &self.fixups {
            if !selection.matches(evidence) {
                continue;
            }
            let file_offset = ThinFileOffset(offset);
            let source_va = self.image.address_map().thin_offset_to_va(file_offset)?;
            let project_as_legacy_rebase = selection == PointerInventorySelection::LegacyRebases;
            let target = match (
                project_as_legacy_rebase,
                &evidence.encoding,
                &evidence.target,
            ) {
                (true, _, _)
                | (false, PointerEncoding::LegacyRebase, InventoryPointerTarget::Address(_)) => {
                    inventory_direct_target(self.image, file_offset, width)?
                }
                _ => evidence.target.clone(),
            };
            let pointer = DyldPointer {
                file_offset,
                source_va,
                width,
                encoding: if project_as_legacy_rebase {
                    PointerEncoding::LegacyRebase
                } else {
                    evidence.encoding
                },
                chained_pointer_format: (!project_as_legacy_rebase)
                    .then_some(evidence.chained_pointer_format)
                    .flatten(),
                authentication: (!project_as_legacy_rebase)
                    .then_some(evidence.authentication)
                    .flatten(),
                legacy_bind_occurrences: if project_as_legacy_rebase {
                    Vec::new()
                } else {
                    evidence.legacy_bind_occurrences.clone()
                },
                legacy_rebase: evidence.legacy_rebase_type.is_some(),
                target,
            };
            if pointers.len() == usize::try_from(limit).unwrap_or(usize::MAX) {
                continuation = Some(PointerInventoryContinuation {
                    next_file_offset: pointer.file_offset,
                    next_source_va: pointer.source_va,
                });
                break;
            }
            pointers.push(pointer);
        }
        Ok(match continuation {
            Some(continuation) => PointerInventory::Truncated {
                pointers,
                available,
                continuation,
            },
            None => PointerInventory::Complete(pointers),
        })
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
                (PointerEncoding::LegacyRebase, InventoryPointerTarget::Address(_)) => {
                    direct_target(self.image, &raw)
                }
                _ => project_inventory_target(&evidence.target),
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

impl PointerInventorySelection {
    fn matches(self, evidence: &FixupEvidence) -> bool {
        match self {
            Self::All => true,
            Self::LegacyBinds => evidence.encoding == PointerEncoding::LegacyBind,
            Self::LegacyRebases => evidence.legacy_rebase_type.is_some(),
        }
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

fn inventory_direct_target(
    image: &MachoFile<'_>,
    offset: ThinFileOffset,
    width: u8,
) -> Result<InventoryPointerTarget> {
    let raw = image.read_bytes_at(offset, usize::from(width))?;
    Ok(match direct_target(image, raw) {
        PointerTarget::Null => InventoryPointerTarget::Null,
        PointerTarget::Address(address) => InventoryPointerTarget::Address(address),
        PointerTarget::Import { .. } => unreachable!("direct bytes cannot produce an import"),
    })
}

fn project_inventory_target(target: &InventoryPointerTarget) -> PointerTarget {
    match target {
        InventoryPointerTarget::Null => PointerTarget::Null,
        InventoryPointerTarget::Address(address) => PointerTarget::Address(*address),
        InventoryPointerTarget::Import {
            name,
            library_ordinal,
            ..
        } => PointerTarget::Import {
            name: name.clone(),
            library_ordinal: *library_ordinal,
        },
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
    let decoded = crate::metadata::dyld::chained::parse_chained_fixups(image)?;
    let mut evidence: BTreeMap<u64, FixupEvidence> = BTreeMap::new();
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
                chained_pointer_format: Some(fixup.pointer_format),
                authentication: None,
                target: rebased_target(image, fixup.pointer_format, target, false)?,
                legacy_bind_occurrences: Vec::new(),
                legacy_rebase_type: None,
            },
            FixupKind::AuthRebase {
                target,
                diversity,
                key,
                addr_div,
            } => FixupEvidence {
                encoding: PointerEncoding::ChainedRebase,
                chained_pointer_format: Some(fixup.pointer_format),
                authentication: Some(PointerAuthentication {
                    diversity,
                    key,
                    address_diversity: addr_div,
                }),
                target: rebased_target(image, fixup.pointer_format, target, true)?,
                legacy_bind_occurrences: Vec::new(),
                legacy_rebase_type: None,
            },
            FixupKind::Bind {
                import_index,
                addend,
            } => FixupEvidence {
                encoding: PointerEncoding::ChainedBind,
                chained_pointer_format: Some(fixup.pointer_format),
                authentication: None,
                target: chained_import(&decoded.imports, import_index, addend)?,
                legacy_bind_occurrences: Vec::new(),
                legacy_rebase_type: None,
            },
            FixupKind::AuthBind {
                import_index,
                diversity,
                key,
                addr_div,
            } => FixupEvidence {
                encoding: PointerEncoding::ChainedBind,
                chained_pointer_format: Some(fixup.pointer_format),
                authentication: Some(PointerAuthentication {
                    diversity,
                    key,
                    address_diversity: addr_div,
                }),
                target: chained_import(&decoded.imports, import_index, 0)?,
                legacy_bind_occurrences: Vec::new(),
                legacy_rebase_type: None,
            },
        };
        if evidence.insert(file_offset, item).is_some() {
            return Err(Error::format("duplicate chained-fixup file offset"));
        }
    }
    Ok(evidence)
}

fn rebased_target(
    image: &MachoFile<'_>,
    pointer_format: u16,
    target: u64,
    authenticated: bool,
) -> Result<InventoryPointerTarget> {
    use crate::metadata::dyld::format::constants::{
        DYLD_CHAINED_PTR_64_OFFSET, DYLD_CHAINED_PTR_ARM64E, DYLD_CHAINED_PTR_ARM64E_USERLAND,
        DYLD_CHAINED_PTR_ARM64E_USERLAND24,
    };
    let is_runtime_offset = authenticated
        || matches!(
            pointer_format,
            DYLD_CHAINED_PTR_64_OFFSET
                | DYLD_CHAINED_PTR_ARM64E
                | DYLD_CHAINED_PTR_ARM64E_USERLAND
                | DYLD_CHAINED_PTR_ARM64E_USERLAND24
        );
    let address = if is_runtime_offset {
        image
            .image_base()
            .0
            .checked_add(target)
            .ok_or_else(|| Error::address("chained rebase target overflows"))?
    } else if matches!(
        pointer_format,
        crate::metadata::dyld::format::constants::DYLD_CHAINED_PTR_64
    ) {
        target
    } else {
        return Err(Error::unsupported(format!(
            "unsupported chained rebase pointer format {pointer_format}"
        )));
    };
    Ok(InventoryPointerTarget::Address(Va(address)))
}

fn chained_import(
    imports: &[crate::metadata::dyld::types::ChainedImport<'_>],
    index: u32,
    pointer_addend: i64,
) -> Result<InventoryPointerTarget> {
    let import = imports
        .get(index as usize)
        .ok_or_else(|| Error::format(format!("chained bind references absent import {index}")))?;
    Ok(InventoryPointerTarget::Import {
        import_ordinal: Some(index),
        name: import.name.to_string(),
        library_ordinal: Some(import.lib_ordinal),
        weak: Some(import.weak),
        import_addend: import.addend,
        pointer_addend,
    })
}

fn legacy_evidence(image: &MachoFile<'_>) -> Result<BTreeMap<u64, FixupEvidence>> {
    let mut evidence: BTreeMap<u64, FixupEvidence> = BTreeMap::new();
    let (regular, weak, lazy) = crate::metadata::dyld::bind::parse_bind_entries(image)?;
    for (stream, binds) in [
        (LegacyBindStream::Regular, regular.as_slice()),
        (LegacyBindStream::Weak, weak.as_slice()),
        (LegacyBindStream::Lazy, lazy.as_slice()),
    ] {
        for bind in binds {
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
            let ordinal = i32::try_from(bind.lib_ordinal)
                .map_err(|_| Error::format("legacy bind library ordinal exceeds i32"))?;
            let occurrence = LegacyBindOccurrence {
                stream,
                bind_type: bind.bind_type,
                library_ordinal: ordinal,
                weak: bind.weak,
                symbol_flags: bind.symbol_flags,
                addend: bind.addend,
            };
            if let Some(existing) = evidence.get_mut(&file_offset) {
                let InventoryPointerTarget::Import {
                    name,
                    pointer_addend,
                    library_ordinal,
                    weak,
                    ..
                } = &mut existing.target
                else {
                    return Err(Error::format(format!(
                        "legacy bind conflicts with a rebase at file offset {file_offset:#x}"
                    )));
                };
                let field_type = existing
                    .legacy_bind_occurrences
                    .first()
                    .map(|source| source.bind_type);
                if name != bind.symbol_name
                    || *pointer_addend != bind.addend
                    || field_type != Some(bind.bind_type)
                {
                    return Err(Error::format(format!(
                        "conflicting legacy bind field facts at file offset {file_offset:#x}"
                    )));
                }
                existing.legacy_bind_occurrences.push(occurrence);
                existing.legacy_bind_occurrences.sort();
                existing.legacy_bind_occurrences.dedup();
                *library_ordinal = unique_value(
                    existing
                        .legacy_bind_occurrences
                        .iter()
                        .map(|source| source.library_ordinal),
                );
                *weak = unique_value(
                    existing
                        .legacy_bind_occurrences
                        .iter()
                        .map(|source| source.weak),
                );
            } else {
                evidence.insert(
                    file_offset,
                    FixupEvidence {
                        encoding: PointerEncoding::LegacyBind,
                        chained_pointer_format: None,
                        authentication: None,
                        target: InventoryPointerTarget::Import {
                            import_ordinal: None,
                            name: bind.symbol_name.to_string(),
                            library_ordinal: Some(ordinal),
                            weak: Some(bind.weak),
                            import_addend: 0,
                            pointer_addend: bind.addend,
                        },
                        legacy_bind_occurrences: vec![occurrence],
                        legacy_rebase_type: None,
                    },
                );
            }
        }
    }
    for rebase in crate::metadata::dyld::rebase::parse_rebase_entries(image)? {
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
        let rebase_evidence = FixupEvidence {
            encoding: PointerEncoding::LegacyRebase,
            chained_pointer_format: None,
            authentication: None,
            target: InventoryPointerTarget::Address(Va(0)),
            legacy_bind_occurrences: Vec::new(),
            legacy_rebase_type: Some(rebase.rebase_type),
        };
        if let Some(existing) = evidence.get_mut(&file_offset) {
            match existing.encoding {
                PointerEncoding::LegacyBind => {
                    if existing
                        .legacy_bind_occurrences
                        .iter()
                        .any(|occurrence| occurrence.stream == LegacyBindStream::Regular)
                    {
                        return Err(Error::format(format!(
                            "regular legacy bind conflicts with a rebase at file offset {file_offset:#x}"
                        )));
                    }
                    if existing
                        .legacy_rebase_type
                        .is_some_and(|existing_type| existing_type != rebase.rebase_type)
                    {
                        return Err(Error::format(format!(
                            "conflicting legacy rebase types at bound file offset {file_offset:#x}"
                        )));
                    }
                    if existing
                        .legacy_bind_occurrences
                        .first()
                        .map(|occurrence| occurrence.bind_type)
                        != Some(rebase.rebase_type)
                    {
                        return Err(Error::format(format!(
                            "legacy bind and rebase types conflict at file offset {file_offset:#x}"
                        )));
                    }
                    existing.legacy_rebase_type = Some(rebase.rebase_type);
                }
                PointerEncoding::LegacyRebase => {
                    if existing.legacy_rebase_type != Some(rebase.rebase_type) {
                        return Err(Error::format(format!(
                            "conflicting legacy rebase types at file offset {file_offset:#x}"
                        )));
                    }
                }
                PointerEncoding::Direct
                | PointerEncoding::ChainedRebase
                | PointerEncoding::ChainedBind => {
                    return Err(Error::format(format!(
                        "legacy rebase conflicts with incompatible pointer evidence at file offset {file_offset:#x}"
                    )));
                }
            }
        } else {
            evidence.insert(file_offset, rebase_evidence);
        }
    }
    Ok(evidence)
}

fn unique_value<T: Copy + PartialEq>(mut values: impl Iterator<Item = T>) -> Option<T> {
    let first = values.next()?;
    values.all(|value| value == first).then_some(first)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::dyld::format::constants::{
        DYLD_CHAINED_PTR_64, DYLD_CHAINED_PTR_ARM64E_USERLAND,
    };

    fn image(bytes: &[u8]) -> crate::core::MachoFile<'_> {
        match crate::core::parse(bytes).expect("fixture parses") {
            crate::core::model::container::MachoContainer::Thin(macho) => macho,
            crate::core::model::container::MachoContainer::Fat(_) => panic!("expected thin image"),
        }
    }

    #[test]
    fn unauthenticated_arm64e_rebases_are_image_relative() {
        let bytes = macho_test_support::disassembly_x86_64();
        let macho = image(&bytes);
        assert_eq!(
            rebased_target(&macho, DYLD_CHAINED_PTR_ARM64E_USERLAND, 0x1234, false).unwrap(),
            InventoryPointerTarget::Address(Va(macho.image_base().0 + 0x1234))
        );
        assert_eq!(
            rebased_target(&macho, DYLD_CHAINED_PTR_64, 0x1234, false).unwrap(),
            InventoryPointerTarget::Address(Va(0x1234))
        );
    }
}
