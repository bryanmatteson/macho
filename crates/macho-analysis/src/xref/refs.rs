use serde::{Deserialize, Serialize};

use crate::Result;
use crate::dyld::bind::parse_bind_entries;
use crate::dyld::chained::parse_chained_fixups;
use crate::dyld::types::FixupKind;
use crate::ext::MachoExt;
use crate::format::constants::*;
use crate::format::relocations_for_section;
use crate::model::addr::types::{ThinFileOffset, Va};
use crate::model::macho_file::MachoFile;
use crate::model::relocation::Relocation;
use crate::model::section::SectionType;
use crate::model::symbol::SymbolTable;

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The XrefIndex type.
pub struct XrefIndex {
    refs: Vec<Xref>,
    #[serde(skip)]
    decode_gaps: Vec<macho_insn::DecodeGap>,
    #[serde(skip)]
    refs_truncated: bool,
    #[serde(skip)]
    decoded_bytes_truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The Xref type.
pub struct Xref {
    #[serde(
        serialize_with = "crate::serde_addr::va",
        deserialize_with = "crate::serde_addr::va_from"
    )]
    /// The source field.
    pub source: Va,
    /// The target field.
    pub target: XrefTarget,
    /// The kind field.
    pub kind: XrefKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
/// The XrefTarget type.
#[non_exhaustive]
pub enum XrefTarget {
    /// The Internal variant.
    Internal {
        #[serde(
            serialize_with = "crate::serde_addr::va",
            deserialize_with = "crate::serde_addr::va_from"
        )]
        /// The Va field.
        va: Va,
    },
    /// The Import variant.
    Import {
        /// The String field.
        name: String,
        /// The i32 field.
        ordinal: i32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// The XrefKind type.
#[non_exhaustive]
pub enum XrefKind {
    /// The Stub variant.
    Stub,
    /// The ChainedBind variant.
    ChainedBind,
    /// The ChainedRebase variant.
    ChainedRebase,
    /// The LegacyBind variant.
    LegacyBind,
    /// The Relocation variant.
    Relocation,
    /// The DirectBranch variant.
    DirectBranch,
}

impl XrefIndex {
    /// Performs build.
    pub fn build(macho: &MachoFile<'_>) -> Result<Self> {
        Self::build_limited(macho, usize::MAX, usize::MAX)
    }

    /// Build while bounding retained references and decoded executable bytes.
    pub fn build_limited(
        macho: &MachoFile<'_>,
        max_refs: usize,
        max_decoded_bytes: usize,
    ) -> Result<Self> {
        let mut refs = Vec::new();
        let mut refs_truncated = false;

        // 1. Extract stub references from indirect symbol tables
        collect_stub_refs(macho, &mut refs, max_refs, &mut refs_truncated)?;

        // 2. Extract chained fixup references
        collect_chained_fixup_refs(macho, &mut refs, max_refs, &mut refs_truncated);

        // 3. Extract legacy bind references
        collect_legacy_bind_refs(macho, &mut refs, max_refs, &mut refs_truncated);

        // 4. Extract relocation-backed references (object files, kexts)
        collect_relocation_refs(macho, &mut refs, max_refs, &mut refs_truncated);

        // 5. Scan for arm64 direct branches in executable sections
        let mut decode_gaps = Vec::new();
        let decoded_bytes_truncated = collect_direct_branches(
            macho,
            &mut refs,
            &mut decode_gaps,
            max_refs,
            max_decoded_bytes,
            &mut refs_truncated,
        );

        // Sort by source address
        refs.sort_by_key(|r| r.source);

        Ok(Self {
            refs,
            decode_gaps,
            refs_truncated,
            decoded_bytes_truncated,
        })
    }

    /// Performs refs_from.
    pub fn refs_from(&self, source: Va) -> impl Iterator<Item = &Xref> {
        let lo = self.refs.partition_point(|r| r.source < source);
        self.refs[lo..]
            .iter()
            .take_while(move |r| r.source == source)
    }

    /// Find all xrefs whose target is the given internal VA.
    ///
    /// Scans linearly: refs are sorted by source address, not target.
    pub fn refs_to(&self, target: Va) -> impl Iterator<Item = &Xref> {
        self.refs.iter().filter(move |r| match &r.target {
            XrefTarget::Internal { va } => *va == target,
            _ => false,
        })
    }

    /// Performs refs_in_range.
    pub fn refs_in_range(&self, start: Va, end: Va) -> &[Xref] {
        let lo = self.refs.partition_point(|r| r.source < start);
        let hi = self.refs.partition_point(|r| r.source < end);
        &self.refs[lo..hi]
    }

    /// Performs all_refs.
    pub fn all_refs(&self) -> &[Xref] {
        &self.refs
    }

    /// Performs decode_gaps.
    pub fn decode_gaps(&self) -> &[macho_insn::DecodeGap] {
        &self.decode_gaps
    }

    /// Whether additional references were discarded at the requested limit.
    pub const fn refs_truncated(&self) -> bool {
        self.refs_truncated
    }

    /// Whether executable bytes were skipped at the requested decode limit.
    pub const fn decoded_bytes_truncated(&self) -> bool {
        self.decoded_bytes_truncated
    }

    /// Performs len.
    pub fn len(&self) -> usize {
        self.refs.len()
    }

    /// Performs is_empty.
    pub fn is_empty(&self) -> bool {
        self.refs.is_empty()
    }
}

impl<'data> MachoExt<'data> for XrefIndex {
    type Error = crate::AnalysisError;

    fn parse<'mf>(macho: &'mf MachoFile<'data>) -> Result<Self>
    where
        'data: 'mf,
    {
        Self::build(macho)
    }
}

fn collect_stub_refs(
    macho: &MachoFile<'_>,
    refs: &mut Vec<Xref>,
    max_refs: usize,
    truncated: &mut bool,
) -> Result<()> {
    let symtab = match macho.ext::<SymbolTable<'_>>() {
        Ok(st) => st,
        Err(_) => return Ok(()),
    };

    let dysymtab = match macho
        .find_load_command(|lc| matches!(lc, crate::model::load_command::LoadCommand::Dysymtab(_)))
    {
        Some(lc) => match lc.kind().as_dysymtab() {
            Some(d) => d.clone(),
            None => return Ok(()),
        },
        None => return Ok(()),
    };

    if dysymtab.nindirectsyms == 0 {
        return Ok(());
    }

    let indirect_off = dysymtab.indirectsymoff as usize;
    let n_indirect = dysymtab.nindirectsyms as usize;
    let endian = macho.endian();

    // Read the indirect symbol table
    let indirect_data = macho.read_bytes_at(ThinFileOffset(indirect_off as u64), n_indirect * 4)?;

    for sect in macho.all_sections() {
        let is_stub_section = matches!(
            sect.section_type(),
            SectionType::SymbolStubs
                | SectionType::NonLazySymbolPointers
                | SectionType::LazySymbolPointers
        );
        if !is_stub_section {
            continue;
        }

        let indirect_start = sect.reserved1() as usize;
        let entry_size = match sect.section_type() {
            SectionType::SymbolStubs => {
                if sect.reserved2() == 0 {
                    continue;
                }
                sect.reserved2() as u64
            }
            _ => {
                // Pointer-sized entries
                if macho.is_64bit() { 8u64 } else { 4u64 }
            }
        };

        let Some(n_entries) = sect
            .size()
            .checked_div(entry_size)
            .and_then(|count| usize::try_from(count).ok())
        else {
            continue;
        };

        for i in 0..n_entries {
            let isym_idx = indirect_start + i;
            if isym_idx >= n_indirect {
                break;
            }

            let table_offset = isym_idx * 4;
            if table_offset + 4 > indirect_data.len() {
                break;
            }

            let raw_index = endian.interpret_u32(u32::from_ne_bytes([
                indirect_data[table_offset],
                indirect_data[table_offset + 1],
                indirect_data[table_offset + 2],
                indirect_data[table_offset + 3],
            ]));

            // Skip INDIRECT_SYMBOL_LOCAL (0x80000000), INDIRECT_SYMBOL_ABS
            // (0x40000000), and any combination of these flag bits.
            if raw_index & 0xC0000000 != 0 {
                continue;
            }

            let source_va = Va(sect.addr().0 + i as u64 * entry_size);

            if let Some(sym) = symtab.get(raw_index as usize) {
                let target = if sym.is_undefined() {
                    XrefTarget::Import {
                        name: sym.name.to_string(),
                        ordinal: sym.library_ordinal() as i32,
                    }
                } else {
                    XrefTarget::Internal { va: Va(sym.value) }
                };

                if !push_ref(
                    refs,
                    max_refs,
                    truncated,
                    Xref {
                        source: source_va,
                        target,
                        kind: XrefKind::Stub,
                    },
                ) {
                    return Ok(());
                }
            }
        }
    }

    Ok(())
}

fn collect_chained_fixup_refs(
    macho: &MachoFile<'_>,
    refs: &mut Vec<Xref>,
    max_refs: usize,
    truncated: &mut bool,
) {
    let fixups = match parse_chained_fixups(macho) {
        Ok(f) => f,
        Err(_) => return,
    };

    let segments = macho.segments();

    for fixup in &fixups.fixups {
        let seg = match segments.get(fixup.segment_index) {
            Some(s) => s,
            None => continue,
        };
        let source_va = Va(seg.vm_addr().0 + fixup.segment_offset);

        match &fixup.kind {
            FixupKind::Bind { import_index, .. } | FixupKind::AuthBind { import_index, .. } => {
                let target = match fixups.imports.get(*import_index as usize) {
                    Some(imp) => XrefTarget::Import {
                        name: imp.name.to_string(),
                        ordinal: imp.lib_ordinal,
                    },
                    None => continue,
                };
                if !push_ref(
                    refs,
                    max_refs,
                    truncated,
                    Xref {
                        source: source_va,
                        target,
                        kind: XrefKind::ChainedBind,
                    },
                ) {
                    return;
                }
            }
            FixupKind::Rebase { target } | FixupKind::AuthRebase { target, .. } => {
                if !push_ref(
                    refs,
                    max_refs,
                    truncated,
                    Xref {
                        source: source_va,
                        target: XrefTarget::Internal { va: Va(*target) },
                        kind: XrefKind::ChainedRebase,
                    },
                ) {
                    return;
                }
            }
            _ => continue,
        }
    }
}

fn collect_legacy_bind_refs(
    macho: &MachoFile<'_>,
    refs: &mut Vec<Xref>,
    max_refs: usize,
    truncated: &mut bool,
) {
    let (regular, weak, lazy) = match parse_bind_entries(macho) {
        Ok(entries) => entries,
        Err(_) => return,
    };

    let segments = macho.segments();

    for bind in regular.iter().chain(weak.iter()).chain(lazy.iter()) {
        let seg = match segments.get(bind.segment_index) {
            Some(s) => s,
            None => continue,
        };
        let source_va = Va(seg.vm_addr().0 + bind.segment_offset);

        if !push_ref(
            refs,
            max_refs,
            truncated,
            Xref {
                source: source_va,
                target: XrefTarget::Import {
                    name: bind.symbol_name.to_string(),
                    ordinal: bind.lib_ordinal.clamp(i32::MIN as i64, i32::MAX as i64) as i32,
                },
                kind: XrefKind::LegacyBind,
            },
        ) {
            return;
        }
    }
}

fn collect_relocation_refs(
    macho: &MachoFile<'_>,
    refs: &mut Vec<Xref>,
    max_refs: usize,
    truncated: &mut bool,
) {
    let symtab = match macho.ext::<SymbolTable<'_>>() {
        Ok(st) => st,
        Err(_) => return,
    };

    for sect in macho.all_sections() {
        if sect.relocation_count() == 0 {
            continue;
        }
        let relocs = match relocations_for_section(macho, sect) {
            Ok(r) => r,
            Err(_) => continue,
        };

        for reloc in &relocs {
            match reloc {
                Relocation::Standard(sr) => {
                    let source_va = Va(sect.addr().0 + sr.address as u64);
                    if sr.is_extern {
                        if let Some(sym) = symtab.get(sr.symbol_num as usize) {
                            let target = if sym.is_undefined() {
                                XrefTarget::Import {
                                    name: sym.name.to_string(),
                                    ordinal: sym.library_ordinal() as i32,
                                }
                            } else {
                                XrefTarget::Internal { va: Va(sym.value) }
                            };
                            if !push_ref(
                                refs,
                                max_refs,
                                truncated,
                                Xref {
                                    source: source_va,
                                    target,
                                    kind: XrefKind::Relocation,
                                },
                            ) {
                                return;
                            }
                        }
                    } else {
                        // Non-extern: symbol_num is a section ordinal, target
                        // is an internal VA. We can't easily resolve the exact
                        // target without addend decoding, so skip these.
                    }
                }
                Relocation::Scattered(_) => {
                    // Scattered relocations are 32-bit-only and are not
                    // converted into xrefs.
                }
            }
        }
    }
}

fn collect_direct_branches(
    macho: &MachoFile<'_>,
    refs: &mut Vec<Xref>,
    gaps: &mut Vec<macho_insn::DecodeGap>,
    max_refs: usize,
    max_decoded_bytes: usize,
    refs_truncated: &mut bool,
) -> bool {
    let cpu_type = macho.header().cpu_type().0;

    let arch = if cpu_type == CPU_TYPE_ARM64 {
        macho_insn::Arch::Arm64
    } else if cpu_type == CPU_TYPE_X86_64 {
        macho_insn::Arch::X86_64
    } else {
        return false;
    };

    let min_insn_size: u64 = if arch.is_arm64() { 4 } else { 5 };

    let mut remaining = max_decoded_bytes;
    let mut decoded_bytes_truncated = false;
    for sect in macho.all_sections() {
        if !sect
            .attributes()
            .contains(SectionAttributes::PURE_INSTRUCTIONS)
        {
            continue;
        }
        if sect.size() < min_insn_size {
            continue;
        }

        if remaining == 0 {
            decoded_bytes_truncated = true;
            break;
        }
        let requested = usize::try_from(sect.size()).unwrap_or(usize::MAX);
        let mut decode_len = requested.min(remaining);
        if arch.is_arm64() {
            decode_len -= decode_len % 4;
        }
        if decode_len < requested {
            decoded_bytes_truncated = true;
        }
        if decode_len < min_insn_size as usize {
            continue;
        }
        let sect_bytes = match macho.read_bytes_at(sect.offset(), decode_len) {
            Ok(b) => b,
            Err(_) => continue,
        };
        remaining -= decode_len;

        let report = macho_insn::decode_lossy(sect_bytes, sect.addr().0, arch);
        gaps.extend(report.gaps);
        for insn in report.instructions {
            let insn_va = sect.addr().0 + insn.offset as u64;

            // Only collect direct branches and calls (not register-indirect).
            match &insn.kind {
                macho_insn::InsnKind::Branch(_) | macho_insn::InsnKind::Call(_) => {}
                _ => continue,
            }

            if let Some(target) = macho_insn::resolve_branch_target(&insn, insn_va) {
                let _ = push_ref(
                    refs,
                    max_refs,
                    refs_truncated,
                    Xref {
                        source: Va(insn_va),
                        target: XrefTarget::Internal { va: Va(target) },
                        kind: XrefKind::DirectBranch,
                    },
                );
            }
        }
    }
    decoded_bytes_truncated
}

fn push_ref(refs: &mut Vec<Xref>, max_refs: usize, truncated: &mut bool, reference: Xref) -> bool {
    if refs.len() >= max_refs {
        *truncated = true;
        return false;
    }
    refs.push(reference);
    true
}
