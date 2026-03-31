use crate::addr::types::{ThinFileOffset, Va};
use crate::constants::*;
use crate::dyld::bind::parse_bind_entries;
use crate::dyld::chained::parse_chained_fixups;
use crate::dyld::types::FixupKind;
use crate::error::Result;
use crate::model::mach::MachFile;
use crate::model::section::SectionType;
use crate::parse::parse_symbol_table;

#[derive(Debug, Clone)]
pub struct XrefIndex {
    refs: Vec<Xref>,
}

#[derive(Debug, Clone)]
pub struct Xref {
    pub source: Va,
    pub target: XrefTarget,
    pub kind: XrefKind,
}

#[derive(Debug, Clone)]
pub enum XrefTarget {
    Internal(Va),
    Import { name: String, ordinal: i32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XrefKind {
    Stub,
    ChainedBind,
    ChainedRebase,
    LegacyBind,
    Relocation,
    DirectBranch,
}

impl XrefIndex {
    pub fn build(mach: &MachFile<'_>) -> Result<Self> {
        let mut refs = Vec::new();

        // 1. Extract stub references from indirect symbol tables
        collect_stub_refs(mach, &mut refs)?;

        // 2. Extract chained fixup references
        collect_chained_fixup_refs(mach, &mut refs);

        // 3. Extract legacy bind references
        collect_legacy_bind_refs(mach, &mut refs);

        // 4. Scan for arm64 direct branches in executable sections
        collect_direct_branches(mach, &mut refs);

        // Sort by source address
        refs.sort_by_key(|r| r.source);

        Ok(Self { refs })
    }

    pub fn refs_from(&self, source: Va) -> impl Iterator<Item = &Xref> {
        let lo = self.refs.partition_point(|r| r.source < source);
        self.refs[lo..]
            .iter()
            .take_while(move |r| r.source == source)
    }

    pub fn refs_to(&self, target: Va) -> impl Iterator<Item = &Xref> {
        self.refs.iter().filter(move |r| match &r.target {
            XrefTarget::Internal(va) => *va == target,
            _ => false,
        })
    }

    pub fn refs_in_range(&self, start: Va, end: Va) -> &[Xref] {
        let lo = self.refs.partition_point(|r| r.source < start);
        let hi = self.refs.partition_point(|r| r.source < end);
        &self.refs[lo..hi]
    }

    pub fn all_refs(&self) -> &[Xref] {
        &self.refs
    }

    pub fn len(&self) -> usize {
        self.refs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.refs.is_empty()
    }
}

fn collect_stub_refs(mach: &MachFile<'_>, refs: &mut Vec<Xref>) -> Result<()> {
    let symtab = match parse_symbol_table(mach) {
        Ok(st) => st,
        Err(_) => return Ok(()),
    };

    let dysymtab = match mach
        .find_load_command(|lc| matches!(lc, crate::model::load_command::LoadCommand::Dysymtab(_)))
    {
        Some(lc) => match lc.kind.as_dysymtab() {
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
    let endian = mach.endian();

    // Read the indirect symbol table
    let indirect_data = mach.read_bytes_at(ThinFileOffset(indirect_off as u64), n_indirect * 4)?;

    for sect in mach.all_sections() {
        let is_stub_section = matches!(
            sect.section_type,
            SectionType::SymbolStubs
                | SectionType::NonLazySymbolPointers
                | SectionType::LazySymbolPointers
        );
        if !is_stub_section {
            continue;
        }

        let indirect_start = sect.reserved1 as usize;
        let entry_size = match sect.section_type {
            SectionType::SymbolStubs => {
                if sect.reserved2 == 0 {
                    continue;
                }
                sect.reserved2 as u64
            }
            _ => {
                // Pointer-sized entries
                if mach.is_64bit() { 8u64 } else { 4u64 }
            }
        };

        let n_entries = if entry_size > 0 {
            (sect.size / entry_size) as usize
        } else {
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

            // Skip INDIRECT_SYMBOL_LOCAL and INDIRECT_SYMBOL_ABS
            if raw_index == 0x80000000 || raw_index == 0x40000000 {
                continue;
            }
            // Also skip combined flags
            if raw_index & 0xC0000000 != 0 {
                continue;
            }

            let source_va = Va(sect.addr.0 + i as u64 * entry_size);

            if let Some(sym) = symtab.get(raw_index as usize) {
                let target = if sym.is_undefined() {
                    XrefTarget::Import {
                        name: sym.name.to_string(),
                        ordinal: sym.library_ordinal() as i32,
                    }
                } else {
                    XrefTarget::Internal(Va(sym.value))
                };

                refs.push(Xref {
                    source: source_va,
                    target,
                    kind: XrefKind::Stub,
                });
            }
        }
    }

    Ok(())
}

fn collect_chained_fixup_refs(mach: &MachFile<'_>, refs: &mut Vec<Xref>) {
    let fixups = match parse_chained_fixups(mach) {
        Ok(f) => f,
        Err(_) => return,
    };

    let segments = mach.segments();

    for fixup in &fixups.fixups {
        let seg = match segments.get(fixup.segment_index) {
            Some(s) => s,
            None => continue,
        };
        let source_va = Va(seg.vm_addr.0 + fixup.segment_offset);

        match &fixup.kind {
            FixupKind::Bind { import_index, .. } | FixupKind::AuthBind { import_index, .. } => {
                let target = match fixups.imports.get(*import_index as usize) {
                    Some(imp) => XrefTarget::Import {
                        name: imp.name.to_string(),
                        ordinal: imp.lib_ordinal,
                    },
                    None => continue,
                };
                refs.push(Xref {
                    source: source_va,
                    target,
                    kind: XrefKind::ChainedBind,
                });
            }
            FixupKind::Rebase { target } | FixupKind::AuthRebase { target, .. } => {
                refs.push(Xref {
                    source: source_va,
                    target: XrefTarget::Internal(Va(*target)),
                    kind: XrefKind::ChainedRebase,
                });
            }
        }
    }
}

fn collect_legacy_bind_refs(mach: &MachFile<'_>, refs: &mut Vec<Xref>) {
    let (regular, weak, lazy) = match parse_bind_entries(mach) {
        Ok(entries) => entries,
        Err(_) => return,
    };

    let segments = mach.segments();

    for bind in regular.iter().chain(weak.iter()).chain(lazy.iter()) {
        let seg = match segments.get(bind.segment_index) {
            Some(s) => s,
            None => continue,
        };
        let source_va = Va(seg.vm_addr.0 + bind.segment_offset);

        refs.push(Xref {
            source: source_va,
            target: XrefTarget::Import {
                name: bind.symbol_name.to_string(),
                ordinal: bind.lib_ordinal as i32,
            },
            kind: XrefKind::LegacyBind,
        });
    }
}

fn collect_direct_branches(mach: &MachFile<'_>, refs: &mut Vec<Xref>) {
    let cpu_type = mach.header().cpu_type.0;

    if cpu_type == CPU_TYPE_ARM64 {
        collect_arm64_branches(mach, refs);
    } else if cpu_type == CPU_TYPE_X86_64 {
        collect_x86_64_calls(mach, refs);
    }
}

fn collect_arm64_branches(mach: &MachFile<'_>, refs: &mut Vec<Xref>) {
    let endian = mach.endian();

    for sect in mach.all_sections() {
        // Only scan executable sections
        if !sect
            .attributes
            .contains(SectionAttributes::PURE_INSTRUCTIONS)
        {
            continue;
        }
        if sect.size < 4 {
            continue;
        }

        let sect_bytes = match mach.read_bytes_at(sect.offset, sect.size as usize) {
            Ok(b) => b,
            Err(_) => continue,
        };

        let n_instrs = sect_bytes.len() / 4;
        for i in 0..n_instrs {
            let off = i * 4;
            let instr = endian.interpret_u32(u32::from_ne_bytes([
                sect_bytes[off],
                sect_bytes[off + 1],
                sect_bytes[off + 2],
                sect_bytes[off + 3],
            ]));

            // BL instruction: bits[31:26] = 100101 (0x94000000 mask 0xFC000000)
            // B instruction:  bits[31:26] = 000101 (0x14000000 mask 0xFC000000)
            let is_bl = instr & 0xFC000000 == 0x94000000;
            let is_b = instr & 0xFC000000 == 0x14000000;
            if !is_bl && !is_b {
                continue;
            }

            // imm26 is a signed offset * 4
            let imm26 = instr & 0x03FF_FFFF;
            let signed_offset = if imm26 & 0x0200_0000 != 0 {
                // Sign-extend 26-bit to i64
                ((imm26 | 0xFC00_0000) as i32 as i64) * 4
            } else {
                (imm26 as i64) * 4
            };

            let source_va = Va(sect.addr.0 + off as u64);
            let target_va = Va((source_va.0 as i64 + signed_offset) as u64);

            refs.push(Xref {
                source: source_va,
                target: XrefTarget::Internal(target_va),
                kind: XrefKind::DirectBranch,
            });
        }
    }
}

fn collect_x86_64_calls(mach: &MachFile<'_>, refs: &mut Vec<Xref>) {
    for sect in mach.all_sections() {
        if !sect
            .attributes
            .contains(SectionAttributes::PURE_INSTRUCTIONS)
        {
            continue;
        }
        if sect.size < 5 {
            continue;
        }

        let sect_bytes = match mach.read_bytes_at(sect.offset, sect.size as usize) {
            Ok(b) => b,
            Err(_) => continue,
        };

        let len = sect_bytes.len();
        let mut i = 0;
        while i + 5 <= len {
            let opcode = sect_bytes[i];

            // E8 = CALL rel32, E9 = JMP rel32
            if opcode == 0xE8 || opcode == 0xE9 {
                let rel32 = i32::from_le_bytes([
                    sect_bytes[i + 1],
                    sect_bytes[i + 2],
                    sect_bytes[i + 3],
                    sect_bytes[i + 4],
                ]);
                let source_va = Va(sect.addr.0 + i as u64);
                // rel32 is relative to the next instruction (i + 5)
                let next_ip = sect.addr.0 + i as u64 + 5;
                let target_va = Va((next_ip as i64 + rel32 as i64) as u64);

                refs.push(Xref {
                    source: source_va,
                    target: XrefTarget::Internal(target_va),
                    kind: XrefKind::DirectBranch,
                });

                i += 5;
                continue;
            }

            i += 1;
        }
    }
}
