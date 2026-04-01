use std::collections::BTreeMap;

use crate::Result;
use crate::addr::Va;
use crate::cpp::types::{
    CppBaseClass, CppConfidence, CppEvidence, CppEvidenceKind, CppTypeInfoKind, CppTypeInfoNode,
};
use crate::dyld::bind::parse_bind_entries;
use crate::dyld::chained::parse_chained_fixups;
use crate::dyld::rebase::parse_rebase_entries;
use crate::dyld::types::FixupKind;
use crate::model::mach::MachFile;
use crate::model::resolution::{ResolutionContext, ResolvedTarget};
use crate::parse::parse_symbol_table;

pub fn build_typeinfo_index(mach: &MachFile<'_>) -> Result<BTreeMap<String, CppTypeInfoNode>> {
    let symtab = parse_symbol_table(mach)?;
    let symbols = symtab.symbols();
    let resolver = PointerResolver::new(mach);
    let mut va_to_symbol = BTreeMap::new();
    for symbol in symbols {
        if symbol.is_defined() && symbol.value != 0 {
            va_to_symbol.insert(symbol.value, symbol.name.to_string());
        }
    }

    let mut out = BTreeMap::new();
    for symbol in symbols.iter().filter(|symbol| {
        symbol.is_defined() && symbol.value != 0 && is_typeinfo_symbol(symbol.name)
    }) {
        let class_name = typeinfo_class_name(symbol.name);
        let raw_kind = resolver.resolve_pointer(Va(symbol.value)).ok();
        let kind = raw_kind
            .as_ref()
            .and_then(|target| match target {
                ResolvedTarget::Address(va) => va_to_symbol.get(&va.0).map(String::as_str),
                ResolvedTarget::Import { name, .. } => Some(name.as_str()),
            })
            .map(classify_typeinfo_kind)
            .unwrap_or(CppTypeInfoKind::Unknown);

        let bases = match kind {
            CppTypeInfoKind::SingleInheritance => {
                parse_single_base(&resolver, &va_to_symbol, Va(symbol.value), mach.is_64bit())
                    .into_iter()
                    .collect()
            }
            CppTypeInfoKind::VirtualMultipleInheritance => {
                parse_vmi_bases(&resolver, &va_to_symbol, Va(symbol.value), mach.is_64bit())
            }
            _ => Vec::new(),
        };

        out.insert(
            class_name.clone(),
            CppTypeInfoNode {
                name: class_name,
                mangled_name: symbol.name.to_string(),
                address: symbol.value,
                kind,
                bases,
                evidence: vec![CppEvidence {
                    kind: CppEvidenceKind::TypeInfo,
                    confidence: CppConfidence::High,
                    detail: symbol.name.to_string(),
                }],
            },
        );
    }

    Ok(out)
}

fn is_typeinfo_symbol(name: &str) -> bool {
    name.starts_with("__ZTI") || name.starts_with("_ZTI")
}

fn typeinfo_class_name(name: &str) -> String {
    crate::demangle::demangle_symbol(name)
        .and_then(|text| text.strip_prefix("typeinfo for ").map(str::to_string))
        .unwrap_or_else(|| name.to_string())
}

fn classify_typeinfo_kind(symbol_name: &str) -> CppTypeInfoKind {
    if symbol_name.contains("__si_class_type_info") {
        CppTypeInfoKind::SingleInheritance
    } else if symbol_name.contains("__vmi_class_type_info") {
        CppTypeInfoKind::VirtualMultipleInheritance
    } else if symbol_name.contains("__class_type_info") {
        CppTypeInfoKind::Class
    } else {
        CppTypeInfoKind::Unknown
    }
}

fn parse_single_base(
    resolver: &PointerResolver<'_>,
    va_to_symbol: &BTreeMap<u64, String>,
    typeinfo_va: Va,
    is_64bit: bool,
) -> Option<CppBaseClass> {
    let ptr_size = if is_64bit { 8 } else { 4 } as u64;
    let base_field = Va(typeinfo_va.0 + ptr_size * 2);
    let target = resolver.resolve_pointer(base_field).ok()?;
    let (name, flags) = resolve_base_name(target, va_to_symbol)?;
    Some(CppBaseClass {
        name,
        offset: None,
        flags,
        is_virtual: false,
        is_public: true,
        evidence: vec![CppEvidence {
            kind: CppEvidenceKind::TypeInfo,
            confidence: CppConfidence::High,
            detail: "single inheritance RTTI".to_string(),
        }],
    })
}

fn parse_vmi_bases(
    resolver: &PointerResolver<'_>,
    va_to_symbol: &BTreeMap<u64, String>,
    typeinfo_va: Va,
    is_64bit: bool,
) -> Vec<CppBaseClass> {
    let ptr_size = if is_64bit { 8 } else { 4 } as u64;
    let count_offset = Va(typeinfo_va.0 + ptr_size * 2 + 4);
    let base_count = resolver.read_u32(count_offset).unwrap_or(0) as usize;
    let mut bases = Vec::new();
    let mut cursor = typeinfo_va.0 + ptr_size * 2 + 8;
    for _ in 0..base_count {
        let target = match resolver.resolve_pointer(Va(cursor)) {
            Ok(target) => target,
            Err(_) => break,
        };
        let flags_offset = Va(cursor + ptr_size);
        let offset_flags = if is_64bit {
            resolver.read_u64(flags_offset).unwrap_or(0)
        } else {
            resolver.read_u32(flags_offset).unwrap_or(0) as u64
        };
        if let Some((name, _)) = resolve_base_name(target, va_to_symbol) {
            let offset = ((offset_flags as i64) >> 8).then_some((offset_flags as i64) >> 8);
            bases.push(CppBaseClass {
                name,
                offset,
                flags: offset_flags,
                is_virtual: offset_flags & 0x1 != 0,
                is_public: offset_flags & 0x2 == 0,
                evidence: vec![CppEvidence {
                    kind: CppEvidenceKind::TypeInfo,
                    confidence: CppConfidence::High,
                    detail: "vmi RTTI base entry".to_string(),
                }],
            });
        }
        cursor += ptr_size * 2;
    }
    bases
}

fn resolve_base_name(
    target: ResolvedTarget,
    va_to_symbol: &BTreeMap<u64, String>,
) -> Option<(String, u64)> {
    match target {
        ResolvedTarget::Address(va) => {
            let symbol_name = va_to_symbol.get(&va.0)?;
            Some((typeinfo_class_name(symbol_name), 0))
        }
        ResolvedTarget::Import { name, .. } => Some((typeinfo_class_name(&name), 0)),
    }
}

struct PointerResolver<'a> {
    ctx: ResolutionContext<'a, 'a>,
    fixups: BTreeMap<u64, ResolvedTarget>,
}

impl<'a> PointerResolver<'a> {
    fn new(mach: &'a MachFile<'a>) -> Self {
        let mut fixups = BTreeMap::new();
        if let Ok(chained) = parse_chained_fixups(mach) {
            for fixup in &chained.fixups {
                let Some(seg) = mach.segments().get(fixup.segment_index) else {
                    continue;
                };
                let file_offset = seg.file_offset.0 + fixup.segment_offset;
                let target = match &fixup.kind {
                    FixupKind::Rebase { target } | FixupKind::AuthRebase { target, .. } => {
                        ResolvedTarget::Address(Va(mach.image_base().0 + target))
                    }
                    FixupKind::Bind { import_index, .. }
                    | FixupKind::AuthBind { import_index, .. } => {
                        let import = chained.imports.get(*import_index as usize);
                        match import {
                            Some(import) => ResolvedTarget::Import {
                                name: import.name.to_string(),
                                lib_ordinal: import.lib_ordinal,
                            },
                            None => continue,
                        }
                    }
                };
                fixups.insert(file_offset, target);
            }
        } else {
            if let Ok((regular, weak, lazy)) = parse_bind_entries(mach) {
                for bind in regular.iter().chain(weak.iter()).chain(lazy.iter()) {
                    if let Some(seg) = mach.segments().get(bind.segment_index) {
                        let file_offset = seg.file_offset.0 + bind.segment_offset;
                        fixups.insert(
                            file_offset,
                            ResolvedTarget::Import {
                                name: bind.symbol_name.to_string(),
                                lib_ordinal: bind.lib_ordinal,
                            },
                        );
                    }
                }
            }
            if let Ok(rebases) = parse_rebase_entries(mach) {
                for rebase in rebases {
                    if let Some(seg) = mach.segments().get(rebase.segment_index) {
                        let file_offset = seg.file_offset.0 + rebase.segment_offset;
                        fixups.insert(file_offset, ResolvedTarget::Address(Va(0)));
                    }
                }
            }
        }
        Self {
            ctx: ResolutionContext::new(mach),
            fixups,
        }
    }

    fn resolve_pointer(&self, va: Va) -> Result<ResolvedTarget> {
        let offset = self.ctx.mach().address_map().va_to_thin_offset(va)?;
        if let Some(target) = self.fixups.get(&offset.0) {
            if let ResolvedTarget::Address(resolved) = target {
                if resolved.0 == 0 {
                    let raw = self.ctx.read_pointer(va)?;
                    return Ok(ResolvedTarget::Address(Va(raw)));
                }
            }
            return Ok(target.clone());
        }
        let raw = self.ctx.read_pointer(va)?;
        Ok(ResolvedTarget::Address(Va(raw)))
    }

    fn read_u32(&self, va: Va) -> Result<u32> {
        let bytes = self.ctx.mach().read_bytes_at_va(va, 4)?;
        Ok(self.ctx.mach().endian().read_u32(bytes.try_into().unwrap()))
    }

    fn read_u64(&self, va: Va) -> Result<u64> {
        let bytes = self.ctx.mach().read_bytes_at_va(va, 8)?;
        Ok(self.ctx.mach().endian().read_u64(bytes.try_into().unwrap()))
    }
}
