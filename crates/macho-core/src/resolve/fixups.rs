use std::collections::BTreeMap;

use crate::Result;
use crate::dyld::bind::parse_bind_entries;
use crate::dyld::chained::parse_chained_fixups;
use crate::dyld::rebase::parse_rebase_entries;
use crate::dyld::types::FixupKind;
use crate::model::addr::Va;
use crate::model::macho_file::MachoFile;

use super::{ResolutionContext, ResolvedTarget};

pub fn collect_resolved_targets(macho: &MachoFile<'_>) -> BTreeMap<u64, ResolvedTarget> {
    let mut fixups = BTreeMap::new();
    if let Ok(chained) = parse_chained_fixups(macho) {
        for fixup in &chained.fixups {
            let Some(seg) = macho.segments().get(fixup.segment_index) else {
                continue;
            };
            let file_offset = seg.file_offset.0 + fixup.segment_offset;
            let target = match &fixup.kind {
                FixupKind::Rebase { target } | FixupKind::AuthRebase { target, .. } => {
                    ResolvedTarget::Address(Va(macho.image_base().0 + target))
                }
                FixupKind::Bind { import_index, .. } | FixupKind::AuthBind { import_index, .. } => {
                    let Some(import) = chained.imports.get(*import_index as usize) else {
                        continue;
                    };
                    ResolvedTarget::Import {
                        name: import.name.to_string(),
                        lib_ordinal: import.lib_ordinal,
                    }
                }
            };
            fixups.insert(file_offset, target);
        }
        return fixups;
    }

    if let Ok((regular, weak, lazy)) = parse_bind_entries(macho) {
        for bind in regular.iter().chain(weak.iter()).chain(lazy.iter()) {
            if let Some(seg) = macho.segments().get(bind.segment_index) {
                let file_offset = seg.file_offset.0 + bind.segment_offset;
                fixups.insert(
                    file_offset,
                    ResolvedTarget::Import {
                        name: bind.symbol_name.to_string(),
                        lib_ordinal: bind.lib_ordinal.clamp(i32::MIN as i64, i32::MAX as i64)
                            as i32,
                    },
                );
            }
        }
    }

    if let Ok(rebases) = parse_rebase_entries(macho) {
        for rebase in rebases {
            if let Some(seg) = macho.segments().get(rebase.segment_index) {
                let file_offset = seg.file_offset.0 + rebase.segment_offset;
                fixups.insert(file_offset, ResolvedTarget::Address(Va(0)));
            }
        }
    }

    fixups
}

pub fn resolve_pointer_target(
    ctx: &ResolutionContext<'_, '_>,
    fixups: &BTreeMap<u64, ResolvedTarget>,
    va: Va,
) -> Result<ResolvedTarget> {
    let offset = ctx.macho().address_map().va_to_thin_offset(va)?;
    if let Some(target) = fixups.get(&offset.0) {
        if let ResolvedTarget::Address(resolved) = target {
            if resolved.0 == 0 {
                let raw = ctx.read_pointer(va)?;
                return Ok(ResolvedTarget::Address(Va(raw)));
            }
        }
        return Ok(target.clone());
    }

    let raw = ctx.read_pointer(va)?;
    Ok(ResolvedTarget::Address(Va(raw)))
}
