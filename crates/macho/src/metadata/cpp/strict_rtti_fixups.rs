//! Pointer-fixup reconstruction for the strict Itanium RTTI decoder.

use std::collections::BTreeMap;

use crate::core::model::addr::{ThinFileOffset, Va};
use crate::core::model::load_command::LoadCommand;
use crate::core::model::macho_file::MachoFile;
use crate::core::model::symbol::SymbolTable;
use crate::metadata::dyld::FixupKind;

use super::super::*;
use crate::metadata::cpp::{Error, Result};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PointerFixup {
    pub(super) encoding: StrictPointerEncoding,
    pub(super) authentication: StrictPointerAuthentication,
    pub(super) target: StrictPointerTarget,
}

pub(super) fn build_pointer_fixups(macho: &MachoFile<'_>) -> Result<BTreeMap<u64, PointerFixup>> {
    let mut values = BTreeMap::new();
    let has_chained = macho
        .load_commands()
        .iter()
        .any(|command| matches!(command.kind(), LoadCommand::DyldChainedFixups(_)));
    if has_chained && !cfg!(feature = "fixups") {
        return Err(Error::unsupported(
            "strict RTTI image uses chained fixups but the fixups feature is disabled",
        ));
    }
    if has_chained {
        let chained = crate::metadata::dyld::parse_chained_fixups(macho)?;
        for fixup in &chained.fixups {
            let segment = macho
                .segments()
                .get(fixup.segment_index)
                .ok_or_else(|| Error::format("chained RTTI fixup has an invalid segment index"))?;
            let file_offset = segment
                .file_offset()
                .0
                .checked_add(fixup.segment_offset)
                .ok_or_else(|| Error::format("chained RTTI fixup file offset overflows"))?;
            let value = match &fixup.kind {
                FixupKind::Rebase { target } => PointerFixup {
                    encoding: StrictPointerEncoding::ChainedRebase,
                    authentication: StrictPointerAuthentication::NotApplicable,
                    target: local_rebase_target(macho, *target)?,
                },
                FixupKind::AuthRebase {
                    target,
                    diversity,
                    key,
                    addr_div,
                } => PointerFixup {
                    encoding: StrictPointerEncoding::ChainedRebase,
                    authentication: StrictPointerAuthentication::Authenticated {
                        key: *key,
                        diversity: *diversity,
                        address_diversity: *addr_div,
                    },
                    target: local_rebase_target(macho, *target)?,
                },
                FixupKind::Bind { import_index, .. } | FixupKind::AuthBind { import_index, .. } => {
                    let import = chained.imports.get(*import_index as usize).ok_or_else(|| {
                        Error::format("chained RTTI bind has an invalid import index")
                    })?;
                    let authentication = match &fixup.kind {
                        FixupKind::AuthBind {
                            diversity,
                            key,
                            addr_div,
                            ..
                        } => StrictPointerAuthentication::Authenticated {
                            key: *key,
                            diversity: *diversity,
                            address_diversity: *addr_div,
                        },
                        _ => StrictPointerAuthentication::NotApplicable,
                    };
                    PointerFixup {
                        encoding: StrictPointerEncoding::ChainedBind {
                            addend: import.addend,
                            weak: import.weak,
                        },
                        authentication,
                        target: StrictPointerTarget::External {
                            symbol: import.name.to_owned(),
                            library_ordinal: import.lib_ordinal,
                        },
                    }
                }
            };
            if values.insert(file_offset, value).is_some() {
                return Err(Error::format("duplicate chained RTTI fixup location"));
            }
        }
        return Ok(values);
    }

    let has_legacy = macho.load_commands().iter().any(|command| {
        matches!(
            command.kind(),
            LoadCommand::DyldInfo(_) | LoadCommand::DyldInfoOnly(_)
        )
    });
    if has_legacy && !cfg!(feature = "fixups") {
        return Err(Error::unsupported(
            "strict RTTI image uses legacy fixups but the fixups feature is disabled",
        ));
    }
    if !has_legacy {
        return Ok(values);
    }
    let mut local_symbols = BTreeMap::<&str, Option<u64>>::new();
    for symbol in macho.ext::<SymbolTable<'_>>()?.symbols() {
        if !symbol.is_defined() || symbol.value == 0 {
            continue;
        }
        local_symbols
            .entry(symbol.name)
            .and_modify(|value| {
                if *value != Some(symbol.value) {
                    *value = None;
                }
            })
            .or_insert(Some(symbol.value));
    }
    let (regular, weak, lazy) = crate::metadata::dyld::parse_bind_entries(macho)?;
    for bind in regular.iter().chain(weak.iter()).chain(lazy.iter()) {
        let segment = macho
            .segments()
            .get(bind.segment_index)
            .ok_or_else(|| Error::format("legacy RTTI bind has an invalid segment index"))?;
        let file_offset = segment
            .file_offset()
            .0
            .checked_add(bind.segment_offset)
            .ok_or_else(|| Error::format("legacy RTTI bind file offset overflows"))?;
        let value = PointerFixup {
            encoding: StrictPointerEncoding::LegacyBind {
                addend: bind.addend,
                weak: bind.weak,
                lazy: bind.lazy,
            },
            authentication: StrictPointerAuthentication::NotApplicable,
            target: if bind.lib_ordinal == 0 {
                local_symbols
                    .get(bind.symbol_name)
                    .and_then(|value| *value)
                    .map_or_else(
                        || StrictPointerTarget::External {
                            symbol: bind.symbol_name.to_owned(),
                            library_ordinal: 0,
                        },
                        |va| StrictPointerTarget::Local { va },
                    )
            } else {
                StrictPointerTarget::External {
                    symbol: bind.symbol_name.to_owned(),
                    library_ordinal: bind
                        .lib_ordinal
                        .clamp(i64::from(i32::MIN), i64::from(i32::MAX))
                        as i32,
                }
            },
        };
        if values.insert(file_offset, value).is_some() {
            return Err(Error::format("duplicate legacy RTTI bind location"));
        }
    }
    for rebase in crate::metadata::dyld::parse_rebase_entries(macho)? {
        let segment = macho
            .segments()
            .get(rebase.segment_index)
            .ok_or_else(|| Error::format("legacy RTTI rebase has an invalid segment index"))?;
        let file_offset = segment
            .file_offset()
            .0
            .checked_add(rebase.segment_offset)
            .ok_or_else(|| Error::format("legacy RTTI rebase file offset overflows"))?;
        let va = macho
            .address_map()
            .thin_offset_to_va(ThinFileOffset(file_offset))?;
        let raw = read_raw_pointer(macho, va)?;
        let value = PointerFixup {
            encoding: StrictPointerEncoding::LegacyRebase,
            authentication: StrictPointerAuthentication::NotApplicable,
            target: if raw == 0 {
                StrictPointerTarget::Null
            } else {
                StrictPointerTarget::Local { va: raw }
            },
        };
        if let Some(existing) = values.get(&file_offset) {
            // A legacy lazy pointer is initially rebased to dyld's stub helper
            // and later overwritten by the lazy bind. Both opcode streams
            // therefore own the same storage. The eventual bind is the
            // semantic target; all other cross-stream collisions are corrupt.
            if matches!(
                existing.encoding,
                StrictPointerEncoding::LegacyBind { lazy: true, .. }
            ) || existing.target == value.target
            {
                continue;
            }
            return Err(Error::format(format!(
                "conflicting legacy RTTI fixup at file offset {file_offset:#x}: {existing:?} versus {value:?}"
            )));
        }
        values.insert(file_offset, value);
    }
    Ok(values)
}

fn local_rebase_target(macho: &MachoFile<'_>, target: u64) -> Result<StrictPointerTarget> {
    let va = macho
        .image_base()
        .0
        .checked_add(target)
        .ok_or_else(|| Error::format("chained RTTI rebase target overflows"))?;
    Ok(if va == 0 {
        StrictPointerTarget::Null
    } else {
        StrictPointerTarget::Local { va }
    })
}

fn read_raw_pointer(macho: &MachoFile<'_>, va: Va) -> Result<u64> {
    let width = if macho.is_64bit() { 8 } else { 4 };
    let bytes = macho.read_bytes_at_va(va, width)?;
    if width == 8 {
        Ok(macho.endian().read_u64(
            bytes
                .try_into()
                .map_err(|_| Error::format("RTTI pointer read returned the wrong width"))?,
        ))
    } else {
        Ok(u64::from(
            macho.endian().read_u32(
                bytes
                    .try_into()
                    .map_err(|_| Error::format("RTTI pointer read returned the wrong width"))?,
            ),
        ))
    }
}
