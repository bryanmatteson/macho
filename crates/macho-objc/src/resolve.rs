use std::collections::HashMap;

#[cfg(feature = "fixups")]
use crate::dyld::chained::{ChainedFixups, parse_chained_fixups};
#[cfg(feature = "fixups")]
use crate::dyld::types::FixupKind;
use crate::error::{Error, Result};
use crate::format::io::endian::Endian;
use crate::format::io::pod;
use crate::model::addr::{ThinFileOffset, Va};
use crate::model::load_command::LoadCommand;
use crate::model::macho_file::MachoFile;

/// Resolves pointers in ObjC metadata, handling chained fixups.
///
/// For arm64e binaries, raw pointer values in metadata sections are chained
/// fixup entries, not actual addresses. This resolver maps file offsets to
/// their resolved targets.
pub struct ObjCResolver<'data> {
    macho: &'data MachoFile<'data>,
    /// Map from file offset -> resolved fixup
    fixup_map: HashMap<u64, ResolvedFixup>,
    image_base: u64,
    endian: Endian,
}

/// Provenance for one pointer-valued Objective-C metadata field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjCPointerProvenance {
    /// The file stores an ordinary pointer and no fixup record covers it.
    Direct,
    /// A chained rebase resolves the pointer within the image.
    ChainedRebase,
    /// A chained bind names an external symbol.
    ChainedBind {
        /// Imported symbol name.
        import_name: String,
    },
    /// A legacy rebase opcode covers the pointer.
    LegacyRebase,
    /// A legacy bind opcode names an external symbol.
    LegacyBind {
        /// Imported symbol name.
        import_name: String,
    },
}

#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "fixups"), allow(dead_code))]
enum ResolvedFixup {
    ChainedRebase(u64),
    ChainedBind { import_name: String },
    LegacyRebase,
    LegacyBind { import_name: String },
}

impl<'data> ObjCResolver<'data> {
    /// Performs new.
    pub fn new(macho: &'data MachoFile<'data>) -> Result<Self> {
        let image_base = macho.image_base().0;
        let endian = macho.endian();

        // Presence is decided by the load command, not by whether its payload
        // happened to parse. Damaged chained metadata must reject rather than
        // being misclassified as an image that uses legacy fixups.
        #[cfg(feature = "fixups")]
        let fixup_map = if macho
            .find_load_command(|command| matches!(command, LoadCommand::DyldChainedFixups(_)))
            .is_some()
        {
            let fixups = parse_chained_fixups(macho)?;
            build_fixup_map(macho, &fixups)?
        } else {
            build_legacy_fixup_map(macho)?
        };
        #[cfg(not(feature = "fixups"))]
        let fixup_map = {
            if macho
                .find_load_command(|command| {
                    matches!(
                        command,
                        LoadCommand::DyldChainedFixups(_)
                            | LoadCommand::DyldInfo(_)
                            | LoadCommand::DyldInfoOnly(_)
                    )
                })
                .is_some()
            {
                return Err(Error::unsupported(
                    "Objective-C fixup decoding requires the `fixups` feature",
                ));
            }
            HashMap::new()
        };

        Ok(Self {
            macho,
            fixup_map,
            image_base,
            endian,
        })
    }

    /// Read a pointer at a file offset, resolving chained fixups.
    /// Returns the resolved VA target, or None if it's an external bind.
    pub fn read_pointer_at_offset(&self, file_offset: u64) -> Result<Option<Va>> {
        // Check fixup map first
        if let Some(fixup) = self.fixup_map.get(&file_offset) {
            return match fixup {
                ResolvedFixup::ChainedRebase(target) => self
                    .image_base
                    .checked_add(*target)
                    .map(Va)
                    .map(Some)
                    .ok_or_else(|| Error::address("chained rebase target overflows")),
                ResolvedFixup::LegacyRebase => {
                    // The linker already wrote the correct un-slid VA.
                    let raw = pod::read_pod::<u64>(self.macho.bytes(), file_offset as usize)
                        .map(|v| self.endian.interpret_u64(v))?;
                    if raw == 0 {
                        Ok(None)
                    } else {
                        Ok(Some(Va(raw)))
                    }
                }
                ResolvedFixup::ChainedBind { .. } | ResolvedFixup::LegacyBind { .. } => Ok(None),
            };
        }

        // No fixup — read raw pointer value
        let raw = pod::read_pod::<u64>(self.macho.bytes(), file_offset as usize)
            .map(|v| self.endian.interpret_u64(v))?;

        if raw == 0 {
            Ok(None)
        } else {
            Ok(Some(Va(raw)))
        }
    }

    /// Read a pointer at a VA, resolving chained fixups.
    pub fn read_pointer_at_va(&self, va: Va) -> Result<Option<Va>> {
        let offset = self.macho.address_map().va_to_thin_offset(va)?;
        self.read_pointer_at_offset(offset.0)
    }

    /// Read a C string at a VA.
    pub fn read_cstring(&self, va: Va) -> Result<&'data str> {
        if va.0 == 0 {
            return Err(Error::address("null pointer"));
        }
        let offset = self.macho.address_map().va_to_thin_offset(va)?;
        let data = self.macho.bytes();
        let start = offset.as_usize();
        if start >= data.len() {
            return Err(Error::bounds(start as u64, 1, data.len() as u64));
        }
        let slice = &data[start..];
        let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
        std::str::from_utf8(&slice[..end])
            .map_err(|e| Error::format(format!("invalid UTF-8 at VA {va}: {e}")))
    }

    /// Get the file offset for a VA.
    pub fn va_to_offset(&self, va: Va) -> Result<ThinFileOffset> {
        Ok(self.macho.address_map().va_to_thin_offset(va)?)
    }

    /// Get the import name if a fixup at this file offset is a bind.
    pub fn bind_name_at_offset(&self, file_offset: u64) -> Option<&str> {
        match self.fixup_map.get(&file_offset) {
            Some(
                ResolvedFixup::ChainedBind { import_name }
                | ResolvedFixup::LegacyBind { import_name },
            ) => Some(import_name),
            _ => None,
        }
    }

    /// Reports how a pointer field is represented without resolving or
    /// discarding its fixup source.
    pub fn pointer_provenance_at_offset(&self, file_offset: u64) -> ObjCPointerProvenance {
        match self.fixup_map.get(&file_offset) {
            None => ObjCPointerProvenance::Direct,
            Some(ResolvedFixup::ChainedRebase(_)) => ObjCPointerProvenance::ChainedRebase,
            Some(ResolvedFixup::ChainedBind { import_name }) => {
                ObjCPointerProvenance::ChainedBind {
                    import_name: import_name.clone(),
                }
            }
            Some(ResolvedFixup::LegacyRebase) => ObjCPointerProvenance::LegacyRebase,
            Some(ResolvedFixup::LegacyBind { import_name }) => ObjCPointerProvenance::LegacyBind {
                import_name: import_name.clone(),
            },
        }
    }

    /// Performs macho.
    pub fn macho(&self) -> &MachoFile<'data> {
        self.macho
    }

    /// Performs image_base.
    pub fn image_base(&self) -> u64 {
        self.image_base
    }

    /// Performs endian.
    pub fn endian(&self) -> Endian {
        self.endian
    }
}

#[cfg(feature = "fixups")]
fn build_fixup_map(
    macho: &MachoFile<'_>,
    fixups: &ChainedFixups<'_>,
) -> Result<HashMap<u64, ResolvedFixup>> {
    let mut map = HashMap::new();

    for fixup in &fixups.fixups {
        // Convert segment_index + segment_offset to file offset
        let seg = macho.segments().get(fixup.segment_index).ok_or_else(|| {
            Error::format(format!(
                "chained fixup references absent segment {}",
                fixup.segment_index
            ))
        })?;
        let file_offset = seg
            .file_offset()
            .0
            .checked_add(fixup.segment_offset)
            .ok_or_else(|| Error::address("chained fixup file offset overflows"))?;

        match &fixup.kind {
            FixupKind::Rebase { target } | FixupKind::AuthRebase { target, .. } => {
                map.insert(file_offset, ResolvedFixup::ChainedRebase(*target));
            }
            FixupKind::Bind { import_index, .. } | FixupKind::AuthBind { import_index, .. } => {
                let name = fixups
                    .imports
                    .get(*import_index as usize)
                    .map(|import| import.name.to_string())
                    .ok_or_else(|| {
                        Error::format(format!(
                            "chained bind references absent import {import_index}"
                        ))
                    })?;
                map.insert(
                    file_offset,
                    ResolvedFixup::ChainedBind { import_name: name },
                );
            }
            _ => {
                return Err(Error::unsupported(
                    "chained fixup kind is not supported by Objective-C decoding",
                ));
            }
        }
    }

    Ok(map)
}

#[cfg(feature = "fixups")]
fn build_legacy_fixup_map(macho: &MachoFile<'_>) -> Result<HashMap<u64, ResolvedFixup>> {
    let mut map = HashMap::new();

    // Import bind entries — these give us symbol names at specific offsets
    let (regular, weak, lazy) = crate::dyld::bind::parse_bind_entries(macho)?;
    for entry in regular.iter().chain(weak.iter()).chain(lazy.iter()) {
        let seg = macho.segments().get(entry.segment_index).ok_or_else(|| {
            Error::format(format!(
                "legacy bind references absent segment {}",
                entry.segment_index
            ))
        })?;
        let file_offset = seg
            .file_offset()
            .0
            .checked_add(entry.segment_offset)
            .ok_or_else(|| Error::address("legacy bind file offset overflows"))?;
        map.insert(
            file_offset,
            ResolvedFixup::LegacyBind {
                import_name: entry.symbol_name.to_string(),
            },
        );
    }

    // Rebase entries — these tell us which pointers contain relocated addresses
    for entry in crate::dyld::rebase::parse_rebase_entries(macho)? {
        let seg = macho.segments().get(entry.segment_index).ok_or_else(|| {
            Error::format(format!(
                "legacy rebase references absent segment {}",
                entry.segment_index
            ))
        })?;
        let file_offset = seg
            .file_offset()
            .0
            .checked_add(entry.segment_offset)
            .ok_or_else(|| Error::address("legacy rebase file offset overflows"))?;
        // The linker already wrote the correct un-slid VA. Do not overwrite
        // a bind if damaged metadata describes both at one location.
        map.entry(file_offset)
            .or_insert(ResolvedFixup::LegacyRebase);
    }

    Ok(map)
}
