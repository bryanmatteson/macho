use std::collections::HashMap;

use crate::dyld::chained::{ChainedFixups, parse_chained_fixups};
use crate::dyld::types::FixupKind;
use crate::error::{Error, Result};
use crate::format::io::endian::Endian;
use crate::format::io::pod;
use crate::model::addr::{ThinFileOffset, Va};
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

#[derive(Debug, Clone)]
enum ResolvedFixup {
    Rebase(u64),
    Bind { import_name: String },
}

impl<'data> ObjCResolver<'data> {
    /// Performs new.
    pub fn new(macho: &'data MachoFile<'data>) -> Self {
        let image_base = macho.image_base().0;
        let endian = macho.endian();

        // Build fixup map from chained fixups if available, else from
        // legacy bind/rebase opcodes
        let fixup_map = match parse_chained_fixups(macho) {
            Ok(fixups) => build_fixup_map(macho, &fixups),
            Err(_) => build_legacy_fixup_map(macho),
        };

        Self {
            macho,
            fixup_map,
            image_base,
            endian,
        }
    }

    /// Read a pointer at a file offset, resolving chained fixups.
    /// Returns the resolved VA target, or None if it's an external bind.
    pub fn read_pointer_at_offset(&self, file_offset: u64) -> Result<Option<Va>> {
        // Check fixup map first
        if let Some(fixup) = self.fixup_map.get(&file_offset) {
            return match fixup {
                ResolvedFixup::Rebase(target) if *target != 0 => {
                    Ok(Some(Va(self.image_base + target)))
                }
                ResolvedFixup::Rebase(_) => {
                    // Legacy rebase sentinel — read the raw pointer value
                    // (the linker already wrote the correct un-slid VA)
                    let raw = pod::read_pod::<u64>(self.macho.bytes(), file_offset as usize)
                        .map(|v| self.endian.interpret_u64(v))?;
                    if raw == 0 {
                        Ok(None)
                    } else {
                        Ok(Some(Va(raw)))
                    }
                }
                ResolvedFixup::Bind { .. } => Ok(None), // external symbol
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
            Some(ResolvedFixup::Bind { import_name }) => Some(import_name),
            _ => None,
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

fn build_fixup_map(
    macho: &MachoFile<'_>,
    fixups: &ChainedFixups<'_>,
) -> HashMap<u64, ResolvedFixup> {
    let mut map = HashMap::new();

    for fixup in &fixups.fixups {
        // Convert segment_index + segment_offset to file offset
        let seg = match macho.segments().get(fixup.segment_index) {
            Some(s) => s,
            None => continue,
        };
        let file_offset = seg.file_offset().0 + fixup.segment_offset;

        match &fixup.kind {
            FixupKind::Rebase { target } | FixupKind::AuthRebase { target, .. } => {
                map.insert(file_offset, ResolvedFixup::Rebase(*target));
            }
            FixupKind::Bind { import_index, .. } | FixupKind::AuthBind { import_index, .. } => {
                let name = fixups
                    .imports
                    .get(*import_index as usize)
                    .map(|i| i.name.to_string())
                    .unwrap_or_default();
                map.insert(file_offset, ResolvedFixup::Bind { import_name: name });
            }
            _ => continue,
        }
    }

    map
}

fn build_legacy_fixup_map(macho: &MachoFile<'_>) -> HashMap<u64, ResolvedFixup> {
    let mut map = HashMap::new();

    // Import bind entries — these give us symbol names at specific offsets
    if let Ok((regular, weak, lazy)) = crate::dyld::bind::parse_bind_entries(macho) {
        for entry in regular.iter().chain(weak.iter()).chain(lazy.iter()) {
            if let Some(seg) = macho.segments().get(entry.segment_index) {
                let file_offset = seg.file_offset().0 + entry.segment_offset;
                map.insert(
                    file_offset,
                    ResolvedFixup::Bind {
                        import_name: entry.symbol_name.to_string(),
                    },
                );
            }
        }
    }

    // Rebase entries — these tell us which pointers contain relocated addresses
    if let Ok(rebases) = crate::dyld::rebase::parse_rebase_entries(macho) {
        for entry in &rebases {
            if let Some(seg) = macho.segments().get(entry.segment_index) {
                let file_offset = seg.file_offset().0 + entry.segment_offset;
                // For rebases, the actual target is the raw value in the file
                // (the linker already wrote the correct un-slid VA)
                // Don't overwrite binds with rebases
                map.entry(file_offset).or_insert(ResolvedFixup::Rebase(0));
            }
        }
    }

    map
}
