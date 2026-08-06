//! Reconstruction of a parseable file image from an immutable mapped RVA view.

use std::ops::Range;

use crate::core::format::io::Endian;
use crate::core::model::header::{Bitness, MagicNumber};
use crate::core::{ParseError, ParseErrorKind, ParseResult};

const LC_SEGMENT: u32 = 0x1;
const LC_SEGMENT_64: u32 = 0x19;

/// Immutable random-access reader over one mapped Mach-O module.
pub trait MappedImageReader {
    /// Copy exactly `range.len()` bytes from module-relative virtual addresses.
    fn read_exact(&self, range: Range<u64>) -> ParseResult<Vec<u8>>;

    /// Total number of captured bytes available to reconstruction.
    fn captured_len(&self) -> ParseResult<u64>;
}

/// Resource limits for mapped-image reconstruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaterializationLimits {
    /// Maximum reconstructed file length.
    pub max_file_bytes: u64,
    /// Maximum total load-command bytes.
    pub max_load_command_bytes: u64,
    /// Maximum number of load commands.
    pub max_load_commands: u32,
}

impl Default for MaterializationLimits {
    fn default() -> Self {
        Self {
            max_file_bytes: 512 * 1024 * 1024,
            max_load_command_bytes: 16 * 1024 * 1024,
            max_load_commands: 65_536,
        }
    }
}

/// Mapping from reconstructed file bytes to the mapped RVA bytes that supplied them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRvaMapping {
    /// Reconstructed thin-file byte range.
    pub file: Range<u64>,
    /// Module-relative virtual byte range.
    pub rva: Range<u64>,
}

/// A reconstructed Mach-O file and its source-coordinate map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializedImage {
    bytes: Vec<u8>,
    mappings: Vec<FileRvaMapping>,
    synthetic_padding: Vec<Range<u64>>,
}

impl MaterializedImage {
    /// Parseable thin Mach-O bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume the result and return its parseable bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// File-to-RVA mappings in file order.
    pub fn mappings(&self) -> &[FileRvaMapping] {
        &self.mappings
    }

    /// Unbacked file ranges filled with zero solely to preserve file layout.
    ///
    /// Consumers must not cite these ranges as captured evidence.
    pub fn synthetic_padding(&self) -> &[Range<u64>] {
        &self.synthetic_padding
    }
}

#[derive(Debug, Clone, Copy)]
struct RawSegment {
    vmaddr: u64,
    fileoff: u64,
    filesize: u64,
}

/// Reconstruct one parseable thin file from an immutable mapped-module snapshot.
pub fn materialize_mapped_image(
    reader: &impl MappedImageReader,
    limits: MaterializationLimits,
) -> ParseResult<MaterializedImage> {
    let prefix = reader.read_exact(0..32)?;
    let magic_bytes: [u8; 4] = prefix
        .get(..4)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| ParseError::bounds(0, 4, prefix.len() as u64))?;
    let magic = MagicNumber::from_u32(u32::from_ne_bytes(magic_bytes))?;
    let endian = magic.endian();
    let bitness = magic.bitness();
    let header_size = bitness.header_size();
    let ncmds = read_u32(&prefix, 16, endian, "Mach-O command count")?;
    let sizeofcmds = u64::from(read_u32(&prefix, 20, endian, "Mach-O load-command bytes")?);
    if ncmds > limits.max_load_commands {
        return Err(ParseError::limit(format!(
            "Mach-O command count {ncmds} exceeds {}",
            limits.max_load_commands
        )));
    }
    if sizeofcmds > limits.max_load_command_bytes {
        return Err(ParseError::limit(format!(
            "Mach-O load-command bytes {sizeofcmds} exceed {}",
            limits.max_load_command_bytes
        )));
    }
    let commands_end = (header_size as u64)
        .checked_add(sizeofcmds)
        .ok_or_else(|| ParseError::command("Mach-O load-command extent overflows"))?;
    let header_and_commands = reader.read_exact(0..commands_end)?;
    let commands_end_usize = usize::try_from(commands_end)
        .map_err(|_| ParseError::limit("Mach-O load commands exceed host limits"))?;
    let mut cursor = header_size;
    let mut segments = Vec::new();
    for index in 0..ncmds {
        let command = read_u32(&header_and_commands, cursor, endian, "Mach-O load command")?;
        let command_size = usize::try_from(read_u32(
            &header_and_commands,
            cursor
                .checked_add(4)
                .ok_or_else(|| ParseError::command("load-command offset overflows"))?,
            endian,
            "Mach-O load-command size",
        )?)
        .map_err(|_| ParseError::limit("Mach-O load-command size exceeds host limits"))?;
        let command_end = cursor
            .checked_add(command_size)
            .ok_or_else(|| ParseError::command("Mach-O load-command extent overflows"))?;
        if command_size < 8 || command_end > commands_end_usize {
            return Err(ParseError::command(format!(
                "Mach-O load command {index} is truncated"
            )));
        }
        let segment = match (command, bitness) {
            (LC_SEGMENT_64, Bitness::Bits64) if command_size >= 72 => Some(RawSegment {
                vmaddr: read_u64(&header_and_commands, cursor + 24, endian, "segment vmaddr")?,
                fileoff: read_u64(&header_and_commands, cursor + 40, endian, "segment fileoff")?,
                filesize: read_u64(
                    &header_and_commands,
                    cursor + 48,
                    endian,
                    "segment filesize",
                )?,
            }),
            (LC_SEGMENT, Bitness::Bits32) if command_size >= 56 => Some(RawSegment {
                vmaddr: u64::from(read_u32(
                    &header_and_commands,
                    cursor + 24,
                    endian,
                    "segment vmaddr",
                )?),
                fileoff: u64::from(read_u32(
                    &header_and_commands,
                    cursor + 32,
                    endian,
                    "segment fileoff",
                )?),
                filesize: u64::from(read_u32(
                    &header_and_commands,
                    cursor + 36,
                    endian,
                    "segment filesize",
                )?),
            }),
            (LC_SEGMENT_64, Bitness::Bits64) | (LC_SEGMENT, Bitness::Bits32) => {
                return Err(ParseError::command(format!(
                    "Mach-O segment command {index} is truncated"
                )));
            }
            _ => None,
        };
        if let Some(segment) = segment.filter(|segment| segment.filesize != 0) {
            segments.push(segment);
        }
        cursor = command_end;
    }
    if cursor != commands_end_usize || segments.is_empty() {
        return Err(ParseError::new(
            ParseErrorKind::InvalidLoadCommand,
            "Mach-O load commands or file-backed segments are incomplete",
        ));
    }
    let image_base = segments
        .iter()
        .map(|segment| segment.vmaddr)
        .min()
        .ok_or_else(|| ParseError::format("Mach-O image base is absent"))?;
    segments.sort_by_key(|segment| segment.fileoff);
    let file_len = segments.iter().try_fold(0_u64, |length, segment| {
        segment
            .fileoff
            .checked_add(segment.filesize)
            .map(|end| length.max(end))
            .ok_or_else(|| ParseError::address("Mach-O file extent overflows"))
    })?;
    if file_len == 0 || file_len > limits.max_file_bytes {
        return Err(ParseError::limit(format!(
            "reconstructed Mach-O length {file_len} exceeds {}",
            limits.max_file_bytes
        )));
    }
    let source_len = segments.iter().try_fold(0_u64, |total, segment| {
        total
            .checked_add(segment.filesize)
            .ok_or_else(|| ParseError::limit("Mach-O mapped source length overflows"))
    })?;
    let captured_len = reader.captured_len()?;
    if source_len > captured_len {
        return Err(ParseError::bounds(0, source_len, captured_len));
    }
    let mut bytes = vec![
        0_u8;
        usize::try_from(file_len).map_err(|_| ParseError::limit(
            "reconstructed Mach-O exceeds host limits"
        ))?
    ];
    let mut mappings = Vec::with_capacity(segments.len());
    let mut synthetic_padding = Vec::new();
    let mut prior_file_end = 0_u64;
    for segment in segments {
        if segment.fileoff < prior_file_end {
            return Err(ParseError::validation(
                "Mach-O file-backed segments overlap",
            ));
        }
        if prior_file_end < segment.fileoff {
            synthetic_padding.push(prior_file_end..segment.fileoff);
        }
        let rva_start = segment
            .vmaddr
            .checked_sub(image_base)
            .ok_or_else(|| ParseError::address("Mach-O segment precedes image base"))?;
        let rva_end = rva_start
            .checked_add(segment.filesize)
            .ok_or_else(|| ParseError::address("Mach-O segment RVA extent overflows"))?;
        let source = reader.read_exact(rva_start..rva_end)?;
        let file_end = segment
            .fileoff
            .checked_add(segment.filesize)
            .ok_or_else(|| ParseError::address("Mach-O segment file extent overflows"))?;
        let start = usize::try_from(segment.fileoff)
            .map_err(|_| ParseError::limit("Mach-O segment file offset exceeds host limits"))?;
        let end = usize::try_from(file_end)
            .map_err(|_| ParseError::limit("Mach-O segment file end exceeds host limits"))?;
        bytes
            .get_mut(start..end)
            .ok_or_else(|| ParseError::bounds(segment.fileoff, segment.filesize, file_len))?
            .copy_from_slice(&source);
        mappings.push(FileRvaMapping {
            file: segment.fileoff..file_end,
            rva: rva_start..rva_end,
        });
        prior_file_end = file_end;
    }
    crate::core::format::parse_macho_file(&bytes)?;
    Ok(MaterializedImage {
        bytes,
        mappings,
        synthetic_padding,
    })
}

fn read_u32(bytes: &[u8], offset: usize, endian: Endian, subject: &str) -> ParseResult<u32> {
    let value: [u8; 4] = bytes
        .get(offset..offset.saturating_add(4))
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| ParseError::command(format!("{subject} is truncated")))?;
    Ok(endian.read_u32(value))
}

fn read_u64(bytes: &[u8], offset: usize, endian: Endian, subject: &str) -> ParseResult<u64> {
    let value: [u8; 8] = bytes
        .get(offset..offset.saturating_add(8))
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| ParseError::command(format!("{subject} is truncated")))?;
    Ok(endian.read_u64(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct BytesReader(Vec<u8>);

    impl MappedImageReader for BytesReader {
        fn read_exact(&self, range: Range<u64>) -> ParseResult<Vec<u8>> {
            self.0
                .get(range.start as usize..range.end as usize)
                .map(<[u8]>::to_vec)
                .ok_or_else(|| {
                    ParseError::bounds(
                        range.start,
                        range.end.saturating_sub(range.start),
                        self.0.len() as u64,
                    )
                })
        }

        fn captured_len(&self) -> ParseResult<u64> {
            Ok(self.0.len() as u64)
        }
    }

    fn mapped_thin64() -> Vec<u8> {
        let mut bytes = vec![0_u8; 104];
        bytes[0..4].copy_from_slice(&0xfeed_facfu32.to_le_bytes());
        bytes[4..8].copy_from_slice(&0x0100_0007i32.to_le_bytes());
        bytes[8..12].copy_from_slice(&3_i32.to_le_bytes());
        bytes[12..16].copy_from_slice(&2_u32.to_le_bytes());
        bytes[16..20].copy_from_slice(&1_u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&72_u32.to_le_bytes());
        bytes[32..36].copy_from_slice(&LC_SEGMENT_64.to_le_bytes());
        bytes[36..40].copy_from_slice(&72_u32.to_le_bytes());
        bytes[40..46].copy_from_slice(b"__TEXT");
        bytes[56..64].copy_from_slice(&0x1000_u64.to_le_bytes());
        bytes[64..72].copy_from_slice(&104_u64.to_le_bytes());
        bytes[72..80].copy_from_slice(&0_u64.to_le_bytes());
        bytes[80..88].copy_from_slice(&104_u64.to_le_bytes());
        bytes[88..92].copy_from_slice(&7_u32.to_le_bytes());
        bytes[92..96].copy_from_slice(&5_u32.to_le_bytes());
        bytes
    }

    #[test]
    fn materialization_retains_file_rva_provenance() {
        let source = mapped_thin64();
        let image = materialize_mapped_image(
            &BytesReader(source.clone()),
            MaterializationLimits::default(),
        )
        .expect("mapped image");
        assert_eq!(image.bytes(), source);
        assert_eq!(
            image.mappings(),
            [FileRvaMapping {
                file: 0..104,
                rva: 0..104,
            }]
        );
        assert!(image.synthetic_padding().is_empty());
    }
}
