use std::collections::BTreeSet;
use std::ops::Range;

use crate::core::error::{Error, Result};
use crate::core::model::addr::{FatFileOffset, ThinFileOffset};
use crate::core::model::header::{ArchSpec, CpuSubtype, CpuType, FatHeader};
use crate::core::model::macho_file::MachoFile;

/// One validated Mach-O slice in a fat container.
#[derive(Debug)]
pub struct FatArch<'data> {
    spec: ArchSpec,
    fat_offset: FatFileOffset,
    size: u64,
    align: u32,
    reserved: u32,
    macho: MachoFile<'data>,
}

impl<'data> FatArch<'data> {
    /// Construct and validate one fat architecture entry.
    pub(crate) fn try_new(
        spec: ArchSpec,
        fat_offset: FatFileOffset,
        size: u64,
        align: u32,
        reserved: u32,
        macho: MachoFile<'data>,
        container_len: usize,
    ) -> Result<Self> {
        if size == 0 {
            return Err(Error::format("fat architecture slice has zero size"));
        }
        if align >= u64::BITS {
            return Err(Error::format(format!(
                "fat architecture alignment exponent {align} is invalid"
            )));
        }
        let alignment = 1u64
            .checked_shl(align)
            .ok_or_else(|| Error::format(format!("fat alignment 2^{align} overflows")))?;
        if fat_offset.0 % alignment != 0 {
            return Err(Error::format(format!(
                "fat slice offset {:#x} is not aligned to 2^{align}",
                fat_offset.0
            )));
        }
        let end = fat_offset
            .0
            .checked_add(size)
            .ok_or_else(|| Error::format("fat slice offset plus size overflows"))?;
        if end > container_len as u64 {
            return Err(Error::bounds(fat_offset.0, size, container_len as u64));
        }
        if macho.file_size() as u64 != size {
            return Err(Error::format(format!(
                "fat entry size {size} differs from parsed slice size {}",
                macho.file_size()
            )));
        }
        Ok(Self {
            spec,
            fat_offset,
            size,
            align,
            reserved,
            macho,
        })
    }

    /// Architecture tuple declared by the fat table.
    pub fn spec(&self) -> ArchSpec {
        self.spec
    }

    /// Fat-container-relative start offset.
    pub fn fat_offset(&self) -> FatFileOffset {
        self.fat_offset
    }

    /// Slice length in bytes.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Base-two alignment exponent.
    pub fn align(&self) -> u32 {
        self.align
    }

    /// Reserved fat64 table value.
    pub fn reserved(&self) -> u32 {
        self.reserved
    }

    /// Parsed Mach-O image for this slice.
    pub fn macho(&self) -> &MachoFile<'data> {
        &self.macho
    }

    /// Translate a thin-image-relative offset to a fat-container-relative offset.
    pub fn thin_to_fat_offset(&self, thin: ThinFileOffset) -> Result<FatFileOffset> {
        if thin.0 >= self.size {
            return Err(Error::address(format!(
                "thin offset {thin} is outside slice size {:#x}",
                self.size
            )));
        }
        self.fat_offset
            .0
            .checked_add(thin.0)
            .map(FatFileOffset)
            .ok_or_else(|| Error::address("fat offset translation overflows"))
    }

    /// Translate a fat-container-relative offset to a thin-image-relative offset.
    pub fn fat_to_thin_offset(&self, fat: FatFileOffset) -> Result<ThinFileOffset> {
        let rel = fat
            .0
            .checked_sub(self.fat_offset.0)
            .ok_or_else(|| Error::address(format!("fat offset {fat} precedes this slice")))?;
        if rel >= self.size {
            let end = self
                .fat_offset
                .0
                .checked_add(self.size)
                .ok_or_else(|| Error::address("fat slice end overflows"))?;
            return Err(Error::address(format!(
                "fat offset {fat} is outside arch slice at {:#x}..{end:#x}",
                self.fat_offset.0,
            )));
        }
        Ok(ThinFileOffset(rel))
    }
}

/// Validated non-empty fat Mach-O container.
pub struct FatBinary<'data> {
    header: FatHeader,
    arches: Vec<FatArch<'data>>,
    bytes: &'data [u8],
}

impl<'data> FatBinary<'data> {
    /// Validate a complete fat table and its parsed slices.
    pub(crate) fn try_new(
        header: FatHeader,
        arches: Vec<FatArch<'data>>,
        bytes: &'data [u8],
    ) -> Result<Self> {
        let container_len = bytes.len();
        if arches.is_empty() {
            return Err(Error::format("fat binary has zero architectures"));
        }
        if arches.len() != header.architecture_count() as usize {
            return Err(Error::format(format!(
                "fat header declares {} architectures but {} were parsed",
                header.architecture_count(),
                arches.len()
            )));
        }
        let mut identities = BTreeSet::new();
        let mut ranges = Vec::with_capacity(arches.len());
        for arch in &arches {
            if !identities.insert((arch.spec.cpu_type.0, arch.spec.cpu_subtype.0)) {
                return Err(Error::format(format!(
                    "duplicate fat architecture {}",
                    arch.spec.name()
                )));
            }
            let end = arch
                .fat_offset
                .0
                .checked_add(arch.size)
                .ok_or_else(|| Error::format("fat slice end overflows"))?;
            if end > container_len as u64 {
                return Err(Error::bounds(
                    arch.fat_offset.0,
                    arch.size,
                    container_len as u64,
                ));
            }
            ranges.push((arch.fat_offset.0, end));
        }
        ranges.sort_unstable();
        for pair in ranges.windows(2) {
            if pair[1].0 < pair[0].1 {
                return Err(Error::format(format!(
                    "fat slices overlap at {:#x}..{:#x} and {:#x}..{:#x}",
                    pair[0].0, pair[0].1, pair[1].0, pair[1].1
                )));
            }
        }
        Ok(Self {
            header,
            arches,
            bytes,
        })
    }

    /// Fat header.
    pub fn header(&self) -> &FatHeader {
        &self.header
    }

    /// Validated architecture slices in table order.
    pub fn arches(&self) -> &[FatArch<'data>] {
        &self.arches
    }

    /// Complete bytes of the enclosing universal Mach-O input.
    pub fn bytes(&self) -> &'data [u8] {
        self.bytes
    }

    /// Find an architecture by CPU type.
    pub fn find_arch(&self, cpu_type: CpuType) -> Option<&FatArch<'data>> {
        self.arches
            .iter()
            .find(|arch| arch.spec.cpu_type == cpu_type)
    }

    /// Find an architecture by CPU type and masked subtype.
    pub fn find_arch_spec(
        &self,
        cpu_type: CpuType,
        cpu_subtype: CpuSubtype,
    ) -> Option<&FatArch<'data>> {
        self.arches.iter().find(|arch| {
            arch.spec.cpu_type == cpu_type && arch.spec.cpu_subtype.masked() == cpu_subtype.masked()
        })
    }
}

/// Parsed thin or fat Mach-O input.
pub enum MachoContainer<'data> {
    /// One standalone Mach-O image.
    Thin(MachoFile<'data>),
    /// A validated non-empty fat container.
    Fat(FatBinary<'data>),
}

/// Stable identity for exactly one image in a thin or universal container.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectionKey {
    /// Zero-based member index. Thin images always use index zero.
    pub container_index: usize,
    /// Exact CPU type and masked subtype expected at that index.
    pub architecture: ArchSpec,
}

/// One image selected from a validated container together with its byte range.
#[derive(Debug, Clone)]
pub struct SelectedImage<'container, 'data> {
    /// Exact identity used for selection.
    pub key: SelectionKey,
    /// Container-relative byte range occupied by the selected image.
    pub container_range: Range<u64>,
    /// Parsed image borrowed from the validated container.
    pub image: &'container MachoFile<'data>,
}

impl<'data> MachoContainer<'data> {
    /// Complete bytes of the original thin or universal Mach-O input.
    pub fn bytes(&self) -> &'data [u8] {
        match self {
            Self::Thin(macho) => macho.bytes(),
            Self::Fat(fat) => fat.bytes(),
        }
    }

    /// Whether the container is thin.
    pub fn is_thin(&self) -> bool {
        matches!(self, Self::Thin(_))
    }

    /// Whether the container is fat.
    pub fn is_fat(&self) -> bool {
        matches!(self, Self::Fat(_))
    }

    /// Iterate parsed images without allocating a temporary collection.
    pub fn macho_files(&self) -> MachoFiles<'_, 'data> {
        match self {
            Self::Thin(macho) => MachoFiles {
                inner: MachoFilesInner::Thin(Some(macho)),
            },
            Self::Fat(fat) => MachoFiles {
                inner: MachoFilesInner::Fat(fat.arches.iter()),
            },
        }
    }

    /// Return the first image when one exists.
    pub fn first_macho(&self) -> Option<&MachoFile<'data>> {
        match self {
            Self::Thin(macho) => Some(macho),
            Self::Fat(fat) => fat.arches.first().map(FatArch::macho),
        }
    }

    /// Find an image by CPU type.
    pub fn find_arch(&self, cpu_type: CpuType) -> Option<&MachoFile<'data>> {
        match self {
            Self::Thin(macho) if macho.header().cpu_type == cpu_type => Some(macho),
            Self::Thin(_) => None,
            Self::Fat(fat) => fat.find_arch(cpu_type).map(FatArch::macho),
        }
    }

    /// Find an image by CPU type and masked subtype.
    pub fn find_arch_spec(
        &self,
        cpu_type: CpuType,
        cpu_subtype: CpuSubtype,
    ) -> Option<&MachoFile<'data>> {
        match self {
            Self::Thin(macho)
                if macho.header().cpu_type == cpu_type
                    && macho.header().cpu_subtype.masked() == cpu_subtype.masked() =>
            {
                Some(macho)
            }
            Self::Thin(_) => None,
            Self::Fat(fat) => fat
                .find_arch_spec(cpu_type, cpu_subtype)
                .map(FatArch::macho),
        }
    }

    /// Select exactly one image by table index and architecture.
    ///
    /// This is the canonical selection boundary for consumers that retain an
    /// image identity across parse, inspection, and mutation. Both fields are
    /// checked so a stale index cannot silently retarget after container drift.
    pub fn select_exact(&self, key: SelectionKey) -> Result<SelectedImage<'_, 'data>> {
        let (image, start, size) = match self {
            Self::Thin(image) if key.container_index == 0 => (image, 0, image.file_size() as u64),
            Self::Thin(_) => {
                return Err(Error::address(format!(
                    "thin Mach-O has no member at index {}",
                    key.container_index
                )));
            }
            Self::Fat(fat) => {
                let arch = fat.arches.get(key.container_index).ok_or_else(|| {
                    Error::address(format!(
                        "fat Mach-O has no member at index {}",
                        key.container_index
                    ))
                })?;
                (arch.macho(), arch.fat_offset.0, arch.size)
            }
        };
        let actual = ArchSpec {
            cpu_type: image.header().cpu_type(),
            cpu_subtype: image.header().cpu_subtype(),
        };
        if actual.cpu_type != key.architecture.cpu_type
            || actual.cpu_subtype.masked() != key.architecture.cpu_subtype.masked()
        {
            return Err(Error::validation(format!(
                "Mach-O member {} is {}, not {}",
                key.container_index,
                actual.name(),
                key.architecture.name()
            )));
        }
        let end = start
            .checked_add(size)
            .ok_or_else(|| Error::address("selected Mach-O range overflows"))?;
        Ok(SelectedImage {
            key,
            container_range: start..end,
            image,
        })
    }
}

/// Zero-allocation iterator over images in a [`MachoContainer`].
pub struct MachoFiles<'container, 'data> {
    inner: MachoFilesInner<'container, 'data>,
}

enum MachoFilesInner<'container, 'data> {
    Thin(Option<&'container MachoFile<'data>>),
    Fat(std::slice::Iter<'container, FatArch<'data>>),
}

impl<'container, 'data> Iterator for MachoFiles<'container, 'data> {
    type Item = &'container MachoFile<'data>;

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.inner {
            MachoFilesInner::Thin(macho) => macho.take(),
            MachoFilesInner::Fat(arches) => arches.next().map(FatArch::macho),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = match &self.inner {
            MachoFilesInner::Thin(macho) => usize::from(macho.is_some()),
            MachoFilesInner::Fat(arches) => arches.len(),
        };
        (len, Some(len))
    }
}

impl ExactSizeIterator for MachoFiles<'_, '_> {}

impl std::fmt::Debug for FatBinary<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FatBinary")
            .field("header", &self.header)
            .field(
                "arches",
                &self
                    .arches
                    .iter()
                    .map(|arch| arch.spec.name())
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl std::fmt::Debug for MachoContainer<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Thin(macho) => formatter.debug_tuple("Thin").field(macho).finish(),
            Self::Fat(fat) => formatter.debug_tuple("Fat").field(fat).finish(),
        }
    }
}

#[cfg(test)]
mod selection_tests {
    use super::*;
    use crate::core::format::parse;

    fn thin64() -> Vec<u8> {
        let mut bytes = vec![0_u8; 32];
        bytes[0..4].copy_from_slice(&0xfeed_facfu32.to_le_bytes());
        bytes[4..8].copy_from_slice(&0x0100_0007i32.to_le_bytes());
        bytes[8..12].copy_from_slice(&3_i32.to_le_bytes());
        bytes[12..16].copy_from_slice(&2_u32.to_le_bytes());
        bytes
    }

    #[test]
    fn exact_selection_rejects_stale_identity() {
        let bytes = thin64();
        let container = parse(&bytes).expect("thin fixture");
        let key = SelectionKey {
            container_index: 0,
            architecture: ArchSpec {
                cpu_type: CpuType(0x0100_0007),
                cpu_subtype: CpuSubtype(3),
            },
        };
        assert_eq!(
            container
                .select_exact(key)
                .expect("selection")
                .container_range,
            0..32
        );
        assert!(
            container
                .select_exact(SelectionKey {
                    architecture: ArchSpec {
                        cpu_type: CpuType(0x0100_000c),
                        cpu_subtype: CpuSubtype(0),
                    },
                    ..key
                })
                .is_err()
        );
    }
}
