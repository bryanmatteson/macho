use crate::core::error::{Error, Result};
use crate::core::model::addr::types::{Rva, ThinFileOffset, Va};

/// One validated file-to-virtual mapping.
#[derive(Debug, Clone)]
pub struct MappingEntry {
    file_offset: ThinFileOffset,
    file_size: u64,
    vm_addr: Va,
    vm_size: u64,
}

impl MappingEntry {
    /// Construct a mapping after checking file and virtual range arithmetic.
    pub fn try_new(
        file_offset: ThinFileOffset,
        file_size: u64,
        vm_addr: Va,
        vm_size: u64,
    ) -> Result<Self> {
        file_offset
            .0
            .checked_add(file_size)
            .ok_or_else(|| Error::address("mapping file range overflows"))?;
        vm_addr
            .0
            .checked_add(vm_size)
            .ok_or_else(|| Error::address("mapping virtual range overflows"))?;
        if file_size > vm_size {
            return Err(Error::address(format!(
                "mapping file size {file_size:#x} exceeds virtual size {vm_size:#x}"
            )));
        }
        Ok(Self {
            file_offset,
            file_size,
            vm_addr,
            vm_size,
        })
    }

    /// Thin-image-relative file start.
    pub fn file_offset(&self) -> ThinFileOffset {
        self.file_offset
    }

    /// File-backed length.
    pub fn file_size(&self) -> u64 {
        self.file_size
    }

    /// Virtual start address.
    pub fn vm_addr(&self) -> Va {
        self.vm_addr
    }

    /// Virtual range length.
    pub fn vm_size(&self) -> u64 {
        self.vm_size
    }
}

/// Sorted, non-overlapping file and virtual address mappings.
#[derive(Debug, Clone)]
pub struct AddressMap {
    entries: Vec<MappingEntry>,
}

impl AddressMap {
    /// Validate, stably sort, and construct an address map.
    pub fn try_new(mut entries: Vec<MappingEntry>) -> Result<Self> {
        entries.sort_by_key(|entry| (entry.file_offset.0, entry.vm_addr.0));
        for pair in entries.windows(2) {
            let left_file_end = pair[0]
                .file_offset
                .0
                .checked_add(pair[0].file_size)
                .ok_or_else(|| Error::address("mapping file range overflows"))?;
            if pair[0].file_size != 0
                && pair[1].file_size != 0
                && pair[1].file_offset.0 < left_file_end
            {
                return Err(Error::address("mapping file ranges overlap"));
            }
        }
        let mut virtual_order: Vec<_> = entries.iter().collect();
        virtual_order.sort_by_key(|entry| entry.vm_addr.0);
        for pair in virtual_order.windows(2) {
            let left_vm_end = pair[0]
                .vm_addr
                .0
                .checked_add(pair[0].vm_size)
                .ok_or_else(|| Error::address("mapping virtual range overflows"))?;
            if pair[0].vm_size != 0 && pair[1].vm_size != 0 && pair[1].vm_addr.0 < left_vm_end {
                return Err(Error::address("mapping virtual ranges overlap"));
            }
        }
        Ok(Self { entries })
    }

    /// Validated mappings in stable file-offset order.
    pub fn entries(&self) -> &[MappingEntry] {
        &self.entries
    }

    /// Convert a thin-image-relative file offset to a virtual address.
    pub fn thin_offset_to_va(&self, offset: ThinFileOffset) -> Result<Va> {
        for entry in &self.entries {
            if entry.file_size == 0 {
                continue;
            }
            let Some(relative) = offset.0.checked_sub(entry.file_offset.0) else {
                continue;
            };
            if relative < entry.file_size {
                return entry
                    .vm_addr
                    .0
                    .checked_add(relative)
                    .map(Va)
                    .ok_or_else(|| Error::address("mapped virtual address overflows"));
            }
        }
        Err(Error::address(format!(
            "file offset {offset} is not mapped to any segment"
        )))
    }

    /// Convert a virtual address to a thin-image-relative file offset.
    pub fn va_to_thin_offset(&self, va: Va) -> Result<ThinFileOffset> {
        for entry in &self.entries {
            if entry.vm_size == 0 {
                continue;
            }
            let Some(relative) = va.0.checked_sub(entry.vm_addr.0) else {
                continue;
            };
            if relative < entry.vm_size {
                if relative >= entry.file_size {
                    return Err(Error::address(format!(
                        "VA {va} maps to zero-fill region (beyond file-backed portion)"
                    )));
                }
                return entry
                    .file_offset
                    .0
                    .checked_add(relative)
                    .map(ThinFileOffset)
                    .ok_or_else(|| Error::address("mapped file offset overflows"));
            }
        }
        Err(Error::address(format!(
            "VA {va} is not mapped to any segment"
        )))
    }

    /// Convert an RVA to a VA with checked arithmetic.
    pub fn rva_to_va(rva: Rva, image_base: Va) -> Result<Va> {
        image_base
            .0
            .checked_add(rva.0)
            .map(Va)
            .ok_or_else(|| Error::address("RVA to VA conversion overflows"))
    }

    /// Convert a VA to an RVA, rejecting addresses before the image base.
    pub fn va_to_rva(va: Va, image_base: Va) -> Result<Rva> {
        va.0.checked_sub(image_base.0)
            .map(Rva)
            .ok_or_else(|| Error::address("VA precedes image base"))
    }

    /// Convert an RVA to a thin-image-relative file offset.
    pub fn rva_to_thin_offset(&self, rva: Rva, image_base: Va) -> Result<ThinFileOffset> {
        let va = Self::rva_to_va(rva, image_base)?;
        self.va_to_thin_offset(va)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(file: u64, size: u64, va: u64) -> MappingEntry {
        MappingEntry::try_new(ThinFileOffset(file), size, Va(va), size).unwrap()
    }

    fn test_map() -> AddressMap {
        AddressMap::try_new(vec![
            entry(0, 0x1000, 0x1_0000_0000),
            entry(0x1000, 0x2000, 0x1_0000_1000),
        ])
        .unwrap()
    }

    #[test]
    fn conversions_are_checked_and_round_trip() {
        let map = test_map();
        let va = map.thin_offset_to_va(ThinFileOffset(0x1500)).unwrap();
        assert_eq!(va, Va(0x1_0000_1500));
        assert_eq!(map.va_to_thin_offset(va).unwrap(), ThinFileOffset(0x1500));
        assert_eq!(
            AddressMap::va_to_rva(va, Va(0x1_0000_0000)).unwrap(),
            Rva(0x1500)
        );
    }

    #[test]
    fn overlap_and_overflow_are_rejected() {
        assert!(
            AddressMap::try_new(vec![entry(0, 0x1000, 0x1000), entry(0x800, 0x1000, 0x3000)])
                .is_err()
        );
        assert!(MappingEntry::try_new(ThinFileOffset(u64::MAX), 2, Va(0), 2).is_err());
    }
}
