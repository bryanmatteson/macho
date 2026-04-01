use crate::error::{Error, Result};
use crate::model::addr::types::{Rva, ThinFileOffset, Va};

#[derive(Debug, Clone)]
pub struct MappingEntry {
    pub file_offset: ThinFileOffset,
    pub file_size: u64,
    pub vm_addr: Va,
    pub vm_size: u64,
}

#[derive(Debug, Clone)]
pub struct AddressMap {
    entries: Vec<MappingEntry>,
}

impl AddressMap {
    pub fn new(entries: Vec<MappingEntry>) -> Self {
        Self { entries }
    }

    pub fn entries(&self) -> &[MappingEntry] {
        &self.entries
    }

    pub fn thin_offset_to_va(&self, offset: ThinFileOffset) -> Result<Va> {
        for e in &self.entries {
            if e.file_size == 0 {
                continue;
            }
            let rel = offset.0.wrapping_sub(e.file_offset.0);
            if rel < e.file_size {
                return Ok(Va(e.vm_addr.0 + rel));
            }
        }
        Err(Error::Address(format!(
            "file offset {offset} is not mapped to any segment"
        )))
    }

    pub fn va_to_thin_offset(&self, va: Va) -> Result<ThinFileOffset> {
        for e in &self.entries {
            if e.vm_size == 0 {
                continue;
            }
            let rel = va.0.wrapping_sub(e.vm_addr.0);
            if rel < e.vm_size {
                if rel < e.file_size {
                    return Ok(ThinFileOffset(e.file_offset.0 + rel));
                } else {
                    return Err(Error::Address(format!(
                        "VA {va} maps to zero-fill region (beyond file-backed portion)"
                    )));
                }
            }
        }
        Err(Error::Address(format!(
            "VA {va} is not mapped to any segment"
        )))
    }

    pub fn rva_to_va(rva: Rva, image_base: Va) -> Va {
        Va(image_base.0 + rva.0)
    }

    pub fn va_to_rva(va: Va, image_base: Va) -> Rva {
        Rva(va.0.wrapping_sub(image_base.0))
    }

    pub fn rva_to_thin_offset(&self, rva: Rva, image_base: Va) -> Result<ThinFileOffset> {
        let va = Self::rva_to_va(rva, image_base);
        self.va_to_thin_offset(va)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_map() -> AddressMap {
        AddressMap::new(vec![
            MappingEntry {
                file_offset: ThinFileOffset(0),
                file_size: 0x1000,
                vm_addr: Va(0x100000000),
                vm_size: 0x1000,
            },
            MappingEntry {
                file_offset: ThinFileOffset(0x1000),
                file_size: 0x2000,
                vm_addr: Va(0x100001000),
                vm_size: 0x2000,
            },
        ])
    }

    #[test]
    fn offset_to_va() {
        let map = test_map();
        assert_eq!(
            map.thin_offset_to_va(ThinFileOffset(0x100)).unwrap(),
            Va(0x100000100)
        );
        assert_eq!(
            map.thin_offset_to_va(ThinFileOffset(0x1500)).unwrap(),
            Va(0x100001500)
        );
    }

    #[test]
    fn va_to_offset() {
        let map = test_map();
        assert_eq!(
            map.va_to_thin_offset(Va(0x100000100)).unwrap(),
            ThinFileOffset(0x100)
        );
    }

    #[test]
    fn unmapped_address_error() {
        let map = test_map();
        assert!(map.va_to_thin_offset(Va(0xDEAD)).is_err());
        assert!(map.thin_offset_to_va(ThinFileOffset(0x9000)).is_err());
    }

    #[test]
    fn rva_round_trip() {
        let base = Va(0x100000000);
        let va = Va(0x100001234);
        let rva = AddressMap::va_to_rva(va, base);
        assert_eq!(rva, Rva(0x1234));
        assert_eq!(AddressMap::rva_to_va(rva, base), va);
    }
}
