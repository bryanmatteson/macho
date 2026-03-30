use crate::addr::Va;
use crate::error::{Error, Result};
use crate::model::mach::MachFile;

/// Target of a resolved pointer.
#[derive(Debug, Clone)]
pub enum ResolvedTarget {
    /// Points to a virtual address within this image.
    Address(Va),
    /// Points to an imported symbol.
    Import { name: String, lib_ordinal: i32 },
}

/// Context for resolving pointers in a Mach-O binary.
///
/// Wraps a MachFile and provides higher-level resolution that accounts
/// for dyld fixup data. This is the foundation that ObjC and other
/// metadata resolvers build on.
pub struct ResolutionContext<'a, 'data> {
    mach: &'a MachFile<'data>,
}

impl<'a, 'data> ResolutionContext<'a, 'data> {
    pub fn new(mach: &'a MachFile<'data>) -> Self {
        Self { mach }
    }

    pub fn mach(&self) -> &MachFile<'data> {
        self.mach
    }

    /// Read a null-terminated C string at the given VA.
    pub fn read_cstring(&self, va: Va) -> Result<&'data str> {
        if va.0 == 0 {
            return Err(Error::Address("null VA".into()));
        }
        let offset = self.mach.address_map().va_to_thin_offset(va)?;
        let start = offset.as_usize();
        let data = self.mach.bytes();
        if start >= data.len() {
            return Err(Error::Bounds {
                offset: start as u64,
                needed: 1,
                available: data.len() as u64,
            });
        }
        let slice = &data[start..];
        let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
        std::str::from_utf8(&slice[..end])
            .map_err(|e| Error::Format(format!("invalid UTF-8 at VA {va}: {e}")))
    }

    /// Read a pointer-sized value at the given VA.
    /// Returns the raw u64 value (may be a fixup target, not a plain address).
    /// Reads 4 bytes for 32-bit Mach-Os and 8 bytes for 64-bit.
    pub fn read_pointer(&self, va: Va) -> Result<u64> {
        let endian = self.mach.endian();
        if self.mach.is_64bit() {
            let data = self.mach.read_bytes_at_va(va, 8)?;
            Ok(endian.interpret_u64(u64::from_ne_bytes(data.try_into().unwrap())))
        } else {
            let data = self.mach.read_bytes_at_va(va, 4)?;
            Ok(endian.interpret_u32(u32::from_ne_bytes(data.try_into().unwrap())) as u64)
        }
    }

    pub fn pointer_size(&self) -> usize {
        if self.mach.is_64bit() { 8 } else { 4 }
    }
}
