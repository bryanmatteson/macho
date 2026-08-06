use crate::metadata::dyld::error::{Error, Result};
use crate::metadata::dyld::model::addr::Va;
use crate::metadata::dyld::model::macho_file::MachoFile;

/// Target of a resolved pointer.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ResolvedTarget {
    /// Points to a virtual address within this image.
    Address(Va),
    /// Points to an imported symbol.
    Import {
        #[doc = "The name field."]
        name: String,
        #[doc = "The lib_ordinal field."]
        lib_ordinal: i32,
    },
}

/// Context for resolving pointers in a Mach-O binary.
///
/// Wraps a MachoFile and provides higher-level resolution that accounts
/// for dyld fixup data. This is the foundation that ObjC and other
/// metadata resolvers build on.
pub struct ResolutionContext<'a, 'data> {
    macho: &'a MachoFile<'data>,
}

impl<'a, 'data> ResolutionContext<'a, 'data> {
    /// Performs new.
    pub fn new(macho: &'a MachoFile<'data>) -> Self {
        Self { macho }
    }

    /// Performs macho.
    pub fn macho(&self) -> &MachoFile<'data> {
        self.macho
    }

    /// Read a null-terminated C string at the given VA.
    pub fn read_cstring(&self, va: Va) -> Result<&'data str> {
        if va.0 == 0 {
            return Err(Error::address("null VA"));
        }
        let offset = self.macho.address_map().va_to_thin_offset(va)?;
        let start = offset.as_usize();
        let data = self.macho.bytes();
        if start >= data.len() {
            return Err(Error::bounds(start as u64, 1, data.len() as u64));
        }
        let slice = &data[start..];
        let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
        std::str::from_utf8(&slice[..end])
            .map_err(|e| Error::format(format!("invalid UTF-8 at VA {va}: {e}")))
    }

    /// Read a pointer-sized value at the given VA.
    ///
    /// Returns the raw pointer value as it appears on disk. This is *not*
    /// automatically pointer-auth-stripped, because some callers legitimately
    /// want the signed form (e.g. chained-fixup decoders). Call
    /// [`read_pointer_stripped`](Self::read_pointer_stripped) when the value
    /// is intended to be dereferenced as a plain VA.
    pub fn read_pointer(&self, va: Va) -> Result<u64> {
        let endian = self.macho.endian();
        if self.macho.is_64bit() {
            let data = self.macho.read_bytes_at_va(va, 8)?;
            let bytes: [u8; 8] = data.try_into().map_err(|_| {
                Error::format("read_bytes_at_va returned unexpected length (want 8)")
            })?;
            Ok(endian.interpret_u64(u64::from_ne_bytes(bytes)))
        } else {
            let data = self.macho.read_bytes_at_va(va, 4)?;
            let bytes: [u8; 4] = data.try_into().map_err(|_| {
                Error::format("read_bytes_at_va returned unexpected length (want 4)")
            })?;
            Ok(endian.interpret_u32(u32::from_ne_bytes(bytes)) as u64)
        }
    }

    /// Read a pointer and strip arm64e pointer-auth metadata, so the result
    /// is a plain VA that can be passed back into address resolution.
    ///
    /// On non-arm64e images this is identical to [`Self::read_pointer`]; on arm64e
    /// it clears the high 16 bits that encode the ptrauth signature.
    pub fn read_pointer_stripped(&self, va: Va) -> Result<u64> {
        let raw = self.read_pointer(va)?;
        let hdr = self.macho.header();
        let arch = crate::metadata::dyld::model::header::ArchSpec {
            cpu_type: hdr.cpu_type(),
            cpu_subtype: hdr.cpu_subtype(),
        };
        if arch.is_arm64e() {
            Ok(crate::metadata::dyld::model::addr::strip_ptrauth(raw))
        } else {
            Ok(raw)
        }
    }

    /// Performs pointer_size.
    pub fn pointer_size(&self) -> usize {
        if self.macho.is_64bit() { 8 } else { 4 }
    }
}
