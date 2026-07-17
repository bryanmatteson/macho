#![deny(missing_docs)]
//! Objective-C runtime metadata parsing.

extern crate self as objc;

pub use macho_core::{format, model};
pub use macho_dyld as dyld;

/// The error module.
pub mod error;
pub(crate) use error::Error;
pub use error::{ObjcError, ObjcErrorKind, Result};

/// The category module.
pub mod category;
/// The class module.
pub mod class;
pub mod compat;
/// The encoding module.
pub mod encoding;
/// The ivar module.
pub mod ivar;
/// The method module.
pub mod method;
/// The property module.
pub mod property;
/// The protocol module.
pub mod protocol;
/// The resolve module.
pub mod resolve;
/// The types module.
pub mod types;

pub use types::{ObjCCategory, ObjCClass, ObjCIvar, ObjCMethod, ObjCProperty, ObjCProtocol};

use crate::model::ext::MachoExt;
use crate::model::macho_file::MachoFile;
use resolve::ObjCResolver;

/// Parsed ObjC metadata from a Mach-O binary.
pub struct ObjCMetadata {
    /// The classes field.
    pub classes: Vec<ObjCClass>,
    /// The categories field.
    pub categories: Vec<ObjCCategory>,
    /// The protocols field.
    pub protocols: Vec<ObjCProtocol>,
}

impl<'data> MachoExt<'data> for ObjCMetadata {
    type Error = ObjcError;

    fn parse<'mf>(macho: &'mf MachoFile<'data>) -> Result<Self>
    where
        'data: 'mf,
    {
        parse_objc_metadata(macho)
    }
}

/// Performs parse_objc_metadata.
pub fn parse_objc_metadata(macho: &MachoFile<'_>) -> Result<ObjCMetadata> {
    if !macho.is_64bit() {
        return Err(Error::unsupported(
            "ObjC metadata parsing is only supported for 64-bit binaries",
        ));
    }
    let resolver = ObjCResolver::new(macho);
    // Parse classes from __objc_classlist
    let classes = parse_pointer_list(macho, "__objc_classlist")
        .map(|ptrs| {
            ptrs.into_iter()
                .filter_map(|file_off| {
                    let va = resolver.read_pointer_at_offset(file_off).ok()??;
                    class::parse_class(&resolver, va).ok()
                })
                .filter(|c| !c.is_meta) // filter out metaclasses
                .collect()
        })
        .unwrap_or_default();

    // Parse categories from __objc_catlist
    let categories = parse_pointer_list(macho, "__objc_catlist")
        .map(|ptrs| {
            ptrs.into_iter()
                .filter_map(|file_off| {
                    let va = resolver.read_pointer_at_offset(file_off).ok()??;
                    category::parse_category(&resolver, va).ok()
                })
                .collect()
        })
        .unwrap_or_default();

    // Parse protocols from __objc_protolist
    let protocols = parse_pointer_list(macho, "__objc_protolist")
        .map(|ptrs| {
            ptrs.into_iter()
                .filter_map(|file_off| {
                    let va = resolver.read_pointer_at_offset(file_off).ok()??;
                    protocol::parse_protocol(&resolver, va).ok()
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(ObjCMetadata {
        classes,
        categories,
        protocols,
    })
}

/// Find a section by name across all segments and return file offsets
/// for each pointer-sized entry.
fn parse_pointer_list(macho: &MachoFile<'_>, sect_name: &str) -> Result<Vec<u64>> {
    // Search in __DATA_CONST first, then __DATA
    let section = macho
        .all_sections()
        .find(|s| s.section_name() == sect_name)
        .ok_or_else(|| Error::format(format!("section {sect_name} not found")))?;

    let offset = section.offset().0;
    let size = section.size();
    let count = (size / 8) as usize; // each entry is a pointer (8 bytes for 64-bit)

    let mut offsets = Vec::with_capacity(count.min(100_000));
    for i in 0..count {
        offsets.push(offset + i as u64 * 8);
    }

    Ok(offsets)
}

impl std::fmt::Debug for ObjCMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObjCMetadata")
            .field("classes", &self.classes.len())
            .field("categories", &self.categories.len())
            .field("protocols", &self.protocols.len())
            .finish()
    }
}
