pub mod category;
pub mod class;
pub mod graph;
pub mod ivar;
pub mod method;
pub mod property;
pub mod protocol;
pub mod render;
pub mod resolve;
pub mod types;

pub use types::{ObjCCategory, ObjCClass, ObjCIvar, ObjCMethod, ObjCProperty, ObjCProtocol};

use crate::error::{Error, Result};
use crate::ext::MachExt;
use crate::model::mach::MachFile;
use resolve::ObjCResolver;

/// Parsed ObjC metadata from a Mach-O binary.
pub struct ObjCMetadata {
    pub classes: Vec<ObjCClass>,
    pub categories: Vec<ObjCCategory>,
    pub protocols: Vec<ObjCProtocol>,
}

impl<'data> MachExt<'data> for ObjCMetadata {
    fn parse<'mf>(mach: &'mf MachFile<'data>) -> Result<Self>
    where
        'data: 'mf,
    {
        parse_objc_metadata(mach)
    }
}

pub fn parse_objc_metadata(mach: &MachFile<'_>) -> Result<ObjCMetadata> {
    if !mach.is_64bit() {
        return Err(Error::Unsupported(
            "ObjC metadata parsing is only supported for 64-bit binaries".into(),
        ));
    }
    let resolver = ObjCResolver::new(mach);
    // Parse classes from __objc_classlist
    let classes = parse_pointer_list(mach, "__objc_classlist")
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
    let categories = parse_pointer_list(mach, "__objc_catlist")
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
    let protocols = parse_pointer_list(mach, "__objc_protolist")
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
fn parse_pointer_list(mach: &MachFile<'_>, sect_name: &str) -> Result<Vec<u64>> {
    // Search in __DATA_CONST first, then __DATA
    let section = mach
        .all_sections()
        .find(|s| s.section_name == sect_name)
        .ok_or_else(|| Error::Format(format!("section {sect_name} not found")))?;

    let offset = section.offset.0;
    let size = section.size;
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
