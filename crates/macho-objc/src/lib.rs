#![deny(missing_docs)]
//! Objective-C runtime metadata parsing.
//!
//! Depend on this crate directly for ObjC metadata without the `macho` façade:
//! parse a [`macho_core::MachoFile`] with [`parse_objc_metadata`] or borrow a
//! raw byte source with [`parse_objc_metadata_from_source`].

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
/// Bounded Objective-C method-implementation traversal.
pub mod imp;
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

pub use imp::{ObjCMethodImp, ObjCMethodKind, fold_method_imps, fold_method_imps_from_source};
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

/// Runtime-list source for one Objective-C metadata observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjCRecordKind {
    /// `__objc_classlist` entry.
    Class,
    /// `__objc_catlist` entry.
    Category,
    /// `__objc_protolist` entry.
    Protocol,
}

/// Lossless accounting for one runtime-list entry.
#[derive(Debug, Clone)]
pub struct ObjCRecordObservation {
    /// Runtime-list source.
    pub kind: ObjCRecordKind,
    /// Zero-based list ordinal.
    pub ordinal: usize,
    /// File offset of the pointer-list entry.
    pub pointer_file_offset: u64,
    /// Resolved runtime object address, when readable.
    pub runtime_address: Option<u64>,
    /// Parsed entity name, when the record was decoded.
    pub parsed_name: Option<String>,
    /// Typed parser failure rendered for diagnostics.
    pub error: Option<String>,
    /// Bounded raw runtime record bytes, or pointer bytes when unresolved.
    pub raw: Vec<u8>,
}

/// Parsed metadata plus a conservation ledger for every runtime-list entry.
#[derive(Debug)]
pub struct ObjCMetadataScan {
    /// Successfully decoded semantic metadata.
    pub metadata: ObjCMetadata,
    /// Every class/category/protocol list entry, including malformed entries.
    pub observations: Vec<ObjCRecordObservation>,
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
    Ok(scan_objc_metadata(macho)?.metadata)
}

/// Parse Objective-C metadata from one borrowed thin Mach-O byte source.
///
/// The source is not copied and may be a byte slice, vector, or caller-owned
/// read-only memory map. Universal binaries are rejected because selecting an
/// architecture is a caller decision; parse those with [`macho_core::parse`]
/// and pass the selected image to [`parse_objc_metadata`].
pub fn parse_objc_metadata_from_source<S>(source: &S) -> Result<ObjCMetadata>
where
    S: AsRef<[u8]> + ?Sized,
{
    let macho = parse_source(source)?;
    parse_objc_metadata(&macho)
}

/// Scans Objective-C runtime lists without silently dropping malformed records.
pub fn scan_objc_metadata(macho: &MachoFile<'_>) -> Result<ObjCMetadataScan> {
    if !macho.is_64bit() {
        return Err(Error::unsupported(
            "ObjC metadata parsing is only supported for 64-bit binaries",
        ));
    }
    let resolver = ObjCResolver::new(macho);
    let mut observations = Vec::new();
    let mut classes = Vec::new();
    let mut categories = Vec::new();
    let mut protocols = Vec::new();

    for (kind, section_name) in [
        (ObjCRecordKind::Class, "__objc_classlist"),
        (ObjCRecordKind::Category, "__objc_catlist"),
        (ObjCRecordKind::Protocol, "__objc_protolist"),
    ] {
        if !macho
            .all_sections()
            .any(|section| section.section_name() == section_name)
        {
            continue;
        }
        let offsets = parse_pointer_list(macho, section_name)?;
        for (ordinal, pointer_file_offset) in offsets.into_iter().enumerate() {
            let pointer_raw = macho
                .bytes()
                .get(pointer_file_offset as usize..pointer_file_offset as usize + 8)
                .unwrap_or_default()
                .to_vec();
            let runtime_address = match resolver.read_pointer_at_offset(pointer_file_offset) {
                Ok(Some(address)) => address,
                Ok(None) => {
                    observations.push(ObjCRecordObservation {
                        kind,
                        ordinal,
                        pointer_file_offset,
                        runtime_address: None,
                        parsed_name: None,
                        error: Some("runtime pointer is null or unresolved".to_owned()),
                        raw: pointer_raw,
                    });
                    continue;
                }
                Err(error) => {
                    observations.push(ObjCRecordObservation {
                        kind,
                        ordinal,
                        pointer_file_offset,
                        runtime_address: None,
                        parsed_name: None,
                        error: Some(error.to_string()),
                        raw: pointer_raw,
                    });
                    continue;
                }
            };
            let raw_size = match kind {
                ObjCRecordKind::Class => 40,
                ObjCRecordKind::Category => 48,
                ObjCRecordKind::Protocol => 72,
            };
            let raw = macho
                .read_bytes_at_va(runtime_address, raw_size)
                .map(ToOwned::to_owned)
                .unwrap_or(pointer_raw);
            let parsed = match kind {
                ObjCRecordKind::Class => {
                    class::parse_class(&resolver, runtime_address).map(|value| {
                        let name = value.name.clone();
                        if !value.is_meta {
                            classes.push(value);
                        }
                        name
                    })
                }
                ObjCRecordKind::Category => category::parse_category(&resolver, runtime_address)
                    .map(|value| {
                        let name = value.name.clone();
                        categories.push(value);
                        name
                    }),
                ObjCRecordKind::Protocol => protocol::parse_protocol(&resolver, runtime_address)
                    .map(|value| {
                        let name = value.name.clone();
                        protocols.push(value);
                        name
                    }),
            };
            observations.push(match parsed {
                Ok(parsed_name) => ObjCRecordObservation {
                    kind,
                    ordinal,
                    pointer_file_offset,
                    runtime_address: Some(runtime_address.0),
                    parsed_name: Some(parsed_name),
                    error: None,
                    raw,
                },
                Err(error) => ObjCRecordObservation {
                    kind,
                    ordinal,
                    pointer_file_offset,
                    runtime_address: Some(runtime_address.0),
                    parsed_name: None,
                    error: Some(error.to_string()),
                    raw,
                },
            });
        }
    }

    Ok(ObjCMetadataScan {
        metadata: ObjCMetadata {
            classes,
            categories,
            protocols,
        },
        observations,
    })
}

/// Scan Objective-C metadata from one borrowed thin Mach-O byte source.
///
/// This is the lossless-observation counterpart to
/// [`parse_objc_metadata_from_source`] and has the same borrowing and universal
/// binary behavior.
pub fn scan_objc_metadata_from_source<S>(source: &S) -> Result<ObjCMetadataScan>
where
    S: AsRef<[u8]> + ?Sized,
{
    let macho = parse_source(source)?;
    scan_objc_metadata(&macho)
}

fn parse_source<'data, S>(source: &'data S) -> Result<MachoFile<'data>>
where
    S: AsRef<[u8]> + ?Sized,
{
    match macho_core::parse(source.as_ref())? {
        macho_core::model::container::MachoContainer::Thin(macho) => Ok(macho),
        macho_core::model::container::MachoContainer::Fat(_) => Err(Error::unsupported(
            "borrowed source contains a universal Mach-O; select an architecture explicitly",
        )),
    }
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
    if size % 8 != 0 {
        return Err(Error::format(format!(
            "section {sect_name} size {size:#x} is not pointer-aligned"
        )));
    }
    let end = offset
        .checked_add(size)
        .ok_or_else(|| Error::address(format!("section {sect_name} file range overflows")))?;
    if end > macho.file_size() as u64 {
        return Err(Error::bounds(offset, size, macho.file_size() as u64));
    }
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
