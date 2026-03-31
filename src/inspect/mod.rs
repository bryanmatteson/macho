pub mod resolve;

use std::sync::OnceLock;

use serde::Serialize;

use crate::addr::map::AddressMap;
use crate::analysis::snapshot::ImportSnapshot;
use crate::codesign::{CodeSignature, parse_code_signature};
use crate::dyld::bind::parse_bind_entries;
use crate::dyld::chained::{ChainedFixups, parse_chained_fixups};
use crate::dyld::exports::parse_exports;
use crate::dyld::types::Export;
use crate::error::Result;
use crate::model::load_command::{LoadCommand, format_uuid};
use crate::model::mach::MachFile;
use crate::model::symbol::SymbolTable;
use crate::objc::graph::ObjCGraph;
use crate::objc::{ObjCMetadata, parse_objc_metadata};
use crate::parse::parse_symbol_table;
use crate::swift::SwiftTypeIndex;
use crate::xref::ranges::SymbolRangeIndex;
use crate::xref::refs::XrefIndex;

pub struct ImageInspector<'data> {
    mach: &'data MachFile<'data>,
    info: ImageInfo,
    symbols: OnceLock<Result<SymbolTable<'data>>>,
    exports: OnceLock<Result<Vec<Export>>>,
    imports: OnceLock<Result<Vec<ImportSnapshot>>>,
    fixups: OnceLock<Result<ChainedFixups<'data>>>,
    objc: OnceLock<Result<ObjCMetadata>>,
    codesign: OnceLock<Result<CodeSignature<'data>>>,
    objc_graph: OnceLock<Result<ObjCGraph>>,
    swift_types: OnceLock<Result<SwiftTypeIndex>>,
    range_index: OnceLock<Result<SymbolRangeIndex>>,
    xref_index: OnceLock<Result<XrefIndex>>,
}

impl<'data> ImageInspector<'data> {
    pub fn new(mach: &'data MachFile<'data>) -> Self {
        let info = ImageInfo::from_mach(mach);
        Self {
            mach,
            info,
            symbols: OnceLock::new(),
            exports: OnceLock::new(),
            imports: OnceLock::new(),
            fixups: OnceLock::new(),
            objc: OnceLock::new(),
            codesign: OnceLock::new(),
            objc_graph: OnceLock::new(),
            swift_types: OnceLock::new(),
            range_index: OnceLock::new(),
            xref_index: OnceLock::new(),
        }
    }

    pub fn info(&self) -> &ImageInfo {
        &self.info
    }

    pub fn mach(&self) -> &MachFile<'data> {
        self.mach
    }

    pub fn address_map(&self) -> &AddressMap {
        self.mach.address_map()
    }

    pub fn symbols(&self) -> Result<&SymbolTable<'data>> {
        self.symbols
            .get_or_init(|| parse_symbol_table(self.mach))
            .as_ref()
            .map_err(|e| e.clone())
    }

    pub fn exports(&self) -> Result<&Vec<Export>> {
        self.exports
            .get_or_init(|| parse_exports(self.mach))
            .as_ref()
            .map_err(|e| e.clone())
    }

    pub fn imports(&self) -> Result<&Vec<ImportSnapshot>> {
        self.imports
            .get_or_init(|| extract_imports_cached(self.mach))
            .as_ref()
            .map_err(|e| e.clone())
    }

    pub fn fixups(&self) -> Result<&ChainedFixups<'data>> {
        self.fixups
            .get_or_init(|| parse_chained_fixups(self.mach))
            .as_ref()
            .map_err(|e| e.clone())
    }

    pub fn objc_metadata(&self) -> Result<&ObjCMetadata> {
        self.objc
            .get_or_init(|| parse_objc_metadata(self.mach))
            .as_ref()
            .map_err(|e| e.clone())
    }

    pub fn code_signature(&self) -> Result<&CodeSignature<'data>> {
        self.codesign
            .get_or_init(|| parse_code_signature(self.mach))
            .as_ref()
            .map_err(|e| e.clone())
    }

    pub fn objc_graph(&self) -> Result<&ObjCGraph> {
        self.objc_graph
            .get_or_init(|| {
                let meta = self.objc_metadata()?;
                Ok(ObjCGraph::build_from_mach(meta, self.mach))
            })
            .as_ref()
            .map_err(|e| e.clone())
    }

    pub fn swift_types(&self) -> Result<&SwiftTypeIndex> {
        self.swift_types
            .get_or_init(|| Ok(SwiftTypeIndex::build(self.mach)))
            .as_ref()
            .map_err(|e| e.clone())
    }

    pub fn range_index(&self) -> Result<&SymbolRangeIndex> {
        self.range_index
            .get_or_init(|| SymbolRangeIndex::build(self.mach))
            .as_ref()
            .map_err(|e| e.clone())
    }

    pub fn xref_index(&self) -> Result<&XrefIndex> {
        self.xref_index
            .get_or_init(|| XrefIndex::build(self.mach))
            .as_ref()
            .map_err(|e| e.clone())
    }
}

impl std::fmt::Debug for ImageInspector<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImageInspector")
            .field("info", &self.info)
            .finish()
    }
}

// -- ImageInfo and related types --

#[derive(Debug, Clone, Serialize)]
pub struct ImageInfo {
    pub arch: String,
    pub file_type: String,
    pub uuid: Option<String>,
    pub image_base: u64,
    pub platform: Option<PlatformInfo>,
    pub source_version: Option<String>,
    pub install_name: Option<String>,
    pub linked_dylibs: Vec<LinkedDylib>,
    pub rpaths: Vec<String>,
    pub target_triple: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PlatformInfo {
    pub platform: String,
    pub min_os: String,
    pub sdk: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct LinkedDylib {
    pub name: String,
    pub ordinal: usize,
    pub current_version: String,
    pub compat_version: String,
    pub kind: DylibLinkKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum DylibLinkKind {
    Required,
    Weak,
    Reexport,
    Lazy,
    Upward,
}

impl std::fmt::Display for DylibLinkKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Required => write!(f, "required"),
            Self::Weak => write!(f, "weak"),
            Self::Reexport => write!(f, "reexport"),
            Self::Lazy => write!(f, "lazy"),
            Self::Upward => write!(f, "upward"),
        }
    }
}

impl ImageInfo {
    fn from_mach(mach: &MachFile<'_>) -> Self {
        let header = mach.header();
        let arch = header.cpu_type.name().to_string();
        let file_type = header.file_type.name().to_string();
        let uuid = mach.uuid().map(format_uuid);
        let image_base = mach.image_base().0;

        let platform = extract_platform(mach);
        let source_version = extract_source_version(mach);
        let install_name = extract_install_name(mach);
        let linked_dylibs = extract_linked_dylibs(mach);
        let rpaths = extract_rpaths(mach);
        let target_triple = extract_target_triple(mach);

        Self {
            arch,
            file_type,
            uuid,
            image_base,
            platform,
            source_version,
            install_name,
            linked_dylibs,
            rpaths,
            target_triple,
        }
    }
}

fn extract_platform(mach: &MachFile<'_>) -> Option<PlatformInfo> {
    // Try LC_BUILD_VERSION first
    if let Some(bv) = mach
        .load_commands()
        .iter()
        .find_map(|lc| lc.kind.as_build_version())
    {
        return Some(PlatformInfo {
            platform: bv.platform.name().to_string(),
            min_os: bv.minos.to_string(),
            sdk: bv.sdk.to_string(),
        });
    }

    // Fall back to LC_VERSION_MIN_*
    for lc in mach.load_commands() {
        match &lc.kind {
            LoadCommand::VersionMinMacOS(d) => {
                return Some(PlatformInfo {
                    platform: "macOS".to_string(),
                    min_os: d.version.to_string(),
                    sdk: d.sdk.to_string(),
                });
            }
            LoadCommand::VersionMinIOS(d) => {
                return Some(PlatformInfo {
                    platform: "iOS".to_string(),
                    min_os: d.version.to_string(),
                    sdk: d.sdk.to_string(),
                });
            }
            LoadCommand::VersionMinTvOS(d) => {
                return Some(PlatformInfo {
                    platform: "tvOS".to_string(),
                    min_os: d.version.to_string(),
                    sdk: d.sdk.to_string(),
                });
            }
            LoadCommand::VersionMinWatchOS(d) => {
                return Some(PlatformInfo {
                    platform: "watchOS".to_string(),
                    min_os: d.version.to_string(),
                    sdk: d.sdk.to_string(),
                });
            }
            _ => {}
        }
    }

    None
}

fn extract_source_version(mach: &MachFile<'_>) -> Option<String> {
    mach.load_commands().iter().find_map(|lc| {
        if let LoadCommand::SourceVersion(d) = &lc.kind {
            Some(d.version.to_string())
        } else {
            None
        }
    })
}

fn extract_install_name(mach: &MachFile<'_>) -> Option<String> {
    mach.load_commands().iter().find_map(|lc| {
        if let LoadCommand::IdDylib(d) = &lc.kind {
            Some(d.name.clone())
        } else {
            None
        }
    })
}

fn extract_linked_dylibs(mach: &MachFile<'_>) -> Vec<LinkedDylib> {
    let mut dylibs = Vec::new();
    let mut ordinal: usize = 1;

    for lc in mach.load_commands() {
        let (data, kind) = match &lc.kind {
            LoadCommand::LoadDylib(d) => (d, DylibLinkKind::Required),
            LoadCommand::LoadWeakDylib(d) => (d, DylibLinkKind::Weak),
            LoadCommand::ReexportDylib(d) => (d, DylibLinkKind::Reexport),
            LoadCommand::LazyLoadDylib(d) => (d, DylibLinkKind::Lazy),
            LoadCommand::LoadUpwardDylib(d) => (d, DylibLinkKind::Upward),
            _ => continue,
        };

        dylibs.push(LinkedDylib {
            name: data.name.clone(),
            ordinal,
            current_version: data.current_version.to_string(),
            compat_version: data.compatibility_version.to_string(),
            kind,
        });
        ordinal += 1;
    }

    dylibs
}

fn extract_rpaths(mach: &MachFile<'_>) -> Vec<String> {
    mach.load_commands()
        .iter()
        .filter_map(|lc| lc.kind.as_rpath().map(|s| s.to_string()))
        .collect()
}

fn extract_target_triple(mach: &MachFile<'_>) -> Option<String> {
    mach.load_commands().iter().find_map(|lc| {
        if let LoadCommand::TargetTriple(d) = &lc.kind {
            Some(d.value.clone())
        } else {
            None
        }
    })
}

fn extract_imports_cached(mach: &MachFile<'_>) -> Result<Vec<ImportSnapshot>> {
    // Try chained fixups first (modern binaries)
    if let Ok(fixups) = parse_chained_fixups(mach) {
        let mut imports: Vec<ImportSnapshot> = fixups
            .imports
            .iter()
            .map(|imp| ImportSnapshot {
                name: imp.name.to_string(),
                lib_ordinal: imp.lib_ordinal,
                weak: imp.weak,
            })
            .collect();
        imports.sort_by(|a, b| a.name.cmp(&b.name).then(a.lib_ordinal.cmp(&b.lib_ordinal)));
        imports.dedup_by(|a, b| a.name == b.name && a.lib_ordinal == b.lib_ordinal);
        return Ok(imports);
    }

    // Fall back to legacy bind entries
    if let Ok((regular, weak, lazy)) = parse_bind_entries(mach) {
        let mut imports: Vec<ImportSnapshot> = regular
            .into_iter()
            .chain(weak)
            .chain(lazy)
            .map(|bind| ImportSnapshot {
                name: bind.symbol_name.to_string(),
                lib_ordinal: bind.lib_ordinal as i32,
                weak: bind.weak,
            })
            .collect();
        imports.sort_by(|a, b| a.name.cmp(&b.name).then(a.lib_ordinal.cmp(&b.lib_ordinal)));
        imports.dedup_by(|a, b| a.name == b.name && a.lib_ordinal == b.lib_ordinal);
        return Ok(imports);
    }

    Ok(Vec::new())
}
