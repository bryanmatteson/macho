use std::sync::OnceLock;

use crate::Result;
use crate::analysis::xref::ranges::SymbolRangeIndex;
use crate::analysis::xref::refs::XrefIndex;
use crate::format::parse_symbol_table;
use crate::metadata::codesign::{CodeSignature, parse_code_signature};
use crate::metadata::image::ImageInfo;
use crate::metadata::objc::{ObjCGraph, ObjCMetadata, parse_objc_metadata};
use crate::metadata::swift::SwiftTypeIndex;
use crate::model::addr::AddressMap;
use crate::model::load_command::LoadCommand;
use crate::model::mach_file::MachFile;
use crate::model::symbol::SymbolTable;
use crate::model::validate;
use crate::symbols::imports::{ImportRecord, collect_imports};

pub struct ImageInspector<'data> {
    mach: &'data MachFile<'data>,
    info: ImageInfo,
    symbols: OnceLock<Result<SymbolTable<'data>>>,
    exports: OnceLock<Result<Vec<crate::metadata::dyld::types::Export>>>,
    imports: OnceLock<Result<Vec<ImportRecord>>>,
    codesign: OnceLock<Result<CodeSignature<'data>>>,
    objc_graph: OnceLock<Result<ObjCGraph>>,
    objc: OnceLock<Result<ObjCMetadata>>,
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
            codesign: OnceLock::new(),
            objc_graph: OnceLock::new(),
            objc: OnceLock::new(),
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

    pub fn exports(&self) -> Result<&Vec<crate::metadata::dyld::types::Export>> {
        self.exports
            .get_or_init(|| crate::metadata::dyld::parse_exports(self.mach))
            .as_ref()
            .map_err(|e| e.clone())
    }

    pub fn imports(&self) -> Result<&Vec<ImportRecord>> {
        self.imports
            .get_or_init(|| extract_imports_cached(self.mach))
            .as_ref()
            .map_err(|e| e.clone())
    }

    pub fn parse_exports(&self) -> Result<&Vec<crate::metadata::dyld::types::Export>> {
        self.exports()
    }

    pub fn has_code_signature(&self) -> bool {
        has_code_signature(self.mach)
    }

    pub fn parse_objc_metadata(&self) -> Result<&ObjCMetadata> {
        self.objc
            .get_or_init(|| parse_objc_metadata(self.mach))
            .as_ref()
            .map_err(|e| e.clone())
    }

    pub fn parse_objc_graph(&self) -> Result<&ObjCGraph> {
        self.objc_graph
            .get_or_init(|| {
                let meta = self.parse_objc_metadata()?;
                Ok(ObjCGraph::build_from_mach(meta, self.mach))
            })
            .as_ref()
            .map_err(|e| e.clone())
    }

    pub fn parse_swift_types(&self) -> Result<&SwiftTypeIndex> {
        self.swift_types
            .get_or_init(|| Ok::<SwiftTypeIndex, crate::Error>(SwiftTypeIndex::build(self.mach)))
            .as_ref()
            .map_err(|e| e.clone())
    }

    pub fn parse_code_signature(&self) -> Result<&CodeSignature<'data>> {
        self.codesign
            .get_or_init(|| parse_code_signature(self.mach))
            .as_ref()
            .map_err(|e| e.clone())
    }

    pub fn symbol_range_index(&self) -> Result<&SymbolRangeIndex> {
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

    pub fn validate(&self) -> Vec<validate::Diagnostic> {
        validate::validate(self.mach)
    }
}

impl std::fmt::Debug for ImageInspector<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImageInspector")
            .field("info", &self.info)
            .field("uuid", &self.mach.uuid())
            .finish()
    }
}

fn extract_imports_cached(mach: &MachFile<'_>) -> Result<Vec<ImportRecord>> {
    collect_imports(mach)
}

fn has_code_signature(mach: &MachFile<'_>) -> bool {
    mach.load_commands()
        .iter()
        .any(|lc| matches!(lc.kind, LoadCommand::CodeSignature(_)))
}
