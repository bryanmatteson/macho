use std::sync::OnceLock;

use crate::Result;
use crate::analysis::xref::ranges::SymbolRangeIndex;
use crate::analysis::xref::refs::XrefIndex;
use crate::metadata::codesign::CodeSignature;
use crate::metadata::image::ImageInfo;
use crate::analysis::reconstruct::objc::ObjCGraph;
use crate::metadata::objc::ObjCMetadata;
use crate::metadata::swift::SwiftTypeIndex;
use crate::model::addr::AddressMap;
use crate::model::load_command::LoadCommand;
use crate::model::macho_file::MachoFile;
use crate::model::symbol::SymbolTable;
use crate::model::validate;
use crate::symbols::imports::{ImportRecord, collect_imports};
use crate::core::dwarf::DwarfFunctionIndex;
use crate::core::rtti::VtableIndex;

pub struct ImageInspector<'data> {
    macho: &'data MachoFile<'data>,
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
    vtable_index: OnceLock<Result<VtableIndex>>,
    dwarf_functions: OnceLock<Result<DwarfFunctionIndex>>,
}

impl<'data> ImageInspector<'data> {
    pub fn new(macho: &'data MachoFile<'data>) -> Self {
        let info = ImageInfo::from_mach(macho);
        Self {
            macho,
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
            vtable_index: OnceLock::new(),
            dwarf_functions: OnceLock::new(),
        }
    }

    pub fn info(&self) -> &ImageInfo {
        &self.info
    }

    pub fn macho(&self) -> &MachoFile<'data> {
        self.macho
    }

    pub fn address_map(&self) -> &AddressMap {
        self.macho.address_map()
    }

    pub fn symbols(&self) -> Result<&SymbolTable<'data>> {
        self.symbols
            .get_or_init(|| self.macho.ext::<SymbolTable<'data>>())
            .as_ref()
            .map_err(|e| e.clone())
    }

    pub fn exports(&self) -> Result<&Vec<crate::metadata::dyld::types::Export>> {
        self.exports
            .get_or_init(|| crate::metadata::dyld::parse_exports(self.macho))
            .as_ref()
            .map_err(|e| e.clone())
    }

    pub fn imports(&self) -> Result<&Vec<ImportRecord>> {
        self.imports
            .get_or_init(|| extract_imports_cached(self.macho))
            .as_ref()
            .map_err(|e| e.clone())
    }

    pub fn parse_exports(&self) -> Result<&Vec<crate::metadata::dyld::types::Export>> {
        self.exports()
    }

    pub fn has_code_signature(&self) -> bool {
        has_code_signature(self.macho)
    }

    pub fn parse_objc_metadata(&self) -> Result<&ObjCMetadata> {
        self.objc
            .get_or_init(|| self.macho.ext::<ObjCMetadata>())
            .as_ref()
            .map_err(|e| e.clone())
    }

    pub fn parse_objc_graph(&self) -> Result<&ObjCGraph> {
        self.objc_graph
            .get_or_init(|| self.macho.ext::<ObjCGraph>())
            .as_ref()
            .map_err(|e| e.clone())
    }

    pub fn parse_swift_types(&self) -> Result<&SwiftTypeIndex> {
        self.swift_types
            .get_or_init(|| self.macho.ext::<SwiftTypeIndex>())
            .as_ref()
            .map_err(|e| e.clone())
    }

    pub fn parse_code_signature(&self) -> Result<&CodeSignature<'data>> {
        self.codesign
            .get_or_init(|| self.macho.ext::<CodeSignature<'data>>())
            .as_ref()
            .map_err(|e| e.clone())
    }

    pub fn symbol_range_index(&self) -> Result<&SymbolRangeIndex> {
        self.range_index
            .get_or_init(|| self.macho.ext::<SymbolRangeIndex>())
            .as_ref()
            .map_err(|e| e.clone())
    }

    pub fn xref_index(&self) -> Result<&XrefIndex> {
        self.xref_index
            .get_or_init(|| self.macho.ext::<XrefIndex>())
            .as_ref()
            .map_err(|e| e.clone())
    }

    pub fn vtable_index(&self) -> Result<&VtableIndex> {
        self.vtable_index
            .get_or_init(|| VtableIndex::build(self.macho))
            .as_ref()
            .map_err(|e| e.clone())
    }

    pub fn dwarf_functions(&self) -> Result<&DwarfFunctionIndex> {
        self.dwarf_functions
            .get_or_init(|| DwarfFunctionIndex::build(self.macho))
            .as_ref()
            .map_err(|e| e.clone())
    }

    pub fn validate(&self) -> Vec<validate::Diagnostic> {
        validate::validate(self.macho)
    }
}

impl std::fmt::Debug for ImageInspector<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImageInspector")
            .field("info", &self.info)
            .field("uuid", &self.macho.uuid())
            .finish()
    }
}

fn extract_imports_cached(macho: &MachoFile<'_>) -> Result<Vec<ImportRecord>> {
    collect_imports(macho)
}

fn has_code_signature(macho: &MachoFile<'_>) -> bool {
    macho
        .load_commands()
        .iter()
        .any(|lc| matches!(lc.kind, LoadCommand::CodeSignature(_)))
}
