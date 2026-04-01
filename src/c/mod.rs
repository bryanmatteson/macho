use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use gimli::{
    self, AttributeValue, DebuggingInformationEntry, Dwarf, EndianSlice, EntriesTreeNode, Reader,
    RunTimeEndian, Unit, UnitOffset,
};
use serde::Serialize;

use crate::dwarf::load_dwarf;
use crate::error::{Error, Result};
use crate::io::endian::Endian;
use crate::model::mach::MachFile;
use crate::model::section::Section;
use crate::model::symbol::{Symbol, SymbolTable};
use crate::parse::parse_symbol_table;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Ord, PartialOrd)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    DwarfExact,
    Correlated,
    Inferred,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    Dwarf,
    Symbol,
    HeaderMatch,
    Inference,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EvidenceFact {
    pub kind: EvidenceKind,
    pub confidence: Confidence,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct SourceLocation {
    pub file: Option<String>,
    pub line: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CTagKind {
    Struct,
    Union,
    Enum,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CType {
    Void,
    Builtin {
        name: String,
    },
    Named {
        name: String,
        tag: Option<CTagKind>,
    },
    Pointer {
        to: Box<CType>,
    },
    Array {
        element: Box<CType>,
        count: Option<u64>,
    },
    Const {
        inner: Box<CType>,
    },
    Volatile {
        inner: Box<CType>,
    },
    Restrict {
        inner: Box<CType>,
    },
    FunctionPointer {
        return_type: Box<CType>,
        params: Vec<CParamType>,
        variadic: bool,
    },
    Unknown {
        display: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CParamType {
    pub name: Option<String>,
    pub ty: CType,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CField {
    pub name: String,
    pub ty: CType,
    pub bit_size: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CRecordDecl {
    pub kind: CTagKind,
    pub name: String,
    pub fields: Vec<CField>,
    pub complete: bool,
    pub size: Option<u64>,
    pub source: SourceLocation,
    pub evidence: Vec<EvidenceFact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CEnumVariant {
    pub name: String,
    pub value: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CEnumDecl {
    pub name: String,
    pub variants: Vec<CEnumVariant>,
    pub complete: bool,
    pub source: SourceLocation,
    pub evidence: Vec<EvidenceFact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CTypedefDecl {
    pub name: String,
    pub target: CType,
    pub source: SourceLocation,
    pub evidence: Vec<EvidenceFact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CFunctionDecl {
    pub name: String,
    pub return_type: CType,
    pub params: Vec<CParamType>,
    pub variadic: bool,
    pub external: bool,
    pub address: Option<u64>,
    pub source: SourceLocation,
    pub confidence: Confidence,
    pub evidence: Vec<EvidenceFact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CGlobalDecl {
    pub name: String,
    pub ty: CType,
    pub external: bool,
    pub address: Option<u64>,
    pub source: SourceLocation,
    pub confidence: Confidence,
    pub evidence: Vec<EvidenceFact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HeaderCorrelationMatch {
    pub path: String,
    pub symbol: String,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CHeaderUnit {
    pub name: String,
    pub declarations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CAnalysis {
    pub records: Vec<CRecordDecl>,
    pub enums: Vec<CEnumDecl>,
    pub typedefs: Vec<CTypedefDecl>,
    pub functions: Vec<CFunctionDecl>,
    pub globals: Vec<CGlobalDecl>,
    pub header_units: Vec<CHeaderUnit>,
    pub correlated_headers: Vec<HeaderCorrelationMatch>,
}

#[derive(Debug, Clone, Default)]
pub struct CAnalysisOptions {
    pub header_root: Option<PathBuf>,
}

pub trait HeaderCorrelator {
    fn correlate(&self, analysis: &mut CAnalysis) -> Result<()>;
}

pub struct FilesystemHeaderCorrelator {
    root: PathBuf,
}

impl FilesystemHeaderCorrelator {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }
}

impl HeaderCorrelator for FilesystemHeaderCorrelator {
    fn correlate(&self, analysis: &mut CAnalysis) -> Result<()> {
        if !self.root.exists() {
            return Ok(());
        }

        let headers = collect_headers(&self.root)?;
        let mut seen = BTreeSet::new();
        for header in headers {
            let Ok(contents) = fs::read_to_string(&header) else {
                continue;
            };

            correlate_named_items(
                &header,
                &contents,
                analysis
                    .functions
                    .iter_mut()
                    .map(|f| (&f.name, &mut f.evidence)),
                &mut analysis.correlated_headers,
                &mut seen,
            );
            correlate_named_items(
                &header,
                &contents,
                analysis
                    .globals
                    .iter_mut()
                    .map(|g| (&g.name, &mut g.evidence)),
                &mut analysis.correlated_headers,
                &mut seen,
            );
            correlate_named_items(
                &header,
                &contents,
                analysis
                    .typedefs
                    .iter_mut()
                    .map(|t| (&t.name, &mut t.evidence)),
                &mut analysis.correlated_headers,
                &mut seen,
            );
            correlate_named_items(
                &header,
                &contents,
                analysis
                    .records
                    .iter_mut()
                    .map(|r| (&r.name, &mut r.evidence)),
                &mut analysis.correlated_headers,
                &mut seen,
            );
            correlate_named_items(
                &header,
                &contents,
                analysis
                    .enums
                    .iter_mut()
                    .map(|e| (&e.name, &mut e.evidence)),
                &mut analysis.correlated_headers,
                &mut seen,
            );
        }

        Ok(())
    }
}

pub fn analyze_headers(mach: &MachFile<'_>, options: &CAnalysisOptions) -> Result<CAnalysis> {
    let mut builder = CAnalysisBuilder::default();
    if let Some(dwarf) = load_dwarf(mach)? {
        let endian = runtime_endian(mach.endian());
        let borrowed = dwarf.borrow(|section| EndianSlice::new(section, endian));
        builder.ingest_dwarf(&borrowed)?;
    }

    let symtab = parse_symbol_table(mach).ok();
    builder.reconcile_symbols(mach, symtab.as_ref());

    let mut analysis = builder.finish();
    if let Some(root) = options.header_root.clone() {
        FilesystemHeaderCorrelator::new(root).correlate(&mut analysis)?;
    }
    analysis.header_units = build_header_units(&analysis);
    Ok(analysis)
}

pub fn render_header(analysis: &CAnalysis) -> String {
    let mut out = String::new();
    for unit in &analysis.header_units {
        if analysis.header_units.len() > 1 {
            out.push_str(&format!("/* {} */\n", unit.name));
        }
        for decl in &unit.declarations {
            out.push_str(decl);
            if !decl.ends_with('\n') {
                out.push('\n');
            }
            out.push('\n');
        }
    }
    out
}

pub fn validate_header_syntax(header: &str) -> Result<()> {
    let path = std::env::temp_dir().join(format!(
        "macho-c-header-{}.h",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|err| Error::Format(format!("clock error: {err}")))?
            .as_nanos()
    ));
    fs::write(&path, header)
        .map_err(|err| Error::Format(format!("failed to write temporary header: {err}")))?;

    let output = Command::new("clang")
        .args([
            "-x",
            "c",
            "-fsyntax-only",
            path.to_str().unwrap_or_default(),
        ])
        .output()
        .or_else(|_| {
            Command::new("xcrun")
                .args([
                    "clang",
                    "-x",
                    "c",
                    "-fsyntax-only",
                    path.to_str().unwrap_or_default(),
                ])
                .output()
        })
        .map_err(|err| Error::Format(format!("failed to invoke clang for validation: {err}")))?;

    let _ = fs::remove_file(&path);

    if output.status.success() {
        return Ok(());
    }

    Err(Error::Format(format!(
        "clang rejected rendered header: {}",
        String::from_utf8_lossy(&output.stderr)
    )))
}

#[derive(Default)]
struct CAnalysisBuilder {
    records: BTreeMap<String, CRecordDecl>,
    enums: BTreeMap<String, CEnumDecl>,
    typedefs: BTreeMap<String, CTypedefDecl>,
    functions: BTreeMap<String, CFunctionDecl>,
    globals: BTreeMap<String, CGlobalDecl>,
}

impl CAnalysisBuilder {
    fn ingest_dwarf<R>(&mut self, dwarf: &Dwarf<R>) -> Result<()>
    where
        R: Reader<Offset = usize>,
    {
        let mut units = dwarf.units();
        while let Some(header) = units
            .next()
            .map_err(|err| Error::Format(format!("failed to iterate DWARF units: {err}")))?
        {
            let unit = dwarf
                .unit(header)
                .map_err(|err| Error::Format(format!("failed to parse DWARF unit: {err}")))?;
            let mut tree = unit
                .entries_tree(None)
                .map_err(|err| Error::Format(format!("failed to build DWARF entry tree: {err}")))?;
            let root = tree
                .root()
                .map_err(|err| Error::Format(format!("failed to access DWARF root: {err}")))?;

            let unit_name = attr_string(dwarf, &unit, root.entry(), gimli::DW_AT_name)?;
            let comp_dir = attr_string(dwarf, &unit, root.entry(), gimli::DW_AT_comp_dir)?;
            let source = SourceLocation {
                file: unit_name.map(|name| match &comp_dir {
                    Some(dir) => format!("{dir}/{name}"),
                    None => name,
                }),
                line: None,
            };

            let mut parser = UnitParser::new(dwarf, &unit, source);
            parser.visit_tree(root, self)?;
        }
        Ok(())
    }

    fn reconcile_symbols(&mut self, mach: &MachFile<'_>, symtab: Option<&SymbolTable<'_>>) {
        let Some(symtab) = symtab else {
            return;
        };

        for function in self.functions.values_mut() {
            if let Some(symbol) = find_symbol(symtab, &function.name) {
                function.address = Some(symbol.value);
                function.external |= symbol.external;
                function.evidence.push(EvidenceFact {
                    kind: EvidenceKind::Symbol,
                    confidence: Confidence::DwarfExact,
                    detail: format!("matched LC_SYMTAB symbol {}", symbol.name),
                });
            }
        }

        for global in self.globals.values_mut() {
            if let Some(symbol) = find_symbol(symtab, &global.name) {
                global.address = Some(symbol.value);
                global.external |= symbol.external;
                global.evidence.push(EvidenceFact {
                    kind: EvidenceKind::Symbol,
                    confidence: Confidence::DwarfExact,
                    detail: format!("matched LC_SYMTAB symbol {}", symbol.name),
                });
            }
        }

        for symbol in symtab.symbols() {
            let Some(normalized) = normalize_c_symbol_name(symbol.name) else {
                continue;
            };
            if self.functions.contains_key(&normalized) || self.globals.contains_key(&normalized) {
                continue;
            }
            if !is_probable_c_symbol(symbol.name) {
                continue;
            }

            match classify_symbol(mach, symbol) {
                SymbolClassification::Function => {
                    self.functions.insert(
                        normalized.clone(),
                        CFunctionDecl {
                            name: normalized,
                            return_type: CType::Builtin {
                                name: "int".to_string(),
                            },
                            params: Vec::new(),
                            variadic: false,
                            external: symbol.external || symbol.is_undefined(),
                            address: symbol.is_defined().then_some(symbol.value),
                            source: SourceLocation::default(),
                            confidence: Confidence::Inferred,
                            evidence: vec![EvidenceFact {
                                kind: EvidenceKind::Inference,
                                confidence: Confidence::Inferred,
                                detail: format!(
                                    "fallback inferred function from symbol {}",
                                    symbol.name
                                ),
                            }],
                        },
                    );
                }
                SymbolClassification::Global => {
                    self.globals.insert(
                        normalized.clone(),
                        CGlobalDecl {
                            name: normalized,
                            ty: CType::Array {
                                element: Box::new(CType::Builtin {
                                    name: "unsigned char".to_string(),
                                }),
                                count: None,
                            },
                            external: symbol.external || symbol.is_undefined(),
                            address: symbol.is_defined().then_some(symbol.value),
                            source: SourceLocation::default(),
                            confidence: Confidence::Inferred,
                            evidence: vec![EvidenceFact {
                                kind: EvidenceKind::Inference,
                                confidence: Confidence::Inferred,
                                detail: format!(
                                    "fallback inferred global from symbol {}",
                                    symbol.name
                                ),
                            }],
                        },
                    );
                }
                SymbolClassification::Skip => {}
            }
        }
    }

    fn finish(self) -> CAnalysis {
        CAnalysis {
            records: self.records.into_values().collect(),
            enums: self.enums.into_values().collect(),
            typedefs: self.typedefs.into_values().collect(),
            functions: self.functions.into_values().collect(),
            globals: self.globals.into_values().collect(),
            header_units: Vec::new(),
            correlated_headers: Vec::new(),
        }
    }
}

struct UnitParser<'a, R>
where
    R: Reader<Offset = usize>,
{
    dwarf: &'a Dwarf<R>,
    unit: &'a Unit<R>,
    unit_source: SourceLocation,
    resolved_types: BTreeMap<u64, CType>,
    in_progress: BTreeSet<u64>,
}

impl<'a, R> UnitParser<'a, R>
where
    R: Reader<Offset = usize>,
{
    fn new(dwarf: &'a Dwarf<R>, unit: &'a Unit<R>, unit_source: SourceLocation) -> Self {
        Self {
            dwarf,
            unit,
            unit_source,
            resolved_types: BTreeMap::new(),
            in_progress: BTreeSet::new(),
        }
    }

    fn visit_tree(&mut self, node: EntriesTreeNode<R>, out: &mut CAnalysisBuilder) -> Result<()> {
        let entry = node.entry();
        match entry.tag() {
            gimli::DW_TAG_subprogram => self.record_function(entry, out)?,
            gimli::DW_TAG_variable => self.record_global(entry, out)?,
            gimli::DW_TAG_typedef
            | gimli::DW_TAG_structure_type
            | gimli::DW_TAG_union_type
            | gimli::DW_TAG_enumeration_type => {
                let _ = self.resolve_die_type(entry.offset(), out)?;
            }
            _ => {}
        }

        let mut children = node.children();
        while let Some(child) = children
            .next()
            .map_err(|err| Error::Format(format!("failed to iterate DWARF children: {err}")))?
        {
            self.visit_tree(child, out)?;
        }
        Ok(())
    }

    fn record_function(
        &mut self,
        entry: &DebuggingInformationEntry<R>,
        out: &mut CAnalysisBuilder,
    ) -> Result<()> {
        let Some(name) = attr_string(self.dwarf, self.unit, entry, gimli::DW_AT_name)? else {
            return Ok(());
        };
        let source = self.source_for(entry)?;
        let return_type = self
            .resolve_attr_type(entry, gimli::DW_AT_type, out)?
            .unwrap_or(CType::Void);

        let mut params = Vec::new();
        let mut variadic = false;
        let mut tree = self
            .unit
            .entries_tree(Some(entry.offset()))
            .map_err(|err| Error::Format(format!("failed to rebuild function tree: {err}")))?;
        let root = tree
            .root()
            .map_err(|err| Error::Format(format!("failed to read function tree root: {err}")))?;
        let mut children = root.children();
        while let Some(child) = children
            .next()
            .map_err(|err| Error::Format(format!("failed to iterate function children: {err}")))?
        {
            match child.entry().tag() {
                gimli::DW_TAG_formal_parameter => {
                    let param_ty = self
                        .resolve_attr_type(child.entry(), gimli::DW_AT_type, out)?
                        .unwrap_or(CType::Unknown {
                            display: "unknown".to_string(),
                        });
                    let param_name =
                        attr_string(self.dwarf, self.unit, child.entry(), gimli::DW_AT_name)?;
                    params.push(CParamType {
                        name: param_name,
                        ty: param_ty,
                    });
                }
                gimli::DW_TAG_unspecified_parameters => variadic = true,
                _ => {}
            }
        }

        let external = attr_flag(entry, gimli::DW_AT_external)?;
        let address = match entry.attr_value(gimli::DW_AT_low_pc) {
            Some(AttributeValue::Addr(addr)) => Some(addr),
            _ => None,
        };

        out.functions.insert(
            name.clone(),
            CFunctionDecl {
                name,
                return_type,
                params,
                variadic,
                external,
                address,
                source,
                confidence: Confidence::DwarfExact,
                evidence: vec![EvidenceFact {
                    kind: EvidenceKind::Dwarf,
                    confidence: Confidence::DwarfExact,
                    detail: "function declaration recovered from DWARF".to_string(),
                }],
            },
        );
        Ok(())
    }

    fn record_global(
        &mut self,
        entry: &DebuggingInformationEntry<R>,
        out: &mut CAnalysisBuilder,
    ) -> Result<()> {
        let Some(name) = attr_string(self.dwarf, self.unit, entry, gimli::DW_AT_name)? else {
            return Ok(());
        };
        let ty = self
            .resolve_attr_type(entry, gimli::DW_AT_type, out)?
            .unwrap_or(CType::Unknown {
                display: "unknown".to_string(),
            });
        let source = self.source_for(entry)?;
        let external = attr_flag(entry, gimli::DW_AT_external)?;

        out.globals.insert(
            name.clone(),
            CGlobalDecl {
                name,
                ty,
                external,
                address: None,
                source,
                confidence: Confidence::DwarfExact,
                evidence: vec![EvidenceFact {
                    kind: EvidenceKind::Dwarf,
                    confidence: Confidence::DwarfExact,
                    detail: "global declaration recovered from DWARF".to_string(),
                }],
            },
        );
        Ok(())
    }

    fn resolve_attr_type(
        &mut self,
        entry: &DebuggingInformationEntry<R>,
        attr_name: gimli::DwAt,
        out: &mut CAnalysisBuilder,
    ) -> Result<Option<CType>> {
        let Some(value) = entry.attr_value(attr_name) else {
            return Ok(None);
        };

        match value {
            AttributeValue::UnitRef(offset) => self.resolve_die_type(offset, out).map(Some),
            _ => Ok(None),
        }
    }

    fn resolve_die_type(
        &mut self,
        offset: UnitOffset<R::Offset>,
        out: &mut CAnalysisBuilder,
    ) -> Result<CType> {
        let key = offset.0 as u64;
        if let Some(existing) = self.resolved_types.get(&key) {
            return Ok(existing.clone());
        }
        if !self.in_progress.insert(key) {
            return Ok(CType::Unknown {
                display: format!("recursive_type_{key:#x}"),
            });
        }

        let entry = self
            .unit
            .entry(offset)
            .map_err(|err| Error::Format(format!("failed to resolve DWARF type DIE: {err}")))?;

        let resolved = match entry.tag() {
            gimli::DW_TAG_base_type => {
                let name = attr_string(self.dwarf, self.unit, &entry, gimli::DW_AT_name)?
                    .unwrap_or_else(|| "int".to_string());
                if name == "void" {
                    CType::Void
                } else {
                    CType::Builtin { name }
                }
            }
            gimli::DW_TAG_pointer_type => {
                let inner = self
                    .resolve_attr_type(&entry, gimli::DW_AT_type, out)?
                    .unwrap_or(CType::Void);
                CType::Pointer {
                    to: Box::new(inner),
                }
            }
            gimli::DW_TAG_const_type => {
                let inner = self
                    .resolve_attr_type(&entry, gimli::DW_AT_type, out)?
                    .unwrap_or(CType::Unknown {
                        display: "const_unknown".to_string(),
                    });
                CType::Const {
                    inner: Box::new(inner),
                }
            }
            gimli::DW_TAG_volatile_type => {
                let inner = self
                    .resolve_attr_type(&entry, gimli::DW_AT_type, out)?
                    .unwrap_or(CType::Unknown {
                        display: "volatile_unknown".to_string(),
                    });
                CType::Volatile {
                    inner: Box::new(inner),
                }
            }
            gimli::DW_TAG_restrict_type => {
                let inner = self
                    .resolve_attr_type(&entry, gimli::DW_AT_type, out)?
                    .unwrap_or(CType::Unknown {
                        display: "restrict_unknown".to_string(),
                    });
                CType::Restrict {
                    inner: Box::new(inner),
                }
            }
            gimli::DW_TAG_array_type => self.resolve_array_type(offset, &entry, out)?,
            gimli::DW_TAG_subroutine_type => self.resolve_subroutine_type(offset, &entry, out)?,
            gimli::DW_TAG_typedef => self.resolve_typedef(offset, &entry, out)?,
            gimli::DW_TAG_structure_type => {
                self.resolve_record(offset, &entry, out, CTagKind::Struct)?
            }
            gimli::DW_TAG_union_type => {
                self.resolve_record(offset, &entry, out, CTagKind::Union)?
            }
            gimli::DW_TAG_enumeration_type => self.resolve_enum(offset, &entry, out)?,
            _ => CType::Unknown {
                display: format!("unsupported_{:?}", entry.tag()),
            },
        };

        self.in_progress.remove(&key);
        self.resolved_types.insert(key, resolved.clone());
        Ok(resolved)
    }

    fn resolve_array_type(
        &mut self,
        offset: UnitOffset<R::Offset>,
        entry: &DebuggingInformationEntry<R>,
        out: &mut CAnalysisBuilder,
    ) -> Result<CType> {
        let element = self
            .resolve_attr_type(entry, gimli::DW_AT_type, out)?
            .unwrap_or(CType::Unknown {
                display: "array_element".to_string(),
            });

        let mut tree = self
            .unit
            .entries_tree(Some(offset))
            .map_err(|err| Error::Format(format!("failed to rebuild array tree: {err}")))?;
        let root = tree
            .root()
            .map_err(|err| Error::Format(format!("failed to access array root: {err}")))?;
        let mut count = None;
        let mut children = root.children();
        while let Some(child) = children
            .next()
            .map_err(|err| Error::Format(format!("failed to iterate array children: {err}")))?
        {
            if child.entry().tag() != gimli::DW_TAG_subrange_type {
                continue;
            }
            if let Some(value) = child.entry().attr_value(gimli::DW_AT_count) {
                count = attr_udata(value);
            } else if let Some(value) = child.entry().attr_value(gimli::DW_AT_upper_bound) {
                count = attr_udata(value).map(|value| value + 1);
            }
        }

        Ok(CType::Array {
            element: Box::new(element),
            count,
        })
    }

    fn resolve_subroutine_type(
        &mut self,
        offset: UnitOffset<R::Offset>,
        entry: &DebuggingInformationEntry<R>,
        out: &mut CAnalysisBuilder,
    ) -> Result<CType> {
        let return_type = self
            .resolve_attr_type(entry, gimli::DW_AT_type, out)?
            .unwrap_or(CType::Void);
        let mut params = Vec::new();
        let mut variadic = false;

        let mut tree = self
            .unit
            .entries_tree(Some(offset))
            .map_err(|err| Error::Format(format!("failed to rebuild subroutine tree: {err}")))?;
        let root = tree
            .root()
            .map_err(|err| Error::Format(format!("failed to access subroutine root: {err}")))?;
        let mut children = root.children();
        while let Some(child) = children
            .next()
            .map_err(|err| Error::Format(format!("failed to iterate subroutine children: {err}")))?
        {
            match child.entry().tag() {
                gimli::DW_TAG_formal_parameter => {
                    params.push(CParamType {
                        name: attr_string(self.dwarf, self.unit, child.entry(), gimli::DW_AT_name)?,
                        ty: self
                            .resolve_attr_type(child.entry(), gimli::DW_AT_type, out)?
                            .unwrap_or(CType::Unknown {
                                display: "fnptr_param".to_string(),
                            }),
                    });
                }
                gimli::DW_TAG_unspecified_parameters => variadic = true,
                _ => {}
            }
        }

        Ok(CType::FunctionPointer {
            return_type: Box::new(return_type),
            params,
            variadic,
        })
    }

    fn resolve_typedef(
        &mut self,
        offset: UnitOffset<R::Offset>,
        entry: &DebuggingInformationEntry<R>,
        out: &mut CAnalysisBuilder,
    ) -> Result<CType> {
        let name = attr_string(self.dwarf, self.unit, entry, gimli::DW_AT_name)?
            .unwrap_or_else(|| format!("__typedef_{:#x}", offset.0 as u64));
        let target = self
            .resolve_attr_type(entry, gimli::DW_AT_type, out)?
            .unwrap_or(CType::Unknown {
                display: format!("typedef_target_{name}"),
            });
        let source = self.source_for(entry)?;

        out.typedefs
            .entry(name.clone())
            .or_insert_with(|| CTypedefDecl {
                name: name.clone(),
                target: target.clone(),
                source,
                evidence: vec![EvidenceFact {
                    kind: EvidenceKind::Dwarf,
                    confidence: Confidence::DwarfExact,
                    detail: "typedef recovered from DWARF".to_string(),
                }],
            });

        Ok(CType::Named { name, tag: None })
    }

    fn resolve_record(
        &mut self,
        offset: UnitOffset<R::Offset>,
        entry: &DebuggingInformationEntry<R>,
        out: &mut CAnalysisBuilder,
        kind: CTagKind,
    ) -> Result<CType> {
        let name = attr_string(self.dwarf, self.unit, entry, gimli::DW_AT_name)?
            .unwrap_or_else(|| synthetic_tag_name(kind, offset.0 as u64));
        let source = self.source_for(entry)?;
        let size = entry
            .attr_value(gimli::DW_AT_byte_size)
            .and_then(attr_udata);

        if !out.records.contains_key(&name) {
            let mut fields = Vec::new();
            let mut tree = self
                .unit
                .entries_tree(Some(offset))
                .map_err(|err| Error::Format(format!("failed to rebuild record tree: {err}")))?;
            let root = tree
                .root()
                .map_err(|err| Error::Format(format!("failed to access record root: {err}")))?;
            let mut children = root.children();
            while let Some(child) = children
                .next()
                .map_err(|err| Error::Format(format!("failed to iterate record children: {err}")))?
            {
                if child.entry().tag() != gimli::DW_TAG_member {
                    continue;
                }
                let field_name =
                    attr_string(self.dwarf, self.unit, child.entry(), gimli::DW_AT_name)?
                        .unwrap_or_else(|| format!("field_{}", fields.len()));
                let field_ty = self
                    .resolve_attr_type(child.entry(), gimli::DW_AT_type, out)?
                    .unwrap_or(CType::Unknown {
                        display: format!("{}_type", field_name),
                    });
                let bit_size = child
                    .entry()
                    .attr_value(gimli::DW_AT_bit_size)
                    .and_then(attr_udata);
                fields.push(CField {
                    name: field_name,
                    ty: field_ty,
                    bit_size,
                });
            }

            out.records.insert(
                name.clone(),
                CRecordDecl {
                    kind,
                    name: name.clone(),
                    fields,
                    complete: true,
                    size,
                    source,
                    evidence: vec![EvidenceFact {
                        kind: EvidenceKind::Dwarf,
                        confidence: Confidence::DwarfExact,
                        detail: format!("{kind:?} recovered from DWARF"),
                    }],
                },
            );
        }

        Ok(CType::Named {
            name,
            tag: Some(kind),
        })
    }

    fn resolve_enum(
        &mut self,
        offset: UnitOffset<R::Offset>,
        entry: &DebuggingInformationEntry<R>,
        out: &mut CAnalysisBuilder,
    ) -> Result<CType> {
        let name = attr_string(self.dwarf, self.unit, entry, gimli::DW_AT_name)?
            .unwrap_or_else(|| synthetic_tag_name(CTagKind::Enum, offset.0 as u64));
        let source = self.source_for(entry)?;

        if !out.enums.contains_key(&name) {
            let mut variants = Vec::new();
            let mut tree = self
                .unit
                .entries_tree(Some(offset))
                .map_err(|err| Error::Format(format!("failed to rebuild enum tree: {err}")))?;
            let root = tree
                .root()
                .map_err(|err| Error::Format(format!("failed to access enum root: {err}")))?;
            let mut children = root.children();
            while let Some(child) = children
                .next()
                .map_err(|err| Error::Format(format!("failed to iterate enum children: {err}")))?
            {
                if child.entry().tag() != gimli::DW_TAG_enumerator {
                    continue;
                }
                let variant_name =
                    attr_string(self.dwarf, self.unit, child.entry(), gimli::DW_AT_name)?
                        .unwrap_or_else(|| format!("{}_{}", name, variants.len()));
                let value = child
                    .entry()
                    .attr_value(gimli::DW_AT_const_value)
                    .and_then(attr_sdata)
                    .unwrap_or(variants.len() as i64);
                variants.push(CEnumVariant {
                    name: variant_name,
                    value,
                });
            }

            out.enums.insert(
                name.clone(),
                CEnumDecl {
                    name: name.clone(),
                    variants,
                    complete: true,
                    source,
                    evidence: vec![EvidenceFact {
                        kind: EvidenceKind::Dwarf,
                        confidence: Confidence::DwarfExact,
                        detail: "enum recovered from DWARF".to_string(),
                    }],
                },
            );
        }

        Ok(CType::Named {
            name,
            tag: Some(CTagKind::Enum),
        })
    }

    fn source_for(&self, entry: &DebuggingInformationEntry<R>) -> Result<SourceLocation> {
        let line = entry
            .attr_value(gimli::DW_AT_decl_line)
            .and_then(attr_udata);
        let file = attr_string(self.dwarf, self.unit, entry, gimli::DW_AT_decl_file)?
            .or_else(|| self.unit_source.file.clone());
        Ok(SourceLocation { file, line })
    }
}

fn build_header_units(analysis: &CAnalysis) -> Vec<CHeaderUnit> {
    let mut grouped: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let header_name = |source: &SourceLocation| {
        source
            .file
            .as_deref()
            .and_then(|file| Path::new(file).file_name())
            .and_then(|name| name.to_str())
            .map(str::to_owned)
            .unwrap_or_else(|| "recovered.h".to_string())
    };

    for record in &analysis.records {
        grouped
            .entry(header_name(&record.source))
            .or_default()
            .push(render_record(record));
    }
    for enumeration in &analysis.enums {
        grouped
            .entry(header_name(&enumeration.source))
            .or_default()
            .push(render_enum(enumeration));
    }
    for typedef in &analysis.typedefs {
        grouped
            .entry(header_name(&typedef.source))
            .or_default()
            .push(render_typedef(typedef));
    }
    for global in &analysis.globals {
        grouped
            .entry(header_name(&global.source))
            .or_default()
            .push(render_global(global));
    }
    for function in &analysis.functions {
        grouped
            .entry(header_name(&function.source))
            .or_default()
            .push(render_function(function));
    }

    grouped
        .into_iter()
        .map(|(name, declarations)| CHeaderUnit { name, declarations })
        .collect()
}

fn render_record(record: &CRecordDecl) -> String {
    let keyword = match record.kind {
        CTagKind::Struct => "struct",
        CTagKind::Union => "union",
        CTagKind::Enum => unreachable!(),
    };
    if !record.complete {
        return format!("{keyword} {};", record.name);
    }

    let mut out = format!("{keyword} {} {{\n", record.name);
    for field in &record.fields {
        out.push_str("    ");
        out.push_str(&render_type_with_name(&field.ty, &field.name));
        if let Some(bit_size) = field.bit_size {
            out.push_str(&format!(" : {bit_size}"));
        }
        out.push_str(";\n");
    }
    out.push_str("};");
    out
}

fn render_enum(enumeration: &CEnumDecl) -> String {
    let mut out = format!("enum {} {{\n", enumeration.name);
    for (index, variant) in enumeration.variants.iter().enumerate() {
        let suffix = if index + 1 == enumeration.variants.len() {
            ""
        } else {
            ","
        };
        out.push_str(&format!(
            "    {} = {}{suffix}\n",
            variant.name, variant.value
        ));
    }
    out.push_str("};");
    out
}

fn render_typedef(typedef: &CTypedefDecl) -> String {
    match &typedef.target {
        CType::Named {
            name,
            tag: Some(tag),
        } => {
            let keyword = match tag {
                CTagKind::Struct => "struct",
                CTagKind::Union => "union",
                CTagKind::Enum => "enum",
            };
            format!("typedef {keyword} {name} {};", typedef.name)
        }
        other => format!("typedef {};", render_type_with_name(other, &typedef.name)),
    }
}

fn render_function(function: &CFunctionDecl) -> String {
    let params = if function.params.is_empty() && !function.variadic {
        "void".to_string()
    } else {
        let mut rendered: Vec<String> = function
            .params
            .iter()
            .enumerate()
            .map(|(index, param)| {
                let name = param.name.clone().unwrap_or_else(|| format!("arg{index}"));
                render_type_with_name(&param.ty, &name)
            })
            .collect();
        if function.variadic {
            rendered.push("...".to_string());
        }
        rendered.join(", ")
    };

    format!(
        "{}({params});",
        render_function_signature(&function.return_type, &function.name)
    )
}

fn render_global(global: &CGlobalDecl) -> String {
    format!(
        "extern {};",
        render_type_with_name(&global.ty, &global.name)
    )
}

fn render_function_signature(return_type: &CType, name: &str) -> String {
    match return_type {
        CType::FunctionPointer { .. } => render_type_with_name(return_type, name),
        _ => format!("{} {name}", render_type(return_type)),
    }
}

fn render_type(ty: &CType) -> String {
    render_type_with_name(ty, "").trim().to_string()
}

fn render_type_with_name(ty: &CType, name: &str) -> String {
    match ty {
        CType::Void => render_named("void", name),
        CType::Builtin { name: builtin } => render_named(builtin, name),
        CType::Named {
            name: named,
            tag: Some(tag),
        } => {
            let keyword = match tag {
                CTagKind::Struct => "struct",
                CTagKind::Union => "union",
                CTagKind::Enum => "enum",
            };
            render_named(&format!("{keyword} {named}"), name)
        }
        CType::Named {
            name: named,
            tag: None,
        } => render_named(named, name),
        CType::Pointer { to } => {
            let decorated = if name.is_empty() {
                "*".to_string()
            } else {
                format!("*{name}")
            };
            match &**to {
                CType::Array { .. } | CType::FunctionPointer { .. } => {
                    render_type_with_name(to, &format!("({decorated})"))
                }
                _ => render_type_with_name(to, &decorated),
            }
        }
        CType::Array { element, count } => {
            let suffix = count.map(|count| count.to_string()).unwrap_or_default();
            render_type_with_name(element, &format!("{name}[{suffix}]"))
        }
        CType::Const { inner } => match &**inner {
            CType::Pointer { .. } | CType::Array { .. } | CType::FunctionPointer { .. } => {
                render_type_with_name(inner, &format!("const {name}"))
            }
            _ => render_named(&format!("const {}", render_type(inner)), name),
        },
        CType::Volatile { inner } => {
            render_named(&format!("volatile {}", render_type(inner)), name)
        }
        CType::Restrict { inner } => {
            render_named(&format!("restrict {}", render_type(inner)), name)
        }
        CType::FunctionPointer {
            return_type,
            params,
            variadic,
        } => {
            let mut rendered: Vec<String> = params
                .iter()
                .enumerate()
                .map(|(index, param)| {
                    let param_name = param.name.clone().unwrap_or_else(|| format!("arg{index}"));
                    render_type_with_name(&param.ty, &param_name)
                })
                .collect();
            if *variadic {
                rendered.push("...".to_string());
            }
            let params = if rendered.is_empty() {
                "void".to_string()
            } else {
                rendered.join(", ")
            };
            render_type_with_name(return_type, &format!("(*{name})({params})"))
        }
        CType::Unknown { display } => render_named(display, name),
    }
}

fn render_named(base: &str, name: &str) -> String {
    if name.is_empty() {
        base.to_string()
    } else {
        format!("{base} {name}")
    }
}

fn correlate_named_items<'a, I>(
    header: &Path,
    contents: &str,
    items: I,
    matches: &mut Vec<HeaderCorrelationMatch>,
    seen: &mut BTreeSet<(String, String)>,
) where
    I: IntoIterator<Item = (&'a String, &'a mut Vec<EvidenceFact>)>,
{
    for (name, evidence) in items {
        if !contains_identifier(contents, name) {
            continue;
        }
        let header_path = header.display().to_string();
        let key = (header_path.clone(), name.clone());
        if !seen.insert(key) {
            continue;
        }
        evidence.push(EvidenceFact {
            kind: EvidenceKind::HeaderMatch,
            confidence: Confidence::Correlated,
            detail: format!("matched symbol name in header {}", header.display()),
        });
        matches.push(HeaderCorrelationMatch {
            path: header_path,
            symbol: name.clone(),
            confidence: Confidence::Correlated,
        });
    }
}

fn contains_identifier(contents: &str, needle: &str) -> bool {
    contents.match_indices(needle).any(|(idx, _)| {
        let before = contents[..idx].chars().next_back();
        let after = contents[idx + needle.len()..].chars().next();
        is_boundary(before) && is_boundary(after)
    })
}

fn is_boundary(ch: Option<char>) -> bool {
    match ch {
        None => true,
        Some(ch) => !(ch.is_ascii_alphanumeric() || ch == '_'),
    }
}

fn collect_headers(root: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        let entries = fs::read_dir(&path).map_err(|err| {
            Error::Format(format!(
                "failed to read header directory {}: {err}",
                path.display()
            ))
        })?;
        for entry in entries {
            let entry = entry
                .map_err(|err| Error::Format(format!("failed to read directory entry: {err}")))?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|ext| ext.to_str()) == Some("h") {
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
}

fn find_symbol<'a>(symtab: &'a SymbolTable<'_>, name: &str) -> Option<&'a Symbol<'a>> {
    let prefixed = format!("_{name}");
    symtab
        .find_by_name(name)
        .or_else(|| symtab.find_by_name(&prefixed))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SymbolClassification {
    Function,
    Global,
    Skip,
}

fn classify_symbol(mach: &MachFile<'_>, symbol: &Symbol<'_>) -> SymbolClassification {
    if symbol.is_stab() {
        return SymbolClassification::Skip;
    }
    let Some(section) = section_for_symbol(mach, symbol) else {
        return if symbol.is_undefined() {
            SymbolClassification::Function
        } else {
            SymbolClassification::Skip
        };
    };
    if section.section_name == "__text" {
        SymbolClassification::Function
    } else {
        SymbolClassification::Global
    }
}

fn section_for_symbol<'a>(mach: &'a MachFile<'_>, symbol: &Symbol<'_>) -> Option<&'a Section> {
    let section_index = usize::from(symbol.section_index);
    if section_index == 0 {
        return None;
    }
    mach.all_sections().nth(section_index - 1)
}

fn normalize_c_symbol_name(name: &str) -> Option<String> {
    let stripped = name.strip_prefix('_').unwrap_or(name);
    if stripped.is_empty() {
        return None;
    }
    let first = stripped.chars().next()?;
    if !(first == '_' || first.is_ascii_alphabetic()) {
        return None;
    }
    if stripped
        .chars()
        .any(|ch| !(ch == '_' || ch.is_ascii_alphanumeric()))
    {
        return None;
    }
    Some(stripped.to_string())
}

fn is_probable_c_symbol(name: &str) -> bool {
    let stripped = name.strip_prefix('_').unwrap_or(name);
    !stripped.starts_with("OBJC_")
        && !stripped.starts_with("_OBJC_")
        && !stripped.starts_with("$s")
        && !stripped.starts_with("swift")
        && !stripped.starts_with("Z")
        && !stripped.starts_with("_Z")
        && !stripped.starts_with("___")
}

fn synthetic_tag_name(kind: CTagKind, offset: u64) -> String {
    match kind {
        CTagKind::Struct => format!("__anon_struct_{offset:x}"),
        CTagKind::Union => format!("__anon_union_{offset:x}"),
        CTagKind::Enum => format!("__anon_enum_{offset:x}"),
    }
}

fn runtime_endian(endian: Endian) -> RunTimeEndian {
    match endian {
        Endian::Little => RunTimeEndian::Little,
        Endian::Big => RunTimeEndian::Big,
    }
}

fn attr_string<R>(
    dwarf: &Dwarf<R>,
    unit: &Unit<R>,
    entry: &DebuggingInformationEntry<R>,
    name: gimli::DwAt,
) -> Result<Option<String>>
where
    R: Reader<Offset = usize>,
{
    let Some(value) = entry.attr_value(name) else {
        return Ok(None);
    };

    if let AttributeValue::FileIndex(index) = value {
        return resolve_decl_file(dwarf, unit, index);
    }

    match dwarf.attr_string(unit, value.clone()) {
        Ok(string) => Ok(Some(reader_to_string(string)?)),
        Err(_) => match value {
            AttributeValue::String(s) => Ok(Some(reader_to_string(s)?)),
            _ => Ok(None),
        },
    }
}

fn resolve_decl_file<R>(dwarf: &Dwarf<R>, unit: &Unit<R>, index: u64) -> Result<Option<String>>
where
    R: Reader<Offset = usize>,
{
    let Some(program) = unit.line_program.as_ref() else {
        return Ok(None);
    };
    let header = program.header();
    let Some(file) = header.file(index) else {
        return Ok(None);
    };
    let path_name = dwarf
        .attr_string(unit, file.path_name())
        .map_err(|err| Error::Format(format!("failed to resolve DWARF file path: {err}")))?;
    Ok(Some(reader_to_string(path_name)?))
}

fn attr_flag<R>(entry: &DebuggingInformationEntry<R>, name: gimli::DwAt) -> Result<bool>
where
    R: Reader<Offset = usize>,
{
    Ok(entry
        .attr_value(name)
        .and_then(|value| match value {
            AttributeValue::Flag(flag) => Some(flag),
            AttributeValue::Udata(value) => Some(value != 0),
            _ => None,
        })
        .unwrap_or(false))
}

fn attr_udata<R>(value: AttributeValue<R>) -> Option<u64>
where
    R: Reader<Offset = usize>,
{
    match value {
        AttributeValue::Udata(value) => Some(value),
        AttributeValue::Data1(value) => Some(u64::from(value)),
        AttributeValue::Data2(value) => Some(u64::from(value)),
        AttributeValue::Data4(value) => Some(u64::from(value)),
        AttributeValue::Data8(value) => Some(value),
        _ => None,
    }
}

fn attr_sdata<R>(value: AttributeValue<R>) -> Option<i64>
where
    R: Reader<Offset = usize>,
{
    match value {
        AttributeValue::Sdata(value) => Some(value),
        AttributeValue::Udata(value) => i64::try_from(value).ok(),
        AttributeValue::Data1(value) => Some(i64::from(value)),
        AttributeValue::Data2(value) => Some(i64::from(value)),
        AttributeValue::Data4(value) => Some(i64::from(value)),
        AttributeValue::Data8(value) => i64::try_from(value).ok(),
        _ => None,
    }
}

fn reader_to_string<R>(reader: R) -> Result<String>
where
    R: Reader<Offset = usize>,
{
    let bytes = reader
        .to_slice()
        .map_err(|err| Error::Format(format!("failed to materialize DWARF string: {err}")))?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_function_pointer_type() {
        let ty = CType::Pointer {
            to: Box::new(CType::FunctionPointer {
                return_type: Box::new(CType::Builtin {
                    name: "int".to_string(),
                }),
                params: vec![CParamType {
                    name: Some("value".to_string()),
                    ty: CType::Builtin {
                        name: "int".to_string(),
                    },
                }],
                variadic: false,
            }),
        };

        assert_eq!(
            render_type_with_name(&ty, "callback"),
            "int (*callback)(int value)"
        );
    }

    #[test]
    fn identifier_correlation_requires_boundaries() {
        assert!(contains_identifier("int widget(void);", "widget"));
        assert!(!contains_identifier("int widgetizer(void);", "widget"));
    }
}
