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
            .map_err(|err| Error::invalid(format!("failed to iterate DWARF units: {err}")))?
        {
            let unit = dwarf
                .unit(header)
                .map_err(|err| Error::invalid(format!("failed to parse DWARF unit: {err}")))?;
            let mut tree = unit
                .entries_tree(None)
                .map_err(|err| Error::invalid(format!("failed to build DWARF entry tree: {err}")))?;
            let root = tree
                .root()
                .map_err(|err| Error::invalid(format!("failed to access DWARF root: {err}")))?;

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

    fn reconcile_symbols(&mut self, macho: &MachoFile<'_>, symtab: Option<&SymbolTable<'_>>) {
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

            match classify_symbol(macho, symbol) {
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
            .map_err(|err| Error::invalid(format!("failed to iterate DWARF children: {err}")))?
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
            .map_err(|err| Error::invalid(format!("failed to rebuild function tree: {err}")))?;
        let root = tree
            .root()
            .map_err(|err| Error::invalid(format!("failed to read function tree root: {err}")))?;
        let mut children = root.children();
        while let Some(child) = children
            .next()
            .map_err(|err| Error::invalid(format!("failed to iterate function children: {err}")))?
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

        upsert_function(
            &mut out.functions,
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

        upsert_global(
            &mut out.globals,
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
            .map_err(|err| Error::invalid(format!("failed to resolve DWARF type DIE: {err}")))?;

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
            .map_err(|err| Error::invalid(format!("failed to rebuild array tree: {err}")))?;
        let root = tree
            .root()
            .map_err(|err| Error::invalid(format!("failed to access array root: {err}")))?;
        let mut count = None;
        let mut children = root.children();
        while let Some(child) = children
            .next()
            .map_err(|err| Error::invalid(format!("failed to iterate array children: {err}")))?
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
            .map_err(|err| Error::invalid(format!("failed to rebuild subroutine tree: {err}")))?;
        let root = tree
            .root()
            .map_err(|err| Error::invalid(format!("failed to access subroutine root: {err}")))?;
        let mut children = root.children();
        while let Some(child) = children
            .next()
            .map_err(|err| Error::invalid(format!("failed to iterate subroutine children: {err}")))?
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
        let declaration_only = attr_flag(entry, gimli::DW_AT_declaration)?;
        let size = entry
            .attr_value(gimli::DW_AT_byte_size)
            .and_then(attr_udata);
        let mut fields = Vec::new();
        let mut complete = !declaration_only;

        if !declaration_only {
            let mut tree = self
                .unit
                .entries_tree(Some(offset))
                .map_err(|err| Error::invalid(format!("failed to rebuild record tree: {err}")))?;
            let root = tree
                .root()
                .map_err(|err| Error::invalid(format!("failed to access record root: {err}")))?;
            let mut children = root.children();
            while let Some(child) = children
                .next()
                .map_err(|err| Error::invalid(format!("failed to iterate record children: {err}")))?
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
            complete = complete && (size.is_some() || !fields.is_empty());
        }

        upsert_record(
            &mut out.records,
            CRecordDecl {
                kind,
                name: name.clone(),
                fields,
                complete,
                size,
                source,
                evidence: vec![EvidenceFact {
                    kind: EvidenceKind::Dwarf,
                    confidence: Confidence::DwarfExact,
                    detail: format!("{kind:?} recovered from DWARF"),
                }],
            },
        );

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
        let declaration_only = attr_flag(entry, gimli::DW_AT_declaration)?;
        let mut variants = Vec::new();
        if !declaration_only {
            let mut tree = self
                .unit
                .entries_tree(Some(offset))
                .map_err(|err| Error::invalid(format!("failed to rebuild enum tree: {err}")))?;
            let root = tree
                .root()
                .map_err(|err| Error::invalid(format!("failed to access enum root: {err}")))?;
            let mut children = root.children();
            while let Some(child) = children
                .next()
                .map_err(|err| Error::invalid(format!("failed to iterate enum children: {err}")))?
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
        }

        upsert_enum(
            &mut out.enums,
            CEnumDecl {
                name: name.clone(),
                variants,
                complete: !declaration_only,
                source,
                evidence: vec![EvidenceFact {
                    kind: EvidenceKind::Dwarf,
                    confidence: Confidence::DwarfExact,
                    detail: "enum recovered from DWARF".to_string(),
                }],
            },
        );

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
        .map_err(|err| Error::invalid(format!("failed to resolve DWARF file path: {err}")))?;
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
        .map_err(|err| Error::invalid(format!("failed to materialize DWARF string: {err}")))?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_function_pointer_type() {
        let ty = CType::FunctionPointer {
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
