//! DWARF function index: extracts function signatures from debug info.
//!
//! Walks `DW_TAG_subprogram` entries across all compilation units, resolving
//! parameter types and return types into [`DwarfFunctionInfo`] values that
//! can be queried by linkage name or address.

use std::collections::{BTreeMap, HashMap, HashSet};

use gimli::{
    AttributeValue, DW_AT_abstract_origin, DW_AT_artificial, DW_AT_byte_size,
    DW_AT_calling_convention, DW_AT_count, DW_AT_encoding, DW_AT_high_pc, DW_AT_linkage_name,
    DW_AT_low_pc, DW_AT_name, DW_AT_type, DW_AT_upper_bound, DW_CC_normal, DW_TAG_array_type,
    DW_TAG_base_type, DW_TAG_class_type, DW_TAG_const_type, DW_TAG_enumeration_type,
    DW_TAG_formal_parameter, DW_TAG_pointer_type, DW_TAG_reference_type, DW_TAG_restrict_type,
    DW_TAG_rvalue_reference_type, DW_TAG_structure_type, DW_TAG_subprogram, DW_TAG_subroutine_type,
    DW_TAG_typedef, DW_TAG_union_type, DW_TAG_unspecified_parameters, DW_TAG_variable,
    DW_TAG_volatile_type, EndianSlice, LittleEndian, UnitOffset,
};

use super::types::*;
use crate::Result;
use crate::model::macho_file::MachoFile;

type R<'a> = EndianSlice<'a, LittleEndian>;
type GDwarf<'a> = gimli::Dwarf<R<'a>>;
type GUnit<'a> = gimli::Unit<R<'a>>;
type GDie<'a> = gimli::DebuggingInformationEntry<R<'a>>;

/// An index of functions extracted from DWARF debug information.
///
/// Supports lookup by mangled/linkage name and by virtual address.
#[derive(Debug, Clone)]
pub struct DwarfFunctionIndex {
    by_linkage_name: HashMap<String, usize>,
    by_address: BTreeMap<u64, usize>,
    functions: Vec<DwarfFunctionInfo>,
}

/// An index of global variables extracted from DWARF debug information.
#[derive(Debug, Clone)]
pub struct DwarfVariableIndex {
    by_linkage_name: HashMap<String, usize>,
    by_name: HashMap<String, usize>,
    variables: Vec<DwarfVariableInfo>,
}

impl DwarfVariableIndex {
    /// Builds a variable index from all `DW_TAG_variable` entries.
    pub fn build(macho: &MachoFile<'_>) -> Result<Self> {
        let sections = super::load_dwarf(macho)?;
        let Some(sections) = sections else {
            return Ok(Self::empty());
        };
        let dwarf = sections.borrow(|section| EndianSlice::new(section, LittleEndian));
        let mut variables = Vec::new();
        let mut headers = dwarf.units();
        while let Ok(Some(header)) = headers.next() {
            let Ok(unit) = dwarf.unit(header) else {
                continue;
            };
            let mut entries = unit.entries();
            while let Ok(Some(entry)) = entries.next_dfs() {
                if entry.tag() == DW_TAG_variable
                    && let Some(variable) = parse_variable(&dwarf, &unit, entry)
                {
                    variables.push(variable);
                }
            }
        }
        let mut by_linkage_name = HashMap::new();
        let mut by_name = HashMap::new();
        for (index, variable) in variables.iter().enumerate() {
            if let Some(name) = &variable.linkage_name {
                by_linkage_name.insert(name.clone(), index);
            }
            if let Some(name) = &variable.name {
                by_name.insert(name.clone(), index);
            }
        }
        Ok(Self {
            by_linkage_name,
            by_name,
            variables,
        })
    }

    /// Creates an empty variable index.
    pub fn empty() -> Self {
        Self {
            by_linkage_name: HashMap::new(),
            by_name: HashMap::new(),
            variables: Vec::new(),
        }
    }

    /// Finds a variable by its linkage spelling.
    pub fn find_by_linkage_name(&self, name: &str) -> Option<&DwarfVariableInfo> {
        self.by_linkage_name
            .get(name)
            .map(|index| &self.variables[*index])
    }

    /// Finds a variable by its source spelling.
    pub fn find_by_name(&self, name: &str) -> Option<&DwarfVariableInfo> {
        self.by_name.get(name).map(|index| &self.variables[*index])
    }

    /// Returns whether the index contains no variables.
    pub fn is_empty(&self) -> bool {
        self.variables.is_empty()
    }

    /// Returns the number of indexed variables.
    pub fn len(&self) -> usize {
        self.variables.len()
    }
}

impl DwarfFunctionIndex {
    /// Build a function index from the DWARF sections in a Mach-O binary.
    ///
    /// Returns an empty index if the binary has no DWARF sections.
    pub fn build(macho: &MachoFile<'_>) -> Result<Self> {
        let sections = super::load_dwarf(macho)?;
        let Some(sections) = sections else {
            return Ok(Self::empty());
        };

        let dwarf = sections.borrow(|section| EndianSlice::new(section, LittleEndian));

        let mut functions = Vec::new();
        let mut headers = dwarf.units();

        while let Ok(Some(header)) = headers.next() {
            let unit = match dwarf.unit(header) {
                Ok(u) => u,
                Err(_) => continue,
            };

            let mut entries = unit.entries();
            while let Ok(Some(entry)) = entries.next_dfs() {
                if entry.tag() != DW_TAG_subprogram {
                    continue;
                }

                if let Some(func) = parse_subprogram(&dwarf, &unit, entry) {
                    functions.push(func);
                }
            }
        }

        let mut by_linkage_name = HashMap::new();
        let mut by_address = BTreeMap::new();

        for (i, func) in functions.iter().enumerate() {
            if let Some(ref name) = func.linkage_name {
                by_linkage_name.insert(name.clone(), i);
            }
            if let Some(addr) = func.address {
                if addr != 0 {
                    by_address.insert(addr, i);
                }
            }
        }

        Ok(Self {
            by_linkage_name,
            by_address,
            functions,
        })
    }

    /// Create an empty index.
    pub fn empty() -> Self {
        Self {
            by_linkage_name: HashMap::new(),
            by_address: BTreeMap::new(),
            functions: Vec::new(),
        }
    }

    /// Find a function by its linkage (mangled) name.
    pub fn find_by_linkage_name(&self, name: &str) -> Option<&DwarfFunctionInfo> {
        self.by_linkage_name.get(name).map(|&i| &self.functions[i])
    }

    /// Find the function containing the given address.
    pub fn find_by_address(&self, addr: u64) -> Option<&DwarfFunctionInfo> {
        let (&func_addr, &idx) = self.by_address.range(..=addr).next_back()?;
        let func = &self.functions[idx];
        if let Some(size) = func.size {
            if addr >= func_addr + size {
                return None;
            }
        }
        Some(func)
    }

    /// All functions in the index.
    pub fn functions(&self) -> &[DwarfFunctionInfo] {
        &self.functions
    }

    /// Whether the index has no functions.
    pub fn is_empty(&self) -> bool {
        self.functions.is_empty()
    }

    /// Number of indexed functions.
    pub fn len(&self) -> usize {
        self.functions.len()
    }
}

// ───────────────────────────────── parsing ─────────────────────────────────

fn parse_subprogram(
    dwarf: &GDwarf<'_>,
    unit: &GUnit<'_>,
    entry: &GDie<'_>,
) -> Option<DwarfFunctionInfo> {
    let unit_offset = unit.header.offset().0 as u64;
    let die_offset = entry.offset().0 as u64;
    let name = attr_string(dwarf, unit, entry, DW_AT_name);
    let linkage_name = attr_string(dwarf, unit, entry, DW_AT_linkage_name);

    // Skip entries with no name and no linkage name.
    if name.is_none() && linkage_name.is_none() {
        return None;
    }

    let address = entry.attr_value(DW_AT_low_pc).and_then(|v| match v {
        AttributeValue::Addr(a) => Some(a),
        _ => None,
    });

    let size = entry.attr_value(DW_AT_high_pc).and_then(|v| match v {
        AttributeValue::Udata(s) => Some(s),
        AttributeValue::Addr(high) => address.map(|low| high - low),
        _ => None,
    });

    let return_type = entry
        .attr_value(DW_AT_type)
        .and_then(type_ref_offset)
        .map(|offset| resolve_type(dwarf, unit, offset, &mut HashSet::new()))
        .unwrap_or(DwarfType::Void);

    let calling_convention = entry
        .attr_value(DW_AT_calling_convention)
        .and_then(|v| match v {
            AttributeValue::Udata(cc) => Some(cc as u8),
            _ => None,
        })
        .map(|cc| {
            if cc == DW_CC_normal.0 {
                CallingConvention::Normal
            } else {
                CallingConvention::Other(cc)
            }
        })
        .unwrap_or(CallingConvention::Normal);

    // Walk children for parameters and variadic marker.
    let mut parameters = Vec::new();
    let mut is_variadic = false;

    let offset = entry.offset();
    if let Ok(mut tree) = unit.entries_tree(Some(offset)) {
        if let Ok(root) = tree.root() {
            let mut children = root.children();
            while let Ok(Some(child)) = children.next() {
                let child_entry = child.entry();
                match child_entry.tag() {
                    DW_TAG_formal_parameter => {
                        if let Some(param) = parse_parameter(dwarf, unit, child_entry) {
                            parameters.push(param);
                        }
                    }
                    DW_TAG_unspecified_parameters => {
                        is_variadic = true;
                    }
                    _ => {}
                }
            }
        }
    }

    Some(DwarfFunctionInfo {
        unit_offset,
        die_offset,
        name,
        linkage_name,
        address,
        size,
        return_type,
        parameters,
        is_variadic,
        calling_convention,
    })
}

fn parse_variable(
    dwarf: &GDwarf<'_>,
    unit: &GUnit<'_>,
    entry: &GDie<'_>,
) -> Option<DwarfVariableInfo> {
    let name = attr_string(dwarf, unit, entry, DW_AT_name);
    let linkage_name = attr_string(dwarf, unit, entry, DW_AT_linkage_name);
    if name.is_none() && linkage_name.is_none() {
        return None;
    }
    let ty = entry
        .attr_value(DW_AT_type)
        .and_then(type_ref_offset)
        .map(|offset| resolve_type(dwarf, unit, offset, &mut HashSet::new()))
        .unwrap_or(DwarfType::Unresolved);
    Some(DwarfVariableInfo {
        unit_offset: unit.header.offset().0 as u64,
        die_offset: entry.offset().0 as u64,
        name,
        linkage_name,
        ty,
    })
}

fn parse_parameter(
    dwarf: &GDwarf<'_>,
    unit: &GUnit<'_>,
    entry: &GDie<'_>,
) -> Option<DwarfParameter> {
    // If this parameter has an abstract_origin, follow it for name/type.
    let (param_name, type_val) = if let Some(origin_offset) = entry
        .attr_value(DW_AT_abstract_origin)
        .and_then(type_ref_offset)
    {
        if let Ok(origin) = unit.entry(origin_offset) {
            let n = attr_string(dwarf, unit, entry, DW_AT_name)
                .or_else(|| attr_string(dwarf, unit, &origin, DW_AT_name));
            let t = entry
                .attr_value(DW_AT_type)
                .or_else(|| origin.attr_value(DW_AT_type));
            (n, t)
        } else {
            (
                attr_string(dwarf, unit, entry, DW_AT_name),
                entry.attr_value(DW_AT_type),
            )
        }
    } else {
        (
            attr_string(dwarf, unit, entry, DW_AT_name),
            entry.attr_value(DW_AT_type),
        )
    };

    let ty = type_val
        .and_then(type_ref_offset)
        .map(|offset| resolve_type(dwarf, unit, offset, &mut HashSet::new()))
        .unwrap_or(DwarfType::Unresolved);

    let is_artificial = entry
        .attr_value(DW_AT_artificial)
        .and_then(|v| match v {
            AttributeValue::Flag(f) => Some(f),
            _ => None,
        })
        .unwrap_or(false);

    Some(DwarfParameter {
        name: param_name,
        ty,
        is_artificial,
    })
}

// ───────────────────────────────── type resolution ─────────────────────────

fn resolve_type(
    dwarf: &GDwarf<'_>,
    unit: &GUnit<'_>,
    offset: UnitOffset,
    visited: &mut HashSet<UnitOffset>,
) -> DwarfType {
    if !visited.insert(offset) {
        return DwarfType::Unresolved; // cycle
    }

    let entry = match unit.entry(offset) {
        Ok(e) => e,
        Err(_) => return DwarfType::Unresolved,
    };

    let result = match entry.tag() {
        DW_TAG_base_type => {
            let name = attr_string(dwarf, unit, &entry, DW_AT_name).unwrap_or_default();
            let byte_size = attr_udata(&entry, DW_AT_byte_size).unwrap_or(0);
            let encoding = attr_udata(&entry, DW_AT_encoding)
                .map(|v| BaseTypeEncoding::from_dwarf(v as u8))
                .unwrap_or(BaseTypeEncoding::Other(0));
            DwarfType::Base {
                name,
                byte_size,
                encoding,
            }
        }
        DW_TAG_pointer_type => {
            let byte_size = attr_udata(&entry, DW_AT_byte_size).unwrap_or(8);
            let pointee = follow_type_attr(dwarf, unit, &entry, visited);
            DwarfType::Pointer {
                pointee: Box::new(pointee),
                byte_size,
            }
        }
        DW_TAG_reference_type => {
            let referent = follow_type_attr(dwarf, unit, &entry, visited);
            DwarfType::Reference {
                referent: Box::new(referent),
            }
        }
        DW_TAG_rvalue_reference_type => {
            let referent = follow_type_attr(dwarf, unit, &entry, visited);
            DwarfType::RvalueReference {
                referent: Box::new(referent),
            }
        }
        DW_TAG_const_type => {
            let inner = follow_type_attr(dwarf, unit, &entry, visited);
            DwarfType::Const(Box::new(inner))
        }
        DW_TAG_volatile_type => {
            let inner = follow_type_attr(dwarf, unit, &entry, visited);
            DwarfType::Volatile(Box::new(inner))
        }
        DW_TAG_restrict_type => {
            let inner = follow_type_attr(dwarf, unit, &entry, visited);
            DwarfType::Restrict(Box::new(inner))
        }
        DW_TAG_typedef => {
            let name = attr_string(dwarf, unit, &entry, DW_AT_name).unwrap_or_default();
            let underlying = follow_type_attr(dwarf, unit, &entry, visited);
            DwarfType::Typedef {
                name,
                underlying: Box::new(underlying),
            }
        }
        DW_TAG_structure_type | DW_TAG_class_type => {
            let name = attr_string(dwarf, unit, &entry, DW_AT_name);
            let byte_size = attr_udata(&entry, DW_AT_byte_size);
            DwarfType::Structure { name, byte_size }
        }
        DW_TAG_union_type => {
            let name = attr_string(dwarf, unit, &entry, DW_AT_name);
            let byte_size = attr_udata(&entry, DW_AT_byte_size);
            DwarfType::Union { name, byte_size }
        }
        DW_TAG_enumeration_type => {
            let name = attr_string(dwarf, unit, &entry, DW_AT_name);
            let byte_size = attr_udata(&entry, DW_AT_byte_size);
            DwarfType::Enumeration { name, byte_size }
        }
        DW_TAG_array_type => {
            let element = follow_type_attr(dwarf, unit, &entry, visited);
            let count = extract_array_count(unit, offset);
            DwarfType::Array {
                element: Box::new(element),
                count,
            }
        }
        DW_TAG_subroutine_type => {
            let return_type = follow_type_attr(dwarf, unit, &entry, visited);
            let params = extract_subroutine_params(dwarf, unit, offset, visited);
            DwarfType::Subroutine {
                return_type: Box::new(return_type),
                params,
            }
        }
        _ => DwarfType::Unresolved,
    };

    visited.remove(&offset);
    result
}

fn follow_type_attr(
    dwarf: &GDwarf<'_>,
    unit: &GUnit<'_>,
    entry: &GDie<'_>,
    visited: &mut HashSet<UnitOffset>,
) -> DwarfType {
    entry
        .attr_value(DW_AT_type)
        .and_then(type_ref_offset)
        .map(|offset| resolve_type(dwarf, unit, offset, visited))
        .unwrap_or(DwarfType::Void)
}

fn extract_array_count(unit: &GUnit<'_>, array_offset: UnitOffset) -> Option<u64> {
    let mut tree = unit.entries_tree(Some(array_offset)).ok()?;
    let root = tree.root().ok()?;
    let mut children = root.children();
    while let Ok(Some(child)) = children.next() {
        let entry = child.entry();
        // DW_TAG_subrange_type = 0x21
        if entry.tag().0 == 0x21 {
            if let Some(count) = attr_udata(entry, DW_AT_count) {
                return Some(count);
            }
            if let Some(upper) = attr_udata(entry, DW_AT_upper_bound) {
                return Some(upper + 1);
            }
        }
    }
    None
}

fn extract_subroutine_params(
    dwarf: &GDwarf<'_>,
    unit: &GUnit<'_>,
    subr_offset: UnitOffset,
    visited: &mut HashSet<UnitOffset>,
) -> Vec<DwarfType> {
    let mut params = Vec::new();
    let Ok(mut tree) = unit.entries_tree(Some(subr_offset)) else {
        return params;
    };
    let Ok(root) = tree.root() else {
        return params;
    };
    let mut children = root.children();
    while let Ok(Some(child)) = children.next() {
        let entry = child.entry();
        if entry.tag() == DW_TAG_formal_parameter {
            let ty = follow_type_attr(dwarf, unit, entry, visited);
            params.push(ty);
        }
    }
    params
}

// ───────────────────────────────── helpers ─────────────────────────────────

fn attr_string(
    dwarf: &GDwarf<'_>,
    unit: &GUnit<'_>,
    entry: &GDie<'_>,
    name: gimli::DwAt,
) -> Option<String> {
    let val = entry.attr_value(name)?;
    match val {
        AttributeValue::DebugStrRef(offset) => dwarf
            .debug_str
            .get_str(offset)
            .ok()
            .and_then(|s| std::str::from_utf8(s.slice()).ok())
            .map(|s| s.to_string()),
        AttributeValue::String(s) => std::str::from_utf8(s.slice()).ok().map(|s| s.to_string()),
        AttributeValue::DebugStrOffsetsIndex(idx) => {
            let offset = dwarf.string_offset(unit, idx).ok()?;
            dwarf
                .debug_str
                .get_str(offset)
                .ok()
                .and_then(|s| std::str::from_utf8(s.slice()).ok())
                .map(|s| s.to_string())
        }
        _ => None,
    }
}

fn attr_udata(entry: &GDie<'_>, name: gimli::DwAt) -> Option<u64> {
    let val = entry.attr_value(name)?;
    match val {
        AttributeValue::Udata(v) => Some(v),
        AttributeValue::Data1(v) => Some(v as u64),
        AttributeValue::Data2(v) => Some(v as u64),
        AttributeValue::Data4(v) => Some(v as u64),
        AttributeValue::Data8(v) => Some(v),
        AttributeValue::Sdata(v) => Some(v as u64),
        _ => None,
    }
}

fn type_ref_offset(val: AttributeValue<R<'_>>) -> Option<UnitOffset> {
    match val {
        AttributeValue::UnitRef(offset) => Some(offset),
        _ => None,
    }
}
