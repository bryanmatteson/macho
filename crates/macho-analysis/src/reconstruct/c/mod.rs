use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use gimli::{
    self, AttributeValue, DebuggingInformationEntry, Dwarf, EndianSlice, EntriesTreeNode, Reader,
    RunTimeEndian, Unit, UnitOffset,
};
use serde::Serialize;

use crate::core::format::io::endian::Endian;
use crate::core::{MachoFile, Section, Symbol, SymbolTable};
use crate::dwarf::load_dwarf;
use crate::{Error, Result};

/// Performs analyze_headers.
pub fn analyze_headers(macho: &MachoFile<'_>, plan: &CReconstructionPlan<'_>) -> Result<CAnalysis> {
    let mut builder = CAnalysisBuilder::default();
    if let Some(sections) = load_dwarf(macho)? {
        let endian = runtime_endian(macho.endian());
        let borrowed = sections.borrow(|section| EndianSlice::new(section, endian));
        builder.ingest_dwarf(&borrowed)?;
    }

    let symtab = macho.ext::<SymbolTable<'_>>().ok();
    builder.reconcile_symbols(macho, symtab.as_ref());

    let mut analysis = builder.finish();
    if let Some(correlator) = plan.correlator {
        correlator.correlate(&mut analysis)?;
    }
    analysis.header_units = build_header_units(&analysis);
    Ok(analysis)
}

include!("model.rs");
include!("correlate.rs");
include!("dwarf.rs");
include!("render.rs");
include!("validate.rs");
