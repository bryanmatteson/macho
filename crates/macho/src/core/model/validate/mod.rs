/// The diagnostics module.
pub mod diagnostics;

pub use diagnostics::{Diagnostic, DiagnosticCode, Severity, Span};

use crate::core::format::constants::VmProtection;
use crate::core::model::header::Bitness;
use crate::core::model::load_command::LoadCommand;
use crate::core::model::macho_file::MachoFile;
use crate::core::model::names::SegmentName;

const HEADER_COMMAND_COUNT_CODE: &str = "parse.validation.header_command_count";
const HEADER_COMMAND_SIZE_CODE: &str = "parse.validation.header_command_size";
const SEGMENT_BOUNDS_CODE: &str = "parse.validation.segment_bounds";
const SECTION_BOUNDS_CODE: &str = "parse.validation.section_bounds";
const DUPLICATE_SEGMENT_CODE: &str = "parse.validation.duplicate_segment";
const SEGMENT_OVERLAP_CODE: &str = "parse.validation.segment_overlap";
const PAGEZERO_FILE_SIZE_CODE: &str = "parse.validation.pagezero_file_size";
const PROTECTION_MISMATCH_CODE: &str = "parse.validation.protection_mismatch";
const SYMBOL_TABLE_BOUNDS_CODE: &str = "parse.validation.symbol_table_bounds";
const STRING_TABLE_BOUNDS_CODE: &str = "parse.validation.string_table_bounds";

/// Performs validate.
pub fn validate(macho: &MachoFile<'_>) -> Vec<Diagnostic> {
    let mut diags = Vec::new();

    check_header_consistency(macho, &mut diags);
    check_segment_bounds(macho, &mut diags);
    check_segment_vm_overlap(macho, &mut diags);
    check_pagezero(macho, &mut diags);
    check_symtab_bounds(macho, &mut diags);
    check_protections(macho, &mut diags);

    diags
}

fn check_header_consistency(macho: &MachoFile<'_>, diags: &mut Vec<Diagnostic>) {
    let expected = macho.header().ncmds as usize;
    let actual = macho.load_commands().len();
    if expected != actual {
        diags.push(Diagnostic::error(
            HEADER_COMMAND_COUNT_CODE,
            format!("header ncmds={expected} but parsed {actual} load commands"),
        ));
    }

    let expected_size = macho.header().sizeofcmds;
    let actual_size: u32 = macho.load_commands().iter().map(|lc| lc.raw_size).sum();
    if expected_size != actual_size {
        diags.push(Diagnostic::error(
            HEADER_COMMAND_SIZE_CODE,
            format!(
                "header sizeofcmds={expected_size:#x} but load commands sum to {actual_size:#x}"
            ),
        ));
    }
}

fn check_segment_bounds(macho: &MachoFile<'_>, diags: &mut Vec<Diagnostic>) {
    let file_size = macho.file_size() as u64;

    for seg in macho.segments() {
        let seg_end = seg.file_offset.0.saturating_add(seg.file_size);
        if seg.file_size > 0 && seg_end > file_size {
            diags.push(Diagnostic::error(
                SEGMENT_BOUNDS_CODE,
                format!(
                    "segment {} file range {:#x}..{:#x} extends beyond file size {:#x}",
                    seg.name, seg.file_offset.0, seg_end, file_size
                ),
            ));
        }

        for sect in &seg.sections {
            if sect.section_type.is_zerofill() || sect.size == 0 {
                continue;
            }
            let sect_end = sect.offset.0.saturating_add(sect.size);
            if sect.offset.0 < seg.file_offset.0 || sect_end > seg_end {
                diags.push(Diagnostic::warning(
                    SECTION_BOUNDS_CODE,
                    format!(
                        "section {},{} file range {:#x}..{:#x} outside segment {} range {:#x}..{:#x}",
                        sect.segment_name, sect.section_name,
                        sect.offset.0, sect_end,
                        seg.name, seg.file_offset.0, seg_end
                    ),
                ));
            }
        }
    }

    // Duplicate segment names
    let mut seen_names = std::collections::HashSet::new();
    for seg in macho.segments() {
        let name_str = seg.name.as_str_lossy().into_owned();
        if !name_str.is_empty() && !seen_names.insert(name_str.clone()) {
            diags.push(Diagnostic::warning(
                DUPLICATE_SEGMENT_CODE,
                format!("duplicate segment name: {name_str}"),
            ));
        }
    }
}

fn check_segment_vm_overlap(macho: &MachoFile<'_>, diags: &mut Vec<Diagnostic>) {
    let segments = macho.segments();
    for (i, a) in segments.iter().enumerate() {
        if a.vm_size == 0 {
            continue;
        }
        let a_end = a.vm_addr.0.saturating_add(a.vm_size);
        for b in &segments[i + 1..] {
            if b.vm_size == 0 {
                continue;
            }
            let b_end = b.vm_addr.0.saturating_add(b.vm_size);
            let overlaps = a.vm_addr.0 < b_end && b.vm_addr.0 < a_end;
            if overlaps {
                diags.push(Diagnostic::error(
                    SEGMENT_OVERLAP_CODE,
                    format!(
                        "segments {} and {} have overlapping VM ranges: \
                         {:#x}..{:#x} vs {:#x}..{:#x}",
                        a.name, b.name, a.vm_addr.0, a_end, b.vm_addr.0, b_end
                    ),
                ));
            }
        }
    }
}

fn check_pagezero(macho: &MachoFile<'_>, diags: &mut Vec<Diagnostic>) {
    for seg in macho.segments() {
        if seg.name == SegmentName::PAGEZERO && seg.file_size != 0 {
            diags.push(Diagnostic::error(
                PAGEZERO_FILE_SIZE_CODE,
                format!(
                    "__PAGEZERO has non-zero file_size {:#x} (must be 0)",
                    seg.file_size
                ),
            ));
        }
    }
}

fn check_protections(macho: &MachoFile<'_>, diags: &mut Vec<Diagnostic>) {
    for seg in macho.segments() {
        // initprot bits should be a subset of maxprot bits
        let init = seg.init_prot;
        let max = seg.max_prot;
        if init.bits() & !max.bits() != 0 {
            diags.push(Diagnostic::warning(
                PROTECTION_MISMATCH_CODE,
                format!(
                    "segment {} has initprot ({}) with bits not in maxprot ({})",
                    seg.name,
                    format_prot(init),
                    format_prot(max),
                ),
            ));
        }
    }
}

fn check_symtab_bounds(macho: &MachoFile<'_>, diags: &mut Vec<Diagnostic>) {
    let file_size = macho.file_size() as u64;
    let nlist_size: u64 = match macho.bitness() {
        Bitness::Bits64 => 16,
        Bitness::Bits32 => 12,
    };

    for lc in macho.load_commands() {
        if let LoadCommand::Symtab(ref st) = lc.kind {
            // Check symbol table bounds
            if let Some(sym_end) = (st.nsyms as u64)
                .checked_mul(nlist_size)
                .and_then(|sz| (st.sym_offset as u64).checked_add(sz))
            {
                if sym_end > file_size {
                    diags.push(Diagnostic::error(
                        SYMBOL_TABLE_BOUNDS_CODE,
                        format!(
                            "LC_SYMTAB symbol table {:#x}..{:#x} extends beyond file size {:#x}",
                            st.sym_offset, sym_end, file_size
                        ),
                    ));
                }
            } else {
                diags.push(Diagnostic::error(
                    SYMBOL_TABLE_BOUNDS_CODE,
                    "LC_SYMTAB symbol table offset+size overflows".to_string(),
                ));
            }

            // Check string table bounds
            if let Some(str_end) = (st.str_offset as u64).checked_add(st.str_size as u64) {
                if str_end > file_size {
                    diags.push(Diagnostic::error(
                        STRING_TABLE_BOUNDS_CODE,
                        format!(
                            "LC_SYMTAB string table {:#x}..{:#x} extends beyond file size {:#x}",
                            st.str_offset, str_end, file_size
                        ),
                    ));
                }
            } else {
                diags.push(Diagnostic::error(
                    STRING_TABLE_BOUNDS_CODE,
                    "LC_SYMTAB string table offset+size overflows".to_string(),
                ));
            }
        }
    }
}

fn format_prot(prot: VmProtection) -> String {
    prot.rwx_string()
}
