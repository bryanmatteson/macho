use crate::format::constants::VmProtection;
use crate::model::container::MachoContainer;
use crate::model::load_command::format_uuid;
use crate::model::macho_file::MachoFile;
use crate::model::validate;
use anyhow::{Context, Result};
use std::io::Write;
use std::path::PathBuf;

use crate::commands::args::{ArchitectureArgs, InputArgs};
use crate::commands::subcommands::common::{arch_name_for_mach, map_input};
use crate::commands::{CliWarning, input_message};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// The InspectScope type.
#[non_exhaustive]
pub enum InspectScope {
    /// The Full variant.
    Full,
    /// The Header variant.
    Header,
    /// The LoadCommands variant.
    LoadCommands,
    /// The Segments variant.
    Segments,
    /// The Sections variant.
    Sections,
}

#[derive(Debug)]
/// The InspectArgs type.
pub struct InspectArgs {
    input: InputArgs,
    selection: ArchitectureArgs,
    validate: bool,
}

/// Performs run.
pub fn run(args: InspectArgs, out: &mut dyn Write) -> Result<()> {
    run_scoped(args, InspectScope::Full, out, &mut Vec::new())
}

/// Performs run_scoped.
pub(crate) fn run_scoped(
    args: InspectArgs,
    scope: InspectScope,
    out: &mut dyn Write,
    warnings: &mut Vec<CliWarning>,
) -> Result<()> {
    let mmap = map_input(&args.input.path)?;

    let options = macho::core::ParseOptions {
        mode: macho::core::ParseMode::Forensic,
        limits: macho::core::ParseLimits::default(),
    };
    let outcome = macho::parse_with_options(&mmap, &options)
        .with_context(|| format!("failed to parse {}", args.input.path.display()))?;
    warnings.extend(outcome.diagnostics.iter().map(|diagnostic| CliWarning {
        code: diagnostic.code.0.to_owned(),
        message: diagnostic.message.clone(),
    }));
    let container = outcome.container;

    match &container {
        MachoContainer::Thin(macho) => {
            if let Some(ref filter) = args.selection.arch {
                let arch_name = arch_name_for_mach(macho);
                if !arch_name.eq_ignore_ascii_case(filter) {
                    return Err(input_message(format!(
                        "no architecture matching '{filter}' found (available: {arch_name})"
                    )));
                }
            }
            if scope == InspectScope::Full {
                let _ = writeln!(out, "Thin Mach-O binary ({} bytes)", mmap.len());
                let _ = writeln!(out,);
            }
            print_mach(macho, args.validate, scope, out);
        }
        MachoContainer::Fat(fat) => {
            if scope == InspectScope::Full {
                let _ = writeln!(
                    out,
                    "Fat binary ({} architecture{}, {} bytes)",
                    fat.arches().len(),
                    if fat.arches().len() == 1 { "" } else { "s" },
                    mmap.len(),
                );
                let _ = writeln!(out,);
            }

            let mut matched = false;
            for (i, arch) in fat.arches().iter().enumerate() {
                let arch_name = arch.spec().name();

                if let Some(ref filter) = args.selection.arch {
                    if !arch_name.eq_ignore_ascii_case(filter) {
                        continue;
                    }
                }

                matched = true;
                if scope == InspectScope::Full {
                    let _ = writeln!(
                        out,
                        "=== Architecture {i}: {} (offset={:#x}, size={:#x}, align=2^{}) ===",
                        arch_name,
                        arch.fat_offset().0,
                        arch.size(),
                        arch.align()
                    );
                    let _ = writeln!(out,);
                } else {
                    let _ = writeln!(out, "=== {arch_name} ===");
                }
                print_mach(arch.macho(), args.validate, scope, out);
                let _ = writeln!(out,);
            }

            if !matched {
                if let Some(ref filter) = args.selection.arch {
                    let available: Vec<String> =
                        fat.arches().iter().map(|a| a.spec().name()).collect();
                    return Err(input_message(format!(
                        "no architecture matching '{filter}' found (available: {})",
                        available.join(", ")
                    )));
                }
            }
        }
    }

    Ok(())
}

impl InspectArgs {
    pub(crate) fn new(path: PathBuf, arch: Option<String>, validate: bool) -> Self {
        Self {
            input: InputArgs { path },
            selection: ArchitectureArgs { arch },
            validate,
        }
    }
}

fn print_mach(macho: &MachoFile<'_>, do_validate: bool, scope: InspectScope, out: &mut dyn Write) {
    match scope {
        InspectScope::Full => {
            print_header(macho, out);
            let _ = writeln!(out,);
            print_segments(macho, true, out);
            let _ = writeln!(out,);
            print_load_commands(macho, out);
            print_summary(macho, out);
            if do_validate {
                print_validation(macho, out);
            }
        }
        InspectScope::Header => {
            print_header(macho, out);
            if do_validate {
                print_validation(macho, out);
            }
        }
        InspectScope::LoadCommands => print_load_commands(macho, out),
        InspectScope::Segments => print_segments(macho, false, out),
        InspectScope::Sections => print_sections(macho, out),
    }
}

fn print_header(macho: &MachoFile<'_>, out: &mut dyn Write) {
    let h = macho.header();

    let _ = writeln!(out, "Header:");
    let _ = writeln!(
        out,
        "  CPU:       {} (subtype: {})",
        h.cpu_type(),
        h.cpu_subtype().name(h.cpu_type())
    );
    let _ = writeln!(out, "  File type: {}", h.file_type().name());
    let _ = writeln!(out, "  Bitness:   {}", macho.bitness());
    let _ = writeln!(out, "  Endian:    {:?}", macho.endian());
    let _ = writeln!(out, "  Commands:  {}", h.load_command_count());
    let _ = writeln!(out, "  Cmd size:  {:#x}", h.load_commands_size());
    let _ = writeln!(out, "  Flags:     {:?}", h.flags());

    if let Some(uuid) = macho.uuid() {
        let _ = writeln!(out, "  UUID:      {}", format_uuid(uuid));
    }
}

fn print_segments(macho: &MachoFile<'_>, include_sections: bool, out: &mut dyn Write) {
    let _ = writeln!(out, "Segments:");
    for seg in macho.segments() {
        let flags_str = if seg.flags().is_empty() {
            String::new()
        } else {
            format!("  flags={:?}", seg.flags())
        };
        let _ = writeln!(
            out,
            "  {:<20} VM {:#018x} ({:#x})  File {:#010x} ({:#x})  maxprot={}  initprot={}{}",
            seg.name(),
            seg.vm_addr().0,
            seg.vm_size(),
            seg.file_offset().0,
            seg.file_size(),
            format_prot(seg.max_prot()),
            format_prot(seg.init_prot()),
            flags_str,
        );

        if include_sections {
            for sect in seg.sections() {
                let extras = format_section_extras(sect);
                let _ = writeln!(
                    out,
                    "    {:<20} {:#018x} ({:#x})  off={:#010x}  align=2^{}  {}{}",
                    sect.section_name(),
                    sect.addr().0,
                    sect.size(),
                    sect.offset().0,
                    sect.align(),
                    sect.section_type().name(),
                    extras,
                );
            }
        }
    }
}

fn print_sections(macho: &MachoFile<'_>, out: &mut dyn Write) {
    let _ = writeln!(out, "Sections:");
    for seg in macho.segments() {
        for sect in seg.sections() {
            let extras = format_section_extras(sect);
            let _ = writeln!(
                out,
                "  {},{}  {:#018x} ({:#x})  off={:#010x}  align=2^{}  {}{}",
                seg.name(),
                sect.section_name(),
                sect.addr().0,
                sect.size(),
                sect.offset().0,
                sect.align(),
                sect.section_type().name(),
                extras,
            );
        }
    }
}

fn print_load_commands(macho: &MachoFile<'_>, out: &mut dyn Write) {
    let _ = writeln!(out, "Load Commands:");
    for (i, lc) in macho.load_commands().iter().enumerate() {
        let summary = lc.kind().summary();
        if summary.is_empty() {
            let _ = writeln!(
                out,
                "  [{:3}] {:<32} off={:#010x}  size={:#x}",
                i,
                lc.kind().name(),
                lc.file_offset().0,
                lc.raw_size(),
            );
        } else {
            let _ = writeln!(
                out,
                "  [{:3}] {:<32} {}  off={:#010x}  size={:#x}",
                i,
                lc.kind().name(),
                summary,
                lc.file_offset().0,
                lc.raw_size(),
            );
        }
    }
}

fn print_summary(macho: &MachoFile<'_>, out: &mut dyn Write) {
    if let Some(st) = macho
        .find_load_command(|lc| lc.as_symtab().is_some())
        .and_then(|lc| lc.kind().as_symtab())
    {
        let _ = writeln!(out,);
        let _ = writeln!(
            out,
            "Symbol Table: {} symbols, string table {} bytes",
            st.nsyms, st.str_size
        );
    }

    let reloc_sections: usize = macho
        .all_sections()
        .filter(|s| s.relocation_count() > 0)
        .count();
    let reloc_total: u32 = macho.all_sections().map(|s| s.relocation_count()).sum();
    if reloc_total > 0 {
        let _ = writeln!(
            out,
            "Relocations: {reloc_total} entries across {reloc_sections} sections"
        );
    }

    if let Ok(fixups) = crate::metadata::dyld::parse_chained_fixups(macho) {
        let _ = writeln!(
            out,
            "Chained Fixups: {} imports, {} fixups",
            fixups.imports.len(),
            fixups.fixups.len()
        );
    }
    if let Ok(exports) = crate::metadata::dyld::parse_exports(macho) {
        if !exports.is_empty() {
            let _ = writeln!(out, "Exports Trie: {} exports", exports.len());
        }
    }
}

fn print_validation(macho: &MachoFile<'_>, out: &mut dyn Write) {
    let diags = validate::validate(macho);
    if diags.is_empty() {
        let _ = writeln!(out,);
        let _ = writeln!(out, "Validation: OK (no issues)");
    } else {
        let _ = writeln!(out,);
        let _ = writeln!(
            out,
            "Validation ({} issue{}):",
            diags.len(),
            if diags.len() == 1 { "" } else { "s" }
        );
        for d in &diags {
            let _ = writeln!(out, "  [{:?}] {} - {}", d.severity, d.code.0, d.message);
        }
    }
}

fn format_prot(prot: VmProtection) -> String {
    prot.rwx_string()
}

fn format_section_extras(sect: &crate::model::section::Section) -> String {
    use crate::model::section::SectionType;
    match sect.section_type() {
        SectionType::SymbolStubs if sect.reserved2() > 0 => {
            format!("  stub_size={}", sect.reserved2())
        }
        SectionType::NonLazySymbolPointers | SectionType::LazySymbolPointers => {
            format!("  indirect_idx={}", sect.reserved1())
        }
        _ => String::new(),
    }
}
