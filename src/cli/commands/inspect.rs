use crate::format::constants::VmProtection;
use crate::model::container::MachoContainer;
use crate::model::load_command::format_uuid;
use crate::model::macho_file::MachoFile;
use crate::model::validate;
use anyhow::{Context, Result, bail};
use std::path::PathBuf;

use crate::cli::commands::common::arch_name_for_mach;

#[derive(clap::Args)]
pub struct InspectArgs {
    /// Path to Mach-O binary
    path: PathBuf,

    /// Filter to a specific architecture (e.g., arm64, x86_64, arm64e)
    #[arg(long)]
    arch: Option<String>,

    /// Show validation diagnostics
    #[arg(long)]
    validate: bool,
}

pub fn run(args: InspectArgs) -> Result<()> {
    let file = std::fs::File::open(&args.path)
        .with_context(|| format!("failed to open {}", args.path.display()))?;
    let mmap = unsafe { memmap2::Mmap::map(&file)? };

    let container =
        macho::parse(&mmap).with_context(|| format!("failed to parse {}", args.path.display()))?;

    match &container {
        MachoContainer::Thin(macho) => {
            if let Some(ref filter) = args.arch {
                let arch_name = arch_name_for_mach(macho);
                if !arch_name.eq_ignore_ascii_case(filter) {
                    bail!("no architecture matching '{filter}' found (available: {arch_name})");
                }
            }
            println!("Thin Mach-O binary ({} bytes)", mmap.len());
            println!();
            print_mach(macho, args.validate);
        }
        MachoContainer::Fat(fat) => {
            println!(
                "Fat binary ({} architecture{}, {} bytes)",
                fat.arches().len(),
                if fat.arches().len() == 1 { "" } else { "s" },
                mmap.len(),
            );
            println!();

            let mut matched = false;
            for (i, arch) in fat.arches().iter().enumerate() {
                let arch_name = arch.spec.name();

                if let Some(ref filter) = args.arch {
                    if !arch_name.eq_ignore_ascii_case(filter) {
                        continue;
                    }
                }

                matched = true;
                println!(
                    "=== Architecture {i}: {} (offset={:#x}, size={:#x}, align=2^{}) ===",
                    arch_name, arch.fat_offset.0, arch.size, arch.align
                );
                println!();
                print_mach(&arch.macho, args.validate);
                println!();
            }

            if !matched {
                if let Some(ref filter) = args.arch {
                    let available: Vec<String> =
                        fat.arches().iter().map(|a| a.spec.name()).collect();
                    bail!(
                        "no architecture matching '{filter}' found (available: {})",
                        available.join(", ")
                    );
                }
            }
        }
    }

    Ok(())
}

fn print_mach(macho: &MachoFile<'_>, do_validate: bool) {
    let h = macho.header();

    println!("Header:");
    println!(
        "  CPU:       {} (subtype: {})",
        h.cpu_type,
        h.cpu_subtype.name(h.cpu_type)
    );
    println!("  File type: {}", h.file_type.name());
    println!("  Bitness:   {}", macho.bitness());
    println!("  Endian:    {:?}", macho.endian());
    println!("  Commands:  {}", h.ncmds);
    println!("  Cmd size:  {:#x}", h.sizeofcmds);
    println!("  Flags:     {:?}", h.flags);

    if let Some(uuid) = macho.uuid() {
        println!("  UUID:      {}", format_uuid(uuid));
    }

    println!();
    println!("Segments:");
    for seg in macho.segments() {
        let flags_str = if seg.flags.is_empty() {
            String::new()
        } else {
            format!("  flags={:?}", seg.flags)
        };
        println!(
            "  {:<20} VM {:#018x} ({:#x})  File {:#010x} ({:#x})  maxprot={}  initprot={}{}",
            seg.name,
            seg.vm_addr.0,
            seg.vm_size,
            seg.file_offset.0,
            seg.file_size,
            format_prot(seg.max_prot),
            format_prot(seg.init_prot),
            flags_str,
        );

        for sect in &seg.sections {
            let extras = format_section_extras(sect);
            println!(
                "    {:<20} {:#018x} ({:#x})  off={:#010x}  align=2^{}  {}{}",
                sect.section_name,
                sect.addr.0,
                sect.size,
                sect.offset.0,
                sect.align,
                sect.section_type.name(),
                extras,
            );
        }
    }

    println!();
    println!("Load Commands:");
    for (i, lc) in macho.load_commands().iter().enumerate() {
        let summary = lc.kind.summary();
        if summary.is_empty() {
            println!(
                "  [{:3}] {:<32} off={:#010x}  size={:#x}",
                i,
                lc.kind.name(),
                lc.file_offset.0,
                lc.raw_size,
            );
        } else {
            println!(
                "  [{:3}] {:<32} {}  off={:#010x}  size={:#x}",
                i,
                lc.kind.name(),
                summary,
                lc.file_offset.0,
                lc.raw_size,
            );
        }
    }

    // Summary: symbol table and relocations
    if let Some(st) = macho
        .find_load_command(|lc| lc.as_symtab().is_some())
        .and_then(|lc| lc.kind.as_symtab())
    {
        println!();
        println!(
            "Symbol Table: {} symbols, string table {} bytes",
            st.nsyms, st.str_size
        );
    }

    let reloc_sections: usize = macho.all_sections().filter(|s| s.nreloc > 0).count();
    let reloc_total: u32 = macho.all_sections().map(|s| s.nreloc).sum();
    if reloc_total > 0 {
        println!("Relocations: {reloc_total} entries across {reloc_sections} sections");
    }

    // Dyld summary
    if let Ok(fixups) = crate::metadata::dyld::parse_chained_fixups(macho) {
        println!(
            "Chained Fixups: {} imports, {} fixups",
            fixups.imports.len(),
            fixups.fixups.len()
        );
    }
    if let Ok(exports) = crate::metadata::dyld::parse_exports(macho) {
        if !exports.is_empty() {
            println!("Exports Trie: {} exports", exports.len());
        }
    }

    if do_validate {
        let diags = validate::validate(macho);
        if diags.is_empty() {
            println!();
            println!("Validation: OK (no issues)");
        } else {
            println!();
            println!(
                "Validation ({} issue{}):",
                diags.len(),
                if diags.len() == 1 { "" } else { "s" }
            );
            for d in &diags {
                println!("  [{:?}] {} - {}", d.severity, d.code.0, d.message);
            }
        }
    }
}

fn format_prot(prot: VmProtection) -> String {
    prot.rwx_string()
}

fn format_section_extras(sect: &crate::model::section::Section) -> String {
    use crate::model::section::SectionType;
    match sect.section_type {
        SectionType::SymbolStubs if sect.reserved2 > 0 => {
            format!("  stub_size={}", sect.reserved2)
        }
        SectionType::NonLazySymbolPointers | SectionType::LazySymbolPointers => {
            format!("  indirect_idx={}", sect.reserved1)
        }
        _ => String::new(),
    }
}
