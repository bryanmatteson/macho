use anyhow::{Context, Result};
use macho::constants::VmProtection;
use macho::model::container::MachContainer;
use macho::model::load_command::format_uuid;
use macho::model::mach::MachFile;
use macho::validate;
use std::path::PathBuf;

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
        MachContainer::Thin(mach) => {
            if let Some(ref filter) = args.arch {
                let arch_name = arch_name_for_mach(mach);
                if !arch_name.eq_ignore_ascii_case(filter) {
                    println!("Thin Mach-O binary ({arch_name}): no match for --arch {filter}");
                    std::process::exit(1);
                }
            }
            println!("Thin Mach-O binary ({} bytes)", mmap.len());
            println!();
            print_mach(mach, args.validate);
        }
        MachContainer::Fat(fat) => {
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
                print_mach(&arch.mach, args.validate);
                println!();
            }

            if !matched {
                if let Some(ref filter) = args.arch {
                    let available: Vec<String> =
                        fat.arches().iter().map(|a| a.spec.name()).collect();
                    eprintln!(
                        "no architecture matching '{filter}' found (available: {})",
                        available.join(", ")
                    );
                    std::process::exit(1);
                }
            }
        }
    }

    Ok(())
}

fn arch_name_for_mach(mach: &MachFile<'_>) -> String {
    use macho::model::fat::ArchSpec;
    let spec = ArchSpec {
        cpu_type: mach.header().cpu_type,
        cpu_subtype: mach.header().cpu_subtype,
    };
    spec.name()
}

fn print_mach(mach: &MachFile<'_>, do_validate: bool) {
    let h = mach.header();

    println!("Header:");
    println!(
        "  CPU:       {} (subtype: {})",
        h.cpu_type,
        h.cpu_subtype.name(h.cpu_type)
    );
    println!("  File type: {}", h.file_type.name());
    println!("  Bitness:   {}", mach.bitness());
    println!("  Endian:    {:?}", mach.endian());
    println!("  Commands:  {}", h.ncmds);
    println!("  Cmd size:  {:#x}", h.sizeofcmds);
    println!("  Flags:     {:?}", h.flags);

    if let Some(uuid) = mach.uuid() {
        println!("  UUID:      {}", format_uuid(uuid));
    }

    println!();
    println!("Segments:");
    for seg in mach.segments() {
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
    for (i, lc) in mach.load_commands().iter().enumerate() {
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
    if let Some(st) = mach
        .find_load_command(|lc| lc.as_symtab().is_some())
        .and_then(|lc| lc.kind.as_symtab())
    {
        println!();
        println!(
            "Symbol Table: {} symbols, string table {} bytes",
            st.nsyms, st.str_size
        );
    }

    let reloc_sections: usize = mach.all_sections().filter(|s| s.nreloc > 0).count();
    let reloc_total: u32 = mach.all_sections().map(|s| s.nreloc).sum();
    if reloc_total > 0 {
        println!("Relocations: {reloc_total} entries across {reloc_sections} sections");
    }

    // Dyld summary
    if let Ok(fixups) = macho::dyld::parse_chained_fixups(mach) {
        println!(
            "Chained Fixups: {} imports, {} fixups",
            fixups.imports.len(),
            fixups.fixups.len()
        );
    }
    if let Ok(exports) = macho::dyld::parse_exports(mach) {
        if !exports.is_empty() {
            println!("Exports Trie: {} exports", exports.len());
        }
    }

    if do_validate {
        let diags = validate::validate(mach);
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
    let r = if prot.contains(VmProtection::READ) {
        'r'
    } else {
        '-'
    };
    let w = if prot.contains(VmProtection::WRITE) {
        'w'
    } else {
        '-'
    };
    let x = if prot.contains(VmProtection::EXECUTE) {
        'x'
    } else {
        '-'
    };
    format!("{r}{w}{x}")
}

fn format_section_extras(sect: &macho::model::section::Section) -> String {
    use macho::model::section::SectionType;
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
