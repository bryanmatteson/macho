use crate::format::constants::VmProtection;
use crate::model::container::MachoContainer;
use crate::model::load_command::format_uuid;
use crate::model::macho_file::MachoFile;
use crate::model::validate;
use anyhow::{Context, Result};
use std::io::Write;
use std::path::PathBuf;

use crate::commands::args::{ArchitectureArgs, InputArgs};
use crate::commands::output::Style;
use crate::commands::output::layout::{self, Cell};
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
    run_scoped(
        args,
        InspectScope::Full,
        Style::new(false),
        out,
        &mut Vec::new(),
    )
}

/// Performs run_scoped.
pub(crate) fn run_scoped(
    args: InspectArgs,
    scope: InspectScope,
    style: Style,
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
                let title = format!("Thin Mach-O binary ({} bytes)", mmap.len());
                let _ = writeln!(out, "{}", style.title(&title));
                let _ = writeln!(out,);
            }
            print_mach(macho, args.validate, scope, style, out);
        }
        MachoContainer::Fat(fat) => {
            if scope == InspectScope::Full {
                let title = format!(
                    "Fat binary ({} architecture{}, {} bytes)",
                    fat.arches().len(),
                    if fat.arches().len() == 1 { "" } else { "s" },
                    mmap.len(),
                );
                let _ = writeln!(out, "{}", style.title(&title));
                let _ = writeln!(out,);
            }

            let mut matched = false;
            for (i, arch) in fat.arches().iter().enumerate() {
                let arch_name = arch.spec().name();

                if let Some(ref filter) = args.selection.arch
                    && !arch_name.eq_ignore_ascii_case(filter)
                {
                    continue;
                }

                matched = true;
                if scope == InspectScope::Full {
                    let title = format!(
                        "=== Architecture {i}: {} (offset={:#x}, size={:#x}, align=2^{}) ===",
                        arch_name,
                        arch.fat_offset().0,
                        arch.size(),
                        arch.align()
                    );
                    let _ = writeln!(out, "{}", style.title(&title));
                    let _ = writeln!(out,);
                } else {
                    let _ = writeln!(out, "{}", style.title(&format!("=== {arch_name} ===")));
                }
                print_mach(arch.macho(), args.validate, scope, style, out);
                let _ = writeln!(out,);
            }

            if !matched && let Some(ref filter) = args.selection.arch {
                let available: Vec<String> = fat.arches().iter().map(|a| a.spec().name()).collect();
                return Err(input_message(format!(
                    "no architecture matching '{filter}' found (available: {})",
                    available.join(", ")
                )));
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

fn print_mach(
    macho: &MachoFile<'_>,
    do_validate: bool,
    scope: InspectScope,
    style: Style,
    out: &mut dyn Write,
) {
    match scope {
        InspectScope::Full => {
            print_header(macho, style, out);
            let _ = writeln!(out,);
            print_segments(macho, true, style, out);
            let _ = writeln!(out,);
            print_load_commands(macho, style, out);
            print_summary(macho, style, out);
            if do_validate {
                print_validation(macho, style, out);
            }
        }
        InspectScope::Header => {
            print_header(macho, style, out);
            if do_validate {
                print_validation(macho, style, out);
            }
        }
        InspectScope::LoadCommands => print_load_commands(macho, style, out),
        InspectScope::Segments => print_segments(macho, false, style, out),
        InspectScope::Sections => print_sections(macho, style, out),
    }
}

fn print_header(macho: &MachoFile<'_>, style: Style, out: &mut dyn Write) {
    let h = macho.header();

    let _ = writeln!(out, "{}", style.heading("Header:"));
    let mut rows = vec![
        vec![
            style.muted_cell("  CPU:"),
            layout::join_cells([
                style.enum_value_cell(&h.cpu_type().to_string()),
                layout::plain_cell(" ("),
                style.muted_cell("subtype:"),
                layout::plain_cell(" "),
                style.value_cell(h.cpu_subtype().name(h.cpu_type())),
                layout::plain_cell(")"),
            ]),
        ],
        vec![
            style.muted_cell("  File type:"),
            style.enum_value_cell(h.file_type().name()),
        ],
        vec![
            style.muted_cell("  Bitness:"),
            style.value_cell(&macho.bitness().to_string()),
        ],
        vec![
            style.muted_cell("  Endian:"),
            style.enum_value_cell(&format!("{:?}", macho.endian())),
        ],
        vec![
            style.muted_cell("  Commands:"),
            style.value_cell(&h.load_command_count().to_string()),
        ],
        vec![
            style.muted_cell("  Cmd size:"),
            style.value_cell(&format!("{:#x}", h.load_commands_size())),
        ],
        vec![
            style.muted_cell("  Flags:"),
            style.enum_value_cell(&format!("{:?}", h.flags())),
        ],
    ];

    if let Some(uuid) = macho.uuid() {
        rows.push(vec![
            style.muted_cell("  UUID:"),
            style.address_cell(&format_uuid(uuid)),
        ]);
    }
    for line in layout::align(&rows, style) {
        let _ = writeln!(out, "{line}");
    }
}

fn print_segments(
    macho: &MachoFile<'_>,
    include_sections: bool,
    style: Style,
    out: &mut dyn Write,
) {
    let _ = writeln!(out, "{}", style.heading("Segments:"));
    let segment_rows = macho
        .segments()
        .iter()
        .map(|segment| format_segment_row(segment, style))
        .collect::<Vec<_>>();
    let segment_lines = layout::align(&segment_rows, style);
    let section_rows = macho
        .segments()
        .iter()
        .flat_map(|segment| {
            segment
                .sections()
                .iter()
                .map(|section| format_nested_section_row(section, style))
        })
        .collect::<Vec<_>>();
    let section_lines = layout::align(&section_rows, style);
    let mut section_index = 0;

    for (segment, line) in macho.segments().iter().zip(segment_lines) {
        let _ = writeln!(out, "{line}");
        if include_sections {
            let end = section_index + segment.sections().len();
            for section_line in &section_lines[section_index..end] {
                let _ = writeln!(out, "{section_line}");
            }
            section_index = end;
        }
    }
}

fn print_sections(macho: &MachoFile<'_>, style: Style, out: &mut dyn Write) {
    let _ = writeln!(out, "{}", style.heading("Sections:"));
    let rows = macho
        .segments()
        .iter()
        .flat_map(|segment| {
            segment
                .sections()
                .iter()
                .map(|section| format_section_row(segment, section, style))
        })
        .collect::<Vec<_>>();
    for line in layout::align(&rows, style) {
        let _ = writeln!(out, "{line}");
    }
}

fn print_load_commands(macho: &MachoFile<'_>, style: Style, out: &mut dyn Write) {
    let _ = writeln!(out, "{}", style.heading("Load Commands:"));
    let index_width = macho
        .load_commands()
        .len()
        .saturating_sub(1)
        .to_string()
        .len()
        .max(3);
    let rows = macho
        .load_commands()
        .iter()
        .enumerate()
        .map(|(index, command)| {
            vec![
                style.muted_cell(&format!("  {index:>index_width$}")),
                style.enum_value_cell(command.kind().name()),
                style.property_cell("off", &format!("{:#010x}", command.file_offset().0)),
                style.property_cell("size", &format!("{:#x}", command.raw_size())),
                style_summary(&command.kind().summary(), style),
            ]
        })
        .collect::<Vec<_>>();
    for line in layout::align(&rows, style) {
        let _ = writeln!(out, "{line}");
    }
}

fn format_segment_row(segment: &crate::model::segment::Segment, style: Style) -> Vec<Cell> {
    vec![
        layout::join_cells([
            layout::plain_cell("  "),
            style.segment_name_cell(segment.name().as_str_lossy().as_ref()),
        ]),
        style.muted_cell("VM"),
        style.address_cell(&format!("{:#018x}", segment.vm_addr().0)),
        parenthesized(style.muted_cell(&format!("{:#x}", segment.vm_size()))),
        style.muted_cell("File"),
        style.address_cell(&format!("{:#010x}", segment.file_offset().0)),
        parenthesized(style.muted_cell(&format!("{:#x}", segment.file_size()))),
        style.property_cell("maxprot", &format_prot(segment.max_prot())),
        style.property_cell("initprot", &format_prot(segment.init_prot())),
        if segment.flags().is_empty() {
            layout::plain_cell("")
        } else {
            style.enum_property_cell("flags", &format!("{:?}", segment.flags()))
        },
    ]
}

/// Wrap a cell in parentheses without letting them take a column of their own.
fn parenthesized(inner: Cell) -> Cell {
    layout::join_cells([layout::plain_cell("("), inner, layout::plain_cell(")")])
}

fn format_nested_section_row(section: &crate::model::section::Section, style: Style) -> Vec<Cell> {
    format_section_cells(
        layout::join_cells([
            layout::plain_cell("    "),
            style.section_name_cell(section.section_name().as_str_lossy().as_ref()),
        ]),
        section,
        style,
    )
}

fn format_section_row(
    segment: &crate::model::segment::Segment,
    section: &crate::model::section::Section,
    style: Style,
) -> Vec<Cell> {
    format_section_cells(
        layout::join_cells([
            layout::plain_cell("  "),
            style.segment_name_cell(segment.name().as_str_lossy().as_ref()),
            layout::plain_cell(","),
            style.section_name_cell(section.section_name().as_str_lossy().as_ref()),
        ]),
        section,
        style,
    )
}

fn format_section_cells(
    name: Cell,
    section: &crate::model::section::Section,
    style: Style,
) -> Vec<Cell> {
    vec![
        name,
        style.address_cell(&format!("{:#018x}", section.addr().0)),
        parenthesized(style.muted_cell(&format!("{:#x}", section.size()))),
        style.property_cell("off", &format!("{:#010x}", section.offset().0)),
        style.property_cell("align", &format!("2^{}", section.align())),
        style.enum_value_cell(section.section_type().name()),
        format_section_extras(section, style),
    ]
}

fn style_summary(summary: &str, style: Style) -> Cell {
    let mut cells = Vec::new();
    for token in summary.split_ascii_whitespace() {
        if !cells.is_empty() {
            cells.push(layout::plain_cell(" "));
        }
        cells.push(match token.split_once('=') {
            Some((key, value)) if !key.is_empty() && !value.is_empty() => {
                style.property_cell(key, value)
            }
            _ => layout::plain_cell(token),
        });
    }
    layout::join_cells(cells)
}

fn print_summary(macho: &MachoFile<'_>, style: Style, out: &mut dyn Write) {
    if let Some(st) = macho
        .find_load_command(|lc| lc.as_symtab().is_some())
        .and_then(|lc| lc.kind().as_symtab())
    {
        let _ = writeln!(out,);
        let _ = writeln!(
            out,
            "{} {} symbols, string table {} bytes",
            style.heading("Symbol Table:"),
            st.nsyms,
            st.str_size
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
            "{} {reloc_total} entries across {reloc_sections} sections",
            style.heading("Relocations:")
        );
    }

    if let Ok(fixups) = crate::metadata::dyld::parse_chained_fixups(macho) {
        let _ = writeln!(
            out,
            "{} {} imports, {} fixups",
            style.heading("Chained Fixups:"),
            fixups.imports.len(),
            fixups.fixups.len()
        );
    }
    if let Ok(exports) = crate::metadata::dyld::parse_exports(macho)
        && !exports.is_empty()
    {
        let _ = writeln!(
            out,
            "{} {} exports",
            style.heading("Exports Trie:"),
            exports.len()
        );
    }
}

fn print_validation(macho: &MachoFile<'_>, style: Style, out: &mut dyn Write) {
    let diags = validate::validate(macho);
    if diags.is_empty() {
        let _ = writeln!(out,);
        let _ = writeln!(out, "{} OK (no issues)", style.heading("Validation:"));
    } else {
        let _ = writeln!(out,);
        let _ = writeln!(
            out,
            "{}",
            style.heading(&format!(
                "Validation ({} issue{}):",
                diags.len(),
                if diags.len() == 1 { "" } else { "s" }
            ))
        );
        for d in &diags {
            let _ = writeln!(out, "  [{:?}] {} - {}", d.severity, d.code.0, d.message);
        }
    }
}

fn format_prot(prot: VmProtection) -> String {
    prot.rwx_string()
}

fn format_section_extras(sect: &crate::model::section::Section, style: Style) -> Cell {
    use crate::model::section::SectionType;
    match sect.section_type() {
        SectionType::SymbolStubs if sect.reserved2() > 0 => {
            style.property_cell("stub_size", &sect.reserved2().to_string())
        }
        SectionType::NonLazySymbolPointers | SectionType::LazySymbolPointers => {
            style.property_cell("indirect_idx", &sect.reserved1().to_string())
        }
        _ => layout::plain_cell(""),
    }
}
