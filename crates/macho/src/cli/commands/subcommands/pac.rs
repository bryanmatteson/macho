//! Pointer-authentication analysis delivery.

use std::io::Write;

use anyhow::{Context, Result};

use crate::analysis::pac::{
    PacAnalysisLimits, PacCodeSite, PacIndex, PacKey, PacModifier, PacPointerAuthentication,
    PacPointerRecord, PacPointerTarget,
};
use crate::cli::commands::OutputFormat;
use crate::cli::commands::args::{ArchitectureArgs, InputArgs};
use crate::cli::commands::subcommands::common::{
    for_each_selected_mach, map_input, write_selected_json,
};

/// Arguments for bounded PAC inventory and code-site recovery.
#[derive(Debug, clap::Args)]
pub struct PacArgs {
    #[command(flatten)]
    input: InputArgs,
    #[command(flatten)]
    selection: ArchitectureArgs,
    /// Print the address-oriented pointer map after the summary
    #[arg(long)]
    pointers: bool,
    /// Print recovered PAC/authenticated control-flow sites after the summary
    #[arg(long, alias = "transfers")]
    gadgets: bool,
    /// Maximum dyld-managed pointer records retained per slice
    #[arg(long, default_value_t = 1_000_000)]
    max_pointers: u64,
    /// Maximum executable bytes decoded per slice
    #[arg(long, default_value_t = 64 * 1024 * 1024)]
    max_code_bytes: usize,
}

/// Execute PAC analysis for selected arm64 images.
pub fn run(args: PacArgs, format: OutputFormat, out: &mut dyn Write) -> Result<()> {
    let mmap = map_input(&args.input.path)?;
    let container = crate::parse(&mmap)
        .with_context(|| format!("failed to parse {}", args.input.path.display()))?;
    let limits = PacAnalysisLimits {
        max_pointers: args.max_pointers,
        max_code_bytes: args.max_code_bytes,
    };

    if format == OutputFormat::Json {
        let mut values = Vec::new();
        for_each_selected_mach(
            &container,
            args.selection.arch.as_deref(),
            |macho, arch, _| {
                let report = PacIndex::recover(macho, limits)?;
                values.push((arch.to_owned(), serde_json::to_value(report)?));
                Ok(())
            },
        )?;
        return write_selected_json(values, out);
    }

    for_each_selected_mach(
        &container,
        args.selection.arch.as_deref(),
        |macho, arch, show_header| {
            let report = PacIndex::recover(macho, limits)?;
            if show_header {
                writeln!(out, "=== {arch} ===")?;
            }
            write_text(&report, args.pointers, args.gadgets, out)?;
            if show_header {
                writeln!(out)?;
            }
            Ok(())
        },
    )
}

fn write_text(
    report: &PacIndex,
    show_pointers: bool,
    show_gadgets: bool,
    out: &mut dyn Write,
) -> Result<()> {
    let summary = &report.summary;
    writeln!(
        out,
        "PAC analysis: {}{}",
        report.architecture,
        if report.arm64e { "" } else { " (non-arm64e)" }
    )?;
    writeln!(out, "Pointers:")?;
    writeln!(
        out,
        "  authenticated          {}",
        summary.authenticated_pointers
    )?;
    writeln!(out, "  plain                  {}", summary.plain_pointers)?;
    writeln!(
        out,
        "  address-diverse        {}",
        summary.address_diverse_pointers
    )?;
    if !summary.pointer_keys.is_empty() {
        writeln!(out, "Authentication keys:")?;
        for item in &summary.pointer_keys {
            writeln!(out, "  {:<22} {}", key_name(item.key), item.count)?;
        }
    }
    if !summary.pointer_diversities.is_empty() {
        writeln!(out, "Diversity inventory:")?;
        for item in &summary.pointer_diversities {
            writeln!(
                out,
                "  key={:<2} diversity={:#06x} modifier={:<15} {}",
                key_name(item.key),
                item.diversity,
                if item.address_diversity {
                    "storage_address"
                } else {
                    "constant"
                },
                item.count
            )?;
        }
    }
    writeln!(out, "PAC code sites:")?;
    writeln!(out, "  sign                   {}", summary.sign_sites)?;
    writeln!(
        out,
        "  authenticate           {}",
        summary.authenticate_sites
    )?;
    writeln!(out, "  strip                  {}", summary.strip_sites)?;
    writeln!(
        out,
        "  authenticated branches {}",
        summary.authenticated_branches
    )?;
    writeln!(
        out,
        "  authenticated calls    {}",
        summary.authenticated_calls
    )?;
    writeln!(
        out,
        "  authenticated returns  {}",
        summary.authenticated_returns
    )?;
    if !summary.code_keys.is_empty() {
        writeln!(out, "PAC instruction keys:")?;
        for item in &summary.code_keys {
            writeln!(out, "  {:<22} {}", key_name(item.key), item.count)?;
        }
    }
    writeln!(
        out,
        "Completeness: pointers={:?}, code_bytes={}, code_truncated={}, decode_gaps={}",
        report.completeness.pointer_status,
        report.completeness.decoded_code_bytes,
        report.completeness.code_truncated,
        report.completeness.decode_gaps
    )?;

    if show_pointers {
        writeln!(out, "Pointer map:")?;
        if report.pointers.is_empty() {
            writeln!(out, "  (none)")?;
        }
        for pointer in &report.pointers {
            write_pointer(pointer, out)?;
        }
    }
    if show_gadgets {
        writeln!(out, "PAC/auth control-flow sites:")?;
        if report.code_sites.is_empty() {
            writeln!(out, "  (none)")?;
        }
        for site in &report.code_sites {
            write_site(site, out)?;
        }
    }
    Ok(())
}

fn write_pointer(pointer: &PacPointerRecord, out: &mut dyn Write) -> Result<()> {
    let location = match (&pointer.segment, &pointer.section) {
        (Some(segment), Some(section)) => format!("{segment},{section}"),
        (Some(segment), None) => segment.clone(),
        _ => "<unmapped>".into(),
    };
    let authentication = match pointer.authentication {
        PacPointerAuthentication::Plain => "plain".to_owned(),
        PacPointerAuthentication::Authenticated {
            key,
            diversity,
            address_diversity,
        } => format!(
            "auth key={} diversity={diversity:#06x} modifier={}",
            key_name(key),
            if address_diversity {
                "storage_address"
            } else {
                "constant"
            }
        ),
    };
    let stored_bytes = pointer
        .stored_bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    writeln!(
        out,
        "  {:#018x}  {:<28} {:<48} encoding={:?} bytes={} -> {}",
        pointer.address,
        location,
        authentication,
        pointer.encoding,
        stored_bytes,
        target_name(&pointer.target)
    )?;
    Ok(())
}

fn write_site(site: &PacCodeSite, out: &mut dyn Write) -> Result<()> {
    let key = site
        .key
        .map_or("-".to_owned(), |key| key_name(key).to_owned());
    writeln!(
        out,
        "  {:#018x}  {},{}  {:?} key={} modifier={}{}  {}",
        site.address,
        site.segment,
        site.section,
        site.kind,
        key,
        modifier_name(site.modifier),
        site.authentication_address
            .map_or_else(String::new, |address| format!(" auth@{address:#x}")),
        site.instruction.trim()
    )?;
    Ok(())
}

fn target_name(target: &PacPointerTarget) -> String {
    match target {
        PacPointerTarget::Null => "null".into(),
        PacPointerTarget::Internal { address } => format!("{address:#x}"),
        PacPointerTarget::Import {
            name,
            library_ordinal,
            ..
        } => library_ordinal.map_or_else(
            || name.clone(),
            |ordinal| format!("{name} (ordinal {ordinal})"),
        ),
    }
}

const fn key_name(key: PacKey) -> &'static str {
    match key {
        PacKey::Ia => "IA",
        PacKey::Ib => "IB",
        PacKey::Da => "DA",
        PacKey::Db => "DB",
        PacKey::Unknown(_) => "unknown",
    }
}

fn modifier_name(modifier: PacModifier) -> String {
    match modifier {
        PacModifier::StackPointer => "sp".into(),
        PacModifier::Zero => "zero".into(),
        PacModifier::Register { number } => format!("x{number}"),
        PacModifier::Unknown => "unknown".into(),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn grammar_accepts_pac_detail_and_limit_options() {
        crate::cli::commands::parse_only([
            "macho",
            "pac",
            "fixture",
            "--arch",
            "arm64e",
            "--pointers",
            "--gadgets",
            "--max-pointers",
            "12",
            "--max-code-bytes",
            "4096",
        ])
        .unwrap();
    }
}
