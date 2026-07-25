use crate::commands::args::{ArchitectureArgs, InputArgs};
use crate::model::macho_file::MachoFile;
use anyhow::{Context, Result};
use macho::metadata::codesign::CodeSignature;
use std::io::Write;

use crate::analysis::{AnalysisDomain, AnalysisLimits};
use crate::commands::OutputFormat;
use crate::commands::subcommands::common::{analyze_selected_domain, write_selected_json};
use crate::commands::subcommands::common::{for_each_selected_mach, map_input};

#[derive(clap::Args)]
/// The CodesignArgs type.
pub struct CodesignArgs {
    /// Path to Mach-O binary
    #[command(flatten)]
    input: InputArgs,
    #[command(flatten)]
    selection: ArchitectureArgs,
    /// Show entitlements XML if present
    #[arg(long)]
    entitlements: bool,
}

/// Performs run.
pub fn run(args: CodesignArgs, format: OutputFormat, out: &mut dyn Write) -> Result<()> {
    let mmap = map_input(&args.input.path)?;
    let container = macho::parse(&mmap)
        .with_context(|| format!("failed to parse {}", args.input.path.display()))?;

    if format == OutputFormat::Json {
        let mut values = analyze_selected_domain(
            &container,
            args.selection.arch.as_deref(),
            AnalysisDomain::Codesign,
            AnalysisLimits::default(),
            true,
        )?;
        if !args.entitlements {
            for (_, value) in &mut values {
                if let Some(object) = value.as_object_mut() {
                    object.remove("entitlements_xml");
                }
            }
        }
        return write_selected_json(values, out);
    }

    for_each_selected_mach(
        &container,
        args.selection.arch.as_deref(),
        |macho, arch_name, show_header| {
            if show_header {
                let _ = writeln!(out, "=== {arch_name} ===");
            }
            print_codesign(macho, &args, out);
            if show_header {
                let _ = writeln!(out,);
            }
            Ok(())
        },
    )?;
    Ok(())
}

fn print_codesign(macho: &MachoFile<'_>, args: &CodesignArgs, out: &mut dyn Write) {
    let sig = match macho.ext::<CodeSignature<'_>>() {
        Ok(s) => s,
        Err(e) => {
            let _ = writeln!(out, "No code signature: {e}");
            return;
        }
    };

    let _ = writeln!(out, "Code Signature:");
    let _ = writeln!(
        out,
        "  SuperBlob: {} blob{}, {} bytes",
        sig.blobs().len(),
        if sig.blobs().len() == 1 { "" } else { "s" },
        sig.blobs().iter().map(|b| b.size as usize).sum::<usize>(),
    );

    for cd in sig.code_directories() {
        let _ = writeln!(
            out,
            "  CodeDirectory v{}: {}, {} code slots, {} special slots",
            cd.version_string(),
            cd.hash_type,
            cd.n_code_slots,
            cd.n_special_slots,
        );
        if let Some(id) = cd.identifier {
            let _ = writeln!(out, "    Identifier: {id}");
        }
        if let Some(team) = cd.team_id {
            let _ = writeln!(out, "    Team ID:    {team}");
        }
        let _ = writeln!(out, "    Hash size:  {} bytes", cd.hash_size);
        let _ = writeln!(out, "    Page size:  {} bytes", 1u64 << cd.page_size);
        let _ = writeln!(out, "    Code limit: {:#x}", cd.code_limit);
    }

    if let Some(xml) = sig.entitlements_xml() {
        if args.entitlements {
            let _ = writeln!(out, "  Entitlements:");
            for line in xml.lines() {
                let _ = writeln!(out, "    {line}");
            }
        } else {
            let _ = writeln!(out, "  Entitlements: present ({} bytes)", xml.len());
        }
    } else {
        let _ = writeln!(out, "  Entitlements: none");
    }

    if let Some(requirement) = sig.designated_requirement() {
        let _ = writeln!(
            out,
            "  Designated requirement: present ({} bytes)",
            requirement.len()
        );
    } else {
        let _ = writeln!(out, "  Designated requirement: none");
    }

    if sig.cms_signature_present() {
        let cms_size = sig
            .blobs()
            .iter()
            .find(|b| b.blob_type == macho::metadata::codesign::BlobType::Signature)
            .map(|b| b.size)
            .unwrap_or(0);
        let _ = writeln!(out, "  CMS Signature: present ({cms_size} bytes)");
    } else {
        let _ = writeln!(out, "  CMS Signature: none");
    }
}
