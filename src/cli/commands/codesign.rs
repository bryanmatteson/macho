use crate::model::macho_file::MachoFile;
use anyhow::{Context, Result};
use macho::metadata::codesign::CodeSignature;
use std::path::PathBuf;

use crate::cli::commands::common::for_each_selected_mach;

#[derive(clap::Args)]
pub struct CodesignArgs {
    /// Path to Mach-O binary
    path: PathBuf,
    #[arg(long)]
    arch: Option<String>,
    /// Show entitlements XML if present
    #[arg(long)]
    entitlements: bool,
}

pub fn run(args: CodesignArgs) -> Result<()> {
    let file = std::fs::File::open(&args.path)
        .with_context(|| format!("failed to open {}", args.path.display()))?;
    let mmap = unsafe { memmap2::Mmap::map(&file)? };
    let container =
        macho::parse(&mmap).with_context(|| format!("failed to parse {}", args.path.display()))?;

    for_each_selected_mach(
        &container,
        args.arch.as_deref(),
        |macho, arch_name, show_header| {
            if show_header {
                println!("=== {arch_name} ===");
            }
            print_codesign(macho, &args);
            if show_header {
                println!();
            }
            Ok(())
        },
    )?;
    Ok(())
}

fn print_codesign(macho: &MachoFile<'_>, args: &CodesignArgs) {
    let sig = match macho.ext::<CodeSignature<'_>>() {
        Ok(s) => s,
        Err(e) => {
            println!("No code signature: {e}");
            return;
        }
    };

    println!("Code Signature:");
    println!(
        "  SuperBlob: {} blob{}, {} bytes",
        sig.blobs().len(),
        if sig.blobs().len() == 1 { "" } else { "s" },
        sig.blobs().iter().map(|b| b.size as usize).sum::<usize>(),
    );

    for cd in sig.code_directories() {
        println!(
            "  CodeDirectory v{}: {}, {} code slots, {} special slots",
            cd.version_string(),
            cd.hash_type,
            cd.n_code_slots,
            cd.n_special_slots,
        );
        if let Some(id) = cd.identifier {
            println!("    Identifier: {id}");
        }
        if let Some(team) = cd.team_id {
            println!("    Team ID:    {team}");
        }
        println!("    Hash size:  {} bytes", cd.hash_size);
        println!("    Page size:  {} bytes", 1u64 << cd.page_size);
        println!("    Code limit: {:#x}", cd.code_limit);
    }

    if let Some(xml) = sig.entitlements_xml() {
        if args.entitlements {
            println!("  Entitlements:");
            for line in xml.lines() {
                println!("    {line}");
            }
        } else {
            println!("  Entitlements: present ({} bytes)", xml.len());
        }
    } else {
        println!("  Entitlements: none");
    }

    if sig.cms_signature_present() {
        let cms_size = sig
            .blobs()
            .iter()
            .find(|b| b.blob_type == macho::metadata::codesign::BlobType::Signature)
            .map(|b| b.size)
            .unwrap_or(0);
        println!("  CMS Signature: present ({cms_size} bytes)");
    } else {
        println!("  CMS Signature: none");
    }
}
