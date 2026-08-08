use crate::cli::commands::args::InputArgs;
use crate::cli::commands::subcommands::common::map_input;
use crate::cli::commands::{OutputFormat, input_message, input_result};
use crate::core::MaterializationLimits;
use crate::dyld_cache::{
    CacheMemberInput, DyldCache, DyldCacheFamily, ReconstructedImage, parse_dyld_cache,
};
use anyhow::{Context, Result};
use memmap2::Mmap;
use serde::Serialize;
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(clap::Args)]
/// Inspect or reconstruct images from an offline dyld shared-cache family.
pub struct DyldCacheArgs {
    /// Path to the primary dyld shared-cache file
    #[command(flatten)]
    input: InputArgs,
    /// Show cache-family header, member, and mapping information
    #[arg(long, conflicts_with_all = ["extract", "search"])]
    info: bool,
    /// List only image paths containing this query
    #[arg(long, value_name = "QUERY", conflicts_with = "extract")]
    search: Option<String>,
    /// Reconstruct one exact image path (a unique substring is also accepted)
    #[arg(long, value_name = "IMAGE_PATH", conflicts_with = "search")]
    extract: Option<String>,
    /// Exact output file for one reconstructed image
    #[arg(
        long,
        value_name = "FILE",
        requires = "extract",
        conflicts_with = "output_dir"
    )]
    output: Option<PathBuf>,
    /// Directory for the reconstructed image's basename
    #[arg(
        long,
        value_name = "DIR",
        requires = "extract",
        conflicts_with = "output"
    )]
    output_dir: Option<PathBuf>,
    /// Replace an existing output file
    #[arg(long, requires = "extract")]
    force: bool,
}

#[derive(Serialize)]
struct ListDocument<'a> {
    schema_version: u32,
    operation: &'static str,
    arch: &'a str,
    images: Vec<&'a crate::dyld_cache::CacheImage>,
}

#[derive(Serialize)]
struct InfoDocument<'a> {
    schema_version: u32,
    operation: &'static str,
    primary: &'a DyldCache,
    members: Vec<MemberDocument<'a>>,
}

#[derive(Serialize)]
struct MemberDocument<'a> {
    name: &'a str,
    kind: crate::dyld_cache::CacheFamilyMemberKind,
    uuid: String,
    format_version: crate::dyld_cache::DyldCacheFormatVersion,
    byte_order: crate::dyld_cache::DyldCacheByteOrder,
    mappings: &'a [crate::dyld_cache::CacheMapping],
    tpro_mappings: &'a [crate::dyld_cache::CacheTproMapping],
}

#[derive(Serialize)]
struct ExtractionDocument<'a> {
    schema_version: u32,
    operation: &'static str,
    output: String,
    written: bool,
    result: &'a ReconstructedImage,
}

/// Run one dyld cache operation.
pub fn run(args: DyldCacheArgs, format: OutputFormat, out: &mut dyn Write) -> Result<()> {
    let primary_map = map_input(&args.input.path)?;
    let primary_cache = input_result(
        parse_dyld_cache(&primary_map),
        format!("failed to parse {}", args.input.path.display()),
    )?;
    let sibling_maps = map_declared_siblings(&args.input.path, &primary_cache)?;
    let sibling_inputs = sibling_maps
        .iter()
        .map(|(suffix, mmap)| CacheMemberInput {
            name: suffix,
            data: mmap,
        })
        .collect::<Vec<_>>();
    let primary_name = args.input.path.to_string_lossy();
    let family = input_result(
        DyldCacheFamily::parse(
            CacheMemberInput {
                name: &primary_name,
                data: &primary_map,
            },
            sibling_inputs,
        ),
        format!(
            "failed to assemble cache family {}",
            args.input.path.display()
        ),
    )?;

    if let Some(selector) = args.extract.as_deref() {
        return extract_image(&args, &family, selector, format, out);
    }
    if args.info {
        return print_info(&family, format, out);
    }
    print_list(&family, args.search.as_deref(), format, out)
}

fn map_declared_siblings(primary_path: &Path, cache: &DyldCache) -> Result<Vec<(String, Mmap)>> {
    let mut suffixes = cache
        .subcaches()
        .iter()
        .map(|entry| entry.file_suffix.clone())
        .collect::<Vec<_>>();
    if cache.requires_symbols_member() {
        suffixes.push(".symbols".to_owned());
    }
    suffixes
        .into_iter()
        .map(|suffix| {
            let mut path = OsString::from(primary_path.as_os_str());
            path.push(&suffix);
            let path = PathBuf::from(path);
            map_input(&path)
                .with_context(|| {
                    format!(
                        "required cache family member {suffix:?} was declared by {}",
                        primary_path.display()
                    )
                })
                .map(|mmap| (suffix, mmap))
        })
        .collect()
}

fn print_info(
    family: &DyldCacheFamily<'_>,
    format: OutputFormat,
    out: &mut dyn Write,
) -> Result<()> {
    if format == OutputFormat::Json {
        let document = InfoDocument {
            schema_version: 1,
            operation: "info",
            primary: family.primary(),
            members: family
                .members()
                .iter()
                .map(|member| MemberDocument {
                    name: member.name(),
                    kind: member.kind(),
                    uuid: format_uuid(member.cache().header.uuid),
                    format_version: member.cache().header.format_version,
                    byte_order: member.cache().header.byte_order,
                    mappings: member.cache().mappings(),
                    tpro_mappings: member.cache().tpro_mappings(),
                })
                .collect(),
        };
        crate::cli::commands::output::json::write_pretty(out, &document)?;
        return Ok(());
    }
    writeln!(out, "dyld shared-cache family")?;
    writeln!(out, "  arch:     {}", family.primary().arch())?;
    writeln!(
        out,
        "  format:   {:?} {:?}",
        family.primary().header.format_version,
        family.primary().header.byte_order
    )?;
    writeln!(out, "  images:   {}", family.primary().images().len())?;
    writeln!(out, "  members:  {}", family.members().len())?;
    for (member_index, member) in family.members().iter().enumerate() {
        writeln!(out)?;
        writeln!(
            out,
            "  member[{member_index}] {}  kind={:?} uuid={}",
            member.name(),
            member.kind(),
            format_uuid(member.cache().header.uuid)
        )?;
        for (mapping_index, mapping) in member.cache().mappings().iter().enumerate() {
            let end = mapping.address + mapping.size;
            writeln!(
                out,
                "    mapping[{mapping_index}] {:#018x}..{end:#018x} @ {:#x} {}",
                mapping.address,
                mapping.file_offset,
                format_prot(mapping.init_prot)
            )?;
        }
        for (mapping_index, mapping) in member.cache().tpro_mappings().iter().enumerate() {
            let end = mapping.address + mapping.size;
            writeln!(
                out,
                "    tpro[{mapping_index}]    {:#018x}..{end:#018x}",
                mapping.address,
            )?;
        }
    }
    Ok(())
}

fn print_list(
    family: &DyldCacheFamily<'_>,
    query: Option<&str>,
    format: OutputFormat,
    out: &mut dyn Write,
) -> Result<()> {
    let images = family
        .primary()
        .images()
        .iter()
        .filter(|image| query.is_none_or(|query| image.path.contains(query)))
        .collect::<Vec<_>>();
    if format == OutputFormat::Json {
        crate::cli::commands::output::json::write_pretty(
            out,
            &ListDocument {
                schema_version: 1,
                operation: if query.is_some() { "search" } else { "list" },
                arch: family.primary().arch(),
                images,
            },
        )?;
        return Ok(());
    }
    writeln!(
        out,
        "dyld shared cache ({}) - {} matching images",
        family.primary().arch(),
        images.len()
    )?;
    for image in images {
        let index = family
            .image_index_by_path(&image.path)
            .expect("listed image came from the primary index");
        writeln!(
            out,
            "  [{index:4}]  {:#018x}  {}",
            image.address, image.path
        )?;
    }
    Ok(())
}

fn extract_image(
    args: &DyldCacheArgs,
    family: &DyldCacheFamily<'_>,
    selector: &str,
    format: OutputFormat,
    out: &mut dyn Write,
) -> Result<()> {
    let index = if let Some(index) = family.image_index_by_path(selector) {
        index
    } else {
        let matches = family.search_images(selector);
        match matches.as_slice() {
            [] => return Err(input_message(format!("no image matching {selector:?}"))),
            [index] => *index,
            _ => {
                let paths = matches
                    .iter()
                    .take(8)
                    .map(|index| family.primary().images()[*index].path.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                return Err(input_message(format!(
                    "image selector {selector:?} is ambiguous ({} matches: {paths}); use an exact image path",
                    matches.len()
                )));
            }
        }
    };
    let image = input_result(
        family.reconstruct_image(index, MaterializationLimits::default()),
        format!(
            "failed to reconstruct {}",
            family.primary().images()[index].path
        ),
    )?;
    let destination = output_path(args, &image.image_path)?;
    atomic_materialize(&destination, image.bytes(), args.force)?;
    if format == OutputFormat::Json {
        crate::cli::commands::output::json::write_pretty(
            out,
            &ExtractionDocument {
                schema_version: 1,
                operation: "extract",
                output: destination.display().to_string(),
                written: true,
                result: &image,
            },
        )?;
        return Ok(());
    }
    writeln!(
        out,
        "reconstructed {} -> {} ({} bytes)",
        image.image_path,
        destination.display(),
        image.byte_len
    )?;
    for (name, state) in [
        ("segments", &image.completeness.segments),
        ("linkedit", &image.completeness.linkedit),
        ("symbols", &image.completeness.symbols),
        ("exports", &image.completeness.exports),
        ("imports", &image.completeness.imports),
        ("fixups", &image.completeness.fixups),
        ("local-symbols", &image.completeness.local_symbols),
        ("code-signature", &image.completeness.code_signature),
    ] {
        writeln!(out, "  {name}: {:?} - {}", state.state, state.detail)?;
    }
    Ok(())
}

fn output_path(args: &DyldCacheArgs, image_path: &str) -> Result<PathBuf> {
    if let Some(path) = &args.output {
        if path.is_dir() {
            return Err(input_message(format!(
                "--output expects a file, but {} is a directory",
                path.display()
            )));
        }
        return Ok(path.clone());
    }
    let filename = image_path
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| input_message(format!("image path {image_path:?} has no basename")))?;
    Ok(args
        .output_dir
        .as_deref()
        .unwrap_or_else(|| Path::new("."))
        .join(filename))
}

fn atomic_materialize(destination: &Path, bytes: &[u8], force: bool) -> Result<()> {
    if destination.exists() && !force {
        return Err(input_message(format!(
            "refusing to overwrite {}; pass --force to replace it",
            destination.display()
        )));
    }
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)
        .with_context(|| format!("failed to create {}", parent.display()))?;
    let stem = destination
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("image");
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temporary = parent.join(format!(
        ".{stem}.macho-cache-{}-{nonce}.tmp",
        std::process::id()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .with_context(|| format!("failed to create {}", temporary.display()))?;
        file.write_all(bytes)
            .with_context(|| format!("failed to write {}", temporary.display()))?;
        file.sync_all()
            .with_context(|| format!("failed to flush {}", temporary.display()))?;
        if force {
            std::fs::rename(&temporary, destination)
                .with_context(|| format!("failed to replace {}", destination.display()))?;
        } else {
            std::fs::hard_link(&temporary, destination).with_context(|| {
                format!(
                    "failed to materialize {} without overwriting",
                    destination.display()
                )
            })?;
            std::fs::remove_file(&temporary)
                .with_context(|| format!("failed to remove {}", temporary.display()))?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

fn format_uuid(uuid: [u8; 16]) -> String {
    uuid.iter().map(|byte| format!("{byte:02X}")).collect()
}

fn format_prot(prot: u32) -> String {
    let r = if prot & 1 != 0 { 'r' } else { '-' };
    let w = if prot & 2 != 0 { 'w' } else { '-' };
    let x = if prot & 4 != 0 { 'x' } else { '-' };
    format!("{r}{w}{x}")
}
