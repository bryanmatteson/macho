use crate::commands::args::InputArgs;
use crate::commands::subcommands::common::map_input;
use crate::commands::{OutputFormat, input_message, input_result};
use crate::inputs::dyld_cache::parse_dyld_cache;
use anyhow::Result;
use std::io::Write;
use std::path::PathBuf;

#[derive(clap::Args)]
/// The DyldCacheArgs type.
pub struct DyldCacheArgs {
    /// Path to dyld shared cache file
    #[command(flatten)]
    input: InputArgs,
    /// Show cache header and mapping info
    #[arg(long)]
    info: bool,
    /// Extract an image whose path contains this string
    #[arg(long)]
    extract: Option<String>,
    /// Output directory for extracted images (defaults to current directory)
    #[arg(long)]
    extract_to: Option<PathBuf>,
}

/// Performs run.
pub fn run(args: DyldCacheArgs, format: OutputFormat, out: &mut dyn Write) -> Result<()> {
    let mmap = map_input(&args.input.path)?;
    let cache = input_result(
        parse_dyld_cache(&mmap),
        format!("failed to parse {}", args.input.path.display()),
    )?;

    if format == OutputFormat::Json {
        let _ = writeln!(out, "{}", serde_json::to_string_pretty(&cache)?);
        return Ok(());
    }

    if let Some(ref pattern) = args.extract {
        return extract_image(&cache, &mmap, pattern, args.extract_to.as_deref(), out);
    }

    if args.info {
        print_info(&cache, out);
        return Ok(());
    }

    // Default: list images
    print_list(&cache, out);
    Ok(())
}

fn print_info(cache: &crate::inputs::dyld_cache::DyldCache, out: &mut dyn Write) {
    let _ = writeln!(out, "dyld shared cache");
    let _ = writeln!(out, "  magic:    {}", cache.header.magic);
    let _ = writeln!(out, "  arch:     {}", cache.arch());
    let _ = writeln!(out, "  images:   {}", cache.images().len());
    let _ = writeln!(out, "  mappings: {}", cache.mappings().len());
    let _ = writeln!(out,);

    for (i, m) in cache.mappings().iter().enumerate() {
        let prot = format_prot(m.init_prot);
        let _ = writeln!(
            out,
            "  mapping[{i}]  {:#018x}..{:#018x}  {:#x} bytes  @ {:#x}  {prot}",
            m.address,
            m.address + m.size,
            m.size,
            m.file_offset,
        );
    }
}

fn print_list(cache: &crate::inputs::dyld_cache::DyldCache, out: &mut dyn Write) {
    let _ = writeln!(
        out,
        "dyld shared cache ({}) - {} images",
        cache.arch(),
        cache.images().len(),
    );
    for (i, img) in cache.images().iter().enumerate() {
        let _ = writeln!(out, "  [{i:4}]  {:#018x}  {}", img.address, img.path);
    }
}

fn extract_image(
    cache: &crate::inputs::dyld_cache::DyldCache,
    data: &[u8],
    pattern: &str,
    output_dir: Option<&std::path::Path>,
    out: &mut dyn Write,
) -> Result<()> {
    let matches: Vec<(usize, &crate::inputs::dyld_cache::CacheImage)> = cache
        .images()
        .iter()
        .enumerate()
        .filter(|(_, img)| img.path.contains(pattern))
        .collect();

    if matches.is_empty() {
        return Err(input_message(format!("no images matching \"{pattern}\"")));
    }

    let out_dir = output_dir.unwrap_or_else(|| std::path::Path::new("."));

    for (idx, img) in &matches {
        let slice = cache
            .extract_image(*idx, data)
            .map_err(|e| anyhow::anyhow!("{e}"))?;

        // Use the last path component as the filename
        let filename = img.path.rsplit('/').next().unwrap_or("extracted");
        let out_path = out_dir.join(filename);

        std::fs::create_dir_all(out_dir)?;
        std::fs::write(&out_path, slice)?;
        let _ = writeln!(
            out,
            "extracted {} -> {} ({} bytes)",
            img.path,
            out_path.display(),
            slice.len()
        );
    }

    Ok(())
}

fn format_prot(prot: u32) -> String {
    let r = if prot & 1 != 0 { 'r' } else { '-' };
    let w = if prot & 2 != 0 { 'w' } else { '-' };
    let x = if prot & 4 != 0 { 'x' } else { '-' };
    format!("{r}{w}{x}")
}
