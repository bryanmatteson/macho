use anyhow::{Context, Result};
use macho::dyld_cache::parse_dyld_cache;
use std::path::PathBuf;

#[derive(clap::Args)]
pub struct DyldCacheArgs {
    /// Path to dyld shared cache file
    path: PathBuf,
    /// Output as JSON
    #[arg(long)]
    json: bool,
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

pub fn run(args: DyldCacheArgs) -> Result<()> {
    let file = std::fs::File::open(&args.path)
        .with_context(|| format!("failed to open {}", args.path.display()))?;
    let mmap = unsafe { memmap2::Mmap::map(&file)? };
    let cache = parse_dyld_cache(&mmap)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .with_context(|| format!("failed to parse {}", args.path.display()))?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&cache)?);
        return Ok(());
    }

    if let Some(ref pattern) = args.extract {
        return extract_image(&cache, &mmap, pattern, args.extract_to.as_deref());
    }

    if args.info {
        print_info(&cache);
        return Ok(());
    }

    // Default: list images
    print_list(&cache);
    Ok(())
}

fn print_info(cache: &macho::dyld_cache::DyldCache) {
    println!("dyld shared cache");
    println!("  magic:    {}", cache.header.magic);
    println!("  arch:     {}", cache.arch());
    println!("  images:   {}", cache.images().len());
    println!("  mappings: {}", cache.mappings().len());
    println!();

    for (i, m) in cache.mappings().iter().enumerate() {
        let prot = format_prot(m.init_prot);
        println!(
            "  mapping[{i}]  {:#018x}..{:#018x}  {:#x} bytes  @ {:#x}  {prot}",
            m.address,
            m.address + m.size,
            m.size,
            m.file_offset,
        );
    }
}

fn print_list(cache: &macho::dyld_cache::DyldCache) {
    println!(
        "dyld shared cache ({}) - {} images",
        cache.arch(),
        cache.images().len(),
    );
    for (i, img) in cache.images().iter().enumerate() {
        println!("  [{i:4}]  {:#018x}  {}", img.address, img.path);
    }
}

fn extract_image(
    cache: &macho::dyld_cache::DyldCache,
    data: &[u8],
    pattern: &str,
    output_dir: Option<&std::path::Path>,
) -> Result<()> {
    let matches: Vec<(usize, &macho::dyld_cache::CacheImage)> = cache
        .images()
        .iter()
        .enumerate()
        .filter(|(_, img)| img.path.contains(pattern))
        .collect();

    if matches.is_empty() {
        anyhow::bail!("no images matching \"{pattern}\"");
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
        println!(
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
