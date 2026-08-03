use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args_os()
        .nth(1)
        .ok_or("usage: cargo run -p macho-dwarf --example traverse -- PATH")?;
    let bytes = std::fs::read(&path)?;
    let container = macho_core::parse(&bytes)?;
    let image = container.first_macho().ok_or("PATH has no Mach-O image")?;
    let Some(receipt) =
        macho_dwarf::traverse_dwarf(image, macho_dwarf::DwarfTraversalLimits::default())?
    else {
        println!("DWARF unavailable");
        return Ok(());
    };
    println!(
        "sections={} units={} entries={} attributes={} files={} line_rows={}",
        receipt.sections.len(),
        receipt.units.len(),
        receipt.entries.len(),
        receipt.attributes.len(),
        receipt.source_files.len(),
        receipt.line_rows.len()
    );
    Ok(())
}
