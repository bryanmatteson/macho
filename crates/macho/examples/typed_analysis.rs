//! Run a selective analysis plan and consume its reports without handling JSON values.

use macho::analysis::{AnalysisDomain, AnalysisPlan, Analyzer, DomainState, domain_reports};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args_os()
        .nth(1)
        .ok_or("usage: cargo run -p macho --example typed_analysis -- <Mach-O>")?;
    let bytes = std::fs::read(path)?;
    let container = macho::parse(&bytes)?;
    let document = Analyzer.run(
        &container,
        &AnalysisPlan::new([
            AnalysisDomain::Header,
            AnalysisDomain::Symbols,
            AnalysisDomain::Xrefs,
        ]),
    )?;

    for slice in &document.slices {
        if let DomainState::Complete { value: header, .. } = slice.report(domain_reports::HEADER)? {
            println!(
                "{}: {} {}",
                slice.identity.arch, header.cpu_type, header.file_type
            );
        }
        if let DomainState::Complete {
            value: symbols,
            issues,
        } = slice.report(domain_reports::SYMBOLS)?
        {
            println!("  {} symbols ({} issue(s))", symbols.len(), issues.len());
        }
        match slice.report(domain_reports::XREFS)? {
            DomainState::Complete {
                value: xrefs,
                issues,
            } => println!("  {} xrefs ({} issue(s))", xrefs.len(), issues.len()),
            DomainState::Unsupported { reason } => {
                println!("  xrefs unsupported: {}", reason.message)
            }
            DomainState::Failed { error, .. } => println!("  xrefs failed: {}", error.message),
            DomainState::NotRequested => unreachable!("xrefs were requested"),
            _ => println!("  xrefs returned a newer state this client does not recognize"),
        }
    }
    Ok(())
}
