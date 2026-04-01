use std::ffi::OsString;
use std::io::Write;

use clap::Parser;

pub mod subcommands;
pub mod output;

#[derive(Parser)]
#[command(name = "macho", version, about = "Mach-O binary inspection tool")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Recover C declarations from DWARF, symbols, and header correlation
    C(subcommands::c::CArgs),
    /// Display headers, segments, sections, and load commands
    Inspect(subcommands::inspect::InspectArgs),
    /// List symbols from the symbol table
    Symbols(subcommands::symbols::SymbolsArgs),
    /// List relocations per section
    Relocations(subcommands::relocations::RelocationsArgs),
    /// List exported symbols from the exports trie
    Exports(subcommands::exports::ExportsArgs),
    /// List chained fixup imports
    Imports(subcommands::imports::ImportsArgs),
    /// Walk chained fixup chains showing binds and rebases
    Fixups(subcommands::fixups::FixupsArgs),
    /// Package evidence and validate LLM-assisted header inference
    HeaderInfer(subcommands::header_infer::HeaderInferArgs),
    /// Display Objective-C metadata (classes, categories, protocols)
    Objc(subcommands::objc::ObjCArgs),
    /// Inspect code signature (entitlements, code directory, CMS)
    Codesign(subcommands::codesign::CodesignArgs),
    /// Recover C++ symbols, RTTI, vtables, and headers
    Cpp(subcommands::cpp::CppArgs),
    /// Dump a full JSON snapshot of the binary
    Snapshot(subcommands::snapshot::SnapshotArgs),
    /// Compare two Mach-O binaries semantically
    Diff(subcommands::diff::DiffArgs),
    /// Run security and policy audit on a binary
    Audit(subcommands::audit::AuditArgs),
    /// Apply structural patches to a binary
    Patch(subcommands::patch::PatchArgs),
    /// Discover Swift types from symbol metadata
    Swift(subcommands::swift::SwiftArgs),
    /// Analyze container structure (fat binary parity, fileset entries)
    Container(subcommands::container::ContainerArgs),
    /// List and inspect fileset entries
    Fileset(subcommands::fileset::FilesetArgs),
    /// Analyze dependencies, imports, exports, and compatibility
    Deps(subcommands::deps::DepsArgs),
    /// Discover and search string regions
    Strings(subcommands::data_surface::StringsArgs),
    /// Analyze C++ vtables
    Vtables(subcommands::data_surface::VtablesArgs),
    /// List symbol ownership ranges by virtual address
    Ranges(subcommands::data_surface::RangesArgs),
    /// List cross-references (stubs, fixups, branches)
    Xrefs(subcommands::data_surface::XrefsArgs),
    /// Inspect a dyld shared cache (list images, extract, info)
    DyldCache(subcommands::dyld_cache::DyldCacheArgs),
}

pub fn run_env() -> u8 {
    run_from(std::env::args_os())
}

pub fn run<I, S>(args: I) -> u8
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    run_from(std::iter::once(OsString::from("macho")).chain(args.into_iter().map(Into::into)))
}

pub struct CapturedRun {
    pub code: u8,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

pub fn run_captured<I, S>(args: I) -> CapturedRun
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let capture = crate::commands::output::begin_capture();
    let code = run(args);
    let captured = capture.finish();
    CapturedRun {
        code,
        stdout: captured.stdout,
        stderr: captured.stderr,
    }
}

fn run_from<I, S>(args: I) -> u8
where
    I: IntoIterator<Item = S>,
    S: Into<OsString> + Clone,
{
    match Cli::try_parse_from(args) {
        Ok(cli) => match dispatch(cli.command) {
            Ok(()) => 0,
            Err(err) => {
                let _ = std::io::stdout().flush();
                crate::errln!("Error: {err:#}");
                1
            }
        },
        Err(err) => {
            let code = err.exit_code();
            let _ = err.print();
            u8::try_from(code).unwrap_or(1)
        }
    }
}

fn dispatch(command: Commands) -> anyhow::Result<()> {
    match command {
        Commands::C(args) => subcommands::c::run(args),
        Commands::Inspect(args) => subcommands::inspect::run(args),
        Commands::Symbols(args) => subcommands::symbols::run(args),
        Commands::Relocations(args) => subcommands::relocations::run(args),
        Commands::Exports(args) => subcommands::exports::run(args),
        Commands::Imports(args) => subcommands::imports::run(args),
        Commands::Fixups(args) => subcommands::fixups::run(args),
        Commands::HeaderInfer(args) => subcommands::header_infer::run(args),
        Commands::Objc(args) => subcommands::objc::run(args),
        Commands::Codesign(args) => subcommands::codesign::run(args),
        Commands::Cpp(args) => subcommands::cpp::run(args),
        Commands::Snapshot(args) => subcommands::snapshot::run(args),
        Commands::Diff(args) => subcommands::diff::run(args),
        Commands::Audit(args) => subcommands::audit::run(args),
        Commands::Patch(args) => subcommands::patch::run(args),
        Commands::Swift(args) => subcommands::swift::run(args),
        Commands::Container(args) => subcommands::container::run(args),
        Commands::Fileset(args) => subcommands::fileset::run(args),
        Commands::Deps(args) => subcommands::deps::run(args),
        Commands::Strings(args) => subcommands::data_surface::run_strings(args),
        Commands::Vtables(args) => subcommands::data_surface::run_vtables(args),
        Commands::Ranges(args) => subcommands::data_surface::run_ranges(args),
        Commands::Xrefs(args) => subcommands::data_surface::run_xrefs(args),
        Commands::DyldCache(args) => subcommands::dyld_cache::run(args),
    }
}
