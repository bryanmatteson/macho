use std::ffi::OsString;
use std::io::Write;

use clap::Parser;

pub mod output;
pub mod subcommands;

#[derive(Parser)]
#[command(name = "macho", version, about = "Mach-O binary inspection tool")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Inspect Mach-O structures and metadata
    View(subcommands::view::ViewArgs),
    /// Apply one or more structural or raw patches in a single transaction
    Patch(subcommands::patch::PatchArgs),
    /// Compare two Mach-O binaries semantically
    Compare(subcommands::compare::CompareArgs),
    /// Recover or materialize higher-level artifacts from a Mach-O input
    Extract(subcommands::extract::ExtractArgs),
    /// List and inspect fileset entries
    Fileset(subcommands::fileset::FilesetArgs),
    /// Inspect a dyld shared cache (list images, extract, info)
    DyldCache(subcommands::dyld_cache::DyldCacheArgs),
    #[command(name = "audit", hide = true)]
    Audit(subcommands::audit::AuditArgs),
    #[command(name = "c", hide = true)]
    C(subcommands::c::CArgs),
    #[command(name = "codesign", hide = true)]
    Codesign(subcommands::codesign::CodesignArgs),
    #[command(name = "container", hide = true)]
    Container(subcommands::container::ContainerArgs),
    #[command(name = "cpp", hide = true)]
    Cpp(subcommands::cpp::CppArgs),
    #[command(name = "deps", hide = true)]
    Deps(subcommands::deps::DepsArgs),
    #[command(name = "diff", hide = true)]
    Diff(subcommands::diff::DiffArgs),
    #[command(name = "exports", hide = true)]
    Exports(subcommands::exports::ExportsArgs),
    #[command(name = "fixups", hide = true)]
    Fixups(subcommands::fixups::FixupsArgs),
    #[command(name = "header-infer", hide = true)]
    HeaderInfer(subcommands::header_infer::HeaderInferArgs),
    #[command(name = "imports", hide = true)]
    Imports(subcommands::imports::ImportsArgs),
    #[command(name = "inspect", hide = true)]
    Inspect(subcommands::inspect::InspectArgs),
    #[command(name = "objc", hide = true)]
    Objc(subcommands::objc::ObjCArgs),
    #[command(name = "ranges", hide = true)]
    Ranges(subcommands::data_surface::RangesArgs),
    #[command(name = "relocations", hide = true)]
    Relocations(subcommands::relocations::RelocationsArgs),
    #[command(name = "snapshot", hide = true)]
    Snapshot(subcommands::snapshot::SnapshotArgs),
    #[command(name = "strings", hide = true)]
    Strings(subcommands::data_surface::StringsArgs),
    #[command(name = "swift", hide = true)]
    Swift(subcommands::swift::SwiftArgs),
    #[command(name = "symbols", hide = true)]
    Symbols(subcommands::symbols::SymbolsArgs),
    #[command(name = "vtables", hide = true)]
    Vtables(subcommands::data_surface::VtablesArgs),
    #[command(name = "xrefs", hide = true)]
    Xrefs(subcommands::data_surface::XrefsArgs),
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
        Commands::View(args) => subcommands::view::run(args),
        Commands::Patch(args) => subcommands::patch::run(args),
        Commands::Compare(args) => subcommands::compare::run(args),
        Commands::Extract(args) => subcommands::extract::run(args),
        Commands::Fileset(args) => subcommands::fileset::run(args),
        Commands::DyldCache(args) => subcommands::dyld_cache::run(args),
        Commands::Audit(args) => subcommands::audit::run(args),
        Commands::C(args) => subcommands::c::run(args),
        Commands::Codesign(args) => subcommands::codesign::run(args),
        Commands::Container(args) => subcommands::container::run(args),
        Commands::Cpp(args) => subcommands::cpp::run(args),
        Commands::Deps(args) => subcommands::deps::run(args),
        Commands::Diff(args) => subcommands::diff::run(args),
        Commands::Exports(args) => subcommands::exports::run(args),
        Commands::Fixups(args) => subcommands::fixups::run(args),
        Commands::HeaderInfer(args) => subcommands::header_infer::run(args),
        Commands::Imports(args) => subcommands::imports::run(args),
        Commands::Inspect(args) => subcommands::inspect::run(args),
        Commands::Objc(args) => subcommands::objc::run(args),
        Commands::Ranges(args) => subcommands::data_surface::run_ranges(args),
        Commands::Relocations(args) => subcommands::relocations::run(args),
        Commands::Snapshot(args) => subcommands::snapshot::run(args),
        Commands::Strings(args) => subcommands::data_surface::run_strings(args),
        Commands::Swift(args) => subcommands::swift::run(args),
        Commands::Symbols(args) => subcommands::symbols::run(args),
        Commands::Vtables(args) => subcommands::data_surface::run_vtables(args),
        Commands::Xrefs(args) => subcommands::data_surface::run_xrefs(args),
    }
}
