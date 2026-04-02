use std::ffi::OsString;
use std::io::Write;

use clap::Parser;

pub mod output;
pub mod subcommands;

const GROUPED_HELP: &str = "\
Structure:
  info           Mach-O structure (header, segments, sections, load commands)
  deps           Linked libraries and compatibility versions
  codesign       Code signature, entitlements, and CMS info
  dwarf          DWARF debug sections (view or extract with --output-dir)

Symbols:
  symbols        Symbol table with filtering
  imports        Imported symbols
  exports        Exported symbols
  fixups         Chained fixup entries
  relocations    Relocation entries
  ranges         Function and symbol address ranges

Data:
  strings        String literals with heuristic scanning
  xrefs          Cross-references between addresses
  vtables        C++ virtual tables

Language:
  objc           Objective-C classes, protocols, selectors
  swift          Swift type metadata
  cpp            C++ RTTI type hierarchies
  c              C type declarations from debug info

Analysis:
  diff           Compare two binaries semantically
  audit          Security and configuration audit
  container      Multi-architecture container analysis
  snapshot       JSON structural snapshot

Mutation:
  patch          Apply structural patches (rpaths, dylibs, signatures, bytes)
  header-infer   Reconstruct Mach-O headers from evidence

Special:
  fileset        Inspect fileset entries
  cache          Inspect dyld shared cache";

#[derive(Parser)]
#[command(
    name = "macho",
    version,
    about = "Mach-O binary inspection tool",
    override_usage = "macho <COMMAND> [OPTIONS]",
    after_help = GROUPED_HELP,
    subcommand_required = true,
    arg_required_else_help = true,
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

// All variants use `hide = true` to suppress clap's auto-generated alphabetical
// subcommand list. The grouped layout in GROUPED_HELP replaces it.
// Every command is fully functional — `hide` is cosmetic only.
#[derive(clap::Subcommand)]
enum Commands {
    // ── Structure ───────────────────────────────────────────────────────
    /// Mach-O structure (header, segments, sections, load commands)
    #[command(hide = true)]
    Info(subcommands::info::InfoArgs),
    /// Linked libraries and compatibility versions
    #[command(hide = true)]
    Deps(subcommands::deps::DepsArgs),
    /// Code signature, entitlements, and CMS info
    #[command(hide = true)]
    Codesign(subcommands::codesign::CodesignArgs),
    /// DWARF debug sections (view or extract with --output-dir)
    #[command(hide = true)]
    Dwarf(subcommands::dwarf::DwarfArgs),

    // ── Symbols ────────────────────────────────────────────────────────
    /// Symbol table with filtering
    #[command(hide = true)]
    Symbols(subcommands::symbols::SymbolsArgs),
    /// Imported symbols
    #[command(hide = true)]
    Imports(subcommands::imports::ImportsArgs),
    /// Exported symbols
    #[command(hide = true)]
    Exports(subcommands::exports::ExportsArgs),
    /// Chained fixup entries
    #[command(hide = true)]
    Fixups(subcommands::fixups::FixupsArgs),
    /// Relocation entries
    #[command(hide = true)]
    Relocations(subcommands::relocations::RelocationsArgs),
    /// Function and symbol address ranges
    #[command(hide = true)]
    Ranges(subcommands::data_surface::RangesArgs),

    // ── Data ───────────────────────────────────────────────────────────
    /// String literals with heuristic scanning
    #[command(hide = true)]
    Strings(subcommands::data_surface::StringsArgs),
    /// Cross-references between addresses
    #[command(hide = true)]
    Xrefs(subcommands::data_surface::XrefsArgs),
    /// C++ virtual tables
    #[command(hide = true)]
    Vtables(subcommands::data_surface::VtablesArgs),

    // ── Language ───────────────────────────────────────────────────────
    /// Objective-C classes, protocols, selectors
    #[command(hide = true)]
    Objc(subcommands::objc::ObjCArgs),
    /// Swift type metadata
    #[command(hide = true)]
    Swift(subcommands::swift::SwiftArgs),
    /// C++ RTTI type hierarchies
    #[command(hide = true)]
    Cpp(subcommands::cpp::CppArgs),
    /// C type declarations from debug info
    #[command(hide = true)]
    C(subcommands::c::CArgs),

    // ── Analysis ───────────────────────────────────────────────────────
    /// Compare two binaries semantically
    #[command(hide = true)]
    Diff(subcommands::diff::DiffArgs),
    /// Security and configuration audit
    #[command(hide = true)]
    Audit(subcommands::audit::AuditArgs),
    /// Multi-architecture container analysis
    #[command(hide = true)]
    Container(subcommands::container::ContainerArgs),
    /// JSON structural snapshot
    #[command(hide = true)]
    Snapshot(subcommands::snapshot::SnapshotArgs),

    // ── Mutation ───────────────────────────────────────────────────────
    /// Apply structural patches (rpaths, dylibs, signatures, bytes)
    #[command(hide = true)]
    Patch(subcommands::patch::PatchArgs),
    /// Reconstruct Mach-O headers from evidence
    #[command(name = "header-infer", hide = true)]
    HeaderInfer(subcommands::header_infer::HeaderInferArgs),

    // ── Special ────────────────────────────────────────────────────────
    /// Inspect fileset entries
    #[command(hide = true)]
    Fileset(subcommands::fileset::FilesetArgs),
    /// Inspect dyld shared cache
    #[command(hide = true)]
    Cache(subcommands::dyld_cache::DyldCacheArgs),
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
        // Structure
        Commands::Info(args) => subcommands::info::run(args),
        Commands::Deps(args) => subcommands::deps::run(args),
        Commands::Codesign(args) => subcommands::codesign::run(args),
        Commands::Dwarf(args) => subcommands::dwarf::run(args),
        // Symbols
        Commands::Symbols(args) => subcommands::symbols::run(args),
        Commands::Imports(args) => subcommands::imports::run(args),
        Commands::Exports(args) => subcommands::exports::run(args),
        Commands::Fixups(args) => subcommands::fixups::run(args),
        Commands::Relocations(args) => subcommands::relocations::run(args),
        Commands::Ranges(args) => subcommands::data_surface::run_ranges(args),
        // Data
        Commands::Strings(args) => subcommands::data_surface::run_strings(args),
        Commands::Xrefs(args) => subcommands::data_surface::run_xrefs(args),
        Commands::Vtables(args) => subcommands::data_surface::run_vtables(args),
        // Language
        Commands::Objc(args) => subcommands::objc::run(args),
        Commands::Swift(args) => subcommands::swift::run(args),
        Commands::Cpp(args) => subcommands::cpp::run(args),
        Commands::C(args) => subcommands::c::run(args),
        // Analysis
        Commands::Diff(args) => subcommands::diff::run(args),
        Commands::Audit(args) => subcommands::audit::run(args),
        Commands::Container(args) => subcommands::container::run(args),
        Commands::Snapshot(args) => subcommands::snapshot::run(args),
        // Mutation
        Commands::Patch(args) => subcommands::patch::run(args),
        Commands::HeaderInfer(args) => subcommands::header_infer::run(args),
        // Special
        Commands::Fileset(args) => subcommands::fileset::run(args),
        Commands::Cache(args) => subcommands::dyld_cache::run(args),
    }
}
