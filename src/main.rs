use clap::Parser;

mod commands;
mod output;

#[derive(Parser)]
#[command(name = "macho", version, about = "Mach-O binary inspection tool")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Display headers, segments, sections, and load commands
    Inspect(commands::inspect::InspectArgs),
    /// List symbols from the symbol table
    Symbols(commands::symbols::SymbolsArgs),
    /// List relocations per section
    Relocations(commands::relocations::RelocationsArgs),
    /// List exported symbols from the exports trie
    Exports(commands::exports::ExportsArgs),
    /// List chained fixup imports
    Imports(commands::imports::ImportsArgs),
    /// Walk chained fixup chains showing binds and rebases
    Fixups(commands::fixups::FixupsArgs),
    /// Display Objective-C metadata (classes, categories, protocols)
    Objc(commands::objc::ObjCArgs),
    /// Inspect code signature (entitlements, code directory, CMS)
    Codesign(commands::codesign::CodesignArgs),
    /// Dump a full JSON snapshot of the binary
    Snapshot(commands::snapshot::SnapshotArgs),
    /// Compare two Mach-O binaries semantically
    Diff(commands::diff::DiffArgs),
    /// Run security and policy audit on a binary
    Audit(commands::audit::AuditArgs),
    /// Apply structural patches to a binary
    Patch(commands::patch::PatchArgs),
    /// Discover Swift types from symbol metadata
    Swift(commands::swift::SwiftArgs),
    /// Analyze container structure (fat binary parity, fileset entries)
    Container(commands::container::ContainerArgs),
    /// List and inspect fileset entries
    Fileset(commands::fileset::FilesetArgs),
    /// Analyze dependencies, imports, exports, and compatibility
    Deps(commands::deps::DepsArgs),
    /// Discover and search string regions
    Strings(commands::data_surface::StringsArgs),
    /// Analyze C++ vtables
    Vtables(commands::data_surface::VtablesArgs),
    /// List symbol ownership ranges by virtual address
    Ranges(commands::data_surface::RangesArgs),
    /// List cross-references (stubs, fixups, branches)
    Xrefs(commands::data_surface::XrefsArgs),
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Inspect(args) => commands::inspect::run(args),
        Commands::Symbols(args) => commands::symbols::run(args),
        Commands::Relocations(args) => commands::relocations::run(args),
        Commands::Exports(args) => commands::exports::run(args),
        Commands::Imports(args) => commands::imports::run(args),
        Commands::Fixups(args) => commands::fixups::run(args),
        Commands::Objc(args) => commands::objc::run(args),
        Commands::Codesign(args) => commands::codesign::run(args),
        Commands::Snapshot(args) => commands::snapshot::run(args),
        Commands::Diff(args) => commands::diff::run(args),
        Commands::Audit(args) => commands::audit::run(args),
        Commands::Patch(args) => commands::patch::run(args),
        Commands::Swift(args) => commands::swift::run(args),
        Commands::Container(args) => commands::container::run(args),
        Commands::Fileset(args) => commands::fileset::run(args),
        Commands::Deps(args) => commands::deps::run(args),
        Commands::Strings(args) => commands::data_surface::run_strings(args),
        Commands::Vtables(args) => commands::data_surface::run_vtables(args),
        Commands::Ranges(args) => commands::data_surface::run_ranges(args),
        Commands::Xrefs(args) => commands::data_surface::run_xrefs(args),
    }
}
