pub mod codesign;
pub mod data_surface;
pub mod deps;
pub mod exports;
pub mod fixups;
pub mod imports;
pub mod inspect;
pub mod relocations;
pub mod symbols;

use anyhow::Result;
use std::path::PathBuf;

use crate::commands::subcommands::dwarf;

#[derive(clap::Args)]
pub struct ViewArgs {
    #[command(subcommand)]
    action: ViewAction,
}

#[derive(clap::Subcommand)]
enum ViewAction {
    Header(InspectViewArgs),
    LoadCommands(InspectViewArgs),
    Segments(InspectViewArgs),
    Sections(InspectViewArgs),
    Symbols(self::symbols::SymbolsArgs),
    Relocations(self::relocations::RelocationsArgs),
    Imports(self::imports::ImportsArgs),
    Exports(self::exports::ExportsArgs),
    Fixups(self::fixups::FixupsArgs),
    Strings(self::data_surface::StringsArgs),
    Xrefs(self::data_surface::XrefsArgs),
    #[command(name = "code-signature", visible_alias = "codesign")]
    CodeSignature(self::codesign::CodesignArgs),
    Dwarf(dwarf::ViewDwarfArgs),
    Dependencies(self::deps::DepsArgs),
}

#[derive(clap::Args)]
struct InspectViewArgs {
    path: PathBuf,
    #[arg(long)]
    arch: Option<String>,
    #[arg(long)]
    validate: bool,
}

pub fn run(args: ViewArgs) -> Result<()> {
    match args.action {
        ViewAction::Header(args) => run_inspect_scope(args, self::inspect::InspectScope::Header),
        ViewAction::LoadCommands(args) => {
            run_inspect_scope(args, self::inspect::InspectScope::LoadCommands)
        }
        ViewAction::Segments(args) => {
            run_inspect_scope(args, self::inspect::InspectScope::Segments)
        }
        ViewAction::Sections(args) => {
            run_inspect_scope(args, self::inspect::InspectScope::Sections)
        }
        ViewAction::Symbols(args) => self::symbols::run(args),
        ViewAction::Relocations(args) => self::relocations::run(args),
        ViewAction::Imports(args) => self::imports::run(args),
        ViewAction::Exports(args) => self::exports::run(args),
        ViewAction::Fixups(args) => self::fixups::run(args),
        ViewAction::Strings(args) => self::data_surface::run_strings(args),
        ViewAction::Xrefs(args) => self::data_surface::run_xrefs(args),
        ViewAction::CodeSignature(args) => self::codesign::run(args),
        ViewAction::Dwarf(args) => dwarf::run_view(args),
        ViewAction::Dependencies(args) => self::deps::run(args),
    }
}

fn run_inspect_scope(args: InspectViewArgs, scope: self::inspect::InspectScope) -> Result<()> {
    self::inspect::run_scoped(
        self::inspect::InspectArgs::new(args.path, args.arch, args.validate),
        scope,
    )
}
