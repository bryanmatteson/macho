use std::ffi::OsString;
use std::io::Write;

use clap::{CommandFactory, Parser, ValueEnum};

/// Shared argument definitions.
pub mod args;
/// The output module.
pub mod output;
/// The subcommands module.
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
/// The Cli type.
pub struct Cli {
    #[command(flatten)]
    output: args::FormatArgs,

    #[command(subcommand)]
    command: Commands,
}

/// Output representation shared by every command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[non_exhaustive]
pub enum OutputFormat {
    /// Human-readable text.
    Text,
    /// Versioned JSON envelope.
    Json,
    /// SARIF 2.1 report (audit only).
    Sarif,
}

/// Return the live Clap command used by production dispatch.
pub fn clap_command() -> clap::Command {
    Cli::command()
}

/// Parse arguments through the production grammar without executing a command.
pub fn parse_only<I, S>(args: I) -> Result<(), clap::Error>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString> + Clone,
{
    Cli::try_parse_from(args).map(|_| ())
}

/// Package version used by both Clap and release checks.
pub const fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
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

impl Commands {
    fn name(&self) -> &'static str {
        match self {
            Self::Info(_) => "info",
            Self::Deps(_) => "deps",
            Self::Codesign(_) => "codesign",
            Self::Dwarf(_) => "dwarf",
            Self::Symbols(_) => "symbols",
            Self::Imports(_) => "imports",
            Self::Exports(_) => "exports",
            Self::Fixups(_) => "fixups",
            Self::Relocations(_) => "relocations",
            Self::Ranges(_) => "ranges",
            Self::Strings(_) => "strings",
            Self::Xrefs(_) => "xrefs",
            Self::Vtables(_) => "vtables",
            Self::Objc(_) => "objc",
            Self::Swift(_) => "swift",
            Self::Cpp(_) => "cpp",
            Self::C(_) => "c",
            Self::Diff(_) => "diff",
            Self::Audit(_) => "audit",
            Self::Container(_) => "container",
            Self::Snapshot(_) => "snapshot",
            Self::Patch(_) => "patch",
            Self::HeaderInfer(_) => "header-infer",
            Self::Fileset(_) => "fileset",
            Self::Cache(_) => "cache",
        }
    }

    fn supports_sarif(&self) -> bool {
        matches!(self, Self::Audit(_))
    }
}

/// Marker returned after a command produced a valid report that failed policy.
#[derive(Debug)]
pub(crate) struct PolicyFailure(pub(crate) String);

impl std::fmt::Display for PolicyFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for PolicyFailure {}

/// Marker for semantic argument combinations that Clap cannot express.
#[derive(Debug)]
pub(crate) struct UsageFailure(String);

impl std::fmt::Display for UsageFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for UsageFailure {}

pub(crate) fn usage_message(message: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(UsageFailure(message.into()))
}

/// Delivery-owned marker for failures while opening, mapping, decoding, or
/// selecting caller-provided input. Output and host-integration I/O must not
/// use this marker so those failures remain execution failures.
#[derive(Debug)]
pub(crate) struct InputFailure {
    message: String,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl InputFailure {
    fn message(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            source: None,
        }
    }

    fn with_source(
        message: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }
}

impl std::fmt::Display for InputFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for InputFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn std::error::Error + 'static))
    }
}

pub(crate) fn input_message(message: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(InputFailure::message(message))
}

pub(crate) fn input_result<T, E>(
    result: Result<T, E>,
    message: impl Into<String>,
) -> anyhow::Result<T>
where
    E: std::error::Error + Send + Sync + 'static,
{
    result.map_err(|source| anyhow::Error::new(InputFailure::with_source(message, source)))
}

/// Stable CLI failure category used only by the delivery layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CliErrorKind {
    /// Command-line grammar or argument failure.
    Usage,
    /// Input mapping, parsing, or selection failure.
    Input,
    /// Command execution or rendering failure.
    Execution,
    /// A completed report crossed a requested policy threshold.
    Policy,
}

/// Typed CLI error retaining its delivery category and original source chain.
#[derive(Debug)]
pub struct CliError {
    /// Stable delivery category.
    pub kind: CliErrorKind,
    source: anyhow::Error,
}

impl CliError {
    fn from_anyhow(source: anyhow::Error) -> Self {
        let kind = if source.downcast_ref::<PolicyFailure>().is_some() {
            CliErrorKind::Policy
        } else if source.downcast_ref::<UsageFailure>().is_some() {
            CliErrorKind::Usage
        } else if source.downcast_ref::<InputFailure>().is_some()
            || source.downcast_ref::<macho::ParseError>().is_some()
            || source
                .downcast_ref::<macho::analysis::AnalysisError>()
                .is_some_and(|error| error.kind == macho::analysis::AnalysisErrorKind::InvalidInput)
        {
            CliErrorKind::Input
        } else {
            CliErrorKind::Execution
        };
        Self { kind, source }
    }

    /// Stable diagnostic code corresponding to [`Self::kind`].
    pub const fn code(&self) -> &'static str {
        match self.kind {
            CliErrorKind::Usage => INVALID_ARGUMENTS_CODE,
            CliErrorKind::Input => INPUT_FAILED_CODE,
            CliErrorKind::Execution => EXECUTION_FAILED_CODE,
            CliErrorKind::Policy => POLICY_THRESHOLD_CODE,
        }
    }
}

const INVALID_ARGUMENTS_CODE: &str = "cli.usage.invalid_arguments";
const UNSUPPORTED_FORMAT_CODE: &str = "cli.usage.unsupported_format";
const INPUT_FAILED_CODE: &str = "cli.input.failed";
const EXECUTION_FAILED_CODE: &str = "cli.execution.failed";
const POLICY_THRESHOLD_CODE: &str = "cli.policy.threshold";

impl std::fmt::Display for CliError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{:#}", self.source)
    }
}

impl std::error::Error for CliError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.root_cause())
    }
}

#[derive(Debug)]
pub(crate) struct CliWarning {
    code: String,
    message: String,
}

/// The CliIo type.
pub struct CliIo<'a> {
    /// The stdout field.
    pub stdout: &'a mut dyn Write,
    /// The stderr field.
    pub stderr: &'a mut dyn Write,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// The ExitStatus type.
pub struct ExitStatus(u8);

impl ExitStatus {
    /// The SUCCESS constant.
    pub const SUCCESS: Self = Self(0);
    /// The EXECUTION_FAILURE constant.
    pub const EXECUTION_FAILURE: Self = Self(1);
    /// The USAGE_ERROR constant.
    pub const USAGE_ERROR: Self = Self(2);
    /// The POLICY_FAILURE constant.
    pub const POLICY_FAILURE: Self = Self(3);
    /// Performs code.
    pub const fn code(self) -> u8 {
        self.0
    }
}

/// The CapturedRun type.
pub struct CapturedRun {
    /// The code field.
    pub code: u8,
    /// The stdout field.
    pub stdout: Vec<u8>,
    /// The stderr field.
    pub stderr: Vec<u8>,
}

/// Performs run_captured.
pub fn run_captured<I, S>(args: I) -> CapturedRun
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut io = CliIo {
        stdout: &mut stdout,
        stderr: &mut stderr,
    };
    let status = run_from(
        std::iter::once(OsString::from("macho")).chain(args.into_iter().map(Into::into)),
        &mut io,
    );
    CapturedRun {
        code: status.code(),
        stdout,
        stderr,
    }
}

/// Performs run_from.
pub fn run_from<I, S>(args: I, io: &mut CliIo<'_>) -> ExitStatus
where
    I: IntoIterator<Item = S>,
    S: Into<OsString> + Clone,
{
    let args: Vec<OsString> = args.into_iter().map(Into::into).collect();
    let requested_format = pre_scan_format(&args);
    let requested_command = pre_scan_command(&args).unwrap_or_else(|| "macho".to_owned());

    match Cli::try_parse_from(args) {
        Ok(cli) => {
            let command_name = cli.command.name();
            let format = cli.output.format;
            if format == OutputFormat::Sarif && !cli.command.supports_sarif() {
                write_failure(
                    io.stderr,
                    requested_format,
                    command_name,
                    UNSUPPORTED_FORMAT_CODE,
                    "SARIF output is supported only by the audit command",
                );
                return ExitStatus::USAGE_ERROR;
            }

            let mut rendered = Vec::new();
            let mut warnings = Vec::new();
            match dispatch(cli.command, format, &mut rendered, &mut warnings) {
                Ok(()) => {
                    if let Err(error) = write_success(io.stdout, format, command_name, &rendered) {
                        write_failure(
                            io.stderr,
                            format,
                            command_name,
                            EXECUTION_FAILED_CODE,
                            &error.to_string(),
                        );
                        return ExitStatus::EXECUTION_FAILURE;
                    }
                    write_warnings(io.stderr, format, command_name, &warnings);
                    ExitStatus::SUCCESS
                }
                Err(err) if err.kind == CliErrorKind::Policy => {
                    if let Err(error) = write_success(io.stdout, format, command_name, &rendered) {
                        write_failure(
                            io.stderr,
                            format,
                            command_name,
                            EXECUTION_FAILED_CODE,
                            &error.to_string(),
                        );
                        return ExitStatus::EXECUTION_FAILURE;
                    }
                    write_warnings(io.stderr, format, command_name, &warnings);
                    write_failure(
                        io.stderr,
                        format,
                        command_name,
                        err.code(),
                        &err.to_string(),
                    );
                    ExitStatus::POLICY_FAILURE
                }
                Err(err) if err.kind == CliErrorKind::Usage => {
                    write_failure(
                        io.stderr,
                        format,
                        command_name,
                        err.code(),
                        &err.to_string(),
                    );
                    ExitStatus::USAGE_ERROR
                }
                Err(err) => {
                    write_failure(
                        io.stderr,
                        format,
                        command_name,
                        err.code(),
                        &err.to_string(),
                    );
                    ExitStatus::EXECUTION_FAILURE
                }
            }
        }
        Err(err) => {
            let code = err.exit_code();
            if code == 0 {
                let _ = write!(io.stdout, "{err}");
                ExitStatus::SUCCESS
            } else {
                write_failure(
                    io.stderr,
                    requested_format,
                    &requested_command,
                    INVALID_ARGUMENTS_CODE,
                    &err.to_string(),
                );
                ExitStatus::USAGE_ERROR
            }
        }
    }
}

fn dispatch(
    command: Commands,
    format: OutputFormat,
    out: &mut dyn Write,
    warnings: &mut Vec<CliWarning>,
) -> Result<(), CliError> {
    let result = match command {
        // Structure
        Commands::Info(args) => subcommands::info::run(args, format, out, warnings),
        Commands::Deps(args) => subcommands::deps::run(args, format, out),
        Commands::Codesign(args) => subcommands::codesign::run(args, format, out),
        Commands::Dwarf(args) => subcommands::dwarf::run(args, format, out),
        // Symbols
        Commands::Symbols(args) => subcommands::symbols::run(args, format, out),
        Commands::Imports(args) => subcommands::imports::run(args, format, out),
        Commands::Exports(args) => subcommands::exports::run(args, format, out),
        Commands::Fixups(args) => subcommands::fixups::run(args, format, out),
        Commands::Relocations(args) => subcommands::relocations::run(args, format, out),
        Commands::Ranges(args) => subcommands::data_surface::run_ranges(args, format, out),
        // Data
        Commands::Strings(args) => subcommands::data_surface::run_strings(args, format, out),
        Commands::Xrefs(args) => subcommands::data_surface::run_xrefs(args, format, out),
        Commands::Vtables(args) => subcommands::data_surface::run_vtables(args, format, out),
        // Language
        Commands::Objc(args) => subcommands::objc::run(args, format, out),
        Commands::Swift(args) => subcommands::swift::run(args, format, out),
        Commands::Cpp(args) => subcommands::cpp::run(args, format, out),
        Commands::C(args) => subcommands::c::run(args, format, out),
        // Analysis
        Commands::Diff(args) => subcommands::diff::run(args, format, out),
        Commands::Audit(args) => subcommands::audit::run(args, format, out),
        Commands::Container(args) => subcommands::container::run(args, format, out),
        Commands::Snapshot(args) => subcommands::snapshot::run(args, out),
        // Mutation
        Commands::Patch(args) => subcommands::patch::run(args, format, out),
        Commands::HeaderInfer(args) => subcommands::header_infer::run(args, format, out),
        // Special
        Commands::Fileset(args) => subcommands::fileset::run(args, format, out),
        Commands::Cache(args) => subcommands::dyld_cache::run(args, format, out),
    };
    result.map_err(CliError::from_anyhow)
}

fn pre_scan_format(args: &[OsString]) -> OutputFormat {
    for (index, arg) in args.iter().enumerate() {
        let arg = arg.to_string_lossy();
        let value = arg
            .strip_prefix("--format=")
            .map(str::to_owned)
            .or_else(|| {
                if arg == "--format" {
                    args.get(index + 1)
                        .map(|value| value.to_string_lossy().into_owned())
                } else {
                    None
                }
            });
        match value.as_deref() {
            Some("json") => return OutputFormat::Json,
            Some("sarif") => return OutputFormat::Sarif,
            Some("text") => return OutputFormat::Text,
            _ => {}
        }
    }
    OutputFormat::Text
}

fn pre_scan_command(args: &[OsString]) -> Option<String> {
    args.iter().skip(1).map(|arg| arg.to_str()).find_map(|arg| {
        arg.filter(|arg| !arg.starts_with('-') && !matches!(*arg, "text" | "json" | "sarif"))
            .map(str::to_owned)
    })
}

fn write_success(
    out: &mut dyn Write,
    format: OutputFormat,
    command: &str,
    bytes: &[u8],
) -> anyhow::Result<()> {
    match format {
        OutputFormat::Text | OutputFormat::Sarif => {
            out.write_all(bytes)?;
        }
        OutputFormat::Json => {
            let data = serde_json::from_slice::<serde_json::Value>(bytes)
                .map_err(|error| anyhow::anyhow!("command returned a non-JSON report: {error}"))?;
            let envelope = serde_json::json!({
                "schema_version": 1,
                "command": command,
                "ok": true,
                "data": data,
                "diagnostics": [],
            });
            writeln!(
                out,
                "{}",
                serde_json::to_string_pretty(&envelope).expect("JSON envelope serializes")
            )?;
        }
    }
    Ok(())
}

fn write_failure(
    out: &mut dyn Write,
    format: OutputFormat,
    command: &str,
    code: &str,
    message: &str,
) {
    if format == OutputFormat::Json {
        let envelope = serde_json::json!({
            "schema_version": 1,
            "command": command,
            "ok": false,
            "data": null,
            "diagnostics": [{ "code": code, "message": message }],
        });
        let _ = writeln!(
            out,
            "{}",
            serde_json::to_string_pretty(&envelope).expect("JSON envelope serializes")
        );
    } else {
        let _ = writeln!(out, "Error: {message}");
    }
}

fn write_warnings(
    out: &mut dyn Write,
    format: OutputFormat,
    command: &str,
    warnings: &[CliWarning],
) {
    if warnings.is_empty() {
        return;
    }
    if format == OutputFormat::Json {
        let diagnostics = warnings
            .iter()
            .map(|warning| serde_json::json!({ "code": warning.code, "message": warning.message }))
            .collect::<Vec<_>>();
        let envelope = serde_json::json!({
            "schema_version": 1,
            "command": command,
            "ok": true,
            "data": null,
            "diagnostics": diagnostics,
        });
        let _ = writeln!(out, "{envelope}");
    } else {
        for warning in warnings {
            let _ = writeln!(out, "Warning [{}]: {}", warning.code, warning.message);
        }
    }
}
