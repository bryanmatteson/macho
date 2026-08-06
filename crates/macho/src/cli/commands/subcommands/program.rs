//! Selective command-line access to Macho-owned whole-program recovery.

use std::io::Write;

use anyhow::{Context, Result};
use serde::Serialize;

use crate::cli::analysis::dependency_index::StaticProgramUniverse;
use crate::cli::analysis::program::{
    ProgramRecoveryLimits, ProgramRecoveryLimitsFile, ProgramRecoveryRequest, ProgramRecoveryStage,
    RecoveredProgram,
};
use crate::cli::analysis::recovery::{
    ProgramCoverage, ProgramCoverageDimension, ProgramSubjectKey, RecoveryGuide,
    RecoveryGuideValidation, RecoveryQuestion, RecoveryQuestionKind, RecoverySignalKind,
};
use crate::cli::commands::OutputFormat;
use crate::cli::commands::args::{AnalysisLimitArgs, ArchitectureArgs, InputArgs};
use crate::cli::commands::subcommands::common::{for_each_selected_mach, read_input};

/// Arguments for selective whole-program recovery.
#[derive(clap::Args)]
pub struct ProgramArgs {
    #[command(flatten)]
    input: InputArgs,
    #[command(flatten)]
    selection: ArchitectureArgs,
    #[command(flatten)]
    limits: AnalysisLimitArgs,
    /// Strict JSON file containing the complete nested `ProgramRecoveryLimits` contract.
    #[arg(long, value_name = "PATH")]
    limits_file: Option<std::path::PathBuf>,
    /// Recovery stage to execute (repeatable; declared dependencies are added).
    #[arg(
        long,
        value_enum,
        action = clap::ArgAction::Append,
        required_unless_present_any = ["all", "questions", "guide", "coverage", "load_dependencies"]
    )]
    stage: Vec<ProgramStageArg>,
    /// Execute every recovery stage.
    #[arg(long, conflicts_with = "stage")]
    all: bool,
    /// Recursively load statically named filesystem dependencies for the selected CPU tuple.
    #[arg(long, conflicts_with_all = ["guide", "validate_guide", "questions"])]
    load_dependencies: bool,
    /// Additional directory searched by dependency basename (repeatable).
    #[arg(long, value_name = "PATH", requires = "load_dependencies")]
    dependency_search_path: Vec<std::path::PathBuf>,
    /// Offline dyld shared-cache primary used to satisfy named system dependencies.
    #[arg(long, value_name = "PATH", requires = "load_dependencies")]
    dyld_cache: Option<std::path::PathBuf>,
    /// List stable recovery questions and the signals that make them ambiguous.
    #[arg(long)]
    questions: bool,
    /// Report truth-aware coverage for the selected stages, or for the complete
    /// program surface when no stages are named.
    #[arg(long)]
    coverage: bool,
    /// Apply a strict versioned recovery guide from JSON.
    #[arg(long, value_name = "PATH")]
    guide: Option<std::path::PathBuf>,
    /// Validate the supplied guide against each exact selected image without
    /// running a guided rebuild.
    #[arg(long, requires = "guide")]
    validate_guide: bool,
    /// Admit plausible untyped text sections to string recovery.
    #[arg(long)]
    heuristic_strings: bool,
    /// Maximum aggregate work units for indirect-target value flow.
    #[arg(long, value_name = "UNITS")]
    max_indirect_value_flow_work: Option<u64>,
    /// Maximum value-flow work units consumed by one function.
    #[arg(long, value_name = "UNITS")]
    max_indirect_value_flow_work_per_function: Option<u64>,
    /// Maximum distinct abstract values retained per register at any join.
    #[arg(long, value_name = "COUNT")]
    max_indirect_values_per_register: Option<usize>,
    /// Maximum loop-carried values per register before widening to unknown.
    #[arg(long, value_name = "COUNT")]
    max_indirect_loop_values_per_register: Option<usize>,
    /// Maximum candidate destinations retained per indirect transfer.
    #[arg(long, value_name = "COUNT")]
    max_indirect_candidates_per_transfer: Option<usize>,
    /// Maximum decoded instructions retained per function CFG.
    #[arg(long, value_name = "COUNT")]
    max_cfg_instructions_per_function: Option<usize>,
    /// Maximum basic blocks retained per function CFG.
    #[arg(long, value_name = "COUNT")]
    max_cfg_blocks_per_function: Option<usize>,
    /// Maximum edges retained per function CFG.
    #[arg(long, value_name = "COUNT")]
    max_cfg_edges_per_function: Option<usize>,
    /// Maximum decode gaps retained per function CFG.
    #[arg(long, value_name = "COUNT")]
    max_cfg_gaps_per_function: Option<usize>,
    /// Maximum jump tables retained per function CFG.
    #[arg(long, value_name = "COUNT")]
    max_cfg_jump_tables_per_function: Option<usize>,
    /// Maximum entries retained from any one jump table.
    #[arg(long, value_name = "COUNT")]
    max_cfg_jump_table_entries: Option<usize>,
    /// Maximum compact-unwind, linked-unwind, and exception-frame records.
    #[arg(long, value_name = "COUNT")]
    max_exception_records: Option<usize>,
    /// Maximum bytes read from one unwind metadata section.
    #[arg(long, value_name = "BYTES")]
    max_exception_section_bytes: Option<usize>,
    /// Maximum bytes examined from any one LSDA.
    #[arg(long, value_name = "BYTES")]
    max_exception_lsda_bytes: Option<usize>,
    /// Maximum semantic LSDA call-site records.
    #[arg(long, value_name = "COUNT")]
    max_exception_call_sites: Option<usize>,
    /// Maximum semantic LSDA action-chain records.
    #[arg(long, value_name = "COUNT")]
    max_exception_actions: Option<usize>,
    /// Maximum evaluated CFI state rows.
    #[arg(long, value_name = "COUNT")]
    max_exception_cfi_rows: Option<usize>,
    /// Maximum named dependencies retained.
    #[arg(long, value_name = "COUNT")]
    max_dependencies: Option<usize>,
    /// Maximum selected images admitted to a static universe.
    #[arg(long, value_name = "COUNT")]
    max_dependency_images: Option<usize>,
    /// Maximum cross-image import resolutions.
    #[arg(long, value_name = "COUNT")]
    max_dependency_resolutions: Option<usize>,
    /// Maximum global/static data identities.
    #[arg(long, value_name = "COUNT")]
    max_data_objects: Option<usize>,
    /// Maximum best-known function signatures.
    #[arg(long, value_name = "COUNT")]
    max_function_signatures: Option<usize>,
    /// Maximum stack-frame summaries.
    #[arg(long, value_name = "COUNT")]
    max_stack_frames: Option<usize>,
    /// Maximum DWARF local and parameter records.
    #[arg(long, value_name = "COUNT")]
    max_local_variables: Option<usize>,
}

/// Command-line spelling of one independently selectable recovery stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ProgramStageArg {
    /// Segments, sections, protections, and address translation.
    ImageLayout,
    /// Fixups, binds, relocations, stubs, and authenticated pointers.
    Pointers,
    /// Nlist, export, and import symbols.
    Symbols,
    /// Typed and optionally heuristic strings.
    Strings,
    /// Objective-C runtime metadata.
    Objc,
    /// Swift ABI metadata.
    Swift,
    /// DWARF records and source mappings.
    Dwarf,
    /// Function identities, evidence, extents, and ownership.
    Functions,
    /// Basic blocks and control-flow graphs.
    ControlFlow,
    /// Conserved executable-section byte classifications.
    ExecutableBytes,
    /// Direct call graph.
    DirectCalls,
    /// Tail calls and forwarding thunks.
    Transfers,
    /// Indirect transfers and dynamic dispatch.
    IndirectCalls,
    /// Format and instruction cross-references.
    Xrefs,
    /// Itanium RTTI, vtables, and type relationships.
    Rtti,
    /// Compact-unwind and exception-frame metadata.
    Exceptions,
    /// Named dependencies and runtime-open frontiers.
    Dependencies,
    /// Data objects, signatures, frames, and local variables.
    Semantics,
}

impl From<ProgramStageArg> for ProgramRecoveryStage {
    fn from(value: ProgramStageArg) -> Self {
        match value {
            ProgramStageArg::ImageLayout => Self::ImageLayout,
            ProgramStageArg::Pointers => Self::Pointers,
            ProgramStageArg::Symbols => Self::Symbols,
            ProgramStageArg::Strings => Self::Strings,
            ProgramStageArg::Objc => Self::Objc,
            ProgramStageArg::Swift => Self::Swift,
            ProgramStageArg::Dwarf => Self::Dwarf,
            ProgramStageArg::Functions => Self::Functions,
            ProgramStageArg::ControlFlow => Self::ControlFlow,
            ProgramStageArg::ExecutableBytes => Self::ExecutableBytes,
            ProgramStageArg::DirectCalls => Self::DirectCalls,
            ProgramStageArg::Transfers => Self::Transfers,
            ProgramStageArg::IndirectCalls => Self::IndirectCalls,
            ProgramStageArg::Xrefs => Self::Xrefs,
            ProgramStageArg::Rtti => Self::Rtti,
            ProgramStageArg::Exceptions => Self::Exceptions,
            ProgramStageArg::Dependencies => Self::Dependencies,
            ProgramStageArg::Semantics => Self::Semantics,
        }
    }
}

#[derive(Serialize)]
struct ProgramSlice {
    architecture: String,
    coverage: ProgramCoverage,
    program: RecoveredProgram,
}

#[derive(Serialize)]
struct GuideValidationSlice {
    architecture: String,
    validation: RecoveryGuideValidation,
}

#[derive(Serialize)]
struct ProgramUniverseSlice {
    architecture: String,
    universe: StaticProgramUniverse,
}

/// Recover only the selected stages and render their typed records and receipts.
pub fn run(args: ProgramArgs, format: OutputFormat, out: &mut dyn Write) -> Result<()> {
    let bytes = read_input(&args.input.path)?;
    let container = crate::parse(&bytes)
        .with_context(|| format!("failed to parse {}", args.input.path.display()))?;
    let guide = args
        .guide
        .as_ref()
        .map(|path| {
            let bytes = std::fs::read(path)
                .with_context(|| format!("read recovery guide {}", path.display()))?;
            serde_json::from_slice::<RecoveryGuide>(&bytes)
                .with_context(|| format!("parse recovery guide {}", path.display()))
        })
        .transpose()?;
    let mut stages = if args.all
        || (guide.is_some() && args.stage.is_empty())
        || (args.coverage && args.stage.is_empty())
    {
        ProgramRecoveryStage::all().to_vec()
    } else {
        args.stage.into_iter().map(Into::into).collect()
    };
    if args.questions && !stages.contains(&ProgramRecoveryStage::ExecutableBytes) {
        stages.push(ProgramRecoveryStage::ExecutableBytes);
    }
    let mut limits = if let Some(path) = &args.limits_file {
        let bytes = std::fs::read(path)
            .with_context(|| format!("read program limits {}", path.display()))?;
        serde_json::from_slice::<ProgramRecoveryLimitsFile>(&bytes)
            .with_context(|| format!("parse program limits {}", path.display()))?
            .validate()
            .with_context(|| format!("validate program limits {}", path.display()))?
    } else {
        recovery_limits(&args.limits)
    };
    limits.strings.include_heuristic_regions = args.heuristic_strings;
    apply_indirect_limits(
        &mut limits,
        args.max_indirect_value_flow_work,
        args.max_indirect_value_flow_work_per_function,
        args.max_indirect_values_per_register,
        args.max_indirect_loop_values_per_register,
        args.max_indirect_candidates_per_transfer,
    );
    apply_control_flow_limits(
        &mut limits,
        args.max_cfg_instructions_per_function,
        args.max_cfg_blocks_per_function,
        args.max_cfg_edges_per_function,
        args.max_cfg_gaps_per_function,
        args.max_cfg_jump_tables_per_function,
        args.max_cfg_jump_table_entries,
    );
    apply_exception_limits(
        &mut limits,
        args.max_exception_records,
        args.max_exception_section_bytes,
        args.max_exception_lsda_bytes,
        args.max_exception_call_sites,
        args.max_exception_actions,
        args.max_exception_cfi_rows,
    );
    apply_dependency_and_semantic_limits(
        &mut limits,
        args.max_dependencies,
        args.max_dependency_images,
        args.max_dependency_resolutions,
        args.max_data_objects,
        args.max_function_signatures,
        args.max_stack_frames,
        args.max_local_variables,
    );
    if args.validate_guide {
        let guide = guide
            .as_ref()
            .expect("clap requires --guide with --validate-guide");
        let mut validations = Vec::new();
        for_each_selected_mach(
            &container,
            args.selection.arch.as_deref(),
            |image, architecture, _| {
                let request = ProgramRecoveryRequest::new(stages.iter().copied(), limits);
                let program = RecoveredProgram::recover(image, request)
                    .with_context(|| format!("recover {architecture} validation base"))?;
                validations.push(GuideValidationSlice {
                    architecture: architecture.to_owned(),
                    validation: program.validate_guide_for_image(image, guide),
                });
                Ok(())
            },
        )?;
        if format.is_json() {
            if validations.len() == 1 {
                serde_json::to_writer_pretty(&mut *out, &validations[0])?;
            } else {
                serde_json::to_writer_pretty(&mut *out, &validations)?;
            }
            writeln!(out)?;
        } else {
            for (ordinal, slice) in validations.iter().enumerate() {
                if ordinal != 0 {
                    writeln!(out)?;
                }
                writeln!(
                    out,
                    "{} guide: {:?}",
                    slice.architecture, slice.validation.applicability
                )?;
                for decision in &slice.validation.decisions {
                    writeln!(
                        out,
                        "  decision {}: {:?} [{}]",
                        decision.decision_index, decision.applicability, decision.reason
                    )?;
                }
            }
        }
        return Ok(());
    }
    if args.load_dependencies {
        let mut universes = Vec::new();
        for_each_selected_mach(
            &container,
            args.selection.arch.as_deref(),
            |image, architecture, _| {
                let request = ProgramRecoveryRequest::new(stages.iter().copied(), limits);
                let universe = StaticProgramUniverse::recover_filesystem_with_cache(
                    &args.input.path,
                    image.header().cpu_type().0,
                    image.header().cpu_subtype().0,
                    request,
                    limits.dependencies,
                    &args.dependency_search_path,
                    args.dyld_cache.as_deref(),
                )
                .with_context(|| format!("recover {architecture} dependency universe"))?;
                universes.push(ProgramUniverseSlice {
                    architecture: architecture.to_owned(),
                    universe,
                });
                Ok(())
            },
        )?;
        if format.is_json() {
            if universes.len() == 1 {
                serde_json::to_writer_pretty(&mut *out, &universes[0])?;
            } else {
                serde_json::to_writer_pretty(&mut *out, &universes)?;
            }
            writeln!(out)?;
        } else {
            for (ordinal, slice) in universes.iter().enumerate() {
                if ordinal != 0 {
                    writeln!(out)?;
                }
                writeln!(
                    out,
                    "{} universe: {} images, {} resolutions",
                    slice.architecture,
                    slice.universe.images.len(),
                    slice.universe.resolutions.len()
                )?;
                for item in &slice.universe.discovery {
                    writeln!(
                        out,
                        "  {}: {}{}",
                        item.install_name,
                        item.status,
                        item.resolved_path
                            .as_deref()
                            .map(|path| format!(" ({path})"))
                            .unwrap_or_default()
                    )?;
                }
                if !slice.universe.reasons.is_empty() {
                    writeln!(out, "  frontiers: {}", slice.universe.reasons.join(", "))?;
                }
                if let Some(continuation) = &slice.universe.continuation {
                    writeln!(out, "  continuation: {continuation}")?;
                }
            }
        }
        return Ok(());
    }
    let mut slices = Vec::new();
    for_each_selected_mach(
        &container,
        args.selection.arch.as_deref(),
        |image, architecture, _| {
            let request = ProgramRecoveryRequest::new(stages.iter().copied(), limits);
            let program = match &guide {
                Some(guide) => RecoveredProgram::recover_with_guide(image, request, guide),
                None => RecoveredProgram::recover(image, request),
            }
            .with_context(|| format!("recover {architecture} program"))?;
            let coverage = program.coverage();
            slices.push(ProgramSlice {
                architecture: architecture.to_owned(),
                coverage,
                program,
            });
            Ok(())
        },
    )?;
    if format.is_json() {
        if slices.len() == 1 {
            serde_json::to_writer_pretty(&mut *out, &slices[0])?;
        } else {
            serde_json::to_writer_pretty(&mut *out, &slices)?;
        }
        writeln!(out)?;
    } else {
        for (ordinal, slice) in slices.iter().enumerate() {
            if ordinal != 0 {
                writeln!(out)?;
            }
            writeln!(
                out,
                "{}: {:?}",
                slice.architecture,
                slice.program.completeness().status
            )?;
            for receipt in &slice.program.completeness().stages {
                let selected = if receipt.requested {
                    "requested"
                } else {
                    "dependency"
                };
                write!(
                    out,
                    "  {:?}: {:?} ({selected})",
                    receipt.stage, receipt.status
                )?;
                if !receipt.reasons.is_empty() {
                    write!(out, " [{}]", receipt.reasons.join(", "))?;
                }
                writeln!(out)?;
            }
            if args.coverage {
                writeln!(out, "  Coverage:")?;
                render_coverage(out, "executable bytes", &slice.coverage.executable_bytes)?;
                render_coverage(out, "functions", &slice.coverage.functions)?;
                render_coverage(out, "control flow", &slice.coverage.control_flow)?;
                render_coverage(out, "direct calls", &slice.coverage.direct_calls)?;
                render_coverage(out, "references", &slice.coverage.references)?;
                render_coverage(
                    out,
                    "indirect transfers",
                    &slice.coverage.indirect_transfers,
                )?;
            }
            if let Some(application) = slice.program.guide_application() {
                writeln!(
                    out,
                    "  Guide preview: {:?}",
                    application.validation.applicability
                )?;
                for decision in &application.decisions {
                    writeln!(
                        out,
                        "    decision {}: {:?} [{}]",
                        decision.decision_index, decision.status, decision.reason
                    )?;
                }
                let delta = application.delta.summary;
                writeln!(
                    out,
                    "  Recovery delta: +{} -{} ~{} resolved={} newly-unresolved={}",
                    delta.added,
                    delta.removed,
                    delta.reclassified,
                    delta.resolved,
                    delta.newly_unresolved
                )?;
                writeln!(out, "  Coverage impact:")?;
                render_coverage_change(
                    out,
                    "executable bytes",
                    &application.coverage_delta.before.executable_bytes,
                    &application.coverage_delta.after.executable_bytes,
                )?;
                render_coverage_change(
                    out,
                    "functions",
                    &application.coverage_delta.before.functions,
                    &application.coverage_delta.after.functions,
                )?;
                render_coverage_change(
                    out,
                    "control flow",
                    &application.coverage_delta.before.control_flow,
                    &application.coverage_delta.after.control_flow,
                )?;
                render_coverage_change(
                    out,
                    "direct calls",
                    &application.coverage_delta.before.direct_calls,
                    &application.coverage_delta.after.direct_calls,
                )?;
                render_coverage_change(
                    out,
                    "references",
                    &application.coverage_delta.before.references,
                    &application.coverage_delta.after.references,
                )?;
                render_coverage_change(
                    out,
                    "indirect transfers",
                    &application.coverage_delta.before.indirect_transfers,
                    &application.coverage_delta.after.indirect_transfers,
                )?;
                writeln!(out, "  Changed subjects:")?;
                for record in &application.delta.records {
                    writeln!(
                        out,
                        "    {:?} {:?}: {:?} (decisions: {:?})",
                        record.layer, record.kind, record.subject, record.derivations
                    )?;
                }
            }
            if args.questions {
                writeln!(
                    out,
                    "  Recovery questions: {}",
                    slice.program.questions().len()
                )?;
                for question in slice.program.questions() {
                    render_question(out, question)?;
                }
            }
        }
    }
    Ok(())
}

fn render_coverage(
    out: &mut dyn Write,
    label: &str,
    coverage: &ProgramCoverageDimension,
) -> Result<()> {
    writeln!(
        out,
        "    {label}: denominator={:?}, established={}, guided={}, candidate={}, conflicted={}, rejected={}, unresolved={}, omitted={}, unavailable={}",
        coverage.denominator,
        coverage.independently_established,
        coverage.caller_guided,
        coverage.candidate,
        coverage.conflicted,
        coverage.rejected,
        coverage.unresolved,
        coverage.budget_omitted,
        coverage.unavailable,
    )?;
    if !coverage.reasons.is_empty() {
        writeln!(out, "      reasons: {}", coverage.reasons.join(", "))?;
    }
    Ok(())
}

fn render_coverage_change(
    out: &mut dyn Write,
    label: &str,
    before: &ProgramCoverageDimension,
    after: &ProgramCoverageDimension,
) -> Result<()> {
    writeln!(
        out,
        "    {label}: established {} -> {}, guided {} -> {}, candidate {} -> {}, conflicted {} -> {}, unresolved {} -> {}, omitted {} -> {}",
        before.independently_established,
        after.independently_established,
        before.caller_guided,
        after.caller_guided,
        before.candidate,
        after.candidate,
        before.conflicted,
        after.conflicted,
        before.unresolved,
        after.unresolved,
        before.budget_omitted,
        after.budget_omitted,
    )?;
    Ok(())
}

fn render_question(out: &mut dyn Write, question: &RecoveryQuestion) -> Result<()> {
    match (&question.kind, &question.subject) {
        (
            RecoveryQuestionKind::ByteRole,
            ProgramSubjectKey::ExecutableByteRange {
                start,
                end_exclusive,
                ..
            },
        ) => writeln!(out, "    Code or data at {start:#x}..{end_exclusive:#x}?")?,
        (
            RecoveryQuestionKind::FunctionEntry | RecoveryQuestionKind::FunctionRelationship,
            ProgramSubjectKey::FunctionCandidate { address },
        ) => writeln!(
            out,
            "    Is {address:#x} a standalone function or part of another one?"
        )?,
        _ => writeln!(out, "    {:?}: {:?}", question.kind, question.subject)?,
    }
    writeln!(out, "      Why this is unclear")?;
    for signal in &question.signals {
        match (&signal.key.kind, &signal.key.subject) {
            (
                RecoverySignalKind::JumpTable,
                ProgramSubjectKey::JumpTable {
                    instruction_address,
                    table_address,
                    end_exclusive,
                },
            ) => writeln!(
                out,
                "        jump table {table_address:#x}..{end_exclusive:#x} dispatched at {instruction_address:#x}"
            )?,
            (RecoverySignalKind::FunctionEntry, ProgramSubjectKey::Function { entry }) => {
                writeln!(out, "        established function entry at {entry:#x}")?;
            }
            (
                RecoverySignalKind::FunctionEntryCandidate,
                ProgramSubjectKey::FunctionCandidate { address },
            ) => match signal.key.source_address {
                Some(source) => writeln!(
                    out,
                    "        candidate entry {address:#x} observed from {source:#x} ({:?})",
                    signal.key.evidence_source
                )?,
                None => writeln!(out, "        candidate function entry at {address:#x}")?,
            },
            (RecoverySignalKind::RangeOwnership, ProgramSubjectKey::Function { entry }) => {
                writeln!(out, "        current range ownership points to {entry:#x}")?;
            }
            (RecoverySignalKind::InlineLiteral, _) => {
                writeln!(
                    out,
                    "        decoded instruction establishes inline literal data"
                )?;
            }
            _ => writeln!(
                out,
                "        {:?}: {:?}",
                signal.key.kind, signal.key.subject
            )?,
        }
    }
    writeln!(
        out,
        "      Available interpretations: {}",
        question.choices.len()
    )?;
    Ok(())
}

fn recovery_limits(args: &AnalysisLimitArgs) -> ProgramRecoveryLimits {
    let mut limits = ProgramRecoveryLimits::default();
    let functions = args.max_ranges.max(1);
    let references = args.max_xrefs.max(1);
    let decoded_bytes = args.max_decoded_bytes.max(1);
    limits.strings.max_strings = args.max_strings.max(1);
    limits.strings.max_scanned_bytes = decoded_bytes;
    limits.functions.max_functions = functions;
    limits.functions.max_decoded_bytes = decoded_bytes;
    limits.control_flow.max_functions = functions;
    limits.control_flow.max_decoded_bytes = decoded_bytes;
    limits.executable_bytes.max_sections = functions;
    limits.executable_bytes.max_bytes = decoded_bytes;
    limits.executable_bytes.max_spans = references;
    limits.direct_calls.max_nodes = functions;
    limits.direct_calls.max_examined_callsites = references;
    limits.direct_calls.max_edges = references;
    limits.direct_calls.max_unresolved_callsites = references;
    limits.transfers.max_functions = functions;
    limits.transfers.max_examined_exits = references;
    limits.transfers.max_transfers = references;
    limits.indirect_calls.max_functions = functions;
    limits.indirect_calls.max_transfers = references;
    limits.xrefs.max_refs = references;
    limits.xrefs.max_decoded_bytes = decoded_bytes;
    limits.xrefs.max_value_flow_work = u64::try_from(decoded_bytes)
        .unwrap_or(u64::MAX)
        .saturating_mul(16)
        .max(1);
    limits.rtti.vtables.max_records = u64::try_from(args.max_vtables.max(1)).unwrap_or(u64::MAX);
    limits.exceptions.max_records = functions;
    limits.exceptions.max_section_bytes = decoded_bytes;
    limits.exceptions.max_lsda_bytes = decoded_bytes;
    limits.exceptions.max_call_sites = references;
    limits.exceptions.max_actions = references;
    limits.exceptions.max_cfi_rows = references;
    limits.dependencies.max_dependencies = references;
    limits.dependencies.max_images = functions;
    limits.dependencies.max_resolutions = references;
    limits.semantics.max_data_objects = references;
    limits.semantics.max_signatures = functions;
    limits.semantics.max_frames = functions;
    limits.semantics.max_locals = references;
    limits
}

#[allow(clippy::too_many_arguments)]
fn apply_dependency_and_semantic_limits(
    limits: &mut ProgramRecoveryLimits,
    dependencies: Option<usize>,
    images: Option<usize>,
    resolutions: Option<usize>,
    data_objects: Option<usize>,
    signatures: Option<usize>,
    frames: Option<usize>,
    locals: Option<usize>,
) {
    if let Some(value) = dependencies {
        limits.dependencies.max_dependencies = value;
    }
    if let Some(value) = images {
        limits.dependencies.max_images = value;
    }
    if let Some(value) = resolutions {
        limits.dependencies.max_resolutions = value;
    }
    if let Some(value) = data_objects {
        limits.semantics.max_data_objects = value;
    }
    if let Some(value) = signatures {
        limits.semantics.max_signatures = value;
    }
    if let Some(value) = frames {
        limits.semantics.max_frames = value;
    }
    if let Some(value) = locals {
        limits.semantics.max_locals = value;
    }
}

fn apply_indirect_limits(
    limits: &mut ProgramRecoveryLimits,
    work: Option<u64>,
    per_function_work: Option<u64>,
    values: Option<usize>,
    loop_values: Option<usize>,
    candidates: Option<usize>,
) {
    if let Some(work) = work {
        limits.indirect_calls.max_value_flow_work = work;
    }
    if let Some(work) = per_function_work {
        limits.indirect_calls.max_value_flow_work_per_function = work;
    }
    if let Some(values) = values {
        limits.indirect_calls.max_values_per_register = values;
    }
    if let Some(loop_values) = loop_values {
        limits.indirect_calls.max_loop_values_per_register = loop_values;
    }
    if let Some(candidates) = candidates {
        limits.indirect_calls.max_candidates_per_transfer = candidates;
    }
}

fn apply_control_flow_limits(
    limits: &mut ProgramRecoveryLimits,
    instructions: Option<usize>,
    blocks: Option<usize>,
    edges: Option<usize>,
    gaps: Option<usize>,
    jump_tables: Option<usize>,
    jump_table_entries: Option<usize>,
) {
    if let Some(instructions) = instructions {
        limits.control_flow.max_instructions_per_function = instructions;
    }
    if let Some(blocks) = blocks {
        limits.control_flow.max_blocks_per_function = blocks;
    }
    if let Some(edges) = edges {
        limits.control_flow.max_edges_per_function = edges;
    }
    if let Some(gaps) = gaps {
        limits.control_flow.max_gaps_per_function = gaps;
    }
    if let Some(jump_tables) = jump_tables {
        limits.control_flow.max_jump_tables_per_function = jump_tables;
    }
    if let Some(jump_table_entries) = jump_table_entries {
        limits.control_flow.max_jump_table_entries = jump_table_entries;
    }
}

fn apply_exception_limits(
    limits: &mut ProgramRecoveryLimits,
    records: Option<usize>,
    section_bytes: Option<usize>,
    lsda_bytes: Option<usize>,
    call_sites: Option<usize>,
    actions: Option<usize>,
    cfi_rows: Option<usize>,
) {
    if let Some(records) = records {
        limits.exceptions.max_records = records;
    }
    if let Some(section_bytes) = section_bytes {
        limits.exceptions.max_section_bytes = section_bytes;
    }
    if let Some(lsda_bytes) = lsda_bytes {
        limits.exceptions.max_lsda_bytes = lsda_bytes;
    }
    if let Some(call_sites) = call_sites {
        limits.exceptions.max_call_sites = call_sites;
    }
    if let Some(actions) = actions {
        limits.exceptions.max_actions = actions;
    }
    if let Some(cfi_rows) = cfi_rows {
        limits.exceptions.max_cfi_rows = cfi_rows;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_file_requires_the_versioned_complete_envelope() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("fixture");
        let limits = directory.path().join("limits.json");
        std::fs::write(&input, macho_test_support::disassembly_x86_64()).unwrap();
        std::fs::write(
            &limits,
            serde_json::to_vec(&ProgramRecoveryLimitsFile::current(
                ProgramRecoveryLimits::default(),
            ))
            .unwrap(),
        )
        .unwrap();
        let valid = crate::cli::commands::run_captured([
            std::ffi::OsString::from("program"),
            input.clone().into_os_string(),
            std::ffi::OsString::from("--stage"),
            std::ffi::OsString::from("image-layout"),
            std::ffi::OsString::from("--limits-file"),
            limits.clone().into_os_string(),
        ]);
        assert_eq!(valid.code, 0, "{}", String::from_utf8_lossy(&valid.stderr));

        std::fs::write(
            &limits,
            serde_json::to_vec(&ProgramRecoveryLimits::default()).unwrap(),
        )
        .unwrap();
        let unversioned = crate::cli::commands::run_captured([
            std::ffi::OsString::from("program"),
            input.into_os_string(),
            std::ffi::OsString::from("--stage"),
            std::ffi::OsString::from("image-layout"),
            std::ffi::OsString::from("--limits-file"),
            limits.into_os_string(),
        ]);
        assert_ne!(unversioned.code, 0);
        assert!(String::from_utf8_lossy(&unversioned.stderr).contains("parse program limits"));
    }
    use crate::cli::analysis::recovery::{
        ProgramSubjectKey, RecoveryChoice, RecoveryContractSchema, RecoveryDecision,
    };

    #[test]
    fn command_stage_spellings_cover_the_program_registry() {
        use clap::ValueEnum;

        let stages = ProgramStageArg::value_variants()
            .iter()
            .copied()
            .map(ProgramRecoveryStage::from)
            .collect::<Vec<_>>();
        assert_eq!(stages, ProgramRecoveryStage::all());
    }

    #[test]
    fn questions_selects_its_required_recovery_stages_without_all() {
        crate::cli::commands::parse_only(["macho", "program", "fixture", "--questions"])
            .expect("questions is a complete program request");
    }

    #[test]
    fn guide_is_a_complete_program_request_without_all() {
        crate::cli::commands::parse_only([
            "macho",
            "program",
            "fixture",
            "--guide",
            "recovery.json",
        ])
        .expect("guide is a complete program request");
    }

    #[test]
    fn filesystem_dependency_universe_is_a_complete_request_and_reports_discovery() {
        crate::cli::commands::parse_only(["macho", "program", "fixture", "--load-dependencies"])
            .expect("automatic dependency loading selects its own required stages");
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("fixture");
        std::fs::write(&input, macho_test_support::disassembly_x86_64()).unwrap();
        let run = crate::cli::commands::run_captured([
            std::ffi::OsString::from("program"),
            input.into_os_string(),
            std::ffi::OsString::from("--load-dependencies"),
            std::ffi::OsString::from("--format"),
            std::ffi::OsString::from("json"),
        ]);
        assert_eq!(run.code, 0, "{}", String::from_utf8_lossy(&run.stderr));
        let json: serde_json::Value = serde_json::from_slice(&run.stdout).unwrap();
        assert_eq!(
            json["data"]["universe"]["images"].as_array().unwrap().len(),
            1
        );
        assert_eq!(
            json["data"]["universe"]["discovery"][0]["status"],
            "selected"
        );
    }

    #[test]
    fn dyld_cache_dependency_source_requires_and_accepts_recursive_loading() {
        crate::cli::commands::parse_only([
            "macho",
            "program",
            "fixture",
            "--load-dependencies",
            "--dyld-cache",
            "dyld_shared_cache_arm64e",
        ])
        .expect("an explicit cache augments recursive dependency loading");
        assert!(
            crate::cli::commands::parse_only([
                "macho",
                "program",
                "fixture",
                "--all",
                "--dyld-cache",
                "dyld_shared_cache_arm64e",
            ])
            .is_err(),
            "cache selection without dependency loading must be rejected"
        );
    }

    #[test]
    fn coverage_is_a_complete_program_request_and_is_available_in_human_and_json_output() {
        crate::cli::commands::parse_only(["macho", "program", "fixture", "--coverage"])
            .expect("coverage is a complete all-stage program request");

        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("fixture");
        std::fs::write(&input, macho_test_support::disassembly_arm64()).unwrap();

        let human = crate::cli::commands::run_captured([
            std::ffi::OsString::from("program"),
            input.clone().into_os_string(),
            std::ffi::OsString::from("--stage"),
            std::ffi::OsString::from("executable-bytes"),
            std::ffi::OsString::from("--coverage"),
        ]);
        assert_eq!(human.code, 0, "{}", String::from_utf8_lossy(&human.stderr));
        let human = String::from_utf8(human.stdout).unwrap();
        assert!(human.contains("Coverage:"));
        assert!(human.contains("executable bytes: denominator=Some("));
        assert!(human.contains("rejected="));
        assert!(human.contains("indirect transfers: denominator=None"));

        let json = crate::cli::commands::run_captured([
            std::ffi::OsString::from("program"),
            input.into_os_string(),
            std::ffi::OsString::from("--stage"),
            std::ffi::OsString::from("executable-bytes"),
            std::ffi::OsString::from("--coverage"),
            std::ffi::OsString::from("--format"),
            std::ffi::OsString::from("json"),
        ]);
        assert_eq!(json.code, 0, "{}", String::from_utf8_lossy(&json.stderr));
        let value: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
        assert_eq!(
            value["data"]["coverage"]["executable_bytes"]["unit"],
            "bytes"
        );
        assert_eq!(
            value["data"]["coverage"]["indirect_transfers"]["unavailable"],
            true
        );
    }

    #[test]
    fn cli_applies_a_function_guide_and_reports_the_cold_rebuild() {
        let mut bytes = macho_test_support::disassembly_x86_64();
        bytes[0x104..0x109].copy_from_slice(&[0xe8, 0x07, 0x00, 0x00, 0x00]);
        bytes[0x109] = 0xc3;
        bytes[0x110] = 0xc3;
        let container = crate::parse(&bytes).unwrap();
        let image = match &container {
            crate::model::container::MachoContainer::Thin(image) => image,
            crate::model::container::MachoContainer::Fat(_) => panic!("expected thin fixture"),
        };
        let base = RecoveredProgram::recover_all(image, ProgramRecoveryLimits::default()).unwrap();
        let candidate = 0x1_0000_0110;
        let question = base
            .questions()
            .iter()
            .find(|question| {
                question.subject == ProgramSubjectKey::FunctionCandidate { address: candidate }
            })
            .unwrap();
        let guide = RecoveryGuide {
            schema: RecoveryContractSchema::CURRENT,
            image: base.image().clone(),
            decisions: vec![RecoveryDecision {
                point: question.key.clone(),
                choice: RecoveryChoice::AcceptFunctionEntry,
                expected_signals: question
                    .signals
                    .iter()
                    .map(|signal| signal.key.clone())
                    .collect(),
            }],
        };
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("fixture");
        let guide_path = directory.path().join("guide.json");
        std::fs::write(&input, bytes).unwrap();
        std::fs::write(&guide_path, serde_json::to_vec(&guide).unwrap()).unwrap();

        let run = crate::cli::commands::run_captured([
            std::ffi::OsString::from("program"),
            input.into_os_string(),
            std::ffi::OsString::from("--guide"),
            guide_path.into_os_string(),
            std::ffi::OsString::from("--questions"),
        ]);
        assert_eq!(run.code, 0, "{}", String::from_utf8_lossy(&run.stderr));
        let output = String::from_utf8(run.stdout).unwrap();
        assert!(output.contains("Guide preview: Applicable"));
        assert!(output.contains("decision 0: Applied"));
        assert!(output.contains("Recovery delta:"));
        assert!(output.contains("Coverage impact:"));
        assert!(output.contains("Changed subjects:"));
    }

    #[test]
    fn cli_validates_an_operator_authored_premise_without_an_emitted_question() {
        let bytes = macho_test_support::disassembly_x86_64();
        let container = crate::parse(&bytes).unwrap();
        let image = match &container {
            crate::model::container::MachoContainer::Thin(image) => image,
            crate::model::container::MachoContainer::Fat(_) => panic!("expected thin fixture"),
        };
        let base = RecoveredProgram::recover_all(image, ProgramRecoveryLimits::default()).unwrap();
        let guide = RecoveryGuide::builder(base.image().clone())
            .accept_function(0x1_0000_0118)
            .build();
        assert!(base.questions().iter().all(|question| {
            question.subject
                != ProgramSubjectKey::FunctionCandidate {
                    address: 0x1_0000_0118,
                }
        }));
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("fixture");
        let guide_path = directory.path().join("guide.json");
        std::fs::write(&input, bytes).unwrap();
        std::fs::write(&guide_path, serde_json::to_vec(&guide).unwrap()).unwrap();

        let run = crate::cli::commands::run_captured([
            std::ffi::OsString::from("program"),
            input.into_os_string(),
            std::ffi::OsString::from("--guide"),
            guide_path.into_os_string(),
            std::ffi::OsString::from("--validate-guide"),
        ]);
        assert_eq!(run.code, 0, "{}", String::from_utf8_lossy(&run.stderr));
        let output = String::from_utf8(run.stdout).unwrap();
        assert!(output.contains("guide: Applicable"));
        assert!(output.contains("authored_premise_applicable"));
    }

    #[test]
    fn explicit_indirect_value_flow_limits_reach_the_rust_contract() {
        let mut limits = ProgramRecoveryLimits::default();
        apply_indirect_limits(
            &mut limits,
            Some(123),
            Some(61),
            Some(17),
            Some(9),
            Some(31),
        );

        assert_eq!(limits.indirect_calls.max_value_flow_work, 123);
        assert_eq!(limits.indirect_calls.max_value_flow_work_per_function, 61);
        assert_eq!(limits.indirect_calls.max_values_per_register, 17);
        assert_eq!(limits.indirect_calls.max_loop_values_per_register, 9);
        assert_eq!(limits.indirect_calls.max_candidates_per_transfer, 31);
    }

    #[test]
    fn explicit_cfg_limits_reach_the_rust_contract() {
        let mut limits = ProgramRecoveryLimits::default();
        apply_control_flow_limits(
            &mut limits,
            Some(11),
            Some(12),
            Some(13),
            Some(14),
            Some(15),
            Some(16),
        );

        assert_eq!(limits.control_flow.max_instructions_per_function, 11);
        assert_eq!(limits.control_flow.max_blocks_per_function, 12);
        assert_eq!(limits.control_flow.max_edges_per_function, 13);
        assert_eq!(limits.control_flow.max_gaps_per_function, 14);
        assert_eq!(limits.control_flow.max_jump_tables_per_function, 15);
        assert_eq!(limits.control_flow.max_jump_table_entries, 16);
    }

    #[test]
    fn explicit_exception_limits_reach_the_rust_contract() {
        let mut limits = ProgramRecoveryLimits::default();
        apply_exception_limits(
            &mut limits,
            Some(11),
            Some(12),
            Some(13),
            Some(14),
            Some(15),
            Some(16),
        );

        assert_eq!(limits.exceptions.max_records, 11);
        assert_eq!(limits.exceptions.max_section_bytes, 12);
        assert_eq!(limits.exceptions.max_lsda_bytes, 13);
        assert_eq!(limits.exceptions.max_call_sites, 14);
        assert_eq!(limits.exceptions.max_actions, 15);
        assert_eq!(limits.exceptions.max_cfi_rows, 16);
    }

    #[test]
    fn explicit_dependency_and_semantic_limits_reach_the_rust_contract() {
        let mut limits = ProgramRecoveryLimits::default();
        apply_dependency_and_semantic_limits(
            &mut limits,
            Some(11),
            Some(12),
            Some(13),
            Some(14),
            Some(15),
            Some(16),
            Some(17),
        );
        assert_eq!(limits.dependencies.max_dependencies, 11);
        assert_eq!(limits.dependencies.max_images, 12);
        assert_eq!(limits.dependencies.max_resolutions, 13);
        assert_eq!(limits.semantics.max_data_objects, 14);
        assert_eq!(limits.semantics.max_signatures, 15);
        assert_eq!(limits.semantics.max_frames, 16);
        assert_eq!(limits.semantics.max_locals, 17);
    }
}
