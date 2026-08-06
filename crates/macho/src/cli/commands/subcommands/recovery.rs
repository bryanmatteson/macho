//! Shared C and C++ recovery grammar, planning, and rendering.

mod header;

use header::project_entity;

use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::analysis::report::{
    AnalysisLevel, CollectorCounts, CollectorExecution, CollectorId, CollectorOutcome, EntityKind,
    Fact, HashedHeaderFile, HashedHeaderRoot, HeaderCorrelationInput, HeaderGap,
    HeaderIneligibilityReason, HeaderProjection, HeaderProjectionSpec, HeaderValidationReport,
    LogicalInputLabel, NonEmpty, ObservationDisposition, Presence, RecoveryGapReason,
    RecoveryLanguage, RecoveryReport, RecoveryScope, RecoveryView, ValidatedGlob, canonical_json,
    execute_header_correlation, execute_recovery_abi, execute_recovery_sources,
    recover_symbol_container, sha256_hex,
};
use crate::header_syntax::{
    self as syntax, HeaderParser as _, Language, TreeSitterHeaderParser, ValidationLimits,
};
use anyhow::{Context, Result, bail};
use clap::{Args, ValueEnum};

use crate::cli::commands::args::{ArchitectureArgs, InputArgs};
use crate::cli::commands::output::layout;
use crate::cli::commands::output::{Options as OutputOptions, Style};
use crate::cli::commands::subcommands::common::map_input;
use crate::cli::commands::{OutputFormat, usage_message};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ViewArg {
    Surface,
    Header,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ScopeArg {
    Defined,
    Imports,
    All,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AnalysisArg {
    Sources,
    Abi,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum EvidenceArg {
    None,
    Sources,
}

/// Shared plan arguments for C and C++ recovery.
#[derive(Debug, Clone, Args)]
pub struct RecoveryArgs {
    /// Render an evidence surface or a safe header projection.
    #[arg(long, value_enum)]
    pub view: Option<ViewArg>,
    /// Visible alias for `--view header`.
    #[arg(long)]
    pub headers: bool,
    /// Select defined entities, imported references, or both.
    #[arg(long, value_enum, default_value_t = ScopeArg::Defined)]
    pub scope: ScopeArg,
    /// Select one or more language-specific entity kinds.
    #[arg(long = "kind")]
    pub kinds: Vec<String>,
    /// Select names with a case-sensitive shell glob.
    #[arg(long = "name")]
    pub names: Vec<String>,
    /// Select source evidence or bounded ABI evidence.
    #[arg(long, value_enum, default_value_t = AnalysisArg::Sources)]
    pub analysis: AnalysisArg,
    /// Control per-entity evidence detail in text surface output.
    #[arg(long, value_enum)]
    pub evidence: Option<EvidenceArg>,
    /// Add a deterministic external header root as `LABEL=PATH`.
    #[arg(long = "header-root", value_name = "LABEL=PATH")]
    pub header_roots: Vec<String>,
}

pub fn run(
    input: InputArgs,
    selection: ArchitectureArgs,
    args: RecoveryArgs,
    language: RecoveryLanguage,
    output: OutputOptions,
    out: &mut dyn Write,
) -> Result<()> {
    if output.format() == OutputFormat::Sarif {
        return Err(usage_message(
            "C and C++ recovery support only text and JSON",
        ));
    }
    let view = resolved_view(args.view, args.headers)?;
    if args.evidence.is_some() && (output.format() != OutputFormat::Text || view == ViewArg::Header)
    {
        return Err(usage_message(
            "--evidence is valid only with text surface output",
        ));
    }
    let mmap = map_input(&input.path)?;
    let container =
        crate::parse(&mmap).with_context(|| format!("failed to parse {}", input.path.display()))?;
    let mut report = recover_symbol_container(&container, language, selection.arch.as_deref())?;
    let kinds = parse_kinds(language, &args.kinds)?;
    let globs = args
        .names
        .iter()
        .map(|value| {
            ValidatedGlob::new(value.clone())
                .map_err(|error| usage_message(format!("invalid --name `{value}`: {error}")))
        })
        .collect::<Result<Vec<_>>>()?;
    apply_selection(&mut report, args.scope, kinds, globs);
    report.request.analysis = match args.analysis {
        AnalysisArg::Sources => AnalysisLevel::Sources,
        AnalysisArg::Abi => AnalysisLevel::Abi,
    };
    execute_recovery_sources(&container, &mut report)?;
    if args.analysis == AnalysisArg::Abi {
        execute_recovery_abi(&container, &mut report)?;
    }
    if !args.header_roots.is_empty() {
        let corpus = load_header_roots(&args.header_roots, language, report.request.limits)?;
        execute_header_correlation(&mut report, corpus.roots, &corpus.declarations)?;
    }
    if view == ViewArg::Header {
        if report.slices.as_slice().len() > 1 {
            return Err(usage_message(
                "header output requires exactly one selected architecture; use a qualified --arch such as arm64e",
            ));
        }
        project_headers(&mut report, language)?;
    }
    report.request.view = match view {
        ViewArg::Surface => RecoveryView::Surface,
        ViewArg::Header => RecoveryView::Header,
    };
    report
        .refresh_request_digest()
        .map_err(|error| anyhow::anyhow!(error))?;
    report.validate().map_err(|error| anyhow::anyhow!(error))?;

    match output.format() {
        OutputFormat::Json => crate::cli::commands::output::json::write_pretty(out, &report)?,
        OutputFormat::Text if view == ViewArg::Header => {
            let header = report.slices.as_slice()[0]
                .header
                .as_ref()
                .expect("header view creates a projection");
            out.write_all(header.source.as_bytes())?;
            if !header.source.ends_with('\n') {
                writeln!(out)?;
            }
        }
        OutputFormat::Text => print_surface(
            &report,
            args.evidence.unwrap_or(EvidenceArg::Sources),
            output.style(),
            out,
        ),
        OutputFormat::Sarif => unreachable!("rejected above"),
    }
    Ok(())
}

fn resolved_view(view: Option<ViewArg>, headers: bool) -> Result<ViewArg> {
    match (view, headers) {
        (Some(_), true) => Err(usage_message("--headers conflicts with --view")),
        (Some(view), false) => Ok(view),
        (None, true) => Ok(ViewArg::Header),
        (None, false) => Ok(ViewArg::Surface),
    }
}

fn parse_kinds(language: RecoveryLanguage, raw: &[String]) -> Result<Vec<EntityKind>> {
    raw.iter()
        .map(|value| {
            let kinds = match (language, value.as_str()) {
                (RecoveryLanguage::CAbi, "function") => vec![EntityKind::Function],
                (RecoveryLanguage::CAbi, "data") => vec![EntityKind::Data],
                (RecoveryLanguage::CAbi, "tls") => vec![EntityKind::Tls],
                (RecoveryLanguage::CAbi, "runtime-artifact") => {
                    vec![EntityKind::RuntimeArtifact]
                }
                (RecoveryLanguage::CAbi, "unknown") => vec![EntityKind::Unknown],
                (RecoveryLanguage::Cpp, "function" | "qualified-function") => {
                    vec![EntityKind::Function]
                }
                (RecoveryLanguage::Cpp, "data") => vec![EntityKind::Data],
                (RecoveryLanguage::Cpp, "tls") => vec![EntityKind::Tls],
                (RecoveryLanguage::Cpp, "class") => vec![EntityKind::Type],
                (RecoveryLanguage::Cpp, "method") => vec![EntityKind::Method],
                (RecoveryLanguage::Cpp, "rtti") => vec![EntityKind::Typeinfo],
                (RecoveryLanguage::Cpp, "vtable") => vec![EntityKind::Vtable],
                (RecoveryLanguage::Cpp, "thunk") => vec![EntityKind::Thunk],
                (RecoveryLanguage::Cpp, "runtime-artifact") => {
                    vec![EntityKind::RuntimeArtifact]
                }
                (RecoveryLanguage::Cpp, "unknown") => vec![EntityKind::Unknown],
                _ => {
                    return Err(usage_message(format!(
                        "kind `{value}` is not valid for {} recovery",
                        language_name(language)
                    )));
                }
            };
            Ok(kinds)
        })
        .collect::<Result<Vec<_>>>()
        .map(|nested| nested.into_iter().flatten().collect())
}

fn apply_selection(
    report: &mut RecoveryReport,
    scope: ScopeArg,
    kinds: Vec<EntityKind>,
    globs: Vec<ValidatedGlob>,
) {
    report.request.selection.scope = match scope {
        ScopeArg::Defined => RecoveryScope::Defined,
        ScopeArg::Imports => RecoveryScope::Referenced,
        ScopeArg::All => RecoveryScope::All,
    };
    report.request.selection.kinds = kinds.clone();
    report.request.selection.name_globs = globs.clone();
    for slice in report.slices.as_mut_slice() {
        let selected = slice
            .entities
            .iter()
            .filter(|entity| scope_matches(scope, entity_presence(entity)))
            .filter(|entity| {
                kinds.is_empty() || entity_kind(entity).is_some_and(|kind| kinds.contains(&kind))
            })
            .filter(|entity| {
                globs.is_empty()
                    || entity_names(entity)
                        .iter()
                        .any(|name| globs.iter().any(|glob| glob_matches(glob.as_str(), name)))
            })
            .map(|entity| entity.id.clone())
            .collect::<Vec<_>>();
        slice.resolved_plan.selected_entity_ids = selected;
        if let Some(execution) = slice
            .executions
            .as_mut_slice()
            .iter_mut()
            .find(|execution| execution.collector == CollectorId::SymbolDiscovery)
        {
            execution.counts.selected_targets =
                slice.resolved_plan.selected_entity_ids.len() as u64;
        }
    }
}

fn project_headers(report: &mut RecoveryReport, language: RecoveryLanguage) -> Result<()> {
    for slice in report.slices.as_mut_slice() {
        let selected = slice.resolved_plan.selected_entity_ids.clone();
        let selected_set = selected
            .iter()
            .map(|id| id.as_str())
            .collect::<BTreeSet<_>>();
        let mut unresolved = Vec::new();
        let mut declarations = Vec::new();
        let mut syntax_declarations = Vec::new();
        for entity in slice
            .entities
            .iter()
            .filter(|entity| selected_set.contains(entity.id.as_str()))
        {
            if let Some((wire, syntax)) = project_entity(entity, language) {
                declarations.push(wire);
                syntax_declarations.push(syntax);
            } else {
                unresolved.extend(entity.gaps.iter().map(|gap| HeaderGap {
                    entity_id: entity.id.clone(),
                    field: gap.field,
                    reason: header_reason(&gap.reason),
                    diagnostic_ids: Vec::new(),
                }));
            }
        }
        let syntax_language = match language {
            RecoveryLanguage::CAbi => Language::C,
            RecoveryLanguage::Cpp => Language::Cpp,
        };
        let source = if syntax_declarations.is_empty() {
            format!(
                "#pragma once\n/* macho {} recovery: 0 declarations emitted; {} unresolved facts across {} selected entities. */\n",
                language_name(language),
                unresolved.len(),
                selected.len()
            )
        } else {
            syntax::render(&syntax::TranslationUnit {
                language: syntax_language,
                declarations: syntax_declarations,
                declaration_spans: Vec::new(),
            })
            .map_err(anyhow::Error::new)?
        };
        let unit = TreeSitterHeaderParser
            .parse(syntax_language, &source)
            .map_err(anyhow::Error::new)?;
        let syntax_report = crate::header_syntax::validate(&unit, ValidationLimits::default())
            .map_err(anyhow::Error::new)?;
        let validation = HeaderValidationReport::from(&syntax_report);
        slice.header = Some(HeaderProjection {
            language,
            declarations,
            unresolved,
            diagnostics: Vec::new(),
            source,
            validation,
        });
        if let Ok(non_empty) = NonEmpty::new(selected.clone()) {
            slice.resolved_plan.projection = Some(HeaderProjectionSpec {
                target_entity_ids: non_empty,
                language,
            });
            let mut executions = slice.executions.clone().into_vec();
            executions.push(CollectorExecution {
                collector: CollectorId::HeaderProjection,
                request_digest: slice.resolved_plan.request_digest.clone(),
                target_entity_ids: selected.clone(),
                outcome: CollectorOutcome::Complete,
                counts: CollectorCounts {
                    input_records: selected.len() as u64,
                    output_records: slice
                        .header
                        .as_ref()
                        .map_or(0, |header| header.declarations.len() as u64),
                    selected_targets: selected.len() as u64,
                },
            });
            slice.executions =
                NonEmpty::new(executions).expect("execution ledger remains non-empty");
        }
    }
    Ok(())
}

fn header_reason(reason: &RecoveryGapReason) -> HeaderIneligibilityReason {
    match reason {
        RecoveryGapReason::Unavailable { .. } => HeaderIneligibilityReason::UnavailableRequiredFact,
        RecoveryGapReason::Conflicted { .. } => HeaderIneligibilityReason::ConflictedRequiredFact,
        RecoveryGapReason::HeaderIneligible { reason } => *reason,
    }
}

fn load_header_roots(
    values: &[String],
    language: RecoveryLanguage,
    limits: crate::analysis::report::RecoveryLimits,
) -> Result<LoadedHeaderCorpus> {
    let mut roots = Vec::new();
    let mut declarations = Vec::new();
    for value in values {
        let (label, root) = value
            .split_once('=')
            .ok_or_else(|| usage_message(format!("--header-root `{value}` must use LABEL=PATH")))?;
        let logical_label = LogicalInputLabel::new(label.to_owned())
            .map_err(|error| usage_message(format!("invalid header-root label: {error}")))?;
        if roots
            .iter()
            .any(|root: &HashedHeaderRoot| root.logical_label == logical_label)
        {
            return Err(usage_message(format!(
                "duplicate header-root label `{label}`"
            )));
        }
        let root = PathBuf::from(root);
        let loaded = read_header_files(&root, language, limits)?;
        let files = loaded
            .iter()
            .map(|file| file.hashed.clone())
            .collect::<Vec<_>>();
        let root_bytes = canonical_json(&files).map_err(anyhow::Error::new)?;
        for file in loaded {
            for (declaration, span) in file
                .unit
                .declarations
                .into_iter()
                .zip(file.unit.declaration_spans)
            {
                declarations.push(HeaderCorrelationInput {
                    root_label: logical_label.clone(),
                    relative_path: file.hashed.relative_path.clone(),
                    content_sha256: file.hashed.content_sha256.clone(),
                    span,
                    declaration,
                });
            }
        }
        roots.push(HashedHeaderRoot {
            logical_label,
            content_hash: crate::analysis::report::ContentHash::new(sha256(&root_bytes))
                .expect("SHA-256 is a valid content hash"),
            files,
        });
    }
    let unit = syntax::TranslationUnit {
        language: match language {
            RecoveryLanguage::CAbi => Language::C,
            RecoveryLanguage::Cpp => Language::Cpp,
        },
        declarations: declarations
            .iter()
            .map(|input| input.declaration.clone())
            .collect(),
        declaration_spans: declarations.iter().map(|input| input.span).collect(),
    };
    let validation = syntax::validate(&unit, ValidationLimits::default())
        .context("validate external header corpus")?;
    if !validation.syntax_valid || !validation.semantic_valid {
        let detail = validation
            .diagnostics
            .iter()
            .map(|diagnostic| format!("{:?}: {}", diagnostic.code, diagnostic.message))
            .collect::<Vec<_>>()
            .join("; ");
        bail!("external header corpus is not semantically valid: {detail}");
    }
    Ok(LoadedHeaderCorpus {
        roots,
        declarations,
    })
}

struct LoadedHeaderCorpus {
    roots: Vec<HashedHeaderRoot>,
    declarations: Vec<HeaderCorrelationInput>,
}

struct LoadedHeaderFile {
    hashed: HashedHeaderFile,
    unit: syntax::TranslationUnit,
}

fn read_header_files(
    root: &Path,
    language: RecoveryLanguage,
    limits: crate::analysis::report::RecoveryLimits,
) -> Result<Vec<LoadedHeaderFile>> {
    let mut paths = Vec::new();
    collect_files(root, root, language, &mut paths)?;
    paths.sort_by(|left, right| left.0.cmp(&right.0));
    if paths.len() as u64 > limits.max_header_files {
        bail!(
            "header root exceeds max_header_files={}",
            limits.max_header_files
        );
    }
    let syntax_language = match language {
        RecoveryLanguage::CAbi => Language::C,
        RecoveryLanguage::Cpp => Language::Cpp,
    };
    let mut total_bytes = 0u64;
    let mut files = Vec::new();
    for (relative, path) in paths {
        let bytes =
            std::fs::read(&path).with_context(|| format!("read header {}", path.display()))?;
        total_bytes = total_bytes.saturating_add(bytes.len() as u64);
        if total_bytes > limits.max_header_bytes {
            bail!(
                "header root exceeds max_header_bytes={}",
                limits.max_header_bytes
            );
        }
        let source = std::str::from_utf8(&bytes)
            .with_context(|| format!("header {} is not UTF-8", path.display()))?;
        let unit = TreeSitterHeaderParser
            .parse(syntax_language, source)
            .with_context(|| format!("parse header {}", path.display()))?;
        files.push(LoadedHeaderFile {
            hashed: HashedHeaderFile {
                relative_path: relative,
                content_sha256: crate::analysis::report::ContentHash::new(sha256(&bytes))
                    .expect("SHA-256 is a valid content hash"),
                byte_len: bytes.len() as u64,
            },
            unit,
        });
    }
    Ok(files)
}

fn collect_files(
    root: &Path,
    directory: &Path,
    language: RecoveryLanguage,
    output: &mut Vec<(String, PathBuf)>,
) -> Result<()> {
    for entry in std::fs::read_dir(directory)
        .with_context(|| format!("read header root {}", directory.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            bail!("header roots may not contain symlinks: {}", path.display());
        }
        if file_type.is_dir() {
            collect_files(root, &path, language, output)?;
        } else if file_type.is_file() && is_header_path(&path, language) {
            let relative = path
                .strip_prefix(root)
                .expect("walked path is under root")
                .components()
                .map(|component| component.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/");
            if relative.is_empty() || relative.contains('\0') {
                bail!("invalid header relative path `{relative}`");
            }
            output.push((relative, path));
        }
    }
    Ok(())
}

fn is_header_path(path: &Path, language: RecoveryLanguage) -> bool {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    match language {
        RecoveryLanguage::CAbi => extension == "h",
        RecoveryLanguage::Cpp => matches!(extension.as_str(), "h" | "hh" | "hpp" | "hxx"),
    }
}

fn print_surface(
    report: &RecoveryReport,
    evidence: EvidenceArg,
    style: Style,
    out: &mut dyn Write,
) {
    let _ = writeln!(
        out,
        "{}",
        style.title(&format!("{} recovery", language_name(report.language)))
    );
    for slice in report.slices.as_slice() {
        let included = slice
            .observations
            .iter()
            .filter(|observation| {
                matches!(
                    observation.disposition,
                    ObservationDisposition::Included { .. }
                )
            })
            .count();
        let unknown = slice
            .observations
            .iter()
            .filter(|observation| {
                matches!(
                    observation.disposition,
                    ObservationDisposition::Unknown { .. }
                )
            })
            .count();
        let excluded = slice.observations.len() - included - unknown;
        let _ = writeln!(
            out,
            "  {}  {}  {}  {}  {}",
            style.enum_property("arch", &slice_arch(slice)),
            style.property("observations", &slice.observations.len().to_string()),
            style.property("entities", &slice.entities.len().to_string()),
            style.property(
                "selected",
                &slice.resolved_plan.selected_entity_ids.len().to_string()
            ),
            style.property("unknown/excluded", &format!("{unknown}/{excluded}")),
        );
        let selected_ids = slice
            .resolved_plan
            .selected_entity_ids
            .iter()
            .map(|id| id.as_str())
            .collect::<BTreeSet<_>>();
        let selected = slice
            .entities
            .iter()
            .filter(|entity| selected_ids.contains(entity.id.as_str()))
            .collect::<Vec<_>>();
        if selected.is_empty() {
            let _ = writeln!(
                out,
                "  {}",
                style.muted("No entities matched the selection.")
            );
            continue;
        }
        let rows = selected
            .iter()
            .map(|entity| {
                let address = entity_address(entity)
                    .map(|value| format!("0x{value:016x}"))
                    .unwrap_or_else(|| "-".to_owned());
                let mut row = vec![
                    style.address_cell(&address),
                    style.enum_value_cell(presence_name(entity_presence(entity))),
                    style.enum_value_cell(role_name(entity)),
                    layout::plain_cell(&entity_name(entity)),
                    style.property_cell("gaps", &entity.gaps.len().to_string()),
                ];
                if evidence == EvidenceArg::Sources {
                    row.push(style.enum_property_cell("source", "nlist"));
                }
                row
            })
            .collect::<Vec<_>>();
        for line in layout::align(&rows, style) {
            let _ = writeln!(out, "  {line}");
        }
    }
}

fn entity_presence(entity: &crate::analysis::report::RecoveredEntity) -> Presence {
    match &entity.presence {
        Fact::Known { value, .. } => *value,
        _ => Presence::Unknown,
    }
}

fn entity_kind(entity: &crate::analysis::report::RecoveredEntity) -> Option<EntityKind> {
    match &entity.role {
        Fact::Known { value, .. } => Some(match value {
            crate::analysis::report::EntityRole::Function => EntityKind::Function,
            crate::analysis::report::EntityRole::Data
            | crate::analysis::report::EntityRole::CppStaticData => EntityKind::Data,
            crate::analysis::report::EntityRole::Tls => EntityKind::Tls,
            crate::analysis::report::EntityRole::RuntimeArtifact => EntityKind::RuntimeArtifact,
            crate::analysis::report::EntityRole::CppMethod => EntityKind::Method,
            crate::analysis::report::EntityRole::Type => EntityKind::Type,
            crate::analysis::report::EntityRole::Typeinfo => EntityKind::Typeinfo,
            crate::analysis::report::EntityRole::Vtable
            | crate::analysis::report::EntityRole::Vtt => EntityKind::Vtable,
            crate::analysis::report::EntityRole::Thunk => EntityKind::Thunk,
            crate::analysis::report::EntityRole::Guard => EntityKind::Guard,
            crate::analysis::report::EntityRole::Unknown => EntityKind::Unknown,
        }),
        _ => None,
    }
}

fn entity_names(entity: &crate::analysis::report::RecoveredEntity) -> Vec<&str> {
    let mut result = Vec::new();
    if let Fact::Known { value, .. } = &entity.display_name {
        result.push(value.as_str());
    }
    if let Fact::Known { value, .. } = &entity.linkage {
        result.push(value.raw.as_str());
    }
    result
}

fn entity_name(entity: &crate::analysis::report::RecoveredEntity) -> String {
    entity_names(entity)
        .first()
        .copied()
        .unwrap_or("<unknown>")
        .to_owned()
}

fn entity_address(entity: &crate::analysis::report::RecoveredEntity) -> Option<u64> {
    match &entity.location {
        Fact::Known { value, .. } => value.address,
        _ => None,
    }
}

fn scope_matches(scope: ScopeArg, presence: Presence) -> bool {
    match scope {
        ScopeArg::Defined => matches!(presence, Presence::Defined | Presence::Tentative),
        ScopeArg::Imports => matches!(presence, Presence::Imported | Presence::Reexported),
        ScopeArg::All => true,
    }
}

fn role_name(entity: &crate::analysis::report::RecoveredEntity) -> &'static str {
    match entity_kind(entity) {
        Some(EntityKind::Function) => "function",
        Some(EntityKind::Data) => "data",
        Some(EntityKind::Tls) => "tls",
        Some(EntityKind::RuntimeArtifact) => "runtime-artifact",
        Some(EntityKind::Method) => "method",
        Some(EntityKind::Type) => "type",
        Some(EntityKind::Vtable) => "vtable",
        Some(EntityKind::Typeinfo) => "typeinfo",
        Some(EntityKind::Thunk) => "thunk",
        Some(EntityKind::Guard) => "guard",
        Some(EntityKind::Unknown) => "unknown",
        None => "unknown",
    }
}

fn presence_name(value: Presence) -> &'static str {
    match value {
        Presence::Defined => "defined",
        Presence::Imported => "imported",
        Presence::Reexported => "reexported",
        Presence::Tentative => "tentative",
        Presence::Unknown => "unknown",
    }
}

fn language_name(language: RecoveryLanguage) -> &'static str {
    match language {
        RecoveryLanguage::CAbi => "C ABI",
        RecoveryLanguage::Cpp => "C++",
    }
}

fn slice_arch(slice: &crate::analysis::report::SliceRecovery) -> String {
    crate::core::model::header::ArchSpec {
        cpu_type: crate::core::model::header::CpuType(slice.architecture.cpu_type),
        cpu_subtype: crate::core::model::header::CpuSubtype(slice.architecture.cpu_subtype),
    }
    .name()
}

fn sha256(bytes: &[u8]) -> String {
    sha256_hex(bytes)
}

fn glob_matches(pattern: &str, value: &str) -> bool {
    fn inner(pattern: &[u8], value: &[u8]) -> bool {
        match pattern.first().copied() {
            None => value.is_empty(),
            Some(b'*') => {
                inner(&pattern[1..], value) || (!value.is_empty() && inner(pattern, &value[1..]))
            }
            Some(b'?') => !value.is_empty() && inner(&pattern[1..], &value[1..]),
            Some(b'[') => {
                let Some(end) = pattern.iter().position(|byte| *byte == b']') else {
                    return false;
                };
                !value.is_empty()
                    && pattern[1..end].contains(&value[0])
                    && inner(&pattern[end + 1..], &value[1..])
            }
            Some(byte) => value.first() == Some(&byte) && inner(&pattern[1..], &value[1..]),
        }
    }
    inner(pattern.as_bytes(), value.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_subset_is_deterministic() {
        assert!(glob_matches("Widget::*", "Widget::run"));
        assert!(glob_matches("f?o", "foo"));
        assert!(glob_matches("[ab]ar", "bar"));
        assert!(!glob_matches("foo", "foobar"));
    }

    #[test]
    fn view_alias_conflicts_are_explicit() {
        assert_eq!(resolved_view(None, false).unwrap(), ViewArg::Surface);
        assert_eq!(resolved_view(None, true).unwrap(), ViewArg::Header);
        assert_eq!(
            resolved_view(Some(ViewArg::Header), false).unwrap(),
            ViewArg::Header
        );
        assert!(resolved_view(Some(ViewArg::Surface), true).is_err());
    }
}
