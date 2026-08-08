//! Shared C and C++ recovery grammar, planning, and rendering.

mod header;

use header::project_entity_with_owner;

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::analysis::hypothesis::{
    EvidenceAuthority, HYPOTHESIS_SELECTION_DOCUMENT_VERSION, HypothesisCandidate,
    HypothesisConsequence, HypothesisEvidenceKind, HypothesisEvidenceRef, HypothesisLedger,
    HypothesisOverride, HypothesisSelectionDocument, HypothesisSelectionPolicy, HypothesisSubject,
    RecoveryHypothesis, SelectionPolicyMode,
};
use crate::analysis::report::{
    AnalysisLevel, CollectorCounts, CollectorExecution, CollectorId, CollectorOutcome, EntityKind,
    Fact, HashedHeaderFile, HashedHeaderRoot, HeaderCorrelationInput, HeaderGap,
    HeaderIneligibilityReason, HeaderProjection, HeaderProjectionSpec, HeaderValidationReport,
    LogicalInputLabel, NonEmpty, ObservationDisposition, Presence, RecoveryGapId, RecoveryLanguage,
    RecoveryReport, RecoveryScope, RecoveryView, ValidatedGlob, canonical_json,
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
use crate::cli::commands::{OutputFormat, input_message, input_result, usage_message};

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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum ProjectionPolicyArg {
    /// Project independent and explicitly selected facts only.
    #[default]
    Strict,
    /// Retain strict output and emit ranked hypotheses for blockers.
    Suggest,
    /// Permit the top-ranked hypothesis to affect projection.
    BestEffort,
}

impl From<ProjectionPolicyArg> for SelectionPolicyMode {
    fn from(value: ProjectionPolicyArg) -> Self {
        match value {
            ProjectionPolicyArg::Strict => Self::Strict,
            ProjectionPolicyArg::Suggest => Self::Suggest,
            ProjectionPolicyArg::BestEffort => Self::BestEffort,
        }
    }
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
    /// Control whether ranked recovery hypotheses may affect C++ headers.
    #[arg(long = "projection-policy", value_enum, default_value = "strict")]
    pub projection_policy: ProjectionPolicyArg,
    /// Select an exact suggested candidate as GAP_ID=CANDIDATE_ID.
    #[arg(long = "hypothesis-selection", value_name = "GAP_ID=CANDIDATE_ID")]
    pub hypothesis_selections: Vec<String>,
    /// Load exact selections from a versioned JSON or compact TOML document.
    #[arg(long = "hypothesis-selection-file", value_name = "PATH")]
    pub hypothesis_selection_file: Option<PathBuf>,
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
    if (args.projection_policy != ProjectionPolicyArg::Strict
        || !args.hypothesis_selections.is_empty()
        || args.hypothesis_selection_file.is_some())
        && (language != RecoveryLanguage::Cpp || view != ViewArg::Header)
    {
        return Err(usage_message(
            "hypothesis selection is currently supported only by C++ header projection",
        ));
    }
    let hypothesis_overrides = load_hypothesis_overrides(
        &args.hypothesis_selections,
        args.hypothesis_selection_file.as_deref(),
    )?;
    let hypothesis_selection_policy = HypothesisSelectionPolicy {
        mode: args.projection_policy.into(),
        overrides: hypothesis_overrides,
    };
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
    report.request.hypothesis_selection_policy = hypothesis_selection_policy.clone();
    let kinds = parse_kinds(language, &args.kinds)?;
    let globs = args
        .names
        .iter()
        .map(|value| {
            ValidatedGlob::new(value.clone())
                .map_err(|error| usage_message(format!("invalid --name `{value}`: {error}")))
        })
        .collect::<Result<Vec<_>>>()?;
    apply_selection(&mut report, args.scope, kinds, globs, language, view);
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
        project_headers(&mut report, language, hypothesis_selection_policy)?;
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

fn parse_hypothesis_overrides(values: &[String]) -> Result<Vec<HypothesisOverride>> {
    values
        .iter()
        .map(|value| {
            let (key, candidate_id) = value.split_once('=').ok_or_else(|| {
                usage_message(format!(
                    "--hypothesis-selection `{value}` must use GAP_ID=CANDIDATE_ID"
                ))
            })?;
            if key.is_empty() || candidate_id.is_empty() {
                return Err(usage_message(format!(
                    "--hypothesis-selection `{value}` must use non-empty IDs"
                )));
            }
            Ok(HypothesisOverride {
                subject: HypothesisSubject {
                    domain: "cpp_header".to_owned(),
                    key: key.to_owned(),
                },
                candidate_id: candidate_id.to_owned(),
            })
        })
        .collect()
}

fn load_hypothesis_overrides(
    inline: &[String],
    document_path: Option<&Path>,
) -> Result<Vec<HypothesisOverride>> {
    let mut selections = if let Some(path) = document_path {
        let extension = path
            .extension()
            .and_then(std::ffi::OsStr::to_str)
            .map(str::to_ascii_lowercase);
        let document = match extension.as_deref() {
            Some("json") => {
                let bytes = input_result(
                    std::fs::read(path),
                    format!(
                        "failed to read hypothesis selection document {}",
                        path.display()
                    ),
                )?;
                HypothesisSelectionDocument::load_json(&bytes)
            }
            Some("toml") => {
                let source = input_result(
                    std::fs::read_to_string(path),
                    format!(
                        "failed to read hypothesis selection document {}",
                        path.display()
                    ),
                )?;
                HypothesisSelectionDocument::load_toml(&source)
            }
            _ => {
                return Err(usage_message(
                    "--hypothesis-selection-file must have a .json or .toml extension",
                ));
            }
        };
        document
            .map_err(|error| {
                input_message(format!(
                    "failed to load hypothesis selection document {}: {error}",
                    path.display()
                ))
            })?
            .selections
    } else {
        Vec::new()
    };
    selections.extend(parse_hypothesis_overrides(inline)?);
    let document = HypothesisSelectionDocument {
        schema_version: HYPOTHESIS_SELECTION_DOCUMENT_VERSION,
        selections,
    };
    document
        .validate()
        .map_err(|error| input_message(format!("invalid hypothesis selections: {error}")))?;
    Ok(document.selections)
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
    language: RecoveryLanguage,
    view: ViewArg,
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
                view != ViewArg::Header
                    || entity_kind(entity)
                        .is_some_and(|kind| header_projectable_kind(language, kind))
            })
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

fn header_projectable_kind(language: RecoveryLanguage, kind: EntityKind) -> bool {
    match language {
        RecoveryLanguage::CAbi => {
            matches!(
                kind,
                EntityKind::Function | EntityKind::Data | EntityKind::Tls
            )
        }
        RecoveryLanguage::Cpp => matches!(
            kind,
            EntityKind::Function
                | EntityKind::Method
                | EntityKind::Data
                | EntityKind::Tls
                | EntityKind::Type
        ),
    }
}

fn project_headers(
    report: &mut RecoveryReport,
    language: RecoveryLanguage,
    selection_policy: HypothesisSelectionPolicy,
) -> Result<()> {
    for slice in report.slices.as_mut_slice() {
        let cpp_type_anchors = cpp_type_anchor_paths(&slice.entities);
        let selected = slice.resolved_plan.selected_entity_ids.clone();
        let selected_set = selected
            .iter()
            .map(|id| id.as_str())
            .collect::<BTreeSet<_>>();
        let mut unresolved = Vec::new();
        let mut declarations = Vec::new();
        let mut syntax_declarations = Vec::new();
        let mut assumption_ledger = HypothesisLedger::default();
        for entity in slice
            .entities
            .iter()
            .filter(|entity| selected_set.contains(entity.id.as_str()))
        {
            let mut projection_entity = entity.clone();
            let mut owner_override = None;
            let mut actual_projection = true;
            let mut actual_gap = None;
            let mut emitted = false;
            let mut visited = BTreeSet::new();
            loop {
                let result = project_entity_with_owner(
                    &projection_entity,
                    language,
                    owner_override.as_ref(),
                );
                let blocker = match result {
                    Ok((wire, _)) if actual_projection => {
                        let syntax =
                            crate::analysis::header_infer::syntax::projected_declaration(&wire)
                                .map_err(anyhow::Error::new)?;
                        declarations.push(wire);
                        syntax_declarations.push(syntax);
                        emitted = true;
                        break;
                    }
                    Ok(_) => break,
                    Err(blocker) => blocker,
                };
                let gap = header_gap(entity, language, blocker);
                if actual_projection {
                    actual_gap = Some(gap.clone());
                }
                if language != RecoveryLanguage::Cpp
                    || (selection_policy.mode == SelectionPolicyMode::Strict
                        && selection_policy.overrides.is_empty())
                {
                    break;
                }
                if !visited.insert(gap.id.clone()) {
                    break;
                }

                let (hypothesis, owners) =
                    cpp_owner_hypothesis(entity, &gap, blocker, &cpp_type_anchors)
                        .or_else(|| {
                            cpp_opaque_return_hypothesis(entity, &gap, blocker)
                                .map(|hypothesis| (hypothesis, BTreeMap::new()))
                        })
                        .or_else(|| {
                            cpp_opaque_type_name_hypothesis(entity, &gap, blocker)
                                .map(|hypothesis| (hypothesis, BTreeMap::new()))
                        })
                        .unwrap_or_else(|| {
                            (
                                unsupported_cpp_projection_hypothesis(&gap, blocker),
                                BTreeMap::new(),
                            )
                        });
                let selected = selection_policy
                    .select(&hypothesis)
                    .map_err(hypothesis_contract_error)?;
                if let Some((candidate, authority)) = selected
                    && !candidate.consequences.is_empty()
                {
                    assumption_ledger.selections.push(selection_policy.receipt(
                        &hypothesis,
                        candidate,
                        authority,
                    ));
                }
                let candidate = selected.map(|(candidate, _)| candidate).or_else(|| {
                    (selection_policy.mode == SelectionPolicyMode::Suggest)
                        .then(|| hypothesis.candidates.first())
                        .flatten()
                });
                assumption_ledger.hypotheses.push(hypothesis.clone());
                let Some(candidate) = candidate else {
                    break;
                };
                if selected.is_none() {
                    actual_projection = false;
                }
                if let Some(owner) = owners.get(candidate.id.as_str()) {
                    owner_override = Some(owner.clone());
                    continue;
                }
                if candidate.id == "opaque_return_type" {
                    projection_entity = cpp_entity_with_opaque_return(&projection_entity, &gap);
                    continue;
                }
                if candidate.id == "opaque_type_name" {
                    projection_entity = cpp_entity_with_opaque_type_name(
                        &projection_entity,
                        &gap,
                        owner_override.as_ref(),
                    );
                    continue;
                }
                break;
            }
            if let Some(gap) = actual_gap
                && !emitted
            {
                unresolved.push(gap);
            }
        }
        assumption_ledger
            .validate(&selection_policy)
            .map_err(hypothesis_contract_error)?;
        let syntax_language = match language {
            RecoveryLanguage::CAbi => Language::C,
            RecoveryLanguage::Cpp => Language::Cpp,
        };
        let syntax_declarations =
            crate::analysis::header_infer::syntax::merge_owner_declarations(syntax_declarations);
        let mut source = if syntax_declarations.is_empty() {
            empty_header_source(
                language,
                selected.len(),
                &unresolved,
                slice.executions.as_slice(),
            )
        } else {
            syntax::render(&syntax::TranslationUnit {
                language: syntax_language,
                declarations: syntax_declarations,
                declaration_spans: Vec::new(),
            })
            .map_err(anyhow::Error::new)?
        };
        if !assumption_ledger.selections.is_empty() {
            source = format!(
                "{}{}",
                crate::analysis::report::recovery_assumption_preamble(
                    &assumption_ledger,
                    &declarations,
                ),
                source
            );
        }
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
            assumption_ledger,
            diagnostics: Vec::new(),
            source,
            validation,
        });
        if let Ok(non_empty) = NonEmpty::new(selected.clone()) {
            slice.resolved_plan.projection = Some(HeaderProjectionSpec {
                target_entity_ids: non_empty,
                language,
                selection_policy: selection_policy.clone(),
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

fn cpp_owner_hypothesis(
    entity: &crate::analysis::report::RecoveredEntity,
    gap: &HeaderGap,
    blocker: header::ProjectionBlocker,
    type_anchors: &BTreeSet<Vec<crate::analysis::report::Identifier>>,
) -> Option<(
    RecoveryHypothesis,
    BTreeMap<String, crate::analysis::report::HeaderOwnerRef>,
)> {
    use crate::analysis::report::{
        Access, Fact, HeaderIneligibilityReason, HeaderOwnerKind, HeaderOwnerRef, RecoveryField,
    };

    let subject = HypothesisSubject {
        domain: "cpp_header".to_owned(),
        key: gap.id.to_string(),
    };
    if blocker.field != RecoveryField::Owner
        || !matches!(
            blocker.reason,
            HeaderIneligibilityReason::UnprovenOwner
                | HeaderIneligibilityReason::IncompleteTemplateContext
        )
    {
        return None;
    }

    let recovered_owner = match &entity.owner {
        Fact::Known { value, .. } => Some(value),
        Fact::Conflicted { .. } | Fact::Unavailable { .. } => None,
    };
    let components = recovered_owner
        .map(|owner| owner.path.clone())
        .filter(|path| !path.is_empty())
        .or_else(|| cpp_symbol_owner_path(entity));
    let Some(components) = components else {
        return Some((
            RecoveryHypothesis {
                subject,
                unresolved: "C++ declaration owner could not be recovered".to_owned(),
                candidates: Vec::new(),
                abstention: Some(
                    "no valid source owner path can be derived from retained evidence".to_owned(),
                ),
            },
            BTreeMap::new(),
        ));
    };
    let depth = components.len();
    let recovered_scope_kinds = recovered_owner
        .filter(|owner| owner.scope_kinds.len() == depth)
        .map(|owner| owner.scope_kinds.as_slice());
    let recovered_scope_access = recovered_owner
        .filter(|owner| owner.scope_access.len() == depth)
        .map(|owner| owner.scope_access.as_slice());
    let anchored_scope_kinds = (0..depth)
        .map(|index| {
            type_anchors
                .contains(&components[..=index])
                .then_some(HeaderOwnerKind::Class)
        })
        .collect::<Vec<_>>();
    if recovered_scope_kinds.is_some_and(|kinds| {
        kinds
            .iter()
            .zip(&anchored_scope_kinds)
            .any(|(recovered, anchored)| {
                *anchored == Some(HeaderOwnerKind::Class)
                    && *recovered == Some(HeaderOwnerKind::Namespace)
            })
    }) {
        return Some((
            RecoveryHypothesis {
                subject,
                unresolved:
                    "independent C++ type anchors conflict with the recovered owner scope kinds"
                        .to_owned(),
                candidates: Vec::new(),
                abstention: Some(
                    "contradictory owner evidence cannot be resolved by projection policy"
                        .to_owned(),
                ),
            },
            BTreeMap::new(),
        ));
    }
    let has_member_qualifiers = matches!(
        &entity.signature.qualifiers,
        Fact::Known { value, .. }
            if value.is_const == Some(true)
                || value.is_volatile == Some(true)
                || value.reference.is_some()
    );
    let first_record_anchor = recovered_scope_kinds
        .and_then(|kinds| {
            kinds.iter().position(|kind| {
                matches!(kind, Some(HeaderOwnerKind::Record | HeaderOwnerKind::Class))
            })
        })
        .or_else(|| anchored_scope_kinds.iter().position(Option::is_some))
        .or_else(|| {
            recovered_scope_access.and_then(|access| {
                access
                    .iter()
                    .enumerate()
                    .skip(1)
                    .find_map(|(index, access)| access.is_some().then_some(index - 1))
            })
        })
        .or_else(|| {
            (recovered_owner.is_some_and(|owner| owner.entity_id.is_some())
                || entity_kind(entity) == Some(EntityKind::Method)
                || has_member_qualifiers)
                .then_some(depth - 1)
        });
    let class_anchored = first_record_anchor.is_some();
    if first_record_anchor.is_some_and(|record_start| {
        recovered_scope_kinds.is_some_and(|kinds| {
            kinds.iter().enumerate().any(|(index, kind)| {
                index >= record_start && *kind == Some(HeaderOwnerKind::Namespace)
            })
        })
    }) {
        return Some((
            RecoveryHypothesis {
                subject,
                unresolved: "recovered scope kinds conflict with the C++ nesting required by the declaration"
                    .to_owned(),
                candidates: Vec::new(),
                abstention: Some(
                    "contradictory namespace and record nesting evidence must remain unresolved"
                        .to_owned(),
                ),
            },
            BTreeMap::new(),
        ));
    }
    let namespace_owner = HeaderOwnerRef {
        path: NonEmpty::new(components.clone()).ok()?,
        scope_kinds: NonEmpty::new(vec![HeaderOwnerKind::Namespace; depth]).ok()?,
        scope_access: NonEmpty::new(vec![None; depth]).ok()?,
        member_access: None,
        entity_id: None,
    };
    let record_start = first_record_anchor.unwrap_or(depth - 1);
    let class_kinds = (0..depth)
        .map(|index| {
            recovered_scope_kinds
                .and_then(|kinds| kinds[index])
                .or(anchored_scope_kinds[index])
                .unwrap_or(if index >= record_start {
                    HeaderOwnerKind::Class
                } else {
                    HeaderOwnerKind::Namespace
                })
        })
        .collect::<Vec<_>>();
    let class_access = (0..depth)
        .map(|index| {
            if index == 0 || class_kinds[index - 1] == HeaderOwnerKind::Namespace {
                None
            } else {
                recovered_scope_access
                    .and_then(|access| access[index])
                    .or(Some(Access::Public))
            }
        })
        .collect::<Vec<_>>();
    let class_owner = HeaderOwnerRef {
        path: NonEmpty::new(components.clone()).ok()?,
        scope_kinds: NonEmpty::new(class_kinds).ok()?,
        scope_access: NonEmpty::new(class_access).ok()?,
        member_access: recovered_owner
            .and_then(|owner| owner.member_access)
            .or(Some(Access::Public)),
        entity_id: recovered_owner.and_then(|owner| owner.entity_id.clone()),
    };
    let mut candidates = Vec::new();
    let mut owners = BTreeMap::new();
    if !class_anchored {
        candidates.push(HypothesisCandidate {
            id: "namespace_owner".to_owned(),
            rank: 1,
            interpretation: format!(
                "treat {} as a namespace path",
                components
                    .iter()
                    .map(|part| part.as_str())
                    .collect::<Vec<_>>()
                    .join("::")
            ),
            evidence_authority: EvidenceAuthority::Heuristic,
            confidence_basis_points: 7_000,
            evidence: candidate_evidence(
                entity,
                gap,
                "qualified spelling retained from the canonical demangler",
            ),
            rule:
                "unknown owner prefixes default to namespaces unless contrary class evidence exists"
                    .to_owned(),
            consequences: vec![HypothesisConsequence {
                stage: "header_projection".to_owned(),
                subject: Some(entity.id.to_string()),
                description: "adds the projected declaration under the assumed namespace path without changing recovered facts"
                    .to_owned(),
            }],
        });
        owners.insert("namespace_owner".to_owned(), namespace_owner);
    }
    candidates.push(HypothesisCandidate {
            id: "class_owner_public".to_owned(),
            rank: if class_anchored { 1 } else { 2 },
            interpretation: format!(
                "preserve known scope kinds and access, treat the terminal unresolved scope as a record, and default missing record access to public within {}",
                components
                    .iter()
                    .map(|part| part.as_str())
                    .collect::<Vec<_>>()
                    .join("::")
            ),
            // Even with a correlated class anchor, completing missing scope
            // kinds and access requires a heuristic. The candidate is
            // therefore classified at the weakest authority it depends on.
            evidence_authority: EvidenceAuthority::Heuristic,
            confidence_basis_points: if class_anchored { 6_500 } else { 3_500 },
            evidence: candidate_evidence(
                entity,
                gap,
                if class_anchored {
                    "a retained type anchor supports record ownership; missing access still requires a public default"
                } else {
                    "the retained qualified spelling admits a member interpretation"
                },
            ),
            rule: "known scope kinds and access are preserved; anchored or terminal unresolved scopes become classes and missing record access uses the operator-policy public default"
                .to_owned(),
            consequences: vec![HypothesisConsequence {
                stage: "header_projection".to_owned(),
                subject: Some(entity.id.to_string()),
                description: "adds the declaration inside a synthetic partial record shell; missing bases, members, layout, and ABI remain unauthoritative"
                    .to_owned(),
            }],
        });
    owners.insert("class_owner_public".to_owned(), class_owner);
    candidates.sort_by_key(|candidate| candidate.rank);
    Some((
        RecoveryHypothesis {
            subject,
            unresolved: "the binary spelling does not fully encode namespace/class ownership and member access"
                .to_owned(),
            candidates,
            abstention: None,
        },
        owners,
    ))
}

fn cpp_type_anchor_paths(
    entities: &[crate::analysis::report::RecoveredEntity],
) -> BTreeSet<Vec<crate::analysis::report::Identifier>> {
    entities
        .iter()
        .filter(|entity| entity_kind(entity) == Some(EntityKind::Type))
        .filter_map(|entity| {
            cpp_qualified_components(&entity_name(entity))
                .into_iter()
                .map(|component| crate::analysis::report::Identifier::new(component).ok())
                .collect::<Option<Vec<_>>>()
        })
        .filter(|path| !path.is_empty())
        .collect()
}

fn hypothesis_contract_error(
    error: crate::analysis::hypothesis::HypothesisContractError,
) -> anyhow::Error {
    match error {
        crate::analysis::hypothesis::HypothesisContractError::UnknownOverride { .. } => {
            input_message(format!("invalid or stale hypothesis selection: {error}"))
        }
        other => anyhow::Error::new(other),
    }
}

fn unsupported_cpp_projection_hypothesis(
    gap: &HeaderGap,
    blocker: header::ProjectionBlocker,
) -> RecoveryHypothesis {
    RecoveryHypothesis {
        subject: HypothesisSubject {
            domain: "cpp_header".to_owned(),
            key: gap.id.to_string(),
        },
        unresolved: format!(
            "{} is blocked by {}; no supported projection hypothesis exists",
            recovery_field_name(blocker.field),
            header_reason_name(blocker.reason)
        ),
        candidates: Vec::new(),
        abstention: Some(
            "Macho has no contract-preserving interpretation for this blocker".to_owned(),
        ),
    }
}

fn cpp_symbol_owner_path(
    entity: &crate::analysis::report::RecoveredEntity,
) -> Option<Vec<crate::analysis::report::Identifier>> {
    use crate::analysis::report::Fact;

    let raw = match &entity.linkage {
        Fact::Known { value, .. } => value.raw.as_str(),
        Fact::Conflicted { .. } | Fact::Unavailable { .. } => "",
    };
    let candidate = raw.strip_prefix('_').unwrap_or(raw);
    if candidate.starts_with("_ZZ") || candidate.starts_with("_ZGVZ") {
        return None;
    }
    if let Some(record) = crate::analysis::reconstruct::cpp::symbol::parse_symbol(raw, None, None)
        && let crate::analysis::reconstruct::cpp::CppSymbolKind::Function { decl } = record.kind
        && let Some(parent) = decl.name.parent()
    {
        return parent
            .components
            .iter()
            .map(|component| crate::analysis::report::Identifier::new(component.clone()).ok())
            .collect();
    }
    let mut components = cpp_qualified_components(&entity_name(entity));
    if components.len() < 2 {
        return None;
    }
    components.pop();
    components
        .into_iter()
        .map(|component| crate::analysis::report::Identifier::new(component).ok())
        .collect()
}

fn cpp_qualified_components(value: &str) -> Vec<String> {
    let mut components = Vec::new();
    let mut start = 0;
    let mut angles = 0_u32;
    let mut parentheses = 0_u32;
    let mut brackets = 0_u32;
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'<' => angles += 1,
            b'>' => angles = angles.saturating_sub(1),
            b'(' => parentheses += 1,
            b')' => parentheses = parentheses.saturating_sub(1),
            b'[' => brackets += 1,
            b']' => brackets = brackets.saturating_sub(1),
            b':' if angles == 0
                && parentheses == 0
                && brackets == 0
                && bytes.get(index + 1) == Some(&b':') =>
            {
                components.push(value[start..index].trim().to_owned());
                index += 1;
                start = index + 1;
            }
            _ => {}
        }
        index += 1;
    }
    components.push(value[start..].trim().to_owned());
    components
        .into_iter()
        .filter(|component| !component.is_empty())
        .collect()
}

fn cpp_opaque_return_hypothesis(
    entity: &crate::analysis::report::RecoveredEntity,
    gap: &HeaderGap,
    blocker: header::ProjectionBlocker,
) -> Option<RecoveryHypothesis> {
    use crate::analysis::report::{HeaderIneligibilityReason, RecoveryField};

    (blocker.field == RecoveryField::ReturnType
        && blocker.reason == HeaderIneligibilityReason::UnavailableRequiredFact)
        .then(|| RecoveryHypothesis {
            subject: HypothesisSubject {
                domain: "cpp_header".to_owned(),
                key: gap.id.to_string(),
            },
            unresolved: "the ordinary Itanium function name does not encode a source return type"
                .to_owned(),
            candidates: vec![HypothesisCandidate {
                id: "opaque_return_type".to_owned(),
                rank: 1,
                interpretation: "project an explicit generated opaque return placeholder"
                    .to_owned(),
                evidence_authority: EvidenceAuthority::Heuristic,
                confidence_basis_points: 1_000,
                evidence: candidate_evidence(
                    entity,
                    gap,
                    "the canonical demangler recovered the function shape but no return spelling",
                ),
                rule: format!(
                    "preserve an unavailable return type as {} rather than inventing a concrete ABI type",
                    opaque_return_identifier(gap).as_str()
                ),
                consequences: vec![HypothesisConsequence {
                    stage: "header_projection".to_owned(),
                    subject: Some(entity.id.to_string()),
                    description: "adds a declaration whose return type is intentionally opaque"
                        .to_owned(),
                }],
            }],
            abstention: None,
        })
}

fn cpp_opaque_type_name_hypothesis(
    entity: &crate::analysis::report::RecoveredEntity,
    gap: &HeaderGap,
    blocker: header::ProjectionBlocker,
) -> Option<RecoveryHypothesis> {
    use crate::analysis::report::{HeaderIneligibilityReason, RecoveryField};

    (entity_kind(entity) == Some(EntityKind::Type)
        && blocker.field == RecoveryField::DisplayName
        && blocker.reason == HeaderIneligibilityReason::IncompleteTemplateContext)
        .then(|| RecoveryHypothesis {
            subject: HypothesisSubject {
                domain: "cpp_header".to_owned(),
                key: gap.id.to_string(),
            },
            unresolved:
                "the recovered type spelling cannot be represented as a standalone declaration"
                    .to_owned(),
            candidates: vec![HypothesisCandidate {
                id: "opaque_type_name".to_owned(),
                rank: 1,
                interpretation:
                    "project a stable synthetic record name for this recovered type entity"
                        .to_owned(),
                evidence_authority: EvidenceAuthority::Heuristic,
                confidence_basis_points: 500,
                evidence: candidate_evidence(
                    entity,
                    gap,
                    "the retained type entity remains useful even though its specialization spelling is not declaration-safe",
                ),
                rule: format!(
                    "replace only the unrepresentable declaration leaf with {} and preserve the selected owner",
                    opaque_type_identifier(gap).as_str()
                ),
                consequences: vec![HypothesisConsequence {
                    stage: "header_projection".to_owned(),
                    subject: Some(entity.id.to_string()),
                    description: "adds a synthetic partial class forward declaration; the name, specialization spelling, layout, and ABI remain unauthoritative"
                        .to_owned(),
                }],
            }],
            abstention: None,
        })
}

fn candidate_evidence(
    entity: &crate::analysis::report::RecoveredEntity,
    gap: &HeaderGap,
    description: &str,
) -> Vec<HypothesisEvidenceRef> {
    let mut evidence = vec![HypothesisEvidenceRef {
        kind: HypothesisEvidenceKind::RecoveryGap,
        id: gap.id.to_string(),
        description: format!("unresolved {}", recovery_field_name(gap.field)),
    }];
    if let Some(source) = entity.evidence.first() {
        evidence.push(HypothesisEvidenceRef {
            kind: HypothesisEvidenceKind::Evidence,
            id: source.id.to_string(),
            description: description.to_owned(),
        });
    } else {
        evidence.push(HypothesisEvidenceRef {
            kind: HypothesisEvidenceKind::Entity,
            id: entity.id.to_string(),
            description: description.to_owned(),
        });
    }
    evidence
}

fn cpp_entity_with_opaque_return(
    entity: &crate::analysis::report::RecoveredEntity,
    gap: &HeaderGap,
) -> crate::analysis::report::RecoveredEntity {
    use crate::analysis::report::{EvidenceStrength, Fact, HeaderType, NamedTypeTag, TypeEvidence};

    let mut projection = entity.clone();
    let id = match &projection.signature.return_type {
        Fact::Known { id, .. } | Fact::Conflicted { id, .. } | Fact::Unavailable { id, .. } => {
            id.clone()
        }
    };
    let evidence_id = projection
        .evidence
        .first()
        .expect("a recovered entity retains source evidence")
        .id
        .clone();
    projection.signature.return_type = Fact::Known {
        id,
        value: TypeEvidence::Source {
            ty: HeaderType::Named {
                // The generated preamble declares this name as a class. Use
                // an unelaborated spelling in the function signature so the
                // declaration parses unambiguously as `Type function()`.
                tag: NamedTypeTag::Typedef,
                path: NonEmpty::new(vec![opaque_return_identifier(gap)])
                    .expect("one placeholder component"),
                template_arguments: Vec::new(),
            },
        },
        // This clone exists only long enough to lower a projection. The
        // serialized receipt, not this temporary strength, is its authority.
        strength: EvidenceStrength::Exact,
        evidence_ids: NonEmpty::new(vec![evidence_id]).expect("one source evidence ID"),
    };
    projection
}

fn cpp_entity_with_opaque_type_name(
    entity: &crate::analysis::report::RecoveredEntity,
    gap: &HeaderGap,
    owner: Option<&crate::analysis::report::HeaderOwnerRef>,
) -> crate::analysis::report::RecoveredEntity {
    use crate::analysis::report::{EvidenceStrength, Fact};

    let mut projection = entity.clone();
    let id = match &projection.display_name {
        Fact::Known { id, .. } | Fact::Conflicted { id, .. } | Fact::Unavailable { id, .. } => {
            id.clone()
        }
    };
    let evidence_id = projection
        .evidence
        .first()
        .expect("a recovered entity retains source evidence")
        .id
        .clone();
    let mut components = owner
        .map(|owner| {
            owner
                .path
                .as_slice()
                .iter()
                .map(|component| component.as_str())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let opaque = opaque_type_identifier(gap);
    components.push(opaque.as_str());
    projection.display_name = Fact::Known {
        id,
        value: components.join("::"),
        strength: EvidenceStrength::Exact,
        evidence_ids: NonEmpty::new(vec![evidence_id]).expect("one source evidence ID"),
    };
    projection
}

fn opaque_return_identifier(gap: &HeaderGap) -> crate::analysis::report::Identifier {
    crate::analysis::report::Identifier::new(format!("macho_unknown_return_{}", gap.id))
        .expect("a recovery gap hash produces a valid non-reserved C++ identifier")
}

fn opaque_type_identifier(gap: &HeaderGap) -> crate::analysis::report::Identifier {
    crate::analysis::report::Identifier::new(format!("macho_unknown_type_{}", gap.id))
        .expect("a recovery gap hash produces a valid non-reserved C++ identifier")
}

fn header_gap(
    entity: &crate::analysis::report::RecoveredEntity,
    language: RecoveryLanguage,
    blocker: header::ProjectionBlocker,
) -> HeaderGap {
    HeaderGap {
        id: header_gap_id(&entity.id, blocker.field, blocker.reason),
        entity_id: entity.id.clone(),
        field: blocker.field,
        reason: blocker.reason,
        declaration_template: header_declaration_template(entity, language, blocker),
        diagnostic_ids: Vec::new(),
    }
}

fn header_gap_id(
    entity_id: &crate::analysis::report::EntityId,
    field: crate::analysis::report::RecoveryField,
    reason: HeaderIneligibilityReason,
) -> RecoveryGapId {
    RecoveryGapId::new(sha256_hex(
        format!(
            "macho.header_projection.gap.v1\0{entity_id}\0{}\0{}",
            recovery_field_name(field),
            header_reason_name(reason)
        )
        .as_bytes(),
    ))
    .expect("SHA-256 header projection gap ID")
}

fn header_declaration_template(
    entity: &crate::analysis::report::RecoveredEntity,
    language: RecoveryLanguage,
    blocker: header::ProjectionBlocker,
) -> Option<crate::analysis::report::HeaderDecl> {
    use crate::analysis::report::{HeaderIneligibilityReason, HeaderOwnerKind, HeaderOwnerRef};

    if blocker.reason != HeaderIneligibilityReason::UnprovenOwner {
        return None;
    }
    let mut components = entity_name(entity)
        .split("::")
        .map(|component| crate::analysis::report::Identifier::new(component.to_owned()).ok())
        .collect::<Option<Vec<_>>>()?;
    components.pop()?;
    let scope_kinds = vec![HeaderOwnerKind::Namespace; components.len()];
    let scope_access = vec![None; components.len()];
    let owner = HeaderOwnerRef {
        path: NonEmpty::new(components).ok()?,
        scope_kinds: NonEmpty::new(scope_kinds).ok()?,
        scope_access: NonEmpty::new(scope_access).ok()?,
        member_access: None,
        entity_id: None,
    };
    let (mut declaration, _) = project_entity_with_owner(entity, language, Some(&owner)).ok()?;
    strip_declaration_owner(&mut declaration)?;
    Some(declaration)
}

fn strip_declaration_owner(declaration: &mut crate::analysis::report::HeaderDecl) -> Option<()> {
    use crate::analysis::report::HeaderDecl;

    match declaration {
        HeaderDecl::Function { owner, .. }
        | HeaderDecl::Variable { owner, .. }
        | HeaderDecl::Record { owner, .. }
        | HeaderDecl::Forward { owner, .. } => *owner = None,
        HeaderDecl::Alias { path, .. } => {
            *path = NonEmpty::new(vec![path.as_slice().last()?.clone()]).ok()?;
        }
        HeaderDecl::ObjcInterface { .. }
        | HeaderDecl::ObjcCategory { .. }
        | HeaderDecl::ObjcProtocol { .. }
        | HeaderDecl::ObjcForward { .. } => return None,
    }
    Some(())
}

fn empty_header_source(
    language: RecoveryLanguage,
    selected: usize,
    unresolved: &[HeaderGap],
    executions: &[CollectorExecution],
) -> String {
    let mut blockers = std::collections::BTreeMap::<(&'static str, &'static str), usize>::new();
    for gap in unresolved {
        *blockers
            .entry((
                recovery_field_name(gap.field),
                header_reason_name(gap.reason),
            ))
            .or_default() += 1;
    }
    let mut source = format!(
        "#pragma once\n/*\n * macho {} recovery: no independently projectable declarations.\n * selected source entities: {selected}; exact projection blockers: {}.\n",
        language_name(language),
        unresolved.len()
    );
    for execution in executions {
        if let CollectorOutcome::Unsupported { reason } = execution.outcome {
            use std::fmt::Write as _;
            let _ = writeln!(
                source,
                " * collector {}: unsupported ({}).",
                collector_name(execution.collector),
                unsupported_reason_name(reason)
            );
        }
    }
    if !blockers.is_empty() {
        source.push_str(" * blockers:\n");
        for ((field, reason), count) in blockers {
            use std::fmt::Write as _;
            let _ = writeln!(source, " *   {field}/{reason}: {count}");
        }
        source.push_str(" * exact blocker IDs: JSON slices[].header.unresolved[].id\n");
        source.push_str(
            " * next: emit --format json, then use macho header-infer export --all-header-gaps.\n",
        );
    }
    source.push_str(" */\n");
    source
}

fn collector_name(value: CollectorId) -> &'static str {
    match value {
        CollectorId::SymbolDiscovery => "symbol_discovery",
        CollectorId::FunctionRanges => "function_ranges",
        CollectorId::Dwarf => "dwarf",
        CollectorId::Rtti => "rtti",
        CollectorId::Vtables => "vtables",
        CollectorId::HeaderCorrelation => "header_correlation",
        CollectorId::AbiBody => "abi_body",
        CollectorId::HeaderProjection => "header_projection",
    }
}

fn unsupported_reason_name(value: crate::analysis::report::UnsupportedReasonCode) -> &'static str {
    use crate::analysis::report::UnsupportedReasonCode;
    match value {
        UnsupportedReasonCode::Architecture => "architecture",
        UnsupportedReasonCode::Format => "format",
        UnsupportedReasonCode::MissingSection => "missing_section",
        UnsupportedReasonCode::MissingDebugInfo => "missing_debug_info",
        UnsupportedReasonCode::MissingRuntimeMetadata => "missing_runtime_metadata",
        UnsupportedReasonCode::HeaderLanguageSubset => "header_language_subset",
    }
}

fn recovery_field_name(value: crate::analysis::report::RecoveryField) -> &'static str {
    use crate::analysis::report::RecoveryField;
    match value {
        RecoveryField::Linkage => "linkage",
        RecoveryField::DisplayName => "display_name",
        RecoveryField::Role => "role",
        RecoveryField::Presence => "presence",
        RecoveryField::Visibility => "visibility",
        RecoveryField::Weakness => "weakness",
        RecoveryField::Location => "location",
        RecoveryField::Owner => "owner",
        RecoveryField::ValueType => "value_type",
        RecoveryField::ReturnType => "return_type",
        RecoveryField::Parameters => "parameters",
        RecoveryField::Variadic => "variadic",
        RecoveryField::CallingConvention => "calling_convention",
        RecoveryField::Qualifiers => "qualifiers",
        RecoveryField::LayoutSize => "layout_size",
        RecoveryField::LayoutAlignment => "layout_alignment",
        RecoveryField::LayoutFields => "layout_fields",
        RecoveryField::LayoutCompleteness => "layout_completeness",
        RecoveryField::Bases => "bases",
        RecoveryField::VirtualSurface => "virtual_surface",
    }
}

fn header_reason_name(value: HeaderIneligibilityReason) -> &'static str {
    match value {
        HeaderIneligibilityReason::UnavailableRequiredFact => "unavailable_required_fact",
        HeaderIneligibilityReason::ConflictedRequiredFact => "conflicted_required_fact",
        HeaderIneligibilityReason::AbiClassIsNotSourceType => "abi_class_is_not_source_type",
        HeaderIneligibilityReason::UnsupportedType => "unsupported_type",
        HeaderIneligibilityReason::UnsupportedCallingConvention => "unsupported_calling_convention",
        HeaderIneligibilityReason::UnprovenOwner => "unproven_owner",
        HeaderIneligibilityReason::IncompleteLayout => "incomplete_layout",
        HeaderIneligibilityReason::IncompleteTemplateContext => "incomplete_template_context",
        HeaderIneligibilityReason::InvalidLinkage => "invalid_linkage",
        HeaderIneligibilityReason::SemanticValidationFailed => "semantic_validation_failed",
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

    #[test]
    fn header_gap_identity_uses_frozen_wire_tokens() {
        let entity = crate::analysis::report::EntityId::new("a".repeat(64)).unwrap();
        let gap = header_gap_id(
            &entity,
            crate::analysis::report::RecoveryField::Owner,
            HeaderIneligibilityReason::UnprovenOwner,
        );
        assert_eq!(
            gap.as_str(),
            "c2731c1646cfca767a19c769b7e68f0ef58872f34849bec24847521eadec9e8c"
        );
    }
}
