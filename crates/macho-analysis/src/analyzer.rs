//! Dependency-driven, selective analysis and schema-v3 snapshots.

mod payload;
mod typed;

pub use payload::DomainPayload;
pub use typed::{DomainReportKey, domain_reports};

use std::collections::{BTreeMap, BTreeSet};

use macho_core::model::container::MachoContainer;
use macho_core::model::macho_file::MachoFile;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::error::{AnalysisDomain, AnalysisError, AnalysisErrorKind, Result};
use crate::planner::{AnalysisLimits, AnalysisPlan, DependencyKind, dependencies, resolve_domains};

/// The SNAPSHOT_SCHEMA_VERSION constant.
pub const SNAPSHOT_SCHEMA_VERSION: u32 = 3;

const ADVISORY_DEPENDENCY_FAILED_CODE: &str = "analysis.dependency.advisory_failed";
const ADVISORY_DEPENDENCY_UNSUPPORTED_CODE: &str = "analysis.dependency.advisory_unsupported";
const REQUIRED_DEPENDENCY_FAILED_CODE: &str = "analysis.dependency.required_failed";
const LIMIT_TRUNCATED_CODE: &str = "analysis.limit.truncated";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// The AnalysisIssue type.
pub struct AnalysisIssue {
    /// The code field.
    pub code: String,
    /// The message field.
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// The AnalysisFailure type.
pub struct AnalysisFailure {
    /// The code field.
    pub code: String,
    /// The message field.
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// The UnsupportedReason type.
pub struct UnsupportedReason {
    /// The code field.
    pub code: String,
    /// The message field.
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
/// The DomainState type.
#[non_exhaustive]
pub enum DomainState<T> {
    /// The NotRequested variant.
    NotRequested,
    /// The Complete variant.
    Complete {
        /// The T field.
        value: T,
        /// The item field.
        issues: Vec<AnalysisIssue>,
    },
    /// The Unsupported variant.
    Unsupported {
        /// The UnsupportedReason field.
        reason: UnsupportedReason,
    },
    /// The Failed variant.
    Failed {
        /// The AnalysisFailure field.
        error: AnalysisFailure,
        /// The item field.
        issues: Vec<AnalysisIssue>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// The ContainerIdentity type.
pub struct ContainerIdentity {
    /// The format field.
    pub format: String,
    /// Number of selected slices present in this snapshot document.
    pub slice_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// The SliceIdentity type.
pub struct SliceIdentity {
    /// The index field.
    pub index: usize,
    /// The arch field.
    pub arch: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// The SliceSnapshot type.
pub struct SliceSnapshot {
    /// The identity field.
    pub identity: SliceIdentity,
    /// The domains field.
    pub domains: BTreeMap<AnalysisDomain, DomainState<DomainPayload>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// The SnapshotDocument type.
pub struct SnapshotDocument {
    /// The schema_version field.
    pub schema_version: u32,
    /// The container field.
    pub container: ContainerIdentity,
    /// The slices field.
    pub slices: Vec<SliceSnapshot>,
}

/// The AnalysisDocument type.
pub type AnalysisDocument = SnapshotDocument;

impl SnapshotDocument {
    /// Performs from_json.
    pub fn from_json(input: &str) -> Result<Self> {
        let value: Value = serde_json::from_str(input).map_err(|error| {
            snapshot_error(format!(
                "invalid snapshot JSON: {error}; regenerate the snapshot"
            ))
        })?;
        let version = value
            .get("schema_version")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                snapshot_error("snapshot is unversioned; regenerate it with macho 0.2")
            })?;
        if version != SNAPSHOT_SCHEMA_VERSION as u64 {
            return Err(snapshot_error(format!(
                "unsupported snapshot schema version {version}; expected {SNAPSHOT_SCHEMA_VERSION}; regenerate it"
            )));
        }
        let document: Self = serde_json::from_value(value).map_err(|error| {
            snapshot_error(format!(
                "invalid schema-v3 snapshot: {error}; regenerate it"
            ))
        })?;
        document.validate()?;
        Ok(document)
    }

    /// Performs validate.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != SNAPSHOT_SCHEMA_VERSION {
            return Err(snapshot_error(format!(
                "unsupported snapshot schema version {}; expected {}",
                self.schema_version, SNAPSHOT_SCHEMA_VERSION
            )));
        }
        if self.slices.is_empty() {
            return Err(snapshot_error("snapshot must contain at least one slice"));
        }
        if self.container.slice_count != self.slices.len() {
            return Err(snapshot_error(format!(
                "container declares {} slice(s), but snapshot contains {}",
                self.container.slice_count,
                self.slices.len()
            )));
        }
        for slice in &self.slices {
            for domain in AnalysisDomain::ALL {
                let state = slice.domains.get(domain).ok_or_else(|| {
                    snapshot_error(format!(
                        "slice {} is missing domain {}",
                        slice.identity.arch,
                        domain.as_str()
                    ))
                })?;
                if let DomainState::Complete { value, .. } = state {
                    if value.domain() != *domain {
                        return Err(snapshot_error(format!(
                            "domain {} contains {} payload",
                            domain.as_str(),
                            value.domain().as_str()
                        )));
                    }
                }
            }
        }
        Ok(())
    }
}

fn snapshot_error(message: impl Into<String>) -> AnalysisError {
    AnalysisError::new(
        AnalysisDomain::Container,
        AnalysisErrorKind::InvalidInput,
        message,
    )
}

impl AnalysisDomain {
    /// The ALL constant.
    pub const ALL: &'static [Self] = &[
        Self::Container,
        Self::Header,
        Self::LoadCommands,
        Self::Segments,
        Self::Relocations,
        Self::Symbols,
        Self::Exports,
        Self::Imports,
        Self::Fixups,
        Self::Codesign,
        Self::Objc,
        Self::Swift,
        Self::Dwarf,
        Self::Vtables,
        Self::Strings,
        Self::Ranges,
        Self::Xrefs,
        Self::Dependencies,
        Self::Audit,
        Self::CSurface,
        Self::CppSurface,
        Self::ObjcHeaders,
    ];

    /// Performs as_str.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Container => "container",
            Self::Header => "header",
            Self::LoadCommands => "load_commands",
            Self::Segments => "segments",
            Self::Relocations => "relocations",
            Self::Symbols => "symbols",
            Self::Exports => "exports",
            Self::Imports => "imports",
            Self::Fixups => "fixups",
            Self::Codesign => "codesign",
            Self::Objc => "objc",
            Self::Swift => "swift",
            Self::Dwarf => "dwarf",
            Self::Vtables => "vtables",
            Self::Strings => "strings",
            Self::Ranges => "ranges",
            Self::Xrefs => "xrefs",
            Self::Dependencies => "dependencies",
            Self::Audit => "audit",
            Self::CSurface => "c_surface",
            Self::CppSurface => "cpp_surface",
            Self::ObjcHeaders => "objc_headers",
        }
    }
}

#[derive(Debug, Default)]
struct FactStore {
    values: BTreeMap<AnalysisDomain, Value>,
    issues: BTreeMap<AnalysisDomain, Vec<AnalysisIssue>>,
}

#[derive(Debug, Default)]
/// The Analyzer type.
pub struct Analyzer;

/// Testability and telemetry hook invoked immediately before a selected domain runner.
pub trait DomainObserver: Send + Sync {
    /// Observe one runner invocation or return an injected typed failure.
    fn before_domain(&self, domain: AnalysisDomain) -> Result<()>;
}

#[derive(Debug)]
struct NoopObserver;

impl DomainObserver for NoopObserver {
    fn before_domain(&self, _domain: AnalysisDomain) -> Result<()> {
        Ok(())
    }
}

struct SliceRunContext<'a> {
    resolved: &'a BTreeSet<AnalysisDomain>,
    limits: &'a AnalysisLimits,
    audit_rules: Option<&'a BTreeSet<String>>,
    heuristic_strings: bool,
    observer: &'a dyn DomainObserver,
}

impl Analyzer {
    /// Performs run.
    pub fn run(
        &self,
        container: &MachoContainer<'_>,
        plan: &AnalysisPlan,
    ) -> Result<AnalysisDocument> {
        self.run_with_observer(container, plan, &NoopObserver)
    }

    /// Run a plan with an injected observer used to prove runner selectivity.
    pub fn run_with_observer(
        &self,
        container: &MachoContainer<'_>,
        plan: &AnalysisPlan,
        observer: &dyn DomainObserver,
    ) -> Result<AnalysisDocument> {
        let resolved = resolve_domains(plan);
        let images: Vec<&MachoFile<'_>> = container.macho_files().collect();
        if let Some(selected) = &plan.selected_slices {
            let unmatched = selected
                .iter()
                .filter(|selector| {
                    !images.iter().any(|macho| {
                        macho
                            .header()
                            .arch_spec()
                            .matches_selector(selector.as_str())
                    })
                })
                .cloned()
                .collect::<Vec<_>>();
            if !unmatched.is_empty() {
                return Err(AnalysisError::invalid(format!(
                    "no architecture matching '{}' found",
                    unmatched.join(", ")
                )));
            }
        }
        let format = match container {
            MachoContainer::Thin(_) => "thin",
            MachoContainer::Fat(_) => "fat",
        }
        .to_string();
        let mut slices = Vec::new();
        let run_context = SliceRunContext {
            resolved: &resolved,
            limits: &plan.limits,
            audit_rules: plan.audit_rules.as_ref(),
            heuristic_strings: plan.heuristic_strings,
            observer,
        };
        for (index, macho) in images.into_iter().enumerate() {
            let architecture = macho.header().arch_spec();
            if plan.selected_slices.as_ref().is_some_and(|selected| {
                !selected
                    .iter()
                    .any(|selector| architecture.matches_selector(selector))
            }) {
                continue;
            }
            let arch = architecture.name();
            slices.push(self.run_slice(index, arch, macho, &run_context)?);
        }
        let document = SnapshotDocument {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            container: ContainerIdentity {
                format,
                // Snapshot identity describes the emitted document, so an
                // architecture filter reports only the selected slices.
                slice_count: slices.len(),
            },
            slices,
        };
        document.validate()?;
        Ok(document)
    }

    fn run_slice(
        &self,
        index: usize,
        arch: String,
        macho: &MachoFile<'_>,
        run: &SliceRunContext<'_>,
    ) -> Result<SliceSnapshot> {
        let mut states = AnalysisDomain::ALL
            .iter()
            .copied()
            .map(|domain| (domain, DomainState::NotRequested))
            .collect::<BTreeMap<_, _>>();
        let mut facts = FactStore::default();
        for domain in AnalysisDomain::ALL.iter().copied() {
            if !run.resolved.contains(&domain) {
                continue;
            }
            let mut inherited = Vec::new();
            let mut blocked = None;
            for dependency in dependencies(domain) {
                match states
                    .get(&dependency.domain)
                    .expect("resolved prerequisite has state")
                {
                    DomainState::Failed { error, .. }
                        if dependency.kind == DependencyKind::Required =>
                    {
                        blocked = Some(DomainState::Failed {
                            error: error.clone(),
                            issues: vec![dependency_issue(dependency.domain)],
                        })
                    }
                    DomainState::Unsupported { reason }
                        if dependency.kind == DependencyKind::Required =>
                    {
                        blocked = Some(DomainState::Unsupported {
                            reason: reason.clone(),
                        })
                    }
                    DomainState::Failed { error, .. } => inherited.push(AnalysisIssue {
                        code: ADVISORY_DEPENDENCY_FAILED_CODE.into(),
                        message: format!(
                            "advisory dependency {} failed: {}",
                            dependency.domain.as_str(),
                            error.message
                        ),
                    }),
                    DomainState::Unsupported { reason } => inherited.push(AnalysisIssue {
                        code: ADVISORY_DEPENDENCY_UNSUPPORTED_CODE.into(),
                        message: format!(
                            "advisory dependency {} unsupported: {}",
                            dependency.domain.as_str(),
                            reason.message
                        ),
                    }),
                    _ => {}
                }
                if blocked.is_some() {
                    break;
                }
            }
            let state = if let Some(blocked) = blocked {
                blocked
            } else {
                match run.observer.before_domain(domain).and_then(|()| {
                    run_domain(
                        domain,
                        macho,
                        run.limits,
                        run.audit_rules,
                        run.heuristic_strings,
                        &facts,
                    )
                }) {
                    Ok((payload, mut issues)) => {
                        inherited.append(&mut issues);
                        bound_issues(domain, &mut inherited, run.limits.max_issues_per_domain);
                        facts.issues.insert(domain, inherited.clone());
                        facts.values.insert(domain, payload_value(&payload).clone());
                        DomainState::Complete {
                            value: payload,
                            issues: inherited,
                        }
                    }
                    Err(error) if error.kind == AnalysisErrorKind::UnsupportedCapability => {
                        DomainState::Unsupported {
                            reason: UnsupportedReason {
                                code: error.code().into(),
                                message: error.message().into(),
                            },
                        }
                    }
                    Err(error) => DomainState::Failed {
                        error: AnalysisFailure {
                            code: error.code().into(),
                            message: error.message().into(),
                        },
                        issues: inherited,
                    },
                }
            };
            states.insert(domain, state);
        }
        Ok(SliceSnapshot {
            identity: SliceIdentity { index, arch },
            domains: states,
        })
    }
}

fn dependency_issue(domain: AnalysisDomain) -> AnalysisIssue {
    AnalysisIssue {
        code: REQUIRED_DEPENDENCY_FAILED_CODE.into(),
        message: format!("required dependency {} did not complete", domain.as_str()),
    }
}

fn serialize<T: Serialize>(domain: AnalysisDomain, value: T) -> Result<Value> {
    serde_json::to_value(value).map_err(|error| {
        AnalysisError::new(
            domain,
            AnalysisErrorKind::Validation,
            format!("serialize domain payload: {error}"),
        )
    })
}

fn bounded_collection_issue(domain: AnalysisDomain, limit: usize, resource: &str) -> AnalysisIssue {
    AnalysisIssue {
        code: LIMIT_TRUNCATED_CODE.into(),
        message: format!(
            "{} {resource} reached configured limit {limit}",
            domain.as_str()
        ),
    }
}

fn bound_issues(domain: AnalysisDomain, issues: &mut Vec<AnalysisIssue>, limit: usize) {
    if issues.len() <= limit {
        return;
    }
    if limit == 0 {
        issues.clear();
    } else {
        issues.truncate(limit - 1);
    }
    issues.push(bounded_collection_issue(domain, limit, "issues"));
}

fn run_domain(
    domain: AnalysisDomain,
    macho: &MachoFile<'_>,
    limits: &AnalysisLimits,
    audit_rules: Option<&BTreeSet<String>>,
    heuristic_strings: bool,
    facts: &FactStore,
) -> Result<(DomainPayload, Vec<AnalysisIssue>)> {
    use AnalysisDomain as D;
    let mut issues = Vec::new();
    let payload = match domain {
        D::Container => DomainPayload::Container(
            json!({ "file_type": macho.header().file_type().name(), "size": macho.bytes().len() }),
        ),
        D::Header => {
            DomainPayload::Header(serialize(domain, crate::snapshot::extract_header(macho))?)
        }
        D::LoadCommands => DomainPayload::LoadCommands(serialize(
            domain,
            crate::snapshot::extract_load_commands(macho),
        )?),
        D::Segments => {
            DomainPayload::Segments(serialize(domain, crate::snapshot::extract_segments(macho))?)
        }
        D::Relocations => {
            let mut sections = Vec::new();
            for section in macho.all_sections() {
                let relocations = crate::format::relocations_for_section(macho, section)?;
                if !relocations.is_empty() {
                    sections.push(json!({ "segment": section.segment_name().to_string(), "section": section.section_name().to_string(), "count": relocations.len() }));
                }
            }
            DomainPayload::Relocations(Value::Array(sections))
        }
        D::Symbols => {
            let value = crate::snapshot::extract_symbols(macho, &mut issues);
            DomainPayload::Symbols(serialize(domain, value)?)
        }
        D::Exports => {
            let value = crate::snapshot::extract_exports(macho, &mut issues);
            DomainPayload::Exports(serialize(domain, value)?)
        }
        D::Imports => {
            let value = crate::snapshot::extract_imports(macho, &mut issues);
            DomainPayload::Imports(serialize(domain, value)?)
        }
        D::Fixups => {
            let value = crate::snapshot::extract_fixups(macho, &mut issues);
            DomainPayload::Fixups(serialize(domain, value)?)
        }
        D::Codesign => {
            let value = crate::snapshot::extract_codesign(macho, &mut issues);
            DomainPayload::Codesign(serialize(domain, value)?)
        }
        D::Objc => {
            let report = crate::report::recover_objc_surface(macho)?;
            DomainPayload::Objc(serialize(domain, report)?)
        }
        D::Swift => {
            let report = crate::report::recover_swift_surface(macho)?;
            DomainPayload::Swift(serialize(domain, report)?)
        }
        D::Dwarf => {
            let index = macho_dwarf::DwarfFunctionIndex::build(macho)?;
            DomainPayload::Dwarf(json!({ "function_count": index.len() }))
        }
        D::Vtables => {
            let index = macho_cpp::VtableIndex::build_limited(macho, limits.max_vtables_per_slice)?;
            if index.was_truncated() {
                issues.push(bounded_collection_issue(
                    domain,
                    limits.max_vtables_per_slice,
                    "vtables",
                ));
            }
            DomainPayload::Vtables(serialize(domain, index.vtables())?)
        }
        D::Strings => {
            let regions = if heuristic_strings {
                crate::strings::StringRegions::with_heuristic(macho)
            } else {
                crate::strings::StringRegions::discover(macho)
            };
            let (values, truncated) =
                regions.all_strings_limited(macho, limits.max_strings_per_slice);
            if truncated {
                issues.push(bounded_collection_issue(
                    domain,
                    limits.max_strings_per_slice,
                    "strings",
                ));
            }
            DomainPayload::Strings(serialize(domain, values)?)
        }
        D::Ranges => {
            let index = crate::xref::ranges::SymbolRangeIndex::build_limited(
                macho,
                limits.max_ranges_per_slice,
            )?;
            if index.was_truncated() {
                issues.push(bounded_collection_issue(
                    domain,
                    limits.max_ranges_per_slice,
                    "ranges",
                ));
            }
            DomainPayload::Ranges(serialize(domain, index.entries())?)
        }
        D::Xrefs => {
            let cpu_type = macho.header().cpu_type().0;
            if !matches!(
                cpu_type,
                crate::format::constants::CPU_TYPE_ARM64
                    | crate::format::constants::CPU_TYPE_X86_64
            ) {
                return Err(AnalysisError::new(
                    domain,
                    AnalysisErrorKind::UnsupportedCapability,
                    format!(
                        "cross-reference instruction decoding does not support architecture {}",
                        macho.header().cpu_type().name()
                    ),
                ));
            }
            let index = crate::xref::refs::XrefIndex::build_limited(
                macho,
                limits.max_xrefs_per_slice,
                limits.max_decoded_bytes_per_slice,
            )?;
            for gap in index.decode_gaps() {
                issues.push(AnalysisIssue {
                    code: macho_insn::DecodeError::CODE.into(),
                    message: format!(
                        "skipped {} invalid byte(s) at VA {:#x}: {}",
                        gap.len, gap.va, gap.error
                    ),
                });
            }
            if index.refs_truncated() {
                issues.push(bounded_collection_issue(
                    domain,
                    limits.max_xrefs_per_slice,
                    "cross-references",
                ));
            }
            if index.decoded_bytes_truncated() {
                issues.push(bounded_collection_issue(
                    domain,
                    limits.max_decoded_bytes_per_slice,
                    "decoded bytes",
                ));
            }
            DomainPayload::Xrefs(serialize(domain, index.all_refs())?)
        }
        D::Dependencies => {
            let graph = crate::deps::DepGraph::build(macho)?;
            DomainPayload::Dependencies(
                json!({ "install_name": graph.install_name, "dylib_count": graph.dylibs.len(), "import_count": graph.imports.len(), "export_count": graph.exports.len() }),
            )
        }
        D::Audit => {
            let input = crate::audit::AuditInput {
                arch: macho.header().arch_spec().name(),
                header: optional_fact(facts, D::Header)?,
                load_commands: optional_fact(facts, D::LoadCommands)?,
                segments: optional_fact(facts, D::Segments)?,
                codesign: optional_fact(facts, D::Codesign)?.flatten(),
                analysis_issues: facts.issues.get(&D::Codesign).cloned().unwrap_or_default(),
                enabled_rules: audit_rules.cloned().unwrap_or_else(|| {
                    crate::audit::rules::all_rule_ids()
                        .into_iter()
                        .map(str::to_owned)
                        .collect()
                }),
            };
            DomainPayload::Audit(serialize(domain, crate::audit::audit_slice(&input))?)
        }
        D::CSurface => {
            let report = crate::report::recover_symbol_surface(
                macho,
                crate::report::RecoveryLanguage::CAbi,
            )?;
            DomainPayload::CSurface(serialize(domain, report)?)
        }
        D::CppSurface => {
            let report =
                crate::report::recover_symbol_surface(macho, crate::report::RecoveryLanguage::Cpp)?;
            DomainPayload::CppSurface(serialize(domain, report)?)
        }
        D::ObjcHeaders => {
            let mut report = crate::report::recover_objc_surface(macho)?;
            crate::report::project_objc_headers(&mut report)?;
            DomainPayload::ObjcHeaders(serialize(domain, report)?)
        }
    };
    Ok((payload, issues))
}

fn payload_value(payload: &DomainPayload) -> &Value {
    payload.value()
}

fn optional_fact<T: DeserializeOwned>(
    facts: &FactStore,
    domain: AnalysisDomain,
) -> Result<Option<T>> {
    facts
        .values
        .get(&domain)
        .map(|value| {
            serde_json::from_value(value.clone()).map_err(|error| {
                AnalysisError::new(
                    AnalysisDomain::Audit,
                    AnalysisErrorKind::Validation,
                    format!("decode optional audit fact {}: {error}", domain.as_str()),
                )
            })
        })
        .transpose()
}

#[cfg(test)]
#[path = "analyzer/tests.rs"]
mod tests;
