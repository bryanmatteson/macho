//! Public plan front ends and dependency resolution for selective analysis.

use std::collections::BTreeSet;

use crate::error::AnalysisDomain;

/// Hard collection and decode limits applied independently to each slice.
#[derive(Debug, Clone)]
pub struct AnalysisLimits {
    /// The max_strings_per_slice field.
    pub max_strings_per_slice: usize,
    /// The max_xrefs_per_slice field.
    pub max_xrefs_per_slice: usize,
    /// The max_ranges_per_slice field.
    pub max_ranges_per_slice: usize,
    /// The max_vtables_per_slice field.
    pub max_vtables_per_slice: usize,
    /// The max_decoded_bytes_per_slice field.
    pub max_decoded_bytes_per_slice: usize,
    /// The max_issues_per_domain field.
    pub max_issues_per_domain: usize,
}

impl Default for AnalysisLimits {
    fn default() -> Self {
        Self {
            max_strings_per_slice: 100_000,
            max_xrefs_per_slice: 1_000_000,
            max_ranges_per_slice: 1_000_000,
            max_vtables_per_slice: 100_000,
            max_decoded_bytes_per_slice: 64 * 1024 * 1024,
            max_issues_per_domain: 1_000,
        }
    }
}

/// Fully compiled analysis request consumed by [`crate::Analyzer`].
#[derive(Debug, Clone)]
pub struct AnalysisPlan {
    pub(crate) selected_slices: Option<BTreeSet<String>>,
    pub(crate) domains: BTreeSet<AnalysisDomain>,
    pub(crate) excluded: BTreeSet<AnalysisDomain>,
    /// The limits field.
    pub limits: AnalysisLimits,
    pub(crate) audit_rules: Option<BTreeSet<String>>,
    pub(crate) heuristic_strings: bool,
}

impl AnalysisPlan {
    /// Performs new.
    pub fn new(domains: impl IntoIterator<Item = AnalysisDomain>) -> Self {
        Self {
            selected_slices: None,
            domains: domains.into_iter().collect(),
            excluded: BTreeSet::new(),
            limits: AnalysisLimits::default(),
            audit_rules: None,
            heuristic_strings: true,
        }
    }

    /// Performs all.
    pub fn all() -> Self {
        Self::new(AnalysisDomain::ALL.iter().copied())
    }

    /// Performs with_slices.
    pub fn with_slices(mut self, arches: impl IntoIterator<Item = String>) -> Self {
        self.selected_slices = Some(arches.into_iter().collect());
        self
    }

    /// Performs with_limits.
    pub fn with_limits(mut self, limits: AnalysisLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Configure whether string analysis also scans plausible untyped text sections.
    pub fn with_heuristic_strings(mut self, enabled: bool) -> Self {
        self.heuristic_strings = enabled;
        self
    }

    /// Performs excluding.
    pub fn excluding(mut self, domains: impl IntoIterator<Item = AnalysisDomain>) -> Self {
        self.excluded.extend(domains);
        self
    }

    /// Performs domains.
    pub fn domains(&self) -> &BTreeSet<AnalysisDomain> {
        &self.domains
    }
}

/// Selective comparison plan. Exclusions are applied before either input runs.
#[derive(Debug, Clone)]
pub struct DiffPlan {
    domains: BTreeSet<AnalysisDomain>,
    excluded: BTreeSet<AnalysisDomain>,
    slices: Option<BTreeSet<String>>,
    limits: AnalysisLimits,
}

impl Default for DiffPlan {
    fn default() -> Self {
        Self {
            domains: [
                AnalysisDomain::Header,
                AnalysisDomain::LoadCommands,
                AnalysisDomain::Segments,
                AnalysisDomain::Symbols,
                AnalysisDomain::Exports,
                AnalysisDomain::Imports,
                AnalysisDomain::Fixups,
                AnalysisDomain::Codesign,
                AnalysisDomain::Objc,
            ]
            .into_iter()
            .collect(),
            excluded: BTreeSet::new(),
            slices: None,
            limits: AnalysisLimits::default(),
        }
    }
}

impl DiffPlan {
    /// Performs exclude.
    pub fn exclude(mut self, domain: AnalysisDomain) -> Self {
        self.domains.remove(&domain);
        self.excluded.insert(domain);
        self
    }

    /// Performs with_slices.
    pub fn with_slices(mut self, arches: impl IntoIterator<Item = String>) -> Self {
        self.slices = Some(arches.into_iter().collect());
        self
    }

    /// Replace the bounded collection and decode limits for both inputs.
    pub fn with_limits(mut self, limits: AnalysisLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Performs compile.
    pub fn compile(&self) -> AnalysisPlan {
        let mut plan = AnalysisPlan::new(self.domains.iter().copied())
            .excluding(self.excluded.iter().copied())
            .with_limits(self.limits.clone());
        plan.selected_slices = self.slices.clone();
        plan
    }

    /// Performs selected_domains.
    pub fn selected_domains(&self) -> &BTreeSet<AnalysisDomain> {
        &self.domains
    }
}

/// Data declaration for one audit rule's domain needs.
#[derive(Debug, Clone, Copy)]
pub struct AuditRuleSpec {
    /// The id field.
    pub id: &'static str,
    /// The required field.
    pub required: &'static [AnalysisDomain],
    /// The advisory field.
    pub advisory: &'static [AnalysisDomain],
}

const AUDIT_RULES: &[AuditRuleSpec] = &[
    AuditRuleSpec {
        id: "CS000",
        required: &[AnalysisDomain::LoadCommands],
        advisory: &[AnalysisDomain::Codesign],
    },
    AuditRuleSpec {
        id: "CS001",
        required: &[AnalysisDomain::Header, AnalysisDomain::LoadCommands],
        advisory: &[],
    },
    AuditRuleSpec {
        id: "CS002",
        required: &[],
        advisory: &[AnalysisDomain::Codesign],
    },
    AuditRuleSpec {
        id: "CS003",
        required: &[],
        advisory: &[AnalysisDomain::Codesign],
    },
    AuditRuleSpec {
        id: "CS004",
        required: &[],
        advisory: &[AnalysisDomain::Codesign],
    },
    AuditRuleSpec {
        id: "CS005",
        required: &[],
        advisory: &[AnalysisDomain::Codesign],
    },
    AuditRuleSpec {
        id: "LP001",
        required: &[AnalysisDomain::LoadCommands],
        advisory: &[],
    },
    AuditRuleSpec {
        id: "LP002",
        required: &[AnalysisDomain::LoadCommands],
        advisory: &[],
    },
    AuditRuleSpec {
        id: "LP003",
        required: &[AnalysisDomain::LoadCommands],
        advisory: &[],
    },
    AuditRuleSpec {
        id: "LP004",
        required: &[AnalysisDomain::LoadCommands],
        advisory: &[],
    },
    AuditRuleSpec {
        id: "LP005",
        required: &[AnalysisDomain::LoadCommands],
        advisory: &[],
    },
    AuditRuleSpec {
        id: "MEM001",
        required: &[AnalysisDomain::Segments],
        advisory: &[],
    },
    AuditRuleSpec {
        id: "MEM002",
        required: &[AnalysisDomain::Header],
        advisory: &[],
    },
    AuditRuleSpec {
        id: "MEM003",
        required: &[AnalysisDomain::Header],
        advisory: &[],
    },
    AuditRuleSpec {
        id: "CTR001",
        required: &[AnalysisDomain::Segments],
        advisory: &[],
    },
];

/// Front end that derives analysis work from enabled audit rules.
#[derive(Debug, Clone)]
pub struct AuditPlan {
    enabled: BTreeSet<String>,
    slices: Option<BTreeSet<String>>,
    limits: AnalysisLimits,
}

impl Default for AuditPlan {
    fn default() -> Self {
        Self {
            enabled: AUDIT_RULES.iter().map(|rule| rule.id.to_owned()).collect(),
            slices: None,
            limits: AnalysisLimits::default(),
        }
    }
}

impl AuditPlan {
    /// Disable one registered audit rule by stable rule ID.
    pub fn excluding_rule(mut self, id: &str) -> Self {
        self.enabled.remove(id);
        self
    }

    /// Performs with_slices.
    pub fn with_slices(mut self, arches: impl IntoIterator<Item = String>) -> Self {
        self.slices = Some(arches.into_iter().collect());
        self
    }

    /// Replace the bounded collection and decode limits for this audit.
    pub fn with_limits(mut self, limits: AnalysisLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Performs compile.
    pub fn compile(&self) -> AnalysisPlan {
        let mut domains = BTreeSet::from([AnalysisDomain::Audit]);
        for rule in AUDIT_RULES
            .iter()
            .filter(|rule| self.enabled.contains(rule.id))
        {
            domains.extend(rule.required.iter().copied());
            domains.extend(rule.advisory.iter().copied());
        }
        let mut plan = AnalysisPlan::new(domains).with_limits(self.limits.clone());
        plan.selected_slices = self.slices.clone();
        plan.audit_rules = Some(self.enabled.clone());
        plan
    }

    /// Performs rule_specs.
    pub fn rule_specs() -> &'static [AuditRuleSpec] {
        AUDIT_RULES
    }
}

/// Front end for multi-slice parity analysis.
#[derive(Debug, Clone)]
pub struct ContainerPlan {
    domains: BTreeSet<AnalysisDomain>,
    slices: Option<BTreeSet<String>>,
    limits: AnalysisLimits,
}

impl ContainerPlan {
    /// Performs new.
    pub fn new(domains: impl IntoIterator<Item = AnalysisDomain>) -> Self {
        Self {
            domains: domains.into_iter().collect(),
            slices: None,
            limits: AnalysisLimits::default(),
        }
    }

    /// Performs with_slices.
    pub fn with_slices(mut self, arches: impl IntoIterator<Item = String>) -> Self {
        self.slices = Some(arches.into_iter().collect());
        self
    }

    /// Replace the bounded collection and decode limits for this container analysis.
    pub fn with_limits(mut self, limits: AnalysisLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Performs compile.
    pub fn compile(&self) -> AnalysisPlan {
        let mut plan = AnalysisPlan::new(
            std::iter::once(AnalysisDomain::Container).chain(self.domains.iter().copied()),
        )
        .with_limits(self.limits.clone());
        plan.selected_slices = self.slices.clone();
        plan
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DependencyKind {
    Required,
    Advisory,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Dependency {
    pub domain: AnalysisDomain,
    pub kind: DependencyKind,
}

const fn required(domain: AnalysisDomain) -> Dependency {
    Dependency {
        domain,
        kind: DependencyKind::Required,
    }
}

const fn advisory(domain: AnalysisDomain) -> Dependency {
    Dependency {
        domain,
        kind: DependencyKind::Advisory,
    }
}

pub(crate) fn dependencies(domain: AnalysisDomain) -> Vec<Dependency> {
    use AnalysisDomain as D;
    match domain {
        D::Container | D::Header => vec![],
        D::LoadCommands => vec![required(D::Header)],
        D::Segments => vec![required(D::LoadCommands)],
        D::Relocations => vec![required(D::Segments)],
        D::Symbols | D::Exports | D::Codesign => vec![required(D::LoadCommands)],
        D::Fixups => vec![required(D::LoadCommands), required(D::Segments)],
        D::Imports => vec![
            required(D::LoadCommands),
            advisory(D::Symbols),
            advisory(D::Fixups),
        ],
        D::Objc => vec![required(D::Segments), advisory(D::Fixups)],
        D::Swift => vec![
            required(D::Segments),
            advisory(D::Symbols),
            advisory(D::Objc),
        ],
        D::Dwarf | D::Strings => vec![required(D::Segments)],
        D::Vtables => vec![
            required(D::Segments),
            advisory(D::Symbols),
            advisory(D::Fixups),
        ],
        D::Ranges => vec![
            required(D::Segments),
            advisory(D::Symbols),
            advisory(D::Dwarf),
        ],
        D::Xrefs => vec![
            required(D::Ranges),
            advisory(D::Fixups),
            advisory(D::Relocations),
        ],
        D::Dependencies => vec![
            required(D::LoadCommands),
            advisory(D::Imports),
            advisory(D::Exports),
        ],
        D::CHeaders => vec![required(D::Dwarf), advisory(D::Symbols)],
        D::CppHeaders => vec![
            required(D::Segments),
            required(D::Vtables),
            advisory(D::Symbols),
            advisory(D::Dwarf),
            advisory(D::Ranges),
        ],
        D::ObjcHeaders => vec![required(D::Objc), advisory(D::Swift)],
        D::Audit => vec![],
    }
}

pub(crate) fn resolve_domains(plan: &AnalysisPlan) -> BTreeSet<AnalysisDomain> {
    fn add(
        domain: AnalysisDomain,
        excluded: &BTreeSet<AnalysisDomain>,
        resolved: &mut BTreeSet<AnalysisDomain>,
    ) {
        if excluded.contains(&domain) || !resolved.insert(domain) {
            return;
        }
        for dependency in dependencies(domain) {
            add(dependency.domain, excluded, resolved);
        }
    }

    let mut resolved = BTreeSet::new();
    for domain in &plan.domains {
        add(*domain, &plan.excluded, &mut resolved);
    }
    resolved
}
