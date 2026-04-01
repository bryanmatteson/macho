use std::collections::BTreeMap;
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeaderLanguage {
    C,
    Cpp,
    Mixed,
}

impl HeaderLanguage {
    pub fn prompt_name(self) -> &'static str {
        match self {
            Self::C => "C",
            Self::Cpp => "C++",
            Self::Mixed => "mixed C/C++",
        }
    }

    pub fn clang_language(self) -> &'static str {
        match self {
            Self::C => "c-header",
            Self::Cpp | Self::Mixed => "c++-header",
        }
    }

    pub fn clang_std(self) -> &'static str {
        match self {
            Self::C => "c11",
            Self::Cpp | Self::Mixed => "c++20",
        }
    }

    pub fn accepts_entity_language(self, entity_language: Self) -> bool {
        match self {
            Self::Mixed => true,
            Self::C => matches!(entity_language, Self::C),
            Self::Cpp => matches!(entity_language, Self::Cpp),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStrength {
    Exact,
    Correlated,
    Inferred,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSourceKind {
    MangledSymbolAst,
    Rtti,
    Vtable,
    BodyAnalysis,
    Dwarf,
    CrossBinary,
    ExternalHeader,
    StringHeuristic,
    Validator,
    Manual,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityKind {
    Function,
    Method,
    Class,
    Struct,
    Union,
    Enum,
    Typedef,
    Variable,
    Namespace,
    ForwardDecl,
    HeaderNote,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationTargetKind {
    Syntax,
    EntityCoverage,
    Mangling,
    Vtable,
    Dwarf,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceSource {
    pub kind: EvidenceSourceKind,
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceFact {
    pub id: String,
    pub summary: String,
    pub strength: EvidenceStrength,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f32>,
    pub source: EvidenceSource,
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceEntity {
    pub id: String,
    pub kind: EntityKind,
    pub language: HeaderLanguage,
    pub display_name: String,
    #[serde(default)]
    pub required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical_decl: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferred_spelling: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mangled_name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dependencies: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exact_fact_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<EvidenceFact>,
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnresolvedGap {
    pub id: String,
    pub entity_id: String,
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggested_fallback: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationTarget {
    pub kind: ValidationTargetKind,
    pub label: String,
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub expected: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderUnit {
    pub id: String,
    pub name: String,
    pub language: HeaderLanguage,
    pub target_abi: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_triple: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prompt_hints: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceBundle {
    pub schema_version: u32,
    pub header_unit: HeaderUnit,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entities: Vec<EvidenceEntity>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unresolved: Vec<UnresolvedGap>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub validation_targets: Vec<ValidationTarget>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

impl EvidenceBundle {
    pub const CURRENT_SCHEMA_VERSION: u32 = 1;

    pub fn entity(&self, id: &str) -> Option<&EvidenceEntity> {
        self.entities.iter().find(|entity| entity.id == id)
    }

    pub fn fact(&self, id: &str) -> Option<&EvidenceFact> {
        self.entities
            .iter()
            .flat_map(|entity| entity.evidence.iter())
            .find(|fact| fact.id == id)
    }

    pub fn required_entity_ids(&self) -> Vec<&str> {
        self.entities
            .iter()
            .filter(|entity| entity.required)
            .map(|entity| entity.id.as_str())
            .collect()
    }
}

pub trait HeaderEvidenceProvider {
    fn build_bundle(&self) -> crate::Result<EvidenceBundle>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleValidationIssue {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleValidationReport {
    pub valid: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issues: Vec<BundleValidationIssue>,
}

pub fn validate_bundle(bundle: &EvidenceBundle) -> BundleValidationReport {
    let mut issues = Vec::new();

    if bundle.schema_version != EvidenceBundle::CURRENT_SCHEMA_VERSION {
        issues.push(BundleValidationIssue {
            code: "HB001".into(),
            message: format!(
                "unsupported schema_version {} (expected {})",
                bundle.schema_version,
                EvidenceBundle::CURRENT_SCHEMA_VERSION
            ),
        });
    }

    if bundle.header_unit.id.trim().is_empty() {
        issues.push(BundleValidationIssue {
            code: "HB002".into(),
            message: "header_unit.id must not be empty".into(),
        });
    }

    if bundle.header_unit.name.trim().is_empty() {
        issues.push(BundleValidationIssue {
            code: "HB003".into(),
            message: "header_unit.name must not be empty".into(),
        });
    }

    if bundle.header_unit.target_abi.trim().is_empty() {
        issues.push(BundleValidationIssue {
            code: "HB012".into(),
            message: "header_unit.target_abi must not be empty".into(),
        });
    }

    let mut seen_entities = BTreeSet::new();
    let mut seen_facts = BTreeSet::new();
    let mut seen_gaps = BTreeSet::new();
    let mut seen_validation_targets = BTreeSet::new();
    for entity in &bundle.entities {
        if entity.id.trim().is_empty() {
            issues.push(BundleValidationIssue {
                code: "HB004".into(),
                message: "entity id must not be empty".into(),
            });
        }
        if entity.display_name.trim().is_empty() {
            issues.push(BundleValidationIssue {
                code: "HB013".into(),
                message: format!("entity '{}' has empty display_name", entity.id),
            });
        }
        if !seen_entities.insert(entity.id.as_str()) {
            issues.push(BundleValidationIssue {
                code: "HB005".into(),
                message: format!("duplicate entity id '{}'", entity.id),
            });
        }
        if !bundle
            .header_unit
            .language
            .accepts_entity_language(entity.language)
        {
            issues.push(BundleValidationIssue {
                code: "HB014".into(),
                message: format!(
                    "entity '{}' language {:?} is incompatible with header unit language {:?}",
                    entity.id, entity.language, bundle.header_unit.language
                ),
            });
        }
        for dep in &entity.dependencies {
            if dep.trim().is_empty() {
                issues.push(BundleValidationIssue {
                    code: "HB006".into(),
                    message: format!("entity '{}' has empty dependency id", entity.id),
                });
            }
        }
        for fact in &entity.evidence {
            if fact.id.trim().is_empty() {
                issues.push(BundleValidationIssue {
                    code: "HB007".into(),
                    message: format!("entity '{}' has fact with empty id", entity.id),
                });
            }
            if !seen_facts.insert(fact.id.as_str()) {
                issues.push(BundleValidationIssue {
                    code: "HB008".into(),
                    message: format!("duplicate fact id '{}'", fact.id),
                });
            }
        }
    }

    for entity in &bundle.entities {
        for dep in &entity.dependencies {
            if !dep.is_empty() && bundle.entity(dep).is_none() {
                issues.push(BundleValidationIssue {
                    code: "HB009".into(),
                    message: format!("entity '{}' depends on unknown entity '{}'", entity.id, dep),
                });
            }
        }
        for fact_id in &entity.exact_fact_ids {
            if bundle.fact(fact_id).is_none() {
                issues.push(BundleValidationIssue {
                    code: "HB010".into(),
                    message: format!(
                        "entity '{}' references unknown exact fact '{}'",
                        entity.id, fact_id
                    ),
                });
            }
        }
    }

    for gap in &bundle.unresolved {
        if gap.id.trim().is_empty() {
            issues.push(BundleValidationIssue {
                code: "HB015".into(),
                message: "unresolved gap id must not be empty".into(),
            });
        }
        if !seen_gaps.insert(gap.id.as_str()) {
            issues.push(BundleValidationIssue {
                code: "HB016".into(),
                message: format!("duplicate unresolved gap id '{}'", gap.id),
            });
        }
        if bundle.entity(&gap.entity_id).is_none() {
            issues.push(BundleValidationIssue {
                code: "HB011".into(),
                message: format!(
                    "unresolved gap '{}' references unknown entity '{}'",
                    gap.id, gap.entity_id
                ),
            });
        }
    }

    for target in &bundle.validation_targets {
        if target.label.trim().is_empty() {
            issues.push(BundleValidationIssue {
                code: "HB017".into(),
                message: "validation target label must not be empty".into(),
            });
        }
        let key = (target.kind, target.label.as_str());
        if !seen_validation_targets.insert(key) {
            issues.push(BundleValidationIssue {
                code: "HB018".into(),
                message: format!(
                    "duplicate validation target '{:?}:{}'",
                    target.kind, target.label
                ),
            });
        }
    }

    BundleValidationReport {
        valid: issues.is_empty(),
        issues,
    }
}
