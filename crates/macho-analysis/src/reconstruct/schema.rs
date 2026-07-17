use std::collections::BTreeMap;
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// The HeaderLanguage type.
#[non_exhaustive]
pub enum HeaderLanguage {
    /// The C variant.
    C,
    /// The Cpp variant.
    Cpp,
    /// The Mixed variant.
    Mixed,
}

impl HeaderLanguage {
    /// Performs prompt_name.
    pub fn prompt_name(self) -> &'static str {
        match self {
            Self::C => "C",
            Self::Cpp => "C++",
            Self::Mixed => "mixed C/C++",
        }
    }

    /// Performs clang_language.
    pub fn clang_language(self) -> &'static str {
        match self {
            Self::C => "c-header",
            Self::Cpp | Self::Mixed => "c++-header",
        }
    }

    /// Performs clang_std.
    pub fn clang_std(self) -> &'static str {
        match self {
            Self::C => "c11",
            Self::Cpp | Self::Mixed => "c++20",
        }
    }

    /// Performs accepts_entity_language.
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
/// The EvidenceStrength type.
#[non_exhaustive]
pub enum EvidenceStrength {
    /// The Exact variant.
    Exact,
    /// The Correlated variant.
    Correlated,
    /// The Inferred variant.
    Inferred,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// The EvidenceSourceKind type.
#[non_exhaustive]
pub enum EvidenceSourceKind {
    /// The MangledSymbolAst variant.
    MangledSymbolAst,
    /// The Rtti variant.
    Rtti,
    /// The Vtable variant.
    Vtable,
    /// The BodyAnalysis variant.
    BodyAnalysis,
    /// The Dwarf variant.
    Dwarf,
    /// The CrossBinary variant.
    CrossBinary,
    /// The ExternalHeader variant.
    ExternalHeader,
    /// The StringHeuristic variant.
    StringHeuristic,
    /// The Validator variant.
    Validator,
    /// The Manual variant.
    Manual,
    /// The Other variant.
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// The EntityKind type.
#[non_exhaustive]
pub enum EntityKind {
    /// The Function variant.
    Function,
    /// The Method variant.
    Method,
    /// The Class variant.
    Class,
    /// The Struct variant.
    Struct,
    /// The Union variant.
    Union,
    /// The Enum variant.
    Enum,
    /// The Typedef variant.
    Typedef,
    /// The Variable variant.
    Variable,
    /// The Namespace variant.
    Namespace,
    /// The ForwardDecl variant.
    ForwardDecl,
    /// The HeaderNote variant.
    HeaderNote,
    /// The Unknown variant.
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// The ValidationTargetKind type.
#[non_exhaustive]
pub enum ValidationTargetKind {
    /// The Syntax variant.
    Syntax,
    /// The EntityCoverage variant.
    EntityCoverage,
    /// The Mangling variant.
    Mangling,
    /// The Vtable variant.
    Vtable,
    /// The Dwarf variant.
    Dwarf,
    /// The Custom variant.
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The EvidenceSource type.
pub struct EvidenceSource {
    /// The kind field.
    pub kind: EvidenceSourceKind,
    /// The label field.
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// The image field.
    pub image: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// The path field.
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// The line field.
    pub line: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// The address field.
    pub address: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// The note field.
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The EvidenceFact type.
pub struct EvidenceFact {
    /// The id field.
    pub id: String,
    /// The summary field.
    pub summary: String,
    /// The strength field.
    pub strength: EvidenceStrength,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// The confidence field.
    pub confidence: Option<f32>,
    /// The source field.
    pub source: EvidenceSource,
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    /// The payload field.
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The EvidenceEntity type.
pub struct EvidenceEntity {
    /// The id field.
    pub id: String,
    /// The kind field.
    pub kind: EntityKind,
    /// The language field.
    pub language: HeaderLanguage,
    /// The display_name field.
    pub display_name: String,
    #[serde(default)]
    /// The required field.
    pub required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// The canonical_decl field.
    pub canonical_decl: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// The preferred_spelling field.
    pub preferred_spelling: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// The mangled_name field.
    pub mangled_name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    /// The dependencies field.
    pub dependencies: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    /// The exact_fact_ids field.
    pub exact_fact_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    /// The evidence field.
    pub evidence: Vec<EvidenceFact>,
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    /// The payload field.
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The UnresolvedGap type.
pub struct UnresolvedGap {
    /// The id field.
    pub id: String,
    /// The entity_id field.
    pub entity_id: String,
    /// The summary field.
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// The suggested_fallback field.
    pub suggested_fallback: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The ValidationTarget type.
pub struct ValidationTarget {
    /// The kind field.
    pub kind: ValidationTargetKind,
    /// The label field.
    pub label: String,
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    /// The expected field.
    pub expected: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The HeaderUnit type.
pub struct HeaderUnit {
    /// The id field.
    pub id: String,
    /// The name field.
    pub name: String,
    /// The language field.
    pub language: HeaderLanguage,
    /// The target_abi field.
    pub target_abi: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// The target_triple field.
    pub target_triple: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// The module field.
    pub module: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// The summary field.
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    /// The prompt_hints field.
    pub prompt_hints: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The EvidenceBundle type.
pub struct EvidenceBundle {
    /// The schema_version field.
    pub schema_version: u32,
    /// The header_unit field.
    pub header_unit: HeaderUnit,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    /// The entities field.
    pub entities: Vec<EvidenceEntity>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    /// The unresolved field.
    pub unresolved: Vec<UnresolvedGap>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    /// The validation_targets field.
    pub validation_targets: Vec<ValidationTarget>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    /// The notes field.
    pub notes: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    /// The metadata field.
    pub metadata: BTreeMap<String, String>,
}

impl EvidenceBundle {
    /// The CURRENT_SCHEMA_VERSION constant.
    pub const CURRENT_SCHEMA_VERSION: u32 = 1;

    /// Performs entity.
    pub fn entity(&self, id: &str) -> Option<&EvidenceEntity> {
        self.entities.iter().find(|entity| entity.id == id)
    }

    /// Performs fact.
    pub fn fact(&self, id: &str) -> Option<&EvidenceFact> {
        self.entities
            .iter()
            .flat_map(|entity| entity.evidence.iter())
            .find(|fact| fact.id == id)
    }

    /// Performs required_entity_ids.
    pub fn required_entity_ids(&self) -> Vec<&str> {
        self.entities
            .iter()
            .filter(|entity| entity.required)
            .map(|entity| entity.id.as_str())
            .collect()
    }
}

/// The HeaderEvidenceProvider type.
pub trait HeaderEvidenceProvider {
    /// Performs build_bundle.
    fn build_bundle(&self) -> crate::Result<EvidenceBundle>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The BundleValidationIssue type.
pub struct BundleValidationIssue {
    /// The code field.
    pub code: String,
    /// The message field.
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The BundleValidationReport type.
pub struct BundleValidationReport {
    /// The valid field.
    pub valid: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    /// The issues field.
    pub issues: Vec<BundleValidationIssue>,
}

/// Performs validate_bundle.
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
