//! Strict, bounded offline hypothesis artifacts.

use std::collections::BTreeSet;

use crate::analysis::report::{
    Architecture, ContentHash, EntityId, EvidenceId, FactId, HeaderDecl, HeaderOwnerRef,
    HeaderProjection, HeaderValidationReport, HypothesisBundleVersion, HypothesisId,
    HypothesisReportVersion, Identifier, ImageIdentity, ModelResponseVersion, NonEmpty,
    RecoveryField, RecoveryGapId, RecoveryLanguage, RecoverySchemaVersion, Severity,
    canonical_json, sha256_hex,
};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

/// Validation or bounds failure for an offline inference artifact.
#[derive(Debug, thiserror::Error)]
pub enum ArtifactError {
    /// Strict JSON decoding failed.
    #[error("decode hypothesis artifact: {0}")]
    Decode(#[from] serde_json::Error),
    /// Canonical encoding failed.
    #[error("encode hypothesis artifact: {0}")]
    Canonical(#[from] crate::analysis::report::CanonicalJsonError),
    /// A configured or hard byte/count limit was exceeded.
    #[error("hypothesis {limit} limit exceeded: selected {selected}, limit {maximum}")]
    Limit {
        /// Limit name.
        limit: &'static str,
        /// Requested or encoded count.
        selected: u64,
        /// Maximum permitted count.
        maximum: u64,
    },
    /// A structural or referential invariant failed.
    #[error("invalid hypothesis artifact: {0}")]
    Invalid(String),
}

/// Limits carried by every bundle and enforced before prompt or response use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HypothesisLimits {
    /// Maximum target entities.
    pub max_target_entities: u64,
    /// Maximum fact excerpts.
    pub max_fact_excerpts: u64,
    /// Maximum evidence excerpts.
    pub max_evidence_excerpts: u64,
    /// Maximum canonical bundle bytes.
    pub max_bundle_bytes: u64,
    /// Maximum prompt bytes.
    pub max_prompt_bytes: u64,
    /// Maximum response bytes.
    pub max_response_bytes: u64,
    /// Maximum rendered header bytes.
    pub max_rendered_header_bytes: u64,
}

impl Default for HypothesisLimits {
    fn default() -> Self {
        Self {
            max_target_entities: 512,
            max_fact_excerpts: 8_192,
            max_evidence_excerpts: 4_096,
            max_bundle_bytes: 2_097_152,
            max_prompt_bytes: 2_097_152,
            max_response_bytes: 2_097_152,
            max_rendered_header_bytes: 2_097_152,
        }
    }
}

impl HypothesisLimits {
    pub(crate) fn validate(self) -> Result<(), ArtifactError> {
        let values = [
            ("target entities", self.max_target_entities, 4_096),
            ("fact excerpts", self.max_fact_excerpts, 32_768),
            ("evidence excerpts", self.max_evidence_excerpts, 16_384),
            ("bundle bytes", self.max_bundle_bytes, 4_194_304),
            ("prompt bytes", self.max_prompt_bytes, 2_097_152),
            ("response bytes", self.max_response_bytes, 2_097_152),
            (
                "rendered header bytes",
                self.max_rendered_header_bytes,
                2_097_152,
            ),
        ];
        for (limit, selected, maximum) in values {
            if selected == 0 || selected > maximum {
                return Err(ArtifactError::Limit {
                    limit,
                    selected,
                    maximum,
                });
            }
        }
        Ok(())
    }
}

/// Exact shared header subset understood by hypothesis fragments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct HeaderSubsetVersion(u32);

impl HeaderSubsetVersion {
    /// Current and only supported subset.
    pub const CURRENT: Self = Self(1);
}

impl<'de> Deserialize<'de> for HeaderSubsetVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = u32::deserialize(deserializer)?;
        if value == 1 {
            Ok(Self(value))
        } else {
            Err(serde::de::Error::custom(format!(
                "unsupported header subset {value}; expected 1"
            )))
        }
    }
}

/// Operation families allowed for one deterministic recovery gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HypothesisOperationKind {
    /// Select one already-recorded conflicted candidate.
    ChooseCandidate,
    /// Propose an identifier without changing a deterministic name fact.
    ProposeCanonicalName,
    /// Propose one shared typed header declaration.
    ProposeDeclarationFragment,
    /// Propose an owner from the shared header owner vocabulary.
    ProposeGrouping,
}

/// One entity and its explicitly selected gap set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HypothesisTarget {
    /// Existing recovery entity.
    pub entity_id: EntityId,
    /// Existing recovery gaps in deterministic order.
    pub gap_ids: NonEmpty<RecoveryGapId>,
    /// Closed operation set available for these gaps.
    pub allowed_operations: NonEmpty<HypothesisOperationKind>,
    /// Macho-derived terminal declaration that a grouping operation may qualify.
    pub projection_template: Option<HeaderDecl>,
}

/// Source-equal canonical projection of one evidence record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceExcerpt {
    /// Existing evidence ID.
    pub evidence_id: EvidenceId,
    /// Entity that owns the evidence record.
    pub entity_id: EntityId,
    /// Canonical subtree copied from the validated recovery report.
    pub canonical_projection: Value,
}

/// Source-equal canonical projection of one deterministic fact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactExcerpt {
    /// Existing fact ID.
    pub fact_id: FactId,
    /// Entity that owns the fact.
    pub entity_id: EntityId,
    /// Recovery field represented by the fact.
    pub field: RecoveryField,
    /// Canonical subtree copied from the validated recovery report.
    pub canonical_projection: Value,
}

/// Constraints that prevent hypothesis output from becoming deterministic input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleConstraints {
    /// Exact and correlated facts that proposals cannot replace.
    pub pinned_fact_ids: Vec<FactId>,
    /// Shared typed-header subset.
    pub supported_header_subset: HeaderSubsetVersion,
}

/// Deterministic bounded export from one validated recovery-report slice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HypothesisBundle {
    schema_version: HypothesisBundleVersion,
    recovery_schema_version: RecoverySchemaVersion,
    recovery_digest: ContentHash,
    bundle_digest: ContentHash,
    language: RecoveryLanguage,
    architecture: Architecture,
    image: ImageIdentity,
    targets: NonEmpty<HypothesisTarget>,
    facts: Vec<FactExcerpt>,
    evidence: Vec<EvidenceExcerpt>,
    constraints: BundleConstraints,
    limits: HypothesisLimits,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HypothesisBundleWire {
    schema_version: HypothesisBundleVersion,
    recovery_schema_version: RecoverySchemaVersion,
    recovery_digest: ContentHash,
    bundle_digest: ContentHash,
    language: RecoveryLanguage,
    architecture: Architecture,
    image: ImageIdentity,
    targets: NonEmpty<HypothesisTarget>,
    facts: Vec<FactExcerpt>,
    evidence: Vec<EvidenceExcerpt>,
    constraints: BundleConstraints,
    limits: HypothesisLimits,
}

pub(crate) struct HypothesisBundleParts {
    pub recovery_digest: ContentHash,
    pub language: RecoveryLanguage,
    pub architecture: Architecture,
    pub image: ImageIdentity,
    pub targets: NonEmpty<HypothesisTarget>,
    pub facts: Vec<FactExcerpt>,
    pub evidence: Vec<EvidenceExcerpt>,
    pub constraints: BundleConstraints,
    pub limits: HypothesisLimits,
}

impl<'de> Deserialize<'de> for HypothesisBundle {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = HypothesisBundleWire::deserialize(deserializer)?;
        let bundle = Self {
            schema_version: wire.schema_version,
            recovery_schema_version: wire.recovery_schema_version,
            recovery_digest: wire.recovery_digest,
            bundle_digest: wire.bundle_digest,
            language: wire.language,
            architecture: wire.architecture,
            image: wire.image,
            targets: wire.targets,
            facts: wire.facts,
            evidence: wire.evidence,
            constraints: wire.constraints,
            limits: wire.limits,
        };
        bundle.validate().map_err(serde::de::Error::custom)?;
        Ok(bundle)
    }
}

impl HypothesisBundle {
    pub(crate) fn new(parts: HypothesisBundleParts) -> Result<Self, ArtifactError> {
        let mut bundle = Self {
            schema_version: HypothesisBundleVersion::CURRENT,
            recovery_schema_version: RecoverySchemaVersion::CURRENT,
            recovery_digest: parts.recovery_digest,
            bundle_digest: zero_hash(),
            language: parts.language,
            architecture: parts.architecture,
            image: parts.image,
            targets: parts.targets,
            facts: parts.facts,
            evidence: parts.evidence,
            constraints: parts.constraints,
            limits: parts.limits,
        };
        bundle.bundle_digest = bundle.computed_digest()?;
        bundle.validate()?;
        Ok(bundle)
    }

    /// Strictly decodes and validates one bounded bundle.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ArtifactError> {
        enforce("bundle bytes", bytes.len() as u64, 4_194_304)?;
        Ok(serde_json::from_slice(bytes)?)
    }

    /// Returns canonical JSON bytes for deterministic storage and hashing.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ArtifactError> {
        Ok(canonical_json(self)?)
    }

    /// Re-runs bounds, digest, uniqueness, and bundle-local reference checks.
    pub fn validate(&self) -> Result<(), ArtifactError> {
        self.limits.validate()?;
        enforce(
            "target entities",
            self.targets.as_slice().len() as u64,
            self.limits.max_target_entities,
        )?;
        enforce(
            "fact excerpts",
            self.facts.len() as u64,
            self.limits.max_fact_excerpts,
        )?;
        enforce(
            "evidence excerpts",
            self.evidence.len() as u64,
            self.limits.max_evidence_excerpts,
        )?;
        if self.architecture != self.image.architecture {
            return Err(ArtifactError::Invalid(
                "bundle architecture does not match image identity".into(),
            ));
        }
        let entities = unique(
            "target entity",
            self.targets
                .as_slice()
                .iter()
                .map(|target| target.entity_id.as_str()),
        )?;
        let mut gaps = BTreeSet::new();
        for target in self.targets.as_slice() {
            unique(
                "target gap",
                target.gap_ids.as_slice().iter().map(RecoveryGapId::as_str),
            )?;
            unique(
                "allowed operation",
                target
                    .allowed_operations
                    .as_slice()
                    .iter()
                    .map(|kind| match kind {
                        HypothesisOperationKind::ChooseCandidate => "choose_candidate",
                        HypothesisOperationKind::ProposeCanonicalName => "propose_canonical_name",
                        HypothesisOperationKind::ProposeDeclarationFragment => {
                            "propose_declaration_fragment"
                        }
                        HypothesisOperationKind::ProposeGrouping => "propose_grouping",
                    }),
            )?;
            for gap in target.gap_ids.as_slice() {
                if !gaps.insert(gap.as_str()) {
                    return Err(ArtifactError::Invalid(format!(
                        "duplicate target gap {gap}"
                    )));
                }
            }
            let allows_grouping = target
                .allowed_operations
                .as_slice()
                .contains(&HypothesisOperationKind::ProposeGrouping);
            if allows_grouping != target.projection_template.is_some() {
                return Err(ArtifactError::Invalid(
                    "grouping target must carry exactly one projection template".into(),
                ));
            }
            if let Some(template) = &target.projection_template {
                let template_id = match template {
                    HeaderDecl::Function { id, owner, .. }
                    | HeaderDecl::Variable { id, owner, .. } => {
                        if owner.is_some() {
                            return Err(ArtifactError::Invalid(
                                "grouping function or variable template already has an owner"
                                    .into(),
                            ));
                        }
                        id
                    }
                    HeaderDecl::Record { id, path, .. }
                    | HeaderDecl::Forward { id, path, .. }
                    | HeaderDecl::Alias { id, path, .. } => {
                        if path.as_slice().len() != 1 {
                            return Err(ArtifactError::Invalid(
                                "grouping type template must have one terminal path component"
                                    .into(),
                            ));
                        }
                        id
                    }
                    HeaderDecl::ObjcInterface { .. }
                    | HeaderDecl::ObjcCategory { .. }
                    | HeaderDecl::ObjcProtocol { .. }
                    | HeaderDecl::ObjcForward { .. } => {
                        return Err(ArtifactError::Invalid(
                            "C/C++ projection template contains an Objective-C declaration".into(),
                        ));
                    }
                };
                if template_id != &target.entity_id {
                    return Err(ArtifactError::Invalid(
                        "projection template does not match its grouping target".into(),
                    ));
                }
            }
        }
        let facts = unique("fact", self.facts.iter().map(|fact| fact.fact_id.as_str()))?;
        let evidence = unique(
            "evidence",
            self.evidence
                .iter()
                .map(|record| record.evidence_id.as_str()),
        )?;
        for fact in &self.facts {
            require(&entities, fact.entity_id.as_str(), "fact entity")?;
        }
        for record in &self.evidence {
            require(&entities, record.entity_id.as_str(), "evidence entity")?;
        }
        for fact in &self.constraints.pinned_fact_ids {
            require(&facts, fact.as_str(), "pinned fact")?;
        }
        if self.computed_digest()? != self.bundle_digest {
            return Err(ArtifactError::Invalid("bundle digest mismatch".into()));
        }
        let encoded = canonical_json(self)?;
        enforce(
            "bundle bytes",
            encoded.len() as u64,
            self.limits.max_bundle_bytes,
        )?;
        let _ = evidence;
        Ok(())
    }

    fn computed_digest(&self) -> Result<ContentHash, ArtifactError> {
        let mut material = self.clone();
        material.bundle_digest = zero_hash();
        ContentHash::new(sha256_hex(&canonical_json(&material)?))
            .map_err(|error| ArtifactError::Invalid(error.to_string()))
    }

    /// Bundle digest that responses must match exactly.
    pub const fn bundle_digest(&self) -> &ContentHash {
        &self.bundle_digest
    }

    /// Recovery language.
    pub const fn language(&self) -> RecoveryLanguage {
        self.language
    }

    /// Selected architecture.
    pub const fn architecture(&self) -> Architecture {
        self.architecture
    }

    /// Selected image identity.
    pub const fn image(&self) -> &ImageIdentity {
        &self.image
    }

    /// Explicit target ledger.
    pub fn targets(&self) -> &[HypothesisTarget] {
        self.targets.as_slice()
    }

    /// Deterministic fact excerpts.
    pub fn facts(&self) -> &[FactExcerpt] {
        &self.facts
    }

    /// Deterministic evidence excerpts.
    pub fn evidence(&self) -> &[EvidenceExcerpt] {
        &self.evidence
    }

    /// Bundle constraints.
    pub const fn constraints(&self) -> &BundleConstraints {
        &self.constraints
    }

    /// Enforced limits.
    pub const fn limits(&self) -> HypothesisLimits {
        self.limits
    }

    pub(crate) fn target_for_gap(&self, gap: &RecoveryGapId) -> Option<&HypothesisTarget> {
        self.targets
            .as_slice()
            .iter()
            .find(|target| target.gap_ids.as_slice().contains(gap))
    }
}

/// Exact support for a proposed hypothesis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SupportRef {
    /// Existing evidence record.
    Evidence {
        /// Referenced evidence ID.
        evidence_id: EvidenceId,
    },
    /// Existing deterministic fact.
    DeterministicFact {
        /// Referenced fact ID.
        fact_id: FactId,
    },
    /// Existing related target entity.
    RelatedEntity {
        /// Referenced target entity ID.
        entity_id: EntityId,
    },
}

/// One operation over an existing recovery gap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HypothesisOperation {
    /// Select a recorded conflicted fact candidate by zero-based index.
    ChooseCandidate {
        /// Zero-based index in the supported conflicted fact.
        candidate_index: u32,
    },
    /// Propose a canonical source identifier.
    ProposeCanonicalName {
        /// Proposed source identifier.
        name: Identifier,
    },
    /// Propose exactly one shared typed declaration.
    ProposeDeclarationFragment {
        /// Shared typed declaration.
        fragment: HeaderDecl,
    },
    /// Propose an owner/grouping relation.
    ProposeGrouping {
        /// Shared typed owner reference.
        owner: HeaderOwnerRef,
    },
}

impl HypothesisOperation {
    pub(crate) const fn kind(&self) -> HypothesisOperationKind {
        match self {
            Self::ChooseCandidate { .. } => HypothesisOperationKind::ChooseCandidate,
            Self::ProposeCanonicalName { .. } => HypothesisOperationKind::ProposeCanonicalName,
            Self::ProposeDeclarationFragment { .. } => {
                HypothesisOperationKind::ProposeDeclarationFragment
            }
            Self::ProposeGrouping { .. } => HypothesisOperationKind::ProposeGrouping,
        }
    }
}

/// One untrusted proposal from an offline model or human tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposedHypothesis {
    /// Stable proposal ID.
    pub(crate) id: HypothesisId,
    /// Existing target entity.
    pub(crate) entity_id: EntityId,
    /// Existing target gap.
    pub(crate) gap_id: RecoveryGapId,
    /// Closed typed operation.
    pub(crate) operation: HypothesisOperation,
    /// Exact support ledger.
    pub(crate) support: NonEmpty<SupportRef>,
}

impl ProposedHypothesis {
    /// Stable proposal ID.
    pub const fn id(&self) -> &HypothesisId {
        &self.id
    }

    /// Existing target entity ID.
    pub const fn entity_id(&self) -> &EntityId {
        &self.entity_id
    }

    /// Existing target gap ID.
    pub const fn gap_id(&self) -> &RecoveryGapId {
        &self.gap_id
    }

    /// Closed typed operation.
    pub const fn operation(&self) -> &HypothesisOperation {
        &self.operation
    }

    /// Exact support ledger.
    pub const fn support(&self) -> &NonEmpty<SupportRef> {
        &self.support
    }
}

/// Strict response bound to one exact bundle digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelResponse {
    /// Exact response schema.
    pub(crate) schema_version: ModelResponseVersion,
    /// Exact source bundle digest.
    pub(crate) bundle_digest: ContentHash,
    /// Proposed operations.
    pub(crate) hypotheses: Vec<ProposedHypothesis>,
    /// Explicitly unresolved target gaps.
    pub(crate) unresolved_gap_ids: Vec<RecoveryGapId>,
}

impl ModelResponse {
    /// Strictly decodes a response within the bundle's configured byte limit.
    pub fn from_json(bytes: &[u8], limits: HypothesisLimits) -> Result<Self, ArtifactError> {
        enforce(
            "response bytes",
            bytes.len() as u64,
            limits.max_response_bytes,
        )?;
        Ok(serde_json::from_slice(bytes)?)
    }

    /// Exact response schema.
    pub const fn schema_version(&self) -> ModelResponseVersion {
        self.schema_version
    }

    /// Exact source bundle digest.
    pub const fn bundle_digest(&self) -> &ContentHash {
        &self.bundle_digest
    }

    /// Proposed operations in response order.
    pub fn hypotheses(&self) -> &[ProposedHypothesis] {
        &self.hypotheses
    }

    /// Explicitly unresolved target gaps.
    pub fn unresolved_gap_ids(&self) -> &[RecoveryGapId] {
        &self.unresolved_gap_ids
    }

    pub(crate) fn digest(&self) -> Result<ContentHash, ArtifactError> {
        ContentHash::new(sha256_hex(&canonical_json(self)?))
            .map_err(|error| ArtifactError::Invalid(error.to_string()))
    }
}

/// Closed diagnostic codes emitted while validating proposed hypotheses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HypothesisDiagnosticCode {
    /// Artifact schema version differs from the accepted version.
    SchemaVersionMismatch,
    /// Response does not match the bundle digest.
    BundleDigestMismatch,
    /// Proposal ID is duplicated.
    DuplicateHypothesis,
    /// More than one response disposition targets a gap.
    DuplicateGapOperation,
    /// A referenced deterministic ID is absent.
    DanglingReference,
    /// Operation is not allowed for the target gap.
    OperationNotAllowed,
    /// A pinned deterministic fact would be changed.
    PinnedFactChange,
    /// Proposed source identifier is invalid.
    InvalidIdentifier,
    /// Shared typed declaration is not supported.
    UnsupportedHeaderFragment,
    /// Proposed declaration does not parse after rendering.
    HeaderSyntaxInvalid,
    /// Proposed declaration violates semantic header rules.
    HeaderSemanticInvalid,
    /// A response or projection bound was exceeded.
    LimitExceeded,
}

/// One stable hypothesis diagnostic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HypothesisDiagnostic {
    /// Stable diagnostic code.
    pub code: HypothesisDiagnosticCode,
    /// Severity.
    pub severity: Severity,
    /// Human-readable detail.
    pub message: String,
    /// Related hypothesis, if any.
    pub hypothesis_id: Option<HypothesisId>,
}

/// Post-validation disposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HypothesisDisposition {
    /// Proposal survived all applicable checks.
    Accepted,
    /// Concrete validation contradicted the proposal.
    Rejected,
    /// Proposal is structurally legal but cannot establish a safe declaration.
    Unresolved,
}

/// One auditable result for one proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HypothesisResult {
    /// Proposal ID.
    pub hypothesis_id: HypothesisId,
    /// Existing target entity.
    pub entity_id: EntityId,
    /// Existing target gap.
    pub gap_id: RecoveryGapId,
    /// Validated disposition.
    pub disposition: HypothesisDisposition,
    /// Preserved exact support ledger.
    pub support: NonEmpty<SupportRef>,
    /// Stable result diagnostics.
    pub diagnostics: Vec<HypothesisDiagnostic>,
}

/// Immutable result of validating one response against one exact bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HypothesisReport {
    /// Exact report schema.
    pub schema_version: HypothesisReportVersion,
    /// Source bundle digest.
    pub bundle_digest: ContentHash,
    /// Canonical response digest.
    pub response_digest: ContentHash,
    /// Per-proposal results.
    pub results: Vec<HypothesisResult>,
    /// Explicit and validation-produced unresolved gaps.
    pub unresolved_gap_ids: Vec<RecoveryGapId>,
    /// Shared header validation result.
    pub validation: HeaderValidationReport,
    /// Header projection when at least one declaration remains accepted.
    pub projected_header: Option<HeaderProjection>,
}

fn zero_hash() -> ContentHash {
    ContentHash::new("0".repeat(64)).expect("64 lowercase hexadecimal characters")
}

pub(crate) fn enforce(
    limit: &'static str,
    selected: u64,
    maximum: u64,
) -> Result<(), ArtifactError> {
    if selected <= maximum {
        Ok(())
    } else {
        Err(ArtifactError::Limit {
            limit,
            selected,
            maximum,
        })
    }
}

fn unique<'a>(
    kind: &str,
    values: impl Iterator<Item = &'a str>,
) -> Result<BTreeSet<&'a str>, ArtifactError> {
    let mut result = BTreeSet::new();
    for value in values {
        if !result.insert(value) {
            return Err(ArtifactError::Invalid(format!("duplicate {kind} {value}")));
        }
    }
    Ok(result)
}

fn require(values: &BTreeSet<&str>, value: &str, kind: &str) -> Result<(), ArtifactError> {
    if values.contains(value) {
        Ok(())
    } else {
        Err(ArtifactError::Invalid(format!(
            "dangling {kind} reference {value}"
        )))
    }
}
