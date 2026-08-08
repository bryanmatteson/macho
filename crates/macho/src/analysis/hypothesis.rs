//! Reusable hypotheses and operator selection policy for lossy projections.
//!
//! Recovery facts remain owned by their originating recovery model.  This
//! module describes possible interpretations of unresolved subjects and the
//! authority that allowed one interpretation to affect a projection.  In
//! particular, operator permission to guess never upgrades heuristic evidence
//! into an independently recovered fact.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Current wire version for operator-authored hypothesis selections.
pub const HYPOTHESIS_SELECTION_DOCUMENT_VERSION: u32 = 1;

/// Whether hypotheses may affect a projection automatically.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectionPolicyMode {
    /// Project facts and explicit operator choices only.
    #[default]
    Strict,
    /// Keep strict output while reporting ranked hypotheses for blockers.
    Suggest,
    /// Permit the highest-ranked candidate to affect projection.
    BestEffort,
}

/// Epistemic authority of evidence supporting a candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceAuthority {
    /// Recovered without depending on the proposition being decided.
    Independent,
    /// Correlated with another typed source or independently anchored fact.
    Correlated,
    /// Produced by a fallible rule or heuristic.
    Heuristic,
}

/// Authority allowing a candidate to affect projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionAuthority {
    /// The active best-effort policy authorized automatic selection.
    OperatorPolicy,
    /// An exact operator override selected this candidate.
    ExplicitOperatorChoice,
}

/// Stable kind of source supporting a hypothesis candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HypothesisEvidenceKind {
    /// Recovered entity identity.
    Entity,
    /// Typed fact identity within a recovered entity or program.
    Fact,
    /// Evidence record retained by the originating recovery model.
    Evidence,
    /// Raw or normalized observation retained by recovery.
    Observation,
    /// Recovery gap whose absence or ambiguity motivates the interpretation.
    RecoveryGap,
}

/// Auditable reference to one retained source supporting a candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HypothesisEvidenceRef {
    /// Kind of retained source identified by `id`.
    pub kind: HypothesisEvidenceKind,
    /// Stable ID in the originating recovery model.
    pub id: String,
    /// Concise explanation of how this source supports the interpretation.
    pub description: String,
}

/// Domain-neutral stable identity for one unresolved subject.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HypothesisSubject {
    /// Subsystem defining the key, such as `cpp_header` or `functions`.
    pub domain: String,
    /// Stable subsystem-local key.
    pub key: String,
}

/// One stage or declaration that could change if a candidate is selected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HypothesisConsequence {
    /// Stable affected stage name.
    pub stage: String,
    /// Stable affected declaration or subject key, when narrower than a stage.
    pub subject: Option<String>,
    /// Human-readable description of the possible change.
    pub description: String,
}

/// One ranked interpretation of an unresolved subject.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HypothesisCandidate {
    /// Stable candidate key within the hypothesis.
    pub id: String,
    /// One-based rank; lower ranks are preferred.
    pub rank: u32,
    /// Concise interpretation presented to an operator.
    pub interpretation: String,
    /// Least authoritative evidence required for this interpretation. A
    /// candidate that combines correlated observations with any heuristic
    /// step remains heuristic as a whole.
    pub evidence_authority: EvidenceAuthority,
    /// Integer confidence in the inclusive range 0..=10,000 basis points.
    pub confidence_basis_points: u16,
    /// Typed evidence or observations supporting the interpretation.
    pub evidence: Vec<HypothesisEvidenceRef>,
    /// Rule or heuristic that produced the candidate.
    pub rule: String,
    /// Effects that selection may have.
    pub consequences: Vec<HypothesisConsequence>,
}

/// Ranked alternatives for one unresolved subject.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryHypothesis {
    /// Stable unresolved subject.
    pub subject: HypothesisSubject,
    /// Human-readable statement of the blocker.
    pub unresolved: String,
    /// Ranked competing interpretations. Alternatives are retained even when
    /// one candidate is selected. An empty collection means Macho has no
    /// supported interpretation and must abstain.
    pub candidates: Vec<HypothesisCandidate>,
    /// Explanation retained when no supported candidate exists. This is an
    /// explicit absence of a decision, not a high-confidence candidate.
    pub abstention: Option<String>,
}

/// An exact candidate selection authored by an operator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HypothesisOverride {
    /// Exact unresolved subject.
    pub subject: HypothesisSubject,
    /// Exact candidate ID within that subject.
    pub candidate_id: String,
}

/// Versioned, operator-authored selections suitable for durable machine or
/// hand-authored input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HypothesisSelectionDocument {
    /// Selection document wire version.
    pub schema_version: u32,
    /// Exact subject/candidate choices.
    pub selections: Vec<HypothesisOverride>,
}

/// Failure to decode or validate a selection document.
#[derive(Debug, Error)]
pub enum HypothesisSelectionDocumentError {
    /// The input is not valid strict JSON for this document.
    #[error("invalid hypothesis selection JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// The input is not valid strict TOML for this document.
    #[error("invalid hypothesis selection TOML: {0}")]
    Toml(#[from] toml::de::Error),
    /// The document uses a schema this build does not understand.
    #[error("unsupported hypothesis selection schema version {found}; expected {supported}")]
    UnsupportedSchemaVersion {
        /// Version found in the document.
        found: u32,
        /// Version supported by this build.
        supported: u32,
    },
    /// More than one selection targets the same unresolved subject.
    #[error("duplicate hypothesis selection subject {domain}:{key}")]
    DuplicateSubject {
        /// Subject namespace in which the duplicate occurred.
        domain: String,
        /// Stable subject key that occurred more than once.
        key: String,
    },
    /// A durable subject or candidate identity is empty.
    #[error("hypothesis selection identities must be non-empty")]
    EmptyIdentity,
}

impl HypothesisSelectionDocument {
    /// Decode a strict selection document and reject unknown versions or
    /// duplicate subjects before any projection work begins.
    pub fn load_json(bytes: &[u8]) -> Result<Self, HypothesisSelectionDocumentError> {
        let document: Self = serde_json::from_slice(bytes)?;
        document.validate()?;
        Ok(document)
    }

    /// Decode the compact TOML representation and normalize it into the same
    /// domain-neutral document used by JSON input.
    pub fn load_toml(source: &str) -> Result<Self, HypothesisSelectionDocumentError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct TomlDocument {
            #[serde(default = "selection_document_version")]
            schema_version: u32,
            selections: BTreeMap<String, BTreeMap<String, String>>,
        }

        fn selection_document_version() -> u32 {
            HYPOTHESIS_SELECTION_DOCUMENT_VERSION
        }

        let source: TomlDocument = toml::from_str(source)?;
        let document = Self {
            schema_version: source.schema_version,
            selections: source
                .selections
                .into_iter()
                .flat_map(|(domain, selections)| {
                    selections
                        .into_iter()
                        .map(move |(key, candidate_id)| HypothesisOverride {
                            subject: HypothesisSubject {
                                domain: domain.clone(),
                                key,
                            },
                            candidate_id,
                        })
                })
                .collect(),
        };
        document.validate()?;
        Ok(document)
    }

    /// Validate schema identity and subject uniqueness.
    pub fn validate(&self) -> Result<(), HypothesisSelectionDocumentError> {
        if self.schema_version != HYPOTHESIS_SELECTION_DOCUMENT_VERSION {
            return Err(HypothesisSelectionDocumentError::UnsupportedSchemaVersion {
                found: self.schema_version,
                supported: HYPOTHESIS_SELECTION_DOCUMENT_VERSION,
            });
        }
        let mut subjects = BTreeSet::new();
        for selection in &self.selections {
            if selection.subject.domain.trim().is_empty()
                || selection.subject.key.trim().is_empty()
                || selection.candidate_id.trim().is_empty()
            {
                return Err(HypothesisSelectionDocumentError::EmptyIdentity);
            }
            if !subjects.insert(&selection.subject) {
                return Err(HypothesisSelectionDocumentError::DuplicateSubject {
                    domain: selection.subject.domain.clone(),
                    key: selection.subject.key.clone(),
                });
            }
        }
        Ok(())
    }
}

/// Operator policy controlling hypothesis emission and selection.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HypothesisSelectionPolicy {
    /// Global projection behavior.
    pub mode: SelectionPolicyMode,
    /// Subject-specific choices. These always win over automatic selection.
    pub overrides: Vec<HypothesisOverride>,
}

/// Complete receipt for one guessed declaration or other selected effect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HypothesisSelectionReceipt {
    /// The unresolved subject being decided.
    pub subject: HypothesisSubject,
    /// Human-readable statement of the unresolved condition.
    pub unresolved: String,
    /// Selected candidate.
    pub chosen_candidate_id: String,
    /// Human-readable interpretation selected for projection.
    pub chosen_interpretation: String,
    /// Retained competing candidate IDs in ranked order.
    pub alternative_candidate_ids: Vec<String>,
    /// Authority of the evidence, independent from decision authority.
    pub evidence_authority: EvidenceAuthority,
    /// Confidence copied from the selected candidate.
    pub confidence_basis_points: u16,
    /// Typed evidence copied from the selected candidate.
    pub evidence: Vec<HypothesisEvidenceRef>,
    /// Rule or heuristic used by the selected candidate.
    pub rule: String,
    /// Policy mode in force when the selection was made.
    pub operator_policy: SelectionPolicyMode,
    /// Authority that allowed the candidate to affect projection.
    pub decision_authority: DecisionAuthority,
    /// Whether an exact override, rather than automatic policy, selected it.
    pub explicitly_chosen: bool,
    /// Complete affected-stage/declaration ledger.
    pub consequences: Vec<HypothesisConsequence>,
}

/// Machine-readable assumptions accompanying one projection.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HypothesisLedger {
    /// Ranked hypotheses emitted for blockers.
    pub hypotheses: Vec<RecoveryHypothesis>,
    /// Selections that were allowed to affect the projection.
    pub selections: Vec<HypothesisSelectionReceipt>,
}

/// Invalid hypothesis or selection-policy input.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HypothesisContractError {
    /// A subject occurs more than once.
    #[error("duplicate hypothesis subject {domain}:{key}")]
    DuplicateSubject {
        /// Subject namespace in which the duplicate occurred.
        domain: String,
        /// Stable subject key that occurred more than once.
        key: String,
    },
    /// A candidate ID occurs more than once within a subject.
    #[error("duplicate hypothesis candidate identity for {domain}:{key}")]
    DuplicateCandidate {
        /// Subject namespace containing the duplicate candidate.
        domain: String,
        /// Stable subject key containing the duplicate candidate.
        key: String,
    },
    /// Confidence is outside the wire range.
    #[error("hypothesis confidence exceeds 10,000 basis points")]
    InvalidConfidence,
    /// An override does not identify one emitted candidate.
    #[error("hypothesis override does not identify an emitted candidate for {domain}:{key}")]
    UnknownOverride {
        /// Subject namespace targeted by the invalid override.
        domain: String,
        /// Stable subject key targeted by the invalid override.
        key: String,
    },
    /// A receipt is inconsistent with the policy or ranked hypothesis.
    #[error("hypothesis selection receipt is inconsistent")]
    InvalidReceipt,
    /// Candidate ranks are invalid or abstention state is inconsistent.
    #[error(
        "hypothesis candidates are not in strictly increasing rank order or abstention state is inconsistent"
    )]
    InvalidRanking,
    /// A durable subject or candidate identity is empty.
    #[error("hypothesis identities must be non-empty")]
    EmptyIdentity,
    /// Required explanatory or evidence content is empty.
    #[error("hypothesis explanatory content and evidence must be non-empty")]
    EmptyContent,
}

impl HypothesisSelectionPolicy {
    /// Choose a candidate according to exact overrides first and automatic
    /// best-effort policy second. Strict and suggest never auto-select.
    pub fn select<'a>(
        &self,
        hypothesis: &'a RecoveryHypothesis,
    ) -> Result<Option<(&'a HypothesisCandidate, DecisionAuthority)>, HypothesisContractError> {
        if let Some(selection) = self
            .overrides
            .iter()
            .find(|selection| selection.subject == hypothesis.subject)
        {
            let candidate = hypothesis
                .candidates
                .iter()
                .find(|candidate| candidate.id == selection.candidate_id)
                .ok_or_else(|| HypothesisContractError::UnknownOverride {
                    domain: hypothesis.subject.domain.clone(),
                    key: hypothesis.subject.key.clone(),
                })?;
            return Ok(Some((candidate, DecisionAuthority::ExplicitOperatorChoice)));
        }
        if self.mode != SelectionPolicyMode::BestEffort {
            return Ok(None);
        }
        Ok(hypothesis
            .candidates
            .iter()
            .min_by_key(|candidate| candidate.rank)
            .map(|candidate| (candidate, DecisionAuthority::OperatorPolicy)))
    }

    /// Build a complete receipt for a selected candidate.
    pub fn receipt(
        &self,
        hypothesis: &RecoveryHypothesis,
        candidate: &HypothesisCandidate,
        decision_authority: DecisionAuthority,
    ) -> HypothesisSelectionReceipt {
        HypothesisSelectionReceipt {
            subject: hypothesis.subject.clone(),
            unresolved: hypothesis.unresolved.clone(),
            chosen_candidate_id: candidate.id.clone(),
            chosen_interpretation: candidate.interpretation.clone(),
            alternative_candidate_ids: {
                let mut alternatives = hypothesis
                    .candidates
                    .iter()
                    .filter(|alternative| alternative.id != candidate.id)
                    .collect::<Vec<_>>();
                alternatives.sort_by_key(|alternative| alternative.rank);
                alternatives
                    .into_iter()
                    .map(|alternative| alternative.id.clone())
                    .collect()
            },
            evidence_authority: candidate.evidence_authority,
            confidence_basis_points: candidate.confidence_basis_points,
            evidence: candidate.evidence.clone(),
            rule: candidate.rule.clone(),
            operator_policy: self.mode,
            decision_authority,
            explicitly_chosen: decision_authority == DecisionAuthority::ExplicitOperatorChoice,
            consequences: candidate.consequences.clone(),
        }
    }
}

impl HypothesisLedger {
    /// Validate stable identities, rankings, overrides, and authority receipts.
    pub fn validate(
        &self,
        policy: &HypothesisSelectionPolicy,
    ) -> Result<(), HypothesisContractError> {
        let mut subjects = BTreeMap::new();
        for hypothesis in &self.hypotheses {
            if hypothesis.subject.domain.trim().is_empty()
                || hypothesis.subject.key.trim().is_empty()
            {
                return Err(HypothesisContractError::EmptyIdentity);
            }
            if hypothesis.unresolved.trim().is_empty()
                || hypothesis
                    .abstention
                    .as_ref()
                    .is_some_and(|reason| reason.trim().is_empty())
            {
                return Err(HypothesisContractError::EmptyContent);
            }
            if subjects.insert(&hypothesis.subject, hypothesis).is_some() {
                return Err(HypothesisContractError::DuplicateSubject {
                    domain: hypothesis.subject.domain.clone(),
                    key: hypothesis.subject.key.clone(),
                });
            }
            let mut ids = BTreeSet::new();
            let mut previous_rank = 0;
            if hypothesis.candidates.is_empty() != hypothesis.abstention.is_some() {
                return Err(HypothesisContractError::InvalidRanking);
            }
            for candidate in &hypothesis.candidates {
                if candidate.id.trim().is_empty() {
                    return Err(HypothesisContractError::EmptyIdentity);
                }
                if candidate.interpretation.trim().is_empty()
                    || candidate.evidence.is_empty()
                    || candidate
                        .evidence
                        .iter()
                        .any(|item| item.id.trim().is_empty() || item.description.trim().is_empty())
                    || candidate.rule.trim().is_empty()
                    || candidate.consequences.iter().any(|consequence| {
                        consequence.stage.trim().is_empty()
                            || consequence.description.trim().is_empty()
                            || consequence
                                .subject
                                .as_ref()
                                .is_some_and(|subject| subject.trim().is_empty())
                    })
                {
                    return Err(HypothesisContractError::EmptyContent);
                }
                if candidate.rank == 0 || candidate.rank <= previous_rank {
                    return Err(HypothesisContractError::InvalidRanking);
                }
                if !ids.insert(candidate.id.as_str()) {
                    return Err(HypothesisContractError::DuplicateCandidate {
                        domain: hypothesis.subject.domain.clone(),
                        key: hypothesis.subject.key.clone(),
                    });
                }
                previous_rank = candidate.rank;
                if candidate.confidence_basis_points > 10_000 {
                    return Err(HypothesisContractError::InvalidConfidence);
                }
            }
        }
        let mut override_subjects = BTreeSet::new();
        for selection in &policy.overrides {
            if !override_subjects.insert(&selection.subject) {
                return Err(HypothesisContractError::UnknownOverride {
                    domain: selection.subject.domain.clone(),
                    key: selection.subject.key.clone(),
                });
            }
            let Some(hypothesis) = subjects.get(&selection.subject) else {
                return Err(HypothesisContractError::UnknownOverride {
                    domain: selection.subject.domain.clone(),
                    key: selection.subject.key.clone(),
                });
            };
            if !hypothesis
                .candidates
                .iter()
                .any(|candidate| candidate.id == selection.candidate_id)
            {
                return Err(HypothesisContractError::UnknownOverride {
                    domain: selection.subject.domain.clone(),
                    key: selection.subject.key.clone(),
                });
            }
        }
        let mut selected_subjects = BTreeSet::new();
        for receipt in &self.selections {
            if !selected_subjects.insert(&receipt.subject) {
                return Err(HypothesisContractError::InvalidReceipt);
            }
            let Some(hypothesis) = subjects.get(&receipt.subject) else {
                return Err(HypothesisContractError::InvalidReceipt);
            };
            let Some(candidate) = hypothesis
                .candidates
                .iter()
                .find(|candidate| candidate.id == receipt.chosen_candidate_id)
            else {
                return Err(HypothesisContractError::InvalidReceipt);
            };
            let expected = policy.receipt(hypothesis, candidate, receipt.decision_authority);
            let selected = policy.select(hypothesis)?;
            if &expected != receipt
                || !matches!(
                    selected,
                    Some((selected_candidate, authority))
                        if selected_candidate.id == receipt.chosen_candidate_id
                            && authority == receipt.decision_authority
                )
            {
                return Err(HypothesisContractError::InvalidReceipt);
            }
        }
        for hypothesis in &self.hypotheses {
            let selected = policy.select(hypothesis)?;
            let affects_projection =
                selected.is_some_and(|(candidate, _)| !candidate.consequences.is_empty());
            if affects_projection != selected_subjects.contains(&hypothesis.subject) {
                return Err(HypothesisContractError::InvalidReceipt);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence(id: &str, description: &str) -> HypothesisEvidenceRef {
        HypothesisEvidenceRef {
            kind: HypothesisEvidenceKind::Evidence,
            id: id.into(),
            description: description.into(),
        }
    }

    fn hypothesis() -> RecoveryHypothesis {
        RecoveryHypothesis {
            subject: HypothesisSubject {
                domain: "cpp_header".into(),
                key: "gap-1".into(),
            },
            unresolved: "owner kind is not encoded".into(),
            candidates: vec![
                HypothesisCandidate {
                    id: "namespace".into(),
                    rank: 1,
                    interpretation: "namespace owner".into(),
                    evidence_authority: EvidenceAuthority::Heuristic,
                    confidence_basis_points: 7_000,
                    evidence: vec![evidence("evidence-1", "qualified Itanium name")],
                    rule: "unknown prefixes default to namespaces".into(),
                    consequences: Vec::new(),
                },
                HypothesisCandidate {
                    id: "class".into(),
                    rank: 2,
                    interpretation: "public class member".into(),
                    evidence_authority: EvidenceAuthority::Heuristic,
                    confidence_basis_points: 3_000,
                    evidence: vec![evidence(
                        "evidence-1",
                        "qualified spelling admits a member interpretation",
                    )],
                    rule: "competing owner interpretation".into(),
                    consequences: Vec::new(),
                },
            ],
            abstention: None,
        }
    }

    #[test]
    fn strict_and_suggest_do_not_auto_select() {
        let hypothesis = hypothesis();
        for mode in [SelectionPolicyMode::Strict, SelectionPolicyMode::Suggest] {
            let policy = HypothesisSelectionPolicy {
                mode,
                overrides: Vec::new(),
            };
            assert_eq!(policy.select(&hypothesis).unwrap(), None);
        }
    }

    #[test]
    fn explicit_override_wins_over_best_effort_rank() {
        let hypothesis = hypothesis();
        let policy = HypothesisSelectionPolicy {
            mode: SelectionPolicyMode::BestEffort,
            overrides: vec![HypothesisOverride {
                subject: hypothesis.subject.clone(),
                candidate_id: "class".into(),
            }],
        };
        let (candidate, authority) = policy.select(&hypothesis).unwrap().unwrap();
        assert_eq!(candidate.id, "class");
        assert_eq!(authority, DecisionAuthority::ExplicitOperatorChoice);
        let receipt = policy.receipt(&hypothesis, candidate, authority);
        assert_eq!(receipt.evidence_authority, EvidenceAuthority::Heuristic);
        assert_eq!(
            receipt.decision_authority,
            DecisionAuthority::ExplicitOperatorChoice
        );
        assert!(receipt.explicitly_chosen);
    }

    #[test]
    fn selection_document_loads_strict_versioned_json() {
        let document = HypothesisSelectionDocument::load_json(
            br#"{
                "schema_version": 1,
                "selections": [{
                    "subject": {"domain": "cpp_header", "key": "gap-1"},
                    "candidate_id": "class"
                }]
            }"#,
        )
        .unwrap();
        assert_eq!(document.selections[0].candidate_id, "class");
    }

    #[test]
    fn selection_document_loads_compact_toml() {
        let document = HypothesisSelectionDocument::load_toml(
            r#"
                [selections.cpp_header]
                "gap-1" = "class"
                "gap-2" = "opaque_return_type"
            "#,
        )
        .unwrap();
        assert_eq!(document.selections.len(), 2);
        assert_eq!(document.selections[0].subject.domain, "cpp_header");
        assert_eq!(document.selections[0].subject.key, "gap-1");
        assert_eq!(document.selections[0].candidate_id, "class");
        assert_eq!(
            document.schema_version,
            HYPOTHESIS_SELECTION_DOCUMENT_VERSION
        );
    }

    #[test]
    fn selection_document_rejects_unknown_fields_versions_and_duplicates() {
        let unknown = br#"{
            "schema_version": 1,
            "selections": [],
            "mode": "best_effort"
        }"#;
        assert!(matches!(
            HypothesisSelectionDocument::load_json(unknown),
            Err(HypothesisSelectionDocumentError::Json(_))
        ));

        let unsupported = br#"{"schema_version": 0, "selections": []}"#;
        assert!(matches!(
            HypothesisSelectionDocument::load_json(unsupported),
            Err(HypothesisSelectionDocumentError::UnsupportedSchemaVersion { .. })
        ));

        let duplicate = br#"{
            "schema_version": 1,
            "selections": [
                {
                    "subject": {"domain": "cpp_header", "key": "gap-1"},
                    "candidate_id": "namespace"
                },
                {
                    "subject": {"domain": "cpp_header", "key": "gap-1"},
                    "candidate_id": "class"
                }
            ]
        }"#;
        assert!(matches!(
            HypothesisSelectionDocument::load_json(duplicate),
            Err(HypothesisSelectionDocumentError::DuplicateSubject { .. })
        ));

        let duplicate_toml = r#"
            schema_version = 1
            [selections.cpp_header]
            "gap-1" = "namespace"
            "gap-1" = "class"
        "#;
        assert!(matches!(
            HypothesisSelectionDocument::load_toml(duplicate_toml),
            Err(HypothesisSelectionDocumentError::Toml(_))
        ));

        let empty = br#"{
            "schema_version": 1,
            "selections": [{
                "subject": {"domain": "cpp_header", "key": ""},
                "candidate_id": "class"
            }]
        }"#;
        assert!(matches!(
            HypothesisSelectionDocument::load_json(empty),
            Err(HypothesisSelectionDocumentError::EmptyIdentity)
        ));
    }

    #[test]
    fn ledger_requires_rank_order_and_every_effectful_selection_receipt() {
        let mut hypothesis = hypothesis();
        hypothesis.candidates[0].consequences = vec![HypothesisConsequence {
            stage: "header_projection".into(),
            subject: Some("entity-1".into()),
            description: "adds a declaration".into(),
        }];
        let policy = HypothesisSelectionPolicy {
            mode: SelectionPolicyMode::BestEffort,
            overrides: Vec::new(),
        };
        let missing = HypothesisLedger {
            hypotheses: vec![hypothesis.clone()],
            selections: Vec::new(),
        };
        assert_eq!(
            missing.validate(&policy),
            Err(HypothesisContractError::InvalidReceipt)
        );

        let (candidate, authority) = policy.select(&hypothesis).unwrap().unwrap();
        let complete = HypothesisLedger {
            hypotheses: vec![hypothesis.clone()],
            selections: vec![policy.receipt(&hypothesis, candidate, authority)],
        };
        assert!(complete.validate(&policy).is_ok());

        hypothesis.candidates.swap(0, 1);
        let unsorted = HypothesisLedger {
            hypotheses: vec![hypothesis],
            selections: Vec::new(),
        };
        assert_eq!(
            unsorted.validate(&HypothesisSelectionPolicy::default()),
            Err(HypothesisContractError::InvalidRanking)
        );
    }

    #[test]
    fn receipts_sort_alternatives_by_rank() {
        let mut hypothesis = hypothesis();
        hypothesis.candidates.push(HypothesisCandidate {
            id: "record".into(),
            rank: 3,
            interpretation: "record owner".into(),
            evidence_authority: EvidenceAuthority::Heuristic,
            confidence_basis_points: 2_000,
            evidence: vec![evidence(
                "evidence-3",
                "a third supported interpretation exists",
            )],
            rule: "third interpretation".into(),
            consequences: Vec::new(),
        });
        hypothesis.candidates.swap(0, 2);
        let policy = HypothesisSelectionPolicy::default();
        let candidate = hypothesis
            .candidates
            .iter()
            .find(|candidate| candidate.id == "class")
            .unwrap();
        let receipt = policy.receipt(
            &hypothesis,
            candidate,
            DecisionAuthority::ExplicitOperatorChoice,
        );
        assert_eq!(receipt.alternative_candidate_ids, ["namespace", "record"]);
    }

    #[test]
    fn ledger_rejects_missing_explanations_and_evidence() {
        let mut hypothesis = hypothesis();
        hypothesis.candidates[0].evidence.clear();
        let ledger = HypothesisLedger {
            hypotheses: vec![hypothesis],
            selections: Vec::new(),
        };
        assert_eq!(
            ledger.validate(&HypothesisSelectionPolicy::default()),
            Err(HypothesisContractError::EmptyContent)
        );
    }

    #[test]
    fn abstention_is_explicit_and_cannot_be_selected() {
        let abstention = RecoveryHypothesis {
            subject: HypothesisSubject {
                domain: "cpp_header".into(),
                key: "gap-without-supported-interpretation".into(),
            },
            unresolved: "the retained evidence does not admit a source declaration".into(),
            candidates: Vec::new(),
            abstention: Some("no contract-preserving interpretation exists".into()),
        };
        let policy = HypothesisSelectionPolicy {
            mode: SelectionPolicyMode::BestEffort,
            overrides: Vec::new(),
        };
        assert!(policy.select(&abstention).unwrap().is_none());
        assert!(
            HypothesisLedger {
                hypotheses: vec![abstention.clone()],
                selections: Vec::new(),
            }
            .validate(&policy)
            .is_ok()
        );

        let mut implicit = abstention;
        implicit.abstention = None;
        assert_eq!(
            HypothesisLedger {
                hypotheses: vec![implicit],
                selections: Vec::new(),
            }
            .validate(&policy),
            Err(HypothesisContractError::InvalidRanking)
        );
    }
}
