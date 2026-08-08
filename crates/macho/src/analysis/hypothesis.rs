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
    /// No decision authorized selection.
    None,
    /// The active best-effort policy authorized automatic selection.
    OperatorPolicy,
    /// An exact operator override selected this candidate.
    ExplicitOperatorChoice,
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
    /// Strongest authority among the evidence supporting this candidate.
    pub evidence_authority: EvidenceAuthority,
    /// Integer confidence in the inclusive range 0..=10,000 basis points.
    pub confidence_basis_points: u16,
    /// Evidence or observations supporting the interpretation.
    pub evidence: Vec<String>,
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
    /// one candidate is selected.
    pub candidates: Vec<HypothesisCandidate>,
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
    /// Selected candidate.
    pub chosen_candidate_id: String,
    /// Retained competing candidate IDs in ranked order.
    pub alternative_candidate_ids: Vec<String>,
    /// Authority of the evidence, independent from decision authority.
    pub evidence_authority: EvidenceAuthority,
    /// Confidence copied from the selected candidate.
    pub confidence_basis_points: u16,
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
    DuplicateSubject { domain: String, key: String },
    /// A candidate ID or rank occurs more than once within a subject.
    #[error("duplicate hypothesis candidate identity or rank for {domain}:{key}")]
    DuplicateCandidate { domain: String, key: String },
    /// Confidence is outside the wire range.
    #[error("hypothesis confidence exceeds 10,000 basis points")]
    InvalidConfidence,
    /// An override does not identify one emitted candidate.
    #[error("hypothesis override does not identify an emitted candidate for {domain}:{key}")]
    UnknownOverride { domain: String, key: String },
    /// A receipt is inconsistent with the policy or ranked hypothesis.
    #[error("hypothesis selection receipt is inconsistent")]
    InvalidReceipt,
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
            chosen_candidate_id: candidate.id.clone(),
            alternative_candidate_ids: hypothesis
                .candidates
                .iter()
                .filter(|alternative| alternative.id != candidate.id)
                .map(|alternative| alternative.id.clone())
                .collect(),
            evidence_authority: candidate.evidence_authority,
            confidence_basis_points: candidate.confidence_basis_points,
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
            if subjects.insert(&hypothesis.subject, hypothesis).is_some() {
                return Err(HypothesisContractError::DuplicateSubject {
                    domain: hypothesis.subject.domain.clone(),
                    key: hypothesis.subject.key.clone(),
                });
            }
            let mut ids = BTreeSet::new();
            let mut ranks = BTreeSet::new();
            for candidate in &hypothesis.candidates {
                if candidate.rank == 0
                    || !ids.insert(candidate.id.as_str())
                    || !ranks.insert(candidate.rank)
                {
                    return Err(HypothesisContractError::DuplicateCandidate {
                        domain: hypothesis.subject.domain.clone(),
                        key: hypothesis.subject.key.clone(),
                    });
                }
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
        for receipt in &self.selections {
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
            if &expected != receipt
                || (receipt.decision_authority == DecisionAuthority::OperatorPolicy
                    && policy.mode != SelectionPolicyMode::BestEffort)
                || receipt.decision_authority == DecisionAuthority::None
            {
                return Err(HypothesisContractError::InvalidReceipt);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
                    evidence: vec!["qualified Itanium name".into()],
                    rule: "unknown prefixes default to namespaces".into(),
                    consequences: Vec::new(),
                },
                HypothesisCandidate {
                    id: "class".into(),
                    rank: 2,
                    interpretation: "public class member".into(),
                    evidence_authority: EvidenceAuthority::Heuristic,
                    confidence_basis_points: 3_000,
                    evidence: Vec::new(),
                    rule: "competing owner interpretation".into(),
                    consequences: Vec::new(),
                },
            ],
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
        assert_eq!(receipt.decision_authority, DecisionAuthority::ExplicitOperatorChoice);
        assert!(receipt.explicitly_chosen);
    }
}
