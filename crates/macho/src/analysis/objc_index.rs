//! Bounded image-bound Objective-C runtime metadata recovery.

use crate::core::model::macho_file::MachoFile;
use crate::metadata::objc::strict::{StrictObjCLimits, StrictObjCOutcome, decode_strict_objc};
use crate::metadata::objc::{ObjCMethodKind, ObjCRecordKind};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::analysis::functions::FunctionImageIdentity;

/// Explicit limits for one strict Objective-C inventory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjcRecoveryLimits {
    /// Maximum runtime-list observations.
    pub max_observations: usize,
    /// Maximum decoded class, category, and protocol entities.
    pub max_entities: usize,
    /// Maximum retained method records.
    pub max_methods: usize,
    /// Maximum entries in any nested protocol list or superclass walk.
    pub max_nested_records: usize,
}

impl Default for ObjcRecoveryLimits {
    fn default() -> Self {
        Self {
            max_observations: 8_000_000,
            max_entities: 2_000_000,
            max_methods: 8_000_000,
            max_nested_records: 2_000_000,
        }
    }
}

impl ObjcRecoveryLimits {
    /// Reject zero-valued limits.
    pub fn validate(self) -> Result<Self, ObjcRecoveryError> {
        if self.max_observations == 0
            || self.max_entities == 0
            || self.max_methods == 0
            || self.max_nested_records == 0
        {
            return Err(ObjcRecoveryError::InvalidLimits);
        }
        Ok(self)
    }

    const fn strict(self) -> StrictObjCLimits {
        StrictObjCLimits {
            max_observations: self.max_observations,
            max_entities: self.max_entities,
            max_methods: self.max_methods,
            max_nested_records: self.max_nested_records,
        }
    }
}

/// Failure preventing Objective-C recovery from producing a typed outcome.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ObjcRecoveryError {
    /// At least one limit is zero.
    #[error("Objective-C recovery limits must be non-zero")]
    InvalidLimits,
    /// The strict leaf decoder rejected the request itself.
    #[error("strict Objective-C recovery failed: {0}")]
    Decode(String),
}

/// Objective-C inventory completion state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjcIndexStatus {
    /// No Objective-C runtime-list surface exists.
    Absent,
    /// Every admitted runtime observation and method was conserved.
    Complete,
    /// Runtime metadata exists but strict decoding rejected some evidence.
    Partial,
    /// An explicit structural limit prevented complete recovery.
    Truncated,
}

/// Objective-C runtime entity kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjcEntityKind {
    /// Runtime class record.
    Class,
    /// Runtime category record.
    Category,
    /// Runtime protocol record.
    Protocol,
}

/// Addressable Objective-C runtime entity identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredObjcEntity {
    /// Runtime entity kind.
    pub kind: ObjcEntityKind,
    /// Exact runtime record address.
    pub address: u64,
    /// Parsed runtime name.
    pub name: String,
}

/// One exact Objective-C method implementation and storage record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredObjcMethod {
    /// Runtime address of the owning class, metaclass, or category.
    pub owner_address: u64,
    /// Owning class name.
    pub class_name: String,
    /// Owning category, when applicable.
    pub category_name: Option<String>,
    /// Selector spelling.
    pub selector: String,
    /// Raw Objective-C type encoding.
    pub type_encoding: String,
    /// Whether this is an instance or class method.
    pub class_method: bool,
    /// Exact implementation address.
    pub implementation: u64,
    /// Runtime address of the method record.
    pub record_address: u64,
    /// Thin-image file offset of the method record.
    pub record_file_offset: u64,
}

/// One recovered Objective-C class hierarchy and protocol record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredObjcClass {
    /// Runtime class record address when present in `__objc_classlist`.
    pub address: Option<u64>,
    /// Runtime metaclass record address reached through the class object's isa pointer.
    pub metaclass_address: Option<u64>,
    /// Runtime class name.
    pub name: String,
    /// Direct superclass name.
    pub superclass: Option<String>,
    /// Directly adopted protocols.
    pub protocols: Vec<String>,
}

/// One runtime protocol and its transitive-narrowing surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredObjcProtocol {
    /// Runtime protocol name.
    pub name: String,
    /// Directly adopted protocols.
    pub adopted_protocols: Vec<String>,
    /// Required instance selectors.
    pub required_instance_selectors: Vec<String>,
    /// Required class selectors.
    pub required_class_selectors: Vec<String>,
    /// Optional instance selectors.
    pub optional_instance_selectors: Vec<String>,
    /// Optional class selectors.
    pub optional_class_selectors: Vec<String>,
}

/// Completeness and conservation receipt for Objective-C recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjcIndexCompleteness {
    /// Overall status.
    pub status: ObjcIndexStatus,
    /// Stable reason codes.
    pub reasons: Vec<String>,
    /// Source observations attempted.
    pub attempted: u64,
    /// Source observations included.
    pub included: u64,
    /// Source observations unresolved.
    pub unknown: u64,
    /// Source observations deliberately excluded.
    pub excluded: u64,
}

/// Deterministic strict Objective-C inventory for one exact image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjcIndex {
    image: FunctionImageIdentity,
    limits: ObjcRecoveryLimits,
    entities: Vec<RecoveredObjcEntity>,
    methods: Vec<RecoveredObjcMethod>,
    classes: Vec<RecoveredObjcClass>,
    protocols: Vec<RecoveredObjcProtocol>,
    completeness: ObjcIndexCompleteness,
}

impl ObjcIndex {
    /// Recover strict runtime entities and methods exactly once.
    pub fn recover(
        macho: &MachoFile<'_>,
        limits: ObjcRecoveryLimits,
    ) -> Result<Self, ObjcRecoveryError> {
        let limits = limits.validate()?;
        let outcome = decode_strict_objc(macho, limits.strict())
            .map_err(|error| ObjcRecoveryError::Decode(error.to_string()))?;
        Self::from_outcome(macho, limits, outcome)
    }

    /// Recover from the selected-image evidence session used by program recovery.
    pub fn recover_with_evidence(
        evidence: &crate::evidence::SelectedImageEvidence<'_, '_>,
        limits: ObjcRecoveryLimits,
    ) -> Result<Self, ObjcRecoveryError> {
        let limits = limits.validate()?;
        let outcome = evidence
            .objective_c(limits.strict())
            .map_err(|error| ObjcRecoveryError::Decode(error.to_string()))?;
        Self::from_outcome(evidence.image(), limits, outcome)
    }

    fn from_outcome(
        macho: &MachoFile<'_>,
        limits: ObjcRecoveryLimits,
        outcome: StrictObjCOutcome,
    ) -> Result<Self, ObjcRecoveryError> {
        let (mut entities, mut methods, mut classes, mut protocols, completeness) =
            project_outcome(macho, &outcome);
        entities.sort_by_key(|entity| (entity.address, entity.kind, entity.name.clone()));
        methods.sort_by_key(|method| {
            (
                method.implementation,
                method.record_address,
                method.class_name.clone(),
                method.selector.clone(),
            )
        });
        classes.sort_by(|left, right| left.name.cmp(&right.name));
        protocols.sort_by(|left, right| left.name.cmp(&right.name));
        let index = Self {
            image: FunctionImageIdentity::from_macho(macho),
            limits,
            entities,
            methods,
            classes,
            protocols,
            completeness,
        };
        debug_assert!(index.durable_invariants_hold());
        Ok(index)
    }

    /// Exact selected-image identity.
    pub fn image(&self) -> &FunctionImageIdentity {
        &self.image
    }

    /// Exact recovery limits.
    pub const fn limits(&self) -> ObjcRecoveryLimits {
        self.limits
    }

    /// Addressable runtime entities sorted by address.
    pub fn entities(&self) -> &[RecoveredObjcEntity] {
        &self.entities
    }

    /// Method implementations sorted by implementation address.
    pub fn methods(&self) -> &[RecoveredObjcMethod] {
        &self.methods
    }

    /// Class hierarchy and protocol records sorted by class name.
    pub fn classes(&self) -> &[RecoveredObjcClass] {
        &self.classes
    }

    /// Runtime protocols sorted by name.
    pub fn protocols(&self) -> &[RecoveredObjcProtocol] {
        &self.protocols
    }

    /// Overall completion state.
    pub const fn status(&self) -> ObjcIndexStatus {
        self.completeness.status
    }

    /// Completeness and conservation receipt.
    pub const fn completeness(&self) -> &ObjcIndexCompleteness {
        &self.completeness
    }

    /// Find an exact runtime entity address.
    pub fn entity_by_address(&self, address: u64) -> Option<&RecoveredObjcEntity> {
        self.entities
            .binary_search_by_key(&address, |entity| entity.address)
            .ok()
            .map(|index| &self.entities[index])
    }

    /// Iterate every method with an exact implementation address.
    pub fn methods_by_implementation(
        &self,
        address: u64,
    ) -> impl Iterator<Item = &RecoveredObjcMethod> {
        let start = self
            .methods
            .partition_point(|method| method.implementation < address);
        let end = self
            .methods
            .partition_point(|method| method.implementation <= address);
        self.methods[start..end].iter()
    }

    /// Iterate every retained method matching a selector.
    pub fn methods_by_selector<'index>(
        &'index self,
        selector: &'index str,
    ) -> impl Iterator<Item = &'index RecoveredObjcMethod> + 'index {
        self.methods
            .iter()
            .filter(move |method| method.selector == selector)
    }

    pub(crate) fn durable_invariants_hold(&self) -> bool {
        if self.limits.validate().is_err()
            || self.entities.len() > self.limits.max_observations
            || self.classes.len() > self.limits.max_entities
            || self.protocols.len() > self.limits.max_entities
            || self.methods.len() > self.limits.max_methods
        {
            return false;
        }

        let entities_are_canonical = self.entities.windows(2).all(|pair| {
            (pair[0].address, pair[0].kind, &pair[0].name)
                <= (pair[1].address, pair[1].kind, &pair[1].name)
        });
        let methods_are_canonical = self.methods.windows(2).all(|pair| {
            (
                pair[0].implementation,
                pair[0].record_address,
                &pair[0].class_name,
                &pair[0].selector,
            ) <= (
                pair[1].implementation,
                pair[1].record_address,
                &pair[1].class_name,
                &pair[1].selector,
            )
        });
        let classes_are_canonical = self
            .classes
            .windows(2)
            .all(|pair| pair[0].name <= pair[1].name);
        let protocols_are_canonical = self
            .protocols
            .windows(2)
            .all(|pair| pair[0].name <= pair[1].name);
        let class_protocols_are_canonical = self
            .classes
            .iter()
            .all(|class| class.protocols.windows(2).all(|pair| pair[0] < pair[1]));
        let reasons_are_canonical = self
            .completeness
            .reasons
            .windows(2)
            .all(|pair| pair[0] < pair[1]);
        let conserved = self
            .completeness
            .included
            .checked_add(self.completeness.unknown)
            .and_then(|count| count.checked_add(self.completeness.excluded));
        let retained = self
            .entities
            .len()
            .checked_add(self.methods.len())
            .and_then(|count| u64::try_from(count).ok());
        let payload_is_empty = self.entities.is_empty()
            && self.methods.is_empty()
            && self.classes.is_empty()
            && self.protocols.is_empty();
        let receipt_matches_payload = match self.completeness.status {
            ObjcIndexStatus::Absent => {
                payload_is_empty
                    && self.completeness.reasons.is_empty()
                    && self.completeness.attempted == 0
                    && self.completeness.included == 0
                    && self.completeness.unknown == 0
                    && self.completeness.excluded == 0
            }
            ObjcIndexStatus::Complete => {
                self.completeness.reasons.is_empty()
                    && self.completeness.unknown == 0
                    && self.completeness.excluded == 0
                    && retained == Some(self.completeness.included)
            }
            ObjcIndexStatus::Partial | ObjcIndexStatus::Truncated => {
                let truncated = self.completeness.reasons.iter().any(|reason| {
                    reason.contains("limit")
                        || reason.contains("budget")
                        || reason.contains("overflow")
                });
                payload_is_empty
                    && !self.completeness.reasons.is_empty()
                    && self.completeness.included == 0
                    && self.completeness.unknown == self.completeness.attempted
                    && self.completeness.excluded == 0
                    && truncated == (self.completeness.status == ObjcIndexStatus::Truncated)
            }
        };

        entities_are_canonical
            && methods_are_canonical
            && classes_are_canonical
            && protocols_are_canonical
            && class_protocols_are_canonical
            && reasons_are_canonical
            && conserved == Some(self.completeness.attempted)
            && receipt_matches_payload
            && self.entities.iter().all(|entity| !entity.name.is_empty())
            && self.methods.iter().all(|method| {
                !method.class_name.is_empty()
                    && !method.selector.is_empty()
                    && method.record_file_offset < self.image.byte_len
            })
            && self.classes.iter().all(|class| !class.name.is_empty())
            && self
                .protocols
                .iter()
                .all(|protocol| !protocol.name.is_empty())
    }
}

fn project_outcome(
    macho: &MachoFile<'_>,
    outcome: &StrictObjCOutcome,
) -> (
    Vec<RecoveredObjcEntity>,
    Vec<RecoveredObjcMethod>,
    Vec<RecoveredObjcClass>,
    Vec<RecoveredObjcProtocol>,
    ObjcIndexCompleteness,
) {
    match outcome {
        StrictObjCOutcome::Absent => (
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            ObjcIndexCompleteness {
                status: ObjcIndexStatus::Absent,
                reasons: Vec::new(),
                attempted: 0,
                included: 0,
                unknown: 0,
                excluded: 0,
            },
        ),
        StrictObjCOutcome::Complete(batch) => {
            let entities = batch
                .observations
                .iter()
                .filter_map(|observation| {
                    Some(RecoveredObjcEntity {
                        kind: match observation.kind {
                            ObjCRecordKind::Class => ObjcEntityKind::Class,
                            ObjCRecordKind::Category => ObjcEntityKind::Category,
                            ObjCRecordKind::Protocol => ObjcEntityKind::Protocol,
                        },
                        address: observation.runtime_address?,
                        name: observation.parsed_name.clone()?,
                    })
                })
                .collect::<Vec<_>>();
            let methods = batch
                .method_records
                .iter()
                .map(|method| RecoveredObjcMethod {
                    owner_address: method.owner_va.0,
                    class_name: method.class_name.clone(),
                    category_name: method.category_name.clone(),
                    selector: method.method_name.clone(),
                    type_encoding: method.type_encoding.clone(),
                    class_method: method.kind == ObjCMethodKind::Class,
                    implementation: method.imp.0,
                    record_address: method.provenance.record_va.0,
                    record_file_offset: method.provenance.record_file_offset.0,
                })
                .collect();
            let addresses = entities
                .iter()
                .filter(|entity| entity.kind == ObjcEntityKind::Class)
                .map(|entity| (entity.name.clone(), entity.address))
                .collect::<std::collections::BTreeMap<_, _>>();
            let category_protocols = batch.metadata.categories.iter().fold(
                std::collections::BTreeMap::<String, Vec<String>>::new(),
                |mut map, category| {
                    map.entry(category.class_name.clone())
                        .or_default()
                        .extend(category.protocols.iter().cloned());
                    map
                },
            );
            let resolver = crate::metadata::objc::resolve::ObjCResolver::new(macho).ok();
            let classes = batch
                .metadata
                .classes
                .iter()
                .map(|class| {
                    let mut protocols = class.protocols.clone();
                    protocols.extend(
                        category_protocols
                            .get(&class.name)
                            .into_iter()
                            .flatten()
                            .cloned(),
                    );
                    protocols.sort();
                    protocols.dedup();
                    RecoveredObjcClass {
                        address: addresses.get(&class.name).copied(),
                        metaclass_address: addresses.get(&class.name).and_then(|address| {
                            resolver.as_ref().and_then(|resolver| {
                                crate::metadata::objc::strict::class_metaclass_reference_with_resolver(
                                    macho,
                                    resolver,
                                    crate::core::model::addr::Va(*address),
                                )
                                .ok()
                                .map(|reference| reference.runtime_address.0)
                            })
                        }),
                        name: class.name.clone(),
                        superclass: class.superclass_name.clone(),
                        protocols,
                    }
                })
                .collect();
            let protocols = batch
                .metadata
                .protocols
                .iter()
                .map(|protocol| RecoveredObjcProtocol {
                    name: protocol.name.clone(),
                    adopted_protocols: protocol.adopted_protocols.clone(),
                    required_instance_selectors: protocol
                        .instance_methods
                        .iter()
                        .map(|method| method.name.clone())
                        .collect(),
                    required_class_selectors: protocol
                        .class_methods
                        .iter()
                        .map(|method| method.name.clone())
                        .collect(),
                    optional_instance_selectors: protocol
                        .optional_instance_methods
                        .iter()
                        .map(|method| method.name.clone())
                        .collect(),
                    optional_class_selectors: protocol
                        .optional_class_methods
                        .iter()
                        .map(|method| method.name.clone())
                        .collect(),
                })
                .collect();
            (
                entities,
                methods,
                classes,
                protocols,
                ObjcIndexCompleteness {
                    status: ObjcIndexStatus::Complete,
                    reasons: Vec::new(),
                    attempted: batch.conservation.attempted,
                    included: batch.conservation.included,
                    unknown: batch.conservation.unknown,
                    excluded: batch.conservation.excluded,
                },
            )
        }
        StrictObjCOutcome::Rejected(rejection) => {
            let mut reasons = rejection
                .gaps
                .iter()
                .map(|gap| gap.code.to_owned())
                .collect::<Vec<_>>();
            reasons.sort();
            reasons.dedup();
            let truncated = reasons.iter().any(|reason| {
                reason.contains("limit") || reason.contains("budget") || reason.contains("overflow")
            });
            (
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                ObjcIndexCompleteness {
                    status: if truncated {
                        ObjcIndexStatus::Truncated
                    } else {
                        ObjcIndexStatus::Partial
                    },
                    reasons,
                    attempted: rejection.conservation.attempted,
                    included: rejection.conservation.included,
                    unknown: rejection.conservation.unknown,
                    excluded: rejection.conservation.excluded,
                },
            )
        }
    }
}
