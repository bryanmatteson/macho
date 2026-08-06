/// The ranges module.
pub mod ranges;
/// The refs module.
pub mod refs;

pub use ranges::{CodeEntity, RangeEntry, RangeSource, SymbolRangeIndex};
pub use refs::{
    Xref, XrefCollectorReceipt, XrefCollectorStatus, XrefCompleteness, XrefEvidenceSource,
    XrefIndex, XrefIndexStatus, XrefKind, XrefRecoveryLimits, XrefTarget,
};
