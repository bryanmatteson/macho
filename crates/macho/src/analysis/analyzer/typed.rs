//! Closed typed access to schema-v3 domain reports.

use std::marker::PhantomData;

use serde::de::DeserializeOwned;

use super::{DomainPayload, DomainState, SliceSnapshot};
use crate::analysis::audit::AuditReport;
use crate::analysis::error::{AnalysisDomain, AnalysisError, AnalysisErrorKind, Result};
use crate::analysis::report::{ObjCReport, RecoveryReport, SwiftReport};
use crate::analysis::snapshot::{
    CodesignSnapshot, ContainerSnapshot, DependencySnapshot, DwarfSnapshot, ExportSnapshot,
    FixupSnapshot, HeaderSnapshot, LoadCommandSnapshot, RelocationSectionSnapshot, SegmentSnapshot,
    SymbolSnapshot,
};
use crate::analysis::strings::FoundString;
use crate::analysis::vtables::VtableEntry;
use crate::analysis::xref::{RangeEntry, Xref};
use crate::metadata::dyld::imports::ImportRecord;

/// An opaque, compile-time association between an analysis domain and its Rust report type.
///
/// Keys can only be obtained from [`domain_reports`], preventing callers from
/// associating a structurally similar Rust type with the wrong domain.
pub struct DomainReportKey<T: DeserializeOwned> {
    domain: AnalysisDomain,
    marker: PhantomData<fn() -> T>,
}

impl<T: DeserializeOwned> DomainReportKey<T> {
    const fn new(domain: AnalysisDomain) -> Self {
        Self {
            domain,
            marker: PhantomData,
        }
    }

    /// Return the analysis domain represented by this key.
    pub const fn domain(self) -> AnalysisDomain {
        self.domain
    }
}

impl<T: DeserializeOwned> Copy for DomainReportKey<T> {}

impl<T: DeserializeOwned> Clone for DomainReportKey<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl DomainPayload {
    /// Decode this completed payload using one of the closed typed report keys.
    ///
    /// This rejects a key/payload domain mismatch before deserialization, even
    /// when the two report shapes happen to be structurally compatible.
    pub fn decode<T: DeserializeOwned>(&self, key: DomainReportKey<T>) -> Result<T> {
        let actual = self.domain();
        let expected = key.domain();
        if actual != expected {
            return Err(AnalysisError::new(
                actual,
                AnalysisErrorKind::DomainTypeMismatch,
                format!(
                    "cannot decode {} payload with {} report key",
                    actual.as_str(),
                    expected.as_str()
                ),
            ));
        }
        let value = super::payload::validate_typed_payload(actual, self.value().clone()).map_err(
            |error| {
                AnalysisError::new(
                    actual,
                    AnalysisErrorKind::Validation,
                    format!(
                        "{} payload failed typed validation: {error}",
                        actual.as_str()
                    ),
                )
            },
        )?;
        serde_json::from_value(value).map_err(|error| {
            AnalysisError::new(
                actual,
                AnalysisErrorKind::Validation,
                format!(
                    "{} payload does not match its typed report: {error}",
                    actual.as_str()
                ),
            )
        })
    }
}

impl DomainState<DomainPayload> {
    fn decode<T: DeserializeOwned>(&self, key: DomainReportKey<T>) -> Result<DomainState<T>> {
        Ok(match self {
            Self::NotRequested => DomainState::NotRequested,
            Self::Complete { value, issues } => DomainState::Complete {
                value: value.decode(key)?,
                issues: issues.clone(),
            },
            Self::Unsupported { reason } => DomainState::Unsupported {
                reason: reason.clone(),
            },
            Self::Failed { error, issues } => DomainState::Failed {
                error: error.clone(),
                issues: issues.clone(),
            },
        })
    }
}

impl SliceSnapshot {
    /// Retrieve a report as its public Rust type while retaining all four domain states.
    ///
    /// The returned value is [`DomainState::Complete`] only when analysis
    /// completed. `NotRequested`, `Unsupported`, failures, and issues remain
    /// explicit, so a caller never mistakes missing evidence for an empty report.
    pub fn report<T: DeserializeOwned>(&self, key: DomainReportKey<T>) -> Result<DomainState<T>> {
        let domain = key.domain();
        self.domains
            .get(&domain)
            .ok_or_else(|| {
                AnalysisError::new(
                    domain,
                    AnalysisErrorKind::Validation,
                    format!(
                        "slice {} is missing domain {}",
                        self.identity.arch,
                        domain.as_str()
                    ),
                )
            })?
            .decode(key)
    }
}

/// Closed keys for every schema-v3 analysis domain.
///
/// Typical callers pass one of these constants to [`SliceSnapshot::report`].
pub mod domain_reports {
    use super::*;

    /// Container facts.
    pub const CONTAINER: DomainReportKey<ContainerSnapshot> =
        DomainReportKey::new(AnalysisDomain::Container);
    /// Mach-O header facts.
    pub const HEADER: DomainReportKey<HeaderSnapshot> =
        DomainReportKey::new(AnalysisDomain::Header);
    /// Load commands.
    pub const LOAD_COMMANDS: DomainReportKey<Vec<LoadCommandSnapshot>> =
        DomainReportKey::new(AnalysisDomain::LoadCommands);
    /// Segments and sections.
    pub const SEGMENTS: DomainReportKey<Vec<SegmentSnapshot>> =
        DomainReportKey::new(AnalysisDomain::Segments);
    /// Per-section relocation counts.
    pub const RELOCATIONS: DomainReportKey<Vec<RelocationSectionSnapshot>> =
        DomainReportKey::new(AnalysisDomain::Relocations);
    /// Symbol table entries.
    pub const SYMBOLS: DomainReportKey<Vec<SymbolSnapshot>> =
        DomainReportKey::new(AnalysisDomain::Symbols);
    /// Exported symbols.
    pub const EXPORTS: DomainReportKey<Vec<ExportSnapshot>> =
        DomainReportKey::new(AnalysisDomain::Exports);
    /// Imported symbols.
    pub const IMPORTS: DomainReportKey<Vec<ImportRecord>> =
        DomainReportKey::new(AnalysisDomain::Imports);
    /// Chained fixups.
    pub const FIXUPS: DomainReportKey<Vec<FixupSnapshot>> =
        DomainReportKey::new(AnalysisDomain::Fixups);
    /// Code-signature facts, or `None` for an unsigned image.
    pub const CODESIGN: DomainReportKey<Option<CodesignSnapshot>> =
        DomainReportKey::new(AnalysisDomain::Codesign);
    /// Canonical Objective-C surface recovery.
    pub const OBJC: DomainReportKey<ObjCReport> = DomainReportKey::new(AnalysisDomain::Objc);
    /// Canonical Swift surface recovery.
    pub const SWIFT: DomainReportKey<SwiftReport> = DomainReportKey::new(AnalysisDomain::Swift);
    /// DWARF function summary.
    pub const DWARF: DomainReportKey<DwarfSnapshot> = DomainReportKey::new(AnalysisDomain::Dwarf);
    /// Recovered C++ vtables.
    pub const VTABLES: DomainReportKey<Vec<VtableEntry>> =
        DomainReportKey::new(AnalysisDomain::Vtables);
    /// Recovered strings.
    pub const STRINGS: DomainReportKey<Vec<FoundString>> =
        DomainReportKey::new(AnalysisDomain::Strings);
    /// Symbol and method ranges.
    pub const RANGES: DomainReportKey<Vec<RangeEntry>> =
        DomainReportKey::new(AnalysisDomain::Ranges);
    /// Cross-references.
    pub const XREFS: DomainReportKey<Vec<Xref>> = DomainReportKey::new(AnalysisDomain::Xrefs);
    /// Dynamic-link dependency summary.
    pub const DEPENDENCIES: DomainReportKey<DependencySnapshot> =
        DomainReportKey::new(AnalysisDomain::Dependencies);
    /// Security audit report.
    pub const AUDIT: DomainReportKey<AuditReport> = DomainReportKey::new(AnalysisDomain::Audit);
    /// Canonical C ABI recovery report.
    pub const C_SURFACE: DomainReportKey<RecoveryReport> =
        DomainReportKey::new(AnalysisDomain::CSurface);
    /// Canonical C++ recovery report.
    pub const CPP_SURFACE: DomainReportKey<RecoveryReport> =
        DomainReportKey::new(AnalysisDomain::CppSurface);
    /// Canonical Objective-C recovery with projected headers.
    pub const OBJC_HEADERS: DomainReportKey<ObjCReport> =
        DomainReportKey::new(AnalysisDomain::ObjcHeaders);
}
