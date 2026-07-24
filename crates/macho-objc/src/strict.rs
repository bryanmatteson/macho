//! Strict Objective-C runtime metadata collection.
//!
//! The ordinary scan API deliberately retains per-record failures. This
//! module converts that lossless scan into an all-or-error result and combines
//! it with the strict method-record fold so callers cannot accidentally treat
//! a partial scan as complete metadata.

use crate::model::macho_file::MachoFile;
use crate::{
    Error, ObjCMetadata, ObjCMethodRecord, ObjCRecordObservation, Result, fold_method_records,
    scan_objc_metadata,
};

/// Complete Objective-C metadata and its conserved source records.
#[derive(Debug)]
pub struct StrictObjCMetadata {
    /// Successfully decoded class, category, and protocol metadata.
    pub metadata: ObjCMetadata,
    /// Every admitted runtime-list observation.
    pub observations: Vec<ObjCRecordObservation>,
    /// Every strict method record with exact encoding and storage provenance.
    pub method_records: Vec<ObjCMethodRecord>,
    /// Runtime-list records plus method records considered.
    pub attempted: u64,
    /// Records retained in the result.
    pub included: u64,
    /// Strict collection never silently classifies an observation as unknown.
    pub unknown: u64,
    /// Strict collection never silently excludes an observation.
    pub excluded: u64,
}

/// Collect strict Objective-C metadata from one selected thin image.
///
/// Any runtime-list observation that did not resolve and decode rejects the
/// entire operation. The method limit is checked during folding so hostile
/// inputs cannot grow the retained result without a bound.
pub fn scan_strict_objc_metadata(
    macho: &MachoFile<'_>,
    method_limit: usize,
) -> Result<StrictObjCMetadata> {
    if method_limit == 0 {
        return Err(Error::unsupported(
            "strict Objective-C method limit must be nonzero",
        ));
    }
    let scan = scan_objc_metadata(macho)?;
    if let Some(observation) = scan.observations.iter().find(|observation| {
        observation.runtime_address.is_none()
            || observation.parsed_name.is_none()
            || observation.error.is_some()
    }) {
        return Err(Error::format(format!(
            "strict Objective-C {:?} observation {} is incomplete: {}",
            observation.kind,
            observation.ordinal,
            observation
                .error
                .as_deref()
                .unwrap_or("missing decoded identity")
        )));
    }
    let method_records = fold_method_records(macho, Vec::new(), |records, record| {
        if records.len() == method_limit {
            return Err(Error::unsupported(
                "strict Objective-C method limit exceeded",
            ));
        }
        records.push(record);
        Ok(())
    })?;
    let attempted = scan
        .observations
        .len()
        .checked_add(method_records.len())
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(|| Error::format("strict Objective-C record count exceeds u64"))?;
    Ok(StrictObjCMetadata {
        metadata: scan.metadata,
        observations: scan.observations,
        method_records,
        attempted,
        included: attempted,
        unknown: 0,
        excluded: 0,
    })
}
