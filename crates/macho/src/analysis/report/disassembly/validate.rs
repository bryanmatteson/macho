use std::collections::BTreeSet;

use super::*;
use crate::analysis::report::ContainerKind;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid disassembly report: {0}")]
pub struct DisassemblyReportValidationError(pub String);

fn invalid(message: impl Into<String>) -> DisassemblyReportValidationError {
    DisassemblyReportValidationError(message.into())
}

pub(super) fn validate(report: &DisassemblyReport) -> Result<(), DisassemblyReportValidationError> {
    if report.schema_version != DisassemblySchemaVersion::CURRENT {
        return Err(invalid("schema_version must be 2"));
    }
    if report.container.slice_count as usize != report.slices.len() {
        return Err(invalid("container slice_count does not match slices"));
    }
    if report.request.max_decoded_bytes_per_slice == 0
        || report.request.max_symbol_ranges_per_slice == 0
    {
        return Err(invalid("request limits must be non-zero"));
    }
    validate_selection(&report.request.selection)?;
    if let ReportSelection::Symbols { names } = &report.request.selection
        && names.len() as u64 > report.request.max_symbol_ranges_per_slice
    {
        return Err(invalid(
            "requested symbol count exceeds the symbol-range limit",
        ));
    }
    let emitted_architectures = report
        .slices
        .iter()
        .map(|slice| slice.identity.image.architecture)
        .collect::<Vec<_>>();
    if !report
        .request
        .architectures
        .matches_resolved(&emitted_architectures)
    {
        return Err(invalid(
            "request architecture selection does not match emitted slices",
        ));
    }

    let mut identities = BTreeSet::new();
    for slice in &report.slices {
        let image = &slice.identity.image;
        if image.container != report.container.container {
            return Err(invalid("slice and container kinds differ"));
        }
        if image.byte_len != slice.slice_size {
            return Err(invalid("image byte_len differs from slice_size"));
        }
        if !identities.insert((
            image.slice_index,
            image.architecture.cpu_type,
            image.architecture.cpu_subtype,
        )) {
            return Err(invalid("slice identities are not unique"));
        }
        if report.container.container == ContainerKind::Thin {
            if report.slices.len() != 1 || image.slice_index != 0 || slice.container_offset != 0 {
                return Err(invalid("thin input must have one zero-offset slice"));
            }
            if image.content_sha256 != report.container.content_sha256
                || image.byte_len != report.container.byte_len
            {
                return Err(invalid("thin container and image identities differ"));
            }
        }
        let slice_end = slice
            .container_offset
            .checked_add(slice.slice_size)
            .ok_or_else(|| invalid("slice container range overflows"))?;
        if slice_end > report.container.byte_len {
            return Err(invalid("slice exceeds container byte_len"));
        }
        if slice.decoded_bytes > report.request.max_decoded_bytes_per_slice {
            return Err(invalid("slice exceeds the decoded-byte request limit"));
        }
        validate_slice(slice, &report.request)?;
    }
    Ok(())
}

fn validate_selection(selection: &ReportSelection) -> Result<(), DisassemblyReportValidationError> {
    match selection {
        ReportSelection::Sections { selectors } => {
            if selectors.is_empty() {
                return Err(invalid("section selectors must not be empty"));
            }
            if selectors.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err(invalid("section selectors must be sorted and unique"));
            }
            Ok(())
        }
        ReportSelection::Symbols { names } => {
            if names.is_empty() {
                return Err(invalid("symbol names must not be empty"));
            }
            if names.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err(invalid("symbol names must be sorted and unique"));
            }
            Ok(())
        }
        ReportSelection::Address { extent, .. } => match extent {
            ReportAddressExtent::InstructionCount { value }
            | ReportAddressExtent::ByteLength { value }
                if *value == 0 =>
            {
                Err(invalid("address extent must be non-zero"))
            }
            _ => Ok(()),
        },
        _ => Ok(()),
    }
}

fn validate_slice(
    slice: &DisassemblySlice,
    request: &DisassemblyReportRequest,
) -> Result<(), DisassemblyReportValidationError> {
    match &request.selection {
        ReportSelection::Sections { selectors } if slice.regions.len() != selectors.len() => {
            return Err(invalid("explicit section request and region counts differ"));
        }
        ReportSelection::Address { .. } if slice.regions.len() != 1 => {
            return Err(invalid("address request must have exactly one region"));
        }
        ReportSelection::Symbols { names }
            if slice.regions.is_empty() || slice.regions.len() > names.len() =>
        {
            return Err(invalid("symbol request and region counts differ"));
        }
        _ => {}
    }
    let issues_sorted = slice.issues.windows(2).all(|pair| pair[0] < pair[1]);
    if !issues_sorted && slice.issues.len() > 1 {
        return Err(invalid("issues must be sorted and unique"));
    }
    let mut decoded = 0u64;
    let mut has_gap = false;
    let mut has_opaque_instruction = false;
    let mut previous_end = None;
    let mut has_unexamined = false;
    for region in &slice.regions {
        if previous_end.is_some_and(|end| region.start_va < end) {
            return Err(invalid("slice regions are not ordered and non-overlapping"));
        }
        validate_region(slice, region, &request.selection)?;
        previous_end = region.requested_end_va.or(Some(region.examined_end_va));
        has_unexamined |= region.next_unexamined_va.is_some();
        for record in &region.records {
            decoded = decoded
                .checked_add(record.byte_len())
                .ok_or_else(|| invalid("decoded byte count overflows"))?;
            has_gap |= matches!(record, DisassemblyRecord::Gap { .. });
            has_opaque_instruction |= matches!(
                record,
                DisassemblyRecord::Instruction {
                    encoding: Some(_),
                    ..
                }
            );
        }
    }
    if decoded != slice.decoded_bytes {
        return Err(invalid("slice decoded_bytes differs from record sum"));
    }
    let retained_labels = slice.regions.iter().try_fold(0u64, |total, region| {
        total
            .checked_add(region.labels.len() as u64)
            .ok_or_else(|| invalid("retained label count overflows"))
    })?;
    if retained_labels > request.max_symbol_ranges_per_slice {
        return Err(invalid("slice exceeds the symbol-range request limit"));
    }
    if request.mode == ReportDecodeMode::Strict && has_gap {
        return Err(invalid("strict reports cannot contain decode gaps"));
    }
    if slice.decoded_bytes_truncated != has_unexamined {
        return Err(invalid(
            "decoded-byte truncation flag differs from region boundaries",
        ));
    }
    let partial = has_gap
        || has_opaque_instruction
        || !slice.issues.is_empty()
        || slice.decoded_bytes_truncated
        || slice.symbol_ranges_truncated;
    if (slice.status == DisassemblyStatus::Partial) != partial {
        return Err(invalid("slice status does not match evidence loss"));
    }
    Ok(())
}

fn validate_region(
    slice: &DisassemblySlice,
    region: &DisassemblyRegion,
    request: &ReportSelection,
) -> Result<(), DisassemblyReportValidationError> {
    match request {
        ReportSelection::ExecutableSections
            if region.selection_source != SelectionSource::ExecutableSection =>
        {
            return Err(invalid("region selection source differs from request"));
        }
        ReportSelection::Sections { selectors } => {
            if region.selection_source != SelectionSource::ExplicitSection
                || !selectors.iter().any(|selector| {
                    selector.segment == region.segment && selector.section == region.section
                })
            {
                return Err(invalid("explicit section region differs from request"));
            }
        }
        ReportSelection::Symbols { .. } if region.selection_source != SelectionSource::Symbol => {
            return Err(invalid("symbol region differs from request"));
        }
        ReportSelection::Address { start_va, extent } => {
            if region.selection_source != SelectionSource::Address || region.start_va != *start_va {
                return Err(invalid("address region differs from request"));
            }
            match extent {
                ReportAddressExtent::InstructionCount { value }
                    if region.requested_instruction_count != Some(*value)
                        || region.requested_end_va.is_some() =>
                {
                    return Err(invalid("instruction-count extent differs from request"));
                }
                ReportAddressExtent::ByteLength { value } => {
                    let requested_end = start_va
                        .checked_add(*value)
                        .ok_or_else(|| invalid("address request extent overflows"))?;
                    if region.requested_end_va != Some(requested_end)
                        || region.requested_instruction_count.is_some()
                    {
                        return Err(invalid("byte-length extent differs from request"));
                    }
                }
                _ => {}
            }
        }
        _ => {}
    }
    let is_symbol = region.selection_source == SelectionSource::Symbol;
    if is_symbol != (region.range_source.is_some() && region.end_source.is_some()) {
        return Err(invalid("symbol range sources are inconsistent"));
    }
    if region.range_source == Some(SymbolSource::ObjcMetadata) {
        return Err(invalid(
            "Objective-C metadata cannot be a symbol selection source",
        ));
    }
    if (region.requested_end_va.is_some() as u8
        + region.requested_instruction_count.is_some() as u8)
        != 1
    {
        return Err(invalid("region must carry exactly one request extent"));
    }
    if region.examined_end_va < region.start_va {
        return Err(invalid("region examined end precedes start"));
    }
    if region
        .requested_end_va
        .is_some_and(|end| end <= region.start_va)
        || region.requested_instruction_count == Some(0)
    {
        return Err(invalid("region request extent must be non-zero"));
    }
    if region.labels.windows(2).any(|pair| {
        (
            pair[0].va,
            pair[0].source,
            &pair[0].raw_name,
            &pair[0].display_name,
        ) >= (
            pair[1].va,
            pair[1].source,
            &pair[1].raw_name,
            &pair[1].display_name,
        )
    }) {
        return Err(invalid("region labels must be sorted and unique"));
    }
    if region
        .labels
        .iter()
        .any(|label| label.va < region.start_va || label.va >= region.examined_end_va)
    {
        return Err(invalid("region label lies outside the examined range"));
    }
    let mut expected_va = region.start_va;
    let mut expected_offset = None;
    let mut instructions = 0u64;
    for record in &region.records {
        if let DisassemblyRecord::Gap { code, .. } = record
            && !matches!(
                code.as_str(),
                "insn.decode.invalid"
                    | "insn.decode.invalid_encoding"
                    | "insn.decode.unknown_encoding"
                    | "insn.decode.truncated"
                    | "insn.decode.too_long"
                    | "analysis.disassembly.selection.partial_instruction"
            )
        {
            return Err(invalid("gap code is not defined by schema version 2"));
        }
        if record.va() != expected_va {
            return Err(invalid("region records are not contiguous"));
        }
        if let Some(offset) = expected_offset {
            if record.thin_file_offset() != offset {
                return Err(invalid("record file offsets are not contiguous"));
            }
        }
        let expected_container = slice
            .container_offset
            .checked_add(record.thin_file_offset())
            .ok_or_else(|| invalid("container file offset overflows"))?;
        if record.container_file_offset() != expected_container {
            return Err(invalid("container file offset translation is invalid"));
        }
        let len = record.byte_len();
        if len == 0 {
            return Err(invalid("record byte length must be non-zero"));
        }
        if record
            .thin_file_offset()
            .checked_add(len)
            .is_none_or(|end| end > slice.slice_size)
        {
            return Err(invalid("record exceeds the slice byte length"));
        }
        if let DisassemblyRecord::Instruction {
            size,
            bytes,
            kind,
            direct_target,
            encoding,
            ..
        } = record
        {
            instructions += 1;
            if bytes.as_str().len() as u64 != size.saturating_mul(2) {
                return Err(invalid("instruction size differs from byte string"));
            }
            if let Some(target) = direct_target {
                if !matches!(
                    kind,
                    InstructionKind::Branch
                        | InstructionKind::Call
                        | InstructionKind::ConditionalBranch
                ) {
                    return Err(invalid(
                        "only direct control-flow instructions may carry a target",
                    ));
                }
                let option_count = [
                    target.raw_symbol.is_some(),
                    target.display_symbol.is_some(),
                    target.source.is_some(),
                    target.offset.is_some(),
                ]
                .into_iter()
                .filter(|present| *present)
                .count();
                if option_count != 0 && option_count != 4 {
                    return Err(invalid("direct target symbol fields are not all-or-none"));
                }
            }
            if let Some(encoding) = encoding {
                if *kind != InstructionKind::Other || direct_target.is_some() {
                    return Err(invalid(
                        "opaque instruction encoding must not carry authoritative semantics",
                    ));
                }
                if encoding.source.is_empty() {
                    return Err(invalid("opaque instruction encoding source is empty"));
                }
            }
        }
        expected_va = expected_va
            .checked_add(len)
            .ok_or_else(|| invalid("record VA overflows"))?;
        expected_offset = Some(
            record
                .thin_file_offset()
                .checked_add(len)
                .ok_or_else(|| invalid("record offset overflows"))?,
        );
    }
    if expected_va != region.examined_end_va || instructions != region.emitted_instruction_count {
        return Err(invalid("region summary differs from records"));
    }
    if let Some(next) = region.next_unexamined_va {
        if next != region.examined_end_va || !slice.decoded_bytes_truncated {
            return Err(invalid("next_unexamined_va is inconsistent"));
        }
        if region.requested_end_va.is_some_and(|end| next >= end) {
            return Err(invalid(
                "truncated byte range must retain an unexamined suffix",
            ));
        }
        if region
            .requested_instruction_count
            .is_some_and(|count| instructions >= count)
        {
            return Err(invalid(
                "truncated instruction-count range must remain unsatisfied",
            ));
        }
    } else if let Some(end) = region.requested_end_va {
        if end != region.examined_end_va {
            return Err(invalid("complete byte range was not fully examined"));
        }
    } else if let Some(count) = region.requested_instruction_count {
        if instructions != count {
            return Err(invalid("instruction-count range was not satisfied"));
        }
    }
    Ok(())
}
