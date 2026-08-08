use super::*;

pub(super) fn collector(
    collector: &str,
    status: SwiftCollectorStatusV1,
    attempted: u64,
) -> SwiftCollectorOutcomeV1 {
    SwiftCollectorOutcomeV1 {
        collector: collector.into(),
        status,
        attempted,
    }
}

pub(super) fn validated(batch: SwiftDecodeBatchV1) -> SwiftDecodeBatchV1 {
    debug_assert!(batch.validate().is_ok());
    batch
}

pub(super) fn rejected(
    attempted: u64,
    code: &str,
    section: Option<String>,
    safe_detail: impl Into<String>,
) -> SwiftDecodeBatchV1 {
    validated(SwiftDecodeBatchV1 {
        outcome: SwiftDecodeOutcomeV1::Rejected,
        records: Vec::new(),
        conformances: Vec::new(),
        associated_types: Vec::new(),
        protocol_requirements: Vec::new(),
        protocol_signature_requirements: Vec::new(),
        class_trailing_layouts: Vec::new(),
        class_vtable_entries: Vec::new(),
        class_overrides: Vec::new(),
        gaps: vec![SwiftDecodeGapV1 {
            code: code.into(),
            section,
            record_index: None,
            safe_detail: safe_detail.into(),
        }],
        collector_outcomes: vec![SwiftCollectorOutcomeV1 {
            collector: "nominal_descriptors".into(),
            status: SwiftCollectorStatusV1::Rejected,
            attempted,
        }],
        conservation: SwiftObservationConservationV1 {
            attempted,
            included: 0,
            unknown: attempted,
            excluded: 0,
        },
    })
}
