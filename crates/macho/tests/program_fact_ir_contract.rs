#![cfg(feature = "analysis")]

use macho::analysis::{
    ControlFlowEdgeKind, PROGRAM_FACT_IR_SCHEMA_VERSION, ProgramFactDocument, ProgramImageIdentity,
    ProgramRecoveryLimits, ProgramRecoveryRequest, ProgramRecoveryStage, ProgramStageStatus,
    ProgramSubjectKey, RecoveredProgram, RecoveryDeltaError, RecoveryGuide, RecoveryReferenceKind,
    RecoveryReferenceTargetKey,
};

#[test]
fn public_program_facade_round_trips_the_durable_fact_contract() {
    let bytes = macho_test_support::disassembly_x86_64();
    let container = macho::parse(&bytes).unwrap();
    let image = container.first_macho().expect("fixture image");
    let request = ProgramRecoveryRequest::new(
        [ProgramRecoveryStage::ImageLayout],
        ProgramRecoveryLimits::default(),
    );
    let recovered = RecoveredProgram::recover(image, request).unwrap();
    let encoded = recovered
        .to_fact_document()
        .to_json_pretty()
        .expect("current Fact IR encodes");
    let document = ProgramFactDocument::load_json(&encoded).expect("current Fact IR loads");

    assert_eq!(document.schema_version, PROGRAM_FACT_IR_SCHEMA_VERSION);
    let loaded = RecoveredProgram::from_document(document).expect("validated program loads");
    let identity: ProgramImageIdentity = loaded.image().clone();
    let empty_guide = RecoveryGuide::builder(identity.clone()).build();
    assert!(empty_guide.decisions.is_empty());
    let precise_guide = RecoveryGuide::builder(identity)
        .suppress_control_flow_edge(0x1000, 0x1000, 0x1010, ControlFlowEdgeKind::Branch)
        .suppress_direct_call(0x1000, 0x1008, 0x2000)
        .assign_reference_owner(
            0x1008,
            RecoveryReferenceTargetKey::Internal { address: 0x2000 },
            RecoveryReferenceKind::Data,
            0x1000,
        )
        .build();
    assert_eq!(precise_guide.decisions.len(), 3);
    assert_eq!(loaded, recovered);
    assert_eq!(
        loaded.stage_status(ProgramRecoveryStage::ImageLayout),
        ProgramStageStatus::Complete
    );
    assert_eq!(
        loaded.stage_status(ProgramRecoveryStage::Strings),
        ProgramStageStatus::Absent
    );

    let facts = loaded.facts();
    assert!(facts.image_layout.is_some());
    assert!(facts.functions.is_none());
    assert!(facts.disassembly_inputs().is_none());
    assert!(loaded.functions().is_none());
    assert!(loaded.control_flow().is_none());
    assert!(loaded.xrefs().is_none());
    assert!(loaded.pointers().is_none());
    assert!(loaded.function_by_entry(0x1000).is_none());
    assert_eq!(
        loaded.subject_authority(&ProgramSubjectKey::Function { entry: 0x1000 }),
        None
    );
    let _ = loaded.annotations_at(0x1000);
    let _ = loaded.completeness();
    let _ = loaded.coverage();
    let _ = loaded.questions();
    let _ = loaded.frontier_subjects();
}

#[test]
fn public_program_facade_refines_and_deepens_immutable_states() {
    let bytes = macho_test_support::disassembly_x86_64();
    let container = macho::parse(&bytes).unwrap();
    let image = container.first_macho().expect("fixture image");
    let request = ProgramRecoveryRequest::new(
        [ProgramRecoveryStage::ImageLayout],
        ProgramRecoveryLimits::default(),
    );
    let base = RecoveredProgram::recover(image, request).unwrap();
    let guide = RecoveryGuide::builder(base.image().clone()).build();

    let refined = RecoveredProgram::refine(image, &base, &guide).expect("empty guide refines");
    assert!(refined.guide_application().is_some());
    assert!(
        refined
            .delta_from(&base)
            .expect("same request delta")
            .records
            .is_empty()
    );
    assert!(base.guide_application().is_none());

    let deepened = base
        .deepen(image, [ProgramRecoveryStage::Strings], None)
        .expect("additional stage deepens");
    assert_ne!(
        deepened.stage_status(ProgramRecoveryStage::Strings),
        ProgramStageStatus::Absent
    );
    assert!(matches!(
        deepened.delta_from(&base),
        Err(RecoveryDeltaError::RequestMismatch)
    ));
    assert_eq!(
        base.stage_status(ProgramRecoveryStage::Strings),
        ProgramStageStatus::Absent
    );
}
