#![cfg(feature = "evidence")]

use macho::dyld::resolve::PointerInventory;
use macho::dyld::{ChainedImportLookup, FunctionStartsOutcome};
use macho::evidence::SelectedImageEvidence;
use macho::symbol_metadata::IndirectBindingsOutcome;

fn empty_macho() -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0xfeed_facf_u32.to_le_bytes());
    bytes.extend_from_slice(&0x0100_0007_u32.to_le_bytes());
    bytes.extend_from_slice(&3_u32.to_le_bytes());
    bytes.extend_from_slice(&2_u32.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes
}

#[test]
fn selected_image_session_exposes_leaf_states_without_a_graph_layer() {
    let bytes = empty_macho();
    let image = macho::format::parse_macho_file(&bytes).unwrap();
    let evidence = SelectedImageEvidence::new(&image).unwrap();
    assert!(matches!(
        evidence.pointer_inventory(16).unwrap(),
        PointerInventory::Absent
    ));
    assert!(matches!(
        evidence.legacy_bindings(16).unwrap(),
        PointerInventory::Absent
    ));
    assert!(matches!(
        evidence.legacy_rebases(16).unwrap(),
        PointerInventory::Absent
    ));
    assert_eq!(
        evidence.chained_import("_missing").unwrap(),
        ChainedImportLookup::Absent
    );
    assert_eq!(
        evidence.function_starts(16).unwrap(),
        FunctionStartsOutcome::Absent
    );
    assert_eq!(
        evidence.indirect_bindings(16).unwrap(),
        IndirectBindingsOutcome::Absent
    );
}

#[test]
fn program_recovery_routes_strict_leaves_through_selected_image_evidence() {
    let program = include_str!("../src/analysis/program.rs");
    for forbidden in [
        "decode_strict_objc(",
        "decode_swift_strict(",
        "decode_strict_rtti(",
        "decode_strict_vtables(",
        "PointerResolver::new(",
        "decode_function_starts(",
        "decode_indirect_bindings(",
    ] {
        assert!(
            !program.contains(forbidden),
            "whole-program recovery bypasses SelectedImageEvidence via {forbidden}"
        );
    }
    assert!(program.contains("SelectedImageEvidence::new("));
    assert!(program.contains("recover_with_evidence("));
    assert!(program.contains(".function_starts("));
    let xrefs = include_str!("../src/analysis/xref/refs.rs");
    assert!(xrefs.contains("collect_legacy_bind_refs_with_evidence("));
    assert!(xrefs.contains(".legacy_bindings("));
    assert!(xrefs.contains("collect_legacy_rebase_refs_with_evidence("));
    assert!(xrefs.contains(".legacy_rebases("));
}

#[cfg(target_os = "macos")]
#[test]
fn system_true_is_consumable_through_leaf_evidence_only() {
    let bytes = std::fs::read("/usr/bin/true").unwrap();
    let container = macho::parse(&bytes).unwrap();
    let mut count = 0;
    for image in container.macho_files() {
        count += 1;
        let evidence = SelectedImageEvidence::new(image).unwrap();
        let _ = evidence.pointer_inventory(32).unwrap();
        let _ = evidence.legacy_bindings(32).unwrap();
        let _ = evidence.legacy_rebases(32).unwrap();
        let _ = evidence.chained_import("_exit").unwrap();
        let _ = evidence.function_starts(32).unwrap();
        let _ = evidence.indirect_bindings(32).unwrap();
    }
    assert!(count > 0);
}

#[cfg(all(target_os = "macos", feature = "analysis"))]
#[test]
fn system_pointer_recovery_public_entry_matches_the_leaf_session() {
    use macho::analysis::pointer_index::{PointerIndex, PointerRecoveryLimits};

    let bytes = std::fs::read("/bin/ls").unwrap();
    let container = macho::parse(&bytes).unwrap();
    let mut count = 0;
    let mut saw_chained = false;
    for image in container.macho_files() {
        count += 1;
        let evidence = SelectedImageEvidence::new(image).unwrap();
        let full = PointerIndex::recover(image, PointerRecoveryLimits::default()).unwrap();
        saw_chained |= full.pointers().iter().any(|pointer| {
            matches!(
                pointer.kind,
                macho::analysis::pointer_index::PointerRecordKind::ChainedBind
                    | macho::analysis::pointer_index::PointerRecordKind::ChainedRebase
            )
        });
        let stub_count = full
            .pointers()
            .iter()
            .filter(|pointer| {
                pointer.kind == macho::analysis::pointer_index::PointerRecordKind::Stub
            })
            .count();
        for max_records in [1, stub_count.saturating_add(1).max(1)] {
            let limits = PointerRecoveryLimits { max_records };
            let facade = PointerIndex::recover(image, limits).unwrap();
            let shared = PointerIndex::recover_with_evidence(&evidence, limits).unwrap();
            if shared != facade {
                let first_pointer_difference = shared
                    .pointers()
                    .iter()
                    .zip(facade.pointers())
                    .position(|(shared, facade)| shared != facade);
                panic!(
                    "pointer recovery differs at max_records={max_records}: \
                     shared_len={}, facade_len={}, first_pointer_difference={first_pointer_difference:?}, \
                     shared_pointer={:?}, facade_pointer={:?}, shared_completeness={:?}, \
                     facade_completeness={:?}",
                    shared.pointers().len(),
                    facade.pointers().len(),
                    first_pointer_difference.and_then(|index| shared.pointers().get(index)),
                    first_pointer_difference.and_then(|index| facade.pointers().get(index)),
                    shared.completeness(),
                    facade.completeness(),
                );
            }
        }
        let shared =
            PointerIndex::recover_with_evidence(&evidence, PointerRecoveryLimits::default())
                .unwrap();
        assert_eq!(shared, full);
    }
    assert!(count > 0);
    assert!(
        saw_chained,
        "system parity fixture must exercise chained pointers"
    );
}
