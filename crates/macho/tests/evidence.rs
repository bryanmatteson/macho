#![cfg(feature = "evidence")]

use macho::dyld::resolve::PointerInventory;
use macho::dyld::{ChainedImportLookup, FunctionStartsOutcome};
use macho::evidence::SelectedImageEvidence;

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
    assert_eq!(
        evidence.chained_import("_missing").unwrap(),
        ChainedImportLookup::Absent
    );
    assert_eq!(
        evidence.function_starts(16).unwrap(),
        FunctionStartsOutcome::Absent
    );
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
        let _ = evidence.chained_import("_exit").unwrap();
        let _ = evidence.function_starts(32).unwrap();
    }
    assert!(count > 0);
}
