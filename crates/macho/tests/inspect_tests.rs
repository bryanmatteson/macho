#![cfg(feature = "cli")]

use macho::analysis::{AnalysisDomain, AnalysisPlan, Analyzer, DomainState, SnapshotDocument};

#[test]
fn selective_analysis_replaces_fixed_inspection_facade() {
    let bytes = macho_test_support::thin64_arm64(2);
    let container = macho::parse(&bytes).expect("fixture parses");
    let document = Analyzer
        .run(&container, &AnalysisPlan::new([AnalysisDomain::Header]))
        .expect("analysis runs");

    assert!(matches!(
        document.slices[0].domains[&AnalysisDomain::Header],
        DomainState::Complete { .. }
    ));
    assert!(matches!(
        document.slices[0].domains[&AnalysisDomain::Objc],
        DomainState::NotRequested
    ));
}

#[test]
fn schema_v3_round_trips_and_rejects_unversioned_input() {
    let bytes = macho_test_support::thin64_arm64(2);
    let container = macho::parse(&bytes).expect("fixture parses");
    let document = Analyzer
        .run(&container, &AnalysisPlan::new([AnalysisDomain::Segments]))
        .expect("analysis runs");
    let json = serde_json::to_string(&document).expect("serialize v3");
    SnapshotDocument::from_json(&json).expect("read v3");
    assert!(SnapshotDocument::from_json("{}").is_err());
}
