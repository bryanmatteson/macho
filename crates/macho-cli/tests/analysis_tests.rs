use macho::analysis::{
    AnalysisDomain, AnalysisPlan, Analyzer, DomainPayload, DomainState, SnapshotDocument,
};

#[test]
fn selective_snapshot_is_schema_v2_and_owned() {
    let bytes = macho_test_support::thin64_arm64(2);
    let container = macho::parse(&bytes).expect("parse fixture");
    let document = Analyzer
        .run(&container, &AnalysisPlan::new([AnalysisDomain::Header]))
        .expect("run header plan");
    drop(container);
    drop(bytes);

    assert_eq!(document.schema_version, 2);
    assert!(matches!(
        document.slices[0].domains[&AnalysisDomain::Header],
        DomainState::Complete {
            value: DomainPayload::Header(_),
            ..
        }
    ));
    assert!(matches!(
        document.slices[0].domains[&AnalysisDomain::Symbols],
        DomainState::NotRequested
    ));

    let encoded = serde_json::to_string(&document).expect("serialize snapshot");
    let decoded = SnapshotDocument::from_json(&encoded).expect("read schema v2");
    assert_eq!(decoded, document);
}

#[test]
fn snapshot_reader_rejects_unversioned_and_future_documents() {
    assert!(SnapshotDocument::from_json(r#"{"container":{},"slices":[]}"#).is_err());
    assert!(
        SnapshotDocument::from_json(
            r#"{"schema_version":3,"container":{"format":"thin","slice_count":0},"slices":[]}"#
        )
        .is_err()
    );
}
