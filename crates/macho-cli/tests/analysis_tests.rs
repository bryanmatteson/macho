use macho::analysis::{
    AnalysisDomain, AnalysisPlan, Analyzer, DomainPayload, DomainState, SnapshotDocument,
};

#[test]
fn selective_snapshot_is_schema_v3_and_owned() {
    let bytes = macho_test_support::thin64_arm64(2);
    let container = macho::parse(&bytes).expect("parse fixture");
    let document = Analyzer
        .run(&container, &AnalysisPlan::new([AnalysisDomain::Header]))
        .expect("run header plan");
    drop(container);
    drop(bytes);

    assert_eq!(document.schema_version, 3);
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
    let decoded = SnapshotDocument::from_json(&encoded).expect("read schema v3");
    assert_eq!(decoded, document);
}

#[test]
fn snapshot_reader_rejects_unversioned_old_future_and_unknown_documents() {
    assert!(SnapshotDocument::from_json(r#"{"container":{},"slices":[]}"#).is_err());
    let bytes = macho_test_support::thin64_arm64(2);
    let container = macho::parse(&bytes).expect("parse fixture");
    let document = Analyzer
        .run(&container, &AnalysisPlan::new([AnalysisDomain::Header]))
        .expect("run header plan");
    let mut value = serde_json::to_value(document).expect("snapshot JSON");
    for unsupported in [1, 2, 4] {
        value["schema_version"] = serde_json::json!(unsupported);
        let error = SnapshotDocument::from_json(&value.to_string()).expect_err("reject version");
        assert!(
            error
                .to_string()
                .contains("unsupported snapshot schema version")
        );
    }
    value["schema_version"] = serde_json::json!(3);
    value["unknown"] = serde_json::json!(true);
    assert!(SnapshotDocument::from_json(&value.to_string()).is_err());
}
