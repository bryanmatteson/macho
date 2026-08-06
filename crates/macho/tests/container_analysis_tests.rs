#![cfg(feature = "cli")]

use macho::analysis::container::ContainerDocumentReport;
use macho::analysis::container::ext::MachoContainerExt;
use macho::analysis::{AnalysisDomain, Analyzer, ContainerPlan};

#[test]
fn container_plan_reports_selected_header_parity() {
    let bytes = macho_test_support::fat32(&[
        (
            macho_test_support::CPU_TYPE_ARM64,
            0,
            macho_test_support::thin64_arm64(2),
        ),
        (
            macho_test_support::CPU_TYPE_X86_64,
            0,
            macho_test_support::thin64_x86_64(2),
        ),
    ]);
    let container = macho::parse(&bytes).expect("parse fat fixture");
    let document = Analyzer
        .run(
            &container,
            &ContainerPlan::new([AnalysisDomain::Header]).compile(),
        )
        .expect("analyze container");
    let report =
        ContainerDocumentReport::from_document(&document, &[AnalysisDomain::Header], false);
    assert_eq!(report.arches.len(), 2);
    assert_eq!(report.parity.domains, vec![AnalysisDomain::Header]);
    assert_eq!(report.parity.divergences.len(), 1);
}

#[test]
fn fileset_plan_lists_and_structurally_inspects_two_entries() {
    let bytes = macho_test_support::fileset64_arm64();
    let container = macho::parse(&bytes).expect("parse fileset");
    let document = Analyzer
        .run(
            &container,
            &ContainerPlan::new([AnalysisDomain::LoadCommands]).compile(),
        )
        .expect("analyze fileset");
    let report =
        ContainerDocumentReport::from_document(&document, &[AnalysisDomain::LoadCommands], false);
    assert_eq!(report.fileset.expect("fileset report").entries.len(), 2);

    let inspections = container.inspect_fileset_entry("com.example.second");
    assert_eq!(inspections.len(), 1);
    assert!(inspections[0].member.is_some());
    assert!(inspections[0].parse_error.is_none());
}
