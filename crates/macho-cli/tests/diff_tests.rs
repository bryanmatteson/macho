use std::collections::BTreeSet;

use macho::analysis::diff::{ChangeSeverity, DiffDomain, diff_documents};
use macho::analysis::{AnalysisDomain, AnalysisPlan, Analyzer};

#[test]
fn v2_diff_preserves_detailed_header_comparison() {
    let old_bytes = macho_test_support::thin64_arm64(2);
    let new_bytes = macho_test_support::thin64_arm64(6);
    let old_container = macho::parse(&old_bytes).expect("parse old");
    let new_container = macho::parse(&new_bytes).expect("parse new");
    let plan = AnalysisPlan::new([AnalysisDomain::Header]);
    let old = Analyzer.run(&old_container, &plan).expect("analyze old");
    let new = Analyzer.run(&new_container, &plan).expect("analyze new");
    let selected = BTreeSet::from([AnalysisDomain::Header]);

    let report = diff_documents(&old, &new, &selected);
    assert!(report.findings.iter().any(|finding| {
        finding.domain == DiffDomain::Header
            && finding.severity == ChangeSeverity::Breaking
            && finding.message.contains("file type changed")
    }));
}

#[test]
fn unselected_domains_cannot_create_findings() {
    let bytes = macho_test_support::thin64_arm64(2);
    let container = macho::parse(&bytes).expect("parse");
    let document = Analyzer
        .run(&container, &AnalysisPlan::new([AnalysisDomain::Header]))
        .expect("analyze");
    let report = diff_documents(&document, &document, &BTreeSet::new());
    assert!(report.findings.is_empty());
}
