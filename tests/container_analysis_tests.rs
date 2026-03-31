use macho::analysis::snapshot::ContainerSnapshot;
use macho::container_analysis::ContainerReport;
use macho::container_analysis::parity::compute_parity;
use macho::container_analysis::resolve::resolve_cross_image;

fn snapshot_for(path: &str) -> ContainerSnapshot {
    let data = std::fs::read(path).expect("read binary");
    let container = macho::parse(&data).expect("parse");
    ContainerSnapshot::from_container(&container)
}

#[test]
fn parity_report_for_fat_binary() {
    let snap = snapshot_for("/usr/bin/true");
    assert!(snap.slices.len() >= 2, "need a fat binary for parity test");

    let parity = compute_parity(&snap.slices);
    assert_eq!(parity.arches.len(), snap.slices.len());
    // /usr/bin/true should be fairly consistent across arches
    // but may have some arch-specific imports
}

#[test]
fn parity_divergence_has_all_arches() {
    let snap = snapshot_for("/usr/bin/plutil");
    let parity = compute_parity(&snap.slices);

    for div in &parity.divergences {
        // Every divergence should report on all arches
        assert_eq!(
            div.per_arch.len(),
            snap.slices.len(),
            "divergence '{}' should cover all arches",
            div.description
        );
    }
}

#[test]
fn container_report_from_snapshot() {
    let snap = snapshot_for("/usr/bin/true");
    let report = ContainerReport::from_snapshot(&snap);

    assert_eq!(report.format, "Fat");
    assert!(report.arches.len() >= 2);
    assert!(report.parity.is_some());
}

#[test]
fn container_report_thin_has_no_parity() {
    // Build a thin snapshot by taking just one slice
    let mut snap = snapshot_for("/usr/bin/true");
    snap.slices.truncate(1);
    snap.format = macho::analysis::snapshot::ContainerFormat::Thin;

    let report = ContainerReport::from_snapshot(&snap);
    assert_eq!(report.format, "Thin");
    assert!(
        report.parity.is_none(),
        "thin binary should not have parity report"
    );
}

#[test]
fn cross_image_resolution() {
    // plutil has arch-specific imports (e.g., different bzero variants per arch)
    let snap = snapshot_for("/usr/bin/plutil");
    let resolution = resolve_cross_image(&snap);

    // plutil has imports divergent across arches (x86_64 vs arm64e have
    // different intrinsic imports like ___bzero vs _bzero)
    assert!(
        !resolution.import_divergence.is_empty(),
        "fat binary with arch-specific imports should have import divergences"
    );

    for div in &resolution.import_divergence {
        assert!(!div.symbol.is_empty());
        assert!(!div.present_in.is_empty());
        assert!(!div.absent_from.is_empty());
    }
}

#[test]
fn cross_image_resolution_arch_specific_exports() {
    // plutil has some arch-specific symbols
    let snap = snapshot_for("/usr/bin/plutil");
    let resolution = resolve_cross_image(&snap);

    for eo in &resolution.export_ownership {
        assert!(!eo.symbol.is_empty(), "export symbol should not be empty");
        assert!(
            !eo.arches.is_empty(),
            "export should be present in at least one arch"
        );
        assert!(
            eo.arches.len() < snap.slices.len(),
            "arch-specific export should not be in all arches"
        );
    }
}

#[test]
fn container_report_serializes() {
    let snap = snapshot_for("/usr/bin/true");
    let report = ContainerReport::from_snapshot(&snap);
    let json = serde_json::to_string(&report).expect("serialize");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("deserialize");
    assert!(parsed["arches"].is_array());
    assert!(parsed["format"].is_string());
}
