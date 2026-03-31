use macho::analysis::snapshot::ContainerSnapshot;
use macho::analysis::snapshot::{
    CodesignSnapshot, ContainerFormat, ExportSnapshot, HeaderSnapshot, ImportSnapshot,
    ObjCSnapshot, SliceSnapshot,
};
use macho::container_analysis::ContainerReport;
use macho::container_analysis::parity::compute_parity;
use macho::container_analysis::resolve::{
    all_signed, common_exports, common_imports, diff_slices, divergent_exports, resolve_cross_image,
};
use macho::model::container::MachContainer;

fn snapshot_for(path: &str) -> ContainerSnapshot {
    let data = std::fs::read(path).expect("read binary");
    let container = macho::parse(&data).expect("parse");
    ContainerSnapshot::from_container(&container)
}

fn minimal_fileset_binary(entry_id: &str, vm_addr: u64, file_offset: u64) -> Vec<u8> {
    const MH_MAGIC_64: u32 = 0xFEEDFACF;
    const CPU_TYPE_ARM64: u32 = 0x0100000C;
    const MH_FILESET: u32 = 0xC;
    const LC_REQ_DYLD: u32 = 0x8000_0000;
    const LC_FILESET_ENTRY: u32 = 0x35 | LC_REQ_DYLD;

    let str_offset = 32u32;
    let cmdsize = ((str_offset as usize + entry_id.len() + 1 + 7) & !7) as u32;

    let mut data = Vec::new();
    data.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
    data.extend_from_slice(&(CPU_TYPE_ARM64 as i32).to_le_bytes());
    data.extend_from_slice(&0i32.to_le_bytes());
    data.extend_from_slice(&MH_FILESET.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&cmdsize.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());

    data.extend_from_slice(&LC_FILESET_ENTRY.to_le_bytes());
    data.extend_from_slice(&cmdsize.to_le_bytes());
    data.extend_from_slice(&vm_addr.to_le_bytes());
    data.extend_from_slice(&file_offset.to_le_bytes());
    data.extend_from_slice(&str_offset.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(entry_id.as_bytes());
    data.push(0);
    while data.len() % 8 != 0 {
        data.push(0);
    }

    data
}

fn synthetic_cross_slice_snapshot() -> ContainerSnapshot {
    fn slice(arch: &str, exports: &[&str], imports: &[&str], signed: bool) -> SliceSnapshot {
        SliceSnapshot {
            arch: arch.into(),
            header: HeaderSnapshot {
                cpu_type: arch.into(),
                cpu_subtype: "all".into(),
                file_type: "MH_EXECUTE".into(),
                flags: Vec::new(),
                ncmds: 0,
                uuid: None,
                platform: None,
            },
            load_commands: Vec::new(),
            segments: Vec::new(),
            symbols: Vec::new(),
            exports: exports
                .iter()
                .map(|name| ExportSnapshot {
                    name: (*name).into(),
                    kind: macho::analysis::snapshot::ExportKindSnapshot::Regular { address: 0 },
                    weak: false,
                })
                .collect(),
            imports: imports
                .iter()
                .map(|name| ImportSnapshot {
                    name: (*name).into(),
                    lib_ordinal: 0,
                    weak: false,
                })
                .collect(),
            objc: ObjCSnapshot {
                classes: Vec::new(),
                categories: Vec::new(),
                protocols: Vec::new(),
            },
            codesign: signed.then_some(CodesignSnapshot {
                identifier: Some(format!("com.example.{arch}")),
                team_id: Some("TEAMID".into()),
                hash_type: "sha256".into(),
                has_entitlements: false,
                entitlements_xml: None,
                has_der_entitlements: false,
                has_cms_signature: true,
                n_code_slots: 0,
                code_limit: 0,
            }),
            analysis_issues: Vec::new(),
            diagnostics: Vec::new(),
        }
    }

    ContainerSnapshot {
        format: ContainerFormat::Fat,
        slices: vec![
            slice(
                "arm64",
                &["common", "only_arm64"],
                &["shared", "libSystem"],
                true,
            ),
            slice(
                "x86_64",
                &["common", "only_x86_64"],
                &["shared", "AppKit"],
                true,
            ),
        ],
    }
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

#[test]
fn container_helpers_cover_fileset_and_snapshot_surface() {
    let data = minimal_fileset_binary("com.example.member", 0x1000_0000, 0x2000);
    let container = macho::parse(&data).expect("parse");

    let snapshot = container.snapshot();
    assert_eq!(snapshot.available_arches(), vec!["arm64"]);

    let report = container.container_report();
    let fileset = report.fileset.as_ref().expect("expected fileset report");
    assert_eq!(fileset.entries.len(), 1);
    assert_eq!(fileset.entries[0].entry_id, "com.example.member");
    assert_eq!(
        container.fileset_report().unwrap().entries[0].file_offset,
        0x2000
    );
}

#[test]
fn helper_queries_surface_common_and_divergent_names() {
    let snap = synthetic_cross_slice_snapshot();

    assert_eq!(common_exports(&snap), vec!["common"]);
    assert_eq!(common_imports(&snap), vec!["shared"]);

    let divergent = divergent_exports(&snap);
    let symbols: Vec<_> = divergent
        .iter()
        .map(|entry| entry.symbol.as_str())
        .collect();
    assert!(symbols.contains(&"only_arm64"));
    assert!(symbols.contains(&"only_x86_64"));
}

#[test]
fn helper_queries_detect_signature_and_slice_diff() {
    let mut snap = synthetic_cross_slice_snapshot();
    assert!(all_signed(&snap));
    snap.slices[1].codesign = None;
    assert!(!all_signed(&snap));

    let diff = diff_slices(&snap, "arm64", "x86_64").expect("expected slice diff");
    assert!(!diff.findings.is_empty());
    assert!(
        diff.findings
            .iter()
            .all(|finding| finding.arch.as_deref() == Some("arm64 -> x86_64")),
        "unexpected slice diff arch labels: {:?}",
        diff.findings
            .iter()
            .map(|finding| finding.arch.as_deref().unwrap_or("*"))
            .collect::<Vec<_>>()
    );
    assert!(
        diff.findings
            .iter()
            .any(|finding| finding.message.contains("export removed: only_arm64")),
        "missing removed export finding: {:?}",
        diff.findings
            .iter()
            .map(|finding| &finding.message)
            .collect::<Vec<_>>()
    );
    assert!(
        diff.findings
            .iter()
            .any(|finding| finding.message.contains("export added: only_x86_64")),
        "missing added export finding: {:?}",
        diff.findings
            .iter()
        .map(|finding| &finding.message)
        .collect::<Vec<_>>()
    );
}

#[test]
fn container_methods_match_snapshot_helpers() {
    let data = std::fs::read("/usr/bin/plutil").expect("read binary");
    let container = macho::parse(&data).expect("parse");
    let snapshot = container.snapshot();

    let expected_parity = if snapshot.slices.len() > 1 {
        Some(compute_parity(&snapshot.slices))
    } else {
        None
    };
    assert_eq!(
        serde_json::to_value(container.parity_report()).expect("serialize parity"),
        serde_json::to_value(expected_parity).expect("serialize parity")
    );
    assert_eq!(container.common_exports(), common_exports(&snapshot));
    assert_eq!(container.common_imports(), common_imports(&snapshot));
    assert_eq!(container.all_signed(), all_signed(&snapshot));
    assert_eq!(
        serde_json::to_value(container.resolve_cross_image()).expect("serialize resolution"),
        serde_json::to_value(resolve_cross_image(&snapshot)).expect("serialize resolution")
    );

    if snapshot.slices.len() >= 2 {
        let old_arch = snapshot.slices[0].arch.clone();
        let new_arch = snapshot.slices[1].arch.clone();
        let method_report = container
            .diff_slices(&old_arch, &new_arch)
            .expect("expected container diff");
        let helper_report = diff_slices(&snapshot, &old_arch, &new_arch).expect("expected diff");
        assert_eq!(
            method_report
                .findings
                .iter()
                .map(|finding| (&finding.domain, &finding.severity, finding.arch.as_deref(), finding.message.as_str()))
                .collect::<Vec<_>>(),
            helper_report
                .findings
                .iter()
                .map(|finding| (&finding.domain, &finding.severity, finding.arch.as_deref(), finding.message.as_str()))
                .collect::<Vec<_>>()
        );
    }

    if let MachContainer::Fat(fat) = &container {
        assert_eq!(fat.common_exports(), container.common_exports());
        assert_eq!(fat.common_imports(), container.common_imports());
        assert_eq!(fat.all_signed(), container.all_signed());
    }
}
