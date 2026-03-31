use macho::analysis::snapshot::{
    AnalysisIssueSnapshot, CodesignSnapshot, ContainerFormat, ContainerSnapshot,
    DiagnosticSnapshot, ExportKindSnapshot, ExportSnapshot, FilesetEntrySnapshot,
    FixupKindSnapshot, FixupSnapshot, HeaderSnapshot, ImportSnapshot, LoadCommandSnapshot,
    ObjCCategorySnapshot, ObjCClassSnapshot, ObjCMethodSnapshot, ObjCProtocolSnapshot,
    ObjCSnapshot, PlatformSnapshot, SliceSnapshot,
};
use macho::diff::{ChangeSeverity, DiffDomain, diff_containers};
use std::process::Command;

fn macho_bin() -> &'static str {
    env!("CARGO_BIN_EXE_macho")
}

fn snapshot_for(path: &str) -> ContainerSnapshot {
    let data = std::fs::read(path).expect("read binary");
    let container = macho::parse(&data).expect("parse");
    ContainerSnapshot::from_container(&container)
}

fn synthetic_snapshot() -> ContainerSnapshot {
    ContainerSnapshot {
        format: ContainerFormat::Thin,
        slices: vec![SliceSnapshot {
            arch: "arm64".into(),
            header: HeaderSnapshot {
                cpu_type: "arm64".into(),
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
            exports: Vec::new(),
            imports: Vec::new(),
            fixups: Vec::new(),
            objc: ObjCSnapshot {
                classes: Vec::new(),
                categories: Vec::new(),
                protocols: Vec::new(),
            },
            codesign: None,
            analysis_issues: Vec::new(),
            diagnostics: Vec::new(),
        }],
    }
}

fn synthetic_fileset_snapshot(vm_addr: u64, file_offset: u64) -> ContainerSnapshot {
    let mut snap = synthetic_snapshot();
    snap.slices[0].load_commands.push(LoadCommandSnapshot {
        name: "LC_FILESET_ENTRY".into(),
        summary: "com.example.member".into(),
        fileset_entry: Some(FilesetEntrySnapshot {
            entry_id: "com.example.member".into(),
            vm_addr,
            file_offset,
        }),
    });
    snap
}

fn synthetic_load_command_snapshot(name: &str, summary: &str) -> ContainerSnapshot {
    let mut snap = synthetic_snapshot();
    snap.slices[0].load_commands.push(LoadCommandSnapshot {
        name: name.into(),
        summary: summary.into(),
        fileset_entry: None,
    });
    snap
}

fn synthetic_import_variants(imports: &[(&str, i32, bool)]) -> ContainerSnapshot {
    let mut snap = synthetic_snapshot();
    snap.slices[0].imports = imports
        .iter()
        .map(|(name, lib_ordinal, weak)| ImportSnapshot {
            name: (*name).into(),
            lib_ordinal: *lib_ordinal,
            weak: *weak,
        })
        .collect();
    snap
}

fn synthetic_signed_snapshot() -> ContainerSnapshot {
    let mut snap = synthetic_snapshot();
    snap.slices[0].codesign = Some(CodesignSnapshot {
        identifier: Some("com.example.test".into()),
        team_id: Some("TEAMID".into()),
        hash_type: "sha256".into(),
        has_entitlements: false,
        entitlements_xml: None,
        has_der_entitlements: false,
        has_cms_signature: true,
        n_code_slots: 0,
        code_limit: 0,
    });
    snap.slices[0].load_commands.push(LoadCommandSnapshot {
        name: "LC_CODE_SIGNATURE".into(),
        summary: "off=0x100 size=0x40".into(),
        fileset_entry: None,
    });
    snap
}

fn synthetic_objc_snapshot() -> ContainerSnapshot {
    let mut snap = synthetic_snapshot();
    snap.slices[0].objc = ObjCSnapshot {
        classes: vec![ObjCClassSnapshot {
            name: "Widget".into(),
            superclass: Some("NSObject".into()),
            instance_methods: vec![ObjCMethodSnapshot {
                name: "render".into(),
                type_encoding: "v16@0:8".into(),
            }],
            class_methods: Vec::new(),
            properties: vec!["title".into()],
            protocols: vec!["WidgetProtocol".into()],
            ivars: vec!["_title".into()],
            is_swift: false,
        }],
        categories: vec![ObjCCategorySnapshot {
            name: "Debug".into(),
            class_name: "Widget".into(),
            instance_methods: Vec::new(),
            class_methods: Vec::new(),
            protocols: vec!["Debuggable".into()],
        }],
        protocols: vec![ObjCProtocolSnapshot {
            name: "WidgetProtocol".into(),
            instance_methods: vec!["render".into()],
            class_methods: Vec::new(),
            optional_instance_methods: Vec::new(),
            optional_class_methods: Vec::new(),
            adopted_protocols: vec!["NSObject".into()],
        }],
    };
    snap
}

fn synthetic_metadata_snapshot(
    uuid: &str,
    platform: &str,
    min_os: &str,
    sdk: &str,
) -> ContainerSnapshot {
    let mut snap = synthetic_snapshot();
    snap.slices[0].header.uuid = Some(uuid.into());
    snap.slices[0].header.platform = Some(PlatformSnapshot {
        platform: platform.into(),
        min_os: min_os.into(),
        sdk: sdk.into(),
    });
    snap.slices[0].load_commands.push(LoadCommandSnapshot {
        name: "LC_UUID".into(),
        summary: uuid.into(),
        fileset_entry: None,
    });
    snap.slices[0].load_commands.push(LoadCommandSnapshot {
        name: "LC_BUILD_VERSION".into(),
        summary: format!("{platform} {min_os}"),
        fileset_entry: None,
    });
    snap
}

#[test]
fn diff_identical_binary_has_no_findings() {
    let snap = snapshot_for("/usr/bin/true");
    let report = diff_containers(&snap, &snap);
    assert!(
        report.findings.is_empty(),
        "diffing a binary against itself should produce no findings, got: {:?}",
        report
            .findings
            .iter()
            .map(|f| &f.message)
            .collect::<Vec<_>>()
    );
}

#[test]
fn diff_different_binaries_has_findings() {
    let old = snapshot_for("/usr/bin/true");
    let new = snapshot_for("/usr/bin/false");
    let report = diff_containers(&old, &new);
    assert!(!report.findings.is_empty());
}

#[test]
fn diff_true_vs_false_detects_identifier_change() {
    let old = snapshot_for("/usr/bin/true");
    let new = snapshot_for("/usr/bin/false");
    let report = diff_containers(&old, &new);

    let codesign_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.domain == DiffDomain::Codesign)
        .collect();

    assert!(
        !codesign_findings.is_empty(),
        "should detect codesign differences"
    );

    assert!(
        codesign_findings
            .iter()
            .any(|f| f.message.contains("identifier changed"))
    );
}

#[test]
fn diff_true_vs_false_has_uuid_change() {
    let old = snapshot_for("/usr/bin/true");
    let new = snapshot_for("/usr/bin/false");
    let report = diff_containers(&old, &new);

    let uuid_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.message.contains("UUID changed"))
        .collect();

    assert!(
        !uuid_findings.is_empty(),
        "should detect UUID change between true and false"
    );
}

#[test]
fn diff_filter_domain() {
    let old = snapshot_for("/usr/bin/true");
    let new = snapshot_for("/usr/bin/false");
    let report = diff_containers(&old, &new);

    let codesign_only = report.filter_domain(DiffDomain::Codesign);
    for f in &codesign_only {
        assert_eq!(f.domain, DiffDomain::Codesign);
    }
}

#[test]
fn diff_filter_severity() {
    let old = snapshot_for("/usr/bin/true");
    let new = snapshot_for("/usr/bin/false");
    let report = diff_containers(&old, &new);

    let warnings = report.filter_severity(ChangeSeverity::Warning);
    for f in &warnings {
        assert!(f.severity >= ChangeSeverity::Warning);
    }
}

#[test]
fn diff_max_severity() {
    let old = snapshot_for("/usr/bin/true");
    let new = snapshot_for("/usr/bin/false");
    let report = diff_containers(&old, &new);
    assert!(report.max_severity().is_some());
}

#[test]
fn diff_has_breaking_returns_false_for_true_vs_false() {
    let old = snapshot_for("/usr/bin/true");
    let new = snapshot_for("/usr/bin/false");
    let report = diff_containers(&old, &new);
    // true and false are nearly identical — no breaking changes expected
    assert!(!report.has_breaking());
}

#[test]
fn diff_report_serializes_to_json() {
    let old = snapshot_for("/usr/bin/true");
    let new = snapshot_for("/usr/bin/false");
    let report = diff_containers(&old, &new);
    let json = serde_json::to_string_pretty(&report).expect("serialize");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("deserialize");
    assert!(parsed["findings"].is_array());
}

#[test]
fn diff_severity_ordering() {
    assert!(ChangeSeverity::Info < ChangeSeverity::Warning);
    assert!(ChangeSeverity::Warning < ChangeSeverity::Breaking);
}

#[test]
fn diff_domain_ordering() {
    assert!(DiffDomain::Container < DiffDomain::Header);
    assert!(DiffDomain::Header < DiffDomain::Exports);
}

#[test]
fn diff_validation_detects_message_changes_for_same_code() {
    let mut old = synthetic_snapshot();
    old.slices[0].diagnostics.push(DiagnosticSnapshot {
        severity: "error".into(),
        code: "E010".into(),
        message: "string table truncated".into(),
        spans: Vec::new(),
    });

    let mut new = synthetic_snapshot();
    new.slices[0].diagnostics.push(DiagnosticSnapshot {
        severity: "warning".into(),
        code: "E010".into(),
        message: "string table overlaps __LINKEDIT".into(),
        spans: Vec::new(),
    });

    let report = diff_containers(&old, &new);
    let validation: Vec<_> = report
        .findings
        .iter()
        .filter(|finding| finding.domain == DiffDomain::Validation)
        .collect();

    assert_eq!(
        validation.len(),
        2,
        "expected add/remove pair: {validation:?}"
    );
    assert!(
        validation.iter().any(|finding| {
            finding
                .message
                .contains("new validation finding E010: string table overlaps __LINKEDIT")
        }),
        "missing added finding: {validation:?}"
    );
    assert!(
        validation.iter().any(|finding| {
            finding
                .message
                .contains("validation finding E010 resolved: string table truncated")
        }),
        "missing resolved finding: {validation:?}"
    );
}

#[test]
fn diff_reports_analysis_issue_changes() {
    let mut old = synthetic_snapshot();
    old.slices[0].analysis_issues.push(AnalysisIssueSnapshot {
        component: "codesign".into(),
        message: "failed to parse code signature: truncated superblob".into(),
    });

    let new = synthetic_snapshot();
    let report = diff_containers(&old, &new);

    let analysis: Vec<_> = report
        .findings
        .iter()
        .filter(|finding| finding.domain == DiffDomain::Analysis)
        .collect();

    assert_eq!(
        analysis.len(),
        1,
        "expected one resolved issue: {analysis:?}"
    );
    assert!(
        analysis[0]
            .message
            .contains("analysis issue resolved in codesign"),
        "unexpected finding: {:?}",
        analysis[0]
    );
}

#[test]
fn diff_reports_fileset_entry_changes() {
    let old = synthetic_fileset_snapshot(0x1000_0000, 0x2000);
    let new = synthetic_fileset_snapshot(0x1000_0000, 0x2400);

    let report = diff_containers(&old, &new);
    let load_commands: Vec<_> = report
        .findings
        .iter()
        .filter(|finding| finding.domain == DiffDomain::LoadCommands)
        .collect();

    assert_eq!(
        load_commands.len(),
        2,
        "expected add/remove pair: {load_commands:?}"
    );
    assert!(
        load_commands
            .iter()
            .any(|finding| finding.message.contains("LC_FILESET_ENTRY")),
        "missing fileset entry diff: {load_commands:?}"
    );
    assert!(
        load_commands
            .iter()
            .any(|finding| finding.message.contains("file_offset")),
        "missing file offset detail: {load_commands:?}"
    );
}

#[test]
fn diff_load_command_severity_distinguishes_dependencies_and_rpaths() {
    let old_dylib = synthetic_load_command_snapshot("LC_LOAD_DYLIB", "/usr/lib/libfoo.dylib");
    let no_dylib = synthetic_snapshot();
    let dylib_report = diff_containers(&old_dylib, &no_dylib);
    let dylib_findings: Vec<_> = dylib_report
        .findings
        .iter()
        .filter(|finding| finding.domain == DiffDomain::LoadCommands)
        .collect();
    assert_eq!(dylib_findings.len(), 1, "expected one dylib finding");
    assert_eq!(dylib_findings[0].severity, ChangeSeverity::Breaking);

    let old_rpath = synthetic_load_command_snapshot("LC_RPATH", "/tmp/old");
    let no_rpath = synthetic_snapshot();
    let rpath_report = diff_containers(&old_rpath, &no_rpath);
    let rpath_findings: Vec<_> = rpath_report
        .findings
        .iter()
        .filter(|finding| finding.domain == DiffDomain::LoadCommands)
        .collect();
    assert_eq!(rpath_findings.len(), 1, "expected one rpath finding");
    assert_eq!(rpath_findings[0].severity, ChangeSeverity::Warning);

    let old_main = synthetic_load_command_snapshot("LC_MAIN", "entry_offset=0x1000");
    let no_main = synthetic_snapshot();
    let main_report = diff_containers(&old_main, &no_main);
    let main_findings: Vec<_> = main_report
        .findings
        .iter()
        .filter(|finding| finding.domain == DiffDomain::LoadCommands)
        .collect();
    assert_eq!(main_findings.len(), 1, "expected one main finding");
    assert_eq!(main_findings[0].severity, ChangeSeverity::Breaking);
}

#[test]
fn diff_skips_code_signature_load_command_when_codesign_state_changes() {
    let old = synthetic_signed_snapshot();
    let mut new = synthetic_signed_snapshot();
    new.slices[0].codesign = None;

    let report = diff_containers(&old, &new);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.domain == DiffDomain::Codesign),
        "expected codesign diff"
    );
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.domain != DiffDomain::LoadCommands),
        "code signature should not produce a separate load-command diff: {:?}",
        report
            .findings
            .iter()
            .map(|finding| (&finding.domain, &finding.message))
            .collect::<Vec<_>>()
    );
}

#[test]
fn diff_reports_fixup_changes() {
    let mut old = synthetic_snapshot();
    old.slices[0].fixups.push(FixupSnapshot {
        segment_index: 0,
        segment_offset: 0x10,
        kind: FixupKindSnapshot::Bind {
            import_index: 1,
            addend: 0,
        },
    });

    let mut new = synthetic_snapshot();
    new.slices[0].fixups.push(FixupSnapshot {
        segment_index: 0,
        segment_offset: 0x10,
        kind: FixupKindSnapshot::AuthBind {
            import_index: 2,
            diversity: 7,
            key: 1,
            addr_div: false,
        },
    });

    let report = diff_containers(&old, &new);
    let fixup_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|finding| finding.domain == DiffDomain::Fixups)
        .collect();

    assert_eq!(fixup_findings.len(), 1, "{fixup_findings:?}");
    assert_eq!(fixup_findings[0].severity, ChangeSeverity::Warning);
    assert!(fixup_findings[0].message.contains("changed"));
}

#[test]
fn diff_reports_import_metadata_changes() {
    let mut old = synthetic_snapshot();
    old.slices[0]
        .imports
        .push(macho::analysis::snapshot::ImportSnapshot {
            name: "_objc_msgSend".into(),
            lib_ordinal: 1,
            weak: false,
        });

    let mut new = synthetic_snapshot();
    new.slices[0]
        .imports
        .push(macho::analysis::snapshot::ImportSnapshot {
            name: "_objc_msgSend".into(),
            lib_ordinal: 2,
            weak: true,
        });

    let report = diff_containers(&old, &new);
    let import_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|finding| finding.domain == DiffDomain::Imports)
        .collect();

    assert!(
        import_findings
            .iter()
            .any(|finding| finding.message.contains("variants changed")),
        "missing import-variant finding: {import_findings:?}"
    );
}

#[test]
fn diff_ignores_layout_only_linkedit_load_command_churn() {
    let old = synthetic_load_command_snapshot("LC_FUNCTION_STARTS", "off=0x100 size=0x20");
    let new = synthetic_load_command_snapshot("LC_FUNCTION_STARTS", "off=0x140 size=0x20");

    let report = diff_containers(&old, &new);
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.domain != DiffDomain::LoadCommands),
        "layout-only LINKEDIT offsets should not produce semantic load-command diffs: {:?}",
        report.findings
    );
}

#[test]
fn diff_reports_export_payload_changes() {
    let mut old = synthetic_snapshot();
    old.slices[0].exports.push(ExportSnapshot {
        name: "_widget".into(),
        kind: ExportKindSnapshot::Regular { address: 0x1000 },
        weak: false,
    });

    let mut new = synthetic_snapshot();
    new.slices[0].exports.push(ExportSnapshot {
        name: "_widget".into(),
        kind: ExportKindSnapshot::Regular { address: 0x2000 },
        weak: false,
    });

    let report = diff_containers(&old, &new);
    assert!(
        report.findings.iter().any(|finding| {
            finding.domain == DiffDomain::Exports
                && finding.message.contains("export _widget changed")
                && finding.message.contains("0x1000")
                && finding.message.contains("0x2000")
        }),
        "missing export payload diff: {:?}",
        report.findings
    );
}

#[test]
fn diff_reports_import_variant_changes_for_duplicate_names() {
    let mut old = synthetic_snapshot();
    old.slices[0].imports.extend([
        ImportSnapshot {
            name: "_objc_msgSend".into(),
            lib_ordinal: 1,
            weak: false,
        },
        ImportSnapshot {
            name: "_objc_msgSend".into(),
            lib_ordinal: 2,
            weak: false,
        },
    ]);

    let mut new = synthetic_snapshot();
    new.slices[0].imports.extend([
        ImportSnapshot {
            name: "_objc_msgSend".into(),
            lib_ordinal: 1,
            weak: false,
        },
        ImportSnapshot {
            name: "_objc_msgSend".into(),
            lib_ordinal: 3,
            weak: true,
        },
    ]);

    let report = diff_containers(&old, &new);
    let findings: Vec<_> = report
        .findings
        .iter()
        .filter(|finding| finding.domain == DiffDomain::Imports)
        .collect();

    assert_eq!(
        findings.len(),
        1,
        "unexpected import findings: {findings:?}"
    );
    assert!(findings[0].message.contains("variants changed"));
    assert!(findings[0].message.contains("ordinal=2 weak=false"));
    assert!(findings[0].message.contains("ordinal=3 weak=true"));
}

#[test]
fn diff_reports_objc_surface_changes_beyond_methods() {
    let old = synthetic_objc_snapshot();
    let mut new = synthetic_objc_snapshot();
    let class = &mut new.slices[0].objc.classes[0];
    class.superclass = Some("UIResponder".into());
    class.is_swift = true;
    class.properties.push("subtitle".into());
    class.ivars.push("_subtitle".into());
    class.protocols.push("Serializable".into());
    new.slices[0].objc.categories[0]
        .protocols
        .push("Inspectable".into());
    new.slices[0].objc.protocols[0]
        .adopted_protocols
        .push("NSCopying".into());

    let report = diff_containers(&old, &new);
    let objc_messages: Vec<_> = report
        .findings
        .iter()
        .filter(|finding| finding.domain == DiffDomain::ObjC)
        .map(|finding| finding.message.as_str())
        .collect();

    assert!(
        objc_messages
            .iter()
            .any(|message| message.contains("superclass changed"))
    );
    assert!(
        objc_messages
            .iter()
            .any(|message| message.contains("Swift marker changed"))
    );
    assert!(
        objc_messages
            .iter()
            .any(|message| message.contains("property added: subtitle"))
    );
    assert!(
        objc_messages
            .iter()
            .any(|message| message.contains("ivar added: _subtitle"))
    );
    assert!(
        objc_messages
            .iter()
            .any(|message| message.contains("protocol added: Serializable"))
    );
    assert!(
        objc_messages
            .iter()
            .any(|message| message.contains("category Debug on Widget protocol added: Inspectable"))
    );
    assert!(
        objc_messages
            .iter()
            .any(|message| message.contains("adopted protocol added: NSCopying"))
    );
}

#[test]
fn diff_reports_der_entitlements_changes() {
    let mut old = synthetic_signed_snapshot();
    old.slices[0].codesign.as_mut().unwrap().has_entitlements = true;

    let mut new = synthetic_signed_snapshot();
    let codesign = new.slices[0].codesign.as_mut().unwrap();
    codesign.has_entitlements = true;
    codesign.has_der_entitlements = true;

    let report = diff_containers(&old, &new);
    assert!(
        report.findings.iter().any(|finding| finding
            .message
            .contains("DER entitlements presence changed")),
        "missing DER-entitlements diff: {:?}",
        report
            .findings
            .iter()
            .map(|finding| &finding.message)
            .collect::<Vec<_>>()
    );
}

#[test]
fn diff_ignores_metadata_load_commands_covered_by_header() {
    let old =
        synthetic_metadata_snapshot("AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE", "ios", "1.0", "1.0");
    let new =
        synthetic_metadata_snapshot("FFFFFFFF-1111-2222-3333-444444444444", "ios", "2.0", "2.0");

    let report = diff_containers(&old, &new);
    let load_commands: Vec<_> = report
        .findings
        .iter()
        .filter(|finding| finding.domain == DiffDomain::LoadCommands)
        .collect();

    assert!(
        load_commands.is_empty(),
        "metadata load commands should be covered by header diffs: {load_commands:?}"
    );

    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.domain == DiffDomain::Header
                && finding.message.contains("UUID changed")),
        "expected header UUID diff"
    );
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.domain == DiffDomain::Header
                && finding.message.contains("min OS changed")),
        "expected header platform diff"
    );
}

#[test]
fn diff_reports_export_payload_changes() {
    let mut old = synthetic_snapshot();
    old.slices[0].exports.push(ExportSnapshot {
        name: "_symbol".into(),
        kind: macho::analysis::snapshot::ExportKindSnapshot::Regular { address: 0x1000 },
        weak: false,
    });

    let mut new = synthetic_snapshot();
    new.slices[0].exports.push(ExportSnapshot {
        name: "_symbol".into(),
        kind: macho::analysis::snapshot::ExportKindSnapshot::Regular { address: 0x2000 },
        weak: false,
    });

    let report = diff_containers(&old, &new);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.message.contains("export _symbol changed")),
        "expected export payload change finding: {:?}",
        report
            .findings
            .iter()
            .map(|finding| &finding.message)
            .collect::<Vec<_>>()
    );
}

#[test]
fn diff_reports_import_provider_variant_changes() {
    let old = synthetic_import_variants(&[("_sym", 1, false), ("_sym", 2, false)]);
    let new = synthetic_import_variants(&[("_sym", 1, false)]);

    let report = diff_containers(&old, &new);
    assert!(
        report.findings.iter().any(|finding| {
            finding.domain == DiffDomain::Imports
                && finding.message.contains("import _sym variants changed")
        }),
        "expected import variant change finding: {:?}",
        report
            .findings
            .iter()
            .map(|finding| &finding.message)
            .collect::<Vec<_>>()
    );
}

#[test]
fn diff_reports_objc_superclass_and_property_changes() {
    let mut old = synthetic_snapshot();
    old.slices[0]
        .objc
        .classes
        .push(macho::analysis::snapshot::ObjCClassSnapshot {
            name: "Widget".into(),
            superclass: Some("NSObject".into()),
            instance_methods: Vec::new(),
            class_methods: Vec::new(),
            properties: vec!["title".into()],
            protocols: vec!["NSCopying".into()],
            ivars: vec!["_title".into()],
            is_swift: false,
        });

    let mut new = synthetic_snapshot();
    new.slices[0]
        .objc
        .classes
        .push(macho::analysis::snapshot::ObjCClassSnapshot {
            name: "Widget".into(),
            superclass: Some("BaseWidget".into()),
            instance_methods: Vec::new(),
            class_methods: Vec::new(),
            properties: vec!["subtitle".into()],
            protocols: vec!["NSCoding".into()],
            ivars: vec!["_subtitle".into()],
            is_swift: true,
        });

    let report = diff_containers(&old, &new);
    let messages: Vec<_> = report
        .findings
        .iter()
        .map(|finding| finding.message.as_str())
        .collect();
    assert!(
        messages
            .iter()
            .any(|message| message.contains("superclass changed"))
    );
    assert!(
        messages
            .iter()
            .any(|message| message.contains("property removed: title"))
    );
    assert!(
        messages
            .iter()
            .any(|message| message.contains("property added: subtitle"))
    );
    assert!(
        messages
            .iter()
            .any(|message| message.contains("Swift marker changed"))
    );
}

#[test]
fn diff_cli_json_outputs_findings() {
    let output = Command::new(macho_bin())
        .args(["diff", "/usr/bin/true", "/usr/bin/false", "--json"])
        .output()
        .expect("run macho diff");

    assert!(
        output.status.success(),
        "diff command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid diff JSON");
    assert!(json["findings"].is_array());
    assert!(
        !json["findings"]
            .as_array()
            .expect("findings array")
            .is_empty(),
        "expected diff output to contain findings"
    );
}

#[test]
fn diff_cli_fail_on_info_exits_nonzero() {
    let output = Command::new(macho_bin())
        .args([
            "diff",
            "/usr/bin/true",
            "/usr/bin/false",
            "--json",
            "--fail-on",
            "info",
        ])
        .output()
        .expect("run macho diff");

    assert!(
        !output.status.success(),
        "expected fail-on threshold to trigger a non-zero exit status"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("valid JSON on fail-on exit");
    assert!(
        !json["findings"]
            .as_array()
            .expect("findings array")
            .is_empty(),
        "expected findings to be preserved when failing"
    );
}
