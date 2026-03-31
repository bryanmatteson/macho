pub mod snapshot;

use crate::codesign::parse_code_signature;
use crate::dyld::bind::parse_bind_entries;
use crate::constants::VmProtection;
use crate::dyld::chained::parse_chained_fixups;
use crate::dyld::exports::parse_exports;
use crate::dyld::types::ExportKind;
use crate::model::container::MachContainer;
use crate::model::load_command::LoadCommand;
use crate::model::load_command::format_uuid;
use crate::model::mach::MachFile;
use crate::objc::parse_objc_metadata;
use crate::parse::parse_symbol_table;
use crate::validate;

use snapshot::*;

impl SliceSnapshot {
    pub fn from_mach(mach: &MachFile<'_>) -> Self {
        let mut analysis_issues = Vec::new();

        Self {
            arch: mach.header().cpu_type.name().to_string(),
            header: extract_header(mach),
            load_commands: extract_load_commands(mach),
            segments: extract_segments(mach),
            symbols: extract_symbols(mach, &mut analysis_issues),
            exports: extract_exports(mach, &mut analysis_issues),
            imports: extract_imports(mach, &mut analysis_issues),
            objc: extract_objc(mach, &mut analysis_issues),
            codesign: extract_codesign(mach, &mut analysis_issues),
            analysis_issues,
            diagnostics: extract_diagnostics(mach),
        }
    }
}

impl ContainerSnapshot {
    pub fn from_container(container: &MachContainer<'_>) -> Self {
        match container {
            MachContainer::Thin(mach) => Self {
                format: ContainerFormat::Thin,
                slices: vec![SliceSnapshot::from_mach(mach)],
            },
            MachContainer::Fat(fat) => Self {
                format: ContainerFormat::Fat,
                slices: fat
                    .arches()
                    .iter()
                    .map(|arch| {
                        let mut snap = SliceSnapshot::from_mach(&arch.mach);
                        snap.arch = arch.spec.name();
                        snap
                    })
                    .collect(),
            },
        }
    }
}

fn extract_header(mach: &MachFile<'_>) -> HeaderSnapshot {
    let h = mach.header();

    let uuid = mach.uuid().map(format_uuid);

    let platform = mach
        .load_commands()
        .iter()
        .find_map(|lc| lc.kind.as_build_version())
        .map(|bv| PlatformSnapshot {
            platform: bv.platform.name().to_string(),
            min_os: bv.minos.to_string(),
            sdk: bv.sdk.to_string(),
        });

    let flags: Vec<String> = {
        let mut out = Vec::new();
        let bits = h.flags;
        for (name, _) in bits.iter_names() {
            out.push(name.to_string());
        }
        out
    };

    HeaderSnapshot {
        cpu_type: h.cpu_type.name().to_string(),
        cpu_subtype: h.cpu_subtype.name(h.cpu_type).to_string(),
        file_type: h.file_type.name().to_string(),
        flags,
        ncmds: h.ncmds,
        uuid,
        platform,
    }
}

fn extract_load_commands(mach: &MachFile<'_>) -> Vec<LoadCommandSnapshot> {
    mach.load_commands()
        .iter()
        .map(|lc| {
            let fileset_entry = match &lc.kind {
                LoadCommand::FilesetEntry(entry) => Some(FilesetEntrySnapshot {
                    entry_id: entry.entry_id.clone(),
                    vm_addr: entry.vm_addr,
                    file_offset: entry.file_offset,
                }),
                _ => None,
            };

            LoadCommandSnapshot {
                name: lc.kind.name().to_string(),
                summary: lc.kind.summary(),
                fileset_entry,
            }
        })
        .collect()
}

fn extract_segments(mach: &MachFile<'_>) -> Vec<SegmentSnapshot> {
    mach.segments()
        .iter()
        .map(|seg| SegmentSnapshot {
            name: seg.name.to_string(),
            vm_addr: seg.vm_addr.0,
            vm_size: seg.vm_size,
            file_offset: seg.file_offset.0,
            file_size: seg.file_size,
            max_prot: format_prot(seg.max_prot),
            init_prot: format_prot(seg.init_prot),
            sections: seg
                .sections
                .iter()
                .map(|s| SectionSnapshot {
                    segment_name: s.segment_name.to_string(),
                    section_name: s.section_name.to_string(),
                    addr: s.addr.0,
                    size: s.size,
                    section_type: s.section_type.name().to_string(),
                })
                .collect(),
        })
        .collect()
}

fn extract_symbols(
    mach: &MachFile<'_>,
    analysis_issues: &mut Vec<AnalysisIssueSnapshot>,
) -> Vec<SymbolSnapshot> {
    if !has_symbol_table(mach) {
        return Vec::new();
    }

    let symtab = match parse_symbol_table(mach) {
        Ok(st) => st,
        Err(err) => {
            push_analysis_issue(
                analysis_issues,
                "symbols",
                format!("failed to parse symbol table: {err}"),
            );
            return Vec::new();
        }
    };
    symtab
        .symbols()
        .iter()
        .filter(|s| !s.is_stab())
        .map(|s| SymbolSnapshot {
            name: s.name.to_string(),
            sym_type: s.sym_type.name().to_string(),
            value: s.value,
            external: s.external,
            undefined: s.is_undefined(),
        })
        .collect()
}

fn extract_exports(
    mach: &MachFile<'_>,
    analysis_issues: &mut Vec<AnalysisIssueSnapshot>,
) -> Vec<ExportSnapshot> {
    if !has_export_trie(mach) {
        return Vec::new();
    }

    let exports = match parse_exports(mach) {
        Ok(e) => e,
        Err(err) => {
            push_analysis_issue(
                analysis_issues,
                "exports",
                format!("failed to parse exports trie: {err}"),
            );
            return Vec::new();
        }
    };
    exports
        .into_iter()
        .map(|e| {
            let weak = e.is_weak();
            let kind = match e.kind {
                ExportKind::Regular { address } => ExportKindSnapshot::Regular { address },
                ExportKind::ThreadLocal { address } => ExportKindSnapshot::ThreadLocal { address },
                ExportKind::Absolute { address } => ExportKindSnapshot::Absolute { address },
                ExportKind::Reexport { ordinal, name } => {
                    ExportKindSnapshot::Reexport { ordinal, name }
                }
                ExportKind::StubAndResolver {
                    stub_offset,
                    resolver_offset,
                } => ExportKindSnapshot::StubAndResolver {
                    stub_offset,
                    resolver_offset,
                },
            };
            ExportSnapshot {
                name: e.name,
                kind,
                weak,
            }
        })
        .collect()
}

fn collect_imports(mut imports: Vec<ImportSnapshot>) -> Vec<ImportSnapshot> {
    imports.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then(left.lib_ordinal.cmp(&right.lib_ordinal))
            .then(left.weak.cmp(&right.weak))
    });
    imports.dedup_by(|left, right| {
        left.name == right.name && left.lib_ordinal == right.lib_ordinal && left.weak == right.weak
    });
    imports
}

fn has_legacy_bind_info(mach: &MachFile<'_>) -> bool {
    mach.load_commands().iter().any(|lc| match &lc.kind {
        LoadCommand::DyldInfo(data) | LoadCommand::DyldInfoOnly(data) => {
            data.bind_size > 0 || data.weak_bind_size > 0 || data.lazy_bind_size > 0
        }
        _ => false,
    })
}

fn extract_imports(
    mach: &MachFile<'_>,
    analysis_issues: &mut Vec<AnalysisIssueSnapshot>,
) -> Vec<ImportSnapshot> {
    if !has_chained_fixups(mach) && !has_legacy_bind_info(mach) {
        return Vec::new();
    }

    match extract_imports_from_dynamic_linker(mach) {
        Err(err) => {
            push_analysis_issue(
                analysis_issues,
                "imports",
                err,
            );
            return Vec::new();
        }
        Ok(imports) => imports,
    }
}

fn extract_imports_from_dynamic_linker(
    mach: &MachFile<'_>,
) -> std::result::Result<Vec<ImportSnapshot>, String> {
    if has_chained_fixups(mach) {
        let fixups = parse_chained_fixups(mach)
            .map_err(|err| format!("failed to parse chained fixups: {err}"))?;
        return Ok(collect_imports(
            fixups
                .imports
                .iter()
                .map(|imp| ImportSnapshot {
                    name: imp.name.to_string(),
                    lib_ordinal: imp.lib_ordinal,
                    weak: imp.weak,
                })
                .collect(),
        ));
    }

    if has_legacy_bind_info(mach) {
        let (regular, weak, lazy) =
            parse_bind_entries(mach).map_err(|err| format!("failed to parse legacy bind info: {err}"))?;
        return Ok(collect_imports(
            regular
                .into_iter()
                .chain(weak)
                .chain(lazy)
                .map(|bind| ImportSnapshot {
                    name: bind.symbol_name.to_string(),
                    lib_ordinal: bind.lib_ordinal as i32,
                    weak: bind.weak,
                })
                .collect(),
        ));
    }

    Ok(Vec::new())
}

fn extract_objc(
    mach: &MachFile<'_>,
    analysis_issues: &mut Vec<AnalysisIssueSnapshot>,
) -> ObjCSnapshot {
    if !has_objc_metadata(mach) {
        return ObjCSnapshot {
            classes: Vec::new(),
            categories: Vec::new(),
            protocols: Vec::new(),
        };
    }

    let meta = match parse_objc_metadata(mach) {
        Ok(m) => m,
        Err(err) => {
            push_analysis_issue(
                analysis_issues,
                "objc",
                format!("failed to parse Objective-C metadata: {err}"),
            );
            return ObjCSnapshot {
                classes: Vec::new(),
                categories: Vec::new(),
                protocols: Vec::new(),
            };
        }
    };

    ObjCSnapshot {
        classes: meta
            .classes
            .iter()
            .map(|c| ObjCClassSnapshot {
                name: c.name.clone(),
                superclass: c.superclass_name.clone(),
                instance_methods: c.instance_methods.iter().map(snap_method).collect(),
                class_methods: c.class_methods.iter().map(snap_method).collect(),
                properties: c.properties.iter().map(|p| p.name.clone()).collect(),
                protocols: c.protocols.clone(),
                ivars: c.ivars.iter().map(|iv| iv.name.clone()).collect(),
                is_swift: c.is_swift,
            })
            .collect(),
        categories: meta
            .categories
            .iter()
            .map(|c| ObjCCategorySnapshot {
                name: c.name.clone(),
                class_name: c.class_name.clone(),
                instance_methods: c.instance_methods.iter().map(snap_method).collect(),
                class_methods: c.class_methods.iter().map(snap_method).collect(),
                protocols: c.protocols.clone(),
            })
            .collect(),
        protocols: meta
            .protocols
            .iter()
            .map(|p| ObjCProtocolSnapshot {
                name: p.name.clone(),
                instance_methods: p.instance_methods.iter().map(|m| m.name.clone()).collect(),
                class_methods: p.class_methods.iter().map(|m| m.name.clone()).collect(),
                optional_instance_methods: p
                    .optional_instance_methods
                    .iter()
                    .map(|m| m.name.clone())
                    .collect(),
                optional_class_methods: p
                    .optional_class_methods
                    .iter()
                    .map(|m| m.name.clone())
                    .collect(),
                adopted_protocols: p.adopted_protocols.clone(),
            })
            .collect(),
    }
}

fn extract_codesign(
    mach: &MachFile<'_>,
    analysis_issues: &mut Vec<AnalysisIssueSnapshot>,
) -> Option<CodesignSnapshot> {
    if !has_code_signature(mach) {
        return None;
    }

    let sig = match parse_code_signature(mach) {
        Ok(sig) => sig,
        Err(err) => {
            push_analysis_issue(
                analysis_issues,
                "codesign",
                format!("failed to parse code signature: {err}"),
            );
            return None;
        }
    };
    let Some(cd) = sig.code_directories().first() else {
        push_analysis_issue(
            analysis_issues,
            "codesign",
            "failed to parse code signature: no CodeDirectory blobs found".to_string(),
        );
        return None;
    };

    Some(CodesignSnapshot {
        identifier: cd.identifier.map(|s| s.to_string()),
        team_id: cd.team_id.map(|s| s.to_string()),
        hash_type: cd.hash_type.name().to_string(),
        has_entitlements: sig.entitlements_xml().is_some() || sig.entitlements_der().is_some(),
        entitlements_xml: sig.entitlements_xml().map(|s| s.to_string()),
        has_der_entitlements: sig.entitlements_der().is_some(),
        has_cms_signature: sig.cms_signature_present(),
        n_code_slots: cd.n_code_slots,
        code_limit: cd.code_limit as u64,
    })
}

fn extract_diagnostics(mach: &MachFile<'_>) -> Vec<DiagnosticSnapshot> {
    validate::validate(mach)
        .into_iter()
        .map(|d| DiagnosticSnapshot {
            severity: match d.severity {
                validate::Severity::Error => "error".to_string(),
                validate::Severity::Warning => "warning".to_string(),
                validate::Severity::Info => "info".to_string(),
            },
            code: d.code.0.to_string(),
            message: d.message,
            spans: d
                .spans
                .into_iter()
                .map(|span| DiagnosticSpanSnapshot {
                    offset: span.offset.0,
                    size: span.size,
                    label: span.label,
                })
                .collect(),
        })
        .collect()
}

fn snap_method(m: &crate::objc::ObjCMethod) -> ObjCMethodSnapshot {
    ObjCMethodSnapshot {
        name: m.name.clone(),
        type_encoding: m.type_encoding.clone(),
    }
}

fn format_prot(prot: VmProtection) -> String {
    prot.rwx_string()
}

fn push_analysis_issue(
    analysis_issues: &mut Vec<AnalysisIssueSnapshot>,
    component: &'static str,
    message: String,
) {
    analysis_issues.push(AnalysisIssueSnapshot {
        component: component.to_string(),
        message,
    });
}

fn has_symbol_table(mach: &MachFile<'_>) -> bool {
    mach.find_load_command(|lc| lc.as_symtab().is_some())
        .is_some()
}

fn has_export_trie(mach: &MachFile<'_>) -> bool {
    mach.load_commands().iter().any(|lc| match &lc.kind {
        LoadCommand::DyldExportsTrie(_) => true,
        LoadCommand::DyldInfo(data) | LoadCommand::DyldInfoOnly(data) => data.export_size > 0,
        _ => false,
    })
}

fn has_chained_fixups(mach: &MachFile<'_>) -> bool {
    mach.find_load_command(|lc| matches!(lc, LoadCommand::DyldChainedFixups(_)))
        .is_some()
}

fn has_objc_metadata(mach: &MachFile<'_>) -> bool {
    mach.all_sections().any(|section| {
        matches!(
            section.section_name.as_str_lossy().as_ref(),
            "__objc_classlist" | "__objc_catlist" | "__objc_protolist"
        )
    })
}

fn has_code_signature(mach: &MachFile<'_>) -> bool {
    mach.find_load_command(|lc| matches!(lc, LoadCommand::CodeSignature(_)))
        .is_some()
}
