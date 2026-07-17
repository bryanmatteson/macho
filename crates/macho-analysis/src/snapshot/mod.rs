/// The model module.
pub mod model;

use crate::AnalysisIssue;
use crate::codesign::CodeSignature;
use crate::dyld::chained::parse_chained_fixups;
use crate::dyld::exports::parse_exports;
use crate::dyld::types::ExportKind;
use crate::error::{
    CODESIGN_FAILED_CODE, EXPORTS_FAILED_CODE, FIXUPS_FAILED_CODE, IMPORTS_FAILED_CODE,
    OBJC_FAILED_CODE, SYMBOLS_FAILED_CODE,
};
use crate::format::constants::VmProtection;
use crate::model::load_command::LoadCommand;
use crate::model::load_command::format_uuid;
use crate::model::macho_file::MachoFile;
use crate::model::symbol::SymbolTable;
use crate::objc::ObjCMetadata;
use crate::symbols::imports::{ImportRecord, collect_imports};

pub use self::model::*;

pub(crate) fn extract_header(macho: &MachoFile<'_>) -> HeaderSnapshot {
    let h = macho.header();

    let uuid = macho.uuid().map(format_uuid);

    let platform = extract_platform_snapshot(macho);

    let flags: Vec<String> = {
        let mut out = Vec::new();
        let bits = h.flags();
        for (name, _) in bits.iter_names() {
            out.push(name.to_string());
        }
        out
    };

    HeaderSnapshot {
        cpu_type: h.cpu_type().name().to_string(),
        cpu_subtype: h.cpu_subtype().name(h.cpu_type()).to_string(),
        file_type: h.file_type().name().to_string(),
        flags,
        ncmds: h.load_command_count(),
        uuid,
        platform,
    }
}

pub(crate) fn extract_load_commands(macho: &MachoFile<'_>) -> Vec<LoadCommandSnapshot> {
    macho
        .load_commands()
        .iter()
        .map(|lc| {
            let fileset_entry = match lc.kind() {
                LoadCommand::FilesetEntry(entry) => Some(FilesetEntrySnapshot {
                    entry_id: entry.entry_id.clone(),
                    vm_addr: entry.vm_addr,
                    file_offset: entry.file_offset,
                }),
                _ => None,
            };

            LoadCommandSnapshot {
                name: lc.kind().name().to_string(),
                summary: lc.kind().summary(),
                fileset_entry,
            }
        })
        .collect()
}

pub(crate) fn extract_segments(macho: &MachoFile<'_>) -> Vec<SegmentSnapshot> {
    macho
        .segments()
        .iter()
        .map(|seg| SegmentSnapshot {
            name: seg.name().to_string(),
            vm_addr: seg.vm_addr().0,
            vm_size: seg.vm_size(),
            file_offset: seg.file_offset().0,
            file_size: seg.file_size(),
            max_prot: format_prot(seg.max_prot()),
            init_prot: format_prot(seg.init_prot()),
            sections: seg
                .sections()
                .iter()
                .map(|s| SectionSnapshot {
                    segment_name: s.segment_name().to_string(),
                    section_name: s.section_name().to_string(),
                    addr: s.addr().0,
                    size: s.size(),
                    section_type: s.section_type().name().to_string(),
                })
                .collect(),
        })
        .collect()
}

pub(crate) fn extract_symbols(
    macho: &MachoFile<'_>,
    analysis_issues: &mut Vec<AnalysisIssue>,
) -> Vec<SymbolSnapshot> {
    if !has_symbol_table(macho) {
        return Vec::new();
    }

    let symtab = match macho.ext::<SymbolTable<'_>>() {
        Ok(st) => st,
        Err(err) => {
            push_analysis_issue(
                analysis_issues,
                SYMBOLS_FAILED_CODE,
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

pub(crate) fn extract_exports(
    macho: &MachoFile<'_>,
    analysis_issues: &mut Vec<AnalysisIssue>,
) -> Vec<ExportSnapshot> {
    if !has_export_trie(macho) {
        return Vec::new();
    }

    let exports = match parse_exports(macho) {
        Ok(e) => e,
        Err(err) => {
            push_analysis_issue(
                analysis_issues,
                EXPORTS_FAILED_CODE,
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
                _ => ExportKindSnapshot::Unknown,
            };
            ExportSnapshot {
                name: e.name,
                kind,
                weak,
            }
        })
        .collect()
}

pub(crate) fn extract_imports(
    macho: &MachoFile<'_>,
    analysis_issues: &mut Vec<AnalysisIssue>,
) -> Vec<ImportRecord> {
    match collect_imports(macho) {
        Ok(imports) => imports,
        Err(err) => {
            push_analysis_issue(analysis_issues, IMPORTS_FAILED_CODE, err.to_string());
            Vec::new()
        }
    }
}

pub(crate) fn extract_fixups(
    macho: &MachoFile<'_>,
    analysis_issues: &mut Vec<AnalysisIssue>,
) -> Vec<FixupSnapshot> {
    if !has_chained_fixups(macho) {
        return Vec::new();
    }

    let fixups = match parse_chained_fixups(macho) {
        Ok(fixups) => fixups,
        Err(err) => {
            push_analysis_issue(
                analysis_issues,
                FIXUPS_FAILED_CODE,
                format!("failed to parse chained fixups: {err}"),
            );
            return Vec::new();
        }
    };

    let mut snapshots: Vec<FixupSnapshot> = fixups.fixups.into_iter().map(snap_fixup).collect();
    snapshots.sort_by(|a, b| {
        a.segment_index
            .cmp(&b.segment_index)
            .then(a.segment_offset.cmp(&b.segment_offset))
            .then(a.kind.cmp(&b.kind))
    });
    snapshots
}

pub(crate) fn extract_objc(
    macho: &MachoFile<'_>,
    analysis_issues: &mut Vec<AnalysisIssue>,
) -> ObjCSnapshot {
    if !has_objc_metadata(macho) {
        return ObjCSnapshot {
            classes: Vec::new(),
            categories: Vec::new(),
            protocols: Vec::new(),
        };
    }

    let meta = match macho.ext::<ObjCMetadata>() {
        Ok(m) => m,
        Err(err) => {
            push_analysis_issue(
                analysis_issues,
                OBJC_FAILED_CODE,
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
                properties: c.properties.iter().map(snap_property).collect(),
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
                properties: c.properties.iter().map(snap_property).collect(),
                protocols: c.protocols.clone(),
            })
            .collect(),
        protocols: meta
            .protocols
            .iter()
            .map(|p| ObjCProtocolSnapshot {
                name: p.name.clone(),
                instance_methods: p.instance_methods.iter().map(snap_method).collect(),
                class_methods: p.class_methods.iter().map(snap_method).collect(),
                optional_instance_methods: p
                    .optional_instance_methods
                    .iter()
                    .map(snap_method)
                    .collect(),
                optional_class_methods: p.optional_class_methods.iter().map(snap_method).collect(),
                properties: p.properties.iter().map(snap_property).collect(),
                adopted_protocols: p.adopted_protocols.clone(),
            })
            .collect(),
    }
}

pub(crate) fn extract_codesign(
    macho: &MachoFile<'_>,
    analysis_issues: &mut Vec<AnalysisIssue>,
) -> Option<CodesignSnapshot> {
    if !has_code_signature(macho) {
        return None;
    }

    let sig = match macho.ext::<CodeSignature<'_>>() {
        Ok(sig) => sig,
        Err(err) => {
            push_analysis_issue(
                analysis_issues,
                CODESIGN_FAILED_CODE,
                format!("failed to parse code signature: {err}"),
            );
            return None;
        }
    };
    let Some(cd) = sig.code_directories().first() else {
        push_analysis_issue(
            analysis_issues,
            CODESIGN_FAILED_CODE,
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
        entitlement_keys: collect_entitlement_keys(sig.entitlements_xml(), sig.entitlements_der()),
        has_der_entitlements: sig.entitlements_der().is_some(),
        entitlements_der_fingerprint: sig.entitlements_der().map(stable_fingerprint),
        has_cms_signature: sig.cms_signature_present(),
        n_code_slots: cd.n_code_slots,
        code_limit: cd.code_limit as u64,
    })
}

fn snap_property(property: &crate::objc::types::ObjCProperty) -> ObjCPropertySnapshot {
    ObjCPropertySnapshot {
        name: property.name.clone(),
        attributes: property.attributes.clone(),
        is_class: property.is_class,
    }
}

fn collect_entitlement_keys(xml: Option<&str>, der: Option<&[u8]>) -> Vec<String> {
    let mut keys = extract_xml_entitlement_keys(xml.unwrap_or_default());
    if let Some(der) = der {
        keys.extend(extract_der_entitlement_candidates(der));
    }
    keys.sort();
    keys.dedup();
    keys
}

fn extract_xml_entitlement_keys(xml: &str) -> Vec<String> {
    let mut keys = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find("<key>") {
        let after_start = &rest[start + 5..];
        let Some(end) = after_start.find("</key>") else {
            break;
        };
        let key = after_start[..end].trim();
        if !key.is_empty() {
            keys.push(key.to_string());
        }
        rest = &after_start[end + 6..];
    }
    keys
}

fn extract_der_entitlement_candidates(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = Vec::new();

    for &byte in data {
        let ch = byte as char;
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
            current.push(byte);
        } else {
            push_entitlement_candidate(&mut out, &mut current);
        }
    }

    push_entitlement_candidate(&mut out, &mut current);
    out
}

fn push_entitlement_candidate(out: &mut Vec<String>, current: &mut Vec<u8>) {
    if current.len() < 3 {
        current.clear();
        return;
    }

    if let Ok(candidate) = std::str::from_utf8(current) {
        if candidate.contains('.') || candidate.contains('-') {
            out.push(candidate.to_string());
        }
    }

    current.clear();
}

fn stable_fingerprint(bytes: &[u8]) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("fnv1a64:{hash:016x}")
}

fn snap_method(m: &crate::objc::ObjCMethod) -> ObjCMethodSnapshot {
    ObjCMethodSnapshot {
        name: m.name.clone(),
        type_encoding: m.type_encoding.clone(),
    }
}

fn snap_fixup(fixup: crate::dyld::types::Fixup) -> FixupSnapshot {
    use crate::dyld::types::FixupKind;

    let kind = match fixup.kind {
        FixupKind::Rebase { target } => FixupKindSnapshot::Rebase { target },
        FixupKind::Bind {
            import_index,
            addend,
        } => FixupKindSnapshot::Bind {
            import_index,
            addend,
        },
        FixupKind::AuthRebase {
            target,
            diversity,
            key,
            addr_div,
        } => FixupKindSnapshot::AuthRebase {
            target,
            diversity,
            key,
            addr_div,
        },
        FixupKind::AuthBind {
            import_index,
            diversity,
            key,
            addr_div,
        } => FixupKindSnapshot::AuthBind {
            import_index,
            diversity,
            key,
            addr_div,
        },
        _ => FixupKindSnapshot::Unknown,
    };

    FixupSnapshot {
        segment_index: fixup.segment_index,
        segment_offset: fixup.segment_offset,
        kind,
    }
}

fn format_prot(prot: VmProtection) -> String {
    prot.rwx_string()
}

fn push_analysis_issue(
    analysis_issues: &mut Vec<AnalysisIssue>,
    code: &'static str,
    message: String,
) {
    analysis_issues.push(AnalysisIssue {
        code: code.into(),
        message,
    });
}

fn has_symbol_table(macho: &MachoFile<'_>) -> bool {
    macho
        .find_load_command(|lc| lc.as_symtab().is_some())
        .is_some()
}

fn has_export_trie(macho: &MachoFile<'_>) -> bool {
    macho.load_commands().iter().any(|lc| match lc.kind() {
        LoadCommand::DyldExportsTrie(_) => true,
        LoadCommand::DyldInfo(data) | LoadCommand::DyldInfoOnly(data) => data.export_size > 0,
        _ => false,
    })
}

fn has_chained_fixups(macho: &MachoFile<'_>) -> bool {
    macho
        .find_load_command(|lc| matches!(lc, LoadCommand::DyldChainedFixups(_)))
        .is_some()
}

fn has_objc_metadata(macho: &MachoFile<'_>) -> bool {
    macho.all_sections().any(|section| {
        matches!(
            section.section_name().as_str_lossy().as_ref(),
            "__objc_classlist" | "__objc_catlist" | "__objc_protolist"
        )
    })
}

fn has_code_signature(macho: &MachoFile<'_>) -> bool {
    macho
        .find_load_command(|lc| matches!(lc, LoadCommand::CodeSignature(_)))
        .is_some()
}

fn extract_platform_snapshot(macho: &MachoFile<'_>) -> Option<PlatformSnapshot> {
    // Try LC_BUILD_VERSION first
    if let Some(bv) = macho
        .load_commands()
        .iter()
        .find_map(|lc| lc.kind().as_build_version())
    {
        return Some(PlatformSnapshot {
            platform: bv.platform.name().to_string(),
            min_os: bv.minos.to_string(),
            sdk: bv.sdk.to_string(),
        });
    }

    // Fall back to LC_VERSION_MIN_*
    for lc in macho.load_commands() {
        match lc.kind() {
            LoadCommand::VersionMinMacOS(d) => {
                return Some(PlatformSnapshot {
                    platform: "macOS".to_string(),
                    min_os: d.version.to_string(),
                    sdk: d.sdk.to_string(),
                });
            }
            LoadCommand::VersionMinIOS(d) => {
                return Some(PlatformSnapshot {
                    platform: "iOS".to_string(),
                    min_os: d.version.to_string(),
                    sdk: d.sdk.to_string(),
                });
            }
            LoadCommand::VersionMinTvOS(d) => {
                return Some(PlatformSnapshot {
                    platform: "tvOS".to_string(),
                    min_os: d.version.to_string(),
                    sdk: d.sdk.to_string(),
                });
            }
            LoadCommand::VersionMinWatchOS(d) => {
                return Some(PlatformSnapshot {
                    platform: "watchOS".to_string(),
                    min_os: d.version.to_string(),
                    sdk: d.sdk.to_string(),
                });
            }
            _ => {}
        }
    }

    None
}
