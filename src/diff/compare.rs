use std::collections::{BTreeMap, BTreeSet};

use crate::analysis::snapshot::*;
use crate::diff::{ChangeSeverity, DiffDomain, DiffFinding, DiffReport};

pub fn diff_slice_snapshots(old: &SliceSnapshot, new: &SliceSnapshot) -> DiffReport {
    let mut findings = Vec::new();
    let arch = Some(format!("{} -> {}", old.arch, new.arch));
    diff_slice_details(old, new, &arch, &mut findings);
    DiffReport { findings }
}

pub fn diff_containers(old: &ContainerSnapshot, new: &ContainerSnapshot) -> DiffReport {
    let mut findings = Vec::new();

    diff_container_format(old, new, &mut findings);

    let old_arches: BTreeSet<&str> = old.slices.iter().map(|s| s.arch.as_str()).collect();
    let new_arches: BTreeSet<&str> = new.slices.iter().map(|s| s.arch.as_str()).collect();

    for removed in old_arches.difference(&new_arches) {
        findings.push(DiffFinding {
            domain: DiffDomain::Container,
            severity: ChangeSeverity::Breaking,
            arch: Some(removed.to_string()),
            message: format!("architecture {removed} removed"),
        });
    }
    for added in new_arches.difference(&old_arches) {
        findings.push(DiffFinding {
            domain: DiffDomain::Container,
            severity: ChangeSeverity::Info,
            arch: Some(added.to_string()),
            message: format!("architecture {added} added"),
        });
    }

    for arch in old_arches.intersection(&new_arches) {
        let old_slice = old.slices.iter().find(|s| s.arch == *arch).unwrap();
        let new_slice = new.slices.iter().find(|s| s.arch == *arch).unwrap();
        let arch = Some(old_slice.arch.clone());
        diff_slice_details(old_slice, new_slice, &arch, &mut findings);
    }

    DiffReport { findings }
}

fn diff_container_format(
    old: &ContainerSnapshot,
    new: &ContainerSnapshot,
    findings: &mut Vec<DiffFinding>,
) {
    let old_fmt = format!("{:?}", old.format);
    let new_fmt = format!("{:?}", new.format);
    if old_fmt != new_fmt {
        findings.push(DiffFinding {
            domain: DiffDomain::Container,
            severity: ChangeSeverity::Warning,
            arch: None,
            message: format!("container format changed: {old_fmt} -> {new_fmt}"),
        });
    }
}

fn diff_slice_details(
    old: &SliceSnapshot,
    new: &SliceSnapshot,
    arch: &Option<String>,
    findings: &mut Vec<DiffFinding>,
) {
    diff_headers(&old.header, &new.header, arch, findings);
    diff_load_commands(&old.load_commands, &new.load_commands, arch, findings);
    diff_segments(&old.segments, &new.segments, arch, findings);
    diff_symbols(&old.symbols, &new.symbols, arch, findings);
    diff_exports(&old.exports, &new.exports, arch, findings);
    diff_imports(&old.imports, &new.imports, arch, findings);
    diff_fixups(&old.fixups, &new.fixups, arch, findings);
    diff_objc(&old.objc, &new.objc, arch, findings);
    diff_codesign(old.codesign.as_ref(), new.codesign.as_ref(), arch, findings);
    diff_analysis_issues(&old.analysis_issues, &new.analysis_issues, arch, findings);
    diff_diagnostics(&old.diagnostics, &new.diagnostics, arch, findings);
}

fn diff_headers(
    old: &HeaderSnapshot,
    new: &HeaderSnapshot,
    arch: &Option<String>,
    findings: &mut Vec<DiffFinding>,
) {
    if old.file_type != new.file_type {
        findings.push(DiffFinding {
            domain: DiffDomain::Header,
            severity: ChangeSeverity::Breaking,
            arch: arch.clone(),
            message: format!("file type changed: {} -> {}", old.file_type, new.file_type),
        });
    }

    let old_flags: BTreeSet<&str> = old.flags.iter().map(|s| s.as_str()).collect();
    let new_flags: BTreeSet<&str> = new.flags.iter().map(|s| s.as_str()).collect();
    for removed in old_flags.difference(&new_flags) {
        let sev = flag_severity(removed);
        findings.push(DiffFinding {
            domain: DiffDomain::Header,
            severity: sev,
            arch: arch.clone(),
            message: format!("flag removed: {removed}"),
        });
    }
    for added in new_flags.difference(&old_flags) {
        findings.push(DiffFinding {
            domain: DiffDomain::Header,
            severity: ChangeSeverity::Info,
            arch: arch.clone(),
            message: format!("flag added: {added}"),
        });
    }

    if old.uuid != new.uuid {
        findings.push(DiffFinding {
            domain: DiffDomain::Header,
            severity: ChangeSeverity::Info,
            arch: arch.clone(),
            message: format!(
                "UUID changed: {} -> {}",
                old.uuid.as_deref().unwrap_or("none"),
                new.uuid.as_deref().unwrap_or("none")
            ),
        });
    }

    diff_platform(old.platform.as_ref(), new.platform.as_ref(), arch, findings);
}

fn flag_severity(flag: &str) -> ChangeSeverity {
    match flag {
        "PIE" | "TWOLEVEL" | "NOUNDEFS" => ChangeSeverity::Warning,
        _ => ChangeSeverity::Info,
    }
}

fn diff_platform(
    old: Option<&PlatformSnapshot>,
    new: Option<&PlatformSnapshot>,
    arch: &Option<String>,
    findings: &mut Vec<DiffFinding>,
) {
    match (old, new) {
        (Some(o), Some(n)) => {
            if o.platform != n.platform {
                findings.push(DiffFinding {
                    domain: DiffDomain::Header,
                    severity: ChangeSeverity::Breaking,
                    arch: arch.clone(),
                    message: format!("platform changed: {} -> {}", o.platform, n.platform),
                });
            }
            if o.min_os != n.min_os {
                findings.push(DiffFinding {
                    domain: DiffDomain::Header,
                    severity: ChangeSeverity::Warning,
                    arch: arch.clone(),
                    message: format!("min OS changed: {} -> {}", o.min_os, n.min_os),
                });
            }
            if o.sdk != n.sdk {
                findings.push(DiffFinding {
                    domain: DiffDomain::Header,
                    severity: ChangeSeverity::Info,
                    arch: arch.clone(),
                    message: format!("SDK changed: {} -> {}", o.sdk, n.sdk),
                });
            }
        }
        (None, Some(n)) => {
            findings.push(DiffFinding {
                domain: DiffDomain::Header,
                severity: ChangeSeverity::Info,
                arch: arch.clone(),
                message: format!("platform added: {}", n.platform),
            });
        }
        (Some(o), None) => {
            findings.push(DiffFinding {
                domain: DiffDomain::Header,
                severity: ChangeSeverity::Warning,
                arch: arch.clone(),
                message: format!("platform removed: {}", o.platform),
            });
        }
        (None, None) => {}
    }
}

fn diff_load_commands(
    old: &[LoadCommandSnapshot],
    new: &[LoadCommandSnapshot],
    arch: &Option<String>,
    findings: &mut Vec<DiffFinding>,
) {
    let old = old
        .iter()
        .filter(|lc| should_compare_load_command(&lc.name))
        .collect::<Vec<_>>();
    let new = new
        .iter()
        .filter(|lc| should_compare_load_command(&lc.name))
        .collect::<Vec<_>>();

    let old_cmds: BTreeMap<LoadCommandFingerprint, usize> =
        count_items(old.into_iter().map(load_command_fingerprint));
    let new_cmds: BTreeMap<LoadCommandFingerprint, usize> =
        count_items(new.into_iter().map(load_command_fingerprint));

    for (cmd, removed) in diff_counts(&new_cmds, &old_cmds) {
        findings.push(DiffFinding {
            domain: DiffDomain::LoadCommands,
            severity: load_command_change_severity(cmd.name.as_str(), true),
            arch: arch.clone(),
            message: format!(
                "load command removed: {}{}",
                describe_load_command(&cmd),
                format_count_suffix(removed)
            ),
        });
    }
    for (cmd, added) in diff_counts(&old_cmds, &new_cmds) {
        findings.push(DiffFinding {
            domain: DiffDomain::LoadCommands,
            severity: load_command_change_severity(cmd.name.as_str(), false),
            arch: arch.clone(),
            message: format!(
                "load command added: {}{}",
                describe_load_command(&cmd),
                format_count_suffix(added)
            ),
        });
    }
}

fn should_compare_load_command(name: &str) -> bool {
    !matches!(
        name,
        "LC_UUID"
            | "LC_BUILD_VERSION"
            | "LC_SEGMENT"
            | "LC_SEGMENT_64"
            | "LC_CODE_SIGNATURE"
            | "LC_SYMTAB"
            | "LC_DYSYMTAB"
            | "LC_DYLD_INFO"
            | "LC_DYLD_INFO_ONLY"
            | "LC_DYLD_EXPORTS_TRIE"
            | "LC_DYLD_CHAINED_FIXUPS"
            | "LC_FUNCTION_STARTS"
            | "LC_DATA_IN_CODE"
            | "LC_SEGMENT_SPLIT_INFO"
            | "LC_DYLIB_CODE_SIGN_DRS"
            | "LC_LINKER_OPTIMIZATION_HINT"
            | "LC_ATOM_INFO"
            | "LC_FUNCTION_VARIANTS"
            | "LC_FUNCTION_VARIANT_FIXUPS"
    )
}

fn load_command_change_severity(name: &str, removed: bool) -> ChangeSeverity {
    match name {
        "LC_LOAD_DYLIB"
        | "LC_LOAD_WEAK_DYLIB"
        | "LC_REEXPORT_DYLIB"
        | "LC_LOAD_UPWARD_DYLIB"
        | "LC_LAZY_LOAD_DYLIB" => {
            if removed {
                ChangeSeverity::Breaking
            } else {
                ChangeSeverity::Warning
            }
        }
        "LC_RPATH" | "LC_FILESET_ENTRY" => {
            if removed {
                ChangeSeverity::Warning
            } else {
                ChangeSeverity::Info
            }
        }
        "LC_MAIN" => {
            if removed {
                ChangeSeverity::Breaking
            } else {
                ChangeSeverity::Warning
            }
        }
        "LC_ID_DYLIB" | "LC_DYLD_EXPORTS_TRIE" | "LC_DYLD_CHAINED_FIXUPS" => {
            if removed {
                ChangeSeverity::Warning
            } else {
                ChangeSeverity::Info
            }
        }
        _ => ChangeSeverity::Info,
    }
}

fn diff_segments(
    old: &[SegmentSnapshot],
    new: &[SegmentSnapshot],
    arch: &Option<String>,
    findings: &mut Vec<DiffFinding>,
) {
    let old_names: BTreeSet<&str> = old.iter().map(|s| s.name.as_str()).collect();
    let new_names: BTreeSet<&str> = new.iter().map(|s| s.name.as_str()).collect();

    for removed in old_names.difference(&new_names) {
        findings.push(DiffFinding {
            domain: DiffDomain::Segments,
            severity: ChangeSeverity::Breaking,
            arch: arch.clone(),
            message: format!("segment removed: {removed}"),
        });
    }
    for added in new_names.difference(&old_names) {
        findings.push(DiffFinding {
            domain: DiffDomain::Segments,
            severity: ChangeSeverity::Info,
            arch: arch.clone(),
            message: format!("segment added: {added}"),
        });
    }

    for name in old_names.intersection(&new_names) {
        let o = old.iter().find(|s| s.name == *name).unwrap();
        let n = new.iter().find(|s| s.name == *name).unwrap();

        if o.init_prot != n.init_prot {
            findings.push(DiffFinding {
                domain: DiffDomain::Segments,
                severity: ChangeSeverity::Warning,
                arch: arch.clone(),
                message: format!(
                    "segment {name} init_prot changed: {} -> {}",
                    o.init_prot, n.init_prot
                ),
            });
        }
        if o.max_prot != n.max_prot {
            findings.push(DiffFinding {
                domain: DiffDomain::Segments,
                severity: ChangeSeverity::Warning,
                arch: arch.clone(),
                message: format!(
                    "segment {name} max_prot changed: {} -> {}",
                    o.max_prot, n.max_prot
                ),
            });
        }

        // Section-level diff
        let old_sects: BTreeSet<&str> =
            o.sections.iter().map(|s| s.section_name.as_str()).collect();
        let new_sects: BTreeSet<&str> =
            n.sections.iter().map(|s| s.section_name.as_str()).collect();
        for removed in old_sects.difference(&new_sects) {
            findings.push(DiffFinding {
                domain: DiffDomain::Segments,
                severity: ChangeSeverity::Info,
                arch: arch.clone(),
                message: format!("section {name},{removed} removed"),
            });
        }
        for added in new_sects.difference(&old_sects) {
            findings.push(DiffFinding {
                domain: DiffDomain::Segments,
                severity: ChangeSeverity::Info,
                arch: arch.clone(),
                message: format!("section {name},{added} added"),
            });
        }
    }
}

fn diff_symbols(
    old: &[SymbolSnapshot],
    new: &[SymbolSnapshot],
    arch: &Option<String>,
    findings: &mut Vec<DiffFinding>,
) {
    // Build maps of external defined symbols by name
    let old_map: BTreeMap<&str, &SymbolSnapshot> = old
        .iter()
        .filter(|s| s.external && !s.undefined)
        .map(|s| (s.name.as_str(), s))
        .collect();
    let new_map: BTreeMap<&str, &SymbolSnapshot> = new
        .iter()
        .filter(|s| s.external && !s.undefined)
        .map(|s| (s.name.as_str(), s))
        .collect();

    // Removed symbols
    let removed: Vec<&str> = old_map
        .keys()
        .filter(|k| !new_map.contains_key(*k))
        .copied()
        .collect();
    if removed.len() > 20 {
        findings.push(DiffFinding {
            domain: DiffDomain::Symbols,
            severity: ChangeSeverity::Warning,
            arch: arch.clone(),
            message: format!("{} external defined symbols removed", removed.len()),
        });
    } else {
        for name in &removed {
            findings.push(DiffFinding {
                domain: DiffDomain::Symbols,
                severity: ChangeSeverity::Warning,
                arch: arch.clone(),
                message: format!("external defined symbol removed: {name}"),
            });
        }
    }

    // Added symbols
    let added: Vec<&str> = new_map
        .keys()
        .filter(|k| !old_map.contains_key(*k))
        .copied()
        .collect();
    if added.len() > 20 {
        findings.push(DiffFinding {
            domain: DiffDomain::Symbols,
            severity: ChangeSeverity::Info,
            arch: arch.clone(),
            message: format!("{} external defined symbols added", added.len()),
        });
    } else {
        for name in &added {
            findings.push(DiffFinding {
                domain: DiffDomain::Symbols,
                severity: ChangeSeverity::Info,
                arch: arch.clone(),
                message: format!("external defined symbol added: {name}"),
            });
        }
    }

    // Address changes for shared symbols
    for (name, old_sym) in &old_map {
        if let Some(new_sym) = new_map.get(name) {
            if old_sym.value != new_sym.value && old_sym.value != 0 && new_sym.value != 0 {
                findings.push(DiffFinding {
                    domain: DiffDomain::Symbols,
                    severity: ChangeSeverity::Info,
                    arch: arch.clone(),
                    message: format!(
                        "symbol {name} address changed: {:#x} -> {:#x}",
                        old_sym.value, new_sym.value
                    ),
                });
            }
        }
    }
}

fn diff_exports(
    old: &[ExportSnapshot],
    new: &[ExportSnapshot],
    arch: &Option<String>,
    findings: &mut Vec<DiffFinding>,
) {
    let old_map: BTreeMap<&str, &ExportSnapshot> = old.iter().map(|e| (e.name.as_str(), e)).collect();
    let new_map: BTreeMap<&str, &ExportSnapshot> = new.iter().map(|e| (e.name.as_str(), e)).collect();

    for name in old_map.keys() {
        if !new_map.contains_key(name) {
            findings.push(DiffFinding {
                domain: DiffDomain::Exports,
                severity: ChangeSeverity::Breaking,
                arch: arch.clone(),
                message: format!("export removed: {name}"),
            });
        }
    }
    for name in new_map.keys() {
        if !old_map.contains_key(name) {
            findings.push(DiffFinding {
                domain: DiffDomain::Exports,
                severity: ChangeSeverity::Info,
                arch: arch.clone(),
                message: format!("export added: {name}"),
            });
        }
    }

    // Check for kind or weakness changes on shared exports
    for (name, old_exp) in &old_map {
        if let Some(new_exp) = new_map.get(name) {
            if old_exp.kind != new_exp.kind {
                findings.push(DiffFinding {
                    domain: DiffDomain::Exports,
                    severity: ChangeSeverity::Warning,
                    arch: arch.clone(),
                    message: format!(
                        "export {name} changed: {} -> {}",
                        describe_export_kind(&old_exp.kind),
                        describe_export_kind(&new_exp.kind)
                    ),
                });
            }
            if old_exp.weak != new_exp.weak {
                findings.push(DiffFinding {
                    domain: DiffDomain::Exports,
                    severity: ChangeSeverity::Warning,
                    arch: arch.clone(),
                    message: format!(
                        "export {name} weakness changed: {} -> {}",
                        old_exp.weak, new_exp.weak
                    ),
                });
            }
        }
    }
}

fn diff_imports(
    old: &[ImportSnapshot],
    new: &[ImportSnapshot],
    arch: &Option<String>,
    findings: &mut Vec<DiffFinding>,
) {
    let old_by_name = imports_by_name(old);
    let new_by_name = imports_by_name(new);
    let old_names: BTreeSet<&str> = old_by_name.keys().copied().collect();
    let new_names: BTreeSet<&str> = new_by_name.keys().copied().collect();

    for removed in old_names.difference(&new_names) {
        findings.push(DiffFinding {
            domain: DiffDomain::Imports,
            severity: ChangeSeverity::Info,
            arch: arch.clone(),
            message: format!("import removed: {removed}"),
        });
    }
    for added in new_names.difference(&old_names) {
        findings.push(DiffFinding {
            domain: DiffDomain::Imports,
            severity: ChangeSeverity::Info,
            arch: arch.clone(),
            message: format!("import added: {added}"),
        });
    }

    for name in old_names.intersection(&new_names) {
        let old_imports = old_by_name.get(name).expect("name present in old");
        let new_imports = new_by_name.get(name).expect("name present in new");
        let old_variants: BTreeSet<(i32, bool)> = old_imports
            .iter()
            .map(|import| (import.lib_ordinal, import.weak))
            .collect();
        let new_variants: BTreeSet<(i32, bool)> = new_imports
            .iter()
            .map(|import| (import.lib_ordinal, import.weak))
            .collect();

        if old_variants != new_variants {
            findings.push(DiffFinding {
                domain: DiffDomain::Imports,
                severity: ChangeSeverity::Warning,
                arch: arch.clone(),
                message: format!(
                    "import {name} variants changed: {} -> {}",
                    describe_import_variants(old_imports),
                    describe_import_variants(new_imports)
                ),
            });
        }
    }
}

fn diff_fixups(
    old: &[FixupSnapshot],
    new: &[FixupSnapshot],
    arch: &Option<String>,
    findings: &mut Vec<DiffFinding>,
) {
    let old_map: BTreeMap<(usize, u64), &FixupSnapshot> = old
        .iter()
        .map(|fixup| ((fixup.segment_index, fixup.segment_offset), fixup))
        .collect();
    let new_map: BTreeMap<(usize, u64), &FixupSnapshot> = new
        .iter()
        .map(|fixup| ((fixup.segment_index, fixup.segment_offset), fixup))
        .collect();

    for key in old_map.keys() {
        if !new_map.contains_key(key) {
            findings.push(DiffFinding {
                domain: DiffDomain::Fixups,
                severity: ChangeSeverity::Breaking,
                arch: arch.clone(),
                message: format!(
                    "fixup removed at segment {} offset {:#x}",
                    key.0, key.1
                ),
            });
        }
    }
    for key in new_map.keys() {
        if !old_map.contains_key(key) {
            findings.push(DiffFinding {
                domain: DiffDomain::Fixups,
                severity: ChangeSeverity::Info,
                arch: arch.clone(),
                message: format!("fixup added at segment {} offset {:#x}", key.0, key.1),
            });
        }
    }

    for key in old_map.keys().filter(|key| new_map.contains_key(key)) {
        let old_fixup = old_map.get(key).copied().unwrap();
        let new_fixup = new_map.get(key).copied().unwrap();
        if old_fixup.kind != new_fixup.kind {
            findings.push(DiffFinding {
                domain: DiffDomain::Fixups,
                severity: ChangeSeverity::Warning,
                arch: arch.clone(),
                message: format!(
                    "fixup at segment {} offset {:#x} changed: {:?} -> {:?}",
                    key.0, key.1, old_fixup.kind, new_fixup.kind
                ),
            });
        }
    }
}

fn diff_objc(
    old: &ObjCSnapshot,
    new: &ObjCSnapshot,
    arch: &Option<String>,
    findings: &mut Vec<DiffFinding>,
) {
    // Classes
    let old_classes: BTreeSet<&str> = old.classes.iter().map(|c| c.name.as_str()).collect();
    let new_classes: BTreeSet<&str> = new.classes.iter().map(|c| c.name.as_str()).collect();

    for removed in old_classes.difference(&new_classes) {
        findings.push(DiffFinding {
            domain: DiffDomain::ObjC,
            severity: ChangeSeverity::Breaking,
            arch: arch.clone(),
            message: format!("ObjC class removed: {removed}"),
        });
    }
    for added in new_classes.difference(&old_classes) {
        findings.push(DiffFinding {
            domain: DiffDomain::ObjC,
            severity: ChangeSeverity::Info,
            arch: arch.clone(),
            message: format!("ObjC class added: {added}"),
        });
    }

    // For shared classes, compare instance and class methods (name + type encoding)
    for name in old_classes.intersection(&new_classes) {
        let oc = old.classes.iter().find(|c| c.name == *name).unwrap();
        let nc = new.classes.iter().find(|c| c.name == *name).unwrap();
        if oc.superclass != nc.superclass {
            findings.push(DiffFinding {
                domain: DiffDomain::ObjC,
                severity: ChangeSeverity::Warning,
                arch: arch.clone(),
                message: format!(
                    "ObjC class {name} superclass changed: {} -> {}",
                    oc.superclass.as_deref().unwrap_or("<none>"),
                    nc.superclass.as_deref().unwrap_or("<none>")
                ),
            });
        }
        if oc.is_swift != nc.is_swift {
            findings.push(DiffFinding {
                domain: DiffDomain::ObjC,
                severity: ChangeSeverity::Warning,
                arch: arch.clone(),
                message: format!("ObjC class {name} Swift marker changed: {} -> {}", oc.is_swift, nc.is_swift),
            });
        }
        diff_string_set(
            DiffDomain::ObjC,
            ChangeSeverity::Info,
            ChangeSeverity::Warning,
            arch,
            findings,
            oc.properties.iter().map(|value| value.as_str()).collect(),
            nc.properties.iter().map(|value| value.as_str()).collect(),
            |value, removed| {
                format!(
                    "ObjC class {name} property {}: {value}",
                    if removed { "removed" } else { "added" }
                )
            },
        );
        diff_string_set(
            DiffDomain::ObjC,
            ChangeSeverity::Info,
            ChangeSeverity::Warning,
            arch,
            findings,
            oc.ivars.iter().map(|value| value.as_str()).collect(),
            nc.ivars.iter().map(|value| value.as_str()).collect(),
            |value, removed| {
                format!(
                    "ObjC class {name} ivar {}: {value}",
                    if removed { "removed" } else { "added" }
                )
            },
        );
        diff_string_set(
            DiffDomain::ObjC,
            ChangeSeverity::Info,
            ChangeSeverity::Warning,
            arch,
            findings,
            oc.protocols.iter().map(|value| value.as_str()).collect(),
            nc.protocols.iter().map(|value| value.as_str()).collect(),
            |value, removed| {
                format!(
                    "ObjC class {name} protocol {}: {value}",
                    if removed { "removed" } else { "added" }
                )
            },
        );
        diff_objc_methods(
            name,
            '-',
            &oc.instance_methods,
            &nc.instance_methods,
            arch,
            findings,
        );
        diff_objc_methods(
            name,
            '+',
            &oc.class_methods,
            &nc.class_methods,
            arch,
            findings,
        );
    }

    // Categories
    let old_cats: BTreeSet<(&str, &str)> = old
        .categories
        .iter()
        .map(|c| (c.name.as_str(), c.class_name.as_str()))
        .collect();
    let new_cats: BTreeSet<(&str, &str)> = new
        .categories
        .iter()
        .map(|c| (c.name.as_str(), c.class_name.as_str()))
        .collect();

    for (cat, cls) in old_cats.difference(&new_cats) {
        findings.push(DiffFinding {
            domain: DiffDomain::ObjC,
            severity: ChangeSeverity::Warning,
            arch: arch.clone(),
            message: format!("ObjC category removed: {cat} on {cls}"),
        });
    }
    for (cat, cls) in new_cats.difference(&old_cats) {
        findings.push(DiffFinding {
            domain: DiffDomain::ObjC,
            severity: ChangeSeverity::Info,
            arch: arch.clone(),
            message: format!("ObjC category added: {cat} on {cls}"),
        });
    }

    // For shared categories, compare instance and class methods
    for (cat, cls) in old_cats.intersection(&new_cats) {
        let oc = old
            .categories
            .iter()
            .find(|c| c.name == *cat && c.class_name == *cls)
            .unwrap();
        let nc = new
            .categories
            .iter()
            .find(|c| c.name == *cat && c.class_name == *cls)
            .unwrap();
        let label = format!("{cat}({cls})");
        diff_string_set(
            DiffDomain::ObjC,
            ChangeSeverity::Info,
            ChangeSeverity::Warning,
            arch,
            findings,
            oc.protocols.iter().map(|value| value.as_str()).collect(),
            nc.protocols.iter().map(|value| value.as_str()).collect(),
            |value, removed| {
                format!(
                    "ObjC category {cat} on {cls} protocol {}: {value}",
                    if removed { "removed" } else { "added" }
                )
            },
        );
        diff_objc_methods(
            &label,
            '-',
            &oc.instance_methods,
            &nc.instance_methods,
            arch,
            findings,
        );
        diff_objc_methods(
            &label,
            '+',
            &oc.class_methods,
            &nc.class_methods,
            arch,
            findings,
        );
    }

    // Protocols
    let old_protos: BTreeSet<&str> = old.protocols.iter().map(|p| p.name.as_str()).collect();
    let new_protos: BTreeSet<&str> = new.protocols.iter().map(|p| p.name.as_str()).collect();

    for removed in old_protos.difference(&new_protos) {
        findings.push(DiffFinding {
            domain: DiffDomain::ObjC,
            severity: ChangeSeverity::Warning,
            arch: arch.clone(),
            message: format!("ObjC protocol removed: {removed}"),
        });
    }
    for added in new_protos.difference(&old_protos) {
        findings.push(DiffFinding {
            domain: DiffDomain::ObjC,
            severity: ChangeSeverity::Info,
            arch: arch.clone(),
            message: format!("ObjC protocol added: {added}"),
        });
    }

    // For shared protocols, compare required and optional method sets
    for name in old_protos.intersection(&new_protos) {
        let op = old.protocols.iter().find(|p| p.name == *name).unwrap();
        let np = new.protocols.iter().find(|p| p.name == *name).unwrap();
        diff_string_set(
            DiffDomain::ObjC,
            ChangeSeverity::Info,
            ChangeSeverity::Warning,
            arch,
            findings,
            op.adopted_protocols
                .iter()
                .map(|value| value.as_str())
                .collect(),
            np.adopted_protocols
                .iter()
                .map(|value| value.as_str())
                .collect(),
            |value, removed| {
                format!(
                    "protocol {name}: adopted protocol {}: {value}",
                    if removed { "removed" } else { "added" }
                )
            },
        );
        diff_protocol_selectors(
            name,
            "required-",
            &op.instance_methods,
            &np.instance_methods,
            arch,
            findings,
        );
        diff_protocol_selectors(
            name,
            "required+",
            &op.class_methods,
            &np.class_methods,
            arch,
            findings,
        );
        diff_protocol_selectors(
            name,
            "optional-",
            &op.optional_instance_methods,
            &np.optional_instance_methods,
            arch,
            findings,
        );
        diff_protocol_selectors(
            name,
            "optional+",
            &op.optional_class_methods,
            &np.optional_class_methods,
            arch,
            findings,
        );
    }
}

fn diff_codesign(
    old: Option<&CodesignSnapshot>,
    new: Option<&CodesignSnapshot>,
    arch: &Option<String>,
    findings: &mut Vec<DiffFinding>,
) {
    match (old, new) {
        (Some(o), Some(n)) => {
            if o.identifier != n.identifier {
                findings.push(DiffFinding {
                    domain: DiffDomain::Codesign,
                    severity: ChangeSeverity::Warning,
                    arch: arch.clone(),
                    message: format!(
                        "identifier changed: {} -> {}",
                        o.identifier.as_deref().unwrap_or("none"),
                        n.identifier.as_deref().unwrap_or("none")
                    ),
                });
            }
            if o.team_id != n.team_id {
                findings.push(DiffFinding {
                    domain: DiffDomain::Codesign,
                    severity: ChangeSeverity::Warning,
                    arch: arch.clone(),
                    message: format!(
                        "team ID changed: {} -> {}",
                        o.team_id.as_deref().unwrap_or("none"),
                        n.team_id.as_deref().unwrap_or("none")
                    ),
                });
            }
            if o.hash_type != n.hash_type {
                findings.push(DiffFinding {
                    domain: DiffDomain::Codesign,
                    severity: ChangeSeverity::Info,
                    arch: arch.clone(),
                    message: format!("hash type changed: {} -> {}", o.hash_type, n.hash_type),
                });
            }
            if o.has_entitlements != n.has_entitlements {
                findings.push(DiffFinding {
                    domain: DiffDomain::Codesign,
                    severity: ChangeSeverity::Warning,
                    arch: arch.clone(),
                    message: format!(
                        "entitlements presence changed: {} -> {}",
                        o.has_entitlements, n.has_entitlements
                    ),
                });
            }
            if o.has_der_entitlements != n.has_der_entitlements {
                findings.push(DiffFinding {
                    domain: DiffDomain::Codesign,
                    severity: ChangeSeverity::Warning,
                    arch: arch.clone(),
                    message: format!(
                        "DER entitlements presence changed: {} -> {}",
                        o.has_der_entitlements, n.has_der_entitlements
                    ),
                });
            }
            if o.has_cms_signature != n.has_cms_signature {
                findings.push(DiffFinding {
                    domain: DiffDomain::Codesign,
                    severity: ChangeSeverity::Warning,
                    arch: arch.clone(),
                    message: format!(
                        "CMS signature presence changed: {} -> {}",
                        o.has_cms_signature, n.has_cms_signature
                    ),
                });
            }
            // Compare entitlements XML when both builds have entitlements
            if o.has_entitlements && n.has_entitlements {
                if let (Some(ox), Some(nx)) = (&o.entitlements_xml, &n.entitlements_xml) {
                    if ox != nx {
                        findings.push(DiffFinding {
                            domain: DiffDomain::Codesign,
                            severity: ChangeSeverity::Warning,
                            arch: arch.clone(),
                            message: "entitlements content changed".to_string(),
                        });
                    }
                } else if o.entitlements_xml != n.entitlements_xml {
                    findings.push(DiffFinding {
                        domain: DiffDomain::Codesign,
                        severity: ChangeSeverity::Warning,
                        arch: arch.clone(),
                        message: "entitlements representation changed".to_string(),
                    });
                }
            }
        }
        (Some(_), None) => {
            findings.push(DiffFinding {
                domain: DiffDomain::Codesign,
                severity: ChangeSeverity::Breaking,
                arch: arch.clone(),
                message: "code signature removed".to_string(),
            });
        }
        (None, Some(_)) => {
            findings.push(DiffFinding {
                domain: DiffDomain::Codesign,
                severity: ChangeSeverity::Info,
                arch: arch.clone(),
                message: "code signature added".to_string(),
            });
        }
        (None, None) => {}
    }
}

fn diff_analysis_issues(
    old: &[AnalysisIssueSnapshot],
    new: &[AnalysisIssueSnapshot],
    arch: &Option<String>,
    findings: &mut Vec<DiffFinding>,
) {
    let old_counts = count_items(old.iter().cloned());
    let new_counts = count_items(new.iter().cloned());

    for (issue, added) in diff_counts(&old_counts, &new_counts) {
        findings.push(DiffFinding {
            domain: DiffDomain::Analysis,
            severity: ChangeSeverity::Warning,
            arch: arch.clone(),
            message: format!(
                "new analysis issue in {}: {}{}",
                issue.component,
                issue.message,
                format_count_suffix(added),
            ),
        });
    }

    for (issue, resolved) in diff_counts(&new_counts, &old_counts) {
        findings.push(DiffFinding {
            domain: DiffDomain::Analysis,
            severity: ChangeSeverity::Info,
            arch: arch.clone(),
            message: format!(
                "analysis issue resolved in {}: {}{}",
                issue.component,
                issue.message,
                format_count_suffix(resolved),
            ),
        });
    }
}

fn diff_diagnostics(
    old: &[DiagnosticSnapshot],
    new: &[DiagnosticSnapshot],
    arch: &Option<String>,
    findings: &mut Vec<DiffFinding>,
) {
    let old_counts = count_items(old.iter().cloned());
    let new_counts = count_items(new.iter().cloned());

    for (diag, added) in diff_counts(&old_counts, &new_counts) {
        let sev = match diag.severity.as_str() {
            "error" => ChangeSeverity::Warning,
            _ => ChangeSeverity::Info,
        };
        findings.push(DiffFinding {
            domain: DiffDomain::Validation,
            severity: sev,
            arch: arch.clone(),
            message: format!(
                "new validation finding {}: {}{}",
                diag.code,
                format_diagnostic_summary(&diag),
                format_count_suffix(added),
            ),
        });
    }

    for (diag, resolved) in diff_counts(&new_counts, &old_counts) {
        findings.push(DiffFinding {
            domain: DiffDomain::Validation,
            severity: ChangeSeverity::Info,
            arch: arch.clone(),
            message: format!(
                "validation finding {} resolved: {}{}",
                diag.code,
                format_diagnostic_summary(&diag),
                format_count_suffix(resolved),
            ),
        });
    }
}

fn count_items<T>(items: impl Iterator<Item = T>) -> BTreeMap<T, usize>
where
    T: Ord,
{
    let mut map = BTreeMap::new();
    for item in items {
        *map.entry(item).or_insert(0) += 1;
    }
    map
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct LoadCommandFingerprint {
    name: String,
    summary: String,
    fileset_entry: Option<FilesetEntrySnapshot>,
}

fn load_command_fingerprint(lc: &LoadCommandSnapshot) -> LoadCommandFingerprint {
    LoadCommandFingerprint {
        name: lc.name.clone(),
        summary: lc.summary.clone(),
        fileset_entry: lc.fileset_entry.clone(),
    }
}

fn describe_load_command(cmd: &LoadCommandFingerprint) -> String {
    if cmd.name == "LC_FILESET_ENTRY" {
        if let Some(entry) = cmd.fileset_entry.as_ref() {
            return format!(
                "{} {} vm_addr={:#x} file_offset={:#x}",
                cmd.name, entry.entry_id, entry.vm_addr, entry.file_offset
            );
        }
    }

    if cmd.summary.is_empty() {
        cmd.name.clone()
    } else {
        format!("{} {}", cmd.name, cmd.summary)
    }
}

fn describe_export_kind(kind: &ExportKindSnapshot) -> String {
    match kind {
        ExportKindSnapshot::Regular { address } => format!("regular@{address:#x}"),
        ExportKindSnapshot::ThreadLocal { address } => format!("thread-local@{address:#x}"),
        ExportKindSnapshot::Absolute { address } => format!("absolute@{address:#x}"),
        ExportKindSnapshot::Reexport { ordinal, name } => {
            format!("reexport ordinal={ordinal} name={}", name.as_deref().unwrap_or("<none>"))
        }
        ExportKindSnapshot::StubAndResolver {
            stub_offset,
            resolver_offset,
        } => format!(
            "stub-and-resolver stub={stub_offset:#x} resolver={resolver_offset:#x}"
        ),
    }
}

fn imports_by_name<'a>(imports: &'a [ImportSnapshot]) -> BTreeMap<&'a str, Vec<&'a ImportSnapshot>> {
    let mut map: BTreeMap<&str, Vec<&ImportSnapshot>> = BTreeMap::new();
    for import in imports {
        map.entry(import.name.as_str()).or_default().push(import);
    }
    for variants in map.values_mut() {
        variants.sort_by(|left, right| {
            left.lib_ordinal
                .cmp(&right.lib_ordinal)
                .then(left.weak.cmp(&right.weak))
        });
    }
    map
}

fn describe_import_variants(imports: &[&ImportSnapshot]) -> String {
    imports
        .iter()
        .map(|import| format!("ordinal={} weak={}", import.lib_ordinal, import.weak))
        .collect::<Vec<_>>()
        .join(", ")
}

fn diff_counts<T>(baseline: &BTreeMap<T, usize>, candidate: &BTreeMap<T, usize>) -> Vec<(T, usize)>
where
    T: Clone + Ord,
{
    candidate
        .iter()
        .filter_map(|(item, candidate_count)| {
            let baseline_count = baseline.get(item).copied().unwrap_or(0);
            (candidate_count > &baseline_count)
                .then(|| (item.clone(), candidate_count - baseline_count))
        })
        .collect()
}

fn format_diagnostic_summary(diag: &DiagnosticSnapshot) -> String {
    let mut summary = format!("{} ({})", diag.message, diag.severity);
    if !diag.spans.is_empty() {
        let spans = diag
            .spans
            .iter()
            .map(format_span_summary)
            .collect::<Vec<_>>()
            .join(", ");
        summary.push_str(" @ ");
        summary.push_str(&spans);
    }
    summary
}

fn format_span_summary(span: &DiagnosticSpanSnapshot) -> String {
    match &span.label {
        Some(label) => format!("{label} {:#x}+{:#x}", span.offset, span.size),
        None => format!("{:#x}+{:#x}", span.offset, span.size),
    }
}

fn format_count_suffix(count: usize) -> String {
    if count > 1 {
        format!(" ({count} occurrences)")
    } else {
        String::new()
    }
}

fn diff_string_set<F>(
    domain: DiffDomain,
    add_severity: ChangeSeverity,
    remove_severity: ChangeSeverity,
    arch: &Option<String>,
    findings: &mut Vec<DiffFinding>,
    old: BTreeSet<&str>,
    new: BTreeSet<&str>,
    mut message: F,
) where
    F: FnMut(&str, bool) -> String,
{
    for value in old.difference(&new) {
        findings.push(DiffFinding {
            domain,
            severity: remove_severity,
            arch: arch.clone(),
            message: message(value, true),
        });
    }
    for value in new.difference(&old) {
        findings.push(DiffFinding {
            domain,
            severity: add_severity,
            arch: arch.clone(),
            message: message(value, false),
        });
    }
}

/// Diff two method lists (with type encoding) for a class or category.
/// `prefix` is `-` for instance methods or `+` for class methods.
fn diff_objc_methods(
    label: &str,
    prefix: char,
    old: &[ObjCMethodSnapshot],
    new: &[ObjCMethodSnapshot],
    arch: &Option<String>,
    findings: &mut Vec<DiffFinding>,
) {
    let old_map: BTreeMap<&str, &str> = old
        .iter()
        .map(|m| (m.name.as_str(), m.type_encoding.as_str()))
        .collect();
    let new_map: BTreeMap<&str, &str> = new
        .iter()
        .map(|m| (m.name.as_str(), m.type_encoding.as_str()))
        .collect();

    for sel in old_map.keys() {
        if !new_map.contains_key(sel) {
            findings.push(DiffFinding {
                domain: DiffDomain::ObjC,
                severity: ChangeSeverity::Warning,
                arch: arch.clone(),
                message: format!("{label}: {prefix}{sel} removed"),
            });
        }
    }
    for sel in new_map.keys() {
        if !old_map.contains_key(sel) {
            findings.push(DiffFinding {
                domain: DiffDomain::ObjC,
                severity: ChangeSeverity::Info,
                arch: arch.clone(),
                message: format!("{label}: {prefix}{sel} added"),
            });
        }
    }
    for (sel, old_enc) in &old_map {
        if let Some(new_enc) = new_map.get(sel) {
            if !old_enc.is_empty() && !new_enc.is_empty() && old_enc != new_enc {
                findings.push(DiffFinding {
                    domain: DiffDomain::ObjC,
                    severity: ChangeSeverity::Warning,
                    arch: arch.clone(),
                    message: format!(
                        "{label}: {prefix}{sel} type encoding changed: {old_enc} -> {new_enc}"
                    ),
                });
            }
        }
    }
}

/// Diff two protocol selector lists (plain strings, no type encoding).
fn diff_protocol_selectors(
    protocol: &str,
    method_kind: &str,
    old: &[String],
    new: &[String],
    arch: &Option<String>,
    findings: &mut Vec<DiffFinding>,
) {
    let old_set: BTreeSet<&str> = old.iter().map(|s| s.as_str()).collect();
    let new_set: BTreeSet<&str> = new.iter().map(|s| s.as_str()).collect();
    for sel in old_set.difference(&new_set) {
        findings.push(DiffFinding {
            domain: DiffDomain::ObjC,
            severity: ChangeSeverity::Warning,
            arch: arch.clone(),
            message: format!("protocol {protocol}: {method_kind} method removed: {sel}"),
        });
    }
    for sel in new_set.difference(&old_set) {
        findings.push(DiffFinding {
            domain: DiffDomain::ObjC,
            severity: ChangeSeverity::Info,
            arch: arch.clone(),
            message: format!("protocol {protocol}: {method_kind} method added: {sel}"),
        });
    }
}
