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
    let old_map: BTreeMap<&str, &ExportSnapshot> =
        old.iter().map(|e| (e.name.as_str(), e)).collect();
    let new_map: BTreeMap<&str, &ExportSnapshot> =
        new.iter().map(|e| (e.name.as_str(), e)).collect();

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
    old: &[ImportRecord],
    new: &[ImportRecord],
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
                message: format!("fixup removed at segment {} offset {:#x}", key.0, key.1),
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

    for (key, old_fixup) in old_map.iter() {
        let Some(new_fixup) = new_map.get(key) else {
            continue;
        };
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
