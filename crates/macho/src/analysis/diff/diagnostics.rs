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
            format!(
                "reexport ordinal={ordinal} name={}",
                name.as_deref().unwrap_or("<none>")
            )
        }
        ExportKindSnapshot::StubAndResolver {
            stub_offset,
            resolver_offset,
        } => format!("stub-and-resolver stub={stub_offset:#x} resolver={resolver_offset:#x}"),
        ExportKindSnapshot::Unknown => "unknown".to_owned(),
    }
}

fn imports_by_name(imports: &[ImportRecord]) -> BTreeMap<&str, Vec<&ImportRecord>> {
    let mut map: BTreeMap<&str, Vec<&ImportRecord>> = BTreeMap::new();
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

fn describe_import_variants(imports: &[&ImportRecord]) -> String {
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
    values: (BTreeSet<&str>, BTreeSet<&str>),
    mut message: F,
) where
    F: FnMut(&str, bool) -> String,
{
    let (old, new) = values;
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
            if old_enc != new_enc {
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

fn diff_objc_properties(
    subject: &str,
    old: &[ObjCPropertySnapshot],
    new: &[ObjCPropertySnapshot],
    arch: &Option<String>,
    findings: &mut Vec<DiffFinding>,
) {
    let old_map: BTreeMap<(bool, &str), &str> = old
        .iter()
        .map(|property| {
            (
                (property.is_class, property.name.as_str()),
                property.attributes.as_str(),
            )
        })
        .collect();
    let new_map: BTreeMap<(bool, &str), &str> = new
        .iter()
        .map(|property| {
            (
                (property.is_class, property.name.as_str()),
                property.attributes.as_str(),
            )
        })
        .collect();

    for name in old_map.keys() {
        if !new_map.contains_key(name) {
            findings.push(DiffFinding {
                domain: DiffDomain::ObjC,
                severity: ChangeSeverity::Warning,
                arch: arch.clone(),
                message: format!("{subject} {} removed: {}", property_label(name.0), name.1),
            });
        }
    }

    for name in new_map.keys() {
        if !old_map.contains_key(name) {
            findings.push(DiffFinding {
                domain: DiffDomain::ObjC,
                severity: ChangeSeverity::Info,
                arch: arch.clone(),
                message: format!("{subject} {} added: {}", property_label(name.0), name.1),
            });
        }
    }

    for (name, old_attrs) in &old_map {
        if let Some(new_attrs) = new_map.get(name) {
            if old_attrs != new_attrs {
                findings.push(DiffFinding {
                    domain: DiffDomain::ObjC,
                    severity: ChangeSeverity::Warning,
                    arch: arch.clone(),
                    message: format!(
                        "{subject} {} changed: {} attributes: {old_attrs} -> {new_attrs}",
                        property_label(name.0),
                        name.1,
                    ),
                });
            }
        }
    }
}

fn property_label(is_class: bool) -> &'static str {
    if is_class {
        "class property"
    } else {
        "property"
    }
}
