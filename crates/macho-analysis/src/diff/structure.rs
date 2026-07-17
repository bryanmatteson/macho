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
        let (Some(o), Some(n)) = (
            old.iter().find(|s| s.name == *name),
            new.iter().find(|s| s.name == *name),
        ) else {
            continue;
        };

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
