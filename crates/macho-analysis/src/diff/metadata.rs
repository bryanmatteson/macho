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
        let (Some(oc), Some(nc)) = (
            old.classes.iter().find(|c| c.name == *name),
            new.classes.iter().find(|c| c.name == *name),
        ) else {
            continue;
        };
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
                message: format!(
                    "ObjC class {name} Swift marker changed: {} -> {}",
                    oc.is_swift, nc.is_swift
                ),
            });
        }
        diff_objc_properties(
            &format!("ObjC class {name}"),
            &oc.properties,
            &nc.properties,
            arch,
            findings,
        );
        diff_string_set(
            DiffDomain::ObjC,
            ChangeSeverity::Info,
            ChangeSeverity::Warning,
            arch,
            findings,
            (
                oc.ivars.iter().map(|value| value.as_str()).collect(),
                nc.ivars.iter().map(|value| value.as_str()).collect(),
            ),
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
            (
                oc.protocols.iter().map(|value| value.as_str()).collect(),
                nc.protocols.iter().map(|value| value.as_str()).collect(),
            ),
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
        let (Some(oc), Some(nc)) = (
            old.categories
                .iter()
                .find(|c| c.name == *cat && c.class_name == *cls),
            new.categories
                .iter()
                .find(|c| c.name == *cat && c.class_name == *cls),
        ) else {
            continue;
        };
        let label = format!("{cat}({cls})");
        diff_string_set(
            DiffDomain::ObjC,
            ChangeSeverity::Info,
            ChangeSeverity::Warning,
            arch,
            findings,
            (
                oc.protocols.iter().map(|value| value.as_str()).collect(),
                nc.protocols.iter().map(|value| value.as_str()).collect(),
            ),
            |value, removed| {
                format!(
                    "ObjC category {cat} on {cls} protocol {}: {value}",
                    if removed { "removed" } else { "added" }
                )
            },
        );
        diff_objc_properties(
            &format!("ObjC category {cat} on {cls}"),
            &oc.properties,
            &nc.properties,
            arch,
            findings,
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
        let (Some(op), Some(np)) = (
            old.protocols.iter().find(|p| p.name == *name),
            new.protocols.iter().find(|p| p.name == *name),
        ) else {
            continue;
        };
        diff_string_set(
            DiffDomain::ObjC,
            ChangeSeverity::Info,
            ChangeSeverity::Warning,
            arch,
            findings,
            (
                op.adopted_protocols
                    .iter()
                    .map(|value| value.as_str())
                    .collect(),
                np.adopted_protocols
                    .iter()
                    .map(|value| value.as_str())
                    .collect(),
            ),
            |value, removed| {
                format!(
                    "protocol {name}: adopted protocol {}: {value}",
                    if removed { "removed" } else { "added" }
                )
            },
        );
        diff_objc_properties(
            &format!("ObjC protocol {name}"),
            &op.properties,
            &np.properties,
            arch,
            findings,
        );
        diff_objc_methods(
            &format!("protocol {name} required"),
            '-',
            &op.instance_methods,
            &np.instance_methods,
            arch,
            findings,
        );
        diff_objc_methods(
            &format!("protocol {name} required"),
            '+',
            &op.class_methods,
            &np.class_methods,
            arch,
            findings,
        );
        diff_objc_methods(
            &format!("protocol {name} optional"),
            '-',
            &op.optional_instance_methods,
            &np.optional_instance_methods,
            arch,
            findings,
        );
        diff_objc_methods(
            &format!("protocol {name} optional"),
            '+',
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
                diff_entitlement_keys(&o.entitlement_keys, &n.entitlement_keys, arch, findings);

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

                if o.entitlements_der_fingerprint != n.entitlements_der_fingerprint
                    && o.entitlements_der_fingerprint.is_some()
                    && n.entitlements_der_fingerprint.is_some()
                {
                    findings.push(DiffFinding {
                        domain: DiffDomain::Codesign,
                        severity: ChangeSeverity::Warning,
                        arch: arch.clone(),
                        message: "DER entitlements content changed".to_string(),
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

fn diff_entitlement_keys(
    old: &[String],
    new: &[String],
    arch: &Option<String>,
    findings: &mut Vec<DiffFinding>,
) {
    let old_keys: BTreeSet<&str> = old.iter().map(String::as_str).collect();
    let new_keys: BTreeSet<&str> = new.iter().map(String::as_str).collect();
    if old_keys == new_keys {
        return;
    }

    let removed: Vec<&str> = old_keys.difference(&new_keys).copied().collect();
    let added: Vec<&str> = new_keys.difference(&old_keys).copied().collect();
    let mut parts = Vec::new();
    if !removed.is_empty() {
        parts.push(format!("removed: {}", removed.join(", ")));
    }
    if !added.is_empty() {
        parts.push(format!("added: {}", added.join(", ")));
    }

    findings.push(DiffFinding {
        domain: DiffDomain::Codesign,
        severity: ChangeSeverity::Warning,
        arch: arch.clone(),
        message: format!("entitlement keys changed ({})", parts.join("; ")),
    });
}
