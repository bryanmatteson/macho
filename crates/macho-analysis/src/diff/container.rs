fn diff_container_identity(
    old: &crate::ContainerIdentity,
    new: &crate::ContainerIdentity,
    findings: &mut Vec<DiffFinding>,
) {
    if old.format != new.format {
        findings.push(DiffFinding {
            domain: DiffDomain::Container,
            severity: ChangeSeverity::Warning,
            arch: None,
            message: format!(
                "container format changed: {} -> {}",
                old.format, new.format
            ),
        });
    }
    if old.slice_count != new.slice_count {
        findings.push(DiffFinding {
            domain: DiffDomain::Container,
            severity: ChangeSeverity::Breaking,
            arch: None,
            message: format!(
                "container slice count changed: {} -> {}",
                old.slice_count, new.slice_count
            ),
        });
    }
}
