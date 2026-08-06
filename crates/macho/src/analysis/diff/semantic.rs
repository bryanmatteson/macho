use crate::analysis::audit::{AuditFinding, AuditReport, AuditSeverity};
use crate::analysis::report::{ObjCReport, RecoveryReport, SwiftReport};
use crate::analysis::strings::FoundString;
use crate::analysis::xref::ranges::RangeEntry;
use crate::analysis::xref::refs::Xref;
use serde_json::Value;

fn diff_objc_payload(
    old: &Value,
    new: &Value,
    arch: &Option<String>,
    findings: &mut Vec<DiffFinding>,
) -> Result<(), serde_json::Error> {
    match (
        serde_json::from_value::<ObjCReport>(old.clone()),
        serde_json::from_value::<ObjCReport>(new.clone()),
    ) {
        (Ok(old), Ok(new)) => {
            let old = objc_entities(&old)?;
            let new = objc_entities(&new)?;
            diff_entity_maps(
                &old,
                &new,
                DiffDomain::ObjC,
                "Objective-C entity",
                arch,
                findings,
            );
            Ok(())
        }
        _ => {
            // Retain the detailed comparator for legacy in-memory payloads.
            // Schema-v3 documents validate the canonical report before here.
            diff_objc(
                &serde_json::from_value(old.clone())?,
                &serde_json::from_value(new.clone())?,
                arch,
                findings,
            );
            Ok(())
        }
    }
}

fn objc_entities(
    report: &ObjCReport,
) -> Result<BTreeMap<String, (String, String)>, serde_json::Error> {
    let mut candidates = Vec::new();
    for slice in report.slices.as_slice() {
        for entity in &slice.entities {
            let mut semantic = serde_json::to_value(entity)?;
            let kind = semantic
                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or("entity");
            let payload = semantic.get("value").unwrap_or(&semantic);
            let label = payload
                .get("common")
                .and_then(|common| common.get("name"))
                .and_then(find_string_value)
                .unwrap_or_else(|| entity.common().id.to_string());
            let base = format!("{kind}:{label}");
            remove_provenance(&mut semantic);
            candidates.push((base, label, serde_json::to_string(&semantic)?));
        }
    }
    Ok(index_entity_candidates(candidates))
}

fn diff_relocations(
    old: &[RelocationSectionSnapshot],
    new: &[RelocationSectionSnapshot],
    arch: &Option<String>,
    findings: &mut Vec<DiffFinding>,
) {
    let old = old
        .iter()
        .map(|value| ((value.segment.as_str(), value.section.as_str()), value.count))
        .collect::<BTreeMap<_, _>>();
    let new = new
        .iter()
        .map(|value| ((value.segment.as_str(), value.section.as_str()), value.count))
        .collect::<BTreeMap<_, _>>();

    for section in old.keys().chain(new.keys()).copied().collect::<BTreeSet<_>>() {
        match (old.get(&section), new.get(&section)) {
            (Some(count), None) => push_semantic(
                findings,
                DiffDomain::Relocations,
                ChangeSeverity::Warning,
                arch,
                format!("removed {count} relocation(s) from {}/{}", section.0, section.1),
            ),
            (None, Some(count)) => push_semantic(
                findings,
                DiffDomain::Relocations,
                ChangeSeverity::Info,
                arch,
                format!("added {count} relocation(s) to {}/{}", section.0, section.1),
            ),
            (Some(old), Some(new)) if old != new => push_semantic(
                findings,
                DiffDomain::Relocations,
                ChangeSeverity::Warning,
                arch,
                format!(
                    "relocation count changed in {}/{}: {old} -> {new}",
                    section.0, section.1
                ),
            ),
            _ => {}
        }
    }
}

fn diff_strings(
    old: &[FoundString],
    new: &[FoundString],
    arch: &Option<String>,
    findings: &mut Vec<DiffFinding>,
) {
    let old = counted(old.iter().map(|value| value.value.clone()));
    let new = counted(new.iter().map(|value| value.value.clone()));
    diff_counted_surface(
        &old,
        &new,
        DiffDomain::Strings,
        "string",
        arch,
        findings,
    );
}

fn diff_ranges(
    old: &[RangeEntry],
    new: &[RangeEntry],
    arch: &Option<String>,
    findings: &mut Vec<DiffFinding>,
) -> Result<(), serde_json::Error> {
    let old = range_map(old)?;
    let new = range_map(new)?;
    for key in old.keys().chain(new.keys()).collect::<BTreeSet<_>>() {
        match (old.get(key), new.get(key)) {
            (Some((label, _, _, _, _)), None) => push_semantic(
                findings,
                DiffDomain::Ranges,
                ChangeSeverity::Warning,
                arch,
                format!("removed code range for {label}"),
            ),
            (None, Some((label, _, _, _, _))) => push_semantic(
                findings,
                DiffDomain::Ranges,
                ChangeSeverity::Info,
                arch,
                format!("added code range for {label}"),
            ),
            (
                Some((label, old_start, old_end, old_source, old_alt)),
                Some((_, new_start, new_end, new_source, new_alt)),
            ) if (old_start, old_end, old_source, old_alt)
                != (new_start, new_end, new_source, new_alt) =>
            {
                let old_size = old_end.saturating_sub(*old_start);
                let new_size = new_end.saturating_sub(*new_start);
                push_semantic(
                    findings,
                    DiffDomain::Ranges,
                    if old_size == new_size && old_source == new_source && old_alt == new_alt {
                        ChangeSeverity::Info
                    } else {
                        ChangeSeverity::Warning
                    },
                    arch,
                    format!(
                        "code range changed for {label}: {old_start:#x}..{old_end:#x} ({old_source}) -> {new_start:#x}..{new_end:#x} ({new_source})"
                    ),
                );
            }
            _ => {}
        }
    }
    Ok(())
}

type RangeFacts = (String, u64, u64, String, bool);

fn range_map(values: &[RangeEntry]) -> Result<BTreeMap<String, RangeFacts>, serde_json::Error> {
    let mut candidates = values
        .iter()
        .map(|range| {
            let entity = serde_json::to_value(&range.entity)?;
            let key = serde_json::to_string(&entity)?;
            let label = range_entity_label(&entity);
            let source = serde_json::to_value(range.source)?;
            Ok::<_, serde_json::Error>((
                key,
                (
                    label,
                    range.start.0,
                    range.end.0,
                    source.as_str().unwrap_or("unknown").to_owned(),
                    range.is_alt_entry,
                ),
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    candidates.sort();
    let mut occurrences = BTreeMap::<String, usize>::new();
    Ok(candidates
        .into_iter()
        .map(|(base, facts)| {
            let occurrence = occurrences.entry(base.clone()).or_default();
            let key = format!("{base}#{occurrence}");
            *occurrence += 1;
            (key, facts)
        })
        .collect())
}

fn range_entity_label(value: &Value) -> String {
    let kind = value
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("entity");
    for key in ["name", "selector", "section_name"] {
        if let Some(value) = value.get(key).and_then(Value::as_str) {
            return format!("{kind} {value}");
        }
    }
    kind.to_owned()
}

fn diff_xrefs(
    old: &[Xref],
    new: &[Xref],
    arch: &Option<String>,
    findings: &mut Vec<DiffFinding>,
) -> Result<(), serde_json::Error> {
    let old = counted(old.iter().map(xref_identity).collect::<Result<Vec<_>, _>>()?);
    let new = counted(new.iter().map(xref_identity).collect::<Result<Vec<_>, _>>()?);
    diff_counted_surface(
        &old,
        &new,
        DiffDomain::Xrefs,
        "cross-reference relationship",
        arch,
        findings,
    );
    Ok(())
}

fn xref_identity(value: &Xref) -> Result<String, serde_json::Error> {
    let target = serde_json::to_value(&value.target)?;
    let kind = serde_json::to_value(value.kind)?;
    let kind = kind.as_str().unwrap_or("unknown");
    if target.get("type").and_then(Value::as_str) == Some("internal") {
        let target = target
            .get("va")
            .and_then(address_value)
            .unwrap_or_default();
        let delta = i128::from(target) - i128::from(value.source.0);
        return Ok(format!("{kind} to internal delta {delta:+#x}"));
    }
    let name = target.get("name").and_then(Value::as_str).unwrap_or("?");
    let ordinal = target.get("ordinal").and_then(Value::as_i64).unwrap_or(0);
    Ok(format!("{kind} to import {name} (ordinal {ordinal})"))
}

fn address_value(value: &Value) -> Option<u64> {
    value.as_u64().or_else(|| {
        value
            .as_str()
            .and_then(|value| u64::from_str_radix(value.trim_start_matches("0x"), 16).ok())
    })
}

fn diff_dependencies(
    old: &DependencySnapshot,
    new: &DependencySnapshot,
    arch: &Option<String>,
    findings: &mut Vec<DiffFinding>,
) {
    field_change(
        old.install_name.as_deref(),
        new.install_name.as_deref(),
        "install name",
        DiffDomain::Dependencies,
        ChangeSeverity::Breaking,
        arch,
        findings,
    );
    for (label, old, new) in [
        ("linked dylib count", old.dylib_count, new.dylib_count),
        ("import count", old.import_count, new.import_count),
        ("export count", old.export_count, new.export_count),
    ] {
        if old != new {
            push_semantic(
                findings,
                DiffDomain::Dependencies,
                ChangeSeverity::Warning,
                arch,
                format!("{label} changed: {old} -> {new}"),
            );
        }
    }
}

fn diff_audit(
    old: &AuditReport,
    new: &AuditReport,
    arch: &Option<String>,
    findings: &mut Vec<DiffFinding>,
) -> Result<(), serde_json::Error> {
    let old = audit_by_rule(&old.findings)?;
    let new = audit_by_rule(&new.findings)?;
    for rule in old.keys().chain(new.keys()).collect::<BTreeSet<_>>() {
        let old = old.get(rule).map(Vec::as_slice).unwrap_or_default();
        let new = new.get(rule).map(Vec::as_slice).unwrap_or_default();
        diff_audit_rule(rule, old, new, arch, findings);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct AuditOccurrence {
    title: String,
    severity: AuditSeverity,
    semantic: String,
}

fn audit_by_rule(
    values: &[AuditFinding],
) -> Result<BTreeMap<String, Vec<AuditOccurrence>>, serde_json::Error> {
    let mut result = BTreeMap::<String, Vec<AuditOccurrence>>::new();
    for finding in values {
        result
            .entry(finding.rule_id.clone())
            .or_default()
            .push(AuditOccurrence {
                title: finding.title.clone(),
                severity: finding.severity,
                semantic: serde_json::to_string(finding)?,
            });
    }
    for occurrences in result.values_mut() {
        occurrences.sort();
    }
    Ok(result)
}

fn diff_audit_rule(
    rule: &str,
    old: &[AuditOccurrence],
    new: &[AuditOccurrence],
    arch: &Option<String>,
    findings: &mut Vec<DiffFinding>,
) {
    let old = counted_occurrences(old);
    let new = counted_occurrences(new);
    let mut old_remaining = Vec::new();
    let mut new_remaining = Vec::new();
    for semantic in old.keys().chain(new.keys()).collect::<BTreeSet<_>>() {
        let (old_value, old_count) = old
            .get(semantic)
            .map(|(value, count)| (Some(value), *count))
            .unwrap_or((None, 0));
        let (new_value, new_count) = new
            .get(semantic)
            .map(|(value, count)| (Some(value), *count))
            .unwrap_or((None, 0));
        let matched = old_count.min(new_count);
        if let Some(value) = old_value {
            old_remaining.extend(std::iter::repeat_n(value.clone(), old_count - matched));
        }
        if let Some(value) = new_value {
            new_remaining.extend(std::iter::repeat_n(value.clone(), new_count - matched));
        }
    }
    old_remaining.sort();
    new_remaining.sort();

    let paired = old_remaining.len().min(new_remaining.len());
    for (old, new) in old_remaining.iter().zip(&new_remaining).take(paired) {
        push_semantic(
            findings,
            DiffDomain::Audit,
            audit_change_severity(new.severity),
            arch,
            format!(
                "audit finding {rule} changed: {} ({}) -> {} ({})",
                old.title, old.severity, new.title, new.severity
            ),
        );
    }
    for old in &old_remaining[paired..] {
        push_semantic(
            findings,
            DiffDomain::Audit,
            ChangeSeverity::Info,
            arch,
            format!("resolved audit finding {rule}: {}", old.title),
        );
    }
    for new in &new_remaining[paired..] {
        push_semantic(
            findings,
            DiffDomain::Audit,
            audit_change_severity(new.severity),
            arch,
            format!("new audit finding {rule}: {}", new.title),
        );
    }
}

fn counted_occurrences(
    values: &[AuditOccurrence],
) -> BTreeMap<String, (AuditOccurrence, usize)> {
    values
        .iter()
        .cloned()
        .fold(BTreeMap::new(), |mut result, value| {
            let entry = result
                .entry(value.semantic.clone())
                .or_insert_with(|| (value, 0));
            entry.1 += 1;
            result
        })
}

fn audit_change_severity(severity: AuditSeverity) -> ChangeSeverity {
    match severity {
        AuditSeverity::Info => ChangeSeverity::Info,
        AuditSeverity::Warning => ChangeSeverity::Warning,
        AuditSeverity::Error | AuditSeverity::Critical => ChangeSeverity::Breaking,
    }
}

fn diff_recovery_surface(
    old: &RecoveryReport,
    new: &RecoveryReport,
    domain: DiffDomain,
    arch: &Option<String>,
    findings: &mut Vec<DiffFinding>,
) -> Result<(), serde_json::Error> {
    let old = recovery_entities(old)?;
    let new = recovery_entities(new)?;
    diff_entity_maps(&old, &new, domain, "recovered entity", arch, findings);
    Ok(())
}

fn recovery_entities(
    report: &RecoveryReport,
) -> Result<BTreeMap<String, (String, String)>, serde_json::Error> {
    let mut candidates = Vec::new();
    for slice in report.slices.as_slice() {
        for entity in &slice.entities {
            let mut semantic = serde_json::to_value(entity)?;
            let label = semantic_entity_label(&semantic, entity.id.as_str());
            let base = if has_cross_build_identity(&semantic) {
                format!("id:{}", entity.id)
            } else {
                let mut role = semantic.get("role").cloned().unwrap_or(Value::Null);
                remove_provenance(&mut role);
                format!("slice:{}:{}", label, serde_json::to_string(&role)?)
            };
            remove_provenance(&mut semantic);
            candidates.push((base, label, serde_json::to_string(&semantic)?));
        }
    }
    Ok(index_entity_candidates(candidates))
}

fn diff_swift(
    old: &SwiftReport,
    new: &SwiftReport,
    arch: &Option<String>,
    findings: &mut Vec<DiffFinding>,
) -> Result<(), serde_json::Error> {
    let old = swift_entities(old)?;
    let new = swift_entities(new)?;
    diff_entity_maps(
        &old,
        &new,
        DiffDomain::Swift,
        "Swift declaration",
        arch,
        findings,
    );
    Ok(())
}

fn swift_entities(
    report: &SwiftReport,
) -> Result<BTreeMap<String, (String, String)>, serde_json::Error> {
    let mut candidates = Vec::new();
    for slice in report.slices.as_slice() {
        for entity in &slice.entities {
            let mut semantic = serde_json::to_value(entity)?;
            let label = semantic_entity_label(&semantic, entity.id.as_str());
            let base = if has_cross_build_identity(&semantic) {
                format!("id:{}", entity.id)
            } else {
                format!(
                    "slice:{}:{}",
                    label,
                    semantic
                        .get("kind")
                        .map(serde_json::to_string)
                        .transpose()?
                        .unwrap_or_default()
                )
            };
            remove_provenance(&mut semantic);
            candidates.push((base, label, serde_json::to_string(&semantic)?));
        }
    }
    Ok(index_entity_candidates(candidates))
}

fn diff_objc_headers(
    old: &ObjCReport,
    new: &ObjCReport,
    arch: &Option<String>,
    findings: &mut Vec<DiffFinding>,
) -> Result<(), serde_json::Error> {
    let old = objc_header_values(old)?;
    let new = objc_header_values(new)?;
    diff_objc_header_values(&old, &new, arch, findings)
}

fn diff_objc_header_values(
    old: &[Value],
    new: &[Value],
    arch: &Option<String>,
    findings: &mut Vec<DiffFinding>,
) -> Result<(), serde_json::Error> {
    let old = objc_header_declarations(old)?;
    let new = objc_header_declarations(new)?;
    diff_entity_maps(
        &old,
        &new,
        DiffDomain::ObjCHeaders,
        "Objective-C declaration",
        arch,
        findings,
    );
    Ok(())
}

fn objc_header_values(report: &ObjCReport) -> Result<Vec<Value>, serde_json::Error> {
    let mut values = Vec::new();
    for slice in report.slices.as_slice() {
        let Some(header) = &slice.header else {
            continue;
        };
        for declaration in &header.declarations {
            values.push(serde_json::to_value(declaration)?);
        }
    }
    Ok(values)
}

fn objc_header_declarations(
    values: &[Value],
) -> Result<BTreeMap<String, (String, String)>, serde_json::Error> {
    let mut candidates = Vec::new();
    for value in values {
        let mut value = value.clone();
        let fallback = serde_json::to_string(&value)?;
        let label = declaration_label(&value, &fallback);
        let kind = value
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("declaration")
            .to_owned();
        remove_provenance(&mut value);
        candidates.push((
            format!("{kind}:{label}"),
            label,
            serde_json::to_string(&value)?,
        ));
    }
    Ok(index_entity_candidates(candidates))
}

fn has_cross_build_identity(value: &Value) -> bool {
    value.get("identity_stability").and_then(Value::as_str) == Some("cross_build")
}

fn index_entity_candidates(
    mut candidates: Vec<(String, String, String)>,
) -> BTreeMap<String, (String, String)> {
    candidates.sort();
    let mut occurrences = BTreeMap::<String, usize>::new();
    candidates
        .into_iter()
        .map(|(base, label, semantic)| {
            let occurrence = occurrences.entry(base.clone()).or_default();
            let key = format!("{base}#{occurrence}");
            *occurrence += 1;
            (key, (label, semantic))
        })
        .collect()
}

fn diff_entity_maps(
    old: &BTreeMap<String, (String, String)>,
    new: &BTreeMap<String, (String, String)>,
    domain: DiffDomain,
    noun: &str,
    arch: &Option<String>,
    findings: &mut Vec<DiffFinding>,
) {
    for identity in old.keys().chain(new.keys()).collect::<BTreeSet<_>>() {
        match (old.get(identity), new.get(identity)) {
            (Some((label, _)), None) => push_semantic(
                findings,
                domain,
                ChangeSeverity::Breaking,
                arch,
                format!("removed {noun} {label}"),
            ),
            (None, Some((label, _))) => push_semantic(
                findings,
                domain,
                ChangeSeverity::Info,
                arch,
                format!("added {noun} {label}"),
            ),
            (Some((old_label, old_value)), Some((new_label, new_value)))
                if old_value != new_value =>
            {
                push_semantic(
                    findings,
                    domain,
                    ChangeSeverity::Warning,
                    arch,
                    format!("changed {noun} {old_label} -> {new_label}"),
                );
            }
            _ => {}
        }
    }
}

fn semantic_entity_label(value: &Value, fallback: &str) -> String {
    for key in ["display_name", "qualified_name", "name", "linkage"] {
        if let Some(value) = value.get(key).and_then(find_string_value) {
            return value;
        }
    }
    fallback.to_owned()
}

fn find_string_value(value: &Value) -> Option<String> {
    if let Some(value) = value.as_str() {
        return Some(value.to_owned());
    }
    match value {
        Value::Array(values) => values.iter().find_map(find_string_value),
        Value::Object(values) => ["value", "normalized", "spelling", "components"]
            .iter()
            .find_map(|key| values.get(*key).and_then(find_string_value)),
        _ => None,
    }
}

fn declaration_label(value: &Value, fallback: &str) -> String {
    let kind = value
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("declaration");
    let name = ["name", "path", "names"]
        .iter()
        .find_map(|key| value.get(*key).and_then(find_string_value))
        .unwrap_or_else(|| fallback.to_owned());
    format!("{kind} {name}")
}

fn remove_provenance(value: &mut Value) {
    match value {
        Value::Array(values) => values.iter_mut().for_each(remove_provenance),
        Value::Object(values) => {
            for key in [
                "id",
                "observation_ids",
                "evidence_ids",
                "evidence",
                "location",
                "descriptor",
                "implementation",
                "virtual_address",
                "file_offset",
                "address",
                "ordinal",
            ] {
                values.remove(key);
            }
            values.values_mut().for_each(remove_provenance);
        }
        _ => {}
    }
}

fn counted(values: impl IntoIterator<Item = String>) -> BTreeMap<String, usize> {
    values.into_iter().fold(BTreeMap::new(), |mut counts, value| {
        *counts.entry(value).or_default() += 1;
        counts
    })
}

fn diff_counted_surface(
    old: &BTreeMap<String, usize>,
    new: &BTreeMap<String, usize>,
    domain: DiffDomain,
    noun: &str,
    arch: &Option<String>,
    findings: &mut Vec<DiffFinding>,
) {
    for value in old.keys().chain(new.keys()).collect::<BTreeSet<_>>() {
        let old = old.get(value).copied().unwrap_or_default();
        let new = new.get(value).copied().unwrap_or_default();
        if old > new {
            push_semantic(
                findings,
                domain,
                ChangeSeverity::Warning,
                arch,
                format!("removed {} {noun}(s): {}", old - new, concise(value)),
            );
        } else if new > old {
            push_semantic(
                findings,
                domain,
                ChangeSeverity::Info,
                arch,
                format!("added {} {noun}(s): {}", new - old, concise(value)),
            );
        }
    }
}

fn concise(value: &str) -> String {
    const LIMIT: usize = 120;
    let escaped = value.escape_default().to_string();
    if escaped.chars().count() <= LIMIT {
        return format!("\"{escaped}\"");
    }
    let prefix = escaped.chars().take(LIMIT).collect::<String>();
    format!("\"{prefix}…\"")
}

fn push_semantic(
    findings: &mut Vec<DiffFinding>,
    domain: DiffDomain,
    severity: ChangeSeverity,
    arch: &Option<String>,
    message: String,
) {
    findings.push(DiffFinding {
        domain,
        severity,
        arch: arch.clone(),
        message,
    });
}

fn field_change<T: std::fmt::Debug + PartialEq>(
    old: T,
    new: T,
    label: &str,
    domain: DiffDomain,
    severity: ChangeSeverity,
    arch: &Option<String>,
    findings: &mut Vec<DiffFinding>,
) {
    if old != new {
        push_semantic(
            findings,
            domain,
            severity,
            arch,
            format!("{label} changed: {old:?} -> {new:?}"),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::report::{
        EntityId, EvidenceId, Fact, FactId, IdentityStability, NonEmpty, ObservationId,
        RecoveryLanguage, Weakness, recover_symbol_surface,
    };
    use serde_json::json;

    fn digest(byte: char) -> String {
        std::iter::repeat_n(byte, 64).collect()
    }

    #[test]
    fn slice_only_recovery_identity_ignores_provenance_but_reports_semantic_change() {
        let bytes = macho_test_support::thin64_x86_64_with_symbols(&[
            macho_test_support::SymbolFixture {
                name: "_duplicate",
                external: true,
                defined: true,
            },
            macho_test_support::SymbolFixture {
                name: "_duplicate",
                external: true,
                defined: true,
            },
        ]);
        let container = crate::core::parse(&bytes).expect("parse fixture");
        let old = recover_symbol_surface(
            container.first_macho().expect("image"),
            RecoveryLanguage::CAbi,
        )
        .expect("recover surface");
        assert_eq!(old.slices.as_slice()[0].entities.len(), 2);
        assert!(old.slices.as_slice()[0]
            .entities
            .iter()
            .all(|entity| entity.identity_stability == IdentityStability::SliceOnly));

        let mut provenance_only = old.clone();
        for (index, entity) in provenance_only.slices.as_mut_slice()[0]
            .entities
            .iter_mut()
            .enumerate()
        {
            let entity_byte = if index == 0 { 'a' } else { 'b' };
            entity.id = EntityId::new(digest(entity_byte)).expect("entity ID");
            entity.observation_ids = NonEmpty::new(vec![
                ObservationId::new(digest(if index == 0 { 'c' } else { 'd' }))
                    .expect("observation ID"),
            ])
            .expect("non-empty observations");
            if let Fact::Known {
                id, evidence_ids, ..
            } = &mut entity.role
            {
                *id = FactId::new(digest(if index == 0 { 'e' } else { 'f' }))
                    .expect("fact ID");
                *evidence_ids = NonEmpty::new(vec![
                    EvidenceId::new(digest(if index == 0 { '1' } else { '2' }))
                        .expect("evidence ID"),
                ])
                .expect("non-empty evidence");
            }
            if let Fact::Known {
                id,
                value,
                evidence_ids,
                ..
            } = &mut entity.location
            {
                *id = FactId::new(digest(if index == 0 { '3' } else { '4' }))
                    .expect("location fact ID");
                value.address = value.address.map(|address| address + 0x10_0000);
                *evidence_ids = NonEmpty::new(vec![
                    EvidenceId::new(digest(if index == 0 { '5' } else { '6' }))
                        .expect("location evidence ID"),
                ])
                .expect("non-empty location evidence");
            }
            entity.evidence.reverse();
        }
        provenance_only.slices.as_mut_slice()[0].entities.reverse();

        let arch = Some("x86_64".to_owned());
        let mut findings = Vec::new();
        diff_recovery_surface(
            &old,
            &provenance_only,
            DiffDomain::CSurface,
            &arch,
            &mut findings,
        )
        .expect("compare provenance-only change");
        assert!(findings.is_empty(), "{findings:?}");

        let mut semantic_change = provenance_only;
        let changed = &mut semantic_change.slices.as_mut_slice()[0].entities[0];
        let Fact::Known { value, .. } = &mut changed.weakness else {
            panic!("fixture weakness should be known");
        };
        *value = Weakness::WeakDefinition;
        diff_recovery_surface(
            &old,
            &semantic_change,
            DiffDomain::CSurface,
            &arch,
            &mut findings,
        )
        .expect("compare semantic change");
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].domain, DiffDomain::CSurface);
        assert!(findings[0].message.starts_with("changed recovered entity"));
    }

    #[test]
    fn objc_header_identity_ignores_ids_but_reports_declaration_changes() {
        let declaration = |id: char, protocols: Value| {
            json!({
                "kind":"objc_interface",
                "id":digest(id),
                "name":"Widget",
                "superclass":null,
                "protocols":protocols,
                "ivars":[],
                "members":[]
            })
        };
        let old = vec![declaration('a', json!([]))];
        let id_only = vec![declaration('b', json!([]))];
        let arch = Some("arm64".to_owned());
        let mut findings = Vec::new();
        diff_objc_header_values(&old, &id_only, &arch, &mut findings)
            .expect("compare ID-only change");
        assert!(findings.is_empty(), "{findings:?}");

        let changed = vec![declaration('c', json!(["NSCopying"]))];
        diff_objc_header_values(&old, &changed, &arch, &mut findings)
            .expect("compare declaration change");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].domain, DiffDomain::ObjCHeaders);
        assert_eq!(findings[0].severity, ChangeSeverity::Warning);
        assert!(
            findings[0]
                .message
                .contains("changed Objective-C declaration")
        );
    }
}
